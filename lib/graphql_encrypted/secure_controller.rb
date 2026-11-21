# Base controller for the session endpoint. One action serves three kinds of request, picked by params[:operation]:
# a sign-in action, 'logout' and 'graphql'. A request with a sequence is a write: it runs once, in order,
# and its answer is replayed on resend. A request without one is a read: queries only, each requestId once.
#
#   class EncryptedRequestsController < GraphqlEncrypted::SecureController
#     schema AppSchema
#     session ApiSession
#     sign_in :otp, :confirm, with: SignIn
#     sign_out with: SignOut
#   end
#
# A first request that would create a session counts against the +session_start+ limit of the remote address and answers RATE_LIMITED with +retryAfter+ (seconds) past it.
# A sign-in handler responds to call(session, body, action, request:) and returns the answer Hash; it marks the session authenticated.
# Logout ignores the sequence: any sequence or none ends the session once (the sign-out handler runs once) and answers { revoked: true }
# with the sequence the client sent, so it works after SEQUENCE_CONFLICT too.
# A sign-out handler responds to call(session) and runs before logout ends the session. The session model answers
# +user+, +refusal+ and +diagnostic_tags+ (see GraphqlEncrypted::Session); the GraphQL context carries encrypted_session, after_refusal,
# current_user, current_user_id, limiter_key, request_ip and user_agent. Execution runs inside +configuration.with_user+ and publishes
# an execute.graphql_encrypted notification with operation_name, kind and sql (counted only while someone listens).
#
# @see GraphqlEncrypted::BaseController
# @see GraphqlEncrypted::Session
# @see GraphqlEncrypted::Client
class GraphqlEncrypted::SecureController < GraphqlEncrypted::BaseController
  GRAPHQL = 'graphql'.freeze
  LOGOUT = 'logout'.freeze
  INVALID_INPUT = 'INVALID_INPUT'.freeze
  RATE_LIMITED = 'RATE_LIMITED'.freeze
  EXECUTION_EVENT = 'execute.graphql_encrypted'.freeze
  UNCOUNTED_SQL = %w[SCHEMA CACHE].freeze

  class_attribute :encrypted_schema, :encrypted_session_model, :sign_in_handler, :sign_out_handler, instance_writer: false
  class_attribute :sign_in_actions,
                  instance_writer: false,
                  default: [].freeze

  class << self
    def schema(schema)
      self.encrypted_schema = schema
    end

    # @param model [Class, String] ActiveRecord model that includes GraphqlEncrypted::Session
    def session(model)
      self.encrypted_session_model = model
    end

    # A first request (sequence 1) to a sign-in action creates the session, within the +session_start+ limit (see GraphqlEncrypted::Configuration#limit).
    def sign_in(*actions, with:)
      self.sign_in_actions = (sign_in_actions + actions.map(&:to_s)).freeze

      self.sign_in_handler = with
    end

    def sign_out(with:)
      self.sign_out_handler = with
    end
  end

  def create
    serve_encrypted(GraphqlEncrypted::Envelope::FIELDS) { |data| encrypted_answer(data) }
  end

  private

  def encrypted_operation
    params[:operation].to_s
  end

  def sign_in_operation?
    sign_in_actions.include?(encrypted_operation)
  end

  def diagnostics_operation
    sign_in_operation? ? "auth/#{encrypted_operation}" : encrypted_operation
  end

  def encrypted_answer(data)
    session = encrypted_session(data)
    report_request(session, data)
    return seal(data, session_missing(data)) unless session
    return end_session(session, data) if encrypted_operation == LOGOUT

    data['sequence'] ? write(session, data) : read(session, data)
  end

  def session_missing(data)
    return { error: 'UNAUTHENTICATED' } unless starting_session?(data)

    { error: RATE_LIMITED, retryAfter: GraphqlEncrypted::Limiter.retry_after(:session_start, request.remote_ip) }
  end

  def starting_session?(data)
    sign_in_operation? && data['sequence'] == 1
  end

  def encrypted_session(data)
    model = encrypted_session_model.is_a?(String) ? encrypted_session_model.constantize : encrypted_session_model
    session = model.find_by_credential(data.fetch('credential'))
    return session if session

    model.start_with_credential(data['credential']) if starting_session?(data) && GraphqlEncrypted::Limiter.take?(:session_start, request.remote_ip)
  end

  # A persisted query miss is answered after the replay and sequence checks and does not spend the sequence: the client resends the same sequence with the full query.
  def write(session, data)
    session.exchange(data, admit: -> { query_failure(data) }) { perform(session, data) }
  end

  def query_failure(data)
    GraphqlEncrypted::PersistedQuery.failure(resolution(data['body'])) if encrypted_operation == GRAPHQL
  end

  def perform(session, data)
    return sign_in_handler.call(session, data['body'], encrypted_operation, request: request) if sign_in_operation?
    return INVALID_REQUEST unless encrypted_operation == GRAPHQL

    error = session_refusal(session)
    return { error: error } if error

    rolled_back_on_refusal(session) { execute_graphql(session, data['body'], resolution(data['body']).document) }
  end

  def read(session, data)
    return seal(data, { error: 'UNAUTHENTICATED' }) unless encrypted_operation == GRAPHQL

    error = session_refusal(session)
    return seal(data, { error: error }) if error

    failure = GraphqlEncrypted::PersistedQuery.failure(resolution(data['body']))
    return seal(data, failure) if failure

    document = resolution(data['body']).document
    return seal(data, { error: 'SEQUENCE_REQUIRED' }) if write_document?(document)

    admission = session.admit_read(data)
    return seal(data, { error: admission }) if admission

    seal(data, execute_graphql(session, data['body'], document))
  end

  # Logout skips the sequence check and the stored answer: a client that lost its pending write must still end the session.
  def end_session(session, data)
    session.revoke(data) { sign_out_handler&.call(session) }
  end

  def session_refusal(session)
    session.signed_in? ? session.refusal : 'UNAUTHENTICATED'
  end

  # The savepoint keeps a refused mutation from committing partial writes and the session record returns to its state before it; after_refusal callbacks run once it is rolled back.
  def rolled_back_on_refusal(session)
    result = nil
    refused = false
    snapshot = session.attributes
    ActiveRecord::Base.transaction(requires_new: true) do
      result = yield
      refused = result[:error] || result['errors']&.any?
      raise ActiveRecord::Rollback if refused
    end
    if refused
      session.restore_snapshot(snapshot)
      after_refusal.each(&:call)
    end

    result
  end

  def after_refusal
    @after_refusal ||= []
  end

  def resolution(body)
    @resolution ||= body['extensions'].nil? || body['extensions'].is_a?(Hash) ? GraphqlEncrypted::PersistedQuery.resolve(body['query'], body['extensions']) : GraphqlEncrypted::PersistedQuery::NONE
  end

  def execute_graphql(session, body, document)
    return INVALID_REQUEST unless valid_graphql_request?(document, body)

    GraphqlEncrypted::Diagnostics.document(document, body['operationName'])

    GraphqlEncrypted.with_user(session.user) do
      instrumented(body['operationName'], document) { variable_errors_coded(execute_schema(session, body, document)) }
    end
  end

  def instrumented(operation_name, document)
    return yield unless ActiveSupport::Notifications.notifier.listening?(EXECUTION_EVENT)

    payload = { operation_name: operation_name, kind: write_document?(document) ? 'mutation' : 'query', sql: 0 }
    counter = ->(*, query) { payload[:sql] += 1 unless query[:cached] || UNCOUNTED_SQL.include?(query[:name]) }

    ActiveSupport::Notifications.instrument(EXECUTION_EVENT, payload) do
      ActiveSupport::Notifications.subscribed(counter, 'sql.active_record') { yield }
    end
  end

  def execute_schema(session, body, document)
    encrypted_schema.execute(document, variables: body['variables'] || {}, operation_name: body['operationName'], context: execution_context(session)).to_h
  end

  def execution_context(session)
    user = session.user

    {
      encrypted_session: session, after_refusal: after_refusal, current_user: user, current_user_id: user&.id,
      limiter_key: "session:#{session.id}", request_ip: request.remote_ip, user_agent: request.user_agent
    }
  end

  # A variable problem carries no code of its own; the client gets INVALID_INPUT.
  def variable_errors_coded(result)
    result['errors']&.each do |error|
      extensions = error['extensions']
      extensions['code'] ||= INVALID_INPUT if extensions&.key?('problems')
    end

    result
  end

  def valid_graphql_request?(document, body)
    document.is_a?(String) && hash_fields?(body) && operation_name?(body['operationName'])
  end

  def hash_fields?(body)
    [body['extensions'], body['variables']].all? { |value| value.nil? || value.is_a?(Hash) }
  end

  def operation_name?(name)
    name.nil? || name.is_a?(String)
  end

  def write_document?(document)
    return false unless document.is_a?(String)

    GraphQL.parse(document).definitions.grep(GraphQL::Language::Nodes::OperationDefinition).any? { |operation| operation.operation_type != 'query' }
  rescue GraphQL::ParseError
    false
  end
end
