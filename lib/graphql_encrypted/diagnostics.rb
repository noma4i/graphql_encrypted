# Error-report context for every request the gem serves. With +config.sentry = true+ each request scope carries the
# user, tags (operation, GraphQL operation, kind, body tags, session tags) and a context with the decrypted request,
# secrets filtered, literal values of the document cut and long values cut. Without Sentry every method is a no-op, so applications that do not report errors lose nothing.
#
# @see GraphqlEncrypted::Configuration
# @see GraphqlEncrypted::Session#diagnostic_tags
module GraphqlEncrypted::Diagnostics
  SECRET_KEYS = %w[credential responseKey accessToken access_token token code idToken id_token authCode auth_code password secret key challenge otp].freeze
  EXPECTED_ERRORS = %w[ActiveRecord::RecordInvalid ActiveRecord::RecordNotFound ActiveRecord::RecordNotUnique JSON::JWT::Exception].freeze
  MAX_STRING = 4000
  MAX_VARIABLES_BYTES = 32.kilobytes
  FILTERED = '[FILTERED]'.freeze
  UNPARSED = '[unparsed document]'.freeze

  module_function

  # Runs a request or a job: Sentry scope, reporting of an exception that leaves it, and a log silenced below WARN.
  def call(&)
    scoped { silenced(&) }
  end

  def scoped
    return yield unless enabled?

    ::Sentry.with_scope do
      yield
    rescue GraphqlEncrypted::Cable::Rejected
      raise
    rescue StandardError => e
      ::Sentry.capture_exception(e)
      raise
    end
  end

  def capture(error)
    ::Sentry.capture_exception(error) if enabled?
  end

  # Warning for a payload the PayloadMiddleware could not decrypt; +request+ is a Rack::Request and
  # +config.payload_failure_context+ adds the values the application knows about it.
  def payload_refused(request)
    return unless enabled?

    ::Sentry.capture_message(
      'GraphQL transport security rejected', level: :warning,
      tags: { error_code: 'PAYLOAD_DECRYPTION_FAILED', transport_layer: 'payload_encryption' },
      extra: { request_id: request.get_header('action_dispatch.request_id') || request.get_header('HTTP_X_REQUEST_ID') }.merge(GraphqlEncrypted.configuration.payload_failure_context.call(request))
    )
  end

  # Context of an HTTP request; +data+ is the opened envelope, nil before it is opened.
  def request(request:, operation:, session: nil, data: nil)
    annotate(
      operation: operation, session: session, body: data && data['body'], graphql: operation == 'graphql',
      values: {
        'requestId' => data && data['requestId'], 'sequence' => data && data['sequence'], 'path' => request.path, 'session_id' => session&.id,
        'ip' => request.remote_ip, 'user_agent' => request.user_agent
      }
    )
  end

  # Context of any request: +graphql+ reads operation name, query, variables and persisted hash from +body+, else the body is kept as is.
  # @param user [Hash] Sentry user used when the session has none
  def annotate(operation:, session: nil, user: nil, body: nil, graphql: false, values: {})
    return unless enabled?

    fields = graphql ? graphql_fields(body) : { 'body' => body }

    publish(
      user: session_user(session) || user, session: session,
      tags: { operation: operation, graphql_operation_name: fields['operation_name'] }.merge(body_tags(body)),
      values: values.merge(fields)
    )
  end

  # Context of a socket command; +connection+ is a GraphqlEncrypted::Cable::Connection and +body+ the opened frame.
  def socket(connection, session: nil, channel: nil, command: nil, stream: nil, body: nil)
    annotate(
      operation: 'ws', session: session, user: { id: connection.user_id }.compact, body: body&.to_h&.deep_stringify_keys, graphql: true,
      values: {
        'path' => connection.request_path, 'session_id' => session&.id || connection.session_id, 'connection_id' => connection.connection_id,
        'ip' => connection.remote_ip, 'user_agent' => connection.user_agent, 'channel' => channel, 'command' => command, 'stream' => stream
      }
    )
  end

  def document(document, operation_name)
    return unless enabled?

    publish(user: nil, tags: { kind: document_kind(document, operation_name) }, values: { 'query' => redact(document) })
  end

  # Sentry before_send: drops expected errors of the gem's requests and removes stack frame variables.
  def before_send(event, hint)
    return event unless event.tags[namespace.to_sym]
    return if expected?(hint[:exception])

    event.is_a?(::Sentry::ErrorEvent) ? filter_frames(event) : event
  end

  def expected?(error)
    return false unless error

    ancestors = error.class.ancestors.filter_map(&:name)

    (EXPECTED_ERRORS + GraphqlEncrypted.option(:expected_errors)).any? { |entry| entry.respond_to?(:call) ? entry.call(error) : ancestors.include?(entry) }
  end

  def enabled?
    GraphqlEncrypted.option(:sentry) && defined?(::Sentry) && ::Sentry.initialized?
  end

  def namespace
    GraphqlEncrypted.option(:sentry_namespace)
  end

  def silenced(&)
    logger = GraphqlEncrypted.option(:logger)

    logger.respond_to?(:silence) ? logger.silence(Logger::WARN, &) : yield
  end

  def filter_frames(event)
    event.exception&.values&.each do |exception|
      exception.stacktrace&.frames&.each { |frame| frame.vars = nil }
    end

    event
  end

  def filter
    parameters = GraphqlEncrypted.option(:filter_parameters) + SECRET_KEYS.map { |key| /\A#{Regexp.escape(key)}\z/i }

    filters.compute_if_absent(parameters) { ActiveSupport::ParameterFilter.new(parameters) }
  end

  def filters
    @filters ||= Concurrent::Map.new
  end

  def graphql_fields(body)
    return {} unless body.is_a?(Hash)

    {
      'operation_name' => body['operationName'], 'query' => redact(body['query']), 'variables' => body['variables'], 'persisted_query_hash' => persisted_hash(body['extensions'])
    }
  end

  def redact(document)
    return document unless document.is_a?(String)

    printer = Redactor.new
    redacted = printer.print(GraphQL.parse(document))

    printer.filtered? ? redacted : document
  rescue GraphQL::ParseError
    UNPARSED
  end

  def persisted_hash(extensions)
    persisted = extensions['persistedQuery'] if extensions.is_a?(Hash)

    persisted['sha256Hash'] if persisted.is_a?(Hash)
  end

  def document_kind(document, operation_name)
    return unless document.is_a?(String)

    operations = GraphQL.parse(document).definitions.grep(GraphQL::Language::Nodes::OperationDefinition)
    operation = operation_name ? operations.find { |candidate| candidate.name == operation_name } : operations.first

    operation&.operation_type
  rescue GraphQL::ParseError
    nil
  end

  def body_tags(body)
    return {} unless body.is_a?(Hash)

    GraphqlEncrypted.option(:body_tags).transform_values { |keys| body.values_at(*keys).find { |value| value.is_a?(String) } }
  end

  def session_user(session)
    user = session&.user
    return unless session&.authenticated_at && user

    { id: user.id, username: (user.username if user.respond_to?(:username)) }.compact
  end

  def defer_session_tags(session)
    return unless session&.user

    ::Sentry.get_current_scope.add_event_processor do |event, _hint|
      event.tags = session.diagnostic_tags.compact.transform_values(&:to_s).merge(event.tags)
      event
    rescue ActiveRecord::ActiveRecordError
      event
    end
  end

  def publish(user:, tags:, values:, session: nil)
    defer_session_tags(session)
    ::Sentry.set_user(user) if user
    ::Sentry.set_tags(tags.compact.transform_values(&:to_s).merge(namespace.to_sym => 'true'))

    ::Sentry.set_context(namespace.to_sym, bound(sanitize(values.compact)))
  end

  def sanitize(values)
    clip(filter.filter(values))
  end

  def bound(values)
    return values unless values['variables']

    json = JSON.generate(values['variables'])
    return values if json.bytesize <= MAX_VARIABLES_BYTES

    values.merge('variables' => { 'truncated' => true, 'bytes' => json.bytesize, 'preview' => json.byteslice(0, MAX_VARIABLES_BYTES).scrub })
  end

  def clip(value)
    case value
    when String then value.length > MAX_STRING ? "#{value[0, MAX_STRING]}...[truncated #{value.length - MAX_STRING} characters]" : value
    when Hash then value.transform_values { |item| clip(item) }
    when Array then value.map { |item| clip(item) }
    else value
    end
  end
end
