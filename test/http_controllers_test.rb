require 'test_helper'
require 'tmpdir'

class HttpControllersTest < Minitest::Test
  class QueryStore
    def initialize
      @queries = {}
    end

    def fetch_query(sha)
      @queries[sha]
    end

    def save_query(sha, query)
      @queries[sha] = query
    end
  end

  GRAPHQL = '/rig/graphql'.freeze
  LOGIN = '/rig/login'.freeze
  MUTATION = 'mutation { bump }'.freeze

  def setup
    @directory = Dir.mktmpdir
    @exchanges = []
    configure(key_generator: ActiveSupport::KeyGenerator.new('test-secret-key-base'), cache: ActiveSupport::Cache::MemoryStore.new, persisted_query_store: QueryStore.new)
    GraphqlEncrypted.configuration.limits.replace(GraphqlEncrypted::Configuration.new.limits)
    HttpRigSession.delete_all
    HttpRigSchema.bumps = 0
    HttpRigSchema.reads = 0
    @client = build_client('session.json')
  end

  def teardown
    FileUtils.remove_entry(@directory)

    super
  end

  def build_client(name)
    transport = lambda do |path, ciphertext|
      HttpRig.post(path, ciphertext).tap { |(_status, body)| @exchanges << [path, ciphertext, body] }
    end

    GraphqlEncrypted::Client.new(origin: TestKeys::AUDIENCE, public_key: TestKeys::SERVER.public_key.to_pem, pin: TestKeys::PIN, state_file: File.join(@directory, name), transport: transport)
  end

  def session
    HttpRigSession.find_by_credential(GraphqlEncrypted::Client.stored_credential(File.join(@directory, 'session.json')))
  end

  def test_each_write_takes_the_next_sequence_and_runs_once
    assert_equal true, @client.call(LOGIN, {}).dig('body', 'ok')

    first = @client.call(GRAPHQL, { query: MUTATION })
    second = @client.call(GRAPHQL, { query: MUTATION })

    assert_equal [1, 2], [first.dig('body', 'data', 'bump'), second.dig('body', 'data', 'bump')]
    assert_equal [2, 3], [first['sequence'], second['sequence']]

    assert_equal 3, session.sequence
  end

  def test_a_resent_write_gets_the_stored_answer_and_does_not_run_again
    @client.call(LOGIN, {})
    @client.call(GRAPHQL, { query: MUTATION })
    path, ciphertext, response = @exchanges.last

    status, replayed = HttpRig.post(path, ciphertext)

    assert_equal [200, response], [status, replayed]
    assert_equal 1, HttpRigSchema.bumps

    assert_equal 2, session.sequence
  end

  def test_a_resent_hash_only_write_gets_its_stored_answer_after_the_query_store_loses_the_hash
    @client.call(LOGIN, {})
    @client.call(GRAPHQL, GraphqlEncrypted::Client.persisted_body(query: MUTATION))
    accepted = @client.call(GRAPHQL, GraphqlEncrypted::Client.persisted_body(sha256: Digest::SHA256.hexdigest(MUTATION)))
    assert_equal [2, 3], [accepted.dig('body', 'data', 'bump'), accepted['sequence']]
    path, ciphertext, = @exchanges.last
    stored = session.encrypted_response
    GraphqlEncrypted.configuration.persisted_query_store = QueryStore.new

    status, replayed = HttpRig.post(path, ciphertext)

    assert_equal [200, stored], [status, replayed]
    assert_equal 3, session.sequence

    assert_equal 2, HttpRigSchema.bumps
  end

  def test_a_persisted_query_miss_answers_without_spending_the_sequence_and_the_full_query_then_uses_it
    @client.call(LOGIN, {})
    sha = Digest::SHA256.hexdigest(MUTATION)

    miss = @client.call(GRAPHQL, GraphqlEncrypted::Client.persisted_body(sha256: sha))

    assert_equal 'PERSISTED_QUERY_NOT_FOUND', miss.dig('body', 'errors', 0, 'extensions', 'code')
    assert_nil miss['sequence']
    assert_equal 1, session.sequence
    assert_equal 0, HttpRigSchema.bumps

    hit = @client.call(GRAPHQL, GraphqlEncrypted::Client.persisted_body(query: MUTATION))

    assert_equal [1, 2], [hit.dig('body', 'data', 'bump'), hit['sequence']]

    assert_equal 2, session.sequence
  end

  def test_a_read_runs_each_request_id_once
    @client.call(LOGIN, {})

    answer = @client.call(GRAPHQL, { query: '{ ok }' }, read: true)

    assert_equal true, answer.dig('body', 'data', 'ok')
    assert_nil answer['sequence']
    path, ciphertext, response = @exchanges.last
    status, replayed = HttpRig.post(path, ciphertext)

    assert_equal 200, status
    refute_equal response, replayed

    assert_equal 1, HttpRigSchema.reads
  end

  def test_a_public_answer_is_bound_to_the_request_that_asked
    answer = @client.public_request('/rig/config', { name: 'probe' })

    assert_equal({ 'minimumVersion' => '1.2.0', 'echo' => 'probe' }, answer['body'])

    assert answer['requestDigest']
  end

  def test_a_request_that_is_not_a_bare_jose_post_is_refused
    @client.call(LOGIN, {})
    _path, ciphertext, = @exchanges.last

    assert_equal 400, HttpRig.post(GRAPHQL, ciphertext, 'CONTENT_TYPE' => 'application/json').first
    assert_equal 400, HttpRig.post(GRAPHQL, ciphertext, 'HTTP_AUTHORIZATION' => 'Bearer x').first

    assert_equal 400, HttpRig.post(GRAPHQL, 'not-a-jwe').first
  end

  def test_session_starts_of_one_address_stop_at_the_default_limit
    answers = Array.new(31) { |index| build_client("starter-#{index}.json").call(LOGIN, {}) }

    assert_equal(Array.new(30, true), answers.first(30).map { |answer| answer.dig('body', 'ok') })

    assert_equal 'RATE_LIMITED', answers.last.dig('body', 'error')

    assert_includes 1..600, answers.last.dig('body', 'retryAfter')
  end

  def test_oversized_bodies_are_rejected_with_or_without_content_length
    body = 'x' * (GraphqlEncrypted::BaseController::MAX_BODY_BYTES + 1)
    assert_equal 413, HttpRig.post(LOGIN, body).first

    assert_equal 413, HttpRig.post(LOGIN, body, 'CONTENT_LENGTH' => '0').first
  end

  def test_key_and_database_failures_answer_unavailable_and_reach_the_reporter
    errors = []
    configure(error_reporter: ->(error) { errors << error })
    configure(private_key: 'not a key')
    assert_equal 503, HttpRig.post(LOGIN, 'ciphertext').first
    configure(private_key: TestKeys::SERVER.to_pem)
    HttpRigSession.stubs(:find_by_credential).raises(ActiveRecord::ConnectionNotEstablished)
    assert_raises(GraphqlEncrypted::Client::Retryable) { @client.call(LOGIN, {}) }

    assert_equal [KeyError, ActiveRecord::ConnectionNotEstablished], errors.map(&:class)
  end

  def test_unknown_operations_and_unsigned_sessions_cannot_execute_graphql
    assert_equal 'UNAUTHENTICATED', @client.call(GRAPHQL, { query: '{ ok }' }, read: true).dig('body', 'error')
    @client.call(LOGIN, {})
    assert_equal 'INVALID_REQUEST', @client.call('/rig/unknown', {}).dig('body', 'error')
    assert_equal 'UNAUTHENTICATED', @client.call(LOGIN, {}, read: true).dig('body', 'error')
    session.update!(authenticated_at: nil)
    [false, true].each do |read|
      assert_equal 'UNAUTHENTICATED', @client.call(GRAPHQL, { query: '{ ok }' }, read: read).dig('body', 'error')
    end

    assert_equal 0, HttpRigSchema.reads
  end

  def test_read_requests_reject_mutations_missing_persisted_queries_and_account_refusals
    @client.call(LOGIN, {})
    assert_equal 'SEQUENCE_REQUIRED', @client.call(GRAPHQL, { query: MUTATION }, read: true).dig('body', 'error')
    body = GraphqlEncrypted::Client.persisted_body(sha256: 'f' * 64)
    assert_equal 'PERSISTED_QUERY_NOT_FOUND', @client.call(GRAPHQL, body, read: true).dig('body', 'errors', 0, 'extensions', 'code')
    HttpRigSession.any_instance.stubs(:refusal).returns('ACCOUNT_LOCKED')
    [true, false].each do |read|
      assert_equal 'ACCOUNT_LOCKED', @client.call(GRAPHQL, { query: '{ ok }' }, read: read).dig('body', 'error')
    end

    assert_equal 0, HttpRigSchema.bumps
  end

  def test_invalid_graphql_inputs_and_documents_answer_errors
    @client.call(LOGIN, {})
    [{ query: '{ ok }', extensions: [] }, { query: '{ ok }', variables: [] }, { query: '{ ok }', operationName: 1 }, {}].each do |body|
      assert_equal 'INVALID_REQUEST', @client.call(GRAPHQL, body).dig('body', 'error')
    end
    assert @client.call(GRAPHQL, { query: '{' }, read: true).dig('body', 'errors').any?

    assert_equal 'INVALID_REQUEST', @client.call(GRAPHQL, {}, read: true).dig('body', 'error')
  end

  def test_logout_runs_the_configured_action_before_revoking_the_session
    @client.call(LOGIN, {})
    record = session
    ended = []
    previous = HttpRigSecureController.sign_out_handler
    HttpRigSecureController.sign_out(with: ->(current) { ended << [current.id, current.ended_at] })
    assert_equal true, @client.call('/rig/logout', {}).dig('body', 'revoked')
    assert_equal [[record.id, nil]], ended
    assert record.reload.ended_at
  ensure
    HttpRigSecureController.sign_out(with: previous)
  end

  def test_logout_ends_the_session_after_a_sequence_conflict_and_answers_the_client_sequence
    @client.call(LOGIN, {})
    record = session
    record.update!(sequence: 7)
    answer = @client.call('/rig/logout', {})

    assert_equal true, answer.dig('body', 'revoked')
    assert_equal 2, answer['sequence']
    assert record.reload.ended_at

    assert_equal 7, record.sequence
  end

  def test_logout_without_a_sequence_ends_the_session_and_answers_no_sequence
    @client.call(LOGIN, {})
    answer = @client.call('/rig/logout', {}, read: true)

    assert_equal true, answer.dig('body', 'revoked')
    assert_nil answer['sequence']

    assert session.ended_at
  end

  def test_logout_twice_answers_revoked_and_runs_the_handler_once
    @client.call(LOGIN, {})
    calls = []
    previous = HttpRigSecureController.sign_out_handler
    HttpRigSecureController.sign_out(with: ->(current) { calls << current.id })
    2.times { assert_equal true, @client.call('/rig/logout', {}, read: true).dig('body', 'revoked') }

    assert_equal 1, calls.size
  ensure
    HttpRigSecureController.sign_out(with: previous)
  end

  def test_logout_does_not_require_an_application_handler
    @client.call(LOGIN, {})

    assert_equal true, @client.call('/rig/logout', {}).dig('body', 'revoked')
  end

  def test_refused_mutations_roll_back_writes_before_running_refusal_actions
    @client.call(LOGIN, {})
    record = session
    seen = []
    HttpRigSchema.stubs(:execute).with do |_document, **options|
      current = options[:context][:encrypted_session]
      current.update!(ended_at: Time.current)
      options[:context][:after_refusal] << -> { seen << HttpRigSession.find(record.id).ended_at }
      true
    end.returns({ 'errors' => [{ 'message' => 'refused' }] })
    assert_equal 'refused', @client.call(GRAPHQL, { query: MUTATION }).dig('body', 'errors', 0, 'message')
    assert_equal [nil], seen

    assert_nil record.reload.ended_at
  end

  def test_a_refused_mutation_leaves_no_session_change_in_memory_and_closes_no_socket
    @client.call(LOGIN, {})
    record = session
    HttpRigSchema.stubs(:execute).with do |_document, **options|
      options[:context][:encrypted_session].ended_at = Time.current
      true
    end.returns({ 'errors' => [{ 'message' => 'refused' }] })
    GraphqlEncrypted::Cable::Revoke.expects(:session).never

    @client.call(GRAPHQL, { query: MUTATION })

    assert_nil record.reload.ended_at
  end

  def test_a_refused_mutation_that_saved_the_session_inside_the_savepoint_closes_no_socket
    @client.call(LOGIN, {})
    HttpRigSchema.stubs(:execute).with do |_document, **options|
      options[:context][:encrypted_session].update!(ended_at: Time.current)
      true
    end.returns({ 'errors' => [{ 'message' => 'refused' }] })
    GraphqlEncrypted::Cable::Revoke.expects(:session).never

    @client.call(GRAPHQL, { query: MUTATION })

    assert_nil session.ended_at
  end

  def test_an_accepted_mutation_keeps_the_session_change_and_closes_the_socket_once
    @client.call(LOGIN, {})
    record = session
    HttpRigSchema.stubs(:execute).with do |_document, **options|
      options[:context][:encrypted_session].ended_at = Time.current
      true
    end.returns({ 'data' => { 'bump' => 1 } })
    GraphqlEncrypted::Cable::Revoke.expects(:session).with(record.id, reason: GraphqlEncrypted::Cable::Codes::Reason::LOGGED_OUT).once

    @client.call(GRAPHQL, { query: MUTATION })

    refute_nil record.reload.ended_at
  end

  def test_variable_errors_receive_a_code_without_overwriting_domain_codes
    @client.call(LOGIN, {})
    errors = [{ 'extensions' => { 'problems' => [] } }, { 'extensions' => { 'problems' => [], 'code' => 'DOMAIN' } }, { 'message' => 'syntax' }]
    HttpRigSchema.stubs(:execute).returns({ 'errors' => errors })
    answer = @client.call(GRAPHQL, { query: '{ ok }' }, read: true)

    assert_equal(['INVALID_INPUT', 'DOMAIN', nil], answer.dig('body', 'errors').map { |error| error.dig('extensions', 'code') })
  end

  def test_execution_notifications_count_only_uncached_non_schema_sql
    @client.call(LOGIN, {})
    events = []
    subscriber = ActiveSupport::Notifications.subscribe('execute.graphql_encrypted') { |event| events << event.payload }
    HttpRigSchema.stubs(:execute).with do |*|
      [{ name: 'Query' }, { name: 'SCHEMA' }, { name: 'CACHE' }, { name: 'Query', cached: true }].each do |payload|
        ActiveSupport::Notifications.instrument('sql.active_record', payload)
      end
      true
    end.returns({ 'data' => { 'ok' => true } })
    @client.call(GRAPHQL, { query: '{ ok }' }, read: true)
    @client.call(GRAPHQL, { query: MUTATION })
    assert_equal(%w[query mutation], events.map { |event| event[:kind] })
    assert_equal([1, 1], events.map { |event| event[:sql] })
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
  end

  def test_named_session_models_and_current_user_scopes_reach_the_schema
    previous = HttpRigSecureController.encrypted_session_model
    HttpRigSecureController.session('HttpRigSession')
    users = []
    configure(with_user: ->(user, &block) {
      users << user.id
      block.call
    })
    HttpRigSession.any_instance.stubs(:user).returns(Struct.new(:id).new(17))
    @client.call(LOGIN, {})
    assert_equal true, @client.call(GRAPHQL, { query: '{ ok }' }, read: true).dig('body', 'data', 'ok')
    assert_equal [17], users
  ensure
    HttpRigSecureController.session(previous)
  end
end
