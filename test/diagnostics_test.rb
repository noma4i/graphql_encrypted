require 'test_helper'

class DiagnosticsTest < Minitest::Test
  Diagnostics = GraphqlEncrypted::Diagnostics
  User = Struct.new(:id, :username)
  Visitor = Struct.new(:id)
  Fake = Struct.new(:id, :user, :authenticated_at, :tags) do
    def diagnostic_tags
      tags
    end
  end

  def setup
    Sentry.init do |config|
      config.dsn = 'http://key@localhost/1'
      config.transport.transport_class = Sentry::DummyTransport
      config.background_worker_threads = 0
      config.traces_sample_rate = 0.0
    end

    configure(sentry: true, sentry_namespace: 'app', filter_parameters: [], expected_errors: [], body_tags: {}, logger: nil)
  end

  def test_an_expected_error_is_matched_by_name_ancestry_or_callable
    configure(expected_errors: ['Errno::ENOENT', ->(error) { error.message == 'tolerated' }])

    assert Diagnostics.expected?(ActiveRecord::RecordNotFound.new)
    assert Diagnostics.expected?(Errno::ENOENT.new)
    assert Diagnostics.expected?(RuntimeError.new('tolerated'))
    refute Diagnostics.expected?(RuntimeError.new('broken'))

    refute Diagnostics.expected?(nil)
  end

  def test_annotate_sets_the_user_tags_and_context_under_the_namespace
    configure(body_tags: { platform: %w[platform], version: %w[version appVersion] })
    session = Fake.new(5, User.new(9, 'ann'), Time.now, {})
    body = { 'operationName' => 'Feed', 'query' => '{ feed }', 'platform' => 'web', 'appVersion' => '1.2' }

    Sentry.with_scope do |scope|
      Diagnostics.annotate(operation: 'graphql', session: session, body: body, graphql: true, values: { 'path' => '/graphql' })

      assert_equal({ id: 9, username: 'ann' }, scope.user)
      assert_equal({ operation: 'graphql', graphql_operation_name: 'Feed', platform: 'web', version: '1.2', app: 'true' }, scope.tags)
      assert_equal({ 'path' => '/graphql', 'operation_name' => 'Feed', 'query' => '{ feed }' }, scope.contexts[:app].except('variables', 'persisted_query_hash'))
    end
  end

  def test_a_session_without_sign_in_gives_the_fallback_user
    session = Fake.new(5, User.new(9, 'ann'), nil, {})

    Sentry.with_scope do |scope|
      Diagnostics.annotate(operation: 'ws', session: session, user: { id: 3 })

      assert_equal({ id: 3 }, scope.user)
    end
  end

  def test_secret_keys_are_filtered_at_any_depth_and_long_strings_are_cut
    configure(filter_parameters: [:pin])
    variables = { 'items' => [{ 'idToken' => 'secret-1', 'name' => 'Ann' }], 'pin' => '0000', 'long' => 'x' * (Diagnostics::MAX_STRING + 7) }

    Sentry.with_scope do |scope|
      Diagnostics.annotate(operation: 'graphql', body: { 'variables' => variables }, graphql: true)
      shown = scope.contexts[:app]['variables']

      assert_equal %w[[FILTERED] Ann], [shown.dig('items', 0, 'idToken'), shown.dig('items', 0, 'name')]
      assert_equal '[FILTERED]', shown['pin']
      assert_includes shown['long'], '[truncated 7 characters]'
    end
  end

  def test_variables_above_the_limit_become_a_truncated_preview
    variables = (1..20).to_h { |index| ["field#{index}", 'y' * 3000] }

    Sentry.with_scope do |scope|
      Diagnostics.annotate(operation: 'graphql', body: { 'variables' => variables }, graphql: true)
      shown = scope.contexts[:app]['variables']

      assert_equal true, shown['truncated']
      assert_operator shown['bytes'], :>, Diagnostics::MAX_VARIABLES_BYTES
      assert_operator shown['preview'].bytesize, :<=, Diagnostics::MAX_VARIABLES_BYTES
    end
  end

  def test_document_adds_the_kind_and_the_resolved_query_without_dropping_the_context
    Sentry.with_scope do |scope|
      Diagnostics.annotate(operation: 'graphql', values: { 'path' => '/graphql' })
      Diagnostics.document('mutation Save { save }', 'Save')

      assert_equal 'mutation', scope.tags[:kind]
      assert_equal ['/graphql', 'mutation Save { save }'], scope.contexts[:app].values_at('path', 'query')
    end
  end

  def test_literals_of_the_document_and_default_variable_values_never_reach_the_event
    default, token, note = %w[alpha bravo charlie].map { |name| "zq#{name}zq" }
    code = 4000 + 242
    query = "mutation Login($pin: String = \"#{default}\") { login(token: \"#{token}\", options: { code: #{code}, note: \"#{note}\" }, pin: $pin) { ok } }"
    body = { 'operationName' => 'Login', 'query' => query, 'extensions' => { 'persistedQuery' => { 'sha256Hash' => 'hash-kept' } } }

    Sentry.with_scope do
      Diagnostics.annotate(operation: 'graphql', body: body, graphql: true)
      Diagnostics.document(query, 'Login')
      Sentry.capture_message('failure')
    end
    serialized = JSON.generate(Sentry.get_current_client.transport.events.last.to_json_compatible)

    [default, token, note, code.to_s].each { |leak| refute serialized.include?(leak), "#{leak} reached the event" }

    assert serialized.include?('"operation_name":"Login"') && serialized.include?('hash-kept'), 'the operation name or the hash was lost'
  end

  def test_a_document_without_literals_is_kept_as_written_and_one_that_does_not_parse_is_dropped
    Sentry.with_scope do |scope|
      Diagnostics.annotate(operation: 'graphql', body: { 'query' => 'query Q($id: ID!) { node(id: $id) { id } }' }, graphql: true)

      assert_equal 'query Q($id: ID!) { node(id: $id) { id } }', scope.contexts[:app]['query']

      Diagnostics.annotate(operation: 'graphql', body: { 'query' => 'mutation { login(token: "zqbrokenzq" ' }, graphql: true)

      refute_includes scope.contexts[:app]['query'], 'zqbrokenzq'
    end
  end

  def test_session_tags_are_resolved_only_when_an_event_is_sent
    resolved = []
    session = Fake.new(5, Visitor.new(9), Time.now, nil)
    session.define_singleton_method(:diagnostic_tags) do
      resolved << true
      { platform: 'web', build: nil }
    end

    Sentry.with_scope do
      Diagnostics.annotate(operation: 'graphql', session: session)

      assert_empty resolved

      Sentry.capture_message('failure')
    end

    event = Sentry.get_current_client.transport.events.last

    assert_equal 1, resolved.size
    assert_equal({ platform: 'web', operation: 'graphql', app: 'true' }, event.tags.slice(:platform, :operation, :app))

    refute event.tags.key?(:build)
  end

  def test_before_send_drops_expected_errors_of_its_own_events_only
    own = Sentry::Event.new(configuration: Sentry.configuration).tap { |event| event.tags = { app: 'true' } }
    other = Sentry::Event.new(configuration: Sentry.configuration)
    expected = { exception: ActiveRecord::RecordNotFound.new }

    assert_nil Diagnostics.before_send(own, expected)
    assert_same other, Diagnostics.before_send(other, expected)

    assert_same own, Diagnostics.before_send(own, { exception: RuntimeError.new })
  end

  def test_scoped_reports_an_exception_that_leaves_it_and_raises_it_again
    assert_raises(ArgumentError) { Diagnostics.scoped { raise ArgumentError, 'boom' } }

    assert_equal(['ArgumentError'], Sentry.get_current_client.transport.events.map { |event| event.exception.values.first.type })
  end

  def test_scoped_propagates_protocol_refusals_without_reporting_them
    error = GraphqlEncrypted::Cable::Rejected.new(GraphqlEncrypted::Cable::Codes::Close::BAD_FRAME)
    assert_same error, assert_raises(GraphqlEncrypted::Cable::Rejected) { Diagnostics.scoped { raise error } }

    assert_empty Sentry.get_current_client.transport.events
  end

  def test_everything_is_a_no_op_while_sentry_is_off
    configure(sentry: false)

    assert_nil Diagnostics.annotate(operation: 'graphql', values: { 'path' => '/graphql' })
    assert_equal(:ran, Diagnostics.call { :ran })
    assert_raises(ArgumentError) { Diagnostics.scoped { raise ArgumentError, 'boom' } }

    assert_empty Sentry.get_current_client.transport.events
  end

  def test_call_silences_the_configured_logger_below_warn
    levels = []
    logger = Object.new
    logger.define_singleton_method(:silence) do |level, &block|
      levels << level
      block.call
    end
    configure(logger: logger)

    assert_equal(:ran, Diagnostics.call { :ran })

    assert_equal [Logger::WARN], levels
  end

  def test_decrypted_values_in_stack_locals_never_reach_the_event
    exception = assert_raises(RuntimeError) { raise 'failure' }
    Sentry.capture_exception(exception)
    event = Sentry.get_current_client.transport.events.last
    event.tags = { app: 'true' }
    frame = event.exception.values.first.stacktrace.frames.last
    frame.vars = { 'data' => '{"body":{"query":"mutation { login(token: secret-marker) }"}}', 'query' => 'secret-marker' }

    filtered = Diagnostics.before_send(event, { exception: RuntimeError.new })

    refute_includes JSON.generate(filtered.to_json_compatible), 'secret-marker'
  end

  def test_variable_directives_are_redacted_and_scalar_variables_keep_their_types
    Sentry.with_scope do |scope|
      Diagnostics.annotate(operation: 'graphql', graphql: true, body: {
                             'query' => 'query Q($id: ID! @tag(value: "secret-marker")) { node(id: $id) { id } }',
                            'variables' => { 'count' => 7, 'active' => false, 'missing' => nil }
                           })
      refute_includes scope.contexts[:app]['query'], 'secret-marker'
      assert_equal({ 'count' => 7, 'active' => false, 'missing' => nil }, scope.contexts[:app]['variables'])
    end
  end

  def test_unparseable_and_absent_documents_do_not_invent_an_operation_kind
    [nil, 'query {', 'fragment Bits on Query { ok }', 'query A { ok }'].each do |document|
      Sentry.with_scope do |scope|
        Diagnostics.annotate(operation: 'graphql', body: nil, graphql: true)
        Diagnostics.document(document, 'Missing')
        refute scope.tags.key?(:kind)
      end
    end

    Sentry.with_scope do |scope|
      Diagnostics.document('query A { ok }', nil)
      assert_equal 'query', scope.tags[:kind]
    end
  end

  def test_a_database_failure_while_loading_session_tags_does_not_drop_the_error
    session = Fake.new(5, User.new(9, 'ann'), Time.now, {})
    session.stubs(:diagnostic_tags).raises(ActiveRecord::ConnectionNotEstablished)
    Sentry.with_scope do
      Diagnostics.annotate(operation: 'graphql', session: session)
      GraphqlEncrypted.report(ArgumentError.new('reported'))
    end

    assert_equal 'ArgumentError', Sentry.get_current_client.transport.events.last.exception.values.first.type
  end

  def test_errors_without_a_stacktrace_are_preserved
    Sentry.capture_exception(ArgumentError.new('reported'))
    event = Sentry.get_current_client.transport.events.last
    event.tags = { app: 'true' }
    assert_same event, Diagnostics.before_send(event, {})
    event.stubs(:exception).returns(nil)

    assert_same event, Diagnostics.before_send(event, {})
  end

  def test_the_default_session_diagnostic_tags_do_not_drop_an_error
    record = Session.create!(credential_digest: SecureRandom.hex(16), authenticated_at: Time.current)
    record.define_singleton_method(:user) { Struct.new(:id).new(9) }
    Sentry.with_scope do
      Diagnostics.annotate(operation: 'graphql', session: record)
      Sentry.capture_message('reported')
    end

    assert_equal 'graphql', Sentry.get_current_client.transport.events.last.tags[:operation]
  end
end
