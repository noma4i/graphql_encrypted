require 'test_helper'
require 'tmpdir'

class ClientTest < Minitest::Test
  ORIGIN = TestKeys::AUDIENCE

  def setup
    @directory = Dir.mktmpdir
    @state_file = File.join(@directory, 'state.json')
    @requests = []
  end

  def teardown
    FileUtils.remove_entry(@directory)

    super
  end

  def build_client(&)
    transport = lambda do |path, ciphertext|
      data = GraphqlEncrypted::Envelope.open(ciphertext, method: 'POST', path: path, fields: fields_of(ciphertext))
      @requests << data

      [200, yield(data)]
    end

    GraphqlEncrypted::Client.new(origin: ORIGIN, public_key: TestKeys::SERVER.public_key.to_pem, pin: TestKeys::PIN, state_file: @state_file, transport: transport)
  end

  def fields_of(ciphertext)
    data = JSON.parse(JSON::JWE.decode(ciphertext, TestKeys::SERVER, ['RSA-OAEP'], ['A256GCM']).plain_text)

    data.key?('credential') ? GraphqlEncrypted::Envelope::FIELDS : GraphqlEncrypted::Envelope::PUBLIC_FIELDS
  end

  def test_a_write_carries_the_next_sequence_and_the_answer_advances_the_state
    client = build_client { |data| GraphqlEncrypted::Envelope.seal(data, { ok: true }, sequence: data['sequence']) }

    client.call('/graphql', { query: 'mutation { x }' })
    client.call('/graphql', { query: 'mutation { y }' })

    assert_equal([1, 2], @requests.map { |data| data['sequence'] })

    assert_equal 2, GraphqlEncrypted::Client.read_state(@state_file)['sequence']
  end

  def test_an_answer_without_a_sequence_frees_the_pending_one
    client = build_client { |data| GraphqlEncrypted::Envelope.seal(data, { errors: [] }) }

    client.call('/graphql', { query: 'mutation { x }' })
    client.call('/graphql', { query: 'mutation { x }' })

    assert_equal([1, 1], @requests.map { |data| data['sequence'] })

    refute GraphqlEncrypted::Client.read_state(@state_file).key?('pending')
  end

  def test_a_revoked_answer_deletes_the_state_file
    client = build_client { |data| GraphqlEncrypted::Envelope.seal(data, { revoked: true }, sequence: data['sequence']) }

    client.call('/logout', {})

    refute File.exist?(@state_file)
  end

  def test_a_read_has_no_sequence
    client = build_client { |data| GraphqlEncrypted::Envelope.seal(data, {}) }

    client.call('/graphql', { query: '{ x }' }, read: true)

    assert_nil @requests.first['sequence']
  end

  def test_a_public_answer_must_carry_the_request_digest
    bound = build_client { |data| GraphqlEncrypted::Envelope.seal(data, {}, bound: true) }
    unbound = build_client { |data| GraphqlEncrypted::Envelope.seal(data, {}) }

    assert_equal({}, bound.public_request('/config', { a: 1 })['body'])

    assert_raises(IOError) { unbound.public_request('/config', { a: 1 }) }
  end

  def test_persisted_body_hashes_the_query
    body = GraphqlEncrypted::Client.persisted_body(query: '{ x }')

    assert_equal Digest::SHA256.hexdigest('{ x }'), body.dig(:extensions, :persistedQuery, :sha256Hash)
  end

  def test_a_key_that_does_not_match_the_pin_is_refused
    assert_raises(ArgumentError) do
      GraphqlEncrypted::Client.new(origin: ORIGIN, public_key: TestKeys::SERVER.public_key.to_pem, pin: 'f' * 64, state_file: @state_file)
    end
  end

  def test_an_answer_for_another_sequence_is_refused_without_losing_the_pending_write
    client = build_client { |data| GraphqlEncrypted::Envelope.seal(data, { ok: true }, sequence: data['sequence'] + 1) }

    assert_raises(IOError) { client.call('/graphql', { query: 'mutation { x }' }) }

    state = GraphqlEncrypted::Client.read_state(@state_file)
    assert_equal 0, state['sequence']

    assert_equal 1, state.fetch('pending')['sequence']
  end

  def test_a_lost_answer_can_only_be_retried_with_its_original_body_and_credential
    calls = 0
    client = build_client do |data|
      calls += 1
      raise IOError, 'lost answer' if calls == 1

      GraphqlEncrypted::Envelope.seal(data, { ok: true }, sequence: data['sequence'])
    end
    credential = GraphqlEncrypted::Client.stored_credential(@state_file)
    assert_raises(GraphqlEncrypted::Client::Retryable) { client.call('/graphql', { query: 'mutation { x }' }) }
    assert_raises(ArgumentError) { client.call('/graphql', { query: 'mutation { y }' }) }
    assert_equal true, client.retry_pending.dig('body', 'ok')
    assert_equal([credential, credential], @requests.map { |data| data['credential'] })

    assert_equal 1, @requests.map { |data| data['requestId'] }.uniq.size
  end

  def test_a_replayed_read_is_repeated_with_a_new_request_id
    client = build_client do |data|
      body = @requests.size == 1 ? { error: 'REPLAYED_REQUEST' } : { ok: true }
      GraphqlEncrypted::Envelope.seal(data, body)
    end
    assert_equal true, client.call('/graphql', {}, read: true).dig('body', 'ok')

    assert_equal 2, @requests.map { |data| data['requestId'] }.uniq.size
  end

  def test_a_sequence_conflict_preserves_the_request_for_diagnosis
    client = build_client { |data| GraphqlEncrypted::Envelope.seal(data, { error: 'SEQUENCE_CONFLICT' }) }
    assert_raises(GraphqlEncrypted::Client::SequenceConflict) { client.call('/graphql', {}) }
    assert_equal 0, GraphqlEncrypted::Client.read_state(@state_file)['sequence']

    assert_equal 1, GraphqlEncrypted::Client.read_state(@state_file).dig('pending', 'sequence')
  end

  def test_http_failures_keep_pending_requests_and_distinguish_retryable_statuses
    { 503 => GraphqlEncrypted::Client::Retryable, 400 => GraphqlEncrypted::Client::Rejected }.each do |status, error|
      client = GraphqlEncrypted::Client.new(origin: ORIGIN, public_key: TestKeys::SERVER.public_key.to_pem, pin: TestKeys::PIN,
                                            state_file: @state_file, transport: ->(*) { [status, ''] })
      assert_raises(error) { client.call('/graphql', {}) }
      assert_equal 0, GraphqlEncrypted::Client.read_state(@state_file)['sequence']
    end

    [GraphqlEncrypted::Client::Retryable, GraphqlEncrypted::Client::Rejected].each do |error|
      client = GraphqlEncrypted::Client.new(origin: ORIGIN, public_key: TestKeys::SERVER.public_key.to_pem, pin: TestKeys::PIN,
                                            state_file: @state_file, transport: ->(*) { raise error, 'transport failed' })
      assert_raises(error) { client.call('/graphql', {}) }
    end
  end

  def test_damaged_and_publicly_readable_state_is_refused
    build_client { |data| GraphqlEncrypted::Envelope.seal(data, {}) }
    ['{', '[]', '{"credential":"key","sequence":"1"}'].each do |state|
      File.write(@state_file, state)
      assert_raises(GraphqlEncrypted::Client::StateError) { GraphqlEncrypted::Client.stored_credential(@state_file) }
    end
    File.chmod(0o644, @state_file)

    assert_raises(GraphqlEncrypted::Client::StateError) { GraphqlEncrypted::Client.stored_credential(@state_file) }
  end

  def test_untrusted_origins_are_rejected_before_a_request_is_sent
    ['http://example.test', 'https://example.test/path'].each do |origin|
      assert_raises(ArgumentError) do
        GraphqlEncrypted::Client.new(origin: origin, public_key: TestKeys::SERVER.public_key.to_pem, pin: TestKeys::PIN, state_file: @state_file)
      end
    end
  end

  def test_reply_headers_and_request_ids_are_bound_to_the_exchange
    [{ 'requestId' => 'another' }, { 'header' => true }].each do |change|
      client = build_client do |data|
        answer = { requestId: change.fetch('requestId', data['requestId']), body: {} }
        jwe = JSON::JWE.new(JSON.generate(answer))
        jwe.alg = 'dir'
        jwe.enc = 'A256GCM'
        jwe.header['kid'] = 'unexpected' if change['header']
        jwe.encrypt!(Base64.urlsafe_decode64(data['responseKey']))
        jwe.to_s
      end
      assert_raises(IOError) { client.call('/graphql', {}) }
    end
  end

  def test_the_default_transport_posts_a_jose_body_over_tls
    http = mock('http')
    http.expects(:request).with do |request|
      assert_equal 'application/jose', request['Content-Type']
      data = GraphqlEncrypted::Envelope.open(request.body, method: 'POST', path: '/graphql', fields: GraphqlEncrypted::Envelope::FIELDS)
      assert_equal({ 'query' => '{ x }' }, data['body'])
    end.returns(Struct.new(:code, :body).new('503', ''))
    Net::HTTP.expects(:start).with(URI(ORIGIN).host, URI(ORIGIN).port, use_ssl: true).yields(http).returns(Struct.new(:code, :body).new('503', ''))
    client = GraphqlEncrypted::Client.new(origin: ORIGIN, public_key: TestKeys::SERVER.public_key.to_pem, pin: TestKeys::PIN, state_file: @state_file)

    assert_raises(GraphqlEncrypted::Client::Retryable) { client.call('/graphql', { query: '{ x }' }) }
  end

  def test_the_default_transport_refuses_paths_with_query_parameters
    client = GraphqlEncrypted::Client.new(origin: ORIGIN, public_key: TestKeys::SERVER.public_key.to_pem, pin: TestKeys::PIN, state_file: @state_file)

    assert_raises(ArgumentError) { client.public_request('/graphql?token=secret', {}) }
  end
end
