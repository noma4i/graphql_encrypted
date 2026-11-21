require 'test_helper'

class EnvelopeTest < Minitest::Test
  def test_opens_a_request_addressed_to_this_server
    data = request_data

    assert_equal data, open_request(data)
  end

  def test_refuses_every_other_destination
    { 'audience' => 'https://other.example.test', 'kid' => 'f' * 64, 'path' => '/other' }.each do |field, value|
      assert_raises(ArgumentError, field) { open_request(request_data(field => value)) }
    end

    assert_raises(ArgumentError) { open_request(request_data, method: 'GET') }
  end

  def test_refuses_a_request_outside_the_time_window
    assert_raises(ArgumentError) { open_request(request_data('issuedAt' => Time.now.to_i - GraphqlEncrypted::Envelope::WINDOW - 5)) }

    assert_raises(ArgumentError) { open_request(request_data('issuedAt' => Time.now.to_i + GraphqlEncrypted::Envelope::CLOCK_SKEW + 5)) }
  end

  def test_refuses_missing_extra_and_malformed_fields
    assert_raises(ArgumentError) { open_request(request_data.except('credential')) }
    assert_raises(ArgumentError) { open_request(request_data('extra' => 1)) }
    assert_raises(ArgumentError) { open_request(request_data('sequence' => 0)) }
    assert_raises(ArgumentError) { open_request(request_data('requestId' => 'x')) }
    assert_raises(ArgumentError) { open_request(request_data('responseKey' => 'short')) }

    assert_raises(ArgumentError) { open_request(request_data('body' => 'text')) }
  end

  def test_public_fields_have_no_credential_or_sequence
    data = request_data.except('credential', 'sequence')

    assert_equal data, open_request(data, fields: GraphqlEncrypted::Envelope::PUBLIC_FIELDS)

    assert_raises(ArgumentError) { open_request(request_data, fields: GraphqlEncrypted::Envelope::PUBLIC_FIELDS) }
  end

  def test_seal_answers_under_the_response_key_with_the_request_id
    data = request_data
    answer = open_answer(GraphqlEncrypted::Envelope.seal(data, { ok: true }, sequence: 3), data)

    assert_equal [data['requestId'], 3, { 'ok' => true }], answer.values_at('requestId', 'sequence', 'body')

    assert_nil answer['requestDigest']
  end

  def test_bound_seal_carries_the_request_digest
    data = request_data.except('credential', 'sequence')
    answer = open_answer(GraphqlEncrypted::Envelope.seal(data, {}, bound: true), data)

    assert_equal GraphqlEncrypted::Envelope.digest(data), answer['requestDigest']
  end

  def test_digest_ignores_issued_at_and_key_order_but_not_the_body
    data = request_data

    assert_equal GraphqlEncrypted::Envelope.digest(data), GraphqlEncrypted::Envelope.digest(data.merge('issuedAt' => 1).to_a.reverse.to_h)

    refute_equal GraphqlEncrypted::Envelope.digest(data), GraphqlEncrypted::Envelope.digest(data.merge('body' => {}))
  end

  def test_a_weak_server_key_is_unusable
    weak = OpenSSL::PKey::RSA.new(2048).to_pem
    original = GraphqlEncrypted.configuration.private_key
    GraphqlEncrypted.configuration.private_key = weak

    assert_raises(KeyError) { GraphqlEncrypted.server_key }
  ensure
    GraphqlEncrypted.configuration.private_key = original
  end

  def test_additional_protected_headers_and_invalid_credentials_are_refused
    data = request_data
    jwe = JSON::JWE.new(JSON.generate(data))
    jwe.alg = 'RSA-OAEP'
    jwe.enc = 'A256GCM'
    jwe.kid = 'extra'
    jwe.encrypt!(TestKeys::SERVER.public_key)
    assert_raises(ArgumentError) { GraphqlEncrypted::Envelope.open(jwe.to_s, method: 'POST', path: PATH) }

    assert_raises(ArgumentError) { open_request(data.merge('credential' => 'bad')) }
  end

  def test_a_noncanonical_response_key_is_rejected_before_execution
    assert_raises(ArgumentError) { open_request(request_data('responseKey' => ('A' * 42) + 'B')) }
  end
end
