require 'test_helper'

class CableHelloTest < Minitest::Test
  include CableSupport

  Hello = GraphqlEncrypted::Cable::Hello
  Rejected = GraphqlEncrypted::Cable::Rejected

  def setup
    configure_cable
    @credential = encode(SecureRandom.random_bytes(32))
    @session = start_cable_session(credential: @credential)
  end

  def test_opens_the_hello_and_returns_the_session_with_the_two_keys_the_client_sent
    plain = hello_plain(credential: @credential)

    result = Hello.call(hello_token(plain), challenge: CHALLENGE, session: CableSession)

    assert_equal @session, result.session
    assert_equal Base64.urlsafe_decode64(plain['responseKey']), result.response_key

    assert_equal Base64.urlsafe_decode64(plain['clientKey']), result.client_key
  end

  def test_every_refusal_closes_as_unauthenticated_and_names_its_own_reason
    refusals = {
      challenge: [{ challenge: encode(SecureRandom.random_bytes(32)) }],
      audience: [{ audience: 'https://other.example.com' }],
      kid: [{ kid: 'f' * 64 }],
      method: [{ method: 'POST' }],
      path: [{ path: '/graphql' }],
      purpose: [{ purpose: 'other.purpose' }],
      version: [{ v: 2 }],
      fields: [{ extra: 1 }, { challenge: nil }, { clientKey: nil }],
      credential: [{ credential: 'short' }, { credential: 5 }],
      response_key: [{ responseKey: encode(SecureRandom.random_bytes(31)) }, { responseKey: ('A' * 42) + 'B' }],
      client_key: [{ clientKey: 'not a key' }],
      session_unknown: [{ credential: encode(SecureRandom.random_bytes(32)) }]
    }

    refusals.each do |reason, variants|
      variants.each do |overrides|
        error = assert_raises(Rejected) { Hello.call(hello_token(hello_plain(credential: @credential, **overrides)), challenge: CHALLENGE, session: CableSession) }

        assert_equal [GraphqlEncrypted::Cable::Codes::Close::UNAUTHENTICATED, reason], [error.code, error.reason], overrides.inspect
      end
    end
  end

  def test_a_protected_header_that_is_not_a_json_object_is_refused
    ['null', '[]', '1', 'true', '"t"'].each do |header|
      token = [Base64.urlsafe_encode64(header, padding: false), 'AA', 'AA', 'AA', 'AA'].join('.')

      assert_equal :jwe, assert_raises(Rejected) { Hello.call(token, challenge: CHALLENGE, session: CableSession) }.reason, header
    end
  end

  def test_a_header_beyond_alg_and_enc_a_foreign_key_and_garbage_are_refused
    foreign = JSON::JWE.new(JSON.generate(hello_plain(credential: @credential))).tap do |jwe|
      jwe.alg = 'RSA-OAEP'
      jwe.enc = 'A256GCM'
      jwe.encrypt!(OpenSSL::PKey::RSA.generate(3072).public_key)
    end

    [hello_token(hello_plain(credential: @credential), header: { zip: 'DEF' }), foreign.to_s, 'a.b.c.d.e', '', nil].each do |token|
      assert_equal :jwe, assert_raises(Rejected) { Hello.call(token, challenge: CHALLENGE, session: CableSession) }.reason
    end
  end

  def test_a_session_that_is_not_authenticated_ended_or_refused_by_the_model_is_refused
    cases = { session_not_authenticated: { authenticated: false }, session_ended: { ended: true }, user_unavailable: { locked: true } }

    cases.each do |reason, options|
      credential = encode(SecureRandom.random_bytes(32))
      start_cable_session(credential: credential, **options)
      error = assert_raises(Rejected) { Hello.call(hello_token(hello_plain(credential: credential)), challenge: CHALLENGE, session: CableSession) }

      assert_equal reason, error.reason
    end
  end

  def test_the_destination_follows_the_configuration
    configure(cable_path: '/socket', cable_hello_purpose: 'custom.hello')

    result = Hello.call(hello_token(hello_plain(credential: @credential, path: '/socket', purpose: 'custom.hello')), challenge: CHALLENGE, session: CableSession)

    assert_equal @session, result.session
  end
end
