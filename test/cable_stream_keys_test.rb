require 'test_helper'

class CableStreamKeysTest < Minitest::Test
  include CableSupport

  StreamKeys = GraphqlEncrypted::Cable::StreamKeys

  # RFC 7748 section 6.1
  SERVER_PRIVATE = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'.freeze
  CLIENT_PUBLIC = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'.freeze
  SHARED_SECRET = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'.freeze

  def setup
    @inputs = {
      challenge: SecureRandom.random_bytes(32), shared_secret: [SHARED_SECRET].pack('H*'), response_key: SecureRandom.random_bytes(32),
      kid: 'a' * 64, audience: 'https://api.example.com', path: '/cable'
    }
  end

  def test_derives_the_keys_from_the_documented_hkdf_inputs
    keys = StreamKeys.derive(**@inputs)

    %i[client_to_server server_to_client].zip(%w[c2s s2c]).each do |name, direction|
      info = ['graphql-encrypted-ws-v1', direction, @inputs[:kid], @inputs[:audience], @inputs[:path]].join("\x00")
      expected = OpenSSL::KDF.hkdf(@inputs[:shared_secret] + @inputs[:response_key], salt: @inputs[:challenge], info: info, length: 32, hash: 'SHA256')

      assert_equal expected, keys.public_send(name)
    end
  end

  def test_the_protocol_label_comes_from_the_configuration
    base = StreamKeys.derive(**@inputs)
    configure(cable_protocol_label: 'other-label')

    refute_equal base.client_to_server, StreamKeys.derive(**@inputs).client_to_server
  end

  def test_each_input_changes_both_direction_keys_and_the_directions_never_share_a_key
    base = StreamKeys.derive(**@inputs)
    refute_equal base.client_to_server, base.server_to_client

    changed = {
      challenge: SecureRandom.random_bytes(32), shared_secret: SecureRandom.random_bytes(32), response_key: SecureRandom.random_bytes(32),
      kid: 'f' * 64, audience: 'https://other.example.com', path: '/other'
    }

    changed.each do |name, value|
      keys = StreamKeys.derive(**@inputs, name => value)

      refute_equal base.client_to_server, keys.client_to_server, name.to_s
      refute_equal base.server_to_client, keys.server_to_client, name.to_s
    end
  end

  def test_a_server_agrees_on_the_published_x25519_secret
    server = OpenSSL::PKey.new_raw_private_key('X25519', [SERVER_PRIVATE].pack('H*'))

    assert_equal [SHARED_SECRET].pack('H*'), StreamKeys.agree(server, [CLIENT_PUBLIC].pack('H*'))
  end

  def test_rejects_a_peer_key_that_is_not_32_bytes_or_that_yields_the_all_zero_secret
    server = StreamKeys.generate

    [''.b, SecureRandom.random_bytes(31), "\x00".b * 32].each do |peer|
      error = assert_raises(GraphqlEncrypted::Cable::Rejected) { StreamKeys.agree(server, peer) }

      assert_equal GraphqlEncrypted::Cable::Codes::Close::UNAUTHENTICATED, error.code
    end
  end

  def test_a_backend_that_returns_a_zero_secret_is_also_refused
    backend = mock('key agreement')
    backend.expects(:derive).returns("\x00" * 32)

    assert_raises(GraphqlEncrypted::Cable::Rejected) { StreamKeys.agree(backend, [CLIENT_PUBLIC].pack('H*')) }
  end
end
