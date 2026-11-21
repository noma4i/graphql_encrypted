# Per-connection keys: X25519 agreement, then HKDF-SHA256 over the shared secret and the client response key.
# The salt is the server challenge; the info binds the protocol label, direction, key id, audience and path.
#
# @see GraphqlEncrypted::Cable::Hello
# @see GraphqlEncrypted::Cable::Frame
module GraphqlEncrypted::Cable::StreamKeys
  Keys = Data.define(:client_to_server, :server_to_client)

  KEY_BYTES = 32

  module_function

  def generate
    OpenSSL::PKey.generate_key('X25519')
  end

  def agree(private_key, peer_public)
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::UNAUTHENTICATED unless peer_public.is_a?(String) && peer_public.bytesize == KEY_BYTES

    secret = private_key.derive(OpenSSL::PKey.new_raw_public_key('X25519', peer_public))
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::UNAUTHENTICATED if secret.bytes.all?(&:zero?)

    secret
  rescue OpenSSL::PKey::PKeyError
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::UNAUTHENTICATED
  end

  def derive(challenge:, shared_secret:, response_key:, kid:, audience:, path:)
    ikm = shared_secret + response_key
    label = GraphqlEncrypted.setting(:cable_protocol_label)
    key = lambda do |direction|
      OpenSSL::KDF.hkdf(ikm, salt: challenge, info: [label, direction, kid, audience, path].join("\x00"), length: KEY_BYTES, hash: 'SHA256')
    end

    Keys.new(client_to_server: key.call('c2s'), server_to_client: key.call('s2c'))
  end
end
