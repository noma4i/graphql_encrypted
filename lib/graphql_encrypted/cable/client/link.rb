# Shares no code with the server on purpose: the two sides are checked against each other and against known-answer vectors.
class GraphqlEncrypted::Cable::Client::Link
  attr_reader :hello, :challenge, :connection_id

  def initialize(challenge_frame:, public_key:, pin:, audience:, credential:, path: GraphqlEncrypted::Cable::Client::DEFAULT_PATH, label: GraphqlEncrypted::Cable::Client::DEFAULT_LABEL,
                   purpose: GraphqlEncrypted::Cable::Client::DEFAULT_PURPOSE,
                 ephemeral: OpenSSL::PKey.generate_key('X25519'), response_key: SecureRandom.random_bytes(32))
    raise GraphqlEncrypted::Cable::Client::ProtocolError, 'Challenge version mismatch' unless challenge_frame['type'] == 'challenge' && challenge_frame['v'] == GraphqlEncrypted::Cable::Client::VERSION
    raise GraphqlEncrypted::Cable::Client::ProtocolError, 'Untrusted server key' unless challenge_frame['kid'] == pin && Digest::SHA256.hexdigest(public_key.public_key.to_der) == pin

    @challenge = decode(challenge_frame.fetch('challenge'))
    shared = ephemeral.derive(OpenSSL::PKey.new_raw_public_key('X25519', decode(challenge_frame.fetch('x25519'))))
    raise GraphqlEncrypted::Cable::Client::ProtocolError, 'Degenerate key agreement' if shared.bytes.all?(&:zero?)

    keys = %w[c2s s2c].map do |direction|
      OpenSSL::KDF.hkdf(shared + response_key, salt: @challenge, info: [label, direction, pin, audience, path].join("\x00"), length: 32, hash: 'SHA256')
    end
    @send_key, @receive_key = keys
    @sent = 0
    @received = 0
    @hello = encrypt_hello(public_key, JSON.generate(
                                         v: GraphqlEncrypted::Cable::Client::VERSION, purpose: purpose, audience: audience, kid: pin, method: 'GET', path: path, challenge: challenge_frame.fetch('challenge'),
                                         clientKey: encode(ephemeral.raw_public_key), credential: credential, responseKey: encode(response_key)
                                       ))
  rescue KeyError, ArgumentError, TypeError, OpenSSL::OpenSSLError => e
    raise GraphqlEncrypted::Cable::Client::ProtocolError, e.class.name
  end

  def seal(type, **fields)
    body = { n: @sent, t: type.to_s }.merge(fields)
    @sent += 1

    jwe = JSON::JWE.new(JSON.generate(body))
    jwe.alg = 'dir'
    jwe.enc = 'A256GCM'
    jwe.encrypt!(@send_key)

    jwe.to_s
  end

  def open(token)
    body = JSON.parse(JSON::JWE.decode(token, @receive_key, ['dir'], ['A256GCM']).plain_text)
    raise GraphqlEncrypted::Cable::Client::ProtocolError, 'Frame counter mismatch' unless body['n'] == @received

    @received += 1
    @connection_id = body['connectionId'] if body['t'] == 'ready'
    raise GraphqlEncrypted::Cable::Client::ProtocolError, 'Ready does not match the challenge' if body['t'] == 'ready' && body['challengeDigest'] != Digest::SHA256.hexdigest(@challenge)

    body
  rescue JSON::JWT::Exception, JSON::ParserError, OpenSSL::OpenSSLError => e
    raise GraphqlEncrypted::Cable::Client::ProtocolError, e.class.name
  end

  private

  def encrypt_hello(public_key, plain_text)
    jwe = JSON::JWE.new(plain_text)
    jwe.alg = 'RSA-OAEP'
    jwe.enc = 'A256GCM'
    jwe.encrypt!(public_key)

    jwe.to_s
  end

  def encode(bytes)
    Base64.urlsafe_encode64(bytes, padding: false)
  end

  def decode(text)
    Base64.urlsafe_decode64(text)
  end
end
