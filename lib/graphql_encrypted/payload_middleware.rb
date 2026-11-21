# Rack middleware that decrypts a request marked +X-Payload-Encryption: 1+ and encrypts its response with AES-256-GCM. A request without
# the header, a request outside +config.payload_paths+ and any other verb than POST pass through untouched.
#
# Crypto contract v1, shared with the mobile client byte for byte:
#   key = HKDF-SHA256(ikm: config.payload_secret, salt: '', info: 'payload-enc-v1', length: 32)
#   envelope = { v: 1, iv: hex(12-byte nonce), ct: hex(ciphertext), tag: hex(16-byte GCM tag) }
#
# A body that cannot be opened is answered in plaintext with 403, PAYLOAD_DECRYPTION_FAILED and +X-Payload-Encryption: 0+: a client that
# does not share the key could not read an encrypted refusal. With +config.sentry+ the refusal is a Sentry warning, see GraphqlEncrypted::Diagnostics.payload_refused.
#
# @note +config.payload_secret+ is read on every request; a missing secret raises KeyError.
# @see GraphqlEncrypted::Configuration
class GraphqlEncrypted::PayloadMiddleware
  ENCRYPTION_HEADER = 'HTTP_X_PAYLOAD_ENCRYPTION'.freeze
  HKDF_INFO = 'payload-enc-v1'.freeze
  HKDF_KEY_LENGTH = 32
  ENVELOPE_VERSION = 1

  def initialize(app)
    @app = app
  end

  def call(env)
    request = Rack::Request.new(env)
    return @app.call(env) unless encrypted_request?(request)

    plaintext = decrypt_request_body(request)
    unless plaintext
      GraphqlEncrypted::Diagnostics.payload_refused(request)

      return decryption_error_response
    end

    env['rack.input'] = StringIO.new(plaintext)
    env['CONTENT_LENGTH'] = plaintext.bytesize.to_s
    env['CONTENT_TYPE'] = 'application/json'

    encrypt_response(*@app.call(env))
  end

  private

  def encrypted_request?(request)
    request.post? && GraphqlEncrypted.option(:payload_paths).include?(request.path) && request.get_header(ENCRYPTION_HEADER).present?
  end

  def decrypt_request_body(request)
    decrypt(JSON.parse(request.body.read))
  rescue JSON::ParserError, OpenSSL::Cipher::CipherError, TypeError, ArgumentError
    nil
  end

  def encrypt_response(status, headers, response_body)
    plaintext = +''
    response_body.each { |chunk| plaintext << chunk }
    response_body.close if response_body.respond_to?(:close)

    json = encrypt(plaintext).to_json

    [status, headers.merge('content-type' => 'application/json', 'content-length' => json.bytesize.to_s, 'x-payload-encryption' => '1'), [json]]
  end

  def decryption_error_response
    body = { errors: [{ message: 'Failed to decrypt request payload', extensions: { code: 'PAYLOAD_DECRYPTION_FAILED' } }] }.to_json

    [403, { 'content-type' => 'application/json', 'content-length' => body.bytesize.to_s, 'x-payload-encryption' => '0' }, [body]]
  end

  def encrypt(plaintext)
    iv = SecureRandom.random_bytes(12)
    cipher = OpenSSL::Cipher.new('aes-256-gcm').encrypt
    cipher.key = derived_key
    cipher.iv = iv
    ciphertext = cipher.update(plaintext) + cipher.final

    { v: ENVELOPE_VERSION, iv: iv.unpack1('H*'), ct: ciphertext.unpack1('H*'), tag: cipher.auth_tag.unpack1('H*') }
  end

  def decrypt(envelope)
    raise ArgumentError, 'unsupported payload envelope version' unless envelope['v'] == ENVELOPE_VERSION

    cipher = OpenSSL::Cipher.new('aes-256-gcm').decrypt
    cipher.key = derived_key
    cipher.iv = [envelope['iv']].pack('H*')
    cipher.auth_tag = [envelope['tag']].pack('H*')

    (cipher.update([envelope['ct']].pack('H*')) + cipher.final).force_encoding(Encoding::UTF_8)
  end

  def derived_key
    secret = GraphqlEncrypted.setting(:payload_secret)
    raise KeyError, 'GraphqlEncrypted.configuration.payload_secret is not set' if secret.blank?

    OpenSSL::KDF.hkdf(secret, salt: '', info: HKDF_INFO, length: HKDF_KEY_LENGTH, hash: 'SHA256')
  end
end
