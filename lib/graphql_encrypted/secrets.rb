# Encryption and keyed digests for values an application stores or compares (one-time codes, tokens).
# Keys come from +configuration.key_generator+ (an object with generate_key(salt, size)), one key per purpose and use.
#
# @see GraphqlEncrypted::Limiter
module GraphqlEncrypted::Secrets
  KEY_BYTES = 32

  module_function

  # @param purpose [String] names the key; the same purpose must be used to decrypt
  def encrypt(value, purpose:)
    encryptor(purpose).encrypt_and_sign(value)
  end

  def decrypt(value, purpose:)
    encryptor(purpose).decrypt_and_verify(value)
  end

  # Hex HMAC-SHA256 of the parts joined by a NUL byte, under a key of its own for the purpose.
  def digest(purpose, *parts)
    OpenSSL::HMAC.hexdigest('SHA256', key("#{purpose}.verifier"), parts.join("\0"))
  end

  def encryptor(purpose)
    ActiveSupport::MessageEncryptor.new(key("#{purpose}.storage"), cipher: 'aes-256-gcm')
  end

  def key(salt)
    GraphqlEncrypted.setting(:key_generator).generate_key(salt, KEY_BYTES)
  end
end
