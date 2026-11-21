require 'graphql_encrypted'

module TestKeys
  SERVER = OpenSSL::PKey::RSA.new(GraphqlEncrypted::MIN_KEY_BITS)
  AUDIENCE = 'https://api.example.test'.freeze
  PIN = Digest::SHA256.hexdigest(SERVER.public_key.to_der)
end
