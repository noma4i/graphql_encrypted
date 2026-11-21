require 'active_support/testing/time_helpers'

class Minitest::Test
  include ActiveSupport::Testing::TimeHelpers

  PATH = '/graphql'.freeze

  # Sets configuration values for one test; teardown restores the previous ones.
  def configure(**settings)
    @saved_settings ||= {}

    settings.each do |name, value|
      @saved_settings[name] = GraphqlEncrypted.configuration.public_send(name) unless @saved_settings.key?(name)
      GraphqlEncrypted.configuration.public_send("#{name}=", value)
    end
  end

  def teardown
    @saved_settings&.each { |name, value| GraphqlEncrypted.configuration.public_send("#{name}=", value) }

    super
  end

  def request_data(overrides = {})
    {
      'audience' => TestKeys::AUDIENCE, 'kid' => TestKeys::PIN, 'method' => 'POST', 'path' => PATH,
      'requestId' => SecureRandom.uuid, 'issuedAt' => Time.now.to_i, 'responseKey' => SecureRandom.urlsafe_base64(32),
      'credential' => SecureRandom.urlsafe_base64(32), 'sequence' => 1, 'body' => { 'query' => '{ __typename }' }
    }.merge(overrides)
  end

  def encrypt(data)
    jwe = JSON::JWE.new(JSON.generate(data))
    jwe.alg = 'RSA-OAEP'
    jwe.enc = 'A256GCM'
    jwe.encrypt!(TestKeys::SERVER.public_key)

    jwe.to_s
  end

  def open_answer(token, data)
    JSON.parse(JSON::JWE.decode(token, Base64.urlsafe_decode64(data.fetch('responseKey')), ['dir'], ['A256GCM']).plain_text)
  end

  def open_request(data, fields: GraphqlEncrypted::Envelope::FIELDS, method: 'POST', path: PATH)
    GraphqlEncrypted::Envelope.open(encrypt(data), method: method, path: path, fields: fields)
  end

  def start_session(sequence: 0)
    Session.create!(credential_digest: SecureRandom.hex(16), sequence: sequence, authenticated_at: Time.current)
  end
end
