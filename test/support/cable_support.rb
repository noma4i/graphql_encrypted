# Support for the encrypted socket tests.
module CableSupport
  CHALLENGE = SecureRandom.random_bytes(32)

  def configure_cable
    configure(cable_path: '/cable', cable_namespace: GraphqlEncrypted::Testing.unique_namespace('graphql_encrypted'))
  end

  def clean_cable_redis(namespace = GraphqlEncrypted.configuration.cable_namespace)
    GraphqlEncrypted::Testing.clean_redis(namespace)
  end

  def encode(bytes)
    Base64.urlsafe_encode64(bytes, padding: false)
  end

  def start_cable_session(credential:, locked: false, ended: false, authenticated: true)
    CableSession.create!(
      user: CableUser.create!(locked: locked), credential_digest: Digest::SHA256.hexdigest(credential),
      authenticated_at: (Time.current if authenticated), ended_at: (Time.current if ended)
    )
  end

  def hello_plain(credential:, **overrides)
    {
      'v' => 1, 'purpose' => GraphqlEncrypted.option(:cable_hello_purpose), 'audience' => TestKeys::AUDIENCE, 'kid' => TestKeys::PIN, 'method' => 'GET',
      'path' => GraphqlEncrypted.option(:cable_path), 'challenge' => encode(CHALLENGE), 'clientKey' => encode(SecureRandom.random_bytes(32)),
      'credential' => credential, 'responseKey' => encode(SecureRandom.random_bytes(32))
    }.merge(overrides.transform_keys(&:to_s)).compact
  end

  def hello_token(plain, header: {})
    GraphqlEncrypted::Testing.hello_token(plain, key: TestKeys::SERVER, header: header)
  end

  def seal_raw(key, body)
    jwe = JSON::JWE.new(JSON.generate(body))
    jwe.alg = 'dir'
    jwe.enc = 'A256GCM'
    jwe.encrypt!(key)

    jwe.to_s
  end
end
