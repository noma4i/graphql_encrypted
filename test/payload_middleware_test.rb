require 'test_helper'
require 'rack/mock'

class PayloadMiddlewareTest < Minitest::Test
  SECRET = '3f61b4c83d5b6de893ed75de12f2a57a2405f902575273a0f6c7394772f3bc8c'.freeze
  RESPONSE = '{"data":{"me":{"id":"u-1"}}}'.freeze
  REQUEST = '{"operationName":"MyProfile","variables":{}}'.freeze

  def setup
    @downstream_env = {}
    downstream = lambda do |env|
      @downstream_env.replace(env)
      [200, { 'content-type' => 'application/json' }, [RESPONSE]]
    end
    @middleware = GraphqlEncrypted::PayloadMiddleware.new(downstream)
    @reported = []

    configure(payload_secret: -> { SECRET }, payload_paths: ['/', '/graphql'], error_reporter: ->(error) { @reported << error })
  end

  def test_decrypts_the_request_and_encrypts_the_response
    status, headers, body = @middleware.call(env('/', encrypt(REQUEST), 'HTTP_X_PAYLOAD_ENCRYPTION' => '1'))

    assert_equal REQUEST, @downstream_env['rack.input'].read
    assert_equal 'application/json', @downstream_env['CONTENT_TYPE']
    assert_equal 200, status
    assert_equal '1', headers['x-payload-encryption']

    assert_equal RESPONSE, decrypt(body.first)
  end

  def test_passes_a_request_without_the_header_untouched
    status, headers, body = @middleware.call(env('/', REQUEST))

    assert_equal REQUEST, @downstream_env['rack.input'].read
    assert_equal 200, status
    assert_nil headers['x-payload-encryption']

    assert_equal [RESPONSE], body
  end

  def test_refuses_a_body_that_cannot_be_decrypted_in_plaintext
    status, headers, body = @middleware.call(env('/', 'not-json', 'HTTP_X_PAYLOAD_ENCRYPTION' => '1'))

    assert_equal 403, status
    assert_equal '0', headers['x-payload-encryption']
    assert_empty @downstream_env
    assert_equal 'PAYLOAD_DECRYPTION_FAILED', JSON.parse(body.first)['errors'].first['extensions']['code']

    assert_empty @reported
  end

  def test_reports_a_refusal_to_sentry_with_the_context_of_the_application
    init_sentry
    configure(sentry: true, payload_failure_context: ->(request) { { app_version: request.get_header('HTTP_X_APP_VERSION'), apq_mode: 'unknown' } })
    Sentry.expects(:capture_message).with(
      'GraphQL transport security rejected', level: :warning,
      tags: { error_code: 'PAYLOAD_DECRYPTION_FAILED', transport_layer: 'payload_encryption' },
      extra: { request_id: 'req-1', app_version: '3.7.0', apq_mode: 'unknown' }
    )

    @middleware.call(env('/', 'not-json', 'HTTP_X_PAYLOAD_ENCRYPTION' => '1', 'HTTP_X_REQUEST_ID' => 'req-1', 'HTTP_X_APP_VERSION' => '3.7.0'))
  end

  def test_reports_nothing_when_sentry_is_off
    init_sentry
    configure(sentry: false)
    Sentry.expects(:capture_message).never

    status, = @middleware.call(env('/', 'not-json', 'HTTP_X_PAYLOAD_ENCRYPTION' => '1'))

    assert_equal 403, status
  end

  def test_refuses_a_forged_auth_tag
    envelope = JSON.parse(encrypt(REQUEST))
    envelope['tag'] = envelope['tag'].sub(/\A../, envelope['tag'].start_with?('00') ? '01' : '00')

    status, _headers, body = @middleware.call(env('/', envelope.to_json, 'HTTP_X_PAYLOAD_ENCRYPTION' => '1'))

    assert_equal 403, status

    assert_equal 'PAYLOAD_DECRYPTION_FAILED', JSON.parse(body.first)['errors'].first['extensions']['code']
  end

  def test_refuses_an_unknown_envelope_version
    status, _headers, _body = @middleware.call(env('/', JSON.parse(encrypt(REQUEST)).merge('v' => 2).to_json, 'HTTP_X_PAYLOAD_ENCRYPTION' => '1'))

    assert_equal 403, status
  end

  def test_leaves_other_paths_and_get_requests_alone
    @middleware.call(env('/other', 'raw', 'HTTP_X_PAYLOAD_ENCRYPTION' => '1'))
    assert_equal 'raw', @downstream_env['rack.input'].read

    @middleware.call(env('/', 'raw', 'HTTP_X_PAYLOAD_ENCRYPTION' => '1', method: 'GET'))

    assert_equal 'raw', @downstream_env['rack.input'].read
  end

  def test_serves_only_the_configured_paths
    configure(payload_paths: ['/graphql'])

    @middleware.call(env('/', 'raw', 'HTTP_X_PAYLOAD_ENCRYPTION' => '1'))

    assert_equal 'raw', @downstream_env['rack.input'].read
  end

  def test_requires_a_secret
    [nil, ''].each do |secret|
      configure(payload_secret: secret)

      assert_raises(KeyError) { @middleware.call(env('/', encrypt(REQUEST), 'HTTP_X_PAYLOAD_ENCRYPTION' => '1')) }
    end
  end

  def test_closes_a_streamed_response_body
    body = Rack::BodyProxy.new([RESPONSE]) { @closed = true }
    middleware = GraphqlEncrypted::PayloadMiddleware.new(->(_env) { [200, {}, body] })

    _status, _headers, encrypted = middleware.call(env('/', encrypt(REQUEST), 'HTTP_X_PAYLOAD_ENCRYPTION' => '1'))

    assert @closed

    assert_equal RESPONSE, decrypt(encrypted.first)
  end

  private

  def init_sentry
    Sentry.init do |config|
      config.dsn = 'http://key@localhost/1'
      config.transport.transport_class = Sentry::DummyTransport
      config.background_worker_threads = 0
    end
  end

  def key
    OpenSSL::KDF.hkdf(SECRET, salt: '', info: 'payload-enc-v1', length: 32, hash: 'SHA256')
  end

  def encrypt(plaintext)
    iv = SecureRandom.random_bytes(12)
    cipher = OpenSSL::Cipher.new('aes-256-gcm').encrypt
    cipher.key = key
    cipher.iv = iv
    ciphertext = cipher.update(plaintext) + cipher.final

    { v: 1, iv: iv.unpack1('H*'), ct: ciphertext.unpack1('H*'), tag: cipher.auth_tag.unpack1('H*') }.to_json
  end

  def decrypt(json)
    envelope = JSON.parse(json)
    cipher = OpenSSL::Cipher.new('aes-256-gcm').decrypt
    cipher.key = key
    cipher.iv = [envelope['iv']].pack('H*')
    cipher.auth_tag = [envelope['tag']].pack('H*')

    cipher.update([envelope['ct']].pack('H*')) + cipher.final
  end

  def env(path, body, headers = {})
    method = headers.delete(:method) || 'POST'

    Rack::MockRequest.env_for(path, { method: method, input: body, 'CONTENT_TYPE' => 'application/json' }.merge(headers))
  end
end
