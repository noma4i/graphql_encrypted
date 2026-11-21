require 'test_helper'
require_relative 'support/silent_server'

class CableClientTest < Minitest::Test
  include CableSupport

  Cable = GraphqlEncrypted::Cable

  class ScriptedSocket
    attr_reader :sent, :terminated

    def initialize(challenge)
      @challenge = challenge
      @sent = []
    end

    def send_text(text)
      @sent << text
    end

    def next_event(_timeout)
      @challenge.tap { @challenge = nil } || raise(IOError, 'The script ended')
    end

    def terminate
      @terminated = true
    end
  end

  def setup
    configure_cable
    @credential = encode(SecureRandom.random_bytes(32))
    @session = start_cable_session(credential: @credential)
    @server_key = Cable::StreamKeys.generate
    @challenge = SecureRandom.random_bytes(32)
  end

  def test_the_client_and_the_server_derive_the_same_keys_and_read_each_others_frames
    link = new_link
    result = Cable::Hello.call(link.hello, challenge: @challenge, session: CableSession)
    keys = server_keys(result)
    reader = Cable::Frame::Reader.new(keys.client_to_server, direction: :client_to_server)
    writer = Cable::Frame::Writer.new(keys.server_to_client)

    assert_equal @session, result.session
    assert_equal 'subscribe', reader.open(link.seal(:subscribe, id: 'one', query: 'subscription { a }'))[:t]

    assert_equal 5, link.open(writer.seal(:pong, ts: 5))['ts']
  end

  def test_the_client_refuses_a_challenge_for_another_key_and_a_tampered_ready
    other = encode(SecureRandom.random_bytes(32))

    assert_raises(Cable::Client::ProtocolError) { new_link(challenge_frame: challenge_frame.merge('kid' => 'f' * 64)) }
    assert_raises(Cable::Client::ProtocolError) { new_link(challenge_frame: challenge_frame.merge('v' => 2)) }

    link = new_link
    keys = server_keys(Cable::Hello.call(link.hello, challenge: @challenge, session: CableSession))
    ready = Cable::Frame::Writer.new(keys.server_to_client).seal(:ready, connectionId: SecureRandom.uuid, challengeDigest: Digest::SHA256.hexdigest(other))

    assert_raises(Cable::Client::ProtocolError) { link.open(ready) }
  end

  def test_the_reconnect_policy_stops_on_final_codes_and_backs_off_otherwise
    policy = Cable::Client::ReconnectPolicy

    assert_nil policy.delay(1000, 0)
    assert_nil policy.delay(4403, 0)
    assert_equal 0, policy.delay(4400, 0, random: 0.0)
    assert_equal 5, policy.delay(4429, 0, random: 0.0)

    assert_equal 4, policy.delay(1006, 2, random: 0.0)

    assert_equal 2.5, policy.delay(1001, 0, random: 0.5)
  end

  def test_a_client_takes_the_channel_and_the_protocol_constants_of_the_configuration
    configure(cable_channel: 'ConfiguredChannel', cable_path: '/configured/cable', cable_hello_purpose: 'configured.hello', cable_protocol_label: 'configured-label')
    socket = ScriptedSocket.new(JSON.generate(challenge_frame))
    urls = []
    client = Cable::Client.new(origin: 'https://api.example.test', public_key: TestKeys::SERVER.public_key.to_pem, pin: TestKeys::PIN, credential: @credential,
                               socket_factory: ->(url) { socket.tap { urls << url } })

    assert_raises(IOError) { client.connect }

    assert_equal ['wss://api.example.test:443/configured/cable'], urls

    assert_equal({ 'channel' => 'ConfiguredChannel' }, JSON.parse(JSON.parse(socket.sent.first)['identifier']))
  end

  def test_a_socket_whose_upgrade_is_never_answered_closes_its_io_and_ends_its_reader
    silent = silent_server
    before = Thread.list
    socket_class = recording_socket_class

    assert_raises(IOError) { socket_class.new(url: "ws://127.0.0.1:#{silent.addr[1]}/cable", tls: false, timeout: 0.2) }

    assert socket_class.ios.all?(&:closed?), 'the io of a failed socket stayed open'
    assert_empty Thread.list - before
  ensure
    silent&.close
  end

  def test_a_malformed_challenge_closes_the_socket_and_reports_a_protocol_error
    ['not-json', JSON.generate(challenge_frame.except('x25519'))].each do |message|
      socket = ScriptedSocket.new(message)
      client = Cable::Client.new(origin: TestKeys::AUDIENCE, public_key: TestKeys::SERVER.public_key.to_pem, pin: TestKeys::PIN,
                                 credential: @credential, channel: 'ExampleChannel', socket_factory: ->(_url) { socket })

      assert_raises(Cable::Client::ProtocolError) { client.connect }
      assert socket.terminated, 'the failed connection kept its socket'
    end
  end

  def test_a_server_that_accepts_tcp_and_stays_silent_in_tls_is_refused_within_the_deadline
    silent = silent_server
    attempt = Thread.new do
      Cable::Client::Socket.new(url: "wss://127.0.0.1:#{silent.addr[1]}/cable", timeout: 0.3)
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError => e
      e
    end

    assert attempt.join(5), 'the TLS handshake ignored the deadline'
    assert_kind_of IOError, attempt.value
  ensure
    attempt&.kill
    silent&.close
  end

  def test_link_rejects_degenerate_key_agreement_and_invalid_frame_counters
    ephemeral = mock('ephemeral key')
    ephemeral.expects(:derive).returns("\x00" * 32)
    assert_raises(Cable::Client::ProtocolError) do
      Cable::Client::Link.new(challenge_frame: challenge_frame, public_key: TestKeys::SERVER.public_key, pin: TestKeys::PIN,
                              audience: TestKeys::AUDIENCE, credential: @credential, ephemeral: ephemeral)
    end
    link = new_link
    keys = server_keys(Cable::Hello.call(link.hello, challenge: @challenge, session: CableSession))
    token = Cable::Frame::Writer.new(keys.server_to_client).seal(:pong, ts: 1)
    link.open(token)
    assert_raises(Cable::Client::ProtocolError) { link.open(token) }

    assert_raises(Cable::Client::ProtocolError) { link.open('bad') }
  end

  private

  def silent_server
    SilentServer.new
  end

  def recording_socket_class
    Class.new(Cable::Client::Socket) do
      def self.ios
        @ios ||= []
      end

      define_method(:connect) { |uri, tls| super(uri, tls).tap { |io| self.class.ios << io } }
    end
  end

  def challenge_frame
    { 'type' => 'challenge', 'v' => 1, 'challenge' => encode(@challenge), 'kid' => TestKeys::PIN, 'x25519' => encode(@server_key.raw_public_key) }
  end

  def new_link(challenge_frame: self.challenge_frame)
    Cable::Client::Link.new(challenge_frame: challenge_frame, public_key: TestKeys::SERVER.public_key, pin: TestKeys::PIN, audience: TestKeys::AUDIENCE,
                            credential: @credential, path: GraphqlEncrypted.option(:cable_path))
  end

  def server_keys(result)
    Cable::StreamKeys.derive(
      challenge: @challenge, shared_secret: Cable::StreamKeys.agree(@server_key, result.client_key), response_key: result.response_key,
      kid: TestKeys::PIN, audience: TestKeys::AUDIENCE, path: GraphqlEncrypted.option(:cable_path)
    )
  end
end
