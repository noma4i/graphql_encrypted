require 'test_helper'
require_relative 'support/cable_client_socket'

class CableClientSessionTest < Minitest::Test
  include CableSupport
  include CableRig

  Cable = GraphqlEncrypted::Cable

  def setup
    install_rig
    credential = new_credential
    @peer = open_peer(credential: credential)
    @socket = CableClientSocket.new(@peer)
    @client = Cable::Client.new(origin: TestKeys::AUDIENCE, public_key: TestKeys::SERVER.public_key.to_pem, pin: TestKeys::PIN,
                                credential: credential, channel: 'CableRigChannel', socket_factory: ->(_url) { @socket })
    socket = @socket

    @client.define_singleton_method(:now) { socket.time }
  end

  def teardown
    @client.terminate
    remove_rig

    super
  end

  def test_the_client_subscribes_pings_unsubscribes_and_closes_through_the_server
    @client.connect
    @client.subscribe('one', 'subscription { tick { value } }')
    assert_equal 'subscribed', @client.next_event(1).fetch('t')
    @client.ping
    assert_equal 'pong', @client.next_event(1).fetch('t')
    @client.unsubscribe('one')
    assert_empty CableRigSchema.subscriptions.live
    @client.close

    assert_equal 1000, @client.next_event(1).code
  end

  def test_idle_connections_ping_and_report_a_missing_answer_without_waiting
    @client.connect
    @socket.time += Cable::Client::PING_AFTER
    assert_equal 'pong', @client.next_event(1).fetch('t')
    @socket.answer = false
    @socket.time += Cable::Client::PING_AFTER

    assert_equal 1006, @client.next_event(Cable::Client::PONG_WITHIN + 2).code
  end

  def test_timeout_and_unrelated_messages_do_not_create_events
    @client.connect
    @socket.events.push(JSON.generate(type: 'ping'), JSON.generate(message: {}))
    assert_nil @client.next_event(1)

    assert_nil @client.next_event(0)
  end

  def test_bad_messages_are_reported_as_protocol_errors
    @client.connect

    ['[]', 'null', JSON.generate(message: 'bad'), '{'].each do |message|
      @socket.events << message
      assert_raises(Cable::Client::ProtocolError) { @client.next_event(1) }
    end
  end

  def test_run_delivers_connected_and_pong_then_stops_on_a_normal_close
    events = []
    @client.run([]) do |event|
      events << event
      @client.ping if event['t'] == 'connected'
      @client.close if event['t'] == 'pong'
    end
    assert_equal(%w[connected pong stopped], events.map { |event| event['t'] })
    assert_equal 1000, events.last['code']

    assert @socket.terminated
  end

  def test_run_stops_when_requested_and_terminates_the_socket
    stopped = false
    delays = []
    @client.run([{ id: 'one', query: 'subscription { tick { value } }' }], stop: -> { stopped }, sleeper: ->(delay) { delays << delay }) do |event|
      stopped = true if event['t'] == 'subscribed'
    end
    assert @socket.terminated

    assert_equal 1, delays.size
  end

  def test_run_retries_transport_failures_and_reports_terminal_refusals
    @socket.events << Cable::Client::Socket::Closed.new(4403, '')
    events = []
    @client.run([]) { |event| events << event }

    assert_equal [{ 't' => 'stopped', 'code' => 4403 }], events
  end

  def test_failed_upgrade_and_subscription_refusal_close_the_socket
    [nil, Cable::Client::Socket::Closed.new(4403, ''), JSON.generate(type: 'reject_subscription')].each do |message|
      @socket.events << message
      error = message.nil? ? IOError : Cable::Client::Refused
      assert_raises(error) { @client.connect }
      assert @socket.terminated
    end
  end

  def test_untrusted_keys_and_insecure_origins_never_open_a_socket
    [{ pin: 'bad' }, { origin: 'http://example.test' }].each do |changes|
      options = { origin: TestKeys::AUDIENCE, pin: TestKeys::PIN, public_key: TestKeys::SERVER.public_key.to_pem, credential: 'secret', channel: 'CableRigChannel' }
      assert_raises(ArgumentError) { Cable::Client.new(**options, **changes) }
    end
    unopened = Cable::Client.new(origin: TestKeys::AUDIENCE, pin: TestKeys::PIN, public_key: TestKeys::SERVER.public_key.to_pem, credential: 'secret', channel: 'CableRigChannel')

    assert_nil unopened.terminate
  end

  def test_a_factory_can_supply_an_http_transport_and_reports_a_closed_ready
    client = Cable::Client.new(origin: 'http://example.test', pin: TestKeys::PIN, public_key: TestKeys::SERVER.public_key.to_pem, credential: 'secret',
                               channel: 'CableRigChannel',
                               socket_factory: ->(url) {
                                 assert_equal 'ws://example.test:80/cable', url
                                 @socket
                               })
    @socket.events.push(JSON.generate(@peer.challenge), JSON.generate(type: 'confirm_subscription'), Cable::Client::Socket::Closed.new(4403, ''))

    assert_equal 4403, assert_raises(Cable::Client::Refused) { client.connect }.code
  end

  def test_a_missing_ready_is_a_protocol_failure
    @socket.events.push(JSON.generate(@peer.challenge), JSON.generate(type: 'confirm_subscription'))
    @socket.answer = false
    assert_raises(Cable::Client::ProtocolError) { @client.connect }

    assert @socket.terminated
  end

  def test_a_stable_session_resets_backoff_and_io_failures_retry
    attempts = 0
    delays = []
    @client.stubs(:connect).raises(IOError).then.returns(@client)
    @client.stubs(:next_event).returns(nil, Cable::Client::Socket::Closed.new(1006, ''))
    @client.run([], stop: -> { attempts == 2 }, sleeper: ->(delay) {
      delays << delay
      attempts += 1
    }) do |_event|
      @socket.time += 61
    end
    assert_equal 2, delays.size

    assert(delays.all? { |delay| delay.between?(1, 1.5) })
  end
end
