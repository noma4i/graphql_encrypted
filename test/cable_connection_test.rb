require 'test_helper'

class CableConnectionTest < Minitest::Test
  include CableSupport
  include CableRig

  Cable = GraphqlEncrypted::Cable
  Close = Cable::Codes::Close

  def setup
    install_rig
  end

  def teardown
    remove_rig

    super
  end

  def test_malformed_commands_cannot_reach_the_channel
    ['{', '[]', '{}', JSON.generate(command: 'message', identifier: 'bad'), JSON.generate(command: 'subscribe', identifier: '{}'),
     JSON.generate(command: 'message', identifier: CableRig::IDENTIFIER)].each do |command|
      peer = open_peer
      peer.connection.receive(command)
      assert_equal [Close::BAD_FRAME, ''], peer.socket.closed
    end
  end

  def test_unsubscribe_closes_the_transport_and_later_commands_are_ignored
    peer = ready_peer
    peer.connection.receive(JSON.generate(command: 'unsubscribe', identifier: CableRig::IDENTIFIER))
    peer.connection.receive('{}')

    assert_equal [Close::NORMAL, ''], peer.socket.closed
  end

  def test_a_frame_burst_closes_the_transport_before_dispatch
    configure(cable_limits: { frame_burst: 1 })
    peer = open_peer
    peer.connection.receive(JSON.generate(command: 'subscribe', identifier: CableRig::IDENTIFIER))
    peer.connection.receive(JSON.generate(command: 'subscribe', identifier: CableRig::IDENTIFIER))

    assert_equal [Close::RATE_LIMITED, ''], peer.socket.closed
  end

  def test_the_hello_deadline_only_closes_an_unauthenticated_overdue_peer
    peer = open_peer
    peer.connection.expire_hello
    assert_nil peer.socket.closed
    travel(Cable::Limits.hello_deadline + 1)
    peer.connection.expire_hello
    assert_equal [Close::TIMEOUT, ''], peer.socket.closed
    ready = ready_peer
    travel(Cable::Limits.hello_deadline + 1)
    ready.connection.expire_hello

    assert_nil ready.socket.closed
  end

  def test_closing_the_connections_of_every_server_closes_open_peers_so_they_reconnect
    peer = ready_peer

    Cable::Server.close_connections

    assert_equal 'SERVER_RESTART', peer.new_frames.last['reason']

    assert_equal [Close::GOING_AWAY, ''], peer.socket.closed
  end

  def test_restart_closes_authenticated_peers_gracefully_and_pending_peers_directly
    pending = open_peer
    pending.connection.close
    assert_equal [Close::GOING_AWAY, ''], pending.socket.closed
    peer = ready_peer
    peer.connection.close
    assert_equal 'SERVER_RESTART', peer.new_frames.last['reason']

    assert_equal [Close::GOING_AWAY, ''], peer.socket.closed
  end

  def test_admission_and_key_failures_do_not_send_a_challenge
    Cable::Limits.stubs(:admit_open).raises(Cable::Rejected.new(Close::RATE_LIMITED))
    peer = open_peer
    assert_equal [Close::RATE_LIMITED, ''], peer.socket.closed
    assert_nil peer.challenge
    Cable::Limits.unstub(:admit_open)
    configure(private_key: nil)
    peer = open_peer
    assert_equal [Close::UNAVAILABLE, ''], peer.socket.closed

    assert_nil peer.challenge
  end

  def test_an_unhandled_dispatch_error_closes_the_connection
    peer = open_peer
    errors = []
    error = RuntimeError.new('application failed')
    configure(error_reporter: ->(reported) { errors << reported })
    peer.connection.stubs(:handle_channel_command).raises(error)
    peer.connection.receive(JSON.generate(command: 'subscribe', identifier: CableRig::IDENTIFIER))

    assert_equal [Close::INTERNAL, ''], peer.socket.closed

    assert_equal [error], errors
  end

  def test_an_expected_dispatch_refusal_keeps_its_code_without_reporting_an_application_error
    peer = open_peer
    errors = []
    configure(error_reporter: ->(reported) { errors << reported })
    peer.connection.stubs(:handle_channel_command).raises(Cable::Rejected.new(Close::UNAVAILABLE))
    peer.connection.receive(JSON.generate(command: 'subscribe', identifier: CableRig::IDENTIFIER))
    assert_equal [Close::UNAVAILABLE, ''], peer.socket.closed

    assert_empty errors
  end

  def test_a_redis_failure_during_disconnect_does_not_keep_the_socket_open
    peer = ready_peer
    Cable::Limits.stubs(:release_pending).raises(Cable::Rejected.new(Close::UNAVAILABLE))
    peer.connection.on_close('', 1000)

    assert pubsub.live.values.all?(&:empty?)
  end

  def test_server_close_is_logged_with_its_original_code
    peer = ready_peer
    peer.connection.close_with(Close::GOING_AWAY)
    peer.connection.on_close('restart', 1000)

    assert_equal [Close::GOING_AWAY, ''], peer.socket.closed
  end

  def test_multiple_close_requests_keep_the_first_reason
    peer = ready_peer
    peer.connection.close_with(Close::GOING_AWAY)
    peer.connection.close_with(Close::INTERNAL)

    assert_equal [Close::GOING_AWAY, ''], peer.socket.closed
  end

  def test_an_unauthenticated_channel_refuses_frames_and_late_subscriptions
    peer = open_peer
    peer.connection.receive(JSON.generate(command: 'subscribe', identifier: CableRig::IDENTIFIER))
    peer.connection.receive(JSON.generate(command: 'message', identifier: CableRig::IDENTIFIER, data: JSON.generate(action: 'frame', frame: 'bad')))
    assert_equal [Close::BAD_FRAME, ''], peer.socket.closed
    peer = ready_peer
    channel = CableRigChannel.new(peer.connection, JSON.generate(channel: 'late'))
    channel.unsubscribed
    channel.subscribe_to_channel

    assert_equal 'reject_subscription', peer.socket.sent.last['type']
  end

  def test_disconnect_without_a_pending_lease_does_not_remove_other_connections
    peer = ready_peer
    Cable::Limits.release_pending('203.0.113.7', nil)
    assert_nil peer.socket.closed
    peer.send_frame(:ping, ts: 1)

    assert_equal 'pong', peer.new_frames.last['t']
  end

  def test_the_hello_challenge_can_only_be_taken_once
    peer = open_peer
    refute_empty peer.connection.take_challenge
    error = assert_raises(Cable::Rejected) { peer.connection.take_challenge }

    assert_equal Close::UNAUTHENTICATED, error.code
  end

  def test_a_command_enqueued_while_the_drain_releases_ownership_is_not_lost
    peer = ready_peer
    draining = peer.connection.instance_variable_get(:@draining)
    release = draining.method(:make_false)
    inject = true
    draining.define_singleton_method(:make_false) do
      if inject
        inject = false
        peer.send_frame(:ping, ts: 2)
      end
      release.call
    end
    peer.send_frame(:ping, ts: 1)

    assert_equal([1, 2], peer.new_frames.map { |frame| frame['ts'] })
  end
end
