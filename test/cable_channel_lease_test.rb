require 'test_helper'

class CableChannelLeaseTest < Minitest::Test
  include CableSupport
  include CableRig

  Close = GraphqlEncrypted::Cable::Codes::Close
  Limits = GraphqlEncrypted::Cable::Limits

  def setup
    install_rig
  end

  def teardown
    remove_rig

    super
  end

  def test_a_hello_whose_control_streams_do_not_register_is_refused_and_everything_it_took_is_released
    with_stream_wait(0) do
      work.stall_posts
      peer = open_peer
      peer.handshake

      assert_empty peer.new_frames
      refute peer.connection.authenticated?

      peer.connection.complete_refusal

      assert_equal [Close::UNAVAILABLE, ''], peer.socket.closed
      assert_equal 0, lease_size(peer.session)
    end
    refute_empty work.timers
    assert work.timers.all?(&:shut_down?)

    work.run_held_posts

    assert pubsub.live.values.all?(&:empty?), 'a control stream registered after the hello was refused'
  end

  def test_a_lease_key_that_vanished_is_admitted_again_by_the_next_tick
    peer = ready_peer
    Limits.redis.del(Limits.key('lease', 'session', peer.session.id))

    peer.connection.channel.tick

    assert_equal 1, lease_size(peer.session)
  end

  def test_a_hello_that_arrives_late_cannot_exceed_the_connection_limit
    credential = new_credential
    session = start_cable_session(credential: credential)
    oldest = open_peer(credential: credential, session: session)
    others = Array.new(Limits.connections_per_session) do
      travel(1.second)
      ready_peer(credential: credential, session: session)
    end

    oldest.handshake

    assert_empty oldest.new_frames
    oldest.connection.complete_refusal
    assert_equal [Close::SUPERSEDED, ''], oldest.socket.closed
    assert_equal Limits.connections_per_session, lease_size(session)

    assert(others.all? { |peer| peer.connection.authenticated? && peer.socket.closed.nil? })
  end

  def test_a_session_that_changed_who_or_when_it_authenticated_closes_the_socket_with_reconnect_when_no_revoke_arrived
    configure(cable_limits: { session_check_interval: 0, idle_deadline: 1.day })
    changes = {
      'another user' => ->(session) { session.update!(user: CableUser.create!) },
      'authentication cleared' => ->(session) { session.update!(authenticated_at: nil) },
      'authenticated again' => ->(session) { session.update!(authenticated_at: 1.hour.from_now) }
    }

    changes.each do |name, change|
      peer = ready_peer
      peer.connection.channel.tick

      assert_nil peer.socket.closed, "#{name}: closed without a change"

      change.call(peer.session)
      peer.connection.channel.tick

      assert_equal [Close::GOING_AWAY, ''], peer.socket.closed, name
      assert_equal 'RECONNECT', peer.new_frames.last['reason'], name
    end
  end

  def test_posts_held_past_a_subscription_refusal_never_register
    peer = ready_peer

    with_stream_wait(0) do
      work.stall_posts
      peer.send_frame(:subscribe, id: 'failed', query: 'subscription { tick { value } }')

      assert_equal [%w[error failed]], peer.summary
      work.run_held_posts

      assert_empty CableRigSchema.subscriptions.live
      assert_equal 3, pubsub.live.values.sum(&:size)
    end
  end

  def test_a_subscribe_waits_for_stream_registration_and_then_announces_it
    peer = ready_peer
    work.stall_posts
    thread = Thread.new { peer.send_frame(:subscribe, id: 'one', query: 'subscription { tick { value } }') }
    work.wait_for_posts(2)
    settle(thread)
    assert_empty peer.new_frames
    work.run_held_posts
    assert thread.join(5), 'subscription did not resume after registration'

    assert_equal [%w[subscribed one]], peer.summary
  end

  def test_the_session_model_can_be_resolved_by_name
    original = CableRigChannel.encrypted_session_model
    CableRigChannel.session('CableSession')
    peer = ready_peer
    peer.send_frame(:ping, ts: 7)
    assert_equal 7, peer.new_frames.last['ts']
  ensure
    CableRigChannel.session(original)
  end

  private

  def lease_size(session)
    Limits.redis.zcard(Limits.key('lease', 'session', session.id))
  end

  def with_stream_wait(seconds)
    channel = GraphqlEncrypted::Cable::Channel
    original = channel::STREAM_WAIT
    channel.send(:remove_const, :STREAM_WAIT)
    channel.const_set(:STREAM_WAIT, seconds)
    yield
  ensure
    channel.send(:remove_const, :STREAM_WAIT)
    channel.const_set(:STREAM_WAIT, original)
  end
end
