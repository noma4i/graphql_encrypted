require 'test_helper'

class CableChannelRefusalTest < Minitest::Test
  include CableSupport
  include CableRig

  Cable = GraphqlEncrypted::Cable
  Close = Cable::Codes::Close
  TICK = 'subscription { tick { value } }'.freeze

  def setup
    install_rig
  end

  def teardown
    remove_rig

    super
  end

  def test_subscription_admission_refuses_duplicates_excess_and_bursts
    configure(cable_limits: { subscriptions: 1, subscribe_burst: 1, subscribes_per_minute: 0 })
    peer = ready_peer
    peer.send_frame(:subscribe, id: 'one', query: TICK)
    peer.send_frame(:subscribe, id: 'one', query: TICK)
    peer.send_frame(:subscribe, id: 'two', query: TICK)
    peer.send_frame(:unsubscribe, id: 'one')
    peer.send_frame(:subscribe, id: 'two', query: TICK)
    assert_equal(['DUPLICATE_ID', 'TOO_MANY_SUBSCRIPTIONS', 'RATE_LIMITED'], peer.new_frames.drop(1).map { |frame| frame['code'] })

    assert_empty CableRigSchema.subscriptions.live
  end

  def test_subscription_documents_must_select_one_subscription
    peer = ready_peer
    [
      ['{ ok }', nil, 'OPERATION_NOT_ALLOWED'],
      ['subscription A { tick { value } } subscription B { tick { value } }', nil, 'INVALID_INPUT'],
      ['subscription A { tick { value } }', 'Missing', 'INVALID_INPUT'],
      ['subscription {', nil, 'INVALID_INPUT'],
      ['subscription { unknown }', nil, 'INVALID_INPUT']
    ].each_with_index do |(query, operation, code), index|
      fields = { id: index.to_s, query: query, operationName: operation }.compact
      peer.send_frame(:subscribe, **fields)
      assert_equal code, peer.new_frames.last.fetch('code')
    end
    peer.send_frame(:subscribe, id: 'named', query: 'subscription A { tick { value } }', operationName: 'A')
    assert_equal 'subscribed', peer.new_frames.last.fetch('t')
    peer.send_frame(:unsubscribe, id: 'unknown')

    assert_nil peer.socket.closed
  end

  def test_ticks_close_idle_expired_ended_and_locked_connections
    cases = {
      'idle' => [->(peer) { peer.connection.stubs(:last_client_frame_at).returns(1.day.ago) }, Close::TIMEOUT],
      'lifetime' => [->(peer) { peer.connection.stubs(:opened_at).returns(2.days.ago) }, Close::GOING_AWAY],
      'ended' => [->(peer) { peer.session.update!(ended_at: Time.current) }, Close::NORMAL],
      'locked' => [->(peer) { peer.session.user.update!(locked: true) }, Close::ACCOUNT_LOCKED]
    }
    configure(cable_limits: { session_check_interval: 0 })

    cases.each do |name, (change, code)|
      peer = ready_peer
      change.call(peer)
      peer.connection.channel.tick
      assert_equal [code, ''], peer.socket.closed, name
    end
  end

  def test_each_revoke_scope_closes_only_its_matching_connection
    %i[connection session user].each do |scope|
      peer = ready_peer
      other = ready_peer
      ids = { connection: peer.connection.connection_id, session: peer.session.id, user: peer.session.user_id }
      Cable::Revoke.public_send(scope, ids.fetch(scope), reason: Cable::Codes::Reason::LOGGED_OUT)
      assert_equal [Close::NORMAL, ''], peer.socket.closed
      assert_nil other.socket.closed
    end
  end

  def test_unknown_revoke_messages_do_not_close_connections
    peer = ready_peer
    stream = Cable::Revoke.stream('session', peer.session.id)

    [nil, { type: 'other' }, { type: 'revoke', reason: 'UNKNOWN' }].each do |message|
      ActionCable.server.broadcast(stream, message)
      assert_nil peer.socket.closed
    end
  end

  def test_an_oversized_update_refuses_that_delivery_without_closing_the_connection
    peer = ready_peer
    peer.send_frame(:subscribe, id: 'one', query: TICK)
    peer.new_frames
    CableRigSchema.subscriptions.trigger(:tick, {}, { value: 'x' * Cable::Limits.server_frame_bytes })
    assert_equal ['error', 'INTERNAL'], peer.new_frames.last.values_at('t', 'code')
    assert_nil peer.socket.closed
    CableRigSchema.subscriptions.trigger(:tick, {}, { value: 'small' })

    assert_equal 'small', peer.new_frames.last.dig('result', 'data', 'tick', 'value')
  end

  def test_hello_database_and_application_errors_refuse_the_connection
    [ActiveRecord::ConnectionNotEstablished, RuntimeError].each do |error|
      peer = open_peer
      CableSession.stubs(:find_by_credential).raises(error)
      peer.handshake
      peer.connection.complete_refusal
      code = error == RuntimeError ? Close::INTERNAL : Close::UNAVAILABLE
      assert_equal [code, ''], peer.socket.closed
      CableSession.unstub(:find_by_credential)
    end
  end

  def test_tick_database_and_application_failures_close_the_connection
    configure(cable_limits: { session_check_interval: 0 })

    [ActiveRecord::ConnectionNotEstablished, RuntimeError].each do |error|
      peer = ready_peer
      CableSession.stubs(:find_by).raises(error)
      peer.connection.channel.tick
      code = error == RuntimeError ? Close::INTERNAL : Close::UNAVAILABLE
      assert_equal [code, ''], peer.socket.closed
      CableSession.unstub(:find_by)
    end
  end

  def test_a_failed_revoke_is_reported_without_raising_from_the_publisher
    errors = []
    configure(error_reporter: ->(error) { errors << error })
    ActionCable.server.stubs(:broadcast).raises(Redis::BaseError)
    Cable::Revoke.session(1, reason: Cable::Codes::Reason::LOGGED_OUT)

    assert_equal [Redis::BaseError], errors.map(&:class)
  end

  def test_a_stream_without_a_subscription_or_callback_is_rejected
    peer = ready_peer
    assert_raises(ArgumentError) { peer.connection.channel.stream_from('unowned') }
    peer.connection.channel.unsubscribed
    peer.connection.channel.stream_from('late') { |message| flunk message.inspect }

    assert pubsub.live.values.all?(&:empty?)
  end

  def test_hello_is_refused_when_rate_limited_or_replayed
    peer = open_peer
    Cable::Limits.stubs(:hello_blocked?).returns(true)
    peer.handshake
    peer.connection.complete_refusal
    assert_equal [Close::RATE_LIMITED, 'hello_blocked'], [peer.socket.closed.first, JSON.parse(peer.socket.closed.last)['code']]
    Cable::Limits.unstub(:hello_blocked?)
    peer = ready_peer
    peer.hello

    assert_equal [Close::BAD_FRAME, ''], peer.socket.closed
  end

  def test_a_blocked_hello_closes_with_the_seconds_until_the_block_window_ends
    window = Cable::Limits.hello_failure_window.to_i
    ends_at = ((Time.current.to_i / window) + 1) * window

    travel_to(Time.at(ends_at - 40)) do
      Cable::Limits.hello_failures_per_ip.times { Cable::Limits.record_hello_failure('203.0.113.7') }
      peer = open_peer
      peer.handshake
      peer.connection.complete_refusal

      assert_equal [Close::RATE_LIMITED, JSON.generate(code: 'hello_blocked', retryAfter: 40)], peer.socket.closed
    end
  end

  def test_a_hello_for_an_unknown_session_does_not_count_toward_the_address_block_and_a_forged_one_does
    (Cable::Limits.hello_failures_per_ip + 1).times do
      credential = new_credential
      session = start_cable_session(credential: credential).tap(&:destroy!)
      peer = open_peer(credential: credential, session: session)
      peer.handshake
      peer.connection.complete_refusal
    end
    unknown_blocked = Cable::Limits.hello_blocked?('203.0.113.7')
    Cable::Limits.hello_failures_per_ip.times { forged_hello('203.0.113.8') }

    assert_equal [false, true], [unknown_blocked, Cable::Limits.hello_blocked?('203.0.113.8')]
  end

  def test_an_invalid_hello_is_still_refused_when_its_failure_counter_is_unavailable
    peer = open_peer
    Cable::Limits.stubs(:record_hello_failure).raises(Cable::Rejected.new(Close::UNAVAILABLE))
    peer.start_link
    peer.connection.receive(JSON.generate(command: 'subscribe', identifier: CableRig::IDENTIFIER))
    peer.connection.receive(JSON.generate(command: 'message', identifier: CableRig::IDENTIFIER, data: JSON.generate(action: 'hello', hello: 'bad')))
    peer.connection.complete_refusal

    assert_equal [Close::UNAUTHENTICATED, ''], peer.socket.closed
  end

  def test_lease_renewal_refusal_preserves_the_failure_code
    [Close::SUPERSEDED, Close::UNAVAILABLE].each do |code|
      peer = ready_peer
      Cable::Limits.stubs(:renew).returns(false)
      Cable::Limits.stubs(:join).raises(Cable::Rejected.new(code))
      peer.connection.channel.tick
      assert_equal [code, ''], peer.socket.closed
      Cable::Limits.unstub(:join)
      Cable::Limits.unstub(:renew)
    end
  end

  def test_admitting_a_newer_connection_revokes_the_older_one
    configure(cable_limits: { connections_per_session: 1 })
    credential = new_credential
    older = ready_peer(credential: credential)
    travel(1.second)
    newer = ready_peer(credential: credential, session: older.session)
    assert_equal [Close::SUPERSEDED, ''], older.socket.closed

    assert_nil newer.socket.closed
  end

  def test_exhausted_frame_keys_close_gracefully_even_when_the_closing_frame_cannot_be_sent
    configure(cable_limits: { frames_per_key: 1 })
    peer = ready_peer
    peer.connection.close
    assert_equal [Close::GOING_AWAY, ''], peer.socket.closed

    assert_empty peer.new_frames
  end

  def test_subscription_errors_before_registration_release_nothing_and_answer_internal
    peer = ready_peer
    GraphQL.stubs(:parse).raises(RuntimeError)
    peer.send_frame(:subscribe, id: 'one', query: TICK)
    assert_equal 'INTERNAL', peer.new_frames.last['code']

    assert_nil peer.socket.closed
  end

  def test_a_transport_refusal_during_subscription_closes_the_connection
    peer = ready_peer
    CableRigSchema.stubs(:execute).raises(Cable::Rejected.new(Close::UNAVAILABLE))
    peer.send_frame(:subscribe, id: 'one', query: TICK)

    assert_equal [Close::UNAVAILABLE, ''], peer.socket.closed
  end

  def test_a_schema_that_does_not_register_a_subscription_answers_its_error_code
    peer = ready_peer

    [nil, [], [{ 'extensions' => { 'code' => 'RATE_LIMITED' } }]].each do |errors|
      result = mock('query result')
      result.stubs(:context).returns({})
      result.stubs(:to_h).returns({ 'errors' => errors })
      CableRigSchema.stubs(:execute).returns(result)
      peer.send_frame(:subscribe, id: 'one', query: TICK)
      expected = errors && errors.any? ? 'RATE_LIMITED' : 'INVALID_INPUT'
      assert_equal expected, peer.new_frames.last['code']
    end
  end

  def test_the_server_broadcasts_using_the_application_pubsub
    messages = []
    pubsub.subscribe('shared', ->(message) { messages << JSON.parse(message) })
    Cable::Server.new(channel: CableRigChannel).broadcast('shared', { ok: true })

    assert_equal [{ 'ok' => true }], messages
  end

  def test_a_stream_update_before_registration_finishes_is_delivered_in_order
    peer = ready_peer
    subscribe = pubsub.method(:subscribe)
    pubsub.define_singleton_method(:subscribe) do |name, callback, success|
      subscribe.call(name, callback, success)
      if name.start_with?('graphql-subscription:')
        callback.call(JSON.generate(result: nil, more: true))
        callback.call(JSON.generate(result: { data: { tick: { value: 'early' } } }, more: false))
      end
    end
    peer.send_frame(:subscribe, id: 'one', query: TICK)
    assert_equal(%w[subscribed next complete], peer.new_frames.map { |frame| frame['t'] })

    assert_empty CableRigSchema.subscriptions.live
  end

  private

  def forged_hello(ip)
    peer = open_peer(ip: ip)
    peer.start_link
    peer.connection.receive(JSON.generate(command: 'subscribe', identifier: CableRig::IDENTIFIER))
    peer.connection.receive(JSON.generate(command: 'message', identifier: CableRig::IDENTIFIER, data: JSON.generate(action: 'hello', hello: 'bad')))

    peer.connection.complete_refusal
  end
end
