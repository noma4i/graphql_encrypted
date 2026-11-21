require 'test_helper'

class CableChannelTest < Minitest::Test
  include CableSupport
  include CableRig

  TICK = 'subscription { tick { value } }'.freeze
  STOP = 'subscription { stop { value } }'.freeze
  EXPLODE = 'subscription { explode { value } }'.freeze

  def setup
    install_rig
    @peer = ready_peer
  end

  def teardown
    remove_rig

    super
  end

  def test_the_stock_graphql_transport_delivers_an_event_without_an_adapter_of_the_application
    @peer.send_frame(:subscribe, id: 'tick', query: TICK)

    assert_equal [%w[subscribed tick]], @peer.summary

    trigger_tick('one')
    frames = @peer.new_frames

    assert_equal([%w[next tick]], frames.map { |frame| [frame['t'], frame['id']] })

    assert_equal({ 'tick' => { 'value' => 'one' } }, frames.first.dig('result', 'data'))
  end

  def test_with_update_logging_each_written_update_names_its_connection_and_field_and_without_it_nothing_is_logged
    @peer.send_frame(:subscribe, id: 'tick', query: TICK)
    @peer.new_frames
    log = UpdateLog.new
    configure(logger: log)

    trigger_tick('quiet')
    configure(cable_log_updates: true)
    trigger_tick('loud')

    assert_equal [%w[update tick]], log.updates.map { |payload| payload.values_at(:event, :field) }
    assert_equal 2, @peer.new_frames.size
    refute_nil log.updates.first[:connection_id]
  end

  def test_an_update_without_data_is_logged_without_a_field
    @peer.send_frame(:subscribe, id: 'tick', query: TICK)
    @peer.new_frames
    log = UpdateLog.new
    configure(logger: log, cable_log_updates: true)

    trigger_tick(nil)

    assert_equal [['update', nil]], log.updates.map { |payload| payload.values_at(:event, :field) }
    assert_equal 1, @peer.new_frames.size
  end

  class UpdateLog
    attr_reader :updates

    def initialize
      @updates = []
    end

    def info(_message, payload = nil)
      @updates << payload if payload.is_a?(Hash) && payload[:event] == 'update'
    end

    %i[warn error].each do |level|
      define_method(level) { |*| true }
    end
  end

  def test_a_subscription_that_ends_without_a_result_completes_alone_and_the_socket_lives
    @peer.send_frame(:subscribe, id: 'stop', query: STOP)
    @peer.send_frame(:subscribe, id: 'tick', query: TICK)
    @peer.new_frames

    CableRigSchema.subscriptions.trigger(:stop, {}, { final: false })

    assert_equal [%w[complete stop]], @peer.summary
    assert_nil @peer.socket.closed

    trigger_tick('still here')

    assert_equal [%w[next tick]], @peer.summary

    assert_equal 1, CableRigSchema.subscriptions.live.size
  end

  def test_a_final_result_is_followed_by_complete_and_removes_that_subscription_only
    @peer.send_frame(:subscribe, id: 'stop', query: STOP)
    @peer.send_frame(:subscribe, id: 'tick', query: TICK)
    @peer.new_frames

    CableRigSchema.subscriptions.trigger(:stop, {}, { final: true })

    assert_equal [%w[next stop], %w[complete stop]], @peer.summary

    assert_nil @peer.socket.closed
  end

  def test_an_event_published_between_stream_registration_and_subscribed_is_delivered_after_subscribed
    gate = CableRig::Gate.new
    @peer.socket.hold_next_transmit(gate)
    opener = Thread.new { @peer.send_frame(:subscribe, id: 'tick', query: TICK) }
    gate.wait_arrived
    work.defer_jobs
    trigger_tick('early')
    publisher = Thread.new { work.run_all_jobs }
    settle(publisher)
    gate.open
    [opener, publisher].each(&:join)

    assert_equal [%w[subscribed tick], %w[next tick]], @peer.summary
  end

  def test_a_subscription_whose_execution_raises_after_it_took_a_stream_releases_that_stream
    @peer.send_frame(:subscribe, id: 'boom', query: EXPLODE)

    assert_equal [%w[error boom]], @peer.summary
    assert_empty pubsub.live['rig:leak']

    assert_empty CableRigSchema.subscriptions.live
  end

  def test_a_connection_that_closes_while_a_subscription_opens_leaves_nothing_behind
    gate = CableRig::Gate.new
    CableRigSchema.on_subscribe = -> { gate.hold }
    opener = Thread.new { @peer.send_frame(:subscribe, id: 'tick', query: TICK) }
    gate.wait_arrived
    @peer.connection.send(:handle_close)
    gate.open
    opener.join

    assert_empty CableRigSchema.subscriptions.live
    assert pubsub.live.values.all?(&:empty?), 'a stream stayed registered after the close'

    assert_empty(@peer.summary.reject { |frame| frame.first == 'error' })
  end

  def test_an_update_queued_for_a_removed_subscription_does_not_reach_the_subscription_that_reuses_its_id
    @peer.send_frame(:subscribe, id: 'a', query: TICK)
    @peer.new_frames
    work.defer_jobs
    trigger_tick('old')
    work.run_next_job
    @peer.send_frame(:unsubscribe, id: 'a')
    @peer.send_frame(:subscribe, id: 'a', query: TICK)
    work.run_all_jobs

    assert_equal [%w[subscribed a]], @peer.summary

    trigger_tick('new')
    work.run_all_jobs
    frames = @peer.new_frames

    assert_equal([%w[next a]], frames.map { |frame| [frame['t'], frame['id']] })

    assert_equal 'new', frames.first.dig('result', 'data', 'tick', 'value')
  end

  def test_a_delivery_in_flight_cannot_remove_the_subscription_that_took_the_same_id_meanwhile
    @peer.send_frame(:subscribe, id: 'a', query: STOP)
    @peer.new_frames
    work.defer_jobs
    CableRigSchema.subscriptions.trigger(:stop, {}, { final: true })
    gate = CableRig::Gate.new
    @peer.socket.hold_next_transmit(gate)
    delivery = Thread.new { work.run_all_jobs }
    gate.wait_arrived
    resubscribe = Thread.new do
      @peer.send_frame(:unsubscribe, id: 'a')
      @peer.send_frame(:subscribe, id: 'a', query: TICK)
    end
    settle(resubscribe)
    gate.open
    [delivery, resubscribe].each(&:join)

    assert_equal [%w[next a], %w[complete a], %w[subscribed a]], @peer.summary

    trigger_tick('new')
    work.run_all_jobs

    assert_equal [%w[next a]], @peer.summary
  end

  private

  def trigger_tick(value)
    CableRigSchema.subscriptions.trigger(:tick, {}, { value: value })
  end
end
