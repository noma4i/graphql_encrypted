require 'test_helper'

class CableLimitsTest < Minitest::Test
  include CableSupport

  Close = GraphqlEncrypted::Cable::Codes::Close
  Limits = GraphqlEncrypted::Cable::Limits
  Rejected = GraphqlEncrypted::Cable::Rejected

  def setup
    configure_cable
  end

  def teardown
    namespace = GraphqlEncrypted.configuration.cable_namespace
    super

    clean_cable_redis(namespace)
  end

  def test_a_token_bucket_allows_a_burst_refuses_the_next_take_and_refills_at_the_rate
    clock = 0.0
    bucket = GraphqlEncrypted::Cable::TokenBucket.new(rate: 20, capacity: 40, clock: -> { clock })

    assert_equal [true] * 40, Array.new(40) { bucket.take }
    assert_equal false, bucket.take

    clock += 0.1
    assert_equal [true, true, false], Array.new(3) { bucket.take }

    clock += 60

    assert_equal 40, Array.new(60) { bucket.take }.count(true)
  end

  def test_the_open_after_the_per_minute_cap_is_refused_for_one_address_only
    Limits.opens_per_ip_per_minute.times do
      id = SecureRandom.uuid
      Limits.admit_open('198.51.100.1', id)
      Limits.release_pending('198.51.100.1', id)
    end

    assert_equal Close::RATE_LIMITED, assert_raises(Rejected) { Limits.admit_open('198.51.100.1', SecureRandom.uuid) }.code
    Limits.admit_open('198.51.100.2', SecureRandom.uuid)

    travel_to(61.seconds.from_now) { Limits.admit_open('198.51.100.1', SecureRandom.uuid) }
  end

  def test_an_address_holds_a_capped_number_of_sockets_without_hello_and_a_release_frees_a_place
    ids = Array.new(Limits.unauthenticated_per_ip) { SecureRandom.uuid }
    ids.each { |id| Limits.admit_open('198.51.100.3', id) }

    assert_equal Close::RATE_LIMITED, assert_raises(Rejected) { Limits.admit_open('198.51.100.3', SecureRandom.uuid) }.code
    Limits.release_pending('198.51.100.3', ids.first)

    Limits.admit_open('198.51.100.3', SecureRandom.uuid)
  end

  def test_refused_hellos_block_further_hellos_from_the_address_until_the_window_ends
    Limits.hello_failures_per_ip.times { Limits.record_hello_failure('198.51.100.4') }

    assert Limits.hello_blocked?('198.51.100.4')
    assert_equal false, Limits.hello_blocked?('198.51.100.5')

    travel_to((Limits.hello_failure_window + 1.second).from_now) { assert_equal false, Limits.hello_blocked?('198.51.100.4') }
  end

  def test_a_session_keeps_its_connections_and_the_next_one_supersedes_the_oldest
    ids = Array.new(Limits.connections_per_session) { SecureRandom.uuid }
    ids.each do |id|
      travel(1.second)
      assert_empty Limits.join(session_id: 's', user_id: 1, connection_id: id)
    end
    travel(1.second)
    assert_equal [ids.first], Limits.join(session_id: 's', user_id: 1, connection_id: SecureRandom.uuid)

    Limits.leave(session_id: 's', user_id: 1, connection_id: ids.first)
    Limits.leave(session_id: 's', user_id: 1, connection_id: ids[1])

    assert_empty Limits.join(session_id: 's', user_id: 1, connection_id: SecureRandom.uuid)
  end

  def test_a_user_keeps_its_connections_across_sessions_and_the_next_one_supersedes_the_oldest
    ids = Array.new(Limits.connections_per_user) { SecureRandom.uuid }
    ids.each_with_index do |id, index|
      travel(1.second)
      assert_empty Limits.join(session_id: "s#{index / 3}", user_id: 7, connection_id: id)
    end
    travel(1.second)

    assert_equal [ids.first], Limits.join(session_id: 's9', user_id: 7, connection_id: SecureRandom.uuid)
  end

  def test_leases_that_are_not_renewed_expire
    Limits.join(session_id: 's', user_id: 1, connection_id: SecureRandom.uuid)

    travel_to((Limits.lease_ttl + 1.second).from_now) do
      Array.new(Limits.connections_per_session) { Limits.join(session_id: 's', user_id: 1, connection_id: SecureRandom.uuid) }.each { |superseded| assert_empty superseded }
    end
  end

  def test_a_renewal_extends_the_ttl_of_the_lease_key
    Limits.join(session_id: 's', user_id: 1, connection_id: 'c1')
    key = Limits.key('lease', 'session', 's')
    Limits.redis.expire(key, 5)

    assert Limits.renew(session_id: 's', user_id: 1, connection_id: 'c1')

    assert_operator Limits.redis.ttl(key), :>, 3000
  end

  def test_a_renewal_of_a_connection_the_lease_does_not_hold_reports_it
    Limits.join(session_id: 's', user_id: 1, connection_id: 'c1')

    assert_equal false, Limits.renew(session_id: 's', user_id: 1, connection_id: 'ghost')
  end

  def test_a_late_join_of_the_oldest_connection_is_refused_and_leaves_the_live_ones_alone
    opened = Time.current
    live = %w[b c d].each_with_index.map do |id, index|
      Limits.join(session_id: 's', user_id: 1, connection_id: id, opened_at: opened + (index + 1).seconds)

      id
    end

    error = assert_raises(Rejected) { Limits.join(session_id: 's', user_id: 1, connection_id: 'a', opened_at: opened) }

    assert_equal Close::SUPERSEDED, error.code

    assert_equal live, Limits.redis.zrange(Limits.key('lease', 'session', 's'), 0, -1).map { |member| member.split(':', 2).last }.sort
  end

  def test_a_configured_limit_replaces_its_default
    configure(cable_limits: { connections_per_session: 1 })
    first = SecureRandom.uuid
    Limits.join(session_id: 's', user_id: 1, connection_id: first)
    travel(1.second)

    assert_equal [first], Limits.join(session_id: 's', user_id: 1, connection_id: SecureRandom.uuid)
  end

  def test_a_refused_session_join_does_not_evict_a_connection_of_another_session
    configure(cable_limits: { connections_per_session: 1, connections_per_user: 2 })
    opened = Time.current
    Limits.join(session_id: 'other', user_id: 1, connection_id: 'old', opened_at: opened)
    Limits.join(session_id: 'full', user_id: 1, connection_id: 'new', opened_at: opened + 2)

    error = assert_raises(Rejected) do
      Limits.join(session_id: 'full', user_id: 1, connection_id: 'late', opened_at: opened + 1)
    end

    assert_equal Close::SUPERSEDED, error.code
    assert Limits.renew(session_id: 'other', user_id: 1, connection_id: 'old')

    assert Limits.renew(session_id: 'full', user_id: 1, connection_id: 'new')
  end

  def test_an_unknown_limit_name_raises
    assert_raises(ArgumentError) { configure(cable_limits: { nope: 1 }) }
  end

  def test_when_redis_is_unavailable_every_limit_call_closes_with_unavailable
    configure(cable_redis: -> { raise Redis::CannotConnectError })
    Limits.instance_variable_set(:@redis_pid, nil)

    [-> { Limits.admit_open('198.51.100.9', 'x') }, -> { Limits.hello_blocked?('198.51.100.9') }, -> { Limits.join(session_id: 's', user_id: 1, connection_id: 'x') }].each do |call|
      assert_equal Close::UNAVAILABLE, assert_raises(Rejected, &call).code
    end
  end
end
