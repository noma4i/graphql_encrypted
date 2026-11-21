require 'test_helper'

class LimiterTest < Minitest::Test
  class SilentCache
    def increment(*)
      nil
    end

    def write(*)
      false
    end
  end

  def test_session_start_is_limited_to_30_per_10_minutes_without_any_declaration
    configure(key_generator: ActiveSupport::KeyGenerator.new('test-secret-key-base'), cache: ActiveSupport::Cache::MemoryStore.new)
    GraphqlEncrypted.configuration.limits.replace(GraphqlEncrypted::Configuration.new.limits)

    results = Array.new(31) { GraphqlEncrypted::Limiter.take?(:session_start, '203.0.113.9') }

    assert_equal Array.new(30, true) + [false], results
  end

  def setup
    configure(key_generator: ActiveSupport::KeyGenerator.new('test-secret-key-base'), cache: ActiveSupport::Cache::MemoryStore.new)
    GraphqlEncrypted.configuration.limits.clear

    GraphqlEncrypted.configuration.limit :sign_in, limit: 3, window: 5.minutes
  end

  def test_attempts_up_to_the_limit_pass_and_the_next_one_is_refused
    results = Array.new(4) { GraphqlEncrypted::Limiter.take?(:sign_in, '+15550100') }

    assert_equal [true, true, true, false], results
  end

  def test_retry_after_is_the_whole_window_before_any_attempt_and_counts_down_after_one
    assert_equal 300, GraphqlEncrypted::Limiter.retry_after(:sign_in, 'a')

    start = Time.at(1_800_000_000)
    travel_to(start) { GraphqlEncrypted::Limiter.take?(:sign_in, 'a') }

    travel_to(start + 100) { assert_equal 200, GraphqlEncrypted::Limiter.retry_after(:sign_in, 'a') }

    travel_to(start + 299.9) { assert_equal 1, GraphqlEncrypted::Limiter.retry_after(:sign_in, 'a') }
  end

  def test_a_refusal_answers_the_longest_wait_among_the_given_subjects
    start = Time.at(1_800_000_000)
    travel_to(start) { GraphqlEncrypted::Limiter.take?(:sign_in, 'a') }
    travel_to(start + 100) { GraphqlEncrypted::Limiter.take?(:sign_in, 'b') }

    travel_to(start + 150) do
      assert_equal({ error: 'RATE_LIMITED', retryAfter: 250 }, GraphqlEncrypted::Limiter.refusal(:sign_in, 'a', nil, 'b'))
    end
  end

  def test_each_subject_has_its_own_counter
    3.times { GraphqlEncrypted::Limiter.take?(:sign_in, 'a') }

    assert GraphqlEncrypted::Limiter.take?(:sign_in, 'b')

    refute GraphqlEncrypted::Limiter.take?(:sign_in, 'a')
  end

  def test_every_subject_is_counted_even_when_an_earlier_one_is_over
    3.times { GraphqlEncrypted::Limiter.take?(:sign_in, 'a') }

    refute GraphqlEncrypted::Limiter.take?(:sign_in, 'a', 'b')
    2.times { assert GraphqlEncrypted::Limiter.take?(:sign_in, 'b') }

    refute GraphqlEncrypted::Limiter.take?(:sign_in, 'b')
  end

  def test_a_nil_subject_is_skipped
    assert GraphqlEncrypted::Limiter.take?(:sign_in, nil)

    assert_equal [true, true, true, false], Array.new(4) { GraphqlEncrypted::Limiter.take?(:sign_in, nil, 'c') }
  end

  def test_the_counter_restarts_after_the_window
    3.times { GraphqlEncrypted::Limiter.take?(:sign_in, 'a') }
    refute GraphqlEncrypted::Limiter.take?(:sign_in, 'a')

    travel(6.minutes) { assert GraphqlEncrypted::Limiter.take?(:sign_in, 'a') }
  end

  def test_a_disabled_limit_always_allows
    enabled = false
    GraphqlEncrypted.configuration.limit :sign_in, limit: 1, window: 1.minute, enabled: -> { enabled }

    assert_equal [true, true, true], Array.new(3) { GraphqlEncrypted::Limiter.take?(:sign_in, 'a') }
    refute GraphqlEncrypted::Limiter.enabled?(:sign_in)

    enabled = true

    assert_equal [true, false], Array.new(2) { GraphqlEncrypted::Limiter.take?(:sign_in, 'a') }
  end

  def test_a_cache_that_returns_no_count_refuses
    configure(cache: SilentCache.new)

    refute GraphqlEncrypted::Limiter.take?(:sign_in, 'a')
  end

  def test_a_cache_without_an_initial_counter_admits_the_first_attempt
    cache = mock('cache')
    cache.expects(:increment).returns(nil)
    cache.expects(:write).with { |_key, value, **options| value == 1 && options[:unless_exist] }.returns(true)
    cache.expects(:write).with { |key, _value, **_options| key.end_with?(':ends_at') }.returns(true)
    configure(cache: cache)

    assert GraphqlEncrypted::Limiter.take?(:sign_in, 'a')
  end

  def test_an_undeclared_limit_raises_key_error
    assert_raises(KeyError) { GraphqlEncrypted::Limiter.take?(:unknown, 'a') }
  end

  def test_the_cache_holds_a_digest_of_the_subject_not_the_subject
    cache = GraphqlEncrypted.configuration.cache
    GraphqlEncrypted::Limiter.take?(:sign_in, '+15550100')
    keys = cache.instance_variable_get(:@data).keys

    refute(keys.any? { |key| key.include?('15550100') })

    assert_equal 2, keys.size
  end
end
