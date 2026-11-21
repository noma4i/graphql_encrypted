# Thread-safe token bucket: +rate+ tokens per second up to +capacity+, one token per take.
#
# @see GraphqlEncrypted::Cable::Connection
class GraphqlEncrypted::Cable::TokenBucket
  def initialize(rate:, capacity:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
    @rate = rate.to_f
    @capacity = capacity.to_f
    @clock = clock
    @tokens = @capacity
    @refilled_at = clock.call
    @lock = Mutex.new
  end

  def take
    @lock.synchronize do
      now = @clock.call
      @tokens = [@capacity, @tokens + ((now - @refilled_at) * @rate)].min
      @refilled_at = now
      next false if @tokens < 1

      @tokens -= 1

      true
    end
  end
end
