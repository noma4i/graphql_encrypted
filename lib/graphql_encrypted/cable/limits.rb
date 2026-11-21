# Numeric limits of the socket and the Redis counters behind them: opens and unauthenticated sockets per address,
# refused hellos per address, and the connection leases of a session and of a user. Redis is unavailable -> the socket closes with 4503.
# Defaults live in DEFAULTS, +config.cable_limits+ overrides single entries.
#
# @see GraphqlEncrypted::Configuration#cable_limits
# @see GraphqlEncrypted::Cable::Connection
module GraphqlEncrypted::Cable::Limits
  DEFAULTS = {
    client_frame_bytes: 32.kilobytes,
    server_frame_bytes: 256.kilobytes,
    subscriptions: 32,
    connections_per_session: 3,
    connections_per_user: 10,
    frames_per_second: 20,
    frame_burst: 40,
    subscribes_per_minute: 30,
    subscribe_burst: 32,
    opens_per_ip_per_minute: 60,
    hello_failures_per_ip: 10,
    hello_failure_window: 10.minutes,
    unauthenticated_per_ip: 20,
    connection_lifetime: 24.hours,
    hello_deadline: 10.seconds,
    hello_refusal_floor: 0.2,
    idle_deadline: 60.seconds,
    session_check_interval: 60.seconds,
    maintenance_interval: 15.seconds,
    lease_ttl: 45.seconds,
    frames_per_key: 2**20
  }.freeze

  LEASE_KEY_TTL = 3600

  ADMIT_SCRIPT = <<~LUA.freeze
    local opens = redis.call('INCR', KEYS[1])
    if opens == 1 then redis.call('EXPIRE', KEYS[1], ARGV[6]) end
    if opens > tonumber(ARGV[2]) then return 1 end
    redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[1])
    if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[3]) then return 2 end
    redis.call('ZADD', KEYS[2], ARGV[1] + ARGV[5], ARGV[4])
    redis.call('EXPIRE', KEYS[2], ARGV[5])
    return 0
  LUA

  JOIN_SCRIPT = <<~LUA.freeze
    local function opened(member) return tonumber(string.match(member, '^(%d+):')) end
    local victims = {}
    for scope, key in ipairs(KEYS) do
      redis.call('ZREMRANGEBYSCORE', key, '-inf', ARGV[1])
      local members = redis.call('ZRANGE', key, 0, -1)
      local found = false
      for _, member in ipairs(members) do
        if member == ARGV[3] then found = true end
      end
      if not found then members[#members + 1] = ARGV[3] end
      table.sort(members, function(a, b)
        local x, y = opened(a), opened(b)
        if x == y then return a < b end
        return x < y
      end)
      victims[scope] = {}
      for index = 1, #members - tonumber(ARGV[4 + scope]) do
        if members[index] == ARGV[3] then return { 'refused' } end
        victims[scope][#victims[scope] + 1] = members[index]
      end
    end
    local verdict = { 'admitted' }
    for scope, key in ipairs(KEYS) do
      redis.call('ZADD', key, ARGV[2], ARGV[3])
      redis.call('EXPIRE', key, ARGV[4])
      for _, victim in ipairs(victims[scope]) do
        redis.call('ZREM', key, victim)
        verdict[#verdict + 1] = victim
      end
    end
    return verdict
  LUA

  RENEW_SCRIPT = <<~LUA.freeze
    local found = 0
    for _, member in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
      if string.sub(member, -#ARGV[1]) == ARGV[1] then
        redis.call('ZADD', KEYS[1], 'XX', ARGV[2], member)
        found = 1
      end
    end
    if found == 1 then redis.call('EXPIRE', KEYS[1], ARGV[3]) end
    return found
  LUA

  LEAVE_SCRIPT = <<~LUA.freeze
    for _, member in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
      if string.sub(member, -#ARGV[1]) == ARGV[1] then redis.call('ZREM', KEYS[1], member) end
    end
    return 1
  LUA

  module_function

  DEFAULTS.each_key do |name|
    define_singleton_method(name) { GraphqlEncrypted.configuration.cable_limits.fetch(name) { DEFAULTS.fetch(name) } }
  end

  def redis
    @redis = nil if @redis_pid != Process.pid
    @redis_pid = Process.pid
    @redis ||= GraphqlEncrypted.setting(:cable_redis)
  end

  def admit_open(ip, connection_id)
    now = Time.current.to_i
    verdict = guard do
      redis.eval(ADMIT_SCRIPT, keys: [key('open', ip, now / 60), key('pending', ip)],
                               argv: [now, opens_per_ip_per_minute, unauthenticated_per_ip, connection_id, (hello_deadline + 5.seconds).to_i, 120])
    end
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::RATE_LIMITED unless verdict.zero?
  end

  def release_pending(ip, connection_id)
    guard { redis.zrem(key('pending', ip), connection_id) } if connection_id
  end

  def hello_blocked?(ip)
    guard { redis.get(key('hello_failures', ip, hello_window)).to_i >= hello_failures_per_ip }
  end

  def hello_retry_after
    window = hello_failure_window.to_i

    window - (Time.current.to_i % window)
  end

  def record_hello_failure(ip)
    guard do
      redis.multi do |transaction|
        transaction.incr(key('hello_failures', ip, hello_window))
        transaction.expire(key('hello_failures', ip, hello_window), (hello_failure_window * 2).to_i)
      end
    end
  end

  # Admits the connection and answers the ids of the older connections it superseded. A connection that is itself the one
  # the limit evicts (a late hello of the oldest socket) is removed again and refused with SUPERSEDED.
  def join(session_id:, user_id:, connection_id:, opened_at: Time.current)
    member = "#{(opened_at.to_f * 1000).to_i}:#{connection_id}"
    verdict = guard do
      redis.eval(JOIN_SCRIPT, keys: [key('lease', 'session', session_id), key('lease', 'user', user_id)],
                             argv: [Time.current.to_i, lease_expiry, member, LEASE_KEY_TTL, connections_per_session, connections_per_user])
    end

    if verdict.first == 'refused'
      raise GraphqlEncrypted::Cable::Rejected.new(GraphqlEncrypted::Cable::Codes::Close::SUPERSEDED, :lease_superseded)
    end

    verdict.drop(1).map { |entry| entry.split(':', 2).last }.uniq
  end

  # Extends the lease and its key; false when the lease of the connection is missing in the session or the user scope.
  def renew(session_id:, user_id:, connection_id:)
    guard do
      [['session', session_id], ['user', user_id]].map do |scope, id|
        redis.eval(RENEW_SCRIPT, keys: [key('lease', scope, id)], argv: [":#{connection_id}", lease_expiry, LEASE_KEY_TTL])
      end.all?(1)
    end
  end

  def leave(session_id:, user_id:, connection_id:)
    guard do
      [['session', session_id], ['user', user_id]].each do |scope, id|
        redis.eval(LEAVE_SCRIPT, keys: [key('lease', scope, id)], argv: [":#{connection_id}"])
      end
    end
  end

  def guard
    yield
  rescue Redis::BaseError => e
    GraphqlEncrypted.report(e)
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::UNAVAILABLE
  end

  def key(*parts)
    [GraphqlEncrypted.option(:cable_namespace), *parts].join(':')
  end

  def hello_window
    Time.current.to_i / hello_failure_window.to_i
  end

  def lease_expiry
    Time.current.to_i + lease_ttl.to_i
  end
end
