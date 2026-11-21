# Fixed-window counters on the configured cache. A limit is declared once with +config.limit+ and checked by name;
# the subject (phone, token, address) is stored only as a keyed digest.
#
#   GraphqlEncrypted::Limiter.take?(:sign_in, phone)
#
# @see GraphqlEncrypted::Configuration#limit
# @see GraphqlEncrypted::Secrets
module GraphqlEncrypted::Limiter
  module_function

  # Counts one attempt for every subject (nil subjects are skipped) and tells whether all of them are within the limit.
  # A disabled limit always allows. A cache that returns no count refuses.
  def take?(name, *subjects)
    return true unless enabled?(name)

    rule = rule(name)

    subjects.compact.map { |subject| within?(name, rule, subject) }.all?
  end

  def enabled?(name)
    enabled = rule(name).enabled

    enabled.respond_to?(:call) ? enabled.call : enabled
  end

  def rule(name)
    GraphqlEncrypted.configuration.limits.fetch(name.to_sym)
  end

  # Whole seconds until the window of the subject ends, at least 1; the whole window when none is open.
  def retry_after(name, subject)
    window = rule(name).window
    ends_at = GraphqlEncrypted.setting(:cache).read(ends_key(name, subject))

    ends_at ? [(ends_at - Time.now.to_f).ceil, 1].max : window.to_i
  end

  # The answer of a refused attempt: `RATE_LIMITED` with the longest wait among the (non-nil) subjects.
  def refusal(name, *subjects)
    { error: 'RATE_LIMITED', retryAfter: subjects.compact.map { |subject| retry_after(name, subject) }.max }
  end

  def within?(name, rule, subject)
    cache = GraphqlEncrypted.setting(:cache)
    key = counter_key(name, subject)
    count = cache.increment(key, 1, expires_in: rule.window) || first_attempt(cache, key, rule.window)
    cache.write(ends_key(name, subject), Time.now.to_f + rule.window.to_i, expires_in: rule.window) if count == 1

    count.is_a?(Integer) && count <= rule.limit
  end

  def counter_key(name, subject)
    "graphql_encrypted:limit:#{name}:#{GraphqlEncrypted::Secrets.digest("limit.#{name}", subject)}"
  end

  def ends_key(name, subject)
    "#{counter_key(name, subject)}:ends_at"
  end

  def first_attempt(cache, key, window)
    cache.write(key, 1, expires_in: window, unless_exist: true) ? 1 : cache.increment(key, 1, expires_in: window)
  end
end
