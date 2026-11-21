module GraphqlEncrypted::Cable::Client::ReconnectPolicy
  SCHEDULE = [1, 2, 4, 8, 16, 30].freeze
  STOP_CODES = [1000, 4403, 4430].freeze
  GOING_AWAY = 1001
  ONCE_IMMEDIATE = [4400, 4409].freeze
  MINIMUM = { 4429 => 5 }.freeze
  STABLE_AFTER = 60

  module_function

  def delay(code, attempt, random: Random.rand)
    return if STOP_CODES.include?(code)
    return random * 5 if code == GOING_AWAY
    return 0 if ONCE_IMMEDIATE.include?(code) && attempt.zero?

    [SCHEDULE.fetch([attempt, SCHEDULE.size - 1].min), MINIMUM.fetch(code, 0)].max * (1 + (random * 0.5))
  end
end
