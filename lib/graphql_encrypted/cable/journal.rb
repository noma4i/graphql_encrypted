# Structured log of the socket: one line per event with a fixed set of fields, never a query, variable, key or token.
# The message is +config.cable_log_name+, the event name is a payload field. A logger whose +info+ takes a message and a payload (SemanticLogger)
# gets them apart, any other logger (Logger, ActiveSupport::Logger) gets one line: the name and the payload as JSON.
#
# @see GraphqlEncrypted::Configuration#cable_log_name
module GraphqlEncrypted::Cable::Journal
  FIELDS = %i[connection_id session_id user_id code reason initiator frame_type n bytes duration_ms limit exception_class field].freeze
  MESSAGE_LENGTH = 120
  POSITIONAL_ARGUMENTS = %i[req opt].freeze

  module_function

  def event(name, **fields)
    unknown = fields.keys - FIELDS
    raise ArgumentError, "Unlogged fields: #{unknown.join(', ')}" if unknown.any?

    write(GraphqlEncrypted.option(:logger), GraphqlEncrypted.option(:cable_log_name), { event: name, **fields.compact })
  end

  def error(connection_id, error)
    event('error', connection_id: connection_id, exception_class: error.class.name)
  end

  def sink
    @sink ||= Sink.new
  end

  def write(logger, log_name, payload)
    if structured?(logger)
      logger.info(log_name, payload)
    else
      logger.info("#{log_name} #{JSON.generate(payload)}")
    end
  end

  def structured?(logger)
    logger.method(:info).parameters.count { |kind, _name| POSITIONAL_ARGUMENTS.include?(kind) } > 1
  end
end
