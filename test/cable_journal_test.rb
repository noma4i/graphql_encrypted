require 'test_helper'
require 'stringio'

class CableJournalTest < Minitest::Test
  Journal = GraphqlEncrypted::Cable::Journal

  class StructuredLogger
    attr_reader :calls

    def initialize
      @calls = []
    end

    def info(message = nil, payload = nil)
      @calls << [message, payload]
    end
  end

  def test_an_event_reaches_a_plain_ruby_logger_as_one_line_with_the_name_and_the_fields
    output = StringIO.new
    configure(logger: Logger.new(output), cable_log_name: 'test.cable')

    Journal.event('open', connection_id: 'c1', code: 1000, reason: nil)

    assert_includes output.string, 'test.cable'

    assert_equal({ 'event' => 'open', 'connection_id' => 'c1', 'code' => 1000 }, JSON.parse(output.string[/\{.*\}/]))
  end

  def test_an_error_reaches_a_plain_ruby_logger_with_the_exception_class
    output = StringIO.new
    configure(logger: ActiveSupport::Logger.new(output), cable_log_name: 'test.cable')

    Journal.error('c1', ArgumentError.new('boom'))

    assert_equal %w[error ArgumentError], JSON.parse(output.string[/\{.*\}/]).values_at('event', 'exception_class')
  end

  def test_a_logger_that_takes_a_message_and_a_payload_gets_them_apart
    logger = StructuredLogger.new
    configure(logger: logger, cable_log_name: 'test.cable')

    Journal.event('open', connection_id: 'c1')

    assert_equal [['test.cable', { event: 'open', connection_id: 'c1' }]], logger.calls
  end

  def test_arbitrary_fields_cannot_enter_the_structured_log
    assert_raises(ArgumentError) { Journal.event('open', credential: 'secret') }
  end

  def test_the_framework_sink_drops_verbose_messages_and_preserves_warnings
    output = StringIO.new
    configure(logger: Logger.new(output))
    Journal.sink.debug('secret-debug')
    Journal.sink.info('secret-info')
    Journal.sink.warn('visible-warning')
    refute_includes output.string, 'secret'

    assert_includes output.string, 'visible-warning'
  end
end
