require 'test_helper'

class ErrorsTest < Minitest::Test
  class Query < GraphQL::Schema::Object
    field :boom, Integer, null: false
    field :missing, Integer, null: false

    def boom
      raise ArgumentError, 'secret detail'
    end

    def missing
      raise Errno::ENOENT, 'gone'
    end
  end

  class Schema < GraphQL::Schema
    query Query
    use GraphqlEncrypted::Errors
  end

  def setup
    Sentry.init do |config|
      config.dsn = 'http://key@localhost/1'
      config.transport.transport_class = Sentry::DummyTransport
      config.background_worker_threads = 0
      config.before_send = ->(event, hint) { GraphqlEncrypted::Diagnostics.before_send(event, hint) }
    end
    @reported = []

    configure(sentry: true, sentry_namespace: 'app', expected_errors: ['Errno::ENOENT'], error_reporter: ->(error) { @reported << error })
  end

  def test_a_resolver_error_answers_internal_retryable_and_is_reported_without_its_message
    error = run_query('{ boom }').dig('errors', 0)

    assert_equal({ 'code' => GraphqlEncrypted::Cable::Codes::Failure::INTERNAL, 'retryable' => true }, error['extensions'])
    refute_includes error['message'], 'secret detail'
    assert_equal(['ArgumentError'], @reported.map { |reported| reported.class.name })

    assert_equal ['ArgumentError'], sent_types
  end

  def test_an_expected_error_is_reported_to_the_app_but_never_sent_to_sentry
    run_query('{ missing }')

    assert_equal(['Errno::ENOENT'], @reported.map { |reported| reported.class.name })

    assert_empty sent_types
  end

  private

  def run_query(query)
    Sentry.with_scope do |scope|
      scope.set_tags(app: 'true')

      Schema.execute(query).to_h
    end
  end

  def sent_types
    Sentry.get_current_client.transport.events.map { |event| event.exception.values.first.type }
  end
end
