# Settings of the gem. A value is a plain object or a callable; callables are read on every use, so keys can rotate without a restart.
#
# @see GraphqlEncrypted.configure
class GraphqlEncrypted::Configuration
  Limit = Data.define(:limit, :window, :enabled)

  attr_accessor :private_key, :audience, :persisted_query_store, :error_reporter, :key_generator, :cache, :logger,
                :sentry, :sentry_namespace, :filter_parameters, :expected_errors, :body_tags, :refuse_headers, :with_user,
                :payload_secret, :payload_paths, :payload_failure_context, :cable_path, :cable_channel, :cable_protocol_label, :cable_hello_purpose, :cable_redis, :cable_namespace, :cable_log_name, :cable_log_updates
  attr_reader :limits, :cable_limits

  def initialize
    @error_reporter = ->(_error) {}
    @sentry = false
    @sentry_namespace = 'graphql_encrypted'
    @filter_parameters = []
    @expected_errors = []
    @body_tags = {}
    @refuse_headers = []
    @limits = { session_start: Limit.new(limit: 30, window: 10.minutes, enabled: true) }
    @payload_paths = ['/']
    @payload_failure_context = ->(_request) { {} }
    @cable_path = '/cable'
    @cable_protocol_label = 'graphql-encrypted-ws-v1'
    @cable_hello_purpose = 'graphql_encrypted.ws.hello'
    @cable_namespace = 'graphql_encrypted:cable'
    @cable_log_name = 'graphql_encrypted.cable'
    @cable_log_updates = false
    @cable_limits = {}
  end

  # Overrides entries of GraphqlEncrypted::Cable::Limits::DEFAULTS; an unknown name raises.
  def cable_limits=(values)
    unknown = values.keys - GraphqlEncrypted::Cable::Limits::DEFAULTS.keys
    raise ArgumentError, "Unknown cable limits: #{unknown.join(', ')}" if unknown.any?

    @cable_limits = values
  end

  # Declares a named counter for GraphqlEncrypted::Limiter. +enabled+ is a boolean or a callable.
  def limit(name, limit:, window:, enabled: true)
    limits[name.to_sym] = Limit.new(limit: limit, window: window, enabled: enabled)
  end
end
