require 'base64'
require 'digest'
require 'json'
require 'openssl'
require 'securerandom'
require 'concurrent/map'
require 'json/jwt'
require 'graphql'
require 'active_support'
require 'active_support/concern'
require 'active_support/core_ext/class/attribute'
require 'active_support/core_ext/enumerable'
require 'active_record'
require 'action_controller'
require 'active_support/core_ext/object/blank'
require 'active_support/core_ext/numeric/bytes'
require 'active_support/core_ext/numeric/time'
require 'active_support/parameter_filter'
require 'active_support/message_encryptor'
require 'active_support/notifications'
require 'erb'
require 'fileutils'
require 'logger'
require 'redis'

# End-to-end encrypted GraphQL over HTTP: JOSE envelopes, ordered and replay-safe mutations, persisted queries.
#
# @see GraphqlEncrypted::SecureController
# @see GraphqlEncrypted::Client
module GraphqlEncrypted
  MIN_KEY_BITS = 3072

  class << self
    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield configuration
    end

    # @note Raises KeyError when the key is missing, unreadable or shorter than MIN_KEY_BITS; endpoints answer 503 for it.
    def server_key
      pem = setting(:private_key)
      key = parsed_keys.compute_if_absent(pem) { OpenSSL::PKey::RSA.new(pem) }
      raise KeyError, "The server key must be a private RSA key of at least #{MIN_KEY_BITS} bits" unless key.private? && key.n.num_bits >= MIN_KEY_BITS

      key
    rescue OpenSSL::PKey::PKeyError
      raise KeyError, 'The server key is not a readable RSA key'
    end

    def kid
      Digest::SHA256.hexdigest(server_key.public_key.to_der)
    end

    def audience
      setting(:audience)
    end

    def persisted_query_store
      setting(:persisted_query_store)
    end

    # Runs the block inside +configuration.with_user+ (a current-user holder), or plainly when none is set.
    def with_user(user, &)
      scope = configuration.with_user

      scope ? scope.call(user, &) : yield
    end

    def report(error)
      GraphqlEncrypted::Diagnostics.capture(error)

      configuration.error_reporter.call(error)
    end

    # A setting that must be present; raises KeyError when it is not set.
    def setting(name)
      value = option(name)
      raise KeyError, "GraphqlEncrypted.configuration.#{name} is not set" if value.nil?

      value
    end

    # A setting that may be absent; a callable is called.
    def option(name)
      value = configuration.public_send(name)

      value.respond_to?(:call) ? value.call : value
    end

    private

    def parsed_keys
      @parsed_keys ||= Concurrent::Map.new
    end
  end
end

require_relative 'graphql_encrypted/version'
require_relative 'graphql_encrypted/initializer_template'
require_relative 'graphql_encrypted/configuration'
require_relative 'graphql_encrypted/secrets'
require_relative 'graphql_encrypted/limiter'
require_relative 'graphql_encrypted/diagnostics'
require_relative 'graphql_encrypted/diagnostics/redactor'
require_relative 'graphql_encrypted/envelope'
require_relative 'graphql_encrypted/persisted_query'
require_relative 'graphql_encrypted/persisted_query/catalog'
require_relative 'graphql_encrypted/session'
require_relative 'graphql_encrypted/errors'
require_relative 'graphql_encrypted/payload_middleware'
require_relative 'graphql_encrypted/base_controller'
require_relative 'graphql_encrypted/secure_controller'
require_relative 'graphql_encrypted/public_controller'
require_relative 'graphql_encrypted/client'
require_relative 'graphql_encrypted/client/retryable'
require_relative 'graphql_encrypted/client/rejected'
require_relative 'graphql_encrypted/client/sequence_conflict'
require_relative 'graphql_encrypted/client/state_error'
require_relative 'graphql_encrypted/cable'
# simplecov:disable
require_relative 'graphql_encrypted/railtie' if defined?(Rails::Railtie)
# simplecov:enable
