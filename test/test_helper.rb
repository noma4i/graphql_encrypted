require 'tmpdir'
require 'simplecov'

SimpleCov.start do
  root File.expand_path('..', __dir__)
  enable_coverage :branch
  minimum_coverage line: 100, branch: 100
  cover 'lib/**/*.rb'
  add_filter 'lib/graphql_encrypted/testing.rb'
  coverage_dir ENV.fetch('COVERAGE_DIR', File.join(Dir.tmpdir, 'graphql-encrypted-coverage'))
end

require 'minitest/autorun'
require 'mocha/minitest'
require 'graphql_encrypted'
require 'sentry-ruby'

ActiveRecord::Base.establish_connection(adapter: 'sqlite3', database: ':memory:')
ActiveRecord::Schema.verbose = false
ActiveRecord::Schema.define do
  create_table :sessions do |t|
    t.string :credential_digest, null: false, index: { unique: true }
    t.datetime :authenticated_at
    t.datetime :ended_at
    t.bigint :sequence, null: false, default: 0
    t.string :request_digest
    t.text :encrypted_response
    t.json :read_requests, null: false, default: {}
  end
  create_table :cable_users do |t|
    t.boolean :locked, null: false, default: false
  end
  create_table :cable_sessions do |t|
    t.string :credential_digest, null: false, index: { unique: true }
    t.datetime :authenticated_at
    t.datetime :ended_at
    t.bigint :user_id
    t.bigint :sequence, null: false, default: 0
    t.string :request_digest
    t.text :encrypted_response
    t.json :read_requests, null: false, default: {}
  end
end

class Session < ActiveRecord::Base
  include GraphqlEncrypted::Session
end

require_relative 'support/test_keys'

ActionCable.server.config.logger = Logger.new(nil)
ActionCable.server.config.cable = { 'adapter' => 'test' }

GraphqlEncrypted.configure do |config|
  config.private_key = TestKeys::SERVER.to_pem
  config.audience = TestKeys::AUDIENCE
  config.cable_redis = -> { Redis.new(url: ENV.fetch('REDIS_URL', 'redis://127.0.0.1:6379/15'), connect_timeout: 1, read_timeout: 1, write_timeout: 1) }
end

require_relative 'support/test_case'
require_relative 'support/cable_support'
require_relative 'support/cable_user'
require_relative 'support/cable_session'
require_relative 'support/cable_rig'
require_relative 'support/cable_rig_schema'
require_relative 'support/cable_rig_channel'
require_relative 'support/http_rig_schema'
require_relative 'support/http_rig_session'
require_relative 'support/http_rig_secure_controller'
require_relative 'support/http_rig_public_controller'
require_relative 'support/http_rig'
