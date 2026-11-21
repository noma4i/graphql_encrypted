require 'test_helper'
require 'rails/generators/test_case'
require 'generators/graphql_encrypted/install/install_generator'

class InstallGeneratorTest < Rails::Generators::TestCase
  tests GraphqlEncrypted::Generators::InstallGenerator
  destination File.join(Dir.tmpdir, 'graphql_encrypted_generator')
  setup :prepare_destination

  INITIALIZER = 'config/initializers/graphql_encrypted.rb'.freeze
  MISSING_SETTING = 'Add the setting to lib/generators/graphql_encrypted/install/templates/initializer.rb.tt'.freeze

  test 'creates an initializer that parses as Ruby' do
    run_generator

    assert_file INITIALIZER
    assert RubyVM::InstructionSequence.compile(File.read(File.join(destination_root, INITIALIZER)))
  end

  test 'every setting of the configuration has a line in the initializer' do
    run_generator
    content = File.read(File.join(destination_root, INITIALIZER))
    settings = GraphqlEncrypted::Configuration.instance_methods(false).map { |name| name.to_s.delete_suffix('=').to_sym }.uniq - [:limits]

    missing = settings.reject { |name| content.match?(/^\s*#?\s*config\.#{name}\b/) }

    assert_empty missing, MISSING_SETTING
  end

  test 'the initializer configures the gem from the environment' do
    run_generator
    env = { 'ENCRYPTION_PRIVATE_KEY' => 'pem', 'API_HOST' => 'https://api.example.test' }
    saved = GraphqlEncrypted.instance_variable_get(:@configuration)
    GraphqlEncrypted.instance_variable_set(:@configuration, GraphqlEncrypted::Configuration.new)

    ENV.update(env)
    load File.join(destination_root, INITIALIZER)

    assert_equal 'pem', GraphqlEncrypted.option(:private_key)
    assert_equal 'https://api.example.test', GraphqlEncrypted.audience
  ensure
    env.each_key { |key| ENV.delete(key) }
    GraphqlEncrypted.instance_variable_set(:@configuration, saved)
  end

  test 'keeps an existing initializer' do
    FileUtils.mkdir_p(File.join(destination_root, 'config/initializers'))
    File.write(File.join(destination_root, INITIALIZER), '# mine')

    run_generator ['--skip']

    assert_file INITIALIZER, '# mine'
  end
end
