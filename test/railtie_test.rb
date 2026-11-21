require 'test_helper'
require 'rails/railtie'
require 'rails/generators/test_case'
require 'graphql_encrypted/railtie'
require 'generators/graphql_encrypted/install/install_generator'

class RailtieTest < Minitest::Test
  INITIALIZER = 'config/initializers/graphql_encrypted.rb'.freeze

  def setup
    @root = Pathname.new(Dir.mktmpdir('graphql_encrypted_railtie'))
    @file = @root.join(INITIALIZER)
  end

  def teardown
    FileUtils.rm_rf(@root)

    super
  end

  def test_writes_the_default_initializer_in_development_once
    boot('development')
    written = @file.read
    @file.write("#{written}# edited")
    boot('development')

    assert_equal "#{written}# edited", @file.read
  end

  def test_writes_what_the_generator_writes
    boot('development')
    generated = Pathname.new(Dir.mktmpdir('graphql_encrypted_generated'))
    GraphqlEncrypted::Generators::InstallGenerator.start([], destination_root: generated.to_s, quiet: true)

    assert_equal generated.join(INITIALIZER).read, @file.read
  ensure
    FileUtils.rm_rf(generated)
  end

  def test_writes_nothing_outside_development
    %w[test production].each do |env|
      boot(env)

      refute @file.exist?, env
    end
  end

  def test_keeps_an_existing_initializer_byte_for_byte
    @file.dirname.mkpath
    @file.binwrite("# mine \xFF\n")

    boot('development')

    assert_equal "# mine \xFF\n".b, @file.binread
  end

  def test_the_default_initializer_loads_without_the_environment
    boot('development')
    saved = GraphqlEncrypted.instance_variable_get(:@configuration)
    GraphqlEncrypted.instance_variable_set(:@configuration, GraphqlEncrypted::Configuration.new)
    names = %w[API_HOST ENCRYPTION_PRIVATE_KEY]
    environment = ENV.to_h.slice(*names)
    names.each { |name| ENV.delete(name) }

    load @file.to_s

    assert_raises(KeyError) { GraphqlEncrypted.audience }
  ensure
    ENV.update(environment)
    GraphqlEncrypted.instance_variable_set(:@configuration, saved)
  end

  private

  def boot(env)
    Rails.stubs(:env).returns(ActiveSupport::StringInquirer.new(env))
    Rails.stubs(:logger).returns(Logger.new(nil))
    initializer = GraphqlEncrypted::Railtie.initializers.find { |item| item.name == 'graphql_encrypted.default_initializer' }

    initializer.bind(GraphqlEncrypted::Railtie.instance).run(Struct.new(:root).new(@root))
  end
end
