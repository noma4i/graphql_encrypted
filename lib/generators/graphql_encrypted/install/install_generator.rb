require 'rails/generators'

module GraphqlEncrypted
  module Generators
    # Writes config/initializers/graphql_encrypted.rb: the required settings and every optional one, commented out with its default.
    #
    # @see GraphqlEncrypted::Configuration
    class InstallGenerator < Rails::Generators::Base
      def create_initializer
        create_file GraphqlEncrypted::InitializerTemplate::PATH, GraphqlEncrypted::InitializerTemplate.render
      end
    end
  end
end
