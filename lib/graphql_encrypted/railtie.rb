# Writes the default initializer of the gem when the application boots in development for the first time; an existing file is never touched.
#
# @see GraphqlEncrypted::InitializerTemplate
class GraphqlEncrypted::Railtie < Rails::Railtie
  initializer 'graphql_encrypted.default_initializer', before: :load_config_initializers do |app|
    written = GraphqlEncrypted::InitializerTemplate.write_missing(app.root) if Rails.env.development?
    Rails.logger.info("graphql_encrypted: wrote #{written}") if written
  end
end
