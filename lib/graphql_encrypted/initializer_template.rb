# The default application initializer, one template for the install generator and the Railtie.
#
# @see GraphqlEncrypted::Railtie
# @see GraphqlEncrypted::Generators::InstallGenerator
module GraphqlEncrypted::InitializerTemplate
  PATH = 'config/initializers/graphql_encrypted.rb'.freeze
  TEMPLATE = File.expand_path('../generators/graphql_encrypted/install/templates/initializer.rb.tt', __dir__).freeze

  module_function

  def render
    ERB.new(File.read(TEMPLATE), trim_mode: '-').result
  end

  # Writes the initializer under +root+ unless one exists; returns its path, nil when it was left alone.
  def write_missing(root)
    file = File.join(root, PATH)
    return if File.exist?(file)

    FileUtils.mkdir_p(File.dirname(file))
    File.write(file, render)

    file
  end
end
