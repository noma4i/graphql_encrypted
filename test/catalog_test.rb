require 'test_helper'
require 'tmpdir'

class CatalogTest < Minitest::Test
  def with_directory
    Dir.mktmpdir do |directory|
      %w[queries fragments].each { |folder| FileUtils.mkdir_p(File.join(directory, folder)) }
      File.write(File.join(directory, 'queries', 'a.graphql'), "query Ping {\n  ...Bits   \n}\n")
      File.write(File.join(directory, 'fragments', 'a.graphql'), "fragment Bits on Query {\n  __typename\n}\n")
      yield directory
    end
  end

  def test_a_document_is_the_operation_followed_by_its_fragments_right_trimmed
    with_directory do |directory|
      assert_equal({ 'Ping' => "query Ping {\n  ...Bits\n}\n\nfragment Bits on Query {\n  __typename\n}" }, GraphqlEncrypted::PersistedQuery::Catalog.documents(directory))
    end
  end

  def test_register_stores_each_document_under_its_hash
    with_directory do |directory|
      saved = {}
      store = Object.new
      store.define_singleton_method(:save_query) { |sha, document| saved[sha] = document }

      hashes = GraphqlEncrypted::PersistedQuery::Catalog.register(directory, store: store)

      assert_equal GraphqlEncrypted::PersistedQuery::Catalog.hashes(directory), hashes
      assert_equal Digest::SHA256.hexdigest(saved.values.first), saved.keys.first
    end
  end

  def test_an_unknown_fragment_is_refused
    with_directory do |directory|
      File.delete(File.join(directory, 'fragments', 'a.graphql'))
      File.write(File.join(directory, 'fragments', 'b.graphql'), "fragment Other on Query {\n  __typename\n}\n")

      assert_raises(ArgumentError) { GraphqlEncrypted::PersistedQuery::Catalog.documents(directory) }
    end
  end

  def test_invalid_catalogs_report_the_input_error
    {
      '' => 'no definitions',
      'query Same { a }\nquery Same { b }' => 'duplicate definition',
      'query One { a } query Two { b }' => 'column 0',
      '{ a }' => 'anonymous operation',
      'query Bad {' => 'Expected'
    }.each do |source, message|
      Dir.mktmpdir do |directory|
        FileUtils.mkdir_p(File.join(directory, 'queries'))
        File.write(File.join(directory, 'queries', 'query.graphql'), source.gsub('\\n', "\n"))
        error = assert_raises(ArgumentError) { GraphqlEncrypted::PersistedQuery::Catalog.documents(directory) }
        assert_includes error.message, message
      end
    end
  end

  def test_cyclic_and_repeated_fragment_dependencies_are_included_once
    with_directory do |directory|
      File.write(File.join(directory, 'fragments', 'b.graphql'), 'fragment More on Query { ...Bits }')
      File.write(File.join(directory, 'fragments', 'a.graphql'), 'fragment Bits on Query { ...More ...More }')
      document = GraphqlEncrypted::PersistedQuery::Catalog.documents(directory).fetch('Ping')
      assert_equal 1, document.scan('fragment Bits').size
      assert_equal 1, document.scan('fragment More').size
    end
  end
end
