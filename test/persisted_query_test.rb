require 'test_helper'

class PersistedQueryTest < Minitest::Test
  class MemoryStore
    def initialize
      @queries = {}
    end

    def fetch_query(sha)
      @queries[sha]
    end

    def save_query(sha, query)
      @queries[sha] = query
    end
  end

  QUERY = '{ __typename }'.freeze
  SHA = Digest::SHA256.hexdigest(QUERY)

  def setup
    @store = MemoryStore.new

    GraphqlEncrypted.configuration.persisted_query_store = @store
  end

  def extensions(sha = SHA)
    { 'persistedQuery' => { 'sha256Hash' => sha } }
  end

  def test_a_plain_query_needs_no_store
    assert_equal :full, GraphqlEncrypted::PersistedQuery.resolve(QUERY, nil).kind
  end

  def test_a_full_query_with_its_hash_is_stored_and_then_found_by_hash
    assert_equal :full, GraphqlEncrypted::PersistedQuery.resolve(QUERY, extensions).kind

    stored = GraphqlEncrypted::PersistedQuery.resolve(nil, extensions)

    assert_equal [:stored, QUERY], [stored.kind, stored.document]
  end

  def test_an_unknown_hash_is_missing
    resolution = GraphqlEncrypted::PersistedQuery.resolve(nil, extensions)

    assert_equal :missing, resolution.kind

    assert_equal 'PERSISTED_QUERY_NOT_FOUND', GraphqlEncrypted::PersistedQuery.failure(resolution).dig(:errors, 0, 'extensions', 'code')
  end

  def test_a_hash_that_does_not_match_the_query_is_invalid_and_not_stored
    resolution = GraphqlEncrypted::PersistedQuery.resolve('{ other }', extensions)

    assert_equal :invalid, resolution.kind
    assert_nil @store.fetch_query(SHA)

    assert_equal 'INVALID_INPUT', GraphqlEncrypted::PersistedQuery.failure(resolution).dig(:errors, 0, 'extensions', 'code')
  end

  def test_a_malformed_hash_is_invalid
    assert_equal :invalid, GraphqlEncrypted::PersistedQuery.resolve(nil, extensions('nope')).kind

    assert_equal :invalid, GraphqlEncrypted::PersistedQuery.resolve(nil, { 'persistedQuery' => 'x' }).kind
  end

  def test_a_servable_resolution_has_no_failure
    assert_nil GraphqlEncrypted::PersistedQuery.failure(GraphqlEncrypted::PersistedQuery.resolve(QUERY, nil))
  end
end
