# Automatic persisted queries: a request names its document by sha256Hash, the full query is sent only once.
#
# @see GraphqlEncrypted::PersistedQuery::Catalog
module GraphqlEncrypted::PersistedQuery
  SHA256 = /\A[0-9a-f]{64}\z/
  ERRORS = {
    missing: { code: 'PERSISTED_QUERY_NOT_FOUND', message: 'The persisted query is not stored, send the query with its hash' },
    invalid: { code: 'INVALID_INPUT', message: 'The persisted query hash is invalid or does not match the query' }
  }.freeze
  Resolution = Data.define(:kind, :document)
  NONE = Resolution.new(kind: nil, document: nil)

  module_function

  # Pair [kind, document], kind is :full, :stored, :missing or :invalid.
  def document(query, extensions)
    persisted = extensions.is_a?(Hash) ? extensions['persistedQuery'] : nil
    return [:full, query] if persisted.nil?

    sha = persisted.is_a?(Hash) ? persisted['sha256Hash'] : nil
    return [:invalid, nil] unless sha.is_a?(String) && sha.match?(SHA256)
    return [:full, query] if query.present?

    stored = GraphqlEncrypted.persisted_query_store.fetch_query(sha)

    stored ? [:stored, stored] : [:missing, nil]
  end

  # @note A full query sent with its hash is stored only when the hash matches the query.
  def resolve(query, extensions)
    kind, found = document(query, extensions)
    return Resolution.new(kind: kind, document: found) unless kind == :full && extensions.is_a?(Hash) && extensions['persistedQuery']

    sha = extensions.dig('persistedQuery', 'sha256Hash')
    return Resolution.new(kind: :invalid, document: nil) unless query.is_a?(String) && Digest::SHA256.hexdigest(query) == sha

    GraphqlEncrypted.persisted_query_store.save_query(sha, query)

    Resolution.new(kind: :full, document: query)
  end

  # GraphQL response body for a resolution the server cannot run, nil when it can.
  def failure(resolution)
    error = ERRORS[resolution.kind]

    { errors: [GraphQL::ExecutionError.new(error.fetch(:message), extensions: { code: error.fetch(:code) }).to_h] } if error
  end
end
