# Builds the hash -> document table for persisted queries straight from a client's .graphql files
# and registers it in the configured store. A document is the operation followed by the fragments it needs
# (transitively, sorted by name, once). Definitions start at column 0, are right-trimmed per line and
# are joined by one blank line, so any client reproduces the same bytes without a GraphQL printer.
#
# @see GraphqlEncrypted::PersistedQuery
module GraphqlEncrypted::PersistedQuery::Catalog
  DEFINITION_START = /^(?=(?:query|mutation|subscription|fragment)\b)/
  DIRECTORIES = %w[queries mutations subscriptions fragments].freeze

  Definition = Struct.new(:name, :fragment, :text, :spreads, keyword_init: true)

  module_function

  def documents(directory)
    definitions = load(directory)
    fragments, operations = definitions.partition(&:fragment)
    by_name = fragments.index_by(&:name)

    operations.to_h { |operation| [operation.name, document(operation, by_name)] }
  end

  def hashes(directory)
    documents(directory).transform_values { |document| Digest::SHA256.hexdigest(document) }
  end

  def register(directory, store: GraphqlEncrypted.persisted_query_store)
    documents(directory).to_h do |name, document|
      sha = Digest::SHA256.hexdigest(document)
      store.save_query(sha, document)

      [name, sha]
    end
  end

  def load(directory)
    definitions = DIRECTORIES.flat_map { |folder| Dir.glob(File.join(directory, folder, '*.graphql')).sort }.flat_map { |path| split(File.read(path), path) }
    duplicate = definitions.group_by { |definition| [definition.fragment, definition.name] }.find { |_key, group| group.size > 1 }
    raise ArgumentError, "duplicate definition #{duplicate.first.last}" if duplicate
    raise ArgumentError, "no definitions in #{directory}" if definitions.empty?

    definitions
  end

  def split(source, path)
    source.split(DEFINITION_START).map(&:strip).reject(&:empty?).map do |chunk|
      parsed = GraphQL.parse(chunk).definitions
      raise ArgumentError, "#{path}: a definition must start at column 0" unless parsed.one?

      node = parsed.first
      raise ArgumentError, "#{path}: anonymous operation" if node.name.blank?

      Definition.new(name: node.name, fragment: node.is_a?(GraphQL::Language::Nodes::FragmentDefinition), text: chunk.lines.map(&:rstrip).join("\n"), spreads: spreads(node))
    end
  rescue GraphQL::ParseError => e
    raise ArgumentError, "#{path}: #{e.message}"
  end

  def spreads(node)
    found = []
    stack = [node]
    while (current = stack.pop)
      found << current.name if current.is_a?(GraphQL::Language::Nodes::FragmentSpread)
      stack.concat(current.children)
    end

    found.uniq
  end

  def document(operation, fragments)
    needed = {}
    queue = operation.spreads.dup
    while (name = queue.shift)
      next if needed.key?(name)

      fragment = fragments.fetch(name) { raise ArgumentError, "#{operation.name}: unknown fragment #{name}" }
      needed[name] = fragment
      queue.concat(fragment.spreads)
    end

    [operation.text, *needed.sort.map { |_name, fragment| fragment.text }].join("\n\n")
  end
end
