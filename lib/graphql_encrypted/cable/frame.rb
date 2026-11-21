# Frames of the socket: compact JWE (alg dir, enc A256GCM) under a per-direction key, each with a counter n and a type t.
# A schema per direction lists the types with their required and optional fields; anything else closes the socket.
#
# @see GraphqlEncrypted::Cable::StreamKeys
# @see GraphqlEncrypted::Cable::Codes
module GraphqlEncrypted::Cable::Frame
  HEADER = '{"alg":"dir","enc":"A256GCM"}'.freeze
  ID_FORMAT = /\A[A-Za-z0-9_-]{1,64}\z/
  UUID_FORMAT = /\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/
  SHA256_FORMAT = /\A\h{64}\z/

  VALUE_CHECKS = {
    id: ->(value) { value.is_a?(String) && ID_FORMAT.match?(value) },
    string: ->(value) { value.is_a?(String) },
    object: ->(value) { value.is_a?(Hash) },
    integer: ->(value) { value.is_a?(Integer) },
    boolean: ->(value) { [true, false].include?(value) },
    uuid: ->(value) { value.is_a?(String) && UUID_FORMAT.match?(value) },
    sha256: ->(value) { value.is_a?(String) && SHA256_FORMAT.match?(value) },
    failure: ->(value) { GraphqlEncrypted::Cable::Codes.values(GraphqlEncrypted::Cable::Codes::Failure).include?(value) },
    reason: ->(value) { GraphqlEncrypted::Cable::Codes.values(GraphqlEncrypted::Cable::Codes::Reason).include?(value) },
    close_code: ->(value) { GraphqlEncrypted::Cable::Codes.values(GraphqlEncrypted::Cable::Codes::Close).include?(value) }
  }.freeze

  SCHEMAS = {
    client_to_server: {
      'subscribe' => { required: { 'id' => :id, 'query' => :string }, optional: { 'variables' => :object, 'operationName' => :string } },
      'unsubscribe' => { required: { 'id' => :id }, optional: {} },
      'ping' => { required: { 'ts' => :integer }, optional: {} },
      'close' => { required: {}, optional: {} }
    },
    server_to_client: {
      'ready' => { required: { 'connectionId' => :uuid, 'challengeDigest' => :sha256 }, optional: {} },
      'subscribed' => { required: { 'id' => :id }, optional: {} },
      'next' => { required: { 'id' => :id, 'result' => :object }, optional: {} },
      'error' => { required: { 'code' => :failure, 'retryable' => :boolean }, optional: { 'id' => :id } },
      'complete' => { required: { 'id' => :id }, optional: {} },
      'pong' => { required: { 'ts' => :integer }, optional: {} },
      'closing' => { required: { 'code' => :close_code, 'reason' => :reason }, optional: {} }
    }
  }.freeze

  module_function

  def conforms?(direction, body)
    schema = SCHEMAS.fetch(direction)[body['t']]
    return false unless schema && counter?(body['n'])

    fields = body.except('n', 't')
    allowed = schema[:required].merge(schema[:optional])

    required_fields_valid?(schema, allowed, fields) && optional_fields_valid?(schema, allowed, fields)
  end

  def counter?(value)
    value.is_a?(Integer) && value >= 0
  end

  def required_fields_valid?(schema, allowed, fields)
    schema[:required].keys.all? { |name| fields.key?(name) && VALUE_CHECKS.fetch(allowed.fetch(name)).call(fields[name]) }
  end

  def optional_fields_valid?(schema, allowed, fields)
    (fields.keys - schema[:required].keys).all? { |name| allowed.key?(name) && (fields[name].nil? || VALUE_CHECKS.fetch(allowed.fetch(name)).call(fields[name])) }
  end

  def read_limit(direction)
    direction == :client_to_server ? GraphqlEncrypted::Cable::Limits.client_frame_bytes : GraphqlEncrypted::Cable::Limits.server_frame_bytes
  end
end
