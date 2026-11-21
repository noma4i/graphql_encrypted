require 'json/jwt'
require 'net/http'
require 'tempfile'

# Reference client: pins the server key, keeps the credential and the last sequence in a private state file,
# and resends an unanswered write with the same sequence until the server answers it.
#
#   client = GraphqlEncrypted::Client.new(origin: 'https://api.example.com', public_key: pem, pin: kid, state_file: 'session.json')
#   client.call('/api/graphql', { query: 'mutation { ... }' })
#   client.call('/api/graphql', { query: '{ viewer { id } }' }, read: true)
#
# @see GraphqlEncrypted::SecureController
class GraphqlEncrypted::Client
  def self.persisted_body(query: nil, sha256: nil, variables: nil, operation_name: nil)
    hash = sha256 || Digest::SHA256.hexdigest(query)

    { query: query, variables: variables, operationName: operation_name, extensions: { persistedQuery: { version: 1, sha256Hash: hash } } }.compact
  end

  def self.read_state(state_file)
    raise StateError, 'State file must be private to its owner' unless File.stat(state_file).mode.nobits?(0o077)

    state = JSON.parse(File.read(state_file))
    raise StateError, 'State file is damaged' unless state.is_a?(Hash) && state['credential'].is_a?(String) && state['sequence'].is_a?(Integer)

    state
  rescue JSON::ParserError
    raise StateError, 'State file is damaged'
  end

  def self.stored_credential(state_file)
    read_state(state_file).fetch('credential')
  end

  # @param pin [String] hex SHA-256 of the server public key DER, the kid the server checks
  # @param transport [#call, nil] (path, ciphertext) -> [status, body]; HTTPS POST when nil
  def initialize(origin:, public_key:, pin:, state_file:, transport: nil)
    @origin = URI(origin)
    @key = OpenSSL::PKey::RSA.new(public_key)
    raise ArgumentError, 'HTTPS is required' unless @origin.scheme == 'https' && ['', '/'].include?(@origin.path)
    raise ArgumentError, 'Untrusted server key' unless @key.n.num_bits >= GraphqlEncrypted::MIN_KEY_BITS && Digest::SHA256.hexdigest(@key.public_key.to_der) == pin

    @pin = pin
    @state_file = state_file
    @transport = transport || method(:send_http)
    initialize_state
  end

  # A write (read: false) holds the next sequence until the server answers it; a later call with another request
  # raises until retry_pending resolves the held one.
  def call(path, body, read: false)
    return read(path, body) if read

    with_state_lock do
      state = load_state
      pending = state['pending'] || prepare(path, body, state)
      raise ArgumentError, 'Resolve the pending request first' unless pending['path'] == path && pending['body'] == JSON.parse(JSON.generate(body))

      state['pending'] = pending
      save_state(state)
      answer = exchange(pending)
      raise SequenceConflict, 'The server holds another request for this sequence' if answer.dig('body', 'error') == 'SEQUENCE_CONFLICT'

      settle(state, pending, answer)

      answer
    end
  end

  def retry_pending
    pending = load_state.fetch('pending')

    call(pending.fetch('path'), pending.fetch('body'))
  end

  # Request to a GraphqlEncrypted::PublicController; the answer must carry the digest of this request.
  def public_request(path, body)
    data = envelope_fields(path, body)
    answer = exchange(data)
    raise IOError, 'Response is not bound to this request' unless answer['requestDigest'] == Digest::SHA256.hexdigest(JSON.generate(data.except('issuedAt').sort.to_h))

    answer
  end

  private

  # An answer without a sequence did not use it (a persisted query miss), so the same sequence is free again.
  def settle(state, pending, answer)
    raise IOError, 'Response belongs to another sequence' unless answer['sequence'].nil? || answer['sequence'] == pending['sequence']

    state.delete('pending')
    state['sequence'] = pending['sequence'] if answer['sequence']
    return File.delete(@state_file) if answer.dig('body', 'revoked') == true

    save_state(state)
  end

  def read(path, body)
    answer = exchange(prepare(path, body, load_state, read: true))
    return answer unless answer.dig('body', 'error') == 'REPLAYED_REQUEST'

    exchange(prepare(path, body, load_state, read: true))
  end

  def with_state_lock(&)
    File.open("#{@state_file}.lock", File::RDWR | File::CREAT, 0o600) do |lock|
      lock.flock(File::LOCK_EX)
      yield
    end
  end

  def initialize_state
    with_state_lock do
      next load_state if File.exist?(@state_file)

      save_state(credential: SecureRandom.urlsafe_base64(32), sequence: 0)
    end
  end

  def load_state
    self.class.read_state(@state_file)
  end

  def save_state(state)
    Tempfile.create('.graphql-encrypted-state', File.dirname(@state_file)) do |file|
      file.chmod(0o600)
      file.write(JSON.generate(state))
      file.flush
      file.fsync
      File.rename(file.path, @state_file)
    end

    File.open(File.dirname(@state_file)) { |directory| directory.fsync }
  end

  def prepare(path, body, state, read: false)
    envelope_fields(path, body).merge('credential' => state.fetch('credential'), 'sequence' => (state.fetch('sequence') + 1 unless read))
  end

  def envelope_fields(path, body)
    {
      'audience' => @origin.to_s.delete_suffix('/'), 'kid' => @pin, 'method' => 'POST', 'path' => path,
      'requestId' => SecureRandom.uuid, 'issuedAt' => Time.now.to_i,
      'responseKey' => SecureRandom.urlsafe_base64(32), 'body' => JSON.parse(JSON.generate(body))
    }
  end

  def exchange(data)
    jwe = JSON::JWE.new(JSON.generate(data.merge('issuedAt' => Time.now.to_i)))
    jwe.alg = 'RSA-OAEP'
    jwe.enc = 'A256GCM'
    jwe.encrypt!(@key.public_key)
    status, ciphertext = deliver(data.fetch('path'), jwe.to_s)
    raise (status == 503 ? Retryable : Rejected), "HTTP #{status}" unless status == 200

    reply = JSON::JWE.decode(ciphertext, Base64.urlsafe_decode64(data.fetch('responseKey')), ['dir'], ['A256GCM'])
    raise IOError, 'Invalid response header' unless (reply.header.keys.map(&:to_s) - %w[alg enc]).empty?

    answer = JSON.parse(reply.plain_text)
    raise IOError, 'Response belongs to another request' unless answer['requestId'] == data['requestId']

    answer
  end

  def deliver(path, ciphertext)
    @transport.call(path, ciphertext)
  rescue Retryable, Rejected
    raise
  rescue IOError, SystemCallError, SocketError, Timeout::Error => e
    raise Retryable, e.message
  end

  def send_http(path, ciphertext)
    raise ArgumentError, 'Invalid API path' unless path.start_with?('/') && !path.include?('?')

    request = Net::HTTP::Post.new(path, 'Content-Type' => 'application/jose')
    request.body = ciphertext
    response = Net::HTTP.start(@origin.host, @origin.port, use_ssl: true) { |http| http.request(request) }

    [response.code.to_i, response.body]
  end
end
