# Request and response envelopes. A request is RSA-OAEP + A256GCM to the server key and names its destination;
# the response is A256GCM under the one-time responseKey the client put inside the request.
#
# @see GraphqlEncrypted::Client#call
module GraphqlEncrypted::Envelope
  WINDOW = 120
  CLOCK_SKEW = 30
  TOKEN = /\A[A-Za-z0-9_-]{43}\z/
  REQUEST_ID = /\A[0-9a-f-]{36}\z/
  FIELDS = %w[audience kid method path requestId issuedAt responseKey credential sequence body].freeze
  PUBLIC_FIELDS = (FIELDS - %w[credential sequence]).freeze

  module_function

  # @param fields [Array<String>] FIELDS for a session request, PUBLIC_FIELDS before a session exists
  # @note Raises ArgumentError for any request the server must not answer; KeyError when the server key is unusable.
  def open(token, method:, path:, fields: FIELDS)
    key = GraphqlEncrypted.server_key
    raise ArgumentError, 'Invalid protected header' unless header_object?(token)

    jwe = JSON::JWE.decode(token, key, ['RSA-OAEP'], ['A256GCM'])
    raise ArgumentError, 'Invalid protected header' unless (jwe.header.keys.map(&:to_s) - %w[alg enc]).empty?

    data = JSON.parse(jwe.plain_text)
    check(data, fields: fields, method: method, path: path)

    data
  end

  def check(data, fields:, method:, path:)
    raise ArgumentError, 'Invalid request' unless data.is_a?(Hash) && data.keys.sort == fields.sort
    raise ArgumentError, 'Invalid destination' unless data.values_at('audience', 'kid', 'method', 'path') == [GraphqlEncrypted.audience, GraphqlEncrypted.kid, method, path]
    raise ArgumentError, 'Invalid timestamp' unless data['issuedAt'].is_a?(Integer) && (Time.now.to_i - data['issuedAt']).between?(-CLOCK_SKEW, WINDOW)
    raise ArgumentError, 'Invalid credential' if fields.include?('credential') && !token?(data['credential'])
    raise ArgumentError, 'Invalid request id' unless data['requestId'].is_a?(String) && REQUEST_ID.match?(data['requestId'])
    raise ArgumentError, 'Invalid body' unless data['body'].is_a?(Hash)
    raise ArgumentError, 'Invalid response key' unless token?(data['responseKey']) && Base64.urlsafe_decode64(data['responseKey']).bytesize == 32
    raise ArgumentError, 'Invalid sequence' unless data['sequence'].nil? || (data['sequence'].is_a?(Integer) && data['sequence'].positive?)
  end

  # @param sequence [Integer, nil] set only when the answer consumed this sequence number
  # @param bound [Boolean] adds requestDigest, so a public client can tell the answer belongs to its request
  def seal(data, body, sequence: nil, bound: false)
    payload = { requestId: data.fetch('requestId') }
    payload[:requestDigest] = digest(data) if bound
    jwe = JSON::JWE.new(JSON.generate(payload.merge(sequence: sequence, body: body)))
    jwe.alg = 'dir'
    jwe.enc = 'A256GCM'
    jwe.encrypt!(Base64.urlsafe_decode64(data.fetch('responseKey')))

    jwe.to_s
  end

  # @note issuedAt is left out, so a resent request with a fresh timestamp has the same digest.
  def digest(data)
    Digest::SHA256.hexdigest(JSON.generate(data.except('issuedAt').sort.to_h))
  end

  def token?(value)
    value.is_a?(String) && TOKEN.match?(value)
  end

  def header_object?(token)
    JSON.parse(Base64.urlsafe_decode64(token.to_s.split('.', 2).first.to_s)).is_a?(Hash)
  rescue JSON::ParserError, ArgumentError
    false
  end
end
