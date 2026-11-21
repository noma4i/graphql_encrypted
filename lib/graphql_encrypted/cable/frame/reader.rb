class GraphqlEncrypted::Cable::Frame::Reader
  def initialize(key, direction:, budget: GraphqlEncrypted::Cable::Limits.frames_per_key)
    @key = key
    @direction = direction
    @budget = budget
    @expected = 0
  end

  def open(token)
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::GOING_AWAY if @expected >= @budget

    body = decrypt(token)
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::BAD_FRAME unless GraphqlEncrypted::Cable::Frame.conforms?(@direction, body)
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::COUNTER_MISMATCH unless body['n'] == @expected

    @expected += 1

    body.symbolize_keys
  end

  private

  def decrypt(token)
    segments = token.is_a?(String) && token.bytesize <= GraphqlEncrypted::Cable::Frame.read_limit(@direction) ? token.split('.', -1) : []
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::BAD_FRAME unless compact_jwe?(segments) && Base64.urlsafe_decode64(segments[0]) == GraphqlEncrypted::Cable::Frame::HEADER

    body = JSON.parse(JSON::JWE.decode(token, @key, ['dir'], ['A256GCM']).plain_text)
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::BAD_FRAME unless body.is_a?(Hash)

    body
  rescue JSON::JWT::Exception, JSON::ParserError, ArgumentError, TypeError, EncodingError, OpenSSL::OpenSSLError
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::BAD_FRAME
  end

  def compact_jwe?(segments)
    segments.size == 5 && segments[1].empty?
  end
end
