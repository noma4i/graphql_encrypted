class GraphqlEncrypted::Cable::Frame::Writer
  def initialize(key, budget: GraphqlEncrypted::Cable::Limits.frames_per_key)
    @key = key
    @budget = budget
    @n = 0
  end

  def seal(type, **fields)
    raise GraphqlEncrypted::Cable::Rejected, GraphqlEncrypted::Cable::Codes::Close::GOING_AWAY if @n >= @budget

    body = { 'n' => @n, 't' => type.to_s }.merge(fields.stringify_keys)
    raise ArgumentError, "Invalid #{type} frame" unless GraphqlEncrypted::Cable::Frame.conforms?(:server_to_client, JSON.parse(JSON.generate(body)))

    jwe = JSON::JWE.new(JSON.generate(body))
    jwe.alg = 'dir'
    jwe.enc = 'A256GCM'
    jwe.encrypt!(@key)
    token = jwe.to_s
    raise GraphqlEncrypted::Cable::Frame::TooLarge, "Frame of #{token.bytesize} bytes" if token.bytesize > GraphqlEncrypted::Cable::Limits.server_frame_bytes

    @n += 1

    token
  end
end
