# Opens the hello of a new socket: an RSA-OAEP envelope with the challenge, the client X25519 key, the response key and the session
# credential. Every refusal closes with 4401; the reason is kept for the journal only.
#
# @see GraphqlEncrypted::Cable::Channel
# @see GraphqlEncrypted::Cable::StreamKeys
module GraphqlEncrypted::Cable::Hello
  Result = Data.define(:session, :response_key, :client_key)

  FIELDS = %w[v purpose audience kid method path challenge clientKey credential responseKey].freeze
  METHOD = 'GET'.freeze
  VERSION = 1
  TOKEN = /\A[A-Za-z0-9_-]{43}\z/
  SESSION_STATE_REASONS = %i[session_unknown session_not_authenticated session_ended user_unavailable].freeze

  module_function

  # @param session [Class] model that includes GraphqlEncrypted::Session
  def call(token, challenge:, session:)
    data = open(token)
    check_destination(data)
    refuse(:challenge) unless data['challenge'].is_a?(String) && ActiveSupport::SecurityUtils.secure_compare(encode(challenge), data['challenge'])
    credential = data['credential']
    refuse(:credential) unless credential.is_a?(String) && TOKEN.match?(credential)
    response_key = key_bytes(data['responseKey'], :response_key)
    client_key = key_bytes(data['clientKey'], :client_key)

    Result.new(session: find_session(session, credential), response_key: response_key, client_key: client_key)
  end

  def encode(bytes)
    Base64.urlsafe_encode64(bytes, padding: false)
  end

  def jwe_shaped?(token)
    return false unless token.is_a?(String)

    token.bytesize <= GraphqlEncrypted::Cable::Limits.client_frame_bytes && token.count('.') == 4
  end

  def open(token)
    refuse(:jwe) unless jwe_shaped?(token)
    refuse(:jwe) unless GraphqlEncrypted::Envelope.header_object?(token)

    jwe = JSON::JWE.decode(token, GraphqlEncrypted.server_key, ['RSA-OAEP'], ['A256GCM'])
    refuse(:jwe) unless (jwe.header.keys.map(&:to_s) - %w[alg enc]).empty?

    data = JSON.parse(jwe.plain_text)
    refuse(:fields) unless data.is_a?(Hash) && data.keys.sort == FIELDS.sort

    data
  rescue JSON::JWT::Exception, JSON::ParserError, ArgumentError
    refuse(:jwe)
  end

  def check_destination(data)
    refuse(:version) unless data['v'] == VERSION
    refuse(:purpose) unless data['purpose'] == GraphqlEncrypted.setting(:cable_hello_purpose)
    refuse(:audience) unless data['audience'] == GraphqlEncrypted.audience
    refuse(:kid) unless data['kid'] == GraphqlEncrypted.kid
    refuse(:method) unless data['method'] == METHOD
    refuse(:path) unless data['path'] == GraphqlEncrypted.setting(:cable_path)
  end

  def key_bytes(text, reason)
    refuse(reason) unless text.is_a?(String) && TOKEN.match?(text)
    Base64.urlsafe_decode64(text)
  rescue ArgumentError
    refuse(reason)
  end

  def find_session(model, credential)
    session = model.find_by_credential(credential)
    refuse(:session_unknown) unless session
    refuse(:session_not_authenticated) unless session.authenticated_at && session.user
    refuse(:session_ended) if session.ended_at
    refuse(:user_unavailable) if session.refusal

    session
  end

  def refuse(reason)
    raise GraphqlEncrypted::Cable::Rejected.new(GraphqlEncrypted::Cable::Codes::Close::UNAUTHENTICATED, reason)
  end
end
