# HTTP side shared by both controllers: accepts only a bare application/jose POST, caps the body,
# opens the envelope, reports the request to GraphqlEncrypted::Diagnostics and renders the sealed answer.
#
# @see GraphqlEncrypted::SecureController
# @see GraphqlEncrypted::PublicController
class GraphqlEncrypted::BaseController < ActionController::API
  MAX_BODY_BYTES = 256 * 1024
  MEDIA_TYPE = 'application/jose'.freeze
  REFUSED_HEADERS = %w[Authorization Cookie].freeze
  INVALID_REQUEST = { error: 'INVALID_REQUEST' }.freeze

  abstract!

  class << self
    # Headers that make a request invalid: Authorization, Cookie and the configured ones.
    def refused_headers
      REFUSED_HEADERS + GraphqlEncrypted.option(:refuse_headers)
    end
  end

  private

  def serve_encrypted(fields, &answer)
    GraphqlEncrypted::Diagnostics.call { process_encrypted(fields, &answer) }
  end

  def process_encrypted(fields)
    response.headers['Cache-Control'] = 'no-store'
    return head :bad_request unless jose_request?
    return head :content_too_large if request.content_length.to_i > MAX_BODY_BYTES

    raw = request.body.read(MAX_BODY_BYTES + 1).to_s
    return head :content_too_large if raw.bytesize > MAX_BODY_BYTES

    report_request(nil, nil)
    GraphqlEncrypted.server_key
    data = open_envelope(raw, fields)
    return head :bad_request unless data

    render plain: yield(data), content_type: MEDIA_TYPE
  rescue KeyError, ActiveRecord::ActiveRecordError => e
    GraphqlEncrypted.report(e)
    head :service_unavailable
  end

  def jose_request?
    request.media_type == MEDIA_TYPE && request.query_string.empty? && self.class.refused_headers.none? { |header| request.headers[header].present? }
  end

  def open_envelope(raw, fields)
    GraphqlEncrypted::Envelope.open(raw, method: request.request_method, path: request.path, fields: fields)
  rescue JSON::JWT::Exception, JSON::ParserError, ArgumentError
    nil
  end

  def report_request(session, data)
    GraphqlEncrypted::Diagnostics.request(request: request, operation: diagnostics_operation, session: session, data: data)
  end

  def seal(data, body, **)
    GraphqlEncrypted::Envelope.seal(data, body, **)
  end
end
