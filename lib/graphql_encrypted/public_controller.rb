# Base controller for requests sent before a session exists (bootstrap config, a help form). A subclass
# defines encrypted_answer(body) and returns a Hash; the answer is sealed with requestDigest, so only the
# sender of this exact request accepts it. +diagnostics_operation+ names the endpoint in error reports (default: the controller name).
#
#   class ConfigsController < GraphqlEncrypted::PublicController
#     diagnostics_operation 'config'
#
#     private
#
#     def encrypted_answer(body)
#       { minimumVersion: '1.2.0' }
#     end
#   end
#
# @see GraphqlEncrypted::BaseController
# @see GraphqlEncrypted::Client#public_request
class GraphqlEncrypted::PublicController < GraphqlEncrypted::BaseController
  class_attribute :operation_label, instance_writer: false

  class << self
    def diagnostics_operation(label)
      self.operation_label = label
    end
  end

  def create
    serve_encrypted(GraphqlEncrypted::Envelope::PUBLIC_FIELDS) do |data|
      report_request(nil, data)

      seal(data, encrypted_answer(data['body']), bound: true)
    end
  end

  private

  def diagnostics_operation
    operation_label || controller_name
  end
end
