# Schema plugin (+use GraphqlEncrypted::Errors+): any StandardError a resolver raises is reported through GraphqlEncrypted.report,
# so +expected_errors+, the secret filter and the session tags apply, and the client gets the INTERNAL failure code marked retryable.
# More specific +rescue_from+ handlers of the schema win over it.
#
# @see GraphqlEncrypted.report
module GraphqlEncrypted::Errors
  MESSAGE = 'The request failed, try again later'.freeze

  def self.use(schema, **)
    schema.rescue_from(StandardError) do |error, *|
      GraphqlEncrypted.report(error)

      raise GraphQL::ExecutionError.new(MESSAGE, extensions: { code: GraphqlEncrypted::Cable::Codes::Failure::INTERNAL, retryable: true })
    end
  end
end
