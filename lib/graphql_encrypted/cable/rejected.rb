# Raised to close the socket with a code and an optional client reason; +reason+ names the cause in the journal.
#
# @see GraphqlEncrypted::Cable::Codes::Close
class GraphqlEncrypted::Cable::Rejected < StandardError
  attr_reader :code, :reason, :close_reason

  def initialize(code, reason = nil, close_reason = '')
    super("Cable rejected with #{code}")
    @code = code
    @reason = reason
    @close_reason = close_reason
  end
end
