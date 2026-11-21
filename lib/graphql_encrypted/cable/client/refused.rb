class GraphqlEncrypted::Cable::Client::Refused < IOError
  attr_reader :code

  def initialize(code)
    super("The server closed the connection with #{code}")
    @code = code
  end
end
