# Wire codes of the socket: WebSocket close codes, subscription failure codes and the reasons of a graceful close.
#
# @see GraphqlEncrypted::Cable::Frame
module GraphqlEncrypted::Cable::Codes
  module_function

  # Every code of one group (Close, Failure or Reason).
  def values(group)
    group.constants.map { |name| group.const_get(name) }
  end
end
