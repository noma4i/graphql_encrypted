# ActionCable WebSocket whose driver caps a client message at the client frame limit and closes with an explicit code.
#
# @see GraphqlEncrypted::Cable::Connection
class GraphqlEncrypted::Cable::WebSocket < ActionCable::Connection::WebSocket
  def initialize(env, event_target, event_loop, protocols: ActionCable::INTERNAL[:protocols])
    @websocket = ::WebSocket::Driver.websocket?(env) ? ClientSocket.new(env, event_target, event_loop, protocols) : nil
  end
end
