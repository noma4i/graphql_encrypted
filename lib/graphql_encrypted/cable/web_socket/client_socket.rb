class GraphqlEncrypted::Cable::WebSocket::ClientSocket < ActionCable::Connection::ClientSocket
  def initialize(env, event_target, event_loop, protocols)
    @env = env
    @event_target = event_target
    @event_loop = event_loop
    @url = self.class.determine_url(env)
    @close_params = ['', 1006]
    @ready_state = CONNECTING
    @driver = ::WebSocket::Driver.rack(self, protocols: protocols, max_length: GraphqlEncrypted::Cable::Limits.client_frame_bytes)
    @driver.on(:open) { open }
    @driver.on(:message) { |event| receive_message(event.data) }
    @driver.on(:close) { |event| begin_close(event.reason, event.code) }
    @driver.on(:error) { |event| emit_error(event.message) }
    @stream = ActionCable::Connection::Stream.new(@event_loop, self)
  end

  def close(code = nil, reason = nil)
    @ready_state = CLOSING unless @ready_state == CLOSED

    @driver.close(reason || '', code || GraphqlEncrypted::Cable::Codes::Close::NORMAL)
  end
end
