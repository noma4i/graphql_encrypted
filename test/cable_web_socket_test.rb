require 'test_helper'

class CableWebSocketTest < Minitest::Test
  def setup
    @outgoing = []
    wire = Object.new
    wire.define_singleton_method(:url) { 'ws://example.test/cable' }
    outgoing = @outgoing
    wire.define_singleton_method(:write) { |data| outgoing << data }
    @client = WebSocket::Driver.client(wire, protocols: ['actioncable-v1-json'])
    @received = []
    @closed = []
    @client.on(:message) { |event| @received << event.data }
    @client.on(:close) { |event| @closed << event.code }
    @client.start
    request = @outgoing.shift
    headers = request.split("\r\n").drop(1).filter_map do |line|
      key, value = line.split(': ', 2)
      ["HTTP_#{key.upcase.tr('-', '_')}", value] if value
    end.to_h
    @events = []
    target = Object.new
    events = @events
    %i[open message close error].each do |name|
      target.define_singleton_method("on_#{name}") { |*args| events << [name, *args] }
    end
    env = Rack::MockRequest.env_for('/cable', headers)
    env['stream.send'] = ->(bytes) { @client.parse(bytes) }
    env['async.callback'] = ->(response) { @stream = response.last }
    @socket = GraphqlEncrypted::Cable::WebSocket.new(env, target, CableRig::Work.new)

    @socket.rack_response
  end

  def test_the_rack_socket_transports_client_and_server_messages_and_explicit_close_codes
    @client.text('request')
    flush_client
    assert_includes @events, [:message, 'request']
    @socket.transmit('response')
    assert_equal ['response'], @received
    @socket.close(1001, 'restart')
    flush_client
    assert_equal [1001], @closed
    assert_includes @events, [:close, 'restart', 1001]

    @socket.close
  end

  def test_oversized_client_frames_close_with_a_protocol_size_error
    @client.text('x' * (GraphqlEncrypted::Cable::Limits.client_frame_bytes + 1))
    flush_client
    assert_equal [1009], @closed
    assert(@events.any? { |event| event.first == :error })

    refute(@events.any? { |event| event.first == :message })
  end

  private

  def flush_client
    @stream.receive(@outgoing.shift) until @outgoing.empty?
  end
end
