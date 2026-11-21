require 'test_helper'
require_relative 'support/echo_socket_server'
require_relative 'support/negotiated_socket'

class CableSocketTest < Minitest::Test
  Socket = GraphqlEncrypted::Cable::Client::Socket

  def test_the_socket_upgrades_exchanges_text_and_receives_a_close
    server = EchoSocketServer.new
    socket = Socket.new(url: server.url, tls: false)
    socket.send_text('hello')
    assert_equal 'hello', socket.next_event(5)
    socket.close(1000, 'finished')
    closed = socket.next_event(5)
    assert_equal [1000, 'finished'], [closed.code, closed.reason]
    socket.terminate
    socket.terminate
    socket.write('after close')
    assert_equal 1006, socket.next_event(5).code
  ensure
    socket&.terminate
    server&.close
  end

  def test_tls_handshake_waits_for_writability_and_then_uses_the_negotiated_socket
    server = EchoSocketServer.new
    raw = TCPSocket.new('127.0.0.1', URI(server.url).port)
    ssl = NegotiatedSocket.new(raw)
    ::Socket.expects(:tcp).returns(raw)
    OpenSSL::SSL::SSLSocket.expects(:new).returns(ssl)
    socket = Socket.new(url: server.url.sub('ws:', 'wss:'), timeout: 5)
    socket.send_text('negotiated')
    assert_equal 'negotiated', socket.next_event(5)
  ensure
    socket&.terminate
    raw&.close unless raw&.closed?
    server&.close
  end
end
