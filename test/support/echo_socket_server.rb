class EchoSocketServer
  def initialize
    @listener = TCPServer.new('127.0.0.1', 0)
    @accepted = Queue.new
    @thread = Thread.new { serve }
  end

  def url
    "ws://127.0.0.1:#{@listener.addr[1]}/cable"
  end

  def close
    io = @accepted.pop(timeout: 5) || raise('No client connected')
    io.close unless io.closed?
    @thread.join(5) || raise('The echo server did not stop')

    @listener.close
  end

  private

  def serve
    io = @listener.accept
    @accepted << io
    driver = WebSocket::Driver.server(io, protocols: ['actioncable-v1-json'])
    driver.on(:connect) { driver.start }
    driver.on(:message) { |event| driver.text(event.data) }
    loop { driver.parse(io.readpartial(65_536)) }
  rescue IOError, SystemCallError
    io.close unless io.closed?
  end
end
