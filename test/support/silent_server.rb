class SilentServer
  def initialize
    @server = TCPServer.new('127.0.0.1', 0)
    @accepted = Queue.new
    @release = Queue.new
    @thread = Thread.new do
      socket = @server.accept
      @accepted << true
      @release.pop
    ensure
      socket&.close
    end
  end

  def addr
    @server.addr
  end

  def close
    @accepted.pop(timeout: 5) || raise('The client never connected')
    @release << true
    @thread.join(5) || raise('The server did not stop')

    @server.close
  end
end
