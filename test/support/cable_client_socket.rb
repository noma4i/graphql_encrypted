class CableClientSocket
  attr_accessor :time, :answer
  attr_reader :frames, :terminated, :events

  def initialize(peer)
    @peer = peer
    @offset = 0
    @time = 0.0
    @answer = true
    @frames = []
    @events = []
  end

  def send_text(text)
    @frames << JSON.parse(text)
    @peer.connection.receive(text) if answer
  end

  def next_event(timeout)
    return @events.shift unless @events.empty?

    message = @peer.socket.sent[@offset]
    if message
      @offset += 1
      return JSON.generate(message)
    end
    if @peer.socket.closed
      return GraphqlEncrypted::Cable::Client::Socket::Closed.new(*@peer.socket.closed)
    end

    @time += timeout

    nil
  end

  def terminate
    @terminated = true

    @peer.connection.disconnect
  end
end
