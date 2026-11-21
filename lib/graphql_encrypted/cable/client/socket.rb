class GraphqlEncrypted::Cable::Client::Socket
  Closed = Data.define(:code, :reason)

  attr_reader :url

  # @param timeout [Numeric] one deadline for the TCP connect, the TLS handshake and the WebSocket upgrade
  def initialize(url:, tls: true, timeout: 10)
    @url = url
    @deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    @timeout = timeout
    @events = Queue.new
    @opened = Queue.new
    @write_lock = Mutex.new
    establish(URI(url), tls)
  end

  def write(data)
    @write_lock.synchronize { @io.write(data) }
  rescue IOError, SystemCallError
    @events << Closed.new(1006, '')
  end

  def send_text(text)
    @driver.text(text)
  end

  def next_event(timeout = @timeout)
    @events.pop(timeout: timeout)
  end

  def close(code = 1000, reason = '')
    @driver.close(reason, code)
  end

  def terminate
    @io.close if @io && !@io.closed?

    @reader&.join(1)
  end

  private

  def establish(uri, tls)
    @io = connect(uri, tls)
    @driver = WebSocket::Driver.client(self, protocols: [GraphqlEncrypted::Cable::Client::PROTOCOL])
    @driver.on(:open) { @opened << true }
    @driver.on(:message) { |event| @events << event.data }
    @driver.on(:close) { |event| @events << Closed.new(event.code, event.reason) }
    @driver.on(:error) { |event| @events << Closed.new(1006, event.message) }
    @driver.start
    @reader = Thread.new { read_loop }
    await_open
  rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
    terminate
    raise
  end

  def connect(uri, tls)
    @io = ::Socket.tcp(uri.host, uri.port, connect_timeout: remaining)
    return @io unless tls

    ssl = OpenSSL::SSL::SSLSocket.new(@io, OpenSSL::SSL::SSLContext.new.tap { |context| context.set_params(verify_mode: OpenSSL::SSL::VERIFY_PEER) })
    ssl.hostname = uri.host
    ssl.sync_close = true
    @io = ssl

    handshake(ssl)
  end

  def handshake(ssl)
    loop do
      step = ssl.connect_nonblock(exception: false)
      return ssl if step.equal?(ssl)

      ready = step == :wait_readable ? ssl.to_io.wait_readable(remaining) : ssl.to_io.wait_writable(remaining)
      raise IOError, 'TLS handshake did not finish in time' unless ready
    end
  end

  def await_open
    raise IOError, 'WebSocket did not open' unless @opened.pop(timeout: remaining)
  end

  def remaining
    [@deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC), 0.001].max
  end

  def read_loop
    loop { @driver.parse(@io.readpartial(65_536)) }
  rescue IOError, SystemCallError
    @events << Closed.new(1006, '')
  end
end
