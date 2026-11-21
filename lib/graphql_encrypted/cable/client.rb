require 'websocket/driver'
require 'socket'
require 'openssl'
require 'json'
require 'json/jwt'
require 'base64'

# Reference client of the encrypted socket. Pins the server key, performs the hello, seals frames and reconnects by a fixed policy.
#
#   client = GraphqlEncrypted::Cable::Client.new(origin: 'https://api.example.com', public_key: pem, pin: kid, credential: credential)
#   client.run([{ id: 'one', query: 'subscription { changes { id } }' }]) { |event| puts event }
#
# @see GraphqlEncrypted::Cable::Channel
class GraphqlEncrypted::Cable::Client
  PROTOCOL = 'actioncable-v1-json'.freeze
  VERSION = 1
  DEFAULT_PATH = '/cable'.freeze
  DEFAULT_PURPOSE = 'graphql_encrypted.ws.hello'.freeze
  DEFAULT_LABEL = 'graphql-encrypted-ws-v1'.freeze

  HANDSHAKE_TIMEOUT = 10
  PING_AFTER = 25
  PONG_WITHIN = 20

  attr_reader :connection_id

  # @param channel [String] class name of the server channel, the identifier clients subscribe to; +path+, +label+ and +purpose+ default to the
  #   configuration of the server side, +channel+ to +config.cable_channel+
  # @param timeout [Numeric] deadline of the default socket for the TCP connect, the TLS handshake and the upgrade
  def initialize(origin:, public_key:, pin:, credential:, channel: GraphqlEncrypted.setting(:cable_channel), path: GraphqlEncrypted.setting(:cable_path),
                 label: GraphqlEncrypted.setting(:cable_protocol_label), purpose: GraphqlEncrypted.setting(:cable_hello_purpose), socket_factory: nil, timeout: 10)
    @origin = URI(origin)
    @key = OpenSSL::PKey::RSA.new(public_key)
    raise ArgumentError, 'Untrusted server key' unless @key.n.num_bits >= 3072 && Digest::SHA256.hexdigest(@key.public_key.to_der) == pin
    raise ArgumentError, 'HTTPS is required' unless @origin.scheme == 'https' || (socket_factory && @origin.scheme == 'http')

    @pin = pin
    @credential = credential
    @identifier = JSON.generate(channel: channel)
    @path = path
    @label = label
    @purpose = purpose
    @socket_factory = socket_factory || ->(url) { Socket.new(url: url, timeout: timeout) }
  end

  def connect
    connected = false
    @socket = @socket_factory.call("#{@origin.scheme == 'https' ? 'wss' : 'ws'}://#{@origin.host}:#{@origin.port}#{@path}")
    challenge = await_message('challenge')
    @link = Link.new(challenge_frame: challenge, public_key: @key.public_key, pin: @pin, audience: @origin.to_s.delete_suffix('/'), credential: @credential,
                     path: @path, label: @label, purpose: @purpose)
    @last_sent = @last_received = now
    @ping_deadline = nil
    send_command('subscribe')
    await_message('confirm_subscription')
    send_command('message', JSON.generate(action: 'hello', hello: @link.hello))
    ready = next_event(HANDSHAKE_TIMEOUT)
    raise Refused, ready.code if ready.is_a?(Socket::Closed)
    raise ProtocolError, 'The server did not answer with ready' unless ready.is_a?(Hash) && ready['t'] == 'ready'

    @connection_id = ready['connectionId']
    connected = true

    self
  ensure
    terminate unless connected
  end

  def subscribe(id, query, variables: nil, operation_name: nil)
    send_frame(:subscribe, id: id, query: query, variables: variables, operationName: operation_name)
  end

  def unsubscribe(id)
    send_frame(:unsubscribe, id: id)
  end

  def ping
    send_frame(:ping, ts: (now * 1000).to_i)
  end

  def close
    send_frame(:close)
  end

  def next_event(timeout)
    deadline = now + timeout

    loop do
      return if now >= deadline

      keep_alive
      raw = @socket.next_event([deadline - now, 1.0].min)
      next if raw.nil? && !lost?
      return Socket::Closed.new(1006, 'No answer to ping') if raw.nil?
      return raw if raw.is_a?(Socket::Closed)

      frame = decode(raw)
      return frame if frame
    end
  end

  def terminate
    @socket&.terminate
  end

  def run(subscriptions, stop: -> { false }, sleeper: Kernel.method(:sleep))
    attempt = 0
    until stop.call
      started = now
      code = session(subscriptions, stop) { |event| yield event }
      attempt = 0 if now - started >= ReconnectPolicy::STABLE_AFTER
      delay = ReconnectPolicy.delay(code, attempt)
      return yield({ 't' => 'stopped', 'code' => code }) if delay.nil?

      sleeper.call(delay)
      attempt += 1
    end
  end

  private

  def session(subscriptions, stop)
    connect
    subscriptions.each { |subscription| subscribe(subscription.fetch(:id), subscription.fetch(:query), variables: subscription[:variables], operation_name: subscription[:operation_name]) }
    yield({ 't' => 'connected', 'connectionId' => connection_id })
    until stop.call
      event = next_event(1)
      next if event.nil?
      return event.code if event.is_a?(Socket::Closed)

      yield event
    end
    nil
  rescue Refused => e
    e.code
  rescue IOError, SystemCallError
    1006
  ensure
    terminate
  end

  def send_command(command, data = nil)
    @socket.send_text(JSON.generate({ command: command, identifier: @identifier, data: data }.compact))
  end

  def send_frame(type, **fields)
    send_command('message', JSON.generate(action: 'frame', frame: @link.seal(type, **fields.compact)))
    @last_sent = now
  end

  def await_message(type)
    deadline = now + HANDSHAKE_TIMEOUT

    loop do
      raw = @socket.next_event([deadline - now, 0.1].max)
      raise IOError, "No #{type} within #{HANDSHAKE_TIMEOUT} s" if raw.nil? || now > deadline
      raise Refused, raw.code if raw.is_a?(Socket::Closed)

      message = parse_message(raw)
      return message if message['type'] == type
      raise Refused, 4401 if message['type'] == 'reject_subscription'
    end
  end

  def decode(raw)
    message = parse_message(raw)['message']
    raise ProtocolError, 'Invalid message body' unless message.nil? || message.is_a?(Hash)

    token = message && message['frame']
    return unless token

    frame = @link.open(token)
    @last_received = now
    @ping_deadline = nil

    frame
  end

  def parse_message(raw)
    message = JSON.parse(raw)
    raise ProtocolError, 'Invalid message' unless message.is_a?(Hash)

    message
  rescue JSON::ParserError, TypeError
    raise ProtocolError, 'Invalid message'
  end

  def keep_alive
    return unless @link && now - [@last_sent, @last_received].max >= PING_AFTER && @ping_deadline.nil?

    ping
    @ping_deadline = now + PONG_WITHIN
  end

  def lost?
    @ping_deadline && now > @ping_deadline
  end

  def now
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end
end
