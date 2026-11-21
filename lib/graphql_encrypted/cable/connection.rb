# One socket of an encrypted client. Holds the state (awaiting hello, hello received, ready, refused), the challenge and server key,
# the frame bucket and the inbox that serializes incoming commands. Everything after the hello is done by the channel.
#
# @see GraphqlEncrypted::Cable::Server
# @see GraphqlEncrypted::Cable::Channel
class GraphqlEncrypted::Cable::Connection < ActionCable::Connection::Base
  Close = GraphqlEncrypted::Cable::Codes::Close
  Reason = GraphqlEncrypted::Cable::Codes::Reason
  Journal = GraphqlEncrypted::Cable::Journal
  Limits = GraphqlEncrypted::Cable::Limits
  COMMANDS = %w[subscribe message unsubscribe].freeze

  attr_reader :channel, :connection_id, :opened_at, :closing_code, :server_key, :session_id, :user_id, :last_client_frame_at

  def initialize(server, env, coder: ActiveSupport::JSON)
    super
    @websocket = GraphqlEncrypted::Cable::WebSocket.new(env, self, event_loop)
    @connection_id = SecureRandom.uuid
    @inbox = Queue.new
    @draining = Concurrent::AtomicBoolean.new(false)
    @state = :awaiting_hello
    @state_lock = Mutex.new
    @frame_bucket = GraphqlEncrypted::Cable::TokenBucket.new(rate: Limits.frames_per_second, capacity: Limits.frame_burst)
    @last_client_frame_at = Time.current
  end

  def connect
    Limits.admit_open(remote_ip, connection_id)
    @opened_at = Time.current
    @challenge = SecureRandom.random_bytes(32)
    @server_key = GraphqlEncrypted::Cable::StreamKeys.generate
    @kid = GraphqlEncrypted.kid
    @hello_deadline = Concurrent::ScheduledTask.execute(Limits.hello_deadline.to_f) { send_async(:expire_hello) }
    Journal.event('open', connection_id: connection_id)
  rescue GraphqlEncrypted::Cable::Rejected => e
    close_with(e.code)
  rescue KeyError, OpenSSL::PKey::PKeyError => e
    GraphqlEncrypted.report(e)
    close_with(Close::UNAVAILABLE)
  end

  def on_close(reason, code)
    Journal.event('closed', connection_id: connection_id, session_id: session_id, user_id: user_id, code: closing_code || code,
                            reason: reason.to_s.squish.first(Journal::MESSAGE_LENGTH).presence, initiator: closing_code ? 'server' : 'client')

    super
  end

  def disconnect
    @hello_deadline&.cancel
    @refusal_task&.cancel
    release_places

    Journal.event('disconnect', connection_id: connection_id, session_id: session_id, user_id: user_id)
  end

  def awaiting_hello?
    @state == :awaiting_hello
  end

  def authenticated?
    @state == :ready
  end

  def register_channel(channel)
    @channel = channel
  end

  def remote_ip
    request.remote_ip
  end

  def user_agent
    request.user_agent
  end

  def request_path
    request.path
  end

  def take_challenge
    @state_lock.synchronize do
      raise GraphqlEncrypted::Cable::Rejected.new(Close::UNAUTHENTICATED, :challenge_used) unless @challenge

      challenge = @challenge
      @challenge = nil
      @state = :hello_received

      challenge
    end
  end

  def authenticate!(session)
    @state_lock.synchronize do
      @session_id = session.id
      @user_id = session.user_id
      @state = :ready
    end

    @hello_deadline.cancel
  end

  def touch_client_frame
    @last_client_frame_at = Time.current
  end

  def expire_hello
    close_with(Close::TIMEOUT) if hello_overdue?
  end

  def refuse_after_floor(code, started_at, reason = '')
    @state = :refused
    @refusal_code = code
    @refusal_reason = reason
    delay = [Limits.hello_refusal_floor - (Time.current - started_at), 0].max
    @refusal_task = Concurrent::ScheduledTask.execute(delay) { send_async(:complete_refusal) }
  end

  def complete_refusal
    close_with(@refusal_code, @refusal_reason)
  end

  def close_with(code, reason = '')
    return if @state_lock.synchronize { @closing_code ? true : (@closing_code = code) && false }

    websocket.close(code, reason)

    Journal.event('close', connection_id: connection_id, code: code)
  end

  def close(reason: nil, reconnect: true)
    return close_with(Close::GOING_AWAY) unless authenticated? && @channel

    @channel.close_gracefully(Reason::SERVER_RESTART)
  end

  def receive(message)
    return close_with(Close::RATE_LIMITED) unless @frame_bucket.take

    @inbox << message

    drain_later
  end

  def dispatch_websocket_message(message)
    return if closing_code || !websocket.alive?

    command = parse(message)
    return close_with(Close::BAD_FRAME) unless command
    return close_with(Close::NORMAL) if command['command'] == 'unsubscribe'
    return close_with(Close::BAD_FRAME) if command['command'] == 'message' && subscriptions.identifiers.exclude?(command['identifier'])

    GraphqlEncrypted::Diagnostics.scoped do
      GraphqlEncrypted::Diagnostics.socket(self, command: command['command'])
      handle_channel_command(command)
    end
  rescue GraphqlEncrypted::Cable::Rejected => e
    close_with(e.code)
  rescue StandardError => e
    GraphqlEncrypted.report(e)
    Journal.error(connection_id, e)
    close_with(Close::INTERNAL)
  end

  def challenge_frame
    {
      type: 'challenge', v: GraphqlEncrypted::Cable::Hello::VERSION, challenge: GraphqlEncrypted::Cable::Hello.encode(@challenge), kid: @kid,
      x25519: GraphqlEncrypted::Cable::Hello.encode(@server_key.raw_public_key),
      limits: { maxFrameBytes: Limits.client_frame_bytes, maxSubscriptions: Limits.subscriptions }
    }
  end

  def drain
    while (message = next_message)
      dispatch_websocket_message(message)
    end
  ensure
    @draining.make_false
    drain_later unless @inbox.empty?
  end

  private

  def hello_overdue?
    !authenticated? && @state != :refused && Time.current - opened_at >= Limits.hello_deadline
  end

  def release_places
    Limits.release_pending(remote_ip, connection_id)
    Limits.leave(session_id: session_id, user_id: user_id, connection_id: connection_id) if session_id
  rescue GraphqlEncrypted::Cable::Rejected
    Journal.event('release_failed', connection_id: connection_id)
  end

  def drain_later
    send_async(:drain) if @draining.make_true
  end

  def next_message
    @inbox.pop(true)
  rescue ThreadError
    nil
  end

  def send_welcome_message
    return if closing_code

    super

    transmit(challenge_frame)
  end

  def channel_identifier
    { 'channel' => server.channel.name }
  end

  def parse(message)
    command = ActiveSupport::JSON.decode(message)

    command if command.is_a?(Hash) && COMMANDS.include?(command['command']) && command['identifier'].is_a?(String) && ActiveSupport::JSON.decode(command['identifier']) == channel_identifier
  rescue JSON::ParserError
    nil
  end

  def new_tagged_logger
    ActionCable::Connection::TaggedLoggerProxy.new(server.logger, tags: [])
  end
end
