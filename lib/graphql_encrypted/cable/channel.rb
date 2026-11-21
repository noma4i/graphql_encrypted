# Channel of the encrypted socket. A client sends one hello, then sealed frames: subscribe, unsubscribe, ping and close.
# Subclass it and name the schema and the session model; the subclass name is the channel identifier clients subscribe to.
#
#   class AppChannel < GraphqlEncrypted::Cable::Channel
#     schema AppSchema
#     session Session
#   end
#
# The session model answers +user+, +user_id+, +refusal+, +connect_presence+ and +touch_presence+ (see GraphqlEncrypted::Session). The GraphQL context carries
# current_user, current_user_id, encrypted_session, limiter_key and channel. Execution runs inside +configuration.with_user+.
# The stock +GraphQL::Subscriptions::ActionCableSubscriptions+ delivers to the channel: its subscription stream (a +stream_from+ without a block while a
# subscribe is open) belongs to that subscription, and its pushes reach the client as +next+ and +complete+ frames.
#
# @see GraphqlEncrypted::Cable::Server
# @see GraphqlEncrypted::Cable::Connection
class GraphqlEncrypted::Cable::Channel < ActionCable::Channel::Base
  Codes = GraphqlEncrypted::Cable::Codes
  Journal = GraphqlEncrypted::Cable::Journal
  Limits = GraphqlEncrypted::Cable::Limits
  Rejected = GraphqlEncrypted::Cable::Rejected
  Entry = Struct.new(:client_id, :subscription_id, :streams, :status, :pending)

  HANDLERS = { 'subscribe' => :open_subscription, 'unsubscribe' => :close_subscription, 'ping' => :answer_ping, 'close' => :close_connection }.freeze
  STREAM_WAIT = 5

  class_attribute :encrypted_schema, :encrypted_session_model, instance_writer: false

  class << self
    def schema(schema)
      self.encrypted_schema = schema
    end

    # @param model [Class, String] ActiveRecord model that includes GraphqlEncrypted::Session
    def session(model)
      self.encrypted_session_model = model
    end

    def action_methods
      @action_methods ||= Set.new(%w[hello frame])
    end
  end

  def subscribed
    reject unless connection.awaiting_hello?
    @entries = {}
    @closed = false
    @control_streams = []
    @collecting = nil
    @pending_streams = Set.new
    @table_lock = Mutex.new
    @send_lock = Mutex.new
    @execute_lock = Mutex.new
    @stream_lock = Mutex.new
    @streams_registered = ConditionVariable.new
    @subscribe_bucket = GraphqlEncrypted::Cable::TokenBucket.new(rate: Limits.subscribes_per_minute / 60.0, capacity: Limits.subscribe_burst)
  end

  def hello(data)
    return connection.close_with(Codes::Close::BAD_FRAME) unless connection.awaiting_hello? && data.keys.sort == %w[action hello] && data['hello'].is_a?(String)

    started_at = Time.current
    if Limits.hello_blocked?(connection.remote_ip)
      raise Rejected.new(Codes::Close::RATE_LIMITED, :hello_blocked, JSON.generate(code: 'hello_blocked', retryAfter: Limits.hello_retry_after))
    end

    establish(data['hello'])
  rescue Rejected => e
    refuse_hello(e.code, e.reason, started_at, e.close_reason)
  rescue ActiveRecord::ActiveRecordError => e
    GraphqlEncrypted.report(e)
    refuse_hello(Codes::Close::UNAVAILABLE, :database, started_at)
  rescue StandardError => e
    GraphqlEncrypted.report(e)
    Journal.error(connection.connection_id, e)
    refuse_hello(Codes::Close::INTERNAL, :internal, started_at)
  end

  def frame(data)
    guarded do
      raise Rejected, Codes::Close::BAD_FRAME unless connection.authenticated? && data.keys.sort == %w[action frame]

      body = @reader.open(data['frame'])
      GraphqlEncrypted::Diagnostics.socket(connection, session: @session, channel: self.class.name, command: body[:t], stream: body[:id], body: body)
      connection.touch_client_frame
      send(HANDLERS.fetch(body[:t]), body)
    end
  end

  def stream_from(broadcasting, callback = nil, coder: nil, &block)
    return if @closed || unsubscribed?

    name = String(broadcasting)
    handler = @stream_lock.synchronize { register_stream(name, callback || block, coder) }

    post_subscribe(name, handler)
  end

  def unsubscribed
    return unless @table_lock

    release_channel

    detach_entries.each { |entry| teardown(entry) }
  end

  def tick
    guarded do
      now = Time.current
      next connection.close_with(Codes::Close::TIMEOUT) if now - connection.last_client_frame_at > Limits.idle_deadline
      next close_gracefully(Codes::Reason::RECONNECT) if now - connection.opened_at >= Limits.connection_lifetime
      next if check_account(now)

      renew_lease
    end
  end

  def close_gracefully(reason)
    send_frame(:closing, code: Codes::Reason::CLOSE_CODE.fetch(reason), reason: reason)
  rescue Rejected
    nil
  ensure
    connection.close_with(Codes::Reason::CLOSE_CODE.fetch(reason))
  end

  private

  def session_model
    model = encrypted_session_model

    model.is_a?(String) ? model.constantize : model
  end

  def check_account(now)
    return false if now - @checked_at < Limits.session_check_interval

    @checked_at = now
    reason = account_closing_reason(session_model.find_by(id: @session.id))
    close_gracefully(reason) if reason

    reason.present?
  end

  def account_closing_reason(session)
    if session.nil? || session.ended_at
      Codes::Reason::LOGGED_OUT
    elsif session.refusal
      Codes::Reason::ACCOUNT_LOCKED
    elsif identity_changed?(session)
      Codes::Reason::RECONNECT
    end
  end

  def identity_changed?(session)
    [session.user_id, session.authenticated_at] != @hello_identity
  end

  def renew_lease
    return if Limits.renew(session_id: @session.id, user_id: @session.user_id, connection_id: connection.connection_id)

    admit_connection
  rescue Rejected => e
    raise unless e.code == Codes::Close::SUPERSEDED

    close_gracefully(Codes::Reason::SUPERSEDED)
  end

  def establish(token)
    challenge = connection.take_challenge
    result = GraphqlEncrypted::Cable::Hello.call(token, challenge: challenge, session: session_model)
    @session = result.session
    @hello_identity = [@session.user_id, @session.authenticated_at]
    @checked_at = Time.current
    open_frames(challenge, result)
    admit_connection
    connection.authenticate!(@session)
    connection.register_channel(self)
    watch_control_streams
    @maintenance = connection.event_loop.timer(Limits.maintenance_interval.to_f) { connection.worker_pool.async_invoke(self, :tick, connection: connection) }
    refuse_unregistered_streams unless await_streams
    @session.connect_presence
    Journal.event('hello_ok', connection_id: connection.connection_id, session_id: @session.id, user_id: @session.user_id)

    send_frame(:ready, connectionId: connection.connection_id, challengeDigest: Digest::SHA256.hexdigest(challenge))
  end

  def refuse_unregistered_streams
    release_channel
    Limits.leave(session_id: @session.id, user_id: @session.user_id, connection_id: connection.connection_id)

    raise Rejected.new(Codes::Close::UNAVAILABLE, :streams_unregistered)
  end

  def release_channel
    @table_lock.synchronize { @closed = true }
    @stream_lock.synchronize { @streams_registered.broadcast }
    @maintenance&.shutdown
    released = @stream_lock.synchronize { @control_streams.dup.tap { @control_streams.clear } }

    released.each { |name, handler| remove_stream(name, handler) }
  end

  def open_frames(challenge, result)
    secret = GraphqlEncrypted::Cable::StreamKeys.agree(connection.server_key, result.client_key)
    keys = GraphqlEncrypted::Cable::StreamKeys.derive(
      challenge: challenge, shared_secret: secret, response_key: result.response_key, kid: GraphqlEncrypted.kid,
      audience: GraphqlEncrypted.audience, path: GraphqlEncrypted.setting(:cable_path)
    )
    @writer = GraphqlEncrypted::Cable::Frame::Writer.new(keys.server_to_client)
    @reader = GraphqlEncrypted::Cable::Frame::Reader.new(keys.client_to_server, direction: :client_to_server)
  end

  def admit_connection
    Limits.release_pending(connection.remote_ip, connection.connection_id)

    Limits.join(session_id: @session.id, user_id: @session.user_id, connection_id: connection.connection_id, opened_at: connection.opened_at).each do |older|
      GraphqlEncrypted::Cable::Revoke.connection(older, reason: Codes::Reason::SUPERSEDED)
    end
  end

  def watch_control_streams
    [['connection', connection.connection_id], ['session', @session.id], ['user', @session.user_id]].each do |scope, id|
      stream_from(GraphqlEncrypted::Cable::Revoke.stream(scope, id), coder: ActiveSupport::JSON) { |message| revoke(message) }
    end
  end

  def revoke(message)
    reason = message['reason'] if message.is_a?(Hash) && message['type'] == 'revoke'
    guarded { close_gracefully(reason) } if Codes::Reason::CLOSE_CODE.key?(reason)
  end

  def refuse_hello(code, reason, started_at, close_reason = '')
    Journal.event('hello_fail', connection_id: connection.connection_id, code: code, reason: reason)
    record_failed_hello if code == Codes::Close::UNAUTHENTICATED && !GraphqlEncrypted::Cable::Hello::SESSION_STATE_REASONS.include?(reason)

    connection.refuse_after_floor(code, started_at, close_reason)
  end

  def record_failed_hello
    Limits.record_hello_failure(connection.remote_ip)
  rescue Rejected
    Journal.event('hello_failure_uncounted', connection_id: connection.connection_id)
  end

  def guarded
    yield
  rescue Rejected => e
    connection.close_with(e.code)
  rescue ActiveRecord::ActiveRecordError => e
    GraphqlEncrypted.report(e)
    connection.close_with(Codes::Close::UNAVAILABLE)
  rescue StandardError => e
    GraphqlEncrypted.report(e)
    Journal.error(connection.connection_id, e)
    connection.close_with(Codes::Close::INTERNAL)
  end

  def open_subscription(body)
    id = body[:id]
    failure = admission_failure(id) || document_failure(body)
    return reply_error(id, failure) if failure

    entry = Entry.new(id, nil, [], :opening, [])
    failure = start_subscription(entry, body)
    return abandon_subscription(id, entry, failure) if failure

    announce(entry)
  rescue StandardError => e
    raise if e.is_a?(Rejected)

    GraphqlEncrypted.report(e)
    abandon_subscription(id, entry, Codes::Failure::INTERNAL)
  end

  def start_subscription(entry, body)
    result = @execute_lock.synchronize { execute_collecting(entry, body) }
    entry.subscription_id = result.context[:subscription_id]
    errors = result.to_h['errors']

    if errors.present? || entry.subscription_id.nil?
      error_code(errors)
    elsif !await_streams
      Codes::Failure::INTERNAL
    end
  end

  def announce(entry)
    outcome = @table_lock.synchronize { publish_entry(entry) }
    teardown(entry) unless outcome == :live
    Journal.event('subscribe', connection_id: connection.connection_id) if outcome == :live
  end

  def publish_entry(entry)
    return :refused if @closed

    @entries[entry.client_id] = entry
    send_frame(:subscribed, id: entry.client_id)
    entry.status = :live
    finished = false
    entry.pending.each do |data|
      finished = deliver_update(entry, data)
      break if finished
    end
    entry.pending.clear

    finished ? :finished : :live
  end

  def admission_failure(id)
    failure = @table_lock.synchronize { table_failure(id) }
    return failure if failure

    Codes::Failure::RATE_LIMITED unless @subscribe_bucket.take
  end

  def table_failure(id)
    return Codes::Failure::DUPLICATE_ID if @entries.key?(id)

    Codes::Failure::TOO_MANY_SUBSCRIPTIONS if @entries.size >= Limits.subscriptions
  end

  def document_failure(body)
    document = GraphQL.parse(body[:query], max_tokens: encrypted_schema.max_query_string_tokens)
    operations = document.definitions.grep(GraphQL::Language::Nodes::OperationDefinition)
    operation = body[:operationName] ? operations.find { |candidate| candidate.name == body[:operationName] } : (operations.first if operations.one?)

    if operation.nil?
      Codes::Failure::INVALID_INPUT
    elsif operation.operation_type != 'subscription'
      Codes::Failure::OPERATION_NOT_ALLOWED
    end
  rescue GraphQL::ParseError
    Codes::Failure::INVALID_INPUT
  end

  def execute(body)
    GraphqlEncrypted.with_user(@session.user) do
      encrypted_schema.execute(
        body[:query], variables: body[:variables] || {}, operation_name: body[:operationName],
        context: {
          current_user: @session.user, current_user_id: @session.user_id, encrypted_session: @session,
          limiter_key: "session:#{@session.id}", channel: self
        }
      )
    end
  end

  def execute_collecting(entry, body)
    @stream_lock.synchronize { @collecting = entry }

    execute(body)
  ensure
    @stream_lock.synchronize { @collecting = nil }
  end

  def error_code(errors)
    code = errors&.first&.dig('extensions', 'code')

    Codes.values(Codes::Failure).include?(code) ? code : Codes::Failure::INVALID_INPUT
  end

  def abandon_subscription(id, entry, code)
    teardown(entry) if entry

    reply_error(id, code)
  end

  def register_stream(name, user_handler, coder)
    entry = @collecting
    raise ArgumentError, 'A stream without a block belongs to the subscription that is being opened' unless user_handler || entry

    handler = worker_pool_stream_handler(name, user_handler || ->(data) { route_update(entry, data) }, coder: user_handler ? coder : ActiveSupport::JSON)
    @pending_streams.add(handler)
    (entry ? entry.streams : @control_streams) << [name, handler]

    handler
  end

  def post_subscribe(name, handler)
    connection.server.event_loop.post do
      pending = @stream_lock.synchronize { @pending_streams.include?(handler) }
      pubsub.subscribe(name, handler, -> { stream_registered(handler) }) if pending && !@closed
    end
  end

  def remove_stream(name, handler)
    @stream_lock.synchronize do
      @pending_streams.delete(handler)
      @streams_registered.broadcast
    end

    connection.server.event_loop.post { pubsub.unsubscribe(name, handler) }
  end

  def route_update(entry, data)
    GraphqlEncrypted::Diagnostics.scoped do
      GraphqlEncrypted::Diagnostics.socket(connection, session: @session, channel: self.class.name, command: 'next', stream: entry.client_id)
      guarded { push_update(entry, data) }
    end
  end

  def push_update(entry, data)
    finished = @table_lock.synchronize do
      if entry.status == :live
        deliver_update(entry, data)
      else
        entry.pending << data if entry.status == :opening
        false
      end
    end

    teardown(entry) if finished
  end

  def detach_entries
    @table_lock.synchronize do
      @entries.values.tap do |entries|
        @entries.clear
        entries.each { |entry| entry.status = :closed }
      end
    end
  end

  def close_subscription(body)
    entry = @table_lock.synchronize do
      @entries.delete(body[:id])&.tap { |removed| removed.status = :closed }
    end
    return unless entry

    teardown(entry)

    Journal.event('unsubscribe', connection_id: connection.connection_id)
  end

  def answer_ping(body)
    @session.touch_presence

    send_frame(:pong, ts: body[:ts])
  end

  def close_connection(_body)
    connection.close_with(Codes::Close::NORMAL)
  end

  def teardown(entry)
    @table_lock.synchronize { entry.status = :closed }
    encrypted_schema.subscriptions.delete_subscription(entry.subscription_id) if entry.subscription_id

    entry.streams.each { |name, handler| remove_stream(name, handler) }
  end

  def deliver_update(entry, data)
    result = data['result']
    return finish_subscription(entry) if result.nil? && data['more'] == false
    return false if result.nil?

    send_frame(:next, id: entry.client_id, result: result)
    Journal.event('update', connection_id: connection.connection_id, field: result['data']&.keys&.first) if GraphqlEncrypted.option(:cable_log_updates)

    data['more'] == false ? finish_subscription(entry) : false
  rescue GraphqlEncrypted::Cable::Frame::TooLarge => e
    GraphqlEncrypted.report(e)
    Journal.event('oversized_update', connection_id: connection.connection_id)
    reply_error(entry.client_id, Codes::Failure::INTERNAL)

    false
  end

  def finish_subscription(entry)
    send_frame(:complete, id: entry.client_id)
    entry.status = :closed
    @entries.delete(entry.client_id)

    true
  end

  def reply_error(id, code)
    send_frame(:error, id: id, code: code, retryable: Codes::Failure::RETRYABLE.include?(code))
  end

  def send_frame(type, **fields)
    @send_lock.synchronize do
      connection.transmit(identifier: @identifier, message: { frame: @writer.seal(type, **fields) })
    end
  end

  def stream_registered(handler)
    @stream_lock.synchronize do
      @pending_streams.delete(handler)
      @streams_registered.broadcast
    end
  end

  def await_streams
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + STREAM_WAIT

    @stream_lock.synchronize do
      until @pending_streams.empty? || @closed
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        return false unless remaining.positive?

        @streams_registered.wait(@stream_lock, remaining)
      end

      @pending_streams.empty?
    end
  end
end
