require 'logger'
require 'rack'
require 'rack/mock_request'
require 'graphql_encrypted/testing'

# Runs the channel of the encrypted socket against a fake socket, a controllable worker pool and an in-memory pubsub.
module CableRig
  class Gate
    DEADLINE = 10

    def initialize
      @arrived = Queue.new
      @released = Queue.new
    end

    def hold
      @arrived << true

      @released.pop(timeout: DEADLINE)
    end

    def wait_arrived
      @arrived.pop(timeout: DEADLINE) || raise('The gate was never reached')
    end

    def open
      @released << true
    end
  end

  FakeSocket = GraphqlEncrypted::Testing::FakeSocket
  Work = GraphqlEncrypted::Testing::Work

  class EventLog
    %i[info warn error].each do |level|
      define_method(level) { |*| true }
    end
  end

  class Pubsub < ActionCable::SubscriptionAdapter::Inline
    attr_reader :live

    def initialize(*)
      super
      @live = Hash.new { |hash, name| hash[name] = [] }
    end

    def subscribe(channel, callback, success_callback = nil)
      @live[channel] << callback

      super
    end

    def unsubscribe(channel, callback)
      @live[channel].delete(callback)

      super
    end
  end

  IDENTIFIER = JSON.generate(channel: 'CableRigChannel')

  attr_reader :work, :pubsub

  def install_rig
    configure_cable
    configure(logger: EventLog.new)
    @work = Work.new
    @pubsub = nil
    @cable_server = GraphqlEncrypted::Cable::Server.new(channel: CableRigChannel)
    work = @work
    @cable_server.define_singleton_method(:worker_pool) { work }
    @cable_server.define_singleton_method(:event_loop) { work }
    @pubsub = Pubsub.new(@cable_server)
    pubsub = @pubsub
    @cable_server.define_singleton_method(:pubsub) { pubsub }
    ActionCable.server.define_singleton_method(:pubsub) { pubsub }
    @saved_logger = ActionCable.server.config.logger
    ActionCable.server.config.logger = Logger.new(nil)
    @connections = []

    CableRigSchema.reset_hooks
  end

  def remove_rig
    @connections.each { |connection| connection.send(:handle_close) }
    ActionCable.server.singleton_class.send(:remove_method, :pubsub)
    ActionCable.server.config.logger = @saved_logger

    clean_cable_redis
  end

  def new_credential
    encode(SecureRandom.random_bytes(32))
  end

  def open_peer(credential: new_credential, session: nil, ip: '203.0.113.7')
    session ||= start_cable_session(credential: credential)
    connection = GraphqlEncrypted::Cable::Connection.new(@cable_server, Rack::MockRequest.env_for('/cable', 'REMOTE_ADDR' => ip))
    socket = FakeSocket.new
    connection.instance_variable_set(:@websocket, socket)
    connection.send(:handle_open)
    @connections << connection

    GraphqlEncrypted::Testing::Peer.new(connection, socket, key: TestKeys::SERVER, audience: TestKeys::AUDIENCE, identifier: IDENTIFIER, credential: credential, session: session)
  end

  def ready_peer(**)
    peer = open_peer(**)
    peer.handshake
    peer.new_frames

    peer
  end

  def settle(thread)
    Thread.pass until thread.stop? || !thread.alive?
  end
end
