require 'json'
require 'json/jwt'
require 'securerandom'
require 'action_cable'
require 'graphql_encrypted'

# Test doubles for the encrypted socket: a fake websocket, an inline worker pool and a client peer. Require it from a test helper only.
module GraphqlEncrypted::Testing
  class FakeSocket
    attr_reader :sent, :closed

    def initialize
      @sent = []
      @closed = nil
      @gate = nil
    end

    def hold_next_transmit(gate)
      @gate = gate
    end

    def alive?
      @closed.nil?
    end

    def possible?
      true
    end

    def transmit(text)
      gate = @gate
      @gate = nil
      gate&.hold

      @sent << JSON.parse(text)
    end

    def close(code = nil, reason = nil)
      @closed = [code, reason] if @closed.nil?
    end

    def protocol
      ActionCable::INTERNAL[:protocols].first
    end

    def rack_response
      [-1, {}, []]
    end
  end

  class Timer
    def initialize
      @shut_down = false
    end

    def shutdown
      @shut_down = true
    end

    def shut_down?
      @shut_down
    end
  end

  # Event loop and worker pool in one. Jobs run inline until +defer_jobs+ queues them or +stall_posts+ holds the event loop.
  class Work
    attr_reader :timers

    def initialize
      @timers = []
      @jobs = Queue.new
      @held = []
      @posted = Queue.new
      @defer = false
      @stall = false
    end

    def defer_jobs
      @defer = true
    end

    def stall_posts
      @stall = true
    end

    def run_next_job
      @jobs.pop(true).call
    end

    def run_all_jobs
      run_next_job until @jobs.empty?
    end

    def run_held_posts
      @held.shift.call until @held.empty?
    end

    def wait_for_posts(count)
      count.times { @posted.pop(timeout: 5) || raise('No stream registration was posted') }
    end

    def async_invoke(receiver, method, *args, connection: receiver, &block)
      job = -> { receiver.send(method, *args, &block) }

      @defer && receiver.is_a?(Proc) ? @jobs << job : job.call
    end

    def async_exec(receiver, *, connection:, &)
      receiver.instance_exec(*, &)
    end

    def post(task = nil, &block)
      job = task || block

      if @stall
        @held << job
        @posted << true
      else
        job.call
      end
    end

    def timer(_interval, &)
      Timer.new.tap { |timer| @timers << timer }
    end
  end

  # Client side of one fake connection: drives subscribe, hello and sealed frames through the server connection.
  class Peer
    attr_reader :connection, :socket, :link, :session, :tokens

    def initialize(connection, socket, key:, audience:, identifier:, credential:, session: nil)
      @connection = connection
      @socket = socket
      @key = key
      @audience = audience
      @identifier = identifier
      @credential = credential
      @session = session
      @opened = 0
      @tokens = []
    end

    def challenge
      socket.sent.find { |message| message['type'] == 'challenge' }
    end

    def start_link(**overrides)
      @link = GraphqlEncrypted::Cable::Client::Link.new(
        challenge_frame: challenge, public_key: @key.public_key, pin: Digest::SHA256.hexdigest(@key.public_key.to_der), audience: @audience, credential: @credential,
        path: GraphqlEncrypted.option(:cable_path), label: GraphqlEncrypted.option(:cable_protocol_label), purpose: GraphqlEncrypted.option(:cable_hello_purpose), **overrides
      )
    end

    def subscribe_channel
      command('subscribe')
    end

    def hello(token = link.hello)
      @tokens << token

      message('hello' => token)
    end

    def handshake(**overrides)
      start_link(**overrides)
      subscribe_channel

      hello
    end

    def send_frame(type, **fields)
      raw_frame(link.seal(type, **fields))
    end

    def raw_frame(token)
      @tokens << token

      message('frame' => token)
    end

    def new_frames
      fresh = socket.sent.drop(@opened).filter_map { |message| message.dig('message', 'frame') }
      @opened = socket.sent.size

      fresh.map { |token| link.open(token) }
    end

    def summary
      new_frames.map { |frame| [frame['t'], frame['id']].compact }
    end

    private

    def command(name, data = nil)
      connection.receive(JSON.generate({ command: name, identifier: @identifier, data: data }.compact))
    end

    def message(**fields)
      action = fields.key?('hello') ? 'hello' : 'frame'

      command('message', JSON.generate({ 'action' => action }.merge(fields)))
    end
  end

  # Encrypts a hello plaintext to the server key, the way a client does before opening the socket.
  def self.hello_token(plain, key:, header: {})
    jwe = JSON::JWE.new(JSON.generate(plain))
    jwe.alg = 'RSA-OAEP'
    jwe.enc = 'A256GCM'
    header.each { |name, value| jwe.header[name] = value }
    jwe.encrypt!(key.public_key)

    jwe.to_s
  end

  def self.unique_namespace(prefix)
    "#{prefix}:cable:test-#{Process.pid}-#{SecureRandom.hex(4)}"
  end

  def self.clean_redis(namespace)
    redis = GraphqlEncrypted::Cable::Limits.redis

    redis.scan_each(match: "#{namespace}:*") { |key| redis.del(key) }
  end
end
