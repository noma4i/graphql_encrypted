# Rack app that serves the encrypted socket; mount it where +config.cable_path+ points.
#
#   mount GraphqlEncrypted::Cable::Server.new(channel: AppChannel) => GraphqlEncrypted.option(:cable_path)
#
# +channel+ is a subclass of GraphqlEncrypted::Cable::Channel; its class name is the channel identifier clients subscribe to.
#
# +close_connections+ closes the open sockets of every server so clients reconnect; a host app with code reloading calls it before class unload.
#
# @see GraphqlEncrypted::Cable::Channel
class GraphqlEncrypted::Cable::Server < ActionCable::Server::Base
  SERVERS = ObjectSpace::WeakMap.new

  attr_reader :channel

  def self.close_connections
    SERVERS.keys.each do |server|
      server.connections.each { |connection| connection.close(reason: ActionCable::INTERNAL[:disconnect_reasons][:server_restart]) }
    end
  end

  def initialize(channel:)
    @channel = channel
    SERVERS[self] = true

    super(config: ActionCable.server.config.dup.tap do |config|
      config.connection_class = -> { GraphqlEncrypted::Cable::Connection }
      config.disable_request_forgery_protection = true
      config.logger = GraphqlEncrypted::Cable::Journal.sink
    end)
  end

  def pubsub
    ActionCable.server.pubsub
  end
end
