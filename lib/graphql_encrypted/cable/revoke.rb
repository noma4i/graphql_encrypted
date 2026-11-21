# Revokes live sockets from anywhere in the app: by connection, by session or by user. A socket that holds the revoked
# scope closes gracefully with the given reason (see GraphqlEncrypted::Cable::Codes::Reason).
#
#   GraphqlEncrypted::Cable::Revoke.session(session.id, reason: GraphqlEncrypted::Cable::Codes::Reason::LOGGED_OUT)
#
# @see GraphqlEncrypted::Cable::Channel
module GraphqlEncrypted::Cable::Revoke
  module_function

  def session(id, reason:)
    publish('session', id, reason)
  end

  def user(id, reason:)
    publish('user', id, reason)
  end

  def connection(id, reason:)
    publish('connection', id, reason)
  end

  def stream(scope, id)
    [GraphqlEncrypted.option(:cable_namespace), 'control', scope, id].join(':')
  end

  def publish(scope, id, reason)
    ActionCable.server.broadcast(stream(scope, id), { type: 'revoke', reason: reason })
  rescue Redis::BaseError => e
    GraphqlEncrypted.report(e)
    GraphqlEncrypted::Cable::Journal.event('revoke_unpublished', limit: scope)
  end
end
