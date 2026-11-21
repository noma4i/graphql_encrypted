require 'action_cable'
require 'redis'
require 'websocket/driver'

# Encrypted GraphQL subscriptions over a WebSocket: RSA-OAEP hello, X25519 key agreement, A256GCM frames with counters.
#
# @see GraphqlEncrypted::Cable::Server
# @see GraphqlEncrypted::Cable::Channel
# @see GraphqlEncrypted::Cable::Client
module GraphqlEncrypted::Cable
end

require_relative 'cable/rejected'
require_relative 'cable/codes'
require_relative 'cable/codes/close'
require_relative 'cable/codes/failure'
require_relative 'cable/codes/reason'
require_relative 'cable/limits'
require_relative 'cable/token_bucket'
require_relative 'cable/stream_keys'
require_relative 'cable/hello'
require_relative 'cable/frame'
require_relative 'cable/frame/too_large'
require_relative 'cable/frame/reader'
require_relative 'cable/frame/writer'
require_relative 'cable/journal'
require_relative 'cable/journal/sink'
require_relative 'cable/revoke'
require_relative 'cable/web_socket'
require_relative 'cable/web_socket/client_socket'
require_relative 'cable/connection'
require_relative 'cable/channel'
require_relative 'cable/server'
require_relative 'cable/client'
require_relative 'cable/client/protocol_error'
require_relative 'cable/client/refused'
require_relative 'cable/client/reconnect_policy'
require_relative 'cable/client/socket'
require_relative 'cable/client/link'
