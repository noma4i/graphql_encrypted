# graphql_encrypted

The gem is published only on GitHub, not on RubyGems. Pin a release tag; `branch: 'master'` follows the latest commit.

End-to-end encrypted GraphQL over HTTP for Rails. Every request is a JWE envelope sealed to the server key, every answer is sealed to a one-time key the client put inside the request. Mutations carry a session sequence number: they run once, in order, and a resend gets the original sealed answer back.

- RSA-OAEP + A256GCM request envelope pinned to the server key, audience, method and path.
- Replay-safe writes: one run per sequence number, stored answer on resend.
- Single-use reads: a query without a sequence is accepted once per `requestId`.
- Automatic persisted queries, with a catalog builder for `.graphql` files.
- Base controllers for a session endpoint and a public endpoint, a session model concern and a reference Ruby client.
- An encrypted WebSocket for GraphQL subscriptions: hello, X25519 key agreement, counted A256GCM frames, limits, revoke, reference client.

Requires Ruby 3.3+, Rails 7.1+, graphql-ruby 2.3+ and `openssl` 3.2+ (raw X25519 keys).

## Installation

```ruby
gem 'graphql_encrypted', github: 'noma4i/graphql_encrypted', tag: 'v0.1.0'
```

The gem is published only on GitHub, not on RubyGems. Pin a release tag; `branch: 'master'` follows the latest commit.

Run `bundle`, then `bin/rails generate graphql_encrypted:install` to write `config/initializers/graphql_encrypted.rb`: the three required settings (`private_key`, `audience`, `persisted_query_store`) and every optional one, commented out with its default. On the first boot in development the gem writes the same file by itself when it is missing; an existing file is never touched, and nothing is written in test or production.

## Configuration

```ruby
GraphqlEncrypted.configure do |config|
  config.private_key = -> { ENV.fetch('ENCRYPTION_PRIVATE_KEY') }
  config.audience = -> { ENV.fetch('API_HOST') }
  config.persisted_query_store = -> { MySchema.persisted_query_store }
  config.refuse_headers = %w[X-Legacy-Auth]
  config.key_generator = -> { Rails.application.key_generator }
  config.cache = -> { Rails.cache }
  config.logger = -> { Rails.logger }
  config.with_user = ->(user, &run) { Current.set(user: user, &run) }

  config.cable_path = '/api/cable'
  config.cable_channel = 'AppChannel'
  config.cable_redis = -> { Redis.new(url: ENV.fetch('REDIS_URL')) }

  config.limit :sign_in, limit: 3, window: 5.minutes, enabled: -> { !Rails.env.development? }
  config.limit :session_start, limit: 30, window: 10.minutes, enabled: -> { !Rails.env.development? }

  config.sentry = true
  config.sentry_namespace = 'api'
  config.filter_parameters = -> { Rails.application.config.filter_parameters }
  config.body_tags = { platform: %w[platform], app_version: %w[version appVersion] }
  config.expected_errors = %w[Google::Auth::IDTokens::VerificationError]
end
```

| Setting | Meaning |
| --- | --- |
| `private_key` | PEM of the server RSA key, at least 3072 bits. |
| `audience` | Origin the clients address, for example `https://api.example.com`. |
| `persisted_query_store` | Object with `fetch_query(sha)` and `save_query(sha, query)`. |
| `refuse_headers` | Headers that make a request invalid, on top of `Authorization` and `Cookie`: credentials live inside the envelope only. |
| `payload_secret` | Shared secret of `GraphqlEncrypted::PayloadMiddleware` (string or callable, read on every request); a blank one raises KeyError. |
| `payload_paths` | Paths the middleware serves, `['/']` by default. |
| `payload_failure_context` | Callable `request -> Hash` (default `{}`) with the values of the application added to the Sentry warning for a payload that cannot be decrypted. |
| `error_reporter` | Called with errors that make an endpoint answer 503. |
| `key_generator` | Object with `generate_key(salt, size)`, for `Secrets` and `Limiter`. |
| `cache` | Cache store with `increment` and `write`, for `Limiter`. |
| `logger` | Logger that answers `silence` (requests run with it silenced below WARN). The socket journal writes to it: a logger whose `info` takes a message and a payload (SemanticLogger) gets them apart, any other logger (`Logger`, `ActiveSupport::Logger`) gets one line, the name and the payload as JSON. |
| `limit` | `config.limit :name, limit:, window:, enabled:` declares a counter of `Limiter`. `session_start` (30 per 10 minutes per remote address) is declared by default: it bounds the sessions that unauthenticated first requests create. |
| `with_user` | Callable `(user, &run)` that wraps GraphQL execution, for a current-user holder. |
| `sentry`, `sentry_namespace` | Switch the Sentry adapter on; the namespace names the marker tag and the context. |
| `filter_parameters` | Extra keys filtered from reported values, on top of the built-in secret keys. |
| `body_tags` | `{ tag => [body keys] }`: tags read from the request body. |
| `expected_errors` | Class names or callables `(error)`; matching errors are not sent to Sentry. |
| `cable_path` | Path the socket is mounted on, default `/cable`. A hello for another path is refused. |
| `cable_channel` | Class name of the channel, the identifier the reference socket client subscribes to by default. |
| `cable_redis` | Callable that builds the Redis client for socket limits; called once per process. |
| `cable_namespace` | Prefix of the Redis keys and revoke streams, default `graphql_encrypted:cable`. |
| `cable_protocol_label` | HKDF label of the key schedule, default `graphql-encrypted-ws-v1`. |
| `cable_hello_purpose` | `purpose` a hello must carry, default `graphql_encrypted.ws.hello`. |
| `cable_log_name` | Message of the socket journal lines, default `graphql_encrypted.cable`. |
| `cable_log_updates` | Write one `update` journal line (connection id and top-level field) per subscription update sent to a socket, default `false`. |
| `cable_limits` | Hash overriding entries of `GraphqlEncrypted::Cable::Limits::DEFAULTS`. |

Each value is a plain object or a callable. Callables run on every use, so a key can rotate without a restart. A missing, unreadable or short key makes both endpoints answer `503`.

## Keys

The server and every client app hold key material. Get each item to the right place before the first request.

| Item | Secret | Where it lives |
| --- | --- | --- |
| Server RSA private key, PEM, at least 3072 bits (`GraphqlEncrypted::MIN_KEY_BITS`) | yes | The server secret store only, read through `private_key`. |
| Server public key, PEM | no | Built into every client app. |
| `kid`, the pin: hex SHA-256 of the public key DER (SubjectPublicKeyInfo) | no | Built into every client app next to the public key. The server computes it from the private key (`GraphqlEncrypted.kid`). |
| `key_generator` secret (Rails `secret_key_base`) | yes | The server. It derives the `Secrets` and `Limiter` keys; a new value makes stored secrets unreadable. |
| Socket X25519 keys | - | Created per connection, nothing to store. |
| Client credential and state file | yes | The device: Keychain, EncryptedSharedPreferences, or a file with mode `0600` (`GraphqlEncrypted::Client` refuses other modes). |

### Generate a server key

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out server.pem
openssl pkey -in server.pem -pubout -out server_public.pem
openssl pkey -in server.pem -pubout -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
```

The last line prints the `kid`. It equals `GraphqlEncrypted.kid` on the server and `Digest::SHA256.hexdigest(OpenSSL::PKey::RSA.new(File.read('server_public.pem')).public_key.to_der)` in Ruby. Make one key per environment (development, staging, production): each has its own `kid`.

### Store the private key

- Put `server.pem` into the secret store of the deployment and expose it to the app as one value (for example an environment variable read by `private_key`). Keep the PEM line breaks: in a `.env` file use a double-quoted multi-line value.
- Never commit it, never bake it into an image, never log it, never ship it in a client.
- Delete the local `server.pem` after the upload. Keep `server_public.pem` and the `kid`: they are public and go to the clients.
- Check after a deploy: the `kid` that the socket `challenge` frame announces must equal the `kid` built into the clients. A missing or short key answers `503` on both endpoints.

### Ship the public key to clients

- Build the public PEM and the `kid` into the app. Do not download them at run time: whoever intercepts TLS could hand over another key.
- Before the first request the client checks that the key has at least 3072 bits and that its SHA-256 DER equals the pin. `GraphqlEncrypted::Client` raises `Untrusted server key` otherwise; a native client must do the same.
- The client `origin` must equal the server `audience` exactly (scheme, host, port), and one build talks to one environment: a development build carries the development key and `kid`.

### Rotate the key

The server has one active key. A request encrypted to the old key cannot be decrypted after the switch, and a socket hello with the old `kid` is refused. So a rotation breaks every app build that carries the old key:

1. Generate the new key and its `kid`.
2. Release client builds with the new public key and `kid`, and force the update of older builds.
3. Replace the private key in the secret store. `private_key` is a callable, so the next request uses the new key without a restart.

Rotate at once when the private key leaks; plan a forced client update for any other rotation. A client can compare the `kid` of the `challenge` frame with its own before the hello and ask for an update when they differ.

## Session table

The session model keeps the sequence log. Include `GraphqlEncrypted::Session` in an ActiveRecord model whose table has these columns:

| Column | Type | Purpose |
| --- | --- | --- |
| `credential_digest` | string, not null, unique index | SHA-256 of the client credential. |
| `authenticated_at` | datetime | Set by your sign-in handler. |
| `ended_at` | datetime | Set by logout. |
| `user_id` | bigint, indexed, no foreign key | The signed-in account. The model owns the relation (`belongs_to :user, optional: true`); the socket reads `user_id` to supersede connections of one user. |
| `sequence` | bigint, not null, default 0 | Last accepted write. |
| `request_digest` | string | Digest of the last accepted write. |
| `encrypted_response` | text | Sealed answer of the last accepted write. |
| `read_requests` | json or jsonb, not null, default `{}` | Request ids of reads still inside the time window. |

```ruby
class CreateSessions < ActiveRecord::Migration[8.1]
  def change
    create_table :sessions do |t|
      t.string :credential_digest, null: false, index: { unique: true }
      t.datetime :authenticated_at
      t.datetime :ended_at
      t.bigint :user_id, index: true
      t.bigint :sequence, null: false, default: 0
      t.string :request_digest
      t.text :encrypted_response
      t.jsonb :read_requests, null: false, default: {}
    end
  end
end

class Session < ApplicationRecord
  include GraphqlEncrypted::Session

  belongs_to :user, optional: true

  def refusal
    'ACCOUNT_UNAVAILABLE' if user.disabled?
  end

  def diagnostic_tags
    { platform: user.platform }
  end
end
```

Add your own columns (user, device, one-time codes) to the same table. The gem reads `user` from the session (nil before sign-in) and calls three methods you may override:

| Method | Purpose |
| --- | --- |
| `refusal` | Error code that refuses GraphQL for a signed-in session (a locked account), `nil` to serve it. |
| `diagnostic_tags` | Hash of tags added to an error report of this session; resolved only when a report is sent. |
| `touch_presence` | Called on every ping of the socket; record that the user is online. |
| `connect_presence` | Called after the hello of the socket; defaults to `touch_presence`. |

## Session controller

Inherit from `GraphqlEncrypted::SecureController`. It is an `ActionController::API`, so the usual controller features work.

```ruby
class EncryptedRequestsController < GraphqlEncrypted::SecureController
  schema AppSchema
  session Session
  sign_in :otp, :confirm, with: SignIn
  sign_out with: SignOut
end
```

```ruby
post '/api/auth/:operation', to: 'encrypted_requests#create'
post '/api/logout', to: 'encrypted_requests#create', defaults: { operation: 'logout' }
post '/api/graphql', to: 'encrypted_requests#create', defaults: { operation: 'graphql' }
```

The route sets `params[:operation]`. Its value picks the kind of request:

- A name given to `sign_in` calls its handler `call(session, body, action, request:)`. The handler returns a Hash and marks the session authenticated. A first request (sequence 1) to a sign-in operation creates the session, within the `session_start` limit of the remote address; past it the answer is `{ error: 'RATE_LIMITED', retryAfter: <seconds> }`.
- `logout` calls the `sign_out` handler `call(session)`, ends the session and answers `{ revoked: true }`. It ignores the sequence (stale, ahead or none) and is idempotent: an ended session answers the same without calling the handler; the answer echoes the client's own sequence.
- `graphql` runs the schema.

The GraphQL context has `encrypted_session`, `after_refusal`, `current_user`, `current_user_id`, `limiter_key`, `request_ip` and `user_agent`. A mutation that answers with an `errors` array or an `error` code runs in a savepoint that is rolled back, and the session record returns to its attributes from before the mutation. Callables pushed to `context[:after_refusal]` run after the rollback. An error whose `extensions` has `problems` and no `code` gets the code `INVALID_INPUT`.

Each execution publishes an `execute.graphql_encrypted` notification with `operation_name`, `kind` (`query` or `mutation`) and `sql` (the query count, measured only while something subscribes). The duration of the event is the execution time.

## Public controller

Inherit from `GraphqlEncrypted::PublicController` for requests that run before a session exists (bootstrap config, a help form).

```ruby
class ConfigsController < GraphqlEncrypted::PublicController
  diagnostics_operation 'config'

  private

  def encrypted_answer(body)
    { minimumVersion: '1.2.0' }
  end
end
```

`diagnostics_operation` names the endpoint in error reports; the default is the controller name. The answer carries `requestDigest`, so only the sender of the exact request accepts it. `INVALID_REQUEST` is a ready answer for a body that fails validation.

## Payload encryption

`config.middleware.use GraphqlEncrypted::PayloadMiddleware` decrypts a POST to one of `payload_paths` marked `X-Payload-Encryption: 1` and encrypts its response with AES-256-GCM. The key is HKDF-SHA256 of `payload_secret` (salt empty, info `payload-enc-v1`, 32 bytes) and the envelope is `{ v: 1, iv, ct, tag }` in hex. A body that cannot be opened gets a plaintext 403 with `PAYLOAD_DECRYPTION_FAILED` and `X-Payload-Encryption: 0`, and with `sentry = true` a warning goes to Sentry. Other requests pass untouched.

## Diagnostics

With `config.sentry = true` every request runs in its own Sentry scope. The scope carries the user (`id` and `username` of `session.user`), the tags `operation`, `graphql_operation_name`, `kind`, the `body_tags`, the session's `diagnostic_tags`, a marker tag named after `sentry_namespace`, and a context of the same name with the decrypted request: path, request id, sequence, IP, query, variables and persisted query hash. Values under secret keys (credentials, tokens, codes, passwords and `filter_parameters`) are `[FILTERED]`. The value of every literal argument and every variable default in the query is `[FILTERED]` too, so a secret written into a document never leaves the process; a document that does not parse is reported as `[unparsed document]`. Strings over 4000 characters are cut and variables over 32 KiB become a preview.

```ruby
Sentry.init do |config|
  config.before_send = ->(event, hint) { GraphqlEncrypted::Diagnostics.before_send(event, hint) }
end
```

Add `use GraphqlEncrypted::Errors` to the schema so an error a resolver raises goes through `GraphqlEncrypted.report` (not straight to Sentry) and answers the INTERNAL code with `retryable: true`; a more specific `rescue_from` of the schema wins.

`before_send` drops expected errors (record not found or invalid, JWT errors and `expected_errors`) of the gem's requests and removes stack frame variables. Locals can contain decrypted payloads serialized under arbitrary names, outside the structured context filter. Code outside the controllers uses the same API: `Diagnostics.call { ... }` for a job, `Diagnostics.scoped { ... }` and `Diagnostics.annotate(operation:, session:, body:, values:)` for another transport. Without Sentry every call is a no-op.

## Limiter

```ruby
config.limit :sign_in, limit: 3, window: 5.minutes

GraphqlEncrypted::Limiter.take?(:sign_in, phone)         # false after the third attempt in the window
GraphqlEncrypted::Limiter.take?(:support, session_key, ip) # counts both subjects
```

A subject is stored as a keyed digest, never as given. `enabled:` (boolean or callable) switches a limit off, for example in development. A cache that returns no count refuses. `GraphqlEncrypted::Limiter.retry_after(:sign_in, phone)` gives the whole seconds (at least 1) until the window ends; a refused session start answers `{ error: 'RATE_LIMITED', retryAfter: 240 }`, and a handler should answer its own RATE_LIMITED the same way.

## Secrets

```ruby
sealed = GraphqlEncrypted::Secrets.encrypt(json, purpose: 'otp')
GraphqlEncrypted::Secrets.decrypt(sealed, purpose: 'otp')
GraphqlEncrypted::Secrets.digest('otp', session.id, code)  # hex HMAC-SHA256
```

Keys derive from `key_generator` with the salts `<purpose>.storage` and `<purpose>.verifier`.

## Client

```ruby
client = GraphqlEncrypted::Client.new(
  origin: 'https://api.example.com', public_key: File.read('server.pub'),
  pin: kid, state_file: 'session.json'
)

client.call('/api/auth/otp', { phone: '+15550100' })
client.call('/api/graphql', { query: 'mutation { ... }' })
client.call('/api/graphql', { query: '{ viewer { id } }' }, read: true)
client.public_request('/api/config', { platform: 'web' })
```

The client keeps the credential and the last sequence in a state file that only its owner can read. A write that got no answer stays pending: `retry_pending` resends it with the same sequence. `GraphqlEncrypted::Client::Retryable` (network error or HTTP 503) and `Rejected` (any other non-200) tell which case it was. `SequenceConflict` means the server holds another request for that sequence. A logout answer deletes the state file.

## Encrypted socket

GraphQL subscriptions run over a WebSocket (ActionCable protocol `actioncable-v1-json`). The gem owns the whole protocol; the application names a schema, a session model and a path.

```ruby
class AppChannel < GraphqlEncrypted::Cable::Channel
  schema AppSchema
  session Session
end

# config/routes.rb
mount GraphqlEncrypted::Cable::Server.new(channel: AppChannel) => GraphqlEncrypted.option(:cable_path)
```

A host app with code reloading calls `GraphqlEncrypted::Cable::Server.close_connections` before class unload (`Rails.application.reloader.before_class_unload`), so open sockets reconnect to the restarted pub/sub.

The schema uses the stock transport of graphql-ruby, no adapter of your own: `use GraphQL::Subscriptions::ActionCableSubscriptions, namespace: 'app:'`. The channel binds the pub/sub stream of every subscription itself and delivers each `trigger` as a `next` frame; a subscription that ends without a result (`unsubscribe`) answers `complete` and closes only that subscription.

The class name of the channel is the identifier clients subscribe to (`{"channel":"AppChannel"}`). The session model is the one of the HTTP endpoint (see Session table): the socket reads `user`, `user_id`, `ended_at`, `refusal`, `connect_presence` and `touch_presence` from it. A subscription runs the schema inside `config.with_user`; the GraphQL context has `current_user`, `current_user_id`, `encrypted_session`, `limiter_key`, `channel` and `multiplex`.

`GraphqlEncrypted::Session` closes the socket of its own session: `ended_at` set from nil gives LOGGED_OUT, a replaced or cleared `user_id` gives RECONNECT. `after_update` records a plan under the current transaction; one flush after the commit of the outermost transaction drops the plans of rolled back transactions or savepoints and sends one revoke per session, LOGGED_OUT winning. The result does not depend on which instance of the row was saved or on `run_commit_callbacks_on_first_saved_instances_in_transaction`. Close a live socket from anywhere else (a locked account):

```ruby
GraphqlEncrypted::Cable::Revoke.session(session.id, reason: GraphqlEncrypted::Cable::Codes::Reason::LOGGED_OUT)
GraphqlEncrypted::Cable::Revoke.user(user.id, reason: GraphqlEncrypted::Cable::Codes::Reason::ACCOUNT_LOCKED)
```

The socket reports through `GraphqlEncrypted::Diagnostics.socket` and writes one journal line per event (`open`, `hello_ok`, `hello_fail`, `hello_failure_uncounted`, `subscribe`, `unsubscribe`, `oversized_update`, `revoke_unpublished`, `release_failed`, `close`, `closed`, `disconnect`, `error`). The line goes to `config.logger` under the message `cable_log_name`, as a payload or as JSON (see `logger`). A line carries ids, codes and counts, never a query, variable, key or token.

### Handshake

1. The client opens the WebSocket with the subprotocol `actioncable-v1-json` and subscribes to the channel. The server sends `{type: "challenge", v: 1, challenge, kid, x25519, limits}`: `challenge` (32 random bytes) and `x25519` (an ephemeral X25519 public key) are base64url without padding, `kid` is the hex SHA-256 of the server public key DER, `limits` holds the frame and subscription limits.
2. The client sends the action `hello` with a compact JWE (`RSA-OAEP`, `A256GCM`, sealed to the server key). Its plaintext has exactly these keys:

| Field | Value |
| --- | --- |
| `v` | `1`. |
| `purpose` | `cable_hello_purpose`. |
| `audience`, `kid` | The configured audience and the hex SHA-256 of the server public key DER. |
| `method`, `path` | `GET` and `cable_path`. |
| `challenge` | The challenge of step 1. |
| `clientKey` | The client ephemeral X25519 public key. |
| `credential` | The session credential (43 characters base64url). |
| `responseKey` | 32 random bytes, base64url. |

3. Keys: `HKDF-SHA256(ikm = dh || responseKey, salt = challenge, info = label 0x00 direction 0x00 kid 0x00 audience 0x00 path, length = 32)` with `direction` `c2s` or `s2c` and `label` = `cable_protocol_label`.
4. The server answers with the sealed frame `ready` (`connectionId`, `challengeDigest` = hex SHA-256 of the challenge).

A hello that is not valid is answered after a fixed floor (0.2 s) with close code `4401`, whatever the reason: a malformed envelope, a wrong destination, an unknown, signed-out or refused session. The reason is logged only. Malformed or forged hellos count toward the address block; session state refusals do not. A blocked hello closes with `4429` and JSON reason `{"code":"hello_blocked","retryAfter":N}`, where `N` is whole seconds until the current window ends. Other limits and failures answer with an empty reason and their own code: `4429` (too many opens or unauthenticated sockets), `4503` (Redis, the database or the control streams are unavailable) and `4500` (internal error).

### Frames

A frame is a compact JWE (`alg: dir`, `enc: A256GCM`, protected header exactly `{"alg":"dir","enc":"A256GCM"}`) under the key of its direction. The plaintext is a JSON object with a counter `n` (0, 1, 2 ... per direction) and a type `t`. A repeated or skipped counter closes with `4409`; a key is retired after 2^20 frames.

| Direction | Type | Fields |
| --- | --- | --- |
| client | `subscribe` | `id`, `query`, optional `variables`, `operationName`. |
| client | `unsubscribe` | `id`. |
| client | `ping` | `ts` (Integer). |
| client | `close` | none. |
| server | `ready` | `connectionId`, `challengeDigest`. |
| server | `subscribed`, `complete` | `id`. |
| server | `next` | `id`, `result`. |
| server | `error` | `code`, `retryable`, optional `id`. |
| server | `pong` | `ts`. |
| server | `closing` | `code`, `reason`. |

An `id` is 1 to 64 characters of `A-Za-z0-9_-`. A frame with unknown or missing fields closes with `4400`.

### Codes

| Close code | Meaning |
| --- | --- |
| `1000` | Normal close, also the answer to a client `close` and a logout. |
| `1001` | Going away: server restart, frame budget used, reconnect after the connection lifetime. |
| `1009` | A message above the client frame limit. |
| `4400` | Malformed command or frame. |
| `4401` | Hello refused as invalid (see Handshake). The reference client reports it as well when the server rejects the channel subscription. |
| `4403` | The account is refused (`Session#refusal`). |
| `4408` | No hello in time, or no client frame within the idle deadline. |
| `4409` | Frame counter mismatch. |
| `4429` | Rate limit: opens, unauthenticated sockets, frames, refused hellos per address. |
| `4430` | Superseded by a newer connection of the same session or user. |
| `4500` | Internal error. |
| `4503` | Redis or the database is unavailable. |

A `closing` frame precedes a graceful close; its `reason` is `LOGGED_OUT`, `ACCOUNT_LOCKED`, `SERVER_RESTART`, `SUPERSEDED` or `RECONNECT`. Subscription failures are `error` frames with the codes `INVALID_INPUT`, `NOT_FOUND`, `OPERATION_NOT_ALLOWED`, `TOO_MANY_SUBSCRIPTIONS`, `DUPLICATE_ID`, `RATE_LIMITED`, `QUERY_TOO_COMPLEX`, `QUERY_TOO_DEEP`, `INTERNAL` and `REGISTRATION_REQUIRED`; `RATE_LIMITED` and `INTERNAL` are retryable.

### Limits

Defaults live in `GraphqlEncrypted::Cable::Limits::DEFAULTS`; `config.cable_limits = { idle_deadline: 30.seconds }` replaces single entries (an unknown name raises). Counters live in Redis (`cable_redis`); when Redis is down the socket closes with `4503`.

| Name | Default |
| --- | --- |
| `client_frame_bytes`, `server_frame_bytes` | 32 KiB, 256 KiB |
| `subscriptions` | 32 per connection |
| `connections_per_session`, `connections_per_user` | 3, 10 (the oldest is superseded) |
| `frames_per_second`, `frame_burst` | 20, 40 |
| `subscribes_per_minute`, `subscribe_burst` | 30, 32 |
| `opens_per_ip_per_minute`, `unauthenticated_per_ip` | 60, 20 |
| `hello_failures_per_ip`, `hello_failure_window` | 10 per 10 minutes |
| `hello_deadline`, `hello_refusal_floor` | 10 s, 0.2 s |
| `idle_deadline`, `connection_lifetime` | 60 s, 24 h |
| `session_check_interval`, `maintenance_interval`, `lease_ttl` | 60 s, 15 s, 45 s |
| `frames_per_key` | 2^20 |

### Client

```ruby
client = GraphqlEncrypted::Cable::Client.new(
  origin: 'https://api.example.com', public_key: pem, pin: kid, credential: credential,
  channel: 'AppChannel', path: '/api/cable'
)
client.run([{ id: 'one', query: 'subscription { changes { id } }' }]) { |event| puts event }
```

`channel`, `path`, `label` and `purpose` default to the server configuration (`cable_channel`, `cable_path`, `cable_protocol_label`, `cable_hello_purpose`). `timeout:` (default 10 s) is one deadline for the TCP connect, the TLS handshake and the WebSocket upgrade; a socket that does not open in time is closed and its thread ends. `socket_factory:` takes a callable `(url)` that returns a socket for tests.

`run` connects, subscribes, yields every frame and reconnects by a fixed policy (stop on `1000`, `4403`, `4430`; one immediate retry on `4400`, `4409`; otherwise exponential back-off with jitter). The client shares no code with the server: pass the same `path`, `label` and `purpose` as the server configuration.

## Persisted queries

A request may send `extensions.persistedQuery.sha256Hash` without `query`. The server looks the document up in `persisted_query_store`. A request that sends both stores the document, but only when the hash matches the query.

```ruby
GraphqlEncrypted::Client.persisted_body(query: document, variables: { id: 1 })
GraphqlEncrypted::Client.persisted_body(sha256: hash, variables: { id: 1 })
```

`GraphqlEncrypted::PersistedQuery::Catalog` builds the table from a directory of `.graphql` files (`queries`, `mutations`, `subscriptions`, `fragments`). A document is the operation followed by the fragments it needs, sorted by name, each once. Definitions start at column 0, lines are right-trimmed and definitions are joined by one blank line, so any client can reproduce the bytes without a GraphQL printer.

```ruby
Catalog = GraphqlEncrypted::PersistedQuery::Catalog
Catalog.hashes('app/graphql_documents')    # { 'Viewer' => 'ab12...' }
Catalog.register('app/graphql_documents')  # saves every document to the store
```

## Protocol

Transport: `POST`, `Content-Type: application/jose`, body is a compact JWE (`alg: RSA-OAEP`, `enc: A256GCM`), at most 256 KiB, no query string. `Authorization` and `Cookie` must be absent. Every answer has `Cache-Control: no-store`.

Request envelope (the JWE plaintext is a JSON object with exactly these keys):

| Field | Meaning |
| --- | --- |
| `audience` | The configured audience. |
| `kid` | Hex SHA-256 of the server public key DER. |
| `method`, `path` | HTTP method and path of this request. |
| `requestId` | Lowercase UUID. |
| `issuedAt` | Unix seconds. Accepted from 120 seconds in the past to 30 seconds in the future. |
| `responseKey` | 43 characters of base64url: the A256GCM key for the answer. |
| `credential` | 43 characters of base64url, the client secret. Absent on public requests. |
| `sequence` | Positive Integer for a write, `null` for a read. Absent on public requests. |
| `body` | JSON object: the operation payload. |

Answer envelope: a JWE with `alg: dir`, `enc: A256GCM` under `responseKey`. Plaintext: `requestId`, `sequence` (set only when the answer consumed that sequence), `body`, and `requestDigest` on public answers.

`requestDigest` is the hex SHA-256 of the request JSON without `issuedAt`, keys sorted. A resend with a fresh timestamp has the same digest.

Sequence rules for a write:

- Sequence `n + 1` after the last accepted `n` runs the request and stores the sealed answer.
- A resend of `n` with the same digest returns the stored ciphertext. The block does not run again.
- Any other number, or the same number with another digest, answers `SEQUENCE_CONFLICT`.
- A persisted query miss or invalid hash is checked last, after the stored answer and the sequence check, so a resend of an accepted write is answered even when the query store lost its hash. The miss answers without a sequence, so the client resends the same sequence with the full query.

A read (no sequence) must be a query. Its `requestId` is accepted once until the envelope expires.

HTTP status: `400` for a request that cannot be opened or addresses another destination, `413` for a body over the limit, `503` for an unusable server key or a database error, `200` with a sealed answer otherwise.

Error codes in `body.error`:

| Code | Cause |
| --- | --- |
| `UNAUTHENTICATED` | Unknown credential, signed-out session, or a read that is not a GraphQL query. |
| `SEQUENCE_CONFLICT` | The sequence is not the next one. |
| `SESSION_ENDED` | A write on an ended session. |
| `SEQUENCE_REQUIRED` | A read that contains a mutation or subscription. |
| `REPLAYED_REQUEST` | A read `requestId` seen before, or a read on an ended session. |
| `INVALID_REQUEST` | Unknown operation, or `query`, `variables`, `extensions` or `operationName` of the wrong type. |
| `ACCOUNT_UNAVAILABLE` | Your session's `refusal` returned this code (any code it returns is passed through). |

GraphQL errors for persisted queries are returned as `errors[].extensions.code`: `PERSISTED_QUERY_NOT_FOUND` and `INVALID_INPUT`.

## Development

### Test doubles

`require 'graphql_encrypted/testing'` gives `GraphqlEncrypted::Testing`: `FakeSocket`, `Timer`, `Work` (inline worker pool and event loop), `Peer` (a client that subscribes, sends hello and sealed frames), `hello_token`, and namespace helpers `unique_namespace` and `clean_redis` for Redis isolation.

### Unexpected application errors

Application callbacks can raise errors the transport cannot classify in advance.
The transport reports those errors through `error_reporter` and Sentry when enabled.
Socket dispatch and handshake failures close with `INTERNAL` (4500).
A failed subscription reports an `INTERNAL` frame and releases its registered streams.
Disconnect releases connection leases, control streams and remaining subscriptions.
Protocol refusals retain their own codes and are not reported as unexpected application errors.

```sh
bundle install
bundle exec rake test
```

The test suite requires Redis at `redis://127.0.0.1:6379/15` or `REDIS_URL`.
Each test uses its own Redis namespace. Tests check both line and branch coverage of every file under `lib/`, with a 100% minimum.
SimpleCov writes its report to the system temporary directory under `graphql-encrypted-coverage`.
Set `COVERAGE_DIR` to choose another report directory.

## License

MIT.
