# Changelog

## 0.1.0 (unreleased)

- A resend of an accepted write gets its stored answer before the persisted query lookup, so it survives a query store that lost the hash; a miss is answered after the sequence checks and still does not spend the sequence (`Session#exchange` takes `admit:`).
- Logout bypasses the sequence check: any sequence or none ends the session once (the sign-out handler runs once) and answers `{ revoked: true }` with the client's own sequence, so a client that lost its pending write can still sign out. Unknown credential stays UNAUTHENTICATED.
- Add the session method `connect_presence`, called after a cable hello; `touch_presence` stays for pings.
- Tell blocked cable hello clients when to retry and count only malformed or forged hellos toward the address block.
- Add `GraphqlEncrypted::Cable::Server.close_connections`: closes the open sockets of every server with SERVER_RESTART so clients reconnect after the host app restarts its pub/sub on code reload.
- Answer every RATE_LIMITED of a limiter (session start included) with `retryAfter`, whole seconds until the window ends: `GraphqlEncrypted::Limiter.retry_after(name, subject)`.
- Add `bin/rails generate graphql_encrypted:install` and a Railtie that writes the default initializer on the first development boot.
- Add `GraphqlEncrypted::PayloadMiddleware`, the AES-256-GCM payload encryption of HTTP (`payload_secret`, `payload_paths`, `payload_failure_context`); a refused payload is a Sentry warning.
- Send one revoke per session after the commit of the outermost transaction, at any savepoint depth, from any instance of the row and any fiber; plans live with their transaction, so a rolled back one leaves nothing behind.
- Add the `use GraphqlEncrypted::Errors` schema plugin: resolver errors are reported through `GraphqlEncrypted.report` and answer INTERNAL, retryable.
- Close the live socket of a session from `GraphqlEncrypted::Session` after the commit that ends it (LOGGED_OUT) or replaces its user (RECONNECT).
- Return the session record to its state before a refused mutation, so changes made in memory inside the rolled back savepoint are not saved and close no socket.
- Add `GraphqlEncrypted::Testing` (`require 'graphql_encrypted/testing'`): fake socket, inline worker pool, client peer, hello token and Redis namespace helpers for tests of the socket.
- Make connection admission atomic across session and user limits.
- Cancel delayed stream registrations when a subscription or connection is refused.
- Close client sockets after malformed handshakes and reject replies for another sequence.
- Remove decrypted stack locals from encrypted request error events.
- Reject malformed response keys before HTTP execution and return the hello refusal code for malformed socket keys.
- Cover HTTP and socket transport failures, subscription races, request replay and resource cleanup with line and branch coverage checks.

- JOSE request and response envelopes pinned to the server key (`GraphqlEncrypted::Envelope`).
- Session controller base class: sign-in actions, logout, GraphQL reads and sequenced writes (`GraphqlEncrypted::SecureController`).
- Public controller base class with request-bound answers (`GraphqlEncrypted::PublicController`).
- Shared HTTP side in an abstract base class (`GraphqlEncrypted::BaseController`).
- Session model concern: one run per sequence, sealed answer replay, single-use reads (`GraphqlEncrypted::Session`).
- Automatic persisted queries; a miss on a write does not use its sequence (`GraphqlEncrypted::PersistedQuery`).
- Persisted query catalog built from `.graphql` files (`GraphqlEncrypted::PersistedQuery::Catalog`).
- Conventions instead of hooks: `schema`, `session`, `sign_in ... with:`, `sign_out with:`, session methods `refusal` and `diagnostic_tags`.
- Built-in Sentry diagnostics (`GraphqlEncrypted::Diagnostics`), switched on by configuration.
- Fixed-window limiter (`GraphqlEncrypted::Limiter`) and keyed secrets (`GraphqlEncrypted::Secrets`).
- `execute.graphql_encrypted` notification for every GraphQL execution.
- Reference Ruby client with a crash-safe state file (`GraphqlEncrypted::Client`).
- Encrypted WebSocket for GraphQL subscriptions: `GraphqlEncrypted::Cable::Server`, `Channel` (DSL `schema`, `session`), `Connection`, `Hello`, `StreamKeys`, `Frame`, `Codes`, `Limits`, `Revoke`, `Journal` and the reference `Cable::Client`.
- Configuration: `cable_path`, `cable_redis`, `cable_namespace`, `cable_protocol_label`, `cable_hello_purpose`, `cable_log_name`, `cable_log_updates`, `cable_limits`.
- `GraphqlEncrypted::Diagnostics.socket`, `GraphqlEncrypted.with_user` and the session method `touch_presence`.
- Subscriptions run on the stock `GraphQL::Subscriptions::ActionCableSubscriptions`; the channel binds the stream of every subscription itself, so no adapter of the application is needed.
- `session_start` limit (30 per 10 minutes per address) is declared by default.
- `cable_channel` setting: default channel of the reference socket client.
- Requires `openssl` 3.2 or newer.
- Style config of the gem is self-contained.
- One constant per file in `Cable::Client`, `Cable::Frame` and `Cable::Codes`; the names are unchanged.
- Request tests of `SecureController` and `PublicController` on a rack rig inside the gem tests.
