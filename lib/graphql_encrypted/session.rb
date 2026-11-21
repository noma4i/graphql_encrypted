# Session record of an encrypted client. Include it in an ActiveRecord model whose table has the columns
# listed in the README: the record keeps the last sequence with its sealed answer, so a resent mutation gets
# the same ciphertext back and never runs twice.
#
# The record reads +user+ (the signed-in account, nil before sign-in). Override +refusal+ and +diagnostic_tags+ to take part in
# GraphQL gating and error reports.
#
# After the commit that sets +ended_at+ the live socket of the session closes with LOGGED_OUT; after the commit that changes or clears a
# +user_id+ it closes with RECONNECT. A rolled back change closes nothing.
#
# @see GraphqlEncrypted::SecureController
# @see GraphqlEncrypted::Cable::Revoke
module GraphqlEncrypted::Session
  extend ActiveSupport::Concern

  READ_LOG_LIMIT = 5000

  REVOCATIONS = ObjectSpace::WeakKeyMap.new

  included do
    after_update :note_revocation
  end

  class_methods do
    def digest_credential(credential)
      Digest::SHA256.hexdigest(credential)
    end

    def find_by_credential(credential)
      find_by(credential_digest: digest_credential(credential))
    end

    def start_with_credential(credential)
      create_or_find_by!(credential_digest: digest_credential(credential))
    end
  end

  def signed_in?
    authenticated_at.present? && ended_at.nil?
  end

  # Error code that refuses GraphQL for this signed-in session (a locked account), nil to serve it.
  def refusal
    nil
  end

  # Called on every ping of an encrypted socket; override it to record that the user is online.
  def touch_presence
  end

  # Called after the hello of an encrypted socket; defaults to `touch_presence`, override it to treat a new socket differently from a ping.
  def connect_presence
    touch_presence
  end

  # Tags added to an error report of this session, resolved only when a report is sent.
  def diagnostic_tags
    {}
  end

  # Runs the block once per sequence number and seals its answer under the session lock.
  # @param data [Hash] opened request with an Integer sequence
  # @param admit [#call, nil] answers a failure Hash (sealed without a sequence, the sequence is not spent) or nil to run the block
  # @note Under one lock: a resend of the last sequence gets the stored answer first, then a sequence that is not the next one gets SEQUENCE_CONFLICT, an ended session SESSION_ENDED, and only then +admit+ runs, so a resend is answered even when the persisted query store lost its hash. Logout does not use it (see +revoke+).
  def exchange(data, admit: nil)
    with_lock do
      digest = GraphqlEncrypted::Envelope.digest(data)
      next encrypted_response if sequence == data['sequence'] && request_digest == digest
      next GraphqlEncrypted::Envelope.seal(data, { error: 'SEQUENCE_CONFLICT' }) unless data['sequence'] == sequence + 1
      next GraphqlEncrypted::Envelope.seal(data, { error: 'SESSION_ENDED' }) if ended_at

      failure = admit&.call
      next GraphqlEncrypted::Envelope.seal(data, failure) if failure

      result = yield
      update!(sequence: data['sequence'], request_digest: digest, encrypted_response: GraphqlEncrypted::Envelope.seal(data, result, sequence: data['sequence']))

      encrypted_response
    end
  end

  # Ends the session under the session lock and seals { revoked: true }; an ended session runs nothing and answers the same.
  # @param data [Hash] opened request with any sequence or none
  # @note The answer echoes the sequence of the request (nil when absent); +sequence+, +request_digest+ and +encrypted_response+ stay as they are.
  def revoke(data)
    with_lock do
      unless ended_at
        yield
        update!(ended_at: Time.current)
      end

      GraphqlEncrypted::Envelope.seal(data, { revoked: true }, sequence: data['sequence'])
    end
  end

  # Remembers the requestId of a read until its envelope expires. Answers nil when the read is admitted, REPLAYED_REQUEST for a replay or an
  # ended session and RATE_LIMITED when READ_LOG_LIMIT reads are still remembered; the log does not grow in the last two cases.
  def admit_read(data)
    with_lock do
      now = Time.now.to_i
      active = read_requests.select { |_id, expires_at| expires_at >= now }
      next 'REPLAYED_REQUEST' if ended_at || active.key?(data['requestId'])
      next 'RATE_LIMITED' if active.size >= READ_LOG_LIMIT

      active[data['requestId']] = data['issuedAt'] + GraphqlEncrypted::Envelope::WINDOW
      update!(read_requests: active)
      nil
    end
  end

  # Returns the record to attributes read before a savepoint that was rolled back, so nothing the savepoint changed in memory reaches a later save
  # and its pending revocation is dropped.
  def restore_snapshot(snapshot)
    assign_attributes(snapshot)

    clear_changes_information
  end

  private

  def note_revocation
    reason = revocation_reason

    return unless reason

    connection = self.class.connection
    transaction = connection.current_transaction
    entries = REVOCATIONS[connection] ||= []
    entries.reject! { |entry_transaction, _plans| entry_transaction.state.rolledback? }
    entry = entries.find { |entry_transaction, _plans| entry_transaction.equal?(transaction) } || entries.push([transaction, []]).last
    entry.last << [id, reason]

    ActiveRecord.after_all_transactions_commit { publish_revocations(connection) }
  end

  def publish_revocations(connection)
    # Rails 8.1 gives no public way to ask a transaction whether it rolled back, so this reads transaction.state; the gem tests fail if that changes.
    entries = REVOCATIONS.delete(connection) || []
    surviving = entries.reject { |transaction, _plans| transaction.state.rolledback? }.flat_map(&:last)

    surviving.group_by(&:first).each do |id, entries_of_session|
      reasons = entries_of_session.map(&:last)
      reason = reasons.include?(GraphqlEncrypted::Cable::Codes::Reason::LOGGED_OUT) ? GraphqlEncrypted::Cable::Codes::Reason::LOGGED_OUT : reasons.first
      GraphqlEncrypted::Cable::Revoke.session(id, reason: reason)
    end
  end

  def revocation_reason
    return GraphqlEncrypted::Cable::Codes::Reason::LOGGED_OUT if saved_change_to_ended_at?(from: nil)

    GraphqlEncrypted::Cable::Codes::Reason::RECONNECT if user_replaced?
  end

  def user_replaced?
    has_attribute?(:user_id) && saved_change_to_user_id? && user_id_before_last_save
  end
end
