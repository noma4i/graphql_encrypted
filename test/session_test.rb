require 'test_helper'

class SessionTest < Minitest::Test
  Cable = GraphqlEncrypted::Cable

  def test_a_sequence_runs_once_and_its_resend_gets_the_same_ciphertext
    session = start_session
    data = request_data('sequence' => 1)
    runs = 0
    run = proc do
      runs += 1

      { done: true }
    end

    first = session.exchange(data, &run)
    resent = session.exchange(data.merge('issuedAt' => data['issuedAt'] + 1), &run)

    assert_equal [1, first], [runs, resent]
    assert_equal({ 'done' => true }, open_answer(first, data)['body'])

    assert_equal 1, open_answer(first, data)['sequence']
  end

  def test_the_same_sequence_with_another_request_conflicts
    session = start_session
    data = request_data('sequence' => 1)
    session.exchange(data) { {} }
    other = data.merge('body' => { 'query' => '{ other }' })

    assert_equal 'SEQUENCE_CONFLICT', open_answer(session.exchange(other) { raise 'must not run' }, other).dig('body', 'error')
  end

  def test_a_skipped_sequence_conflicts
    session = start_session
    data = request_data('sequence' => 3)

    assert_equal 'SEQUENCE_CONFLICT', open_answer(session.exchange(data) { raise 'must not run' }, data).dig('body', 'error')
  end

  def test_an_ended_session_answers_session_ended
    session = start_session
    session.update!(ended_at: Time.current)
    data = request_data('sequence' => 1)

    assert_equal 'SESSION_ENDED', open_answer(session.exchange(data) { raise 'must not run' }, data).dig('body', 'error')
  end

  def test_a_raising_block_keeps_the_sequence_free
    session = start_session
    data = request_data('sequence' => 1)

    assert_raises(RuntimeError) { session.exchange(data) { raise 'boom' } }

    assert_equal 0, session.reload.sequence
  end

  def test_a_read_request_id_is_admitted_once_until_its_envelope_expires
    session = start_session
    data = request_data('sequence' => nil)

    assert_nil session.admit_read(data)

    assert_equal 'REPLAYED_REQUEST', session.admit_read(data)
  end

  def test_an_ended_session_admits_no_read
    session = start_session
    session.update!(ended_at: Time.current)

    assert_equal 'REPLAYED_REQUEST', session.admit_read(request_data('sequence' => nil))
  end

  def test_a_full_read_log_refuses_a_new_read_without_growing_and_still_answers_a_replay
    session = start_session
    expires_at = Time.now.to_i + 1000
    session.update!(read_requests: (1..Session::READ_LOG_LIMIT).to_h { |index| ["read-#{index}", expires_at] })

    assert_equal 'RATE_LIMITED', session.admit_read(request_data('sequence' => nil, 'requestId' => 'one-more'))
    assert_equal Session::READ_LOG_LIMIT, session.reload.read_requests.size

    assert_equal 'REPLAYED_REQUEST', session.admit_read(request_data('sequence' => nil, 'requestId' => 'read-1'))
  end

  def test_expired_reads_leave_room_in_a_full_read_log
    session = start_session
    session.update!(read_requests: (1..Session::READ_LOG_LIMIT).to_h { |index| ["read-#{index}", Time.now.to_i - 1] })

    assert_nil session.admit_read(request_data('sequence' => nil, 'requestId' => 'fresh'))

    assert_equal ['fresh'], session.reload.read_requests.keys
  end

  def test_a_credential_finds_its_session_by_digest_only
    session = Session.start_with_credential('secret')

    assert_equal session, Session.find_by_credential('secret')
    assert_equal Digest::SHA256.hexdigest('secret'), session.credential_digest

    assert_equal session, Session.start_with_credential('secret')
  end

  def test_ending_a_session_revokes_its_socket_after_commit_with_logged_out
    session = start_cable_session
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::LOGGED_OUT).once

    CableSession.transaction do
      session.update!(ended_at: Time.current)
      nil
    end
  end

  def test_nothing_is_revoked_before_the_commit
    session = start_cable_session
    Cable::Revoke.expects(:session).never

    CableSession.transaction do
      session.update!(ended_at: Time.current)
      raise ActiveRecord::Rollback
    end
  end

  def test_a_rolled_back_end_does_not_leak_into_the_next_save
    session = start_cable_session
    CableSession.transaction do
      session.update!(ended_at: Time.current)
      raise ActiveRecord::Rollback
    end
    session.reload
    Cable::Revoke.expects(:session).never

    session.update!(sequence: 1)
  end

  def test_a_rolled_back_savepoint_after_the_end_keeps_the_pending_revoke
    session = start_cable_session
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::LOGGED_OUT).once

    CableSession.transaction do
      session.update!(ended_at: Time.current)
      CableSession.transaction(requires_new: true) do
        session.update!(sequence: 1)
        raise ActiveRecord::Rollback
      end
    end
  end

  def test_another_instance_of_the_row_saved_later_in_the_same_transaction_keeps_the_revoke
    saved_flag = ActiveRecord::Base.run_commit_callbacks_on_first_saved_instances_in_transaction
    ActiveRecord::Base.run_commit_callbacks_on_first_saved_instances_in_transaction = false
    session = start_cable_session(user: CableUser.create!)
    other = CableSession.find(session.id)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    CableSession.transaction do
      session.update!(user: CableUser.create!)
      other.update!(sequence: 1)
    end
  ensure
    ActiveRecord::Base.run_commit_callbacks_on_first_saved_instances_in_transaction = saved_flag
  end

  def test_the_session_released_inside_exchange_revokes_with_reconnect
    session = start_cable_session(user: CableUser.create!)
    data = request_data('sequence' => 1)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    session.exchange(data) do
      session.assign_attributes(user: nil, authenticated_at: nil)
      session.save!
      {}
    end
  end

  def test_a_save_in_exchange_through_a_second_instance_and_a_job_instance_still_revokes
    session = start_cable_session(user: CableUser.create!)
    data = request_data('sequence' => 1)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    session.exchange(data) do
      session.update!(user: CableUser.create!)
      CableSession.find(session.id).update!(authenticated_at: Time.current)
      {}
    end
  end

  def test_a_user_change_after_the_end_in_one_transaction_still_sends_logged_out_once
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::LOGGED_OUT).once

    CableSession.transaction do
      session.update!(ended_at: Time.current)
      session.update!(user: CableUser.create!)
    end
  end

  def test_the_release_inside_exchange_revokes_under_a_non_joinable_outer_transaction_like_transactional_tests
    session = start_cable_session(user: CableUser.create!)
    other = CableSession.find(session.id)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    CableSession.transaction(joinable: false) do
      session.exchange(request_data('sequence' => 1)) do
        session.update!(user: nil)
        other.update!(authenticated_at: Time.current)
        {}
      end
    end
  end

  def test_the_same_change_in_the_outer_transaction_and_a_committed_savepoint_publishes_once
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    CableSession.transaction do
      session.update!(user: CableUser.create!)
      CableSession.transaction(requires_new: true) { session.update!(user: CableUser.create!) }
    end
  end

  def test_a_change_made_before_a_rolled_back_savepoint_stays_and_the_savepoint_adds_nothing
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    CableSession.transaction do
      session.update!(user: CableUser.create!)
      CableSession.transaction(requires_new: true) do
        session.update!(ended_at: Time.current)
        raise ActiveRecord::Rollback
      end
    end
  end

  def test_a_change_inside_a_rolled_back_savepoint_publishes_nothing
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).never

    CableSession.transaction do
      CableSession.transaction(requires_new: true) do
        session.update!(user: CableUser.create!)
        raise ActiveRecord::Rollback
      end
    end
  end

  def test_a_change_inside_a_committed_savepoint_publishes_once
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    CableSession.transaction do
      CableSession.transaction(requires_new: true) { session.update!(user: CableUser.create!) }
    end
  end

  def test_two_updates_with_the_same_reason_in_one_transaction_publish_once
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    CableSession.transaction do
      session.update!(user: CableUser.create!)
      session.update!(user: CableUser.create!)
    end
  end

  def test_an_update_of_an_already_ended_session_publishes_no_new_logged_out
    session = start_cable_session(ended_at: 1.hour.ago)
    Cable::Revoke.expects(:session).never

    session.update!(ended_at: Time.current)

    session.update!(sequence: 1)
  end

  def test_two_sessions_changed_in_one_transaction_publish_once_each
    first = start_cable_session(user: CableUser.create!)
    second = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(first.id, reason: Cable::Codes::Reason::RECONNECT).once
    Cable::Revoke.expects(:session).with(second.id, reason: Cable::Codes::Reason::LOGGED_OUT).once

    CableSession.transaction do
      first.update!(user: CableUser.create!)
      second.update!(ended_at: Time.current)
    end
  end

  def test_a_save_in_another_fiber_is_published_by_the_commit_of_the_outer_fiber
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    CableSession.transaction do
      Fiber.new { session.update!(user: CableUser.create!) }.resume
    end
  end

  def test_a_plan_survives_garbage_collection_between_the_save_and_the_commit
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    CableSession.transaction do
      session.update!(user: CableUser.create!)
      5.times { GC.start(full_mark: true, immediate_sweep: true) }
      GC.compact
    end
  end

  def test_a_rolled_back_plan_leaves_nothing_for_a_later_transaction
    rolled_back = start_cable_session(user: CableUser.create!)
    committed = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(rolled_back.id, anything).never
    Cable::Revoke.expects(:session).with(committed.id, reason: Cable::Codes::Reason::RECONNECT).once

    held = nil
    CableSession.transaction do
      held = CableSession.connection.current_transaction
      rolled_back.update!(user: CableUser.create!)
      raise ActiveRecord::Rollback
    end

    committed.update!(user: CableUser.create!)

    assert_predicate held.state, :rolledback?
  end

  def test_an_outer_reconnect_and_a_committed_savepoint_end_publish_logged_out_once
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::LOGGED_OUT).once

    CableSession.transaction do
      session.update!(user: CableUser.create!)
      CableSession.transaction(requires_new: true) { session.update!(ended_at: Time.current) }
    end
  end

  def test_changing_the_user_revokes_with_reconnect
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    session.update!(user: CableUser.create!)
  end

  def test_releasing_the_user_revokes_with_reconnect
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::RECONNECT).once

    session.update!(user: nil)
  end

  def test_ending_wins_over_a_user_change_in_one_transaction
    session = start_cable_session(user: CableUser.create!)
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::LOGGED_OUT).once

    CableSession.transaction do
      session.update!(user: nil)
      session.update!(ended_at: Time.current)
    end
  end

  def test_other_changes_and_the_first_sign_in_revoke_nothing
    Cable::Revoke.expects(:session).never
    session = start_cable_session

    session.update!(sequence: 1, authenticated_at: Time.current)

    session.update!(user: CableUser.create!)
  end

  def test_a_session_without_a_user_column_still_ends_with_logged_out
    session = start_session
    Cable::Revoke.expects(:session).with(session.id, reason: Cable::Codes::Reason::LOGGED_OUT).once

    session.update!(ended_at: Time.current)
  end

  private

  def start_cable_session(**attrs)
    CableSession.create!(credential_digest: SecureRandom.hex(16), **attrs)
  end
end
