require 'test_helper'

class CableFrameTest < Minitest::Test
  include CableSupport

  Close = GraphqlEncrypted::Cable::Codes::Close
  Frame = GraphqlEncrypted::Cable::Frame
  Rejected = GraphqlEncrypted::Cable::Rejected

  def setup
    @client_key = SecureRandom.random_bytes(32)
    @server_key = SecureRandom.random_bytes(32)
    @writer = Frame::Writer.new(@server_key)
    @reader = Frame::Reader.new(@server_key, direction: :server_to_client)
  end

  def test_a_sealed_frame_carries_a_strictly_increasing_counter_and_survives_a_round_trip
    first = @reader.open(@writer.seal(:ready, connectionId: SecureRandom.uuid, challengeDigest: 'a' * 64))
    second = @reader.open(@writer.seal(:pong, ts: 7))

    assert_equal [[0, 'ready'], [1, 'pong']], [[first[:n], first[:t]], [second[:n], second[:t]]]

    assert_equal 7, second[:ts]
  end

  def test_a_repeated_skipped_or_reordered_counter_closes_with_a_counter_mismatch
    frames = Array.new(3) { @writer.seal(:pong, ts: 1) }

    { repeat: [0, 0], skip: [0, 2], reorder: [1] }.each do |name, order|
      reader = Frame::Reader.new(@server_key, direction: :server_to_client)
      error = assert_raises(Rejected, name.to_s) { order.each { |index| reader.open(frames[index]) } }

      assert_equal Close::COUNTER_MISMATCH, error.code, name.to_s
    end
  end

  def test_a_changed_tag_a_foreign_direction_key_and_garbage_close_with_a_bad_frame
    segments = @writer.seal(:pong, ts: 1).split('.')
    segments[3] = segments[3].sub(/\A./) { |char| char == 'A' ? 'B' : 'A' }

    [segments.join('.'), 'not.a.jwe', ''].each do |token|
      assert_equal Close::BAD_FRAME, assert_raises(Rejected) { @reader.open(token) }.code
    end
    wrong_direction = Frame::Reader.new(@client_key, direction: :server_to_client)

    assert_equal Close::BAD_FRAME, assert_raises(Rejected) { wrong_direction.open(@writer.seal(:pong, ts: 1)) }.code
  end

  def test_a_protected_header_with_anything_beyond_alg_and_enc_is_refused
    forged = JSON::JWE.new(JSON.generate(n: 0, t: 'pong', ts: 1)).tap do |jwe|
      jwe.alg = 'dir'
      jwe.enc = 'A256GCM'
      jwe.kid = 'extra'
      jwe.encrypt!(@server_key)
    end

    assert_equal Close::BAD_FRAME, assert_raises(Rejected) { @reader.open(forged.to_s) }.code
  end

  def test_every_client_frame_type_refuses_unknown_fields_missing_fields_wrong_types_and_a_bad_id
    reader = ->(body) { Frame::Reader.new(@client_key, direction: :client_to_server).open(seal_raw(@client_key, body)) }
    good = { n: 0, t: 'subscribe', id: 'chat-1', query: 'subscription { changes { id } }' }
    assert_equal 'chat-1', reader.call(good)[:id]

    [
      good.merge(extra: 1), good.except(:query), good.merge(query: 5), good.merge(id: 'bad id'), good.merge(id: 'a' * 65), good.merge(variables: 'x'),
      good.merge(t: 'next'), good.merge(t: 'unknown'), good.except(:n), good.merge(n: '0'), good.merge(n: -1),
      { n: 0, t: 'unsubscribe' }, { n: 0, t: 'ping', ts: 1.5 }, { n: 0, t: 'close', id: 'x' }
    ].each do |body|
      assert_equal Close::BAD_FRAME, assert_raises(Rejected) { reader.call(body) }.code, body.inspect
    end
  end

  def test_a_key_is_retired_after_its_frame_budget_and_a_frame_above_the_server_limit_is_not_sealed
    short = Frame::Writer.new(@server_key, budget: 2)
    2.times { short.seal(:pong, ts: 1) }

    assert_equal Close::GOING_AWAY, assert_raises(Rejected) { short.seal(:pong, ts: 1) }.code

    assert_raises(Frame::TooLarge) { @writer.seal(:next, id: 'a', result: { data: 'x' * GraphqlEncrypted::Cable::Limits.server_frame_bytes }) }
  end

  def test_a_limit_override_changes_the_size_a_frame_may_have
    configure(cable_limits: { server_frame_bytes: 200 })

    assert_raises(Frame::TooLarge) { @writer.seal(:next, id: 'a', result: { data: 'x' * 300 }) }
  end

  def test_a_reader_retires_its_key_and_rejects_oversized_non_string_and_non_object_frames
    reader = Frame::Reader.new(@server_key, direction: :server_to_client, budget: 1)
    reader.open(@writer.seal(:pong, ts: 1))
    assert_equal Close::GOING_AWAY, assert_raises(Rejected) { reader.open(@writer.seal(:pong, ts: 2)) }.code
    [nil, 'x' * (GraphqlEncrypted::Cable::Limits.server_frame_bytes + 1), seal_raw(@server_key, [])].each do |token|
      assert_equal Close::BAD_FRAME, assert_raises(Rejected) { @reader.open(token) }.code
    end

    assert_raises(ArgumentError) { @writer.seal(:pong, ts: 'bad') }
  end
end
