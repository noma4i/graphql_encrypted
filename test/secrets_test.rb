require 'test_helper'

class SecretsTest < Minitest::Test
  def setup
    configure(key_generator: ActiveSupport::KeyGenerator.new('test-secret-key-base'))
  end

  def test_an_encrypted_value_decrypts_under_the_same_purpose
    sealed = GraphqlEncrypted::Secrets.encrypt('one-time message', purpose: 'otp')

    refute_includes sealed, 'one-time message'

    assert_equal 'one-time message', GraphqlEncrypted::Secrets.decrypt(sealed, purpose: 'otp')
  end

  def test_another_purpose_cannot_decrypt
    sealed = GraphqlEncrypted::Secrets.encrypt('one-time message', purpose: 'otp')

    assert_raises(ActiveSupport::MessageEncryptor::InvalidMessage) { GraphqlEncrypted::Secrets.decrypt(sealed, purpose: 'login') }
  end

  def test_a_digest_is_stable_and_depends_on_purpose_and_every_part
    digest = GraphqlEncrypted::Secrets.digest('otp', 'session-1', '1234')

    assert_equal digest, GraphqlEncrypted::Secrets.digest('otp', 'session-1', '1234')
    assert_match(/\A\h{64}\z/, digest)
    refute_equal digest, GraphqlEncrypted::Secrets.digest('login', 'session-1', '1234')
    refute_equal digest, GraphqlEncrypted::Secrets.digest('otp', 'session-2', '1234')

    refute_equal digest, GraphqlEncrypted::Secrets.digest('otp', 'session-1', '1235')
  end

  def test_the_split_between_parts_matters
    refute_equal GraphqlEncrypted::Secrets.digest('otp', 'a', 'bc'), GraphqlEncrypted::Secrets.digest('otp', 'ab', 'c')
  end

  def test_a_missing_key_generator_raises_key_error
    configure(key_generator: nil)

    assert_raises(KeyError) { GraphqlEncrypted::Secrets.digest('otp', 'x') }
  end
end
