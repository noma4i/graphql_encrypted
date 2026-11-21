class CableSession < ActiveRecord::Base
  include GraphqlEncrypted::Session

  belongs_to :user, class_name: 'CableUser', optional: true

  def refusal
    'LOCKED' if user.locked
  end
end
