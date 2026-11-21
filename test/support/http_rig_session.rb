class HttpRigSession < ActiveRecord::Base
  include GraphqlEncrypted::Session

  self.table_name = 'cable_sessions'

  def user
    nil
  end
end
