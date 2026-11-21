module GraphqlEncrypted::Cable::Codes::Reason
  LOGGED_OUT = 'LOGGED_OUT'.freeze
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED'.freeze
  SERVER_RESTART = 'SERVER_RESTART'.freeze
  SUPERSEDED = 'SUPERSEDED'.freeze
  RECONNECT = 'RECONNECT'.freeze

  CLOSE_CODE = {
    LOGGED_OUT => GraphqlEncrypted::Cable::Codes::Close::NORMAL, ACCOUNT_LOCKED => GraphqlEncrypted::Cable::Codes::Close::ACCOUNT_LOCKED, SERVER_RESTART => GraphqlEncrypted::Cable::Codes::Close::GOING_AWAY,
    SUPERSEDED => GraphqlEncrypted::Cable::Codes::Close::SUPERSEDED, RECONNECT => GraphqlEncrypted::Cable::Codes::Close::GOING_AWAY
  }.freeze
end
