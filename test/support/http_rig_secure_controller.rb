class HttpRigSecureController < GraphqlEncrypted::SecureController
  LOGIN = lambda do |session, _body, _action, request:|
    session.update!(authenticated_at: Time.current)

    { ok: true, ip: request.remote_ip }
  end

  schema HttpRigSchema
  session HttpRigSession
  sign_in :login, with: LOGIN
end
