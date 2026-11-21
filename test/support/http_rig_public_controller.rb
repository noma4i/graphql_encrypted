class HttpRigPublicController < GraphqlEncrypted::PublicController
  diagnostics_operation 'config'

  private

  def encrypted_answer(body)
    { minimumVersion: '1.2.0', echo: body['name'] }
  end
end
