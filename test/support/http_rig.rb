# Dispatches an encrypted POST to the controller that owns the last path segment, the way a router would, without a Rails application.
module HttpRig
  CONTROLLERS = { 'config' => HttpRigPublicController }.freeze

  module_function

  def post(path, ciphertext, headers = {})
    operation = path.split('/').last
    controller = CONTROLLERS.fetch(operation, HttpRigSecureController)
    env = Rack::MockRequest.env_for(path, { method: 'POST', input: ciphertext, 'CONTENT_TYPE' => 'application/jose' }.merge(headers))
    env['action_dispatch.request.path_parameters'] = { operation: operation }
    status, _headers, body = controller.action(:create).call(env)

    [status, body.each.to_a.join]
  end

  def transport(log = [])
    lambda do |path, ciphertext|
      log << [path, ciphertext]

      post(path, ciphertext)
    end
  end
end
