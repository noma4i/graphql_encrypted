Gem::Specification.new do |s|
  s.name        = 'graphql_encrypted'
  s.version     = File.read(File.join(__dir__, 'lib/graphql_encrypted/version.rb'))[/VERSION = '([^']+)'/, 1]
  s.summary     = 'End-to-end encrypted GraphQL for Rails: JOSE envelopes, ordered replay-safe mutations, persisted queries'
  s.description = 'Serves a GraphQL schema behind JWE envelopes pinned to the server key. Mutations carry a session sequence, run once and replay their sealed answer on resend; reads are single use. Ships controller DSLs, a session model concern, a persisted query catalog and a reference client.'

  s.license     = 'MIT'
  s.authors     = ['Alex Tsirel']
  s.email       = ['noma4i@gmail.com']
  s.homepage    = 'https://github.com/noma4i/graphql_encrypted'
  s.metadata = {
    'bug_tracker_uri' => 'https://github.com/noma4i/graphql_encrypted/issues',
    'changelog_uri' => 'https://github.com/noma4i/graphql_encrypted/blob/master/CHANGELOG.md',
    'homepage_uri' => s.homepage,
    'source_code_uri' => 'https://github.com/noma4i/graphql_encrypted',
    'rubygems_mfa_required' => 'true'
  }

  s.files = Dir['lib/**/*.rb', 'lib/**/*.tt', 'README.md', 'CHANGELOG.md', 'LICENSE']
  s.require_paths = ['lib']
  s.required_ruby_version = '>= 3.3'

  s.add_dependency 'actioncable', '>= 7.1'
  s.add_dependency 'actionpack', '>= 7.1'
  s.add_dependency 'activerecord', '>= 7.1'
  s.add_dependency 'activesupport', '>= 7.1'
  s.add_dependency 'concurrent-ruby', '>= 1.2'
  s.add_dependency 'graphql', '>= 2.3'
  s.add_dependency 'json-jwt', '>= 1.16'
  s.add_dependency 'openssl', '>= 3.2'
  s.add_dependency 'redis', '>= 5.0'
end
