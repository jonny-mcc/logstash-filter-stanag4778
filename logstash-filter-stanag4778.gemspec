Gem::Specification.new do |s|
  s.name            = 'logstash-filter-stanag4778'
  s.version         = ::File.read('version').split("\n").first
  s.licenses        = ['Apache-2.0']
  s.summary         = 'Parses and validates STANAG 4778 cryptographic signatures (XMLDSIG/JWS)'
  s.description     = 'A Logstash filter plugin that parses and verifies STANAG 4778 Binding Data Objects (BDOs) using XMLDSIG (ADatP-4778.2) and JWS (ADatP-4778.7), extracts STANAG 4774 confidentiality labels, and evaluates reference integrity.'
  s.authors         = ['Logstash Plugin Contributors']
  s.email           = 'info@elastic.co'
  s.homepage        = 'https://github.com/logstash-plugins/logstash-filter-stanag4778'
  s.require_paths   = ['lib']

  # Files
  s.files = Dir[
    'lib/**/*',
    'spec/**/*',
    'resources/**/*',
    '*.gemspec',
    '*.md',
    'CONTRIBUTORS',
    'Gemfile',
    'LICENSE',
    'NOTICE.TXT',
    'version',
    'docs/**/*'
  ]

  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  s.metadata = { 'logstash_plugin' => 'true', 'logstash_group' => 'filter' }

  s.add_runtime_dependency 'logstash-core-plugin-api', '>= 1.60', '<= 2.99'
  s.add_runtime_dependency 'jmespath', '~> 1.6'

  s.add_development_dependency 'logstash-devutils'
  s.add_development_dependency 'insist'
end
