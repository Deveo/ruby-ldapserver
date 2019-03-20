# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ldap/server/version'

Gem::Specification.new do |s|
  s.name = %q{ruby-ldapserver}
  s.version = LDAP::Server::VERSION

  s.authors = ["Brian Candler", "Juha-Pekka Laiho"]
  s.description = %q{ruby-ldapserver is a lightweight, pure-Ruby skeleton for implementing LDAP server applications.}
  s.email = %q{jp@deveo.com}
  s.files = `git ls-files`.split($/)
  s.homepage = %q{https://github.com/Deveo/ruby-ldapserver}
  s.rdoc_options = ["--main", "README.txt"]
  s.require_paths = ["lib"]
  s.summary = %q{A pure-Ruby framework for building LDAP servers}
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  s.required_ruby_version = '>= 1.9'

  s.add_development_dependency 'bundler', '~> 1.3'
  s.add_development_dependency 'rake', '~> 10.0'
  s.add_development_dependency 'ruby-ldap', '~> 0.9.16' unless RUBY_PLATFORM == 'java'
  s.add_development_dependency 'jruby-ldap', '~> 0.0' if RUBY_PLATFORM == 'java'
  s.add_development_dependency 'rspec', '~> 3.1'
end
