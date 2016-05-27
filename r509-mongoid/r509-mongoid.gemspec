# encoding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'r509/mongoid/version'

Gem::Specification.new do |spec|
  spec.name          = "r509-mongoid"
  spec.version       = R509::Mongoid::VERSION
  spec.authors       = ["Pablo Baños Lopez"]
  spec.email         = ["pbanos@flexiant.com"]
  spec.summary       = %q{R509 gem to store certificate, certificate authorities and CRLs on Mongo DB}
  #spec.description   = %q{TODO: Write a longer description. Optional.}
  spec.homepage      = ""
  spec.license       = "All rights reserved"

  spec.files         = %w(README.md Rakefile) + Dir["{lib,script,spec,doc,cert_data}/**/*"]
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency 'mongoid', "~> 4.0.0"
  spec.add_dependency 'r509', "~> 0.10.0"
  spec.add_dependency 'dependo', '~> 0.2.0'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency "bundler", "~> 1.7"
end
