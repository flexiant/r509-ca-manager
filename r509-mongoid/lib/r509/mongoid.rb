require "r509/mongoid/version"
require 'r509'
require 'mongoid'
require 'dependo'

module R509
  module Mongoid
    
    def self.load_config(mongoid_config_file= nil, mongoid_logger=nil)
      Dependo::Registry[:environment] ||= ENV['RACK_ENV'] || ENV['MONGOID_ENV'] || 'development'
      ::Mongoid.logger = mongoid_logger
      mongoid_config_file ||= ENV['MONGOID_CONFIG_FILE'] || './mongoid.yml'
      ::Mongoid.load!(mongoid_config_file, Dependo::Registry[:environment])
      Dependo::Registry[:config_pool] = R509::Mongoid::Models::CertificateAuthority::ConfigPool
      Dependo::Registry[:certificate_authorities] = R509::Mongoid::Models::CertificateAuthority
      Dependo::Registry[:certificates] = R509::Mongoid::Models::Certificate
      Dependo::Registry[:config_printer] = self
    end

    def self.print_config
      Dependo::Registry[:log].warn "Currently managing following CAs:"
      Dependo::Registry[:config_pool].all.each do |config|
        Dependo::Registry[:log].warn config.ca_cert.subject.to_s
      end
    end
  end
end

require 'r509/mongoid/models'
