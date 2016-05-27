# File modified by Pablo Baños López
# Copyright 2016 Flexiant Ltd. (for modifications only)

require 'dependo'
require 'logger'
require 'r509/mongoid'

Dependo::Registry[:log] = Logger.new(ENV['CA_MANAGER_LOGFILE'] || STDOUT)

Dependo::Registry[:crl_store] = R509::Mongoid::Models::Crl

R509::Mongoid.load_config

require 'r509/certificateauthority/http/server'

R509::Mongoid.print_config

server = R509::CertificateAuthority::HTTP::Server
run server
