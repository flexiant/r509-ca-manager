require 'r509/mongoid'

R509::Mongoid.load_config

[
  R509::Mongoid::Models::CertificateAuthority,
  R509::Mongoid::Models::Certificate,
  R509::Mongoid::Models::Crl
  ].map(&:collection).map(&:drop)
