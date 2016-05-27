require 'r509/mongoid'
require 'erb'

R509::Mongoid.load_config

conf = YAML.load(ERB.new(File.read('config.yaml')).result)[Dependo::Registry[:environment]]

conf['certificate_authorities'].each do |name, ca_config|
  ca = R509::Mongoid::Models::CertificateAuthority.create!(name: name, config_yaml: ca_config.to_yaml)
  ca_cert_config = ca_config['ca_cert']
  public_key = File.read(ca_cert_config['cert'])
  private_key = File.read(ca_cert_config['key'])
  cert = R509::Mongoid::Models::Certificate.create!(public_key: public_key, private_key: private_key, password: ca_cert_config['password'], signing_ca: ca)
  ca.update_attributes(ca_certificate: cert)
end
