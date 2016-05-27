require 'r509'
require 'r509/mongoid/models'

RSpec.describe R509::Mongoid::Models::CertificateAuthority do

  let(:ca_name) { 'My Cool CA'}
  subject { described_class.new }

  describe '.get_certificate_authority' do
    context 'when CA does not exist' do
      before(:each) { described_class.destroy_all }
      it 'should return nil' do
        expect(described_class.get_certificate_authority(ca_name)).to be_nil
      end
    end
    context 'when CA does exist' do
      let(:ca_double) { double('CA')}
      let(:ca_config) { double('CA config')}
      before(:each) do
        allow(described_class).to receive(:where).with(name: ca_name).and_return([ca_double])
        allow(ca_double).to receive(:config).and_return(ca_config)
      end
      it 'should return the signed cert' do
        signed_cert = double('signed cert')
        expect(R509::CertificateAuthority::Signer).to receive(:new).and_return(signed_cert)
        expect(described_class.get_certificate_authority(ca_name)).to eq(signed_cert)
      end
    end
  end

  describe '.get_crl' do
    context 'when CA does not exist' do
      before(:each) { described_class.destroy_all }
      it 'should return nil' do
        expect(described_class.get_crl(ca_name)).to be_nil
      end
    end
    context 'when CA does exist' do
      let(:my_ca) { described_class.new(name: ca_name, config_yaml: '') }
      let(:ca_config) { double('CA config')}
      before(:each) do
        allow(described_class).to receive(:where).with(name: ca_name).and_return([my_ca])
        allow(my_ca).to receive(:config).and_return(ca_config)
      end
      it 'should return the CRL' do
        crl = double('crl')
        expect(R509::CRL::Administrator).to receive(:new).and_return(crl)
        expect(described_class.get_crl(ca_name)).to eq(crl)
      end
    end
  end

  describe '.get_option_builder' do
    context 'when CA does not exist' do
      before(:each) { described_class.destroy_all }
      it 'should return nil' do
        expect(described_class.get_option_builder(ca_name)).to be_nil
      end
    end
    context 'when CA does exist' do
      let(:my_ca) { described_class.new(name: ca_name, config_yaml: '') }
      let(:ca_config) { double('CA config')}
      before(:each) do
        allow(described_class).to receive(:where).with(name: ca_name).and_return([my_ca])
        allow(my_ca).to receive(:config).and_return(ca_config)
      end
      it 'should return the builder' do
        ob = double('crl')
        expect(R509::CertificateAuthority::OptionsBuilder).to receive(:new).with(ca_config).and_return(ob)
        expect(described_class.get_option_builder(ca_name)).to eq(ob)
      end
    end
  end

  describe '.get_certificate_serial' do
    context 'when CA does not exist' do
      before(:each) { described_class.destroy_all }
      it 'should return nil' do
        expect(described_class.get_certificate_serial(ca_name)).to be_nil
      end
    end
    context 'when CA does exist' do
      let(:my_ca) { described_class.new(name: ca_name, config_yaml: '') }
      let(:ca_certificate) { double('CA certificate', serial: '123456')}
      before(:each) do
        allow(described_class).to receive(:where).with(name: ca_name).and_return([my_ca])
      end
      it 'should return the serial' do
        allow(my_ca).to receive(:ca_certificate).and_return(ca_certificate)
        expect(described_class.get_certificate_serial(ca_name)).to eq('123456')
      end
    end
  end

  describe '#config' do
    let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:password) { 'somepass' }
    let(:private_key) { rsa_key.to_pem }
    let(:cert) {
      rsa_key.public_key
      root_ca = OpenSSL::X509::Certificate.new
      root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
      root_ca.serial = 1
      root_ca.subject = OpenSSL::X509::Name.parse "/DC=org/DC=Test/CN=Test"
      root_ca.issuer = root_ca.subject # "self-signed"
      root_ca.public_key = rsa_key.public_key
      root_ca.not_before = Time.now
      root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 years validity
      # ef = OpenSSL::X509::ExtensionFactory.new
      # ef.subject_certificate = root_ca
      # ef.issuer_certificate = root_ca
      # root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
      # root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
      # root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
      # root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
      root_ca.sign(rsa_key, OpenSSL::Digest::SHA256.new)
      root_ca.to_pem
    }
    let(:ca_cert) { R509::Mongoid::Models::Certificate.new(public_key: cert)}
    let(:config_yaml) { '"profiles": { "pro1": {} }'}
    subject do
      described_class.new(
        name: ca_name,
        config_yaml: config_yaml,
        ca_certificate: ca_cert
      )
    end
    it 'should return a CAConfig object' do
      expect(subject.config).to be_kind_of(R509::Config::CAConfig)
    end
  end

end
