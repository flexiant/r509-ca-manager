require 'r509'
require 'r509/mongoid/models'

RSpec.describe R509::Mongoid::Models::Certificate do

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

  subject do
    described_class.new(
      private_key: private_key,
      public_key: cert,
      password: password
    )
  end

  it { is_expected.to respond_to('public_key') }
  it { is_expected.to respond_to('private_key') }
  it { is_expected.to respond_to('password') }
  it { is_expected.to respond_to('signing_ca') }
  it { is_expected.to respond_to('signing_ca_name') }
  it { is_expected.to respond_to('serial') }

  describe '.revocation_checker' do
    it { is_expected.to_not be_nil }
  end

  describe '#r509_cert' do
    it { expect(subject.r509_cert).to be_kind_of(R509::Cert) }

    context 'when complete option passed' do
      it 'should generate cert with private key and password' do
        key = double('key')
        cert_double = double('cert_double')
        expect(R509::PrivateKey).to receive(:new).with(hash_including(
          key: private_key, password: password
        )).and_return(key)
        expect(R509::Cert).to receive(:new).with(hash_including(
          key: key
        )).and_return(cert_double)
        expect(subject.r509_cert(complete: true)).to eq(cert_double)
      end
    end
  end

  describe '#revoked?' do
    let(:revocation_checker) { double('revocation_checker') }
    let(:signing_ca) { double('signing_ca') }
    let(:signing_ca_name) { double('signing_ca_name') }
    let(:serial) { double('serial') }

    before(:each) do
      allow(subject).to receive(:revocation_checker).and_return(revocation_checker)
      allow(subject).to receive(:signing_ca_name).and_return(signing_ca_name)
      allow(subject).to receive(:serial).and_return(serial)
    end

    it 'should call revocation checker with proper parameters' do
      response = double('response')
      expect(revocation_checker).to receive(:call).with(signing_ca_name, serial).and_return(response)
      expect(subject.revoked?).to eq(response)
    end
  end

end
