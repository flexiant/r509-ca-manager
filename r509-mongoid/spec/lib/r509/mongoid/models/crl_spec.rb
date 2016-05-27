require 'r509'
require 'r509/mongoid/models'

RSpec.describe R509::Mongoid::Models::Crl do

  let(:ca_name) { 'CA name' }
  let(:crl_pem) { 'CRL pem' }

  describe '.store_crl' do
    it 'should save the CRL model with the parameters passed' do
      R509::Mongoid::Models::Crl.destroy_all
      described_class.store_crl(ca_name, crl_pem)
      crl = R509::Mongoid::Models::Crl.where(ca_name: ca_name).first
      expect(crl.crl_pem).to eq(crl_pem)
    end
  end

end
