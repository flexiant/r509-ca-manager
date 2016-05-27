require 'r509'
require 'r509/crl/mongoid_reader_writer'

RSpec.describe R509::CRL::MongoidReaderWriter do

  let(:ca_name) { 'CA name' }
  let(:ca) { double('CA', name: ca_name) }
  let(:crl_pem) { 'CRL pem' }

  describe '#initialize' do
    it 'should accept a parameter' do
      described_class.new(double('CA'))
    end
  end

  subject do
    described_class.new(ca)
  end

  describe '#write_number' do
    context 'when none exists for the CA' do
      before(:each) do
        described_class::CrlNumberEntry.destroy_all
      end
      it 'should be created' do
        subject.write_number(1357)
        expect(described_class::CrlNumberEntry.where(ca_name: ca_name, number: 1357).count).to eq(1)
      end
    end
    context 'when it already exists for the CA' do
      before(:each) do
        described_class::CrlNumberEntry.destroy_all
        described_class::CrlNumberEntry.create!(ca_name: ca_name, number: 123)
      end
      it 'should be updated' do
        subject.write_number(456)
        expect(described_class::CrlNumberEntry.where(ca_name: ca_name, number: 123).count).to eq(0)
        expect(described_class::CrlNumberEntry.where(ca_name: ca_name, number: 456).count).to eq(1)
      end
    end
  end

  describe '#read_number' do
    before(:each) do
      described_class::CrlNumberEntry.destroy_all
    end
    context 'when it does not exist' do
      it 'should read zero' do
        expect(subject.read_number).to eq(0)
      end
    end
    context 'when it exists' do
      before(:each) do
        described_class::CrlNumberEntry.create!(ca_name: ca_name, number: 123)
      end
      it 'should read the number for the CA' do
        expect(subject.read_number).to eq(123)
      end
    end
  end

  describe '#write_list_entry' do
    let(:serial) { 'serial12345'}
    let(:revoke_time) { Time.now.to_i }
    let(:reason) { 11 }
    before(:each) do
      described_class::CrlEntry.destroy_all
    end
    it 'should create an entry with the parameters passed' do
      subject.write_list_entry(serial, revoke_time, reason)
      crlentry = described_class::CrlEntry.first
      expect(crlentry.ca_name).to eq(ca_name)
      expect(crlentry.serial).to eq(serial)
      expect(crlentry.reason).to eq(reason)
      expect(crlentry.revoked_at).to eq(revoke_time)
    end
  end

  describe '#remove_list_entry' do
    let(:serial) { 'serial12345'}
    let(:revoke_time) { Time.now.to_i }
    let(:reason) { 11 }
    before(:each) do
      described_class::CrlEntry.destroy_all
      described_class::CrlEntry.create!(ca_name: ca_name, serial: serial, revoked_at: revoke_time, reason: reason)
    end
    it 'should unrevoke the indicated entry' do
      subject.remove_list_entry(serial)
      entry = described_class::CrlEntry.where(ca_name: ca_name, serial: serial).first
      expect(entry.unrevoked_at).to_not be_blank
    end
  end

  describe '#read_list' do
    let(:serial) { '12345'}
    let(:revoke_time) { Time.now.to_i }
    let(:reason) { 11 }

    it 'should trigger R509::CRL::Administrator#revoke_cert for every entry' do
      admin = double('R509::CRL::Administrator')
      described_class::CrlEntry.destroy_all
      described_class::CrlEntry.create!(ca_name: ca_name, serial: serial.to_s, revoked_at: revoke_time, reason: reason)
      described_class::CrlEntry.create!(ca_name: ca_name, serial: serial.reverse.to_s, revoked_at: revoke_time, reason: reason)
      expect(admin).to receive(:revoke_cert).with(serial.to_i, reason, revoke_time, false)
      expect(admin).to receive(:revoke_cert).with(serial.reverse.to_i, reason, revoke_time, false)
      expect(subject.read_list(admin)).to be_nil
    end
  end

  describe 'REVOCATION_CHECKER' do
    let(:serial) { 'serial12345'}
    let(:revoke_time) { Time.now.to_i }
    let(:reason) { 11 }
    before(:each) do
      described_class::CrlEntry.destroy_all
    end
    context 'when revocation exists' do
      before(:each) do
        described_class::CrlEntry.create!(ca_name: ca_name, serial: serial, revoked_at: revoke_time, reason: reason)
      end
      it 'should return true' do
        expect(described_class::REVOCATION_CHECKER.call(ca_name, serial)).to be_truthy
      end
    end
    context 'when revocation does not exist' do
      it 'should return false' do
        expect(described_class::REVOCATION_CHECKER.call(ca_name, serial)).to be_falsey
      end
    end
  end

end
