require 'spec_helper'

describe R509::CertificateAuthority::HTTP::Factory::Certificate do
  describe '#validity_period_converter' do
    let(:factory){described_class.new}
    let(:new_validity_period_converter){double(:new_validity_period_converter)}
    before(:each) do
      allow(R509::CertificateAuthority::HTTP::ValidityPeriodConverter).to receive(:new).and_return(new_validity_period_converter)
    end
    context "without a validity_period_converter set" do
      context "the first time" do
        it "should build one validity_period_converter" do
          expect(R509::CertificateAuthority::HTTP::ValidityPeriodConverter).to receive(:new).with(any_args).once.and_return(new_validity_period_converter)
          factory.validity_period_converter
        end
        it "should build a validity_period_converter without arguments" do
          expect(R509::CertificateAuthority::HTTP::ValidityPeriodConverter).to receive(:new).with(no_args).and_return(new_validity_period_converter)
          factory.validity_period_converter
        end
        it "should return the built validity_period_converter" do
          expect(factory.validity_period_converter).to eq(new_validity_period_converter)
        end
      end
      context "the second and subsequent times" do
        before(:each) do
          @first_time_returned_value = factory.validity_period_converter
        end
        it "should not build a new validity_period_converter" do
          expect(R509::CertificateAuthority::HTTP::ValidityPeriodConverter).not_to receive(:new)
          factory.validity_period_converter
        end
        it "should return the value obtained the first time" do
          expect(factory.validity_period_converter).to eq(@first_time_returned_value)
        end
      end
    end
    context "with a validity_period_converter set" do
      let(:set_validity_period_converter){double(:set_validity_period_converter)}
      before(:each) do
        factory.validity_period_converter = set_validity_period_converter
      end
      it "should not build a new validity_period_converter" do
        expect(R509::CertificateAuthority::HTTP::ValidityPeriodConverter).not_to receive(:new)
        factory.validity_period_converter
      end
      it "should return the set value" do
        expect(factory.validity_period_converter).to eq(set_validity_period_converter)
      end
    end
  end
  describe '#csr_factory' do
    let(:factory){described_class.new}
    let(:new_csr_factory){double(:new_csr_factory)}
    before(:each) do
      allow(R509::CertificateAuthority::HTTP::Factory::CSRFactory).to receive(:new).and_return(new_csr_factory)
    end
    context "without a csr_factory set" do
      context "the first time" do
        it "should build one csr_factory" do
          expect(R509::CertificateAuthority::HTTP::Factory::CSRFactory).to receive(:new).with(any_args).once.and_return(new_csr_factory)
          factory.csr_factory
        end
        it "should build a csr_factory without arguments" do
          expect(R509::CertificateAuthority::HTTP::Factory::CSRFactory).to receive(:new).with(no_args).and_return(new_csr_factory)
          factory.csr_factory
        end
        it "should return the built csr_factory" do
          expect(factory.csr_factory).to eq(new_csr_factory)
        end
      end
      context "the second and subsequent times" do
        before(:each) do
          @first_time_returned_value = factory.csr_factory
        end
        it "should not build a new csr_factory" do
          expect(R509::CertificateAuthority::HTTP::Factory::CSRFactory).not_to receive(:new)
          factory.csr_factory
        end
        it "should return the value obtained the first time" do
          expect(factory.csr_factory).to eq(@first_time_returned_value)
        end
      end
    end
    context "with a csr_factory set" do
      let(:set_csr_factory){double(:set_csr_factory)}
      before(:each) do
        factory.csr_factory = set_csr_factory
      end
      it "should not build a new csr_factory" do
        expect(R509::CertificateAuthority::HTTP::Factory::CSRFactory).not_to receive(:new)
        factory.csr_factory
      end
      it "should return the set value" do
        expect(factory.csr_factory).to eq(set_csr_factory)
      end
    end
  end
  describe '#spki_factory' do
    let(:factory){described_class.new}
    let(:new_spki_factory){double(:new_spki_factory)}
    before(:each) do
      allow(R509::CertificateAuthority::HTTP::Factory::SPKIFactory).to receive(:new).and_return(new_spki_factory)
    end
    context "without a spki_factory set" do
      context "the first time" do
        it "should build one spki_factory" do
          expect(R509::CertificateAuthority::HTTP::Factory::SPKIFactory).to receive(:new).with(any_args).once.and_return(new_spki_factory)
          factory.spki_factory
        end
        it "should build a spki_factory without arguments" do
          expect(R509::CertificateAuthority::HTTP::Factory::SPKIFactory).to receive(:new).with(no_args).and_return(new_spki_factory)
          factory.spki_factory
        end
        it "should return the built spki_factory" do
          expect(factory.spki_factory).to eq(new_spki_factory)
        end
      end
      context "the second and subsequent times" do
        before(:each) do
          @first_time_returned_value = factory.spki_factory
        end
        it "should not build a new spki_factory" do
          expect(R509::CertificateAuthority::HTTP::Factory::SPKIFactory).not_to receive(:new)
          factory.spki_factory
        end
        it "should return the value obtained the first time" do
          expect(factory.spki_factory).to eq(@first_time_returned_value)
        end
      end
    end
    context "with a spki_factory set" do
      let(:set_spki_factory){double(:set_spki_factory)}
      before(:each) do
        factory.spki_factory = set_spki_factory
      end
      it "should not build a new spki_factory" do
        expect(R509::CertificateAuthority::HTTP::Factory::SPKIFactory).not_to receive(:new)
        factory.spki_factory
      end
      it "should return the set value" do
        expect(factory.spki_factory).to eq(set_spki_factory)
      end
    end
  end
  describe '#build' do
    let(:factory){described_class.new}
    let(:validity_period_converter){double(:validity_period_converter, convert: converted_validity_period)}
    let(:subject){double(:subject, empty?: subject_empty)}
    let(:signer_opt_builder){double(:signer_opt_builder)}
    let(:options) do
      {
        'profile' => profile,
        'validityPeriod' => validity_period,
        'csr' => csr,
        'spki' => spki
      }.select{|k, v| v}
    end
    let(:extensions){double(:extensions)}
    let(:converted_validity_period){double(:converted_validity_period)}
    let(:built_signer_options){double(:built_signer_options)}
    let(:signed_cert){double(:signed_cert)}
    before(:each) do
      allow(factory).to receive(:validity_period_converter).and_return(validity_period_converter)
      allow(factory).to receive(:build_extensions).and_return(extensions)
      allow(factory).to receive(:build_signer_options).and_return(built_signer_options)
    end
    context "with a nil CA" do
      let(:ca){nil}
      context "with a profile option" do
        let(:profile){double(:profile)}
        context "with a validity period option" do
          let(:validity_period){double(:validity_period)}
          context "with a csr option" do
            let(:csr){double(:csr)}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
          context "without a csr option" do
            let(:csr){nil}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
        end
        context "without a validity period option" do
          let(:validity_period){nil}
          context "with a csr option" do
            let(:csr){double(:csr)}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
          context "without a csr option" do
            let(:csr){nil}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
        end
      end
      context "without a profile option" do
        let(:profile){nil}
        context "with a validity period option" do
          let(:validity_period){double(:validity_period)}
          context "with a csr option" do
            let(:csr){double(:csr)}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
          context "without a csr option" do
            let(:csr){nil}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
        end
        context "without a validity period option" do
          let(:validity_period){nil}
          context "with a csr option" do
            let(:csr){double(:csr)}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
          context "without a csr option" do
            let(:csr){nil}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
        end
      end
    end
    context "with a CA" do
      let(:ca){double(:ca, sign: signed_cert)}
      context "with a profile option" do
        let(:profile){double(:profile)}
        context "with a validity period option" do
          let(:validity_period){double(:validity_period)}
          context "with a csr option" do
            let(:csr){double(:csr)}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should build extensions once" do
                  expect(factory).to receive(:build_extensions).with(any_args).once.and_return(extensions)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build extensions with the given options" do
                  expect(factory).to receive(:build_extensions).with(options).and_return(extensions)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should convert one validity period" do
                  expect(validity_period_converter).to receive(:convert).with(any_args).once.and_return(converted_validity_period)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should convert the given validity period option" do
                  expect(validity_period_converter).to receive(:convert).with(options['validityPeriod']).and_return(converted_validity_period)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options once" do
                  expect(factory).to receive(:build_signer_options).with(any_args).once.and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the given signer opt builder" do
                  expect(factory).to receive(:build_signer_options).with(signer_opt_builder, any_args).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the given subject" do
                  expect(factory).to receive(:build_signer_options).with(anything, subject, any_args).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the converted validity period" do
                  expect(factory).to receive(:build_signer_options).with(anything, anything, converted_validity_period, any_args).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the built extensions" do
                  expect(factory).to receive(:build_signer_options).with(anything, anything, anything, extensions, anything).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the given options" do
                  expect(factory).to receive(:build_signer_options).with(anything, anything, anything, anything, options).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should sign with the ca once" do
                  expect(ca).to receive(:sign).with(any_args).once.and_return(signed_cert)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should sign with the ca once" do
                  expect(ca).to receive(:sign).with(built_signer_options).and_return(signed_cert)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should returned the CA-signed cert" do
                  expect(factory.build(ca, subject, signer_opt_builder, options)).to eq(signed_cert)
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should build extensions once" do
                  expect(factory).to receive(:build_extensions).with(any_args).once.and_return(extensions)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build extensions with the given options" do
                  expect(factory).to receive(:build_extensions).with(options).and_return(extensions)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should convert one validity period" do
                  expect(validity_period_converter).to receive(:convert).with(any_args).once.and_return(converted_validity_period)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should convert the given validity period option" do
                  expect(validity_period_converter).to receive(:convert).with(options['validityPeriod']).and_return(converted_validity_period)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options once" do
                  expect(factory).to receive(:build_signer_options).with(any_args).once.and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the given signer opt builder" do
                  expect(factory).to receive(:build_signer_options).with(signer_opt_builder, any_args).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the given subject" do
                  expect(factory).to receive(:build_signer_options).with(anything, subject, any_args).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the converted validity period" do
                  expect(factory).to receive(:build_signer_options).with(anything, anything, converted_validity_period, any_args).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the built extensions" do
                  expect(factory).to receive(:build_signer_options).with(anything, anything, anything, extensions, anything).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the given options" do
                  expect(factory).to receive(:build_signer_options).with(anything, anything, anything, anything, options).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should sign with the ca once" do
                  expect(ca).to receive(:sign).with(any_args).once.and_return(signed_cert)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should sign with the ca once" do
                  expect(ca).to receive(:sign).with(built_signer_options).and_return(signed_cert)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should returned the CA-signed cert" do
                  expect(factory.build(ca, subject, signer_opt_builder, options)).to eq(signed_cert)
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
          context "without a csr option" do
            let(:csr){nil}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should build extensions once" do
                  expect(factory).to receive(:build_extensions).with(any_args).once.and_return(extensions)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build extensions with the given options" do
                  expect(factory).to receive(:build_extensions).with(options).and_return(extensions)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should convert one validity period" do
                  expect(validity_period_converter).to receive(:convert).with(any_args).once.and_return(converted_validity_period)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should convert the given validity period option" do
                  expect(validity_period_converter).to receive(:convert).with(options['validityPeriod']).and_return(converted_validity_period)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options once" do
                  expect(factory).to receive(:build_signer_options).with(any_args).once.and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the given signer opt builder" do
                  expect(factory).to receive(:build_signer_options).with(signer_opt_builder, any_args).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the given subject" do
                  expect(factory).to receive(:build_signer_options).with(anything, subject, any_args).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the converted validity period" do
                  expect(factory).to receive(:build_signer_options).with(anything, anything, converted_validity_period, any_args).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the built extensions" do
                  expect(factory).to receive(:build_signer_options).with(anything, anything, anything, extensions, anything).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should build signer options with the given options" do
                  expect(factory).to receive(:build_signer_options).with(anything, anything, anything, anything, options).and_return(built_signer_options)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should sign with the ca once" do
                  expect(ca).to receive(:sign).with(any_args).once.and_return(signed_cert)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should sign with the ca once" do
                  expect(ca).to receive(:sign).with(built_signer_options).and_return(signed_cert)
                  factory.build(ca, subject, signer_opt_builder, options)
                end
                it "should returned the CA-signed cert" do
                  expect(factory.build(ca, subject, signer_opt_builder, options)).to eq(signed_cert)
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
        end
        context "without a validity period option" do
          let(:validity_period){nil}
          context "with a csr option" do
            let(:csr){double(:csr)}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
          context "without a csr option" do
            let(:csr){nil}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
        end
      end
      context "without a profile option" do
        let(:profile){nil}
        context "with a validity period option" do
          let(:validity_period){double(:validity_period)}
          context "with a csr option" do
            let(:csr){double(:csr)}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
          context "without a csr option" do
            let(:csr){nil}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
        end
        context "without a validity period option" do
          let(:validity_period){nil}
          context "with a csr option" do
            let(:csr){double(:csr)}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
          context "without a csr option" do
            let(:csr){nil}
            context "with a spki option" do
              let(:spki){double(:spki)}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
            context "without a spki option" do
              let(:spki){nil}
              context "with a non empty subject" do
                let(:subject_empty){false}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
              context "with an empty subject" do
                let(:subject_empty){true}
                it "should raise error" do
                  expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
                end
                it "should not build any extensions" do
                  expect(factory).not_to receive(:build_extensions).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should not try to convert any validity periods" do
                  expect(validity_period_converter).not_to receive(:convert).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
                it "should build any signer options" do
                  expect(factory).not_to receive(:build_signer_options).with(any_args)
                  begin
                    factory.build(ca, subject, signer_opt_builder, options)
                  rescue
                  end
                end
              end
            end
          end
        end
      end
    end
  end

  describe '#build_extensions' do
    let(:factory){described_class.new}
    let(:san_extension_opt) do
      [
        double(:san_opt1, empty?: false),
        double(:san_opt2, empty?: false),
        [],
        "",
        double(:san_opt3, empty?: false)
      ]
    end
    let(:dns_names_opt) do
      [
        "",
        double(:dns_opt1, empty?: false, strip: double(:dns_opt_1_stripped)),
        double(:dns_opt2, empty?: false, strip: double(:dns_opt_2_stripped)),
        [],
        double(:dns_opt3, empty?: false, strip: double(:dns_opt_3_stripped))
      ]
    end
    let(:san_extension){double(:san_extension)}
    let(:asn1_general_names){double(:asn1_general_names, create_item: nil, names: double(:names, empty?: false))}
    let(:asn1_parsed_names){double(:asn1_parsed_names)}
    before(:each) do
      allow(R509::Cert::Extensions::SubjectAlternativeName).to receive(:new).and_return(san_extension)
      allow(R509::ASN1::GeneralNames).to receive(:new).and_return(asn1_general_names)
      allow(R509::ASN1).to receive(:general_name_parser).and_return(asn1_parsed_names)
    end
    context "with an extensions option" do
      let(:options) do
        {
          'extensions' => extension_option,
          'other_option' => 'other_value'
         }
      end
      context "including a subjectAlternativeName extension" do
        context "and a dNSNames extension" do
          let(:extension_option) do
            {
              'subjectAlternativeName' => san_extension_opt,
              'dNSNames' => dns_names_opt
            }
          end
          it "should create no asn1 general names" do
            expect(R509::ASN1::GeneralNames).not_to receive(:new).with(any_args)
            factory.send(:build_extensions, options)
          end
          it "should parse subject alternative names once" do
            expect(R509::ASN1).to receive(:general_name_parser).with(any_args).once.and_return(asn1_general_names)
            factory.send(:build_extensions, options)
          end
          it "should parse subject alternative names with the non empty elements of the subject alternative name extension specification" do
            expect(R509::ASN1).to receive(:general_name_parser).with(san_extension_opt.reject(&:empty?)).and_return(asn1_parsed_names)
            factory.send(:build_extensions, options)
          end
          it "should build one subject alternative name extension" do
            expect(R509::Cert::Extensions::SubjectAlternativeName).to receive(:new).with(any_args).once.and_return(san_extension)
            factory.send(:build_extensions, options)
          end
          it "should build a subject alternative name extension with te parsed san elements as value" do
            expect(R509::Cert::Extensions::SubjectAlternativeName).to receive(:new).with(value: asn1_parsed_names).and_return(san_extension)
            factory.send(:build_extensions, options)
          end
          it "should return an array" do
            expect(factory.send(:build_extensions, options)).to be_a_kind_of(Array)
          end
          it "should return a set of 1 element" do
            expect(factory.send(:build_extensions, options).length).to eq(1)
          end
          it "should return an array with the built subject Alternative Name extension" do
            expect(factory.send(:build_extensions, options).first).to eq(san_extension)
          end
        end
        context "but no dNSNames extension" do
          let(:extension_option) do
            {
              'subjectAlternativeName' => san_extension_opt
            }
          end
          it "should create no asn1 general names" do
            expect(R509::ASN1::GeneralNames).not_to receive(:new).with(any_args)
            factory.send(:build_extensions, options)
          end
          it "should parse subject alternative names once" do
            expect(R509::ASN1).to receive(:general_name_parser).with(any_args).once.and_return(asn1_general_names)
            factory.send(:build_extensions, options)
          end
          it "should parse subject alternative names with the non empty elements of the subject alternative name extension specification" do
            expect(R509::ASN1).to receive(:general_name_parser).with(san_extension_opt.reject(&:empty?)).and_return(asn1_parsed_names)
            factory.send(:build_extensions, options)
          end
          it "should build one subject alternative name extension" do
            expect(R509::Cert::Extensions::SubjectAlternativeName).to receive(:new).with(any_args).once.and_return(san_extension)
            factory.send(:build_extensions, options)
          end
          it "should build a subject alternative name extension with te parsed san elements as value" do
            expect(R509::Cert::Extensions::SubjectAlternativeName).to receive(:new).with(value: asn1_parsed_names).and_return(san_extension)
            factory.send(:build_extensions, options)
          end
          it "should return an array" do
            expect(factory.send(:build_extensions, options)).to be_a_kind_of(Array)
          end
          it "should return a set of 1 element" do
            expect(factory.send(:build_extensions, options).length).to eq(1)
          end
          it "should return an array with the built subject Alternative Name extension" do
            expect(factory.send(:build_extensions, options).first).to eq(san_extension)
          end
        end
      end
      context "not including a subjectAlternativeName extension" do
        context "but including a dNSNames extension" do
          let(:extension_option) do
            {
              'dNSNames' => dns_names_opt
            }
          end
          it "should parse no subject alternative names" do
            expect(R509::ASN1).not_to receive(:general_name_parser).with(any_args)
            factory.send(:build_extensions, options)
          end
          it "should create one asn1 general names" do
            expect(R509::ASN1::GeneralNames).to receive(:new).with(any_args).once.and_return(asn1_general_names)
            factory.send(:build_extensions, options)
          end
          it "should create a asn1 general names without any arguments" do
            expect(R509::ASN1::GeneralNames).to receive(:new).with(no_args).and_return(asn1_general_names)
            factory.send(:build_extensions, options)
          end
          it "should create exactly as many items in the asn1 general names as non-empty dNSNames options" do
            expect(asn1_general_names).to receive(:create_item).with(any_args).exactly(dns_names_opt.reject(&:empty?).length).times
            factory.send(:build_extensions, options)
          end
          it "should create as many items in the asn1 general names as non-empty dNSNames options with a 2 tags" do
            dns_names_opt.reject(&:empty?).each do |dns_name_opt|
              expect(asn1_general_names).to receive(:create_item).with(hash_including(tag: 2))
            end
            factory.send(:build_extensions, options)
          end
          it "should create as many items in the asn1 general names as non-empty dNSNames options with the stripped dns name opt as value" do
            dns_names_opt.reject(&:empty?).each do |dns_name_opt|
              expect(asn1_general_names).to receive(:create_item).with(hash_including(value: dns_name_opt.strip))
            end
            factory.send(:build_extensions, options)
          end
          it "should build one subject alternative name extension" do
            expect(R509::Cert::Extensions::SubjectAlternativeName).to receive(:new).with(any_args).once.and_return(san_extension)
            factory.send(:build_extensions, options)
          end
          it "should build a subject alternative name extension with the asn1 general names element as value" do
            expect(R509::Cert::Extensions::SubjectAlternativeName).to receive(:new).with(value: asn1_general_names).and_return(san_extension)
            factory.send(:build_extensions, options)
          end
          it "should build the subject alternative name extension after creating all the items on the on the asn1 general names element" do
            dns_names_opt.reject(&:empty?).each do |dns_name_opt|
              expect(asn1_general_names).to receive(:create_item).with(any_args).ordered
            end
            expect(R509::Cert::Extensions::SubjectAlternativeName).to receive(:new).with(any_args).and_return(san_extension).ordered
            factory.send(:build_extensions, options)
          end
          it "should return an array" do
            expect(factory.send(:build_extensions, options)).to be_a_kind_of(Array)
          end
          it "should return a set of 1 element" do
            expect(factory.send(:build_extensions, options).length).to eq(1)
          end
          it "should return an array with the built subject Alternative Name extension" do
            expect(factory.send(:build_extensions, options).first).to eq(san_extension)
          end
        end
        context "nor a dNSNames extension" do
          let(:extension_option){Hash.new}
          it "should parse no subject alternative names" do
            expect(R509::ASN1).not_to receive(:general_name_parser).with(any_args)
            factory.send(:build_extensions, options)
          end
          it "should create no asn1 general names" do
            expect(R509::ASN1::GeneralNames).not_to receive(:new).with(any_args)
            factory.send(:build_extensions, options)
          end
          it "should build no subject alternative name extension" do
            expect(R509::Cert::Extensions::SubjectAlternativeName).not_to receive(:new).with(any_args)
            factory.send(:build_extensions, options)
          end
          it "should return an array" do
            expect(factory.send(:build_extensions, options)).to be_a_kind_of(Array)
          end
          it "should return an empty set" do
            expect(factory.send(:build_extensions, options)).to be_empty
          end
        end
      end
    end
    context "without an extensions option" do
      let(:options) do
        {
          "other_option" => 'other_value'
        }
      end
      it "should parse no subject alternative names" do
        expect(R509::ASN1).not_to receive(:general_name_parser).with(any_args)
        factory.send(:build_extensions, options)
      end
      it "should create no asn1 general names" do
        expect(R509::ASN1::GeneralNames).not_to receive(:new).with(any_args)
        factory.send(:build_extensions, options)
      end
      it "should build no subject alternative name extension" do
        expect(R509::Cert::Extensions::SubjectAlternativeName).not_to receive(:new).with(any_args)
        factory.send(:build_extensions, options)
      end
      it "should return an array" do
        expect(factory.send(:build_extensions, options)).to be_a_kind_of(Array)
      end
      it "should return an empty set" do
        expect(factory.send(:build_extensions, options)).to be_empty
      end
    end
  end
  describe '#build_signer_options' do
    let(:factory){described_class.new}
    let(:signer_opt_builder){double(:signer_opt_builder, build_and_enforce: signer_options)}
    let(:subject){double(:subject)}
    let(:extensions){double(:extensions)}
    let(:validity_period) do
      {
        not_before: double(:validity_period_not_before),
        not_after: double(:validity_period_not_after)
      }
    end
    let(:csr_option){double(:csr_option)}
    let(:spki_option){double(:spki_option)}
    let(:profile_option){double(:profile_option)}
    let(:message_digest_option){double(:message_digest_option)}
    let(:signer_options){double(:signer_options)}
    let(:csr_factory){double(:csr_factory, build: csr)}
    let(:spki_factory){double(:spki_factory, build: spki)}
    let(:csr){double(:csr)}
    let(:spki){double(:spki)}
    before(:each) do
      allow(factory).to receive(:csr_factory).and_return(csr_factory)
      allow(factory).to receive(:spki_factory).and_return(spki_factory)
    end
    context "with a csr option" do
      context "with a spki option" do
        let(:options) do
          {
            'csr' => csr_option,
            'spki' => spki_option,
            'profile' => profile_option,
            'message_digest' => message_digest_option
          }
        end
        it "should build exactly one csr with the csr factory" do
          expect(csr_factory).to receive(:build).with(any_args).once.and_return(csr)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build no spki with the spki factory" do
          expect(spki_factory).not_to receive(:build).with(any_args)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build exactly a csr with the csr factory and the given csr option" do
          expect(csr_factory).to receive(:build).with(csr: csr_option).and_return(csr)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly one set of signer opts with the given signer opt builder" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(any_args).once.and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the built csr" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(csr: csr)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and no spki option" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_not_including(spki: anything)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given profile option" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(profile_name: profile_option)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given subject" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(subject: subject)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given extensions" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(extensions: extensions)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given message digest option" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(message_digest: message_digest_option)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the not before property of the given validity period" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(not_before: validity_period[:not_before])).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the not after property of the given validity period" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(not_after: validity_period[:not_after])).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should return the built and enforced set of signer opts" do
          expect(factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)).to eq(signer_options)
        end
      end
      context "with no spki option" do
        let(:options) do
          {
            'csr' => csr_option,
            'profile' => profile_option,
            'message_digest' => message_digest_option
          }
        end
        it "should build exactly one csr with the csr factory" do
          expect(csr_factory).to receive(:build).with(any_args).once.and_return(csr)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build no spki with the spki factory" do
          expect(spki_factory).not_to receive(:build).with(any_args)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build exactly a csr with the csr factory and the given csr option" do
          expect(csr_factory).to receive(:build).with(csr: csr_option).and_return(csr)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly one set of signer opts with the given signer opt builder" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(any_args).once.and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the built csr" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(csr: csr)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and no spki option" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_not_including(spki: anything)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given profile option" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(profile_name: profile_option)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given subject" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(subject: subject)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given extensions" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(extensions: extensions)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given message digest option" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(message_digest: message_digest_option)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the not before property of the given validity period" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(not_before: validity_period[:not_before])).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the not after property of the given validity period" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(not_after: validity_period[:not_after])).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should return the built and enforced set of signer opts" do
          expect(factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)).to eq(signer_options)
        end
      end
    end
    context "with no csr option" do
      context "with a spki option" do
        let(:options) do
          {
            'spki' => spki_option,
            'profile' => profile_option,
            'message_digest' => message_digest_option
          }
        end
        it "should build exactly one spki with the spki factory" do
          expect(spki_factory).to receive(:build).with(any_args).once.and_return(spki)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build exactly a spki with the spki factory and the given spki option" do
          expect(spki_factory).to receive(:build).with(hash_including(spki: spki_option)).and_return(spki)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build exactly a spki with the spki factory and the given subject" do
          expect(spki_factory).to receive(:build).with(hash_including(subject: subject)).and_return(spki)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build no csr with the csr factory" do
          expect(csr_factory).not_to receive(:build).with(any_args)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly one set of signer opts with the given signer opt builder" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(any_args).once.and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the built spki" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(spki: spki)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and no csr option" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_not_including(csr: anything)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given profile option" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(profile_name: profile_option)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given subject" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(subject: subject)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given extensions" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(extensions: extensions)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the given message digest option" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(message_digest: message_digest_option)).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the not before property of the given validity period" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(not_before: validity_period[:not_before])).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should build and enforce exactly a set of signer opts with the given signer opt builder and the not after property of the given validity period" do
          expect(signer_opt_builder).to receive(:build_and_enforce).with(hash_including(not_after: validity_period[:not_after])).and_return(signer_options)
          factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
        end
        it "should return the built and enforced set of signer opts" do
          expect(factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)).to eq(signer_options)
        end
      end
      context "with no spki option" do
        let(:options) do
          {
            'profile' => profile_option,
            'message_digest' => message_digest_option
          }
        end
        it "should not build any spki with the spki factory" do
          expect(spki_factory).not_to receive(:build).with(any_args)
          begin
            factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
          rescue
          end
        end
        it "should not build any csr with the csr factory" do
          expect(csr_factory).not_to receive(:build).with(any_args)
          begin
            factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
          rescue
          end
        end
        it "should not build and enforce any signer option set with the signer opt builder" do
          expect(signer_opt_builder).not_to receive(:build_and_enforce).with(any_args)
          begin
            factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)
          rescue
          end
        end
        it "should raise error" do
          expect{factory.send(:build_signer_options, signer_opt_builder, subject, validity_period, extensions, options)}.to raise_error(ArgumentError)
        end
      end
    end
  end
end
