require 'spec_helper'

describe R509::CertificateAuthority::HTTP::Factory::CA do
  describe '#certificate_factory' do
    let(:factory){described_class.new}
    let(:new_certificate_factory){double(:new_certificate_factory)}
    before(:each) do
      allow(R509::CertificateAuthority::HTTP::Factory::Certificate).to receive(:new).and_return(new_certificate_factory)
    end
    context "without a certificate_factory set" do
      context "the first time" do
        it "should build one certificate_factory" do
          expect(R509::CertificateAuthority::HTTP::Factory::Certificate).to receive(:new).with(any_args).once.and_return(new_certificate_factory)
          factory.certificate_factory
        end
        it "should build a certificate_factory without arguments" do
          expect(R509::CertificateAuthority::HTTP::Factory::Certificate).to receive(:new).with(no_args).and_return(new_certificate_factory)
          factory.certificate_factory
        end
        it "should return the built certificate_factory" do
          expect(factory.certificate_factory).to eq(new_certificate_factory)
        end
      end
      context "the second and subsequent times" do
        before(:each) do
          @first_time_returned_value = factory.certificate_factory
        end
        it "should not build a new certificate_factory" do
          expect(R509::CertificateAuthority::HTTP::Factory::Certificate).not_to receive(:new)
          factory.certificate_factory
        end
        it "should return the value obtained the first time" do
          expect(factory.certificate_factory).to eq(@first_time_returned_value)
        end
      end
    end
    context "with a certificate_factory set" do
      let(:set_certificate_factory){double(:set_certificate_factory)}
      before(:each) do
        factory.certificate_factory = set_certificate_factory
      end
      it "should not build a new certificate_factory" do
        expect(R509::CertificateAuthority::HTTP::Factory::Certificate).not_to receive(:new)
        factory.certificate_factory
      end
      it "should return the set value" do
        expect(factory.certificate_factory).to eq(set_certificate_factory)
      end
    end
  end

  describe '#build' do
    let(:factory){described_class.new}
    let(:certificate_factory){double(:certificate_factory)}
    let(:ca){double(:ca)}
    let(:subject){double(:subject, empty?: subject_empty)}
    let(:signer_opt_builder){double(:signer_opt_builder)}
    let(:csr){double(:csr)}
    let(:ca_cert){double(:ca_cert)}
    let(:validity_period){double(:validity_period)}
    let(:profile){double(:profile)}
    let(:extensions){double(:extensions)}
    let(:message_digest){double(:message_digest)}
    before(:each) do
      allow(factory).to receive(:build_csr).and_return(csr)
      allow(factory).to receive(:certificate_factory).and_return(certificate_factory)
      allow(certificate_factory).to receive(:build).and_return(ca_cert)
      allow(factory).to receive(:store_ca)
    end
    context "without a ca_name option" do
      let(:options) do
        {
          'validityPeriod' => validity_period,
          'profile' => profile,
          'extensions' => extensions,
          'message_digest' => message_digest
        }
      end
      context "with an empty subject" do
        let(:subject_empty){true}
        it "should not build any csr" do
          expect(factory).not_to receive(:build_csr)
          begin
            factory.build(ca, subject, signer_opt_builder, options)
          rescue
          end
        end
        it "should not build any certificates with the certificate factory" do
          expect(certificate_factory).not_to receive(:build)
          begin
            factory.build(ca, subject, signer_opt_builder, options)
          rescue
          end
        end
        it "should not store any CAs" do
          expect(factory).not_to receive(:store_ca)
          begin
            factory.build(ca, subject, signer_opt_builder, options)
          rescue
          end
        end
        it "should raise error" do
          expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
        end
      end
      context "with a non-empty subject" do
        let(:subject_empty){false}
        it "should not build any csr" do
          expect(factory).not_to receive(:build_csr)
          begin
            factory.build(ca, subject, signer_opt_builder, options)
          rescue
          end
        end
        it "should not build any certificates with the certificate factory" do
          expect(certificate_factory).not_to receive(:build)
          begin
            factory.build(ca, subject, signer_opt_builder, options)
          rescue
          end
        end
        it "should not store any CAs" do
          expect(factory).not_to receive(:store_ca)
          begin
            factory.build(ca, subject, signer_opt_builder, options)
          rescue
          end
        end
        it "should raise error" do
          expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
        end
      end
    end
    context "with a ca_name option" do
      let(:options) do
        {
          'validityPeriod' => validity_period,
          'profile' => profile,
          'extensions' => extensions,
          'message_digest' => message_digest,
          'ca_name' => double(:ca_name)
        }
      end
      context "with an empty subject" do
        let(:subject_empty){true}
        it "should not build any csr" do
          expect(factory).not_to receive(:build_csr)
          begin
            factory.build(ca, subject, signer_opt_builder, options)
          rescue
          end
        end
        it "should not build any certificates with the certificate factory" do
          expect(certificate_factory).not_to receive(:build)
          begin
            factory.build(ca, subject, signer_opt_builder, options)
          rescue
          end
        end
        it "should not store any CAs" do
          expect(factory).not_to receive(:store_ca)
          begin
            factory.build(ca, subject, signer_opt_builder, options)
          rescue
          end
        end
        it "should raise error" do
          expect{factory.build(ca, subject, signer_opt_builder, options)}.to raise_error(ArgumentError)
        end
      end
      context "with a non-empty subject" do
        let(:subject_empty){false}
        it "should build exactly one csr" do
          expect(factory).to receive(:build_csr).with(any_args).once.and_return(csr)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should build a csr with the given subject" do
          expect(factory).to receive(:build_csr).with(subject).and_return(csr)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should build exactly one certificate with the certificate factory" do
          expect(certificate_factory).to receive(:build).with(any_args).once.and_return(ca_cert)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should build exactly a certificate with the certificate factory and the given ca" do
          expect(certificate_factory).to receive(:build).with(ca, any_args).and_return(ca_cert)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should build exactly a certificate with the certificate factory and the given subject" do
          expect(certificate_factory).to receive(:build).with(anything, subject, any_args).and_return(ca_cert)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should build exactly a certificate with the certificate factory and the given signer opt builder" do
          expect(certificate_factory).to receive(:build).with(anything, anything, signer_opt_builder, anything).and_return(ca_cert)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should build exactly a certificate with the certificate factory and the built csr as option" do
          expect(certificate_factory).to receive(:build).with(anything, anything, anything, hash_including('csr' => csr)).and_return(ca_cert)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should build exactly a certificate with the certificate factory and the validity period option as option" do
          expect(certificate_factory).to receive(:build).with(anything, anything, anything, hash_including('validityPeriod' => validity_period)).and_return(ca_cert)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should build exactly a certificate with the certificate factory and the profile option as option" do
          expect(certificate_factory).to receive(:build).with(anything, anything, anything, hash_including('profile' => profile)).and_return(ca_cert)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should build exactly a certificate with the certificate factory and the extensions option as option" do
          expect(certificate_factory).to receive(:build).with(anything, anything, anything, hash_including('extensions' => extensions)).and_return(ca_cert)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should build exactly a certificate with the certificate factory and the message digest option as option" do
          expect(certificate_factory).to receive(:build).with(anything, anything, anything, hash_including('message_digest' => message_digest)).and_return(ca_cert)
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should store exactly one CA" do
          expect(factory).to receive(:store_ca).with(any_args).once
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should store a CA with the built certificate" do
          expect(factory).to receive(:store_ca).with(ca_cert, any_args).once
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should store a CA with the built csr" do
          expect(factory).to receive(:store_ca).with(anything, csr, anything).once
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should store a CA with the given options" do
          expect(factory).to receive(:store_ca).with(anything, anything, options).once
          factory.build(ca, subject, signer_opt_builder, options)
        end
        it "should return the built certificate" do
          expect(factory.build(ca, subject, signer_opt_builder, options)).to eq(ca_cert)
        end
      end
    end
  end

  describe '#build_csr' do
    let(:factory){described_class.new}
    let(:csr){double(:csr)}
    let(:subject){double(:subject)}
    before(:each) do
      allow(R509::CSR).to receive(:new).and_return(csr)
    end
    context "with just the subject" do
      it "should build exactly one csr" do
        expect(R509::CSR).to receive(:new).with(any_args).once.and_return(csr)
        factory.send(:build_csr, subject)
      end
      it "should build a csr with the given subject as subject" do
        expect(R509::CSR).to receive(:new).with(subject: subject).and_return(csr)
        factory.send(:build_csr, subject)
      end
      it "should return the built csr" do
        expect(factory.send(:build_csr, subject)).to eq(csr)
      end
    end
    context "with the subject and a key" do
      let(:key){double(:key)}
      it "should build exactly one csr" do
        expect(R509::CSR).to receive(:new).with(any_args).once.and_return(csr)
        factory.send(:build_csr, subject, key)
      end
      it "should build a csr with the given subject as subject and the key as key" do
        expect(R509::CSR).to receive(:new).with(subject: subject, key: key).and_return(csr)
        factory.send(:build_csr, subject, key)
      end
      it "should return the built csr" do
        expect(factory.send(:build_csr, subject, key)).to eq(csr)
      end
    end
  end

  describe '#store_ca' do
    let(:factory){described_class.new}
    let(:ca_cert){double(:ca_cert, to_pem: public_key)}
    let(:csr){double(:csr)}
    let(:options) do
      {
        'ca_name' => double(:ca_name),
        'ca' => double(:ca),
        'ca_cert_password' => double(:ca_cert_password)
      }
    end
    let(:certificate_authority_model){double(:certificate_authority_model, new: new_ca_model_object, where: [ca_model_object])}
    let(:certificate_model){double(:certificate_model, new: new_certificate_model_object)}
    let(:ca_model_object){double(:ca_model_object)}
    let(:new_ca_model_object){double(:new_ca_model_object, save: new_ca_can_be_saved, new_record?: !new_ca_can_be_saved, update_attributes: new_ca_can_be_updated, errors: double(:errors, as_json: double(:errors_as_json)), destroy: true)}
    let(:new_certificate_model_object){double(:new_certificate_model_object, save: new_cert_can_be_saved, new_record?: !new_cert_can_be_saved, errors: double(:errors, as_json: double(:errors_as_json)), destroy: true)}
    let(:ca_config){double(:ca_config, to_yaml: ca_config_yaml)}
    let(:new_ca_can_be_saved){true}
    let(:new_ca_can_be_updated){true}
    let(:new_cert_can_be_saved){true}
    let(:private_key){double(:private_key)}
    let(:public_key){double(:public_key)}
    let(:ca_config_yaml){double(:ca_config_yaml)}
    before(:each) do
      allow(factory).to receive(:build_ca_config).and_return(ca_config)
      allow(factory).to receive(:build_private_key).and_return(private_key)
      allow(factory).to receive(:certificate_model).and_return(certificate_model)
      allow(factory).to receive(:certificate_authority_model).and_return(certificate_authority_model)
    end
    context "if the ca can be created" do
      context "if the certificate can be created" do
        context "if the ca can be updated with the created certificate" do
          it "should build one CA config" do
            expect(factory).to receive(:build_ca_config).with(any_args).once.and_return(ca_config)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build a CA config with the given options" do
            expect(factory).to receive(:build_ca_config).with(options).and_return(ca_config)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build exactly one new CA model object" do
            expect(certificate_authority_model).to receive(:new).with(any_args).once.and_return(new_ca_model_object)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build a new CA model object with the given ca name option" do
            expect(certificate_authority_model).to receive(:new).with(hash_including(name: options['ca_name'])).and_return(new_ca_model_object)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build a new CA model object with the built ca config yaml as config yaml" do
            expect(certificate_authority_model).to receive(:new).with(hash_including(config_yaml: ca_config_yaml)).and_return(new_ca_model_object)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should save the built CA once" do
            expect(new_ca_model_object).to receive(:save).and_return(new_ca_can_be_saved)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should query for a CA model once" do
            expect(certificate_authority_model).to receive(:where).with(any_args).once.and_return([ca_model_object])
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should query for a CA model with the given ca option as name" do
            expect(certificate_authority_model).to receive(:where).with(name: options['ca']).and_return([ca_model_object])
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build one private key" do
            expect(factory).to receive(:build_private_key).with(any_args).once.and_return(private_key)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build a private key with the given csr" do
            expect(factory).to receive(:build_private_key).with(csr, anything).once.and_return(private_key)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build a private key with the given options" do
            expect(factory).to receive(:build_private_key).with(anything, options).once.and_return(private_key)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build exactly one new certificate model" do
            expect(certificate_model).to receive(:new).with(any_args).once.and_return(new_certificate_model_object)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build a new certificate model with the given ca_cert pem representation as public key" do
            expect(certificate_model).to receive(:new).with(hash_including(public_key: public_key)).and_return(new_certificate_model_object)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build a new certificate model with the built private key as private key" do
            expect(certificate_model).to receive(:new).with(hash_including(private_key: private_key)).and_return(new_certificate_model_object)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build a new certificate model with the given ca_cert_password option as password" do
            expect(certificate_model).to receive(:new).with(hash_including(password: options['ca_cert_password'])).and_return(new_certificate_model_object)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should build a new certificate model with the queried CA model as signing CA" do
            expect(certificate_model).to receive(:new).with(hash_including(signing_ca: ca_model_object)).and_return(new_certificate_model_object)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should save the cert once" do
            expect(new_certificate_model_object).to receive(:save).once.and_return(new_cert_can_be_saved)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should update the built CA once" do
            expect(new_ca_model_object).to receive(:update_attributes).with(any_args).once.and_return(new_ca_can_be_updated)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should update the built CA with the built certificate as CA certificate" do
            expect(new_ca_model_object).to receive(:update_attributes).with(ca_certificate: new_certificate_model_object).and_return(new_ca_can_be_updated)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should save the built CA before saving the built certificate" do
            expect(new_ca_model_object).to receive(:save).and_return(new_ca_can_be_saved).ordered
            expect(new_certificate_model_object).to receive(:save).and_return(new_cert_can_be_saved).ordered
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should update the built CA after saving the built certificate" do
            expect(new_certificate_model_object).to receive(:save).and_return(new_cert_can_be_saved).ordered
            expect(new_ca_model_object).to receive(:update_attributes).with(any_args).and_return(new_ca_can_be_updated).ordered
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should save the built CA before updating it" do
            expect(new_ca_model_object).to receive(:save).and_return(new_certificate_model_object).ordered
            expect(new_ca_model_object).to receive(:update_attributes).with(any_args).and_return(new_ca_can_be_updated).ordered
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should not raise error" do
            expect{factory.send(:store_ca, ca_cert, csr, options)}.not_to raise_error
          end
          it "should not destroy the created certificate" do
            expect(new_certificate_model_object).not_to receive(:destroy)
            factory.send(:store_ca, ca_cert, csr, options)
          end
          it "should not destroy the created CA" do
            expect(new_ca_model_object).not_to receive(:destroy)
            factory.send(:store_ca, ca_cert, csr, options)
          end
        end
        context "if the ca cannot be updated with the created certificate" do
          let(:new_ca_can_be_updated){false}
          it "should build one CA config" do
            expect(factory).to receive(:build_ca_config).with(any_args).once.and_return(ca_config)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build a CA config with the given options" do
            expect(factory).to receive(:build_ca_config).with(options).and_return(ca_config)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build exactly one new CA model object" do
            expect(certificate_authority_model).to receive(:new).with(any_args).once.and_return(new_ca_model_object)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build a new CA model object with the given ca name option" do
            expect(certificate_authority_model).to receive(:new).with(hash_including(name: options['ca_name'])).and_return(new_ca_model_object)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build a new CA model object with the built ca config yaml as config yaml" do
            expect(certificate_authority_model).to receive(:new).with(hash_including(config_yaml: ca_config_yaml)).and_return(new_ca_model_object)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should save the built CA once" do
            expect(new_ca_model_object).to receive(:save).and_return(new_ca_can_be_saved)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should query for a CA model once" do
            expect(certificate_authority_model).to receive(:where).with(any_args).once.and_return([ca_model_object])
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should query for a CA model with the given ca option as name" do
            expect(certificate_authority_model).to receive(:where).with(name: options['ca']).and_return([ca_model_object])
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build one private key" do
            expect(factory).to receive(:build_private_key).with(any_args).once.and_return(private_key)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build a private key with the given csr" do
            expect(factory).to receive(:build_private_key).with(csr, anything).once.and_return(private_key)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build a private key with the given options" do
            expect(factory).to receive(:build_private_key).with(anything, options).once.and_return(private_key)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build exactly one new certificate model" do
            expect(certificate_model).to receive(:new).with(any_args).once.and_return(new_certificate_model_object)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build a new certificate model with the given ca_cert pem representation as public key" do
            expect(certificate_model).to receive(:new).with(hash_including(public_key: public_key)).and_return(new_certificate_model_object)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build a new certificate model with the built private key as private key" do
            expect(certificate_model).to receive(:new).with(hash_including(private_key: private_key)).and_return(new_certificate_model_object)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build a new certificate model with the given ca_cert_password option as password" do
            expect(certificate_model).to receive(:new).with(hash_including(password: options['ca_cert_password'])).and_return(new_certificate_model_object)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should build a new certificate model with the queried CA model as signing CA" do
            expect(certificate_model).to receive(:new).with(hash_including(signing_ca: ca_model_object)).and_return(new_certificate_model_object)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should save the cert once" do
            expect(new_certificate_model_object).to receive(:save).once.and_return(new_cert_can_be_saved)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should update the built CA once" do
            expect(new_ca_model_object).to receive(:update_attributes).with(any_args).once.and_return(new_ca_can_be_updated)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should update the built CA with the built certificate as CA certificate" do
            expect(new_ca_model_object).to receive(:update_attributes).with(ca_certificate: new_certificate_model_object).and_return(new_ca_can_be_updated)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should save the built CA before saving the built certificate" do
            expect(new_ca_model_object).to receive(:save).and_return(new_ca_can_be_saved).ordered
            expect(new_certificate_model_object).to receive(:save).and_return(new_cert_can_be_saved).ordered
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should update the built CA after saving the built certificate" do
            expect(new_certificate_model_object).to receive(:save).and_return(new_cert_can_be_saved).ordered
            expect(new_ca_model_object).to receive(:update_attributes).with(any_args).and_return(new_ca_can_be_updated).ordered
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should save the built CA before updating it" do
            expect(new_ca_model_object).to receive(:save).and_return(new_certificate_model_object).ordered
            expect(new_ca_model_object).to receive(:update_attributes).with(any_args).and_return(new_ca_can_be_updated).ordered
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should raise an error" do
            expect{factory.send(:store_ca, ca_cert, csr, options)}.to raise_error(RuntimeError)
          end
          it "should destroy the created certificate" do
            expect(new_certificate_model_object).to receive(:destroy)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
          it "should destroy the created CA" do
            expect(new_ca_model_object).to receive(:destroy)
            begin
              factory.send(:store_ca, ca_cert, csr, options)
            rescue
            end
          end
        end
      end
      context "if the certificate cannot be created" do
        let(:new_cert_can_be_saved){false}
        it "should build one CA config" do
          expect(factory).to receive(:build_ca_config).with(any_args).once.and_return(ca_config)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build a CA config with the given options" do
          expect(factory).to receive(:build_ca_config).with(options).and_return(ca_config)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build exactly one new CA model object" do
          expect(certificate_authority_model).to receive(:new).with(any_args).once.and_return(new_ca_model_object)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build a new CA model object with the given ca name option" do
          expect(certificate_authority_model).to receive(:new).with(hash_including(name: options['ca_name'])).and_return(new_ca_model_object)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build a new CA model object with the built ca config yaml as config yaml" do
          expect(certificate_authority_model).to receive(:new).with(hash_including(config_yaml: ca_config_yaml)).and_return(new_ca_model_object)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should save the built CA once" do
          expect(new_ca_model_object).to receive(:save).and_return(new_ca_can_be_saved)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should query for a CA model once" do
          expect(certificate_authority_model).to receive(:where).with(any_args).once.and_return([ca_model_object])
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should query for a CA model with the given ca option as name" do
          expect(certificate_authority_model).to receive(:where).with(name: options['ca']).and_return([ca_model_object])
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build one private key" do
          expect(factory).to receive(:build_private_key).with(any_args).once.and_return(private_key)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build a private key with the given csr" do
          expect(factory).to receive(:build_private_key).with(csr, anything).once.and_return(private_key)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build a private key with the given options" do
          expect(factory).to receive(:build_private_key).with(anything, options).once.and_return(private_key)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build exactly one new certificate model" do
          expect(certificate_model).to receive(:new).with(any_args).once.and_return(new_certificate_model_object)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build a new certificate model with the given ca_cert pem representation as public key" do
          expect(certificate_model).to receive(:new).with(hash_including(public_key: public_key)).and_return(new_certificate_model_object)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build a new certificate model with the built private key as private key" do
          expect(certificate_model).to receive(:new).with(hash_including(private_key: private_key)).and_return(new_certificate_model_object)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build a new certificate model with the given ca_cert_password option as password" do
          expect(certificate_model).to receive(:new).with(hash_including(password: options['ca_cert_password'])).and_return(new_certificate_model_object)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should build a new certificate model with the queried CA model as signing CA" do
          expect(certificate_model).to receive(:new).with(hash_including(signing_ca: ca_model_object)).and_return(new_certificate_model_object)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should save the cert once" do
          expect(new_certificate_model_object).to receive(:save).once.and_return(new_cert_can_be_saved)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should not update the built CA" do
          expect(new_ca_model_object).not_to receive(:update_attributes)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should save the built CA before saving the built certificate" do
          expect(new_ca_model_object).to receive(:save).and_return(new_ca_can_be_saved).ordered
          expect(new_certificate_model_object).to receive(:save).and_return(new_cert_can_be_saved).ordered
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should raise an error" do
          expect{factory.send(:store_ca, ca_cert, csr, options)}.to raise_error(RuntimeError)
        end
        it "should not destroy the created certificate" do
          expect(new_certificate_model_object).not_to receive(:destroy)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
        it "should destroy the created CA" do
          expect(new_ca_model_object).to receive(:destroy)
          begin
            factory.send(:store_ca, ca_cert, csr, options)
          rescue
          end
        end
      end
    end
    context "if the ca cannot be created" do
      let(:new_ca_can_be_saved){false}
      it "should build one CA config" do
        expect(factory).to receive(:build_ca_config).with(any_args).once.and_return(ca_config)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
      it "should build a CA config with the given options" do
        expect(factory).to receive(:build_ca_config).with(options).and_return(ca_config)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
      it "should build exactly one new CA model object" do
        expect(certificate_authority_model).to receive(:new).with(any_args).once.and_return(new_ca_model_object)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
      it "should build a new CA model object with the given ca name option" do
        expect(certificate_authority_model).to receive(:new).with(hash_including(name: options['ca_name'])).and_return(new_ca_model_object)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
      it "should build a new CA model object with the built ca config yaml as config yaml" do
        expect(certificate_authority_model).to receive(:new).with(hash_including(config_yaml: ca_config_yaml)).and_return(new_ca_model_object)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
      it "should save the built CA once" do
        expect(new_ca_model_object).to receive(:save).and_return(new_ca_can_be_saved)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
      it "should not query for any CA model" do
        expect(certificate_authority_model).not_to receive(:where).with(any_args)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
      it "should build no private key" do
        expect(factory).not_to receive(:build_private_key).with(any_args)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
      it "should not build any new certificate model" do
        expect(certificate_model).not_to receive(:new).with(any_args)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
      it "should not update the built CA" do
        expect(new_ca_model_object).not_to receive(:update_attributes)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
      it "should raise an error" do
        expect{factory.send(:store_ca, ca_cert, csr, options)}.to raise_error(RuntimeError)
      end
      it "should not destroy the new CA" do
        expect(new_ca_model_object).not_to receive(:destroy)
        begin
          factory.send(:store_ca, ca_cert, csr, options)
        rescue
        end
      end
    end
  end

  describe '#build_private_key' do
    let(:factory){described_class.new}
    let(:csr){double(:csr, key: csr_key)}
    let(:csr_key){double(:csr_key, to_encrypted_pem: encrypted_pem, to_pem: non_encrypted_pem)}
    let(:encrypted_pem){double(:encrypted_pem)}
    let(:non_encrypted_pem){double(:non_encrypted_pem)}
    context "with a ca_password option" do
      let(:options) do
        {
          'ca_password' => double(:ca_password_option)
        }
      end
      it "should encrypt the key to pem once" do
        expect(csr_key).to receive(:to_encrypted_pem).with(any_args).once.and_return(encrypted_pem)
        factory.send(:build_private_key, csr, options)
      end
      it "should encrypt the key to pem using aes256" do
        expect(csr_key).to receive(:to_encrypted_pem).with('aes256', anything).and_return(encrypted_pem)
        factory.send(:build_private_key, csr, options)
      end
      it "should encrypt the key to pem with the given ca password" do
        expect(csr_key).to receive(:to_encrypted_pem).with(anything, options['ca_password']).and_return(encrypted_pem)
        factory.send(:build_private_key, csr, options)
      end
      it "should return the encrypted pem" do
        expect(factory.send(:build_private_key, csr, options)).to eq(encrypted_pem)
      end
    end
    context "without a ca_password option" do
      let(:options) do
        {
          'other_property' => double(:other_value)
        }
      end
      it "should not encrypt the csr key" do
        expect(csr_key).not_to receive(:to_encrypted_pem)
        factory.send(:build_private_key, csr, options)
      end
      it "should return the non-encrypted pem representation of the csr key" do
        expect(factory.send(:build_private_key, csr, options)).to eq(non_encrypted_pem)
      end
    end
  end

  describe '#build_ca_config' do
    let(:factory){described_class.new}
    let(:options) do
      {
        'other_option' => 'other_value',
        'ca_config' => ca_config_json
      }
    end
    let(:ca_config_json){ ca_config.to_json}
    let(:ca_config) do
      {
        "ocsp_start_skew_seconds"=>3600,
        "ocsp_validity_hours"=>168,
        "crl_validity_hours"=>4,
        "crl_md"=>"SHA512",
        "profiles"=> {
          "server"=> {
            "basic_constraints"=>{:ca=>false},
            "crl_distribution_points"=> {
              :value=> [
                {
                  :type=>"URI",
                  :value=>"http://crl.concerto.io/crls/production_root_ca.crl"
                }
              ]
            },
            "key_usage"=> {
              :value=> ["digitalSignature", "keyEncipherment"]
            },
            "extended_key_usage"=> {
              :value=>["serverAuth"]
            },
            "default_md"=>"SHA512",
            "allowed_mds"=>["SHA256", "SHA512"],
            "subject_item_policy"=> {
              "CN"=>{:policy=>"required"},
              "O"=>{:policy=>"required"},
              "OU"=>{:policy=>"optional"},
              "ST"=>{:policy=>"required"},
              "C"=>{:policy=>"required"},
              "L"=>{:policy=>"required"}
            }
          },
          "ca"=> {
            "basic_constraints"=>{:ca=>true},
            "crl_distribution_points"=> {
              :value=> [
                {
                  :type=>"URI",
                  :value=>"http://crl.concerto.io/crls/production_root_ca.crl"
                }
              ]
            },
            "key_usage"=> {
              :value=>["digitalSignature", "keyEncipherment", "keyCertSign", "cRLSign"]
            },
            "default_md"=>"SHA512",
            "allowed_mds"=>["SHA256", "SHA512"],
            "subject_item_policy"=> {
              "CN"=>{:policy=>"required"},
              "O"=>{:policy=>"required"},
              "OU"=>{:policy=>"optional"},
              "ST"=>{:policy=>"required"},
              "C"=>{:policy=>"required"},
              "L"=>{:policy=>"required"}
            }
          }
        }
      }
    end
    let(:processed_ca_config) do
      {
        "ocsp_start_skew_seconds" => 3600,
        "ocsp_validity_hours" => 168,
        "crl_validity_hours" => 4,
        "crl_md" => "SHA512",
        "profiles" => {
          "server" => {
            basic_constraints:{:ca=>false},
            crl_distribution_points: {
              :value=> [
                {
                  :type=>"URI",
                  :value=>"http://crl.concerto.io/crls/production_root_ca.crl"
                }
              ]
            },
            key_usage: {
              :value=> ["digitalSignature", "keyEncipherment"]
            },
            extended_key_usage: {
              :value=>["serverAuth"]
            },
            default_md:"SHA512",
            allowed_mds:["SHA256", "SHA512"],
            subject_item_policy: {
              "CN"=>{:policy=>"required"},
              "O"=>{:policy=>"required"},
              "OU"=>{:policy=>"optional"},
              "ST"=>{:policy=>"required"},
              "C"=>{:policy=>"required"},
              "L"=>{:policy=>"required"}
            }
          },
          "ca" => {
            basic_constraints:{:ca=>true},
            crl_distribution_points: {
              :value=> [
                {
                  :type=>"URI",
                  :value=>"http://crl.concerto.io/crls/production_root_ca.crl"
                }
              ]
            },
            key_usage: {
              :value=>["digitalSignature", "keyEncipherment", "keyCertSign", "cRLSign"]
            },
            default_md:"SHA512",
            allowed_mds:["SHA256", "SHA512"],
            subject_item_policy: {
              "CN"=>{:policy=>"required"},
              "O"=>{:policy=>"required"},
              "OU"=>{:policy=>"optional"},
              "ST"=>{:policy=>"required"},
              "C"=>{:policy=>"required"},
              "L"=>{:policy=>"required"}
            }
          }
        }
      }
    end
    it "should return a the CA config option json-parsed symbolizing the hash keys in the profiles property but for the inmediate subkeys under subject_item_policy" do
      expect(factory.send(:build_ca_config, options)).to eq(processed_ca_config)
    end
  end

  describe '#renew' do
    let(:factory){described_class.new}
    let(:certificate_authority_model){double(:certificate_authority_model, where: [ca_to_renew])}
    let(:certificate_factory){double(:certificate_factory, build: new_ca_cert)}
    let(:new_ca_cert){double(:new_ca_cert)}
    let(:ca_to_renew){double(:ca_to_renew, ca_certificate: ca_certificate)}
    let(:ca_certificate){double(:ca_certificate, r509_cert: ca_r509_cert, password: password, private_key: private_key)}
    let(:ca_r509_cert){double(:ca_r509_cert, subject: r509_subject, key: r509_key)}
    let(:r509_subject){double(:r509_subject)}
    let(:r509_key){double(:r509_key)}
    let(:password){double(:password)}
    let(:private_key){double(:private_key)}
    let(:signer_opt_builder){double(:signer_opt_builder)}
    let(:log){double(:log, info: nil)}
    let(:csr){double(:csr)}
    let(:options) do
      {
        'profile' => profile,
        'validityPeriod' => validity_period,
        'ca_name' => ca_name,
        'ca_password' => double(:ca_password),
        'message_digest' => double(:message_digest),
        'extensions' => double(:extensions)
      }.select{|k,v| v}
    end
    before(:each) do
      allow(factory).to receive(:certificate_authority_model).and_return(certificate_authority_model)
      allow(factory).to receive(:certificate_factory).and_return(certificate_factory)
      allow(factory).to receive(:build_csr).and_return(csr)
      allow(factory).to receive(:store_ca_renewed_cert)
    end
    context "with a non-nil CA" do
      let(:ca){double(:ca)}
      context "with a profile option" do
        let(:profile){double(:profile)}
        context "with a validity period option" do
          let(:validity_period){double(:validity_period)}
          context "with a CA name option" do
            let(:ca_name){double(:ca_name)}
            it "should query the CA model once" do
              expect(certificate_authority_model).to receive(:where).with(any_args).once.and_return([ca_to_renew])
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should query the CA model with the CA name option as name" do
              expect(certificate_authority_model).to receive(:where).with(name: ca_name).and_return([ca_to_renew])
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build one r509 certificate representation for the CA certificate of the queried CA" do
              expect(ca_certificate).to receive(:r509_cert).with(any_args).once.and_return(ca_r509_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a complete r509 certificate representation for the CA certificate of the queried CA" do
              expect(ca_certificate).to receive(:r509_cert).with(hash_including(complete: true)).and_return(ca_r509_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a r509 certificate representation for the CA certificate of the queried CA with the received CA password option" do
              expect(ca_certificate).to receive(:r509_cert).with(hash_including(password: options['ca_password'])).and_return(ca_r509_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build one CSR" do
              expect(factory).to receive(:build_csr).with(any_args).once.and_return(csr)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a CSR with the CA R509 certificate subject" do
              expect(factory).to receive(:build_csr).with(r509_subject, anything).and_return(csr)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a CSR with the CA R509 certificate key" do
              expect(factory).to receive(:build_csr).with(anything, r509_key).and_return(csr)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build one certificate with the certificate factory" do
              expect(certificate_factory).to receive(:build).with(any_args).once.and_return(new_ca_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a certificate with the certificate factory and the receive CA" do
              expect(certificate_factory).to receive(:build).with(ca, any_args).and_return(new_ca_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a certificate with the certificate factory and the subject of the CA r509 certificate" do
              expect(certificate_factory).to receive(:build).with(anything, r509_subject, any_args).and_return(new_ca_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a certificate with the certificate factory and the given signer opt builder" do
              expect(certificate_factory).to receive(:build).with(anything, anything, signer_opt_builder, anything).and_return(new_ca_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a certificate with the certificate factory and the given validityPeriod option as validityPeriod" do
              expect(certificate_factory).to receive(:build).with(anything, anything, anything, hash_including('validityPeriod' => validity_period)).and_return(new_ca_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a certificate with the certificate factory and the given profile option as profile" do
              expect(certificate_factory).to receive(:build).with(anything, anything, anything, hash_including('profile' => profile)).and_return(new_ca_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a certificate with the certificate factory and the given extensions option as extensions" do
              expect(certificate_factory).to receive(:build).with(anything, anything, anything, hash_including('extensions' => options['extensions'])).and_return(new_ca_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a certificate with the certificate factory and the built CSR as csr option" do
              expect(certificate_factory).to receive(:build).with(anything, anything, anything, hash_including('csr' => csr)).and_return(new_ca_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should build a certificate with the certificate factory and the given message_digest option as message_digest" do
              expect(certificate_factory).to receive(:build).with(anything, anything, anything, hash_including('message_digest' => options['message_digest'])).and_return(new_ca_cert)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should store one CA renewed certificate" do
              expect(factory).to receive(:store_ca_renewed_cert).with(any_args).once
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should store a built CA certificate as CA renewed certificate for the queried CA" do
              expect(factory).to receive(:store_ca_renewed_cert).with(ca_to_renew, any_args)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should store the built CA certificate as CA renewed certificate" do
              expect(factory).to receive(:store_ca_renewed_cert).with(anything, new_ca_cert, any_args)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should store a built CA certificate with the private key of the queried CA certificate" do
              expect(factory).to receive(:store_ca_renewed_cert).with(anything, anything, private_key, anything, anything)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should store a built CA certificate with the password of the queried CA certificate" do
              expect(factory).to receive(:store_ca_renewed_cert).with(anything, anything, anything, password, anything)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should store a built CA certificate with the given options" do
              expect(factory).to receive(:store_ca_renewed_cert).with(anything, anything, anything, anything, options)
              factory.renew(ca, signer_opt_builder, log, options)
            end
            it "should return the built certificate" do
              expect(factory.renew(ca, signer_opt_builder, log, options)).to eq(new_ca_cert)
            end
          end
          context "without a CA name option" do
            let(:ca_name){nil}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
        end
        context "without a validity period option" do
          let(:validity_period){nil}
          context "with a CA name option" do
            let(:ca_name){double(:ca_name)}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
          context "without a CA name option" do
            let(:ca_name){nil}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
        end
      end
      context "with no profile option" do
        let(:profile){nil}
        context "with a validity period option" do
          let(:validity_period){double(:validity_period)}
          context "with a CA name option" do
            let(:ca_name){double(:ca_name)}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
          context "without a CA name option" do
            let(:ca_name){nil}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
        end
        context "without a validity period option" do
          let(:validity_period){nil}
          context "with a CA name option" do
            let(:ca_name){double(:ca_name)}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
          context "without a CA name option" do
            let(:ca_name){nil}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
        end
      end
    end
    context "with a nil CA" do
      let(:ca){nil}
      context "with a profile option" do
        let(:profile){double(:profile)}
        context "with a validity period option" do
          let(:validity_period){double(:validity_period)}
          context "with a CA name option" do
            let(:ca_name){double(:ca_name)}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
          context "without a CA name option" do
            let(:ca_name){nil}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
        end
        context "without a validity period option" do
          let(:validity_period){nil}
          context "with a CA name option" do
            let(:ca_name){double(:ca_name)}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
          context "without a CA name option" do
            let(:ca_name){nil}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
        end
      end
      context "with no profile option" do
        let(:profile){nil}
        context "with a validity period option" do
          let(:validity_period){double(:validity_period)}
          context "with a CA name option" do
            let(:ca_name){double(:ca_name)}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
          context "without a CA name option" do
            let(:ca_name){nil}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
        end
        context "without a validity period option" do
          let(:validity_period){nil}
          context "with a CA name option" do
            let(:ca_name){double(:ca_name)}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
          context "without a CA name option" do
            let(:ca_name){nil}
            it "should raise an Argument error" do
              expect{factory.renew(ca, signer_opt_builder, log, options)}.to raise_error(ArgumentError)
            end
            it "should not log anything" do
              expect(log).not_to receive(:info)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not query the CA model" do
              expect(certificate_authority_model).not_to receive(:where)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not build any CSRs" do
              expect(factory).not_to receive(:build_csr)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
            it "should not store any renewed CA certificates" do
              expect(factory).not_to receive(:store_ca_renewed_cert)
              begin
                factory.renew(ca, signer_opt_builder, log, options)
              rescue
              end
            end
          end
        end
      end
    end
  end
end
