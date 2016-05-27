require File.dirname(__FILE__) + '/spec_helper'
require "openssl"

describe R509::CertificateAuthority::HTTP::Server do
  let(:test_crl) { double("crl") }
  let(:test_options_builder) { double("options_builder") }
  let(:test_ca) { double("test_ca") }
  let(:certificate_authorities) { double("certificate_authorities") }
  let(:certificates) { double("certificates") }
  let(:certificate_factory){ double(:certificate_factory, build: signed_cert)}
  let(:ca_factory){ double(:ca_factory, build: signed_cert, renew_ca: signed_cert)}
  let(:signed_cert){double(:signed_cert, to_pem: 'signed cert')}
  before :each do
    # clear the dependo before each test
    Dependo::Registry.clear
    Dependo::Registry[:log] = Logger.new(nil)
    Dependo::Registry[:certificate_authorities] = certificate_authorities
    allow(certificate_authorities).to receive(:get_crl).and_return(nil)
    allow(certificate_authorities).to receive(:get_crl).with('test_ca', anything).and_return(test_crl)
    allow(certificate_authorities).to receive(:get_option_builder).and_return(nil)
    allow(certificate_authorities).to receive(:get_option_builder).with('test_ca').and_return(test_options_builder)
    allow(certificate_authorities).to receive(:get_certificate_authority).and_return(nil)
    allow(certificate_authorities).to receive(:get_certificate_authority).with('test_ca', anything).and_return(test_ca)
    Dependo::Registry[:certificates] = certificates
    @subject_parser = double("subject parser", parse: R509::Subject.new)
    #@validity_period_converter = double("validity period converter")
    @csr_factory = double("csr factory")
    @spki_factory = double("spki factory")
  end

  def app
    @app ||= R509::CertificateAuthority::HTTP::Server
    @app.send(:set, :subject_parser, @subject_parser)
    #@app.send(:set, :validity_period_converter, @validity_period_converter)
    @app.send(:set, :csr_factory, @csr_factory)
    @app.send(:set, :spki_factory, @spki_factory)
    @app.send(:set, :certificate_factory, certificate_factory)
    @app.send(:set, :ca_factory, ca_factory)
  end

  context "generate CRL" do
    it "generates the CRL" do
      crl = double('crl')
      crl.should_receive(:to_pem).and_return("generated crl")
      test_crl.should_receive(:generate_crl).and_return(crl)
      get "/1/crl/test_ca/generate"
      last_response.should be_ok
      last_response.body.should == "generated crl"
    end
    it "when CA is not found" do
      get "/1/crl/bogus/generate/"
      last_response.status.should == 500
      last_response.body.should == "#<ArgumentError: CA not found>"
    end
  end

  context "operations on certificates" do

    context "issue certificate" do
      it "when no parameters are given" do
        post "/1/certificate/issue"
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: Must provide a CA>"
      end
      it "when there's a profile, subject, CSR, validity period, but no ca" do
        post "/1/certificate/issue", "profile" => "my profile", "subject" => "subject", "csr" => "my csr", "validityPeriod" => 365
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: Must provide a CA>"
      end
      it "when there's a ca, profile, subject, CSR, but no validity period" do
        allow(certificate_factory).to receive(:build).and_raise(ArgumentError, 'Must provide a validity period')
        post "/1/certificate/issue", "ca" => "test_ca", "profile" => "my profile", "subject" => "subject", "csr" => "my csr"
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: Must provide a validity period>"
      end
      it "when there's a ca, profile, subject, validity period, but no CSR" do
        allow(certificate_factory).to receive(:build).and_raise(ArgumentError, 'Must provide a CSR or SPKI')
        post "/1/certificate/issue", "ca" => "test_ca", "profile" => "my profile", "subject" => "subject", "validityPeriod" => 365
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: Must provide a CSR or SPKI>"
      end
      it "when there's a ca, profile, CSR, validity period, but no subject" do
        allow(certificate_factory).to receive(:build).and_raise(ArgumentError, 'Must provide a subject')
        post "/1/certificate/issue", "ca" => "test_ca", "profile" => "profile", "validityPeriod" => 365, "csr" => "csr"
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: Must provide a subject>"
      end
      it "when there's a ca, subject, CSR, validity period, but no profile" do
        allow(certificate_factory).to receive(:build).and_raise(ArgumentError, 'Must provide a CA profile')
        post "/1/certificate/issue", "ca" => "test_ca", "subject" => "subject", "validityPeriod" => 365, "csr" => "csr"
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: Must provide a CA profile>"
      end
      it "when the given CA is not found" do
        allow(certificate_factory).to receive(:build).and_raise(ArgumentError, 'CA not found')
        post "/1/certificate/issue", "ca" => "some bogus CA"
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: CA not found>"
      end
      it "fails to issue" do
        allow(certificate_factory).to receive(:build).and_raise(R509::R509Error.new("failed to issue because of: good reason"))

        post "/1/certificate/issue", "ca" => "test_ca", "profile" => "profile", "subject" => "subject", "validityPeriod" => 365, "csr" => "csr"
        last_response.should_not be_ok
        last_response.body.should == "#<R509::R509Error: failed to issue because of: good reason>"
      end
    end

    context "revoke certificate" do
      it "when no CA is given" do
        post "/1/certificate/revoke", "serial" => "foo"
        last_response.status.should == 500
        last_response.body.should == "#<ArgumentError: CA must be provided>"
      end
      it "when CA is not found" do
        post "/1/certificate/revoke", "ca" => "bogus ca name", "serial" => "foo"
        last_response.status.should == 500
        last_response.body.should == "#<ArgumentError: CA not found>"
      end
      it "when no serial is given" do
        post "/1/certificate/revoke", "ca" => "test_ca"
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: Serial must be provided>"
      end
      it "when serial is given but not reason" do
        test_crl.should_receive(:revoke_cert).with("12345", nil).and_return(nil)
        crl_obj = double("crl-obj")
        test_crl.should_receive(:generate_crl).and_return(crl_obj)
        crl_obj.should_receive(:to_pem).and_return("generated crl")
        post "/1/certificate/revoke", "ca" => "test_ca", "serial" => "12345"
        last_response.should be_ok
        last_response.body.should == "generated crl"
      end
      it "when serial and reason are given" do
        test_crl.should_receive(:revoke_cert).with("12345", 1).and_return(nil)
        crl_obj = double("crl-obj")
        test_crl.should_receive(:generate_crl).and_return(crl_obj)
        crl_obj.should_receive(:to_pem).and_return("generated crl")
        post "/1/certificate/revoke", "ca" => "test_ca", "serial" => "12345", "reason" => "1"
        last_response.should be_ok
        last_response.body.should == "generated crl"
      end
      it "when serial is not an integer" do
        test_crl.should_receive(:revoke_cert).with("foo", nil).and_raise(R509::R509Error.new("some r509 error"))
        post "/1/certificate/revoke", "ca" => "test_ca", "serial" => "foo"
        last_response.should_not be_ok
        last_response.body.should == "#<R509::R509Error: some r509 error>"
      end
      it "when reason is not an integer" do
        test_crl.should_receive(:revoke_cert).with("12345", 0).and_return(nil)
        crl_obj = double("crl-obj")
        test_crl.should_receive(:generate_crl).and_return(crl_obj)
        crl_obj.should_receive(:to_pem).and_return("generated crl")
        post "/1/certificate/revoke", "ca" => "test_ca", "serial" => "12345", "reason" => "foo"
        last_response.should be_ok
        last_response.body.should == "generated crl"
      end
      it "when reason is an empty string" do
        test_crl.should_receive(:revoke_cert).with("12345", nil).and_return(nil)
        crl_obj = double("crl-obj")
        test_crl.should_receive(:generate_crl).and_return(crl_obj)
        crl_obj.should_receive(:to_pem).and_return("generated crl")
        post "/1/certificate/revoke", "ca" => "test_ca", "serial" => "12345", "reason" => ""
        last_response.should be_ok
        last_response.body.should == "generated crl"
      end
    end

    context "unrevoke certificate" do
      it "when no CA is given" do
        post "/1/certificate/unrevoke", "serial" => "foo"
        last_response.status.should == 500
        last_response.body.should == "#<ArgumentError: CA must be provided>"
      end
      it "when CA is not found" do
        post "/1/certificate/unrevoke", "ca" => "bogus ca", "serial" => "foo"
        last_response.status.should == 500
        last_response.body.should == "#<ArgumentError: CA not found>"
      end
      it "when no serial is given" do
        post "/1/certificate/unrevoke", "ca" => "test_ca"
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: Serial must be provided>"
      end
      it "when serial is given" do
        test_crl.should_receive(:unrevoke_cert).with(12345).and_return(nil)
        crl_obj = double("crl-obj")
        test_crl.should_receive(:generate_crl).and_return(crl_obj)
        crl_obj.should_receive(:to_pem).and_return("generated crl")
        post "/1/certificate/unrevoke", "ca" => "test_ca", "serial" => "12345"
        last_response.should be_ok
        last_response.body.should == "generated crl"
      end
    end
  end

  context "operations on subordinate CAs" do

    context "issue CA" do
      it "when no parameters are given" do
        post "/1/cas"
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: Must provide a root CA>"
      end
      it "when there's a profile, subject, validity period, but no ca" do
        post "/1/cas", "profile" => "my profile", "subject" => "subject", "validityPeriod" => 365
        last_response.should_not be_ok
        last_response.body.should == "#<ArgumentError: Must provide a root CA>"
      end
      it "when there is a password" do
        allow(certificate_factory).to receive(:build).and_return(signed_cert)

        post "/1/cas", "ca" => "test_ca", "ca_name" => "new_ca_name", "profile" => "profile", "subject" => "subject", "validityPeriod" => 365, "ca_config" => "{}", "ca_password" => "Password.123"
        last_response.should be_ok
        expect(last_response.body).to eq(signed_cert.to_pem)
      end
    end

    context "revoke CA" do
      it "when no Root CA is given" do
        post "/1/cas/revoke"
        last_response.status.should == 500
        last_response.body.should == "#<ArgumentError: CA must be provided>"
      end
      it "when no subordinate CA is given" do
        post "/1/cas/revoke", "ca" => "test_ca"
        last_response.status.should == 500
        last_response.body.should == "#<ArgumentError: Name of subordinate CA to revoke must be provided>"
      end
      it "when Root CA is not found" do
        post "/1/cas/revoke", "ca" => "bogus ca name", "ca_name" => "sub ca name"
        last_response.status.should == 500
        last_response.body.should == "#<ArgumentError: CA not found>"
      end
      it "when reason is not an integer" do
        test_crl.should_receive(:revoke_cert).with("12345", 0).and_return(nil)
        crl_obj = double("crl-obj")
        test_crl.should_receive(:generate_crl).and_return(crl_obj)
        crl_obj.should_receive(:to_pem).and_return("generated crl")
        expect(certificate_authorities).to receive(:get_certificate_serial).with("sub ca name").and_return("12345")
        post "/1/cas/revoke", "ca" => "test_ca", "ca_name" => "sub ca name", "reason" => "foo"
        last_response.should be_ok
        last_response.body.should == "generated crl"
      end
      it "when reason is an empty string" do
        test_crl.should_receive(:revoke_cert).with("12345", nil).and_return(nil)
        crl_obj = double("crl-obj")
        test_crl.should_receive(:generate_crl).and_return(crl_obj)
        crl_obj.should_receive(:to_pem).and_return("generated crl")
        expect(certificate_authorities).to receive(:get_certificate_serial).with("sub ca name").and_return("12345")
        post "/1/cas/revoke", "ca" => "test_ca", "ca_name" => "sub ca name", "reason" => ""
        last_response.should be_ok
        last_response.body.should == "generated crl"
      end
    end

    context "unrevoke CA" do
      it "when no root CA is given" do
        post "/1/cas/unrevoke"
        last_response.status.should == 500
        last_response.body.should == "#<ArgumentError: CA must be provided>"
      end
      it "when no subordinate CA is given" do
        post "/1/cas/unrevoke", "ca" => "test_ca"
        last_response.status.should == 500
        last_response.body.should == "#<ArgumentError: Name of subordinate CA to revoke must be provided>"
      end
      it "when CA is not found" do
        post "/1/cas/unrevoke", "ca" => "bogus ca", "ca_name" => "sub ca name"
        last_response.status.should == 500
        last_response.body.should == "#<ArgumentError: CA not found>"
      end
      it "when all is good" do
        test_crl.should_receive(:unrevoke_cert).with(12345).and_return(nil)
        crl_obj = double("crl-obj")
        test_crl.should_receive(:generate_crl).and_return(crl_obj)
        crl_obj.should_receive(:to_pem).and_return("generated crl")
        expect(certificate_authorities).to receive(:get_certificate_serial).with("sub ca name").and_return("12345")
        post "/1/cas/unrevoke", "ca" => "test_ca", "ca_name" => "sub ca name"
        last_response.should be_ok
        last_response.body.should == "generated crl"
      end
    end

    context "renew CA" do
      let(:subject) { R509::Subject.new([["CN", "domain.com"]]) }
      let(:key) { double("key") }
      let(:csr) { double("csr") }
      let(:private_key) { double("private_key") }
      let(:r509_cert) { double('r509 cert', subject: subject, key: key) }
      let(:ca_to_renew_certificate) { double('ca cert', r509_cert: r509_cert, private_key: private_key, password: 'Somepw.456') }
      let(:ca_to_renew) { double('CA to renew', ca_certificate: ca_to_renew_certificate) }

      before(:each) do
        allow(certificate_authorities).to receive(:where).with(name: 'new_ca_name').and_return([ca_to_renew])
      end
      context "when no root CA is given" do
        before(:each) do
          post "/1/cas/renew"
        end
        it "should respond with a 500 status" do
          expect(last_response.status).to eq(500)
        end
        it "should render 'Must provide a root CA' on the response body" do
          expect(last_response.body).to match(/Must provide a root CA/)
        end
      end
      context "when a root CA param is provided" do
        let(:request_params) do
          {
            'ca' => 'some-ca-name'
          }
        end
        context "when the CA factory succeeds in renewing the CA" do
          before(:each) do
            allow(ca_factory).to receive(:renew).and_return(signed_cert)
            post "/1/cas/renew", request_params
          end
          it "should return a 200 code" do
            expect(last_response).to be_ok
          end
          it "should render the PEM representation of the ca_cert provided by the factory as body" do
            expect(last_response.body).to eq(signed_cert.to_pem)
          end
        end
        context "when the CA factory fails to renew the CA" do
          let(:error_message){"failed to issue because of: good reason"}
          before(:each) do
            allow(ca_factory).to receive(:renew).and_raise(R509::R509Error.new(error_message))
            post "/1/cas/renew", request_params
          end
          it "should respond with a 500 status" do
            expect(last_response.status).to eq(500)
          end
          it "should render the error message on the response body" do
            expect(last_response.body).to match(/#{Regexp.escape(error_message)}/)
          end
        end
      end
    end
  end
end
