# File modified by Pablo Baños López
# Copyright 2016 Flexiant Ltd. (for modifications only)

require 'sinatra/base'
require 'r509'
require 'r509/certificateauthority/http/subjectparser'
require 'r509/certificateauthority/http/validityperiodconverter'
require 'r509/certificateauthority/http/factory'
require 'base64'
require 'yaml'
require 'json'
require 'logger'
require 'dependo'

# Capture USR2 calls so we can reload and print the config
# I'd rather use HUP, but daemons like thin already capture that
# so we can't use it.
Signal.trap("USR2") do
  Dependo::Registry[:config_printer].print_config
end

module R509
  module CertificateAuthority
    module HTTP
      class Server < Sinatra::Base
        extend Dependo::Mixin
        include Dependo::Mixin

        configure do
          disable :protection #disable Rack::Protection (for speed)
          disable :logging
          set :environment, Dependo::Registry[:environment].to_sym
          disable :show_exceptions

          set :subject_parser, R509::CertificateAuthority::HTTP::SubjectParser.new
          set :validity_period_converter, R509::CertificateAuthority::HTTP::ValidityPeriodConverter.new
          set :certificate_factory, R509::CertificateAuthority::HTTP::Factory::Certificate.new
          ca_factory = R509::CertificateAuthority::HTTP::Factory::CA.new.tap do |ca_factory|
            ca_factory.certificate_model = Dependo::Registry[:certificates]
            ca_factory.certificate_authority_model = Dependo::Registry[:certificate_authorities]
          end
          set :ca_factory, ca_factory
        end

        before do
          content_type :text
        end

        helpers do
          def crl(name, opts={})
            Dependo::Registry[:certificate_authorities].get_crl(name, params[:password])
          end
          def ca(name, opts={})
            Dependo::Registry[:certificate_authorities].get_certificate_authority(name, params[:password])
          end
          def builder(name, opts={})
            Dependo::Registry[:certificate_authorities].get_option_builder(name)
          end
          def subject_parser
            settings.subject_parser
          end
          def validity_period_converter
            settings.validity_period_converter
          end
          def certificate_factory
            settings.certificate_factory
          end
          def ca_factory
            settings.ca_factory
          end
        end

        error do
          log.error env["sinatra.error"].inspect
          log.error env["sinatra.error"].backtrace.join("\n")
          "Something is amiss with our CA. You should ... wait?"
        end

        error StandardError do
          log.error env["sinatra.error"].inspect
          log.error env["sinatra.error"].backtrace.join("\n")
          env["sinatra.error"].inspect
        end

        get '/favicon.ico' do
          log.debug "go away. no children."
          "go away. no children"
        end

        get '/1/crl/:ca/generate/?' do
          log.info "Generate CRL for #{params[:ca]}"

          if not crl(params[:ca])
            raise ArgumentError, "CA not found"
          end

          crl(params[:ca]).generate_crl.to_pem.tap do |crl_pem|
            if crl_store = Dependo::Registry[:crl_store]
              log.info "Storing new CRL for CA #{params[:ca]}"
              crl_store.store_crl(params[:ca], crl_pem)
            end
          end
        end

        post '/1/crl/generate/?' do
          log.info "Generate CRL for #{params[:ca]}"

          if not crl(params[:ca])
            raise ArgumentError, "CA not found"
          end

          crl(params[:ca]).generate_crl.to_pem.tap do |crl_pem|
            if crl_store = Dependo::Registry[:crl_store]
              log.info "Storing new CRL for CA #{params[:ca]}"
              crl_store.store_crl(params[:ca], crl_pem)
            end
          end
        end

        post '/1/certificate/issue/?' do
          log.info "Issue Certificate"
          raw = request.env["rack.input"].read
          env["rack.input"].rewind
          log.info raw unless params[:password]

          log.info params.inspect unless params[:password]

          if not params.has_key?('ca')
            raise ArgumentError, 'Must provide a CA'
          end

          subject = subject_parser.parse(raw, 'subject')
          log.info subject.inspect
          log.info subject.to_s

          cert = certificate_factory.build(ca(params['ca']), subject, builder(params['ca']), params)

          pem = cert.to_pem
          log.info pem

          pem
        end

        post '/1/certificate/revoke/?' do
          ca = params[:ca]
          serial = params[:serial]
          reason = params[:reason]
          log.info "Revoke for serial #{serial} on CA #{ca}"

          if not ca
            raise ArgumentError, "CA must be provided"
          end
          if not crl(ca)
            raise ArgumentError, "CA not found"
          end
          if not serial
            raise ArgumentError, "Serial must be provided"
          end

          if reason.nil? or reason.empty?
            reason = nil
          else
            reason = reason.to_i
          end

          crl(ca).revoke_cert(serial, reason)

          crl(ca).generate_crl.to_pem.tap do |crl_pem|
            if crl_store = Dependo::Registry[:crl_store]
              log.info "Storing new CRL for CA #{ca}"
              crl_store.store_crl(ca, crl_pem)
            end
          end
        end

        post '/1/certificate/unrevoke/?' do
          ca = params[:ca]
          serial = params[:serial]
          log.info "Unrevoke for serial #{serial} on CA #{ca}"

          if not ca
            raise ArgumentError, "CA must be provided"
          end
          if not crl(ca)
            raise ArgumentError, "CA not found"
          end
          if not serial
            raise ArgumentError, "Serial must be provided"
          end

          crl(ca).unrevoke_cert(serial.to_i)

          crl(ca).generate_crl.to_pem.tap do |crl_pem|
            if crl_store = Dependo::Registry[:crl_store]
              log.info "Storing new CRL for CA #{ca}"
              crl_store.store_crl(ca, crl_pem)
            end
          end
        end

        post '/1/cas/?' do
          log.info "Create subordinate CA"
          raw = request.env["rack.input"].read
          env["rack.input"].rewind
          log.info raw unless params[:password] || params[:ca_password]

          log.info params.inspect unless params[:password] || params[:ca_password]

          if not params.has_key?('ca')
            raise ArgumentError, 'Must provide a root CA'
          end

          subject = subject_parser.parse(raw, 'subject')
          log.info subject.inspect
          log.info subject.to_s

          ca_cert = ca_factory.build(ca(params['ca']), subject, builder(params['ca']), params)

          pem = ca_cert.to_pem
          log.info pem

          pem
        end

        post '/1/cas/renew/?' do
          log.info "Renew subordinate CA"
          raw = request.env["rack.input"].read
          env["rack.input"].rewind
          log.info raw unless params[:password] || params[:ca_password]

          log.info params.inspect unless params[:password] || params[:ca_password]

          unless params.has_key?("ca")
            raise ArgumentError, "Must provide a root CA"
          end
          ca_cert = ca_factory.renew(ca(params['ca']), builder(params['ca']), log, params)

          pem = ca_cert.to_pem
          log.info pem

          pem
        end

        post '/1/cas/revoke/?' do
          ca = params[:ca]
          reason = params[:reason]
          subordinate_ca_name = params[:ca_name]
          log.info "Revoke for subordinate CA #{subordinate_ca_name} on CA #{ca}"

          if not ca
            raise ArgumentError, "CA must be provided"
          end
          if not subordinate_ca_name
            raise ArgumentError, "Name of subordinate CA to revoke must be provided"
          end
          if not crl(ca)
            raise ArgumentError, "CA not found"
          end
          serial = Dependo::Registry[:certificate_authorities].get_certificate_serial(subordinate_ca_name)
          if not serial
            raise ArgumentError, "Subordinate CA not found or serial not available"
          end

          if reason.nil? or reason.empty?
            reason = nil
          else
            reason = reason.to_i
          end

          crl(ca).revoke_cert(serial, reason)

          crl(ca).generate_crl.to_pem.tap do |crl_pem|
            if crl_store = Dependo::Registry[:crl_store]
              log.info "Storing new CRL for CA #{ca}"
              crl_store.store_crl(ca, crl_pem)
            end
          end
        end

        post '/1/cas/unrevoke/?' do
          ca = params[:ca]
          subordinate_ca_name = params[:ca_name]
          log.info "Unrevoke for subordinate CA #{subordinate_ca_name} on CA #{ca}"

          if not ca
            raise ArgumentError, "CA must be provided"
          end
          if not subordinate_ca_name
            raise ArgumentError, "Name of subordinate CA to revoke must be provided"
          end
          if not crl(ca)
            raise ArgumentError, "CA not found"
          end
          serial = Dependo::Registry[:certificate_authorities].get_certificate_serial(subordinate_ca_name)
          if not serial
            raise ArgumentError, "Subordinate CA not found or serial not available"
          end

          crl(ca).unrevoke_cert(serial.to_i)

          crl(ca).generate_crl.to_pem.tap do |crl_pem|
            if crl_store = Dependo::Registry[:crl_store]
              log.info "Storing new CRL for CA #{ca}"
              crl_store.store_crl(ca, crl_pem)
            end
          end
        end

        get '/test/certificate/issue/?' do
          log.info "Loaded test issuance interface"
          content_type :html
          erb :test_issue
        end

        get '/test/certificate/revoke/?' do
          log.info "Loaded test revoke interface"
          content_type :html
          erb :test_revoke
        end

        get '/test/certificate/unrevoke/?' do
          log.info "Loaded test unrevoke interface"
          content_type :html
          erb :test_unrevoke
        end
      end
    end
  end
end
