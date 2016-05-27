# File by Pablo Baños López
# Copyright 2016 Flexiant Ltd.
require 'active_support/hash_with_indifferent_access'
class R509::CertificateAuthority::HTTP::Factory::CA

  attr_accessor :certificate_factory, :certificate_model, :certificate_authority_model, :csr_factory

  def certificate_factory
    @certificate_factory ||= R509::CertificateAuthority::HTTP::Factory::Certificate.new
  end

  def csr_factory
    @csr_factory ||= R509::CertificateAuthority::HTTP::Factory::CSRFactory.new
  end

  def build(ca, subject, signer_opt_builder, options)
    unless options.has_key?("ca_name")
      raise ArgumentError, "Must provide a name for the new CA"
    end
    if subject.empty?
      raise ArgumentError, "Must provide a subject"
    end

    csr = build_csr(subject)

    ca_cert = certificate_factory.build(
      ca,
      subject,
      signer_opt_builder,
      {
        'validityPeriod' => options['validityPeriod'],
        'profile' => options['profile'],
        'extensions' => options['extensions'],
        'csr' => csr,
        'message_digest' => options['message_digest'],
      }.select{|k,v| v}
    )

    store_ca(ca_cert, csr, options)
    ca_cert
  end

  def renew(ca, signer_opt_builder, log, options)
    unless ca
      raise ArgumentError, "Root CA not found"
    end
    unless options.has_key?("profile")
      raise ArgumentError, "Must provide a CA profile"
    end
    unless options.has_key?("validityPeriod")
      raise ArgumentError, "Must provide a validity period"
    end
    unless options.has_key?("ca_name")
      raise ArgumentError, "Must provide the name of the CA to renew"
    end

    ca_to_renew = certificate_authority_model.where(name: options['ca_name']).first
    ca_current_certificate = ca_to_renew.ca_certificate
    ca_current_r509_certificate = ca_current_certificate.r509_cert(complete: true, password: options['ca_password'])

    subject = ca_current_r509_certificate.subject
    log.info subject.inspect
    log.info subject.to_s

    csr = build_csr(subject, ca_current_r509_certificate.key)

    ca_cert = certificate_factory.build(
      ca,
      subject,
      signer_opt_builder,
      {
        'validityPeriod' => options['validityPeriod'],
        'profile' => options['profile'],
        'extensions' => options['extensions'],
        'csr' => csr,
        'message_digest' => options['message_digest'],
      }.select{|k,v| v}
    )

    # store in model
    store_ca_renewed_cert(ca_to_renew, ca_cert, ca_current_certificate.private_key, ca_current_certificate.password, options)
    ca_cert
  end

  private

  def build_csr(subject, key=nil)
    csr_factory.build({subject: subject}.merge( key ? {key: key} : {}))
  end

  def build_private_key(csr, options)
    if options.has_key?('ca_password')
      csr.key.to_encrypted_pem("aes256", options['ca_password'])
    else
      csr.key.to_pem
    end
  end

  def store_ca(ca_cert, csr, options)
    new_ca = nil
    cert = nil

    ca_config = build_ca_config(options)

    new_ca = certificate_authority_model.new(name: options['ca_name'], config_yaml: ca_config.to_yaml)
    if new_ca.save
      signing_ca = certificate_authority_model.where(name: options['ca']).first
      public_key = ca_cert.to_pem
      private_key = build_private_key(csr, options)
      cert = certificate_model.new(public_key: public_key, private_key: private_key, password: options['ca_cert_password']||'', signing_ca: signing_ca)
      if cert.save
        if new_ca.update_attributes(ca_certificate: cert)
          ca_cert
        else
          raise "Following errors ocurred: #{new_ca.errors.as_json}"
        end
      else
        raise "Following errors ocurred: #{cert.errors.as_json}"
      end
    else
      raise "Following errors ocurred: #{new_ca.errors.as_json}"
    end
  rescue Exception => exc
    if cert and !cert.new_record?
      cert.destroy
    end
    if new_ca and ! new_ca.new_record?
      new_ca.destroy
    end
    raise exc
  end

  def store_ca_renewed_cert(ca_to_renew, ca_cert, private_key, password, options)
    cert = nil
    signing_ca = certificate_authority_model.where(name: options['ca']).first
    public_key = ca_cert.to_pem
    cert = certificate_model.new(public_key: public_key, private_key: private_key, password: password, signing_ca: signing_ca)
    if cert.save
      if ca_to_renew.update_attributes(ca_certificate: cert)
        ca_cert
      else
        raise "Following errors ocurred: #{ca_to_renew.errors.as_json}"
      end
    else
      raise "Following errors ocurred: #{cert.errors.as_json}"
    end
  rescue Exception => exc
    if cert and !cert.new_record?
      cert.destroy
    end
    raise exc
  end

  def build_ca_config(options)
    ca_config = JSON.parse(options['ca_config'])
    if (profile_configs = ca_config['profiles']).is_a?(Hash)
      profile_configs.values.each do |profile_config|
        recursive_symbolize_keys!(profile_config)
      end
    end
    ca_config
  end

  # Taken from http://grosser.it/2009/04/14/recursive-symbolize_keys/
  def recursive_symbolize_keys!(hash)
    hash.symbolize_keys!
    hash.select do |k, v|
      v.is_a?(Hash) || v.is_a?(Array)
    end.each do |k, h|
      if h.is_a?(Array)
        h.map do |v|
          recursive_symbolize_keys!(v) if v.is_a?(Hash)
        end
      else
        if k == :subject_item_policy
          h.values.map do |v|
            v.symbolize_keys! if v.is_a?(Hash)
          end
        else
          recursive_symbolize_keys!(h)
        end
      end
    end
  end
end
