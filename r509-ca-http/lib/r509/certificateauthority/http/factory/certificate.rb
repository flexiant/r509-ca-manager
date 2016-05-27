# File by Pablo Baños López
# Copyright 2016 Flexiant Ltd.
class R509::CertificateAuthority::HTTP::Factory::Certificate

  attr_accessor :validity_period_converter, :csr_factory, :spki_factory

  def validity_period_converter
    @validity_period_converter ||= R509::CertificateAuthority::HTTP::ValidityPeriodConverter.new
  end

  def csr_factory
    @csr_factory ||= R509::CertificateAuthority::HTTP::Factory::CSRFactory.new
  end

  def spki_factory
    @spki_factory ||= R509::CertificateAuthority::HTTP::Factory::SPKIFactory.new
  end

  def build(ca, subject, signer_opt_builder, options)
    unless ca
      raise ArgumentError, "CA not found"
    end
    unless options.has_key?("profile")
      raise ArgumentError, "Must provide a CA profile"
    end
    unless options.has_key?("validityPeriod")
      raise ArgumentError, "Must provide a validity period"
    end
    unless options.has_key?("csr") or options.has_key?("spki")
      raise ArgumentError, "Must provide a CSR or SPKI"
    end
    if subject.empty?
      raise ArgumentError, "Must provide a subject"
    end

    extensions = build_extensions(options)

    validity_period = validity_period_converter.convert(options["validityPeriod"])

    signer_opts = build_signer_options(signer_opt_builder, subject, validity_period, extensions, options)

    ca.sign(signer_opts)
  end

  private
  def build_extensions(options)
    extensions = []
    if options.has_key?("extensions") and options["extensions"].has_key?("subjectAlternativeName")
      san_names = options["extensions"]["subjectAlternativeName"].select { |name| not name.empty? }
      unless san_names.empty?
        extensions.push(R509::Cert::Extensions::SubjectAlternativeName.new(:value => R509::ASN1.general_name_parser(san_names)))
      end
    elsif options.has_key?("extensions") and options["extensions"].has_key?("dNSNames")
      san_names = R509::ASN1::GeneralNames.new
      options["extensions"]["dNSNames"].select{ |name| not name.empty? }.each do |name|
        san_names.create_item(:tag => 2, :value => name.strip)
      end
      unless san_names.names.empty?
        extensions.push(R509::Cert::Extensions::SubjectAlternativeName.new(:value => san_names))
      end
    end
    extensions
  end

  def build_signer_options(signer_opt_builder, subject, validity_period, extensions, options)
    signer_opts = if options.has_key?("csr")
      csr = csr_factory.build(:csr => options["csr"])
      signer_opt_builder.build_and_enforce(
        :csr => csr,
        :profile_name => options["profile"],
        :subject => subject,
        :extensions => extensions,
        :message_digest => options["message_digest"],
        :not_before => validity_period[:not_before],
        :not_after => validity_period[:not_after],
      )
    elsif options.has_key?("spki")
      spki = spki_factory.build(:spki => options["spki"], :subject => subject)
      signer_opt_builder.build_and_enforce(
        :spki => spki,
        :profile_name => options["profile"],
        :subject => subject,
        :extensions => extensions,
        :message_digest => options["message_digest"],
        :not_before => validity_period[:not_before],
        :not_after => validity_period[:not_after],
      )
    else
      raise ArgumentError, "Must provide a CSR or SPKI"
    end
  end
end
