require 'yaml'

class R509::Mongoid::Models::CertificateAuthority
  include ::Mongoid::Document

  field :name, type: String
  field :config_yaml, type: String

  belongs_to :ca_certificate, class_name: 'R509::Mongoid::Models::Certificate'
  belongs_to :ocsp_certificate, class_name: 'R509::Mongoid::Models::Certificate'
  has_many :signed_certs, class_name: 'R509::Mongoid::Models::Certificate'

  validates :name, uniqueness: {scope: [:revoked?], unless: :revoked?}

  def config(opts={})
    config_data = YAML.load(config_yaml)
    r509_ca_cert = ca_certificate.r509_cert(opts[:ca_cert])
    convert_to_indifferent_access_hash(config_data['profiles'])
    opts = {
      ca_cert: r509_ca_cert,
      ocsp_cert: ocsp_certificate ? ocsp_certificate.r509_cert(opts[:ocsp_cert]) : nil,
      crl_cert: r509_ca_cert.key ? r509_ca_cert : nil,
      ocsp_chain: nil,
      crl_validity_hours: config_data['crl_validity_hours'],
      ocsp_validty_hours: config_data['ocsp_validity_hours'],
      ocsp_start_skew_seconds: config_data['ocsp_start_skew_seconds'],
      crl_md: config_data['crl_md'],
      profiles: R509::Config::CAConfig.load_profiles(config_data['profiles'])
    }
    R509::Config::CAConfig.new(opts)
  end

  delegate :revoked?, to: :ca_certificate, allow_nil: true

  cattr_accessor :crl_administrator_reader_writer_builder

  def self.get_certificate_authority(name, password=nil)
    if ca = where(name: name).first
      R509::CertificateAuthority::Signer.new(ca.config(ca_cert: {complete: true, password: password}))
    end
  end

  def self.get_crl(name, password=nil)
    if ca = where(name: name).first
      R509::CRL::Administrator.new(ca.config(ca_cert: {complete: true, password: password}), ca.crl_administrator_reader_writer)
    end
  end

  def self.get_option_builder(name)
    if ca = where(name: name).first
      R509::CertificateAuthority::OptionsBuilder.new(ca.config)
    end
  end

  def self.get_certificate_serial(name)
    if ca = where(name: name).first
      ca.ca_certificate.serial
    end
  end

  module ConfigPool
    def self.all
      R509::Mongoid::Models::CertificateAuthority.all.map(&:config)
    end
    def self.names
      R509::Mongoid::Models::CertificateAuthority.all.map(&:name)
    end
    def self.[](name)
      if ca = R509::Mongoid::Models::CertificateAuthority.where(name: name).first
        ca.config
      end
    end
  end

  def crl_administrator_reader_writer
    if builder = self.class.crl_administrator_reader_writer_builder
      builder.call(self)
    end
  end

  private

  def convert_to_indifferent_access_hash(hash)
    hash.default_proc = proc do |h, k|
       case k
       when String then sym = k.to_sym; h[sym] if h.key?(sym)
       when Symbol then str = k.to_s; h[str] if h.key?(str)
       end
    end
    hash.each do |key, value|
      convert_to_indifferent_access_hash(value) if value.is_a?(Hash)
      if value.is_a?(Array) # for contents of crl_distribution_points
        value.each do |array_value|
          convert_to_indifferent_access_hash(array_value) if array_value.is_a?(Hash)
        end
      end
    end
  end
end

require 'r509/crl/mongoid_reader_writer'
R509::Mongoid::Models::CertificateAuthority.crl_administrator_reader_writer_builder = lambda do |ca|
  R509::CRL::MongoidReaderWriter.new(ca)
end