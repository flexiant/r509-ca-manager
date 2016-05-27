class R509::Mongoid::Models::Crl
  include ::Mongoid::Document
  field :ca_name, type: String
  field :crl_pem, type: String

  def self.store_crl(ca_name, crl_pem)
    crl = where(ca_name: ca_name).first
    crl ||= new(ca_name: ca_name)
    crl.crl_pem = crl_pem
    crl.save
  end
end