class R509::CRL::MongoidReaderWriter < R509::CRL::ReaderWriter

  class CrlEntry
    include ::Mongoid::Document
    field :ca_name, type: String
    field :serial, type: String
    field :reason, type: Integer
    field :revoked_at, type: Integer
    field :unrevoked_at, type: Integer
  end

  class CrlNumberEntry
    include ::Mongoid::Document
    field :ca_name, type: String
    field :number, type: Integer
  end

  REVOCATION_CHECKER = lambda do |ca_name, serial|
    CrlEntry.where(ca_name: ca_name, serial: serial.to_s, :revoked_at.ne => nil, unrevoked_at: nil).exists?
  end

  def initialize(ca)
    @ca = ca
  end

  # Reads a CRL list file from the Mongoid database
  # @param admin [R509::CRL::Administrator] the parent CRL Administrator object
  def read_list(admin)
    CrlEntry.where(ca_name: ca_name, unrevoked_at: nil).each do |crl_entry|
      admin.revoke_cert(crl_entry.serial.to_i, crl_entry.reason, crl_entry.revoked_at, false)
    end
    nil
  end

  # Appends a CRL list entry to the Mongoid database
  # @param serial [Integer] serial number of the certificate to revoke
  # @param reason [Integer,nil] reason for revocation
  # @param revoke_time [Integer]
  def write_list_entry(serial, revoke_time, reason)
    CrlEntry.create!(ca_name: ca_name, serial: serial.to_s, revoked_at: revoke_time, reason: reason)
  end

  # Remove a CRL list entry from Mongoid
  # @param serial [Integer] serial number of the certificate to remove from the list
  def remove_list_entry(serial)
    if crl_entry = CrlEntry.where(ca_name: ca_name, serial: serial.to_s, unrevoked_at: nil).first
      crl_entry.update_attributes(unrevoked_at: Time.now.to_i)
    end
  end

  # read the CRL number from Mongoid
  def read_number
    if crl_number_entry = CrlNumberEntry.where(ca_name: ca_name).first
      crl_number_entry.number
    else
      0
    end
  end

  # write the CRL number to Mongoid
  def write_number(crl_number)
    crl_number_entry = CrlNumberEntry.where(ca_name: ca_name).first
    crl_number_entry ||= CrlNumberEntry.new(ca_name: ca_name)
    crl_number_entry.number = crl_number
    crl_number_entry.save
  end

  private

  def ca_name
    @ca.name
  end
end