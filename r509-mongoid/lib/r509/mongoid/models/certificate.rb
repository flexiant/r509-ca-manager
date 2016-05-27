class R509::Mongoid::Models::Certificate
	include ::Mongoid::Document
	include ::Mongoid::Attributes::Dynamic

	field :public_key, type: String
	field :private_key, type: String
	field :password, type: String, default: ''

	belongs_to :signing_ca, class_name: 'R509::Mongoid::Models::CertificateAuthority', inverse_of: :signed_certs

	def r509_cert(opts=nil)
		opts ||= {}
		cert_opts = {
			cert: public_key
		}
		if opts[:complete] and private_key
			key = R509::PrivateKey.new(
				:key => private_key,
				:password => opts[:password] || self.password
			)
			cert_opts.merge!(key: key)
		end
		R509::Cert.new(cert_opts)
	end

	delegate :serial, to: :r509_cert
	delegate :name, to: :signing_ca, prefix: true, allow_nil: true

	def revoked?
		revocation_checker.call(signing_ca_name, serial)
	end

	cattr_accessor :revocation_checker
end

R509::Mongoid::Models::Certificate.revocation_checker = R509::CRL::MongoidReaderWriter::REVOCATION_CHECKER