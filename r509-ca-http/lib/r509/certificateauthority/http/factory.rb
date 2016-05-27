# File modified by Pablo Baños López
# Copyright 2016 Flexiant Ltd. (for modifications only)

module R509::CertificateAuthority::HTTP
  module Factory
    class CSRFactory
      def build(options)
        R509::CSR.new(options)
      end
    end

    class SPKIFactory
      def build(options)
        R509::SPKI.new(options)
      end
    end
  end
end

require 'r509/certificateauthority/http/factory/certificate'
require 'r509/certificateauthority/http/factory/ca'
