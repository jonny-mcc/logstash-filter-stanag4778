# encoding: utf-8
require "java"
require "json"
require "base64"

java_import java.io.FileInputStream
java_import java.io.ByteArrayInputStream
java_import java.security.KeyStore
java_import java.security.cert.CertificateFactory
java_import java.security.cert.X509Certificate
java_import java.security.cert.PKIXParameters
java_import java.security.cert.TrustAnchor
java_import java.security.cert.CertPathValidator
java_import java.security.KeyFactory
java_import java.security.spec.RSAPublicKeySpec
java_import java.security.spec.ECPublicKeySpec
java_import java.security.spec.ECPoint
java_import java.security.AlgorithmParameters
java_import java.security.spec.ECGenParameterSpec
java_import java.security.spec.ECParameterSpec
java_import java.security.MessageDigest
java_import java.math.BigInteger
java_import javax.crypto.spec.SecretKeySpec

module LogStash
  module Filters
    module Stanag4778Module
      class TrustStore
        attr_reader :trusted_certs, :ca_anchors, :jwks_keys, :hmac_keys

        def initialize(ca_path: nil, trusted_certs: [], jwks_path: nil, hmac_keys: {})
          @cert_factory = CertificateFactory.getInstance("X.509")
          @ca_anchors = load_ca_anchors(ca_path)
          @trusted_certs = load_trusted_certs(trusted_certs)
          @jwks_keys = load_jwks(jwks_path)
          @hmac_keys = normalize_hmac_keys(hmac_keys)
        end

        def has_trust_material?
          !@ca_anchors.empty? || !@trusted_certs.empty? || !@jwks_keys.empty? || !@hmac_keys.empty?
        end

        # Find HMAC secret by key id
        def hmac_secret(key_id)
          return nil unless key_id
          @hmac_keys[key_id.to_s]
        end

        # Validate a certificate chain using PKIX path validation against CA anchors
        # Returns [true, nil] or [false, error_message]
        def validate_cert_path(cert_chain)
          return [false, "No certificate chain provided"] if cert_chain.nil? || cert_chain.empty?
          return [false, "No CA anchors configured for PKIX validation"] if @ca_anchors.empty?

          begin
            cert_path = @cert_factory.generateCertPath(cert_chain)
            pkix_params = PKIXParameters.new(@ca_anchors)
            pkix_params.setRevocationEnabled(false) # Offline mode; revocation can be enabled later
            validator = CertPathValidator.getInstance("PKIX")
            validator.validate(cert_path, pkix_params)
            [true, nil]
          rescue Java::JavaSecurityCert::CertPathValidatorException => e
            [false, "CertPath validation failed: #{e.getMessage}"]
          rescue StandardError => e
            [false, "PKIX validation error: #{e.message}"]
          end
        end

        # Check if a certificate matches any pinned trusted cert (by SHA-256 fingerprint)
        def trusted_pinned_cert?(cert)
          return false if @trusted_certs.empty? || cert.nil?
          cert_fingerprint = sha256_fingerprint(cert)
          @trusted_certs.any? { |trusted| sha256_fingerprint(trusted) == cert_fingerprint }
        end

        # Find key in JWKS by kid
        def find_jwks_key(kid)
          return nil unless kid
          @jwks_keys[kid.to_s]
        end

        # SHA-256 fingerprint in hex
        def sha256_fingerprint(cert)
          md = MessageDigest.getInstance("SHA-256")
          digest = md.digest(cert.getEncoded)
          digest.map { |b| sprintf("%02x", b & 0xff) }.join
        end

        # SHA-256 fingerprint in base64url
        def sha256_thumbprint_b64url(cert)
          md = MessageDigest.getInstance("SHA-256")
          digest = md.digest(cert.getEncoded)
          Base64.urlsafe_encode64(String.from_java_bytes(digest)).tr("=", "")
        end

        # SHA-1 fingerprint in base64url
        def sha1_thumbprint_b64url(cert)
          md = MessageDigest.getInstance("SHA-1")
          digest = md.digest(cert.getEncoded)
          Base64.urlsafe_encode64(String.from_java_bytes(digest)).tr("=", "")
        end

        private

        def load_ca_anchors(path)
          anchors = java.util.HashSet.new
          return anchors unless path && ::File.exist?(path)

          certs = parse_pem_certificates(::File.read(path))
          certs.each do |c|
            anchors.add(TrustAnchor.new(c, nil))
          end
          anchors
        end

        def load_trusted_certs(paths)
          certs = []
          Array(paths).each do |p|
            next unless p && ::File.exist?(p)
            certs.concat(parse_pem_certificates(::File.read(p)))
          end
          certs
        end

        def parse_pem_certificates(pem_string)
          certs = []
          return certs if pem_string.nil? || pem_string.strip.empty?

          pattern = /-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/m
          pem_string.scan(pattern) do |match|
            clean_b64 = match.first.gsub(/\s+/, "")
            bytes = Base64.decode64(clean_b64)
            bais = ByteArrayInputStream.new(bytes.to_java_bytes)
            certs << @cert_factory.generateCertificate(bais)
          end
          certs
        end

        def load_jwks(path)
          keys = {}
          return keys unless path && ::File.exist?(path)

          begin
            data = JSON.parse(::File.read(path))
            array = data["keys"] || (data.is_a?(Array) ? data : [data])
            array.each do |k|
              kid = k["kid"]
              parsed = parse_jwk_key(k)
              keys[kid.to_s] = parsed if kid && parsed
            end
          rescue StandardError => e
            # Ignore or log error
          end
          keys
        end

        def parse_jwk_key(jwk)
          kty = jwk["kty"]
          case kty
          when "RSA"
            n_bytes = base64url_decode_to_bytes(jwk["n"])
            e_bytes = base64url_decode_to_bytes(jwk["e"])
            n = BigInteger.new(1, n_bytes)
            e = BigInteger.new(1, e_bytes)
            spec = RSAPublicKeySpec.new(n, e)
            KeyFactory.getInstance("RSA").generatePublic(spec)
          when "EC"
            crv = jwk["crv"]
            x_bytes = base64url_decode_to_bytes(jwk["x"])
            y_bytes = base64url_decode_to_bytes(jwk["y"])
            x = BigInteger.new(1, x_bytes)
            y = BigInteger.new(1, y_bytes)
            point = ECPoint.new(x, y)

            std_name = case crv
                       when "P-256", "secp256r1" then "secp256r1"
                       when "P-384", "secp384r1" then "secp384r1"
                       when "P-521", "secp521r1" then "secp521r1"
                       else crv
                       end

            params = AlgorithmParameters.getInstance("EC")
            params.init(ECGenParameterSpec.new(std_name))
            ec_params = params.getParameterSpec(ECParameterSpec.java_class)
            spec = ECPublicKeySpec.new(point, ec_params)
            KeyFactory.getInstance("EC").generatePublic(spec)
          when "oct"
            base64url_decode_to_bytes(jwk["k"])
          else
            nil
          end
        rescue StandardError => e
          nil
        end

        def base64url_decode_to_bytes(str)
          return nil unless str
          padded = str + "=" * ((4 - str.length % 4) % 4)
          Base64.urlsafe_decode64(padded).to_java_bytes
        end

        def normalize_hmac_keys(hash)
          normalized = {}
          return normalized unless hash.is_a?(Hash)

          hash.each do |k, v|
            val_str = v.to_s
            # Support ${ENV_VAR} style substitution
            val_str = val_str.gsub(/\$\{([^}]+)\}/) { ENV[$1] || "" }
            normalized[k.to_s] = val_str.to_java_bytes
          end
          normalized
        end
      end
    end
  end
end
