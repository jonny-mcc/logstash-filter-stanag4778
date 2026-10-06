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
java_import java.security.cert.PKIXRevocationChecker
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
        attr_reader :trusted_certs, :ca_anchors, :jwks_keys, :hmac_keys,
                    :revocation_mode, :required_eku, :allowed_subjects

        def initialize(ca_path: nil, trusted_certs: [], jwks_path: nil, hmac_keys: {},
                       revocation_mode: "none", required_eku: [], allowed_subjects: [])
          @cert_factory = CertificateFactory.getInstance("X.509")
          @revocation_mode = revocation_mode.to_s
          @required_eku = Array(required_eku).map(&:to_s)
          @allowed_subjects = Array(allowed_subjects).map do |s|
            s.is_a?(Regexp) ? s : Regexp.new(s.to_s, Regexp::IGNORECASE)
          end

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

          leaf = cert_chain.first
          policy_ok, policy_err = validate_signer_policy(leaf)
          return [false, policy_err] unless policy_ok

          begin
            cert_path = @cert_factory.generateCertPath(cert_chain)
            pkix_params = PKIXParameters.new(@ca_anchors)

            if @revocation_mode == "crl" || @revocation_mode == "ocsp"
              validator = CertPathValidator.getInstance("PKIX")
              rev_checker = validator.getRevocationChecker
              if @revocation_mode == "ocsp"
                rev_checker.setOptions(java.util.EnumSet.of(PKIXRevocationChecker::Option::PREFER_CRLS.class::NO_FALLBACK)) rescue nil
              end
              pkix_params.addCertPathChecker(rev_checker)
              pkix_params.setRevocationEnabled(true)
            else
              pkix_params.setRevocationEnabled(false)
            end

            validator = CertPathValidator.getInstance("PKIX")
            validator.validate(cert_path, pkix_params)
            [true, nil]
          rescue Java::JavaSecurityCert::CertPathValidatorException => e
            [false, "CertPath validation failed: #{e.getMessage}"]
          rescue StandardError, java.lang.Exception => e
            [false, "PKIX validation error: #{e.message}"]
          end
        end

        # Validate signer certificate policy (validity, key usage, EKU, allowed subject)
        def validate_signer_policy(cert)
          return [false, "Certificate is nil"] if cert.nil?

          # 1. Check validity dates
          begin
            cert.checkValidity
          rescue Java::JavaSecurityCert::CertificateExpiredException
            return [false, "Signer certificate has expired (#{cert.getNotAfter})"]
          rescue Java::JavaSecurityCert::CertificateNotYetValidException
            return [false, "Signer certificate is not yet valid (#{cert.getNotBefore})"]
          rescue StandardError => e
            return [false, "Certificate validity check failed: #{e.message}"]
          end

          # 2. KeyUsage check (bit 0: digitalSignature, bit 1: nonRepudiation)
          ku = cert.getKeyUsage
          if ku
            dig_sig = ku[0]
            non_rep = ku[1]
            unless dig_sig || non_rep
              return [false, "Signer certificate KeyUsage does not permit digitalSignature or nonRepudiation"]
            end
          end

          # 3. Extended Key Usage check
          if @required_eku && !@required_eku.empty?
            cert_ekus = cert.getExtendedKeyUsage
            if cert_ekus.nil? || cert_ekus.isEmpty
              return [false, "Signer certificate does not have required Extended Key Usage"]
            end
            @required_eku.each do |req_oid|
              unless cert_ekus.contains(req_oid)
                return [false, "Signer certificate missing required Extended Key Usage OID '#{req_oid}'"]
              end
            end
          end

          # 4. Subject DN whitelist
          if @allowed_subjects && !@allowed_subjects.empty?
            subject_dn = cert.getSubjectX500Principal.getName
            matched = @allowed_subjects.any? { |re| subject_dn =~ re }
            unless matched
              return [false, "Signer subject '#{subject_dn}' does not match any allowed_signer_subjects pattern"]
            end
          end

          [true, nil]
        end

        # Check if a certificate matches any pinned trusted cert (by SHA-256 fingerprint)
        def trusted_pinned_cert?(cert)
          return false if @trusted_certs.empty? || cert.nil?
          cert_fingerprint = sha256_fingerprint(cert)
          @trusted_certs.any? { |trusted| sha256_fingerprint(trusted) == cert_fingerprint }
        end

        # Check if a public key matches any trusted public key from JWKS or pinned certs
        def trusted_public_key?(pub_key)
          return false if pub_key.nil?
          key_encoded = pub_key.getEncoded

          # Compare with pinned cert public keys (and check cert validity)
          matched_cert = @trusted_certs.find { |c| java.util.Arrays.equals(c.getPublicKey.getEncoded, key_encoded) }
          if matched_cert
            ok, _ = validate_signer_policy(matched_cert)
            return true if ok
          end

          # Compare with JWKS keys
          @jwks_keys.values.any? do |k|
            if k.respond_to?(:getEncoded)
              java.util.Arrays.equals(k.getEncoded, key_encoded)
            else
              false
            end
          end
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
          return anchors unless path

          unless ::File.exist?(path)
            raise LogStash::ConfigurationError, "CA bundle file not found: #{path}"
          end

          certs = parse_pem_certificates(::File.read(path))
          if certs.empty?
            raise LogStash::ConfigurationError, "No valid X.509 certificates found in CA bundle: #{path}"
          end

          certs.each do |c|
            anchors.add(TrustAnchor.new(c, nil))
          end
          anchors
        end

        def load_trusted_certs(paths)
          certs = []
          Array(paths).each do |p|
            next unless p
            unless ::File.exist?(p)
              raise LogStash::ConfigurationError, "Trusted certificate file not found: #{p}"
            end
            parsed = parse_pem_certificates(::File.read(p))
            if parsed.empty?
              raise LogStash::ConfigurationError, "No valid X.509 certificate parsed from: #{p}"
            end
            certs.concat(parsed)
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
          return keys unless path

          unless ::File.exist?(path)
            raise LogStash::ConfigurationError, "JWKS file not found: #{path}"
          end

          begin
            data = JSON.parse(::File.read(path))
            array = data["keys"] || (data.is_a?(Array) ? data : [data])
            array.each do |k|
              kid = k["kid"]
              parsed = parse_jwk_key(k)
              keys[kid.to_s] = parsed if kid && parsed
            end
          rescue StandardError, java.lang.Exception => e
            raise LogStash::ConfigurationError, "Failed to parse JWKS file #{path}: #{e.message}"
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
            if val_str.empty?
              raise LogStash::ConfigurationError, "HMAC secret for key ID '#{k}' cannot be empty"
            end
            normalized[k.to_s] = val_str.to_java_bytes
          end
          normalized
        end
      end
    end
  end
end
