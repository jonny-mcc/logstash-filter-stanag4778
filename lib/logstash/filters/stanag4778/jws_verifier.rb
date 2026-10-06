# encoding: utf-8
require "java"
require "json"
require "base64"
require "time"
require "logstash/filters/stanag4778/profile"
require "logstash/filters/stanag4778/reference_resolver"

java_import java.security.Signature
java_import java.security.MessageDigest
java_import java.security.spec.MGF1ParameterSpec
java_import java.security.spec.PSSParameterSpec
java_import javax.crypto.Mac
java_import javax.crypto.spec.SecretKeySpec
java_import java.security.cert.CertificateFactory
java_import java.io.ByteArrayInputStream

module LogStash
  module Filters
    module Stanag4778Module
      class JwsVerifier
        attr_reader :trust_store, :fetcher, :resolver

        def initialize(trust_store:, fetcher:, strict_profile: true, clock_skew: 300,
                       max_age: 0, require_signature: true, default_profile: "auto", bdo_field: "bdo")
          @trust_store = trust_store
          @fetcher = fetcher
          @strict_profile = !!strict_profile
          @clock_skew = clock_skew.to_i
          @max_age = max_age.to_i
          @require_signature = !!require_signature
          @default_profile = default_profile
          @bdo_field = bdo_field
          @resolver = ReferenceResolver.new(fetcher: @fetcher)
        end

        def verify(payload)
          errors = []
          warnings = []

          # Parse JSON payload
          parsed_json, root_doc, embedded = extract_bdo(payload)
          if parsed_json.nil?
            return {
              format: "json",
              binding_type: "unknown",
              signed: false,
              valid: false,
              parse_error: true,
              errors: ["Failed to locate or parse STANAG 4778 JSON BDO"],
              warnings: warnings,
              signatures: [],
              bindings: []
            }
          end

          binding_type = if embedded
                           "embedded"
                         else
                           # Inspect bindings inside to see if encapsulating or detached
                           "encapsulating"
                         end

          # Verify BDO "typ" (STANAG 4778.7 Section 1.4)
          typ = parsed_json["typ"].to_s
          if typ.downcase != Profile::JSON_TYP_BDO.downcase
            msg = "BDO 'typ' parameter '#{typ}' does not match '#{Profile::JSON_TYP_BDO}'"
            @strict_profile ? errors << msg : warnings << msg
          end

          bdis = parsed_json["bdis"]
          if bdis.nil? || !bdis.is_a?(Array) || bdis.empty?
            errors << "BDO 'bdis' array is missing or empty"
            return {
              format: "json",
              binding_type: binding_type,
              signed: false,
              valid: false,
              errors: errors,
              warnings: warnings,
              signatures: [],
              bindings: []
            }
          end

          signatures_res = []
          all_bindings = []
          all_valid = true
          has_unresolved = false
          all_signed = true
          any_signed = false

          bdis.each_with_index do |bdi_obj, idx|
            jws_str = bdi_obj.is_a?(Hash) ? bdi_obj["bdi"] : nil
            unless jws_str.is_a?(String)
              errors << "bdis[#{idx}] 'bdi' member is not a string"
              all_valid = false
              all_signed = false
              next
            end

            sig_res, bindings_res = verify_single_jws(jws_str, root_doc: root_doc, bdo_obj: parsed_json)
            signatures_res << sig_res
            all_bindings.concat(bindings_res)

            if sig_res[:signed]
              any_signed = true
            else
              all_signed = false
            end
            all_valid = false unless sig_res[:valid]

            if sig_res[:errors]&.any?
              errors.concat(sig_res[:errors])
            end
            if sig_res[:warnings]&.any?
              warnings.concat(sig_res[:warnings])
            end

            if sig_res[:references]&.any? { |r| r[:status] == :unresolved }
              has_unresolved = true
            end
          end

          if @require_signature && (!all_signed || bdis.empty?)
            errors << "Payload contains unsigned BDO entries but 'require_signature' is enabled"
            all_valid = false
          end

          # Infer actual binding type based on references and data present
          detected_type = classify_binding_type(all_bindings, embedded)

          {
            format: "json",
            binding_type: detected_type,
            signed: any_signed,
            valid: all_valid && errors.empty?,
            errors: errors,
            warnings: warnings,
            signatures: signatures_res,
            bindings: all_bindings,
            has_unresolved_references: has_unresolved
          }
        rescue StandardError => e
          {
            format: "json",
            binding_type: "unknown",
            signed: false,
            valid: false,
            errors: ["JWS verification failure: #{e.message}"],
            warnings: warnings,
            signatures: [],
            bindings: []
          }
        end

        private

        def extract_bdo(input)
          data = input.is_a?(Hash) ? input : JSON.parse(input.to_s)

          if data.key?(@bdo_field) && data[@bdo_field].is_a?(Hash)
            # Embedded BDO
            [data[@bdo_field], data, true]
          elsif data.key?("typ") && data.key?("bdis")
            # Root encapsulating or detached BDO
            [data, nil, false]
          else
            [nil, nil, false]
          end
        rescue StandardError => e
          [nil, nil, false]
        end

        def verify_single_jws(jws_str, root_doc:, bdo_obj:)
          parts = jws_str.strip.split(".", -1)
          unless parts.length == 3
            return [
              { signed: false, valid: false, errors: ["Invalid JWS compact serialization format: expected 3 parts, got #{parts.length}"] },
              []
            ]
          end

          header_b64, payload_b64, sig_b64 = parts
          signing_input = "#{header_b64}.#{payload_b64}".encode("ASCII-8BIT")

          header_json = decode_b64_json(header_b64)
          payload_json = decode_b64_json(payload_b64)

          unless header_json && payload_json
            return [
              { signed: false, valid: false, errors: ["Failed to base64url-decode JWS header or payload"] },
              []
            ]
          end

          errors = []
          warnings = []
          sig_info = {
            algorithm: header_json["alg"],
            key_id: header_json["kid"],
            header: header_json
          }

          # 1. Header checks
          unless header_json.key?("alg")
            errors << "JWS protected header is missing mandatory 'alg' parameter"
            alg = "missing"
          else
            alg = header_json["alg"].to_s
          end
          sig_info[:algorithm] = alg

          unless Profile::JWS_ALGORITHMS.key?(alg)
            errors << "JWS 'alg' parameter '#{alg}' is not in permitted algorithms list"
          end

          # ADatP-4778.7 Section 1.4.1.1.1: cty MUST be "vnd.nato.bindingdataobject+json"
          cty = header_json["cty"].to_s
          expected_cty = Profile::JSON_CTY_BDO
          expected_full = Profile::JSON_CTY_BDO_FULL
          unless cty == expected_cty || cty == expected_full
            msg = "JWS 'cty' header '#{cty}' is invalid; must be '#{expected_cty}'"
            @strict_profile ? errors << msg : warnings << msg
          end

          # crit parameter
          if header_json.key?("crit")
            crit = header_json["crit"]
            if !crit.is_a?(Array) || crit.empty?
              errors << "JWS 'crit' header must be a non-empty array"
            else
              crit.each do |param|
                p_str = param.to_s
                unless header_json.key?(p_str)
                  errors << "Critical header parameter '#{p_str}' declared in 'crit' is missing from header"
                end
                unless Profile::JWS_UNDERSTOOD_HEADER_PARAMS.include?(p_str)
                  errors << "Unrecognized critical header parameter '#{p_str}' declared in 'crit'"
                end
              end
            end
          end

          # iat check
          iat = header_json["iat"]
          sig_info[:iat] = iat
          is_signed = alg != "none" && alg != "missing"
          sig_info[:signed] = is_signed

          if is_signed
            if iat.nil?
              errors << "Signed BDO is missing mandatory 'iat' header parameter"
            else
              iat_num = iat.to_i
              now = Time.now.to_i
              if iat_num > now + @clock_skew
                errors << "JWS 'iat' (#{iat_num}) is in the future beyond clock skew (#{now} + #{@clock_skew})"
              elsif @max_age > 0 && iat_num < now - @max_age
                errors << "JWS 'iat' (#{iat_num}) exceeds maximum allowed signature age of #{@max_age} seconds"
              end
            end
          end

          # 2. Cryptographic signature verification
          crypto_valid = false
          if alg == "none"
            if !sig_b64.empty?
              errors << "Signature must be empty when alg is 'none'"
            else
              crypto_valid = true
            end
          else
            crypto_valid, crypto_err = verify_crypto_signature(alg, header_json, signing_input, sig_b64)
            errors << crypto_err if crypto_err
          end

          # 3. Reference validation
          ref_results = []
          bindings = []
          expected_hash = Profile::JWS_ALG_TO_HASH[alg]

          mbs = payload_json["mbs"]
          if mbs.is_a?(Array)
            mbs.each do |mb|
              binding_entry = {
                metadata: mb["mds"],
                data_objects: mb["dts"] || [],
                data_references: []
              }

              # Data references
              dtrs = mb["dtrs"] || []
              dtrs.each do |dtr|
                ref_res = @resolver.verify_reference(
                  dtr,
                  root_doc: root_doc || payload_json,
                  bdo_field: @bdo_field,
                  uri_profile: @default_profile,
                  is_signed: is_signed,
                  expected_hash_alg: expected_hash
                )
                ref_results << ref_res
                binding_entry[:data_references] << ref_res
                if ref_res[:status] == :mismatch || ref_res[:status] == :error
                  errors << "Reference verification failed for #{dtr['uri']}: #{ref_res[:message]}"
                end
              end

              # Metadata references
              mdrs = mb["mdrs"] || []
              mdrs.each do |mdr|
                ref_res = @resolver.verify_reference(
                  mdr,
                  root_doc: root_doc || payload_json,
                  bdo_field: @bdo_field,
                  uri_profile: @default_profile,
                  is_signed: is_signed,
                  expected_hash_alg: expected_hash
                )
                ref_results << ref_res
                if ref_res[:status] == :mismatch || ref_res[:status] == :error
                  errors << "Metadata reference verification failed for #{mdr['uri']}: #{ref_res[:message]}"
                end
              end

              bindings << binding_entry
            end
          end

          sig_info[:valid] = crypto_valid && errors.empty?
          sig_info[:revocation_checked] = (@trust_store.revocation_mode != "none")
          sig_info[:errors] = errors
          sig_info[:warnings] = warnings
          sig_info[:references] = ref_results

          [sig_info, bindings]
        end

        def verify_crypto_signature(alg, header_json, signing_input, sig_b64)
          sig_bytes = decode_b64_bytes(sig_b64)
          input_bytes = signing_input.to_java_bytes

          if Profile::JWS_JAVA_MAC_ALGORITHMS.key?(alg)
            verify_mac(alg, header_json, input_bytes, sig_bytes)
          elsif Profile::JWS_JAVA_SIGNATURE_ALGORITHMS.key?(alg)
            verify_pki(alg, header_json, input_bytes, sig_bytes)
          else
            [false, "Unsupported JWS algorithm '#{alg}'"]
          end
        rescue StandardError => e
          [false, "Signature verification error: #{e.message}"]
        end

        def verify_mac(alg, header, input_bytes, sig_bytes)
          kid = header["kid"]
          secret_bytes = @trust_store.hmac_secret(kid)

          return [false, "No HMAC secret found for key ID '#{kid}'"] if secret_bytes.nil?

          mac_name = Profile::JWS_JAVA_MAC_ALGORITHMS[alg]
          key_spec = SecretKeySpec.new(secret_bytes, mac_name)
          mac = Mac.getInstance(mac_name)
          mac.init(key_spec)
          expected_sig = mac.doFinal(input_bytes)

          if MessageDigest.isEqual(expected_sig, sig_bytes)
            [true, nil]
          else
            [false, "HMAC signature mismatch"]
          end
        end

        def verify_pki(alg, header, input_bytes, sig_bytes)
          public_key, err = resolve_public_key(header)
          return [false, err] if err

          java_alg = Profile::JWS_JAVA_SIGNATURE_ALGORITHMS[alg]

          if alg.start_with?("PS")
            sig = Signature.getInstance("RSASSA-PSS")
            md_name, salt_len = case alg
                                when "PS256" then ["SHA-256", 32]
                                when "PS384" then ["SHA-384", 48]
                                when "PS512" then ["SHA-512", 64]
                                end
            pss_spec = PSSParameterSpec.new(
              md_name, "MGF1", MGF1ParameterSpec.new(md_name), salt_len, 1
            )
            sig.setParameter(pss_spec)
            sig.initVerify(public_key)
            sig.update(input_bytes)
            return [true, nil] if sig.verify(sig_bytes)
          else
            sig = Signature.getInstance(java_alg)
            sig.initVerify(public_key)
            sig.update(input_bytes)
            return [true, nil] if sig.verify(sig_bytes)
          end

          [false, "Cryptographic signature validation failed"]
        rescue StandardError => e
          [false, "PKI verification exception: #{e.message}"]
        end

        def resolve_public_key(header)
          # 1. kid in JWKS
          if header["kid"]
            jwk_key = @trust_store.find_jwks_key(header["kid"])
            return [jwk_key, nil] if jwk_key
          end

          # 2. x5c certificate chain
          if header["x5c"] && header["x5c"].is_a?(Array) && !header["x5c"].empty?
            cert_factory = CertificateFactory.getInstance("X.509")
            chain = header["x5c"].map do |b64_cert|
              clean = b64_cert.gsub(/\s+/, "")
              raw = Base64.decode64(clean)
              cert_factory.generateCertificate(ByteArrayInputStream.new(raw.to_java_bytes))
            end

            leaf = chain.first

            # Check if leaf is pinned
            if @trust_store.trusted_pinned_cert?(leaf)
              ok, err = @trust_store.validate_signer_policy(leaf)
              return [nil, "Pinned certificate policy check failed: #{err}"] unless ok
              return [leaf.getPublicKey, nil]
            end

            # Validate chain against CAs
            valid, path_err = @trust_store.validate_cert_path(chain)
            if valid
              return [leaf.getPublicKey, nil]
            else
              return [nil, "x5c certificate path validation failed: #{path_err}"]
            end
          end

          # 3. x5t#S256 / x5t matching pinned certificates
          if header["x5t#S256"]
            target_thumb = header["x5t#S256"].tr("=", "")
            match = @trust_store.trusted_certs.find do |c|
              @trust_store.sha256_thumbprint_b64url(c) == target_thumb
            end
            if match
              ok, err = @trust_store.validate_signer_policy(match)
              return [nil, "Pinned certificate policy check failed: #{err}"] unless ok
              return [match.getPublicKey, nil]
            end
          end

          if header["x5t"]
            target_thumb = header["x5t"].tr("=", "")
            match = @trust_store.trusted_certs.find do |c|
              @trust_store.sha1_thumbprint_b64url(c) == target_thumb
            end
            if match
              ok, err = @trust_store.validate_signer_policy(match)
              return [nil, "Pinned certificate policy check failed: #{err}"] unless ok
              return [match.getPublicKey, nil]
            end
          end

          # 4. Embedded jwk - only accepted if it matches pre-configured trusted keys
          if header["jwk"] && header["jwk"].is_a?(Hash)
            jwk = header["jwk"]
            if jwk["kty"] == "oct"
              return [nil, "Embedded symmetric 'oct' JWK in protected header is prohibited"]
            end
            parsed_key = @trust_store.send(:parse_jwk_key, jwk)
            if parsed_key && @trust_store.trusted_public_key?(parsed_key)
              return [parsed_key, nil]
            elsif parsed_key
              return [nil, "Embedded JWK public key does not match any configured trusted certificate or JWKS key"]
            end
          end

          if header["jku"]
            return [nil, "Fetching public keys from 'jku' is unsupported; configure jwks_path instead"]
          end

          if header["x5u"]
            return [nil, "Fetching certificates from 'x5u' is unsupported; configure trusted_certificates or ssl_certificate_authorities instead"]
          end

          [nil, "Unable to resolve trusted public key for signature verification"]
        end

        def decode_b64_json(str)
          return nil unless str
          padded = str + "=" * ((4 - str.length % 4) % 4)
          raw = Base64.urlsafe_decode64(padded)
          JSON.parse(raw)
        rescue StandardError => e
          nil
        end

        def decode_b64_bytes(str)
          return [].to_java_bytes unless str
          padded = str + "=" * ((4 - str.length % 4) % 4)
          Base64.urlsafe_decode64(padded).to_java_bytes
        rescue StandardError => e
          [].to_java_bytes
        end

        def classify_binding_type(bindings, embedded)
          return "embedded" if embedded

          has_external = false
          has_embedded = false

          bindings.each do |b|
            has_embedded = true if b[:data_objects]&.any?
            b[:data_references]&.each do |dtr|
              uri = dtr[:uri].to_s
              if @resolver.same_document_reference?(uri)
                has_embedded = true
              else
                has_external = true
              end
            end
          end

          if has_external && !has_embedded
            "detached"
          else
            "encapsulating"
          end
        end
      end
    end
  end
end
