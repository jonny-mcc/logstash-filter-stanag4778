# encoding: utf-8
require "java"
require "json"
require "base64"
require "jmespath"
require "logstash/filters/stanag4778/jcs"
require "logstash/filters/stanag4778/profile"

java_import java.security.MessageDigest

module LogStash
  module Filters
    module Stanag4778Module
      class ReferenceResolver
        attr_reader :fetcher

        def initialize(fetcher:)
          @fetcher = fetcher
        end

        # Resolves and validates a DataRef or MetadataRef object
        # Returns a hash { uri:, status: (:valid|:mismatch|:unresolved|:unsupported|:error), message:, cty: }
        def verify_reference(ref, root_doc:, bdo_field: "bdo", uri_profile: "auto", is_signed: false, expected_hash_alg: nil)
          uri_str = ref["uri"].to_s
          cty     = ref["cty"].to_s
          hash_b64= ref["hash"]
          alg     = ref["alg"]&.to_s&.downcase

          if is_signed
            if hash_b64.nil? || hash_b64.to_s.strip.empty?
              return {
                uri: uri_str,
                cty: cty,
                status: :error,
                message: "Cryptographically protected reference is missing mandatory 'hash' parameter"
              }
            end
            if alg.nil? || alg.strip.empty?
              return {
                uri: uri_str,
                cty: cty,
                status: :error,
                message: "Cryptographically protected reference is missing mandatory 'alg' parameter"
              }
            end
            if cty.strip.empty?
              return {
                uri: uri_str,
                cty: cty,
                status: :error,
                message: "Cryptographically protected reference is missing mandatory 'cty' parameter"
              }
            end
            if expected_hash_alg && alg != expected_hash_alg
              return {
                uri: uri_str,
                cty: cty,
                status: :error,
                message: "Reference hash algorithm '#{alg}' does not match JWS algorithm expected hash '#{expected_hash_alg}'"
              }
            end
          else
            # Unsigned reference (non-cryptographic BDO)
            if hash_b64.nil? || hash_b64.to_s.strip.empty?
              return {
                uri: uri_str,
                cty: cty,
                status: :valid,
                message: "Unsigned reference (no hash required)"
              }
            end
          end

          alg ||= "sha-256"

          data_bytes = nil
          is_json = cty.empty? || cty.downcase.include?("json")

          if same_document_reference?(uri_str)
            target_data, err = resolve_same_document(root_doc, uri_str, bdo_field: bdo_field, profile: uri_profile)
            if err
              return {
                uri: uri_str,
                cty: cty,
                status: :error,
                message: err
              }
            end

            # ADatP-4778.7 Section 1.4.1.1.2.1.1.2: if cty is JSON, canonicalise with JCS prior to hashing
            canonical_json = JCS.canonicalize(target_data)
            data_bytes = canonical_json.encode("UTF-8").to_java_bytes
          else
            # Detached external reference
            ok, fetched_bytes, fetched_cty = @fetcher.fetch(uri_str)
            unless ok
              return {
                uri: uri_str,
                cty: cty,
                status: :unresolved,
                message: fetched_bytes # contains error message from fetcher
              }
            end

            if is_json
              begin
                parsed_json = JSON.parse(String.from_java_bytes(fetched_bytes))
                canonical_json = JCS.canonicalize(parsed_json)
                data_bytes = canonical_json.encode("UTF-8").to_java_bytes
              rescue StandardError => e
                return {
                  uri: uri_str,
                  cty: cty,
                  status: :error,
                  message: "Failed to parse fetched JSON for canonicalization: #{e.message}"
                }
              end
            else
              data_bytes = fetched_bytes
            end
          end

          # Compute hash using specified algorithm
          java_alg = Profile::IANA_HASH_TO_JAVA[alg]
          unless java_alg
            return {
              uri: uri_str,
              cty: cty,
              status: :unsupported,
              message: "Unsupported hash algorithm '#{alg}'"
            }
          end

          md = MessageDigest.getInstance(java_alg)
          computed_digest = md.digest(data_bytes)
          computed_b64url = Base64.urlsafe_encode64(String.from_java_bytes(computed_digest)).tr("=", "")

          clean_expected = hash_b64.to_s.strip.tr("=", "")

          if computed_b64url == clean_expected
            {
              uri: uri_str,
              cty: cty,
              status: :valid,
              message: "Hash verified successfully"
            }
          else
            {
              uri: uri_str,
              cty: cty,
              status: :mismatch,
              message: "Hash mismatch: expected #{clean_expected}, computed #{computed_b64url}"
            }
          end
        end

        def same_document_reference?(uri_str)
          uri_str.empty? || uri_str.start_with?("#") || uri_str.start_with?("$") || uri_str.start_with?(".")
        end

        private

        # Resolves same-document reference against root_doc, stripping the embedded BDO
        def resolve_same_document(root_doc, uri_str, bdo_field: "bdo", profile: "auto")
          return [nil, "No root document provided for same-document resolution"] if root_doc.nil?

          # Deep clone and remove embedded BDO (ADatP-4778.7 Section 2.8)
          clean_doc = strip_embedded_bdo(root_doc, bdo_field)

          # Null URI ("") or "#" or "$" refers to the entire document
          if uri_str.empty? || uri_str == "#" || uri_str == "$"
            return [clean_doc, nil]
          end

          # Determine syntax
          effective_profile = detect_profile(uri_str, profile)

          case effective_profile
          when "jsonpointer"
            resolve_json_pointer(clean_doc, uri_str)
          when "jsonpath"
            resolve_json_path(clean_doc, uri_str)
          when "jmespath"
            resolve_jmespath(clean_doc, uri_str)
          else
            [nil, "Unsupported or unknown dereferencing profile '#{effective_profile}' for URI '#{uri_str}'"]
          end
        end

        def detect_profile(uri_str, configured)
          return configured unless configured == "auto" || configured.nil?

          if uri_str.start_with?("#/")
            "jsonpointer"
          elsif uri_str.start_with?("$")
            "jsonpath"
          elsif uri_str.start_with?("#")
            "jmespath"
          elsif uri_str.start_with?(".")
            "jmespath"
          else
            "jsonpointer"
          end
        end

        # RFC 6901 JSON Pointer
        def resolve_json_pointer(doc, pointer)
          # Strip leading '#' if present as fragment
          ptr = pointer.start_with?("#") ? pointer[1..-1] : pointer
          return [doc, nil] if ptr.empty?

          unless ptr.start_with?("/")
            return [nil, "JSON Pointer must start with '/' (got '#{pointer}')"]
          end

          tokens = ptr[1..-1].split("/", -1).map do |token|
            token.gsub("~1", "/").gsub("~0", "~")
          end

          curr = doc
          tokens.each do |t|
            if curr.is_a?(Hash)
              if curr.key?(t)
                curr = curr[t]
              else
                return [nil, "JSON Pointer token '#{t}' not found in object"]
              end
            elsif curr.is_a?(Array)
              if t =~ /\A(0|[1-9]\d*)\z/
                idx = t.to_i
                if idx < curr.length
                  curr = curr[idx]
                else
                  return [nil, "JSON Pointer index #{idx} out of bounds (array length #{curr.length})"]
                end
              else
                return [nil, "Invalid array index '#{t}' in JSON Pointer"]
              end
            else
              return [nil, "Cannot evaluate JSON Pointer token '#{t}' on scalar value"]
            end
          end

          [curr, nil]
        end

        # Basic JSONPath ($ and $.field and $['field'] and $[0])
        def resolve_json_path(doc, path)
          return [doc, nil] if path == "$"

          # Use dot or bracket parsing
          expr = path.start_with?("$") ? path[1..-1] : path
          curr = doc

          # Match dot-notation or array indexing: .prop or [idx] or ['prop']
          scanner = expr.scan(/(\.([a-zA-Z0-9_\-]+))|(\[(\d+)\])|(\['([^']+)'\])|(\["([^"]+)"\])/)
          if scanner.empty?
            # Fallback to simple dot split
            parts = expr.sub(/^\./, "").split(".")
            parts.each do |p|
              if curr.is_a?(Hash) && curr.key?(p)
                curr = curr[p]
              else
                return [nil, "JSONPath property '#{p}' not found"]
              end
            end
            return [curr, nil]
          end

          scanner.each do |match|
            dot_prop    = match[1]
            arr_idx     = match[3]
            squote_prop = match[5]
            dquote_prop = match[7]

            if dot_prop || squote_prop || dquote_prop
              prop = dot_prop || squote_prop || dquote_prop
              if curr.is_a?(Hash) && curr.key?(prop)
                curr = curr[prop]
              else
                return [nil, "JSONPath property '#{prop}' not found"]
              end
            elsif arr_idx
              idx = arr_idx.to_i
              if curr.is_a?(Array) && idx < curr.length
                curr = curr[idx]
              else
                return [nil, "JSONPath array index #{idx} out of bounds"]
              end
            end
          end

          [curr, nil]
        end

        # JMESPath query
        def resolve_jmespath(doc, query)
          # Strip leading '#' if used as fragment
          expr = query.start_with?("#") ? query[1..-1] : query
          expr = expr.sub(/^\./, "") if expr.start_with?(".")
          return [doc, nil] if expr.empty?

          begin
            result = JMESPath.search(expr, doc)
            if result.nil?
              [nil, "JMESPath expression '#{expr}' evaluated to nil"]
            else
              [result, nil]
            end
          rescue StandardError => e
            [nil, "JMESPath search error: #{e.message}"]
          end
        end

        # Deep clone object, removing the embedded BDO field
        def strip_embedded_bdo(obj, bdo_field)
          case obj
          when Hash
            new_hash = {}
            obj.each do |k, v|
              next if k.to_s == bdo_field.to_s
              new_hash[k] = strip_embedded_bdo(v, bdo_field)
            end
            new_hash
          when Array
            obj.map { |item| strip_embedded_bdo(item, bdo_field) }
          else
            obj
          end
        end
      end
    end
  end
end
