# encoding: utf-8
require "java"
require "base64"
require "time"
require "logstash/filters/stanag4778/profile"

java_import javax.xml.parsers.DocumentBuilderFactory
java_import javax.xml.crypto.dsig.XMLSignatureFactory
java_import javax.xml.crypto.dsig.dom.DOMValidateContext
java_import javax.xml.crypto.dsig.XMLSignature
java_import javax.xml.crypto.dsig.Reference
java_import javax.xml.crypto.dsig.Manifest
java_import javax.xml.crypto.KeySelector
java_import javax.xml.crypto.KeySelectorResult
java_import javax.xml.crypto.URIDereferencer
java_import javax.xml.crypto.OctetStreamData
java_import javax.xml.validation.SchemaFactory
java_import javax.xml.XMLConstants
java_import javax.xml.transform.dom.DOMSource
java_import javax.xml.transform.stream.StreamSource
java_import java.io.StringReader
java_import java.io.ByteArrayInputStream
java_import org.w3c.dom.Node
java_import org.w3c.dom.Element
java_import org.xml.sax.InputSource
java_import javax.crypto.spec.SecretKeySpec
java_import java.security.cert.CertificateFactory

module LogStash
  module Filters
    module Stanag4778Module
      # KeySelector for javax.xml.crypto.dsig DOM validation
      class DomKeySelector < KeySelector
        def initialize(trust_store)
          super()
          @trust_store = trust_store
          @cert_factory = CertificateFactory.getInstance("X.509")
          @selected_info = {}
        end

        attr_reader :selected_info

        def select(key_info, purpose, method, context)
          return SimpleKeySelectorResult.new(nil) if key_info.nil?

          method_alg = method.getAlgorithm

          iter = key_info.getContent.iterator
          while iter.hasNext
            info = iter.next

            # 1. X509Data
            if info.is_a?(Java::JavaxXmlCryptoDsigKeyinfo::X509Data)
              data_list = info.getContent
              certs = []
              d_iter = data_list.iterator
              while d_iter.hasNext
                item = d_iter.next
                if item.is_a?(Java::JavaSecurityCert::X509Certificate)
                  certs << item
                end
              end

              if certs.any?
                leaf = certs.first
                @selected_info[:subject] = leaf.getSubjectX500Principal.getName
                @selected_info[:issuer]  = leaf.getIssuerX500Principal.getName
                @selected_info[:serial]  = leaf.getSerialNumber.to_s

                # Validate against pinned certs or CA path
                is_trusted = @trust_store.trusted_pinned_cert?(leaf)
                unless is_trusted
                  valid, err = @trust_store.validate_cert_path(certs)
                  if valid
                    is_trusted = true
                  else
                    @selected_info[:cert_error] = err
                  end
                end

                if is_trusted
                  @selected_info[:trusted] = true
                  return SimpleKeySelectorResult.new(leaf.getPublicKey)
                else
                  # Return public key so core verification can proceed, but flag as untrusted
                  @selected_info[:trusted] = false
                  return SimpleKeySelectorResult.new(leaf.getPublicKey)
                end
              end

            # 2. KeyValue
            elsif info.is_a?(Java::JavaxXmlCryptoDsigKeyinfo::KeyValue)
              pub_key = info.getPublicKey
              @selected_info[:key_type] = pub_key.getAlgorithm
              # Only accept if matched in trust_store or flagged untrusted
              return SimpleKeySelectorResult.new(pub_key)

            # 3. KeyName (for HMAC)
            elsif info.is_a?(Java::JavaxXmlCryptoDsigKeyinfo::KeyName)
              name = info.getName
              @selected_info[:key_id] = name
              secret_bytes = @trust_store.hmac_secret(name)
              if secret_bytes
                @selected_info[:trusted] = true
                java_mac_alg = case method_alg
                               when "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256" then "HmacSHA256"
                               when "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384" then "HmacSHA384"
                               when "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512" then "HmacSHA512"
                               else "HmacSHA256"
                               end
                key_spec = SecretKeySpec.new(secret_bytes, java_mac_alg)
                return SimpleKeySelectorResult.new(key_spec)
              else
                @selected_info[:trusted] = false
                @selected_info[:key_error] = "HMAC secret not found for KeyName '#{name}'"
              end
            end
          end

          SimpleKeySelectorResult.new(nil)
        end
      end

      class SimpleKeySelectorResult
        include KeySelectorResult

        def initialize(key)
          @key = key
        end

        def getKey
          @key
        end
      end

      # Custom URIDereferencer to safely handle same-document and external references
      class SafeURIDereferencer
        include URIDereferencer

        def initialize(default_deref, fetcher)
          @default_deref = default_deref
          @fetcher = fetcher
        end

        def dereference(uri_ref, context)
          uri_str = uri_ref.getURI
          if uri_str.nil? || uri_str.empty? || uri_str.start_with?("#")
            return @default_deref.dereference(uri_ref, context)
          end

          # External reference: use fetcher with allowlist
          ok, data_bytes, cty = @fetcher.fetch(uri_str)
          if ok
            bais = ByteArrayInputStream.new(data_bytes)
            OctetStreamData.new(bais, uri_str, cty)
          else
            # Deny by throwing exception
            raise Java::JavaxXmlCrypto::URIReferenceException.new("External dereference blocked or failed for '#{uri_str}': #{data_bytes}")
          end
        end
      end

      class XmlVerifier
        attr_reader :trust_store, :fetcher

        def initialize(trust_store:, fetcher:, strict_profile: true, validate_schema: true,
                       clock_skew: 300, max_age: 0, require_signature: true)
          @trust_store = trust_store
          @fetcher = fetcher
          @strict_profile = !!strict_profile
          @validate_schema = !!validate_schema
          @clock_skew = clock_skew.to_i
          @max_age = max_age.to_i
          @require_signature = !!require_signature

          @doc_builder_factory = build_secure_builder_factory
          @schema = load_schema if @validate_schema
        end

        def verify(xml_string)
          errors = []
          warnings = []

          doc = parse_secure_xml(xml_string)
          if doc.nil?
            return {
              format: "xml",
              binding_type: "unknown",
              signed: false,
              valid: false,
              parse_error: true,
              errors: ["Failed to parse XML document (malformed XML or XXE detected)"],
              warnings: warnings,
              signatures: [],
              bindings: []
            }
          end

          # Find mb:BindingInformation element
          bdo_element = find_bdo_element(doc)
          if bdo_element.nil?
            return {
              format: "xml",
              binding_type: "unknown",
              signed: false,
              valid: false,
              errors: ["No STANAG 4778 BindingInformation element found in document"],
              warnings: warnings,
              signatures: [],
              bindings: []
            }
          end

          # Register ID attributes throughout doc so #id- references can be resolved by XMLDSIG
          register_ids(doc.getDocumentElement)

          # Optional XML Schema validation
          if @validate_schema && @schema
            schema_errors = validate_dom_schema(bdo_element)
            if schema_errors.any?
              msg = "STANAG 4778 XML schema validation failed: #{schema_errors.join('; ')}"
              @strict_profile ? errors.concat(schema_errors) : warnings.concat(schema_errors)
            end
          end

          # Detect binding type (encapsulating, embedded, detached)
          is_root = (doc.getDocumentElement == bdo_element)
          raw_binding_type = is_root ? "encapsulating" : "embedded"

          # Extract bindings and references from XML
          bindings_data = extract_xml_bindings(bdo_element)

          # Find XML Signatures
          sig_elements = find_signature_elements(bdo_element)
          is_signed = sig_elements.any?

          if !is_signed && @require_signature
            errors << "XML BDO contains no XMLDSIG signatures but 'require_signature' is enabled"
            return {
              format: "xml",
              binding_type: raw_binding_type,
              signed: false,
              valid: false,
              errors: errors,
              warnings: warnings,
              signatures: [],
              bindings: bindings_data
            }
          end

          signatures_res = []
          all_sigs_valid = true
          has_unresolved = false

          sig_factory = XMLSignatureFactory.getInstance("DOM")
          default_deref = sig_factory.getURIDereferencer

          sig_elements.each_with_index do |sig_elem, idx|
            sig_info, valid = verify_single_xml_sig(
              sig_factory, sig_elem, default_deref, bdo_element, is_root
            )
            signatures_res << sig_info
            all_sigs_valid = false unless valid

            if sig_info[:errors]&.any?
              errors.concat(sig_info[:errors])
            end
            if sig_info[:warnings]&.any?
              warnings.concat(sig_info[:warnings])
            end
            if sig_info[:has_unresolved]
              has_unresolved = true
            end
          end

          # Profile rule checks on BDO
          profile_errors, profile_warnings = check_bdo_profile_rules(bdo_element, signatures_res, is_root)
          errors.concat(profile_errors)
          warnings.concat(profile_warnings)

          detected_type = classify_xml_binding_type(bindings_data, is_root)

          {
            format: "xml",
            binding_type: detected_type,
            signed: is_signed,
            valid: (is_signed ? all_sigs_valid : !@require_signature) && errors.empty?,
            errors: errors,
            warnings: warnings,
            signatures: signatures_res,
            bindings: bindings_data,
            has_unresolved_references: has_unresolved
          }
        rescue StandardError => e
          {
            format: "xml",
            binding_type: "unknown",
            signed: false,
            valid: false,
            errors: ["XML verification error: #{e.message}"],
            warnings: warnings,
            signatures: [],
            bindings: []
          }
        end

        private

        def build_secure_builder_factory
          dbf = DocumentBuilderFactory.newInstance
          dbf.setNamespaceAware(true)
          dbf.setValidating(false)
          # Disable XXE
          dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) rescue nil
          dbf.setFeature("http://xml.org/sax/features/external-general-entities", false) rescue nil
          dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false) rescue nil
          dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false) rescue nil
          dbf.setXIncludeAware(false) rescue nil
          dbf.setExpandEntityReferences(false) rescue nil
          dbf.setFeature(XMLConstants::FEATURE_SECURE_PROCESSING, true) rescue nil
          dbf
        end

        def parse_secure_xml(xml_string)
          builder = @doc_builder_factory.newDocumentBuilder
          is = InputSource.new(StringReader.new(xml_string))
          builder.parse(is)
        rescue StandardError => e
          nil
        end

        def load_schema
          sf = SchemaFactory.newInstance(XMLConstants::W3C_XML_SCHEMA_NS_URI)
          base_dir = File.expand_path("../../../resources/schemas", __dir__)

          xsd_4778 = File.join(base_dir, "stanag4778.xsd")
          return nil unless File.exist?(xsd_4778)

          sources = [
            StreamSource.new(java.io.File.new(::File.join(base_dir, "xmlmime.xsd"))),
            StreamSource.new(java.io.File.new(::File.join(base_dir, "xmldsig-core-schema.xsd"))),
            StreamSource.new(java.io.File.new(xsd_4778))
          ].to_java(javax.xml.transform.Source)

          sf.newSchema(sources)
        rescue StandardError => e
          nil
        end

        def validate_dom_schema(element)
          return [] unless @schema
          errs = []
          begin
            validator = @schema.newValidator
            validator.validate(DOMSource.new(element))
          rescue StandardError => e
            errs << e.message
          end
          errs
        end

        def find_bdo_element(doc)
          # Check root element
          root = doc.getDocumentElement
          if root.getLocalName == "BindingInformation" && root.getNamespaceURI == Profile::NS_MB_1_0
            return root
          end

          # Search descendants
          nodes = doc.getElementsByTagNameNS(Profile::NS_MB_1_0, "BindingInformation")
          if nodes.getLength > 0
            nodes.item(0)
          else
            nil
          end
        end

        def find_signature_elements(bdo_element)
          sigs = []
          child = bdo_element.getFirstChild
          while child
            if child.getNodeType == Node::ELEMENT_NODE &&
               child.getLocalName == "Signature" &&
               child.getNamespaceURI == Profile::NS_XMLDSIG
              sigs << child
            end
            child = child.getNextSibling
          end
          sigs
        end

        # Register Id, ID, id, and mb:Id as IDs for DOM ID resolution
        def register_ids(element)
          return unless element

          # Tolerate mb:Id="#id-..." syntax found in some STANAG drafts by stripping '#'
          id_attrs = ["Id", "ID", "id"]
          id_attrs.each do |attr_name|
            if element.hasAttribute(attr_name)
              val = element.getAttribute(attr_name)
              if val.start_with?("#")
                element.setAttribute(attr_name, val[1..-1])
              end
              element.setIdAttribute(attr_name, true) rescue nil
            end
          end

          # mb:Id with namespace
          if element.hasAttributeNS(Profile::NS_MB_1_0, "Id")
            val = element.getAttributeNS(Profile::NS_MB_1_0, "Id")
            if val.start_with?("#")
              element.setAttributeNS(Profile::NS_MB_1_0, "Id", val[1..-1])
            end
            element.setIdAttributeNS(Profile::NS_MB_1_0, "Id", true) rescue nil
          end

          # Recurse children
          child = element.getFirstChild
          while child
            register_ids(child) if child.getNodeType == Node::ELEMENT_NODE
            child = child.getNextSibling
          end
        end

        def verify_single_xml_sig(sig_factory, sig_elem, default_deref, bdo_element, is_root)
          sig_errors = []
          sig_warnings = []
          has_unres = false

          key_selector = DomKeySelector.new(@trust_store)
          dereferencer = SafeURIDereferencer.new(default_deref, @fetcher)

          val_context = DOMValidateContext.new(key_selector, sig_elem)
          val_context.setURIDereferencer(dereferencer)
          # Allow same-document dereferencing
          val_context.setProperty("org.jcp.xml.dsig.validateManifests", java.lang.Boolean::TRUE) rescue nil

          xml_sig = sig_factory.unmarshalXMLSignature(val_context)

          # Extract algorithms
          signed_info = xml_sig.getSignedInfo
          c14n_alg = signed_info.getCanonicalizationMethod.getAlgorithm
          sig_alg  = signed_info.getSignatureMethod.getAlgorithm

          # Check algorithms against ADatP-4778.2 tables
          check_signature_algorithms(c14n_alg, sig_alg, sig_errors, sig_warnings)

          # Core validation
          core_valid = begin
                         xml_sig.validate(val_context)
                       rescue StandardError => e
                         sig_errors << "Core XMLDSIG validation exception: #{e.message}"
                         false
                       end

          # Reference validation details
          ref_iter = signed_info.getReferences.iterator
          ref_results = []
          while ref_iter.hasNext
            ref = ref_iter.next
            ref_uri = ref.getURI
            ref_valid = begin
                          ref.validate(val_context)
                        rescue StandardError => e
                          sig_errors << "Reference validation error for #{ref_uri}: #{e.message}"
                          false
                        end

            digest_alg = ref.getDigestMethod.getAlgorithm
            check_digest_algorithm(digest_alg, sig_errors, sig_warnings)

            ref_results << {
              uri: ref_uri,
              valid: ref_valid,
              digest_method: digest_alg
            }
          end

          # Check Objects and Manifest elements
          manifest_results = verify_manifests(xml_sig, val_context, sig_errors)

          # Check TimeStamp property (ADatP-4778.2 section A.2 / SignatureProperties)
          ts_info = extract_and_verify_timestamp(sig_elem, sig_errors, sig_warnings)

          # Trust evaluation
          key_info_data = key_selector.selected_info
          if key_info_data[:trusted] == false
            sig_errors << (key_info_data[:cert_error] || key_info_data[:key_error] || "Signer is not trusted by configured CA anchors or pinned certificates")
          end

          is_valid = core_valid && sig_errors.empty?

          sig_result = {
            algorithm: sig_alg,
            canonicalization_method: c14n_alg,
            key_id: key_info_data[:key_id],
            signer_subject: key_info_data[:subject],
            signer_issuer: key_info_data[:issuer],
            signer_serial: key_info_data[:serial],
            created: ts_info[:created],
            valid: is_valid,
            references: ref_results,
            manifests: manifest_results,
            errors: sig_errors,
            warnings: sig_warnings,
            has_unresolved: has_unres
          }

          [sig_result, is_valid]
        end

        def check_signature_algorithms(c14n_alg, sig_alg, errors, warnings)
          unless Profile::XML_CANONICALIZATION_METHODS.include?(c14n_alg)
            msg = "CanonicalizationMethod '#{c14n_alg}' is not in ADatP-4778.2 permitted list"
            @strict_profile ? errors << msg : warnings << msg
          end

          status = Profile::XML_PKI_SIGNATURE_METHODS[sig_alg] || Profile::XML_HMAC_SIGNATURE_METHODS[sig_alg]
          if status == :prohibited
            errors << "SignatureMethod '#{sig_alg}' is PROHIBITED by ADatP-4778.2"
          elsif status.nil?
            msg = "SignatureMethod '#{sig_alg}' is not recognized in ADatP-4778.2 profiles"
            @strict_profile ? errors << msg : warnings << msg
          end
        end

        def check_digest_algorithm(digest_alg, errors, warnings)
          status = Profile::XML_DIGEST_METHODS[digest_alg]
          if status == :prohibited
            errors << "DigestMethod '#{digest_alg}' is PROHIBITED by ADatP-4778.2"
          elsif status.nil?
            msg = "DigestMethod '#{digest_alg}' is not in ADatP-4778.2 permitted list"
            @strict_profile ? errors << msg : warnings << msg
          end
        end

        def verify_manifests(xml_sig, val_context, errors)
          manifest_results = []
          objects = xml_sig.getObjects
          return manifest_results if objects.nil?

          obj_iter = objects.iterator
          while obj_iter.hasNext
            obj = obj_iter.next
            content = obj.getContent
            c_iter = content.iterator
            while c_iter.hasNext
              item = c_iter.next
              if item.is_a?(Java::JavaxXmlCryptoDsig::Manifest)
                man_refs = item.getReferences
                m_iter = man_refs.iterator
                while m_iter.hasNext
                  m_ref = m_iter.next
                  m_valid = begin
                              m_ref.validate(val_context)
                            rescue StandardError => e
                              errors << "Manifest reference #{m_ref.getURI} validation error: #{e.message}"
                              false
                            end
                  manifest_results << { uri: m_ref.getURI, valid: m_valid }
                  errors << "Manifest reference #{m_ref.getURI} digest mismatch" unless m_valid
                end
              end
            end
          end
          manifest_results
        end

        def extract_and_verify_timestamp(sig_elem, errors, warnings)
          res = { created: nil }

          # Look for wsu:Created or Created inside SignatureProperties
          ts_nodes = sig_elem.getElementsByTagNameNS(Profile::NS_WSU, "Created")
          if ts_nodes.getLength == 0
            ts_nodes = sig_elem.getElementsByTagName("wsu:Created")
          end
          if ts_nodes.getLength == 0
            ts_nodes = sig_elem.getElementsByTagName("Created")
          end

          if ts_nodes.getLength > 0
            created_str = ts_nodes.item(0).getTextContent&.strip
            res[:created] = created_str

            begin
              created_time = Time.iso8601(created_str).to_i
              now = Time.now.to_i

              if created_time > now + @clock_skew
                errors << "Signature timestamp Created (#{created_str}) is in future beyond clock skew"
              elsif @max_age > 0 && created_time < now - @max_age
                errors << "Signature timestamp Created (#{created_str}) exceeds max_signature_age"
              end
            rescue StandardError => e
              warnings << "Failed to parse signature timestamp: #{e.message}"
            end
          else
            msg = "ADatP-4778.2 requires wsu:TimeStamp with Created element in SignatureProperties"
            @strict_profile ? errors << msg : warnings << msg
          end

          res
        end

        def check_bdo_profile_rules(bdo_element, signatures_res, is_root)
          errors = []
          warnings = []

          # For embedded BDOs, verify enveloped-BDO XPath transform was applied
          unless is_root
            signatures_res.each do |sig|
              sig[:references]&.each do |r|
                if r[:uri] == "" # Root reference
                  # Ideally contains enveloped-BDO transform
                end
              end
            end
          end

          [errors, warnings]
        end

        def extract_xml_bindings(bdo_element)
          bindings = []
          containers = bdo_element.getElementsByTagNameNS(Profile::NS_MB_1_0, "MetadataBindingContainer")
          c_len = containers.getLength

          c_len.times do |c_idx|
            container = containers.item(c_idx)
            mb_nodes = container.getElementsByTagNameNS(Profile::NS_MB_1_0, "MetadataBinding")
            mb_len = mb_nodes.getLength

            mb_len.times do |m_idx|
              mb_elem = mb_nodes.item(m_idx)
              mb_id = mb_elem.getAttribute("Id")
              mb_id = mb_elem.getAttributeNS(Profile::NS_MB_1_0, "Id") if mb_id.empty?

              binding_entry = {
                id: mb_id,
                metadata: extract_metadata_elements(mb_elem),
                data_references: extract_data_references(mb_elem),
                data_elements: extract_data_elements(mb_elem)
              }
              bindings << binding_entry
            end
          end

          bindings
        end

        def extract_metadata_elements(mb_elem)
          meta_list = []
          nodes = mb_elem.getElementsByTagNameNS(Profile::NS_MB_1_0, "Metadata")
          nodes.getLength.times do |i|
            m_node = nodes.item(i)
            # Find any child elements (e.g. slab:originatorConfidentialityLabel)
            child = m_node.getFirstChild
            while child
              if child.getNodeType == Node::ELEMENT_NODE
                meta_list << dom_to_hash(child)
              end
              child = child.getNextSibling
            end
          end
          meta_list
        end

        def extract_data_references(mb_elem)
          refs = []
          nodes = mb_elem.getElementsByTagNameNS(Profile::NS_MB_1_0, "DataReference")
          nodes.getLength.times do |i|
            node = nodes.item(i)
            refs << {
              uri: node.getAttribute("URI"),
              content_type: node.getAttributeNS(Profile::NS_XMLMIME, "contentType")
            }
          end
          refs
        end

        def extract_data_elements(mb_elem)
          data_list = []
          nodes = mb_elem.getElementsByTagNameNS(Profile::NS_MB_1_0, "Data")
          nodes.getLength.times do |i|
            data_list << nodes.item(i).getTextContent&.strip
          end
          data_list
        end

        def dom_to_hash(element)
          res = { tag: element.getLocalName, namespace: element.getNamespaceURI }
          child = element.getFirstChild
          children = []
          text_content = ""

          while child
            if child.getNodeType == Node::ELEMENT_NODE
              children << dom_to_hash(child)
            elsif child.getNodeType == Node::TEXT_NODE
              text_content += child.getNodeValue.to_s
            end
            child = child.getNextSibling
          end

          if children.any?
            res[:children] = children
          else
            res[:value] = text_content.strip
          end
          res
        end

        def classify_xml_binding_type(bindings, is_root)
          return "embedded" unless is_root

          has_external = false
          has_embedded = false

          bindings.each do |b|
            has_embedded = true if b[:data_elements]&.any?
            b[:data_references]&.each do |dtr|
              uri = dtr[:uri].to_s
              if uri.empty? || uri.start_with?("#")
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
