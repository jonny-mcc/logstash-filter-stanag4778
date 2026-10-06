# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "json"
require "base64"
require "tempfile"
require "logstash/filters/stanag4778"
require "logstash/filters/stanag4778/jcs"
require_relative "../support/signing_helper"

describe "LogStash::Filters::Stanag4778 Security Vulnerability Regression Tests" do
  let(:rsa_keypair) { SigningHelper.generate_rsa_keypair }
  let(:cert_and_keys) { SigningHelper.generate_keytool_cert(rsa_keypair, "CN=Legit NATO Originator, O=NATO, C=BE") }
  let(:legit_cert) { cert_and_keys[0] }
  let(:legit_keypair) { cert_and_keys[1] }

  let(:attacker_rsa_keypair) { SigningHelper.generate_rsa_keypair }
  let(:attacker_cert_and_keys) { SigningHelper.generate_keytool_cert(attacker_rsa_keypair, "CN=Attacker, O=EvilCorp, C=XX") }
  let(:attacker_cert) { attacker_cert_and_keys[0] }
  let(:attacker_keypair) { attacker_cert_and_keys[1] }

  let!(:temp_cert_file) do
    path = File.join(Dir.tmpdir, "trusted_cert_sec_#{$$}_#{rand(10000)}.pem")
    b64 = Base64.encode64(String.from_java_bytes(legit_cert.getEncoded))
    File.write(path, "-----BEGIN CERTIFICATE-----\n#{b64}-----END CERTIFICATE-----\n")
    path
  end

  let(:base_payload) do
    {
      "mbs" => [
        {
          "mds" => {
            "@context" => { "@base" => "urn:nato:stanag:5636:A:1:elements:json" },
            "ocl" => { "pol" => "NATO", "cls" => "TOP SECRET" }
          },
          "dtrs" => [
            { "cty" => "json", "uri" => "", "hash" => "abc", "alg" => "sha-256" }
          ]
        }
      ]
    }
  end

  describe "Finding 1: JWS Embedded Keys (Critical)" do
    it "rejects JWS signed with attacker key when attacker embeds public JWK in header without trusted JWKS" do
      attacker_jwk = SigningHelper.public_key_to_jwk(attacker_keypair.getPublic, kid: "attacker-1")
      header = {
        "alg" => "RS256",
        "cty" => "vnd.nato.bindingdataobject+json",
        "iat" => Time.now.to_i,
        "jwk" => attacker_jwk
      }

      signed_bdo = SigningHelper.sign_jws_raw(header, base_payload, keypair: attacker_keypair)

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "trusted_certificates" => [temp_cert_file] # only legit_cert is trusted!
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(signed_bdo))
      filt.filter(event)

      # Under vulnerable code: this PASSED because jws_verifier parses header['jwk'] without matching trusted_certs/JWKS!
      expect(event.get("tags")).to include("_stanag4778_invalid")
      expect(event.get("stanag")["valid"]).to be false
      expect(event.get("stanag")["errors"].join).to match(/trusted/i)
    end

    it "rejects HS256 JWS when attacker embeds oct JWK secret in header" do
      attacker_secret = "attacker-controlled-secret-12345"
      header = {
        "alg" => "HS256",
        "cty" => "vnd.nato.bindingdataobject+json",
        "iat" => Time.now.to_i,
        "jwk" => {
          "kty" => "oct",
          "k" => Base64.urlsafe_encode64(attacker_secret).tr("=", "")
        }
      }

      signed_bdo = SigningHelper.sign_jws_raw(header, base_payload, hmac_secret: attacker_secret)

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "hmac_keys" => { "legit-key" => "real-secret-not-matching-attacker" }
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(signed_bdo))
      filt.filter(event)

      # Under vulnerable code: this PASSED because jws_verifier fell back to header['jwk']['kty'] == 'oct'!
      expect(event.get("tags")).to include("_stanag4778_invalid")
      expect(event.get("stanag")["valid"]).to be false
      expect(event.get("stanag")["errors"].join).to match(/HMAC secret/i)
    end
  end

  describe "Finding 2: XMLDSIG KeyValue acceptance without trust (Critical)" do
    let(:base_xml) { File.read(File.expand_path("../fixtures/unsigned_encapsulating.xml", __dir__)) }

    it "rejects XMLDSIG containing KeyValue that is not in the trusted store" do
      # Sign with attacker keypair using KeyValue in KeyInfo (no certificate)
      signed_xml = SigningHelper.sign_xml(base_xml, attacker_keypair, alg: "rsa-sha256")

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "trusted_certificates" => [temp_cert_file] # only legit_cert is trusted!
      )
      filt.register

      event = LogStash::Event.new("message" => signed_xml)
      filt.filter(event)

      # Under vulnerable code: this PASSED because KeyValue was returned without checking trust_store!
      expect(event.get("tags")).to include("_stanag4778_invalid")
      expect(event.get("stanag")["valid"]).to be false
      expect(event.get("stanag")["errors"].join).to match(/trusted/i)
    end
  end

  describe "Finding 3: Schema validation is enforced and fails on invalid structure (High)" do
    it "actually runs schema validation and rejects XML missing mandatory choices in MetadataBinding" do
      # Schema defines that MetadataBinding requires at least one Metadata/MetadataReference
      # AND at least one Data/DataReference. If both Data and DataReference are omitted, schema must fail.
      invalid_xml = <<-XML
        <mb:BindingInformation xmlns:mb="urn:nato:stanag:4778:bindinginformation:1:0">
          <mb:MetadataBindingContainer>
            <mb:MetadataBinding Id="mb-1">
              <mb:Metadata>
                <someMeta xmlns="http://example.org">val</someMeta>
              </mb:Metadata>
            </mb:MetadataBinding>
          </mb:MetadataBindingContainer>
        </mb:BindingInformation>
      XML

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "validate_schema" => true,
        "require_signature" => false
      )
      filt.register

      event = LogStash::Event.new("message" => invalid_xml)
      filt.filter(event)

      # Under vulnerable code: schema was NOT loaded because base_dir path was wrong (resolved to nil),
      # so invalid XML passed with valid: true!
      expect(event.get("stanag")["valid"]).to be false
      expect(event.get("stanag")["errors"].join).to match(/schema validation failed/i)
    end
  end

  describe "Finding 4: Strict profile enforcement (High)" do
    it "rejects JWS with unknown header in crit array" do
      header = {
        "alg" => "RS256",
        "cty" => "vnd.nato.bindingdataobject+json",
        "iat" => Time.now.to_i,
        "x5c" => [Base64.strict_encode64(String.from_java_bytes(legit_cert.getEncoded))],
        "crit" => ["unknown_extension_param"],
        "unknown_extension_param" => "value"
      }

      signed_bdo = SigningHelper.sign_jws_raw(header, base_payload, keypair: legit_keypair)

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "trusted_certificates" => [temp_cert_file]
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(signed_bdo))
      filt.filter(event)

      expect(event.get("tags")).to include("_stanag4778_invalid")
      expect(event.get("stanag")["valid"]).to be false
      expect(event.get("stanag")["errors"].join).to match(/critical/i)
    end

    it "rejects JWS with empty crit array" do
      header = {
        "alg" => "RS256",
        "cty" => "vnd.nato.bindingdataobject+json",
        "iat" => Time.now.to_i,
        "x5c" => [Base64.strict_encode64(String.from_java_bytes(legit_cert.getEncoded))],
        "crit" => []
      }

      signed_bdo = SigningHelper.sign_jws_raw(header, base_payload, keypair: legit_keypair)

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "trusted_certificates" => [temp_cert_file]
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(signed_bdo))
      filt.filter(event)

      expect(event.get("tags")).to include("_stanag4778_invalid")
      expect(event.get("stanag")["valid"]).to be false
    end

    it "rejects JWS with missing alg header parameter" do
      header = {
        "cty" => "vnd.nato.bindingdataobject+json",
        "iat" => Time.now.to_i
      }

      signed_bdo = SigningHelper.sign_jws_raw(header, base_payload, keypair: nil)

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "require_signature" => false
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(signed_bdo))
      filt.filter(event)

      expect(event.get("stanag")["valid"]).to be false
      expect(event.get("stanag")["errors"].join).to match(/missing mandatory 'alg'/i)
    end
  end

  describe "Finding 5 & 6: Unresolved XML references & SSRF Fetcher hardening" do
    let(:base_xml) { File.read(File.expand_path("../fixtures/unsigned_encapsulating.xml", __dir__)) }

    it "tags blocked external XML references as _stanag4778_unresolved_reference" do
      # Add external DataReference to base_xml
      xml_with_ext = base_xml.sub(
        "</mb:MetadataBinding>",
        "<mb:DataReference URI=\"https://external.nato.int/file.dat\" xmime:contentType=\"application/octet-stream\"/></mb:MetadataBinding>"
      )

      # Sign with valid cert
      signed_xml = SigningHelper.sign_xml(xml_with_ext, legit_keypair, cert: legit_cert, alg: "rsa-sha256")

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "trusted_certificates" => [temp_cert_file],
        "fetch_external_references" => false # Disabled -> blocks dereference
      )
      filt.register

      event = LogStash::Event.new("message" => signed_xml)
      filt.filter(event)

      expect(event.get("tags")).to include("_stanag4778_unresolved_reference")
      expect(event.get("stanag")["has_unresolved_references"]).to be true
      ref_entry = event.get("stanag")["signatures"].first["references"].find { |r| r["uri"].include?("external.nato.int") }
      expect(ref_entry["status"]).to eq("unresolved")
    end

    it "rejects private IP resolution in Fetcher (SSRF protection)" do
      fetcher = LogStash::Filters::Stanag4778Module::Fetcher.new(
        enabled: true,
        allowlist: ["localhost", "127.0.0.1", "*.internal.net"],
        allow_private: false
      )

      ok, err = fetcher.fetch("https://127.0.0.1/test")
      expect(ok).to be false
      expect(err).to match(/loopback|private/i)
    end
  end

  describe "Finding 7: Certificate policy checks and revocation output" do
    let(:doc_body) { { "orderId" => "ORD-999" } }

    it "records revocation_checked status on verified events" do
      canonical = LogStash::Filters::Stanag4778Module::JCS.canonicalize(doc_body)
      md = java.security.MessageDigest.getInstance("SHA-256")
      hash_b64 = Base64.urlsafe_encode64(String.from_java_bytes(md.digest(canonical.encode("UTF-8").to_java_bytes))).tr("=", "")

      payload = {
        "mbs" => [
          {
            "mds" => {
              "@context" => { "@base" => "urn:nato:stanag:5636:A:1:elements:json" },
              "ocl" => { "pol" => "NATO", "cls" => "TOP SECRET" }
            },
            "dtrs" => [
              { "cty" => "json", "uri" => "", "hash" => hash_b64, "alg" => "sha-256" }
            ]
          }
        ]
      }

      header = {
        "alg" => "RS256",
        "cty" => "vnd.nato.bindingdataobject+json",
        "iat" => Time.now.to_i,
        "x5c" => [Base64.strict_encode64(String.from_java_bytes(legit_cert.getEncoded))]
      }

      signed_bdo = SigningHelper.sign_jws_raw(header, payload, keypair: legit_keypair)

      full_doc = doc_body.dup
      full_doc["bdo"] = signed_bdo

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "trusted_certificates" => [temp_cert_file],
        "revocation_mode" => "none"
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(full_doc))
      filt.filter(event)

      expect(event.get("stanag")["valid"]).to be true
      expect(event.get("stanag")["signatures"].first["revocation_checked"]).to be false
    end

    it "rejects signer certificates not matching allowed_signer_subjects" do
      canonical = LogStash::Filters::Stanag4778Module::JCS.canonicalize(doc_body)
      md = java.security.MessageDigest.getInstance("SHA-256")
      hash_b64 = Base64.urlsafe_encode64(String.from_java_bytes(md.digest(canonical.encode("UTF-8").to_java_bytes))).tr("=", "")

      payload = {
        "mbs" => [
          {
            "mds" => {
              "@context" => { "@base" => "urn:nato:stanag:5636:A:1:elements:json" },
              "ocl" => { "pol" => "NATO", "cls" => "TOP SECRET" }
            },
            "dtrs" => [
              { "cty" => "json", "uri" => "", "hash" => hash_b64, "alg" => "sha-256" }
            ]
          }
        ]
      }

      header = {
        "alg" => "RS256",
        "cty" => "vnd.nato.bindingdataobject+json",
        "iat" => Time.now.to_i,
        "x5c" => [Base64.strict_encode64(String.from_java_bytes(legit_cert.getEncoded))]
      }

      signed_bdo = SigningHelper.sign_jws_raw(header, payload, keypair: legit_keypair)

      full_doc = doc_body.dup
      full_doc["bdo"] = signed_bdo

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "trusted_certificates" => [temp_cert_file],
        "allowed_signer_subjects" => ["CN=ExpectedDifferentSigner"]
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(full_doc))
      filt.filter(event)

      expect(event.get("tags")).to include("_stanag4778_invalid")
      expect(event.get("stanag")["valid"]).to be false
      expect(event.get("stanag")["errors"].join).to match(/allowed_signer_subjects/i)
    end
  end

  describe "Finding 8: RFC 8785 JCS Number Serialization" do
    let(:jcs) { LogStash::Filters::Stanag4778Module::JCS }

    it "serializes numbers matching ECMAScript standard" do
      expect(jcs.canonicalize(0)).to eq("0")
      expect(jcs.canonicalize(0.0)).to eq("0")
      expect(jcs.canonicalize(-0.0)).to eq("0")
      expect(jcs.canonicalize(1)).to eq("1")
      expect(jcs.canonicalize(123456789)).to eq("123456789")
      expect(jcs.canonicalize(1.2345)).to eq("1.2345")
      expect(jcs.canonicalize(1e21)).to eq("1e+21")
      expect(jcs.canonicalize(1e-7)).to eq("1e-7")
    end
  end
end
