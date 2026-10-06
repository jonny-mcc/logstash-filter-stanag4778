# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "insist"
require "json"
require "base64"
require "logstash/filters/stanag4778"
require_relative "../support/signing_helper"

describe LogStash::Filters::Stanag4778 do
  let(:rsa_keypair) { SigningHelper.generate_rsa_keypair }
  let(:cert_and_keys) { SigningHelper.generate_keytool_cert(rsa_keypair, "CN=Test Originator, O=NATO, C=BE") }
  let(:test_cert) { cert_and_keys[0] }
  let(:test_keypair) { cert_and_keys[1] }

  describe "Unsigned payloads" do
    let(:raw_xml) { File.read(File.expand_path("../fixtures/unsigned_encapsulating.xml", __dir__)) }
    let(:raw_json) { File.read(File.expand_path("../fixtures/stanag4778_7_fig16.json", __dir__)) }

    context "when require_signature is true (default)" do
      config <<-CONFIG
        filter {
          stanag4778 {
            source => "message"
            target => "stanag"
            require_signature => true
          }
        }
      CONFIG

      sample({"message" => File.read(File.expand_path("../fixtures/unsigned_encapsulating.xml", __dir__))}) do
        insist { subject.get("tags") }.include?("_stanag4778_unsigned")
        insist { subject.get("tags") }.include?("_stanag4778_invalid")
        insist { subject.get("stanag")["valid"] } == false
        insist { subject.get("stanag")["signed"] } == false
      end

      sample({"message" => File.read(File.expand_path("../fixtures/stanag4778_7_fig16.json", __dir__))}) do
        insist { subject.get("tags") }.include?("_stanag4778_unsigned")
        insist { subject.get("stanag")["valid"] } == false
      end
    end

    context "when require_signature is false" do
      config <<-CONFIG
        filter {
          stanag4778 {
            source => "message"
            target => "stanag"
            require_signature => false
            strict_profile => false
          }
        }
      CONFIG

      sample({"message" => File.read(File.expand_path("../fixtures/unsigned_encapsulating.xml", __dir__))}) do
        insist { subject.get("tags") }.nil?
        insist { subject.get("stanag")["valid"] } == true
        insist { subject.get("stanag")["signed"] } == false
        insist { subject.get("stanag")["labels"][0]["classification"] } == "CONFIDENTIAL"
      end

      sample({"message" => File.read(File.expand_path("../fixtures/stanag4778_7_fig16.json", __dir__))}) do
        insist { subject.get("tags") }.nil?
        insist { subject.get("stanag")["valid"] } == true
        insist { subject.get("stanag")["binding_type"] } == "embedded"
        insist { subject.get("stanag")["labels"][0]["classification"] } == "INTERNAL"
      end
    end
  end

  describe "JWS verification" do
    let(:hmac_secret) { "super-secret-hmac-key-for-nato-testing" }
    let(:temp_cert_file) do
      f = Tempfile.new(["trusted_cert", ".pem"])
      b64 = Base64.encode64(String.from_java_bytes(test_cert.getEncoded))
      f.write("-----BEGIN CERTIFICATE-----\n#{b64}-----END CERTIFICATE-----\n")
      f.close
      f.path
    end

    context "with valid HMAC signature (HS256)" do
      let(:doc_body) { { "messageId" => "MSG-100" } }

      let(:payload) do
        canonical = LogStash::Filters::Stanag4778Module::JCS.canonicalize(doc_body)
        md = java.security.MessageDigest.getInstance("SHA-256")
        hash_b64 = Base64.urlsafe_encode64(String.from_java_bytes(md.digest(canonical.encode("UTF-8").to_java_bytes))).tr("=", "")

        {
          "mbs" => [
            {
              "mds" => {
                "@context" => { "@base" => "urn:nato:stanag:5636:A:1:elements:json" },
                "ocl" => { "pol" => "NATO", "cls" => "SECRET" }
              },
              "dtrs" => [
                { "cty" => "json", "uri" => "", "hash" => hash_b64, "alg" => "sha-256" }
              ]
            }
          ]
        }
      end

      let(:signed_bdo) do
        SigningHelper.sign_jws_bdo(
          payload,
          hmac_key_name: "test-hmac-1",
          hmac_secret: hmac_secret,
          alg: "HS256"
        )
      end

      let(:pipeline_config) do
        <<-CONFIG
          filter {
            stanag4778 {
              source => "message"
              target => "stanag"
              hmac_keys => { "test-hmac-1" => "#{hmac_secret}" }
            }
          }
        CONFIG
      end

      it "validates the signature and extracts labels" do
        filt = LogStash::Filters::Stanag4778.new(
          "source" => "message",
          "target" => "stanag",
          "hmac_keys" => { "test-hmac-1" => hmac_secret }
        )
        filt.register

        full_doc = doc_body.dup
        full_doc["bdo"] = signed_bdo

        event = LogStash::Event.new("message" => JSON.generate(full_doc))
        filt.filter(event)

        expect(event.get("tags")).to be_nil
        expect(event.get("stanag")["valid"]).to be true
        expect(event.get("stanag")["signed"]).to be true
        expect(event.get("stanag")["labels"].first["classification"]).to eq("SECRET")
      end

      it "fails on tampered signature" do
        filt = LogStash::Filters::Stanag4778.new(
          "source" => "message",
          "target" => "stanag",
          "hmac_keys" => { "test-hmac-1" => hmac_secret }
        )
        filt.register

        full_doc = doc_body.dup
        full_doc["bdo"] = signed_bdo

        # Tamper payload
        tampered = Marshal.load(Marshal.dump(full_doc))
        parts = tampered["bdo"]["bdis"][0]["bdi"].split(".")
        parts[2] = parts[2][0..-4] + "xyz"
        tampered["bdo"]["bdis"][0]["bdi"] = parts.join(".")

        event = LogStash::Event.new("message" => JSON.generate(tampered))
        filt.filter(event)

        expect(event.get("tags")).to include("_stanag4778_invalid")
        expect(event.get("stanag")["valid"]).to be false
      end
    end

    context "with valid RSA signature and pinned certificate" do
      let(:rsa_doc_body) { { "reportId" => "REP-200" } }

      let(:payload) do
        canonical = LogStash::Filters::Stanag4778Module::JCS.canonicalize(rsa_doc_body)
        md = java.security.MessageDigest.getInstance("SHA-256")
        hash_b64 = Base64.urlsafe_encode64(String.from_java_bytes(md.digest(canonical.encode("UTF-8").to_java_bytes))).tr("=", "")

        {
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
      end

      let(:signed_bdo) do
        SigningHelper.sign_jws_bdo(
          payload,
          keypair: test_keypair,
          cert: test_cert,
          alg: "RS256"
        )
      end

      it "verifies against pinned cert" do
        filt = LogStash::Filters::Stanag4778.new(
          "source" => "message",
          "target" => "stanag",
          "trusted_certificates" => [temp_cert_file]
        )
        filt.register

        full_doc = rsa_doc_body.dup
        full_doc["bdo"] = signed_bdo

        event = LogStash::Event.new("message" => JSON.generate(full_doc))
        filt.filter(event)

        expect(event.get("tags")).to be_nil
        expect(event.get("stanag")["valid"]).to be true
        expect(event.get("stanag")["labels"].first["classification"]).to eq("TOP SECRET")
      end

      it "fails when cert is untrusted" do
        filt = LogStash::Filters::Stanag4778.new(
          "source" => "message",
          "target" => "stanag",
          "trusted_certificates" => [] # No trusted certs
        )
        filt.register

        full_doc = rsa_doc_body.dup
        full_doc["bdo"] = signed_bdo

        event = LogStash::Event.new("message" => JSON.generate(full_doc))
        filt.filter(event)

        expect(event.get("tags")).to include("_stanag4778_invalid")
        expect(event.get("stanag")["valid"]).to be false
      end
    end
  end

  describe "XMLDSIG verification" do
    let(:base_xml) { File.read(File.expand_path("../fixtures/unsigned_encapsulating.xml", __dir__)) }
    let(:temp_cert_file) do
      f = Tempfile.new(["trusted_cert_xml", ".pem"])
      b64 = Base64.encode64(String.from_java_bytes(test_cert.getEncoded))
      f.write("-----BEGIN CERTIFICATE-----\n#{b64}-----END CERTIFICATE-----\n")
      f.close
      f.path
    end

    context "with valid RSA signature and pinned certificate" do
      it "validates signature and references" do
        signed_xml = SigningHelper.sign_xml(base_xml, test_keypair, cert: test_cert, alg: "rsa-sha256")

        filt = LogStash::Filters::Stanag4778.new(
          "source" => "message",
          "target" => "stanag",
          "trusted_certificates" => [temp_cert_file]
        )
        filt.register

        event = LogStash::Event.new("message" => signed_xml)
        filt.filter(event)

        expect(event.get("tags")).to be_nil
        expect(event.get("stanag")["valid"]).to be true
        expect(event.get("stanag")["signed"]).to be true
        expect(event.get("stanag")["labels"].first["classification"]).to eq("CONFIDENTIAL")
      end

      it "rejects prohibited rsa-sha1 signature method under strict profile" do
        signed_xml = SigningHelper.sign_xml(base_xml, test_keypair, cert: test_cert, alg: "rsa-sha1")

        filt = LogStash::Filters::Stanag4778.new(
          "source" => "message",
          "target" => "stanag",
          "trusted_certificates" => [temp_cert_file],
          "strict_profile" => true
        )
        filt.register

        event = LogStash::Event.new("message" => signed_xml)
        filt.filter(event)

        expect(event.get("tags")).to include("_stanag4778_invalid")
        expect(event.get("stanag")["valid"]).to be false
        expect(event.get("stanag")["errors"].join).to match(/PROHIBITED/)
      end

      it "detects XML tampering" do
        signed_xml = SigningHelper.sign_xml(base_xml, test_keypair, cert: test_cert, alg: "rsa-sha256")
        tampered_xml = signed_xml.sub("CONFIDENTIAL", "TOP_SECRET")

        filt = LogStash::Filters::Stanag4778.new(
          "source" => "message",
          "target" => "stanag",
          "trusted_certificates" => [temp_cert_file]
        )
        filt.register

        event = LogStash::Event.new("message" => tampered_xml)
        filt.filter(event)

        expect(event.get("tags")).to include("_stanag4778_invalid")
        expect(event.get("stanag")["valid"]).to be false
      end
    end

    context "security hardening" do
      it "rejects XXE attacks without resolving entities" do
        xxe_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
                  "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>\n" \
                  "<mb:BindingInformation xmlns:mb=\"urn:nato:stanag:4778:bindinginformation:1:0\">\n" \
                  "  <mb:MetadataBindingContainer>\n" \
                  "    <mb:MetadataBinding Id=\"mb-1\">\n" \
                  "      <mb:Metadata>&xxe;</mb:Metadata>\n" \
                  "      <mb:DataReference URI=\"\" />\n" \
                  "    </mb:MetadataBinding>\n" \
                  "  </mb:MetadataBindingContainer>\n" \
                  "</mb:BindingInformation>"

        filt = LogStash::Filters::Stanag4778.new(
          "source" => "message",
          "target" => "stanag"
        )
        filt.register

        event = LogStash::Event.new("message" => xxe_xml)
        filt.filter(event)

        expect(event.get("tags")).to include("_stanag4778_parse_failure")
        expect(event.get("stanag")["valid"]).to be false
        expect(event.get("stanag")["parse_error"]).to be true
      end
    end
  end
end
