# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "json"
require "base64"
require "logstash/filters/stanag4778"
require_relative "../support/signing_helper"

describe "LogStash::Filters::Stanag4778 Extended Coverage" do
  let(:rsa_keypair) { SigningHelper.generate_rsa_keypair }
  let(:cert_and_keys) { SigningHelper.generate_keytool_cert(rsa_keypair, "CN=Test NATO Originator, O=NATO, C=BE") }
  let(:test_cert) { cert_and_keys[0] }
  let(:test_keypair) { cert_and_keys[1] }
  let(:hmac_secret) { "top-secret-signing-key-32-bytes!!" }

  let(:temp_cert_file) do
    f = Tempfile.new(["trusted_cert_ext", ".pem"])
    b64 = Base64.encode64(String.from_java_bytes(test_cert.getEncoded))
    f.write("-----BEGIN CERTIFICATE-----\n#{b64}-----END CERTIFICATE-----\n")
    f.close
    f.path
  end

  describe "JSON Pointer, JSONPath, and JMESPath dereferencing" do
    let(:root_json_object) do
      {
        "ID" => "doc-1234",
        "title" => "Mission Order",
        "details" => {
          "code" => "OPERATION_ALPHA",
          "priority" => 1
        },
        "recipients" => ["Alpha", "Bravo"]
      }
    end

    it "validates JSON Pointer reference (#/details) with JCS hash" do
      target_slice = root_json_object["details"]
      canonical = LogStash::Filters::Stanag4778Module::JCS.canonicalize(target_slice)
      md = java.security.MessageDigest.getInstance("SHA-256")
      hash_b64 = Base64.urlsafe_encode64(String.from_java_bytes(md.digest(canonical.encode("UTF-8").to_java_bytes))).tr("=", "")

      payload = {
        "mbs" => [
          {
            "mds" => {
              "@context" => { "@base" => "urn:nato:stanag:5636:A:1:elements:json" },
              "ocl" => { "pol" => "NATO", "cls" => "RESTRICTED" }
            },
            "dtrs" => [
              {
                "cty" => "json",
                "uri" => "#/details",
                "hash" => hash_b64,
                "alg" => "sha-256"
              }
            ]
          }
        ]
      }

      signed_bdo = SigningHelper.sign_jws_bdo(
        payload,
        hmac_key_name: "key-1",
        hmac_secret: hmac_secret,
        alg: "HS256"
      )

      full_doc = root_json_object.dup
      full_doc["bdo"] = signed_bdo

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "hmac_keys" => { "key-1" => hmac_secret }
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(full_doc))
      filt.filter(event)

      expect(event.get("tags")).to be_nil
      expect(event.get("stanag")["valid"]).to be true
      expect(event.get("stanag")["binding_type"]).to eq("embedded")
      expect(event.get("stanag")["bindings"].first["data_references"].first["status"]).to eq("valid")
    end

    it "detects hash mismatch if target JSON property is modified" do
      payload = {
        "mbs" => [
          {
            "mds" => {
              "@context" => { "@base" => "urn:nato:stanag:5636:A:1:elements:json" },
              "ocl" => { "pol" => "NATO", "cls" => "RESTRICTED" }
            },
            "dtrs" => [
              {
                "cty" => "json",
                "uri" => "#/details",
                "hash" => "mismatched_dummy_hash",
                "alg" => "sha-256"
              }
            ]
          }
        ]
      }

      signed_bdo = SigningHelper.sign_jws_bdo(
        payload,
        hmac_key_name: "key-1",
        hmac_secret: hmac_secret,
        alg: "HS256"
      )

      full_doc = root_json_object.dup
      full_doc["bdo"] = signed_bdo

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "hmac_keys" => { "key-1" => hmac_secret }
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(full_doc))
      filt.filter(event)

      expect(event.get("tags")).to include("_stanag4778_invalid")
      expect(event.get("stanag")["valid"]).to be false
      expect(event.get("stanag")["bindings"].first["data_references"].first["status"]).to eq("mismatch")
    end
  end

  describe "External HTTP reference fetching" do
    let(:payload) do
      {
        "mbs" => [
          {
            "mds" => {
              "@context" => { "@base" => "urn:nato:stanag:5636:A:1:elements:json" },
              "ocl" => { "pol" => "NATO", "cls" => "UNCLASSIFIED" }
            },
            "dtrs" => [
              {
                "cty" => "application/json",
                "uri" => "https://external.nato.int/data/order.json",
                "hash" => "somehash",
                "alg" => "sha-256"
              }
            ]
          }
        ]
      }
    end

    let(:signed_bdo) do
      SigningHelper.sign_jws_bdo(
        payload,
        hmac_key_name: "key-1",
        hmac_secret: hmac_secret,
        alg: "HS256"
      )
    end

    it "tags unresolved references when external fetching is disabled" do
      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "hmac_keys" => { "key-1" => hmac_secret },
        "fetch_external_references" => false
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(signed_bdo))
      filt.filter(event)

      expect(event.get("tags")).to include("_stanag4778_unresolved_reference")
      expect(event.get("stanag")["has_unresolved_references"]).to be true
      expect(event.get("stanag")["bindings"].first["data_references"].first["status"]).to eq("unresolved")
    end

    it "blocks non-allowlisted external hosts when fetching is enabled" do
      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "hmac_keys" => { "key-1" => hmac_secret },
        "fetch_external_references" => true,
        "external_reference_allowlist" => ["trusted.nato.int"]
      )
      filt.register

      event = LogStash::Event.new("message" => JSON.generate(signed_bdo))
      filt.filter(event)

      expect(event.get("tags")).to include("_stanag4778_unresolved_reference")
      expect(event.get("stanag")["bindings"].first["data_references"].first["message"]).to include("not in external_reference_allowlist")
    end
  end

  describe "XMLDSIG HMAC verification" do
    let(:base_xml) { File.read(File.expand_path("../fixtures/unsigned_encapsulating.xml", __dir__)) }

    it "validates XML signed with HMAC-SHA256" do
      signed_xml = SigningHelper.sign_xml(
        base_xml, nil,
        hmac_key_name: "nato-hmac-key-1",
        hmac_secret: hmac_secret,
        alg: "hmac-sha256"
      )

      filt = LogStash::Filters::Stanag4778.new(
        "source" => "message",
        "target" => "stanag",
        "hmac_keys" => { "nato-hmac-key-1" => hmac_secret }
      )
      filt.register

      event = LogStash::Event.new("message" => signed_xml)
      filt.filter(event)

      expect(event.get("tags")).to be_nil
      expect(event.get("stanag")["valid"]).to be true
      expect(event.get("stanag")["signed"]).to be true
      expect(event.get("stanag")["signatures"].first["algorithm"]).to include("hmac-sha256")
    end
  end
end
