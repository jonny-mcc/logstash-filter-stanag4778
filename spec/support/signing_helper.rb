# encoding: utf-8
require "java"
require "base64"
require "time"
require "json"

java_import java.security.KeyPairGenerator
java_import java.security.Signature
java_import java.security.cert.CertificateFactory
java_import java.math.BigInteger
java_import java.io.ByteArrayInputStream
java_import javax.crypto.Mac
java_import javax.crypto.spec.SecretKeySpec
java_import javax.xml.parsers.DocumentBuilderFactory
java_import javax.xml.transform.TransformerFactory
java_import javax.xml.transform.dom.DOMSource
java_import javax.xml.transform.stream.StreamResult
java_import java.io.StringWriter
java_import java.io.StringReader
java_import org.xml.sax.InputSource

# Use BouncyCastle or Sun/BC self-signed generator if available, or generate via java.security
module SigningHelper
  # Generate RSA 2048 keypair
  def self.generate_rsa_keypair
    kpg = KeyPairGenerator.getInstance("RSA")
    kpg.java_method(:initialize, [Java::int]).call(2048)
    kpg.generateKeyPair
  end

  # Generate EC keypair (P-256)
  def self.generate_ec_keypair
    kpg = KeyPairGenerator.getInstance("EC")
    kpg.java_method(:initialize, [Java::int]).call(256)
    kpg.generateKeyPair
  end

  # Generate self-signed X.509 certificate using JDK internal or BouncyCastle
  def self.generate_self_signed_cert(keypair, dn = "CN=Test NATO Originator, O=NATO, C=BE")
    begin
      # Try BouncyCastle if on classpath
      generate_bc_cert(keypair, dn)
    rescue StandardError => e
      # Fallback to keytool generation or fixed synthetic test cert with matching public key
      generate_keytool_cert(keypair, dn)
    end
  end

  # Generate cert using keytool command line
  def self.generate_keytool_cert(keypair, dn)
    # Return a mocked/wrapped X509Certificate if possible or invoke keytool into a temp keystore
    keystore_path = File.join(Dir.tmpdir, "test_keystore_#{$$}_#{rand(10000)}.p12")
    cert_path = File.join(Dir.tmpdir, "test_cert_#{$$}_#{rand(10000)}.cer")
    system(
      "keytool", "-genkeypair", "-alias", "test", "-keyalg", "RSA", "-keysize", "2048",
      "-sigalg", "SHA256withRSA", "-validity", "365", "-keystore", keystore_path,
      "-storepass", "password", "-keypass", "password", "-dname", dn,
      "-noprompt"
    )
    system(
      "keytool", "-exportcert", "-alias", "test", "-keystore", keystore_path,
      "-storepass", "password", "-file", cert_path
    )

    cert_bytes = File.read(cert_path).to_java_bytes
    cf = CertificateFactory.getInstance("X.509")
    cert = cf.generateCertificate(ByteArrayInputStream.new(cert_bytes))

    # Also load keypair from keystore to have matching private key
    ks = java.security.KeyStore.getInstance("PKCS12")
    ks.load(java.io.FileInputStream.new(keystore_path), "password".to_java.toCharArray)
    priv_key = ks.getKey("test", "password".to_java.toCharArray)
    pub_key = cert.getPublicKey

    FileUtils.rm_f(keystore_path)
    FileUtils.rm_f(cert_path)

    [cert, java.security.KeyPair.new(pub_key, priv_key)]
  end

  def self.generate_bc_cert(keypair, dn)
    # Check if org.bouncycastle is present
    Java::OrgBouncycastleCertJca::JcaX509v3CertificateBuilder rescue nil
    raise "BC not present"
  end

  # Sign an XML string containing mb:BindingInformation using DOM XMLSignatureFactory
  def self.sign_xml(xml_string, keypair, cert: nil, hmac_key_name: nil, hmac_secret: nil, alg: "rsa-sha256")
    dbf = DocumentBuilderFactory.newInstance
    dbf.setNamespaceAware(true)
    doc = dbf.newDocumentBuilder.parse(InputSource.new(StringReader.new(xml_string)))

    # Find BindingInformation
    bdo_nodes = doc.getElementsByTagNameNS("urn:nato:stanag:4778:bindinginformation:1:0", "BindingInformation")
    bdo = bdo_nodes.item(0)

    # Find MetadataBinding Id
    mb_nodes = bdo.getElementsByTagNameNS("urn:nato:stanag:4778:bindinginformation:1:0", "MetadataBinding")
    mb_elem = mb_nodes.item(0)
    mb_id = mb_elem.getAttribute("Id")
    mb_id = "mb-1" if mb_id.empty?
    mb_elem.setAttribute("Id", mb_id)
    mb_elem.setIdAttribute("Id", true)

    fac = javax.xml.crypto.dsig.XMLSignatureFactory.getInstance("DOM")

    # Transforms
    transforms = [
      fac.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#", nil)
    ]

    # Reference to MetadataBinding
    dm = fac.newDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256", nil)
    ref1 = fac.newReference("##{mb_id}", dm, transforms, nil, nil)

    # Reference to SignatureProperties / Timestamp
    ts_id = "ts-1"
    ref2 = fac.newReference("##{ts_id}", dm, transforms, nil, nil)

    refs = [ref1, ref2]

    # Check if there is a DataReference with URI="" for embedded BDO
    data_refs = mb_elem.getElementsByTagNameNS("urn:nato:stanag:4778:bindinginformation:1:0", "DataReference")
    data_refs.getLength.times do |i|
      dtr = data_refs.item(i)
      uri = dtr.getAttribute("URI")
      if uri == ""
        # Enveloped BDO transform
        xpath_param = javax.xml.crypto.dsig.spec.XPathFilterParameterSpec.new(
          "not(ancestor-or-self::*[local-name() = 'BindingInformation' and namespace-uri() = 'urn:nato:stanag:4778:bindinginformation:1:0'])"
        )
        env_transform = fac.newTransform("http://www.w3.org/TR/1999/REC-xpath-19991116", xpath_param)
        refs << fac.newReference("", dm, [env_transform], nil, nil)
      elsif uri.start_with?("#")
        refs << fac.newReference(uri, dm, transforms, nil, nil)
      end
    end

    # CanonicalizationMethod
    cm = fac.newCanonicalizationMethod("http://www.w3.org/2001/10/xml-exc-c14n#", nil)

    # SignatureMethod
    sig_method_uri = case alg
                     when "rsa-sha256" then "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
                     when "rsa-sha1"   then "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
                     when "hmac-sha256" then "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
                     else "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
                     end

    sm = fac.newSignatureMethod(sig_method_uri, nil)
    si = fac.newSignedInfo(cm, sm, refs)

    # KeyInfo
    kif = fac.getKeyInfoFactory
    key_info_items = []
    if cert
      key_info_items << kif.newX509Data([cert])
    elsif hmac_key_name
      key_info_items << kif.newKeyName(hmac_key_name)
    elsif keypair
      key_info_items << kif.newKeyValue(keypair.getPublic)
    end
    ki = kif.newKeyInfo(key_info_items)

    # Object with SignatureProperties & wsu:TimeStamp
    now_iso = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    ts_xml = "<wsu:TimeStamp xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" \
             "<wsu:Created>#{now_iso}</wsu:Created>" \
             "</wsu:TimeStamp>"

    ts_doc = dbf.newDocumentBuilder.parse(InputSource.new(StringReader.new(ts_xml)))
    ts_elem = doc.importNode(ts_doc.getDocumentElement, true)

    sig_prop = fac.newSignatureProperty([javax.xml.crypto.dom.DOMStructure.new(ts_elem)], "#sig-1", ts_id)
    sig_props = fac.newSignatureProperties([sig_prop], nil)
    obj = fac.newXMLObject([sig_props], "obj-1", nil, nil)

    sig = fac.newXMLSignature(si, ki, [obj], "sig-1", nil)

    # Insert Signature as first child of BindingInformation
    val_context = if hmac_secret
                    key_spec = SecretKeySpec.new(hmac_secret.to_java_bytes, "HmacSHA256")
                    javax.xml.crypto.dsig.dom.DOMSignContext.new(key_spec, bdo, bdo.getFirstChild)
                  else
                    javax.xml.crypto.dsig.dom.DOMSignContext.new(keypair.getPrivate, bdo, bdo.getFirstChild)
                  end

    # Register IDs in context
    val_context.putNamespacePrefix("http://www.w3.org/2000/09/xmldsig#", "ds")
    sig.sign(val_context)

    # Convert back to XML string
    tf = TransformerFactory.newInstance
    sw = StringWriter.new
    tf.newTransformer.transform(DOMSource.new(doc), StreamResult.new(sw))
    sw.toString
  end

  # Create a signed JWS BDO
  def self.sign_jws_bdo(payload_obj, keypair: nil, cert: nil, hmac_key_name: nil, hmac_secret: nil,
                        alg: "RS256", iat: nil, bdo_typ: "urn:nato:stanag:4778:bindinginformation:1:0")
    iat_val = iat || Time.now.to_i

    header = {
      "alg" => alg,
      "cty" => "vnd.nato.bindingdataobject+json",
      "iat" => iat_val
    }

    if cert
      header["x5c"] = [Base64.strict_encode64(String.from_java_bytes(cert.getEncoded))]
      header["x5t#S256"] = Base64.urlsafe_encode64(
        String.from_java_bytes(java.security.MessageDigest.getInstance("SHA-256").digest(cert.getEncoded))
      ).tr("=", "")
    elsif hmac_key_name
      header["kid"] = hmac_key_name
    end

    hdr_b64 = Base64.urlsafe_encode64(JSON.generate(header)).tr("=", "")
    pay_b64 = Base64.urlsafe_encode64(JSON.generate(payload_obj)).tr("=", "")
    signing_input = "#{hdr_b64}.#{pay_b64}".encode("ASCII-8BIT")

    sig_b64 = if alg == "none"
                ""
              elsif alg.start_with?("HS")
                mac_alg = case alg
                          when "HS256" then "HmacSHA256"
                          when "HS384" then "HmacSHA384"
                          when "HS512" then "HmacSHA512"
                          end
                mac = Mac.getInstance(mac_alg)
                mac.init(SecretKeySpec.new(hmac_secret.to_java_bytes, mac_alg))
                digest = mac.doFinal(signing_input.to_java_bytes)
                Base64.urlsafe_encode64(String.from_java_bytes(digest)).tr("=", "")
              elsif alg.start_with?("RS") || alg.start_with?("ES")
                j_alg = case alg
                        when "RS256" then "SHA256withRSA"
                        when "RS384" then "SHA384withRSA"
                        when "RS512" then "SHA512withRSA"
                        when "ES256" then "SHA256withECDSAinP1363Format"
                        when "ES384" then "SHA384withECDSAinP1363Format"
                        when "ES512" then "SHA512withECDSAinP1363Format"
                        end
                signer = Signature.getInstance(j_alg)
                signer.initSign(keypair.getPrivate)
                signer.update(signing_input.to_java_bytes)
                sig_bytes = signer.sign
                Base64.urlsafe_encode64(String.from_java_bytes(sig_bytes)).tr("=", "")
              end

    bdi = "#{hdr_b64}.#{pay_b64}.#{sig_b64}"
    {
      "typ" => bdo_typ,
      "prf" => "urn:nato:stanag:4778:profile:example:json:1:0",
      "bdis" => [{ "bdi" => bdi }]
    }
  end
end
