# encoding: utf-8

module LogStash
  module Filters
    module Stanag4778Module
      module Profile
        # XML Namespaces
        NS_MB_1_0      = "urn:nato:stanag:4778:bindinginformation:1:0".freeze
        NS_XMLDSIG     = "http://www.w3.org/2000/09/xmldsig#".freeze
        NS_XMLDSIG11   = "http://www.w3.org/2009/xmldsig11#".freeze
        NS_XMLDSIG_MORE= "http://www.w3.org/2001/04/xmldsig-more#".freeze
        NS_XMLENC      = "http://www.w3.org/2001/04/xmlenc#".freeze
        NS_XMLMIME     = "http://www.w3.org/2005/05/xmlmime".freeze
        NS_WSU         = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd".freeze
        NS_SLAB_4774   = "urn:nato:stanag:4774:confidentialitymetadatalabel:1:0".freeze
        NS_SLAB_4774_ALT = "urn:nato:stanag:4774:confidentialitymetadatlabel:1:0".freeze # Typo present in some STANAG drafts

        # JSON URNs
        JSON_TYP_BDO   = "urn:nato:stanag:4778:bindinginformation:1:0".freeze
        JSON_CTY_BDO   = "vnd.nato.bindingdataobject+json".freeze
        JSON_CTY_BDO_FULL = "application/vnd.nato.bindingdataobject+json".freeze

        # JSON Dereferencing Profile Canonical / Version Identifiers
        URI_PROFILES = {
          "jslt" => {
            canonical: "urn:nato:stanag:4778:profile:json:jslt".freeze,
            version:   "urn:nato:stanag:4778:profile:jslt:1:0".freeze
          },
          "jmespath" => {
            canonical: "urn:nato:stanag:4778:profile:json:jmespath".freeze,
            version:   "urn:nato:stanag:4778:profile:jmespath:1:0".freeze
          },
          "jsonpointer" => {
            canonical: "urn:nato:stanag:4778:profile:json:jsonpointer".freeze,
            version:   "urn:nato:stanag:4778:profile:jsonpointer:1:0".freeze
          },
          "jsonpath" => {
            canonical: "urn:nato:stanag:4778:profile:json:jsonpath".freeze,
            version:   "urn:nato:stanag:4778:profile:jsonpath:1:0".freeze
          }
        }.freeze

        # ADatP-4778.2 Table 2-3 DigestMethod status
        XML_DIGEST_METHODS = {
          "http://www.w3.org/2001/04/xmldsig-more#md5"    => :prohibited,
          "http://www.w3.org/2000/09/xmldsig#sha1"        => :prohibited,
          "http://www.w3.org/2001/04/xmldsig-more#sha224" => :prohibited,
          "http://www.w3.org/2001/04/xmlenc#sha256"       => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#sha384" => :mandatory,
          "http://www.w3.org/2001/04/xmlenc#sha512"       => :optional,
          "http://www.w3.org/2001/04/xmlenc#ripemd160"    => :optional
        }.freeze

        # ADatP-4778.2 Table 2-4 SignatureMethod (PKI)
        XML_PKI_SIGNATURE_METHODS = {
          "http://www.w3.org/2000/09/xmldsig#dsa-sha1"        => :prohibited,
          "http://www.w3.org/2009/xmldsig11#dsa-sha256"       => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#rsa-md5"    => :prohibited,
          "http://www.w3.org/2000/09/xmldsig#rsa-sha1"       => :prohibited,
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224" => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => :mandatory,
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160" => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1" => :prohibited,
          "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224" => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => :mandatory,
          "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" => :optional
        }.freeze

        # ADatP-4778.2 Table 2-5 SignatureMethod (HMAC)
        XML_HMAC_SIGNATURE_METHODS = {
          "http://www.w3.org/2000/09/xmldsig#hmac-sha1"        => :prohibited,
          "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224" => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256" => :mandatory,
          "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384" => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512" => :optional,
          "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160" => :optional
        }.freeze

        # ADatP-4778.2 Canonicalization methods
        XML_CANONICALIZATION_METHODS = [
          "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
          "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
          "http://www.w3.org/2006/12/xml-c14n11",
          "http://www.w3.org/2006/12/xml-c14n11#WithComments",
          "http://www.w3.org/2001/10/xml-exc-c14n#",
          "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
          "http://www.w3.org/2010/10/xml-c14n2"
        ].freeze

        # Allowed Transform Algorithms
        XML_TRANSFORM_ALGORITHMS = [
          "http://www.w3.org/2000/09/xmldsig#base64",
          "http://www.w3.org/TR/1999/REC-xpath-19991116",
          "http://www.w3.org/2002/06/xmldsig-filter2",
          "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
          "http://www.w3.org/TR/1999/REC-xslt-19991116",
          *XML_CANONICALIZATION_METHODS
        ].freeze

        # ADatP-4778.7 Table 8 JWS "alg" values
        JWS_ALGORITHMS = {
          "none"  => :mandatory,
          "HS256" => :optional,
          "HS384" => :mandatory,
          "HS512" => :optional,
          "RS256" => :optional,
          "RS384" => :mandatory,
          "RS512" => :optional,
          "ES256" => :optional,
          "ES384" => :mandatory,
          "ES512" => :optional,
          "PS256" => :optional,
          "PS384" => :optional,
          "PS512" => :optional
        }.freeze

        # Java Algorithm Mappings for JWS
        JWS_JAVA_SIGNATURE_ALGORITHMS = {
          "RS256" => "SHA256withRSA",
          "RS384" => "SHA384withRSA",
          "RS512" => "SHA512withRSA",
          "ES256" => "SHA256withECDSAinP1363Format",
          "ES384" => "SHA384withECDSAinP1363Format",
          "ES512" => "SHA512withECDSAinP1363Format",
          "PS256" => "RSASSA-PSS",
          "PS384" => "RSASSA-PSS",
          "PS512" => "RSASSA-PSS"
        }.freeze

        JWS_JAVA_MAC_ALGORITHMS = {
          "HS256" => "HmacSHA256",
          "HS384" => "HmacSHA384",
          "HS512" => "HmacSHA512"
        }.freeze

        # Mapping of IANA hash name to Java MessageDigest name
        IANA_HASH_TO_JAVA = {
          "sha-256" => "SHA-256",
          "sha-384" => "SHA-384",
          "sha-512" => "SHA-512",
          "sha256"  => "SHA-256",
          "sha384"  => "SHA-384",
          "sha512"  => "SHA-512"
        }.freeze
      end
    end
  end
end
