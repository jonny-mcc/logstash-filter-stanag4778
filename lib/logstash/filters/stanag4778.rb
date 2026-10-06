# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

class LogStash::Filters::Stanag4778 < LogStash::Filters::Base
  config_name "stanag4778"

  # Source field containing the XML document or JSON payload
  config :source, :validate => :string, :required => true

  # Target field where the verification results and metadata are written
  config :target, :validate => :string, :default => "stanag4778"

  # Format: "auto", "xml", or "json"
  config :format, :validate => ["auto", "xml", "json"], :default => "auto"

  # Whether to fail verification if the BDO has no cryptographic signature
  config :require_signature, :validate => :boolean, :default => true

  # Enforce strict compliance with ADatP-4778.2 / 4778.7 profile rules
  config :strict_profile, :validate => :boolean, :default => true

  # Validate XML against local STANAG 4778 and XMLDSIG XSD schemas
  config :validate_schema, :validate => :boolean, :default => true

  # Path to PEM bundle with trusted CA certificates
  config :ssl_certificate_authorities, :validate => :path

  # Array of paths to pinned X.509 signer certificates (PEM)
  config :trusted_certificates, :validate => :array, :default => []

  # Certificate revocation check mode: "none", "crl", or "ocsp"
  config :revocation_mode, :validate => ["none", "crl", "ocsp"], :default => "none"

  # Required Extended Key Usage OIDs for signer certificates (e.g. ["1.3.6.1.5.5.7.3.3"])
  config :required_extended_key_usage, :validate => :array, :default => []

  # Whitelist of allowed signer subject regular expressions
  config :allowed_signer_subjects, :validate => :array, :default => []

  # Path to JWKS JSON file for JWS key resolution
  config :jwks_path, :validate => :path

  # Hash of HMAC key-id to secret string or hex/base64
  config :hmac_keys, :validate => :hash, :default => {}

  # Allowed clock skew for iat / timestamp validation in seconds
  config :clock_skew, :validate => :number, :default => 300

  # Maximum age of signature in seconds (nil/0 disables age check)
  config :max_signature_age, :validate => :number, :default => 0

  # Name of JSON field containing embedded BDO
  config :json_bdo_field, :validate => :string, :default => "bdo"

  # Default URI dereferencing profile for JSON ("jsonpointer", "jsonpath", "jmespath")
  config :json_uri_profile, :validate => ["jsonpointer", "jsonpath", "jmespath", "auto"], :default => "auto"

  # Whether to fetch detached HTTP/HTTPS references
  config :fetch_external_references, :validate => :boolean, :default => false

  # Whitelist of allowed hosts for external HTTP fetching
  config :external_reference_allowlist, :validate => :array, :default => []

  # HTTP fetch timeout in seconds
  config :fetch_timeout, :validate => :number, :default => 10

  # Max bytes to fetch for external reference
  config :fetch_max_bytes, :validate => :number, :default => 10_485_760

  # Allow fetching from private / loopback IP addresses (for test environments)
  config :fetch_allow_private_addresses, :validate => :boolean, :default => false

  # Max total memory in bytes for fetcher cache
  config :fetch_cache_max_bytes, :validate => :number, :default => 52_428_800

  # Cache time to live in seconds
  config :fetch_cache_ttl, :validate => :number, :default => 300

  # Path to custom CA bundle for external HTTPS fetching
  config :fetch_ssl_certificate_authorities, :validate => :path

  # Extract STANAG 4774 confidentiality labels into target
  config :extract_labels, :validate => :boolean, :default => true

  TAG_PARSE_FAILURE         = "_stanag4778_parse_failure".freeze
  TAG_INVALID               = "_stanag4778_invalid".freeze
  TAG_UNSIGNED              = "_stanag4778_unsigned".freeze
  TAG_UNRESOLVED_REFERENCE  = "_stanag4778_unresolved_reference".freeze

  def register
    require "logstash/filters/stanag4778/profile"
    require "logstash/filters/stanag4778/trust_store"
    require "logstash/filters/stanag4778/fetcher"
    require "logstash/filters/stanag4778/xml_verifier"
    require "logstash/filters/stanag4778/jws_verifier"
    require "logstash/filters/stanag4778/label_extractor"

    if @fetch_external_references && (@external_reference_allowlist.nil? || @external_reference_allowlist.empty?)
      raise LogStash::ConfigurationError,
            "When 'fetch_external_references' is true, 'external_reference_allowlist' must contain at least one host."
    end

    @trust_store = LogStash::Filters::Stanag4778Module::TrustStore.new(
      ca_path: @ssl_certificate_authorities,
      trusted_certs: @trusted_certificates,
      jwks_path: @jwks_path,
      hmac_keys: @hmac_keys,
      revocation_mode: @revocation_mode,
      required_eku: @required_extended_key_usage,
      allowed_subjects: @allowed_signer_subjects
    )

    @fetcher = LogStash::Filters::Stanag4778Module::Fetcher.new(
      enabled: @fetch_external_references,
      allowlist: @external_reference_allowlist,
      timeout_seconds: @fetch_timeout,
      max_bytes: @fetch_max_bytes,
      allow_private: @fetch_allow_private_addresses,
      cache_max_bytes: @fetch_cache_max_bytes,
      cache_ttl: @fetch_cache_ttl,
      ca_path: @fetch_ssl_certificate_authorities
    )

    @xml_verifier = LogStash::Filters::Stanag4778Module::XmlVerifier.new(
      trust_store: @trust_store,
      fetcher: @fetcher,
      strict_profile: @strict_profile,
      validate_schema: @validate_schema,
      clock_skew: @clock_skew,
      max_age: @max_signature_age,
      require_signature: @require_signature
    )

    @jws_verifier = LogStash::Filters::Stanag4778Module::JwsVerifier.new(
      trust_store: @trust_store,
      fetcher: @fetcher,
      strict_profile: @strict_profile,
      clock_skew: @clock_skew,
      max_age: @max_signature_age,
      require_signature: @require_signature,
      default_profile: @json_uri_profile,
      bdo_field: @json_bdo_field
    )
  end

  def filter(event)
    source_val = event.get(@source)
    return unless source_val

    if source_val.is_a?(Array)
      if source_val.length != 1
        event.tag(TAG_PARSE_FAILURE)
        @logger.warn("stanag4778 filter expects single item array", source: @source, count: source_val.length)
        return
      end
      source_val = source_val.first
    end

    format = detect_format(source_val)
    if format == :unknown
      event.tag(TAG_PARSE_FAILURE)
      @logger.warn("Unable to detect format for STANAG 4778 verification", source: @source)
      return
    end

    result = if format == :xml
               @xml_verifier.verify(source_val)
             else
               @jws_verifier.verify(source_val)
             end

    apply_result(event, result)
  rescue Exception => e
    event.tag(TAG_PARSE_FAILURE)
    if @logger
      @logger.error("Unexpected error in stanag4778 filter", exception: e.class.name, message: e.message, backtrace: e.backtrace)
    end
  end

  private

  def detect_format(val)
    return :json if val.is_a?(Hash)
    return :unknown unless val.is_a?(String)

    stripped = val.strip
    return :unknown if stripped.empty?

    if @format == "xml"
      :xml
    elsif @format == "json"
      :json
    else
      first = stripped[0]
      if first == "{" || first == "["
        :json
      elsif first == "<"
        :xml
      else
        :unknown
      end
    end
  end

  def apply_result(event, result)
    # Convert symbols to strings in result for consistent Logstash Event access
    stringified_result = stringify_keys(result)

    if @extract_labels && stringified_result["bindings"]
      stringified_result["labels"] = LogStash::Filters::Stanag4778Module::LabelExtractor.extract(result[:bindings])
    end

    event.set(@target, stringified_result)

    if stringified_result["parse_error"]
      event.tag(TAG_PARSE_FAILURE)
    elsif stringified_result["signed"] == false && @require_signature
      event.tag(TAG_UNSIGNED)
      event.tag(TAG_INVALID)
    elsif stringified_result["valid"] == false
      event.tag(TAG_INVALID)
    end

    if stringified_result["has_unresolved_references"]
      event.tag(TAG_UNRESOLVED_REFERENCE)
    end

    filter_matched(event) if stringified_result["valid"]
  end

  def stringify_keys(obj)
    case obj
    when Hash
      obj.each_with_object({}) do |(k, v), h|
        h[k.to_s] = stringify_keys(v)
      end
    when Array
      obj.map { |elem| stringify_keys(elem) }
    when Symbol
      obj.to_s
    else
      obj
    end
  end
end
