# 1.1.0 (Security Release)
- **Security**: Eliminate trust-on-first-use flaw where embedded JWS `jwk` (including symmetric `oct` keys) or XMLDSIG `KeyValue` elements were accepted without matching pre-configured trust material. Signers must now match configured CA anchors, pinned certificates, JWKS files, or HMAC secrets.
- **Security**: Fix offline XML schema resolution path and enforce schema compilation at plugin registration time.
- **Security**: Harden external reference HTTP fetcher against Server-Side Request Forgery (SSRF) by validating manual redirect hops, rejecting loopback/private/link-local/multicast IP addresses, enforcing stream-based size caps, and bounding cache memory.
- **Security**: Enforce strict NATO ADatP-4778.2 and ADatP-4778.7 profile constraints (JWS `crit` understood-parameter whitelist, mandatory `alg` parameter, reference hash algorithm alignment, XML enveloped-BDO XPath transform, prohibited `KeyInfo` child element validation).
- **Security**: Add certificate validation policy controls: validity checks, KeyUsage restrictions, configurable `required_extended_key_usage` OIDs, `allowed_signer_subjects` whitelist, and `revocation_mode` (`none`, `crl`, `ocsp`).
- **Reliability**: Add `revocation_checked` flag to event signature metadata.
- **Reliability**: Tag blocked or failed XML external references with `_stanag4778_unresolved_reference`.
- **Standards**: Implement ECMAScript standard number serialization in RFC 8785 JSON Canonicalization Scheme (JCS).

# 1.0.0
- Initial release of `logstash-filter-stanag4778`.
- Parse and validate STANAG 4778 Binding Data Objects (BDOs) in XML and JSON syntaxes.
- Support XMLDSIG verification compliant with ADatP-4778.2 (RSA, ECDSA, HMAC).
- Support JWS verification compliant with ADatP-4778.7 (RS, PS, ES, HS, none).
- Support STANAG 4774 confidentiality label extraction.
- Support same-document dereferencing (JSON Pointer, JSONPath, JMESPath) and detached reference hashing with RFC 8785 JSON Canonicalization Scheme (JCS).
- Optional HTTPS fetching for external references with host allowlist and size/time limits.
