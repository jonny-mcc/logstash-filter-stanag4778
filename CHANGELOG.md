# 1.0.0
- Initial release of `logstash-filter-stanag4778`.
- Parse and validate STANAG 4778 Binding Data Objects (BDOs) in XML and JSON syntaxes.
- Support XMLDSIG verification compliant with ADatP-4778.2 (RSA, ECDSA, HMAC).
- Support JWS verification compliant with ADatP-4778.7 (RS, PS, ES, HS, none).
- Support STANAG 4774 confidentiality label extraction.
- Support same-document dereferencing (JSON Pointer, JSONPath, JMESPath) and detached reference hashing with RFC 8785 JSON Canonicalization Scheme (JCS).
- Optional HTTPS fetching for external references with host allowlist and size/time limits.
