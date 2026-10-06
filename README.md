# Logstash STANAG 4778 Filter Plugin

This Logstash filter parses and validates NATO STANAG 4778 Binding Data Objects (BDOs) in both XML (ADatP-4778 and ADatP-4778.2) and JSON (ADatP-4778.7) formats.

It verifies XMLDSIG and JWS cryptographic signatures using the built-in Java Cryptography Architecture (JCA) on JRuby without third-party native crypto gems or vendored JARs. It also extracts STANAG 4774 confidentiality metadata labels.
