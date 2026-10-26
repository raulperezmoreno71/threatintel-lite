# Local TLS fixture

`ssrf-test.p12.base64` is a Base64-encoded PKCS12 keystore containing a
self-signed RSA certificate for the test-only hostname `rebind.invalid`.
Its private key and password (`test-only-password`) are public test data;
never use this identity outside the tests. It is valid from 2026-01-01
for 3650 days and must be regenerated before expiry.

Only the test client context trusts this certificate. Production clients
continue to use their normal trust stores and hostname verification.
Local fixtures inject loopback targets directly at the transport boundary;
production URL validation still rejects loopback and nonstandard ports.
