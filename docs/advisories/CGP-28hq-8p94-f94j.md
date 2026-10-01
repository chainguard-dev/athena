# CGP-28hq-8p94-f94j

Non-constant-time Arrays.equals() in MacValidator and RsaSignatureValidator enables timing-oracle HMAC/RSA signature forgery

## Affected packages

- **Ecosystem:** Maven
- **Package:** `io.jsonwebtoken:jjwt`
- **Package URL:** `pkg:maven/io.jsonwebtoken/jjwt`
- **Introduced:** 0.1
- **Fixed:** 0.6.0
- **Weaknesses:** CWE-208

**Affected code:**

- `io.jsonwebtoken.impl.crypto.MacValidator.isValid(byte[],byte[])` (`src/main/java/io/jsonwebtoken/impl/crypto/MacValidator.java:34`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N/E:X/RL:X/RC:R`

## Details

### Root Cause

`MacValidator.isValid(byte[], byte[])` (line 34 of `MacValidator.java`) computes the expected HMAC via `this.signer.sign(data)` and then compares it against the attacker-supplied signature with `java.util.Arrays.equals(computed, signature)`. `java.util.Arrays.equals` returns `false` as soon as it encounters the first differing byte, so the time taken by the comparison is proportional to the length of the matching prefix between the two arrays.

The same pattern appears in `RsaSignatureValidator.isValid(byte[], byte[])` (line 55 of `RsaSignatureValidator.java`) on the private-key sign-and-compare path: when the configured key is an `RSAPrivateKey`, the validator signs the data locally with `this.SIGNER.sign(data)` and compares the result to the supplied signature with `Arrays.equals(computed, signature)` rather than delegating to the JCA `Signature.verify()` path.

### Affected Locations

- `io.jsonwebtoken.impl.crypto.MacValidator.isValid(byte[], byte[])` — line 34: `return Arrays.equals(computed, signature);` — covers HS256, HS384, and HS512 token verification.
- `io.jsonwebtoken.impl.crypto.RsaSignatureValidator.isValid(byte[], byte[])` — line 55: `return Arrays.equals(computed, signature);` — covers the RSA private-key sign-and-compare path (RS256, RS384, RS512 when a private key is configured as the validator key).

Both sinks are reached through the same entry point: `DefaultJwtParser.parse(String)` → `DefaultJwtSignatureValidator.isValid()` → the respective validator's `isValid(byte[], byte[])` method.

### Attack Vectors

**Timing oracle via repeated token submission (HMAC path):** An attacker who can repeatedly submit HS256/HS384/HS512 tokens and measure response latency — for example across a low-jitter LAN or a co-located cloud tenant — can exploit the early-exit behavior of `Arrays.equals` to recover the correct MAC byte-by-byte without knowing the HMAC key. Each byte position requires at most 256 probes; a 32-byte HS256 MAC requires at most 8 192 requests in the worst case.

**Timing oracle via repeated token submission (RSA private-key path):** The same timing oracle applies to the `RsaSignatureValidator` private-key path. When a `RSAPrivateKey` is used as the validator key, the validator signs the data locally and compares with `Arrays.equals`, exposing the same byte-by-byte timing differential.

**Prerequisites:** The attacker must be able to submit many tokens to the same endpoint and observe response latency with sufficient resolution. High-resolution timing observation is required, so practical exploitation is more feasible in co-located or low-latency network environments.

### Impact

A successful timing attack allows an attacker to forge a valid JWS token for any algorithm that uses the non-constant-time comparison path (HS256, HS384, HS512, and the RSA private-key-validator path), enabling authentication bypass and impersonation of any user whose token the attacker can forge.

### Trace

1. Attacker submits a crafted JWS compact string to `JwtParser.parse()` or `JwtParser.parseClaimsJws()`.
2. `DefaultJwtParser.parse(String)` extracts the base64url-encoded signature segment (`base64UrlEncodedDigest`).
3. `DefaultJwtSignatureValidator.isValid(String, String)` base64url-decodes the digest and calls the algorithm-specific validator.
4. For HMAC algorithms: `MacValidator.isValid(byte[], byte[])` computes the expected MAC and calls `Arrays.equals(computed, signature)` at line 34.
5. For RSA with a private key: `RsaSignatureValidator.isValid(byte[], byte[])` signs locally and calls `Arrays.equals(computed, signature)` at line 55.
6. The early-exit behavior of `Arrays.equals` leaks timing information to the attacker.

## Sources

- [Advisory JSON](../../advisories/CGP-28hq-8p94-f94j/CGP-28hq-8p94-f94j.json)
- [Patch: CGP-28hq-8p94-f94j-pkg:maven_io.jsonwebtoken_jjwt@0.5.1.patch](../../advisories/CGP-28hq-8p94-f94j/CGP-28hq-8p94-f94j-pkg:maven_io.jsonwebtoken_jjwt@0.5.1.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
