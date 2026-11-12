# CGP-grwg-42x8-w9x7

ECDSAAlgorithm.countPadding reads one byte past the array end when the S-half of a JOSE signature is all zeros, causing an uncaught ArrayIndexOutOfBoundsException (DoS).

## Affected packages

- **Ecosystem:** Maven
- **Package:** `com.auth0:java-jwt`
- **Package URL:** `pkg:maven/com.auth0/java-jwt`
- **Introduced:** 3.0.1
- **Fixed:** 3.19.2
- **Weaknesses:** CWE-125

**Affected code:**

- `com.auth0.jwt.algorithms.ECDSAAlgorithm.countPadding(byte[],int,int)` (`lib/src/main/java/com/auth0/jwt/algorithms/ECDSAAlgorithm.java:208-214`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:X/RL:X/RC:R`

## Details

### Root Cause

The private method `countPadding(byte[] bytes, int fromIndex, int toIndex)` at lines 208–214 of `com/auth0/jwt/algorithms/ECDSAAlgorithm.java` performs an out-of-bounds array read when the entire byte range `[fromIndex, toIndex)` consists of zero bytes.

The method body is:
```java
private int countPadding(byte[] bytes, int fromIndex, int toIndex) {
    int padding = 0;
    while (fromIndex + padding < toIndex && bytes[fromIndex + padding] == 0) {
        padding++;
    }
    return (bytes[fromIndex + padding] & 0xff) > 0x7f ? padding - 1 : padding;
}
```

When all bytes in `[fromIndex, toIndex)` are `0x00`, the while-loop exits with `fromIndex + padding == toIndex`. The `return` statement then reads `bytes[fromIndex + padding]`, which equals `bytes[toIndex]` — one index past the end of the valid range. For the S-component invocation at line 151:
```java
int sPadding = countPadding(joseSignature, ecNumberSize, joseSignature.length);
```
`toIndex` is `joseSignature.length`, so the read is `bytes[joseSignature.length]`, which is always out of bounds, throwing `ArrayIndexOutOfBoundsException`.

### Affected Locations

- **`com.auth0.jwt.algorithms.ECDSAAlgorithm.countPadding(byte[],int,int)`** (lines 208–214): the sink where the out-of-bounds read occurs. Called twice from `JOSEToDER()` at lines 150–151: once for the R component (`fromIndex=0, toIndex=ecNumberSize`) and once for the S component (`fromIndex=ecNumberSize, toIndex=joseSignature.length`). Only the S-component call is reliably exploitable because `toIndex` equals the array length.

The cross-codebase search confirms `countPadding` exists only in `ECDSAAlgorithm.java` and is called only from `JOSEToDER()` within the same class. No sibling sinks of the same pattern exist elsewhere in the codebase.

### Attack Vectors

**All-zero S-half JOSE signature (documented PoC):**
An attacker crafts a JWT whose signature field is the base64url encoding of `2 * ecNumberSize` zero bytes. For ES256 (`ecNumberSize = 32`) this is 64 zero bytes; for ES384 (`ecNumberSize = 48`) it is 96 zero bytes; for ES512 (`ecNumberSize = 66`) it is 132 zero bytes. The documented PoC payload is:
```
<header>.<payload>.<base64url(2*ecNumberSize zero bytes)>
```
For ES256 specifically: a 64-byte all-zero signature base64url-encoded and appended to any valid header and payload. When `JWTVerifier.verify(token)` is called, the token is decoded, `ECDSAAlgorithm.verify(jwt)` is invoked, the signature bytes are base64-decoded to a 64-byte all-zero array, `JOSEToDER(signatureBytes)` is called, which calls `countPadding(joseSignature, 32, 64)`. The while-loop increments `padding` from 0 to 32 (all bytes are zero), then `bytes[32 + 32]` = `bytes[64]` is read — out of bounds — throwing `ArrayIndexOutOfBoundsException`.

**Exception contract violation:**
The `ArrayIndexOutOfBoundsException` is a `RuntimeException` not caught by `ECDSAAlgorithm.verify()`'s catch block (which only handles `NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalStateException | IllegalArgumentException`). It therefore escapes `JWTVerifier.verify()` without being wrapped in `SignatureVerificationException` or any `JWTVerificationException` subclass. Any caller that catches only `JWTVerificationException` will see an unhandled crash.

**Reachability:**
This code path is on the default verification path for any service using ES256, ES384, or ES512 algorithm variants. No special configuration is required; the default code path is affected.

### Impact

An unauthenticated attacker who can submit a JWT token to a service using ECDSA verification can cause the verifying thread to throw an uncaught `ArrayIndexOutOfBoundsException`, resulting in denial of service or unexpected application crash. There is no signature bypass: the exception is thrown before the signature is validated, but the token is also not accepted. Confidentiality and integrity are not affected.

### Trace

1. `JWTVerifier.verify(String token)` — public entry point
2. `new JWTDecoder(parser, token)` — decodes the token
3. `JWTVerifier.verify(DecodedJWT jwt)` — calls `algorithm.verify(jwt)`
4. `ECDSAAlgorithm.verify(DecodedJWT jwt)` (line 42) — decodes the base64url signature: `Base64.getUrlDecoder().decode(jwt.getSignature())`
5. `ECDSAAlgorithm.JOSEToDER(byte[] joseSignature)` (line 46) — converts JOSE to DER
6. `countPadding(joseSignature, ecNumberSize, joseSignature.length)` (line 151) — S-component call
7. `bytes[fromIndex + padding]` (line 213) — out-of-bounds read when all S bytes are zero → `ArrayIndexOutOfBoundsException` thrown
8. Exception propagates uncaught through `ECDSAAlgorithm.verify()` and `JWTVerifier.verify()`, violating the `throws JWTVerificationException` contract

## Sources

- [Advisory JSON](../../advisories/CGP-grwg-42x8-w9x7/CGP-grwg-42x8-w9x7.json)
- [Patch: CGP-grwg-42x8-w9x7-pkg:maven_com.auth0_java-jwt@3.19.1.patch](../../advisories/CGP-grwg-42x8-w9x7/CGP-grwg-42x8-w9x7-pkg:maven_com.auth0_java-jwt@3.19.1.patch)

---

Published 2026-11-12T16:00:00Z · Modified 2026-11-12T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
