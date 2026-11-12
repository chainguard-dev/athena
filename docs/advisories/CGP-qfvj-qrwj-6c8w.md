# CGP-qfvj-qrwj-6c8w

DefaultJwtParser.parse(String) skips all signature verification when the JWT signature segment is empty, bypassing configured signing keys

## Affected packages

- **Ecosystem:** Maven
- **Package:** `io.jsonwebtoken:jjwt-impl`
- **Package URL:** `pkg:maven/io.jsonwebtoken/jjwt-impl`
- **Introduced:** 0
- **Fixed:** 0.12.0
- **Weaknesses:** CWE-347

**Affected code:**

- `io.jsonwebtoken.impl.DefaultJwtParser.parse(String)` (`impl/src/main/java/io/jsonwebtoken/impl/DefaultJwtParser.java:306`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:X/RL:X/RC:R`

## Details

### Root Cause

`DefaultJwtParser.parse(String)` (line 306) gates all signature verification on the condition `if (base64UrlEncodedDigest != null)`. The variable `base64UrlEncodedDigest` is populated only when the StringBuilder `sb` is non-empty after the second `.` delimiter is consumed. When the JWT's third segment is empty (e.g., `header.payload.`), `sb.length() == 0` and `base64UrlEncodedDigest` remains `null`. The code then skips the entire signature-verification block — including the check that a key was configured, the algorithm validation, and the call to `validator.isValid()` — and returns a `DefaultJwt` with the attacker-supplied claims.

The spec-required invariant — "if a verification key is configured, an unsigned or alg:none JWT MUST be rejected" — is entirely absent from the `parse(String)` code path. The enforcement is present only in the type-specific `parseClaimsJws()` / `parsePlaintextJws()` overloads, which use `JwtHandlerAdapter` to throw `UnsupportedJwtException` when a non-JWS token is returned. Applications that call the public `parse(String)` or `parse(String, JwtHandler)` methods directly are not protected.

### Affected Locations

- `io.jsonwebtoken.impl.DefaultJwtParser.parse(String)` (line 306): the `if (base64UrlEncodedDigest != null)` guard is the sole gate for all signature verification. When `base64UrlEncodedDigest` is `null` (empty or absent third JWT segment), the entire verification block is bypassed regardless of configured keys.

### Attack Vectors

**Stripped-signature authentication bypass:**
An attacker takes a legitimate JWT (or crafts one from scratch), removes or empties the signature segment, and submits `header.payload.` (with a trailing dot and empty third segment) to any endpoint that calls `JwtParser.parse(String)` or `JwtParser.parse(String, JwtHandler)`. The parser returns a `DefaultJwt` with the attacker-forged claims without performing any signature verification, even if the application called `setSigningKey()` before parsing.

**alg:none with empty signature:**
An attacker sets `alg:none` in the header and provides an empty signature segment. The same bypass applies: `base64UrlEncodedDigest` is `null`, the verification block is skipped, and the forged claims are returned.

### Impact

An attacker can forge arbitrary JWT claims and have them accepted as valid by any application that uses the `parse(String)` or `parse(String, JwtHandler)` API, even when a signing key has been configured. This enables authentication bypass and privilege escalation. Applications using the type-specific `parseClaimsJws()` overload are protected by the handler adapter, but `parse(String)` is a first-class public method on the `JwtParser` interface and is widely used. Severity is assessed as MEDIUM because exploitability depends on which `parse*` overload the downstream caller uses.

### Trace

1. Attacker crafts a compact JWT: `base64url({"alg":"none"}).base64url({"sub":"admin","role":"superuser"}).` (empty third segment).
2. `DefaultJwtParser.parse(String)` splits on `.` delimiters; after the second delimiter, `sb` is empty, so `base64UrlEncodedDigest = null`.
3. The condition `if (base64UrlEncodedDigest != null)` at line 306 is false; the entire signature-verification block is skipped.
4. No check is made that a signing key was configured or that the algorithm is not `none`.
5. The method returns `new DefaultJwt<>(header, body)` with the attacker-forged claims.

## Sources

- [Advisory JSON](../../advisories/CGP-qfvj-qrwj-6c8w/CGP-qfvj-qrwj-6c8w.json)
- [Patch: CGP-qfvj-qrwj-6c8w-pkg:maven_io.jsonwebtoken_jjwt-impl@0.11.5.patch](../../advisories/CGP-qfvj-qrwj-6c8w/CGP-qfvj-qrwj-6c8w-pkg:maven_io.jsonwebtoken_jjwt-impl@0.11.5.patch)

---

Published 2026-11-12T16:00:00Z · Modified 2026-11-12T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
