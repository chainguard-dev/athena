# CGP-jr7c-c8cq-hxh9

com.auth0:java-jwt 4.1.0 calls String.split() without a limit on attacker-supplied token strings, enabling pre-auth heap amplification

## Affected packages

- **Ecosystem:** Maven
- **Package:** `com.auth0:java-jwt`
- **Package URL:** `pkg:maven/com.auth0/java-jwt`
- **Introduced:** 4.0.0-beta.0
- **Fixed:** 4.2.0
- **Weaknesses:** CWE-770

**Affected code:**

- `com.auth0.jwt.TokenUtils.splitToken(String)` (`lib/src/main/java/com/auth0/jwt/TokenUtils.java:18`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L/E:X/RL:X/RC:R`

## Details

### Root Cause

`TokenUtils.splitToken(String token)` (`lib/src/main/java/com/auth0/jwt/TokenUtils.java`, line 18) calls `token.split("\\.")` — the single-argument form of `String.split(regex)` — without a limit parameter. Java's `String.split(regex)` without a limit allocates a `String[]` containing one element per segment, retaining all leading and embedded empty segments while removing only trailing ones. A token string composed of N leading `'.'` characters (e.g., `'.'*10_000_000 + 'x'`) therefore causes the JVM to allocate a `String[]` of approximately N+1 references (roughly 4–8 bytes each, i.e. 4–8× the input size in array overhead) before any format or signature validation is performed. The `parts.length != 3` guard at line 22 that rejects the malformed token is reached only after this allocation has already completed.

This is a linear pre-authentication memory amplification: the heap allocation is proportional to the input length. It is not super-linear, and is bounded in practice by whatever request-size or header-size limit the calling HTTP framework or application layer imposes.

### Affected Locations

- **`com.auth0.jwt.TokenUtils.splitToken(String)`** (`lib/src/main/java/com/auth0/jwt/TokenUtils.java`, line 18): The sole location of the unbounded `split()` call. This is the only implementation of token splitting in the library; there are no sibling sinks performing the same operation.

The `splitToken` method is called from a single call site: `JWTDecoder(JWTParser, String)` constructor at `lib/src/main/java/com/auth0/jwt/JWTDecoder.java`, line 37. `JWTDecoder` is instantiated by:
- `JWTVerifier.verify(String token)` (`lib/src/main/java/com/auth0/jwt/JWTVerifier.java`, line 444) — the primary authenticated verification path.
- `JWT.decode(String token)` (`lib/src/main/java/com/auth0/jwt/JWT.java`, line 52) — the static unauthenticated decode path.
- `JWT.decodeJwt(String token)` (`lib/src/main/java/com/auth0/jwt/JWT.java`, line 37) — the instance unauthenticated decode path.

All three entry points reach the vulnerable `split()` call before any signature or format validation.

### Attack Vectors

**Pre-authentication linear memory amplification:**
An attacker who can submit an arbitrary string to any of the three entry points (`JWTVerifier.verify(String)`, `JWT.decode(String)`, or `JWT.decodeJwt(String)`) can send a string of many leading `'.'` characters — for example, `'.'*10_000_000 + 'x'` — to force allocation of a `String[]` with one reference per dot before any signature or format validation. The resulting heap pressure is approximately 4–8× the input size in array-reference overhead alone, in addition to the input string itself.

- **Complexity:** Single-step; no authentication or prior access required beyond the ability to submit a token string to the verifier.
- **Prerequisites:** The attacker must be able to submit an arbitrary string to a code path that calls `JWTVerifier.verify(String)`, `JWT.decode(String)`, or `JWT.decodeJwt(String)`. In practice, this is bounded by the HTTP framework's request-size or header-size limits.
- **Impact:** Linear heap amplification proportional to input size, occurring before signature verification. Sustained submission of large dot-prefixed strings can increase garbage-collection pressure or cause out-of-memory conditions in memory-constrained deployments.

### Impact

An attacker able to submit token strings to the library can cause pre-authentication heap allocation proportional to the input length. Confidentiality impact is None; integrity impact is None; availability impact is Low (memory pressure, potential out-of-memory in constrained environments). The amplification factor is linear (not super-linear), and the practical impact is bounded by the calling framework's input-size limits.

### Trace

1. Attacker submits a token string consisting of N leading `'.'` characters (e.g., `'.'*10_000_000 + 'x'`) to `JWTVerifier.verify(String)`, `JWT.decode(String)`, or `JWT.decodeJwt(String)`.
2. Each entry point constructs `new JWTDecoder(parser, token)` or `new JWTDecoder(token)`.
3. `JWTDecoder` constructor calls `TokenUtils.splitToken(token)` (`lib/src/main/java/com/auth0/jwt/JWTDecoder.java`, line 37).
4. `TokenUtils.splitToken()` calls `token.split("\\.")` at line 18 without a limit, allocating a `String[]` of N+1 elements.
5. The `parts.length != 3` check at line 22 rejects the token and throws `JWTDecodeException`, but the large array has already been allocated and must be garbage-collected.

## Sources

- [Advisory JSON](../../advisories/CGP-jr7c-c8cq-hxh9/CGP-jr7c-c8cq-hxh9.json)
- [Patch: CGP-jr7c-c8cq-hxh9-pkg:maven_com.auth0_java-jwt@4.1.0.patch](../../advisories/CGP-jr7c-c8cq-hxh9/CGP-jr7c-c8cq-hxh9-pkg:maven_com.auth0_java-jwt@4.1.0.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
