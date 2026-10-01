# CGP-xpq5-jm7p-884r

Signature stripping authentication bypass via generic parse() accepting unsigned tokens when key is configured.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `io.jsonwebtoken:jjwt`
- **Package URL:** `pkg:maven/io.jsonwebtoken/jjwt`
- **Introduced:** 0.1
- **Fixed:** 0.12.0
- **Weaknesses:** CWE-347

**Affected code:**

- `io.jsonwebtoken.impl.DefaultJwtParser.parse(String)` (`src/main/java/io/jsonwebtoken/impl/DefaultJwtParser.java:237-239,280,416-420`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

## Details

### Root Cause
The parser's signature-verification block is gated solely on the presence of a non-empty third segment (`base64UrlEncodedDigest != null`). If an attacker strips the third segment (sending a token with a trailing dot but no signature), the entire signature-verification block is skipped, even if a key is configured. The parser then returns an unsigned `DefaultJwt` containing attacker-controlled claims.

### Attack Vectors
An unauthenticated remote attacker can send an unsigned token (e.g., `eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.`) to an application using the generic `parse()` method. The parser accepts the token and returns the claims as authentic, enabling complete authentication bypass.

### Remediation
Throw a `MalformedJwtException` or `SignatureException` if `base64UrlEncodedDigest == null` and a key, keyBytes, or signingKeyResolver is configured.

## Sources

- [Advisory JSON](../../advisories/CGP-xpq5-jm7p-884r/CGP-xpq5-jm7p-884r.json)
- [Patch: CGP-xpq5-jm7p-884r-pkg:maven_io.jsonwebtoken_jjwt@0.7.0.patch](../../advisories/CGP-xpq5-jm7p-884r/CGP-xpq5-jm7p-884r-pkg:maven_io.jsonwebtoken_jjwt@0.7.0.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
