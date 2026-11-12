# CGP-qjm4-c96g-8hhw

Unsigned SAML assertions accepted whenever any mutual-TLS client certificate is present, with no binding of TLS client identity to assertion Issuer or subject.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `org.apache.cxf:cxf-rt-rs-security-oauth2-saml`
- **Package URL:** `pkg:maven/org.apache.cxf/cxf-rt-rs-security-oauth2-saml`
- **Introduced:** 2.7.4
- **Fixed:** 4.2.3
- **Weaknesses:** CWE-345

**Affected code:**

- `org.apache.cxf.rs.security.oauth2.grants.saml.Saml2BearerGrantHandler.validateToken(Message,SamlAssertionWrapper)` (`rt/rs/security/oauth-parent/oauth2-saml/src/main/java/org/apache/cxf/rs/security/oauth2/grants/saml/Saml2BearerGrantHandler.java:173-228`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N/E:X/RL:X/RC:R`

## Details

### Root Cause

`Saml2BearerGrantHandler.validateToken` (lines 173–228 of `rt/rs/security/oauth-parent/oauth2-saml/src/main/java/org/apache/cxf/rs/security/oauth2/grants/saml/Saml2BearerGrantHandler.java`) handles unsigned assertions in the following `else` branch:

```java
} else if (getTLSCertificates(message) == null) {
    throw new OAuthServiceException(OAuthConstants.INVALID_GRANT);
}
```

The only check performed is that `TLSSessionInfo.getPeerCertificates()` is non-null — i.e., that the transport session has *some* client TLS certificate. The code never:
- Compares the TLS client certificate's subject DN or issuer to the assertion's `<Issuer>` element.
- Verifies that the TLS client is authorized to assert on behalf of the named subject.
- Checks any binding between the TLS identity and the assertion content.

After this check, execution falls through to `samlOAuthValidator.validate(message, assertion)`, which validates audience and `SubjectConfirmationData` but performs no TLS-identity-to-assertion binding either.

### Affected Locations

- `org.apache.cxf.rs.security.oauth2.grants.saml.Saml2BearerGrantHandler.validateToken(Message,SamlAssertionWrapper)` — the unsigned-assertion `else` branch within lines 173–228 of `rt/rs/security/oauth-parent/oauth2-saml/src/main/java/org/apache/cxf/rs/security/oauth2/grants/saml/Saml2BearerGrantHandler.java`. The `createAccessToken` method calls `validateToken` and, if it returns without throwing, immediately calls `doCreateAccessToken` to issue an access token for the asserted subject.

### Attack Vectors

**Unsigned assertion impersonation over mutual TLS (documented attack scenario):**
In a deployment where the token endpoint is configured for two-way TLS and `Saml2BearerGrantHandler` is registered, any client that can complete the TLS handshake (any certificate accepted by the container truststore — for example, any partner or tenant client certificate) can submit an unsigned SAML assertion naming any user as the subject. The handler's only check is that peer certificates are non-null; it issues an access token for the attacker-chosen subject.

Dataflow: `POST /token` (2-way TLS, any accepted client cert) → `createAccessToken()` → `validateToken()`: `assertion.isSigned() == false` → only check performed is that `TLSSessionInfo` peer certificates are non-null → `SamlOAuthValidator.validate()` (audience + `SubjectConfirmationData` only) → access token issued for arbitrary asserted subject.

**Prerequisites:** `Saml2BearerGrantHandler` must be registered on the token endpoint, and the endpoint must be deployed with two-way TLS (without mutual TLS, unsigned assertions are rejected). The attacker must hold a client certificate accepted by the container truststore.

### Impact

Any lower-trust authenticated party (e.g., a partner or tenant with a valid client certificate) can impersonate any user, including privileged accounts, by submitting unsigned assertions. This constitutes privilege escalation across identities within the same deployment. Confidentiality and integrity of all resources protected by the authorization server are compromised for the impersonated identities.

### Trace

1. Attacker (holding a valid client TLS certificate) POSTs `assertion=<base64url-encoded unsigned SAML>` to the token endpoint over a mutual-TLS connection.
2. `Saml2BearerGrantHandler.createAccessToken(Client, MultivaluedMap)` extracts the `assertion` parameter.
3. `decodeAssertion(String)` base64url-decodes the assertion bytes.
4. `readToken(InputStream)` parses the XML.
5. `new SamlAssertionWrapper(token)` wraps the parsed element.
6. `validateToken(Message, SamlAssertionWrapper)` is called.
7. `assertion.isSigned()` returns `false`.
8. `getTLSCertificates(message)` returns the attacker's peer certificate array (non-null).
9. The `else if` condition is false; no exception is thrown.
10. `samlOAuthValidator.validate(message, assertion)` checks audience and subject confirmation — passes if the attacker set these correctly.
11. `doCreateAccessToken()` issues an access token for the attacker-chosen subject.

## Sources

- [Advisory JSON](../../advisories/CGP-qjm4-c96g-8hhw/CGP-qjm4-c96g-8hhw.json)
- [Patch: CGP-qjm4-c96g-8hhw-pkg:maven_org.apache.cxf_cxf-rt-rs-security-oauth2-saml@4.2.0.patch](../../advisories/CGP-qjm4-c96g-8hhw/CGP-qjm4-c96g-8hhw-pkg:maven_org.apache.cxf_cxf-rt-rs-security-oauth2-saml@4.2.0.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
