# CGP-3x2p-3qw2-2ghh

TokenPreauth in kerb-server 2.0.2 skips JWT signature verification when the request arrives over HTTPS, allowing forged unsigned tokens to authenticate as any principal.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `org.apache.kerby:kerb-server`
- **Package URL:** `pkg:maven/org.apache.kerby/kerb-server`
- **Introduced:** 1.0.0
- **Fixed:** 2.1.0
- **Weaknesses:** CWE-347

**Affected code:**

- `org.apache.kerby.kerberos.kerb.server.preauth.token.TokenPreauth.verify(KdcRequest,PluginRequestContext,PaDataEntry)` (`kerby-kerb/kerb-server/src/main/java/org/apache/kerby/kerberos/kerb/server/preauth/token/TokenPreauth.java:99-102`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/E:U/RL:X/RC:R`

## Details

### Root Cause

`TokenPreauth.verify()` (lines 99–102 of `kerby-kerb/kerb-server/src/main/java/org/apache/kerby/kerberos/kerb/server/preauth/token/TokenPreauth.java`) enforces JWT signature verification with the following guard:

```java
authToken = tokenDecoder.decodeFromBytes(token.getTokenValue());
if (!tokenDecoder.isSigned() && !kdcRequest.isHttps()) {
    throw new KrbException("Token should be signed.");
}
```

The logical conjunction (`&&`) means the exception is thrown only when **both** conditions are true: the token is unsigned **and** the request did not arrive over HTTPS. When `kdcRequest.isHttps()` returns `true`, the right-hand operand short-circuits the condition, and an unsigned JWT is silently accepted. TLS in the HTTPS transport authenticates the server to the client; it does not authenticate the client's token claim. An attacker who can reach the HTTPS KDC endpoint can craft a JWT with an arbitrary `sub` field, submit it as `PA-TOKEN-REQUEST` padata, and have it accepted as proof of identity for the named principal.

On the non-HTTPS path, the padata is additionally unsealed with an armor key (`EncryptionUtil.unseal(encData, clientKey, KeyUsage.PA_TOKEN, PaTokenRequest.class)`), providing a layer of protection absent on the HTTPS path where the token is decoded directly from plaintext.

### Affected Locations

- `org.apache.kerby.kerberos.kerb.server.preauth.token.TokenPreauth.verify(KdcRequest,PluginRequestContext,PaDataEntry)` at lines 99–102: the sink where the JWT signature check is bypassed when `kdcRequest.isHttps()` is true.

### Attack Vectors

**Forged unsigned JWT over HTTPS KDC transport:**
An attacker who can reach the HTTPS KDC endpoint constructs a `PA-TOKEN-REQUEST` padata containing an unsigned JWT with an arbitrary `sub` claim naming the target principal. The issuer must be in the configured issuers list (a known value from KDC configuration). The KDC decodes the token, skips the signature check because `isHttps()` is true, validates the audience against the server principal, sets the token on the request via `kdcRequest.setToken(authToken)`, and proceeds to issue a TGT for the claimed principal. The attacker obtains a valid TGT for any principal whose issuer is configured.

### Impact

An unauthenticated remote attacker who can reach the HTTPS KDC endpoint and knows a configured token issuer name can obtain a valid Kerberos TGT for any principal by presenting a forged unsigned JWT. This constitutes a complete authentication bypass for deployments using the HTTPS KDC transport with token preauth enabled. Confidentiality and integrity of all services protected by this KDC are fully compromised in such deployments.

### Trace

`KdcRequest.process()` → `preauth()` → `TokenPreauth.verify(KdcRequest,PluginRequestContext,PaDataEntry)`: `paTokenRequest = KrbCodec.decode(paData.getPaDataValue(), PaTokenRequest.class)` [plaintext decode on HTTPS path, no armor-key unsealing] → `tokenDecoder.decodeFromBytes(token.getTokenValue())` → `if (!tokenDecoder.isSigned() && !kdcRequest.isHttps())` [condition false when isHttps()==true — signature check skipped] → `kdcRequest.setToken(authToken)` → `AsRequest.checkClient()` uses `getToken().getSubject()` as the authenticated principal → TGT issued for attacker-controlled subject.

## Sources

- [Advisory JSON](../../advisories/CGP-3x2p-3qw2-2ghh/CGP-3x2p-3qw2-2ghh.json)
- [Patch: CGP-3x2p-3qw2-2ghh-pkg:maven_org.apache.kerby_kerb-server@2.0.3.patch](../../advisories/CGP-3x2p-3qw2-2ghh/CGP-3x2p-3qw2-2ghh-pkg:maven_org.apache.kerby_kerb-server@2.0.3.patch)

---

Published 2026-11-12T16:00:00Z · Modified 2026-11-12T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
