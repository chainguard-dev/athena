# CGP-pqgh-898g-975x

XmlSchemaValidator explicitly sets ACCESS_EXTERNAL_DTD and ACCESS_EXTERNAL_SCHEMA to 'all', enabling XXE and SSRF via both schema documents and validated XML instances

## Affected packages

- **Ecosystem:** Maven
- **Package:** `org.mock-server:mockserver-core`
- **Package URL:** `pkg:maven/org.mock-server/mockserver-core`
- **Introduced:** 3.11
- **Fixed:** 6.0.0
- **Weaknesses:** CWE-611

**Affected code:**

- `org.mockserver.validator.xmlschema.XmlSchemaValidator.buildSchemaFactory()` (`mockserver-core/src/main/java/org/mockserver/validator/xmlschema/XmlSchemaValidator.java:59-71`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L/E:U/RL:X/RC:R`

## Details

### Root Cause

`XmlSchemaValidator.buildSchemaFactory()` (lines 59–71 of `mockserver-core/src/main/java/org/mockserver/validator/xmlschema/XmlSchemaValidator.java`) explicitly overrides the secure JAXP defaults:

```java
private SchemaFactory buildSchemaFactory() throws SAXNotRecognizedException, SAXNotSupportedException {
    SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
    schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "all");
    return schemaFactory;
}
```

Setting these properties to `"all"` re-enables all external access protocols that JAXP 1.5 disabled by default. The `XmlSchemaValidator` constructor uses this factory to compile the schema supplied in the `PUT /mockserver/expectation` body. The `isValid` method then validates inbound request bodies against the compiled schema:

```java
schema.newValidator().validate(new StreamSource(new ByteArrayInputStream(xml.getBytes(UTF_8))));
```

Both the schema document and the validated XML instance can trigger external resource fetches. Additionally, when the schema string ends with `.xsd`, the constructor opens it via `FileReader.openReaderToFileFromClassPathOrPath(schema)`, allowing a constrained read of `.xsd` files from the classpath or filesystem.

### Affected Locations

- `org.mockserver.validator.xmlschema.XmlSchemaValidator.buildSchemaFactory()` — lines 59–71: `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` are set to `"all"`, enabling external entity and schema resolution for both the schema document and validated XML instances.

### Attack Vectors

**Vector 1 — XXE/SSRF via attacker-controlled schema document**
An unauthenticated attacker sends `PUT /mockserver/expectation` with an `xmlSchema` body matcher containing an XSD that references an external entity or schema location:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">&xxe;</xs:schema>
```
The `SchemaFactory` resolves the external reference when compiling the schema, reading local files or making outbound HTTP requests from the MockServer host.

**Vector 2 — XXE/SSRF via validated XML instance body**
Once an XML schema expectation is registered, any inbound request whose body is validated against it can carry an XXE payload. The `schema.newValidator().validate(...)` call resolves external entities in the instance document.

**Vector 3 — Constrained path traversal via .xsd suffix**
If the schema string ends with `.xsd`, the constructor opens it via `FileReader.openReaderToFileFromClassPathOrPath(schema)`. An attacker can supply a path such as `../../sensitive.xsd` to read `.xsd` files outside the intended classpath location.

**Precondition:** The attacker must be able to register an XML schema expectation via `PUT /mockserver/expectation`, which is unauthenticated by default.

### Impact

An attacker can read arbitrary files accessible to the MockServer process, perform SSRF to internal network services or cloud metadata endpoints, and (via the `.xsd` path variant) read `.xsd` files from the filesystem. Confidentiality of the host system is compromised; availability may be impacted by resource exhaustion from external fetches.

### Trace

1. Attacker sends `PUT /mockserver/expectation` with `xmlSchema` body matcher containing attacker-controlled XSD
2. `HttpRequestMatcher.withBody(XML_SCHEMA)` creates a new `XmlSchemaMatcher`
3. `XmlSchemaMatcher` constructs `new XmlSchemaValidator(logger, schema)`
4. `XmlSchemaValidator` constructor calls `buildSchemaFactory()` — sets `ACCESS_EXTERNAL_DTD="all"` and `ACCESS_EXTERNAL_SCHEMA="all"`
5. `schemaFactory.newSchema(new StreamSource(new StringReader(schema)))` compiles the schema, resolving external references
6. Later, `XmlSchemaMatcher.matches` calls `schema.newValidator().validate(StreamSource(attackerRequestBody))`
7. External entities in the instance document are resolved — file read or SSRF occurs

## Sources

- [Advisory JSON](../../advisories/CGP-pqgh-898g-975x/CGP-pqgh-898g-975x.json)
- [Patch: CGP-pqgh-898g-975x-pkg:maven_org.mock-server_mockserver-core@5.15.0.patch](../../advisories/CGP-pqgh-898g-975x/CGP-pqgh-898g-975x-pkg:maven_org.mock-server_mockserver-core@5.15.0.patch)

---

Published 2026-11-12T16:00:00Z · Modified 2026-11-12T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
