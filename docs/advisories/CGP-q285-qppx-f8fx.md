# CGP-q285-qppx-f8fx

REST-assured FormAuthFilter interpolates a server-controlled hidden-input name into a GPath template evaluated as Groovy code, enabling RCE on the test host.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `com.jayway.restassured:rest-assured`
- **Package URL:** `pkg:maven/com.jayway.restassured/rest-assured`
- **Introduced:** 2.3.3
- **Fixed:** 5.3.0
- **Weaknesses:** CWE-94

**Affected code:**

- `com.jayway.restassured.internal.filter.FormAuthFilter.filter(FilterableRequestSpecification,FilterableResponseSpecification,FilterContext)` (`rest-assured/src/main/groovy/com/jayway/restassured/internal/filter/FormAuthFilter.groovy:44,80-83`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:X/RC:R`

## Details

### Root Cause

`FormAuthFilter` (at `rest-assured/src/main/groovy/com/jayway/restassured/internal/filter/FormAuthFilter.groovy`) implements the CSRF auto-detection path of form-based authentication. When `formAuthConfig.isAutoDetectCsrfFieldName()` is true, the filter:

1. Fetches the login page via `ctx.send(given().spec(requestSpec).auth().none())`.
2. Parses the response as HTML using `new XmlPath(HTML, response.asString())`.
3. Extracts the CSRF field name at line 81: `html.getString(format(FIND_INPUT_TAG, "hidden"))` — this retrieves the `name` attribute of the first `<input type="hidden">` element from the server's HTML response. The result is entirely server-controlled.
4. At line 83, constructs a second GPath expression by raw string interpolation: `html.getString(format(FIND_INPUT_FIELD_WITH_NAME, csrfFieldName))`, where `FIND_INPUT_FIELD_WITH_NAME` (defined at line 44) is the constant `"html.depthFirst().grep { it.name() == 'input' && it.@name == '%s' }.collect { it.@value }.get(0)"`.

The `XmlPath.getString()` call routes through `XMLAssertion.getResult()` in `xml-path/src/main/groovy/com/jayway/restassured/assertion/XMLAssertion.groovy`. The `eval()` method at line 248 constructs a `GroovyShell` with a `Binding` containing the parsed document and calls `sh.evaluate(expr)` at line 250, where `expr` is the fully attacker-controlled GPath string. `GroovyShell.evaluate()` compiles and executes the expression as unrestricted Groovy code with full JVM access.

### Affected Locations

- `com.jayway.restassured.internal.filter.FormAuthFilter.filter()` — lines 44 and 80–83: the `FIND_INPUT_FIELD_WITH_NAME` template constant and the `String.format` interpolation of the server-controlled `csrfFieldName` into it, followed by `html.getString()` which triggers Groovy evaluation.
- `com.jayway.restassured.assertion.XMLAssertion.eval()` (in `xml-path/src/main/groovy/com/jayway/restassured/assertion/XMLAssertion.groovy`, line 248–250): the `GroovyShell` construction and `sh.evaluate(expr)` call that executes the injected expression. This is the ultimate execution sink; the injection originates in `FormAuthFilter`.

### Attack Vectors

**Primary — Malicious or compromised server returns crafted hidden input name:**

A server (or an on-path attacker performing a man-in-the-middle attack against a plain HTTP login endpoint) returns a login page containing an `<input type="hidden">` element whose `name` attribute is a Groovy expression fragment that breaks out of the string literal in the GPath template. The documented PoC payload is:

```
' }; Runtime.getRuntime().exec(new String[]{'/bin/sh','-c','...'}); x={ '
```

When this value is substituted into `FIND_INPUT_FIELD_WITH_NAME` via `String.format`, the resulting expression becomes:

```groovy
html.depthFirst().grep { it.name() == 'input' && it.@name == '' }; Runtime.getRuntime().exec(new String[]{'/bin/sh','-c','...'}); x={ '' }.collect { it.@value }.get(0)
```

This is valid Groovy that the `GroovyShell` compiles and executes, running the injected shell command in the JVM process.

**Secondary — MITM on HTTP login endpoints:**

Because REST-assured supports plain HTTP, an active network attacker positioned between the test client and the server can intercept the login page response and inject the crafted `name` attribute without compromising the server itself.

**Known bypass — `SecureASTCustomizer` is not applied:**

No `CompilerConfiguration` with `SecureASTCustomizer` or any other AST-level restriction is applied to the `GroovyShell` in `XMLAssertion.eval()`. The shell has unrestricted access to the full JVM class library, including `Runtime.exec()`, `ProcessBuilder`, reflection APIs, and file I/O.

### Prerequisites

- The caller must use `.auth().form(username, password, new FormAuthConfig().autoDetectCsrfFieldName())` or an equivalent configuration that sets `isAutoDetectCsrfFieldName()` to true. This is an advertised public API option, not an internal or undocumented feature.
- The targeted server (or an on-path attacker) must be able to control the `name` attribute of a hidden input field in the login page HTML response.
- If the server uses HTTPS, a network MITM requires a TLS interception capability; if HTTP, no such capability is needed.

### Impact

Arbitrary Groovy/Java code executes in the JVM process running the REST-assured test suite — typically a developer workstation or a CI/CD runner. The injected code runs with the full privileges of that process, which commonly include access to source code, build artifacts, environment variables containing secrets (API keys, cloud credentials, signing keys), SSH private keys, and CI/CD pipeline tokens. Confidentiality, integrity, and availability of the test host are all fully compromised.

### Execution Trace

1. Caller invokes `.auth().form(u, p, new FormAuthConfig().autoDetectCsrfFieldName())`.
2. `FormAuthFilter.filter()` is invoked during request processing.
3. Filter fetches the login page: `ctx.send(given().spec(requestSpec).auth().none())`.
4. Response HTML is parsed: `new XmlPath(HTML, response.asString())`.
5. `csrfFieldName` is extracted from the first hidden input's `name` attribute (line 81) — server-controlled value.
6. `format(FIND_INPUT_FIELD_WITH_NAME, csrfFieldName)` constructs the injected GPath string (line 83).
7. `html.getString(injectedPath)` is called, routing to `XMLAssertion.getResult()`.
8. `XMLAssertion.eval()` constructs `new GroovyShell(new Binding(params))` and calls `sh.evaluate(injectedPath)`.
9. The Groovy compiler compiles and executes the injected expression, including any embedded `Runtime.exec()` or equivalent calls.

## Sources

- [Advisory JSON](../../advisories/CGP-q285-qppx-f8fx/CGP-q285-qppx-f8fx.json)
- [Patch: CGP-q285-qppx-f8fx-pkg:maven_com.jayway.restassured_rest-assured@2.9.0.patch](../../advisories/CGP-q285-qppx-f8fx/CGP-q285-qppx-f8fx-pkg:maven_com.jayway.restassured_rest-assured@2.9.0.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
