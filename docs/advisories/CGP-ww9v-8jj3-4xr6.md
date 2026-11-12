# CGP-ww9v-8jj3-4xr6

DashboardHandler in mockserver-netty concatenates unsanitized URL path onto classpath prefix, enabling path traversal to read arbitrary classpath resources.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `org.mock-server:mockserver-netty`
- **Package URL:** `pkg:maven/org.mock-server/mockserver-netty`
- **Introduced:** 5.4.1
- **Fixed:** 6.0.0
- **Weaknesses:** CWE-22

**Affected code:**

- `org.mockserver.dashboard.DashboardHandler.renderDashboard(ChannelHandlerContext,HttpRequest)` (`mockserver-netty/src/main/java/org/mockserver/dashboard/DashboardHandler.java:50-79`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:X/RL:X/RC:R`

## Details

### Root Cause

`DashboardHandler.renderDashboard()` (lines 50–79 of `mockserver-netty/src/main/java/org/mockserver/dashboard/DashboardHandler.java`) concatenates the attacker-controlled URL suffix directly onto a fixed classpath prefix:

```java
String path = substringAfter(request.getPath().getValue(), PATH_PREFIX + "/dashboard");
if (path.isEmpty() || path.equals("/")) {
    path = "/index.html";
}
try (InputStream contentStream = DashboardHandler.class.getResourceAsStream("/org/mockserver/dashboard" + path)) {
```

There is no call to normalize the path, strip `..` sequences, or validate that the resolved resource falls within the `/org/mockserver/dashboard` subtree. The MIME type is looked up from the file extension after the last `.`, but this lookup does not gate access — if the extension is not in the MIME map, `MIME_MAP.get(extension)` returns `null`, which is passed as the `Content-Type` header, but the resource bytes are still returned.

### Affected Locations

- `org.mockserver.dashboard.DashboardHandler.renderDashboard(ChannelHandlerContext, HttpRequest)` (lines 50–79): the sink where the unsanitized path is concatenated and passed to `getResourceAsStream()`.

### Attack Vectors

- **Directory traversal via `..` sequences**: When MockServer runs with an exploded classpath (IDE, exploded WAR, Spring Boot devtools), a request such as `GET /mockserver/dashboard/../../../../application.properties` causes `getResourceAsStream("/org/mockserver/dashboard/../../../../application.properties")` to resolve to `application.properties` at the classpath root, returning its contents to the attacker.
- **Encoded traversal variants**: URL-encoded or double-encoded `..` sequences (e.g., `%2e%2e`, `%2e%2e%2f`) may bypass simple string-level checks if any intermediate layer decodes them before the path reaches `getResourceAsStream()`.
- **Arbitrary classpath resource disclosure**: Accessible resources include `application.properties`, `logback.xml`, JKS keystores, `.class` bytecode, and any other file on the classpath.
- **Packed JAR limitation**: When running purely from a packed JAR, the `ZipFile` lookup is exact-string, so `..` sequences typically do not resolve across JAR entry boundaries, limiting exploitability to exploded-directory deployments.

### Impact

An unauthenticated remote attacker can read arbitrary classpath resources — including application configuration files, credentials, keystores, and bytecode — when MockServer is deployed with an exploded classpath. Confidentiality impact is high in affected deployment configurations; integrity and availability are not directly affected.

### Trace

`HttpRequestHandler.channelRead0()` receives `GET /mockserver/dashboard/...` → `dashboardHandler.renderDashboard(ctx, request)` → `path = substringAfter(request.getPath().getValue(), '/mockserver/dashboard')` (attacker-controlled, no sanitization) → `DashboardHandler.class.getResourceAsStream('/org/mockserver/dashboard' + path)` → bytes streamed back to client.

## Sources

- [Advisory JSON](../../advisories/CGP-ww9v-8jj3-4xr6/CGP-ww9v-8jj3-4xr6.json)
- [Patch: CGP-ww9v-8jj3-4xr6-pkg:maven_org.mock-server_mockserver-netty@5.13.1.patch](../../advisories/CGP-ww9v-8jj3-4xr6/CGP-ww9v-8jj3-4xr6-pkg:maven_org.mock-server_mockserver-netty@5.13.1.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
