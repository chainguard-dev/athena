# CGP-9x7f-cpwh-f59q

Webserver.process() does not close the client socket on exception, leaking file descriptors; a malformed request line also causes StringIndexOutOfBoundsException.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `org.javassist:javassist`
- **Package URL:** `pkg:maven/org.javassist/javassist`
- **Introduced:** 0
- **Fixed:** 3.32.0-GA
- **Weaknesses:** CWE-404

**Affected code:**

- `javassist.tools.web.Webserver.process(Socket)` (`src/main/javassist/tools/web/Webserver.java:258`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`

## Details

### Root Cause

`Webserver.process(Socket clnt)` at line ~258 of `src/main/javassist/tools/web/Webserver.java`:

```java
try {
    doReply(in, out, cmd);
}
catch (BadHttpRequest e) {
    replyError(out, e);
}
// clnt.close() is called here, but only if no other exception escapes
```

The `doReply` method calls `cmd.substring(5, cmd.indexOf(' ', 5))`. If the request line has no space after position 5 (e.g., `GET /`), `cmd.indexOf(' ', 5)` returns -1, and `cmd.substring(5, -1)` throws `StringIndexOutOfBoundsException`. This exception is not caught by the `BadHttpRequest` handler, escapes `process()`, and the socket is not closed. Each such request leaks one file descriptor.

### Affected Locations

- `src/main/javassist/tools/web/Webserver.java`, line 258 — `process(Socket)`: missing `try/finally` for `clnt.close()`; malformed request line causes `StringIndexOutOfBoundsException` and FD leak.

### Attack Vectors

- **Malformed HTTP request line**: An attacker sends a request line with no space after the path (e.g., `GET /`). `doReply` throws `StringIndexOutOfBoundsException`, the socket is not closed, and a file descriptor is leaked.
- **FD exhaustion via repeated malformed requests**: An attacker repeatedly sends malformed requests, eventually exhausting the process's file descriptor limit and causing all subsequent socket operations to fail.

### Impact

Denial of service (file descriptor exhaustion) for any application that starts `Webserver`. The server binds to all interfaces by default and requires no authentication.

## Sources

- [Advisory JSON](../../advisories/CGP-9x7f-cpwh-f59q/CGP-9x7f-cpwh-f59q.json)
- [Patch: CGP-9x7f-cpwh-f59q-pkg:maven_org.javassist_javassist@3.31.0-GA.patch](../../advisories/CGP-9x7f-cpwh-f59q/CGP-9x7f-cpwh-f59q-pkg:maven_org.javassist_javassist@3.31.0-GA.patch)

---

Published 2026-11-12T16:00:00Z · Modified 2026-11-12T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
