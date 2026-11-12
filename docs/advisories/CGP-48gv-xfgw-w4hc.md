# CGP-48gv-xfgw-w4hc

WireMock DeleteStubFileTask deletes files via user-supplied path with no root-containment check, enabling path traversal deletion on Windows

## Affected packages

- **Ecosystem:** Maven
- **Package:** `com.github.tomakehurst:wiremock-standalone`
- **Package URL:** `pkg:maven/com.github.tomakehurst/wiremock-standalone`
- **Introduced:** 2.14.0
- **Fixed:** 3.0.0-beta-1
- **Weaknesses:** CWE-22

**Affected code:**

- `com.github.tomakehurst.wiremock.admin.tasks.DeleteStubFileTask.execute(Admin,Request,PathParams)` (`src/main/java/com/github/tomakehurst/wiremock/admin/tasks/DeleteStubFileTask.java:33-35`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L`

## Details

### Root Cause

`DeleteStubFileTask.execute()` (lines 33–35) performs:

```java
FileSource fileSource = admin.getOptions().filesRoot().child(FILES_ROOT);
File filename = new File(fileSource.getPath(), pathParams.get("filename"));
boolean deleted = filename.delete();
```

The `pathParams.get("filename")` value is the raw `{filename}` segment from the `DELETE /__admin/files/{filename}` URL, parsed by `AdminUriTemplate` which splits the request URI on `/`. No canonicalization, no `getCanonicalPath()` call, and no root-containment check is applied before `delete()` is invoked.

The sibling write endpoint (`PUT /__admin/files/{filename}` → `EditStubFileTask`) routes through `FileSource.writeBinaryFile()` → `AbstractFileSource.writableFileFor()` → `assertFilePathIsUnderRoot()`, which computes canonical paths and verifies containment. `DeleteStubFileTask` does not use this path and has no equivalent guard.

### Affected Locations

- `com.github.tomakehurst.wiremock.admin.tasks.DeleteStubFileTask.execute(Admin,Request,PathParams)` (lines 33–35): the sole delete sink, with no containment check.

The cross-codebase hunt found no other direct `File.delete()` calls on user-supplied paths in the admin task classes. The `AbstractFileSource.deleteFile(String)` method (which does call `writableFileFor()` and thus `assertFilePathIsUnderRoot()`) is not used by `DeleteStubFileTask`.

### Attack Vectors

**Path traversal file deletion on Windows via backslash:**
`AdminUriTemplate` splits the request URI on `/`, so the `{filename}` segment cannot contain a forward slash on any platform. However, on Windows, the segment may contain backslash (`\`) characters, which `java.io.File` treats as a path separator. An attacker can send:
```
DELETE /__admin/files/..\..\..\Windows\win.ini
```
This constructs `new File(filesRoot, "..\\..\\..\\Windows\\win.ini")` and calls `delete()`, deleting an arbitrary file outside the `__files` root.

**Negative-space gap on Linux:**
On Linux, forward-slash traversal is blocked by the URI template splitting, but the absence of the containment check represents a structural gap relative to the write path. Any future change to URL parsing or path handling could expose traversal on Linux without a corresponding guard being added.

**Unauthenticated access:**
The endpoint is reachable without credentials in the default configuration (NoAuthenticator). Combined with the wildcard CORS policy on the admin context, it is also reachable cross-origin from a victim's browser.

### Impact

On Windows, an unauthenticated remote attacker can delete arbitrary files accessible to the WireMock process outside the configured `__files` root directory. This can be used to delete application binaries, configuration files, or other critical system files, causing denial of service or enabling further exploitation.

### Trace

1. Attacker sends `DELETE /__admin/files/..\..\..\Windows\win.ini` (Windows).
2. `AdminRequestHandler` → `NoAuthenticator.authenticate()` → passes.
3. `AdminRoutes` → `DeleteStubFileTask.execute(admin, request, pathParams)`.
4. `pathParams.get("filename")` returns `"..\\..\\..\\Windows\\win.ini"`.
5. `new File(fileSource.getPath(), "..\\..\\..\\Windows\\win.ini")` resolves to a path outside the `__files` root.
6. `filename.delete()` deletes the target file.

## Sources

- [Advisory JSON](../../advisories/CGP-48gv-xfgw-w4hc/CGP-48gv-xfgw-w4hc.json)
- [Patch: CGP-48gv-xfgw-w4hc-pkg:maven_com.github.tomakehurst_wiremock-standalone@2.27.2.patch](../../advisories/CGP-48gv-xfgw-w4hc/CGP-48gv-xfgw-w4hc-pkg:maven_com.github.tomakehurst_wiremock-standalone@2.27.2.patch)

---

Published 2026-11-12T16:00:00Z · Modified 2026-11-12T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
