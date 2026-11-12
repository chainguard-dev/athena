# CGP-29c2-rpxq-q9xm

AbstractFileSource path containment check uses startsWith() without a separator, allowing sibling-directory escape in WireMock file operations.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `com.github.tomakehurst:wiremock-standalone`
- **Package URL:** `pkg:maven/com.github.tomakehurst/wiremock-standalone`
- **Introduced:** 2.16.0
- **Fixed:** 3.0.0-beta-1
- **Weaknesses:** CWE-22

**Affected code:**

- `com.github.tomakehurst.wiremock.common.AbstractFileSource.assertFilePathIsUnderRoot(String)` (`src/main/java/com/github/tomakehurst/wiremock/common/AbstractFileSource.java:150-166`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N/E:X/RL:X/RC:R`

## Details

### Root Cause

`AbstractFileSource.assertFilePathIsUnderRoot(String path)` (lines 150–166 of `AbstractFileSource.java`) performs the following check:

```java
String rootPath = rootDirectory.getCanonicalPath();
String filePath = file.isAbsolute() ?
    new File(path).getCanonicalPath() :
    new File(rootDirectory, path).getCanonicalPath();
if (!filePath.startsWith(rootPath)) {
    throw new NotAuthorisedException(...);
}
```

Both paths are canonicalised, which correctly defeats `../` traversal sequences. However, the containment check uses `String.startsWith(rootPath)` without appending a file separator character (`/` or the platform separator). As a result, a sibling directory whose name shares the root directory name as a prefix passes the check:

- Root: `/opt/wiremock/__files`
- Sibling: `/opt/wiremock/__files-archive`
- Check: `"/opt/wiremock/__files-archive/secret.txt".startsWith("/opt/wiremock/__files")` → `true` (incorrectly passes)

This check guards all file access operations in `AbstractFileSource`:
- `getBinaryFileNamed(String)` and `getTextFileNamed(String)` — read operations used when serving stub body files
- `writableFileFor(String)` — called by `writeTextFile()`, `writeBinaryFile()`, and `deleteFile()` — write and delete operations

The `bodyFileName` field in stub mappings (set via the admin API) and the rendered `filePathTemplate` in `ResponseTemplateTransformer` (when response templating is enabled) both flow into `getBinaryFileNamed()`. The `PUT /__admin/files/{name}` endpoint and recorder snapshot feature flow into `writeBinaryFile()`/`writeTextFile()`.

### Affected Locations

- `com.github.tomakehurst.wiremock.common.AbstractFileSource.assertFilePathIsUnderRoot(String)` (lines 150–166): the flawed containment check that guards all read and write operations.
- `com.github.tomakehurst.wiremock.common.AbstractFileSource.getBinaryFileNamed(String)` (line 42): calls `assertFilePathIsUnderRoot` before constructing a `BinaryFile` — read path.
- `com.github.tomakehurst.wiremock.common.AbstractFileSource.getTextFileNamed(String)` (line 48): calls `assertFilePathIsUnderRoot` before constructing a `TextFile` — read path.
- `com.github.tomakehurst.wiremock.common.AbstractFileSource.writableFileFor(String)` (line 113): calls `assertFilePathIsUnderRoot` before returning a writable `File` — write/delete path.

### Attack Vectors

**Sibling-directory read via bodyFileName:** An attacker registers a stub mapping (via the unauthenticated admin API) with `bodyFileName` set to a path that resolves into a sibling directory sharing the `__files` prefix (e.g. `../wiremock/__files-archive/sensitive.json`). When a request matches the stub, WireMock reads the file from the sibling directory and returns its contents as the response body.

**Sibling-directory write via PUT /__admin/files/{name}:** An attacker sends `PUT /__admin/files/../__files-archive/injected.txt` (or a name that after canonicalisation resolves into the sibling directory). WireMock writes the supplied content to the sibling directory.

**Templated bodyFileName (response templating enabled):** When response templating is active, the `bodyFileName` field is rendered as a Handlebars template. An attacker can craft a stub where the rendered path escapes into a sibling directory.

### Impact

An attacker who can reach the admin API (unauthenticated by default) can read files from sibling directories that share the `__files` directory name as a prefix, and write or delete files in those sibling directories. Practical exploitation requires a sibling directory with a matching name prefix to exist on the filesystem, which limits real-world impact but represents a classic CWE-22 boundary failure.

### Trace

`bodyFileName` in stub mapping JSON (admin API) or templated `filePathTemplate` → `AbstractFileSource.getBinaryFileNamed(name)` → `assertFilePathIsUnderRoot(name)`: `filePath.startsWith(rootPath)` passes for sibling-prefix directories → `new BinaryFile(new File(rootDirectory, name).toURI())` reads file outside intended root

## Sources

- [Advisory JSON](../../advisories/CGP-29c2-rpxq-q9xm/CGP-29c2-rpxq-q9xm.json)
- [Patch: CGP-29c2-rpxq-q9xm-pkg:maven_com.github.tomakehurst_wiremock-standalone@2.27.2.patch](../../advisories/CGP-29c2-rpxq-q9xm/CGP-29c2-rpxq-q9xm-pkg:maven_com.github.tomakehurst_wiremock-standalone@2.27.2.patch)

---

Published 2026-11-12T16:00:00Z · Modified 2026-11-12T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
