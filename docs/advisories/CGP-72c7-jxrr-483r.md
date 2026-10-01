# CGP-72c7-jxrr-483r

UrlValidator.isValidAuthority() crashes with ArrayIndexOutOfBoundsException on URLs with hostnames containing more than 10 labels.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `commons-validator:commons-validator`
- **Package URL:** `pkg:maven/commons-validator/commons-validator`
- **Introduced:** 1.1.0
- **Fixed:** 1.3.1
- **Weaknesses:** CWE-400

**Affected code:**

- `org.apache.commons.validator.UrlValidator.isValidAuthority(String)` (`src/share/org/apache/commons/validator/UrlValidator.java:355-395`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:X/RL:X/RC:R`

## Details

### Root Cause

`UrlValidator.isValidAuthority(String authority)` (lines 355–395 of `src/share/org/apache/commons/validator/UrlValidator.java`) allocates a fixed-size `String[10]` array:

```java
String[] domainSegment = new String[10];
boolean match = true;
int segmentCount = 0;
int segmentLength = 0;
Perl5Util atomMatcher = new Perl5Util();

while (match) {
    match = atomMatcher.match(ATOM_PATTERN, hostIP);
    if (match) {
        domainSegment[segmentCount] = atomMatcher.group(1);  // segmentCount not bounded to array length 10
        segmentLength = domainSegment[segmentCount].length() + 1;
        ...
        segmentCount++;
    }
}
```

The loop variable `segmentCount` is incremented once per dot-separated label with no guard against `segmentCount >= 10`. When a URL hostname has 11 or more labels, the write at `domainSegment[10]` throws `ArrayIndexOutOfBoundsException`.

### Affected Locations

- `org.apache.commons.validator.UrlValidator.isValidAuthority(String)` — lines 355–395 of `src/share/org/apache/commons/validator/UrlValidator.java`. This is the direct sink. The exception propagates upward through `isValid(String)` without being caught.

### Attack Vectors

- **Crafted URL with 11+ hostname labels**: An attacker supplies a URL such as `http://a.a.a.a.a.a.a.a.a.a.com/` (11 dot-separated labels in the hostname). The public API `UrlValidator.isValid(String)` or `GenericValidator.isUrl(String)` is called with this input. The `isValidAuthority` method iterates to `segmentCount == 10`, writes past the end of the 10-element array, and throws `ArrayIndexOutOfBoundsException`, crashing the request thread.
  - **Complexity**: single short crafted input, no authentication or special access required
  - **Prerequisites**: the application must pass user-supplied input to `UrlValidator.isValid(String)` or `GenericValidator.isUrl(String)` without a surrounding try/catch for `ArrayIndexOutOfBoundsException`
  - **Targets**: availability of the request-handling thread; applications that do not catch unchecked exceptions will expose this as a denial-of-service

### Impact

Any application that feeds user-supplied input into `GenericValidator.isUrl()` or `UrlValidator.isValid()` without catching `ArrayIndexOutOfBoundsException` will have the request thread terminated by the unchecked exception. This enables a trivial denial-of-service with a single short URL string. Confidentiality and integrity are not affected.

### Trace

1. Caller invokes `UrlValidator.isValid(value)` or `GenericValidator.isUrl(value)` with a URL whose hostname has 11+ labels.
2. `isValid` calls `isValidAuthority(matchUrlPat.group(PARSE_URL_AUTHORITY))`.
3. `isValidAuthority` enters the hostname-label `while` loop; on the 11th iteration `segmentCount == 10`, and `domainSegment[10] = atomMatcher.group(1)` throws `ArrayIndexOutOfBoundsException`.
4. The exception propagates uncaught through `isValidAuthority` and `isValid` to the caller.

## Sources

- [Advisory JSON](../../advisories/CGP-72c7-jxrr-483r/CGP-72c7-jxrr-483r.json)
- [Patch: CGP-72c7-jxrr-483r-pkg:maven_commons-validator_commons-validator@1.2.0.patch](../../advisories/CGP-72c7-jxrr-483r/CGP-72c7-jxrr-483r-pkg:maven_commons-validator_commons-validator@1.2.0.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
