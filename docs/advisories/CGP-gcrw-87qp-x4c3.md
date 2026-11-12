# CGP-gcrw-87qp-x4c3

PhoneNumberUtil.isAlphaNumber() bypasses the MAX_INPUT_STRING_LENGTH guard, enabling O(n²) ReDoS via VALID_PHONE_NUMBER_PATTERN and EXTN_PATTERN on unbounded input.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `com.googlecode.libphonenumber:libphonenumber`
- **Package URL:** `pkg:maven/com.googlecode.libphonenumber/libphonenumber`
- **Introduced:** 3.1
- **Fixed:** 9.0.36
- **Weaknesses:** CWE-1333

**Affected code:**

- `com.google.i18n.phonenumbers.PhoneNumberUtil.isViablePhoneNumber(CharSequence)` (`java/libphonenumber/src/com/google/i18n/phonenumbers/PhoneNumberUtil.java:772-778`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:X/RL:X/RC:R`

## Details

### Root Cause

`PhoneNumberUtil.isAlphaNumber(CharSequence number)` (line 2552) is a public API method that accepts an arbitrary `CharSequence` from the caller. It immediately delegates to two internal methods without enforcing any input-length limit:

1. `isViablePhoneNumber(number)` (line 2553 call → method at line 772): executes `VALID_PHONE_NUMBER_PATTERN.matcher(number).matches()` (line 776) over the raw, unbounded input.
2. `maybeStripExtension(strippedNumber)` (line 2558 call → method at line 3062): executes `EXTN_PATTERN.matcher(number).find()` (line 3063) and then calls `isViablePhoneNumber(number.substring(0, m.start()))` (line 3066) on the prefix — again without any length check.

By contrast, `parseHelper()` (line 3253 area) explicitly enforces `MAX_INPUT_STRING_LENGTH=250` characters before any regex evaluation, with a code comment stating this is done specifically "to prevent malicious input from overflowing the regular-expression engine." This guard is entirely absent from the `isAlphaNumber()` code path.

The `VALID_PHONE_NUMBER_PATTERN` (defined at line 425–426) includes a structure of the form `[+]*+(?:[punct]*\d){3,}[punct|alpha|digit]*(?:EXTN)?`. The repeating group `(?:[punct]*\d){3,}` and the trailing `[punct|alpha|digit]*` character class overlap on the set of digit and punctuation characters. Java's NFA-based regex engine, when presented with a non-matching input, must explore all possible ways to partition the overlapping characters between the two sub-expressions before concluding failure. This produces O(n²) backtracking complexity relative to the length of the input.

### Affected Locations

- **`com.google.i18n.phonenumbers.PhoneNumberUtil.isViablePhoneNumber(CharSequence)`** (lines 772–778, `PhoneNumberUtil.java`): The primary regex sink. Executes `VALID_PHONE_NUMBER_PATTERN.matcher(number).matches()` directly on the caller-supplied `CharSequence` with no length bound. Reachable from `isAlphaNumber()` at line 2553.

- **`com.google.i18n.phonenumbers.PhoneNumberUtil.maybeStripExtension(StringBuilder)`** (lines 3062–3067, `PhoneNumberUtil.java`): A secondary regex sink. Executes `EXTN_PATTERN.matcher(number).find()` (line 3063) on the same unbounded input, and then calls `isViablePhoneNumber()` again on the resulting prefix (line 3066). Reachable from `isAlphaNumber()` at line 2558.

Both sinks are reached through the single public entry point `isAlphaNumber(CharSequence)`. The `PhoneNumberMatcher` class uses a separate `PATTERN` that is explicitly documented as having bounded captures to place an upper bound on matched text, and is therefore not a sibling sink for this vulnerability.

### Attack Vectors

**Vector 1 — Direct large-payload injection via isAlphaNumber():**
A caller (e.g., a web service, REST API handler, or form-processing component) that passes user-supplied input directly to `PhoneNumberUtil.isAlphaNumber()` without pre-validating length is vulnerable. An attacker submits a payload consisting of hundreds of kilobytes to several megabytes of digit characters followed by a single invalid character (e.g., `';'`). The invalid trailing character causes the overall regex match to fail, but only after the engine has exhausted all O(n²) backtracking paths through the ambiguous `(?:[punct]*\d){3,}` / `[punct|alpha|digit]*` overlap. Each such request consumes seconds to minutes of CPU time on the server thread.

- **Complexity:** polynomial (O(n²)) backtracking forced by non-matching tail character after a long digit sequence
- **Targets:** CPU resources of the server thread processing the request; availability of the service
- **Prerequisites:** The downstream application must route user-controlled input (e.g., from an HTTP form field, JSON body, or query parameter) directly to `isAlphaNumber()` without enforcing a length limit upstream. Most callers use `parse()`, which is protected; only callers that specifically invoke `isAlphaNumber()` are exposed.

**Vector 2 — Amplification through maybeStripExtension():**
Even if the input passes the initial `isViablePhoneNumber()` check, `maybeStripExtension()` applies `EXTN_PATTERN.find()` and then calls `isViablePhoneNumber()` a second time on the prefix. A crafted input that is structured to pass the first check but fail the second can trigger two separate backtracking episodes per call to `isAlphaNumber()`, doubling the CPU cost.

- **Complexity:** two sequential regex evaluations on the same unbounded input within a single `isAlphaNumber()` call
- **Targets:** CPU resources; service availability
- **Prerequisites:** Same as Vector 1; input must be structured to pass the first `isViablePhoneNumber()` check while failing the second.

### Impact

An attacker who can supply arbitrary string input to a service that calls `isAlphaNumber()` can cause denial of service by consuming disproportionate CPU time per request. The blow-up is polynomial (O(n²)) rather than exponential, so the practical impact depends on input size: payloads in the hundreds-of-KB to low-MB range are sufficient to cause per-request processing times of seconds to minutes. Confidentiality and integrity are not affected. Availability impact is rated High.

### Trace

1. Attacker supplies a large string (e.g., `N` digit characters followed by `';'`) as the `number` argument to `PhoneNumberUtil.isAlphaNumber(CharSequence number)` (line 2552).
2. `isAlphaNumber()` calls `isViablePhoneNumber(number)` (line 2553) without any length check.
3. `isViablePhoneNumber()` (line 772) executes `VALID_PHONE_NUMBER_PATTERN.matcher(number).matches()` (line 776); the NFA engine backtracks O(n²) times before returning `false`.
4. If `isViablePhoneNumber()` returns `true` (for a differently crafted input), `isAlphaNumber()` calls `maybeStripExtension(strippedNumber)` (line 2558).
5. `maybeStripExtension()` (line 3062) executes `EXTN_PATTERN.matcher(number).find()` (line 3063), then calls `isViablePhoneNumber(number.substring(0, m.start()))` (line 3066), triggering a second backtracking episode.
6. The thread is occupied for the duration of the backtracking; repeated requests exhaust available CPU capacity.

## Sources

- [Advisory JSON](../../advisories/CGP-gcrw-87qp-x4c3/CGP-gcrw-87qp-x4c3.json)
- [Patch: CGP-gcrw-87qp-x4c3-pkg:maven_com.googlecode.libphonenumber_libphonenumber@9.0.35.patch](../../advisories/CGP-gcrw-87qp-x4c3/CGP-gcrw-87qp-x4c3-pkg:maven_com.googlecode.libphonenumber_libphonenumber@9.0.35.patch)

---

Published 2026-11-12T16:00:00Z · Modified 2026-11-12T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
