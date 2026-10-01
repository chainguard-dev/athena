# CGP-4qc2-x2g2-q32h

RandomStringUtils and RandomUtils use ThreadLocalRandom (non-cryptographic PRNG), making generated tokens predictable if misused for security-sensitive values.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `org.apache.commons:commons-lang3`
- **Package URL:** `pkg:maven/org.apache.commons/commons-lang3`
- **Introduced:** 3.0
- **Fixed:** 3.15.0
- **Weaknesses:** CWE-338

**Affected code:**

- `org.apache.commons.lang3.RandomStringUtils.random()` (`src/main/java/org/apache/commons/lang3/RandomStringUtils.java:52-54`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`

## Details

### Root Cause

All random-generation methods in `RandomStringUtils` and `RandomUtils` are backed by `java.util.concurrent.ThreadLocalRandom`, a 64-bit-state SplittableRandom-style PRNG that is not cryptographically secure and whose output is predictable after observing a small number of samples.

In `src/main/java/org/apache/commons/lang3/RandomStringUtils.java` (lines 52–54):

```java
private static ThreadLocalRandom random() {
    return ThreadLocalRandom.current();
}
```

Every public method in `RandomStringUtils` — `randomAlphanumeric()`, `randomAlpha()`, `randomNumeric()`, `randomAscii()`, `random(int)`, and all their overloads — delegates to this private method for all character selection.

In `src/main/java/org/apache/commons/lang3/RandomUtils.java` (lines 225–226):

```java
private static ThreadLocalRandom random() {
    return ThreadLocalRandom.current();
}
```

All public methods in `RandomUtils` — `nextBoolean()`, `nextBytes()`, `nextInt()`, `nextLong()`, `nextFloat()`, `nextDouble()` — delegate to this same method.

`ThreadLocalRandom` is a 64-bit-state PRNG designed for high-throughput non-security use cases. Its internal state can be reconstructed from a small number of observed output values, making any value it produces predictable to an attacker who can observe prior outputs.

The class-level Javadoc of `RandomStringUtils` explicitly states: *"Instances of Random, upon which the implementation of this class relies, are not cryptographically secure."* `RandomUtils` is marked `@Deprecated`. Later releases of commons-lang3 (3.16+) switched the default backing PRNG to `SecureRandom`.

### Affected Locations

- `org.apache.commons.lang3.RandomStringUtils.random()` — lines 52–54: returns `ThreadLocalRandom.current()`; all public string-generation methods delegate here.
- `org.apache.commons.lang3.RandomUtils.random()` — lines 225–226: returns `ThreadLocalRandom.current()`; all public numeric/byte-generation methods delegate here.

The cross-codebase hunt also found `ThreadLocalRandom.current()` in `ArrayUtils.java` (lines 4677–4678), used internally for array shuffling operations. Array shuffling is not a security token generation context and is not a security-relevant sink for this CWE.

### Attack Vectors

**Predictable security token generation**
Downstream projects frequently misuse `RandomStringUtils.randomAlphanumeric(n)` to generate session IDs, password-reset tokens, CSRF tokens, or API keys. Because `ThreadLocalRandom`'s 64-bit internal state can be reconstructed from a small number of observed output values, an attacker who can observe any output from the PRNG (e.g. by requesting multiple tokens, or by observing tokens in HTTP responses, logs, or error messages) can predict future and past output values, forging tokens for other users or sessions.

**State reconstruction from observed samples**
An attacker who can observe a sufficient number of `ThreadLocalRandom` outputs (the exact number depends on the output character set and length) can reconstruct the 64-bit internal seed and predict all past and future outputs from the same PRNG instance. This is a well-documented property of linear congruential and SplittableRandom-family PRNGs.

**Scope note**
This finding is classified as a documented sharp edge rather than a hidden flaw: the `RandomStringUtils` class-level Javadoc explicitly warns that the implementation is not cryptographically secure. The risk is downstream misuse of the API for security-sensitive purposes. Later releases of commons-lang3 (3.16+) switched the default to `SecureRandom`.

### Impact

If a downstream application uses `RandomStringUtils` or `RandomUtils` to generate security-sensitive values (session IDs, password-reset tokens, CSRF tokens, API keys, nonces), those values are predictable to an attacker who can observe prior PRNG output. This enables:
- **Session hijacking** — predicting valid session identifiers.
- **Password reset token forgery** — predicting reset tokens for arbitrary accounts.
- **CSRF token bypass** — predicting CSRF tokens for other users' sessions.
- **API key prediction** — predicting API keys generated for other users.

### Trace

1. Downstream application calls `RandomStringUtils.randomAlphanumeric(n)` to generate a security token.
2. `randomAlphanumeric(n)` delegates to `random(n, true, true)`.
3. `random(int, boolean, boolean)` calls the private `random()` method, which returns `ThreadLocalRandom.current()`.
4. `ThreadLocalRandom.nextInt()` drives character selection — output is a function of the 64-bit internal state.
5. Attacker observes multiple token outputs and reconstructs the 64-bit PRNG state.
6. Attacker predicts past or future token values, forging tokens for other users.

## Sources

- [Advisory JSON](../../advisories/CGP-4qc2-x2g2-q32h/CGP-4qc2-x2g2-q32h.json)
- [Patch: CGP-4qc2-x2g2-q32h-pkg:maven_org.apache.commons_commons-lang3@3.13.0.patch](../../advisories/CGP-4qc2-x2g2-q32h/CGP-4qc2-x2g2-q32h-pkg:maven_org.apache.commons_commons-lang3@3.13.0.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
