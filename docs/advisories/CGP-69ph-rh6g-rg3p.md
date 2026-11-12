# CGP-69ph-rh6g-rg3p

Non-constant-time password comparison in AbstractPasswordFilePrincipalDatabase enables timing side-channel credential recovery

## Affected packages

- **Ecosystem:** Maven
- **Package:** `org.apache.qpid:qpid-broker-core`
- **Package URL:** `pkg:maven/org.apache.qpid/qpid-broker-core`
- **Introduced:** 0
- **Fixed:** 10.0.0
- **Weaknesses:** CWE-208

**Affected code:**

- `org.apache.qpid.server.security.auth.database.AbstractPasswordFilePrincipalDatabase.compareCharArray(char[],char[])` (`broker-core/src/main/java/org/apache/qpid/server/security/auth/database/AbstractPasswordFilePrincipalDatabase.java:140-155`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N/E:X/RL:X/RC:R`

## Details

### Root Cause

`AbstractPasswordFilePrincipalDatabase.compareCharArray(char[], char[])` (line 140, `broker-core/src/main/java/org/apache/qpid/server/security/auth/database/AbstractPasswordFilePrincipalDatabase.java`) implements password comparison with an early-exit loop:

```java
protected boolean compareCharArray(char[] a, char[] b) {
    ...
    while (equal && index < a.length) {
        equal = a[index] == b[index];
        index++;
    }
    ...
}
```

The loop exits immediately when `equal` becomes `false` (i.e., on the first mismatching character). This causes the comparison to complete faster for passwords that differ at an earlier position, leaking information about the stored password through response timing.

This method is called in two contexts:

1. **PlainPasswordFilePrincipalDatabase.verifyPassword()** (line 103): compares the stored plaintext password against the attacker-supplied password. The stored value is the raw plaintext, so a timing attack can in principle recover the password one character at a time.
2. **Base64MD5PasswordFilePrincipalDatabase.verifyPassword()** (line 106): compares an unsalted MD5 digest of the stored password against an MD5 digest of the attacker-supplied password. The comparison is over digest bytes, which is harder to exploit due to the non-linear relationship between input and digest, but the comparison itself is still non-constant-time.

### Affected Locations

- `org.apache.qpid.server.security.auth.database.AbstractPasswordFilePrincipalDatabase.compareCharArray(char[], char[])` at lines 140–155 of `broker-core/src/main/java/org/apache/qpid/server/security/auth/database/AbstractPasswordFilePrincipalDatabase.java`: the non-constant-time comparison sink, called by both `PlainPasswordFilePrincipalDatabase` and `Base64MD5PasswordFilePrincipalDatabase`.

### Attack Vectors

**Vector 1 — Timing side-channel against PlainPasswordFile provider:**
A remote attacker sends many SASL PLAIN authentication attempts with varying password prefixes and measures the response time for each. Because `compareCharArray` exits on the first mismatch, a password that matches the first N characters of the stored plaintext takes longer to compare than one that mismatches at position 0. By iterating over candidate characters at each position, the attacker can recover the stored plaintext password one character at a time. Network jitter makes practical exploitation difficult (AC:H), but the attack is feasible in low-latency or co-located environments.

**Vector 2 — Timing side-channel against Base64MD5PasswordFile provider:**
The same early-exit comparison is used when verifying MD5 digests. The non-linear relationship between plaintext and MD5 digest makes direct character-by-character recovery infeasible, but the non-constant-time comparison still leaks information about digest byte values, which could assist in distinguishing candidate passwords.

### Impact

A remote, unauthenticated attacker can in principle recover stored plaintext passwords from the PlainPasswordFile authentication provider via a timing side-channel attack. The attack requires high-precision timing measurements and many authentication attempts (AC:H). Confidentiality of stored credentials is at risk.

### Trace

1. Attacker sends SASL PLAIN authentication request with candidate password
2. `PlainNegotiator.handleResponse` → `PrincipalDatabaseAuthenticationManager.authenticate`
3. `PlainPasswordFilePrincipalDatabase.verifyPassword(principal, password)` → `compareCharArray(storedPlaintext, suppliedPassword)`
4. Early-exit loop terminates on first mismatch — response time varies with position of first differing character
5. Attacker measures response time and iterates to recover password character by character

## Sources

- [Advisory JSON](../../advisories/CGP-69ph-rh6g-rg3p/CGP-69ph-rh6g-rg3p.json)
- [Patch: CGP-69ph-rh6g-rg3p-pkg:maven_org.apache.qpid_qpid-broker-core@9.2.1.patch](../../advisories/CGP-69ph-rh6g-rg3p/CGP-69ph-rh6g-rg3p-pkg:maven_org.apache.qpid_qpid-broker-core@9.2.1.patch)

---

Published 2026-11-12T16:00:00Z · Modified 2026-11-12T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
