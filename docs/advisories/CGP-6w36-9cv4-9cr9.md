# CGP-6w36-9cv4-9cr9

Static synchronized getValidationProviderList() holds the JVM-wide class monitor across untrusted ServiceLoader iteration, enabling cross-tenant denial of service via a blocking provider constructor.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `jakarta.validation:jakarta.validation-api`
- **Package URL:** `pkg:maven/jakarta.validation/jakarta.validation-api`
- **Introduced:** 2.0.1
- **Fixed:** 4.0.0-M1
- **Weaknesses:** CWE-557

**Affected code:**

- `jakarta.validation.Validation.GetValidationProviderListAction.getValidationProviderList()` (`src/main/java/jakarta/validation/Validation.java:333`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L`

## Details

### Root Cause

In `jakarta.validation.Validation`, the private inner class `GetValidationProviderListAction` declares its entry point as:

```java
public static synchronized List<ValidationProvider<?>> getValidationProviderList() {  // L333
```

The `static synchronized` modifier acquires the JVM-wide class monitor for `GetValidationProviderListAction.class`. The method body (lines 334–340) calls either `AccessController.doPrivileged(INSTANCE)` or `INSTANCE.run()` — both execute synchronously on the calling thread, so the class monitor is held for the entire duration of `run()`.

`run()` (lines 347–374) reads the Thread Context ClassLoader (line 349) and, on a cache miss, calls `loadProviders(classloader)` (line 356). `loadProviders()` (lines 378–391) iterates a `ServiceLoader<ValidationProvider>` via `providerIterator.next()`, which invokes each declared provider's no-arg constructor. Only `ServiceConfigurationError` is caught; any blocking operation in a provider constructor (e.g., `Thread.sleep()`, an infinite loop, or network I/O) is not interrupted or bounded by any timeout mechanism.

There is no per-classloader lock striping. Even callers that would hit the cache (and return immediately) must first acquire the same global class monitor. The `clearCache()` method at line 342 is also `static synchronized` on the same monitor, meaning cache invalidation and provider discovery contend on the same global lock.

### Affected Locations

- `jakarta.validation.Validation.GetValidationProviderListAction.getValidationProviderList()` (line 333): the `static synchronized` declaration that acquires the JVM-wide class monitor and holds it across the full `ServiceLoader` iteration.

The cross-codebase hunt found one additional `static synchronized` method (`clearCache()` at line 342) on the same class monitor, confirming that cache invalidation also contends on the same global lock. No other `static synchronized` methods exist in the production source tree.

The taint path from an attacker-controlled META-INF/services entry to the global lock stall is:

```
attacker WAR META-INF/services/jakarta.validation.spi.ValidationProvider (lists EvilProvider)
  → Thread TCCL set to attacker's webapp classloader
    → getValidationProviderList() acquires class monitor [L333]
      → run() [L347]
        → loadProviders(tccl) [L356]
          → ServiceLoader.iterator().next() [L383]
            → EvilProvider constructor blocks indefinitely
              → class monitor held indefinitely
                → all other threads block on class monitor [L333]
```

### Attack Vectors

**Cross-tenant denial of service via blocking provider constructor:**
In a multi-tenant container where `jakarta.validation-api` is loaded by a shared classloader (so all tenants resolve to the same `GetValidationProviderListAction.class` monitor), an attacker deploys a WAR containing a `META-INF/services/jakarta.validation.spi.ValidationProvider` entry listing a provider whose no-arg constructor blocks indefinitely (e.g., `Thread.sleep(Long.MAX_VALUE)` or a blocking network call). The first request into the attacker's webapp triggers `Validation.buildDefaultValidatorFactory()`; the thread enters the static monitor at line 333, calls `providerIterator.next()`, and never returns. Every other webapp's `Validation.buildDefaultValidatorFactory()` call blocks forever on the same monitor — cross-tenant denial of service with no privilege beyond the ability to deploy a WAR.

- **Complexity:** single-step; attacker deploys a WAR with a blocking provider constructor
- **Prerequisites:** `jakarta.validation-api` loaded by a classloader shared across tenants (so all tenants resolve to the same `GetValidationProviderListAction.class` monitor); attacker can deploy code reachable from some thread's TCCL (i.e., can deploy an application or plugin); victim tenants invoke default validation bootstrap after the attacker has entered the lock
- **Targets:** availability of `Validation.buildDefaultValidatorFactory()` for all tenants sharing the same classloader

**Benign-but-slow classloader robustness failure:**
Even without a malicious actor, a provider whose constructor performs slow I/O (e.g., reading a remote configuration file) stalls all concurrent validation bootstrap calls across the JVM for the duration of that I/O, degrading availability under load.

### Impact

`getValidationProviderList()` is the only path into default provider resolution and is gated by a single JVM-global class monitor. A blocking provider constructor in any tenant's TCCL-visible classpath indefinitely stalls validation bootstrap for every other thread and tenant in the JVM. In multi-tenant application server deployments where `jakarta.validation-api` is in the shared lib/, this constitutes a cross-tenant availability weakness. Practical severity is low because the required deploy privilege already affords equivalent denial-of-service by simpler means; nonetheless it is a genuine cross-tenant availability weakness in shared-classloader contexts and a robustness issue for benign-but-slow classloaders.

## Sources

- [Advisory JSON](../../advisories/CGP-6w36-9cv4-9cr9/CGP-6w36-9cv4-9cr9.json)
- [Patch: CGP-6w36-9cv4-9cr9-pkg:maven_jakarta.validation_jakarta.validation-api@3.0.2.patch](../../advisories/CGP-6w36-9cv4-9cr9/CGP-6w36-9cv4-9cr9-pkg:maven_jakarta.validation_jakarta.validation-api@3.0.2.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
