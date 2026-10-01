# CGP-gm3f-w8vf-c6p8

Single-argument doPrivileged in ProviderSpecificBootstrapImpl.run() instantiates a caller-supplied arbitrary class under elevated privilege, enabling a confused-deputy sandbox escape.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `jakarta.validation:jakarta.validation-api`
- **Package URL:** `pkg:maven/jakarta.validation/jakarta.validation-api`
- **Introduced:** 2.0.1
- **Fixed:** 4.0.0-M1
- **Weaknesses:** CWE-272

**Affected code:**

- `jakarta.validation.Validation.ProviderSpecificBootstrapImpl.run(PrivilegedAction)` (`src/main/java/jakarta/validation/Validation.java:240`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N`

## Details

### Root Cause

In `jakarta.validation.Validation`, the private inner class `ProviderSpecificBootstrapImpl<T, U>` contains a `run(PrivilegedAction<P>)` helper at line 240:

```java
return System.getSecurityManager() != null ? AccessController.doPrivileged( action ) : action.run();
```

This single-argument form of `AccessController.doPrivileged` removes the calling thread's restricted `ProtectionDomain` from the access-control stack for the duration of the action. The action is `NewProviderInstance.action(validationProviderClass)`, where `validationProviderClass` is the `Class<U>` object supplied by the caller to the public API `Validation.byProvider(Class<U>)` (line 153).

The generic bound `<U extends ValidationProvider<T>>` is erased at runtime. A caller using a raw or unchecked cast can pass any `Class` object. No `ValidationProvider.class.isAssignableFrom(clazz)` check is performed before the `doPrivileged` block executes. The cast to `ValidationProvider` at line 214 occurs only after `NewProviderInstance.run()` has already called `clazz.newInstance()` at line 419 — meaning the constructor side effects have already fired before any type check.

This constitutes a confused-deputy vulnerability: code running in a restricted `ProtectionDomain` (sandboxed caller) can leverage `jakarta.validation-api`'s broader permissions to instantiate an arbitrary class whose constructor performs security-checked operations, bypassing the sandbox.

### Affected Locations

- `jakarta.validation.Validation.ProviderSpecificBootstrapImpl.run(PrivilegedAction)` (line 240): the single-argument `doPrivileged` call that elevates privilege for a caller-tainted action.
- `jakarta.validation.Validation.NewProviderInstance.run()` (line 419): the `clazz.newInstance()` call that executes inside the elevated privilege context.

The cross-codebase hunt found one additional `doPrivileged` call at line 335 (`GetValidationProviderListAction.getValidationProviderList()`), but that call operates on a fixed, internally-constructed action (`INSTANCE`) with no caller-supplied class, so it is not a confused-deputy sink.

The taint path from the public API to the privileged instantiation is:

```
caller Class (potentially arbitrary via raw cast)
  → Validation.byProvider(providerType) [L153]
    → ProviderSpecificBootstrapImpl.validationProviderClass [L177]
      → configure() [L213]
        → run(NewProviderInstance.action(validationProviderClass))
          → AccessController.doPrivileged(action) [L240]  ← privilege elevation
            → NewProviderInstance.run() [L419]
              → clazz.newInstance()  ← arbitrary class instantiated under elevated privilege
                → ClassCastException at L214 (after constructor side effects have fired)
```

### Attack Vectors

**Confused-deputy sandbox escape via arbitrary class instantiation:**
Sandboxed code under a `SecurityManager` calls `Validation.byProvider((Class) GadgetClass.class).configure()`. Inside `doPrivileged`, `GadgetClass`'s no-arg constructor runs; permission checks see only `jakarta.validation-api`'s `ProtectionDomain` and the gadget's own `ProtectionDomain`, not the sandboxed caller's restricted domain. If a JDK or system class with a security-checked side-effecting no-arg constructor exists in a privileged `ProtectionDomain`, the sandboxed caller gains a privilege-escalation primitive. The subsequent `ClassCastException` at line 214 is irrelevant — the constructor side effect has already fired.

- **Complexity:** multi-step: sandboxed caller must identify a suitable gadget class with a public no-arg constructor and a security-checked side effect reachable in a privileged ProtectionDomain
- **Prerequisites:** JVM running with a SecurityManager (deprecated in JDK 17, removed in JDK 24); `jakarta.validation-api` code source granted broader permissions than the caller; attacker can run sandboxed Java code in-process and invoke `Validation.byProvider`; a useful gadget class with a public no-arg constructor and a security-checked side effect is reachable in a privileged ProtectionDomain
- **Targets:** security-checked operations accessible to `jakarta.validation-api`'s ProtectionDomain but not to the sandboxed caller's domain

### Impact

When a `SecurityManager` is active and `jakarta.validation-api` is granted broader permissions than the caller (typical in application server lib/ deployments), sandboxed code can cause an arbitrary class's no-arg constructor to execute inside an `AccessController.doPrivileged` block. This removes the caller's restricted `ProtectionDomain` from the access-control stack, constituting a confused-deputy / sandbox-escape primitive (CERT SEC01-J). Practical exploitability is constrained because the gadget class's own `ProtectionDomain` remains on the access-control stack (the attacker cannot use a self-defined gadget class to gain permissions it does not already hold), and `SecurityManager` is obsolete in modern JDKs. Severity is capped at LOW given the four required preconditions.

## Sources

- [Advisory JSON](../../advisories/CGP-gm3f-w8vf-c6p8/CGP-gm3f-w8vf-c6p8.json)
- [Patch: CGP-gm3f-w8vf-c6p8-pkg:maven_jakarta.validation_jakarta.validation-api@3.0.2.patch](../../advisories/CGP-gm3f-w8vf-c6p8/CGP-gm3f-w8vf-c6p8-pkg:maven_jakarta.validation_jakarta.validation-api@3.0.2.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
