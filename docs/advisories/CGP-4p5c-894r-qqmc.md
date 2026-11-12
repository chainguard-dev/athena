# CGP-4p5c-894r-qqmc

PredicatedMap.readObject() restores the decorated map without re-validating entries against key/value predicates, allowing attacker-controlled streams to inject predicate-violating entries

## Affected packages

- **Ecosystem:** Maven
- **Package:** `org.apache.commons:commons-collections4`
- **Package URL:** `pkg:maven/org.apache.commons/commons-collections4`
- **Introduced:** 4.0
- **Fixed:** 4.6.0
- **Weaknesses:** CWE-502

**Affected code:**

- `org.apache.commons.collections4.map.PredicatedMap.readObject(ObjectInputStream)` (`src/main/java/org/apache/commons/collections4/map/PredicatedMap.java:155-158`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`

## Details

### Root Cause

`PredicatedMap` in `org.apache.commons.collections4.map` decorates a `Map` to enforce key and value predicates on every entry. The class invariant is that every key-value pair satisfies the configured `keyPredicate` and `valuePredicate`. This invariant is enforced in the constructor (line 102: `map.forEach(this::validate)`) and in every mutator (`put`, `putAll`). However, the custom `readObject()` method at lines 155–158 of `src/main/java/org/apache/commons/collections4/map/PredicatedMap.java` does not re-validate restored entries:

```java
private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    map = (Map<K, V>) in.readObject(); // (1)
}
```

After `in.defaultReadObject()` restores the `keyPredicate` and `valuePredicate` fields, and `in.readObject()` restores the decorated map, no code iterates over `map.entrySet()` to call `validate(e.getKey(), e.getValue())`. An attacker who controls the serialized byte stream can supply a map containing entries that violate the predicates.

### Affected Locations

- **`org.apache.commons.collections4.map.PredicatedMap.readObject(ObjectInputStream)`** (lines 155–158): Restores the decorated map from the stream without iterating over entries to re-invoke `validate(key, value)`. The constructor at line 102 performs this validation; `readObject` does not.

### Attack Vectors

**Vector 1 — Predicate-violating entry injection (documented PoC):**
An attacker crafts a serialized stream containing a `PredicatedMap` configured with `keyPredicate=NotNullPredicate` and a decorated map that contains a null key. After deserialization, the instance reports `containsKey(null) == true`, yet `put(null, ..)` still throws `IllegalArgumentException`. This is the documented PoC state: `keyPredicate=NotNullPredicate`, `containsKey(null)==true`, yet `put(null,..)` still throws. Downstream code that trusts the `PredicatedMap` type as a guarantee that all keys are non-null will silently operate on a map containing a null key.

**Vector 2 — Logic-bug primitive for auth bypass / cache poisoning / TOCTOU:**
Applications that deserialize a `PredicatedMap` and then skip validation because they trust the decorator's type contract (e.g., "this came back as a `PredicatedMap<NotNull,NotNull>` so I don't need to null-check") will silently process predicate-violating entries. For an attacker mapping an enterprise application, this is a logic-bug primitive that can turn a deserialization endpoint into auth bypass, cache poisoning, or TOCTOU without ever touching a gadget chain a JEP-290 filter would catch.

### Impact

Integrity violation. A deserialized `PredicatedMap` can hold entries that its public type contract forbids. The application has no way to detect this without re-validating every entry, defeating the purpose of the decorator. Concrete downstream effects depend on the consuming code. The library-side defect is that `readObject()` restores the decorated map without re-asserting the constructor-time predicate validation. This is not remote code execution — no code executes during `readObject()`. The risk is downstream: applications that trust the `PredicatedMap` type as a correctness or security boundary will silently operate on predicate-violating state.

### Trace

1. Attacker supplies a crafted Java serialized byte stream to an application endpoint that deserializes `PredicatedMap`.
2. Java's `ObjectInputStream.readObject()` is called on the stream.
3. `PredicatedMap.readObject()` (line 155) calls `in.defaultReadObject()`, restoring `keyPredicate` and `valuePredicate` fields.
4. `in.readObject()` (line 157) restores the decorated map, which may contain entries violating the predicates.
5. No iteration over `map.entrySet()` occurs; `validate(key, value)` is never called for restored entries.
6. The deserialized instance is returned to the application with predicate-violating entries.
7. Downstream application code trusts the `PredicatedMap` type and skips validation, silently processing invalid entries.

## Sources

- [Advisory JSON](../../advisories/CGP-4p5c-894r-qqmc/CGP-4p5c-894r-qqmc.json)
- [Patch: CGP-4p5c-894r-qqmc-pkg:maven_org.apache.commons_commons-collections4@4.5.0.patch](../../advisories/CGP-4p5c-894r-qqmc/CGP-4p5c-894r-qqmc-pkg:maven_org.apache.commons_commons-collections4@4.5.0.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
