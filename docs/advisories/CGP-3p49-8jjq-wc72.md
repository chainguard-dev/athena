# CGP-3p49-8jjq-wc72

ValidatorUtils.replace() uses unbounded self-recursion (one frame per key occurrence), causing StackOverflowError on value strings with many repeated placeholder tokens.

## Affected packages

- **Ecosystem:** Maven
- **Package:** `commons-validator:commons-validator`
- **Package URL:** `pkg:maven/commons-validator/commons-validator`
- **Introduced:** 1.1.0
- **Fixed:** 1.8.0
- **Weaknesses:** CWE-674

**Affected code:**

- `org.apache.commons.validator.util.ValidatorUtils.replace(String,String,String)` (`src/main/java/org/apache/commons/validator/util/ValidatorUtils.java:56-86`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L/E:X/RL:X/RC:U`

## Details

### Root Cause

`ValidatorUtils.replace(String value, String key, String replaceValue)` in `src/main/java/org/apache/commons/validator/util/ValidatorUtils.java` (lines 56–86) uses unbounded tail recursion to perform string replacement. The critical branch at lines 82–85 is:

```java
value =
    value.substring(0, start)
    + replaceValue
    + replace(value.substring(end), key, replaceValue);
```

Each occurrence of `key` in `value` causes one additional recursive call. There is no depth limit, no iteration-based alternative, and no guard against deeply repeated keys. A `value` string containing N occurrences of `key` produces a call stack of depth N. When N reaches the JVM's thread stack limit (typically a few thousand to tens of thousands of frames depending on JVM configuration), a `StackOverflowError` is thrown.

### Affected Locations

- `org.apache.commons.validator.util.ValidatorUtils.replace(String,String,String)` (lines 56–86): the recursive sink.

The method is called from multiple locations in the framework's rule-processing pipeline:
- `org.apache.commons.validator.Field.process(Map,Map)` (lines 576, 590): replaces constant tokens in the field's `property` string.
- `org.apache.commons.validator.Field.processVars(String,String)` (line 619): replaces constant tokens in each `Var` value.
- `org.apache.commons.validator.Field.processMessageComponents(String,String)` (line 633): replaces constant tokens in each `Msg` key.
- `org.apache.commons.validator.Field.processArg(String,String)` (line 658): replaces constant tokens in each `Arg` key.
- `org.apache.commons.validator.ValidatorAction.handleIndexedField(Field,int,Object[])` (line 741): replaces the `TOKEN_INDEXED` placeholder in the field key.

All callers share the same recursive `replace()` implementation; the vulnerability is present wherever `ValidatorUtils.replace()` is invoked with a value string containing many occurrences of the key.

### Attack Vectors

**Stack exhaustion via repeated placeholder tokens in validation.xml:**
An attacker who can influence the content of a `validation.xml` configuration file (or who can set validator variable/arg/message values programmatically via `Var`/`Arg` setters) constructs a value string containing tens of thousands of occurrences of a `${var:...}` or constant placeholder token. When `Field.process()` calls `ValidatorUtils.replace()` to expand these tokens, the recursion depth equals the occurrence count, exhausting the JVM stack and throwing `StackOverflowError`.

**Prerequisites:**
The `value` string is normally sourced from developer-authored `validation.xml` configuration. Exploitation requires either: (a) an application that allows untrusted parties to define validator variables, argument values, or message keys; or (b) a malicious or compromised configuration file. Under normal developer-controlled configuration, this is an informational finding.

### Impact

- **Availability (Low):** The calling thread crashes with `StackOverflowError` when processing a deeply repeated key. This terminates the validation operation and may propagate to the application layer if the error is not caught.
- **Confidentiality (None):** No data is exposed.
- **Integrity (None):** No data is modified.

### Trace

1. Validation.xml (or programmatic API) provides a `Var`/`Arg`/`Msg` value string containing N occurrences of a placeholder key (e.g., `${myConst}${myConst}...` repeated N times).
2. `ValidatorResources.process()` triggers `Field.process(globalConstants, constants)`.
3. `Field.process()` calls `ValidatorUtils.replace(property, key2, replaceValue)` (line 576 or 590).
4. `ValidatorUtils.replace()` finds the first occurrence of `key` and recurses on the remaining suffix.
5. Steps 3–4 repeat N times, consuming N JVM stack frames.
6. At depth N (tens of thousands), `StackOverflowError` is thrown, crashing the calling thread.

## Sources

- [Advisory JSON](../../advisories/CGP-3p49-8jjq-wc72/CGP-3p49-8jjq-wc72.json)
- [Patch: CGP-3p49-8jjq-wc72-pkg:maven_commons-validator_commons-validator@1.5.1.patch](../../advisories/CGP-3p49-8jjq-wc72/CGP-3p49-8jjq-wc72-pkg:maven_commons-validator_commons-validator@1.5.1.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
