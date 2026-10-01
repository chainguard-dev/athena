# CGP-57cr-9rvh-qh62

WeakConcurrentMap.run() calls clear() on InterruptedException, silently dropping all live map entries when the cleaner thread is interrupted

## Affected packages

- **Ecosystem:** Maven
- **Package:** `com.blogspot.mydailyjava:weak-lock-free`
- **Package URL:** `pkg:maven/com.blogspot.mydailyjava/weak-lock-free`
- **Introduced:** 0.1
- **Fixed:** 0.15
- **Weaknesses:** CWE-404

**Affected code:**

- `com.blogspot.mydailyjava.weaklockfree.WeakConcurrentMap.run()` (`src/main/java/com/blogspot/mydailyjava/weaklockfree/WeakConcurrentMap.java:138-144`)

## Severity

- **CVSS_V3:** `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:L`

## Details

### Root Cause

The `run()` method of `WeakConcurrentMap` at lines 138–144 of `src/main/java/com/blogspot/mydailyjava/weaklockfree/WeakConcurrentMap.java` implements the background cleaner thread's main loop:

```java
public void run() {
    try {
        while (true) {
            target.remove(remove());
        }
    } catch (InterruptedException ignored) {
        clear();
    }
}
```

The `remove()` call (inherited from `ReferenceQueue`) blocks until a garbage-collected reference is available, then returns it. If the thread is interrupted while blocked in `remove()`, a `java.lang.InterruptedException` is thrown. The catch block silently swallows the exception (`ignored`) and calls `clear()`, which invokes `target.clear()` on the backing `ConcurrentHashMap`. This removes every entry in the map — both stale entries (whose keys have been collected) and live entries (whose keys are still reachable). There is no distinction between the two categories at this point.

The `DetachedThreadLocal` class at `src/main/java/com/blogspot/mydailyjava/weaklockfree/DetachedThreadLocal.java` line 130 delegates its own `run()` method directly to `map.run()`. Any `DetachedThreadLocal` instance configured with `Cleaner.THREAD` (which starts an internal daemon thread) or submitted manually to an external thread via `Cleaner.MANUAL` is subject to the same behavior.

### Affected Locations

- **`com.blogspot.mydailyjava.weaklockfree.WeakConcurrentMap.run()`** (lines 138–144, `src/main/java/com/blogspot/mydailyjava/weaklockfree/WeakConcurrentMap.java`): The primary sink. `InterruptedException` causes `clear()` to be called, removing all entries.
- **`com.blogspot.mydailyjava.weaklockfree.DetachedThreadLocal.run()`** (line 130, `src/main/java/com/blogspot/mydailyjava/weaklockfree/DetachedThreadLocal.java`): Delegates to `map.run()`, exposing the same behavior to all `DetachedThreadLocal` instances that use a cleaner thread.

### Attack Vectors

**Vector 1 — Privileged thread interruption causing total data loss**
Any code with access to the cleaner `Thread` object (obtainable via `WeakConcurrentMap.getCleanerThread()` or `WeakConcurrentSet.getCleanerThread()`) can call `thread.interrupt()`. This triggers the `InterruptedException` catch block, which calls `clear()` and removes all live entries from the map. If the map stores security-sensitive per-thread state (e.g., authentication context in a `DetachedThreadLocal`), all such state is silently dropped.

- **Complexity**: single method call on the thread object
- **Targets**: all live entries in the WeakConcurrentMap, all per-thread values in DetachedThreadLocal
- **Prerequisites**: access to the Thread object returned by `getCleanerThread()`; the map must have been constructed with `cleanerThread = true`

**Vector 2 — JVM shutdown hook or signal-based interruption**
In environments where JVM shutdown hooks or external signals (e.g., SIGINT) interrupt daemon threads, the cleaner thread may receive an `InterruptedException` during normal application operation, causing all map entries to be cleared unexpectedly. This is a reliability issue that can manifest as a security issue when the cleared data is security-sensitive.

- **Complexity**: depends on JVM shutdown sequencing or signal delivery
- **Targets**: all live entries in any WeakConcurrentMap or DetachedThreadLocal using a cleaner thread
- **Prerequisites**: JVM shutdown or external signal delivery while the cleaner thread is active

### Impact

All live entries in the affected `WeakConcurrentMap` (and by extension any `DetachedThreadLocal` or `WeakConcurrentSet` backed by it) are silently removed when the cleaner thread is interrupted. Applications that store security-sensitive per-thread state — such as authentication context, access-control tokens, or distributed tracing context — in a `DetachedThreadLocal` with `Cleaner.THREAD` will find all such state absent after the interruption, with no exception or error signal. Subsequent operations will behave as if no context was set, potentially falling back to an unauthenticated or unprivileged default. The data loss is irreversible for the lifetime of the map instance.

### Trace

1. `WeakConcurrentMap` is constructed with `cleanerThread = true`, starting a daemon thread that runs `WeakConcurrentMap.run()`.
2. The cleaner thread blocks in `ReferenceQueue.remove()` waiting for a collected reference.
3. An actor with access to the thread object calls `getCleanerThread().interrupt()`, or a JVM shutdown hook interrupts the thread.
4. `ReferenceQueue.remove()` throws `InterruptedException`.
5. The catch block in `WeakConcurrentMap.run()` swallows the exception and calls `clear()`.
6. `clear()` calls `target.clear()` on the backing `ConcurrentHashMap`, removing all entries including live ones.
7. Subsequent `get()` calls on the map return `null` or the default value for all keys, including keys whose values were live at the time of interruption.

## Sources

- [Advisory JSON](../../advisories/CGP-57cr-9rvh-qh62/CGP-57cr-9rvh-qh62.json)
- [Patch: CGP-57cr-9rvh-qh62-pkg:maven_com.blogspot.mydailyjava_weak-lock-free@0.11.patch](../../advisories/CGP-57cr-9rvh-qh62/CGP-57cr-9rvh-qh62-pkg:maven_com.blogspot.mydailyjava_weak-lock-free@0.11.patch)

---

Published 2026-09-28T16:00:00Z · Modified 2026-09-28T16:00:00Z · Generated from the advisory JSON by `scripts/generate_advisory_list.py` — do not edit by hand.
