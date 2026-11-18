# fairplayd selector 26 aggregate ownership after the status gate

The modeled selector 26 error and size mismatch release the submitted heap aggregate and preserve the private result through the core return. A modeled zero status keeps the aggregate live through a new 16 B allocation. If that allocation returns null, the same cleanup runs with a distinct allocation-failure result. A nonnull return reaches the next 32 B allocation after reading the submitted aggregate. [Selector 26 return profiles](daemon_selector26_pidpath_returns_report.md)

## Aggregate and status lifetime

All addresses are unslid in the retained `fairplayd.arm64e` image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The inputs carry the 272 B or 288 B aggregate from both process-path ABI forms. Offsets from R refer to the core argument record and offsets from F refer to the restored outer stack frame. [Original aggregate arguments](daemon_selector26_pidpath_paths_report.md)

| Gate outcome and following control | State of the submitted aggregate | Core result at R+8 B |
| --- | --- | --- |
| API status `0xffff5bbc` through either helper | Freed at `0x10072a488`, after ten preceding frees | `0x74c29ded` |
| Direct short size or descriptor size mismatch | Same release sequence | `0x74c29fc9` |
| Zero API status, valid sizes, null `_malloc(16)` at `0x100723080` | Same release sequence | `0x74c29d85` |
| Zero API status, valid sizes, nonnull `_malloc(16)` at `0x100723080` | 14 reads, no writes or free before `_malloc(32)` at `0x100948dd0` | No store to R+8 B in the audited span |

The API and shape failure entry at `0x10065f430` saves the incoming W5 status to SP+0x764 B at `0x10065f458`. The cleanup releases the first standalone allocation, then three child/owner pairs, one list container and the two earlier standalone allocations. The newly added process-path child and owner are the third pair. `0x100942a64` frees each child and `0x100a35f0c` frees its owner. `0x10070f118` frees the prior 208 B or 224 B source aggregate, and `0x10072a488` frees the submitted aggregate last. The replay sees no reads or writes of the submitted aggregate on these paths after the gate. The core writes the row’s result at `0x1009e5714` and returns to `0x100902ae0`. The adapter stores zero at F+0x80 B at `0x100902aec`. The restored outer continuation then reaches `0x1002c99a0`. [Earlier nonpositive process-query route](daemon_selector26_pidpath_paths_report.md)

With a nonnull list allocation, the daemon reads aggregate offsets 6–9, then 0–5, then 10–13. Each load reads 1 B. The first PCs of the three groups are `0x100908f1c`, `0x100a37ddc` and `0x1009f75c8`. The instructions combine the bytes with shifts and bitwise operations before the 32 B allocation. The protocol meaning of the decoded values is unknown.

## IOKit names at outer rejection

The newly audited rejection paths reach the two previously established `IOObjectRelease` imports in the same order. The modeled class `0x98` continues to the primary lookup entry at `0x10014ebf0`. The modeled class `0x99` continues to the final result block at `0x1002bfecc`. The audit stops at those entries.

| Order | Daemon call PC | Name source and use |
| --- | --- | --- |
| 1 | `0x1001dcab8` | Releases the service send right saved at F+0xc B |
| 2 | `0x100205980` | Releases the iterator send right saved at F+0x78 B |
| Through both | No close call in this span | Open connection name remains in the active context at offset 4 B |

The supplied RAX trace observes the service and iterator deallocation traps at PC `0x180547ad0` after a failed open. The new replay uses a modeled successful open and injects the return from selector 26. The trace corroborates the order of the two releases on the earlier route. Native selector 26 traffic and eventual disposition of the surviving connection name remain unknown. [Class retry and release evidence](daemon_selector26_class_retry_report.md) [RAX traces](zut_trace_report.md)

## Assumptions and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| O1 | The positive process query, upstream inputs and synthetic allocation addresses reconstruct the two call frames. The release sequence and reads apply to those states. | Compare aggregate pointer, length and release arguments for an ordinary request on the pinned build. |
| O2 | API status and returned descriptor fields are injected using the already recovered return contract. No simulated provider mutation precedes the first daemon read. | Observe the native reply alongside the aggregate contents at the two API returns and after the gate. |
| O3 | Allocator and release APIs return normally. The replay checks saved links and the stack guard without executing pointer authentication. | Inspect the actual malloc results, port names, return PCs and guard state at the reported call sites. |

The audit evaluates 18 cases across two lengths and two ABI forms. Its event checks take O(J) time and space in the number of recorded loads, stores and branches, excluding instruction interpretation and fixup verification. [Replay audit](triage_evidence/audit_daemon_selector26_pidpath_ownership.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_pidpath_ownership.py
```

| Impact | Open evidence |
| --- | --- |
| High | Determine how the nonnull continuation uses the read bytes and when it releases or publishes the submitted aggregate. |
| High | Match the daemon status and aggregate lifetime to a native request and provider reply. |
| Medium | Trace the exact primary retry and final status after the newly verified outer destinations. |
