# Cached lock release after FairPlayIOKit discovery

The discovery caller uses the cached write-lock pointer from `0x1010c6820` on both sides of the selected IOKit paths. Acquisition requests `pthread_rwlock_wrlock` at `0x10019eed0`. Cleanup calls the getter again, forwards the freshly read pointer, and requests `pthread_rwlock_unlock` at `0x1000db668`. The source replay carries the same allocation to both calls in six nonnull cases. The null-cache case runs the cleanup wrapper and skips the pthread primitive. In the returning open-failure paths, the service and iterator names are released before the unlock request. [Acquisition and initializer](daemon_class_lock_gate_report.md) [Original-byte audit](triage_evidence/audit_daemon_class_lock_release.py) [Audit receipt](triage_evidence/daemon_class_lock_release_audit.json.zst)

```text
cache getter -> pthread_rwlock_wrlock(pointer)
  |
  +-- primary or Avp-to-primary lookup
  |     -> type-0 IOServiceOpen failure -> release service -> release iterator
  |
  +-- main-port failure / iterator exhausted / context skip
  |     -> release an iterator if present -> continue
  |
  +-- common cleanup 0x100523d74
        -> cache getter -> 0x100423a3c
          +-- pointer nonnull -> pthread_rwlock_unlock(pointer) -> 0x118cb413
          +-- pointer NULL    ->                                 0xeb6c70cc
        -> restore the saved discovery status from S+0x62c
```

The null-cache case bypasses acquisition and class lookup before joining common cleanup. The separate metadata-query flow through `0x1004601d0` uses a primary cell at `0x1010c8240` and an unlock at `0x100208efc`. The two flows share the libSystem import but use distinct storage and wrappers. [Metadata-query synchronization](daemon_iokit_sync_report.md)

## Cleanup call and status ABI

S is the retained caller SP. The private record P is at FP−0xa0 B. The compare-miss continuation at `0x1006340c8` saves the incoming W8 marker to S+0x62c B and selects `0x100523d74` using W21=`0x2e7e`, slot `0x1010512e0`, IA `0x6cdc`. The context-skip path reaches the same cleanup through `0x10061e8d4` and `0x1004ba4c0`, saving its marker at `0x10061e8dc`. Both entries give W19=`0x5a82` to cleanup. [Audit receipt](triage_evidence/daemon_class_lock_release_audit.json.zst)

| Source site | Dispatch or field | Verified meaning |
| --- | --- | --- |
| `0x100523dd0` → `0x100418748` | P+8 B, u32 | Encoded getter phase `0x5ca8`. |
| `0x100523e2c` | Slot `0x1010a0df8`, IA `0xb228` → `0x10041859c` | Same cached-pointer getter as acquisition. |
| `0x100087308` → `0x10008730c` | Read cache at `0x1010c6820`, store P+0 B, u64 | Second original cache read, after class continuation. |
| `0x100523e70` → `0x100423ba0` | P+8 B, u64 | Getter result passed by value to the cleanup wrapper. |
| `0x100523e7c` → `0x100423b98` | P+0x10 B, u32 | Encoded cleanup phase `0xb645`. |
| `0x100523ecc` | Slot `0x1010a0130`, IA `0x5c95` → `0x100423a3c` | Cleanup wrapper, X0=P. |
| `0x100423c2c` | Nonnull through `0x1010951d8`, null through `0x101095118`, IA `0xca9b` | Nonnull takes the resolver at `0x1000db600`. NULL goes directly to the return-field writer. |
| `0x1000db668` | Slot `0x1010a0d78`, IA `0x5431` | `pthread_rwlock_unlock` receives the full 64-bit pointer in X0. |
| `0x1000f7554` | P+0 B, u32 | Stores `0x118cb413` after the unlock import returns or `0xeb6c70cc` on null. |
| `0x100523ed4` | X0 ← S+0x560 B, u64 | The caller continues from a separate local field. |
| `0x1006220e4` | W21 ← S+0x62c B, u32 | Restores the saved discovery marker independently of the wrapper marker at P+0 B. |

The unlock continuation at `0x1000db66c` selects a branch from W20, then writes constant W11 before the shared epilogue. The modeled returns 0 and 22 therefore produce the same private marker. Both codecs were independently lifted from source. Their caller/callee address terms match for all 8 B-aligned P projections, and XOR cancellation yields the two stated phases. The bit-vector checks operate at fixed 32-bit width. [Codec receipt](triage_evidence/daemon_class_lock_release_audit.json.zst)

## Continuous local profiles

The private replay executes the source from the admitted helper-pair predecessor through cleanup and the status reload. The bank producers and frame writer are joined under the acquisition report's same-frame premise. For class lookup the replay uses the original byte adapter with a declared completed environmental cache. The 0 and 1 cache controls select the primary-only and Avp-to-primary profiles respectively. IOKit arguments, port-name widths, release order and ownership transitions are checked in the model. [Environmental cache and class decision](daemon_selector26_class_gate_report.md) [Class fallback and name retirement](daemon_selector26_class_retry_report.md)

| Profile | Modeled IOKit releases before cleanup | Unlock request | Reloaded W21 at `0x1006220e4` |
| --- | --- | --- | --- |
| Primary open returns `0xe00002c2` | Service, iterator | Same cached pointer | `0x74c29dee` |
| Avp and primary opens return `0xe00002c2` | Avp service, Avp iterator, primary service, primary iterator | Same cached pointer | `0x74c29dee` |
| Primary context skips class lookup | None | Same cached pointer | `0x74c29dba` |
| `IOMainPort` returns 1 | None | Same cached pointer | `0x74c29dee` |
| `IOIteratorNext` returns zero | Iterator | Same cached pointer | `0x74c29dee` |
| Cached lock allocation returns NULL | None | Omitted | `0x74c29d88` |
| Primary open fails, write-lock returns 5 and unlock returns 22 | Service, iterator | Same cached pointer | `0x74c29dee` |

In the context-skip case, the class routine first returns `0x8b3dc651` at P+0 B. The outer caller then updates the primary context at `0x1010b63a0`. Original stores set C+0 B to `0x70`, write `0x82da5774` at C+4 B and update seven other fields before cleanup. C+4 B is also the type-0 open output address on the lookup route. The written word in this case is a direct constant. The model makes no IOKit request and produces no port right from that store. [Context source spans and writes](triage_evidence/daemon_class_lock_release_audit.json.zst)

The final audited instruction window reloads W21 at `0x1006220e4`. The audit stops before the table lookup at `0x1006220ec`, whose index depends on W24 from the previously saved S+0x2ec B. The native producer of that outer phase is unknown.

## Archived trace and next evidence

The primary open-failure profile reproduces the ordering of the archived type-0 open request 2862 and reply 2962, followed by service and iterator releases. The model uses its own task-local names. The archive supplies guest service `0x1903`, iterator `0x1803`, and Mach transport return 0 with application result `0xe00002c2`. The archive records trap PCs and contains no observation of this cached pointer, its pthread calls, or these daemon caller addresses. No new Mach message or name is attributed to cleanup. [Archived open and port retirement](archived_iokit_open_retirement_report.md)

| Open join | Impact | Evidence required |
| --- | --- | --- |
| Which routine supplies S+0x2ec B and consumes the reloaded marker | High | Trace original entry state into the W6 store and follow the dispatch at `0x1006220ec` to its outcome consumer. |
| Successful open, constructor and release | High | Carry a sourced nonnull connection and the constructor's original outcome into the caller, then identify the associated cleanup or close. |
| Native discovery and lock epoch | High | Match the caller PC, cached pointer, and IOKit port timeline in one ordinary execution. |

## Assumptions and verification

| Assumption | Dependent scope | Stress test |
| --- | --- | --- |
| A1. Pinned image and logical authenticated pointers. | All source sites and discovered import bindings. | Verify 100 original chained words and check each saved branch against its original producer, private store and reload. Hardware PAC remains unknown. |
| A2. Shared reconstructed frame, aligned record and admitted caller state. | Connection from the bank writers to the class lifecycle and cleanup. | Check the original frame producers, verify the two aligned phase equations, and stop at the unresolved outer phase. |
| A3. Declared external returns and stable cached pointer inside each isolated case. | Matched operands, release order and observed local branches. | Execute the initializer, check both original cache copies, vary acquisition and unlock return values, and test null cache and IOKit failure routes. Native ownership and parallel cache mutation remain unknown. |
| A4. Completed environmental cache with independently supplied byte and primary-context state. | Choice of one class, two classes or no lookup. | Execute the byte helper with both cache controls and check actual ordered class labels at the matching call. |
| A5. The RAX capture records a wire sequence at the logged trap boundary. | Evidence comparison only. | Rehash and decode the archived messages, outputs and deallocations. Caller and lock observations are still required. |

Seven cases retain 390 logical transfers, four codec obligations and the relevant original-byte spans. The evaluator uses O(I+T) time and retained space for I modeled instruction visits and T archived trace characters, excluding the fixed-width solver resource and pinned image mapping. Reproduce with `python3 -B triage_evidence/audit_daemon_class_lock_release.py` using Capstone, Unicorn and Z3. No host IOKit, pthread operation or Mach IPC executes in the audit. [Audit generator](triage_evidence/audit_daemon_class_lock_release.py) [Compressed receipt](triage_evidence/daemon_class_lock_release_audit.json.zst)
