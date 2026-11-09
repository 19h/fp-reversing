# Original kernel message construction and populated-cache allocation

The 44-byte notification path now executes original kmsg policy/construction, the populated zone-cache allocator and its zero-memory check. The whole-kmsg allocation return model is removed from seven notification cases. Standalone constructor cases produce all four storage classes, checked arithmetic/heap failures, spare-cache promotion, a different CPU-index stride, pending-preemption handling and explicit zero-check/refill/fallback frontiers. Raw cache/zone/thread state, external heap returns and remaining transport/authentication/retirement effects remain premises. Native startup, cache population and failure guarantees remain unknown. [KA1-KA8]

Evidence: [13 complete functions /2071 instructions and original metadata](triage_evidence/kernel_kmsg_allocation_source.json), [36 private CPU components](triage_evidence/kernel_kmsg_allocation_profiles.json), [fresh producer/replay, field/cache oracles and three policy proofs](triage_evidence/kernel_kmsg_allocation_checks.json). Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Original files suffice; no new IDA access, IDB/memory-store mutation or native target/IPC occurs. Complete capture does not imply all-branch execution.

## Original interfaces and allocation policy

| Entry/site | Established local role |
|---|---|
| `0xfffffe000bcc24a4` | Anonymous kmsg constructor: `(send_bytes,auxiliary_bytes,descriptor_count,flags)` -> pointer or NULL on selected checked failures |
| `0xfffffe000bcc2688` -> `0xfffffe000bd75c64` | Original zone-cache request `(zone,statistics_base,0x8004)` |
| `0xfffffe000bd75c64` | Pop current/spare per-CPU cache entry, account bytes and restore nesting; cache miss has deeper paths |
| `0xfffffe000bc9d9c0` | Original vector/scalar nonzero-memory check; selected extent 256 bytes |
| `0xfffffe000bcc25f8` / `...2668` | External body/header heap allocation calls; raw returns modeled |
| `0xfffffe000bcc274c` | Request body release after header-heap failure |
| `0xfffffe000be8663c` | Pending-preemption helper requested after nesting drops to 0; effect modeled |
| `0xfffffe000bd75e20` | Cache-refill boundary; stopped before its body |
| `0xfffffe000bd76394` | Zone fallback; body captured, stopped before execution |
| `0xfffffe000c633ccc` | Nonzero-cache-object failure handler boundary; not executed |

The [earlier send-only analysis](kernel_notification_send_report.md) supplied an initialized kmsg model. Here raw cache entries are explicit inputs, but original instructions select and remove the entry, verify its zero contents and construct the returned fields. No kmsg-return, zone-pop or zero-check result model remains. [KA2,KA3]

For flags 1 and auxiliary extent0, the checked budget is `send_bytes + 68`. Inline class 0 is selected when that sum is below 193, equivalent to `send_bytes <= 124` over all u32 inputs. This is proved with explicit overflow admission. A 44-byte notification and an 88-byte/one-descriptor request both select class 0 in the constructor probes. The latter is a constructor input test, not a new authentic FairPlay transaction. [KA3,KA4]

| Selected constructor inputs `(bytes,aux,descriptors,flags)` | Class | Header/body capacity words at +0xf8/+0xfc |
|---|---|---|
| `(44,0,0,1)` / `(88,0,1,1)` / `(124,0,0,1)` | 0 | Both remain0 |
| `(125,0,0,1)` | 1 | 36 /161 |
| `(392,0,2,1)` | 1 | 68 /396 |
| `(176,0,8,1)` | 1 | 164 /84 |
| `(180,0,9,1)` | 3 | 180 /72 |
| `(125,0,0,0x11)` | 2 | 193 /0 |
| `(180,0,9,0)` | 3 | 180 /152 |

Capacity words and heap-request extents are not copied-payload extents. For admitted external layouts with flag bit4 clear, the header budget is `16*descriptor_count + 36`; the class 1/class 3 test is at 169. A second constrained all-u32 proof establishes the corresponding descriptor threshold8/9. Class1 publishes a logical signed header pointer to kmsg+0x40 and an external body pointer; class 2/3 publish an external header pointer. Original stores publish class bits at +0x3f, auxiliary low16 bits at +0x30, conditional state byte 1 at +0x32 for flag bit5, pointers+0xe8/+0xf0 and capacities+0xf8/+0xfc. Logical PAC is not hardware signing. [KA3-KA5]

The raw heap flag calculation maps constructor bit3 to heap bit15 and bit1 to heap bit2; a third all-u32 proof checks this formula. Native flag names and raw heap byte-initialization semantics are not assigned. Four arithmetic probes return NULL before zone allocation. A declared body-heap NULL returns NULL before zone access. A declared header-heap NULL requests release of the previously supplied body, then returns NULL. These are original checked paths with declared outcomes, not native OOM observations. [KA4,KA6]

## Element size, static metadata and runtime limits

The original file's kmsg zone/statistics cells at `0xfffffe000caec680` are sixteen zero bytes. The probes explicitly replace them with zone/statistics fixtures. No live zone identity or metadata is obtained from those zero cells. [KA1,KA2]

A fixup at `0xfffffe000cbc8318` points to original string `"ipc kmsgs"` at `0xfffffe000704984a`; the adjacent u64 at `0xfffffe000cbc8320` is 256. The surrounding 48-byte window is retained as a candidate initialization record. Its startup consumer and connection to the runtime zone cells remain unknown. This is separate from the directly derived inline bound: header offset 64 plus inline capacity 192 requires a minimum 256-byte element. [KA1,KA2]

The declared zone element-size field is 256 at zone+0x34. The selected allocator reads that field for accounting and zero-check length. The static size word is consistent with this fixture; it does not independently establish runtime zone size. The earlier 1024-byte kmsg window was an observation reservation, not a proven native element size. [KA2,KA3]

Layout inference: `0xe8 - 0x40 = 168` bytes precede the external-pointer metadata within the inline area. The class 1/class 3 threshold 169 is consistent with retaining that metadata when the body is external; the observed descriptor budgets 164 and 180 lie on opposite sides. This is an arithmetic/layout inference, not recovered source-level intent. [KA4,KA8]

## Per-CPU cache, zero check and control context

```text
original constructor policy
  -> original zone-cache allocator
       -> thread nesting 0 ->1
       -> select cache/statistics at base + (CPU_index <<14)
       -> optionally promote spare list
       -> account256 bytes; pop/clear slot; nesting 1 ->0
       -> optional pending-preemption helper
       -> original zero-memory check over 256 bytes
  -> original constructor field stores -> returned kmsg
       -> seven original notification preparation/send/caller-return cases
```

The selected cache stores current/spare u16 counts at+4/+6 and slot-list pointers at+8/+0x10. Original code removes the last current slot, clears it, increments the selected u64 byte statistic by 256 and restores thread+0x1c8 nesting to 0. Spare promotion swaps the two list pointers, transfers the spare count to current and clears the spare count before the pop. A second CPU-index fixture verifies the 16384-byte stride used for both cache and statistics selection. These addresses and runtime CPU/cache validity remain declared environmental inputs. [KA2,KA3,KA5]

The original zero check executes its NEON reduction. Twenty-eight components read every byte in the declared 256-byte element and exclude the A5 guard immediately beyond it. Six invalid-cache probes place a nonzero byte at offsets0,63,64,127,128 or255. Each reaches the original failure-handler boundary with `(zone,element,256)` after the cache pop/accounting and nesting unwind. No native stale-object condition or defect is established. [KA3,KA5-KA7]

The empty-cache probe stops before refill; the NULL cache-pointer probe stops before zone fallback. Both retain nesting 1 because execution is still inside the allocation context. They are not NULL-return cases or complete unwinds. The pending-flag 4 probe reaches the original helper after nesting becomes0; only that helper's return is modeled. No scheduler/preemption effect is claimed. [KA5-KA7]

## Notification integration and refinement of earlier probes

Seven components restore the exact source notification boundary, remove the earlier initialized-kmsg layout overlays, and supply explicit raw cache/zone/thread epochs. The original allocator receives `(44,0,0,1)`, obtains the populated-cache object and constructs class 0. The original message preparation, kernel right-copyin, trailer inputs, common send and notification caller epilogue then execute. Six declared queue returns and one spare-cache variant retain the previously verified header/body/trailer bytes and caller-return behavior. [KA3,KA6]

The earlier all-class44-byte cases established consumer-layout behavior under supplied layouts. The actual constructor here produces class 0 for that input; class 1/2/3 are instead produced by the distinct constructor inputs in the table above. Likewise, the earlier whole-allocator NULL substitution is not a source-produced return for this populated-cache44-byte path. The constructor passes flags 0x8004 to the zone allocator and does not NULL-check its returned object before field access. Populated-cache replay establishes a non-NULL return under the declared cache prerequisites. Cache-miss, waiting, failure guarantees and native reachability remain unresolved; no universal allocation guarantee is inferred. [KA2,KA4,KA7,KA8]

Remaining notification models are raw transport byte copying, keyed-hash returns, tag/validation, destination lock/preflight/queue and destruction. The source-produced no-senders request state is preserved. Actual send-once consumption, delivery, authentication and allocator retirement remain unknown. [KA6-KA8]

## Assumption register and verification

| ID | Premise / dependent claims | Stress test or falsification probe |
|---|---|---|
| KA1 | Pinned collection, source bodies and candidate metadata identify this build | Recapture all bytes/fixups; recover candidate startup consumer and match runtime build separately |
| KA2 | Raw zeroed element, zone size/cache/statistics/thread epochs and heap pointers are declared | Recover native zone creation, population, element sizing, CPU ownership and heap guarantees |
| KA3 | Exact source/zero RAM origins and explicit overlays define standalone and notification inputs | Reconstruct every patch/register/global; fresh replay all bytes, frames and field/cache oracles |
| KA4 | Selected flags/widths and admitted external budgets bound policy interpretation | Three fixed-width proofs plus size124/125, descriptor 8/9, flag, auxiliary and overflow probes; extend other callers |
| KA5 | Current/spare populated cache and256-byte zero check represent selected allocator branches | Verify other counts/CPUs, refill, fallback, actual element extents and zero-state producers |
| KA6 | Raw heap/pending and remaining transport/hash/lock/destructor outcomes remain models | Execute or independently establish those effects and final right/storage ownership |
| KA7 | Logical PAC and private nesting/cache writes do not prove native concurrency, preemption or OOM | Match hardware keys/locks, scheduler effects, cache validity and real failure prerequisites |
| KA8 | Constructor/layout refinement does not complete authentic FairPlay continuity | Join live endpoint registration, actual request/reply allocation, daemon execution and complete close/retirement |

Thirty-six fresh CPU replays verify 7960 original instruction visits, 2592 reads /18727 bytes, 1503 writes /10926 bytes, 72 primitive models, 151 allocation/cache frames, 49 notification frames and 36 complete RAM images /37748736 bytes. Ninety-two global records and all final SIMD/system states match. Twenty-eight cache pops and full 256-byte zero checks are verified; fifteen standalone field images match independent plans. Twenty-eight components return; six stop at the zero-check failure handler and two at refill/fallback. The notification producer has a separate fresh replay. Seven transport byte-copy effects total 308 bytes; fourteen keyed-hash inputs remain explicit models.

```text
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_kmsg_allocation.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_kmsg_allocation.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_kmsg_allocation.py
```

Recovery/replay time is O(image + source + visits + RAM + effects), space O(image + source + RAM + journals). The zero-check scan is O(element bytes), with 256 bytes tested. Each private RAM image is 1048576 bytes. Counts and arithmetic are exact finite observations; fixed-width solver runtime has no claimed general polynomial bound.

| Impact | Further interface evidence |
|---|---|
| High | Candidate initialization record consumer, runtime zone/statistics publication and actual cache population |
| High | Refill/fallback and flags 0x8004 failure/waiting behavior; replace remaining raw-storage prerequisites |
| High | Original construction joined to descriptor-bearing FairPlay replies and complete queue/destructor/right consumption |
| Medium | Other auxiliary/flag modes, multi-entry cache reuse, CPU ownership, preemption and actual authenticated pointers |

QG1: Factual technical analysis; no normative judgment required.
QG2: KA1-KA8 register premises, dependent claims and falsification probes.
QG3: Scoped allocator/constructor, storage fields, cache/statistics/thread context, zero guards, failure/frontier and notification integration are covered; the full goal remains incomplete.
QG4: Explicit widths, budgets/capacities, pointer offsets, byte counts, formulas, commands and complexity are reproducible.
QG5: Candidate versus runtime metadata, observation versus element extent, consumer layouts versus constructor-produced layouts, injected NULL versus returned NULL, and held versus unwound context are distinguished.
QG6: Original bytes/fixups, fresh source producer, exact state/oracles, scalar queries and independent CPU replay provide primary provenance.
QG7: Impact-labelled continuation targets unresolved startup, storage, concurrency, transport and authentic FairPlay interfaces.

[Preservation](triage_evidence/kernel_kmsg_allocation_delivery.json), [scoped gates](triage_evidence/kernel_kmsg_allocation_quality_gates.json), [publication verifier](triage_evidence/verify_kernel_kmsg_allocation_publication.py). The full goal remains active.
