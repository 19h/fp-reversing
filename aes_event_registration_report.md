# AES event registration, hashed queues and mutex sleep

Original source connects both AES wait families to the same global event-hash/queue interface, but with different interruptibility inputs. Configuration supplies 2; the final synchronous carrier wait supplies 0. With the workloop's raw mutex action 0x10, a registration result other than u32(-1) follows a path without mutex release or a block call. Selected configuration continuations retry without testing that sleep return. These are conditional source contracts; an initialized native queue, matching waiter, lock ownership and scheduler progress remain unknown. [ER1-ER8]

```text
configuration event P+0x150, interruptibility 2
carrier event C,             interruptibility 0
  -> gate/event-source/workloop -> lck_mtx_sleep(M,0x10,event,I)
  -> assert_wait(event,I) -> global event hash -> registration wrapper
  -> mark-wait predicate
       +-> abort: raw result 2; no new membership on this branch
       `-> selected admitted publication: raw result 0xffffffff
            -> queue insertion / event and queue identity stores

lck_mtx_sleep registration result
  +-> !=0xffffffff: cleanup -> return; release/block path bypassed
  `-> ==0xffffffff: release -> block helper -> reacquire -> cleanup

interrupt/common completion -> wake(event,false,0)
  -> same event hash [same table epoch required]
  -> wake wrapper / matching membership / scheduler [not executed]
```

Evidence: [original source and certificates](triage_evidence/aes_event_registration_checks.json.zst), [extractor/lifter](triage_evidence/recover_aes_event_registration.py), [independent integer/byte-memory interpreter](triage_evidence/audit_aes_event_registration.py), [publication auditor](triage_evidence/verify_aes_event_registration_publication.py). Earlier context: [trace/wakeup](aes_trace_wakeup_report.md), [synchronous carrier wait](aes_synchronous_wait_report.md), [source wait membership](kernel_waitq_enqueue_report.md), [receiver selection](kernel_waitq_receiver_report.md).

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| ER1 | The pinned collection, compiler boundaries, original chained slots and exact symbols identify this build. | Rehash and independently decode all fourteen bodies and five slots; compare frozen workloop/mark-wait source. |
| ER2 | Event, queue, provider, gate, workloop, mutex and thread refer to compatible live objects with valid extents and lifetimes. | Establish native allocations, aliasing, owner/class identity and a single event/job epoch. Pointer equality in private components does not establish native correspondence. |
| ER3 | Wait and wake observe the same table root/count epoch; count and extent satisfy the stated bounds. | Match boot/runtime table publication, table capacity and interleavings. A hash bucket alone is not full event identity or waiter membership. |
| ER4 | Registration reaches the declared mark-wait prefix with prior identity/state/lock guards admitted. | Match thread initialization, prior wait fields, DAIF and queue locking; initial state 4 in the finite cases is declared. |
| ER5 | The selected normal publication bypasses the optional thread+0x2d8 path; saved ABI fields and hints remain stable. | Inspect a nonnull optional pointer and its extra state-bit path before generalizing the complete publication mask. |
| ER6 | Each compare-exchange uses a declared single-RMW observation; fast-path conclusions also assume the stated policy word. | Match actual ownership, memory-ordering context and contention. Separate unlock/relock observations do not establish an admissible concurrent interleaving. |
| ER7 | Calls return with ABI-preserved saved registers and the declared thread identity. Counter pairing assumes no intervening writer. | Establish real lower helper effects, blocked-thread resumption and mutex reacquisition; capture slow paths and counter/priority policy before inferring balance over a native lifetime. |
| ER8 | Only source semantics, SMT queries and private finite scalar/byte arrays are evaluated. | Obtain a correlated native daemon/kext/provider request, event registration, interrupt and result. No target scheduler, atomic, MMIO, key or IPC operation executes. |

## Primary source and call interfaces

Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Fourteen complete compiler-bounded bodies retain 1563 instructions / 6252 B. `_lck_mtx_sleep`, `_assert_wait`, `_thread_wakeup_prim` and the gate/workloop interfaces have exact nlist definitions. The lower registration/wake wrappers and core have no exact entry symbol in the retained nlist; their names here describe source roles. IDA was unnecessary because the reference bytes suffice. [ER1,ER8]

| Interface | Preferred address | Source arguments / role |
| --- | --- | --- |
| `IOWorkLoop::sleepGate` | `0xfffffe000c519a8c` | Saves depth, clears owner/depth bookkeeping and calls mutex sleep |
| `_lck_mtx_sleep` | `0xfffffe000bd0c8f4` | (mutex, raw action 0x10, event, interruptibility) |
| `_assert_wait` | `0xfffffe000bd28394` | (event, interruptibility); rejects null event before ordinary hash path |
| Registration wrapper | `0xfffffe000bd6dfdc` | (hashed queue, full event, interruptibility, deadline=0) |
| Shared registration core | `0xfffffe000bd6bc48` | (queue,event,I,urgency=0,deadline=0,leeway=0,current thread) |
| Mark-wait body | `0xfffffe000bd28280` | Effective interruptibility, abort/state/result publication |
| `IOWorkLoop::wakeupGate` | `0xfffffe000c519a78` | Maps (loop,event,false) to (event,false,raw result=0) |
| `_thread_wakeup_prim` | `0xfffffe000bd2b480` | Nonnull-event hash; false selects raw maximum 0xffffffff, true selects 1 |
| Wake wrapper | `0xfffffe000bd6e22c` | Receives queue,event,result,flags=0,maximum; lower matching/scheduler behavior remains unexecuted |

The existing Mach receive producer reaches the same registration core with urgency 0x10 and event 0 through its port/turnstile interface. The AES global-hash route uses urgency 0 and a nonnull full event. Shared code does not imply equal queues, event domains or native thread epochs. These are kernel scheduling interfaces; they create no additional Mach-port endpoint or message emission. [ER2-ER4]

## Shared event hash and table epoch

For u64 event E, the two original source cuts compute identical modular arithmetic. Multiplications and XOR/shift stages below have u64 width; H and count N have u32 width. [ER1,ER3]

```text
A = ((E XOR (E >> 31)) * 0x7fb5d329728ea185) mod 2^64
B = ((A XOR (A >> 27)) * 0x81dadef4bc2dd44d) mod 2^64
H = low32(B XOR (B >> 33))
index = H AND ((N-1) mod 2^32)
byte_offset = zero_extend_u64(index) * 24 B
queue = table_base + byte_offset      [source checked-offset domain]
```

Wait reads table root/count at `0xfffffe000bd283c4` / `0xfffffe000bd28404`; wake reads the same globals at `0xfffffe000bd2b4b0` / `0xfffffe000bd2b4f0`. Under identical E/root/count snapshots, both source address expressions match. Positive power-of-two N implies index<N. Adding N<=2^26 bounds the 24 B stride product to the source's nonnegative signed32 offset domain. Table backing, pointer arithmetic validity and native count constraints remain separate premises. [ER3]

| Original file item | Retained value | Interpretation limit |
| --- | --- | --- |
| Root slot `0xfffffe0007e66df8` | Format-8 chained pointer -> `0xfffffe000cbca628` | File relocation identity, not a current runtime root |
| Count `0xfffffe0007e66e00` | u32 value 1 | Initial file value; runtime publication unknown |
| First 24 B at decoded root | All zero | Does not satisfy the wrappers' queue-valid byte+5 bit-0 test as a live initialized queue |
| Mutex policy word `0xfffffe000cb0bc50` | u32 value 0 | File value; each fast-path proof uses an explicit policy snapshot |

The core stores the full event at thread+0x18 and outer queue identity at thread+0x28; hash collisions do not merge these identities. Its selected empty insertion also initializes a self-ring and queue head. These local stores are proved separately from prior queue/thread guards and locking. The preceding receiver report supplies the FIFO equality checks; no native wake matching or removal executes here. [ER2-ER4,ER8]

## Interruptibility and registration result

Let I=input_interruptibility&3, C=u16[thread+0xc8]&3, EFF=min_unsigned(I,C), and F=u32[thread+0x210]. The five-path source prefix implements:

```text
abort = (EFF != 0) AND ((F & 0x10) != 0)
        AND ((EFF == 2) OR ((F & 0x20) == 0))
```

| Source input | Consequence under the declared prefix |
| --- | --- |
| Carrier wait, raw I=0 | EFF=0; this abort predicate is false |
| Configuration wait, raw I=2 | EFF in 0..2; abort can occur when the thread cap and pending fields admit it |
| Abort arm | Raw result 2; hint byte+0x58d cleared; if F bit5 is set, F bits4/5 clear |
| Selected normal publication | Raw result 0xffffffff; state ORs 9 for EFF=0 or 1 otherwise; byte+0xcb records EFF==2; hint transfers to+0x58e and clears at+0x58d |

These statements do not identify every symbolic thread-flag name or prove native admission. The optional nonnull thread+0x2d8 branch can augment the state mask and is outside the selected publication composition. In the shared core, mark-wait's raw -1 result selects insertion; other results bypass that insertion. [ER4,ER5]

The carrier wait's earlier caller asserts on a nonzero returned sleep result. Configuration's eight sleep-return continuations instead reload status or prepare another helper attempt without testing that returned value. A complete selected CFG walk from each of the eight call returns finds no X0/W0 read before its first overwrite; this distinguishes a new helper's result test from the earlier sleep result. Whole configuration termination and successful device admission remain unproved. [ER5,ER7]

## Mutex release, block and reacquire

The workloop clears u32 depth at mutex+0x20 and u64 owner bookkeeping at+0x18 before calling `_lck_mtx_sleep`. The physical mutex word used below is at+8. Bookkeeping clearing therefore does not itself release that mutex. The action-0x10 source registers the wait before reaching the physical release path. [ER2,ER6,ER7]

| Registration result W0 | Action-0x10 continuation |
| --- | --- |
| 0xffffffff | Enter release path at `0xfffffe000bd0c990`; then call block helper at `0xfffffe000bd0c9c4` after any returning slow release helper |
| Any other u32, including 2 | Reach cleanup at `0xfffffe000bd0ca70`; release and block sites are absent from this selected path |

The two-path dispatch is proved for all u32 registration results. A nonzero result alone does not imply that a block call occurs. This is a control-flow result; a native thread's wait-queue state is not supplied by it. [ER4,ER6,ER7]

| Source operation | Exact local contract under a declared atomic observation |
| --- | --- |
| CASL at `0xfffffe000bd0c9a8` | Compare u32[mutex+8] with u32[thread+0x518]; replace that u32 with 0 on equality; return the observed word in W2 |
| Release fast branch | Observed word equals that thread-ID word AND policy snapshot=0; other outcomes reach a lower release helper |
| Block call setup | X0=0, X1=0, W2=0 before call `0xfffffe000bd0c9c4`; actual scheduler behavior is unexecuted |
| CASA at `0xfffffe000bd0c9e8` | Compare u64[mutex+8] with 0; on equality install zero-extended thread-ID word; return the observed u64 in X2 |
| Reacquire fast branch | Observed u64=0 AND separately read policy snapshot=0; other outcomes reach lower reacquisition code |

The differing u32 release and u64 reacquisition widths are retained. The independent byte-memory checks verify that the u32 operation preserves the adjacent upper four bytes. Each compare-exchange's observation and effect are interpreted independently; no native atomic instruction, lock contention or memory-ordering experiment is performed. [ER6]

Action bit4 also increments u16[thread+0x21e] before registration and records that thread pointer in a stack cell. Cleanup decrements the current thread's same u16 field and can enter additional flag-dependent helper code. The isolated increment/decrement pair balances modulo 2^16 under a stable field/thread premise. Cleanup's zero-result branch tests the full u32 subtraction and requires its incoming u16 value to equal 1. Complete lower policy effects, counter lifetime and native resumption remain unknown. [ER7]

The source saves the sleep/block result across cleanup in a callee-saved register, then returns it. The workloop restores its owner/depth bookkeeping after the returned call. This preservation assumes ordinary callee returns and does not prove successful blocking, physical reacquisition or event progress. [ER7]

## Wake return and validation

The false Boolean used by AES selects raw maximum 0xffffffff at the wake wrapper; true selects 1. The wrapper/core chain uses the full event. `_thread_wakeup_prim` maps a lower raw result of 0 to 48 (0x30), and any nonzero raw result to 0. No unmatched enum name or actual waiter count is inferred from that translation. [ER3,ER7,ER8]

Forty-seven new UNSAT certificates cover twenty straight-line pieces / 130 lifted instructions and both selected source forests: five mark-wait paths and two mutex-result paths, all seven SAT-feasible. Three SAT premise controls cover table-epoch mismatch, possible input-2 abort and a nonzero result that does not select blocking. The publication audit also rechecks the preceding 68 trace/wakeup UNSAT certificates. [ER1-ER8]

| Independent finite cases | Count |
| --- | --- |
| Paired hash calculations | 3132 |
| Mark-wait / selected publication | 125 / 99 |
| Mutex-result dispatch | 6 |
| Release / reacquire RMW snapshots | 96 / 48 |
| Counter pairs / empty memberships / wake translation | 5 / 261 / 5 |
| Total | 3777 |

Hash cases include zero only as an arithmetic-cut probe; full ordinary entry requires a nonnull event. Finite payloads, table roots, queue bytes, thread fields and atomic observations are declared test data. The interpreter imports neither the new generator nor Z3. Generator `--verify`, independent interpretation, original-source audit, archive round trips, original-input preservation, exact artifact ownership and decoded path hygiene qualify this increment. Reproduce the source check with `PYTHONPATH="triage_evidence${Z3_PYTHONPATH:+:$Z3_PYTHONPATH}" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/recover_aes_event_registration.py --verify`, then run the independent interpreter and publication auditor with the same dependency environment.

Extraction/path construction is O(B+I+P) time/space for collection bytes B, decoded instructions I and path visits P. Hash evaluation is O(1) per event. Finite interpretation costs O(cases*visits+compared bytes) time and O(code+private bytes) space. SMT cost is separate, with 15 s observation limits. Widths, modular arithmetic and byte extents are exact; no scheduling latency is measured.

| Impact | Remaining evidence | Purpose |
| --- | --- | --- |
| High | Native global wait-table initialization and root/count epoch | Establishes actual hash-queue backing and admission. |
| High | Provider/gate/workloop/mutex ownership plus real thread admission | Connects source pointer events to registered native waiters. |
| High | Interrupt/status producer, matched event membership and scheduler continuation | Establishes causal wakeup, retry and returned hardware result. |
| Medium | Slow mutex helpers, counter policy and optional mark-wait state path | Completes lock/result behavior beyond selected snapshots. |
| Medium | Same daemon/request/descriptor/job epoch across final and configuration waits | Separates the two event roles in an authentic transaction. |

**QG1**: Descriptive source, ABI and control/data-flow analysis requires no normative judgment.

**QG2**: ER1-ER8 enumerate assumptions, dependent results and falsification probes.

**QG3**: Shared hashing, registration arguments/abort/publication, selected insertion, mutex-result dispatch, RMW widths, counter/result preservation and wake translation are covered. Native and broad interface recovery remain active.

**QG4**: u16/u32/u64 arithmetic, event/hash/count widths, 24 B stride, byte preservation and complexity are reproducible.

**QG5**: File/runtime state, bucket/full-event identity, registration/blocking, bookkeeping/physical mutex fields, separate atomic observations and native progress remain distinct.

**QG6**: Original bytes/bounds/symbols/chains, frozen source comparisons, SMT certificates and independent finite interpretation supply primary provenance.

**QG7**: The impact-ranked continuation table bounds further work; no native wait, device completion or daemon/kext pairing is established.
