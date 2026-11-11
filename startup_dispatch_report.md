# Startup phase ordering and the event-table callback

Original diagnostic strings and phase-name pointers identify the dispatcher as `kernel_startup_initialize_upto` and phase14 as `mach_ipc`. The wait-table initializer is one of42 rank-zero entries in that phase; three further entries have rank0xffffffff. The dispatcher admits entries through an unsigned phase threshold, calls each authenticated callback with its argument, and advances its saved cursor after return. These source contracts resolve the registered ordering mechanism; they do not prove successful native callback effects, reentrancy exclusion or table visibility. [SD1-SD7]

```text
original 3519-entry section -> original sort/comparator -> sorted table
  -> dispatch(3) from sorter tail
  -> later source calls with increasing thresholds
       ipc boot routine: dispatch(13) ... dispatch(14)

for each eligible entry at saved cursor:
  phase_global = entry.phase - 1 [u32]
  phase-observer helper(entry.phase) [effects unexecuted]
  authenticated callback(entry.argument) [effects unexecuted]
  callback returns -> saved cursor += 24 B
on selected dispatch return: phase_global = requested threshold

mach_ipc / rank 0: wait-table callback and 41 tied peers
mach_ipc / rank 0xffffffff: three later-ranked peers
  [the comparator does not order the 42 equal keys]
```

Evidence: [original source, all records and certificates](triage_evidence/startup_dispatch_checks.json.zst), [extractor/lifter](triage_evidence/recover_startup_dispatch.py), [independent source interpreter](triage_evidence/audit_startup_dispatch.py), [publication auditor](triage_evidence/verify_startup_dispatch_publication.py). Primary collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. This extends the [event-table producer](event_wait_table_report.md), [AES wait/wake contract](aes_event_registration_report.md) and [fixed-zone startup context](kernel_zone_startup_report.md). Reference bytes suffice; no new IDA access occurs.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SD1 | Pinned bytes, compiler ranges, chained pointers and section metadata identify this build. | Recapture all six bodies,3519 records,6950 nonnull pointer fixups and phase-name pointers. |
| SD2 | Native dispatch sees a completely sorted, valid, immutable table and a valid cursor prefix. | Observe actual sorting/relocation, initial cursor, completed prefix and table lifetime; detect changes after sorting. Private sorting is one finite input, not a universal sort proof. |
| SD3 | The declared source call sites are reached with returning earlier helpers. | Establish real boot control flow through the phase13/14 call sites; address order alone is not execution evidence. |
| SD4 | Callback and observer calls return under the ordinary ABI without changing the selected table/cursor/phase premises. | Match real helper side effects, callback control flow, nonreturning paths and callee-saved state. Return alone does not establish successful initialization. |
| SD5 | No concurrent or reentrant dispatcher consumes the same cursor during a callback. | Recover boot-thread/interrupt/reentrancy exclusion and relevant locks. The cursor remains at the current entry until that callback returns. |
| SD6 | Selected consumers observe completed callback stores and retain matching table/thread/provider epochs. | Correlate native callback completion, memory visibility, allocation backing and the later AES event. A phase word alone is insufficient. |
| SD7 | Source interpretation uses private relocated records and a logical PAC identity model; observer/callback bodies are ABI return models. | Execute or observe authentic boot/PAC/allocator/scheduler behavior independently. No native target, key, atomic, IPC, device or IDB operation executes. |

## Metadata and recovered names

Six complete compiler-bounded bodies retain3,026 instructions /12,104 B: the specialized sorter, recursive sort helper, comparator, dispatcher, phase observer and IPC boot routine. Exact nlist entry names are absent; the dispatcher name comes from its original diagnostic literal. Phase labels come from original chained string pointers consumed by the observer, rather than a separately versioned header. [SD1]

| Role | Original address | Evidence |
| --- | --- | --- |
| Specialized sort/bootstrap | `0xfffffe000c62f4e4` | Original section start/end; sort body; tail-dispatch argument3 |
| Recursive sort helper | `0xfffffe000c61b4ec` | Original calls to the comparator and recursive body |
| Comparator | `0xfffffe000c630754` | Unsigned phase then unsigned rank; raw u32 -1/0/1 result |
| Dispatcher | `0xfffffe000c6302c4` | Threshold, authenticated callback, cursor and phase stores |
| Diagnostic literal | `0xfffffe000704fabb` | `kernel_startup_initialize_upto` |
| Phase observer | `0xfffffe000bd3ad04` | Phase-name indexing and separate observer state; body effects excluded from dispatch interpretation |
| IPC boot routine | `0xfffffe000c630790` | Literal threshold13 at `0xfffffe000c6308c8`, call at+4; threshold14 at `0xfffffe000c630bf8`, call at+4 |
| Saved cursor | `0xfffffe000cbc9a48` | File chained pointer to section start `0xfffffe000cbea1d0` |
| Dispatch phase word | `0xfffffe0007f8b5f0` | File u32 zero; pre-callback and selected completion stores |

The startup section spans `0xfffffe000cbea1d0..0xfffffe000cbfebb8`:84,456 B /24 B =3,519 entries. Every nonzero callback/argument word has checked original chained-pointer membership; normalization replaces those pointer words with decoded targets only in private interpreter memory. The original collection and evidence bytes remain unchanged. [SD1,SD7]

| Numeric phase | Original label | Relevance |
| --- | --- | --- |
| 3 | `locks` | Sorter's first threshold |
| 6 | `kmem` | Kernel memory initialization phase |
| 7 | `zalloc` | Prior fixed-zone startup record phase |
| 10 | `sched` | Scheduler phase precedes14 under the sorted-table premise |
| 13 | `oslog` | Earlier literal threshold in the retained IPC boot routine |
| 14 | `mach_ipc` | Event-table startup record phase |
| 15 | `thread_call` | Later phase in comparator order |
| 16 | `sysctl` | 2152 registered entries in this collection |
| 19 | `early_boot` | Later retained phase label |

Seventeen original labels are retained. Missing table labels for other numeric values are not invented. The ordering evidence concerns source phases, not elapsed time or native scheduler availability. [SD1-SD3]

## Comparator, ties and source dispatch

The comparator reads only the two leading u32 words. Its result is zero when both phase and rank match; otherwise it returns raw0xffffffff for the unsigned lexicographically smaller pair and1 for the larger pair. Callback and argument fields do not break ties. Thus rank0xffffffff sorts after rank0 within `mach_ipc`; it is not treated as signed -1. The original callback at `0xfffffe000cbebbf8` has key(14,0), callback `0xfffffe000c6319e4`, and argument0. [SD1,SD2]

The specialized original sorter and recursive helper execute in the private interpreter over the entire relocated collection table. The resulting bytes are a record permutation, their keys are sorted, and128 surrounding guard bytes are preserved. The selected callback lands at zero-based index1335 in that finite output. This index is a reproducible result of the declared source/input/model; no stable equal-key or native ordinal guarantee follows. [SD2,SD7]

| Dispatcher site | Local source contract |
| --- | --- |
| `0xfffffe000c630300` / `0xfffffe000c630304` | Cursor>=section end skips the entry loop |
| `0xfffffe000c630318..0xfffffe000c630320` | Read phase; unsigned phase>requested threshold stops the loop |
| `0xfffffe000c630358..0xfffffe000c63035c` | Store entry.phase-1 modulo2^32 to the dispatch phase word |
| `0xfffffe000c630364` | Call the phase observer with the entry's phase |
| `0xfffffe000c630368..0xfffffe000c630370` | Load callback/argument; X17=0x2abe; `BLRAA X8,X17` with argument inX0 |
| `0xfffffe000c630374..0xfffffe000c630378` | After return, add24 B and store the next cursor |
| `0xfffffe000c630384..0xfffffe000c630388` | Call the observer with the requested threshold |
| `0xfffffe000c6303b4` | Store requested threshold to the dispatch phase word |

The callback's raw X0/W0 return is not tested by the immediate post-return cursor/loop instructions. The observer/callback may have additional real effects, and either may fail to return. A completed phase word therefore certifies neither allocation success nor a usable event table. During a callback, the stored cursor still names that entry; excluding reentrancy is an independent premise. [SD4-SD6]

Under an initially valid cursor, sorted immutable keys, returning calls and no reentrancy, a completed threshold14 traversal consumes all remaining entries with phase<=14. The source phase13 and14 call sites supply a concrete boot-path candidate for that traversal. The prior wait-table record's phase-name gap is now resolved to `mach_ipc`; its allocation/backing, publication visibility and same-event native-use gaps remain. These kernel startup interfaces add no Mach endpoint or message emission. [SD2-SD6]

## Validation and evidence limits

Thirteen UNSAT certificates cover11 straight-line pieces /23 instructions: comparator semantics, unsigned admission, pre-callback phase, callback arguments/modifier, post-return cursor, completion phase and the three literal thresholds. Four hundred independent comparator cases include high-bit phase/rank values. [SD1]

The independent interpreter executes231,961 original sort instruction visits and4215 original helper/comparator calls. It then executes56,717 dispatcher visits across11 thresholds. All3519 callbacks are explicit ABI return models with patterned caller-saved register clobbers; their bodies, including the event-table initializer, do not execute in that traversal. Observer calls are also returning ABI models. Logical PAC operations preserve decoded pointers under an explicit model; hardware authentication is unobserved. [SD4,SD7]

| Selected private threshold | Newly consumed callback models | Consequence in this declared traversal |
| --- | --- | --- |
| 3 | 1029 | Entries through `locks` |
| 7 | 136 | Newly admitted phase7 entries after the earlier6 threshold |
| 13 | 114 | Newly admitted phases8..13 after7 |
| 14 | 45 | All42 rank-zero and3 final-rank `mach_ipc` entries |
| 16 | 2152 | Newly admitted phase16 entries after15 |
| 0xffffffff | 1 | Final registered numeric phase after the earlier19 threshold |

Full threshold counts, cursor values and the sorted-table digest are reproduced by the interpreter. Generator `--verify`, source/fixup recapture, prior91 event-table certificate replay, archive round trips, original-input preservation, exact owned-file publication and decoded path hygiene qualify this increment. Reproduce with `PYTHONPATH="triage_evidence${Z3_PYTHONPATH:+:$Z3_PYTHONPATH}" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/recover_startup_dispatch.py --verify`, then the interpreter and publication auditor in that environment.

Extraction is O(B+I+R+P) source time/space for collection bytes B, instructions I, records R and chain probes P. Interpretation costs O(visits+compared bytes) time and O(code+table+stack) space. No universal sort complexity or correctness theorem is inferred from one source run. SMT cost is separate, with15 s query limits. Offsets/extents are bytes; scalar arithmetic widths are explicit; no boot latency is measured.

| Impact | Remaining evidence | Purpose |
| --- | --- | --- |
| High | Actual boot control flow, callback returns and backing | Establishes invocation and usable table initialization. |
| High | Dispatcher reentrancy/concurrency exclusion and consumer visibility | Qualifies cursor ownership and completion publication. |
| High | Same daemon/request/provider/event/thread epoch through scheduler/interrupt | Establishes authentic cross-layer completion. |
| Medium | Effects of phase observer and equal-key callbacks | Resolves hidden phase-state writes and dependencies within the tie group. |
| Medium | Native PAC and actual relocated/sorted table | Tests the logical-pointer model against runtime authentication and ordering. |

**QG1**: Descriptive metadata, source and ABI analysis requires no normative judgment.

**QG2**: SD1-SD7 enumerate assumptions, dependencies and falsification probes.

**QG3**: Phase identity, comparator/ties, sorting correspondence, thresholds, callback ABI and return/cursor/phase order are covered; native cross-layer investigation remains active.

**QG4**: u32 ordering/subtraction, u64 pointers,24 B stride, exact record/fixup counts and finite source visits are reproducible.

**QG5**: Source/native, sorted/stable, invocation/success, callback/observer, phase/visibility and equal-key/ordinal guarantees remain distinct.

**QG6**: Original bytes, compiler/section metadata, chain membership, diagnostic/string pointers, SMT and independent byte interpretation provide primary provenance.

**QG7**: The continuation table bounds native boot, ownership, phase-helper, PAC and daemon/kext evidence gaps.
