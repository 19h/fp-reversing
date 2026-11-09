# Daemon rwlock creation, fallback image and state publication

The source caller at0x1002DAB28 passes the addresses of primary cell0x1010C8240 and second cell0x1010C5748 to creator0x10043A240. The selected creator requests malloc(200), clears the first8 B, calls pthread_rwlock_init(pointer,NULL), and publishes the full pointer through the destination cell only when the initializer returns0. The caller inspects only the second creation result. A decoded-zero second result selects source store0x1001F1FF8, which writes09 to0x1010B6380 before joining0x1003062A4. That byte is the previously established predicate for the selected IOKit initialization path; continuous reachability across the join remains unknown. [RL1-RL12]

The fallback cell's original rebase points to0x1010B7478. Its200 file bytes exactly match an arm64e SDK-compiled PTHREAD_RWLOCK_INITIALIZER object: signature0x2DA8B3B4 in an8 B long followed by192 zero bytes. This establishes a file-initial static-rwlock layout; current runtime contents and validity remain unknown.

[Source contracts](triage_evidence/daemon_rwlock_lifecycle_contracts.json), [retained profiles](triage_evidence/daemon_rwlock_lifecycle_profiles.json), [independent checks](triage_evidence/daemon_rwlock_lifecycle_checks.json), [source proofs](triage_evidence/daemon_rwlock_lifecycle_proofs.json), [current IDB windows](triage_evidence/daemon_rwlock_lifecycle_live_ida.json), [SDK source](triage_evidence/daemon_rwlock_lifecycle_sdk.c), [compiled data object](triage_evidence/daemon_rwlock_lifecycle_sdk.o), [preservation](triage_evidence/daemon_rwlock_lifecycle_preservation.json) and [scoped gates](triage_evidence/daemon_rwlock_lifecycle_quality_gates.json) retain evidence. The [synchronization report](daemon_iokit_sync_report.md) supplies the primary/fallback consumers. The full interface objective remains active.

```text
paired caller [explicit upstream context premises]
  -> creator(record: destination=&primary)
       malloc(200) -> clear8 -> pthread_rwlock_init
       status0 -> *destination=allocation; encoded result0
  -> creator(record: destination=&second)
       same sequence
  -> read second result only
       encoded zero -> store state09
       other        -> retain previous state
  -> STOP before join0x1003062A4

established separate consumer:
  IOKit initialization checks state09
  acquisition chooses primary if nonzero,otherwise fallback
  file-initial fallback -> SDK-compatible static rwlock image
```

Addresses are preferred file virtual addresses. B denotes bytes. All u32/u64 arithmetic is modular. Status comparisons use signed32 where specified. A20 B accessed record extent does not establish a C sizeof or trailing-padding layout.

## Assumption register

| ID | Assumption or bound | Dependent result | Stress test or falsification probe |
| --- | --- | --- | --- |
| RL1 | Pinned daemon images and current IDB identify the inspected source | Addresses,globals,imports and source roles | Rehash originals; compare423 current IDB rows and14 original spans |
| RL2 | Caller enters0x1002DAB28 with W19=0x6293 and declared bank/table/controller/saved-stack roots | Paired creation and state continuation | Recover actual upstream writers and incoming branches; native/startup ownership remains unknown |
| RL3 | Creator control is0xAED7 and record is8-byte aligned | Selected creator/guard/allocator behavior | Prove caller/callee codecs; vary aligned addresses; other controls remain outside this composition |
| RL4 | Destination cells,records,heaps and frames are valid and disjoint | Source publication and memory epochs | Vary placements,initial cells and states; retain unknown padding/heap masks; native aliases remain unknown |
| RL5 | malloc returns NULL or one declared private200 B token | Allocation continuation | Verify requested extent and null/nonzero branch; native heap allocation/lifetime is unproved |
| RL6 | pthread_rwlock_init returns a declared int32 and has no modeled memory writes | Status routing and source pointer publication | Formal predicates cover all u32 returns; finite values0,12,16,22,FFFFFFFF; native object initialization remains unknown |
| RL7 | Original fixups and exhaustive byte banks retain targets | Creator,imports,globals and joins | Decode32 original fixups and all256 inputs for seven bank rules; hardware PAC remains unproved |
| RL8 | API calls return and source integer ABI/PAC premises apply | Creator returns and caller continuation | Producer checks X19-X29/SP restoration; fresh replays and byte audits; native faults/nonreturning calls remain unknown |
| RL9 | Installed arm64e SDK layout is a comparison model | Static fallback-layout identification and API widths | Compile SDK initializer without running it; compare200 original bytes; target-build equivalence/current state remain unknown |
| RL10 | Decoded result means raw XOR0x8B3DC651 algebraically | Result tables and zero predicate | Trace semantic consumers before assigning internal error names; retain raw words |
| RL11 | Literal-bias/page census is bounded to stated encodings | Discovery and negative search coverage | Search other encodings,aliases and computed addresses separately; no complete writer census claimed |
| RL12 | Stop before join0x1003062A4; separate IOKit consumer proof retains its own premises | Cross-interface producer/consumer relationship | Recover the continuous path and native lifetime/concurrency before claiming operational readiness |

## Record, cells and static fallback

| Creator-record offset | Type / accessed width | Source role |
| --- | --- | --- |
| +0 | u32 /4 B | Encoded selected control |
| +4..+7 | Padding /4 B | Unknown and unread in the selected path |
| +8 | Pointer u64 /8 B | Destination-cell address,not its existing pointer value |
| +0x10 | u32 /4 B | Source-written encoded result |

For record R, `K=u32((low32(R) XOR0xDC40790B)*0x5973A279)`. The caller stores `u32(0xAED7-K)`; the callee adds its equivalent key. The first and second caller expressions are independently lifted, and the selected control derives from W19+0x4C44. Both creator calls preserve the caller's integer context under the stated summaries. [RL2-RL8]

| Storage | Address / extent | Established role |
| --- | --- | --- |
| Primary destination cell | 0x1010C8240 /8 B | Creator argument at0x1002DAC48; publication through X22 at0x1002097DC |
| Second destination cell | 0x1010C5748 /8 B | Creator argument at0x1002DAD48; same publication instruction |
| Fallback pointer cell | 0x1010B9638 /8 B | File-initial rebase to0x1010B7478; earlier acquisition/cleanup fallback |
| Static fallback object | 0x1010B7478 /200 B | Exact SDK static-initializer byte match |
| State byte | 0x1010B6380 /1 B | Source store09 at0x1001F1FF8 after second zero result |

Both destination cells belong to __common with Mach-O zerofill type1. The second cell lies within the segment's rounded file extent but remains owned by the zerofill section. Segment-mapped padding bytes do not establish its native contents. Both old values are explicit private fixtures in the case set. [RL1,RL4,RL9]

The SDK compilation verifies sizeof(pthread_rwlock_t)=200, signature offset0, opaque offset8, pointer width8 B, int width4 B, malloc and initializer signatures, and ENOMEM=12/EBUSY=16. It emits a data object only. Original object bytes are `u64(0x2DA8B3B4)` followed by192 zero bytes. No native SDK code or pthread operation executes. [RL9]

## API and control-flow contracts

| Source operation | PC | Original slot / IA discriminator | Arguments |
| --- | --- | --- | --- |
| First creator call | 0x1002DAC48 | 0x1010A0558 /0x8C6D | X0=record; destination=&primary |
| Second creator call | 0x1002DAD48 | Same slot /modifier | X0=same record; destination=&second |
| malloc | 0x10019385C | 0x10109FF58 /0x6AA4 | X0=200 bytes |
| pthread_rwlock_init | 0x100130FCC | 0x1010A0DD0 /0xA027 | X0=allocation,X1=NULL |
| Pointer publication | 0x1002097DC | Source STR X20,[X22] | Full64-bit allocation pointer through destination |
| Result publication | 0x1001C0128 | Source STR W10,[X19,#0x10] | Raw u32 result in the record |

The creator tests the destination address for NULL, not the old contents of the cell. A NULL destination returns before allocation. A nonnull destination requests a fresh allocation without reading the previous cell value. Successful publication can replace an old pointer; ownership of that old object and invocation count remain unknown. [RL3-RL8]

The source clears four u16 fields at allocation offsets0,2,4,6 before calling the initializer. The private model leaves the remaining192 B unknown. A modeled zero return and pointer publication do not establish a natively initialized object. Original import bindings identify the APIs; the private guest uses the shared opaque target0x7C100000,which is not a native address. [RL5,RL6]

The initializer's source partitions use signed status>=12, then signed status>15, and exact equality tests for0,12,16. Their composition is valid for all u32 status words:

| Condition | Raw result | Algebraically decoded signed result | Destination effect |
| --- | --- | ---: | --- |
| Destination address NULL | 0x74C29D88 | -42023 | No allocation or publication |
| malloc returns NULL | 0x74C29D85 | -42028 | Existing cell retained |
| Initializer returns0 | 0x8B3DC651 | 0 | Allocation pointer published |
| Initializer returns12 | 0x74C29D85 | -42028 | Existing cell retained |
| Initializer returns16 | 0x74C29D82 | -42029 | Existing cell retained |
| Other nonzero initializer return | 0x74C29D83 | -42030 | Existing cell retained |

There is no free/destroy call in the followed creator-return fragments. In384 modeled nonzero-initializer returns, allocated tokens remain unpublished by this helper. Reclamation elsewhere is unknown; this is source-local ownership evidence,not a native leak claim. A destroy binding at0x1010A0F58 and a second initializer binding at0x1010AB938 are cataloged but not called by this path. [RL5,RL6,RL12]

The four negative decoded results lie inside the earlier normalizer's preservation interval -49998..-42001. This is an algebraic compatibility between result domains; it does not establish a call edge to0x100422A60.

## Paired publication and state09

The caller's minimum source sequence is:

1. Encode control and primary-cell address; call the creator.
2. Re-encode control and second-cell address in the same record; call the creator again.
3. Read only the second result at record+0x10.
4. If raw result equals0x8B3DC651, write state09; otherwise retain the previous state.
5. Join0x1003062A4 in either case.

Every one of288 paired runs has an independently checked interval between the first return and second call with no read of the first result. The second call overwrites the result field. Forty cases have first creation failure and second success: state09 is still published. Forty have first success and second failure: the primary pointer is published but the state retains its prior0/0A fixture. [RL2,RL4-RL8]

This identifies a source producer for the byte required by the selected IOKit initialization entry and a source writer for its primary synchronization pointer. It does not prove continuous execution from this join into that entry, cross-thread ordering, native lock validity or full initialization readiness. If the primary remains zero and the fallback retains its file-initial target, the earlier acquisition contract selects the statically initialized fallback image. That last statement composes separate declared interfaces; it is not a new native trace. [RL9,RL12]

## Verification and bounded continuation

The290 profiles contain288 paired cases and two isolated NULL-destination guards. Paired cases vary each allocation/initializer outcome independently, two placements, zero/nonzero old cells and initial state0/0A. All290 undergo independent source-byte/read/write epoch reconstruction;12 are freshly replayed. The source makes576 malloc requests and480 initializer calls, publishes96 pointers, and writes state09 in48 cases. The two source cells and all heap/record snapshots retain provenance masks.

Thirty-two source-proof pairs cover187 lifted instructions, including arbitrary-u32 initializer mapping, zero-only publication, record codecs and second-result/state predicates. Fourteen original spans, seven exhaustive banks,32 original fixup decodes, four import bindings and423 current IDB rows pass. The literal census finds two MOVK64 high-half858B sites and seven C81B sites; one C81B match belongs to a larger unrelated64-bit constant. No direct ADRP to the primary page is found in that bounded scan. Other reference forms remain outside the census.

Preservation covers2658 preceding artifacts, with2652 unchanged and exactly six designated existing report/index edits. All three original supplied inputs retain their sizes and hashes.

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High | Incoming context/root producers for0x1002DAB28 | Replace caller premises and establish initialization trigger |
| High | Continuous path from join0x1003062A4 to IOKit entry/callers | Establish whole startup/control sequence |
| High | Creator-local unpublished allocations and later cleanup | Ownership/reclamation beyond this helper |
| High | Native primary/fallback cell epochs and synchronization | Replacement,lifetime and concurrent-use guarantees |
| Medium | Consumers of second cell0x1010C5748 | Role of the second rwlock and relation to state09 |
| Medium | Other initializer/destroy binding callers | Complete lifecycle graph without discriminator inference |

No additional Mach endpoint,right transfer,message identifier or emission location is established. The cells,records,heap objects and marker are process-local architectural interfaces.

## Quality gates and reproduction

QG1: factual analysis. QG2: RL1-RL12 include dependencies and falsification probes. QG3: selected paired creator,static fallback and marker producer covered;full objective incomplete. QG4: accessed extents,u16/u32/u64,signed predicates,unknown192 B and compile-only SDK comparison are explicit. QG5: destination/value,first/second result,file/runtime state,publication/native initialization and producer/continuous path are distinguished. QG6: original bytes/fixups,SDK object,IDB,source proofs and finite cases have separate provenance. QG7: impact-labeled bounded continuations. Scoped gates are issued after verification and preservation pass.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_rwlock_lifecycle.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_rwlock_lifecycle.py
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_rwlock_lifecycle.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_rwlock_lifecycle.py
```
