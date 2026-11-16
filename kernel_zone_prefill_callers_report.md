# Zone prefill, partition lists and incoming wait-arm calls

The unnamed routine at `0xfffffe000bd730f8` conditionally obtains two counted list partitions, inserts them at a zone-owned boundary, and consumes one available entry. Its ordinary W0 return is exactly zero or one according to whether the saved available count was zero. This supplies the previously opaque result tested by [wait-arm](kernel_zone_observer_event_report.md). Two direct callers of wait-arm and three direct calls to prefill are retained with complete compiler-bounded containing routines. Native list-provider effects, synchronization, scheduler admission, physical reclamation and daemon transaction identity remain unknown. [PF1-PF7]

```text
large caller ---------------------> prefill(Z) <----- wait-arm(Z)
       |                               |                  |
       +------> wait-arm(Z)             |             one: return
                                       |             zero: wait path
small cache caller -> lock(Z+0x80)      |
       |                               +-> provider(Z,0,descriptor)
       +-> null refill, Z+0xa8 == 0          merge A and B at boundary
       |          |                         consume one A if available
       |       wait-arm(Z)                  prepare -> bzero -> retire
       |          |
       +-> result all-ones -> unlock(Z+0x80)
```

## Primary evidence and claims

Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized predecessor kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Captured addresses are preferred virtual addresses. Role names are descriptive: these five entries have no exact original nlist definitions. The clear callee has exact original `_bzero` and `___bzero` definitions. Reference data sufficed; no IDA access or mutation was required.

| Role | Interval, end exclusive | Instructions / bytes | SHA-256 |
| --- | --- | --- | --- |
| Prefill | 0xfffffe000bd730f8..0xfffffe000bd7332c | 141 / 564 B | 8d65e179708af1b61ef3372310d16e0e5597e3ac790859790df19233a20285e3 |
| Large caller, complete capture | 0xfffffe000bd71c10..0xfffffe000bd73084 | 1309 / 5236 B | ccc4e3ff32a0ae328b43ad0ad214f98a5d8f02a4d95bcad77a595cb0bc50c7ca |
| Small cache caller | 0xfffffe000bd7ab0c..0xfffffe000bd7ac7c | 92 / 368 B | 8c45093312b73b5c0db4d84aa5a0c45d695b9d4eb888131eab48c77c28563c77 |
| Matched wait-arm | 0xfffffe000bd7332c..0xfffffe000bd73458 | 75 / 300 B | ea0ce2c04c6fcd0aace40c0329960d1efddabbf503c3b5a36c1ca43cdbe7328c |
| Matched nesting acquire | 0xfffffe000bd0aab4..0xfffffe000bd0ab18 | 25 / 100 B | b62845881e90d83df723282f5653953999e0e2c6e6a480c711fa7c3613132894 |

The wait-arm body matches its preceding capture exactly; the acquire body matches [cache-gate evidence](kernel_cache_gate_report.md). The latter already supplies original-byte uncontended acquire/nesting evidence. Likewise, [receive-continuation evidence](kernel_receive_continuation_report.md) already captures the block wrapper at `0xfffffe000bd28f6c`, including its scheduler-selection boundary at `0xfffffe000bd29140`. This report does not treat those existing bodies as newly recovered. No new execution crosses that scheduler boundary.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| PF1 | Collection-wide aligned direct-branch inventory and exact emission sites | PF-A1, PF-A6 |
| PF2 | Quota gate, flag bit2, two list partitions and zone boundary updates | PF-A1-PF-A4 |
| PF3 | Conditional head consumption, count/minimum updates and preparation/clear/retirement ABI | PF-A1-PF-A4 |
| PF4 | Boolean prefill return and source-produced wait-arm early-return join | PF-A1-PF-A5 |
| PF5 | Small caller callback, lock, refill, wait-arm and all-ones return context | PF-A1-PF-A3, PF-A5 |
| PF6 | Large caller local count/cache/quota predicates and continuation sites | PF-A1, PF-A3, PF-A5 |
| PF7 | Local source proofs, independent state checks and altered-store rejection | PF-A1-PF-A6 |

Evidence: [extractor](triage_evidence/recover_kernel_zone_prefill_callers.py), [source audit](triage_evidence/audit_kernel_zone_prefill_callers.py), [private CPU/oracle](triage_evidence/probe_kernel_zone_prefill_callers.py), [delivery verifier](triage_evidence/verify_kernel_zone_prefill_callers_delivery.py), [source capture](triage_evidence/kernel_zone_prefill_callers_checks.json.zst), [audit receipt](triage_evidence/kernel_zone_prefill_callers_audit.json.zst). Decoded capture SHA-256: `415b636adcbaf766e4688e68c6cc592f67848de50342005cfc928857d214f904` (469,438 B). Decoded audit SHA-256: `d48d84e4eec00669f600fbf79c49af28bf7373aa2a03817c76e5dabdfdc30937` (2,762,424 B).

## Incoming control and scan limits

The scanner covers 725 distinct executable-section ranges across all fileset entries: 15,490,987 aligned words, or 61,963,948 B. It selects aligned A64 B/BL encodings targeting the two exact entries, checks each selected instruction with Capstone, and retains section hashes. All five candidates are BL instructions in `com.apple.kernel`. This is a complete result for the explicitly scanned aligned encoding domain. It does not establish execution reachability, indirect-call completeness, function-pointer completeness or calls into body interiors. [PF1]

| Containing compiler entry | Emission PC | Target | X0 |
| --- | --- | --- | --- |
| 0xfffffe000bd71c10 | 0xfffffe000bd71e24 | prefill / 0xfffffe000bd730f8 | Z from X19 |
| 0xfffffe000bd71c10 | 0xfffffe000bd72b30 | prefill / 0xfffffe000bd730f8 | Z from X19 |
| 0xfffffe000bd7332c | 0xfffffe000bd73368 | prefill / 0xfffffe000bd730f8 | Z from X19 |
| 0xfffffe000bd71c10 | 0xfffffe000bd71f88 | wait-arm / 0xfffffe000bd7332c | Z from X19 |
| 0xfffffe000bd7ab0c | 0xfffffe000bd7ac64 | wait-arm / 0xfffffe000bd7332c | Z from X19 |

## Prefill state and list interpretation

Prefill saves a 96 B frame. With u16[Z+0x7c] zero, it bypasses the provider phase and proceeds directly to its final zone+0x60 acquire request. Otherwise it first clears that quota at `0xfffffe000bd7312c`, ORs bit2 into u32[Z+0x3c] at `0xfffffe000bd73138`, initializes a 24 B stack descriptor, and requests the provider at `0xfffffe000bd73154`. The provider receives `(X0=Z,W1=0,X2=descriptor)`. The original quota is a nonzero admission gate; it is not passed as an explicit scalar argument. No native provider output limit follows from this caller. [PF2]

| Storage | Width | Recovered local role |
| --- | --- | --- |
| Z+0x48 | u32 | Available-partition count |
| Z+0x4c | u32 | Reserved-partition count; source role label, not a native type name |
| Z+0x50 | u64 | Head of the combined next-at-zero list |
| Z+0x58 | u64 | Pointer to the link cell separating available and reserved partitions |
| Z+0x64 | u32 | Running minimum updated after an available pop |
| Z+0x7c | u16 | Provider admission quota cleared before the provider request |
| descriptor+0 / +4 | u32 / u32 | Incoming A / B counts |
| descriptor+8 | u64 | Incoming combined head |
| descriptor+16 | u64 | Link-cell pointer before B; initialized to descriptor+8 |

Under PF-A4, write the original list as A0 followed by B0 and the provider list as A1 followed by B1. The source walks exactly count(A1)-1 links when A1 is nonempty, inserts A1 at the zone boundary, advances that boundary to A1's last link cell, and adds its count modulo 2^32. For B1 it walks count(B1)-1 links, inserts B1 at the same boundary and adds its count, without advancing the zone boundary through B1. The combined order becomes `A0 ++ A1 ++ B1 ++ B0`, with the boundary still between available and reserved partitions. Empty A1/B1 skip their respective splice. A valid boundary can be Z+0x50 itself when A0 is empty.

The provider-phase lock request occurs after provider return. Its owner byte at Z+0x62 is incremented modulo 256 with STLURB before the optional monitor followup. The routine then requests the zone+0x60 lock again and snapshots u32[Z+0x48] into W23. If W23 is zero, no node is consumed. Otherwise it removes the combined head, stores count-1 at Z+0x48, lowers Z+0x64 when needed, resets the boundary to &Z+0x50 if the available partition became empty, and clears the consumed node's next pointer. It releases the owner byte and optional monitor before preparation/clear/retirement requests. Lock acquisition, exclusion and visibility remain conditional. [PF2-PF3]

| Request | Emission PC | Arguments |
| --- | --- | --- |
| Provider / 0xfffffe000bd7497c | 0xfffffe000bd73154 | Z, raw0, descriptor |
| Acquire / 0xfffffe000bd0ae78 | 0xfffffe000bd7315c and 0xfffffe000bd73238 | Z+0x60 |
| Node preparation / 0xfffffe000bd74bec | 0xfffffe000bd7329c | Z, zero-extended u16[0xfffffe0007e6a248], node+0x10 |
| _bzero / 0xfffffe000c6480c0 | 0xfffffe000bd732b8 | node, extent |
| Retirement / 0xfffffe000bd74fcc | 0xfffffe000bd732cc | other_zone, accounting, node, extent |
| Monitor / 0xfffffe000bd0ab80 | 0xfffffe000bd7330c / 0xfffffe000bd73318 / 0xfffffe000bd73324 | Z+0x60 |

The preparation call precedes a fresh global-pointer read: u64[0xfffffe0007e66f58] points to the pair `(other_zone,accounting)`. Extent is u16[other_zone+0x34], widened for clear and retirement. This explicitly permits a different zone argument for retirement. A model using the incoming Z for that call would lose the original global indirection. The subsequent return is `W0=(saved_W23 != 0)`, independent of ordinary values returned by preparation, zeroing and retirement. Physical ownership or reclamation is not established. [PF3-PF4]

## Caller context

The 92-instruction small caller receives `(X0=id,X1=control,X2=callback_table)`, saves a 64 B frame, and rejects an initially zero current-thread nesting count through the original diagnostic request. It decrements nesting, checks the pending-context bit2 when the count reaches zero, and computes `Z=0xfffffe000caeb480 + zero_extend(low32(id))*192 mod 2^64`. There is no local independent ID-range guard. Its first BLRAA uses table+0, modifier0xb4ac, X0=id and W1=low32(control)&0xffff7fff. A nonzero returned pointer increments u32[Z+0xac] atomically and returns that pointer. These are source interfaces; actual callbacks and native authentication remain unknown. [PF5]

For a null callback result, control bit15 clear returns zero. Bit15 set requests acquire(Z+0x80), then uses thread u16+0x1b8 as a 16,384 B cache stride after the zone+0x40 authentication boundary. A nonempty cache+4 count selects a pointer from cache+8; an eligible spare at cache+6 swaps the two vector-held arrays and retries the pop. The second BLRAA uses table+8, modifier0x4146 and `(id,popped_pointer)`, followed by unlock(Z+0x80) and its raw callback result.

If those local cache routes cannot supply an entry, the caller requests `0xfffffe000bd75e20(Z,table,control)` at `0xfffffe000bd7ac50`. A nonzero result rejoins the cache pop. A zero result reads u32[Z+0xa8]: nonzero skips wait-arm; zero passes Z to wait-arm at `0xfffffe000bd7ac64`. Both zero-result paths then set X20 to 0xffffffffffffffff, request unlock(Z+0x80) at `0xfffffe000bd7ac00`, and return all-ones if that unlock returns ordinarily. Thus the previously recovered wait-arm unlock/block/reacquire sequence has an explicit incoming acquire and outgoing unlock in this caller. This source order alone does not prove native ownership, sleep or eventual resumption.

The large caller preserves entry X0 as X19=Z, saves 464 B, and contains both prefill sites. At each local prefill gate, byte[Z+0x3d] bit0, the Z+0xa8/Z+0xb0 unsigned comparison, the Z+0x8c/Z+0x84 comparison, cache authentication and quota participate in control flow. Its wait-arm branch at `0xfffffe000bd71f34` requires current W28 bit15 set and unsigned u32[Z+0x8c]>=u32[Z+0x84], then calls at `0xfffffe000bd71f88` and rejoins `0xfffffe000bd72ae4`. The two prefill-return sites test current W28 bit15 and returned W0 bit0 before their local continuations. Complete containing bytes are retained; the full 1,309-instruction caller is not newly proved or replayed in this increment. Its entry lock ownership and every-path admission remain unknown. [PF6]

## Verification and assumption register

Nine satisfiable-premise source queries return UNSAT. They cover all 22 instructions in nine selected blocks, with 13 linked-edge obligations: quota admission/publication, both u32 count additions, Boolean return, and the small caller's result/count/arm/sentinel suffix. Those local certificates do not constitute a whole-caller proof.

Sixty-six private CPU components execute 7,235 original instruction visits and cover all 141 prefill PCs. Their 708 independent checks reconstruct the final partition sequence, boundary, counts, quota, flags, minimum, entire 192 B zone and all other private RAM outside a declared stack/descriptor window. Cases cover A/B/original available lengths0,1,3, initial reserved length2, quota bypass, nonzero monitor handles and owner-byte255 wrap. Source-produced prefill results are composed directly into the original wait-arm prefix without resetting state. Quota-zero arm cases correctly bypass prefill altogether. All selected ordinary returns restore SP and saved GPs.

Provider descriptor writes and a 32 B bzero semantic model are separately journaled external effects. Acquire, monitor, preparation and retirement calls preserve the declared ordinary ABI and have no modeled RAM effects. PAC/AUTDA and authenticated returns are logical models. Retirement is deliberately given a different declared zone/accounting pair and an all-ones ordinary result; prefill still returns its source Boolean. Native list production, callback behavior and allocator validity are not inferred from those fixtures.

Replacing the actual quota-clear store or available-count decrement with NOP in separate private source copies makes the independent RAM oracle reject each result. These are CPU mutation controls, not native reachability or exploitability evidence.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PF-A1: image identity | Pinned original collection, compiler boundaries, symbols and prior captures supply PF1-PF7. | Rehash and recapture all five functions and every scanned section; compare both reused bodies. |
| PF-A2: instruction model | Fixed-width arithmetic, branches, byte-array storage and private CPU semantics support PF2-PF5/PF7. | Reconstruct and solve all nine queries, compare independent state equations, reject both changed stores. |
| PF-A3: storage and ABI | Declared valid nonwrapping mapped regions and ordinary saved-register/callee-return rules support PF2-PF6. | Check native extents, aliases, pointer authentication, thread identity, nonreturn and call-induced effects separately. |
| PF-A4: list descriptor | Counts match finite valid partitions; next fields and boundary cells are coherent. PF2-PF4 and replay claims are conditional. | Vary empty and multi-entry partitions; obtain actual provider evidence; inspect mismatched counts, cycles, shared nodes and concurrent link changes before extending semantics. |
| PF-A5: call/thread epoch | Snapshots and modeled callees belong to the declared component epoch. PF4-PF6 do not establish native synchronization or scheduler effects. | Recover provider/refill and native callbacks; correlate one thread's acquire, wait registration, block, wake, reacquire and caller return. |
| PF-A6: bounded scan/coverage | Executable-section flags and aligned B/BL encoding define PF1's scan domain; selected blocks/components define PF7's proof domain. | Inspect indirect references, interior targets, alternate entrypoints and native reachability; do not extrapolate local proofs to the full large caller. |

Extraction and direct-branch scanning cost O(B+I+S) time/space for input bytes, captured instructions and symbols. Source-formula construction costs O(I+Q) time/space; solver search is separate with 30 s/query limits. Source list walks cost O(a+b) time and O(1) additional space for valid provider counts a,b, excluding callees. Replay/oracle cost O(V+J+R) time/space for visits, journals and private RAM. Every A64 instruction is4 B: 1642*4 B=6568 B; 141*4 B=564 B. Arithmetic widths are u8/u16/u32/u64 as shown; machine-width overflow is modular, without a native nonoverflow premise.

## Bounded continuation

| Impact | Next evidence | Question |
| --- | --- | --- |
| High | Provider at 0xfffffe000bd7497c and refill at 0xfffffe000bd75e20 | Actual partition production, admission, counts and lifetime |
| High | Matched native thread/zone/cache epoch through existing block/scheduler frontier | Successful sleep/wake/reacquire and allocator caller completion |
| High | Consumers of released metadata queues and a matching daemon/userclient allocation | Physical reclamation/reuse and transaction identity |
| Medium | Complete large-caller CFG and indirect incoming references | All-path caller admission and broader call completeness |
| Medium | Observer registration and callbacks | Post-callback flag/list interference and node lifetime |

This increment establishes no additional Mach port, transmitted right or message emission. The internal event remains Z+0x20; its relationship to a specific daemon request remains unknown. The full interface goal remains active.

## Scoped quality gates

- **QG1**: Factual source/ABI/control/data-flow analysis only.
- **QG2**: PF-A1-PF-A6 state dependencies and falsification probes.
- **QG3**: Prefill, direct callers, emission PCs, list state, Boolean join and caller lock/request context are covered within the declared increment.
- **QG4**: Byte counts, frame sizes, list/CPU strides and modular widths are explicit and reproducible.
- **QG5**: Modeled effects, native unknowns, quota-zero arm bypass, list coherence, per-call global indirection and local versus whole-caller coverage are distinguished.
- **QG6**: Pinned bytes, exact symbols, prior matches, fresh source proofs, independent RAM/ABI checks and two changed-source controls supply provenance.
- **QG7**: The impact-ranked continuation bounds opportunities and unresolved interfaces without claiming full-goal completion.

The [per-CPU magazine drain](kernel_magazine_depot_drain_report.md) now identifies the actual full/empty partition producer used by prefill, two direct callers with zero/u16 quota controls, output ordering and the paired zone-bit2 operations. Original cache acquire/unlock bodies execute inside continuous drain/prefill/arm components. Sixteen local source proofs, one composition query and 38 private components pass 241 independent checks. Native cache/storage production, synchronization, full bulk processing, scheduling, reclamation and daemon transaction identity remain unknown; no new Mach endpoint is established. The full goal remains active.

## Bulk-return continuation

The [bulk-return report](kernel_magazine_bulk_return_report.md) establishes original slot clearing, object validation, free-bit/count/encoded-queue transitions, observer/wake request and original-count completion accounting. Forty-four private components pass364 independent checks;21 source queries and two separation lemmas pass. Four direct/prefill components consume exact original-fill-produced slots under explicit ownership handoffs and new-call epochs; the one-slot prefill changes capacity in a separate epoch. This supersedes the preceding full-bulk execution frontier while preserving native storage/ownership, authentication, exclusion, wake delivery and daemon transaction identity as unknown. No additional Mach endpoint, right or message emission is established. The full interface goal remains active.
