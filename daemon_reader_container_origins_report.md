# Reader container origins, default state and comparison-context admission

The N19 pointer previously described only as saved context at frame+0x6368 has a local allocation producer: an original `_malloc` import binding receives a16 B request, its result is stored in that cell, and the non-NULL route zeroes two u64 cells in the returned object. Under the recovered private caller mode, empty decoded input publishes this initialized pair through parent+8 with raw success. Complete container type and native ownership remain unknown.

The comparison context used by N20/N21 has a different source: incoming X10 is saved at frame+0x5e50 before a separate112 B allocation. The context admission block also initializes the two saved comparison values and a saved head pointer. This establishes conditional source provenance and initialization, not a request/process/environment classification for X10. The full interface investigation remains active.

No target code was executed or emulated, no FairPlay request was sent and no IDB was modified. Existing original-file evidence sufficed; no additional IDA query was needed.

## Primary provenance and coverage

Primary binary: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses below are unslid source virtual addresses. Constants, cells and selectors are hexadecimal unless marked as decimal counts or byte units.

- [Exact source, pointer records, allocation banks and writer census](triage_evidence/daemon_reader_container_origins_source.json), [recovery script](triage_evidence/recover_daemon_reader_container_origins.py).
- [Static validator and complete SMT queries](triage_evidence/validate_daemon_reader_container_origins.py), [proof results](triage_evidence/daemon_reader_container_origins_checks.json).
- [Preservation seal](triage_evidence/daemon_reader_container_origins_delivery.json), [scoped quality gates](triage_evidence/daemon_reader_container_origins_quality_gates.json), [independent publication auditor](triage_evidence/verify_daemon_reader_container_origins_publication.py).
- Prior [reader value consumers](daemon_reader_value_consumers_report.md), [bank origins](daemon_constructor_bank_origins_report.md), [typed readers](daemon_reader_typed_dispatch_report.md).

Fourteen source ranges contain249 instructions /996 B. Thirteen ranges end in BRAA; one is a12-instruction prefix. Two ranges contain one BLRAA allocation boundary each. Every other instruction in this set is translated:234 distinct instruction PCs,242 translated instances and216 SSA definitions. The extra eight translation instances reuse the pointer publisher with an independent clear-path state. Eighteen original pointer records support15 branch-slot/modifier matches and the saved continuation/import records. Source SP is not written in these ranges.

The modeled allocation calls preserve SP and all64 bits of X19-X29, supply a symbolic X0 result and assign fresh symbolic values to the remaining registers. The preserved-register set follows [Arm AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst). This is a normal-return analysis premise; native callee execution, identity and compliance were not observed. Memory-owner validity, frame consistency and successful PAC remain separate premises.

## Private caller ABI and phase distinction

Caller continuation0x1004e1f94, under incoming W21=0xb9a and X19=HOST, derives:

| Value | Source result |
|---|---|
| X8 | HOST+8, borrowed output address |
| X9 | &frame[0x82e8], buffer-pointer input cell |
| X10 | &frame[0x285c], raw u32 extent input cell |
| W20 | 0xc4dd, inherited allocator mode |
| W21 | 0xb9a, saved return-table selector |
| Next dispatch | Slot0x3884 ->0x100495808, IA diversity0x6378 |

The upstream production of incoming selector0xb9a and HOST is not joined. Within this conditional source chain, the caller and callee retain the same SP; the call-model premise preserves it across allocation.

Three values must remain distinct: the frame phase at+0x9d0 has low32=0x6cf4, the allocator's inherited W20 is0xc4dd, and the saved return selector is0xb9a. Substituting0x6cf4 for W20 yields unrelated pointer records and does not satisfy this source contract. Original slot0xb9a identifies continuation0x100975d34 with IA diversity0xbcd2; native authenticated return remains unproved.

## Allocation bank and source call boundary

Both allocation sites use original left bank0x100fc4130 and right bank0x101031ea0, supplied through frame cells+0x968/+0x960 or their carried register. For every byte x:

```text
x XOR right[left[x] XOR 0x4e] == 0xff
index = 0xcb0e + 0xff = 0xcc0d
TABLE[index] = original authenticated bind libSystem/_malloc
```

All256 byte inputs are checked from the original512 bank bytes and by a universal bit-vector identity. Source-composed queries then prove that arbitrary controller u32 values still select slot0x10109ff58, IA diversity0x6aa4. The prior bank-origin source supports the frame pointers; native mutable bank contents remain a premise.

| Call instruction | Source argument X0 | Conditional import binding |
|---|---:|---|
| BLRAA at0x1004958d0 | 16 B | libSystem/_malloc |
| BLRAA at0x1006d6804 | 112 B | libSystem/_malloc |

No allocation call is run. Each source proof stops before BLRAA and resumes from the following instruction with a symbolic return and explicit register-preservation model. Raw success/error markers below are local representations, not independently identified external errors.

## N19 default state, result gate and empty-input output

Before the16 B call,0x100495808 reads the supplied raw extent and buffer-pointer cells and stages:

| Frame cell | Width / B | Stored value |
|---|---:|---|
| 0x7910 | 8 | Saved return-table pointer from slot0xb9a |
| 0x8398 | 8 | Borrowed output address HOST+8 |
| 0x631c | 4 | Raw input extent |
| 0x5cf8 | 8 | Input buffer pointer |
| 0xdb8 | 8 | 0 |
| 0x7df0 | 4 | 0x8b3dc651, raw u32-zero representation |
| 0x12c8 | 8 | 0xfa039b7ca50c772e |
| 0x63a0 | 8 | 0, span-pointer default |

The raw64 default constant is not assigned a decoded numeric meaning. These source stores refine the earlier unknown inactive-cache initialization: initialization is now identified in this entry path, while actual native entry/epoch and later overwrites remain unproved.

After a declared normal allocation return,0x1004958d4 stores X0 at frame+0x6368. NULL selects slot0xc4dd ->0x1005b95e8; non-NULL selects0xc4e0 ->0x1005b078c. Both stage W6=0x74c29d85 at this result gate. The NULL continuation returns through saved X21 with IA diversity0xbcd2. It has no direct store through the borrowed output argument. An assertion that the output memory is untouched additionally requires separation from frame stores; the source contract does not assume arbitrary pointers cannot alias.

On the non-NULL route,0x1005b078c writes u64 zero at allocation+0 and+8. A valid16 B allocation separate from the frame is a premise. This establishes an initialized two-word object; a complete list/container class is not inferred from that shape alone.

Continuation0x1004ddaec decodes SIZE=zero_extend64(raw_extent XOR0x8b3dc651), with initial cursor0. It selects slot0xb350 ->0x1005588b4 for SIZE=0 and0xb358 ->0x10052b478 for SIZE>0. This is a remaining-input test, not a proved10 B minimum-header test. The nonempty continuation is outside this increment.

The empty route loads the allocated pair from frame+0x6368, enters the established success stage0x1007f6f54 and then pointer publisher0x10058816c. It writes the allocation pointer as8 B at HOST+8, supplies X6=0x8b3dc651 and restores the saved continuation. The checked path reads the buffer-pointer input cell but does not read bytes through the input buffer pointer before this publication. Complete final native return and output ownership remain unknown.

A separate entry0x10079768c clears frame+0x6368 and publishes NULL through the saved borrowed output while forwarding a named raw status from+0x2b1c. This clear path is not the allocation-failure branch above, and no deallocation is proved by the pointer clear itself.

## Shared comparison-context admission and112 B object

At0x10054984c, under incoming W11=0x50e4, source initializes:

| Frame cell | Stored value |
|---|---|
| 0x78f0 /u32 | 0x8b3dc651 |
| 0x7390 /u32 | 0x8b3dc651 |
| 0x7d98 /u64 | NULL |
| 0x8608 /u64 | NULL |

The first two are the saved comparison-value cells recovered previously. Source tests an independent pointer loaded from frame+0x82d8. NULL selects0x50e6 ->0x1004dd874; non-NULL selects0x50e4 ->0x1004d3e04. Incoming X10 is preserved through this block.

Block0x1004d3e04 saves incoming X10 at frame+0x5e50, restores W22=0x6cf4, stages X19=&frame[0x8608] and selects0x4a8d ->0x1006d679c. Thus the later flag/expected-word context comes from a passed register. Its request, process or environmental provenance remains unknown. The tested pointer at+0x82d8 is a different source value; this checked gate does not establish the validity of incoming X10.

The next block requests112 B and saves its normal X0 result in X20. NULL selects0x1e17 ->0x100707484, which branches through the preserved continuation with IA diversity0xecaa. Non-NULL selects0x1e10 ->0x100939f64. Original return slot0xfd4 identifies0x1005133c0; native return/delivery is not proved.

Only the first12 instructions of0x100939f64 are captured for field initialization:

| New object offset | Width / B | Value |
|---|---:|---|
| 0 | 4 | 0x1d45dafb |
| 4 | 4 | 0 |
| 0x48 | 8 | 0 |
| 0x50 | 1 | 0 |
| 0x51 | 1 | 0x25 |

The maximum touched byte offset is0x51, so the accessed envelope is0x52=82 B, within the112 B request. Later initialization and helper behavior are excluded. No complete object type is assigned.

The saved comparison context and this newly returned object have distinct source origins. A SAT source-state counterexample permits different numeric pointers; native inequality or nonaliasing is not proved. The earlier context reads at+0x68/+0x70/+0x74 imply a120 B accessed envelope if treated as fields of one nonwrapping object. That arithmetic does not associate the context with the separate112 B request, and supplies no native out-of-bounds finding.

## Writer census and evidence limits

A fresh local SP-affine whole-text scan found five candidates for the four investigated8 B cells:

| Cell | Candidate store PC | Source value |
|---|---|---|
| 0x8398 | 0x100495838 | Borrowed output address |
| 0x6368 | 0x1004958d4 | Allocation result |
| 0x6368 | 0x10079769c | NULL |
| 0x5e50 | 0x1004d3e1c | Incoming X10 |
| 0x7d98 | 0x100549880 | NULL |

Each candidate's local effect is covered by the source contracts. The scan excludes nonaffine/memory-derived aliases, unsupported stores and opaque callees. These are not exhaustive writers or proof that every native consumer sees the identified initialization. In particular, the later non-NULL producer of+0x7d98 remains unresolved.

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent result | Stress test / falsification probe |
|---|---|---|---|
| CO1 | The pinned original daemon is the intended build. | Addresses, bytes and original fixups. | Rehash the entire image and every range; do not transfer these addresses to another build. |
| CO2 | Caller16 enters with W21=0xb9a; context admission enters with W11=0x50e4. | Conditional private modes and branch joins. | Trace upstream callers; the first derives W20=0xc4dd,while the second mode remains an entry premise. |
| CO3 | Relevant frame/cache values and file-backed bank pointers/content apply in the selected epoch. | Allocation target/default/provenance contracts. | Recheck bank origins,aliases and intervening stores; the finite census is not exhaustive. |
| CO4 | Allocation returns normally with SP/X19-X29 preserved and X0 carrying the modeled result. | All post-call paths. | Inspect actual callee/PAC/call effects before promoting the ABI premise to native evidence. Other register state is freshly symbolic. |
| CO5 | Non-NULL returned allocations are valid for the requested extent and separate from the active frame. | Pair zeroing and112 B initial stores. | Establish native allocation/lifetime/alias validity; static size arguments alone do not prove it. |
| CO6 | Borrowed input cells and parent+8 output are valid and have the stated frame/heap separation. | Extent/buffer loads and empty output publication. | Recover HOST and input-cell producers and owner sizes; aliased frame writes can affect otherwise untouched output memory. |
| CO7 | Original authentication metadata describes intended destinations. | Conditional call/continuation maps. | Re-decode import/return target,key,diversity; no hardware authentication or endpoint identity is proved. |
| CO8 | Local initialization and different source origins do not establish complete types,global identity or deallocation. | Object-role and context interpretation limits. | Follow consumers/free paths and the non-NULL head producer; do not infer shared allocation or ownership from reused registers. |

## Validation and bounded continuation

Fifteen UNSAT queries cover the256-input bank identity, private caller ABI,16 B request/defaults/result gate/failure continuation/pair zeroing/remaining-input test/empty publication, separate pointer clear, context admission/defaults, saved-context source,112 B request/result gate/failure continuation and initial field prefix. One SAT query rejects conflating the saved context with the returned112 B object. Six changed-ledger controls reject wrong bank data,wrong initialization width,missing caller,invented object type,wrong result branch and omitted writer candidate. They check evidence integrity,not native behavior.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_reader_container_origins.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_reader_container_origins.py
```

The one-pass four-cell census costs O(text words*4); extraction/translation costs O(captured instructions+pointer records+256 bank entries). Memory costs O(text bytes+entry resets+captured evidence+SSA). QF_BV solver worst-case time is not claimed polynomial. Queries have15 s timeout and20 s subprocess limit; unknown/timeouts are rejected. Publication verification costs O(total artifact bytes+links), with O(manifest+largest JSON) memory. Widths,byte units and modular arithmetic are explicit; valid nonwrapping object envelopes remain conditional.

- High: follow ordinary record construction/insertion and the remaining-input back edge to establish the complete two-word object's role and lifecycle.
- High: recover HOST and the admission caller's incoming X10 to classify context control and connect outer operation selectors.
- High: recover the non-NULL producer/consumer history of+0x7d98 and the complete112 B initializer/return path.
- Medium: establish final continuation behavior at0x100975d34 /0x1005133c0,including output ownership and cleanup.
- Medium: recover the raw64 zero/default representation and full value transform; the initialized constant alone does not establish its decoded meaning.
- Low: retain allocated_pair16 as a source-local label until full container/list semantics are proved; no IDB names are changed.

No new Mach endpoint or successful daemon-kext exchange is established. Native selector26/RPC502/700 pairing remains unknown.

## Scoped quality gates

QG1: Pass. Technical source observations and falsification probes require no normative conclusion.

QG2: Pass for CO1-CO8. Dependencies and stress tests are explicit.

QG3: Pass for these conditional allocation/default/admission contracts. Complete container/object types and the broader cross-layer goal remain active.

QG4: Pass. Register/call boundaries,byte units,16/112 B requests,82/120 B conditional envelopes and algorithmic/solver limits are explicit.

QG5: Pass for bounded claims. Frame/inherited/return selectors,allocation result versus passed context,direct output stores versus aliases,and pointer clearing versus deallocation remain distinct.

QG6: Pass. Primary binary identities,recaptured source,all non-control-instruction translation,original fixups,exhaustive banks and complete solver queries support the contracts. The ABI premise has a primary Arm source and is not presented as native execution evidence.

QG7: Pass for the finite high/medium/low continuation list. The full investigation is not marked complete.
