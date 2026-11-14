# Constructor allocation cascade and private 21-byte emitter request

All 76 published non-NULL 64 B constructor states now cross the pending malloc(21) boundary. A declared NULL return reaches an undefined eight-byte field demand at S+0x30. A fresh T/21 B return instead requests malloc(48). NULL at that second allocation requests free(T), then reaches the same field demand after the declared void return. No value is supplied for the undefined field, and neither path is continued beyond its demand. These are conditional source/model results, not observations of native heap contents or cleanup behavior. [AC1-AC6; AC-A1-AC-A5,AC-A8]

Success at both allocations constructs an address-coded request for 21 bytes at private scratch `0x680006c5d0`, control `0xb399`. It calls the previously recovered byte-emitter adapter `0x100add594`, then emitter `0x100acd9c4`. Complete comparison-leaf replay decodes the current generation counter as 9 and selects the full-state twist entry. The two new heap payloads remain entirely undefined and untouched. Their later population, publication, purpose and native lifetime remain unknown. [AC1-AC6; AC-A1-AC-A4,AC-A6-AC-A8]

```text
76 inherited non-NULL S/64 B constructor states
  -> pending malloc(21)
       + NULL -------------------------+
       |                               |
       + fresh T/21 B -> malloc(48)    |
                           + NULL      |
                           | -> free(T)|
                           | -> declared void return / retire T
                           |           |
                           |           v
                           |       cursor -= 32 B
                           |       private status = 74c29d85
                           |       demand S+30[8] undefined -> STOP
                           |
                           + fresh U/48 B
                               -> private request: output21, control b399
                               -> adapter -> emitter
                               -> comparison leaf: counter9 == 0 is false
                               -> full-state twist entry -> STOP
```

No native target API, filesystem operation, allocation/free, IPC, hardware pointer authentication or IDB mutation executes. Model-owner retirement does not observe a native deallocation or memory wipe. Existing generated context bytes remain unchanged. [AC1-AC6; AC-A3-AC-A8]

| Evidence | Primary artifact and scope |
| --- | --- |
| AC1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_state_allocation_cascade.py) retains original instructions, fixups and complete interval states. |
| AC2 | [Parent constructor report](daemon_state_container_construction_report.md), [checks](triage_evidence/daemon_state_container_construction_checks.json.zst) and [audit](triage_evidence/daemon_state_container_construction_audit.json.zst): 76 non-NULL S/64 B states pending malloc(21), with 53 defined and 11 undefined S bytes. |
| AC3 | [Current checks](triage_evidence/daemon_state_allocation_cascade_checks.json.zst): all 76 parents, 456 intervals, allocator/free premises, private emitter records and complete comparison continuations. |
| AC4 | [Independent auditor](triage_evidence/audit_daemon_state_allocation_cascade.py) and [audit](triage_evidence/daemon_state_allocation_cascade_audit.json.zst): full register/byte replay, owner/definedness joins, saved-continuation provenance and eleven original-source equations. |
| AC5 | Parent [compile-only arm64e ABI probe](triage_evidence/daemon_state_container_construction_abi.c), freshly recompiled and retained in AC3: malloc/free prototypes, LP64 widths and SDK-relative header hashes. [Generated-stream](daemon_generated_stream_report.md) and [versioned-header](daemon_versioned_header_report.md) reports establish prior callers of the same adapter/emitter and complete comparison leaf. |
| AC6 | [Publication verifier](triage_evidence/verify_daemon_state_allocation_cascade_publication.py): exact parent coverage, current contracts/equations/source bytes/fixups, twelve Mach-O site brackets, preservation, manifest delta and decoded path hygiene. |

## Exact allocation, storage and failure interfaces

Addresses use the preferred image mapping and retained model placement. Outer SP is `0x6800060100`; S=`0x6600040000`, T=`0x6600050000`, U=`0x6600060000`, J=`0x6500115b20`. Fresh T/U owners are disjoint from all existing owners and have no initially defined bytes. These addresses represent conditional model owners, not observed native allocations. [AC1-AC4,AC6; AC-A1-AC-A4]

| Emission or source site | Interface / IA modifier | Established argument or effect |
| --- | --- | --- |
| 0x1009342fc | malloc / 0x6aa4 | X0=21 B; NULL or fresh T/21 B return |
| 0x100934300 | Private result store | Raw returned pointer at outer SP+0x3e00=0x6800063f00 |
| 0x100934304 | Companion-value reload | X21=0 from outer SP+0x2338=0x6800062438 |
| 0x100934a4c / branch 0x100934a60 | Original target selection / 0x6d79 | Both allocator result and companion zero select cleanup; otherwise select the 48 B request route |
| 0x1008a1038 | malloc / 0x6aa4 | X0=48 B; NULL or fresh U/48 B return |
| 0x1008a103c | Private result store | Raw returned pointer at outer SP+0x76e0=0x68000677e0 |
| 0x1008a1060 / branch 0x1008a1068 | Original target selection / 0x6d40 | NULL selects release of T; non-NULL selects the emitter caller |
| 0x100932674 | free / 0x46a2 | X0=T; pending after NULL malloc(48) |
| 0x10068ae78 | Cursor store | u64 cursor 0x480 becomes 0x460 at outer SP+0x16d0=0x68000617d0 |
| 0x1006ad0bc | Private status store | u32 0x74c29d85 at outer SP+0x2b54=0x6800062c54 |
| 0x10074abc8 | Undefined field demand | Eight-byte read at S+0x30=0x6600040030; stopped before the instruction executes |

The first allocator test is over `(returned_pointer | companion_pointer) != 0`; it is not universally a standalone allocator-NULL test. Original parent store `0x10083c8f0` sets the companion to zero in every retained state. The source proof covers all bits of both operands, and actual states check that zero companion. Under phase W19=0x76bf, original slots are `0x1010754e8 -> 0x10068ae70` for both zero and `0x101075588 -> 0x1008a0fa0` otherwise. The latter route supplies malloc(48). [AC1-AC4,AC6; AC-A1-AC-A3]

For the second allocator test, the established phases select `0x10106df00 -> 0x1008f01f8` on NULL and `0x10106dfb8 -> 0x10092fb3c` otherwise. Source-local equations prove the two partitions for every returned-pointer bit pattern under those phases. Only NULL and one fresh, disjoint non-NULL result per parent are concrete whole-path controls; arbitrary native allocator outcomes or address placements are not established. [AC1-AC4,AC6; AC-A1-AC-A4]

The declared free return removes T/21 B from the model's owner list and invalidates its bytes plus four borrowed errno bytes. The GP return value is arbitrary because the ABI return type is void; callee-saved GP state, low D8-D15, SP and the exact new GP/Q/NZCV join are checked. Every allocation return also invalidates errno. No additional imported memory effects are supplied. The current SDK check supports these widths/prototypes; historical runtime equivalence remains unknown. [AC1-AC6; AC-A3-AC-A5]

Both failure continuations rewind the private cursor by 32 B and store raw status 0x74c29d85 before the same undefined field demand. Original arithmetic at `0x10074abb4..0x10074abc4` adds `0xb545aadb9f1bca6a` to the encoded S pointer. Since S is represented as S+K, K=`0x4aba552460e435c6`, the result is S+48 modulo 2^64. The previous initializer leaves S offsets48..55 undefined. No current source write defines those bytes; no native value or downstream cleanup decision is inferred. Final error propagation and object retirement remain unknown. [AC1-AC4,AC6; AC-A1-AC-A5,AC-A8]

## Private emitter request and seed/temporary channels

The parent constructor reserves 32 B of private scratch, saving `outer SP+0xc070+cursor` at outer SP+0x1b50. Its cursor0x460 gives output `0x680006c5d0`; reservation advances the cursor to0x480. Both failure routes undo that reservation. The 32 B reservation is distinct from the 21 B emitter request and the separate 21 B heap allocation. No alias or later copy between the scratch and T is established in this increment. [AC1-AC4,AC6; AC-A1-AC-A3,AC-A6]

| Call emitted at | Target / IA modifier | Source-established role and arguments |
| --- | --- | --- |
| 0x10093ca80 | 0x100add594 / 0x22a0 | Byte-emitter adapter; X0=record R=0x6800070db8, X1=0x680006bda0 adjustment-output cell |
| 0x100add7d4 | 0x100acd9c4 / 0x7c25 | Emitter; same X0=R, X1=temporary0x6800060070; SP=0x6800060070 |
| 0x100b33030 | 0x10041a5e0 / 0xec9d | Equality/unsigned-greater comparison leaf; X0=Q=0x680005ffd0; SP=0x680005fd40 |

For request R, let `k=u32((low32(R) XOR 0xeaae0ac9)*0x7398180b)`. Source stores at0x10093c9ec,0x10093c9fc,0x10093ca00 produce the following fields. The original-source equation covers arbitrary output-pointer bits and every 16 B aligned outer SP under the checked caller phases. [AC1,AC3,AC4,AC6; AC-A1-AC-A3,AC-A6]

| R-relative field | Width | Decoded value |
| --- | --- | --- |
| +0x08 | u64 | Raw output pointer 0x680006c5d0 |
| +0x10 | u16 | u16(raw-k-0x153b)=21 B |
| +0x14 | u32 | u32(raw+k)=0xb399 |

This request overwrites private storage previously used for other status/record fields. Equal addresses across different intervals do not establish identical record meanings. X2=21 at the nested comparison call is residual emitter state, not a second output pointer or a comparison-leaf length argument. The complete leaf consumes its address-coded record through X0. [AC1-AC5; AC-A2,AC-A6-AC-A8]

Before the adapter, source `0x10093ca10` copies seed C=`0x9c4889212ef8f9c5` into the adjustment-output cell. The adapter writes `u64(C*0x2ec5+1)=0x4c757cf9e2799a9a` to global0x1010b8d78. Its fixed reserve is64 B; dynamic reserve is `16*((updated_seed>>60)+1)=80 B`. Thus `outer SP-64 B-80 B=0x6800060070`, the temporary address. Source0x100add74c writes C-0xb0 there; emitter0x100acdb1c restores C by adding0xb0. All four stores and their distinct addresses are checked in all76 states. This source-selected seed update is not a new entropy API call. The adapter has not returned or written its final adjustment. [AC1-AC5; AC-A1-AC-A3,AC-A6-AC-A8]

No new byte is written to the21 B scratch output before the frontier. Neither T/21 B nor U/48 B is read or written in any retained interval. S retains exactly its inherited53 defined and11 undefined bytes. No current write publishes the non-NULL S pointer at J+0x68. The generated32 B at J+0x34 remain unchanged. [AC1-AC4,AC6; AC-A2,AC-A4-AC-A8]

## Complete comparison and nonzero-counter route

For Q=`0x680005ffd0`, the complete leaf0x10041a5e0 derives `Kq=u64((Q XOR 0xee9763edb3ce6674 XOR 0xa374c17f4a1aff00)*0xda51a827)`. Its record decodes mode0, A=9 and B=0. Mode bit0=0 selects equality; bit0=1 selects unsigned greater. The leaf writes only its four-byte result at Q+16. Original-source equations cover arbitrary record address, u64 operands and u32 mode/mask/choices, plus the actual caller composition for every u32 generation counter. [AC1,AC3-AC6; AC-A1-AC-A3,AC-A6-AC-A8]

| Current predicate | Selected result | Original slot / target | Branch emission / IA |
| --- | --- | --- | --- |
| counter9 == 0 is false | 0x1782, store0x10041a668 | 0x101045b00 -> 0x100a6cd1c full-state twist entry | 0x100b330b8 / 0x504c |

All76 source continuations stop before the first twist-entry instruction. No current twist update, byte emission or completed21 B output is claimed. The previously recovered generator uses repeated full-state transformations and address-dependent byte encoding; shared callee identity and length alone do not establish this caller's output or justify reusing another caller's bytes. Native state epochs, scheduling and transport correlation remain unknown. [AC1-AC6; AC-A1-AC-A3,AC-A6-AC-A8]

The failure cursor route uses an authenticated continuation saved by the preceding constructor: original load0x10083c8b0 from slot0x10103ea90 selects0x1007812e8, store0x10083c8b8 saves it at outer SP+0x8ca8=0x6800068da8, reload0x10068ae7c feeds branch0x10068ae84 with IA0x5ae9. Independent replay checks original word/target/modifier, save/reload bytes, exact state joins and absence of intervening overwrites across both failure chains:152 origin checks. It does not substitute a matching inherited code value for source provenance. [AC1-AC4,AC6; AC-A1-AC-A5]

The original1005-entry LC_FUNCTION_STARTS table has1864 B at file offset17603576, SHA-256 `ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54`. Twelve new sites are bracketed. Adapter0x100add594, emitter0x100acd9c4 and comparison0x10041a5e0 are advertised starts; the other inspected sites are fragments. No exact-site original symbol is present. Complete noncontiguous function chunks, original semantic names and all callers remain unknown. Original image/retained evidence sufficed; IDA was not queried for this increment. [AC1,AC3,AC4,AC6; AC-A1,AC-A8]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| AC-A1: Pinned source and original fixups apply | Sites, equations, routine identity and branch destinations | Verify image/opcode/slot/modifier bytes, twelve function-start brackets and saved-continuation provenance; logical authentication does not observe hardware PAC. |
| AC-A2: All76 frozen constructor states are conditional entries | Whole retained paths, cursor and header/stream preservation | Check exact GP/Q/NZCV/SP/known-byte/owner joins and all parent indices; retain inherited synthetic file-prefix and native-epoch limits. |
| AC-A3: Declared imported return/ABI effects apply | Allocator/free continuations and ordinary int/pointer/void terminology | Recompile current arm64e malloc/free ABI probe, invalidate errno, check full register/vector joins and arbitrary void return; historical runtime equivalence unknown. |
| AC-A4: NULL or fresh disjoint T/21 B and U/48 B owners apply | Allocator partitions, pending free and undefined payloads | Admit no initial payload bytes, verify disjointness and all-bit source predicates; finite controls do not establish arbitrary native allocation reachability. |
| AC-A5: Declared free return retires the model T owner | Failure cleanup and no subsequent T definitions | Remove owner and all definitions; verify every later read/write; native free, wiping and other object retirements remain unknown. |
| AC-A6: Current private caller phases, source reservation and address-coded records apply | Length21/control0xb399 request, seed/temporary and counter9 route | Verify source phase seeds, producer stores, modulo equations, actual record bytes and complete comparison leaf; keep output length distinct from generation counter and scratch extent. |
| AC-A7: Undefined field/output bytes remain unknown | S+0x30 demand and absence of heap/output population | Stop before the field read, compare exact53/11 S mask and all T/U/output read/write extents; do not insert allocator backing values or generated bytes. |
| AC-A8: Local source requests/stores do not establish public/native effects | Publication, final status, payload role and IPC boundaries | Require actual downstream consumers, object/transaction identity and native epochs before asserting transport, final lifetime or public API results. |

## Reproduction, coverage and bounded continuation

Checks logical SHA-256: `661c3f804d79bbbf49c44f4c464a1c773f43cbbc3fb796212d40a4deea46f809`. Audit logical SHA-256: `81d62f637d5d932dce165be5686198ae50afcf727fd8aba6d4b90794f1f99641`. Receipts and manifest use `zstd --ultra -22 -q -T1`. Raw, structured and decoded hexadecimal payloads are checked for analyst-local paths. Target-defined daemon state-file paths in inherited evidence retain their technical meaning. [AC3-AC6]

Per parent: `2 allocation21 + 2 allocation48 + 1 free21-return + 1 comparison-continuation = 6 intervals`. Thus `76*6=456 intervals` and `76*(131+58+75+842+126+70)=98952 source visits`. Journals contain14212 reads,8512 writes,2280 logical edges and228 internal calls. All76 parent constructor states are covered; the earlier836 other terminal malloc(64) requests and complete1543-state SIDB frontier are not expanded by these counts. [AC2-AC4,AC6]

Independent replay checks3181056 scalar and3181056 vector register values,99408 NZCV states,84056 read B,54568 write B and2204 original authenticated edges. Model contracts check304 allocator joins,76 owner-retirement joins,152 undefined-field demands,304 raw pointer stores,76 private21 B request records and76 complete comparison/refill routes. Across456 intervals, inherited masks, entirely undefined new heap payloads, unchanged generated context bytes and absence of J+0x68 publication are checked. Repeated per-state/per-interval byte counts are coverage measures, not distinct native allocations or native memory usage. [AC3,AC4,AC6]

Eleven nonvacuous source equations cover both allocator partitions, cleanup field address, allocator-result stores, failure cursor rewind, original zero companion, aligned caller record, original private reservation, complete comparison leaf and current refill composition. Solver limit is30 s/query. Arithmetic is exact u16/u32/u64 modulo2^width; addresses/offsets/lengths are bytes. Extraction is O(parent bytes+retained visits+effects+source) time/storage. Independent replay is O(V*(register state+effects)+owner joins+query DAG) time, O(receipts+largest interval+known byte map) storage. No native timing or memory cost is measured. [AC1-AC6]

| Impact | Next evidence | Architectural purpose and present boundary |
| --- | --- | --- |
| High | Continue actual full-state twist and21 B emitter completion | Recover this caller's output, retry/refill schedule and return status; current output is unwritten. |
| High | Trace scratch-to-T/U consumers and later S publication | Establish actual payload roles and outgoing ownership/data paths; equal allocation/request lengths do not prove a copy. |
| High | Establish S+0x30 producer/lifetime across admitted native callers | Resolve the cleanup field without substituting an invented heap value; current conditional demand is stopped. |
| High | Join actual object/generated bytes to Mach/IOKit buffers and native epochs | Resolve daemon-kext pairing and external delivery; no new port or IPC emission is established here. |
| Medium | Broaden other836 pending64 B allocator states and caller phases | Determine whether different source state changes the allocation/emitter/cleanup chain. |
| Medium | Final adapter adjustment and aggregate error consumers | Establish actual frame restoration, publication order and final status rather than extrapolating from private raw words. |

**QG1** passes: factual source/ABI analysis. **QG2** passes: AC-A1-AC-A8 register dependencies and falsification probes. **QG3** passes for this all-parent allocation/emitter-interface increment; the full interface goal remains active. **QG4** passes: exact widths, extents, counts, modulo arithmetic and complexity. **QG5** passes: scratch versus heap allocation, length21 versus counter9, undefined demand versus executed read, owner retirement versus native free and private record versus public transport remain distinct. **QG6** passes after source-pinned independent replay, eleven rebuilt equations, current ABI/fixup/function metadata, preserved-input and publication checks. **QG7** passes: bounded expansion covers emitter completion, payload consumers, undefined-field origins, native transport/epochs, other states and final status/adjustment.

Follow-up: The [emitter-completion report](daemon_state_emitter_completion_report.md) establishes the actual21 B private-output-to-heap copy with XOR0x98 and the subsequent original256 B table copy. Four independently replayed classes cover all76 inherited states through exact incoming-byte admission and member-specific terminal exports. U/48 B remains undefined, S/64 B retains53/11 B definedness, and no new J+0x68 publication or Mach/IOKit emission is established. Native pairing and the downstream mixing loop remain unknown.
