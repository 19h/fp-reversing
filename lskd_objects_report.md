# LSKD positive retry, cached slot vector and index-state ABI

Subsequent source evidence: [Vector origin and typed element initialization](lskd_vector_origin_report.md) establishes the source publication into `0xfffffe000ccc78d0`, the 8192 B `site.KDDecryptParamsArray_t` descriptor, a 512 B `site.KDDecryptParams` element descriptor, first-slot/tag writes and the conditional vector-failure release/result suffix. Sixteen UNSAT queries, five exhaustive banks and thirteen reconstructed start frames pass. Native allocator outcomes, completed population, lock ownership and matched reader epochs remain unknown.

The word at `0xfffffe000ccc78d0` has an additional source role beyond presence testing: the positive route loads it as the base of an eight-byte-slot array. Both vault and allowed use the selected ten-bit index to load a raw64-bit slot word and partition zero/nonzero values. The actual vector pointer, native allocation extent, slot contents and object type remain unknown. [OR1-OR7]

The positive routes save the selected index, call the existing acquisition adapter again, then check that the tag is still nonzero before loading the slot. They do not repeat the earlier full low32-bit key comparison in these inspected retry fragments. Native update ordering, synchronization and lifetime conclusions require the producer/writer paths. No complete positive handler or accepted native context executes here.

The loads at `0xfffffe000a57eef8` and `0xfffffe000a57282c` therefore have distinct state roles. The earlier checked first-pass paths loaded unknown X13 values that were discarded before use. On the positive retry, original stores have initialized the same frame cells with the selected index; X13 then supplies the slot-array index. The earlier [discarded-load certificates](lskd_lookup_report.md) retain their original prefix bounds.

[Source contracts](triage_evidence/lskd_objects_contracts.json), [isolated fixtures](triage_evidence/lskd_objects_profiles.json), [fresh local replays](triage_evidence/lskd_objects_replays.json), [independent checks](triage_evidence/lskd_objects_checks.json), [sixteen source proof pairs](triage_evidence/lskd_objects_proofs.json), [source identity](triage_evidence/lskd_objects_source_identity.json), [preservation](triage_evidence/lskd_objects_preservation.json) and [scoped gates](triage_evidence/lskd_objects_quality_gates.json) retain the evidence. The wider daemon/kext/IPC investigation remains active.

```text
previously checked first pass
  acquisition adapter -> tag[key &3FF] == low32(context)
  -> release adapter -> tag entry != 0

conditional positive continuation [static source composition]
  save zero-extended index in frame
  -> call acquisition adapter again, selector2D2, explicit pointerNULL
  -> restore index into X13 and select retry callback
  -> re-read tag: nonzero required
  -> vector = u64[CCC78D0]
  -> raw_slot = u64[vector +8*index]
       zero    -> declared null-slot source fragment
       nonzero -> further consumer [unexecuted]

raw slot words are opaque here; no object body is supplied
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| OR1 | Pinned original KC and normalized kext identify this build | Source bytes, slots and layouts | Rehash and compare bounded windows, exact nlist and original pointer chains |
| OR2 | Local A64 instruction semantics and abstract PAC match the declared architecture | Source lifts and local fixtures | Independently decode both load pairs; execute original bytes; check every read/write and boundary; native PAC remains unknown |
| OR3 | Prior source phases W23=0x72D and W28=0x8AC reach the declared positive routes | Composed continuation and dispatch constants | Re-lift index/phase/record/callback fragments; check exact authenticated destination slots |
| OR4 | The saved index comes from the earlier source low10-bit computation | Indexed8192-byte extent | Re-lift both index formulas; test all1024 indices and both slot polarities locally; native allocation extent unknown |
| OR5 | Same-frame cells and declared distinct symbolic cells remain valid across the retry | Index and callback preservation | Recover actual reaching definitions for later native execution; arbitrary aliasing is outside these local lemmas |
| OR6 | The acquisition adapter preserves source callee-saved registers and returns | Tag-cell pointer and frame continuity | Prior byte-audited helper returns and new record proofs; establish native lock validity/ownership separately |
| OR7 | Native vector/tag updates and reclamation obey an as-yet-unrecovered discipline | Any native identity/lifetime conclusion | Establish writer lock identity, ordering, publication and cleanup; no native race or safety result is claimed |
| OR8 | Local fixtures supply a distinct8192-byte slot array and nonnull base | Exhaustive isolated layout outcomes | Inspect exact initial memory and all source reads/writes; no accepted tag, object body or positive parent path is supplied |
| OR9 | The raw64-bit slot is opaque beyond its null test | Object/carrier naming and consumer frontier | Recover the subsequent pointer transformation and consumers before assigning a C++ type or raw-pointer representation |
| OR10 | Retained actual first-pass calls establish shared source call sites only | Acquisition-adapter attribution | Recheck all38 recorded calls against source bytes/slots; none establishes a second positive invocation |
| OR11 | Shared SP+0xD28 syntax does not establish a writer alias or common frame | Two retained writer candidates | Recover byte-bank pointer inputs and a same-frame reaching definition; reject nearest-function/offset-only association |

OR1-OR11 qualify the corresponding claims. The local fixtures are instruction-layout checks, separate from source entry reachability and native business processing.

## Primary provenance and verification coverage

| Item | Verified value |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Bounded original source windows / authenticated dispatch slots |16 /12 |
| Source proof pairs / lifted instruction instances |16 /115 |
| Cache-root byte-bank input checks |512 |
| Fresh isolated layout cases |4096 =2 providers *1024 indices *2 slot polarities |
| Original local instruction visits / byte checks |65536 /262144 bytes |
| Source u64 read epochs / private frame-zero write epochs |8192 /4096 |
| Independently decoded original load pairs |2 |
| Prior actual first-pass acquisition-call readbacks |38, with prior byte-audit scope retained |
| Native target execution / model memory writes |0 /0 |

## Distinct tables, caches and saved-index roles

| Source interface | Established source role | Remaining native premise |
| --- | --- | --- |
|0xfffffe000ccc7b08 | Shared u32 tag table indexed by low10 bits | Source first-element tag-zero writer now recovered; native contents/epochs unknown; indexed extent4096 bytes |
|0xfffffe000ccc78d0 | Presence test and cached base for an eight-byte-slot vector | Source 8192 B typed allocation and publication now recovered; native pointer, ownership and reclamation unknown |
|0xfffffe000ccc78a8 | Cached RW-lock pointer used by the recovered acquisition/release/free adapters | Source RW construction now recovered in the linked start reports; native identity/lifetime unknown |

The indexed vector extent is1024*8 B=8192 B=8 KiB. The source computes the slot address with X13 shifted by3. This establishes the accessed address range under a valid array-base premise; it does not establish an8192-byte native allocation. [OR4, OR7-OR9]

| Provider | Positive source index forwarding | Retry callback store | Index reload |
| --- | --- | --- | --- |
| Vault |0xfffffe000a54b198 reads u32 SP+0x3C;0xfffffe000a54b1a0 stores its zero-extended u64 at SP+0x18 |0xfffffe000a57ee04 stores target0xfffffe000a52265c at SP+0x20 |0xfffffe000a57eef8 LDP X13,X8 from SP+0x18 |
| Allowed |0xfffffe000a51160c reads u32 SP+0x74;0xfffffe000a511614 stores its zero-extended u64 at SP+0x58 |0xfffffe000a572730 stores target0xfffffe000a591b38 at SP+0xB8 |0xfffffe000a57282c LDR X13 from SP+0x58; subsequent LDR restores X8 callback |

The source phase arithmetic selects vault retry fragment0xfffffe000a57edfc through index0x6F1 and allowed retry fragment0xfffffe000a572728 through index0x34C. Those shared fragments save callbacks selected by indices0x96 and0 respectively. Each edge has original chained-pointer membership and authenticated diversity in the contracts. Function/compiler envelopes supply byte boundaries; no nearest-symbol semantic assignment is used.

## Acquisition retry and tag recheck

Both original retry packers source-write a12-byte acquisition record: explicit pointerNULL at+0 and encoded selector at+8. With record address R and K32=`u32((low32(R)^0x1D65DAD0)*0xE9655F4D)`, decoding `encoded32-K32` yields0x2D2. This is the earlier acquisition selector, whose null explicit pointer selects the cached RW pointer. Source record stores, rather than invented call arguments, establish that contract. [OR3, OR5-OR6]

| Provider | Shared acquisition call site | Original adapter target | Retry tag read |
| --- | --- | --- | --- |
| Vault |0xfffffe000a57ee9c |0xfffffe000a54e220 |0xfffffe000a522668, from X21 |
| Allowed |0xfffffe000a5727e0 |0xfffffe000a54e220 |0xfffffe000a591b44, from X26 |

Thirty-eight previously byte-audited first-pass calls use these exact sites and target. New source lemmas establish the positive retry records and callbacks. A second positive call is not executed by this increment. The first-pass release sites are0xfffffe000a5124a8 (vault) and0xfffffe000a590ccc (allowed), both targeting recovered release adapter0xfffffe000a551f38. Thus the declared static continuation contains a release/reacquisition boundary before the later slot load. No native lock-state transition is inferred from adapter attribution.

| Retry tag value | Vault target, index | Allowed target, index |
| --- | --- | --- |
| Zero |0xfffffe000a59bb00,0x86B |0xfffffe000a535e3c,0x275 |
| Nonzero |0xfffffe000a58b7cc,0x85C |0xfffffe000a57e26c,0x2D0 |

These inspected callbacks require only a nonzero tag; they do not compare its full value with context32. Native writers and actual synchronization are required to characterize identity stability across these source phases. No vulnerability or native concurrency result is inferred from this bounded source fact. [OR7]

## Raw slot load and null partition

| Provider | Vector-base load | Indexed raw-slot load | Null / nonnull destination |
| --- | --- | --- | --- |
| Vault |0xfffffe000a58b7e0: X10=u64[X10] |0xfffffe000a58b7e4: X12=u64[X10+8*X13] |0xfffffe000a533214 /0xfffffe000a525270 |
| Allowed |0xfffffe000a57e29c: X10=u64[X10] |0xfffffe000a57e2a0: X12=u64[X10+8*X13] |0xfffffe000a535820 /0xfffffe000a528b10 |

Both source chains carry X10=0xfffffe000ccc78d0 into the first load under the checked cache-root and callback-preservation premises. Independent machine-word decoding confirms64-bit unsigned-offset root loads and64-bit register-offset slot loads with baseX10,indexX13,shift3,destinationX12. The null partition uses the whole64-bit loaded word. Its source dispatch indices are vault0x455/0x42B and allowed0x515/0x502, with exact original pointer targets retained.

The nullable-slot prefixes source-clear SP+0x40 (vault) or SP+0x90 (allowed). The null-slot fragments subsequently load those frame cells. No successful output/result convention is inferred from those loads alone. Nonzero targets enter substantial further source consumers; their pointer representation, object fields, lifetime and final outputs remain unresolved. [OR9]

The4096 isolated fixtures execute only the original prefixes ending immediately before the dispatch-table load. Each synthetic vector contains1024 distinct nonzero raw words; the selected slot is tested unchanged and with0. Every case performs exactly two eight-byte reads (base cell, selected slot) and one eight-byte private frame-zero store. The whole vector remains unchanged by source. No tag table, accepted context, object body, API call, native lock or positive parent request is supplied. Exhaustive index coverage corroborates the source layout and null partition; the symbolic proofs cover arbitrary raw64-bit slot words.

## Table-writer candidates and external boundary

The indexed-store inventory from the previous report provides a useful candidate at0xfffffe000a5480a0: `STR W26,[X15,W8,UXTW #2]`, with X15 loaded from SP+0xD28. Another source fragment at0xfffffe000a589938 stores `pool[decoded_index]-8` at SP+0xD28. Exact original windows are retained for both. The second fragment requires byte-bank pointer inputs from SP+0xC28 and X26; their reaching definitions are unresolved. A common frame/reaching definition between the two sites is also unresolved. These are source-search anchors, not an established table writer. [OR11]

No new Mach right, incoming/outgoing port, message ID or external emission site is established. The tag table, vector cache, saved index and raw slot word are kernel-local memory interfaces. Native producer epochs and transport linkage remain unknown; the linked vector-origin increment supplies a static producer.

## Reproduction, preservation and scoped quality gates

```sh
PYTHONPATH=triage_evidence python3 -P triage_evidence/recover_lskd_objects.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/probe_lskd_objects.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/prove_lskd_objects.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/validate_lskd_objects.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/validate_lskd_objects_preservation.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/validate_lskd_objects_delivery.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/validate_rpc502_sidecar_delivery.py
```

The fresh verifier reconstructs original source windows/pointers, re-lifts sixteen proof pairs, independently decodes the load words and reruns all4096 local fixtures with exact source reads/writes and outcomes. The baseline contains2030 artifacts,2024 unchanged with six declared report/index edits. Original analysis.md, C and calls inputs remain unchanged. Earlier native/synthetic boundaries and complete-parent evidence remain frozen.

Source recovery is O(B+I+256R); local validation is O(B+C*I+8192C+256R), with O(B+C) retained space plus solver-dependent cost (30 s/query). B denotes pinned source bytes, I inspected/lifted instructions, C local fixtures and R byte-bank rules. Arithmetic widths and address extents are explicit.

| Impact | Further investigation | Required evidence |
| --- | --- | --- |
| High | Establish tag/vector writer and joint publication | Resolve candidate bank inputs, common-frame aliases, source stores and vector allocation/publication |
| High | Establish native synchronization and identity stability | Actual RW-lock identity/ownership and writer ordering across release/reacquisition |
| High | Recover raw-slot representation and positive consumers | Original source after0xfffffe000a525270/0xfffffe000a528b10 and complete downstream data flow |
| Medium | Resolve actual vector allocation extent and reclamation | Original allocator sizes, bounds, null slots and destruction contracts |
| Medium | Connect local context operations to daemon transport | Exact caller/endpoint, packet, port/right and ownership evidence |

| Gate | Scoped disposition | Evidence |
| --- | --- | --- |
| QG1 | Pass | Factual source/interface analysis |
| QG2 | Pass | OR1-OR11 identify dependencies and falsification probes |
| QG3 | Pass for increment | Positive retry/index/vector/null contracts and writer anchors covered; full objective incomplete |
| QG4 | Pass | Explicit widths, exact extents, counts and reproduction |
| QG5 | Pass | First-pass/retry states, static/native execution, indexed/allocation extents and writer aliases separated |
| QG6 | Pass | Original source/pointers, sixteen proof pairs,4096 fresh isolated cases and independent load-word decoding |
| QG7 | Pass | Impact-labeled continuation table |
