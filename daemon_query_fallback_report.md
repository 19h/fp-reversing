# Daemon zero-capability version fallback and result-record ABI

Under the established query-state premises, `0x10043BD18` classifies the guarded version word V when guarded capabilities C=0. It returns a marker through record+0x10. The caller ORs bit0x08 into the encoded capability field exactly when unsigned `V >> 16 >= 0x2E1E`, then returns through the original guard epilogue. Caller state byte0 is subsequently written0x0A. The bit's functional meaning and native applicability remain unknown. [QF1-QF12]

The [preceding query-state report](daemon_query_state_report.md) stopped before this call. This increment follows the original call, all selected decision fragments, result store, leaf return and outer helper return. Retained prior analyses already describe the threshold; current source bytes,16 source proof pairs and564 fresh private cases independently corroborate and extend that evidence. All264 preceding prefixes are preserved exactly. All cases stop before the same unknown iterator load, without a new external model.

[Source contracts](triage_evidence/daemon_query_fallback_contracts.json), [retained cases](triage_evidence/daemon_query_fallback_profiles.json), [fresh replays](triage_evidence/daemon_query_fallback_replays.json), [independent checks](triage_evidence/daemon_query_fallback_checks.json), [source proofs](triage_evidence/daemon_query_fallback_proofs.json), [live IDB source](triage_evidence/daemon_query_fallback_live_ida.json), [source identity](triage_evidence/daemon_query_fallback_source_identity.json), [preservation](triage_evidence/daemon_query_fallback_preservation.json) and [scoped gates](triage_evidence/daemon_query_fallback_quality_gates.json) retain the evidence. The full interface objective remains active.

```text
query22 guarded V32 + query23 guarded C32
  -> source encoded-cache stores
  -> C != 0 ------------------------------+
  -> C == 0:                              |
       source prepares16 B input           |
       call0x10043BD18(X0=record)           |
         controller updates                |
         version byte3/byte2/byte1 gates    |
         record+0x10 <- marker32            |
         return                            |
       marker >u 0x3A9C01D9 ?              |
         yes: encoded_capabilities |= 0x08  |
         no:  field retained               |
       original guard epilogue <-----------+
  -> outer helper returns
  -> source state byte0 <- 0x0A
  -> STOP before unknown iterator read at0x100483CA8
```

All addresses are preferred file virtual addresses. B denotes bytes. V and C are the words after the daemon's status32/size64 guards, including source-zero fallback on a rejected query. Arithmetic is modular u32/u64 unless an unsigned comparison is explicitly stated. No native port, IOKit, guard import or PAC operation executes.

## Assumption register

| ID | Assumption / bound | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| QF1 | Pinned thin image and selected IDB contain the inspected bytes | Address/role correspondence | Rehash original source and universal image; compare162 current IDB rows |
| QF2 | QS1-QS12 from the preceding report hold | Composed query/helper path | Preserve all264 preceding prefixes; recover complete native predecessor separately |
| QF3 | C=0 enters the source-prepared fallback with control word0x6D25 after record decoding | Callee's version-classification role | Source-lift the pointer decoder and multiply-add; arbitrary other input records/controls remain outside this contract |
| QF4 | Cached version fields retain the helper's initial encodings and record cells retain their source epochs | Version-gate inputs | Independently reconstruct every byte epoch and check exact encoded fields; concurrent writes/lifetime remain unknown |
| QF5 | Original byte banks, biased roots and authenticated dispatch slots retain their pinned values | Selected fragments and return chain | Two exhaustive256-input bank identities,33 original fixups and ten direct-slot checks; source uses fixed byte input0x3A |
| QF6 | Private A64 engine and explicit PAC/return abstraction implement the declared model | Finite paths | Check every original instruction byte/edge; hardware authentication remains unknown |
| QF7 | Two API summaries return the declared values and preserve callee-saved state | Guarded V/C words | Retain independent status/size cases and clobber X1-X17/NZCV as before; native values remain unknown |
| QF8 | Leaf record's prepared16 B input and adjacent4 B result cell have their declared stack extents |20 B accessed result-record ABI | Last four bytes start unknown, become source-written at0x1001A88F8, and are read only afterward |
| QF9 | Source decision phases compose through the verified slots with no interfering aliases | Universal threshold/marker theorem | Verify each conditional index,default marker and result store; fresh cases exercise every selected decision edge |
| QF10 | Original private guard fixture stays equal across the helper | Normal return and byte0 publication | Preserve source guard comparison/restoration; no guard-mismatch/native-failure behavior is induced |
| QF11 | Unknown iterator bytes remain unknown | Final frontier | All564 cases stop before0x100483CA8; F+0x68 known mask remains00000000 |
| QF12 | Encoded bit0x08 has no established higher-level semantics | Capability interpretation and IPC limits | Trace actual readers/decoders and downstream call selection; no new right transfer or message emission is inferred |

QF1-QF12 qualify all dependent claims. The universal proofs cover the arithmetic/conditional source phases under these premises, not native reachability, memory validity, concurrency, actual query results or successful authentication.

## Result-record and call ABI

Let F be caller SP, H=F-0x60 the query-state helper SP, L=H-0x10 the nested leaf SP, and Q=H+0x14 the record pointer passed in X0 at `0x100011674`. The nested leaf allocates/restores16 B of stack and has no selected external calls. It preserves X0 as the record pointer; the caller reads the result cell rather than interpreting W0 as a status.

| Offset from Q | Width | Producer/consumer contract |
| --- | --- | --- |
| +0x00 |4 B | Prepared input `J32 + 0x50EBC19F`; not read by selected callee paths |
| +0x04 |4 B | Prepared input `J32 XOR 0x7B3D5095`; not read by selected callee paths |
| +0x08 |4 B | Prepared input `0x6D25 - J32`; read at0x10043BDB0 and decoded to control0x6D25 |
| +0x0C |4 B | Prepared input `J32 XOR 0x0862CC88`; not read by selected callee paths |
| +0x10 |4 B | Initially unknown result; written by callee0x1001A88F8 and read by caller0x100011678 |

`J32=u32((low32(Q) XOR 0x8515CFBD) * 0xC7F6DCA7)`. The callee independently derives the prekey from low32(X0), multiplies it by0xC7F6DCA7 and adds record+8, recovering0x6D25 for every pointer low word. Its result at Q+0x10 aliases H+0x24. The accessed20 B record ends at H+0x28; the outer helper's saved guard starts at H+0x28. The source does not write that guard as part of this record.

The first16 B stay unchanged throughout the selected callee. Its adjacent result4 B acquire source provenance only at the result store. These are input/output cells within the caller's frame, not evidence of a separately allocated16 B heap object or an out-of-bounds access.

## Encoded version decisions and exact marker partition

The callee obtains the same state base `0x1010B6380` through original pool slot0x1010A2D78 and bias0xFFFFFFFFFEFF1ACD. It reads the three version component encodings at state+8/+0x0C/+0x10 as needed by the selected branch. Let b3=V>>24, b2=(V>>16)&255 and b1=(V>>8)&255.

| Condition on guarded V | Result marker32 at record+0x10 | Caller capability action |
| --- | --- | --- |
| Unsigned V>>16 <0x2E1E |0x3A9C01D9 | Retain encoded field0xC49697F0 |
| V>>16=0x2E1E and b1=0 |0x3A9C01DA | OR0x08, yielding0xC49697F8 |
| V>>16>0x2E1E, or V>>16=0x2E1E and b1!=0 |0x3A9C01DB | OR0x08, yielding0xC49697F8 |

Byte0 does not affect this partition. Markers DA and DB differ, while the caller's unsigned `marker > 0x3A9C01D9` accepts both. The threshold is equivalently unsigned V>=0x2E1E0000. No major/minor/patch names or meaning for bit0x08 are established.

| Decision source | Predicate established under predecessor conditions | Original slot / decoded successor |
| --- | --- | --- |
|0x10043BE14..0x10043BE88 |b3>=47 | yes0x101070B20 ->0x1001A88F8 with defaultDB; no0x101070818 ->0x10025784C |
|0x10025784C..0x1002578AC |b3==46, after b3<47 | yes0x10104D4A0 ->0x10036C670; no0x10104D3A8 ->0x1001A88F8 with defaultD9 |
|0x10036C670..0x10036C6C0 |b2>=31, after b3==46 | yes0x10107D7E0 ->0x1001A88F8 with defaultDB; no0x10107D698 ->0x10034F538 |
|0x10034F538..0x10034F598 |b2==30, after b2<31 | yes0x10105F500 ->0x100275B80; no0x10105F7B8 ->0x1001A88F8 with defaultD9 |
|0x100275B80..0x100275BC0 |b1==0, after b3==46,b2==30 | Common result store; markerDA if equal,DB otherwise |

Source CMN/CMP flags are lifted explicitly: CMN uses33-bit addition to recover u32 carry; CMP uses unsigned carry/no-borrow and zero; CSET HI/LO and CINC NE consume those exact conditions. The composed theorem follows the source-selected CFG and original dispatch slots. It does not replace unsigned comparisons with signed comparisons.

The return fragment at0x1001A88F8 stores W14 to[X0+0x10], restores SP by16 B and executes RET. The source caller at0x100011678 reads that exact cell and selects index0x3A37 when marker>D9, otherwise0x2757. Original slots0x1010570A8 and0x10104D9A8 target0x100015278 and0x1000898D8 respectively, both IA diversity0xFDE4. At0x100015278 the source performs a u32 load/OR8/store on state+0x14, then selects the original guard epilogue. Both paths return before caller0x1003C3AF4 writes byte0=0x0A.

## Final state and mutable controllers

Under the full returning private path, state+4 retains the connection fixture, state+8/+0x0C/+0x10 retain their initial encoded version bytes, and state+0 becomes0x0A. The final encoded capability field is:

```text
if C != 0:  encoded32 = C XOR 0xC49697F0
if C == 0:  encoded32 = 0xC49697F8  when unsigned(V >> 16) >= 0x2E1E
                       0xC49697F0  otherwise
```

Query rejection and an accepted numeric zero both produce guarded C=0; the same fallback applies locally. A rejected version query yields guarded V=0 and therefore cannot satisfy this version threshold. Native API failures, actual device metadata and a higher-level meaning for this behavior remain unknown.

The nested leaf updates an additional controller at0x1010B6918 and overwrites the previously updated shared controller0x1010C4670. Let A=[0x1010B6918], B=[0x1010C4670], T=0x73D046208EAED1A6, M=0x0A5CD4CF and leaf SP L=F-0x70:

```text
D = u64(B - A) XOR u64((L + 8) XOR T)
N = u64(D * M)
[0x1010B6918] <- N   at0x10043BD58
[0x1010C4670] <- N   at0x10043BD5C
```

These effects execute before the version decisions and are retained in all532 completed zero-capability cases. Independent byte epochs verify that B is read after the outer helper's earlier write. No locking, concurrent exclusion or native controller lifetime is established by these local stores.

## Validation and provenance

The base264 cases are exactly those of the preceding increment. An additional300 accepted-zero-capability controls cover b3 in{0,45,46,47,255}, b2 in{0,29,30,31,255}, b1 in{0,1,255}, byte0 in{0,255}, and two frame placements. The source proofs cover all V32 values under the stated cache/phase premises, beyond this finite grid.

| Check | Verified result |
| --- | --- |
| Fresh private cases / original instruction visits |564 /324496 |
| Exact preceding prefixes preserved |264 |
| Nonzero capabilities skip fallback |32 |
| Completed zero-capability leaf/helper returns |532 |
| Marker D9 /DA /DB |376 /4 /152 |
| Version-qualified encoded bit0x08 stores |156 |
| Low-byte independence pairs |150 |
| Final unknown-iterator frontiers |564 |
| Source proof pairs / lifted instructions |16 /138 |
| New exhaustive bank identities / byte inputs |2 /512 |
| Original fixups / direct dispatch slots |33 /10 |
| Current IDB instruction rows matching original source |162 |
| Retained external note/proof sources snapshotted and hashed |4 |
| Prior artifacts checked / unchanged |2340 /2334 |
| Original analysis/C/calls inputs preserved |3 |

Retained [helper-successor notes](/Users/___/Downloads/fpx/analysis/arm_iokit_helper_successors_evidence.md) and [threshold-machine notes](/Users/___/Downloads/fpx/analysis/arm_iokit_threshold_machine_evidence.md) supplied analysis leads. The contracts snapshot their complete text, two related proof scripts and current hashes. Earlier native/PAC interpretations are not imported as facts. The current implementation lifts the original source and follows the entire selected private call/return path. No old exploratory script, target process or IDB execution was invoked.

Fresh replays use the same A64 engine as retained cases. Independent checks reconstruct byte epochs/provenance, original reads, controller effects, result aliases, exact prefix equality, marker partition and final field stores. This is not a second independent native engine. SMT queries retain hashed original and simplified files and are rechecked against freshly rebuilt original-source obligations. The earlier input-packing proof supplies an explicit composition premise; arbitrary callee record controls remain unclassified.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_query_fallback.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_query_fallback.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_query_fallback.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_query_fallback.py
```

A regeneration requires a new preservation/delivery seal. Each private case permits at most3000 visits. With B image bytes, C cases, V visits/case, E memory/API events/case, J demand pages, F fixups, I lifted instructions and R bank identities: time O(B+C*(V+E+J*F)+I+256R), retained space O(B+C*(V+E)+I+F+4096J), plus a30 s/query solver bound. Preservation permits changes only in the four consolidated reports, investigation status and aggregate manifest validator.

## Bounded continuation and scoped quality gates

| Impact | Question / pattern | Evidence that would resolve it |
| --- | --- | --- |
| High | Which consumers decode state+0x14 and interpret synthesized bit0x08? | Exact source reads/decoder, bit tests and subsequent API/IPC argument lineage |
| High | What initializes state byte09 and the shared connection before this query path? | Complete native predecessor conditions, service-match/open output provenance and connection ownership |
| High | What produces saved iterator F+0x68 and orders its release? | Source producer/store aliases and object lifetime through0x100483CC0 |
| Medium | API rejection and numeric zero converge on the same local fallback | Trace later error/status handling and native transaction outcomes; local convergence does not prove recovery success |
| Medium | Controller0x1010C4670 is written by both nested helpers | Source synchronization/once ownership and concrete lifetime/order evidence |
| Medium | Other decoded record controls may select different callee fragments | Explicit caller census and record/control provenance; this increment proves control0x6D25 only |
| Low | Version component nomenclature and bit0x08 semantics remain unnamed | Matching consumer/type/schema evidence |

No new incoming Mach endpoint, emitted message, transferred right or native port name is established. This increment closes a daemon-local metadata/control-flow boundary and preserves the unknown iterator frontier. Native reachability, device values, hardware authentication, concurrency and later IPC remain unknown.

| Gate | Result / evidence |
| --- | --- |
| QG1 | Pass: factual source/interface analysis |
| QG2 | Pass: QF1-QF12 include dependent results and falsification probes |
| QG3 | Pass for this increment: result-record ABI, full selected fallback, threshold and return/cache effects covered; full_goal_complete=false |
| QG4 | Pass: explicit B/u32/u64 widths, unsigned predicates, modular formulas, case cardinality and reproduction |
| QG5 | Pass: input/accessed extents, marker/status, byte-field roles, prior/current evidence and native/private boundaries distinguished |
| QG6 | Pass: original bytes/fixups,162 live IDB rows,564 fresh byte audits and16 source proof pairs |
| QG7 | Pass: impact-labeled bounded continuation table |
