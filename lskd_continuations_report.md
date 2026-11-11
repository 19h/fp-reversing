# LSKD context records, RW-lock adapters and guarded continuations

Subsequent source evidence: [Vector origin and typed element initialization](lskd_vector_origin_report.md) establishes the source publication into `0xfffffe000ccc78d0`, the 8192 B `site.KDDecryptParamsArray_t` descriptor, a 512 B `site.KDDecryptParams` element descriptor, first-slot/tag writes and the conditional vector-failure release/result suffix. Sixteen UNSAT queries, five exhaustive banks and thirteen reconstructed start frames pass. Native allocator outcomes, completed population, lock ownership and matched reader epochs remain unknown.

The previously unnamed helper at `0xfffffe000a54e220` is a source lock-acquisition adapter in the checked selector context. Its companion `0xfffffe000a551f38` releases the lock, and `0xfffffe000a5529a8` conditionally frees and clears a cached RW-lock pointer. All three select cell `0xfffffe000ccc78a8`; exact original kernel bindings identify `IORWLockWrite`, `IORWLockUnlock`, and `IORWLockFree`. Native synchronization and destruction remain **unknown** and unexecuted. [CT1-CT12]

Vault and allowed records also have recovered context transformations. Their constant comparisons test zero context after reversible record encoding. Twenty source-derived proof pairs establish the local codecs, selector/pointer gates, source caller composition and conditional cache clear. The proof set contains 286 lifted instruction instances. These constants are not assigned authentication or cryptographic meaning.

The retained set contains355 guarded cases:343 preceding cases plus12 nonzero-cache fixtures. Eighty-five cases extend a preceding boundary. With the cached cell at its file value zero, thirteen stop execution wrappers publish a source-cleared160-byte candidate and return0. Twelve nonzero-cache fixtures stop before the RW write call. Twenty-four nonzero vault/allowed paths stop before a private read whose source initialization is not established. Native reachability, runtime cache contents and later IPC remain **unknown**.

[Source contracts](triage_evidence/lskd_continuations_contracts.json), [retained profiles](triage_evidence/lskd_continuations_profiles.json), [fresh profiles](triage_evidence/lskd_continuations_replays.json), [independent checks](triage_evidence/lskd_continuations_checks.json), [twenty proof pairs](triage_evidence/lskd_continuations_proofs.json), [source identity](triage_evidence/lskd_continuations_source_identity.json), [preservation](triage_evidence/lskd_continuations_preservation.json), and [scoped gates](triage_evidence/lskd_continuations_quality_gates.json) retain the evidence. The broad interface investigation remains active.

```text
source stop / AVD / nonzero vault or allowed context
  -> acquisition record: explicit pointer, encoded selector
       explicit pointer != 0 -> IORWLockWrite(pointer) [STOP]
       explicit pointer == 0 -> load cached G at CCC78A8
                                 G != 0 -> IORWLockWrite(G) [STOP]
                                 G == 0 -> original return, no primitive call

checked stop/AVD continuation with G == 0
  -> source body / record rewriting
  -> release adapter: explicit pointer or fresh cached G
       nonnull -> IORWLockUnlock(pointer) [STATIC BOUNDARY]
       null    -> original return
  -> stop: cached-free adapter
       G != 0 -> IORWLockFree(G) [STATIC BOUNDARY]
                 -> returning-call premise -> source G = 0
       G == 0 -> original return
  -> stop raw success -> zeroed candidate publication -> wrapper return 0

vault / allowed record
  -> decoded value = context XOR constant
       context == 0 -> raw error -> original error wrapper return
       context != 0 -> null acquisition record -> later private-read boundary
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| CT1 | Pinned KC and normalized kext identify this build | Source, names, tables and bindings | Rehash both; compare bounded original windows and original pointer-chain membership |
| CT2 | Guarded private execution and abstract PAC implement the declared semantics | Execution observations | Reject unlisted code/calls/writes, verify source bytes and authenticated slots; native PAC/reachability remain unknown |
| CT3 | Only inherited allocator/free register effects are modeled | Wrapper returns, publication and error cleanup | Check exact sites/operands, clobber caller registers; models write/initialize/free no memory |
| CT4 | Controller globals remain stable except recorded source writes during each run | Flattened dispatch | Original/zero/noise fixtures, exact controller cells, source epochs and exhaustive byte banks; native concurrency remains unknown |
| CT5 | Source selector phases2D2/1D3/52F/72D/8AC hold at their stated local slices | Lock and context partitions | Check every source-produced record and original branch slot; unrelated selector contexts are not classified |
| CT6 | Symbolic cells are distinct except declared source aliases | Record/store composition proofs | Independently reconstruct all byte epochs; vary stack placement and auxiliary location; arbitrary native aliases remain outside scope |
| CT7 | Caller key-basis identities qualify the canonical basis substitutions in two composition proofs | Wide context/scalar record round trips | Re-lift each original caller basis and receiver key first; private execution contains no substitutions |
| CT8 | Cached G is zero in the file; its runtime value and producer are unknown | File-state stop/error paths | Twelve opaque-nonnull fixtures reach the API boundary without reading an invented lock object; recover actual allocation/publication separately |
| CT9 | Returning from the unexecuted free call preserves the source callee-saved cell pointer | Conditional clear at0xfffffe000a5793bc | Establish actual free/lifetime behavior and X20 identity across the native call; no private nonzero-cache destruction is executed |
| CT10 | Preflight known-byte masks reflect source/fixture initialization | Private-read frontiers | Reconstruct masks independently; verify the instruction is absent from source visits and no poison byte is consumed |
| CT11 | Declared context/version/parameter fixtures bound the sample | Provider results | Zero and0x1234567887654321 contexts, both stack placements, both auxiliary locations, three controller fixtures; other environments remain unknown |
| CT12 | Discarded inherited stack probes supply no later value; post-model storage is inspection memory | Stack probing and final snapshots | Check WZR probe sites and no model memory writes; native post-free accessibility remains unknown |

CT1-CT12 qualify corresponding claims. Fresh equality uses the same execution engine; byte reconstruction, compact record expectations, original pointer decoding and source arithmetic check different properties. No finite result establishes the entire native daemon/kext exchange.

## Primary provenance and execution coverage

| Item | Exact identity / scope |
| --- | --- |
| Original KC, full SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Bounded source extraction |38 windows; shared compiler envelopes retain boundary metadata only |
| New controller cells | Five exact eight-byte cells |
| Fresh case set |355, including343 preceding inputs and12 additional cache-presence inputs |
| Source instruction visits / instruction-byte checks |1113798 /4455192 bytes |
| Source proof pairs / lifted instruction instances |20 /286 |
| Source-produced context round trips / scalar record round trips |48 /24 |
| Source acquisition / release / cached-free records |61 /25 /13 |
| Checked bounds argument pairs |48 |
| Helper GP X19-X29 and SP return contexts |159 |
| Cached-cell read epochs / executed cached-cell writes |99 /0 |
| Source stop candidate publications |13, each160 source-cleared bytes |
| Unexecuted private-read / RW-write boundaries |24 /12 |
| Register-only allocator/free models / model memory writes |1912 /0 |

The additional controller cells are `0xfffffe000ccc2b78`, `0xfffffe000ccc2b88`, `0xfffffe000ccc2c78`, `0xfffffe000ccc2dd8`, and `0xfffffe000ccc2ea8`. Neither these cells nor cached cell0xfffffe000ccc78a8 is read in the preceding343 complete prefixes. Additional source writes are restricted to the exact controller cells. The cached-cell presence fixture changes only its declared input word; no lock object is initialized or treated as valid.

The earlier [readback report](lskd_readback_report.md) and its producers remain frozen. The [RW lifecycle report](rw_lifecycle_report.md) had already resolved the free fragment and allocator call but lacked the reaching definition of its pointer cell. This increment establishes that cell for the inspected LSKD free-adapter context. Subsequent [LSKD construction analysis](lskd_lock_origin_report.md) resolves the selected allocator store's X20 through record +8 and a conditional source preparer for this same LSKD cell. Subsequent [sample-cell analysis](cached_lock_origin_report.md) establishes a separate selected startup publication into sample-processing cell `0xfffffe000ccceab8`. Matched native lifetimes remain unknown for both domains.

## Exact routine attribution and lock ABI

| Entry / source context | Established role | Exact nlist evidence |
| --- | --- | --- |
|0xfffffe000a54e220, decoded selector0x2D2 | Acquire explicit RW pointer or cached G; skip a primitive for null/null | No exact nlist symbol |
|0xfffffe000a551f38, selector0x1D3 | Unlock explicit RW pointer or freshly loaded cached G; skip null/null | No exact nlist symbol |
|0xfffffe000a5529a8, selector0x52F | Free cached G when nonnull; clear the cell after the call returns | No exact nlist symbol |
|0xfffffe000a52f9f4, selector0x72D | Vault context/scratch/limit record receiver; bounds and context checks | No exact nlist symbol |
|0xfffffe000a55ce30, selector0x8AC | Allowed context/scalar/scratch/limit record receiver | No exact nlist symbol |

Roles apply to the stated source selector contexts and bounded windows. Compiler envelopes contain shared chunks. Their sizes and neighboring symbols do not establish one source-level routine role.

| Operation | Kext call site | Named wrapper | Import slot | Exact kernel target / alias |
| --- | --- | --- | --- | --- |
| Write acquisition |0xfffffe000a543fd4 |0xfffffe000a508d94 `_kernel_iorw_lock_write` |0xfffffe000847c3d0 |0xfffffe000bd0655c `_IORWLockWrite`, `_lck_rw_lock_exclusive` |
| Unlock |0xfffffe000a535eac |0xfffffe000a508d9c `_kernel_iorw_lock_unlock` |0xfffffe000847c3c8 |0xfffffe000bd08174 `_IORWLockUnlock`, `_lck_rw_done` |
| Free |0xfffffe000a5793b8 |0xfffffe000a508d84 `_kernel_iorw_lock_free` |0xfffffe000847c3b8 |0xfffffe000c4bb780 `_IORWLockFree` |

All three use X0 for the selected pointer. The caller does not establish a result status from their return register. Wrapper branches, stubs, original import slots, authentication metadata and exact kernel names corroborate the [supplied call catalog](com.apple.driver.FairPlayIOKit_calls.txt), lines105-109. No native target is executed. [CT1-CT5, CT8-CT9]

Acquisition checks an explicit pointer before falling back to G. Release separately reloads G when its explicit pointer is null. The inspected source record producers write null explicit pointers. Consequently, matching native acquisition, release and destruction would additionally require runtime cache identity/stability and actual ownership; the source does not retain an acquisition token in these records.

The free adapter's entry computes the exact cached-cell address into X20. Its nonnull branch passes the current G to the free wrapper at0xfffffe000a5793b8. The next original instruction, `STR XZR,[X20]` at0xfffffe000a5793bc, establishes a conditional clear after a returning call. No current execution traverses that nonnull free branch.

The subsequent [start-flow analysis](lskd_start_lock_flow_report.md) establishes a source constructor-to-acquisition handoff on the start success branch. It prepares a null explicit pointer with phase `0x2d2` after RW construction. A stable cached-pointer epoch and actual native ownership remain required to join that handoff to acquisition and later retirement.

## Lock record layouts and selector channels

Offsets are bytes; accessed footprints do not imply C structure sizes. Field gaps are not asserted initialized. Selector arithmetic is unsigned modulo2^32. R is the record address. [CT1, CT5-CT7]

| Adapter | Minimum accessed record footprint | Fields | Decoded selector |
| --- | --- | --- | --- |
| Acquisition |12 bytes |+0x00 pointer64; +0x08 encoded selector32 |`u32(E - u32((R xor0x1D65DAD0)*0xE9655F4D)) = 0x2D2` |
| Release |16 bytes |+0x00 encoded selector32; +0x08 pointer64 |`u32(E - u32((R xor0xDFB9786F)*0x1E2776FD)) = 0x1D3` |
| Cached free |4 bytes |+0x00 encoded selector32 |`u32(E - u32((R xor0xB0A65F3A)*0x4CA11177)) = 0x52F` |

The three selector identities are source-lifted over all64-bit record addresses and32-bit E. Pointer partitions are separately proved under the stated selector phases. These adapters write no result status into the checked records;159 helper returns restore GP X19-X29 and SP, and87 lock-adapter returns preserve the inspected record snapshot.

Three independent byte-bank rules resolve the acquire/release/free global roots to original pool slot0xfffffe0008471818 -> cell0xfffffe000ccc78a8. Three further rules resolve the API wrappers. Each rule checks all256 byte inputs (1536 evaluations total). Original pointer aliases in the normalized image are retained for the bounded delta set `{0,+4,+8,+12,-4,-8,-12}`: cell itself, cell+12 and cell-8. This census does not establish a globally unique producer or exclude other computed aliases.

## Vault and allowed context records

The source preparation is retained in the preceding readback contracts. For each receiver, let K be its64-bit address key:

```text
vault:   K = u64((R XOR 0x0CF045EEC410A4C0) * 0xAED3B63B)
allowed: K = u64((R XOR 0x0448A65EF71C80FA) * 0xDD76FF8F)

vault encoded context XOR K   = context XOR 0xE5FC6C5572D2C184
allowed encoded context XOR K = context XOR 0xFC6C08B9C3804423
```

A decoded value equal to its right-hand constant is therefore equivalent to context=0. Both source caller key bases and receiver keys are proved independently. The two composition proofs substitute canonical key bases only after these checked identities; no source execution uses substitutions. [CT5-CT7]

| Receiver | Field offset | Established field use |
| --- | --- | --- |
| Vault, accessed footprint72 bytes |+0x10 | Encoded selector32; `u32(E+K)=0x72D` |
| Vault |+0x20 | Scratch pointer64; bounds argument scratch+64 bytes |
| Vault |+0x30 | Limit pointer64 for the unsigned bounds helper |
| Vault |+0x38 | Written raw result32 on the checked returning error path |
| Vault |+0x40 | Encoded context64 |
| Allowed, footprint64 bytes |+0x00 | Written raw result32; overwrites an earlier record role |
| Allowed |+0x18 | Limit pointer64 |
| Allowed |+0x20 | Source-written encoded scalar32 derived from tag0x7E |
| Allowed |+0x28 | Encoded context64 |
| Allowed |+0x30 | Encoded selector32; `u32(E+K)=0x8AC` |
| Allowed |+0x38 | Scratch pointer64; bounds argument scratch+128 bytes |

Other caller-written pointer fields remain in the snapshots. Their downstream receiver roles are unknown at the current frontiers. These private record fields are distinct from the big-endian wire fields consumed before preparation.

For allowed scalar V, the original source stores `u32(V + 0x04CCBE9B - u32(K))` at record+0x20. Twenty-four cases independently match V=0x13579BDF from the prior source BE32 field decoder. Later consumption of this encoded scalar is unknown. Both receiver bounds calls resolve to0xfffffe000a561058; all48 argument pairs match their actual incoming record fields and pass the source unsigned check in these fixtures. General arithmetic is modulo2^64, while the finite pointer extents do not wrap.

## Outcomes, status namespaces and local publication

| Fixture class | Cases | Original-source result / frontier |
| --- | --- | --- |
| Stop, G at file value0 |13 | Raw status0x5E561849; source-cleared candidate publication at0xfffffe000a522e44; execution-wrapper return0 |
| Vault, context0 |12 | Receiver record+0x38 raw0x5E55719C; wrapper return0xFFFF5953 |
| Allowed, context0 |12 | Receiver record+0x00 raw0x5E55719C; wrapper return0xFFFF5953 |
| AVD, nonzero context |12 | Acquisition/release adapters return without a primitive for G=0; raw0x5E561848; wrapper return0xFFFFFFFF |
| Vault, nonzero context |12 | Stop before0xfffffe000a57eef8 private pair load |
| Allowed, nonzero context |12 | Stop before0xfffffe000a57282c private load |
| Stop, opaque nonzero G fixture |12 | X0=declared opaque pointer; stop before0xfffffe000a543fd4 -> `_kernel_iorw_lock_write` |

The error normalization remains `u32(raw - 0x5E561849)`:0x5E55719C produces0xFFFF5953;0x5E561848 produces0xFFFFFFFF. AVD's latter result is separate from the zero-context rejection. Its native cause/meaning beyond the checked source/parameter/environment state remains unknown.

Stop's candidate is160 zero bytes from original source clearing. The original publication writes its pointer to the actual caller output reference; it is not asserted to have an initialized compact response header or native validity. Allocation/free backends remain register models. The original stop method's later status handling and stream destruction are outside this increment; the checked endpoint is its execution-wrapper return.

No new Mach port, right transfer or external message emission is established. RW pointers and encoded context values are not assigned Mach port-right semantics. Local pointer publication is not an external reply.

## Guarded private-read frontiers

| Source instruction | Unexecuted input extent | Independently reconstructed state |
| --- | --- | --- |
|0xfffffe000a57eef8 `LDP X13,X8,[SP,#0x18]` |16 bytes at SP+0x18 |First8 bytes have no source/fixture initialization; second8 bytes are source-written target0xfffffe000a56a150 |
|0xfffffe000a57282c `LDR X13,[SP,#0x58]` |8 bytes at SP+0x58 |All8 bytes lack source/fixture initialization |

Preflight stops before either instruction. Neither PC appears in executed source visits, and none of these bytes is consumed as a value. The first pair's initialized target word is independently linked to the source store at0xfffffe000a57ee04. Whether the unknown X13 value is subsequently used, overwritten, or only participates in an invariant dispatch remains unknown. A missing private provenance premise does not establish a native uninitialized-read defect. [CT10-CT12]

## Reproduction and bounded scope

From this directory:

```sh
PYTHONPATH=triage_evidence python3 -P triage_evidence/recover_lskd_continuations.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/probe_lskd_continuations.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/prove_lskd_continuations.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/validate_lskd_continuations.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/validate_lskd_continuations_preservation.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/validate_lskd_continuations_delivery.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/validate_rpc502_sidecar_delivery.py
```

Expected:355 fresh cases,343 exact preceding prefixes plus12 exact parent prefixes,20 source proof pairs UNSAT, six exhaustive banks,13 local stop publications,24 private-read boundaries,12 unexecuted RW-write calls,159 GP/SP helper returns and zero native synchronization operations. Baseline1891 artifacts are preserved with1885 unchanged and six declared report/aggregator edits. Original inputs and IDBs remain intact.

Time is O(B+C*(V+E)+I+256R), plus source mapping and solver-dependent cost (30 s/query); retained space is O(B+C*(V+E)+I). B denotes source bytes, C cases, V visits, E event extents, I lifted instruction instances and R bank rules. All byte counts and fixed-width formulas are explicit. Native lifetime, cache allocation/publication, concurrency and full daemon transport remain unknown.

## Bounded continuations

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| High | Resolve the two X13 provenance frontiers | Source reaching definitions and subsequent uses; preserve unknown-byte state until proven irrelevant or initialized |
| High | Establish creation/publication of cached cell0xfffffe000ccc78a8 | Trace aliases, source allocator return and X20 reaching definitions; compare the known allocator call0xfffffe000a531028 without conflating other cached cells |
| High | Establish native acquisition/release/free ownership | Stable object identity across fresh G loads, actual initializer/lifetime and matching runtime build; current prefixes execute no lock primitive |
| Medium | Complete stop's original method continuation | Actual later status/cleanup behavior and interpretation of its zeroed candidate |
| Medium | Extend nonzero vault/allowed and successful AVD behavior | Validated saved-state/parameter/environment premises and exact next interfaces |
| Medium | Link local operation/context records to daemon transport | Source caller chain plus matching framing, endpoint and lifetime; numeric64-bit width does not establish a Mach right |

## Quality gates

| Gate | Scoped disposition | Evidence |
| --- | --- | --- |
| QG1 | Pass | Factual technical analysis |
| QG2 | Pass | CT1-CT12 state dependencies and falsification probes |
| QG3 | Pass for this increment | Five helper contexts, records, local outputs, locking ABI and explicit frontiers; broad objective incomplete |
| QG4 | Pass | Fixed widths, byte offsets, exact counts and reproducible source verification |
| QG5 | Pass | Distinct raw statuses, source phases, file/runtime cache state, conditional clear, local/Mach publication and private/native evidence |
| QG6 | Pass | Original bytes/names/chains,355 fresh byte-audited cases,20 re-lifted proof pairs and exhaustive banks |
| QG7 | Pass | Impact-labeled continuation table |

[Element population and representation](lskd_element_population_report.md) recovers the conditional 1024-slot loop, 32 sixteen-byte rewrites and 63 distinct-word swaps per nonnull body, transformed-slot publication, completion-record phase `0x1c8ff7c8`, returning-helper raw-success handoff, cached-lock release and the separate presence gate. Twenty-two UNSAT queries cover 154 lifted instruction instances, including the complete 42-instruction SIMD body. Full pointer-codec/helper semantics, native ownership/population and a daemon reply remain unknown.
