# Shared-frame bank origins and constructor consumer compatibility

Original setup source supplies all five bank pairs used by the constructor allocation and retirement paths, plus the controller addresses, dispatch table and phase word. This increment extends the prior ten-field setup ledger to 14 fields: the additional fields are the node allocator's bank pair at frame+0x9b0/+0x9a8 and old-node retirement's pair at+0x5d0/+0x5d8. Short register projections establish the original pool decoders and exact field stores. [BK1-BK4]

The source also contains 26 exact constructor loads of these 14 offsets. The mappings establish initializer/consumer compatibility. A source path reaching each consumer in the same frame with the fields preserved remains unproved; matching offsets and values alone do not establish that reaching definition or native binding. No new Mach name, right transfer or emission is identified. [BK2,BK7,BK8]

Evidence: [original projections, fixups, field ledgers and consumer loads](triage_evidence/daemon_constructor_bank_origins_source.json), [certificate](triage_evidence/daemon_constructor_bank_origins_checks.json), [extractor](triage_evidence/recover_daemon_constructor_bank_origins.py), [validator](triage_evidence/validate_daemon_constructor_bank_origins.py), [preservation](triage_evidence/daemon_constructor_bank_origins_delivery.json), [scoped gates](triage_evidence/daemon_constructor_bank_origins_quality_gates.json). Earlier contracts: [shared setup](daemon_shared_roots_report.md), [constructor allocation](daemon_constructor_inputs_report.md), [old-record retirement](daemon_constructor_lookup_report.md), [candidate cleanup](daemon_constructor_failure_report.md). Existing reference files sufficed; no new IDA access/mutation, target execution, emulation, native API or IPC request occurred.

| Evidence | Exact scope |
| --- | --- |
| Original thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Source capture | Two spans, 1535 instructions, 6140 B; bounded source ranges, not complete semantic function coverage |
| Register projections | 14 fields, 216 projected instruction instances; four fields newly tracked relative to the prior ten-field ledger |
| Pool metadata | 13 original fixup records, freshly matched to the fixup catalog |
| Bank cancellation | Three identities, 256 inputs each: 768 byte cases |
| Accepted certificate | 28 UNSAT queries, 462 translated instruction instances, 309 SSA definitions |
| Excluded attempts | Initial uncut phase-key/store and combined ordered-footprint queries returned unknown at15000 ms; both queries are retained and neither is accepted as proof |
| Frozen setup evidence | Eight profiles; 112 field instances and112 subsequent field reads checked;12624 original daemon instruction instances recaptured |
| Constructor consumers | 26 source loads, each8 B, with exact offsets and destination registers |
| Setup store footprint | All129 stores have fixed SP-relative addresses; no call or SP write before the final branch |
| Literal census | 151 aligned literal STR Xn,[SP,#offset] candidates across14 offsets; frame equivalence of other sites is not established |
| Prior source recapture | 57 ranges, 9788 B |
| Altered controls | Ten source/projection/value/bank/reaching-definition/census/native-label/fixup/SP-invariance alterations rejected |

Addresses and offsets are hexadecimal. Extents use B. F denotes the setup frame SP; K denotes a later constructor frame SP. Equality K=F and preservation between them are not assumed proved. All pointer arithmetic in the local identities is u64 modular arithmetic. Valid nonwrapping owners, original decoded pool values and readable inputs are separate premises. [BK1-BK4]

```text
original pool words / protected record / controller reads
                         |
                         v
              14 source field producers
                         |
                         v
          straight-line setup store footprint
                         |
                 first setup branch
                         |
          ... later path / frame / write gap ...
                         |
                         v
            26 exact constructor field loads
                         |
           allocation / candidate cleanup /
                  old-record retirement
```

## Five bank pairs and exact touch points [BK1-BK4]

The following original writer and consumer PCs are established independently. Values are nominal decoded-image addresses, not observed native pointer contents at a later call.

| Field | Setup writer PC | Produced u64 value | Constructor load PC | Consumer role |
| --- | --- | --- | --- | --- |
| F+0x9b0 | 0x1004c2584 | 0x100fc4230 | 0x1006958e8 | Node allocation left bank |
| F+0x9a8 | 0x1004c349c | 0x101031fa0 | 0x100695900 | Node allocation right bank |
| F+0x968 | 0x1004c2534 | 0x100fc4130 | 0x100948bbc | Record allocation left bank |
| F+0x960 | 0x1004c2b30 | 0x101031ea0 | 0x100948bd0 | Record allocation right bank |
| F+0x5f0 | 0x1004c25cc | 0x101031da0 | 0x1008c3584 | Candidate cleanup left bank |
| F+0x5e0 | 0x1004c3480 | 0x100e99900 | 0x1008c3580 | Candidate cleanup right bank |
| F+0x870 | 0x1004c26f4 | 0x100e99700 | 0x1006c1064 | Old-buffer retirement left bank |
| F+0x868 | 0x1004c2658 | 0x100f4e190 | 0x1006c1080 | Old-buffer retirement right bank |
| F+0x5d0 | 0x1004c26b0 | 0x100e99800 | 0x100747e50 | Old-node retirement left bank |
| F+0x5d8 | 0x1004c26c8 | 0x100f4e290 | 0x100747e64 | Old-node retirement right bank |

The F+0x968 mapping independently agrees with the preceding correction of the allocator's historical0x5f0 label. These are different setup fields with different bank families. The candidate-cleanup bank inputs actually use+0x5f0/+0x5e0.

Register names are epoch-dependent. X1 supplies the left record-allocation bank at0x1004c2534 and is then overwritten by a byte load. X27 first receives the old-buffer right-bank value at0x1004c2654, but0x1004c27ac copies the node-allocation right-bank value from X30 into X27 before the later F+0x9a8 store. The backward slices select these reaching register definitions on the retained setup path; a fixed global meaning for X1 or X27 would misidentify the fields.

## Literal pool decoders and full-width identities [BK1,BK3,BK4]

Each bank-field projection reads one original pool word W and produces `W+bias` modulo2^64, including any intervening register copies. The source queries quantify over every u64 W. If the loaded word instead equals its original decoded value plus arbitrary u64 delta, the produced field equals the expected bank address plus the same delta. This is a local affine loaded-word identity; it is not a full native ASLR, loader, chained-fixup application or authentication test.

| Field | Original pool slot | Decoded pool word | Source bias/u64 |
| --- | --- | --- | --- |
| +0x9b0 | 0x1010a7a50 | 0x159a12bee | 0xffffffffa75b1642 |
| +0x9a8 | 0x1010a3ba0 | 0x106ead96a | 0xfffffffffa184636 |
| +0x968 | 0x1010a4328 | 0x156a329f7 | 0xffffffffaa591739 |
| +0x960 | 0x1010a6578 | 0x1760ab0d3 | 0xffffffff8af86dcd |
| +0x5f0 | 0x1010a44b0 | 0x110d63522 | 0xfffffffff02ce87e |
| +0x5e0 | 0x1010a4a58 | 0x101bdef67 | 0xffffffffff2ba999 |
| +0x870 | 0x1010a7ae8 | 0x1245bb76f | 0xffffffffdc8ddf91 |
| +0x868 | 0x1010a4990 | 0x13a4f6946 | 0xffffffffc6a5784a |
| +0x5d0 | 0x1010a7fa0 | 0x125fdff4a | 0xffffffffdaeb98b6 |
| +0x5d8 | 0x1010a59a8 | 0x147830c47 | 0xffffffffb971d649 |

The bank projections have no live incoming register input after def/use projection. Their explicit memory input is the relevant original decoded pool word. That does not mean the complete setup has no other reads or prerequisites. Projection membership is rebuilt from the retained original instruction path, checked against the backing bytes, and agrees across all eight setup profiles.

## Controller, table and phase producers [BK1-BK5]

| Field | Writer PC | Produced value | Selected constructor load PCs |
| --- | --- | --- | --- |
| F+0x9c8 | 0x10061a75c | 0x1010b8dc8, controller-word address | 0x1006958c0,0x10078c38c,0x1006c103c,0x100747e28 |
| F+0x9c0 | 0x10061a764 | 0x1010c4670, controller-word address | 0x1006958c8,0x10078c394,0x1006c1044,0x100747e30 |
| F+0x9d8 | 0x10061a97c | 0x101039ef0, dispatch table | 0x100695918,0x100948bec,0x10078c3e4,0x1006c109c,0x100747e78 |
| F+0x9d0 | 0x10061a980 | zero_extend64(decoded tag); frozen tag0x6cf4 | 0x1008ecc70,0x1005a37c4,0x100615a20 |

The controller producer equations admit arbitrary values at their runtime controller reads, including independent values at separate reads. Their address results follow from the concrete byte-bank identities, not the particular controller patterns in the frozen profiles.

| Producer | Left/right banks | Key/u8 | Collapsed byte | Index addend | Selected pool slot |
| --- | --- | --- | --- | --- | --- |
| Controller0 address | 0x100fc4230 /0x101031fa0 | 0xf3 | 0x43 | 0xac7 | 0x1010a71b0 |
| Controller1 address | 0x100e99700 /0x100f4e190 | 0x56 | 0x14 | 0x80 | 0x1010a1e00 |
| Dispatch table | 0x100fc4230 /0x101031fa0 | 0x6c | 0x87 | 0x893 | 0x1010a6230 |

Each identity checks all256 byte inputs. Source queries separately prove the exact left/right byte addresses, an index in0..255, the selected pool-load address and final pointer store. The pointer value, the runtime word read through that pointer and the next use of that word are distinct interfaces.

For the phase, let P be the protected-record address and T/u32 its decoded tag. The source key's low32 representation is `u32((low32(P) XOR0xeaae0ac9)*0x7398180b)`. The nominal protected word at P+8 is T XOR that key. The accepted source-prefix lemma proves the full-u64 key normalization before multiplication; a separate phase-origin query then proves the full8 B store `F+0x9d0=zero_extend64(T)` for every T/u32. Arbitrary tags are not claimed to select valid subsequent entries. The eight retained profiles use T=0x6cf4.

An initial uncut key/store query returned unknown under its15000 ms timeout. It is retained in the checks ledger as an excluded attempt, with `accepted_as_proof=false`. The accepted certificate uses the source-prefix normalization and its explicitly justified cut at0x10061a5b4; the unknown result is not counted among the28 UNSAT queries.

## Setup preservation and frozen epoch boundary [BK2,BK5-BK7]

The common setup span `0x1004c24a4..0x1004c3638` contains129 stores, all literal SP-relative STR instructions. It has no call, no SP write and no control-transfer instruction before the final BRAA at0x1004c3634. Each of the ten tracked bank fields has exactly its own initializer store in this span; none of the setup stores overlaps the four tracked controller/table/phase fields initialized in the preceding prefix.

The accepted footprint composition uses three separate facts:

1. Source translation proves every one of the129 store addresses and widths.
2. Finite relative-byte sets are disjoint for all1796 non-own-initializer store/field pairs.
3. A universal u64 theorem proves that adding the same frame base preserves equality/distinctness of relative byte addresses modulo2^64.

Consequently there is no explicit setup store to another tracked field's bytes. This is a local byte-footprint result, including modular address formation; native physical address validity still requires a valid frame owner. The earlier prefix contains aliased stores and is not covered by this129-store result. Later constructor paths are also outside it. The larger combined ordered-interval query returned unknown at15000 ms and is retained as a second excluded attempt, not accepted proof.

Eight pre-existing setup profiles supply a separate finite epoch audit. Each contains one exact8 B write for each of14 fields and no other overlapping write before the stop. All112 tracked field instances and112 subsequent field reads agree with their source-produced values. All12624 retained daemon instruction instances are compared with the original image bytes; no profile or CPU replay was newly executed. The profiles vary declared frame placement, controller values, protected-record/cursor inputs, stack-probe case and operation-gate outcome. They stop before the first setup branch, selecting0x100610388 or0x1004d4aac. They do not reach a constructor consumer within this artifact.

The frame relation in these profiles is `F=entry_SP-0x10dd0`, where0x10dd0=69072 B includes the128 B saves and68944 B local reservation. Physical nonwrapping owner validity remains a premise. The original ten-field analysis establishes this prefix geometry and its finite strict-definedness checks; the new increment extends field tracking and supplies local source equations, not a new execution run.

## Literal-store census and remaining joins [BK7,BK8]

The single-form census has these exact counts:

| SP offset | Literal STR Xn candidates |
| --- | ---: |
| +0x9b0 | 10 |
| +0x9a8 | 8 |
| +0x968 | 6 |
| +0x960 | 8 |
| +0x5f0 | 18 |
| +0x5e0 | 18 |
| +0x870 | 6 |
| +0x868 | 7 |
| +0x5d0 | 12 |
| +0x5d8 | 15 |
| +0x9c0 | 10 |
| +0x9c8 | 8 |
| +0x9d0 | 13 |
| +0x9d8 | 12 |

The total is151 candidates in the original aligned `__text`. Pair stores, other widths/forms, aliased/computed bases and SP movement are outside this inventory. The named initializer is present in each field's candidate list; the other candidates are not assigned its frame or semantic role. The census therefore cannot prove native or later all-path preservation.

The constructor consumer query proves every recorded load reads exactly K+the mapped offset, with an8 B width and the recorded destination register. It does not assume K=F, remove possible intermediate writes, or turn a source initializer into an observed native call. These distinctions retain the remaining data/control-flow obligations instead of promoting field compatibility to full reaching-definition proof.

The controller pointer produced here is0x1010b8dc8. Earlier standalone auxiliary contexts used0x1010b66a8 as a declared fixture. They are not asserted equal or native aliases. Local bank cancellation admits arbitrary controller-byte inputs, but that does not identify the source of native global contents or prove synchronization.

The source decoders, setup stores and constructor loads introduce no new Mach name/right, receive/send emission or IOKit transaction. Native FairPlayIOKit selector26/RPC502/700 endpoint pairing remains unresolved.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BK1 | Pinned thin image/fixups and original bank arrays; nominal pool-word values | Rehash/recapture original bytes,13 fixups and768 bank cases; different loaded data invalidates nominal pointer results |
| BK2 | The recorded source projection order and setup frame epoch describe the selected path; local producer/footprint meaning | Rebuild def/use slices across all eight profiles; source path and frame identity beyond the stop remain unproved |
| BK3 | Loaded decoded pool words apply to the local source expressions; bank decoder results | Check each exact slot/bias; additive-word identities are not full native loader/ASLR/PAC validation |
| BK4 | Valid readable protected record, image/pool and nonaliasing frame owners; actual load/store effects | Establish concrete ownership/extents and source aliasing; modular equations do not validate native addresses |
| BK5 | Source-prefix normalization and concrete byte-collapse identities justify the explicit cuts/relations | Check phase cut0x10061a5b4, bank byte addresses/keys and accepted28 queries; neither unknown formulation is proof |
| BK6 | Frozen profiles retain the named private environments;112-field/read finite audit | Recount writes/reads and compare each daemon opcode; no current native execution is inferred |
| BK7 | Census and129-store footprint are bounded to their stated forms/interval; no global writer claim | Extend alias/pair/width/frame coverage separately; preserve the first-branch boundary and exclude later paths |
| BK8 | Constructor frame equality, intermediate preservation, native roots/phase and transport remain unproved | Require a same-frame path to each consumer and independent native caller/receiver/right evidence before promoting compatibility |

## Bounded continuation

| Impact | Remaining evidence target |
| --- | --- |
| High | Same-frame reaching definitions from setup successors to each constructor/retirement consumer, including every intervening field write |
| High | Native loaded pool/bank values, phase production, frame/heap ownership and authentication before native call-effect claims |
| High | FairPlayIOKit selector26/RPC502/700 caller/receiver pairing and concrete Mach rights/emission identity |
| Medium | Earlier aliased prefix stores and later frame reuse; the local setup footprint does not cover either interval |
| Medium | Other initialization fields among129 stores, with independent source-to-global/interface semantics rather than offset/name inference |
| Low | Broader literal-store inventory covering pairs, aliases and widths, with frame equivalence established before semantic labels |

Extraction costs O(profiles * fields * prefix visits + source bytes + text words + fixup catalog). The14-field register projection and frozen ledgers are linear in their bounded inputs. The census is one aligned-text pass. Finite byte-footprint checking uses1796 store/field pairs; translation is O(selected instruction instances). Solver complexity is separate, with15000 ms per query. Pointer fields are8 B, the phase representation zero-extends u32 to u64, and all local pointer identities are modular u64 operations.

## Scoped quality gates

QG1: No normative conclusion is required; the increment concerns technical source/evidence contracts.

QG2: BK1-BK8 enumerate assumptions, dependencies and falsification probes.

QG3: Fourteen setup producers, ten affine bank decoders, controller/table/tag production, frozen field epochs,26 consumer loads and bounded store footprints are covered. Later reaching definitions and the broad native interface objective remain incomplete.

QG4: Widths, B extents, modular arithmetic, additive delta scope, byte-set composition, solver limits and complexity are explicit and reproducible.

QG5: Prior ten-field versus new14-field tracking, source projections versus execution, two excluded unknown queries, SP interval versus whole-prefix/later preservation, controller fixtures and constructor-frame compatibility are reconciled.

QG6: Original bytes/fixups, exact projections/consumer loads,768 bank cases,112 frozen field/read checks,12624 opcode instances,28 accepted queries and ten altered controls provide scoped primary provenance. Memory supplies build/evidence-boundary guidance only.

QG7: Bounded high/medium/low continuations retain native loader/owner/phase/authentication, same-frame path and daemon-kext endpoint obligations. No full-goal completion or new native port identity is claimed.
