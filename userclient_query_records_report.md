# Second-command query records and constructor ABI

The command selected by decoded scalar `0x73eba01e` calls the recovered version adapter and capability leaf using one workspace record, then prepares three conditional scalar-record construction requests. Their control words normalize by XOR with `0x31ae0066` to `0x4c0b0000`, `0x1f8` and `0x99ab`. The first two values match the pinned getter metadata; the meaning of0x99ab remains unknown. The selected constructor requests a32 B FPTTLVNode and14 B data storage, initializes links/extent and reaches a protected writer. Complete metadata-record serialization, node-list publication and native daemon pairing remain unknown. The linked [emission report](userclient_serializer_emission_report.md) establishes conditional auxiliary-result production for an admitted stable list.

## Evidence and claim register

The [extractor](triage_evidence/recover_userclient_query_records.py), [instruction audit](triage_evidence/audit_userclient_query_records.py) and [delivery verifier](triage_evidence/verify_userclient_query_records_delivery.py) accompany [checks](triage_evidence/userclient_query_records_checks.json.zst) and [proofs](triage_evidence/userclient_query_records_audit.json.zst). Primary evidence is the original kernel collection and normalized kext. Predecessor contracts cover [command selection](userclient_command_dispatch_report.md), [getter values](kext_query_getter_values_report.md), [core copy-back/return](userclient_caller_return_report.md) and [provider transfer/status ordering](userclient_transfer_boundary_report.md).

| Claim | Established result | Dependencies |
| --- | --- | --- |
| QR1 | The second command uses the same workspace record for version/capability calls; capability overwrites the preceding version result word | QR-A1-QR-A5 |
| QR2 | Three requests use distinct tag/scalar control words and saved continuations; first/second success advance, third success reaches the next facility | QR-A1-QR-A6 |
| QR3 | Each admitted request installs the same constructor packet layout and derives a four-byte extent | QR-A1-QR-A6 |
| QR4 | The selected first constructor requests the original32 B FPTTLVNode descriptor, zeroes links, sets extent14 B and requests14 B data storage | QR-A1-QR-A5 |
| QR5 | Allocation results select exact failure/writer frontiers; nonnull data reaches the original protected writer input ABI | QR-A1-QR-A6 |
| QR6 | The third successful continuation passes aliases for the original parsed container and independent auxiliary pointer/extent to a subsequent facility | QR-A1-QR-A7 |
| QR7 | 539 selected instruction locations,31 nonvacuous source queries, five predecessor rechecks and1,280 bank cases support the bounded contracts | QR-A1-QR-A7 |

Normalized image SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The25 selected spans and21 separately captured transfers match both images. Three complete helper ranges,151 instruction words, are recaptured against predecessor bytes. Two straight-line retention ranges contribute583 structural instruction instances; they overlap and are not583 additional distinct instruction locations.

Decoded checks SHA-256: `4dd0123133fd94fa9b2466ad69bc6d2411bacdf2491301581465d209f2a9b6b0`. Decoded audit SHA-256: `08ccbb05495f7618f5e91ca22703bcf043733d60980113b2578cbc66798a35e2`. The audit records3,859 proof instruction instances and an altered-literal SAT counterexample. No target execution, IDB mutation or new live IDA observation supplies these results.

## Workspace record, helper calls and result overwrite

F denotes the selected frame SP, C the outer context, S the workspace, H the parsed container, J a newly requested node and B its data allocation. `SUCCESS=0x31ae0066`, `TOKEN=0x886a1ca3`, `PHASE=0x7795e642`. The existing admitted command phase supplies W19=PHASE and W24=PHASE-0x274; fresh reconstruction of the predecessor instruction model checks both values.

Original `0xfffffe000a6355c4` sets X16=S+0x968; `0xfffffe000a635b50` saves that root at F+0x998. Between those sites,354 straight-line words contain no branch or explicit X16/W16 write. Thus Q=S+0x968 is the selected private query record. Its first word is an address-dependent prepared value; its result word is Q+4. Neither is identified as a wire opcode.

| Call PC | Original slot / target | Arguments and selected result effect |
| --- | --- | --- |
| `0xfffffe000a63ae2c` | `0xfffffe000847aaf8` -> `0xfffffe000a66a5a8`, IA diversity0x5c97 | X0=Q; version adapter writes u32[Q+4]=0x4c0b0000 at `0xfffffe000a66a7b0` |
| `0xfffffe000a63aee0` | `0xfffffe000847aa48` -> `0xfffffe000a5c22a8`, IA diversity0x7787 | X0=the same Q; leaf writes u32[Q+4]=0x1f8 at `0xfffffe000a5c22b0` |

The captured caller does not load Q+4 between the calls or when setting up the first construction request. The second result therefore replaces the first result in that record. The subsequent request uses literal control words, independently of either returned X0. This does not make the version adapter redundant or side-effect-free: its previously recovered controller writes remain part of its contract.

The prepared header words exactly match the named getter request forms, modulo2^32:

```text
version Q+0 = 0x440e0fe1 * (low32(Q) XOR 0x841cb645) - 0x007f03ff
capability Q+0 = 0x3d7a7ab1 - 0x84d77373 * (low32(Q) XOR 0x6133a0c8)
```

The version adapter's nested status leaf is `0xfffffe000a5aec10`. Fresh predecessor-query replay checks its store/return contract, the adapter's original bank/address/call ABI and postcall version store, and the capability leaf's exact store/return. Native canary/PAC success and ordinary continuation remain premises.

## Three request records and status-driven continuation

The first setup begins at `0xfffffe000a63aee4`, the second at `0xfffffe000a656fd8`, and the third at `0xfffffe000a657070`. All select shared entry `0xfffffe000a6613fc`. The first saves H from C+0x600 to C+0x3a8; later requests reload that saved container channel.

| Request | Tag control32 | Scalar control32 | Scalar XOR SUCCESS | Callback index / target |
| --- | --- | --- | --- | --- |
| First | 0x33b7bc52 | 0x7da50066 | 0x4c0b0000 | 0x45 / `0xfffffe000a656f8c` |
| Second | 0xb0ac8a39 | 0x31ae019e | 0x000001f8 | 0x42 / `0xfffffe000a657018` |
| Third | 0xa024e3ab | 0x31ae99cd | 0x000099ab | 0x68 / `0xfffffe000a65f358` |

These are private request control words. This increment does not equate the tag controls, type control or scalar normalization with final serialized wire fields. The first two normalized scalar values match the source-proved getters. No native hardware query or meaning for capability bits or0x99ab is inferred.

| Packet channel | Stored value / role |
| --- | --- |
| C+0x5a8 | Per-request callback from the table above |
| C+0x260 | Shared constructor return `0xfffffe000a664230` |
| C+0x20 | H, the selected container input |
| C+0x168 | Zero at request preparation |
| S+0x1d0 | Per-request tag control32 |
| S+0x1b2 | Type control16=0x3594 |
| S+0x94 | Extent control32=SUCCESS-4=0x31ae0062 |
| S+0x110 | Per-request scalar control32 |
| S+0xad0 | Pointer/control64=0x8f98c6acce5848ca |

The shared entry saves its callback, selects the nonnull-container path and defaults raw status to0xce515bbf. The selected constructor derives gate value4 and takes `0xfffffe000a66159c`. Successful construction/publication is not assumed from that branch alone.

## Allocation, initialization and writer boundary

| Source call / result | Exact established ABI |
| --- | --- |
| `0xfffffe000a661664` | `_IOMallocTypeImpl` at `0xfffffe000c4ba154`; X0=descriptor `0xfffffe000847b4a0`; IA diversity0xd0c8 |
| `0xfffffe000a661670` | Saves returned J at C+0x58; null selects `0xfffffe000a66169c`, nonnull selects `0xfffffe000a6616d4` |
| `0xfffffe000a6616ec` | Nonnull J: zero next64 and previous64 |
| `0xfffffe000a6617f8` | Writes node extent32=14 B at J+0x10 |
| `0xfffffe000a661848` | `_IOMallocData` / `_IOMallocData_external` at `0xfffffe000c4ba60c`; X0=14 B; IA diversity0xca0c |
| `0xfffffe000a66184c` | Saves data result B at J+0x18; null selects `0xfffffe000a664074`, nonnull selects `0xfffffe000a661880` |

The original typed descriptor is named `site.FPTTLVNode`, flags0x64, declared size32 B. Its original name pointer, normalized/original64-byte records and scalar metadata are retained. A matching name/size in another allocation or retirement descriptor does not establish native site interchangeability or ownership.

| Bank selection | Key / additive / bias | Original slot / selected target |
| --- | --- | --- |
| Version adapter | 0x37 /0xf41 /0 | `0xfffffe000847aaf8` / `0xfffffe000a66a5a8` |
| Capability leaf | 0x93 /0xe79 /0 | `0xfffffe000847aa48` / `0xfffffe000a5c22a8` |
| Typed allocation | 0x93 /0xe27 /0 | `0xfffffe000847a7b8` / `0xfffffe000c4ba154` |
| Node descriptor | 0x32 /-0x98 /-8 | `0xfffffe0008472208` / `0xfffffe000847b4a0` |
| Data allocation | 0x3e /0xebc /0 | `0xfffffe000847a7a0` / `0xfffffe000c4ba60c` |

The null-node route reloads C+0x58=0 and the saved raw-status channel F+0x9ec before reaching the same existing failure frontier `0xfffffe000a664074`. The audit stops there: emitted cleanup calls and actual resource effects beyond that frontier are not inferred. After data allocation, that saved raw status is reloaded for either data-result branch.

For nonnull J/B, the writer entry selects table index0x543 -> `0xfffffe000a654ad4`. It passes X16=&J+0x18, X3=S, X11=C, W1=SUCCESS, X0=`0x02e859d27e491464`, W14=PHASE. The key matches the previously recovered protected staging/copy-back key, but this register equality is not a proof of the complete writer's output. Header/payload byte values, link publication, ordering into H and mutation of the original staging bytes remain open.

The31 source obligations specialize the constructor packet for all three requests. Allocation/initialization/writer-entry composition is proved for the first request. The other two use the same constructor-entry packet shape, but their complete downstream allocation/writer paths are not re-proved here.

## Callback and auxiliary-output interface

The shared return block at `0xfffffe000a664230` restores selected phase tokens, reloads C+0x5a8 and retains arbitrary raw status in W23. Composition below requires that this block is reached with the stated C/S/frame/table/phase roots; full internal construction-to-return reachability is not claimed.

| Callback | Expected raw status | Success target | Failure target |
| --- | --- | --- | --- |
| `0xfffffe000a656f8c` | SUCCESS | `0xfffffe000a656fd4`, second request; W22=0x42 | `0xfffffe000a65f358` |
| `0xfffffe000a657018` | SUCCESS | `0xfffffe000a65706c`, third request; W22=0x68 | `0xfffffe000a65f358` |
| `0xfffffe000a65f358` | SUCCESS | `0xfffffe000a65f3b4`, post-request preparation | `0xfffffe000a656f00`, common cleanup |

The second callback's mask depends on F+0x53c. Original TOKEN-producing instructions `0xfffffe000a6355f4`..`0xfffffe000a6355fc` and the subsequent store at `0xfffffe000a63599c` establish F+0x53c=0x5cd5096e; mask0xa32af6f9 gives0x68. The intervening229 words are straight-line and do not explicitly write X15/W15. This proves the second callback compares the same SUCCESS constant, instead of assuming a suitable mask input.

The third callback block was already present in the parser-failure analysis. There, the incoming non-success premise excluded its success edge. This request sequence can supply a distinct success premise, selecting `0xfffffe000a65f3b4`; the earlier conditional result is unchanged.

Post-request preparation passes X11=C+0x600, X12=C+0x3c0 and X21=S+0xbe4, then selects `0xfffffe000a65f3ec`. These are the original container cell and the independent auxiliary pointer/encoded-extent cells consumed by [caller cleanup](userclient_caller_return_report.md). This connects their interface locations to the query-command continuation. It does not establish the subsequent producer, allocation extent or auxiliary bytes.

An isolated null-container entry selects the shared return with raw0xce515bbf. A separately checked empty block reloads its saved constructor-return pointer. Neither is asserted reachable from the admitted successful command-field lookup, which supplies a nonnull parsed H. These direct block contracts preserve evidence for other possible incoming phases.

No additional Mach endpoint, right or emission site is established. The transfers here are private authenticated table calls/branches; their indices are not IOUserClient selectors or Mach message IDs. External port/interface contracts remain in [Mach ports](mach_ports_report.md) and [interface ABI](interface_abi_report.md).

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| QR-A1: Pinned dual images, original pointers/descriptors, helper captures and predecessor receipts | QR1-QR7 | Fresh source/descriptor/pointer checks, five prior formulas, phase reconstruction and original byte-bank verification |
| QR-A2: Stable original banks/table epochs and ordinary authenticated branch interpretation | QR1-QR7 | Exhaust all1,280 byte inputs; check pointer targets, biases and IA diversities; native PAC/table mutation remains separate |
| QR-A3: AArch64 u16/u32/u64 arithmetic and modeled load/store/shift semantics | QR1-QR7 | Arbitrary record addresses/controller snapshots/statuses, exact prepared-word identities, extent4 and14 B store/request proofs |
| QR-A4: Selected C/S/F roots, readable/writable separate context4096 B, workspace16384 B, frame, H16 B and admitted J32 B/B14 B storage | QR1-QR7 | Original root stores,583 structural retention instances, exact allocation-result aliases and each memory-address obligation; native allocation success/identity is not inferred |
| QR-A5: Helper/allocator calls return normally, preserve callee-saved registers/private roots and do not mutate unrelated packet/result/guard cells | QR1, QR3-QR7 | Volatile-register havoc, prior helper store/call proofs, null/non-null results and literal metadata independent of returned X0; actual callee memory effects and canaries remain unknown |
| QR-A6: Shared-return block receives the declared phase/table/context roots and raw status; H remains in C+0x3a8 between request cuts | QR2-QR7 | All three packets, continuation/status splits and null/empty isolated block checks; recover actual publication, all incoming paths and synchronization before claiming whole-path completion |
| QR-A7: Scalar normalization/tag controls, native command meaning, complete writer/auxiliary production and daemon transaction identity remain distinct | QR6, QR7 limits | Recover emitted header/payload bytes, list insertion and the facility at0xfffffe000a65f3ec; establish actual transfer counts, endpoint/selector context and0x99ab semantics independently |

## Bounded continuation and cost

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Protected writer at `0xfffffe000a654ad4` and subsequent list publication | Convert private metadata controls into exact serialized fields and actual container mutations |
| High | Facility selected at `0xfffffe000a65f3ec` | Recover production of the auxiliary pointer/extent later retired by cleanup |
| High | Complete construction-to-callback paths and all three requests | Establish whether the conditional success sequence is realizable under its own complete source effects |
| High | Native daemon request/response bytes, transfer counts and provider/task identity | Correlate this static command path with one actual cross-layer transaction |
| Medium | Meaning and consumers of0x99ab and tag/type controls | Determine metadata semantics without naming fields from numerical resemblance |
| Medium | Native allocator/site identity, PAC, aliasing and locking | Resolve environmental and ownership premises behind the selected calls |

The captured command/request control work is bounded O(1) local work and O(1) private state, excluding helpers, construction/publication and later serialization. The selected allocation requests are32 B and14 B;14=10+4 B. Extraction takes O(B+I+256R) time/space for consumed image bytes B, instructions I and bank rules R. Proof construction takes O(instruction instances+query DAG); SMT search is separate with30 s/query limits. Control/status/scalar words are u32, the type channel is u16, and pointers/address-dependent roots are u64. The SAT control changes the first literal scalar in analysis bytes and refutes the expected value; no target image is patched.

## Quality gates

- **QG1**: Claims are factual source/control/data/ABI analysis.
- **QG2**: QR-A1-QR-A7 identify dependent claims and falsification probes.
- **QG3**: This increment covers query/helper custody, three request packets, callback/status gates, first constructor allocation/initialization and auxiliary-output aliases; full command and interface goals remain active.
- **QG4**: u16/u32/u64 widths, prepared-word formulas, scalar XOR mappings,32/14 B requests, structural overlap and complexity are explicit.
- **QG5**: Helper result/control side effects, private controls/wire fields, packet setup/publication, isolated blocks/admitted paths, allocation requests/native lifetimes and alias handoff/producer remain distinct.
- **QG6**: Dual-image capture, original pointers/descriptors,539 selected locations,31 nonvacuous source formulas, five prior rechecks,1,280 bank cases and the SAT control support the stated boundaries.
- **QG7**: Ranked continuation preserves writer/list publication, auxiliary producer, complete callback reachability, native transfer correlation, unknown metadata meaning and environmental context.


The [serializer extent contract](userclient_serializer_extent_report.md) now establishes checked node-extent accumulation, strict 16 B padded sizing, the original allocator ABI and encoded extent custody. Under the stated successful-publication cut, the original consumer admits copying only when the request length equals that padded allocation extent. Node/padding emission, container stability across passes and native transaction pairing remain unknown; no additional Mach port endpoint is established.


The [serializer emission contract](userclient_serializer_emission_report.md) now closes conditional finite stable-list emission: decoded node-byte concatenation, terminal tag0/type50db/big-endian padding length, exact zero payload, and output pointer/extent publication with flag1/raw SUCCESS. The terminal shape normalizes to the recovered parser type0x6685. Original metadata-node construction, native list/storage validity and daemon transaction pairing remain unknown; no additional Mach endpoint is established.


The [query writer contract](userclient_query_writer_report.md) now establishes the three conditional14 B records: exact big-endian tags, raw type97 77 (parser-normalized0xa129), length4 and big-endian scalars0x4c0b0000/0x1f8/0x99ab. Each writer reaches the shared list lookup with W8 callback index0x6c (separate W0 control0x19) and retained pending-node/constructor-return state. This resolves the earlier query-byte frontier; actual query list publication/order, resulting serializer extent and native daemon pairing remain unknown. No additional Mach endpoint is established.
