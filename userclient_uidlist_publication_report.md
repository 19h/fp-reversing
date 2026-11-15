# UIDList discriminator search, tunnel marker and context-head publication

`_PRnut72j9` conditionally allocates a 16 B `site.UIDList` node, fills its u32 discriminator, u32 tunnel marker and u64 successor, then publishes it through the original context head. This distinguishes node+0, used by the producer's list search, from node+4, used by teardown's table-key codec. The marker comes from candidate tunnel+0x6c through source+0xd8c. Combined with the preceding insertion report, this establishes a conditional marker/key correspondence across insertion, per-context tracking and cleanup. Native object identity, complete dispatcher reachability, complete existing-match resource handling, ownership and serialization remain unknown.

## Provenance and verification

| Evidence | Identity / scope |
| --- | --- |
| Normalized kext | SHA256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original collection | SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Original function container | `_PRnut72j9`, `0xfffffe000a635208`..`0xfffffe000a666930`; 50,634 instruction words; SHA256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` |
| [Extractor](triage_evidence/recover_userclient_uidlist_publication.py) / [checks](triage_evidence/userclient_uidlist_publication_checks.json.zst) | Decoded checks SHA256 `d9e9a2ce995fa6b3703f3eecbc63f6e22328dfd2f1e9601679b9df760dfb5b53`; 17 spans, 232 selected instructions and 12 terminal transfers |
| [Auditor](triage_evidence/audit_userclient_uidlist_publication.py) / [receipt](triage_evidence/userclient_uidlist_publication_audit.json.zst) | Decoded audit SHA256 `b66d2254114e0a7d984faa024007b8193845489d9b83fa9cdcbb78661682db04`; 17 nonvacuous source obligations, six predecessor obligations, 574 instruction instances and 512 finite bank cases |
| [Publication verifier](triage_evidence/verify_userclient_uidlist_publication_delivery.py) | Fresh original extraction/audit reconstruction, canonical SMT comparison, query reruns, exact manifest delta, original-input custody and decoded path scrub |

All 232 selected instruction locations are covered by the source proofs. The spans contain 232*4=928 B; the separately captured transfers add 12*4=48 B. The full compiler envelope is checked for byte custody, not complete semantics. The failed read-only IDA instance/target queries supplied no additional evidence; the original files remain authoritative. No target runs and no IDB is changed.

## Architectural values and exact field map

Let C=X2 be the current scratch base, S=X4 the current source base, P the candidate tunnel, Q the original third argument retained in the correct SP+0x738 frame cell, J a current old node, B a nonzero newly allocated node, K=load_u32(S+0xc90) and M=load_u32(P+0x6c). Register roles and saved slots are phase dependent.

| Claim | Original location | Recovered contract |
| --- | --- | --- |
| UP1 | `0xfffffe000a63524c`; `0xfffffe000a65ed54`..`0xfffffe000a65ed60` | Save incoming X2 at SP+0x738; later copy that Q to C+0x118 and load Q+0 into C+0x410 |
| UP2 | `0xfffffe000a65e4a0`..`0xfffffe000a65e4a4`; `0xfffffe000a65ecf0`; `0xfffffe000a65ed4c`..`0xfffffe000a65ed50` | C+0x218 -> C+0x4c8 -> P; load u32 P+0x6c into W24 and source+0xd8c |
| UP3 | `0xfffffe000a65ed94`; `0xfffffe000a65edc4`..`0xfffffe000a65edc8`; `0xfffffe000a65ee08` | Load K; compare node+0 against K; on inequality advance through u64 node+8 |
| UP4 | `0xfffffe000a65ee70`..`0xfffffe000a65ee88` | Capture matching J at C+0x410, J+4 at C+0x2c8 and old marker32 at S+0xc84; clear separate C+0x7a8/S+0xb68 fields |
| UP5 | `0xfffffe000a65e800` | Call typed allocator with X0=`0xfffffe000847b8a0`, target `0xfffffe000c4ba154`, IA modifier0xd0c8 |
| UP6 | `0xfffffe000a65e834`..`0xfffffe000a65e858` | Null allocation selects failure continuation; nonnull allocation selects node fill |
| UP7 | `0xfffffe000a65e870`..`0xfffffe000a65e880` | Store K/M at B+0/+4, reload current head H=load_u64(Q), store H at B+8, then B at Q+0 |
| UP8 | Producer field/key proofs plus [insertion](secure_tunnel_table_insertion_report.md) and [cleanup](userclient_uidlist_cleanup_report.md) | Under stable marker/object epochs, node+4=M supplies the same XOR-derived table key used during insertion; complete native lifecycle remains unproved |

[The context/task report](context_descriptor_task_flow_report.md) establishes that selector26's provider passes `(staging pointer, extent, context)` into this core, and documents the SP-epoch/interference limits of the saved context cell. [The context lifecycle report](userclient_context_lifecycle_report.md) establishes the conditional 24 B `site.IOUCCtx` layout. This increment recaptures the entry context store and subsequent head alias; it does not remove those frame/lifetime premises.

| Object / offset | Width | Producer use | Cleanup use |
| --- | --- | --- | --- |
| Q+0 | u64 pointer | Context head; reloaded before prepend | Initial traversal head |
| Node+0 | u32 | Discriminator K; compared during list search | Not read by the selected cleanup arm |
| Node+4 | u32 | Candidate tunnel marker M | Raw branch marker; unequal-marker path derives table key |
| Node+8 | u64 pointer | Previous head / traversal successor | Saved before typed node-free request |
| P+0x6c | u32 | Marker source | Distinct from the node pointer and context head |

Neither the `UID` type substring nor either u32 field establishes a user identifier, PID, Mach-port name, entitlement or application identity. The 32 B `site.FPTTLVNode` records with separate buffers near the preceding insertion are a different type; they do not supply this 16 B node's layout.

## Conditional search and marker-update gates

The recovered candidate-gate phase uses incoming W9=0xb33, W3=0x886a1ca3 and W1=0x7795e642. It derives W10=0x90d and W19=0x886a1ca3. Subsequent comparisons are exact u32 equality; successor/head checks are exact u64 zero checks.

| Predicate / stage | Table index | Original target |
| --- | --- | --- |
| Candidate pointer zero | 0xb33 | `0xfffffe000a65ef14`, failure continuation |
| Candidate pointer nonzero | 0xba0 | `0xfffffe000a65ed24`, marker/context-head load |
| Context head zero | 0x90e | `0xfffffe000a65e760`, allocate preparation |
| Context head nonzero | 0x90d | `0xfffffe000a65ed88`, load discriminator then compare |
| node+0 equals K | 0x784 | `0xfffffe000a65ee64`, matching-node capture |
| node+0 differs from K | 0x7a0 | `0xfffffe000a65edf0`, load successor |
| Successor nonzero | 0xcc0 | `0xfffffe000a65edac`, compare next node without reloading K |
| Successor zero | 0xd6c | `0xfffffe000a65ee30`, clear match cell then allocate |
| Matching old marker equals 0x31ae0066 | 0xbc9 | `0xfffffe000a65e6cc`, status gate |
| Matching old marker differs | 0xbc1 | `0xfffffe000a65eee4`, further resource path outside this increment |
| Status at status gate equals 0x31ae0066 | 0xc0e | `0xfffffe000a65e710`, marker update |
| Other status | 0xf4 | `0xfffffe000a65ef14`, failure continuation |
| Update's C+0x410 is nonzero | 0x746 | `0xfffffe000a65e890`, continuation |
| Update's C+0x410 is zero | 0xacd | `0xfffffe000a65e760`, allocate preparation |

The matching-node capture sets W23=0xce515bbf. It does not itself establish the success status required by the later update gate. Therefore a match alone is insufficient to claim that the old marker is replaced. The intervening resource/status paths remain unknown.

When the marker-update block is entered under its verified phase, `0xfffffe000a65e734` stores the retained M through the pointer at C+0x2c8. The preceding matching-node capture establishes that pointer as J+4 under preserved scratch identity. This is a conditional update-channel join, not proof that every matching-node path reaches the update.

A compact description of the selected search/new-node path is:

```text
P = load_u64(C+0x4c8)
if P == 0: goto failure_continuation
M = load_u32(P+0x6c)
Q = load_u64(correct_saved_context_cell)
K = load_u32(S+0xc90)
J = load_u64(Q)
while J != 0:
    if load_u32(J) == K: goto matching_node_resource_path
    J = load_u64(J+8)
B = typed_allocation_request(UIDList_descriptor)
if B == 0: goto failure_continuation
store_u32(B+0, K)
store_u32(B+4, M)
H = load_u64(Q)                 # current head after allocation return
store_u64(B+8, H)
store_u64(Q, B)
goto continuation
```

This pseudocode assumes the selected blocks, stable phase/register roots, valid nodes and ordinary calls. It is not native execution. For n valid nodes in a finite, stable, acyclic list, discriminator search is O(n) time and O(1) traversal state; prepend is O(1). A cycle invalidates the finite-search premise. No lock, atomic head exchange or concurrent linearization is established.

## Allocator, descriptor and exact publication

Both allocation selectors satisfy `x XOR right[left[x] XOR key] = constant` for every byte x. The source-address obligations check each application at its original literal addresses.

| Purpose | Left / right arrays | Key / constant | Index / original slot | Target |
| --- | --- | --- | --- | --- |
| Allocator | `0xfffffe0007949dd0` / `0xfffffe000792fbc0` | 0x3e / 0x54 | 0xf13 / `0xfffffe000847a7b8` | `0xfffffe000c4ba154`, `_IOMallocTypeImpl` |
| Descriptor | `0xfffffe0007941f60` / `0xfffffe000794a0d0` | 0x05 / 0x2d | 0x13 / `0xfffffe0008471f98` | Original pointer minus12 = `0xfffffe000847b8a0` |

The adapter is byte-identical to the adapter already captured in [the allocation report](secure_tunnel_allocation_report.md). Its authenticated slot diversity matches0xd0c8; native authentication remains unexecuted. The allocation descriptor and cleanup descriptor at `0xfffffe000847b2a0` are distinct addresses with identical original and normalized 64 B contents: name `site.UIDList`, signature text `21`, metadata flags32=0x64 and size32=16. Name/signature pointers and raw fields are verified against the original collection/fixups. Signature text is retained without assigning undocumented meaning.

| Allocation result | Index / target | Selected effect |
| --- | --- | --- |
| Zero | 0x51f / `0xfffffe000a65ef14` | Bypass selected node-fill block |
| Nonzero | 0x521 / `0xfffffe000a65e85c` | Fill all 16 B and publish through Q |
| Ordinary completion of node fill | 0x746 / `0xfffffe000a65e890` | Further continuation outside the selected publication |

The ordinary-return cut makes X0-X18 arbitrary and then installs the arbitrary allocator result in X0; X19-X29, SP and saved cells persist under the ABI premise. The source preserves W24 through prepare/return. All 16 node bytes are checked little-endian; four stores account for two u32 node fields, one u64 successor and one u64 context-head update. The new node is required to be valid, nonzero and disjoint for the fill proposition. The null-result branch is proved without assuming allocated storage exists.

```text
insertion marker M -> P+0x6c
                         |
                 C+0x218 -> C+0x4c8 -> P
                                           |
                                  M -> S+0xd8c -> W24
                                                       |
context Q -> current head H                   new B+4 <-+
                  |                                B+0 <- K
                  +------------------------------> B+8
                                                   |
                              after node fill: Q <- B
                                                   |
                                cleanup reads B+4/B+8
```

## Insertion/cleanup correspondence and unresolved source semantics

The preceding [insertion report](secure_tunnel_table_insertion_report.md) proves the raw source marker write at tunnel+0x6c after the occupied-entry writer. Under UP-A2/UP-A4, the newly established UIDList transfer carries that marker to node+4. Cleanup's existing codec gives:

```text
U32 = node_marker32 XOR 0x31ae0066
entry_key64 = 0x1ee45f68039f9913 + zero_extend_64(U32)  (mod 2^64)
```

Consequently the insertion and cleanup keys agree when the candidate tunnel retains the inserted marker and the same object/context epoch is used. This is an equality of recovered fields and codecs; it does not establish native allocation identity or balanced retirement.

The marker default store at `0xfffffe000a63dd40` writes raw0x31ae0066. If such a marker reaches a cleanup node, the preceding cleanup report's fast arm skips the unequal-marker table-processing route. Whether actual new-tunnel marker inputs exclude this value remains unknown; the local all-u32 equations do not establish a native resource imbalance.

K has separate producers: `0xfffffe000a6571f0` stores default0x1505, while `0xfffffe000a6572a0` stores low32(X10) from a derived path. The nearby source contains a 33-times accumulator, but its complete input lineage, recurrence/domain and reduction are not established here. Assigning a string-hash algorithm or business identity remains premature.

No selected call emits a newly identified Mach message or endpoint. The context pointer, node pointers, discriminator and tunnel marker remain separate from Mach names and rights. Existing sites remain in [the Mach-port report](mach_ports_report.md) and [interface ABI report](interface_abi_report.md). Successful fairplayd-kext transaction correlation remains unknown.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| UP-A1: Pinned collection/image, original function envelope, descriptors and fixups | UP1-UP8 provenance | Fresh extraction, original/normalized equality, decoded hashes and fresh source comparison |
| UP-A2: Correct saved SP epoch, stable C/S/Q roots and candidate alias across selected visits | Context/tunnel/node composition | Recapture entry store, candidate alias and context-head transfer; resolve the previously documented SP deltas and intervening interference before asserting native identity |
| UP-A3: Stated dispatcher tokens and ordinary authenticated transfers | Search/gate/allocator binding | Exact branch-slot address checks, all-status/all-pointer/u32 discriminator obligations and 512 finite bank checks; native reachability/PAC unknown |
| UP-A4: Valid, nonwrapping, disjoint source4096 B, scratch2048 B, context24 B, old node16 B, payload120 B and frame4224 B; valid new16 B only for fill | Loads, complete node stores and head publication | Nonvacuous ownership premises, alignment predicates, arbitrary nullable allocator result and explicit ordinary-return cut |
| UP-A5: Stable finite acyclic chain and unchanged discriminator during search | Complete search bound | One-step equality/successor proof; trace actual head writers and locking. A cycle, invalid next pointer or concurrent mutation falsifies full-search composition |
| UP-A6: Saved marker/cells and callee-saved registers survive allocator/resource calls | Marker retention and later update channel | Caller-save GP registers made arbitrary at allocator return; verify W24 persistence and actual resource-path return statuses |
| UP-A7: Earlier source contracts apply in the same marker/context epoch | Insertion/cleanup key agreement and typed node retirement | Six predecessor queries rerun; recover marker-origin domain, actual provider/context identity and complete lifetime before claiming native balance |
| UP-A8: Discriminator/marker/type names alone supply no business or Mach identity | Naming and external-control interpretation | Close source+0xc90 and original insertion-marker producers, compare native connection epochs and correlated daemon transactions |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Existing-match path at `0xfffffe000a65eee4` and its status/resource joins | Complete replacement of a prior marker and any table/tunnel retirement |
| High | Incoming dispatcher paths, saved-frame epochs and source-marker domain | Native reachability and actual allowed marker values |
| High | Context head writers, stop serialization and all node producers | Ownership and concurrency across publication/traversal/free |
| Medium | Full source+0xc90 producer and its input-byte origin | Discriminator algorithm, collision semantics and external influence |
| Medium | Correlated fairplayd selector26 records and context lifetime | Bind these fields to a successful daemon-kext exchange |
| Low | Separate FPTTLVNode producer and buffer lifecycle | Extend adjacent typed-record context without conflating node types |

## Quality gates

- **QG1**: Factual source/ABI analysis; no normative judgment is required.
- **QG2**: UP-A1-UP-A8 list assumptions, dependencies and falsification probes.
- **QG3**: Selected context/tunnel marker lineage, discriminator search, exact gates, typed allocation, nullable result, all node fields, head publication, cleanup-key composition and IPC boundaries are covered. Full investigation remains active.
- **QG4**: u32/u64 widths, 4+4+8=16 B layout, source/transfer byte counts and modular key arithmetic are exact. Extraction/audit construction is O(B+I+256R+query DAG), excluding SMT search with30 s/query limits; finite-list search and prepend complexity are explicit.
- **QG5**: Discriminator versus marker, two node types, candidate versus actual native tunnel, status-gated update versus unconditional match update, fresh head load versus concurrent linearization, and conditional key correspondence versus lifetime balance remain distinct.
- **QG6**: Original bytes/fixups/descriptors, full selected-PC proof coverage, finite-bank/address dependencies, explicit ABI cuts and six predecessor rechecks provide reproducible provenance. No new IDA evidence, native execution or deallocation is claimed.
- **QG7**: Ranked continuation covers existing-match resources, input domains, frame epochs, concurrency, discriminator origin and daemon correlation without declaring the full goal complete.

## Existing UIDList marker replacement follow-up

[The replacement report](userclient_uidlist_replacement_report.md) establishes the selected nonnull shared-holder path from an existing discriminator match through two old-marker lookup records, prior entry+16 payload capture, tombstone/reclamation requests, conditional 120 B typed payload free and status-gated node+4 replacement. Thirty-four nonvacuous obligations, 18 predecessor obligations, 734 selected instructions and 1792 bank inputs pass. Zero saved payload skips free and reaches the same marker-update join; raw success and found outputs remain separate. Null-holder construction, complete incoming reachability, native ownership/deallocation, serialization and daemon correlation remain unknown. No new Mach-port emission site is established.

The [replacement bootstrap report](userclient_replacement_bootstrap_report.md) establishes how the existing-node caller constructs a missing shared table and returns to processing or the saved-status marker-update gate.

The [discriminator-origin report](userclient_discriminator_origin_report.md) closes the selected S+0xc90 hash derivation from the nullable pointer read through C+0x128. Input business identity and its earlier producer remain unknown.

## Shared input-reader increment

The [hash-input reader](userclient_input_reader_report.md) identifies a separate node layout with successor+0, extent+0x10 and buffer+0x18, accessed through32 B. This does not identify that node as the16 B UIDList node or establish the original payload business identity.

## Container-staging increment

The [upstream parser container](userclient_container_staging_report.md) is allocated with an original16 B `site.FPTTLV` descriptor and two cleared64-bit fields. Its allocation identity remains separate from this16 B UIDList node and the reader node accessed through32 B. Nonempty construction is the remaining producer boundary.
