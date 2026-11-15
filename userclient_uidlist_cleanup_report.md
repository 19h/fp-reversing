# Populated UserClient context: UIDList fast cleanup

`_kratpzs81h` at `0xfffffe000a626648` has a populated-context cleanup arm for 16 B nodes whose raw u32 field at +4 equals `0x31ae0066`. It saves the node's u64 +8 successor before requesting `_IOFreeTypeImpl(site.UIDList, node)`, then reloads that saved successor. A nonzero successor repeats the gate; zero joins the previously established 24 B `site.IOUCCtx` cleanup and original context-cell clear. This recovers one populated-list arm. The marker-unequal table-processing path and the first four node bytes remain unknown; its shared-table bootstrap is covered by the linked follow-up. [UL1-UL6; UL-A1-UL-A6]

The type name is original binary evidence. Its `UID` substring does not establish a user identifier, Mach-port name, process identity, entitlement or application-level meaning. The selected source establishes typed-free requests and conditional control flow; native deallocation, task-reference balance and a successful fairplayd-kext transaction remain unknown. [UL3,UL6; UL-A4-UL-A6]

Primary artifacts: [source, descriptors and fixups](triage_evidence/userclient_uidlist_cleanup_checks.json.zst), [independent audit and SMT queries](triage_evidence/userclient_uidlist_cleanup_audit.json.zst), [extractor](triage_evidence/recover_userclient_uidlist_cleanup.py), [auditor](triage_evidence/audit_userclient_uidlist_cleanup.py), [publication verifier](triage_evidence/verify_userclient_uidlist_cleanup_publication.py). Predecessors: [context lifecycle](userclient_context_lifecycle_report.md), [context/task consumers](context_descriptor_task_flow_report.md), [connection close](iokit_connection_lifecycle_report.md). Existing original-byte captures suffice; no new IDA access, IDB mutation, guest execution or native API operation is used.

```text
UserClient stop -> provider adapter -> _kratpzs81h(context-cell address)
                                      |
                                context head
                                      |
                               current node +4
                               /             \
                  == 0x31ae0066              unequal
                         |                    |
                  save node +8           unrecovered arm
                         |
                  typed free: 16 B node
                         |
                  reload saved successor
                     /              \
                 nonzero            zero
                    |                 |
                next gate       typed free: 24 B context
                                      |
                                clear original cell
```

Arrows assume valid disjoint objects, ordinary authenticated transfers/returns and the recorded frame roots. The original incoming context, node, task and Mach connection name are distinct channels. [UL-A1-UL-A6]

## Evidence coverage

| Item | Verified value / scope |
| --- | --- |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Source coverage | Five spans, 79 instructions (316 B), plus three terminal transfers (12 B); original collection, normalized image and prior complete function capture agree |
| Captured predecessor body | 878 instructions; complete capture does not imply complete semantic recovery |
| New static data | Four 256 B arrays; two exhaustive 256-input bank rules; four pool and four branch fixups; one typed descriptor |
| New proof coverage | Five nonvacuous UNSAT obligations; 79 lifted instructions, 19 reads, two writes |
| Predecessor proof rechecks | Five UNSAT queries: entry roots, head/save gate, typed context-free ABI, cell clear, normal epilogue |
| Boundary controls | Two abstract SAT controls; four altered-evidence rejections |
| Checks decoded SHA-256 | `d43b29782714595f1d80e59a2169b2c87ec9ffe55366aaa93ee5f6af597407bd` |
| Audit decoded SHA-256 | `801e96725f8b9bf58dd6c50c705c6978242c84abc372792e2654b34223025c01` |

The five predecessor queries are re-solved from pinned receipts; they are not a fresh semantic reconstruction of every predecessor instruction. Fresh extraction verifies the complete predecessor destroy-function bytes and the selected new source against the original collection. [UL1; UL-A1]

## Exact source mapping

| Evidence | Instruction / data location | Established role |
| --- | --- | --- |
| UL1 | `0xfffffe000a6267d0`; `0xfffffe000a6267f0`; `0xfffffe000a626828`; `0xfffffe000a62682c` | Save context/cell at SP+8/+0x10, load context head into X20, save free-bank roots at SP+0x50/+0x58 and controller pointers at SP+0x68/+0x70 |
| UL2 | `0xfffffe000a6269f8`; `0xfffffe000a6269fc`; `0xfffffe000a626a00` | Load node+8 successor; save it at SP+0x60; load node+4 marker32 |
| UL3 | `0xfffffe000a626a1c`; `0xfffffe000a626a30`; `0xfffffe000a626a38` | Compare against raw `0x31ae0066`, select table index 0xea5/0xe5e, branch with IA modifier 0x234d |
| UL4 | `0xfffffe000a626990`; `0xfffffe000a6269a8`; `0xfffffe000a6269b4` | Resolve free target and UIDList descriptor; call with X0=descriptor, X1=current node, X11=free adapter, X17=0x4d6a |
| UL5 | `0xfffffe000a6269b8`; `0xfffffe000a6269bc`; `0xfffffe000a6269d8`; `0xfffffe000a6269e0` | Restore controller pointers and saved successor, select next gate/context free, branch with IA modifier 0xc338 |
| UL6 | `0xfffffe000a6268c4`; `0xfffffe000a6268d0`; `0xfffffe000a6268fc` | Prior typed context-free call, original cell zero store and normal status-return path |

The second selected write, at `0xfffffe000a626a04`, clears one private byte at SP+0x86. Its wider consumer semantics are unknown. No node+0 access occurs in these 79 instructions. The continuation's reads after free are the private saved controller pointers, saved successor and original branch table; it does not reload the freed node. This is a local source statement, conditional on frame preservation across the call. [UL2,UL5; UL-A2-UL-A4]

| Node byte offset | Width | Meaning established here |
| --- | --- | --- |
| +0 | 4 B | Unknown; no selected read or write |
| +4 | 4 B | Raw branch marker, compared to `0x31ae0066` |
| +8 | 8 B | Successor used by this cleanup traversal |

The context's +0 head and the node's +8 successor are separate fields. No head-update store is recovered in this fast arm; traversal advances X20 via the private saved successor. [UL1,UL2,UL5]

## Branches, banks and typed call

| Predicate / purpose | Index | Original pointer slot | Target |
| --- | --- | --- | --- |
| marker equals `0x31ae0066` | 0xea5 | `0xfffffe000847a448` | `0xfffffe000a626920`, fast node free |
| marker unequal | 0xe5e | `0xfffffe000847a210` | `0xfffffe000a626a3c`, unrecovered arm |
| saved successor is zero | 0x980 | `0xfffffe0008477b20` | `0xfffffe000a626838`, context free |
| saved successor is nonzero | 0x9a4 | `0xfffffe0008477c40` | `0xfffffe000a6269e4`, next node gate |
| free bank, key 0x87, additive 0xe4c | 0xf2b | `0xfffffe000847a878` | `0xfffffe000c4ba368`, `_IOFreeTypeImpl` |
| descriptor bank, key 0x92, additive 0xdb | 0x17d | `0xfffffe0008472ae8` | `0xfffffe000847b2a0`, UIDList descriptor |

For each bank pair, all 256 byte inputs satisfy `x XOR right[left[x] XOR key] = constant`: 0xdf for the free target and 0xa2 for the descriptor. The lifted source also checks the actual controller arithmetic and both literal-array accesses for arbitrary u32 controller values. This does not assume a single favorable controller sample. The free-call chained pointer is authenticated with diversity 0x4d6a, matching the call modifier; hardware authentication is not executed. The exact-symbol adapter has BTI then a tail branch to `0xfffffe000bcff010`; lower allocator semantics are outside this increment. [UL3-UL5; UL-A1,UL-A4]

Descriptor `0xfffffe000847b2a0` contains original string `site.UIDList`, signature text `21`, flags32=0x64 and size32=16 at +0x28/+0x2c. Name/signature pointers are verified against original chained fixups; the normalized 64 B descriptor is recorded separately from its original collection words. Signature text is retained without assigning undocumented semantics. [UL4; UL-A1,UL-A6]

The entry/head source gives W19=0xe5e and W21=0x58c. The node gate produces W24=0x980. The free arm restores W19=0xe5e and W21=0x58c, so each ordinary-return continuation re-enters the same gate phase. It also restores X2/X3 from the private frame before using them again; the audit makes X0-X18 arbitrary at the return cut as a conservative GP clobber set. X19-X29 and SP preservation, including W24, remain explicit ABI premises. [UL1-UL5; UL-A2,UL-A4]

## Conditional traversal contract and IPC relation

```text
current = load_u64(context + 0)
while current != 0:
    successor = load_u64(current + 8)
    marker = load_u32(current + 4)
    if marker != 0x31ae0066: goto unrecovered_arm
    typed_free_request(UIDList_descriptor, current)
    current = successor                 # saved before the call
typed_free_request(IOUCCtx_descriptor, context)
store_u64(original_context_cell, 0)
return raw_u32(0)
```

This compact pseudocode describes the selected all-matching arm plus its rechecked predecessor join, under UL-A1-UL-A5. It is not a reconstruction of the unequal arm. For a finite acyclic chain of n valid 16 B nodes, all with the matching marker and all free calls returning ordinarily, induction gives n node-free requests, one context-free request and the original cell clear. The n=0 case is the prior empty-head path; one iteration preserves the phase and either decreases the remaining chain length or joins context free. Requested type sizes sum to `(16*n + 24) B`; this is not measured heap retirement or allocator footprint. Traversal time is O(n), additional traversal state O(1), excluding free implementation costs. A self-successor defeats the acyclic/finite premise; the SAT control is abstract and provides no native reachability claim. [UL1-UL6; UL-A2-UL-A5]

This local path is reached from the per-UserClient context-cell stop adapter established earlier. The close RPC/termination/stop relation remains conditional on the framework lifecycle. The 79 selected instructions and three terminal transfers contain the typed-free call and table branches, with no newly recovered Mach-port emission or import site. Neither node+0 nor the `UID` label establishes a Mach-port field. The existing [Mach-port report](mach_ports_report.md) remains the port-site inventory; this increment adds teardown ownership context, not a native connection/port pairing. [UL1-UL6; UL-A5,UL-A6]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| UL-A1: Pinned original collection, normalized image and predecessor receipts describe this build. | All source/address/type claims | Freshly compare source bytes, raw chained records, descriptor words and dependency hashes; reject changed instruction, array, descriptor-size or branch-target evidence. |
| UL-A2: Current node, context/cell and private frame are valid, disjoint owned regions; original tables/controllers remain valid at their selected reads. | Marker/successor meanings and traversal joins | Query premises constrain nonwrapping node/frame extents and separate them from each other and selected protected ranges. Find actual node producers and lifetime/serialization evidence; an alias or invalid pointer falsifies the composition. |
| UL-A3: The private saved frame survives each free call and intervening execution. | Saved successor and original context/cell provenance | Independent byte-array proof checks the eight-byte save/reload; trace writes to SP+0x60, SP+8/+0x10 and saved root slots across the actual callee/lifecycle. External modification breaks this join. |
| UL-A4: Transfers authenticate and calls return normally under the expected ABI. | Free target, continuation and final clear | Match original diversity/modifiers and recheck source ABI; return-cut model makes X0-X18 arbitrary. A trap, nonreturn or callee-saved/frame violation excludes the continuation. Native retirement remains unknown. |
| UL-A5: Chain is finite, acyclic, stable and entirely marker-equal; stop uses the captured provider implementation and context epoch. | Complete selected n-node sequence and size formula | Follow head/node writers, synchronization, provider override and framework stop dispatch. Abstract unequal-marker and self-successor SAT controls show why unconditional completion is not established. |
| UL-A6: Type strings and static requests do not supply application identity or native IPC evidence. | Naming and daemon-kext scope | Recover node+0 producers/consumers and compare actual port namespaces/connection epochs before assigning UID/Mach semantics. Current historical trace ends at failed open. |

## Bounded continuation

| Impact | Evidence to recover | Question resolved |
| --- | --- | --- |
| High | Marker-unequal processing at `0xfffffe000a626dc8` and its downstream joins | Remaining populated cleanup and any lower record/resource releases |
| High | Producers of context head, node+0/+4/+8 and their allocation descriptors | Node identity, marker production, ownership and whether both branches share a list protocol |
| High | Task references and framework/provider stop dispatch | Whether the context's task and node lifetime survive every descriptor/teardown use |
| Medium | Serialization of head/node writers, stop and selector26 | Whether the local saved-successor traversal composes under actual concurrent lifecycle events |
| Medium | Native image/class/connection correspondence and successful trace | Whether fairplayd reaches this kext context and cleanup epoch |

## Scoped quality gates

- **QG1**: Claims concern source bytes, control flow, ABI, widths and evidence boundaries; no normative conclusion is required.
- **QG2**: UL-A1-UL-A6 identify assumptions, dependent results and falsification probes; ownership/ABI/frame assumptions are explicit.
- **QG3**: The marker-equal arm, incoming saved roots, outgoing typed-free ABI, successor loop, context cleanup join and Mach-port relevance are covered. The unequal arm and full interaction goal remain active.
- **QG4**: 79*4=316 B; three transfers add 12 B; four arrays contain 1024 B; two rules cover 512 inputs. Node layout is 4+4+8=16 B. Source extraction costs O(B+I+256R) time/space; audit construction costs O(I+256R+query DAG), with separate solver search and 30 s/query limits. Traversal and type-size arithmetic are given above.
- **QG5**: Partial versus full cleanup, context head versus node successor, raw marker versus application semantics, source request versus native retirement, and original versus normalized pointer words remain distinct. Abstract controls retain the finite-chain and unequal-arm boundaries.
- **QG6**: Original collection/image hashes, original code/fixups/type strings, exact free symbol, five reconstructed source queries, five predecessor-query rechecks, exhaustive bank cases and altered-evidence controls supply scoped provenance.
- **QG7**: Ranked continuation identifies the unequal arm, node producers, reference lifetime, concurrency and native pairing without extending the selected-arm conclusion beyond its premises.


## Shared hash-table bootstrap during teardown

The [shared-table bootstrap report](userclient_hash_table_bootstrap_report.md) recovers the marker-unequal arm's module-global `site.FPHashTable` guard, 16 B allocation request, encoded initializer/header join, exact output-status publication gate and rollback. A still-null holder after failure selects UIDList node free and saved-successor continuation even for an unequal marker. Twelve new source obligations and five predecessor rechecks pass. Full table initialization/processing, node semantics, task references and native pairing remain unknown.

## UIDList search and publication follow-up

[The UIDList publication report](userclient_uidlist_publication_report.md) recovers the separate node+0 discriminator and node+4 tunnel marker, exact search/successor gates, typed 16 B allocation and ordered node-fill/context-head stores. Candidate tunnel+0x6c flows into node+4 under the recorded frame/object premises, joining the insertion and cleanup key codecs conditionally. Seventeen new obligations, six predecessor obligations, 232 selected instructions and 512 bank cases pass. Existing-match resource/status completion, discriminator/input identity, native reachability, ownership, serialization and daemon correlation remain unknown; no new Mach endpoint is established.
