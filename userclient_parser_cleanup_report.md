# Parser failure output and container/pending-node cleanup

Subsequent original-entry evidence: The [early header report](userclient_early_header_report.md) continues through declared input bytes in 72 private cases, with 48 exact predecessor prefixes, ten fresh source proofs and two rejected source mutations. It establishes the early BE header and scalar/span domains, conditional wire-field correspondence to staged decoding, zero-tag span success with an unread suffix, and the earlier 32 B FPTTLVNode request. Input custody and allocator returns are fixtures; node allocation/free bodies and matched native daemon/kext identity remain unknown. Earlier boundaries below retain their historical scopes.

Subsequent original-entry evidence: The [earlier FPTTLV entry report](userclient_fpttlv_entry_report.md) continues through the first 16 B allocation return in 84 private cases, preserving 72 predecessor prefixes exactly. Source zeroing, a ten-byte early header-fit gate, the first selected original-input byte at I+6, distinct empty/short cleanup cells and typed-retirement/staging-request frontiers are independently checked. Six source proofs and two rejected store-removal controls pass. No input-content read, native allocation/free or new Mach emission executes. Earlier boundaries below describe their historical increments; later staged objects and matched daemon/kext transactions remain separate open joins.

The selected parser-failure path saves its raw status, passes the retained FPTTLV container through a cleanup cell, and resumes with a null parser output and the saved status restored. For a populated container, the shared destructor saves each node's successor before requesting buffer/node retirement, then requests container retirement and clears the cleanup cell. A separate valid-pending-node path requests its buffer/node retirement before entering that container-failure path. The nonnull-node/null-data-allocation-result seam is composed from original source.

These are source-level request and caller-return contracts under explicit storage, phase and ordinary-call premises. Native deallocation effects, type bookkeeping, ownership, synchronization, all incoming allocation-result paths and successful daemon-kext correlation remain unknown. The full interface objective remains active.

## Primary evidence and validation

| Artifact | SHA-256 of decoded content | Coverage |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Selected instructions and normalized data |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original words, chained pointers, symbols and descriptors |
| [Checks](triage_evidence/userclient_parser_cleanup_checks.json.zst) | `5978028aa3f60f6409364de9bb92a80e00d857649d45eb464f1f8dc3496ff468` | 26 spans, 362 selected instructions, 22 transfers, eight bank rules and six typed sites |
| [Audit](triage_evidence/userclient_parser_cleanup_audit.json.zst) | `d5166982de2c1f49ef3018699ed19c30e8668e61a7fbad3c4541c04230198325` | 31 nonvacuous UNSAT obligations, six predecessor rechecks, 2,893 proof instruction instances |

The [extractor](triage_evidence/recover_userclient_parser_cleanup.py) compares every selected word against both images and checks the complete 50,634-instruction `_PRnut72j9` container hash. All2,048 inputs across eight bank compositions are checked from original bytes. Each selected function/descriptor pointer is independently recovered from the original kernel collection. Six descriptor sites have original name/signature fixups, string bytes and scalar fields checked separately from their normalized blocks.

The [audit](triage_evidence/audit_userclient_parser_cleanup.py) proves null/nonnull container gates, empty-list completion, the arbitrary-successor node step, both node-buffer cases, last-node completion, both valid-pending-node buffer cases and a nonnull-node/null-data-result entry seam. Six frozen formulas are re-solved: parser entry output/continuation ABI, short-header and oversized-body rejection, constructor buffer-result gate, constructor null-node target selection and the publication cut's other-status cleanup-target selection. Rechecking a target-selection formula does not compose that entire incoming state with the valid-node cleanup contract.

Four equality controls reject an altered instruction byte, bank constant, descriptor size and unsupported native-ownership claim. They test custody sensitivity. The [delivery verifier](triage_evidence/verify_userclient_parser_cleanup_delivery.py) reconstructs the receipts and publication custody. No target code executes, no native PAC authentication is tested and no IDB is changed.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| PC1 | Original cleanup-cell root, retained node-bank key and pending descriptor producer | PC-A1-PC-A3 |
| PC2 | Arbitrary raw failure status and container-destructor request | PC-A1-PC-A4 |
| PC3 | Null-container/empty-list gates and typed container retirement | PC-A1-PC-A5 |
| PC4 | Successor-before-retirement node traversal step | PC-A1-PC-A5 |
| PC5 | Exact data/typed retirement request targets, widths and descriptors | PC-A1-PC-A5 |
| PC6 | Valid pending-node cleanup, null-data entry seam and container-failure chain | PC-A1-PC-A6 |
| PC7 | Cleanup-cell/container/output clears and saved-status parser resume | PC-A1-PC-A5 |
| PC8 | Six distinct descriptor sites and matching declared layouts | PC-A1-PC-A3, PC-A7 |
| PC9 | Scoped cost and cross-layer/ownership limits | PC-A1-PC-A8 |

## Failure entry and output contract

C is the scratch base, S the source-state base and F the selected SP epoch. H is the retained16 B container, N a list node, Q its saved successor, J a valid pending32 B node and R the arbitrary raw W23 failure status. The selected [staging caller](userclient_container_staging_report.md) retains output address C+0x600 at C+0x188 and continuation `0xfffffe000a656c08` at C+0x5c8. These are caller-specific cells, not external Mach arguments.

At `0xfffffe000a635d84` the source forms C+0x4e8 and saves that address at F+0x5f8. The selected failure span at `0xfffffe000a662444`..`0xfffffe000a662488` exclusive stores R at S+0xc10, copies H from C+0x228 into C+0x4e8 and loads X19 from F+0x5f8. With the metadata-outcome phase W24=0x50, it sets W25=0x886a1ca3 and selects the bridge at `0xfffffe000a66229c`. That bridge requests the shared destructor at `0xfffffe000a660468`.

| Retained field / register | Selected role |
| --- | --- |
| S+0xc10, u32 | Saved raw failure R |
| C+0x4e8, pointer64 | Cleanup-cell H |
| X19, pointer64 | Address C+0x4e8, not H itself |
| C+0x368, address64 | Destructor callback `0xfffffe000a660a98` |
| F+0xa80, u64 | Parser cursor retained through these cleanup paths |

The [metadata report](userclient_record_metadata_report.md) establishes R=0xce515bb8 at the selected short-header and oversized-body frontiers. The cleanup proof accepts arbitrary R32 and makes no errno/IOReturn translation. For a nullable H, the selected destructor either bypasses retirement when H==0, or traverses its head and eventually requests typed H retirement. Null H and empty H.head are separate cases.

The typed container return at `0xfffffe000a6605c8`..`0xfffffe000a660610` exclusive clears the saved cell through X19 and resumes the callback. At `0xfffffe000a660a9c`..`0xfffffe000a660ac4` exclusive, the callback clears C+0x228, reloads R from S+0xc10 and supplies X8=0. The output span writes zero through C+0x188. The parser-resume span selects C+0x5c8. On this caller, C+0x600 is zero and W23=R at the branch to `0xfffffe000a656c08`. F+0xa80 is unchanged by the captured cleanup paths; this does not undo a cursor committed before entry.

```text
failure R, retained H
        |
S+c10=R; C+4e8=H; X19=&C+4e8
        |
nullable H / linked-node retirement requests
        |
container retirement request when H!=0
        |
clear cleanup cell and C+228
        |
write null through saved parser output
        |
restore R; resume saved parser continuation
```

## Shared list-node destruction step

The retained container head is read into X23. A null head selects typed container retirement. For a valid nonnull N, `0xfffffe000a66075c` saves N.next at offset0 into callee-saved X25, then `0xfffffe000a660760` reads N.buffer at+0x18. Null buffer skips the data request; nonnull buffer requests `_IOFreeData` with its extent read from N+0x10 as u32 and zero-extended into X1.

| Emitted request | Original call PC | Target / authentication modifier | X0 / X1 |
| --- | --- | --- | --- |
| List-node buffer retirement | `0xfffffe000a6607e8` | `_IOFreeData` `0xfffffe000c4ba84c` /0x085d | N.buffer / zero_extend32(N.extent) |
| List-node typed retirement | `0xfffffe000a660708` | `_IOFreeTypeImpl` `0xfffffe000c4ba368` /0x4d6a | descriptor `0xfffffe000847be20` / N |
| Container typed retirement | `0xfffffe000a6605c4` | `_IOFreeTypeImpl` `0xfffffe000c4ba368` /0x4d6a | descriptor `0xfffffe000847bde0` / H |

The data-return span clears N.buffer at `0xfffffe000a660804` before typed node retirement. The typed-return span copies saved Q into X23 and chooses `0xfffffe000a660750` when Q!=0, otherwise `0xfffffe000a660534` for container retirement. It does not dereference the retired N after the typed call returns. The null/non-null buffer paths and arbitrary successor64 selection are proved. Both last-node cases additionally compose the H retirement request, cleanup/output clears and raw-status resume.

Each call cut makes X0-X18/X30 arbitrary and preserves callee-saved registers/SP. Retained frame, context, source and surviving-object fields are preserved as a separate memory premise. The model emits exact requests without simulating native deallocation. Node storage must be accessible through its own retirement request; no post-retirement validity is inferred. H.head is not advanced on every selected node step. The saved successor drives traversal, so native aliases/concurrent readers and intermediate list state require separate analysis.

For a finite stable acyclic list with k valid nodes and readable extents/buffer fields, repeated steps emit k typed node retirement requests, at most k data retirement requests and one typed container request. The source-step contract supports this conditional iteration; native lifetime, global list invariants and complete incoming paths are unproved.

## Valid pending-node cleanup and allocation seam

The pending entry at `0xfffffe000a6622c0` requires F+0x50 to retain a valid J, with phase W25=0x886a1ca3, W14=0x7795e642 and X21=the private table. It loads J into X25 and tests J.buffer at+0x18. The nonnull-data branch requests `_IOFreeData`; both buffer cases request `_IOFreeTypeImpl` for J before selecting the container-failure frontier.

| Emitted request | Original call PC | Target / modifier | X0 / X1 |
| --- | --- | --- | --- |
| Pending buffer retirement | `0xfffffe000a66237c` | `0xfffffe000c4ba84c` /0x085d | J.buffer / zero_extend32(J.extent at+0x10) |
| Pending typed retirement | `0xfffffe000a662404` | `0xfffffe000c4ba368` /0x4d6a | descriptor from F+0x860 / J |

The data-return store at `0xfffffe000a662384` clears J.buffer. The typed-return span does not dereference J; it restores frame roots and selects `0xfffffe000a662440` with W24=0x50 and W23 retained. The following failure span saves that status at S+0xc10 and requests retained-H destruction. F+0x50 is not proved cleared by this pending path, so the result is not an all-aliases removal guarantee.

The pending descriptor producer at `0xfffffe000a6364fc`..`0xfffffe000a636528` exclusive selects pool index0xe1, slot `0xfffffe0008472608`, applies bias-12 and saves `0xfffffe000847b6a0` at F+0x860. It is distinct from the node allocator's F+0x858 descriptor `0xfffffe000847c020`. The producer's bank relation is checked over all256 inputs and its saved-cell store is proved. Its low-byte index is formed by the original AND at `0xfffffe000a636468`. A separate 36-instruction original-byte retention envelope preserves X10/X11 and the X21/X22/X28 roots between that index and the producer; these 36 instructions are checked structurally and are additional to the 362 selected proof PCs. The retained W27=0x37 bank key has an original literal assignment at `0xfffffe000a641be8`; its retention across intervening paths remains a phase premise.

The original buffer-result span at `0xfffffe000a6427c4`..`0xfffffe000a642808` exclusive supplies a concrete incoming seam: with valid allocated J in X27 and null data result X0, it saves J at F+0x50, stores null J.buffer, reloads the saved status and establishes the pending cleanup phase. This composed null-buffer entry selects typed J retirement. The buffer allocation extent and J initialization remain supported by the [constructor report](userclient_record_nodes_report.md).

The constructor's zero-node-result target selection and the publication cut's other-status cleanup target are rechecked separately. They do not, by target address alone, establish the valid J, table root and token values used here. Those complete incoming-state compositions remain open. No claim of handling every native allocation failure or every lookup status follows from the valid-pending-node proofs.

## Descriptor correspondence and bank custody

| Site role | Original descriptor | Declared name / signature | Flags / size |
| --- | --- | --- | --- |
| Container allocation | `0xfffffe000847b620` | site.FPTTLV /11 | 0xe4 /16 B |
| Container destruction | `0xfffffe000847bde0` | site.FPTTLV /11 | 0xe4 /16 B |
| Node allocation | `0xfffffe000847c020` | site.FPTTLVNode /1121 | 0x64 /32 B |
| Pending-node cleanup | `0xfffffe000847b6a0` | site.FPTTLVNode /1121 | 0x64 /32 B |
| List-node destruction | `0xfffffe000847be20` | site.FPTTLVNode /1121 | 0x64 /32 B |
| Replacement retirement | `0xfffffe000847bce0` | site.FPTTLVNode /1121 | 0x64 /32 B |

Within each declared size/name group, normalized64-byte metadata blocks match. Original fixups, strings and scalar fields are independently checked at all six addresses. Address identity and native type/site bookkeeping remain distinct from matching normalized layout metadata. The replacement site belongs to the [publication report](userclient_record_publication_report.md) and is compared here as metadata, not used as this destructor's argument.

| Rule | Left / right roots | Key / constant / additive | Original slot / biased target |
| --- | --- | --- | --- |
| pending_descriptor | 0xfffffe0007949dd0 / 0xfffffe000792fbc0 | 0x5c / 0xd2 / 0xf | 0xfffffe0008472608 / 0xfffffe000847b6a0 |
| container_free | 0xfffffe0007949ed0 / 0xfffffe000792fec0 | 0x92 / 0xa2 / 0xe89 | 0xfffffe000847a878 / 0xfffffe000c4ba368 |
| container_descriptor | 0xfffffe0007949ed0 / 0xfffffe000792fec0 | 0x92 / 0xa2 / -0x55 | 0xfffffe0008472168 / 0xfffffe000847bde0 |
| node_free | 0xfffffe0007949fd0 / 0xfffffe000792ffc0 | 0x37 / 0x3a / 0xef1 | 0xfffffe000847a878 / 0xfffffe000c4ba368 |
| node_descriptor | 0xfffffe000792fcc0 / 0xfffffe00079391f0 | 0x47 / 0x7b / 0x149 | 0xfffffe0008472d20 / 0xfffffe000847be20 |
| data_free | 0xfffffe0007941f60 / 0xfffffe000794a0d0 | 0x6d / 0x13 / 0xf07 | 0xfffffe000847a7f0 / 0xfffffe000c4ba84c |
| pending_data_free | 0xfffffe0007949dd0 / 0xfffffe000792fbc0 | 0x5c / 0xd2 / 0xe48 | 0xfffffe000847a7f0 / 0xfffffe000c4ba84c |
| pending_node_free | 0xfffffe0007949fd0 / 0xfffffe000792ffc0 | 0xef / 0x61 / 0xeca | 0xfffffe000847a878 / 0xfffffe000c4ba368 |

Each rule is checked over all256 inputs, for2,048 bank cases. The rules retain original chained-pointer metadata and biases separately from native authentication.

## Original private table mapping

| Private index | Original slot | Target |
| --- | --- | --- |
| 0x50 | `0xfffffe00084731a0` | `0xfffffe000a660a98` |
| 0x247 | `0xfffffe0008474158` | `0xfffffe000a660614` |
| 0x2b7 | `0xfffffe00084744d8` | `0xfffffe000a66229c` |
| 0x414 | `0xfffffe0008474fc0` | `0xfffffe000a660750` |
| 0x41e | `0xfffffe0008475010` | `0xfffffe000a660534` |
| 0x432 | `0xfffffe00084750b0` | `0xfffffe000a660614` |
| 0x43e | `0xfffffe0008475110` | `0xfffffe000a662310` |
| 0x440 | `0xfffffe0008475120` | `0xfffffe000a662394` |
| 0x480 | `0xfffffe0008475320` | `0xfffffe000a6604fc` |
| 0x4a9 | `0xfffffe0008475468` | `0xfffffe000a662440` |
| 0x6d5 | `0xfffffe00084765c8` | `0xfffffe000a660ae0` |
| 0x766 | `0xfffffe0008476a50` | `0xfffffe000a64280c` |
| 0x7ad | `0xfffffe0008476c88` | `0xfffffe000a6622bc` |
| 0x970 | `0xfffffe0008477aa0` | `0xfffffe000a660ac8` |
| 0x989 | `0xfffffe0008477b68` | `0xfffffe000a66066c` |
| 0x99e | `0xfffffe0008477c10` | `0xfffffe000a660790` |
| 0x9a7 | `0xfffffe0008477c58` | `0xfffffe000a660468` |
| 0xafb | `0xfffffe00084786f8` | `0xfffffe000a660614` |
| 0xafc | `0xfffffe0008478700` | `0xfffffe000a6604a4` |

These are private dispatcher indices, not Mach message IDs or IOUserClient selectors. The selected failure caller uses a nonnull cell address; the shared dispatcher's other callers require their own input-state recovery.

## Architectural scope and cost

The selected source connects parser rejection and valid pending-node cleanup to container/list retirement requests, null output publication and saved-status resume. X23 is reused as a node pointer during shared destruction; its low W23 must not be interpreted as the saved raw status until S+0xc10 is reloaded. The three cleanup descriptors differ from each other and from allocation/replacement sites despite matching declared node layouts.

No new Mach right, port endpoint, message emission site or successful daemon-provider transaction is established. External interfaces remain in [Mach ports](mach_ports_report.md), [interface ABI](interface_abi_report.md) and [investigation status](interface_investigation_status.md). Native allocator effects, aliases, locking, all allocation-result incoming states, other parser types and full cross-layer input identity remain open.

For k finite valid list nodes, selected destruction takes O(k) source work and O(1) auxiliary state, excluding native callee cost. Pending cleanup and output/status publication take O(1) work. Extraction takes O(B+I+256R) time/space, where B is the pinned container/image bytes, I selected instructions and R bank rules. Proof construction takes O(instruction instances+query DAG); SMT search is separate with30 s/query limits. Extents/sizes are bytes; node extent and status are u32, data-free extent explicitly zero-extends to u64, and pointer/cell fields are u64.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PC-A1: Pinned images, original pointers/symbols/descriptors and predecessor receipts | PC1-PC9 | Fresh dual-image/full-container custody, six descriptor sites, reconstructed queries and four altered-evidence controls |
| PC-A2: Selected C/S/F phase, retained bank roots, callback/output fields and W27 key retention | PC1-PC9 | Original root/key/descriptor stores and selected source entry seam; trace every incoming epoch and intervening alias/call |
| PC-A3: AArch64 W/X, comparisons, bank arithmetic and memory widths match the model | PC1-PC9 | All2,048 bank inputs, original pointer biases, arbitrary pointer/status values and explicit u32-to-u64 extent requests |
| PC-A4: Selected cleanup cell/output/context/source storage is valid and separate | PC2-PC7 | Null/nonnull H, exact cell/output clears and arbitrary saved-status proofs; validate actual caller allocation/frame epochs separately |
| PC-A5: Accessible H/N storage through requests, finite stable successor chain and ordinary-call preservation of surviving state | PC3-PC5, PC7 | Empty/list-node/last-node cases, caller-saved havoc and saved-successor gate; establish native callee effects, aliases and synchronization separately |
| PC-A6: Pending J is valid and separate, with selected table/token phase; all incoming allocation-result paths are not composed | PC6, PC9 limits | Both buffer cases and nonnull-J/null-data source seam; recover the complete zero-node-result and other-status incoming states before extending this contract |
| PC-A7: Matching descriptor metadata does not establish native type-site interchangeability or ownership | PC8, PC9 limits | All six original fixup/string/scalar records and normalized-block comparisons; recover native descriptor bookkeeping and actual allocation identities |
| PC-A8: Complete type/dispatcher reachability, native cleanup behavior and daemon correlation remain unknown | PC9 limits | Recover other types, native frame/storage/locking epochs and a successful correlated daemon/provider exchange |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Complete allocation-result and lookup-status incoming states | Establish which source cleanup premises hold on each original entry path |
| High | Native typed/data retirement callees and descriptor bookkeeping | Separate emitted requests from actual ownership, lifetime and site compatibility |
| High | Actual staged-input caller and successful daemon/provider exchange | Bind the parser/cleanup ABI to externally controlled data and cross-layer IPC |
| High | Native aliases and synchronization during successor traversal | Validate surviving-list/frame premises and remaining references |
| Medium | U=0xa129/0xb2db and remaining type handlers | Extend metadata/body/failure semantics beyond selected type0x6685 |
| Medium | Caller continuation `0xfffffe000a656c08` | Recover subsequent status translation and staged-buffer ownership |
| Medium | Decoded zero-tag success with an outer suffix | Establish caller-visible remaining-input policy and business semantics |

## Quality gates

- **QG1**: Factual source/interface/lifecycle claims require no normative conclusion.
- **QG2**: PC-A1-PC-A8 enumerate dependencies and falsification probes.
- **QG3**: Selected failure status/output, container/null/empty/list-node behavior, valid pending cleanup, allocation seam and exact retirement requests are covered; the full objective remains active.
- **QG4**: Byte sizes, u32-to-u64 extent width, pointer fields and conditional O(k) cost are explicit.
- **QG5**: Saved status versus X23 traversal role, cell address versus H, valid pending storage versus all incoming results, normalized metadata versus descriptor identity and emitted requests versus native deallocation are distinct.
- **QG6**: Dual-image words, original pointers/symbols/descriptors, 31 nonvacuous formulas, six predecessor rechecks, 2,048 bank inputs and four custody controls support bounded claims.
- **QG7**: Ranked continuation retains incoming-state composition, native ownership/locking, caller continuation, remaining types and cross-layer correlation.

## Parser caller and command dispatch increment

The actual parser caller now has a conditional command-field lookup, protected scalar reader and exact two-value switch. The first command links to the existing hash-input reader; second-body semantics, native storage/ownership and cross-layer correlation remain open. See the [command-dispatch report](userclient_command_dispatch_report.md) for the source contracts, status frontiers and assumption register.

## Caller cleanup and copy-back increment

Caller cleanup callback0x1a, distinct staged/auxiliary buffers, finite protected copy-back and outer allocation/retirement/status contracts are now established conditionally. Native identity, aliases, callee effects and cross-layer transaction correlation remain open. See the [caller-return report](userclient_caller_return_report.md) for original requests, proofs, scope and assumption probes.


The [kernel allocator boundary](kernel_allocator_boundary_report.md) now establishes selected14/32 B zone-address formation, conditional null-result propagation through the size/data allocators, typed result/frame custody, all-flags typed fallback allocation/free heap-size congruence, data/lower retirement null guards and the small-size query request ABI. Native outcome existence, valid initialized zones, allocation identity/ownership, query-helper effects, PAC, synchronization and daemon-visible transaction behavior remain unknown; no additional Mach endpoint is established.


The [retirement metadata query](kernel_retirement_query_report.md) establishes conditional8 B range admission, the10-bit zone classification and u16 extent output, both large-layout index encodings, explicit destructive u16 offset reads, optional output effects and the14/32 B caller extent/recovered-base request. Complete query register/store inventory and separate composition formulas support the modular caller join. Native metadata initialization/coherence, allocation identity/ownership, actual clear/retirement, synchronization and daemon transaction pairing remain unknown; no additional Mach endpoint is established.

## Subsequent message-allocation failure evidence

The [message-failure report](userclient_message_failure_report.md) composes a distinct later failure epoch: allocation NULL in the second parser leaves both message child pointers zero, so the shared destructor returns through each child callback without deeper container/node retirement. The message and attribute typed-retirement requests then precede a pending cleanup of the original H/J/Z container. That remaining original-container cleanup is not executed in the new increment.

## Subsequent failure fallback evidence

The [failure-fallback report](userclient_failure_fallback_report.md) composes the shared list destructor with the actual original H/J/Z state following message construction failure. The retained successor is zero; the source requests data retirement of the 14 B protected record, typed retirement of the 32 B node and typed retirement of the 16 B container, then clears C+0x418 and resumes the fallback allocator. Ordinary returns are premises; native free effects and broader list/error paths remain unknown.
