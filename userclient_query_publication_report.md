# Query record lookup, publication and constructor return

The selected query callback appends a pending record when protected-tag lookup misses, or replaces the first matching node in place when lookup succeeds. The source updates the affected container and neighbor links, requests retirement of a replaced node's optional data and32 B typed storage, clears the old-result cell and returns raw SUCCESS through the saved constructor and request callbacks. These are conditional source contracts. Native allocator effects, pointer authentication, synchronization, full failure cleanup and an observed daemon transaction remain unknown.

Under the additional finite coherent-list and stable-state premises, three successful distinct-tag query constructions retain all three new14 B records. Their combined contribution is42 B. If the established size pass accepts that list, its padded auxiliary extent M is at least64 B. The successful auxiliary-copy equality gate consequently requires original low32 request length N=M>=64 B. Exact native list contents and the provider's external return status do not follow from this bound.

## Evidence and claim register

Primary evidence is the original kernel collection and normalized kext. The [extractor](triage_evidence/recover_userclient_query_publication.py), [instruction audit](triage_evidence/audit_userclient_query_publication.py), [delivery verifier](triage_evidence/verify_userclient_query_publication_delivery.py), [checks](triage_evidence/userclient_query_publication_checks.json.zst) and [formulas](triage_evidence/userclient_query_publication_audit.json.zst) retain the original words, pointer records and obligations. This increment composes [exact query records](userclient_query_writer_report.md), [request callbacks](userclient_query_records_report.md), [shared reader/search](userclient_input_reader_report.md), [serializer sizing](userclient_serializer_extent_report.md), [serializer emission](userclient_serializer_emission_report.md), and the [auxiliary consumer](userclient_auxiliary_copy_report.md). The earlier [parser-node publication](userclient_record_publication_report.md) is a distinct callback channel.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| QP1 | Original output-slot producer forms &C+0x50; the selected lookup retains that output alias, requested tag and callback0x6c, and performs exact protected-tag match/next dispatch | QP-A1-QP-A5 |
| QP2 | SUCCESS selects query replacement, MISS selects query append, and other raw statuses are retained to the new-node retirement frontier | QP-A1-QP-A4 |
| QP3 | Empty and nonempty append publish J, retain its14 B data/extent and saved callback, set raw SUCCESS and select the constructor return | QP-A1-QP-A4, QP-A6 |
| QP4 | Sole/head/tail/interior replacement copies O's links to J and updates exactly the affected neighbors and container boundaries; neighbor data/extent fields remain unchanged | QP-A1-QP-A4, QP-A6 |
| QP5 | Nullable old-data retirement, exact original _IOFreeData/_IOFreeTypeImpl requests, old-result clear and raw-success return are established under explicit ordinary-call effects cuts | QP-A1-QP-A4, QP-A6 |
| QP6 | Publication preserves an arbitrary saved request callback and returns through C+0x260; the three known request callbacks then select the previously proved next-request/serializer handoffs | QP-A1-QP-A4, QP-A6 |
| QP7 | Separate finite-sequence lemmas preserve earlier distinct-tag records across later publications; three successful constructions imply L>=42 B and, for accepted sizing/copy, M=N>=64 B | QP-A1-QP-A7 |

Normalized-image SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original-collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The containing `_PRnut72j9` range is `0xfffffe000a635208`..`0xfffffe000a666930` exclusive,50,634 words, SHA-256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297`; the original C export names it at line199131. Thirty-two selected spans contain427 words. Four MOVK alternatives are excluded under nominal-pointer guards, leaving423 modeled source locations. Twenty-nine terminal transfers and27 original chained branch pointers are captured separately.

Decoded checks SHA-256: `5d83e2204a81e68d86908a80548779057004a915d36d977af33edbab8c170ff1`. Decoded audit SHA-256: `afd14d7d595374732c477db69b527ef6dee0f56c3a0c84c799ebc2e6bf2707ea`. Seventy-five nonvacuous instruction-source queries contain6,845 instruction instances. Twelve predecessor formulas are re-solved. Four additional nonvacuous finite-sequence/arithmetic formulas are retained separately from source queries and instruction counts. Four bank rules are checked over all256 inputs each, totaling1,024 cases. A changed empty-append store operand produces a SAT counterexample. No target execution, IDB mutation or new IDA observation is used; the reference images are sufficient for the selected boundaries.

## Output alias and protected lookup ABI

F is the selected frame SP, C the4096 B context, S the16384 B workspace, H the16 B list container, J a new32 B node, O the old matching node, P its predecessor and Q its successor. Node links are next+0 and previous+8; extent is u32 at+0x10 and buffer is u64 at+0x18. H.head is at+0 and H.tail at+8. `SUCCESS=0x31ae0066`, `MISS=0xce515bda`, `TOKEN=0x886a1ca3`, `PHASE=0x7795e642`.

| Source location | Established role |
| --- | --- |
| `0xfffffe000a635e64`..`0xfffffe000a635e6c` | Forms C+0x50 and stores it at F+0x348 at the selected producer phase |
| `0xfffffe000a655cec` | Query writer publication request reloads the output address into X10; recaptured in the predecessor |
| `0xfffffe000a662ac0`, `0xfffffe000a662ac8` | Select table[W8=0x6c] and retain callback `0xfffffe000a662b64` at C+0xc8 |
| `0xfffffe000a662acc` | Retain the requested encoded tag at S+0 |
| `0xfffffe000a662ad0` | Retain output address &C+0x50 at C+0x758 |
| `0xfffffe000a663dcc` | Reload F+0x348 into X22 for replacement/retirement result custody |

The complete containing-range literal-SP inventory finds one F+0x348 store and these two loads. This identifies the producer and selected uses; it does not exclude indirect/aliased writes. Applying its value at the later uses retains an explicit same-frame/context-epoch and stable-slot premise.

The lookup starts at H.head, reads each admitted node's protected first four buffer bytes, compares its recovered tag control with the requested control, and follows next+0 on mismatch. Match publishes O at C+0x50 with raw SUCCESS. Exhaustion publishes0 with raw MISS. The callback also selects the existing lookup retirement-descriptor value `0xfffffe000847bce0`; X22 therefore has a different role from its entry H role. The query publication code subsequently selects its own typed-retirement descriptor.

The search theorem covers arbitrary stored/requested tag controls, node/next pointers and a local match/next step. Whole-list termination and first-match interpretation require a finite stable acyclic list with readable headers. The selected lookup's four-byte read relies on a valid readable header; this local path does not derive that property from the node extent field. The earlier record writer's protected bytes and lookup normalization agree on the tag-control channel. Raw decoded wire tags are tagcontrol XOR SUCCESS, rather than the private requested control itself.

| Lookup status at query callback | Source continuation |
| --- | --- |
| W23=SUCCESS | Direct branch at `0xfffffe000a662b74` -> replacement `0xfffffe000a663d28` |
| W23=MISS | Fall through `0xfffffe000a662b88` -> append preparation |
| Other W23 | Branch at `0xfffffe000a662b84` -> `0xfffffe000a664048` -> pending-node retirement frontier `0xfffffe000a664074`, raw status retained |

W8=0x6c is the lookup callback index. W0=0x19 is a separate private control from the preceding writer; its downstream meaning is not inferred. All these indices are internal table controls, not Mach message identifiers or user-client selectors.

## Append and replacement effects

| Append case | Exact source effects | Store locations |
| --- | --- | --- |
| Empty coherent H | H.head=H.tail=J; J.previous=J.next=0 | STP at `0xfffffe000a662bc8` |
| Existing tail T | T.next=J; J.previous=T; H.tail=J; H.head unchanged; J.next=0 | `0xfffffe000a6654e4`, `0xfffffe000a6654ec`, `0xfffffe000a6654f0` |

The pending J.extent=14, J.buffer and arbitrary request callback survive both append paths. Existing tail extent/buffer fields are unchanged. Both paths set W23=SUCCESS and select index0x63d -> `0xfffffe000a664218`.

On replacement, the source loads O and J from C+0x50/C+0x58, then writes O.previous into J.previous at `0xfffffe000a663d50` and O.next into J.next at `0xfffffe000a663d58`.

| Position | P / Q | Surviving-list changes |
| --- | --- | --- |
| Sole | 0 / 0 | H.head=H.tail=J; J.previous=J.next=0 |
| Head | 0 / nonzero | H.head=J; Q.previous=J; old H.tail retained |
| Tail | nonzero / 0 | P.next=J; H.tail=J; old H.head retained |
| Interior | nonzero / nonzero | P.next=J; Q.previous=J; H.head/H.tail retained |

| Mutation | Exact source store |
| --- | --- |
| P.next=J | `0xfffffe000a663d90` |
| Q.previous=J | `0xfffffe000a663dec` |
| H.head=J | `0xfffffe000a663e40` |
| H.tail=J | `0xfffffe000a663ea0` |

```text
miss:     ... <-> T            -> ... <-> T <-> J
match:    ... <-> P <-> O <-> Q -> ... <-> P <-> J <-> Q
                               -> retire O.data if nonnull, then O
both:     raw SUCCESS -> saved constructor return -> saved request callback
```

The replacement proofs retain arbitrary unaffected head/tail values in non-boundary cases. They preserve J's data/extent and the adjacent nodes' data/extent fields, and re-read the surviving fields after each ordinary-call cut. This is a local replacement of the node returned by search. Preexisting duplicate tags are not all removed, global uniqueness is not established, and concurrent mutation is outside the stable-list contract.

## Original retirement requests and return

| Request | Original call PC | Original target / modifier | Argument registers |
| --- | --- | --- | --- |
| _IOFreeData | `0xfffffe000a663f48` | `0xfffffe000c4ba84c` / 0x085d | X0=O.buffer; X1=zero_extend32(O.extent) |
| _IOFreeTypeImpl | `0xfffffe000a663ffc` | `0xfffffe000c4ba368` / 0x4d6a | X0=`0xfffffe000847c2a0`; X1=O |

O.buffer=0 skips data retirement and selects the typed request. Nonzero requests data retirement first; its return clears O.buffer at `0xfffffe000a663f68`. The typed-return block clears C+0x50 at `0xfffffe000a664018`, sets raw SUCCESS and selects the constructor return. The captured caller instructions do not dereference O after the typed request returns. Successful helper effects are not simulated: ordinary-call cuts havoc caller-saved registers and explicitly preserve the surviving list, new data, selected frame/context/workspace and callee-saved state. That memory preservation is an effects premise, not a consequence of the register calling convention alone.

| Descriptor property | Query allocation | Query retirement |
| --- | --- | --- |
| Address | `0xfffffe000847b4a0` | `0xfffffe000847c2a0` |
| Name | site.FPTTLVNode | site.FPTTLVNode |
| Signature | 1121 | 1121 |
| Flags / size | u32 0x64 /32 B | u32 0x64 /32 B |

Normalized64 B descriptor metadata matches; the source addresses differ. Original retirement name/signature pointers, string bytes and scalar fields are checked. Descriptor correspondence does not establish native allocation identity or interchangeable allocator bookkeeping.

| Bank use | Roots | Key / constant / additive | Selected slot / effective target |
| --- | --- | --- | --- |
| Shared lookup descriptor value | FL=`0xfffffe000792fcc0`, FR=`0xfffffe00079391f0` | 0x87 /0xdf /-0x93; pool bias-4 | `0xfffffe0008472160` -> `0xfffffe000847bce0` |
| Query old-data retirement | BL=`0xfffffe0007949fd0`, BR=`0xfffffe000792ffc0` | 0xef /0x61 /0xeb9 | `0xfffffe000847a7f0` -> `0xfffffe000c4ba84c` |
| Query old-node retirement | TL=`0xfffffe0007949dd0`, TR=`0xfffffe000792fbc0` | 0x16 /0x88 /0xea3 | `0xfffffe000847a878` -> `0xfffffe000c4ba368` |
| Query retirement descriptor | TL / TR | 0xd8 /0x20 /0x172; pool bias-4 | `0xfffffe0008472b90` -> `0xfffffe000847c2a0` |

Every rule is checked over256 original bank-byte inputs; controller snapshots remain arbitrary. The different query data-bank family and typed descriptor are recovered independently from the earlier parser-publication path, despite identical free-function targets.

| Return channel | Exact source contract |
| --- | --- |
| Index0x63d | `0xfffffe000a664218`; body sets W21=PHASE and loads C+0x260 |
| Constructor return | C+0x260=`0xfffffe000a664230` |
| Request return | Body at `0xfffffe000a664234` loads C+0x5a8, restores token registers and retains arbitrary W23 |
| First callback | `0xfffffe000a656f8c`; SUCCESS selects the second request |
| Second callback | `0xfffffe000a657018`; SUCCESS selects the third request |
| Third callback | `0xfffffe000a65f358`; SUCCESS supplies H and auxiliary output aliases to the existing serializer entry |

The source publication proofs retain an arbitrary64-bit request callback across list mutation and helper-return cuts. Separate return checks instantiate all three known callbacks. Twelve predecessor rechecks include the exact three callback status splits and the third-success serializer-alias handoff. Full failure-cleanup effects and success of native calls remain outside this increment.

## Finite-list composition and minimum auxiliary extent

Under QP-A6/QP-A7, the source effects implement this finite logical-list operation:

```text
find the first node whose recovered tagcontrol equals requested_tag
if found: replace that node in the same position with J; retire the old node
otherwise: append J
return raw SUCCESS through the saved request callback
```

This pseudocode summarizes the proved selected effects; it is not a native execution trace. Its search costs O(k) for k traversed nodes, mutation/retirement request count is O(1), and additional local state is O(1), excluding allocator implementations. Every selected visited-node comparison consumes four protected header bytes under the established readable-header premise.

The three requested tag controls are distinct:0x33b7bc52,0xb0ac8a39,0xa024e3ab. Their known14 B records are source-established in the predecessor. The four separate composition formulas establish:

1. A matching old node with target tag cannot be an earlier new node whose stable tag differs.
2. For arbitrary finite prefix/suffix sequences, replacing one node retains every different node, contains J and preserves list length.
3. Appending J retains every previous node, contains J and increases list length by one.
4. With three retained14 B records and nonnegative other-byte sum R, accepted sizing gives the minimum extent and copy-length bound below.

Induction over the three successful constructions therefore retains one new node for each requested tag, even if old duplicate tags remain. Replacements retain their old list positions; absent tags are appended in request order. The final three nodes need not be adjacent or occur in request order when some replace existing nodes. The source does not establish a particular initial list or a unique final byte stream.

Let L=42+R B, with R>=0 the sum of other retained extents. Under the accepted-size domain L<=0xffffffe5 B:

```text
P = 16 - ((L + 10) mod 16) B
M = L + 10 + P B
M >= 64 B
R=0 -> L=42 B, P=12 B, M=64 B
admitted auxiliary copy -> N=low32(original argument)=M >=64 B
```

R=0 concerns the other-byte sum, not necessarily the absence of zero-extent nodes. Overflow or size rejection remains possible for other lists; this minimum does not guarantee successful allocation/publication/copy. The prior [transfer boundary](userclient_transfer_boundary_report.md) distinguishes the core result from provider copy-out requests and external status selection. This report's N>=64 bound applies to the successful auxiliary-copy equality gate after three successful constructions, not a universal provider error-code rule or measured native response length.

## Original private table mapping

| Index | Original slot | Target |
| --- | --- | --- |
| 0x6c | `0xfffffe0008473280` | `0xfffffe000a662b64` |
| 0x181 | `0xfffffe0008473b28` | `0xfffffe000a63d624` |
| 0x22f | `0xfffffe0008474098` | `0xfffffe000a656ef0` |
| 0x40b | `0xfffffe0008474f78` | `0xfffffe000a663da4` |
| 0x50c | `0xfffffe0008475780` | `0xfffffe000a662c60` |
| 0x50d | `0xfffffe0008475788` | `0xfffffe000a662c44` |
| 0x52d | `0xfffffe0008475888` | `0xfffffe000a662c00` |
| 0x554 | `0xfffffe00084759c0` | `0xfffffe000a663e94` |
| 0x569 | `0xfffffe0008475a68` | `0xfffffe000a663eb0` |
| 0x630 | `0xfffffe00084760a0` | `0xfffffe000a662be0` |
| 0x63d | `0xfffffe0008476108` | `0xfffffe000a664218` |
| 0x63e | `0xfffffe0008476110` | `0xfffffe000a662b00` |
| 0x6fb | `0xfffffe00084766f8` | `0xfffffe000a663f78` |
| 0x782 | `0xfffffe0008476b30` | `0xfffffe000a663da4` |
| 0x79a | `0xfffffe0008476bf0` | `0xfffffe000a663d80` |
| 0x871 | `0xfffffe00084772a8` | `0xfffffe000a664074` |
| 0x88f | `0xfffffe0008477398` | `0xfffffe000a663e50` |
| 0x8a4 | `0xfffffe0008477440` | `0xfffffe000a663dfc` |
| 0x8dc | `0xfffffe0008477600` | `0xfffffe000a663dd8` |
| 0x9f4 | `0xfffffe0008477ec0` | `0xfffffe000a663f78` |
| 0xa01 | `0xfffffe0008477f28` | `0xfffffe000a663ef0` |
| 0xa0b | `0xfffffe0008477f78` | `0xfffffe000a663e2c` |
| 0xd20 | `0xfffffe0008479820` | `0xfffffe000a6654e0` |
| 0xd6a | `0xfffffe0008479a70` | `0xfffffe000a662bc4` |
| 0xe07 | `0xfffffe0008479f58` | `0xfffffe000a637138` |
| 0xe91 | `0xfffffe000847a3a8` | `0xfffffe000a63d680` |
| 0xeb6 | `0xfffffe000847a4d0` | `0xfffffe000a662c44` |

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| QP-A1: Only the pinned original and normalized images are covered | QP1-QP7 | Complete containing-function hash,427 selected words,29 terminal transfers,27 original pointers, descriptors and original bank bytes; recapture for another build |
| QP-A2: Modeled AArch64 u32/u64 operations, address arithmetic and protected byte reads apply | QP1-QP7 | Arbitrary tags/status/extent/addresses,75 nonvacuous source formulas,1,024 bank cases and changed append-store SAT control |
| QP-A3: Selected F/C/S/H/J/O/neighbor storage is valid, nonwrapping and separate at each admitted phase | QP1-QP6 | Exact read/write addresses, interval constraints, node/callback/data custody; native capacity/identity remains unknown |
| QP-A4: Same frame/context epoch, stable F+0x348 and declared predecessor phase/state cuts apply | QP1-QP7 | Original producer, three literal slot accesses, exact output/result aliases and predecessor request/callback rechecks; inspect indirect writes/aliases independently |
| QP-A5: Every visited old header is readable and nominal-pointer branch guards hold | QP1, QP7 | Exact four-byte decode/address obligations and four captured MOVK alternatives; local lookup does not itself prove capacity from node extent |
| QP-A6: Input list is coherent, finite and stable, new live allocations are distinct, and ordinary free-call cuts preserve surviving list/data/private state | QP3-QP7 | Empty/nonempty append, four replacement positions, eight old-data cases, fresh post-call field reads and explicit memory-effects cuts; inspect native ownership/synchronization and allocation identity |
| QP-A7: All three requests use the same H, complete successfully with stable distinct tags, and accepted sizing/copy uses that resulting list | QP7 | Source callback/serializer-alias rechecks, four separate finite-sequence/arithmetic lemmas and exact size/equality-gate rechecks; actual initial/final list, native call success and daemon pairing remain unknown |

## Bounded continuation and quality gates

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | Observed daemon/provider request and complete response tied to the same pinned image, selector and endpoint | Correlate native transaction bytes/counts with the recovered records and conditional64 B minimum |
| High | Actual H before/after the three requests and list ownership/synchronization | Determine replaced/retained/duplicate records, final order and exact L/M |
| High | Remaining failure cleanup at `0xfffffe000a664074` and allocator effects | Close unsuccessful-construction/lookup-status lifetimes and raw-status propagation |
| Medium | Native descriptor/allocation identity and free effects | Discharge the distinction between matching descriptor metadata and actual ownership |
| Medium | Indirect F+0x348 writes and frame/context epoch retention | Discharge the remaining output-slot phase premise |
| Medium | Daemon consumers of the three tags, type0xa129 and scalar0x99ab | Determine field semantics through independent source rather than numerical resemblance |
| Low | Other callers of the shared lookup and query callback | Identify independently verifiable format/control touch points |

Extraction takes O(B+I+256R) time/space for consumed image bytes B, instructions I and R=4 bank rules. Formula construction takes O(instruction instances+query DAG); SMT search is separate with30 s/query limits. Finite-sequence composition formulas use logical node sequences, not native heap execution. Byte quantities, u16/u32/u64 field widths, zero-extension, big-endian predecessor records and integer padding are explicit. No new Mach port endpoint is allocated, emitted or identified by these internal list/retirement blocks.

- **QG1**: Claims are factual source/data/control/ABI analysis.
- **QG2**: QP-A1-QP-A7 identify dependencies and falsification probes.
- **QG3**: Output producer/search, status partition, both append cases, all four replacements, optional-data/typed retirement requests, saved returns and bounded list/serializer composition are covered; the full interface goal remains active.
- **QG4**: Node/data extents, source/query counts,32 B descriptor layout, u32-to-u64 retirement extent,42/64 B derivation, overflow domain and complexity are reproducible.
- **QG5**: Source producer versus stable-slot premise, local search versus finite-list termination, descriptor correspondence versus identity, effects cuts versus native calls, and internal copy gate versus provider status remain distinct.
- **QG6**: Dual-image capture,27 original pointers,75 nonvacuous source formulas, four separate composition formulas,12 predecessor rechecks,1,024 bank cases and the mutation counterexample support the stated bounds.
- **QG7**: Ranked continuation preserves native transaction pairing, actual list context, failure cleanup, ownership/synchronization, output-slot aliases and unresolved semantics.
