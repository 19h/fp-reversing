# Record lookup, append/replacement and retirement requests

The selected post-copy path looks up the new record's encoded tag in the retained FPTTLV container. Lookup miss appends the new node; lookup success replaces the returned matching node. The source establishes next at node+0, previous at node+8, head at container+0 and tail at container+8. Empty/nonempty append and all four replacement positions are covered. Replacement issues original data/typed retirement requests for the old node and clears its saved result cell before returning to the parser cursor gate.

This closes selected list publication after the [protected writer](userclient_record_writer_report.md). It does not close the original staged-input metadata/body producers, cursor advancement, every type/failure path, native ownership or synchronization, or a successful daemon-kext exchange. The full interface goal remains active.

## Primary evidence and validation

| Artifact | SHA-256 of decoded content | Coverage |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Pinned instructions and normalized data |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original instructions, chained pointers, symbols and two allocation-site descriptors |
| [Checks](triage_evidence/userclient_record_publication_checks.json.zst) | `4b157c18d0acd48c69026544f558fb8d592cb90e1f0df1763cef9a6adb6aca09` | 34 spans, 466 selected instructions, 29 terminal transfers, three bank rules |
| [Audit](triage_evidence/userclient_record_publication_audit.json.zst) | `021b332b5e5fb87a033c015fc17547366499957d189d448224e5452279358bef` | 69 new nonvacuous UNSAT obligations, five predecessor rechecks, 5,632 proof instruction instances |

The [extractor](triage_evidence/recover_userclient_record_publication.py) compares selected words with both images and rechecks the complete 50,634-instruction `_PRnut72j9` container hash. Ten selected spans reuse the previously recovered reader/search source; the new proofs bind it to this caller's arbitrary requested tag, output cell and return continuation. All 466 selected PCs and all 768 inputs across three bank compositions are checked. Four alternate lookup retags have separate pointer-bit proofs. The [audit](triage_evidence/audit_userclient_record_publication.py) covers two append cases, four replacement positions and eight null/non-null old-buffer retirement cases.

Five frozen predecessor formulas are re-solved: complete header preservation, the writer's universal payload step and finite reverse-index certificate, and the reader's tag-match/callback formulas. These are formula rechecks, not a fresh complete writer replay in this increment. Four altered-evidence equality controls reject a changed instruction byte, descriptor size, bank constant and unsupported native-ownership claim. They test custody sensitivity. The [delivery verifier](triage_evidence/verify_userclient_record_publication_delivery.py) reconstructs the receipts and publication custody. No target code executes, no native PAC authentication is tested and no IDB is changed.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| RP1 | Original output-cell alias and selected retained bank-root stores | RP-A1-RP-A3 |
| RP2 | Caller-specific tag lookup/output/continuation ABI | RP-A1-RP-A4 |
| RP3 | Arbitrary-tag match/successor step, empty/matched results and original retirement descriptor | RP-A1-RP-A5 |
| RP4 | Success, miss and other-status dispatch | RP-A1-RP-A3 |
| RP5 | Empty-container and tail-append field stores | RP-A1-RP-A4, RP-A6 |
| RP6 | Sole/head/tail/interior replacement field stores | RP-A1-RP-A4, RP-A6 |
| RP7 | Old-buffer gate, original retirement calls, old-result clear and return | RP-A1-RP-A3, RP-A6, RP-A7 |
| RP8 | Unchanged cursor and exact parser continuation predicate | RP-A1-RP-A3, RP-A7 |
| RP9 | Descriptor correspondence, cost and architectural limits | RP-A1-RP-A8 |

## Post-copy lookup interface

C is the scratch base, S the source-state base and F the current SP epoch. H is the retained16 B container, J the new32 B node, O a returned old node, P its previous node and N its next node. T is the encoded requested tag32. The [constructor](userclient_record_nodes_report.md) and writer establish the selected input cells and initialized new links; this increment uses those as composition premises. Native allocation identity is not inferred from the symbolic objects.

At `0xfffffe000a635e5c`..`0xfffffe000a635e64` exclusive, the original source forms C+0x628 and saves that address at F+0x350. Separate captured stores retain FL/FR roots at F+0xa00/F+0xa20 and TL at F+0xa48. Their source-register root identities and retention through intervening dispatcher epochs remain explicit premises.

The post-copy body at `0xfffffe000a655ef4`..`0xfffffe000a655f6c` exclusive clears C+0x628, loads H from C+0x780, T from S+0x128 and the output address from F+0x350. It requests the same private search used by the [reader](userclient_input_reader_report.md), with a different output/return pair.

| Input / retained cell | Width | Selected caller meaning |
| --- | --- | --- |
| X22 at lookup entry | pointer64 | H |
| W9 at lookup entry | value32 | T |
| X10 at lookup entry | address64 | C+0x628 |
| W8 at lookup entry | index32 | 0x7b |
| C+0xc8 | address64 | Retained table[0x7b]=`0xfffffe000a66248c` |
| S+0 | value32 | Retained requested tag T |
| C+0x758 | address64 | Retained output address C+0x628 |
| C+0x2b0 | pointer64 | Current search node |
| C+0x628 | pointer64 | Caller-specific old-node result |
| X22 after search callback | address64 | Retirement descriptor `0xfffffe000847bce0`; register role has changed |

The selected caller reloads W1=0x7795e642, W3=0x886a1ca3 and W30=0x31ae0066, and retains the matching reader protection keys. Its nonnull H gate enters `0xfffffe000a662be0`. Empty H.head yields zero output and status0xce515bda. For a readable protected node header, the decoder recovers its encoded tag, compares it with arbitrary T, and either returns that node with raw success0x31ae0066 or follows next+0 and repeats the node gate. The proofs cover the exact local search step; whole-list termination requires a finite stable acyclic input list and readable headers.

## Lookup status and append

| Lookup result at `0xfffffe000a66248c` | Source action |
| --- | --- |
| W23==0x31ae0066 | Enter replacement at `0xfffffe000a662538`; C+0x628 supplies O |
| W23==0xce515bda | Enter append at `0xfffffe000a6624b0` |
| Other W23 | Save J at F+0x50 and select cleanup frontier `0xfffffe000a6622bc`; cleanup body remains open |

The status partition is local to this return. W23 is subsequently reused through X23 as the saved old-result address in replacement. Append also need not set raw success before resuming the parser. These register values must not be treated as a universal status contract across later phases.

For a coherent empty list, H.head=H.tail=0 and J.next=J.previous=0. The source STP at `0xfffffe000a662878` publishes J into both H fields. For nonempty append, Q=H.tail is a valid separate node with Q.next=0. Stores at `0xfffffe000a662514`, `0xfffffe000a66251c` and `0xfffffe000a662520` set Q.next=J, J.previous=Q and H.tail=J. J.next remains0; H.head is unchanged. The local store proofs retain an arbitrary existing head in the nonempty case rather than assuming it equals the tail.

```text
empty append:   H(head=0, tail=0)  -> H(head=J, tail=J)

tail append:    ... <-> Q          -> ... <-> Q <-> J
                         tail                      tail

replacement:   ... <-> P <-> O <-> N <-> ...
                         |
               ... <-> P <-> J <-> N <-> ...
               boundary cases update H.head and/or H.tail
```

## Four replacement positions

The source first copies O.previous into J.previous at `0xfffffe000a662568`, and O.next into J.next at `0xfffffe000a662570`. It then updates surviving neighbor links and only the affected container boundary. The old node and new node are distinct valid allocations in these premises. The proof's old head is arbitrary when P is nonnull, and its old tail is arbitrary when N is nonnull; it does not reduce every position to a one-node list.

| Position | Old P / N | Surviving-list effects |
| --- | --- | --- |
| Sole | 0 / 0 | H.head=J; H.tail=J; J.previous=J.next=0 |
| Head | 0 / nonzero | H.head=J; N.previous=J; old H.tail unchanged |
| Tail | nonzero / 0 | P.next=J; H.tail=J; old H.head unchanged |
| Interior | nonzero / nonzero | P.next=J; N.previous=J; H.head/H.tail unchanged |

| Store | Original PC |
| --- | --- |
| P.next=J | `0xfffffe000a66258c` |
| N.previous=J | `0xfffffe000a6625e4` |
| H.head=J when J.previous==0 | `0xfffffe000a662644` |
| H.tail=J when J.next==0 | `0xfffffe000a662698` |

The source replaces the returned matching node. It does not prove that the original list contains unique tags, remove all preexisting duplicate tags, or establish a global list invariant under concurrent mutation. Interpreting the local rewiring as preservation of a complete list requires the stated coherent, stable input-list premise.

## Retirement requests and descriptor correspondence

After the surviving links are rewired, the source reloads O through the saved result address X23=C+0x628 and tests O.buffer at+0x18. Null skips data retirement; nonnull requests `_IOFreeData`. Both paths request `_IOFreeTypeImpl` for O. Each ordinary call cut havocs X0-X18/X30 and preserves SP, callee-saved registers and the retained live state as explicit premises. No native allocator/free side effects are simulated.

| Request | Original call PC | Selected target / modifier | Argument registers |
| --- | --- | --- | --- |
| `_IOFreeData` | `0xfffffe000a66275c` | `0xfffffe000c4ba84c` / 0x085d | X0=old buffer; X1=zero_extend32(O.extent at+0x10) |
| `_IOFreeTypeImpl` | `0xfffffe000a6627e4` | `0xfffffe000c4ba368` / 0x4d6a | X0=retirement descriptor; X1=O |

The captured data-return span reloads O and clears O.buffer at `0xfffffe000a66277c` before the typed retirement request. The typed-return span clears the saved result cell C+0x628 at `0xfffffe000a662800`; captured caller instructions do not dereference O after the typed call returns. The proofs then observe surviving H/J/neighbor/frame state. Old storage is required to be accessible only through the typed-retirement request; no claim is made that it remains valid afterward. Native ownership, aliases, double-free prevention and callee effects remain unknown.

| Descriptor property | Allocation site | Retirement site |
| --- | --- | --- |
| Address | `0xfffffe000847c020` | `0xfffffe000847bce0` |
| Name | `site.FPTTLVNode` | `site.FPTTLVNode` |
| Signature | `1121` | `1121` |
| Flags | u32 0x64 | u32 0x64 |
| Size | u32 32 B | u32 32 B |

The two normalized64-byte metadata blocks match, but their addresses differ. Original name/signature fixups, string bytes and scalar fields are checked at both sites. This supports a matching declared allocation/retirement layout, not runtime allocation identity or interchangeable native descriptor bookkeeping.

| Bank use | Roots | Key / constant / additive | Selected original slot / target |
| --- | --- | --- | --- |
| Callback retirement descriptor | FL=`0xfffffe000792fcc0`, FR=`0xfffffe00079391f0` | 0x87 / 0xdf / -0x93; pool, bias-4 | `0xfffffe0008472160` -> `0xfffffe000847bce0` after bias |
| Data retirement | SL=`0xfffffe0007941f60`, SR=`0xfffffe000794a0d0` | 0x98 / 0x95 / 0xe85; table | `0xfffffe000847a7f0` -> `0xfffffe000c4ba84c` |
| Typed retirement | TL=`0xfffffe0007949dd0`, TR=`0xfffffe000792fbc0` | 0x73 / 0x47 / 0xee4; table | `0xfffffe000847a878` -> `0xfffffe000c4ba368` |

Each bank composition is checked over all256 possible byte inputs from original bank bytes. Callback selection produces the retirement descriptor in X22 even for an empty search; that register no longer holds H. Original pointer diversity is checked separately from native authentication. The allocation-site descriptor in the constructor is a distinct address and selection rule.

## Parser return and cursor boundary

Empty append, nonempty append and every modeled replacement/retirement path select `0xfffffe000a642138`. The cursor F+0xa80 is unchanged by these captured publication paths. The next local predicate is exactly `unsigned64(cursor) < zero_extend32(outer_length)` to enter `0xfffffe000a6421dc`, otherwise `0xfffffe000a642180`. The encoded outer length is retained at S+0xc8c and is distinct from an individual payload length L.

This establishes a return to the existing parser gate with the same cursor, not cursor advancement. The earlier producer of S+0xcf8/F+0xa80 must still show how a record changes the cursor and how header/body bounds relate to the complete staged envelope. A syntactically present backedge does not prove parser termination or complete nonempty-input correctness.

## Original private table mapping

| Private index | Original slot | Target |
| --- | --- | --- |
| 0x7b | `0xfffffe00084732f8` | `0xfffffe000a66248c` |
| 0x181 | `0xfffffe0008473b28` | `0xfffffe000a63d624` |
| 0x22f | `0xfffffe0008474098` | `0xfffffe000a656ef0` |
| 0x376 | `0xfffffe0008474ad0` | `0xfffffe000a6625a0` |
| 0x377 | `0xfffffe0008474ad8` | `0xfffffe000a662654` |
| 0x49a | `0xfffffe00084753f0` | `0xfffffe000a662ab4` |
| 0x50c | `0xfffffe0008475780` | `0xfffffe000a662c60` |
| 0x50d | `0xfffffe0008475788` | `0xfffffe000a662c44` |
| 0x52d | `0xfffffe0008475888` | `0xfffffe000a662c00` |
| 0x57f | `0xfffffe0008475b18` | `0xfffffe000a6625d0` |
| 0x582 | `0xfffffe0008475b30` | `0xfffffe000a6625f4` |
| 0x5cb | `0xfffffe0008475d78` | `0xfffffe000a66278c` |
| 0x630 | `0xfffffe00084760a0` | `0xfffffe000a662be0` |
| 0x63e | `0xfffffe0008476110` | `0xfffffe000a662b00` |
| 0x765 | `0xfffffe0008476a48` | `0xfffffe000a6626a8` |
| 0x7ad | `0xfffffe0008476c88` | `0xfffffe000a6622bc` |
| 0x87f | `0xfffffe0008477318` | `0xfffffe000a6421dc` |
| 0x891 | `0xfffffe00084773a8` | `0xfffffe000a642138` |
| 0x893 | `0xfffffe00084773b8` | `0xfffffe000a642180` |
| 0x8e0 | `0xfffffe0008477620` | `0xfffffe000a662584` |
| 0x8ee | `0xfffffe0008477690` | `0xfffffe000a6625a0` |
| 0x8f9 | `0xfffffe00084776e8` | `0xfffffe000a662684` |
| 0x963 | `0xfffffe0008477a38` | `0xfffffe000a662634` |
| 0x9e8 | `0xfffffe0008477e60` | `0xfffffe000a662700` |
| 0xa0d | `0xfffffe0008477f88` | `0xfffffe000a66278c` |
| 0xdb9 | `0xfffffe0008479ce8` | `0xfffffe000a66286c` |
| 0xdbb | `0xfffffe0008479cf8` | `0xfffffe000a6624f4` |
| 0xe07 | `0xfffffe0008479f58` | `0xfffffe000a637138` |
| 0xe91 | `0xfffffe000847a3a8` | `0xfffffe000a63d680` |
| 0xeb6 | `0xfffffe000847a4d0` | `0xfffffe000a662c44` |

Indices are private dispatcher selectors, not Mach message IDs or IOUserClient selectors. The mapping includes lookup, decoder, list-update, retirement and parser-return branches. Captured transfers and pointer metadata are separate from source arithmetic proofs; native PAC/BTI behavior remains outside the model.

## Architectural scope and cost

The recovered selected operation is tag lookup followed by append-on-miss or replacement-on-success, with explicit old-record retirement requests. It connects the writer's J to the container's source-level linked-list representation under stable caller/storage premises. Original field identity, staged-envelope parsing/cursor progress, native lifecycle/locking and successful daemon/provider exchange remain open. No new Mach right, port endpoint, message emission site or correlated daemon-kext transaction is established. External-interface evidence remains in [Mach ports](mach_ports_report.md), [interface ABI](interface_abi_report.md) and [investigation status](interface_investigation_status.md).

For a finite stable list containing k examined nodes with readable headers, repeated search steps take O(k) time and O(1) auxiliary state. The selected field rewiring takes O(1) work, as do the emitted retirement requests when excluding callee cost. This increment makes no new allocation request and no complete parser complexity claim. Extraction takes O(B+I+256R) time/space; proof construction takes O(instruction instances+query DAG), with SMT search separate and30 s/query limits. Sizes are bytes; tag/status fields are u32, pointers/cursor are u64 and the retirement extent argument explicitly zero-extends a u32 field.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RP-A1: Pinned images, original pointers/symbols/descriptors and predecessor receipts | RP1-RP9 | Fresh dual-image/full-container custody, both descriptor sites, reconstructed formulas and four altered-evidence controls |
| RP-A2: Selected post-copy phase inputs, stable C/S/F epochs and retained FL/FR/TL/SL/SR roots | RP1-RP9 | Original alias/root stores and fresh caller-specific lookup proofs; trace all incoming epochs, root producers and intervening aliases/calls |
| RP-A3: AArch64 W/X, status comparisons, pointer arithmetic and source load/store semantics match the model | RP1-RP9 | Arbitrary tag32/result pointers, all four positions, all buffer64 null gates and explicit u32-to-u64 extent proof |
| RP-A4: Valid H/J storage with distinct new node; predecessor writer fields and requested tag are retained | RP2, RP3, RP5, RP6 | Prior header/copy formulas plus current local stores; recover actual allocation epochs and complete input-to-node provenance |
| RP-A5: Finite stable readable old list, matching protection keys, normal decoder pointer branches | RP3, RP9 | Arbitrary-tag decode/match/successor step and alternate retag transforms; establish complete traversal invariants, native retag behavior and live reader linkage |
| RP-A6: Coherent head/tail and old neighbor relations, valid separate surviving neighbor nodes | RP5-RP7 | Empty/tail append and sole/head/tail/interior replacement with arbitrary preserved boundaries; validate native list invariants, uniqueness and concurrency separately |
| RP-A7: Retirement call cuts preserve callee-saved/SP and retained live H/J/neighbor/frame state; native effects remain open | RP7, RP8 | Exact original call targets/arguments, caller-saved havoc, old-result clear and surviving-state proofs; recover native callee/ownership/alias effects |
| RP-A8: Cursor advancement, full type/failure coverage, business tag identity, termination and daemon correlation remain unknown | RP8, RP9 limits | Trace metadata/body/cursor producers and cleanup frontier, other type handlers, lock epochs and successful correlated provider exchanges |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Post-header S+0xcf8 cursor producer and metadata/body producers | Close cursor advancement, record bounds and original staged-byte provenance |
| High | Common new-node cleanup `0xfffffe000a6622bc` | Recover rollback and allocation/free ownership on construction, type and lookup failures |
| High | Actual input caller and successful daemon/provider exchange | Establish external control and cross-layer correlation |
| High | Native ownership and synchronization across the selected list operation | Determine whether the source storage/call/list premises hold across real epochs |
| Medium | Other payload types and additional lookup callers | Extend the selected type0x6685 construction/publication contract without assuming equivalent handlers |
| Medium | Full finite-list traversal and duplicate-tag invariants | Establish whole-list behavior beyond the proved local comparison/successor step |
| Low | Descriptor bookkeeping differences despite matching normalized metadata | Refine native allocator type/site identity if the kernel facilities expose additional evidence |

## Quality gates

- **QG1**: Factual source, data-flow and interface claims require no normative conclusion.
- **QG2**: RP-A1-RP-A8 enumerate dependencies and falsification probes.
- **QG3**: Caller lookup ABI, append/replacement cases, emitted retirement requests, result clear and parser return are covered; the full objective remains active.
- **QG4**: u32 tag/status/extent, u64 pointer/cursor, zero extension, byte sizes and scoped costs are explicit.
- **QG5**: Encoded tag versus status, X22/X23 phase roles, arbitrary old boundaries versus sole-node inputs, descriptor metadata versus address identity, emitted requests versus native frees and unchanged cursor versus advancement remain distinct.
- **QG6**: Original dual-image words/pointers/symbols/descriptors, 69 nonvacuous formulas, five predecessor rechecks, 768 bank inputs and four custody controls support bounded claims.
- **QG7**: Ranked continuation retains input/cursor provenance, rollback/ownership, other types, traversal invariants and daemon-correlation requirements.

## Staged metadata and cursor increment

The [metadata follow-up](userclient_record_metadata_report.md) establishes this increment. The earlier metadata return now has selected staged-byte provenance: cursor advances by ten plus decoded payload length before node construction/publication. Publication itself still preserves that committed cursor; full native and cross-layer composition remain conditional.

## Parser cleanup increment

The [cleanup follow-up](userclient_parser_cleanup_report.md) establishes this increment. It recovers the separate selected pending-node and retained-container failure paths. The counterfactual other-status target-selection cut does not by itself supply the cleanup phase/storage premises.
