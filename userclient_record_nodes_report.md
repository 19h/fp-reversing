# Post-header record dispatch and FPTTLVNode construction

The selected nonempty parser path allocates a 32 B `site.FPTTLVNode`, clears two pointer-width fields, stores the decoded payload length plus a ten-byte header as a u32 extent, and requests a separate buffer of exactly that total size. Both allocation results have explicit null gates. Successful buffer allocation prepares metadata and enters a shared writer setup with the address of the new node's buffer field.

The metadata gate has a separate success bypass: encoded tag `0x31ae0066` and transformed type `0x6685` together select the existing parser success path without entering this node constructor. The control role is established; the business meaning of this pair is unknown. The post-header ABI is established conditionally at its return cut. Production of those metadata channels from staged input, complete node serialization, list insertion, cursor advancement, cleanup, external input identity and a successful daemon-kext exchange remain unknown.

## Primary evidence and validation

| Artifact | SHA-256 of decoded content | Coverage |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Pinned instructions and normalized data |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original instructions, chained pointers, allocation descriptor and symbol table |
| [Checks](triage_evidence/userclient_record_nodes_checks.json.zst) | `fd1e454922e399cca19d2b7a2757ce613c38a3f3cab48c2f3d5ccbc3e1cc5f69` | 16 spans, 358 selected instructions, 12 terminal transfers, three bank rules |
| [Audit](triage_evidence/userclient_record_nodes_audit.json.zst) | `d43c0b38851f5df6d375a5aacd08a5f1b5cb2b3d43b8e97b43036db171fb34fc` | 15 new nonvacuous UNSAT obligations, five predecessor rechecks, 2,102 proof instruction instances |

The [extractor](triage_evidence/recover_userclient_record_nodes.py) checks the selected words against both images and rechecks the complete 50,634-instruction `_PRnut72j9` container hash. It checks original bank bytes, original table/descriptor pointers, allocation-site strings, flags and size. A separate ten-instruction def-use envelope preserves X1 and SP between descriptor selection and saving, with stores only to two other stack cells. The [audit](triage_evidence/audit_userclient_record_nodes.py) covers all 358 selected PCs and all 768 inputs across three bank compositions. The [delivery verifier](triage_evidence/verify_userclient_record_nodes_delivery.py) reconstructs both receipts and checks publication custody.

Five frozen predecessor formulas are re-solved: parser entry retention, container initialization and the reader's protected tag/type/length decoding. These are formula rechecks with fresh enclosing-function custody, rather than complete predecessor replays. Four altered-evidence equality controls reject a changed instruction byte, descriptor size, size-gate description and complete-parser claim. They establish custody sensitivity. No target code executes, native PAC authentication is not tested and no IDB is changed.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| RN1 | Post-header cursor, tag, type and length return channels; separate outcome/status | RN-A1-RN-A3 |
| RN2 | Exact special tag/type success bypass and ordinary record path | RN-A1-RN-A3 |
| RN3 | Container/body/metadata retention and nullable container gate | RN-A1-RN-A3, RN-A6 |
| RN4 | Universal u32 payload-plus-ten gate | RN-A1-RN-A3 |
| RN5 | Original 32 B typed node descriptor and allocator request | RN-A1-RN-A4 |
| RN6 | Node-result gate, two zero pointer-width fields and exact total extent | RN-A1-RN-A5 |
| RN7 | Separate exact-size buffer allocation, result storage and null gate | RN-A1-RN-A5 |
| RN8 | Successful-buffer metadata preparation, shared writer ABI and first writer selection | RN-A1-RN-A6 |
| RN9 | Reader-layout correspondence, cost and external-interface limits | RN-A1-RN-A8 |

## Conditional metadata interface and control flow

C is the selected scratch base, S the source-state base and F the current SP epoch. H is the retained container, J the abstract typed-node result, Z the abstract buffer result and P the retained body pointer. T is the encoded tag channel, U the transformed u16 type and E the encoded payload length. Define `SUCCESS=0x31ae0066` and `L=E XOR SUCCESS`, with L an unsigned32 value. These are source roles; no native allocation identity is assumed.

At `0xfffffe000a63dcd4` through `0xfffffe000a63dd10` exclusive, the selected return cut uses W8=0x54d, W1=0x7795e642 and W3=0x886a1ca3. It copies the following channels, sets W10=1 and W23=SUCCESS, and branches to `0xfffffe000a6423c0`. Encoded tag T and raw success W23 are distinct channels even when their values coincide.

| Input cell | Width | Output / retained channel |
| --- | --- | --- |
| S+0xcf8 | 8 B | Updated cursor -> F+0xa80 |
| S+0xa18 | 4 B | T -> S+0xaec |
| S+0x2a0 | 2 B | U -> S+0xa08 |
| S+0xa64 | 4 B | E -> S+0x9e8 |
| W10 | 32 bits | Header outcome1 on this return; independent of T |
| W23 | 32 bits | Raw SUCCESS on this return |

The outcome gate at `0xfffffe000a6423c4` selects the metadata-kind gate for W10=1. With the same phase inputs but W10=0, it selects `0xfffffe000a662440`. Only these two outcome values are claimed. The kind gate at `0xfffffe000a6423f8` uses CMP/CCMP to require both T=SUCCESS and U=0x6685. Exactly that pair selects `0xfffffe000a6421b0`, the previously established success path. Every other tag32/type16 pair selects `0xfffffe000a642454`.

Under the predecessor reader's recovered encoding, encoded tag SUCCESS represents decoded tag zero. This does not identify a business field or establish that the special pair was read from a particular original input. Its success-bypass role is a separate result from the reader's ordinary type acceptance.

```text
post-header channels: cursor64, T32, U16, E32
                         |
                 valid outcome W10=1
                         |
          T==SUCCESS and U==0x6685 ?
             | yes                   | no
       parser success          retain H/P/metadata
                                     |
                                H != 0 ?
                                     |
                         L <= 0xfffffff5 ?
                                     |
                     typed node allocation, 32 B
                              J != 0 ?
                                     |
                 J[0]=0; J[8]=0; extent32=L+10
                                     |
                     data allocation, L+10 B
                              Z != 0 ?
                                     |
                 J.buffer=Z; prepare metadata
                                     |
                  shared writer setup -> first tag writer
                                     |
             serialization / payload copy / linking: open
```

The outcome, H-null and length-failure paths select `0xfffffe000a662440`. Node-null and buffer-null select `0xfffffe000a6622bc`. Selection of these failure continuations is proved; their cleanup and final status effects remain outside this increment.

## Record retention and size predicate

At `0xfffffe000a642458` through `0xfffffe000a6424c4` exclusive, the ordinary record path retains H at C+0x780, T at S+0x128, U at S+0xb90 and E at S+0xe28/in W22. It copies S+0x2ac into S+0xdf8, S+0xbb8 into F+0xbe0 and P from C+0x280 into C+0x348. The selected premises give S+0x2ac=SUCCESS and S+0xbb8=0x688dbcd0b072e922; their wider producer/business meanings remain unknown. H is tested before constructor allocation. W23 is set to0xce515bbf in this retention block.

The obfuscated arithmetic at `0xfffffe000a6424cc` through `0xfffffe000a642544` exclusive is reduced over every possible E32. Its CMN32/CSET-lo predicate is exactly:

```text
L = E XOR 0x31ae0066
pass = unsigned32(L) <= 0xfffffff5
total32 = L + 10                 [used on the passing path]
total64 = zero_extend32(total32) = zero_extend32(L) + 10
```

The greatest admitted L is 4,294,967,285 B; its total is 4,294,967,295 B. L=0 gives total10 B. L=0xfffffff6 through0xffffffff select the failure continuation. These are exact integer limits, without rounding. The constructor guard concerns representability of a u32 sum; the [reader](userclient_input_reader_report.md) separately uses widened64 extent predicates. No native allocation success at any particular size is inferred.

## Original allocation metadata and node fields

The descriptor root at `0xfffffe000a636490` through `0xfffffe000a6364cc` exclusive uses the TL/TR bank pair and pool index0x179. Original slot `0xfffffe0008472ac8` yields `0xfffffe000847c02c`; subtraction of12 at `0xfffffe000a6364f4` gives the descriptor address saved at F+0x858. X1 retention across the intervening ten instructions is checked. Retention of that saved cell through the complete intervening dispatcher is a phase/storage premise.

| Descriptor property | Original evidence |
| --- | --- |
| Address | `0xfffffe000847c020` |
| Name | `site.FPTTLVNode` |
| Signature | `1121` |
| Flags | u32 0x64 |
| Declared size | u32 32 B |
| Name / signature pointer offsets | +0x10 / +0x20; original fixups and string bytes checked |
| Flags / size offsets | +0x28 / +0x2c |

At `0xfffffe000a6425cc`, BLRAA requests `_IOMallocTypeImpl` at `0xfffffe000c4ba154`, with X0=the descriptor and modifier0xd0c8. The ordinary return cut havocs X0-X18/X30 and preserves callee-saved registers, SP and retained cells as explicit premises. The source stores result J at C+0x6b8. J==0 selects `0xfffffe000a6425fc`, whose captured block saves J at F+0x50, reloads W23 from F+0x9ec and selects the common allocation-failure target. The native domain of that saved status remains unknown.

For nonnull writable J, the initializer at `0xfffffe000a642630` through `0xfffffe000a642760` exclusive proves:

| Node offset | Width | Established constructor action / reader relationship |
| --- | --- | --- |
| +0x00 | 8 B | Zero store at `0xfffffe000a6426d8`; reader uses this offset as next pointer |
| +0x08 | 8 B | Zero store at the same STP; further semantic role unknown |
| +0x10 | 4 B | Store L+10 at `0xfffffe000a64275c`; reader accesses extent at this offset |
| +0x14 | 4 B | No write by the captured initializer stores; padding/other semantics unknown |
| +0x18 | 8 B | Buffer result Z stored at `0xfffffe000a6427c8`; reader accesses buffer here |

The separate 64-bit arithmetic channel written at S+0x100 is exactly `zero_extend32(L)+0x41a549061921706d` modulo2^64, proved for every E32. Its downstream role remains unknown. The original typed name, size and field offsets support correspondence with the reader's 32 B-accessed node layout. They do not establish that the reader reaches this particular runtime allocation; list publication and epochs remain open.

## Buffer request and shared writer handoff

The buffer call at `0xfffffe000a6427c0` requests `_IOMallocData` at `0xfffffe000c4ba60c`, modifier0xca0c, with X0=zero_extend32(L)+10. The saved allocation-site node pointer survives the ordinary call cut in X27. The result is stored at J+0x18 and J is retained at F+0x50. Null Z selects `0xfffffe000a6622bc`; nonnull Z selects `0xfffffe000a64280c`. The block starting at `0xfffffe000a642810` is therefore successful-buffer preparation.

That block sets X16=J+0x18 and W23=T XOR0x14ac30f9. At `0xfffffe000a642860`, the outgoing private ABI has X0=0x02e859d27e491464, X3=S, X11=C, X16=J+0x18, W1=SUCCESS and modifier0xdfc5, targeting `0xfffffe000a654ad4`. This establishes a writer request, not an already completed buffer write.

The captured writer setup at `0xfffffe000a654ad8` through `0xfffffe000a654b94` exclusive reloads J from C+0x6b8, saves it again at F+0x50, sets X10=J+0x18 and preserves X16=J+0x18. It transforms the saved length channel into W7=E XOR0x14ac30f9. It prepares W19=(zero_extend16(U)>>8) XOR0x36 and W30=zero_extend16(U) XOR0x5e. The low bytes of these type channels correspond to U XOR0x365e; actual protected header stores are outside this proof. Other retained pointer/scalar channels read by this setup are arbitrary symbolic cell values, rather than assumed identities. The setup selects first tag-writer entry `0xfffffe000a654c64` with modifier0x682a.

| Bank use | Roots | Key / constant / additive | Original selected slot / target |
| --- | --- | --- | --- |
| Node descriptor | TL=`0xfffffe0007949dd0`, TR=`0xfffffe000792fbc0` | 0x16 / 0x88 / 0xf1; pool, bias-12 | `0xfffffe0008472ac8` -> `0xfffffe000847c020` after bias |
| Typed allocation | TL / TR | 0x5c / 0xd2 / 0xe41; table | `0xfffffe000847a7b8` -> `0xfffffe000c4ba154` |
| Data allocation | SL=`0xfffffe0007941f60`, SR=`0xfffffe000794a0d0` | 0x05 / 0x2d / 0xee3; table | `0xfffffe000847a7a0` -> `0xfffffe000c4ba60c` |

SL and SR are derived from pool+0xc08 minus8 and pool+0x158 minus4. They are a distinct bank pair from TL/TR. All three bank identities admit every8-bit controller input. Original allocation pointers carry diversity0xd0c8/0xca0c respectively; capture of PAC metadata does not establish native authentication.

## Original private table mapping

Indices identify private dispatcher entries, not Mach message IDs or IOUserClient selectors. The same target can have different index/continuation roles; the post-header return's0x54d and the predecessor parser's0x560 both target `0xfffffe000a6423c0` with different incoming state.

| Private index | Original slot | Target |
| --- | --- | --- |
| 0x238 | `0xfffffe00084740e0` | `0xfffffe000a64262c` |
| 0x23c | `0xfffffe0008474100` | `0xfffffe000a6425fc` |
| 0x439 | `0xfffffe00084750e8` | `0xfffffe000a654c64` |
| 0x449 | `0xfffffe0008475168` | `0xfffffe000a6421b0` |
| 0x46d | `0xfffffe0008475288` | `0xfffffe000a642454` |
| 0x4a9 | `0xfffffe0008475468` | `0xfffffe000a662440` |
| 0x4ba | `0xfffffe00084754f0` | `0xfffffe000a642548` |
| 0x543 | `0xfffffe0008475938` | `0xfffffe000a654ad4` |
| 0x54d | `0xfffffe0008475988` | `0xfffffe000a6423c0` |
| 0x766 | `0xfffffe0008476a50` | `0xfffffe000a64280c` |
| 0x7ad | `0xfffffe0008476c88` | `0xfffffe000a6622bc` |
| 0x88c | `0xfffffe0008477380` | `0xfffffe000a6423f4` |
| 0xc88 | `0xfffffe0008479360` | `0xfffffe000a6424c8` |
| 0xcb2 | `0xfffffe00084794b0` | `0xfffffe000a662440` |

## Architectural boundary and cost

This increment connects the conditional post-header metadata interface to original typed node and data-buffer allocation and a selected writer handoff. No new incoming/outgoing Mach right, port endpoint, message emission site or successful daemon-kext transaction is established. Existing endpoint/transport evidence remains in [Mach ports](mach_ports_report.md), [interface ABI](interface_abi_report.md) and [investigation status](interface_investigation_status.md). A retained payload pointer is not by itself proof of external controllability.

The selected constructor requests32+(L+10)=L+42 B across two allocations, excluding the earlier16 B container, staging buffer, allocator metadata and failure-path reclamation. Its selected arithmetic/field stores take O(1) time and O(1) auxiliary space, excluding allocator cost and later serialization. No complete nonempty-parser time/space bound is claimed. Extraction costs O(B+I+256R) time/space; proof construction costs O(instruction instances+query DAG), with separate SMT search and30 s/query limits. All sizes are bytes; bit widths and wrap domains are explicit.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RN-A1: Pinned images, original pointer metadata/symbols and predecessor receipts | RN1-RN9 | Fresh dual-image/full-container custody, descriptor strings/scalars, original bank bytes, reconstructed formulas and altered-evidence controls |
| RN-A2: Selected phase constants, bank roots and stable C/S/F epochs; saved F+0x858 survives intervening dispatcher | RN1-RN9 | Follow incoming paths and escaped aliases; local descriptor selection/ten-instruction retention does not prove whole-path cell preservation |
| RN-A3: AArch64 W/X, CCMP and carry semantics match the modeled bit vectors | RN1-RN4, RN6-RN9 | Universal tag32/type16/length32 obligations and all-result64 gates; independently execute instructions if native semantic confirmation is required |
| RN-A4: Ordinary allocation calls preserve callee-saved/SP/retained cells | RN5-RN8 | Original symbols, descriptors and call modifiers; caller-saved havoc; recover native callee effects and allocation semantics |
| RN-A5: Nonnull J provides writable32 B, separated from stable frame/scratch/source/container storage | RN6-RN9 | Explicit nonwrapping/disjoint extents and source-store widths; establish actual allocation validity, aliases, ownership and free pairs |
| RN-A6: Post-header channels and body/container cells have the stated incoming values; other writer-setup cells are arbitrary stable values | RN1-RN3, RN8, RN9 | Recover metadata producers from staged bytes, cursor/body bounds and actual caller epochs; trace list publication into the reader |
| RN-A7: Reader layout correspondence is structural; semantic tag identity, serialization, payload termination and runtime linkage remain unknown | RN9 | Follow selected writer entries, payload copy, list insertion, iterator/cursor and field consumers; compare actual protected header production with the reader |
| RN-A8: Failure-target selection does not establish cleanup/final status, locking, native external control or daemon correlation | RN9 limits | Trace allocation-failure paths and saved status, ownership/locks and correlated provider/user-client transactions |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | First writer `0xfffffe000a654c64` and following header/type/length stores | Establish actual protected ten-byte header production and compatibility with the reader |
| High | Payload copy, node linking and cursor advancement after writer completion | Connect staged input to the container's reachable node list and establish record bounds |
| High | Allocation-failure continuations `0xfffffe000a662440` and `0xfffffe000a6622bc` | Establish cleanup, retained-node ownership and status propagation |
| High | Metadata producer into S+0xa18/S+0x2a0/S+0xa64 and body C+0x280 | Close post-header cuts, byte provenance and original field identity |
| High | Actual input caller and successful daemon/provider exchange | Establish external influence and cross-layer transaction correlation |
| Medium | Other parser callers and special-pair producer | Determine reuse and business meaning without inferring it from a magic value |
| Low | Additional syntax inventories of node aliases | Guide later alias recovery without substituting counts for data-flow proofs |

## Quality gates

- **QG1**: All claims concern factual source and interface behavior.
- **QG2**: RN-A1-RN-A8 state dependencies and falsification probes.
- **QG3**: Conditional metadata dispatch, size guard, typed descriptor, node initialization, buffer allocation and writer handoff are covered; the wider investigation remains active.
- **QG4**: u16/u32/u64 channels, unsigned carry, exact limits, modulo arithmetic, byte extents and scoped costs are explicit.
- **QG5**: Outcome/status/tag, special bypass/ordinary record, successful/null allocation, phase-specific roots, layout/runtime identity and handoff/completed serialization are distinguished.
- **QG6**: Original words/fixups/symbols/descriptor, 15 nonvacuous formulas, five predecessor rechecks, 768 bank inputs and four custody controls support the stated scope.
- **QG7**: Ranked continuation preserves producer, writer, copy/link/cursor, failure ownership and daemon-correlation questions.

## Protected record-writer increment

The [writer follow-up](userclient_record_writer_report.md) closes the selected ten-byte header stores and, for transformed type0x6685, the exact-L protected payload copy. It proves saved-control roots, the zero-copy gate, universal loop step and finite coverage. Metadata/body production, other type handlers, actual list publication and cleanup remain open.
