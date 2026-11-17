# Input staging and shared FPTTLV parser entry/return contract

Subsequent original-entry evidence: The [earlier node report](userclient_early_node_report.md) continues 60 exact predecessor prefixes through a fourth register-only allocation return. Original source retains the node, clears 16 B, publishes a 4 B extent and requests L+10 B from IOMallocData. Ten source proofs, 113172 independently interpreted visits and two rejected mutations pass. The pinned external typed wrapper masks incoming flags with 0x7. A synthetic NULL result stops before an unbacked load; native allocation effects/failure reachability, marker production and matched daemon/kext identity remain unknown. Earlier boundaries below retain their historical scopes.

Subsequent original-entry evidence: The [early header report](userclient_early_header_report.md) continues through declared input bytes in 72 private cases, with 48 exact predecessor prefixes, ten fresh source proofs and two rejected source mutations. It establishes the early BE header and scalar/span domains, conditional wire-field correspondence to staged decoding, zero-tag span success with an unread suffix, and the earlier 32 B FPTTLVNode request. Input custody and allocator returns are fixtures; node allocation/free bodies and matched native daemon/kext identity remain unknown. Earlier boundaries below retain their historical scopes.

Subsequent original-entry evidence: The [earlier FPTTLV entry report](userclient_fpttlv_entry_report.md) continues through the first 16 B allocation return in 84 private cases, preserving 72 predecessor prefixes exactly. Source zeroing, a ten-byte early header-fit gate, the first selected original-input byte at I+6, distinct empty/short cleanup cells and typed-retirement/staging-request frontiers are independently checked. Six source proofs and two rejected store-removal controls pass. No input-content read, native allocation/free or new Mach emission executes. Earlier boundaries below describe their historical increments; later staged objects and matched daemon/kext transactions remain separate open joins.

Subsequent entry evidence: The [entry-execution report](userclient_entry_execution_report.md) now derives the three saved arguments, the S/C allocation roots and the first pointer/size publications continuously from the compiler entry in 48 private cases. The non-NULL prefixes stop at the earlier FPTTLV allocation; the later staging/parser spans below remain conditional. No full intervening native epoch, input schema or transaction join is established.

The upstream path stages a saved input pointer using exactly the low32 size from the saved size argument. The allocation request, reverse-copy count and parser's decoded extent all recover that same u32 value N. The copy writes an address-keyed protected representation. The shared parser receives that staged pointer, an encoded extent, a caller output address and a private continuation. Its original typed-allocation descriptor names `site.FPTTLV`, declares 16 B and precedes two zeroed 64-bit fields.

For empty parser input, the selected path is complete: allocate the container, clear its two fields, skip record parsing, publish the container and resume the saved continuation with raw success. Nonempty parsing remains incomplete. The later [record-node increment](userclient_record_nodes_report.md) establishes conditional node/buffer construction from a post-header cut; metadata production, completed serialization and list publication remain open. The [hash-input reader](userclient_input_reader_report.md) later takes its incoming container from scratch+0x600. This increment establishes the staging and private parser interface; it does not establish the original tag's field identity, a termination guarantee, complete parser behavior, native object lifetime or a successful daemon-kext transaction.

## Primary evidence and validation

| Artifact | SHA-256 of decoded content | Coverage |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Pinned instruction/data image |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original words, typed descriptor, symbols and pointer-format-8 chains |
| [Checks](triage_evidence/userclient_container_staging_checks.json.zst) | `71cda6acf4e89a9f7849607d59aedc61618ec94f3071ddc08233d8cab7fe9ab1` | 28 spans, 488 selected instructions, 17 terminal transfers, three bank rules and six-cell literal-base inventory |
| [Audit](triage_evidence/userclient_container_staging_audit.json.zst) | `7b1b4bcd525575b1e976ed683a07e5a86fa041269346e6724a635f67621846d6` | 20 new nonvacuous UNSAT obligations, five predecessor formula rechecks, 2,181 proof instruction instances |

The [extractor](triage_evidence/recover_userclient_container_staging.py) compares selected instruction bytes with both images and rechecks the complete 50,634-instruction `_PRnut72j9` container hash. It captures original allocator pointers and the allocation descriptor's name/signature pointers, scalar metadata and string bytes. The [audit](triage_evidence/audit_userclient_container_staging.py) covers all 488 selected PCs, checks all 768 inputs across three bank compositions and separately proves the alternate MOVK pointer transform. The main copy proof assumes the source's normal pointer branch. The [delivery verifier](triage_evidence/verify_userclient_container_staging_delivery.py) reconstructs the evidence and checks publication custody.

Five frozen predecessor formulas are re-solved: protected tag decoding, low16 type decoding, encoded length decoding, the reader's universal decoded-copy step and the finite reverse-index induction certificate. These are formula rechecks with fresh enclosing-function custody, not complete fresh predecessor replays. Four altered-evidence comparisons reject a changed source word, descriptor size, allocation-size description and unsupported complete-parser claim. They are custody equality controls. No native target or IDB executes or changes.

| Claim | Established result | Principal dependencies |
| --- | --- | --- |
| CS1 | Post-stack-probe saved arguments and staging output-cell roots | CS-A1, CS-A2 |
| CS2 | Every saved size64 yields exact low32 N in three size/count channels | CS-A1-CS-A3 |
| CS3 | Original `_IOMallocData(N)` request and nullable result gate | CS-A1-CS-A4 |
| CS4 | Exact N-byte protected reverse copy and distinct zero/nonzero completion paths | CS-A1-CS-A5 |
| CS5 | Caller-specific shared parser input/output/continuation ABI | CS-A1-CS-A4 |
| CS6 | Original `site.FPTTLV` 16 B allocation, initialization and complete empty-input return | CS-A1-CS-A4, CS-A6 |
| CS7 | Exact first cursor/nullable-input gates; nonempty body remains open | CS-A1-CS-A4, CS-A6 |
| CS8 | Later reader setup reuses scratch+0x600; fixed protection-key assignments are located | CS-A1-CS-A3, CS-A5, CS-A7 |
| CS9 | Literal-base inventory, cost and external-interface limits | CS-A1-CS-A8 |

## Saved inputs and staging lineage

C is the selected scratch base, S the selected source base and F the current SP epoch. I is the saved input pointer; A is the saved 64-bit size argument and N=low32(A). Z is an abstract staging allocator result; H is an abstract typed container allocation. Register roles change between phases. These arguments are saved after the compiler stack-probe call; preservation across that probe and actual incoming caller identity are separate premises.

```text
saved pointer I at F+0x8f8       saved size A at F+0x878
          |                                 |
          |                       N = low32(A)
          |                                 |
          +----> _IOMallocData(N) -> Z <-----+
                         |
              copy I[N-1] ... I[0]
              as protected bytes into Z
                         |
     parser(Z, N XOR success, &C[0x600], continuation0xb9)
                         |
       typed site.FPTTLV allocation: 16 B, two fields zero
                         |
             N == 0: publish H -> C+0x600 -> resume
             N != 0: first input/header gates -> body unknown

later selected reader setup: C+0x600 -> X22 and C+0x4b0
                            -> shared input reader -> hash gate
```

The final reader composition uses stable caller cells/epochs. The nonempty parser's transformation from staged bytes into linked nodes is not proved by the arrows. A source buffer supplied to this routine is not yet a field identified in a daemon request or external wire record.

| Cell / source site | Width | Established role |
| --- | --- | --- |
| `0xfffffe000a63524c`..`0xfffffe000a635254` | three stores64 | Save third argument at F+0x738, A at F+0x878 and I at F+0x8f8 |
| F+0x670 | address64 | C+0x90, formed with a writeback store and retained at `0xfffffe000a6355c0` |
| C+0x90 | pointer64 | Staging allocator output via the saved address |
| F+0x524 / S+0xc8 | value32 | Encoded parser extent N XOR0x31ae0066 |
| F+0x4d8 | value64 | N-0x1cc01a010500480b modulo2^64 |
| F+0x4b8 | value64 | zero_extend32(N XOR0xc03f95d4), used by the zero-size gate |
| F+0x4b0 | value64 | zero_extend32(N), used as the copy count |
| F+0x888 | address64 | S+0xbe4; root at `0xfffffe000a63603c`..`0xfffffe000a636040` |
| C+0x358 | pointer64 | Retained staging result after selected completion |
| F+0x988 | address64 | C+0x600; root at `0xfffffe000a635e74`..`0xfffffe000a635e78` |
| C+0x600 | pointer64 | Precleared caller container output cell |
| C+0x3c0 | pointer64 | Cleared in selected staging completion; further role remains unknown |

The size proofs admit every 64-bit A, including nonzero upper32 bits. The low32 projection is intentional in the captured arithmetic. At `0xfffffe000a6355ec`..`0xfffffe000a63561c` exclusive, the W-register transform gives N XOR0x31ae0066. The independent 64-bit allocation-size expression at `0xfffffe000a6356ac`..`0xfffffe000a6357b4` exclusive and later saved count roots recover zero_extend32(N). This is not an assumption that the three obfuscated expressions have the same meaning. The separate 773-instruction initialization envelope is captured and checked for zero control transfers and zero SP writes, plus preservation of X19/W19, X11/W11 and X1/W1 between the relevant codec definitions and uses. This is register def-use custody across the selected spans, not an alias-complete memory proof.

## Original allocator and protected staging copy

The request at `0xfffffe000a641c80`..`0xfffffe000a641cf8` exclusive passes X0=N after reconstructing the allocation extent. Original table slot `0xfffffe000847a7a0`, index0xf10, targets `_IOMallocData` at `0xfffffe000c4ba60c`, with modifier0xca0c. The size request adds no byte. The return proof havocs X0-X18/X30, supplies abstract result Z and assumes ordinary callee-saved/SP/storage preservation. It proves the store through F+0x670, reload of I into X15, saved-status reload into W26 and the exact Z-null branch. Native allocator effects and zero-size behavior are unproved.

| Gate | Predicate | Target |
| --- | --- | --- |
| Staging allocation return | Z==0 | `0xfffffe000a6661bc`; subsequent failure body outside this increment |
| Staging allocation return | Z!=0 | `0xfffffe000a641d54`; size/copy gate |
| Initial size gate | N==0 | `0xfffffe000a641dc4`; no-copy completion |
| Initial size gate | N!=0 | `0xfffffe000a641e08`; copy loop |
| Reverse copy step | old counter==1 | `0xfffffe000a641e68`; post-copy completion |
| Reverse copy step | old counter>1 | `0xfffffe000a641e08`; repeat |

The no-copy and post-copy completion blocks are distinct. In the selected nonnull result paths, both retain Z at C+0x358, clear C+0x600 and C+0x3c0, initialize the caller state cell S+0xbe4 through F+0x888 and request the same parser ABI. The no-copy seam requires an abstract nonnull result for a zero-size allocation; no native behavior for that allocation size is asserted.

For admitted normal pointer branches, the byte protection is:

```text
K0 = 0x02e859d27e491464
K1 = 0x4dae26df20976138
mask8(a) = low8(((ROR64(a AND ~7, 8) + K0) XOR K1)
                >> ((a AND 7)*8))

for old_i = N, N-1, ..., 1:
    i = old_i-1
    stored_byte(Z+i) = I[i] XOR mask8(Z+i)
```

The addition wraps modulo2^64. The original byte store is at `0xfffffe000a641e48`. The all-counter64/all-byte8 proof checks1<=old_i<=N, exact input/destination addresses, protected output byte, decrement, exit/backedge and preservation of the loop's pointers, keys and phase constants. The predecessor's general finite-index certificate supplies the index induction: N-1-j,0<=j<N, ending at0 and never writing index N. Storage validity, nonwrapping separated extents and the normal pointer branch at every iteration remain premises.

The alternate MOVK at `0xfffffe000a641e24` replaces upper16 pointer bits with0xc8a2 and preserves low48. Its bit transform is independently proved; native retagged storage equivalence/readability is unknown. The staging copy and the downstream reader use the same address-keyed transform when the reader key is K0. A zero plaintext byte need not be stored as zero. Searching the protected storage for a literal NUL would not establish the decoded termination contract.

No terminator is added by this N-byte staging copy. The selected reader subsequently copies exactly its own decoded payload length L. The relationship between the staged N-byte envelope, individual decoded L-byte nodes and field-level termination requires the nonempty parser/producer contract.

## Shared parser entry and original FPTTLV descriptor

The selected caller at `0xfffffe000a641ee4`..`0xfffffe000a641f10` exclusive loads encoded extent from F+0x524 and output address from F+0x988. It supplies W9=0xb9 and selects private entry index0x330. Entry at `0xfffffe000a641fb8` retains the original pointer at that continuation index, not an external RPC identifier.

| Parser field / input | Width | Meaning in this caller |
| --- | --- | --- |
| X0 at entry | pointer64 | Staged input Z |
| W22 at entry | value32 | N XOR0x31ae0066 |
| X8 at entry | address64 | Caller output address C+0x600 |
| W9 at entry | index32 | Continuation0xb9 |
| C+0x5c8 | address64 | Original continuation target `0xfffffe000a656c08` |
| C+0x188 | address64 | Retained caller output address |
| C+0x618 | pointer64 | Retained staged input |
| S+0xc8c | value32 | Retained encoded extent |
| F+0xa80 | cursor64 | Initial cursor0 |
| C+0x228 | pointer64 | Typed container allocator result H |

The typed request selects index0xf13 at original slot `0xfffffe000847a7b8`, target `0xfffffe000c4ba154`, original symbol `_IOMallocTypeImpl`, modifier0xd0c8. The descriptor selection is an independent bank rule:

| Descriptor property | Original evidence |
| --- | --- |
| Pool selection | Index0x172, slot `0xfffffe0008472a90` |
| Descriptor address | `0xfffffe000847b620` |
| Name | `site.FPTTLV` |
| Signature | `11` |
| Flags | u32 0xe4 |
| Declared size | u32 16 B |
| Name/signature pointer offsets | +0x10 / +0x20, with original chain membership and string bytes checked |
| Flags/size offsets | +0x28 / +0x2c |

This establishes an original allocation-site label and size, not complete native C++ type identity. It is a separate allocation request from the [replacement bootstrap](userclient_replacement_bootstrap_report.md) and does not identify their runtime objects merely because both descriptors contain the name `site.FPTTLV`.

After the ordinary call cut, H==0 branches directly to the saved-continuation resume at `0xfffffe000a660ae0`. That path does not publish through the output address. The selected staging caller already cleared C+0x600; that clear belongs to the caller, not a universal shared-entry output-clear guarantee. W23 is reloaded from F+0x9ec, whose native value domain remains unknown.

For H!=0, `0xfffffe000a642100` stores two zero 64-bit fields at H+0 and H+8; the source also assigns X26=K0. With cursor0, the next gate takes the empty finish path exactly when N==0. The complete captured empty path publishes H through C+0x188, writes raw success0x31ae0066 at S+0xc10/in W23 and resumes C+0x5c8=`0xfffffe000a656c08`. Both fields remain zero. No node buffer is read on that path.

For an arbitrary cursor J, the exact local gate is unsigned64(J)<zero_extend32(N) to enter the nonempty path, otherwise finish. This local predicate alone does not establish a global cursor<=N invariant. The first nonempty input gate saves the retained pointer at C+0x3d8 and selects `0xfffffe000a642248` for nonnull input or `0xfffffe000a6423c0` for null input. Subsequent header parsing, node creation/publication, cleanup and nonempty cursor advancement remain unknown.

## Handoff to the reader and reference inventory

At `0xfffffe000a63dd14`..`0xfffffe000a63dd7c` exclusive, the selected setup loads O from C+0x600, retains O at C+0x4b0/in X22, clears hash-input pointer C+0x128 and initializes the encoded-length output S+0xaa8 to0x31ae0066. It tests the saved third argument Q at F+0x738: Q!=0 selects the reader request at `0xfffffe000a63dd80`; Q==0 selects `0xfffffe000a656f00`. W23 is initialized to0xce515bbf. This Q is a saved pointer value, not a newly identified Mach port, task or external identity.

The earlier phase at `0xfffffe000a636d7c`..`0xfffffe000a636d9c` exclusive explicitly assigns reader-side X20=K1 and X26=K0. The current parser initialization also assigns X26=K0; the staging writer assigns X21=K0 and X1=K1. Those source assignments locate producers of the matching transform constants. Full retention through every incoming dispatcher path and native key/storage epochs remains unproved.

| Literal-base cell syntax | Width | Reads | Writes | Boundary |
| --- | --- | --- | --- | --- |
| F+0x988 | 8 B | 5 | 1 | Saved C+0x600 output address; indirect writes remain separate |
| X2+0x600 | 8 B | 2 | 2 | Direct reads and clears; parser publication uses another register |
| X2+0x4b0 | 8 B | 2 | 1 | Retained reader container; same-base epochs still require proof |
| X2+0x90 | 8 B | 3 | 0 | Staging result written through the saved alias despite zero direct writes |
| X2+0x188 | 8 B | 1 | 1 | Parser output-address retention/read |
| X2+0x5c8 | 8 B | 1 | 1 | Parser continuation retention/read |

These counts cover all 50,634 instructions in the pinned container for nonindexed literal-base overlap, including paired accesses. They exclude other-base aliases, indexed operands, calls and changed object/SP epochs. The proven aliased staging/result stores demonstrate why a zero direct-write count is not a semantic absence result.

## Original private table mapping

Indices are private dispatcher indices. The mapping includes the exact selected branches, successful empty-parser path and saved continuation. Original slot words and terminal transfers are captured separately from the instruction proofs; native PAC/BTI is unproved.

| Private index | Original slot | Target |
| --- | --- | --- |
| 0xb9 | `0xfffffe00084734e8` | `0xfffffe000a656c08` |
| 0x330 | `0xfffffe00084748a0` | `0xfffffe000a641fb4` |
| 0x353 | `0xfffffe00084749b8` | `0xfffffe000a641ee0` |
| 0x449 | `0xfffffe0008475168` | `0xfffffe000a6421b0` |
| 0x560 | `0xfffffe0008475a20` | `0xfffffe000a6423c0` |
| 0x593 | `0xfffffe0008475bb8` | `0xfffffe000a642248` |
| 0x5aa | `0xfffffe0008475c70` | `0xfffffe000a665fc8` |
| 0x69e | `0xfffffe0008476410` | `0xfffffe000a6420f8` |
| 0x6d5 | `0xfffffe00084765c8` | `0xfffffe000a660ae0` |
| 0x87f | `0xfffffe0008477318` | `0xfffffe000a6421dc` |
| 0x891 | `0xfffffe00084773a8` | `0xfffffe000a642138` |
| 0x893 | `0xfffffe00084773b8` | `0xfffffe000a642180` |
| 0x8b6 | `0xfffffe00084774d0` | `0xfffffe000a641e08` |
| 0x8c4 | `0xfffffe0008477540` | `0xfffffe000a63dd80` |
| 0x8ed | `0xfffffe0008477688` | `0xfffffe000a656f00` |
| 0x926 | `0xfffffe0008477850` | `0xfffffe000a641dc4` |
| 0x970 | `0xfffffe0008477aa0` | `0xfffffe000a660ac8` |
| 0xb10 | `0xfffffe00084787a0` | `0xfffffe000a6661bc` |
| 0xb16 | `0xfffffe00084787d0` | `0xfffffe000a641d54` |
| 0xd40 | `0xfffffe0008479920` | `0xfffffe000a641e68` |

The data allocator bank uses TL/TR with key0x16, constant0x88 and additive0xe88. The typed allocator uses TL/TR with key0xd8, constant0x20 and additive0xef3. Descriptor selection uses distinct BL/BR roots with key0xef, constant0x61 and additive0x111. TL/TR are `0xfffffe0007949dd0`/`0xfffffe000792fbc0`; BL/BR are `0xfffffe0007949fd0`/`0xfffffe000792ffc0`. The three 256-input identities are checked from original normalized bytes; the source-phase root identities remain explicit premises tied to retained predecessor/root metadata.

## Architectural scope and cost

The recovered private interface is a reusable protected-buffer parser with caller-specific output and continuation cells. The current evidence establishes staging, typed container allocation, empty parsing and the first nonempty gates. It does not yet establish the nonempty parse that supplies the reader's matched32 B-accessed node, or connect decoded tag0x172ba3a8 to a named daemon field. Neither the 16 B FPTTLV allocation nor the earlier16 B UIDList node identifies the reader node's allocation merely by size or naming.

No new Mach endpoint, incoming/outgoing right, message emission or successful daemon-kext transaction is established. Existing external interfaces remain in [Mach ports](mach_ports_report.md), [interface ABI](interface_abi_report.md), [context/task flow](context_descriptor_task_flow_report.md) and [investigation status](interface_investigation_status.md). The source input pointer/size interface does not by itself establish native external controllability.

Under the stated valid-storage premises, staging takes O(N) time, requests N B and uses O(1) auxiliary state, with exactly N input-byte reads and N protected-byte stores. Empty parser input takes O(1) selected work plus the16 B container allocation, excluding allocator cost. No cost bound for the complete nonempty parser is claimed. Extraction/inventory take O(B+I+256R) time/space; source-proof construction takes O(instruction instances+query DAG), with SMT search separate and30 s/query limits.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CS-A1: Pinned images, symbols, original fixups/descriptor and predecessor receipts | CS1-CS9 provenance | Fresh dual-image/whole-container custody, original pointer/string checks, reconstructed formulas and four altered-evidence controls |
| CS-A2: Stable C/S/F epochs, saved post-stack-probe arguments and selected phase/root registers | CS1-CS9 composition | Recover actual incoming caller/probe preservation and all intervening alias effects; current roots and exact local branches do not prove whole incoming reachability |
| CS-A3: AArch64 W/X widths, zero extension, writeback and arithmetic semantics | CS1, CS2, CS4-CS9 | All-argument64 codec proofs, explicit writeback-root proof, all-counter64 byte proof and every-cursor64 predicate; independent native instruction execution remains separate |
| CS-A4: Ordinary allocation cuts preserve callee-saved/SP/retained cells; native allocator semantics remain open | CS3-CS7 | Original symbols/slots/descriptors, caller-saved havoc and all-result64 gates; recover actual callee effects, allocation validity and zero-size behavior |
| CS-A5: Readable stable input, writable separate nonwrapping staging extent and normal pointer branches | CS4, CS8, CS9 | Exact byte-address/store proof and alternate MOVK transform; establish native retag compatibility, storage lifetime and key retention before generalizing |
| CS-A6: Nonnull typed result provides writable16 B and retained input/output/continuation cells remain stable | CS5-CS7 | Two-field initialization and complete empty-input source composition; inspect nonempty node construction, cursor invariants, publication and cleanup |
| CS-A7: Reader setup shares the intended container/cell epoch; original tag identity and termination remain unknown | CS8, CS9 | Trace nonempty parser records into J/B/N and decoded tag0x172ba3a8; source key assignments alone do not prove every path retains that key |
| CS-A8: Inventory is syntactic; native ownership, locking, saved-status domain, marker origin and daemon correlation remain unknown | CS9 limits | Follow escaped aliases/callees, allocation/free pairs, source+0x20 and correlated successful context/provider transactions |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Nonempty body from `0xfffffe000a642248` and node publication into FPTTLV | Connect staged envelope bytes to the reader's node/buffer/type/length fields |
| High | Parser output continuation `0xfffffe000a656c08` and later command dispatch | Establish which constructed fields drive the selected reader command and their business identities |
| High | Actual saved input caller, stack-probe preservation and source pointer/size ownership | Close native external influence, extent and lifetime contracts |
| High | Parser/copy cleanup and allocation/free pairs | Establish staging/container/node ownership and termination invariants without inferring faults from source gaps |
| Medium | Key/retag behavior across all incoming epochs | Establish native storage compatibility and transform continuity |
| Medium | Saved-status aliases, original marker producer and correlated daemon/provider exchanges | Compose remaining status/marker and successful cross-layer behavior |
| Low | Other callers of the same parser output/continuation ABI | Characterize reuse after caller epochs and output types are established |

## Quality gates

- **QG1**: Factual source, memory and interface claims require no normative conclusion.
- **QG2**: CS-A1-CS-A8 enumerate dependencies and falsification probes.
- **QG3**: Saved-input codecs, allocator request, exact protected copy, parser private ABI, typed initialization, complete empty return and first nonempty gates are covered; wider investigation remains active.
- **QG4**: low32 projection, u32/u64 codecs, modulo2^64 arithmetic, byte extents, writeback, reverse-index induction and scoped costs are explicit.
- **QG5**: Caller clear versus shared-entry behavior, zero-copy versus copy completion, encoded extent versus raw status, descriptor label versus runtime identity, empty versus nonempty parser coverage and direct versus aliased writes remain distinct.
- **QG6**: Original dual-image words/fixups/symbols/descriptor, 20 nonvacuous formulas, five predecessor rechecks, 768 bank inputs and four custody comparisons support bounded claims.
- **QG7**: Ranked continuation preserves nonempty construction, command/field identity, native input/ownership, key/retag and daemon-correlation questions.

## Record-node construction increment

The [post-header constructor follow-up](userclient_record_nodes_report.md) closes the selected metadata return, special-pair bypass, payload-plus-ten guard, typed 32 B node initialization and buffer/writer handoff. Complete nonempty parsing, header production, payload copy, list publication and original field identity remain open.

## Protected record-writer increment

The [record-writer increment](userclient_record_writer_report.md) establishes header production and selected type0x6685 payload copying after the post-header cut. It does not yet prove how the original staged envelope supplies the metadata/body pointer, how records enter the container list or how the parser advances its cursor.

## Record lookup and publication increment

The [record-publication follow-up](userclient_record_publication_report.md) closes the selected list operation after construction/copy and returns to the same parser cursor gate. Complete nonempty parsing still requires the original metadata/body/cursor producers, record bounds, all relevant types and failure cleanup.

## Staged metadata and cursor increment

The [metadata follow-up](userclient_record_metadata_report.md) establishes this increment. The selected nonempty continuation now has exact ten-byte header provenance, body bounds, payload pointer and cursor commit. Zero-length payloads consume ten bytes; decoded tag0/type0x6685 can select success before the outer suffix is consumed.

## Parser cleanup increment

The [cleanup follow-up](userclient_parser_cleanup_report.md) establishes this increment. The selected parser-failure continuation now reaches null output at the saved caller address and restores raw status before resume. Staged-buffer ownership after that resume remains open.

## Parser caller and command dispatch increment

The actual parser caller now has a conditional command-field lookup, protected scalar reader and exact two-value switch. The first command links to the existing hash-input reader; second-body semantics, native storage/ownership and cross-layer correlation remain open. See the [command-dispatch report](userclient_command_dispatch_report.md) for the source contracts, status frontiers and assumption register.

## Caller cleanup and copy-back increment

Outer allocation requests now distinguish the4,096 B context and16,384 B aligned workspace from earlier minimum modeled accessible subranges. The original staged copy has a conditional reverse copy-back and exact-size retirement path. See the [caller-return report](userclient_caller_return_report.md) for original requests, proofs, scope and assumption probes.


The [auxiliary copy contract](userclient_auxiliary_copy_report.md) now establishes the conditional publication stores, exact extent/success callback gate, saved-mode split and reverse byte-transcode step between auxiliary and staging masks. Original argument producers establish counter=N and mode=N XOR0x7c233caf, supporting conditional N-byte composition; complete serializer reachability and native transaction pairing remain unknown. This increment establishes no additional Mach port endpoint.
