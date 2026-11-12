# CoreFP1201 caller, scalar guard and conditional argument provenance

The reference CoreFP parent contains a proved local call selection at `0x8f3838` to request1201 builder `0x8d40`. Its destination comes from a four-byte stack cell nominally also passed as request1200's returned-name output. Its scalar comes from a field at `MEM64[SP+0x258]+0x168`; on the selected loop-exit route, unsigned values below2 skip the call and values at least2 are passed unchanged. Its128-byte source pointer comes from `MEM64[SP+0x1b8]`.

The whole-parent port handoff remains conditional. Five explicit dynamic stack assignments and a competing four-byte write to the nominal pointer slot prevent treating equal SP offsets as continuous object identity. Request1200's128-byte output, request1201's candidate source range and the selected XOR loop's destination are three distinct adjacent ranges. Their intervening protected transformation, whole-parent reachability, actual port rights and native daemon/kext continuity remain unknown. The full investigation remains active.

## Reference and evidence

All CoreFP addresses are offsets from preferred base0. Reference universal SHA-256 is `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`; selected arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. The parent is `[0x8e81c8,0x8fcfa0)`,85464 B, SHA-256 `4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e`. Its complete fresh IDA body matches the previously frozen function hash. The changed installed image was not substituted for the reference.

The [read-only IDA capture](triage_evidence/fpsd1201_caller_ida_readback.json.zst) supplies previously missing full parent bytes, a564-byte stack helper, four256-byte banks, ten normalized pointer targets and fourteen140-byte modifier windows:30 spans,89092 B including overlap. The parent, helper and all four banks equal IDA's original-byte API results. Pointer bytes in IDA are normalized targets; their original format12 chained words are decoded separately from the frozen inventory. No IDB edit or native target/API/IPC operation executes.

Artifacts: [recovery](triage_evidence/recover_fpsd1201_caller.py), [checks and complete private states](triage_evidence/fpsd1201_caller_checks.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_caller.py), [audit receipt](triage_evidence/fpsd1201_caller_audit.json.zst), [publication verifier](triage_evidence/verify_fpsd1201_caller_publication.py). Prior [request1200 client paths](corefp_client_paths_report.md), [request1200 contract](fpsd1200_contract_report.md) and [request1201 serializer/parser](fpsd1201_client_report.md) supply the retained interface context; their large earlier replays are not rerun here.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CA1 | The pinned reference and fresh IDA bytes describe this source snapshot. All addresses and local semantics depend on this identity. | Full parent hash matches the prior frozen hash; all new code/banks equal IDA original bytes. A different hash or patch invalidates this mapping. Effective native image selection remains unknown. |
| CA2 | X19 and the relevant bank cells retain their recovered initialization when the selected call block executes. The constant target and modifier claim depends on this premise. | Three exhaustive256-input bank identities, original initialization instructions and ten separately decoded pointer words agree. A changed table base, bank pointer or memory write invalidates selection. Whole-parent reaching definitions are not exhausted. |
| CA3 | The fragment starts at the selected128-byte loop with X8=128,W11=0x8b,W12=0x3e5,W20=0x55e1 and declared readable/writable referents. Loop/gate profiles depend on this entry. | Twelve independently reconstructed private cases cover all256 byte values and six scalar controls. Upstream reachability, object ownership and native allocation bounds remain unknown. |
| CA4 | Authenticated indirect branches use decoded reference targets under a private PAC model. Local branch continuation depends on this model. | Every one of1548 modeled branches checks its original pointer slot, target, IA key, address-diversity0 and modifier. No hardware authentication result is asserted. |
| CA5 | SP epoch and cell contents agree between the stated definitions and uses. Conditional port/input/owner joins depend on this premise. | Complete21366-instruction parent census finds11 SP writes, including five dynamic assignments; competing pointer-slot and owner-slot stores are retained. Zero delta, same epoch and absence of alias/callee writes are unproved. |
| CA6 | The source request1200 parser's accepted reply reaches its output stores. Returned-name and128-byte output roles depend on this accepted-reply branch. | Original builder frame arithmetic and exact output-store instructions agree with the previous complete client contract. This increment injects no successful protected-core response and executes no request1200 transaction. |
| CA7 | The helper's final four instructions execute with the stated saved scalar and child-produced word. Its delta formula depends on reaching that suffix. | Original-byte execution checks20 input pairs; the local full-domain formula proves alignment, extent and the exact zero condition. The opaque child and whole helper return are not replayed. |
| CA8 | Source-local argument roles can be reported without assigning external semantics. All architectural conclusions retain this boundary. | Cross-check source loads, serializer entry ABI and prior daemon grammar. Native endpoint identity, field meaning, authorization, rights lifetime and daemon/kext/deeper execution remain unknown. |

## Constant table selection [CA1,CA2,CA4]

For256-entry byte banks L,R, define `f(i,k)=i XOR R[L[i] XOR k]`, with i and k unsigned8-bit values. Every possible i is checked independently.

| Role | L | R | k | f(i,k), every i | Selected source result |
| --- | --- | --- | --- | --- | --- |
| Parent table |0x18ac070 |0x1ac18c0 |0x89 |0x77 | `0x1d05fa0 + 8*(0x14b2+0x77) = 0x1d108e8`; decoded target0x1c81944 minus4 gives X19=0x1c81940 |
| Request1201 |0x18ac270 |0x1ac1ac0 |0xc8 |0xc0 | `X19 + 8*(0x10351+0xa8+0xc0) = 0x1d03f08` |
| Preceding helper |0x18ac270 |0x1ac1ac0 |0xe7 |0x1f | `X19 + 8*(0x10351+0x193+0x1f) = 0x1d04158` |

Original pointer0x1d03f08 has word `0x8008839000008d40`: authenticated rebase to0x8d40, IA, discriminator0x8390, address diversity0. The call at0x8f3838 uses `BLRAA X8,X17` after `MOV X17,#0x8390`. Thus selector-byte uncertainty does not make its target variable under CA2. The helper pointer0x1d04158 similarly selects0x981c38 with discriminator0xe454.

The call banks are initialized from original pointer0x1d146f0 ->0x18ac270, stored at SP+0x3a8, and pointer0x1d09f68 ->0x1ac1ac8 minus8, stored at SP+0x3a0. The exhaustive constants do not prove that those stack cells retain their values throughout every parent route.

Fourteen reference modifier-pattern candidates are retained. Exactly one lies within this parent, at0x8f3834. Reused discriminator0x8390 elsewhere is a candidate locator; the other thirteen windows are not promoted to proved request1201 call edges.

## Conditional destination and output lineage [CA1,CA5,CA6,CA8]

| Source location | Exact local action | Established role / boundary |
| --- | --- | --- |
|0x8ea090 | `STR WZR,[SP,#0x4e8]` | Initial four-byte output cell |
|0x8ea108 /0x8ea10c | `SP+0x4e8` stored at `[SP+0x18]` | Fourth stack-passed argument of request1200 |
|0x8ea14c | Call request1200 builder0x8ae0 | Previously established source call |
|0x8c98 /0x8cf4 | Load X8 from builderFP+0x28; store W13 through X8 | Accepted reply's descriptor-name word reaches that stack argument |
|0x8f3810 | `LDR W0,[SP,#0x4e8]` | Request1201 destination argument |
|0x8f3838 | Call builder0x8d40 | Local target established under CA2 |
|0x8e04 | Builder's `mach_msg` call | Previously recovered emission: request1201,send164 B,receive capacity44 B |

Builder0x8ae0 subtracts0x130 from entrySP and sets FP=entrySP-0x10. Its `[FP+0x28]` therefore equals `[entrySP+0x18]`. The accepted branch loads W13 from builderSP+0x38 and stores it through that exact pointer. This verifies the output argument's role independently of guessing from stack offsets.

```text
request1200 accepted reply descriptor-name word
  -> builder0x8cf4 -> *MEM64[entrySP+0x18]
  -> parent nominal SP+0x4e8
       [same SP epoch and retained contents required]
  -> parent0x8f3810 W0
  -> builder0x8d40 -> mach_msg0x8e04
```

Only one direct immediate-SP store overlaps the nominal four-byte port cell in the complete parent:0x8ea090. That census excludes aliased writes, callees and path/epoch equivalence. It does not prove a single native producer, a continuous right, or the identity of the receiving daemon endpoint. No new direct Mach port emission is present in this fragment; emission remains inside the previously audited builder.

## Three distinct128-byte ranges [CA1,CA3,CA5,CA6]

Let P denote X21 at0x8ea07c, retained in X20 at0x8ea09c. The following associations are conditional on that owner and the intervening frame/register continuity.

| Range | Source evidence | Local role |
| --- | --- | --- |
| P+0x800 through P+0x87f |0x8ea07c sets request1200 X5=P+0x800; builder preserves X5 in X21 and copies128 reply bytes there | Request1200 inline output |
| P+0x880 through P+0x8ff |0x8ea1b4 /0x8ea1b8 saves P+0x880 at SP+0x1b8;0x8f382c reloads X2 from that slot | Candidate request1201 inline source |
| P+0x900 through P+0x97f |0x8ea1bc /0x8ea1c0 saves P+0x900 at SP+0x1a8;0x8f3430 loads the loop destination X25 from that slot | Selected XOR-loop destination |

The128-byte extents do not overlap:0x800+128=0x880 and0x880+128=0x900. This is a conditional source-level owner layout, not a proof that a native object has the required allocation extent.

At0x8f34d0 the candidate request1201 source pointer is also loaded into a protected record at FP-0x98, before helper0x981c38 is invoked. The record's other fields, child transformation and full input definedness are not established. The observed XOR loop cannot itself establish production of the +0x880 input, because its destination is the distinct +0x900 range under these definitions.

The parent has a second, four-byte write to SP+0x1b8 at0x8f61c4. It also has two direct SP+0x1f0 pointer stores, at0x8ea208 and0x8f4cf0; that slot feeds the loop's X13 via0x8f3564. Branch order, frame epochs and alias effects must be resolved before assigning a unique native buffer producer. The local profiles declare separate input/destination ranges and leave the +0x880 bytes unchanged.

## Selected XOR loop and scalar guard [CA1-CA4]

The local fragment starts at0x8f35cc with counter128. Each iteration decrements the counter, reads source[counter], computes the expression below and writes destination[counter]. Its original branch table maps state0x55e1 to exit0x8f35fc and `0x55e1 XOR 0x3e5=0x5604` to loop0x8f35cc. The128 stores therefore occur at indices127 through0.

```text
b = source[index]                         # u8, zero extended
stored = low8(b + (0x8b OR NOT(b << 1)) - 0x45)
       = b XOR 0xba                       # all256 possible bytes
```

The source loop then reaches:

```text
X25 = MEM64[SP+0x258]
W1  = MEM32[X25+0x168]                    # 0x8f3638
if unsigned(W1) < 2:
    branch0x8f3658 ->0x8f365c ->0x8f389c # skips1201
else:
    branch0x8f3658 ->0x8f37d8
    W0 = MEM32[SP+0x4e8]
    X2 = MEM64[SP+0x1b8]
    call0x8f3838 ->0x8d40                 # fragment stops before call
```

With the loop's W20=0x55e1, the branch index is `((W20-0x53df) OR 0xe089) XOR (28 if W1<2 else0)`:0xe297 for skip,0xe28b for call. Original authenticated table entries select exactly those continuations. A full-u32 local proof establishes the guard; W1 is passed unchanged on this selected route. No semantic name such as operation, version, length or authorization is assigned to the field at+0x168.

The twelve cases use scalar0,1,2,3,0x80000000,0xffffffff and two128-byte patterns covering all256 possible byte values. Eight cases stop immediately before the request1201 call; four stop at the skip continuation. Every case performs the complete128-byte loop. These are declared fragment entries and do not establish their occurrence on a complete successful native operation.

## Stack epochs and helper delta [CA1,CA5,CA7]

The complete parent has11 explicit SP writes: the prologue predecrement, two frame allocations, five `MOV SP,X8` sites, two frame additions and the epilogue postincrement. The dynamic sites are:

| SP assignment | Loaded delta cell in its local predecessor | Relation to selected call |
| --- | --- | --- |
|0x8e9588 | SP+0x970 | Earlier source location; full control-flow ordering unknown |
|0x8f1db4 | SP+0x980 | Between request1200 and1201 in address order; path participation unknown |
|0x8f3590 | SP+0x978 | Immediately preceding selected local loop/gate region |
|0x8f8444 | SP+0x990 | Later address; loops/backedges not excluded |
|0x8fc7b4 | SP+0x988 | Later address; loops/backedges not excluded |

The helper selected at0x8f3560 is0x981c38..0x981e6c,564 B,SHA-256 `846f13ab786587b080533af89eda9f3ac1e5b5fb4b95458fa67d49a658738ff6`. Its original suffix0x981e48..0x981e58 computes:

```text
delta_B = ((MEM32[X20] - low32(X21)) mod 65536) * 16
MEM64[X19] = delta_B
```

The output is a multiple of16 B in the inclusive range0..1048560 B (`0xffff0`). It equals0 exactly when the two input low16-bit values agree. The selected parent subsequently adds a loaded delta to SP. Thus zero is a condition to prove, not an intrinsic property of this helper. Its child call at0x981e44, the child's writeback and the whole-parent cumulative delta remain unknown. Twenty independent original-byte suffix cases include zero, nonzero, maximal and wrapping differences; the local alignment/extent/zero-condition query is UNSAT for counterexamples.

## Validation and bounded continuation

Independent validation checks18920 original fragment visits,3212 reads,1560 writes,1548 PAC models,1572 complete CPU frames and983040 B of final mutable RAM across12 profiles. It scans the full21366-instruction parent, verifies68 selected exact instructions and ten original pointer words, checks768 exhaustive bank inputs and reruns three retained SMT queries plus two independent local queries. An additional20 suffix cases execute80 original instructions. Source and private execution agree; no whole-parent, native transport, hardware PAC or successful protected-core processing is claimed.

Reproduce with configured Python, Unicorn, Capstone and Z3:

```text
$PYTHON triage_evidence/recover_fpsd1201_caller.py
$PYTHON triage_evidence/audit_fpsd1201_caller.py
$PYTHON triage_evidence/verify_fpsd1201_caller_publication.py
```

Static extraction is O(B+F+256K); private replay is O(CV+CR), with source bytes B, fixups F, bank identities K, cases C, visited instructions V and retained RAM R. Space is O(B+F+C(V+R)). Solver complexity is separate, with30 s retained-query limits. Widths, modular arithmetic and byte extents are explicit; these bounds are not native timing measurements.

| Impact | Next discriminating evidence |
| --- | --- |
| High | Recover helper0x981c38's child, protected record grammar and writeback. Establish the actual SP delta and production/definedness of the +0x880 range. |
| High | Join the complete parent from request1200's accepted output through request1201's call, retaining all frame epochs, competing stores and alias/callee effects. |
| High | Establish the scalar+0x168 object's producer, semantic field role and actual public-export reachability. |
| High | Match native image selection, returned-right copyout, client name and daemon receive endpoint before asserting a continuous session or daemon/kext/deeper transaction. |
| Medium | Resolve the remaining thirteen modifier candidates by their own banks/tables rather than discriminator reuse. |
| Medium | Continue marker0x4d/tail-object ownership and retirement from source-produced objects, independently of the client layout recovered here. |

**QG1** passes: factual technical analysis only. **QG2** passes: CA1-CA8 identify dependencies and falsification probes. **QG3** passes for this bounded caller/argument/frame increment; the full goal remains incomplete. **QG4** passes: widths, byte extents, range bounds and reproduction artifacts agree. **QG5** passes: adjacent buffers, competing stores, dynamic frames, declared fragment entry and native gaps remain explicit. **QG6** passes: frozen hashes, fresh read-only IDA, normalized versus raw pointers and independent replay/solver checks are distinguished. **QG7** passes: impact-ranked continuations cover the unresolved architectural joins.

The subsequent [protected-record report](fpsd1201_record_report.md) resolves helper child0x981104, original80-byte record staging, selected admission predicates and exact cursor compensation on16 complete rejections. Eight continuing cases stop before0x17bbb8 with the output seed retained; complete successful return and whole-parent stack continuity remain unknown.

The [export and complete local helper report](fpsd1201_export_report.md) now establishes private production of the candidate P+0x880 range under the original constructor's declared pointer. Original helper call 0x8f3560, returned cursor consumption and root-marker comparison at 0x8f3594/0x8f3598 are source-checked. The private helper returns to its declared stop; the actual parent frame/register/global state and later builder continuity remain conditional. This does not collapse the distinct +0x800, +0x880 and +0x900 ranges or resolve the full-parent SP epochs.
