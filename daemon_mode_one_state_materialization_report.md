# Mode1 word spills and two scattered64-byte state planes

Two selected blocks materialize the mixed register state into the private frame.0x100bf3160 writes20 encoded/control u32 words.0x100c9d2b8 writes128 derived bytes and twelve further u32 words. The byte writes form two64-cell logical runs under the existing scratch permutation. They overwrite all16 former raw-A permutation cells while preserving the800 live digit-map and arithmetic-table cells. The byte-value expressions separate into first-bank and second-bank input families. A compact full algorithm for the128-byte expansion,caller output and native daemon/kext linkage remain unknown. [SM1-SM8]

Evidence: [original blocks,lineage and pointer records](triage_evidence/daemon_mode_one_state_materialization_source.json), [source proofs,store/value ledger and dependency certificates](triage_evidence/daemon_mode_one_state_materialization_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_state_materialization.py), [validator](triage_evidence/validate_daemon_mode_one_state_materialization.py), [preservation](triage_evidence/daemon_mode_one_state_materialization_delivery.json), [quality gates](triage_evidence/daemon_mode_one_state_materialization_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_state_materialization_publication.py). Parents: [word mix](daemon_mode_one_word_mix_report.md), [digit/arithmetic tables](daemon_mode_one_digit_maps_report.md).

| Evidence | Verified scope |
| --- | --- |
| Image |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| New blocks |1465 instructions;all1463 nonbranch sites translated |
| With lineage |Four ranges,1643 instructions/6572 B;all1640 distinct nonbranch sites translated |
| Recapture |Twenty-one parent ranges/6108 B |
| Metadata |Three original pointer records and branch/modifier matches |
| SMT |29 new plus39 replayed UNSAT certificates;one SAT abstract input-domain check |
| Addresses |Three universal computed-index identities;all160 store addresses certified |
| Values |Twenty compact preparatory spill equations;full SSA DAG and value expressions for all32 word and128 byte stores |
| Dependencies |128 checked byte-value dependency sets and predecessor bank-family classification |
| Memory |256 distinct bytes written;800 live arithmetic cells preserved;928 identified live scratch cells after materialization |
| Controls |Four source/store/target/native-claim alterations rejected by fresh original-source comparison |
| Execution |No target execution,emulation,API/IPC request,hardware PAC or IDB mutation |

## Exact byte-plane layout and the raw-A boundary

Let F be the protected-core frame,T=F+0xd00,and physical(i)=T+((757*i) mod963). The new bytes occupy:

| Plane | Logical indices | Cells | Source input family |
| --- | --- | --- | --- |
|Plane0 |40..103 |64 |Incoming W1,W10,W11,W15,W20 |
|Plane1 |112..175 |64 |Incoming W0,W2,W13,W14,W19 |

The two runs are disjoint. Every cell is written exactly once by the selected straight-line materializer. Three source addresses use computed register indices;the other125 byte addresses use fixed frame offsets or source-proved constant frame aliases. The exact site/offset/width/value ledger is retained. [SM3-SM6]

The old raw-A table occupied logical indices112..127. Plane1 therefore overwrites all sixteen of its cells,starting with STRB at0x100c9d2e8. Its old A[j]=E(pi(j)) storage contract ends here. This is an address/write fact,not a claim that every native byte value changes or that future code can never interpret those cells differently.

The new writes do not overlap the forward digit map B,inverse digit map U,or binary-operation tables C,D,Q. Those800 cells retain their established contracts. The two state planes add128 live cells,including the sixteen repurposed raw-A locations,for928 identified live cells in the963 B scratch domain. The remaining35 positions are outside these identified live sets;their contents are not assigned a value. [SM3,SM6]

The computed-index stores are:

| Store | Proved address | Logical index |
| --- | --- | --- |
|0x100c9d7dc |T+529 |133 |
|0x100c9dba4 |T+946 |145 |
|0x100c9dd48 |T+673 |151 |

The first two addresses use u64 sums of zero-extended masked words;the third uses a u32 index promoted by UXTW. Separate universal certificates over the original local source spans establish all three constants. A diagnostic query over the entire expansion timed out for the first index and is excluded. The accepted local certificate proves the same address without assuming a bank sample. The full model then substitutes each constant only after its source identity is established and verifies every store address. [SM4-SM5]

## Plane dependencies and data-flow separation

For each stored byte,the validator follows the exact SSA definition DAG to its free entry-word inputs. Plane0's dependency set is contained in {W1,W10,W11,W15,W20};Plane1's is contained in {W0,W2,W13,W14,W19}. The predecessor's compact formulas classify the first set as functions of its first four-word bank,with earlier size-context dependence in W1/W15,and the second set as functions of its second four-word bank.

This establishes local data-flow separation under the recorded source semantics. It does not establish statistical independence,equality of the banks,a standard cipher/hash identity,or native scheduling behavior. All128 per-byte dependency records and the predecessor-variable classifications are retained.

The local context register W24,called SIZE in the new queries,does not occur in any byte-value expression. Here it controls the terminal continuation. Upstream generated words can already contain length-derived context,so the absence of direct SIZE dependence is not a claim that the complete expansion is length independent. Exact byte values are retained as SSA expressions;their full compact algorithmic normalization is not proved. [SM4-SM6]

## Twenty preparatory word spills

Use entry words a=W0,b=W1,c=W2,d=W10,e=W11,f=W13,g=W14,h=W15. All assignments below wrap to u32. The predecessor supplies W8=0x3146;the spill block sets p=W22=0xbce7.

```
v  = d+b+0x59156063
q  = v XOR e
t  = a+0xf09eaeb1
u  = t+c+p+0x814a0789
z  = u XOR g
w  = u+z
s  = w+t
r  = s XOR z
v2 = q+v
a1 = d+v2
H  = h-d
b1 = a1+0xf09eaeb1
q1 = b1 XOR q
X  = f-t
```

The source's XOR-plus-doubled-conjunction expressions are ordinary additions;another masked/complementary pair cancels its constants. Twenty independent field queries establish:

| Frame offset | Stored u32 value |
| --- | --- |
|0x464 |0 |
|0x510 |0x73576316-a |
|0x514 |d+0xe883a007 |
|0x50c |c+0x302c2b9d |
|0x550 |0x53d90af6-b |
|0x548 |0xeda438e4-e |
|0x558 |0x55ab6027-f |
|0x540 |0x6f33df6f-w |
|0x560 |s+0x0931b687 |
|0x534 |0x8a2b031a-H |
|0x51c |q1+0xc35d6b23 |
|0x508 |v2+0xe2827773 |
|0x538 |0x0bd0911f-r |
|0x52c |0x7dba1bd4-a1 |
|0x444 |s |
|0x520 |g+0x4ecaba8e |
|0x530 |X+0xaeec38ab |
|0x518 |h+0xb84929d6 |
|0x504 |0x0dc87a81 |
|0x460 |0x34 |

These are local frame encodings,not recovered public structure/type names. The adjacent u32 writes at+0x460/+0x464 are recorded separately;no external u64 field type is inferred. Additional live register values pass into the byte materializer;their full source SSA is retained rather than claiming that this field table alone is its complete input ABI. [SM2,SM4-SM6]

The byte materializer adds twelve u32 stores at+0x730,+0x750,+0x4f8,+0x6c8,+0x6d0,+0x4f4,+0x6c0,+0x690,+0x6c4,+0x748,+0x6cc,+0x6bc. Their exact value expressions are in the same source ledger. The32 word stores and128 byte stores write256 distinct bytes,with no overlap among the new writes.

## Frame/register epochs and outgoing private ABI

| Location | Established change |
| --- | --- |
|F+0x730 |New u32 value0x4923;earlier source-bank word role has expired |
|F+0x750 |New u32 value0x4923;the earlier saved-size decoder contract no longer applies to this cell |
|F+0x748 |New materialized state word;the previous private phase value is replaced |
|X21 |First repurposed by ADD W21 at0x100c9d47c;it no longer carries the saved view |
|F+0x568 |Saved F+0x8348 view remains unchanged and is not dereferenced here |

The source/image roots at F+0x458/+0x450,the scratch/branch roots at+0x738/+0x740,the retained word-cell/image-bank roots and the8 B budget cell at+0x1210 are disjoint from the new writes. The earlier literal initializer and its untouched F+0x424 word are also not written by these two blocks. [SM3,SM6]

The materializer loads T through F+0x738 for the three computed-index stores. Near exit,it moves T into X26 and reloads SRC into X25 from F+0x458 and the fixed image-data base into X23 from F+0x450. These are source pointer/root transfers;native mapping,extent and ownership remain premises.

| Exit register | Value / role |
| --- | --- |
|X26 |T=F+0xd00 |
|X25 |SRC |
|X23 |0x100f715a0,image-data base |
|W16,W28,W20 |757,527,963 |
|W4 |0x440dd2cf |
|W8,W9 |0xeb,0x77453be2 |
|W27,W30 |0x6ada6bd2,0xba9559f3 |
|W0 |0xd693a272 |
|W24 |Retained size-context word |

All seven memory reads in the two new blocks are8 B control/root reads,total56 B. They do not read SRC payload bytes or arithmetic-table entries during this materialization. The derived byte values originate from the register inputs. No SP update,call,trap or Mach emission occurs. No new incoming/outgoing Mach port,name,right or message ABI is established. [SM4,SM7-SM8]

The spill block selects0x3146 ->0x100c9d2b8,IA0x4076. The byte block compares incoming W24 with fixed0x3874e8c9,retains the NE result across its arithmetic,and selects:

| Local context condition | Selector / original target | IA diversity |
| --- | --- | --- |
|W24==0x3874e8c9 |0xbce7 ->0x100a763d4 |0x41f7 |
|W24!=0x3874e8c9 |0xbcff ->0x100c21d7c |0x41f7 |

The selected LEN32 initializer supplies W24=0x3874e8e9,so this source continuation is0x100c21d7c. No general equality preimage or native zero-length reachability is inferred from this comparison. Static authenticated-rebase/modifier agreement does not prove successful hardware PAC,exceptions or actual native traversal. [SM2,SM7]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| SM1 |Pinned original image,unslid source and original fixups |Rehash image,recapture all ranges and compare three pointer records |
| SM2 |Selected mode1 predecessor and LEN32 context lineage |Replay39 predecessor certificates and recheck initializer/context/phase producers;other entries need separate joins |
| SM3 |Valid nonwrapping frame,stable saved roots and coherent memory |Check mappings,owner,lifetime and outside writes;native extent of the saved view is unknown |
| SM4 |SSA widths,ORN/shift/CMP effects and frame aliases match source |All1640 captured nonbranch sites,three computed-index identities and all160 address checks cover these effects |
| SM5 |Local address identities are substituted with actual live bindings |Review the three source spans,constant replacements and retained other-register effects |
| SM6 |State epochs and dependency classifications are interpreted locally |Check raw-A replacement,800 live table cells,128 DAG dependency records and phase-cell rewrites;do not infer statistical independence |
| SM7 |Original authenticated pointers establish static target selection |Hardware PAC,exceptions,native authorization and traversal are not executed or proved |
| SM8 |Compact full expansion,caller output and daemon/kext pairing remain unknown |Trace0x100c21d7c with restored roots and the exact materialized state |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence needed |
| --- | --- | --- |
|High |Trace0x100c21d7c and its table/state consumers |Actual accesses using X26/X25/X23 and the new byte planes |
|High |Connect local state to caller output and cross-layer messages |Ownership,extents,publication and serialization chain |
|Medium |Recover compact algorithms for each64-byte expansion |Independent normalization of the retained full value SSA;layout alone is insufficient |
|Medium |Track the repurposed frame cells and saved view |First readers/writers of+0x730/+0x748/+0x750 and actual use of+0x568 |

The selected blocks are straight-line,with1465 instructions,160 stores/256 distinct bytes written and seven8 B loads. Source extraction/hashing and SSA construction are linear in bytes/instruction instances. The memoized dependency scan is linear in DAG size for this fixed input set. SMT runtime is solver-dependent,limited to15000 ms per query;unknown and timeout are rejected. Word arithmetic uses u32,address arithmetic uses u64,and extents/offsets are bytes.

QG1: Factual source,arithmetic,layout and metadata results are reported.

QG2: SM1-SM8 register assumptions,dependent conclusions and falsification probes.

QG3: Word spills,byte planes,value/dependency records,state epochs,control/root handoff and Mach-emission scope are covered for this increment;the full objective remains active.

QG4: Twenty spill equations,three computed indices,all store widths/offsets,128 dependency checks and exact load/store extents are reproducible.

QG5: The raw-A boundary,local size-control dependence,overwritten size/phase cells and saved-view register/memory roles are distinguished. Compact full expansion and native effects remain unknown.

QG6: Original recapture,1640 translated sites,68 UNSAT certificates,one abstract SAT check,exact ledgers and alteration controls establish scoped provenance.

QG7: Four impact-ranked continuation questions bound the expansion;whole algorithm,caller output and native exchange are not claimed.
