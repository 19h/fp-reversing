# Mode1 post-table size fork,source passes and initializer ABI

The selected32 B mode1 path constructs the arithmetic tables,then reads the same source addresses twice more before a shared initializer. The new gate tests a saved size encoding with an exact zero-length preimage. Its nonzero edge enters two32-round byte mixers;their results are retained as two four-word register banks. The initializer writes32 literal words,two computed words and one frame-view pointer while preserving those banks and all816 identified arithmetic-table cells. Caller output,whole return and native daemon/kext exchange remain unknown. [PT1-PT8]

Evidence: [original source,pointers and earlier write census](triage_evidence/daemon_mode_one_post_table_passes_source.json), [source certificates and state SSA](triage_evidence/daemon_mode_one_post_table_passes_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_post_table_passes.py), [validator](triage_evidence/validate_daemon_mode_one_post_table_passes.py), [preservation](triage_evidence/daemon_mode_one_post_table_passes_delivery.json), [quality gates](triage_evidence/daemon_mode_one_post_table_passes_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_post_table_passes_publication.py). Parents: [digit maps and XOR](daemon_mode_one_digit_maps_report.md), [original paired source passes](daemon_mode_one_source_passes_report.md), [request/size/frame ABI](daemon_mode_one_adapter_report.md).

| Evidence | Verified scope |
| --- | --- |
| Image |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| New routines |Eight ranges,535 instructions;527 nonbranch sites |
| With lineage cuts |Twelve ranges,620 instructions/2480 B;all611 nonbranch sites translated |
| Earlier recapture |27 ranges/9836 B;overlapping prior captures are counted separately |
| Metadata |Nine original pointer records;eleven branch/modifier matches |
| SMT |20 new plus three replayed UNSAT certificates;one SAT decoder counterexample and one SAT abstract-domain check |
| Reads |64 new byte reads over32 distinct source offsets;no loop stores or SP writes |
| Initializer |32 literal u32 stores,two computed u32 stores,one u64 frame-view store |
| Preservation |816 arithmetic-table cells;source,size,scratch/branch roots and budget retained through this increment |
| Controls |Four source/load/branch/native-claim alterations rejected by fresh original-source comparison |
| Execution |No target execution,emulation,API/IPC requests,hardware PAC or IDB mutation |

## Size gate and source provenance

The private request supplies LEN from u32[OBJ+0x58] and SRC=OBJ+0x18. The earlier aligned decoder and normalization supply a source-defined word f(LEN),published at F+0x750 by STR W13 at0x100d5e010. The new proofs establish:

```
f(LEN)==0x16f293c0  iff LEN==0
f(32)==0x16f293e0
```

The global identity f(LEN)=u32(LEN+0x16f293c0) is false. Its SAT counterexample is an abstract arithmetic result,not a native input. The source decoder is retained in full;the gate interpretation uses its proved equality preimages instead of replacing the decoder with that false identity. [PT2,PT4-PT5]

The preceding digit-map routine exits with W1=0xa0c1 and W8=0x0d.0x100daee68 saves the fixed image-data base X23=0x100f715a0 to F+0x450,loads the saved word at0x100daee74,and selects:

| Saved word | Selector / target | Meaning under saved-word lineage |
| --- | --- | --- |
|0x16f293c0 |0xa0c1 ->0x100dda7d8 |Zero-length conditional edge to shared initializer |
|Any other word |0xa0cc ->0x100bd6bbc |Source-mixer setup;selected LEN32 takes this edge |

This does not establish that LEN0 reaches the gate through the preceding table path. Earlier admission includes separate source-pointer/size conditions. The zero edge is a conditional local contract;the proved normal continuation here is LEN32. [PT2,PT7]

SRC was forwarded in X30 by the original source-pass entry and stored at F+0x458 by0x100d5e38c. Fresh recapture and the earlier write census establish the two saved-cell publications and no subsequent direct frame-store overlap. The other intervening stores are source-certified byte writes in T+[0,962],where T=F+0xd00;that domain is disjoint from F+0x458 and F+0x750. Valid private-frame and source-owner premises remain explicit. [PT1-PT4]

## Two additional32-round source walks

The setup at0x100bd6bbc writes phase0x87c8 to F+0x748. This cell previously held a shuffle seed word;that seed's last consumers are earlier in the table-construction path. The new store changes its role rather than preserving the earlier seed-word invariant. The between-pass setup later rewrites the same cell to0x4923. It remains a private phase/mode cell through the new handoff. [PT3,PT6]

| Routine | Source and control contract |
| --- | --- |
|0x100d77c1c |Loads SRC from F+0x458;LDRB at0x100d77c24 reads SRC[j],j=0..31 |
|0x100d77860 |For j<31,advances byte index and encoded counters,then returns to the first loop |
|0x100d64a00 |After j=31,preserves the first four-word bank,sets the second seeds,reloads SRC and rewrites F+0x748 to0x4923 |
|0x100bf2de0 |LDRB at0x100bf2de4 reads SRC[j],j=0..31;advances its counters in the loop body |
|0x100dac01c |After the second j=31,transfers bank words and size/mode to the shared initializer |

The first loop's current/end/pivot are0xd83d9e7c+j,0xd83d9e9b and0xd83d9e7b. The second uses0x17774f93+j,0x17774fb2 and0x17774f92. Source comparison/CSEL certificates establish exactly32 rounds in each case. Neither loop writes memory or changes SP. Both access the same32 source addresses as the earlier paired passes. Equality of native byte values across these stages requires stable-source premises;native concurrency and scheduling are unknown.

The new mixers contain u32 addition/subtraction,XOR,rotation and reciprocal reduction. Their source byte injections reduce to:

```
first:  Z=u32((byte+j)*0x0d1586fd -B +0xed2cd9c2)
second: Z=u32((byte+j)*0x0d1586fd -B +0x6b035573)
shared reduction: u32((Z mod257)-Z)
```

Here B names the respective source accumulator,not the arithmetic digit table. The reciprocal0xff00ff01 shifted by40 gives floor(Z/257) for every u32 Z. Both original source reduction shapes are independently checked. The first reduction also contains masked expressions whose combined constant cancels to zero. Exact SSA definitions and output expressions for both full loop bodies are retained in the checks artifact. A compact equivalence of these two recurrences is not proved,and neither a standard hash/cipher identity nor equality of their final banks is claimed. [PT4-PT6]

## Register and memory epochs at the initializer

The first loop's four-word bank resides in W10,W5,W25,W14. The between-pass setup and complete second loop preserve all four. The second loop's bank resides in W13,W11,W19,W4. The handoff copies W19 to W3 and W4 to W26,and sets W30=u32(W14+0xad732488). These are u32 arithmetic values moved through registers,not recovered native pointer types.

| Bank at initializer exit | Representation |
| --- | --- |
|First |W10,W5,W25,W30;the fourth word has the0xad732488 additive representation |
|Second |W13,W11,W3,W26;the last two were moved from W19/W4 |

0x100dda7d8 preserves all eight represented words. It sets W22=0xad732488,so the representation constant is explicitly present for downstream use;no later decoding or algorithmic interpretation is assigned here. [PT5-PT6]

The initializer performs35 exact stores. Its32 literal u32 values occupy a sparse set between F+0x3b0 and F+0x433. F+0x424..0x427 is a hole:these source instructions do not initialize it. The complete site/offset/value ledger is retained under `literal_words` in the checks artifact. The report does not assign that hole a zero value or describe the literals as one fully initialized contiguous array.

On the selected LEN32 path,the computed u32 stores are0xec2864b6 at F+0x434 and0x3874e8e9 at F+0x44c. The u64 store at0x100ddaa8c publishes F+0x8348 into F+0x568. This is a derived frame view beyond the core's fixed reservation;its downstream offset decoding,native validity and accessible extent remain unknown. The source merely constructs and saves the value here. It does not dereference that view in this initializer. [PT3-PT6]

The gate,setup,between-pass body and initializer write only their certified fixed frame locations. Both loops and the first-loop advance write no memory. These writes are disjoint from all816 identified arithmetic-table cells,the saved source/size cells,the scratch/branch roots and the8 B budget cell at F+0x1210. That preservation stops at the terminal branch0x100ddaa94.

## Private control and external-interface boundary

| Source | Private selector / original continuation | IA diversity |
| --- | --- | --- |
|Gate |a0c1 ->dda7d8;a0cc ->bd6bbc |c0c5 |
|First setup/advance |663b ->d77c1c |6f79 |
|First loop |8980 ->d77860;89a3 ->d64a00 |d546 |
|Between/second loop |87c8 ->bf2de0;87c6 ->dac01c |a17c |
|Handoff |8ad6 ->dda7d8 |7124 |
|Initializer |6284 ->0x100bdba34 |cdf0 |

Abbreviated target addresses in this table retain the common0x100 prefix. Branch slots and modifiers match original authenticated rebases. No call,trap or Mach emission occurs in these captured routines. There is no new incoming/outgoing port,name,right or message contract. Hardware PAC,native ownership,authorization,exceptions and actual traversal remain unknown. The normal path reconverges with the gate's conditional zero edge at the same initializer,but through a different authenticated pointer slot. [PT7-PT8]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| PT1 |Pinned original bytes,unslid addresses and original fixups |Rehash image,recapture all code and earlier write sites,compare pointer metadata |
| PT2 |Aligned mode1 object/request contract and selected nonnull LEN32 path |Recheck original decoder/admission and saved-size publication;do not infer zero-edge reachability |
| PT3 |Valid nonwrapping frame,source owner and coherent memory,with required nonaliasing |Check mappings,lifetimes and outside writes;the F+0x8348 view has no proved native extent |
| PT4 |Saved source/size cells survive the intervening local table writes |Review refreshed fixed-store census and prior scratch-address contracts;outside writes invalidate the join |
| PT5 |SSA widths,comparison roles,rotations and unsigned reduction match source |All611 captured nonbranch sites,source-shape and exact quotient certificates check these properties |
| PT6 |Register/state and memory epochs are interpreted at the correct stage |Check F+0x748 reuse,the bank-preserving handoffs,all35 stores and the F+0x424 gap |
| PT7 |Original authenticated-pointer records establish static target selection |Native PAC,exceptions and actual feasibility are not executed or proved |
| PT8 |Whole operation,caller output and daemon/kext linkage remain unknown |Trace0x100bdba34 and later bank/table/view consumers through publication and serialization |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence needed |
| --- | --- | --- |
|High |Trace0x100bdba34 and the two bank consumers |Source transformation connecting retained banks,literals and arithmetic tables |
|High |Resolve the saved F+0x8348 view before assigning an output buffer |Actual offset expressions,accesses,owner and extent |
|Medium |Recover compact full semantics of both new mixers |Independent algebraic normalization beyond the proved injection/reduction components |
|Medium |Trace the untouched F+0x424 word and later writes |Its first writer/reader and correct state epoch |

The two loops use64 byte reads over32 offsets and no loop stores. Source extraction/hashing is linear in bytes;the read/control induction is O(n) for n=32. Retained SSA is linear in modeled instruction instances;SMT runtime is solver-dependent with15000 ms per query. Unknown and timeout are rejected. Arithmetic widths are explicit8/32/64 bits;extents and offsets are bytes.

QG1: Factual source,metadata and arithmetic results are reported.

QG2: PT1-PT8 register assumptions,dependent conclusions and falsification probes.

QG3: Size control,source provenance,read bounds,state handoff,frame writes and Mach-emission scope are covered for this increment;the full objective remains active.

QG4: Word widths,encoded counters,quotient identity,source offsets and exact store extents are reproducible.

QG5: The false global decoder identity,conditional zero edge,F+0x748 reuse,two distinct recurrences and sparse initializer hole are explicitly separated.

QG6: Original recapture,611 translated sites,23 UNSAT certificates,two distinct SAT results,exact ledgers and alteration controls establish scoped provenance.

QG7: Four impact-ranked continuation questions bound the expansion;whole output,native exchange and algorithm identity are not claimed.
