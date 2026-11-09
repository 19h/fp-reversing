# Mode1 four-round plane gather and local word scatter

Current extension: [Four-stream word-grid extension](daemon_mode_one_word_schedule_report.md) proves48 iterations,384 backward word reads and192 fresh u32 stores,completing four64-word streams/1024 populated bytes in a273-slot private view. All2024 captured nonbranch sites translate;12 UNSAT pass and three IDA code spot checks match the original source. All963 scratch bytes remain unwritten. Byte-table bounds/value semantics,compact recurrence,algorithm identity,caller publication and native daemon-kext exchange remain unknown.

0x100b4ef4c consumes both64-byte state planes in four rounds. Each round reads sixteen bytes from each plane,stores sixteen u32 values into the local F+0x8b0 view and advances an eight-word state. The entire128-byte plane input is read exactly once;64 distinct output words occupy256 B. All963 scratch bytes are preserved. The saved F+0x8348 value is a biased arithmetic anchor whose actual accesses reduce to the existing scratch region. Compact whole-transform semantics,caller publication and native daemon/kext exchange remain unknown. [PC1-PC8]

Evidence: [original source and pointer records](triage_evidence/daemon_mode_one_plane_consumer_source.json), [source proofs,access ledger and state dependencies](triage_evidence/daemon_mode_one_plane_consumer_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_plane_consumer.py), [validator](triage_evidence/validate_daemon_mode_one_plane_consumer.py), [preservation](triage_evidence/daemon_mode_one_plane_consumer_delivery.json), [quality gates](triage_evidence/daemon_mode_one_plane_consumer_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_plane_consumer_publication.py). Parents: [source absorption](daemon_mode_one_source_absorption_report.md), [original local views](daemon_mode_one_source_passes_report.md), [saved biased view](daemon_mode_one_post_table_passes_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original image |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| Source |Four ranges,1486 instructions/5944 B;all1483 nonbranch sites translated |
| New loop |1222 instructions,32 byte-load sites and56 store sites |
| Original lineage recapture |Nine ranges/3332 B |
| Metadata |Three distinct authenticated-rebase records,four branch/modifier matches |
| SMT |Nineteen new plus three replayed UNSAT certificates;one SAT abstract-domain check |
| Address cuts |Three universal source identities;two additional actual-input binding certificates |
| Frame coherence |Sixty-five literal frame loads per round;25 forward values from current-round stores |
| Data |128 plane-byte reads,64 distinct u32 output stores,256 output bytes |
| Dependency certificates |Sixteen output words and eight carried state words |
| Alteration controls |Five source/view/target/native-claim alterations rejected |
| Execution |No target execution,emulation,API/IPC request,hardware PAC check or IDB mutation |

## Root provenance and the resolved biased view

The original entry at0x100d5dfd4 constructs F+0x890,then saves F+0x8b0 into F+0x758 and F+0xd00 into F+0x738. The later initializer saves F+0x8348 into F+0x568. Fresh source certificates cover all three values and their exact store addresses. [PC1-PC3]

Let T=F+0xd00 and P(j)=T+((757*j) mod963). The first read of the biased-view value occurs at0x100b4f028;the first resulting byte access is0x100b4f058. For round r in0..3,the corresponding address simplifies as follows:

```
phase = 12112*r = 757*16*r
n     = 757*(40+16*r)
q     = floor(n/963)
F+0x8348+phase-963*q = T+(n mod963)
```

The last equality uses0x8348=0xd00+40*757. The source's UMULH/shift sequence implements the required quotient for every selected round. A second biased-view read and the remaining address expressions are independently included in the32-address round certificates.

Thus this consumer does not dereference F+0x8348 as a large remote buffer base. Its concrete byte accesses fall in the already identified963 B scratch domain. This resolves the earlier saved-view interpretation for this consumer. Native frame mapping,lifetime and outside writers remain separate assumptions;the certificate does not assign a public buffer type to the anchor. [PC3-PC5]

## Four-round control and state schedule

The preceding handoff seeds X7=0,W3=0x3f0,W20=0x33 and u32 F+0x6d8=0. Coordinate registers and frame cells contain multiples of757. Each round adds0x2f50=12112=16*757 to every next-round coordinate,adds4 to F+0x6d8,subtracts16 from W3 and adds16 to W20.

| Round r | F+0x6d8 on entry | X7 on entry | Selection |
| --- | --- | --- | --- |
|0 |0 |0 |Repeat |
|1 |4 |12112 |Repeat |
|2 |8 |24224 |Repeat |
|3 |12 |36336 |Exit |

At0x100b500fc,the comparison of the updated counter against15 selects repeat for r<3 and exit for r=3. The source proves every coordinate,register constant,root and saved schedule value needed by the next round. All four possible round residues are certified;they are the complete selected induction domain. No target trace is used to infer the four iterations. [PC2,PC4,PC7]

| Selector | Target | IA diversity |
| --- | --- | --- |
|0x803e |0x100b4ef4c |0x505b |
|0x8049 |0x100d76e6c |0x505b |

The final counter is16 and the next X7 phase is48448. F+0x750 retains the current-round phase36336 until a later writer;it is distinct from the next X7 value.

## Exact plane reads and local word output

For every round,the thirty-two byte loads gather:

```
Plane0[16*r .. 16*r+15]
Plane1[16*r .. 16*r+15]
```

Plane0 occupies logical indices40..103 and Plane1 indices112..175 under P. Some source loads reorder adjacent bytes;the exact32-site order,positions and physical offsets are retained. Over four rounds,all128 addresses are distinct and cover both complete planes. No arithmetic-table byte,image byte or further SRC byte is read in this loop. [PC4-PC6]

The sixteen word stores in source order use analytical bases:

```
b = [0,204,135,67, 1,205,136,68,
     2,206,137,69, 3,207,138,70]
address(r,b) = F+0x8b0 + 4*((47*(4*r+b)) mod273)
```

The source's masked/averaged reciprocal reductions are proved against these addresses for every selected round. The logical labels cover four16-word runs:0..15,67..82,135..150 and204..219. Multiplication by47 permutes modulo273 because gcd(47,273)=1. The retained finite ledger verifies all64 destinations directly. All stores are4 B and aligned relative to F+0x8b0. [PC4-PC6]

The written byte set spans F+0x8b0 through F+0xce3 inclusive,but is sparse:256 distinct bytes within a1076 B bounding span. The reduction domain has273 word slots;only64 are written by this consumer. These are private frame stores. Neither their contiguity nor their publication as a caller-owned result is established.

Per round,the loop performs508 B of aggregate reads and348 B of aggregate stores. The stores comprise64 B of word-output writes and284 B of frame/control/state writes. Over four rounds,this is2032 B of read operations and1392 B of store operations. Reused frame locations account for the difference between aggregate accesses and distinct bytes:the complete loop writes536 distinct bytes,comprising256 word-output bytes and280 frame bytes. These two sets are disjoint and lie below T. Every byte of the963 B scratch domain,including all128 plane cells and800 live arithmetic-table cells,is preserved. [PC3,PC6]

## Three hidden address identities and coherent frame reads

The full1221-instruction nonbranch body is retained as width-exact SSA. Three substitutions are justified by universal original-source lemmas:

| Source endpoint | Register | Proved replacement |
| --- | --- | --- |
|0x100b4f878 |W1 |0xd0 |
|0x100b4fa14 |W19 |963 |
|0x100b4fff0 |W4 |4*r+0x43 |

The first identity combines complementary byte masks. Its actual live inputs satisfy W21=W12+0xa3e88c8f,which has its own source certificate. The second cancels complementary masked words to produce the divisor963 for arbitrary input words. The third uses(x AND0x43)+((x AND0x43) XOR0x43)=0x43;its actual masked operands and counter binding are separately certified. Other registers retain their original source effects when a cut replaces its single proved result. [PC4-PC5]

Frame loads are not modeled as unrelated free values after stores. The validator forwards each literal SP-relative read from the most recent same-width store,or from an explicit round-entry root,schedule or state premise. It rejects inconsistent overlapping cells or widths. Twenty-five of the65 frame reads use current-round source stores. Both the store addresses and all forwarded-load addresses have dedicated certificates. The output-address proofs then establish disjointness from these frame cells,closing the alias condition required for this local forwarding model. [PC3-PC5]

## Eight-word carried state and plane-dependent outputs

The analytical state inputs are:

| Name | Round-entry location |
| --- | --- |
|J0,J1,J2 |u32 F+0x6c0,F+0x6c4,F+0x6c8 |
|J3,J4 |u32 F+0x6bc,F+0x748 |
|J5,J6,J7 |W0,W25,W26 |

All eight exit expressions and all sixteen word-store expressions are retained in the source SSA. The dependency scan follows every SSA definition and coherent frame join. It establishes two closed state families:

```
next(J0,J1,J2,J6) depends only on (J0,J1,J2,J6)
next(J3,J4,J5,J7) depends only on (J3,J4,J5,J7)
```

No newly gathered plane-byte symbol or round-index symbol occurs in any carried-state expression. The sixteen word-output value expressions likewise contain no direct round-index symbol;their source-byte positions and destination coordinates still change each round. This is a positional transducer contract,not a claim that the complete transform is independent of the original input:the incoming eight words already have predecessor input lineage. [PC2,PC5-PC6]

The first word output retains Plane0 byte symbols and J0;the second retains Plane1 byte symbols and J4. The third store at0x100b4f380 retains source-SSA symbols from both planes plus carried state. Every later output's variable set is recorded. These are exact structural absence/containment certificates,not proofs that every retained variable is semantically essential or statistically independent. Compact normalization of the two four-word recurrences and byte-to-word output expressions remains unknown.

## Frame epochs and architectural scope

The entry overwrites F+0x6cc with W20's control value,F+0x6d0 with an8 B coordinate,F+0x690 with W3's countdown and F+0x750 with the8 B current phase. Their earlier materialized-word/phase roles end here. The materialized words already reloaded into W0/W25/W26 enter the state separately. F+0x748 is written twice in each round;later reads use the intervening or final value according to source order. [PC5-PC7]

The source/image roots F+0x450/F+0x458,the saved view F+0x568,the arithmetic-bank roots,the scratch/branch roots F+0x738/F+0x740,the local word root F+0x758 and budget F+0x1210 are preserved. The fixed frame and saved-view roots are private architectural touch points. The loop has no calls,traps,Mach send/receive operations,port creation/right transfers or external callbacks. No new incoming/outgoing Mach-port contract or message-emission site is established. [PC1,PC6-PC8]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| PC1 |Pinned image,unslid source and original fixups |Rehash image,recapture5944 source bytes,nine lineage ranges and three distinct pointer records |
| PC2 |Selected mode1 predecessor epoch |Replay three parent certificates and compare fresh parent source;other entries require separate joins |
| PC3 |Valid nonwrapping private frame,coherent roots and no outside writes |Check native frame mapping/lifetime;recompute output/control/scratch disjointness before forwarding memory values |
| PC4 |Width-exact SSA,UMULH,UBFX,UDIV,shifts and flags match source |Recheck all1483 translated sites,three local identities,two actual-input bindings and complete four-residue address certificates |
| PC5 |Proved cuts preserve other source effects and frame chronology |Inspect bindings,all65 frame-read origins,25 current-round forwards and the twice-written F+0x748 epoch |
| PC6 |Plane coverage,word scatter and dependency scope are local |Recompute128 reads,64 unique u32 stores,24 DAG certificates and all963 preserved scratch bytes |
| PC7 |Source induction and authenticated-rebase metadata imply static targets only |Recheck coordinate updates,counter0/4/8/12,selectors and modifiers;hardware PAC/native traversal remain unknown |
| PC8 |Private stores do not establish caller publication or full algorithm identity |Follow0x100d76e6c and later output readers,return,ownership and serialization |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence needed |
| --- | --- | --- |
|High |Follow0x100d76e6c and the64 scattered word consumers |Actual output-read/return/publication chain and remaining state dependencies |
|High |Normalize the two closed four-word state recurrences |Compact equations with independent source equivalence,then four-round composition |
|Medium |Normalize the sixteen byte/state word-output expressions |Actual packing/encoding equations and semantic dependence witnesses |
|Medium |Connect this private view to cross-layer buffers |Owner,extents,copy/serialization producer and paired daemon/kext evidence |

Source capture,SSA construction,frame forwarding and fixed-domain set checks are O(I+A),with I instruction instances and A retained access/dependency records;the fixed eight-word input set bounds dependency-set size. Storage is O(I+A). SMT complexity is solver-dependent,with15000 ms solver and20 s process limits;unknown and timeout are rejected. Arithmetic uses exact u32/u64 widths;UMULH is represented by the high64 bits of a128-bit unsigned product. All frame offsets and access extents are bytes.

QG1: Factual source,data-flow,address and metadata results are reported.

QG2: PC1-PC8 identify dependent assumptions and falsification probes.

QG3: Plane consumers,local word-output ABI,state families,frame chronology,control induction and Mach-emission scope are covered;the full objective remains active.

QG4: All128 byte reads,64 u32 destinations,access widths,aggregate/distinct byte counts and four round residues are reproducible.

QG5: Biased anchors versus actual accesses,private outputs versus publication,structural dependencies versus essential variables,and saved versus next phases are distinguished.

QG6: Original recapture,1483 translated sites,22 UNSAT certificates,one abstract SAT check,24 dependency certificates and five alteration controls establish scoped provenance.

QG7: Four impact-ranked followups bound further work;compact full transform,caller publication and native exchange remain unknown.
