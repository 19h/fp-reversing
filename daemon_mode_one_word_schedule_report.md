# Mode1 four-stream word-grid extension

The continuation at0x100bdc3b0 extends the private word grid from four16-word streams to four64-word streams. Indices16..63 execute48 iterations,each with eight backward word reads and four new u32 stores. The192 new stores add768 B to the256 B initial word set,producing256 populated words/1024 B in the273-slot view. The complete indexing/control interface is proved;the69 byte-table access sites,compact value recurrence,algorithm identity,caller publication and native daemon/kext linkage remain unresolved. [WS1-WS8]

Evidence: [original source,pointers and live IDA spot-check context](triage_evidence/daemon_mode_one_word_schedule_source.json), [source certificates,word-grid induction and exact byte-access expressions](triage_evidence/daemon_mode_one_word_schedule_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_word_schedule.py), [validator](triage_evidence/validate_daemon_mode_one_word_schedule.py), [preservation](triage_evidence/daemon_mode_one_word_schedule_delivery.json), [quality gates](triage_evidence/daemon_mode_one_word_schedule_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_word_schedule_publication.py). Parent: [initial four-stream word population](daemon_mode_one_plane_consumer_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original image |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| Source |Three ranges,2026 instructions/8104 B;all2024 nonbranch sites translated |
| Main loop |1987 instructions,69 byte-load sites and21 store sites |
| Original recapture |Four predecessor ranges/5944 B |
| Pointer metadata |Two distinct authenticated-rebase records,three branch/modifier matches |
| SMT |Nine new and three replayed UNSAT certificates;one SAT abstract-domain check |
| Word reads |Eight sites,384 operations/1536 B over48 iterations |
| Word stores |Four sites,192 new words/768 distinct bytes |
| Final word grid |256 words/1024 populated bytes in273 slots/1092 B |
| Byte-table frontier |69 exact address/value inputs retained;3312 byte-read operations;complete bounds/value semantics not proved |
| Live IDA |Three64 B code spot checks match original source;no IDB mutation |
| Alteration controls |Five source/view/target/native-claim alterations rejected |
| Execution |No target execution,emulation,API/IPC requests or hardware PAC checks |

## Seed,roots and frame epochs

0x100d76e6c reads the retained u32 selector F+0x618=0xb8d8 and selects0x100bdc3b0 with IA diversity0x4a5b. It restores X13=F+0x8b0 from F+0x758. The original five-instruction view producer is recaptured and independently proved. [WS1-WS3]

| Interface | Value/role |
| --- | --- |
|W14 |Logical index16 |
|W12 |0x292=47*(16-2) |
|W5 |0x2dbe0883,encoded backward-read coordinate |
|W1 |47,word-grid stride |
|W16 |0xe01f,reciprocal helper |
|W24 |273,word-grid modulus |
|X13 |F+0x8b0,local word-view root |
|F+0x598 |u32 0x9033 |
|F+0x6cc |u32 0xd241f7ac |

The two scalar codec constants originate from(0xb8d8 XOR0xb8b3)*0x159=0x9033 and0x9033 XOR0xd241679f=0xd241f7ac. The seed stores both constants at their exact source addresses.

At0x100d76e78,the byte read from F+0xe5e is the physical position P(17),where P(j)=F+0xd00+((757*j) mod963). This is the forward digit-map position B[0] from the established table layout. The seed shifts that byte left4 and saves it as u32 F+0x6d8. F+0x6d8 therefore ceases to be the preceding four-round loop's counter. It is retained through the new loop as an arithmetic/table context. The prior map-value theorem supplies its earlier meaning;this increment proves its concrete load and store.

F+0x750 is overwritten with the current u32 index16..63 on each iteration. F+0x720/F+0x730/F+0x728 become u32 coordinate snapshots. Their earlier8 B coordinate/phase interpretations do not carry through these writes. No public structure type or full-width overwrite is inferred. [WS3,WS5]

## Four-stream word-grid ABI

Define W(L) as u32 at:

```
F+0x8b0 + 4*((47*L) mod273)
```

The four analytical stream bases are0,67,135 and204. The parent fills W(base+j) for0<=j<16. For each new index i in16..63,the source reads the following eight labels,in source order:

| Site | Logical label | Stream-relative position |
| --- | --- | --- |
|0x100bdc424 |i-15 |Stream0,i-15 |
|0x100bdc438 |i-2 |Stream0,i-2 |
|0x100bdc454 |204+i-15 |Stream204,i-15 |
|0x100bdc5b4 |204+i-2 |Stream204,i-2 |
|0x100bdca50 |135+i-16 |Stream135,i-16 |
|0x100bdcb18 |135+i-7 |Stream135,i-7 |
|0x100bdcc00 |67+i-16 |Stream67,i-16 |
|0x100bdcc04 |67+i-7 |Stream67,i-7 |

All eight complete original address expressions are proved for every selected index,with arbitrary named word/byte load values and carried register inputs. The address theorem does not assume particular message words. [WS4-WS5]

The four word stores use:

| Site | Logical label |
| --- | --- |
|0x100bdcbe4 |135+i |
|0x100bdda54 |67+i |
|0x100bde1a8 |i |
|0x100bde238 |204+i |

The destination at0x100bde1a8 uses an obfuscated masked sum. The universal source lemma proves(x AND47)+((x AND47) XOR47)=47. The actual live stride47 is separately certified before the source result is replaced. The other source effects remain intact. The four full store-address certificates then establish their logical labels without treating arithmetic data as an index premise. [WS4]

The finite coverage ledger starts with the parent's exact64 known word labels. At each index it checks that all eight reads name already populated words,that the four new destinations are distinct and were not previously populated,and that no new destination equals an in-iteration read. It then adds the four labels. After index63,the populated labels are exactly:

```
0..63, 67..130, 135..198, 204..267
```

The multiplier47 is invertible modulo273. Consequently,these256 labels occupy256 distinct word slots;17 slots remain outside the populated set. The192 new words are disjoint from all64 initial words. This is a coherent producer/read-order theorem for the local grid;it does not prove the compact value function of an expanded word. [WS3-WS6]

## Exact loop control and memory footprint

The entry index is16. The source preserves these next-iteration contracts:

```
W14 = i+1
W12 = 47*(i-1)
W5  = 0x2dbe0883+47*(i-15)  modulo2^32
X13 = F+0x8b0
W1=47; W16=0xe01f; W24=273
```

The terminal comparison uses the saved current index at F+0x750. It selects repeat for i<63 and exit for i=63. Hence the selected execution has47 repeat selections and one exit selection,for48 bodies. [WS4,WS7]

| Selector | Static target | IA diversity |
| --- | --- | --- |
|0xb8d8 |0x100bdc3b0 |0x4a5b |
|0xb8d9 |0x100c5917c |0x4a5b |

The new word writes occupy768 distinct bytes from F+0x8b4 through F+0xcf3,with gaps. Including the parent word set,the complete grid contains1024 written bytes within the1092 B bounding view F+0x8b0..F+0xcf3. Twelve bytes separate that view's exclusive end F+0xcf4 from scratch root F+0xd00.

The loop also has17 literal frame u32 store sites/68 B of aggregate frame stores per body,covering56 distinct frame bytes. These writes are disjoint from the word grid and protected roots,including F+0x618,F+0x6cc,F+0x6d8,F+0x738/F+0x740,F+0x758 and the budget F+0x1210. All963 scratch bytes remain unwritten. Aggregate stores are84 B per body and4032 B over48 bodies:3264 B of frame-write operations plus768 B of word writes. Aggregate reads are277 B per body and13296 B over48 bodies. Counts describe operations rather than distinct readable bytes. [WS5-WS6]

## Byte-table/value frontier and exact evidence boundary

All1986 nonbranch sites in the main body are translated. Their source SSA retains the eight word-load values,the69 byte-load values,their exact addresses,all frame-forwarding joins and the four word-store values. CNEG is modeled from the source comparison condition;UDIV uses the previously established zero-result behavior for a zero divisor. No decompiled algorithm name is substituted for these operations.

The byte inputs are an overapproximation of possible memory values. The word-address and control certificates are universal over those inputs,so they establish the indexing ABI despite unresolved lookup semantics. The full value recurrence and native readability of every computed byte access require additional work.

A combined query intended to prove all69 byte addresses lie within the963 B scratch domain returned unknown at the15000 ms limit. It is excluded from accepted certificates. The evidence explicitly records that the complete byte-address bound and byte-table semantics are not proved. This timeout is not evidence of an out-of-range access. No algorithm identity or native input reachability is inferred from the backward offsets or rotate instructions. [WS4-WS6,WS8]

## Live IDA context and architectural interfaces

The connected database named fairplayd was reachable. On the observation date2026-11-09,it reported input SHA-256 4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7,processor ARM and64-bit mode. Three64 B code reads at0x100bdc3b0,0x100d76e6c and0x100b4ef4c match the pinned thin source exactly. The retained snapshot is192 B of code agreement;it does not establish whole-image equivalence between the reported input and thin-file hashes. Replay checks the retained bytes against the original source and does not repeat the live IDA calls. [WS1]

The knowledge store reported nine facts. Targeted searches and recalled context did not yield a verified label for this word consumer;those notes are not used to identify its algorithm. IDA access was read-only;no annotations or database state were changed.

The recovered architectural touch points are the word-view root F+0x758,the scratch root F+0x738,the private branch-table root F+0x740,the saved selector F+0x618,and the new scalar/state epochs. The selected source has no call,trap,Mach send/receive operation,port creation,right transfer or external callback. No new incoming/outgoing Mach-port contract or message-emission site is established. The local1024 B grid is not identified as a caller-owned buffer or serialized daemon/kext payload. [WS1,WS7-WS8]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| WS1 |Pinned source,fixups and dated IDA spot-check provenance |Rehash8104 source bytes,recapture four lineage ranges,two pointer records and192 retained IDA code bytes;do not equate whole-image hashes |
| WS2 |Selected predecessor mode1 epoch |Replay three parent certificates and verify no prior consumer store overwrites F+0x618 |
| WS3 |Valid private frame,word-view root and coherent memory |Recheck root producers,initial64 labels,frame joins,native mapping/lifetime and outside writers |
| WS4 |Width-exact SSA,flags and proved masked-destination cut |Recheck all2024 sites,the universal47 identity,actual live stride,eight word reads,four stores and complete16..63 control domain |
| WS5 |Literal frame forwarding respects source chronology |Recheck latest same-width store origins,root preservation,word/frame disjointness and u32 epoch changes |
| WS6 |Coverage is a producer/read-order theorem,not a compact value theorem |Recompute48 ledger rows,384 backward reads,192 fresh stores and256 final labels;byte-table bounds remain unresolved |
| WS7 |Authenticated rebases establish static targets only |Recheck0xb8d8/0xb8d9 and0x4a5b;hardware PAC and native traversal are not executed or proved |
| WS8 |Whole algorithm,publication and native pairing remain unknown |Normalize69 byte-access expressions and value recurrence,then follow0x100c5917c through copy/return/serialization |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence needed |
| --- | --- | --- |
|High |Resolve69 byte-access bounds and table families compositionally |Local remainder/codec lemmas and current map/label invariants;the aggregate timeout is insufficient |
|High |Normalize four stream-output value equations |Byte-table algebra,word decoding and independent source equivalence |
|High |Follow0x100c5917c and the completed grid's consumers |Actual read/copy/return/publication chain and owner/extents |
|Medium |Connect static local output to cross-layer buffers |Serialization provenance and paired daemon/kext/native observations |

Source extraction,SSA construction and frame forwarding are O(I+A),with I captured instruction instances and A retained accesses. The explicit coverage pass is O(48*12) for this fixed domain and O(256) storage for known word labels. SMT complexity is solver-dependent,with15000 ms solver and20 s process limits. Accepted queries reject unknown/timeouts. All arithmetic widths are explicit u32/u64;frame offsets and extents are bytes.

QG1: Factual source,control,indexing and metadata results are reported.

QG2: WS1-WS8 identify assumptions,dependent results and falsification probes.

QG3: Four-stream word indexing,coverage,control,frame epochs,IDA provenance and Mach-emission scope are covered for this increment;the full objective remains active.

QG4: All384 word reads,192 fresh stores,1024 populated bytes,273-slot view and48 control iterations are reproducible.

QG5: Byte-table bounds/values,the compact recurrence,algorithm identity,native mapping and caller publication remain explicit unknowns;the excluded timeout is not promoted to evidence.

QG6: Original recapture,2024 translated sites,12 UNSAT certificates,one abstract SAT check,48 coverage rows,three IDA spot checks and five alteration controls establish scoped provenance.

QG7: Four impact-ranked followups preserve the unresolved value,publication and native-interface questions.
