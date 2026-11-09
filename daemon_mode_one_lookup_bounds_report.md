# Mode1 word-extension byte-lookups: all69 scratch bounds

Current extension: [All 69 word-extension lookup families](daemon_mode_one_lookup_roles_report.md) classifies 16 B, 8 U, 23 C, 14 D and 8 Q sites, covering 3312 reads over 48 iterations within an 800-cell table union. Source-ordered codomain induction passes with 378 checked transfers, 23 universal unary proofs, 743 UNSAT and 10 SAT results. Concrete values, the compact word recurrence, caller publication and native daemon-kext pairing remain unknown.

All69 byte-access sites in0x100bdc3b0 are now bounded to offsets0..962 from T=F+0xd00. The proof covers the source expressions behind all3312 byte reads in the selected48-iteration word-extension loop. It combines typed source normalization,237 independently checked range transfers,four exact reciprocal identities and two universally nonzero divisors. Nineteen sites also resolve directly to established digit-map regions. The remaining table-family/value interpretation,compact recurrence,algorithm identity,caller publication and native daemon/kext linkage remain unknown. [LB1-LB8]

Evidence: [recaptured source and lineage](triage_evidence/daemon_mode_one_lookup_bounds_source.json), [component queries,normalization/range ledgers and69 access certificates](triage_evidence/daemon_mode_one_lookup_bounds_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_lookup_bounds.py), [validator](triage_evidence/validate_daemon_mode_one_lookup_bounds.py), [typed DAG/range frontend](triage_evidence/daemon_word_lookup_algebra.py), [preservation](triage_evidence/daemon_mode_one_lookup_bounds_delivery.json), [quality gates](triage_evidence/daemon_mode_one_lookup_bounds_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_lookup_bounds_publication.py). Parent: [word-grid extension](daemon_mode_one_word_schedule_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original image |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| Fresh original source |Three ranges,2026 instructions/8104 B |
| Parent translation replay |All2024 distinct nonbranch sites;four prior ranges/5944 B recaptured |
| Source SSA |1963 value bindings;4394 canonical DAG nodes including address/pattern checks |
| Normalization |6143 recorded rewrite applications;ten symbolic rewrite schemas and one closed-fold query batch |
| Range inference |237 nontrivial node transfers,each independently UNSAT-checked |
| SMT |268 UNSAT,including12 predecessor replays;four SAT domain/negative-control results |
| Coverage |69/69 byte-address sites,3312 read operations over48 iterations |
| Direct map subsets |Twelve B sites and seven U sites |
| Alteration controls |Five source/root/target/native-claim alterations rejected |
| Execution |No target execution,emulation,API/IPC request,new IDA access,IDB mutation or hardware PAC check |

## Closed source-address contract

Every source byte-address expression is an addition of the verified root T and a zero-extended index. Some source paths first extract the low16 bits;others promote a u32 index directly. The frontend checks the actual other addition operand against the canonical F+0xd00 expression. It does not infer the base merely from a similar address shape. [LB1-LB4]

All69 indices reduce to a remainder modulo963. Their quotient constructions partition as follows:

| Source quotient family | Sites | Checked argument domain |
| --- | --- | --- |
|32-bit product by0x2207,shift23 |15 |0<=N<=65535;actual upper bounds do not exceed52990 |
|64-bit product by0x440dd3,shift32 |10 |0<=N<=727477 |
|64-bit product by0x440dd2cf,shift40 |35 |All u32 N |
|32-bit product by0x649eb3,shift23 |7 |0<=A<=15;N=757*A |
|UDIV with an obfuscated divisor |2 |All u32 numerators;divisor universally equals963 |

The four reciprocal lemmas establish exact equality to floor(N/963),or floor(757*A/963) for the final family. They use bounded integer arithmetic,not sampled input evaluation. The source checker verifies the corresponding product width,shift,numerator identity,low-word quotient extraction and subtraction by963 for every site. One short-product quotient uses N AND0xffff;its independently established N bound makes that mask an identity. [LB3-LB5]

For each site,the retained certificate includes its original index node,numerator or argument node,coefficient/shift,argument range,maximum source product,integer quotient bound and optional low16 extraction. It verifies that the multiplication fits its actual32-bit or64-bit container and that the quotient fits u32. The exact Euclidean remainder therefore lies in0..962 without unsigned subtraction underflow. That remainder also fits16 bits,so UXTH paths preserve its value.

These are conservative bounds. The proof does not establish that either endpoint is attained at a native invocation,that all963 locations are read,or that any particular input produces a particular index. [LB4-LB6]

## Why the aggregate timeout is resolved

The preceding report's combined69-address query returned unknown at its15000 ms limit. A further diagnostic comparing complete raw and normalized graphs in one query also returned unknown. Neither result is accepted as a certificate.

The accepted construction uses an induction over typed source expressions. The normalizer records constant folding,commutative operand ordering,zero-extension composition,and low extraction/extension identities. Ten distinct symbolic rewrite schemas are proved with fresh operands. All2587 closed constant folds are checked in one separate closed-expression query. The6143 application records link those identities to actual DAG nodes and source bindings;they include address-shape matching work as well as source-expression normalization. Unchanged operators retain their original typed structure. [LB3-LB4]

Range inference combines unsigned intervals and known-zero/known-one masks. It does not trust the frontend's computed result alone. For every nontrivial transfer needed by the bounded reciprocal arguments,the validator declares fresh operands,asserts only their already derived facts,and asks whether the claimed output range/masks can fail. All237 such queries are UNSAT. Constant leaves and full-width unconstrained leaves terminate the induction.

Thus the accepted proof consists of local normalization identities,checked transfer steps,exact reciprocal lemmas,Euclidean remainder arithmetic and per-access structural matches. It does not depend on the excluded monolithic queries completing. No additional SIZE or iteration-range restriction is used for the new numeric bounds once the parent source model's established entry/root/codecs are in place. Every free word input,byte-load value and scalar retains its source width. [LB2-LB5]

## Two hidden divisors are universally963

The UDIV sites are0x100bdd0e4 and0x100bdd3e0. Both quotient results feed byte addresses in the same remainder shape. The first source divisor is the following expression in an arbitrary u32 V:

```
((V AND0x3c3) XOR0x700966ca)
AND ((V AND0x3c3) XOR0x716d7788)
XOR ((V AND0x281) XOR0x7009654b)
```

The second is:

```
((V+0x827aa) XOR(0x55-V)) AND0x3c3
```

All operations wrap to u32;AND binds before the outer XOR in the first display. Separate universal bit-vector certificates prove that each expression equals0x3c3=963. The frontend also matches each actual source divisor to its corresponding expression,including the shared live operand. The actual UDIV numerator and denominator are checked in the retained zero-divisor-guard/quotient AST. Consequently,the zero-divisor branch is unnecessary for these two proved local divisor expressions. Hardware execution or native exception behavior is not tested. [LB4-LB5]

## Nineteen directly resolved digit-map accesses

Let P(j)=T+((757*j) mod963),as in the previous map reports. Twelve sites have source-proved numerator757*(17+A),where0<=A<=15. Their addresses therefore lie in the forward digit-map B positions P(17)..P(32). Seven sites have numerator757*A with0<=A<=15,and lie in the inverse digit-map U positions P(0)..P(15).

| Established positional subset | Sites |
| --- | --- |
|B |0x100bdccf4,0x100bdcd00,0x100bdcd2c,0x100bdcd6c,0x100bdcdc8,0x100bdcdec,0x100bdce48,0x100bdce6c,0x100bdceec,0x100bdcf4c,0x100bdcf88,0x100bdd000 |
|U |0x100bddf8c,0x100bddf94,0x100bddfa0,0x100bde038,0x100bde044,0x100bde0c0,0x100bde148 |

These are positional identifications using established map regions. This increment does not substitute the maps' values into the word recurrence. The other50 sites are bounded to scratch,but their complete table-family/value classification remains open. In particular,a remainder modulo963 alone does not identify a C,D,Q,B or U operation. [LB5-LB6]

## Data-flow,control-flow and architectural consequences

The parent proof establishes48 bodies with69 byte-read sites each:69*48=3312 byte-read operations. Every such address now falls in the963 B scratch domain. The parent also proves that word-grid and literal frame stores remain below T. Therefore,the word-extension loop reads these byte inputs from the scratch region it leaves unwritten;the byte-address bound is no longer an unresolved local premise. Native mapping,lifetime and concurrent modification remain separate questions. [LB2,LB6-LB8]

The completed word grid remains256 words/1024 populated bytes in a273-slot/1092 B view below T. This increment does not change the four-stream indexing/control theorem or infer an externally visible buffer. It adds the byte-read footprint to the existing private-frame ABI.

The same source bodies contain no call,trap,Mach send/receive operation,port creation,right transfer or external callback. No new incoming/outgoing Mach-port contract or message-emission location is established. No native daemon/kext exchange,hardware PAC success or complete cryptographic primitive is inferred from the bounds. [LB1,LB7-LB8]

## Independent controls and assumptions

Changing the short reciprocal from0x2207 to0x2208 produces a satisfiable counterexample query over N0..65535. Claiming an upper bound14 for X AND15 also produces a satisfiable counterexample. These two controls show that altered arithmetic/range claims are distinguishable by the checker. They are abstract mathematical witnesses,not observed target behavior. The other two SAT results are nonempty-domain checks,one replayed and one new.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| LB1 |Pinned original source and prior ABI evidence |Rehash source,recapture8104 B and four lineage ranges,and compare fresh parent source |
| LB2 |Parent selected entry,roots,codecs and frame chronology |Regenerate and compare all parent translations/semantics and replay its12 UNSAT plus one SAT result |
| LB3 |SMT parsing,typed aliases and normalization applications preserve source structure |Check1963 binding widths,4394 typed nodes,6143 application records,ten symbolic identities and the closed-fold batch |
| LB4 |Range facts follow only from sound local transfers |Independently prove237 fresh-operand transfer queries;reject unknown/timeouts and verify two negative controls |
| LB5 |Each source quotient/remainder matches an exact arithmetic family |Recheck all69 structural matches,integer lemmas,product widths,divisor bindings and low16 preservation |
| LB6 |Bounds and partial map identification are interpreted conservatively |Recompute fifteen/ten/thirty-five/seven/two family counts and19 map sites;do not infer endpoint attainment or unknown table values |
| LB7 |Valid nonwrapping private frame and coherent mapped memory |Verify native owner,lifetime,mapping and outside writers;source offsets alone do not establish native access validity |
| LB8 |Whole recurrence,algorithm identity,publication and native pairing remain unknown |Classify the remaining50 sites,substitute table algebra and follow the completed grid through caller/serialization interfaces |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence needed |
| --- | --- | --- |
|High |Classify the remaining50 lookup sites |Logical-region identities and label/encoding invariants,not only963-byte bounds |
|High |Recover the four stream-output equations |Established B/U/C/D/Q values composed through the original value SSA |
|High |Trace0x100c5917c and the completed grid's consumers |Actual read/copy/return/publication chain and owner/extents |
|Medium |Connect private frame data to cross-layer buffers |Serialization provenance and paired daemon/kext/native observations |

DAG construction,typed interning,normalization and memoized range analysis are O(V+E+R) time and storage for V nodes,E operand edges and R recorded rewrites. The source widths are fixed. Local proof runtime is solver-dependent;each query has a15000 ms solver limit and20 s process limit. Source offsets/extents are bytes;products,quotients and shifts use their explicit32-bit or64-bit widths.

QG1: The report states factual source,arithmetic,range and footprint results.

QG2: LB1-LB8 identify assumptions,dependent results and falsification probes.

QG3: All69 byte-address bounds,normalization/range evidence,partial digit-map positions and architectural/Mach scope are covered;the full objective remains active.

QG4: Family counts,integer domains,overflow checks,237 transfer queries,3312 read operations and all69 access certificates are reproducible.

QG5: The two excluded aggregate timeouts,conservative endpoint bounds,19 classified sites and50 unresolved value/table roles are distinguished.

QG6: Original recapture,parent replay,268 UNSAT results,four SAT controls/domains and five source-alteration controls establish scoped provenance.

QG7: Four impact-ranked followups preserve the unresolved recurrence,publication and native-interface requirements.
