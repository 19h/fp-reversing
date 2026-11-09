# Mode1 encoded-word mix and size-derived context

The block at0x100dab3d0 reduces to five compact unary maps plus XOR,addition and subtraction. Three different constant-heavy source sequences implement the same map,which removes an XOR encoding introduced by the preceding combiner. A computed word from frame+0x434 then participates in the mix. Fifteen exit-register formulas and the actual predecessor substitution are source-certified. Whole algorithm,caller output and native daemon/kext linkage remain unknown. [WM1-WM8]

Evidence: [source,phase and size-word producer](triage_evidence/daemon_mode_one_word_mix_source.json), [universal proofs,live bindings and compact formulas](triage_evidence/daemon_mode_one_word_mix_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_word_mix.py), [validator](triage_evidence/validate_daemon_mode_one_word_mix.py), [preservation](triage_evidence/daemon_mode_one_word_mix_delivery.json), [quality gates](triage_evidence/daemon_mode_one_word_mix_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_word_mix_publication.py). Parents: [two-bank combination](daemon_mode_one_bank_combine_report.md), [size/source/initializer ABI](daemon_mode_one_post_table_passes_report.md).

| Evidence | Verified scope |
| --- | --- |
| Image |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| New block |209 instructions/836 B;all208 nonbranch sites translated |
| With lineage |Three ranges,277 instructions/1108 B;all275 distinct nonbranch sites translated |
| Recapture |Fourteen parent ranges/3832 B |
| Metadata |Two original authenticated pointers and branch/modifier matches |
| SMT |27 new plus twelve replayed UNSAT certificates;one SAT abstract input-domain check |
| Compact semantics |Five unary maps,seven universal source-instance certificates,seven live cuts,one live-seed certificate,fifteen register formulas |
| Composition |Nine input-word bindings to the predecessor;separate source size-word proof and cross-block mixed-word identity |
| Memory |One4 B data read,two8 B control reads,no stores;816 arithmetic-table cells preserved |
| Controls |Four source/producer/target/native-claim alterations rejected by fresh original-source comparison |
| Execution |No target execution,emulation,API/IPC request,hardware PAC or IDB mutation |

## Compact word semantics

All scalar operations below wrap modulo2^32;XOR is bitwise. The five source-certified maps are:

```
U0(x) = (x XOR0x08156cbf)+0x5bc9af7e
U1(x) = ((x XOR0x7ffffffe)+0x22a5c65a) XOR0x5d5a39a4
U2(x) = ((x XOR0x00000002)+0xb80debcc) XOR0x47f21436
U3(x) = ((x XOR0x1aa82d93)+0xc9cad8d0) XOR0x7ffffffd
U4(x) = (x XOR0xe557d26e)+0xbefcbfd6
```

These are verified representations,not unique canonical encodings or standard algorithm names. The acceptance criterion is universal equality with original source SSA. A finite-sample candidate that failed universal checking was excluded;sample fitting alone is not evidence of the final maps. [WM4-WM6]

Let r0,r1,r2,r4,r5,r11,r12,r14,r19 denote the incoming values of the correspondingly numbered W registers. Let L be the u32 word loaded from frame+0x434. Define:

```
v = U0(r1)
x = v+L
h = U1(r5) XOR U2(x)
k = h XOR(v+0xb8ae898b)
a = r0 XOR r14
b = r4+0x315be61c
d = r2-r19
e = r11-r12
```

The full source then gives:

| Register at block exit | Compact value |
| --- | --- |
|W10 |v+0xb8ae898b+(r12 XOR0xfdb8ea3a) |
|W13 |a XOR b |
|W0 |(r19 XOR0xfdb8ea3a)+b |
|W14 |d+0x6fbf8128 |
|W2 |d+a+0x0931a58b |
|W1 |e+0x8d7f1dd4+U3(h) |
|W15 |U4(k)+0xee7664b2 |
|W11 |e+0x916e0de3 |
|W19 |r19 XOR0x0000005f |
|W20 |r12 XOR0x44cba52e |
|W3 |(k XOR0x2d97c0f7)+0x763cad4d |
|W4 |0xca7a0e68 |
|W5 |0xfdb8ea3a |
|W8 |0x00003146 |
|W16 |0x000017d8 |

Each row has its own accepted universal query over the nine independent incoming words and L. No equality or special values of the banks are needed for these formulas. W12 is excluded from the arithmetic-output table:its incoming arithmetic value is consumed,then X12 is overwritten with the selected branch pointer. W17 likewise becomes the authentication modifier after its temporary arithmetic value has contributed to W15. W0 is an internal word here,not an established public result/status. [WM5-WM7]

## Source instances,live bindings and predecessor composition

U0 is implemented separately at0x100dab3d0..0x100dab42c,0x100dab568..0x100dab5b8 and0x100dab5f0..0x100dab640. Each instance has its own universal certificate. U1,U2,U3 and U4 have four further source-instance certificates. The two five-term-looking mixes reduce to U1 and U2;the other mixtures reduce to their short XOR/add forms.

The U2 source span starts with a live auxiliary word W15. The full source prefix independently proves that W15 equals (x XOR0xe89a2bc2)+0x5097c00a at that point. Only then is the generic U2 identity instantiated. All seven cuts preserve other source register effects;their original values,replacements,source query names and input bindings are recorded in the checks artifact. [WM4-WM6]

The predecessor supplies the actual nine entry values through its compact register formulas. Twelve predecessor certificates are replayed:the nine required register outputs,the predecessor initializer's phase/bank binding,and its two universal circuit identities. Its original bytes are recaptured and its source artifact is freshly matched. This is a source-level composition,not a native trace.

In the predecessor's first-bank coordinates,W10=A,W5=B,W25=C and W30=D+0xad732488 before its combination. Its resulting r1 is (C-A+(D XOR B)+0x144c3fb2) XOR0x08156cbf. Therefore the new U0(r1) is exactly:

```
v = C-A+(D XOR B)+0x7015ef30
```

The source producer at0x100dda880 writes0xec2864b6 to frame+0x434 on the selected LEN32 path. Adding that actual context word gives:

```
x = C-A+(D XOR B)+0x5c3e53e6
```

Both equalities have a separate cross-block certificate. Thus the saved word participates in the transformation rather than merely occupying the initializer's frame. L is a computed size-dependent encoding,not the raw length field. Its connection to LEN32 depends on the saved decoder/admission contract in the parent report;other length/path outcomes are not inferred. [WM2,WM4-WM6]

## Memory,view and private control

| Source access | Width | Established role |
| --- | --- | --- |
|LDR W15 at0x100dab480 |4 B |Read L from frame+0x434 |
|LDR X9 at0x100dab704 |8 B |Read saved private branch-table root from frame+0x740 |
|LDR X12 at0x100dab708 |8 B |Read private selector0x17d8 from that table |

The block has no store and no SP update. It preserves all frame memory,including the816 identified arithmetic-table cells,the saved source/image-data roots,the literal/size cells and budget. It does not read the arithmetic tables here. X21 remains frame+0x8348 without being dereferenced;the native extent and downstream offset interpretation of that view remain unknown. [WM3,WM8]

The predecessor's selected slot0x4cf9 reaches this block with IA diversity0x74b2. Its fresh phase-source certificate establishes W16=0x17d8. This block does not change W16,so its terminal pointer selection is fixed under that entry contract. The original authenticated slot is0x101045db0,target0x100bf3160,IA diversity0x9c42. The source performs BRAA X12,X17 at0x100dab710 after setting X17=0x9c42.

These are static source/pointer bindings. Hardware PAC,exceptions,native mapping,authorization and actual traversal are not executed or proved. The captured block contains no call,trap or Mach emission. It establishes no new incoming/outgoing Mach port,name,right or message contract;the selector and arithmetic words are private state. [WM7-WM8]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| WM1 |Pinned original image,unslid source and original fixups |Rehash image,recapture all ranges and compare both pointer records |
| WM2 |Selected mode1 predecessor and saved-size/admission contracts |Recheck its register bindings and LEN32 size-word producer;other paths need separate joins |
| WM3 |Valid nonwrapping private frame,stable branch root and coherent memory |Check mapping,owner,lifetime and outside writes;the saved view has no proved native extent |
| WM4 |SSA word widths and instruction effects match source |All275 captured nonbranch sites,seven source identities and fifteen row queries check the modeled effects |
| WM5 |Universal identities are instantiated with actual live inputs |Review seven cut bindings and the independent U2 live-seed certificate;other register effects remain translated |
| WM6 |Predecessor/source composition respects encodings and epochs |Replay all twelve prerequisite queries,check nine input bindings and the mixed-word identity |
| WM7 |Original authenticated pointer records establish static target selection |Hardware PAC,exceptions and native traversal are not executed or proved |
| WM8 |Whole algorithm,caller output,view extent and daemon/kext pairing remain unknown |Trace0x100bf3160 and later state/table/view consumers through publication |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence needed |
| --- | --- | --- |
|High |Trace0x100bf3160 with the compact exit words |Actual state consumers and the next private ABI |
|High |Connect the computation to arithmetic-table/view accesses and caller output |Address decoding,ownership,extents and publication/serialization evidence |
|Medium |Test wider algorithmic structure using the proved word maps |Independent multi-stage invariants;local affine/XOR maps are insufficient for attribution |
|Low |Identify alternate short representations only if useful downstream |Universal equivalence;sample fits alone are insufficient |

The new block has a fixed209 instructions,three data/control loads totaling20 B,and no stores. Source extraction/hashing and SSA construction are linear in bytes/instruction instances. SMT runtime is solver-dependent,limited to15000 ms per query;unknown and timeout are rejected. Extents use bytes,scalar formulas use u32,and addresses use u64.

QG1: Factual source,arithmetic and metadata results are reported.

QG2: WM1-WM8 register assumptions,dependent conclusions and falsification probes.

QG3: Compact semantics,size-context flow,predecessor composition,memory/control effects and Mach-emission scope are covered for this increment;the full objective remains active.

QG4: Five word maps,fifteen exit formulas,seven substitutions,widths,source accesses and the mixed-word identity are reproducible.

QG5: Nonunique normal forms,rejected sample fits,U2's live seed,and W12/W17 arithmetic/control epochs are distinguished.

QG6: Original recapture,275 translated sites,39 UNSAT certificates,one abstract SAT check and four alteration controls establish scoped provenance.

QG7: Four impact-ranked continuation questions bound the expansion;whole output,native exchange and algorithm identity are not claimed.
