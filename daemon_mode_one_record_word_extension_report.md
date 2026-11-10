# 280-slot word schedule and exact SHA-2 small-sigma components

The consumer at `0x100c557e8` extends four16-word streams to64 words each in exactly48 iterations. It performs384 backward word reads and192 new word stores,initializing256 words /1024 B of the280-slot view. All69 scratch-byte reads per iteration are bounded to the961-byte scratch domain. Four original-source identities establish the SHA-224/SHA-256 small-sigma functions in explicit register projections and XOR representations. The full decoded sum recurrence,whole hash identity,native traversal/ownership,output and daemon/kext pairing remain unknown. [WE1-WE8]

Evidence: [source/fixups/standard provenance](triage_evidence/daemon_mode_one_record_word_extension_source.json.zst), [40 queries and complete source/coverage ledgers](triage_evidence/daemon_mode_one_record_word_extension_checks.json.zst), [extractor](triage_evidence/recover_daemon_mode_one_record_word_extension.py), [validator](triage_evidence/validate_daemon_mode_one_record_word_extension.py), [preservation](triage_evidence/daemon_mode_one_record_word_extension_delivery.json), [quality gates](triage_evidence/daemon_mode_one_record_word_extension_quality_gates.json), [sealer](triage_evidence/seal_daemon_mode_one_record_word_extension.py), [publication audit](triage_evidence/verify_daemon_mode_one_record_word_extension_publication.py), [retained NIST primary PDF](triage_evidence/daemon_mode_one_record_word_extension_fips180-4.pdf). Context: [incoming64-word gather](daemon_mode_one_record_word_gather_report.md), [typed digit/codebook domains](daemon_mode_one_record_codecs_report.md), [earlier273-slot schedule](daemon_mode_one_word_schedule_report.md), [preceding64-byte absorption](daemon_mode_one_record_long_prefix_report.md).

| Evidence | Verified scope |
| --- | --- |
| Image |`fairplayd.arm64e`,SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Current source |1486 instructions /5944 B;1485 unique nonbranch sites,including a seven-instruction next-block prefix |
| Selected traversal |48*1478+7=70951 nonbranch instances;source models,not target execution |
| Incoming recapture |Five ranges /6516 B |
| Control provenance |Two original authenticated records/bindings,IA diversity0x7e96 |
| Accepted results |37 UNSAT /3 SAT,including18 selected incoming queries |
| Memory proof |Eight backward word reads,four new words and69 bounded scratch reads per iteration |
| Primitive proof |Four universal source identities for the two standard small-sigma functions |
| Integrity |42 bitfield decodes,one CMP role correction,seven rejected evidence alterations |
| Reference |FIPS180-4,August2015,833315 B,SHA-256 `0455b406d89648d20cbde375561e19c245b9815e894164c2670772e3d54deb82` |

F is the private frame,T=F+0xd10 and WORD=F+0x8b0. Arithmetic is modular u32/u64;offsets/extents are bytes. Valid coherent nonwrapping mappings,stable roots and no outside writes remain premises. No target execution,emulation,API/IPC request,new IDA access,IDB mutation or hardware PAC check occurred. [WE1-WE4]

## Incoming ABI and exact48-step traversal

The incoming gather's18 selected root,seed,address,counter and exit queries are refreshed. A new query proves F+0x720=0x3f03,F+0x718=0xc013729f and that incoming X23 has zero high32 bits. The latter matters because this state register is read through both W23 and X23. Other data views are universally abstract u32 inputs. An operand-derived first-read census distinguishes actual arguments from Capstone alias read/write-role artifacts. [WE2-WE3]

Entry controls are W16=0,W2=0xea0f,W3=280 and X21=WORD. At iteration IX=0..47,the original source:

- Saves current IX to u32 F+0x730;it does not save the next index there.
- Writes u32(227*IX) to the low word of F+0x738.
- Returns W16=IX+1 and preserves the word root/division constants.
- Decrements the u32 F+0x718 bias from0xc013729f-IX to0xc013729e-IX;that word is not the termination counter.
- Repeats through selector0x3f10 exactly when IX!=47;IX47 selects0x3f03 ->`0x100af5f50`.

Thus W16=48 and F+0x730=47 at exit. Register/frame values have distinct epochs. The source certificate also proves X23's high32 bits remain zero for re-entry and that STATE=u32[F+0x6bc] is unchanged. The generic model accepts arbitrary STATE;its bounds do not require a table-value codomain premise. [WE3-WE5]

## Backward word reads and initialized coverage

Set t=IX+16. The eight source read labels are:

```text
IX+[1,72,14,85,211,220,143,152]
```

Across the four stream bases0,71,143 and211,these correspond to t-15,t-2,t-16 and t-7 in their respective representations. The four new labels are IX+[227,159,16,87],i.e. t plus stream bases211,143,0 and71. Every address is universally source-certified as:

```text
WORD+4*((227*label) mod280)
```

A complete48-case initialized-word ledger starts with the incoming64 words. Each iteration reads only already initialized labels,writes four new distinct labels,and preserves the earlier words. The final set contains64 words in each stream:256 words /1024 B,leaving24 slots unpopulated. This proves the private schedule interface without assuming a decoded word-value recurrence. [WE3-WE5]

There are384 word reads /1536 B and192 new word stores /768 B. The new stores occupy F+0x8b4 through F+0xd0f as a sparse set. They add writes at F+0xd04..0xd07 and F+0xd0c..0xd0f;combined with the preceding gather,all16 bytes F+0xd00..0xd0f of the former963-byte scratch prefix are reused. The current961-byte scratch starts at F+0xd10 and remains unwritten. [WE4-WE5,WE7]

## Exact standard small-sigma projections

[NIST FIPS180-4,August2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf),section4.1.2,equations4.6-4.7,defines the following functions shared by SHA-224 and SHA-256:

```text
sigma0(x)=ROR32(x,7) XOR ROR32(x,18) XOR SHR32(x,3)
sigma1(x)=ROR32(x,17) XOR ROR32(x,19) XOR SHR32(x,10)
```

Let X0..X3 be the arbitrary u32 values loaded at `0x100c55850`, `0x100c55858`, `0x100c55884`, `0x100c558c4`. Let C0=0x88cc152e,C1=0xfe383a95. Four separate UNSAT certificates prove:

| Source PC,after instruction | Exact source identity |
| --- | --- |
|`0x100c558dc` |W16 XOR W2 = sigma0(X1) |
|`0x100c55960` |W0 XOR W11 = sigma1(X3) |
|`0x100c55988` |W15 = sigma0(X0 XOR C0) XOR(C0 SHR3) |
|`0x100c559e0` |W3 = sigma1(X2 XOR C1) XOR(C1 SHR10) |

The first two are XOR projections of two live registers;the latter two use explicit affine input/output XOR representations. Register meanings are specific to these PCs. These are universal source equalities,not matches based only on rotate constants. They establish the mathematical components and a schedule dependency pattern consistent with the standard. The decoded four-stream modular-sum recurrence,padding,compression,initial hash values and output distinction between SHA-224/SHA-256 remain unproved. No whole-hash identification or conformance claim follows. [WE3,WE5-WE6]

The retained primary PDF is the August2015 edition,not the archived2012 copy served by another official link. Its source URL,DOI `10.6028/NIST.FIPS.180-4`,size and hash are recorded in the source artifact. [WE1,WE6]

## All69 scratch-byte bounds

The aggregate direct bound query returned unknown at15000 ms and is excluded. Accepted component certificates establish every access instead:

1. A typed DAG proposes numerator references and remainder shapes. A query against the original,unaltered source SSA proves all69 addresses equal T plus the corresponding source remainder expression. The candidate normalization is not assumed correct.
2. For56 sites,the original source proves unsigned numerator N<=4033828. For13 sites,N may span all u32 values.
3. Two integer theorems prove exact quotients:

```text
floor(N*0x443215 /2^32)=floor(N/961), 0<=N<=4033828
floor(N*0x8864298f/2^41)=floor(N/961), 0<=N<=4294967295
```

4. Separate integer checks prove the u64 products fit,the quotients/products fit the u32 MSUB,and subtraction yields0..960. A bit-vector theorem proves any following low16 extraction preserves that remainder.

Thus all69 byte offsets lie in0..960 for every IX<48 and arbitrary word,byte and state inputs. No lookup-value codomain premise is needed. The bound4033828 is conservative;endpoint attainment is not claimed. A proposed smaller485826 bound is refuted by a SAT control over the abstract domain,not by a native target observation. [WE3-WE4]

These bounds establish containment only. Membership in the initialized800-cell codebook subset,the returned byte values and the decoded arithmetic identities of these lookups remain unknown in this increment. Boundedness must not be substituted for table semantics. [WE4-WE6,WE8]

## Frame effects and next-block input

Each iteration has148 load effects /577 B:69 scratch bytes,eight u32 words,70 frame loads and one branch pointer. Its21 store effects /84 B comprise four new u32 words and17 private u32 frame stores. The private stores cover56 distinct frame bytes. Across48 iterations,this is7104 loads /27696 B and1008 stores /4032 B,including3312 scratch reads and the192 new words. These counts describe source operations,not distinct readable bytes or measured runtime. [WE3-WE4]

The961-byte scratch,64 initial words,saved roots,STATE at F+0x6bc,F+0x720,COUNT,PBUF,the296 B workspace and budget F+0x1210 remain unwritten. Local budget preservation does not prove complete accounting. F+0x738 is a u32 phase in this loop;no conclusion about an upper32-bit clear is imported from that store. [WE4,WE7]

At the selected exit `0x100af5f50`,a captured seven-instruction prefix clears only low32 bits of F+0x738,loads CTX=u32[F+0x458],and stores:

```text
u32[F+0x708]=CTX-final_W1+0xadcdd50d mod2^32
```

CTX is a new explicit frame-input premise. Its owner and semantic role are unknown. The remaining8945-instruction block is not covered by this prefix;the complete block length includes these seven instructions. The captured prefix makes two u32 stores and one u32 load. [WE3,WE7-WE8]

No Mach message,port allocation,right transfer,external call or trap occurs in the captured routine/prefix. No new incoming/outgoing port or emission site is established. The concrete interfaces are the private word grid,scratch-byte reads,scalar state/counters,authenticated continuation and newly consumed F+0x458 word. Caller-visible output and daemon/kext pairing remain unknown. [WE1,WE4,WE7-WE8]

## Assumption register and bounded continuation

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| WE1 |Pinned image and primary reference identify the source variants |Recapture5944 current/6516 incoming bytes;verify two bindings and the833315 B August2015 PDF hash;reject seven alterations |
| WE2 |Incoming controls,roots,64 initial words and X23 type compose |Refresh18 selected predecessor queries;prove saved constants and X23 high32 zero;verify source operand read roles |
| WE3 |ISA,widths,SSA and component composition are accurate |Translate1485 sites;check42 bitfields,all word/frame addresses,counter closure,four sigma identities and all69 source remainder shapes |
| WE4 |Coherent nonwrapping mappings,stable roots and no outside writes |Check initialized-word chronology,192 new words,961 scratch bounds/protection,all frame stores and protected slots;native owners/extent remain unknown |
| WE5 |The48-state word-label graph composes |Prove next-index bounds,47 repeats/one exit and initialized read-before-write coverage for all48 states;retain arbitrary word values |
| WE6 |Standard component identity is interpreted within its actual scope |Use the pinned primary equations;distinguish register projections from decoded sum recurrence and whole hash identity;preserve input/output codebook distinctions |
| WE7 |Counter/frame epochs and PAC prerequisites permit native traversal |Check saved IX versus next W16,low-word phase writes,decreasing bias,slot/modifier binding and F458 transfer;hardware PAC,exceptions and actual arrival remain unproved |
| WE8 |Table values,whole algorithm,post-prefix block,publication and cross-layer pairing remain unknown |Recover initialized lookup families,decoded arithmetic and the remaining next block through actual output/serialization;do not infer them from bounds or standard-looking dependencies |

| Impact | Next investigation | Evidence required |
| --- | --- | --- |
| High |Decoded word recurrence |Initialized table-family/value contracts and representation maps sufficient to prove or refute the standard modular-sum schedule |
| High |`0x100af5f50` beyond its prefix |Uses of F458/final state,compression or other transforms,and actual continuation/publication |
| High |Native output and daemon/kext connection |Concrete owner/extents,serialization and corresponding external interface |
| Medium |Initial-input role recovery |Source operand reads and proven extension widths where register-access metadata disagrees |

The component has48 iterations,O(1) work in COUNT,3312 byte lookups,384 word reads and192 word writes. One parameterized body plus finite word chronology avoids unrolling48 value recurrences. Extraction/translation and chronology are linear in captured instructions/cases;SMT is solver-dependent with15000 ms per query and20 s per process. Unknown,timeout,diagnostics,nonzero exit and unexpected results are rejected.

QG1: Claims concern factual source,ABI,widths,memory/control,mathematics and provenance.

QG2: WE1-WE8 state assumptions,dependent results and falsification probes.

QG3: Word expansion,all scratch containment,source sigma identities,counter closure and next-prefix ABI are covered for this increment;the broader investigation remains active.

QG4: All1485 sites,70951 selected instances,37 UNSAT/three SAT results,48 initialized-word states and exact widths/counts are reproducible.

QG5: Standard components are separated from whole-hash identity;containment from initialized table semantics;current IX from next W16;u32 stores from full-u64 clears;abstract SAT controls from native observations.

QG6: Original bytes/fixups,recaptured predecessor source,original-source solver queries and the pinned NIST publication supply primary provenance;no new native or IDA observation is claimed.

QG7: Bounded continuation prioritizes decoded recurrence,remaining next-block semantics,output linkage and source input-role recovery.

Follow-up: [64-round consumer and COUNT-controlled suffix re-entry](daemon_mode_one_record_rounds_report.md) establishes the complete setup/body/update/adapter interface,all623 scratch-byte bounds,the128-byte refresh,and the original COUNT>64 first-prefix decision.
