# Captured core stores, controller state and conditional zero-delta return

The captured mode1 core contains 3754 distinct store sites. Every site is catalogued:3307 independently decoded SP stores,236 register-based stores with retained frame-offset evidence,174 computed-array destination contracts,32 LOCAL byte stores and five special destinations. Fresh source proofs recover the entry's stack-dependent controller updates,canary destination,budget initialization and exact adapter delta. Under the listed destination,ownership,callee and captured-path premises,the budget remains the original seed and the returned delta is zero. Whole-core control closure,all174 computed bounds in every reaching epoch,native return and daemon-kext transport remain unproved. [BA1-BA8]

Evidence: [source,store catalogue and IDA observation](triage_evidence/daemon_mode_one_budget_store_audit_source.json.zst), [proofs and conditional-law premises](triage_evidence/daemon_mode_one_budget_store_audit_checks.json.zst), [extractor](triage_evidence/recover_daemon_mode_one_budget_store_audit.py), [validator](triage_evidence/validate_daemon_mode_one_budget_store_audit.py), [preservation](triage_evidence/daemon_mode_one_budget_store_audit_delivery.json), [quality gates](triage_evidence/daemon_mode_one_budget_store_audit_quality_gates.json), [sealer](triage_evidence/seal_daemon_mode_one_budget_store_audit.py), [publication audit](triage_evidence/verify_daemon_mode_one_budget_store_audit_publication.py). Context: [second-phase coverage boundary](daemon_mode_one_second_phase_handoff_report.md), [adapter and stack epochs](daemon_mode_one_adapter_report.md), [caller verification](daemon_mode_one_output_verification_report.md), [source/plane contracts](daemon_mode_one_source_absorption_report.md), [architectural triage](foundational_triage_report.md).

| Evidence | Verified scope |
| --- | --- |
| Primary file | fairplayd.arm64e,SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Input inventory |46 pinned source artifacts,with explicit caller/adapter exclusions |
| Recapture |209 retained range instances /518140 B |
| Captured core |110556 distinct A64 instruction sites;3754 store sites |
| Independent store decoding |3307 literal-SP instruction encodings,including paired effects and the initial save epoch |
| Current source equations |Four ranges /81 instructions /324 B,all translated;33 additional structural prologue/return instructions retained |
| Controller provenance |512 original bank-byte cases;four original rebased pointer records |
| Accepted checks |27 UNSAT /two abstract SAT;14 predecessor propositions replayed |
| IDA/code compatibility |All14849960 bytes of `__TEXT,__text` match the pinned file |
| Integrity |Eight changed store,offset,controller,operand,IDA-identity,memory-scope and native records rejected |

F is core SP after allocation. K is wrapper SP before the adapter call. BP is the adapter's budget address;V is the original u64 seed. These are different frame epochs. Arithmetic is modular u32/u64;extents and stack adjustments use bytes. Analytical names are not public C/MIG types. No target execution/emulation or target API/IPC request occurred. IDA was accessed through read-only metadata,byte,knowledge and IDAPython queries;no IDB edit or memory write was requested. Native aliasing,ordinary callee behavior,hardware PAC acceptance and full path coverage remain explicit premises. [BA1-BA4,BA7-BA8]

## IDA provenance and function-boundary limits

The live `fairplayd` database identified itself as database70f8437872ac and reported input SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`. This differs from the pinned file hash. The reason is unknown;neither whole-file identity nor data-section equivalence is asserted. A read-only hash of the entire loaded code section establishes the narrower compatibility result:

```text
region: __TEXT,__text
start:  0x100001058
size:   14849960 B
SHA256: 94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e
```

The original file produces exactly the same section hash. Three prefix-byte comparisons at0x100cf0194,0x100d7cc50 and0x100dc9674 also match. Code-address comparisons in this report therefore have direct byte support;IDA's recorded whole-file identity is not silently substituted for the pinned image. Validation rechecks the local section and source bytes against the retained observation. It does not claim to repeat the live IDA observation. [BA1-BA2,BA8]

IDA represents entry0x100cf0194 as a single860 B chunk ending0x100cf04f0. The result/return block and86-value bridge are separate functions. These database function boundaries do not encompass the logical core's flattened continuations. The entry contains215 aligned A64 words;IDA reports169 code item heads and46 tail words,with no other word classification. Sample tail items belong to8 B macro items. Thus169 IDA items and215 raw A64 instructions are distinct counts. [BA1-BA2,BA8]

IDA's entry frame fields are4608 B locals plus16 B registers,total4624 B. The source prologue reserves4528 B locals plus96 B register saves,also4624 B. These observations corroborate the source extent without making a single IDA function the write-audit scope. Targeted budget/mode1 memory queries returned no relevant fact;the function-anchor retrieval included unverified global/cross-architecture material. No remembered claim was used as proof. [BA1-BA2,BA8]

## Exhaustive catalogue for the captured ranges

The inventory excludes the outer verification source from core-store counting and restricts the adapter source to its core,accepted,result/return and guard-failure fragments. Overlapping captures are deduplicated by PC and checked against original bytes. Every memory-operand mnemonic in the resulting instruction union is classified as an explicit load or store form;no unclassified memory-operand instruction is accepted. The count is static sites,not dynamic writes or executions. [BA1-BA3]

| Category | Sites | Evidence and condition |
| --- | ---: | --- |
| Literal SP stores |3307 |Fresh raw opcode decoding of base,size,offset,paired registers and addressing mode |
| Retained register-based frame offsets |236 |Existing site/offset/width ledgers retained with artifact hashes and JSON paths;their reaching address contracts remain premises |
| Computed private-array stores |174 |Exact PCs and owners catalogued;the conservative `[F+0x8b0,F+0x10f8)` envelope is an explicit retained-component premise |
| LOCAL byte stores |32 |Earlier original-source address theorem replayed;the owner and protected-state alias policy remain premises |
| Initial canary |1 |Fresh source proof of F+0x11a0/u64 |
| Image-controller updates |2 |Fresh source proofs of exact destinations and u64 values |
| Initial budget update |1 |Fresh source proof of BP/u64 and +144 cancellation |
| Request result |1 |Fresh source proof of REQUEST+0/u32 and wrapper-relative disjointness |
| Total |3754 |Complete for the listed captured instruction union |

Evidence presence is not a new universal alias proof. In particular,the236 existing frame-offset records do not by themselves establish every reaching epoch,and the174 computed-array envelopes are not claimed freshly proved at every site. Their complete exception catalogue is retained so future source checks can replace those premises precisely. Control paths not represented by the captured ranges and imported-helper effects require separate coverage. [BA2-BA4,BA7-BA8]

Six of the SP sites are the initial paired register saves. Their twelve8 B effects establish exactly `[F+0x11b0,F+0x1210)`,96 B. The remaining3301 SP-store sites are body/local effects;their greatest decoded end is F+0x0ffe. Retained register-based offsets extend the private effect envelope to F+0x1170. Paired stores count once as sites and twice as effects. No site count is presented as a runtime frequency. [BA1-BA4]

## Exact entry controller and canary effects

The complete72-instruction prefix at `0x100cf01d0..0x100cf02f0` is translated without source-value cuts. It saves the initial guard as a u64 at F+0x11a0 and updates two image cells:

| Store PC | Destination | Width |
| --- | --- | --- |
|0x100cf01dc|F+0x11a0|8 B |
|0x100cf02e8|0x1010b6838|8 B |
|0x100cf02ec|0x1010c4670|8 B |

The first source instruction is an unscaled store through X29-0x60. Its original address is proved to equal F+0x11a0;the normalized frame form is not accepted without that equality. The two controller destinations resolve through original pointer records0x1010a8d38 and0x1010a1e00,with the source's actual additive biases. Two more rebases supply the original byte-bank roots. Both256-input bank cancellations are retained,and the entire source prefix is checked with the literal bank functions for arbitrary old controller values. [BA1-BA4]

Let A=u64[0x1010b6838] and B=u64[0x1010c4670] before these stores. Under coherent stable reads,the exact compact update is:

```text
D = u64(B-A-(F+0x760))
A_new = u64(D*0x0a5cd4cf +0x8c2fb9df71512e5a)
B_new = u64((D XOR0x73d046208eaed1a6)*0x0a5cd4cf)
```

Selector calculations initially read the low32 halves of A/B;later data reads and the emitted stores use full64. The original source and compact expressions are universally equal. The controller data therefore depend on the private stack address as well as prior controller state. Under the pinned original byte banks,the two decoded cell destinations remain constant even though the intermediate byte lookup addresses can depend on the evolving words. This result concerns these controller destinations;it is not a universal indirect-call or side-channel claim. [BA2-BA5]

The shared multiplier has u64 inverse0x74d1c2afcc73b22f. A separate universal lemma proves both recovery equations:

```text
D = u64((A_new-0x8c2fb9df71512e5a)*0x74d1c2afcc73b22f)
D = u64(B_new*0x74d1c2afcc73b22f) XOR0x73d046208eaed1a6
```

After both completed source stores,the pair represents two invertible encodings of one updated u64 carrier. This does not establish atomic pair visibility,native synchronization,randomness or a cryptographic algorithm identity. [BA3-BA5,BA8]

These are image-state writes. Their separation from a native stack/guard owner remains an ownership premise. The stack-dependent arithmetic alone identifies neither a cryptographic key nor a public operation. No native controller value or scheduling behavior is inferred from the original file. [BA3-BA5,BA8]

## Protected frame geometry and request disjointness

The source structural assertions and modular address equations establish:

```text
BP = K-64-reserve                      reserve in16..256 B
F  = BP-0x1210
FP = F+0x1200 = BP-16
canary address = FP-0x60 = F+0x11a0
normal SP restoration = F+0x11b0+0x60 = BP
```

| Region | Half-open extent |
| --- | --- |
| Retained private body-write envelope |Below F+0x1170 |
| Canary |[F+0x11a0,F+0x11a8) |
| Register saves |[F+0x11b0,F+0x1210) |
| Budget |[F+0x1210,F+0x1218) |

The highest private envelope ends48 B before the canary. A fresh u64 lemma proves that any byte below F+0x1170 is disjoint from every byte of the conservative protected band `[F+0x11a0,F+0x1218)`. That band is120 B,including the8 B gap between canary and register saves. The computed-array premise lies strictly inside the private envelope. A byte-array store/select theorem separately proves preservation of a protected byte by each disjoint store;induction extends it to any finite sequence satisfying the destination contracts. [BA2-BA4,BA6-BA7]

The result prefix reloads REQUEST from F+0x388 and stores an arbitrary raw u32 code at REQUEST+0. The wrapper constructs REQUEST=K+0x10cb8. For every retained16..256 B reservation,a separate modular address proof establishes that these four result bytes cannot overlap the protected core band. This request-store result uses the actual wrapper-relative geometry rather than an unconstrained generic external-pointer assumption. [BA2-BA4,BA6]

LOCAL is different:its 32 store addresses are source-proved,but its native ownership/alias policy remains unknown. The conditional return theorem requires those bytes and modeled helper effects not to alter protected core state and to preserve the reaching request/control-root contracts. Source-value identities for the LOCAL serializer retain their own stronger frame-disjointness premises. A valid pointer name or requested32 B extent does not discharge either requirement. [BA2-BA3,BA7-BA8]

## Budget initialization and exact delta interface

The adapter/probe reaching contract supplies u64[BP]=V-144. The three source instructions at `0x100cf02f0..0x100cf02fc` load that same address,add144 and store V back. The original stack-probe's budget preservation and ordinary return remain imported-callee premises. The following conditional law is now explicit:

```text
If the finitely returning path uses this captured store catalogue,
all retained destination/root/counter/epoch contracts hold,
LOCAL/image/helper/outside writes preserve protected return state,
and the reaching adapter/probe contract holds,
then final_budget = V.
```

The four source instructions at `0x100d03584..0x100d03594` implement the exact output relation:

```text
delta = 16 B * low16(final_budget - V)
delta == 0  iff  low16(final_budget) == low16(V)
```

The actual load is u32;the subtract/UBFIZ sequence makes only the low16 difference relevant. Delta is an integer byte adjustment in0..1048560 B,aligned to16 B. Full u64 budget preservation is sufficient for delta zero;equal low16 is its exact minimum scalar condition. An abstract SAT control allows upper48 budget bits to differ while the returned delta stays zero. This is an algebraic model,not a native execution or permission to ignore canary/register integrity. [BA2-BA4,BA6-BA8]

Consequently the captured-path law implies delta zero without assuming delta zero as its scalar conclusion. It does assume the listed capture/destination/callee/owner premises. It does not establish that every normally returning native processing path satisfies them,that all174 computed destinations have valid reaching domains,or that a native call reaches the epilogue. Canary comparison,ordinary saved-register behavior and hardware PAC conditions remain separate from the scalar delta. [BA3-BA4,BA6-BA8]

## Architectural and transport boundary

The captured core has three call sites:the entry stack probe,the previously identified internal bounded fill,and guard-failure handling. Their imported/internal behavior is not executed by this work. The new81-instruction equations additionally include the adapter's separate8 B DOUT store;that store belongs to the delta interface and is not added to the3754-site core catalogue. [BA1-BA2,BA7]

The current ranges emit no Mach message,transfer no right,allocate no port and invoke no IOKit selector. Newly established touch points are two image-controller cells,a private canary and budget,an anchored request result,and the delta output cell. Neither the controller values nor the budget/delta integers are identified as port names. Matching daemon/kext transport and native external serialization remain unknown. [BA1-BA2,BA8]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| BA1 |Pinned file identity,current code bytes and retained source records are accurate. |Rehash the image and209 retained ranges;independently decode3307 SP stores;reject altered source/catalogue/pointer records. |
| BA2 |Selected adapter,LOCAL,table,frame and call-boundary contracts apply to the analyzed epochs. |Replay14 selected propositions;check exact PCs,SP epochs,source widths and wrapper-relative request geometry;an intervening epoch change breaks composition. |
| BA3 |Required owners and coherent mappings are disjoint and no outside write alters protected state. |Audit LOCAL32,controller/global/stack relationships and helper side effects;the catalogue does not prove native ownership. |
| BA4 |ARM instruction widths,aliases,flags,frame updates and memory semantics are exact. |Verify raw SP store forms,original guard alias,full prefix equations,paired save extents,UBFIZ-derived delta and byte-array preservation law. |
| BA5 |Original lookup banks and coherent old controller values supply the prefix model. |Recheck512 byte cases and four rebases;test arbitrary u64 A/B and stack values;changed banks or concurrent controller reads invalidate the stated equations. |
| BA6 |The budget's relevant scalar equality and protected-byte laws are composed as stated. |Prove+144 cancellation,exact low16 criterion,request disjointness and per-byte preservation;the upper48 SAT control rejects a stronger-than-necessary delta condition. |
| BA7 |Every executed write/callee on the modeled finite path satisfies the catalogue and retained destination contracts. |Discharge236 frame-offset and174 array-site reaching domains and close all control paths/import effects;these remain explicit premises rather than freshly universal bounds. |
| BA8 |The saved IDA observation establishes code compatibility only,and static results remain separate from native behavior. |Compare full code hashes,macro/tail counts and input hashes;reobserve live metadata before current-state claims. Reject whole-file/native identity assertions;no remembered claim is used as proof. |

## Bounded continuation

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High |Close the logical core's control coverage and imported-helper effects against this catalogue |Whether the conditional budget law applies to every selected ordinarily returning processing path. |
| High |Replace the174 computed envelopes and236 retained frame-offset premises with reaching source proofs |Whether each executed root/counter/selector/epoch satisfies the private envelope at every relevant visit. |
| High |Establish actual LOCAL cursor/ownership and native protected-state alias policy |Whether the last external byte stores preserve the return state for real caller objects. |
| High |Trace the established caller verification/option path into serialization and matched peer interfaces |Concrete daemon/kext IPC/ABI pairing,beyond private return mechanics. |
| Medium |Compare non-code file regions/loader state between the IDB identity and pinned input |Whether any data/metadata contract can also be transferred;full code identity alone cannot establish it. |

## Scoped quality gates

- QG1:Source,ABI,provenance and conditional memory/return laws require no normative conclusion.
- QG2:BA1-BA8 enumerate assumptions,dependent claims and falsification probes.
- QG3:The increment covers every store site in the filtered captures,fresh SP decoding,exact controller/canary/budget/result/delta equations,frame/protected regions,IDA compatibility and explicit control/ownership/transport limits. The broader goal remains active.
- QG4:3307+236+174+32+5=3754 sites;96+4528=4624 B frame;the protected120 B band includes an8 B gap. The byte delta is16*low16 with maximum16*65535=1048560 B. Extraction/census costs O(input instruction/effect records);the protected-byte induction is per effect. QF_BV/QF_AUFBV checks use45000 ms solver and50 s process limits;general solver worst-case cost is not claimed linear.
- QG5:Site/effect/runtime counts,initial/body SP epochs,raw decoding/retained evidence/computed premises,full/low16 budget equality,IDA item/raw-word counts and code/whole-file identity are separated. Unconditional native budget preservation remains unproved.
- QG6:Original bytes,banks,rebases,209 recaptures,3307 raw store decodes,27 UNSAT,two abstract SAT,14 predecessor replays,read-only IDA observations and eight rejected alterations provide scoped provenance. Validation does not relabel retained destination premises as fresh proofs or reobserve live IDA state.
- QG7:Impact-ranked continuation targets actual remaining coverage,alias,epoch,callee,data-identity and transport gaps without promoting the conditional result to native completion.


## Computed-store footprint refinement

A subsequent increment replaces the conservative destination-envelope premise for ten of the174 computed-array sites with fresh source equality and exhaustive finite footprint proofs. This leaves164 other array sites without this new proof;the original captured-path budget law remains conditional on entry roots,epochs,control closure,callee effects and ownership. [Evidence and exact boundaries](daemon_mode_one_computed_store_footprints_report.md).
