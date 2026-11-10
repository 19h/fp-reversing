# Ten computed stores: exact source coordinates and finite phase footprints

Freshly rebuilt source models establish the destination coordinates of ten stores previously covered by the captured-core audit's conservative computed-array premise. Exhaustive finite-domain evaluation gives 448 store instances and 1600 byte-write operations across three phases. Each phase's selected stores write distinct bytes and remain below the protected canary/register-save/budget band. Their footprints overlap across phases, so an offset alone does not identify a persistent value. The other164 computed-array sites and236 retained frame-offset sites receive no new proof here. Entry roots,phase epochs,counter domains,complete control coverage,native ownership/return and daemon-kext pairing remain unresolved contracts. [CF1-CF8]

Evidence: [original bytes and ten-site ledger](triage_evidence/daemon_mode_one_computed_store_footprints_source.json.zst), [fresh models,queries and complete finite footprints](triage_evidence/daemon_mode_one_computed_store_footprints_checks.json.zst), [extractor](triage_evidence/recover_daemon_mode_one_computed_store_footprints.py), [validator](triage_evidence/validate_daemon_mode_one_computed_store_footprints.py), [preservation](triage_evidence/daemon_mode_one_computed_store_footprints_delivery.json), [quality gates](triage_evidence/daemon_mode_one_computed_store_footprints_quality_gates.json), [sealer](triage_evidence/seal_daemon_mode_one_computed_store_footprints.py), [publication audit](triage_evidence/verify_daemon_mode_one_computed_store_footprints_publication.py). Context: [captured-core store catalogue](daemon_mode_one_budget_store_audit_report.md), [record word extension](daemon_mode_one_record_word_extension_report.md), [secondary word extension](daemon_mode_one_secondary_word_extension_report.md), [source absorption](daemon_mode_one_source_absorption_report.md), [architectural triage](foundational_triage_report.md).

The primary file is fairplayd.arm64e,SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Seven ranges/4152 A64 instructions/16608 B were recaptured and independently disassembled against retained instruction records. Four relevant entry/loop ranges supply4051 translated nonbranch instructions. Three models were rebuilt from those instructions and matched against the retained models,including their source definitions,declarations,loads,stores,frame state and normalization records. Eight changed source/width/root/modulus/domain/native records were rejected by fresh comparison. No target execution,emulation,API/IPC request or new IDA access occurred. [CF1,CF4,CF8]

## Destination equations

F denotes the core frame base after allocation. The SMT symbol K in this increment denotes F;it is not the outer wrapper's differently scoped K. For unsigned32 index i define the following frame offsets in bytes:

| Phase | Exact offset | Domain | Store width | Label b,source PC |
| --- | --- | --- | --- | --- |
| Record word extension |`0x8b0+4*((227*(i+b)) mod280)`|`0<=i<48`|4 B|227:`0x100c55de4`;159:`0x100c565ec`;16:`0x100c56dbc`;87:`0x100c56eac`|
| Secondary word extension |`0xc80+4*((241*(i+b)) mod286)`|`0<=i<48`|4 B|88:`0x100c50dd0`;16:`0x100c50f1c`;158:`0x100c524c4`;228:`0x100c525bc`|
| Source absorption |`0xd00+((757*(i+b)) mod963)`|`0<=i<32`|1 B|40:`0x100bd7a4c`;112:`0x100bd7ae4`|

Each destination is F plus its offset,modulo2^64. The finite-domain additions and products are below2^32;the equations therefore agree with the source's unsigned32 arithmetic before zero extension. Source word models use no value cuts. The absorption model first proves the original obfuscated divisor equals16 throughout its domain,then uses that freshly proved equality for its one cut. No destination-envelope premise is used for any of the ten stores. Arbitrary typed word/byte loads remain component inputs;numeric table values are unnecessary for these destination identities. [CF2-CF5]

## Complete finite footprints and phase reuse

| Phase | Store instances | Byte-write operations and distinct bytes within phase | Minimum offset | Maximum end,exclusive | Gap to canary at F+0x11a0 |
| --- | --- | --- | --- | --- | --- |
| Record |192|768 B|`0x8b4`|`0xd10`|1168 B|
| Secondary |192|768 B|`0xc84`|`0x10f8`|168 B|
| Absorption |64|64 B|`0xd0f`|`0x10ae`|242 B|

These are sparse footprints;the minimum/maximum columns are bounding intervals,not assertions that every intervening byte is written. The machine-readable evidence enumerates every source PC,index,offset,width and written byte. Within each phase,its selected writes are pairwise disjoint. The1600 B count is the sum of byte-write operations across phases,not a cross-phase unique-allocation extent. [CF3,CF6]

| Phase pair | Common written frame bytes |
| --- | --- |
| Record and secondary |64 B|
| Record and absorption |1 B|
| Secondary and absorption |43 B|

The intersections follow from the exact byte sets under a common F. They establish potential replacement of earlier values if those phases execute on that frame. They establish neither phase ordering nor coexecution. Even the single-byte record/absorption intersection prevents treating the two typed views as globally disjoint. Data-flow consumers must identify the reaching writer and epoch;existing phase handoffs remain separate evidence. [CF5-CF7]

Every selected written byte is disjoint from `[F+0x11a0,F+0x1218)`,which conservatively includes the canary,saved registers,budget and intervening gaps. The shared-base cancellation proof holds modulo2^64 and needs no additional no-wrap premise. The three source equalities,complete finite coordinate evaluations,finite-domain exhaustion and modular disjointness compose this result. Six SAT controls establish nonempty component domains and show that dropping the shared-root identity admits protected-byte aliasing. Those are abstract models,not observations of a native alias or failure. [CF3-CF7]

## Control,external interfaces and limits

The source PCs are internal byte/word stores;this increment establishes no new Mach-port emission,port right,serialization site,kernel selector or matched daemon-kext transaction. The obfuscated bodies can be described as phase-dependent scattered word expansion and two-plane byte absorption at this level of evidence. Destination geometry does not identify a complete decoded algorithm or native object owner. [CF7-CF8]

Of174 catalogue computed-array sites,10 now have these finite footprint certificates and164 remain without this refinement. The236 register-based retained frame-offset contracts are unchanged. The conditional budget theorem still requires valid reaching entry registers/roots,covered executed stores and callees,phase transitions,ordinary calling/PAC conditions,protected-state noninterference and a finite normal return. A proof of these ten components does not close the logical core's control graph. [CF5-CF8]

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| CF1 |The pinned image and recorded source bytes are the analyzed artifact;all source claims depend on this identity.|Rehash the complete file;recapture and independently decode all seven ranges;reject changed bytes or instructions.|
| CF2 |The original entry register,preset and typed-load contracts hold on each relevant visit;source coordinate claims depend on them.|Rebuild all three models and compare their complete records;derive reaching producer states separately before asserting native applicability.|
| CF3 |i is unsigned32 and lies in the stated48- or32-value domain;finite footprints depend on this domain.|Prove finite-domain exhaustiveness and every coordinate evaluation;reject a changed iteration count;SAT-check domain consistency.|
| CF4 |ARM widths,register semantics and the source translator implement the captured instructions.|Check raw store classes and widths;rebuild every relevant instruction;prove the original divisor before cutting it;word models contain no value cuts.|
| CF5 |Destination roots identify the phase's common F;source/root/counter contracts are preserved at each modeled visit.|Retain explicit entry models and original coordinates;independent-root SAT controls demonstrate aliasing when root identity is removed;close reaching phase transitions separately.|
| CF6 |Finite enumeration and set arithmetic represent every byte effect of the selected stores.|SMT-check all448 coordinate evaluations,expand each width,check within-phase uniqueness,and recompute sparse intersections;distinguish byte counts from interval spans.|
| CF7 |Component geometry is composed only within the covered scope;whole-path budget preservation remains conditional.|Account for164 other array sites,236 alias sites,all uncovered control/callees and external writers;do not infer phase ordering from set overlap.|
| CF8 |Static equations,abstract SAT controls and previously recorded context remain distinct from native evidence.|Reject target-execution claims;no new IDA observation is asserted;require actual ownership,transport and native control evidence for those conclusions.|

## Bounded continuation

| Impact | Next evidence | Consequence |
| --- | --- | --- |
| High |Discharge the remaining164 computed-site envelopes and236 alias contracts in their reaching domains|Reduce outstanding destination premises of the conditional budget law.|
| High |Close phase-entry preservation and whole logical-core control/callee coverage|Determine whether these component footprints apply on every relevant native processing path.|
| High |Track reaching values at the64,1 and43 B cross-phase intersections|Prevent stale typed views from supplying incorrect data-flow conclusions.|
| High |Follow the established outer verification/option path into serialization and match peer interfaces|Resolve actual daemon-kext IPC/ABI interaction beyond private-frame computation.|
| Medium |Establish native frame/LOCAL ownership and ordinary return conditions|Connect source geometry to concrete object lifetime and return-state preservation.|

## Scoped quality gates

- QG1:Source coordinates,byte footprints,control scope and provenance require no normative conclusion.
- QG2:CF1-CF8 list assumptions,dependent claims and falsification probes.
- QG3:Ten formerly premise-only destinations have fresh source equalities,finite domains,byte footprints,protected-state disjointness and explicit cross-phase intersections;broader interface investigation remains active.
- QG4:8*48+2*32=448 stores;384*4+64*1=1600 B written across phases. All byte extents include store width. Extraction,enumeration and set comparison require O(S+N+M) time and space for S source records,N=448 instances,M=1600 byte effects. General SMT complexity is not claimed linear;solver/process limits are45000 ms/50 s per query.
- QG5:Sparse sets and intervals,within-phase and cross-phase uniqueness,shared and independent roots,source models and native execution remain distinct. Intersections do not establish execution order;164+10=174 array-site accounting is exact.
- QG6:Seven original recaptures,4051 translated source instructions,three freshly matched models,13 UNSAT/six abstract SAT and eight rejected freshness alterations supply scoped provenance. No previous negated goal is reused as a premise in a new footprint proof.
- QG7:Continuation targets remaining destination/control obligations,epoch-dependent data flow,ownership and matched peer interfaces,with impact labels and explicit limits.
