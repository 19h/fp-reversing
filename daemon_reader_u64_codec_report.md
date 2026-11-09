# Complete u64 codec and N19 container/result provenance

The eight-byte reader at `0x100588cb0` now has a complete conditional source contract. It returns X9=decoded_BE64 XOR `0xfa039b7ca50c772e`. Its eight address-mask seeds, 56 rounds and full 885-instruction merge are proved, including the last mask word's `0x9898989898989898` delta. The result is staged into N19's u64 writer operand; the writer's matching XOR cancels it and preserves the decoded eight-byte field across source/destination address masks. This closes the previously unresolved N19 u64 value transform. [UC1-UC7]

The same investigation resolves a container-provenance gap. The 16 B normal allocation result saved at K+`0x6368` is the N19 record-list container. The ordinary path forwards it through K+`0x8760` into lookup/insertion; exhaustion and the zero-identifier/span early-return arm publish that allocated pointer through the borrowed output cell. The separately saved comparison-context role at K+`0x5e50` has a different producer. Equal placeholder names in earlier reports did not establish one shared object or a universal pointer inequality. [UC2,UC8-UC10]

The full goal remains active. Native heap/frame ownership, allocation freshness, synchronization, hardware authentication, external caller admission, exceptional cleanup and successful daemon-kext exchange remain unproved. No target execution, emulation, FairPlay request, native allocation/release or IDB mutation occurred. Reference files suffice; no additional IDA query was necessary.

## Primary source and finite coverage

Pinned original: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are unslid VAs. Offsets/constants are hexadecimal with `0x` prefixes; byte counts use B. u32/u64 arithmetic is modular; BE64 denotes big-endian field assembly. These are flattened private register/stack interfaces, not recovered public C prototypes.

- [Source, original fixups, key states and liveness](triage_evidence/daemon_reader_u64_codec_source.json), [extractor](triage_evidence/recover_daemon_reader_u64_codec.py).
- [Queries, source translations and results](triage_evidence/daemon_reader_u64_codec_checks.json), [validator](triage_evidence/validate_daemon_reader_u64_codec.py).
- [Preservation seal](triage_evidence/daemon_reader_u64_codec_delivery.json), [scoped gates](triage_evidence/daemon_reader_u64_codec_quality_gates.json), [publication auditor](triage_evidence/verify_daemon_reader_u64_codec_publication.py).
- Adjacent [lookup/replacement and progress](daemon_reader_record_replacement_report.md), [typed payloads/append](daemon_reader_record_payloads_report.md), [returned-value staging](daemon_reader_value_consumers_report.md), [16 B allocation origins](daemon_reader_container_origins_report.md), [other constructor u64 convention](daemon_typed_scalar_report.md).

| Evidence | Exact scope |
|---|---|
| Captured source | 21 fragments: 16 branch-terminated ranges and five explicit cuts; 2031 instruction instances / 8124 B |
| Full new coverage | All captured non-BRAA instructions; 1945 distinct PCs, 2898 translated instances, 2813 SSA definitions |
| Reader | Complete 885-instruction body; eight byte loads, no stores or SP writes |
| Source control metadata | 20 original pointer records; 19 fragment/index/modifier matches |
| Key origins | Full preceding word decoder without mask substitutions; full 386-instruction preparer and literal-tail agreement; five intervening liveness ranges |
| Codec certificate | Eight new seed and 56 new arbitrary-state round proofs plus full merge and caller/data-flow joins |
| New/replayed results | 83 new UNSAT; 73 replayed UNSAT; one abstract SAT representation counterexample |
| Prior byte recapture | Earlier reader footprint and complete 746-instruction writer |
| Integrity controls | Six altered source/key/staging/provenance ledgers rejected by fresh-source comparison; not native behavioral tests |

The literal-tail cut overlaps the full preparer and is counted separately in instruction instances. A 156 B allocation-prefix/argument gap is separately checked for preserved X20/X22/X23/X24/SP and absence of control transfer. It is not counted as newly translated source. No captured range writes SP. Branch-terminated ranges and explicit cuts are not assertions of complete compiler-function boundaries.

Historical evidence may resolve from a canonical JSON filename to `.json.zst`. Current tools verify decoded logical hashes read-only; they do not restore or overwrite archives. The previously recorded unavailable historical SDK header citation remains a separate external-reference limitation and is not a dependency of these daemon codec proofs.

## Actual reader ABI, key origins and addresses

The N19 extent gate `0x100499044`, under its established incoming W8=`0x185d`, admits exactly P=8 B and supplies W24=`0x6cf4`. The caller at `0x1004a4de8` restores X3 from X20, loads cursor C from K+`0x7e8`, supplies buffer-pointer cell K+`0x4120`, and selects the reader:

| Operand or source | Established value |
|---|---|
| X0 | Current byte cursor C |
| X10 | K+0x4120, address of the buffer-pointer cell |
| W8 | 0x8c4, reader return selector |
| Call branch | table[0xbe63] -> 0x100588cb0, IA modifier0xa7d2 |
| Reader return | table[0x8c4] -> 0x1004cdeac, IA modifier0xfcf2 |

The complete preparer loads N19 cursor N0 from K+`0xa610` and stores it unchanged at K+`0x7e8`; its u32 total extent and prior fit/admission contracts are retained separately. Thus the reader's cursor is joined to the selected path's actual producer rather than assigned from a fixed snapshot. All nineteen literal-tail outputs agree with the full actual preparer state.

The preceding word decoder supplies X28 from the original first-round key and leaves X6 holding its literal third-round key. Nine required reader keys survive the five extent/type ranges; X20 also survives, and `MOV X3,X20` restores the tenth key. Relevant origins include `0x100800098` for X28 and the four-instruction X6 literal in `[0x1008004cc,0x1008004dc)`.

| Register | Required u64 value / role |
|---|---|
| X3 | 0xeb8e58819a88bf30, round5; restored from X20 |
| X6 | 0x9032dc5079388982, residual round3 key |
| X9 | 0x1dd3a2cc9b1a2a60, seed arithmetic input |
| X19 | 0x622c5d3364e5d59f, canonical seed offset |
| X21 | 0x4f99108510ad96e0, canonical round7 key |
| X23 | 0x7faaf81a732f68b4, round6 |
| X25 | 0xe70987b7a1f527b0, round2 |
| X26 | 0xa7bebfcf1750d389, canonical seed XOR |
| X27 | 0x144db9b1af6b5721, round4 |
| X28 | 0x324a764c67af2e0e, round1 |

The reader loads BUF through X10, fetches its saved return pointer from table[0x8c4], and reads exactly BUF+C+10 through BUF+C+17. The proved logical bound C+18<=S, with u32 total extent S and C<S, places all eight offsets below S without u64 offset wrap. Physical BUF arithmetic, readable owners, eager preparer-context validity and native mapping remain separate premises. [UC1-UC4]

## Canonical byte mask and complete u64 merge

For byte address A, the source masks reduce to the same canonical u64 calculation used by the established writer:

```text
s = ROR64(A & ~7,8) + 0x622c5d3364e5d59f
x = s XOR 0xa7bebfcf1750d389
y = s XOR 0xb6dc5654307e7f72
for k in K[0..6]:
    x = (ROR64(x,8) + y) XOR k
    y = ROR64(y,61) XOR x
m(A) = (x >> (8 * (A & 7))) & 0xff

K = [0x324a764c67af2e0e, 0xe70987b7a1f527b0,
     0x9032dc5079388982, 0x144db9b1af6b5721,
     0xeb8e58819a88bf30, 0x7faaf81a732f68b4,
     0x4f99108510ad96e0]
```

All state operations wrap at 64 bits. The final y update is unused. Each byte has a separate universal seed proof and seven arbitrary-state round proofs; carried precomputed rotates are explicit cuts. The last byte's seventh-round word equals the canonical word XOR `0x9898989898989898`, selecting an additional `0x98` byte contribution. That delta remains explicit in the whole-reader merge. An algorithm/library identity is unknown; the proved claim is this scalar function.

For j=0..7, A_j=BUF+C+10+j and input byte E_j:

```text
b_j = E_j XOR m(A_j)
W = BE64(b_0,b_1,...,b_7)
X9 = W XOR 0xfa039b7ca50c772e
```

The merge is not inferred from eight examples. It translates every instruction before the reader's final BRAA with eight final mask-word cuts justified by the 64 source lemmas. It covers the shifts, BFI, fused bit operations and full-width result for arbitrary input bytes, offsets, pointers and independent canonical mask words. The return pointer remains in X8. One SAT query rejects identifying raw X9 with unencoded W; it supplies no native input or fault fixture. [UC3-UC6]

At `0x1004cdeb4`, the returned X9 is stored as u64 at K+`0x12c8`. The recognized u64 tag `0xc31c` excludes the special span arm. The ordinary packing block reloads that value at `0x10056deec` and stores it at K+`0xa628`. The N19 writer caller supplies that cell to the shared eight-byte writer. Its entry loads the same raw64 value and applies the established pre-XOR `0x80915f9a168f26e3`.

The previously proved writer emits BE64(R XOR `0xfa039b7ca50c772e`) before its destination-address mask. Thus:

```text
reader: R = W XOR 0xfa039b7ca50c772e
writer: W_out = R XOR 0xfa039b7ca50c772e = W
```

At destination D_j, stored byte b_j XOR m(D_j) decodes back to b_j. Source and destination encoded bytes need not match. Seventy-two generic writer seed/round/selection queries and the complete N19 writer composition query are replayed against the byte-identical source.

The other constructor caller uses a different scalar convention:

| Representation | Relation to decoded wire value W |
|---|---|
| N19 reader/writer operand R | W XOR 0xfa039b7ca50c772e |
| Earlier constructor-entry operand B | W XOR 0x2c220a381b62f9ab |
| Conversion | B=R XOR 0xd6219144be6e8e85 |

The conversion is exact u64 XOR arithmetic. Shared writer code does not make the two caller operands interchangeable. These results close all three recognized N19 payload value codecs when composed with the earlier u32 and span proofs; complete packet identity and native exchange remain separate questions.

## Allocated container, comparison context and publication

The new allocation-prefix/argument cuts corroborate a 16 B request. The preceding allocation report establishes its original `_malloc` binding. Under normal return with SP/X19-X29 preserved, CONTAINER=X0 is stored at K+`0x6368`; a non-NULL result takes the two-u64 zero-initialization path. That path clears CONTAINER+0 and CONTAINER+8 before the initial reader loop. The call is not executed, and native allocation freshness/ownership remains unproved. [UC2,UC8-UC10]

| Role | Producer and route | Established use |
|---|---|---|
| List container | malloc result -> K+0x6368 -> join load at0x10047312c -> K+0x8760 | Head at+0, tail at+8 in lookup/append/replacement contracts |
| Comparison-context role | X10 store at0x1004d3e1c -> K+0x5e50 | Earlier comparison/context consumers; separate saved provenance |
| Borrowed result cell | K+0x8398 contains OUT | Receives the allocated list-container pointer |
| Outer continuation | K+0x7910 contains CONT | Return through X21, original IA modifier0xbcd2 |

The ordinary join loads its pointer from K+`0x6368`; packing forwards that same value to K+`0x8760`. Thus the pointer previously called CTX in local lookup/insertion contracts is this allocated head/tail container on the selected N19 path. The incoming comparison role at `0x5e50` is not its source. Different producer cells do not, by themselves, prove unequal numerical pointer values; that requires fresh/disjoint allocation and owner premises. No single global structure type is assigned to both roles.

On exhausted input, the reader loop has C=S. It selects `0x1005588b4`, which reloads CONTAINER from `0x6368`; the shared success/output path stores it through OUT and transfers full X6=`0x000000008b3dc651` through the saved outer continuation. This is a local pointer result, not a flattened-byte-buffer result or a Mach port.

The other publication arm requires encoded HRAW=`0x8b3dc651` and reader tag `0x1742`: decoded identifier zero and wire span tag `0x50db`. It publishes the same allocated container before constructing an ordinary node for that record. Earlier extent fit/admission still applies. The checked publication arm does not establish padding-byte validation or require cursor exhaustion; no external reachability claim is made.

```text
normal16 B allocation -> zero head/tail -> K+6368
                                           |
input record -> decoded fields -> ordinary join -> K+8760
                                           |
                                lookup / append or replace
                                           |
                                 saved-end cursor back edge
                                           |
                    exhaustion or zero-ID/span early return
                                           |
                              *OUT = allocated container
```

Under the earlier stable/fresh/disjoint list and normal-callee premises, these source contracts imply an ordered key/value reconstruction for the successfully completed ordinary prefix:

```text
start with the zeroed head/tail container
for each completed ordinary record before return:
    look up its decoded32-bit identifier
    absent: append a newly constructed record
    found:  replace that node in place with the new record
publish the container on the established successful return arm
```

The empty base has unique keys. Absence adds a new key at the tail; a match preserves its position and updates its record. Induction therefore gives first-occurrence key order and the latest completed ordinary record for each key. This is a consequence of the proved local contracts under their invariants, not a native observation. The source boundary is an allocated container of records; later list flattening is a separate interface.

Decoded field preservation consequently does not imply complete input/output byte-stream identity. Replacement can supersede earlier records, the special record can end reconstruction early, and later serialization can rebuild its own trailing record/padding. Successful-field codecs, container reconstruction and native transport must remain distinct claims.

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent results | Stress test / falsification probe |
|---|---|---|---|
| UC1 | Exact pinned daemon image and original fixup catalog | All VAs, source bytes and dispatch identities | Rehash the image and recapture bytes/fixups; changed builds invalidate address reuse |
| UC2 | Producers/consumers share the recorded K/frame epoch with stable reaching cells | Cursor7e8, raw64 staging, container6368/8760 and result publication | Resolve intervening aliases/writes; matching offsets alone do not prove a reaching definition |
| UC3 | Actual preparer/word residual keys and N19 phases survive as proved | Eight seed/round components and caller-specific reader ABI | Recheck the19 literal-tail outputs, preceding word residuals, five liveness ranges and caller's X3 restore |
| UC4 | BUF, source/destination byte extents, frame and eager preparer reads are valid/stable | Byte-address interpretation and source/target mask composition | Establish owner sizes, physical arithmetic and lifetime; logical offset bounds do not prove native address validity |
| UC5 | Source-justified mask-word cuts compose at the stated register interfaces | Full885-instruction merge and u64 value formula | Recheck each seed, seven arbitrary-state rounds and byte7's9898 delta; no finite example substitutes for these lemmas |
| UC6 | Raw64 reloads and paired writer inputs retain the stated values | Reader-to-writer cancellation and decoded byte preservation | Trace12c8->a628 and the writer's saved-value load; another caller's operand encoding is not interchangeable |
| UC7 | Earlier recognized-tag, P=8 and extent-fit/admission contracts apply | N19 ordinary u64 interpretation and eight payload bounds | Recheck persistent tagc31c, caller phase185d and C+18<=S; external reachability remains unproved |
| UC8 | The16 B allocation returns normally with SP/X19-X29 preserved and has valid/disjoint storage | Two-word initialization, allocated-container identity and lookup use | Establish actual allocator identity/effects, source gap preservation, pointer ownership and later bank/phase reaching definitions |
| UC9 | Comparison-context and list-container roles retain their separate source producers | Correct role/type assignment across5e50 and6368/8760 | Trace both origins independently; distinct cells do not prove pointer inequality without freshness/disjointness premises |
| UC10 | Borrowed OUT/CONT and list owners remain valid with the earlier coherent-link/normal-callee invariants | Publication and ordered reconstruction consequences | Establish complete caller/owner/synchronization protocol; native PAC, admission, rights, delivery and daemon-kext pairing remain unknown |

## Reproduction, complexity and bounded continuation

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_reader_u64_codec.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_reader_u64_codec.py
```

The fixed eight-byte reader has O(1) time and scalar space. Each canonical byte mask uses seven constant-size rounds. Ordinary list processing retains the earlier O(k) first-match search per record and O(P) span transfer; aggregate bounds and normal-retirement premises are in the preceding replacement report. Source-requested object extents are16 B for the container,32 B per node and P+10 B per record buffer; allocator overhead/native allocation effects are not measured here.

Extraction/translation costs O(B+F+I+H) time/space for image bytes B, fixups F, selected instructions I and referenced evidence H. Query construction repeats finite projections. No polynomial solver bound is claimed. Per-query timeout is15 s and subprocess limit20 s; unknown/timeouts are rejected. Publication audit costs O(total logical artifact bytes+links), with O(manifest+largest JSON) memory. All field/extent calculations are exact bit-vector or integer operations, not physical measurements.

- High: trace the allocated-container result through its complete caller/consumer and later flattening interface to build-matched transport operations.
- High: compare normalized field representations across daemon/kext selector26/RPC502/700 contracts, then establish actual endpoint/peer/rights lineage before claiming successful exchange.
- High: complete exceptional cleanup, non-ordinary return/status and partial-result contracts without importing ordinary-path invariants into other epochs.
- Medium: establish frame/heap separation, allocation freshness, bank-root reaching definitions and synchronization governing list mutation.
- Low: retain epoch-specific type names and caller-specific scalar encodings; no IDB renames or unsupported algorithm/library identification are made.

QG1: Pass. The technical source/model investigation requires no normative conclusion.

QG2: Pass for UC1-UC10. Assumptions, dependencies and falsification probes are explicit.

QG3: Pass for complete u64 reader semantics, paired writer composition and allocated-container/result provenance. Complete native parser and cross-layer closure remain active.

QG4: Pass. u32/u64 operations, byte offsets, BE64 merge, XOR representation conversions, logical bounds and computational limits are explicit.

QG5: Pass for bounded claims. Raw versus decoded values, source/destination masks, container versus comparison role, reconstructed records versus packet identity and source versus native behavior remain distinct.

QG6: Pass. Original source/fixup recaptures, full non-BRAA coverage,83 new and73 replayed UNSAT queries support the claims. The SAT representation counterexample and six integrity controls are not native fixtures. Memory supplies guidance rather than a semantic premise.

QG7: Pass for the finite high/medium/low continuation list. The full goal remains active and is not marked complete.


[N19 outer object and lifecycle](daemon_reader_outer_lifecycle_report.md): the selected producer requests128 B and saves OBJ at K1ae8; N19 receives OBJ+8 and its exact composed admission is F==0. A selected context prefix copies eight fields, including an inverted flag lowbit. Exact raw success publishes OBJ through OUT at K1d60; failure forwards a local pointer-cell address to shared cleanup. The local cursor reserves/restores32 B. Thirteen ranges/313 instructions,22 fixups/20 slot matches,512 bank cases,299 translated sites,19 UNSAT queries,one SAT interpretation counterexample and six controls pass. Complete initialization/cleanup, upstream F, native owners/PAC/external delivery and daemon-kext pairing remain unproved.
