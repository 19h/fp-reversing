# SecureTime context comparison and private comparison-record decoder

The source after the selected clock update implements a carry-aware unsigned comparison between the decoded accumulator and a normalized context word. Under the additional saved-phase and helper-binding premises below, its subsequent gate selects index `0x418` exactly when that comparison is true and a saved control word's low byte equals 1; otherwise it selects `0x17`. These are source continuation choices. Their externally visible meaning, actual request lineage and native reachability remain **unknown**. [CX1-CX7]

This increment also corrects a factual composition error in the [preceding accumulator report](lskd_clock_accumulator_report.md): record R`+0x20` receives a carry-flag XOR minus the record key, not seed98 minus that key. The original `EOR W22,W21,W11` at `0xfffffe000a5245c8` overwrites the old seed value. The preceding isolated store query was valid for arbitrary incoming X22; attributing that input to seed98 across the intervening source was not established. The report, generator and compressed evidence now include the correct handoff. The elapsed high-water identities are unaffected. [CX1,CX4-CX5]

[Original source and certificates](triage_evidence/lskd_context_compare_checks.json.zst), the [extractor](triage_evidence/recover_lskd_context_compare.py) and the [publication audit](triage_evidence/verify_lskd_context_compare_publication.py) retain nine spans / 260 instructions / 1,040 B. Twenty-two UNSAT certificates cover 143 lifted instruction instances; two SAT controls reject the erroneous seed handoff and a wrapped-operands-only comparison. A 256-slot census retains three original matching-diversity helper candidates, and eleven original authenticated slots are checked. No new IDA access, native execution or IDB mutation occurred. The broad interface investigation remains active.

```text
fresh decoded accumulator U        raw context word at context_root+178
          |                                      |
       A=U+B                            Z=raw+ab53c9aef42360b8
          +--------------------+-----------------+
                               |
                   cA=(A<B), cZ=(Z<B), CX=cA XOR cZ
                               |
                    record operand = zero_extend(CX)
                               |
        helper binding premise: bank constant37 -> A52F458
                   /                           \
              CX!=0                           CX=0
           index143                         index156
          A55EE4C                           A55B298
          flag=cZ                           flag=(A<Z)
                   \                           /
                    index2eb -> A528950: flag=(U<LIMIT)
                               |
              false -> private code0636782c
              true  -> control byte gate -> code06371ecb or06371ecc
                               |
                    code==06371ecc ? index418 : index17
```

All constants/addresses in this diagram are hexadecimal. B=`0x081864b3`; comparisons are unsigned except the explicitly recovered signed-byte implementation of the control gate. The diagram is a conditional source composition, not a traced transaction.

## Provenance and bounded helper binding

Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized FairPlay image SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every retained code byte is compared between them. Exact supplied-C excerpts at lines 37158-37193 and 47428-47489 corroborate the carry-to-record producer and comparison leaf; original A64 supplies exact widths and reaching-register evidence. The three original supplied inputs remain unchanged. [CX1]

The call at `0xfffffe000a5246ac` loads its target from `TABLE + 8*(0x9fe + c)`, where c is the final byte-bank output, c in [0,255], and the conditional TABLE is `0xfffffe000846c420`. Its discriminator is `0x2971`. The census retains every original slot word and normalized target in indices `0x9fe..0xafd`. Exactly three slots have the original authenticated flag and that diversity; their chain membership and decoded targets are separately verified:

| c | Index | Original slot | Target | Source attribution |
| --- | --- | --- | --- | --- |
| `0x0e` | `0xa0c` | `0xfffffe0008471480` | `0xfffffe000c4ba95c` | Exact original kernel symbol `_IOMallocTypeVarImpl` |
| `0x22` | `0xa20` | `0xfffffe0008471520` | `0xfffffe000a52fd10` | Two-instruction BTI/RET leaf; no record write |
| `0x37` | `0xa35` | `0xfffffe00084715c8` | `0xfffffe000a52f458` | Comparison-to-continuation record decoder |

Thus a matching discriminator does not identify this call's target. The byte-bank roots saved at SP`+188/+180` remain unresolved. The remaining composition explicitly assumes c=`0x37`, reaching the comparison decoder. This is not a proved actual bank constant or an assertion that other candidates execute. The census describes original metadata; no hardware pointer authentication, live pointer state or unconstrained-target validity is tested. [CX2-CX3]

## Complete comparison-leaf contract

`0xfffffe000a52f458..a52f4f0` is a 38-instruction leaf: BTI, 36 lifted scalar instructions and RET. Five source pieces cover every non-BTI/RET instruction, including data-dependent selection of the payload offset. The only explicit memory write is a four-byte result at R`+0x10`, source PC `0xfffffe000a52f4e8`. It makes no external call and leaves X0=R for return. [CX1,CX3,CX5]

Let K=`u64((R XOR 4c2e944469e35e3f) * 7a59c441)`, k=low32(K). The exact decoded ABI is:

| Input location | Width (B) | Decoded role |
| --- | ---: | --- |
| R`+00` | 8 | L=`u64(record00-K)` |
| R`+0c` | 4 | Payload selected when predicate is true |
| R`+14` | 4 | Payload selected when predicate is false |
| R`+18` | 4 | mode=`u32(record18-k)`; only bit zero affects the predicate |
| R`+1c` | 4 | result mask=`u32(record1c+k)` |
| R`+20` | 8 | Q=`u64(record20+K)` |
| R`+10` | 4 | Output: selected payload XOR k XOR result mask |

```text
predicate = (mode & 1) ? unsigned(L)>=unsigned(Q) : L!=Q
payload_offset = predicate ? 0x0c : 0x14
u32[R+10] = u32[R+payload_offset] XOR k XOR u32(u32[R+1c]+k)
return R
```

The decoded operands and mode are otherwise arbitrary. Addresses and all 64-bit arithmetic use u64 modular semantics; word arithmetic uses u32. Valid 40 B record storage is an extent premise. The output overwrites the producer's previously unwritten four-byte gap. It is not an allocation, lock, RPC or Mach-message primitive. [CX3-CX5]

## Corrected producer and two exact result indices

The preceding source establishes A=`u64(U+B)` and Z=`u64(raw_context178+ab53c9aef42360b8)`. Its two carries are cA=`unsigned(A)<B`, cZ=`unsigned(Z)<B`; CX is the XOR of their u32 0/1 forms. The new contiguous lift from `0xfffffe000a5245b4` through `a524654` covers both carry tests, W22's overwrite, selector constants, key mixing and record stores. It explicitly proves X22=zero_extend64(CX) at the record handoff. [CX2,CX4-CX5]

For conditional source phase W23=`0x6e3`, the producer writes:

| Offset (hex) | Width (B) | Exact value |
| --- | ---: | --- |
| `00` | 8 | K |
| `08` | 4 | `u32(392d87ef-k)`; not read by this leaf |
| `0c` | 4 | `k XOR f6074dc1` |
| `10` | 4 | No producer write; leaf result |
| `14` | 4 | `k XOR f6074dd4` |
| `18` | 4 | k |
| `1c` | 4 | `u32(f6074c82-k)` |
| `20` | 8 | `u64(zero_extend64(CX)-K)` |

Joining the complete leaf decoder gives L=0, Q=CX and mode=0. Its `L!=Q` predicate equals CX!=0. The returned word is therefore:

```text
CX!=0: f6074dc1 XOR f6074c82 = 0x143
CX==0: f6074dd4 XOR f6074c82 = 0x156
```

Both values are positive signed u32 indices. The caller's sign extension consequently selects precisely the two original slots below under this binding/record contract. This discharges the range question for this selected callee and producer; it does not supply a range contract for unresolved alternative callees or unmatched record epochs. The prior abstract negative-index control remains valid outside this selected contract. [CX3-CX5]

| Index | Original slot | Target | Diversity | Selected role |
| --- | --- | --- | --- | --- |
| `0x143` | `0xfffffe000846ce38` | `0xfffffe000a55ee4c` | `0xaf5e` | Carries differ; preserve cZ as comparison flag |
| `0x156` | `0xfffffe000846ced0` | `0xfffffe000a55b298` | `0xaf5e` | Carries equal; compare wrapped operands |
| `0x2eb` | `0xfffffe000846db78` | `0xfffffe000a528950` | `0xead5` | Joined comparison flag |

## Carry-aware context predicate and saved control byte

Both result arms load a saved u32 phase from SP`+0x1f4`. The following routing requires that value to be `0x6e3`, independently of the earlier incoming/source-phase premise. Its actual producer has not been recovered. Both arms also reload X14 from SP`+0x1e8`; call this saved u64 CONTROL. Under the saved-phase premise, both select index `0x2eb`, W9=1 and W10=1. At the join, X22=1: on the different-carry arm it is the retained CX; on the equal-carry arm the source explicitly replaces it with X9=1. [CX2-CX4]

The different-carry arm preserves W21=cZ. The equal-carry arm sets W21=`unsigned(A)<unsigned(Z)`. Define the normalized context value:

```text
LIMIT = u64(raw_context178 + ab53c9aeec0afc05)
Z = u64(LIMIT + B)
LT = (cA != cZ) ? cZ : unsigned(A)<unsigned(Z)
LT == unsigned(U)<unsigned(LIMIT)
```

The complete comparison identity is proved for arbitrary u64 U and LIMIT, including wrapping biased operands. A SAT control demonstrates that directly comparing A and Z alone is insufficient. LIMIT is an arithmetic normalization of an unknown context field, not an established expiry timestamp or calibrated physical duration. [CX4-CX6]

The join selects index `0x940` when LT=1 and `0x155` when LT=0. It then replaces W21 with private code `0x0636782c` and restores X24 from SP`+0x1b0`. On the LT=1 arm, `0xfffffe000a522b00` implements another predicate using signed-byte extraction and CINC.GT. With the source-established W9=W10=X22=1, it reduces exactly to:

```text
W21 = 0x06371ecb + (low8(CONTROL) == 1)
```

That arm returns to index `0x155`. The common status dispatcher chooses `0x418` when W21=`0x06371ecc`, otherwise `0x17`. Combining the source contracts gives:

```text
next_index = (unsigned(U)<unsigned(LIMIT) && low8(CONTROL)==1)
             ? 0x418 : 0x17
```

No return to the outer caller, result serialization, success code or request admission is assigned to either choice. W21 here is a private continuation code. [CX2-CX7]

| Index | Original slot | Target | Diversity | Conditional role |
| --- | --- | --- | --- | --- |
| `0x940` | `0xfffffe0008470e20` | `0xfffffe000a522b00` | `0x51e4` | LT true; control-byte gate |
| `0x155` | `0xfffffe000846cec8` | `0xfffffe000a5237a8` | `0x51e4` | Common private-code test |
| `0x17` | `0xfffffe000846c4d8` | `0xfffffe000a527b24` | `0x3757` | Combined predicate false |
| `0x418` | `0xfffffe000846e4e0` | `0xfffffe000a522538` | `0x3757` | Combined predicate true |
| `0x498` | `0xfffffe000846e8e0` | `0xfffffe000a5323f0` | `0x95d7` | True arm's next source hop |

The `0x418` fragment subtracts `0x24b` from the retained phase word `0x6e3` and branches through index `0x498`. The two later bodies at A527B24/A5323F0 are frontier destinations; this report does not claim their complete semantics. No incoming/outgoing Mach port or message-emission location is newly established by this private control interface.

## Assumption register

| ID | Assumption and dependent claims | Stress test / falsification probe |
| --- | --- | --- |
| CX1 | Pinned original KC, normalized image and supplied C identify this build. All addresses and provenance depend on it. | Rehash inputs, compare every retained byte and reparse original chained slots; retain unchanged hashes for all three supplied inputs. |
| CX2 | Conditional source/table/flag/frame/object roots match the declared view; saved SP+1f4 independently equals 6e3. Selected offsets and routing depend on it. | Recover reaching definitions for both phase values and frame roots. An incoming phase alone does not prove the saved phase. |
| CX3 | The byte-bank output is 37 and the call reaches A52F458, with a returning valid record ABI. The leaf-to-producer join and subsequent paths depend on it. | Resolve actual SP+188/+180 roots/key2f; test all256 byte inputs for those roots. Replay the three-candidate census; diversity alone cannot select the comparator. |
| CX4 | Context, current object/seed, record and saved-control values share the declared stable epoch, with valid nonaliasing storage and preserved call state. Cross-piece semantics depend on it. | Match publications, overwrites and call effects; test changed roots/epochs. Replay the corrected W22 source handoff instead of carrying seed98 across its overwrite. |
| CX5 | Scalar A64 u32/u64 operations, CSEL, HS, TST, SXTB and signed GT match the decoder and fixed-cell model. Exact formulas depend on it. | Re-lift every selected slice and all36 scalar helper instructions; replay22 queries and both SAT controls; check the sole4 B result-store footprint. |
| CX6 | The arithmetic LIMIT normalization is used only as an integer relation. Physical/expiry semantics are not assumed. | Recover the context+178 producer and clock/provider relation before attributing units, expiry or calibration. |
| CX7 | Outer result, admission and transport require further consumer/caller joins. No such join is assumed. | Trace both final destinations through actual handler return/serialization and daemon request/reply identity. |
| CX8 | The 256-slot census is bounded to the original call's byte-sized index window and original metadata. Candidate completeness depends on that scope. | Verify the call's mask/additive/table operands, every original slot word and all three matching chained fixups; separately investigate live table mutation or other call windows. |

## Bounded continuation

| Impact | Question | Required evidence |
| --- | --- | --- |
| High | Does this reader actually bind the comparator and saved phase? | Actual incoming edge, SP+188/+180 bank roots, saved SP+1f4 producer and caller state. |
| High | Who controls raw_context178 and CONTROL's low byte? | Source definitions of SP+1f8/SP+1e8 and context+178, their epochs and external-input lineage. |
| High | What does the combined predicate change externally? | Both A527B24/A5323F0 consumers, resulting state/return, serialization and matched daemon-kext transaction. |
| Medium | Do other record producers use the comparator's odd-mode >= predicate? | Caller/bank bindings and exact producer fields, with all-address keys and record lifetimes. |
| Medium | Are alternate matching-diversity slots selected in other frame epochs? | Source-produced bank roots and update history; avoid eliminating allocator/NOP candidates from record resemblance alone. |

## Reproduction and scoped quality gates

Run `recover_lskd_context_compare.py --verify` and the corrected `recover_lskd_clock_accumulator.py --verify` with `triage_evidence` and Z3 on the Python module path. The first re-extracts original/normalized bytes, supplied excerpts, all256 window slots and eleven fixups; it re-solves the new proofs/controls and checks dependencies. The publication audit replays all34 corrected predecessor certificates and both predecessor SAT controls, verifies the exact manifest/file delta and original inputs, and scans raw/decompressed owned content plus commit metadata for analyst paths. Large JSON is published as verified Zstandard archives.

Extraction costs O(B+I+W) time/space plus original chain decoding, for bytes B, instructions I and census width W=256. Scalar expression construction costs O(I); SMT cost is separate, capped at10 s per query. Arithmetic and store extents are exact at their declared widths; offsets use bytes. Native timing, physical clock units and error bounds are unknown.

- **QG1** passes for factual source/interface analysis.
- **QG2** passes with CX1-CX8, dependencies and falsification probes.
- **QG3** passes for the corrected producer, complete comparison leaf, bounded candidate census, context/control predicate and exact original continuations; the broad goal remains active.
- **QG4** passes with explicit u32/u64/signed-byte semantics, four-byte result and byte-sized helper window; no physical units are inferred.
- **QG5** passes with the prior handoff error corrected, actual banks/saved phase unresolved, arbitrary wrapped operands covered and externally visible meanings unassigned.
- **QG6** passes with original bytes/fixups/symbol, supplied C, checked source certificates, pinned dependencies and preserved inputs.
- **QG7** passes with impact-ranked binding, context/control provenance, outer-result and comparator-family questions.


The [named-wrapper reader lineage](lskd_reader_lineage_report.md) now binds phase `0x6e3`, the four reader-call banks and context byte `+0x174` on a matched source template. It recovers the complete flag-record decoder and the conditional clock-entry gate. Earlier unresolved-root statements describe the earlier bounded increment; the intervening context transform, full route preservation, native epoch and daemon request lineage remain open.


The [paired context representation](lskd_context_codec_report.md) now proves pointer recovery and the inverse 512 B data transform for matched seed/slot/object epochs. The decoded initializer has byte `+0x174`=0, byte `+0x175`=1 and a zero normalized comparison limit. Later field writers, representation restoration, native epoch matching and daemon request lineage remain open; earlier codec-unknown statements describe the earlier bounded increment.
