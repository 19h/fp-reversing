# Paired context-pointer and 512 B representation contract

The population writer and selected reader implement inverse context representations. Under a matched seed, slot, frame and object epoch, the reader recovers the allocation pointer from the transformed vector word and restores the writer's 512 B data representation in place. This closes the numerical pointer/data-codec boundary in the preceding [reader-lineage report](lskd_reader_lineage_report.md) for that paired source contract. A matched native context, complete request path and later representation restoration remain **unknown**. [CC1-CC8]

The initializer writes context byte `+0x174`=0, adjacent byte `+0x175`=1, and word `+0x178`=`0x54ac365113f503fb`. The last value normalizes to a zero limit under the recovered reader equation. Consequently, the unchanged initial context skips the selected clock-reader arm; its normalized limit also cannot satisfy the unsigned accumulator-less-than-limit comparison. A later eligible context requires additional state changes. No external acceptance or rejection meaning is assigned. [CC1-CC7]

[Original source and certificates](triage_evidence/lskd_context_codec_checks.json.zst), [extractor](triage_evidence/recover_lskd_context_codec.py) and [publication audit](triage_evidence/verify_lskd_context_codec_publication.py) retain five spans / 460 instructions / 1,840 B, with 48 UNSAT queries over 356 lifted instruction instances in 26 source pieces. Two SAT controls disprove generic raw-slot equality and demonstrate that a mismatched seed can change the recovered pointer. Three register-preservation audits cover 275 instruction rows. No native target, new IDA access or IDB mutation occurs.

```text
typed allocation P, initialized/opaque context bytes B[0..511]
  |
  | writer A51B9D8
  +-> byte rewrite -> swaps i=63..1 -> represented bytes C at P
  +-> pointer-byte permutation -> word-affine map -> XOR mask -> slot E

same seed + unchanged slot E + valid/disjoint object/frame epoch
  |
  | reader A5315B0
  +-> XOR mask -> inverse word-affine map -> inverse permutation -> P
  +-> swaps i=1..63 -> inverse byte rewrite -> original bytes B at P
  +-> SP+118 -> SP+1f8 -> reads byte174 and word178
  |
  +-> later restore/re-encode or retirement path: unresolved
```

Addresses/constants in this diagram use hexadecimal suffixes; byte counts are decimal. The equality is a conditional source correspondence, not a traced transaction.

## Assumption register and primary evidence

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| CC1 | Pinned original KC and normalized FairPlay image describe this build | Source bytes, constants and initializer | Recompute hashes and compare every retained code/constant byte; compare a live image separately |
| CC2 | Writer and reader select the same flag/seed-table epoch; selected flag=255 | Identical seed word, pointer permutation/mask and object key | Check both source selection slices, pointer cells and concurrent writers; mismatched-seed SAT control rejects unconditional recovery |
| CC3 | The read vector word is the writer's unchanged emitted slot for this allocation | Recovered pointer equals that allocation pointer | Match slot/index publication and intervening writes; raw slot is generically encoded, as the SAT control shows |
| CC4 | Scratch bases are eight-byte aligned; frame cells are valid and preserved as stated | Overlapping byte views and pointer codec | Universal OR/add alignment lemma, bounds certificates and high-address symbolic-memory fixture; establish actual frame identity separately |
| CC5 | The 512 B object is accessible, nonwrapping and disjoint from live frame/seed/slot storage | Pointer-mask preservation and in-place data inverse | Check allocation extent and indirect write ranges; direct register audits alone cannot exclude memory aliases |
| CC6 | Key and coordinates remain stable through each source loop; repeated accesses are coherent | Opposite shuffle schedules and byte inverse | Source numerator/counter/step checks, register audits and predecessor certificates; establish native serialization independently |
| CC7 | No relevant context-field updates occur between initialization and the composed observation | Initial byte174 gate and zero-limit consequence | Recover later writers and actual context lineage; do not apply the initial-state consequence after an update |
| CC8 | Stated scalar/SIMD semantics and unsigned integer interpretation model the source | Solver/source compositions | Rebuild the fail-closed interpreter, replay SMT and independently inspect operations, byte order and division-domain joins; native FP/SIMD availability is separate |

Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized FairPlay image SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Both copies agree for all retained code and the 128 B constant region at `0xfffffe0007920f10`. Supplied C lines 29860-30081, 48721-48980 and 52363-52380 are retained as corroborating excerpts; original A64 supplies exact widths, reaching registers and byte overlap. The decompiler's fragment arguments and synthetic STACK notation are not recovered public ABI declarations. The three supplied inputs are unchanged. [CC1,CC8]

The floating-point-looking instruction in the index prefix is `FNEG D6,D6` on the literal `0x8000000080000000`. Its relevant result is `0x0000000080000000`: it supplies two integer lanes, `0x80000000` and zero. The interpreter restricts this case to that exact non-NaN literal; it does not implement general floating-point arithmetic. Arm's FNEG operation and shared FPNeg definition support this bit-sign change outside the AH/NaN special case. Upper-vector merge behavior is unused by the two-lane consumers. Instruction availability/trapping is a native-environment premise. [Arm DDI 0602, ID032025, page 1460 and shared FPNeg pseudocode](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85). The inspected 15,314,151 B document has SHA-256 `b7baa6869789722df70da60170d999a62810409aaabbb6db1ef729ed68686bdf`; the full document is not committed. [CC8]

## Exact pointer-slot representation

Both source prefixes select the word at seed-table byte offset `255 & 0x030c5e1c = 28`, the previously identified seed[7]. Let S be that u32 word, T=`u32(S*0x030c5e1f)` and F=`0x01000193`. No native S value is asserted. For d in {7,6,5,3}, define

```text
N_d = u32(((T+d) XOR T)*F)
j_d = unsigned_remainder(N_d,d)
M_lo = u32(T*T) XOR T
M_hi = u32(T*T+T) XOR T
M = concatenate_u32(M_hi,M_lo)
```

The writer and reader SIMD prefixes produce exactly the same four index formulas. Their magic-quotient domains are independently certified over every integer x in [0,2^32-1]:

| Divisor | High-product multiplier | Quotient after high product h=floor(x*m/2^32) |
| ---: | --- | --- |
| 7 | `0x24924925` | `floor((floor((x-h)/2)+h)/4)` |
| 6 | `0xaaaaaaab` | `floor(h/4)` |
| 5 | `0xcccccccd` | `floor(h/4)` |
| 3 | `0xaaaaaaab` | `floor(h/2)` |

Each lemma proves `d*q <= x < d*(q+1)` and the intermediate nonoverflow bounds used by the word instructions. Thus the source subtractive remainders equal x modulo d and fit in a byte. Source bit-vector formulas and these mathematical unsigned-domain lemmas are separate certificates; the interpretation of high products, logical shifts and nonoverflowing subtraction joins them. Direct arbitrary-word bit-vector comparisons against UDIV did not finish within 10 s per divisor and are not counted as proofs. [CC8]

Let Q_T permute the eight little-endian pointer bytes with swaps `(7,j7),(6,j6),(5,j5),(4,0),(3,j3)`, followed by `(byte0,byte1,byte2)=(old1,old2,old0)`. Its inverse first rotates those three bytes oppositely, then performs the swaps in reverse order. Source byte loads/stores, including halfword accesses overlapping byte stores, are lifted with coherent eight-byte views. Dynamic accesses have separate bounds queries. Initial scratch bytes are symbolic; the zero qword comes from the actual source zeroing store. Permuting that zero scratch and applying its word-affine map produces M. [CC4,CC8]

Define A_M on a qword by applying `u32(word*F+M_word)` independently to each of its two u32 words. Its inverse is `u32((word-M_word)*0x359c449b)`; `u32(F*0x359c449b)=1`.

```text
writer: E = A_M(Q_T(P)) XOR M
reader: P_recovered = inverse_Q_T(inverse_A_M(E XOR M))
paired source theorem: P_recovered = P
```

The composed roundtrip query quantifies arbitrary u64 P, arbitrary u64 mask and all four bounded permutation indices. Separate source lemmas identify the actual mask and indices for the shared S. The first SAT control uses the actual zero-seed codec and an aligned nonzero symbolic P to show E can differ from P. The second compares the zero-seed writer with a seed-one reader. Neither model establishes a mapped or accepted native pointer. [CC2-CC5,CC8]

Writer source `0xfffffe000a51bd34..a51bd48` publishes the XOR-combined qword at the vector index, as certified in the [population report](lskd_element_population_report.md). Reader source `a5317d4` loads the recovered pointer into X11, later used for the data transform. The prior [lineage report](lskd_reader_lineage_report.md) proves the suffix copies from SP`+228` to SP`+118` and then SP`+1f8`. With CC2-CC6, the working pointer therefore identifies the same allocation P; numerical equality between E and P is not required.

## Complete data inverse and representation lifetime

Both bodies use K=`u32(low32(P)*0x030c5e1f) XOR S`. The writer pointer reload/key slice and reader key slice are lifted separately. The writer's SIMD body was already fully interpreted by the [population extractor](triage_evidence/recover_lskd_element_population.py); its retained certificates are replayed here. The new reader interpreter consumes the original widening, widening multiplication, four-lane arithmetic, EOR3, TBL selection, object store and coordinate steps. For byte position n and byte b, let

```text
m(n,K) = low8(K) XOR low8(u32(n+K)*u32(n-K))
writer_byte(b,n,K) = u8((b XOR m(n,K))*0x93)
reader_byte(c,n,K) = u8(c*0x9b) XOR m(n,K)
reader_byte(writer_byte(b,n,K),n,K) = b
```

Both u8/u32 arithmetic reductions are modular. The last equality holds for every byte, coordinate and key because `u8(0x93*0x9b)=1`. The source setup and step cover 32 blocks of 16 B, from offset 0 through the final store at 496..511 B. The existing initializer's unwritten bytes remain opaque; a representation roundtrip does not establish their original values or allocator zeroing. [CC5-CC6,CC8]

For i in 1..63, both shuffle bodies compute `j=unsigned_remainder(u32(((K+i) XOR K)*F),i)`. Thus `0 <= j < i` and each XOR swap touches distinct u64 cells within 64 words / 512 B. The new reader numerator and three-store swap are lifted; its source counter starts at 1, increments and terminates at 64. The previously certified writer counts down from 63 through 1. A generic array transposition-involution query plus the exact reverse schedules establishes cancellation. This is a source/induction composition, not a new instruction execution over a concrete 512 B object. [CC5-CC6,CC8]

The writer applies the byte map before descending swaps; the reader undoes swaps before applying the inverse byte map. Consequently the complete reader restores all 512 B for a matching paired epoch. The object is decoded **in place**. No new allocation or external call appears in either retained transform. A future repeat read needs a compatible representation state; later re-encoding, retirement or alternative state handling is unresolved and cannot be inferred from this roundtrip theorem.

The 79-row writer-middle audit preserves X9-X12, V0, SP and FP, linking the saved permutation indices and mask across the data/shuffle body. The 126-row reader-prefix audit preserves X10, X2, X3, SP and FP, retaining S and the scalar factors until K is formed. The 70-row reader-data audit preserves SP, FP, X8 and X9. Indirect object writes still require CC5; register preservation alone does not preserve aliased scratch storage.

## Initialization and reader-control consequence

Nine original instructions at `0xfffffe000a5342d4..a5342f8` establish these distinct fields:

| Offset | Width (B) | Initial value | Source store PC |
| --- | ---: | --- | --- |
| `0x174` | 1 | 0 | `0xfffffe000a5342d4` |
| `0x175` | 1 | 1 | `0xfffffe000a5342dc` |
| `0x178` | 8 | `0x54ac365113f503fb` | `0xfffffe000a5342f0` |
| `0x180` | 1 | 0 | `0xfffffe000a5342f4` |

The source pairing now permits those original values to be related to the working context after the matching decode. The prior flag-record contract uses byte174, so the unchanged initializer state selects index `0x155`, target `0xfffffe000a5237a8`, rather than the clock-reader presence gate. Byte175=1 cannot substitute for byte174. Independently,

```text
LIMIT = u64(context178 + 0xab53c9aeec0afc05)
      = u64(0x54ac365113f503fb + 0xab53c9aeec0afc05)
      = 0
unsigned(U) < 0 is false for every u64 U
```

These are initial-state continuation facts under CC7. They do not identify an expiration policy, an accepted request, a native object or an external authorization result. Recovering later field writers and their actual inputs is the next control-flow question.

## Validation and bounded continuation questions

The generator rebuilds original-byte captures and all 48 queries; the publication audit replays the 48 new UNSAT queries/two SAT controls plus 22 population and 26 reader-lineage UNSAT certificates. The high-address frame fixture is symbolic storage, not a sampled kernel frame. The universal aligned-OR lemma and the fact that source frame addressing uses only these fixed offsets qualify translation to the stated aligned frame template. Solver replay alone does not independently validate instruction interpretation.

Extraction/expression construction requires O(N+I+L) time/space for consumed source/index bytes N, retained/lifted instruction instances I and modeled byte-lane work L; SMT complexity is separate. Source data loops have fixed 512 B extent: 32 SIMD iterations plus 63 swaps; no elapsed-time or clock-value unit is inferred.

| Impact | Bounded next question | Required evidence |
| --- | --- | --- |
| High | Which later writers change byte174 and normalized word178? | Actual context-root lineage, exact-width stores and input provenance |
| High | Which exit paths restore the stored representation? | Full decode-to-return control flow, re-encoding or retirement epochs and repeated-read state |
| High | Does a daemon/IOKit request reach this named wrapper with this slot? | Actual caller, argument and record lineage; native identity separately |
| High | Can seed, slot or context change during this operation? | Lock ownership/lifetime, intervening writers and matched runtime epochs |
| Medium | Does every relevant caller preserve the required frame cells? | Whole-route write effects and callee noninterference, beyond the retained register audits |
| Low | Do other codec instances use a different representation revision? | Compare constants and source contracts by pinned image, without transferring this build's result |

**QG1** passes: factual representation/interface analysis. **QG2** passes: CC1-CC8 specify dependent claims and falsification probes. **QG3** passes for this increment: paired pointer/data representation, initialization and lifecycle boundary are covered; the broad goal remains incomplete. **QG4** passes: fixed widths, little-endian views, byte extents, modular arithmetic, unsigned-domain division and complexity are explicit. **QG5** passes: seed/slot mismatch, aliases, unknown initial bytes, indirect writes, timeout boundaries and later representation state are retained. **QG6** passes: original bytes/constants, supplied C, primary Arm semantics and certificates are distinguished. **QG7** passes: impact-ranked continuation questions are recorded.
