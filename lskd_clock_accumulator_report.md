# SecureTime elapsed high-water accumulator and continuation record

The selected stored-clock reader updates a seed-encoded accumulator only when the fresh four-byte clock sample exceeds both its decoded clock baseline and its recorded elapsed progress. Its local arithmetic reduces to an unsigned elapsed high-water update. This is a conditional source contract: actual incoming phase `0x6e3`, frame/bank roots, concrete callees, request identity and native object epochs remain **unknown**. No acceptance, rejection, expiry decision or daemon-visible result follows from this update alone. [CA1-CA7]

The [preceding reader report](lskd_clock_reader_report.md) establishes the baseline-zero arm and first unsigned comparison. This increment lifts its formerly captured shared/greater continuations, adds the advancing continuation, and recovers the fresh-pointer release preparation and subsequent continuation record. [Original source, certificates and frozen IDA readback](triage_evidence/lskd_clock_accumulator_checks.json.zst), the [extractor](triage_evidence/recover_lskd_clock_accumulator.py) and [publication audit](triage_evidence/verify_lskd_clock_accumulator_publication.py) retain the evidence. The broad interface goal remains active.

```text
conditional reader, phase=6e3; C=zero_extend(fresh_clock32)
  OLD=0 --------> write encoded C to object+30 -----------+
  OLD!=0                                                |
     C<=OLD --------------------------------------------+--> common: increment=0
     C>OLD --> D=C-OLD                                   |
                   D<=E --------------------------------+
                   D>E --> increment=D-E ---------------> common: encoded add
                                                           |
                      fresh global/object/member reload <--+
                        -> release-shaped record/call [target unknown]
                        -> context operands + continuation record
                        -> helper call [target unknown]
                        -> signed record result -> table branch
```

Offsets and constants are hexadecimal unless marked otherwise. All edges depend on the source/epoch premises below; this is not an observed transaction.

## Primary source and exact control mapping

The original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; the normalized FairPlay image SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every retained instruction byte is compared between them. Four half-open spans contain 814 instructions / 3,256 B. Source lifting uses smaller component slices; whole-span capture does not mean every instruction was semantically lifted. Thirty-four UNSAT certificates cover 754 lifted instruction instances; two SAT controls are retained. [CA1,CA5]

| Source span | Conditional role |
| --- | --- |
| `0xfffffe000a5177e0..a5177f8` | Default encoded increment |
| `0xfffffe000a524054..a5246c4` | Shared accumulator store, fresh reload, release and continuation preparation |
| `0xfffffe000a5271b8..a52744c` | Fresh-minus-baseline and elapsed comparison |
| `0xfffffe000a534e34..a5351d0` | Advancing increment and return to shared store |

| Index | Original slot | Target | Diversity | Selected meaning |
| --- | --- | --- | --- | --- |
| `0x3de` | `0xfffffe000846e310` | `0xfffffe000a524054` | `0x4c8d` | Shared encoded addition |
| `0x7e6` | `0xfffffe0008470350` | `0xfffffe000a5271b8` | `0x4c8d` | Nonzero OLD, C>OLD |
| `0x876` | `0xfffffe00084707d0` | `0xfffffe000a534e34` | `0x4c8d` | Clock delta exceeds elapsed progress |

The first two original fixups are retained in the predecessor; the third is newly reparsed with chain membership, authentication and diversity checks. Table base is conditionally `0xfffffe000846c420`. The advancing suffix loads index `0x3de` before returning to the shared continuation. These are shared fragments, not asserted independent source functions. Hardware pointer authentication is not executed. [CA2,CA5]

## Compact arithmetic contract

All object/seed words below are u64; addition, subtraction and multiplication wrap modulo 2^64. C is a zero-extended u32. M=`0x7fffffffffffffff`, P is the selected object, and T is the selected seed pointer under flag=255.

| Symbol | Exact relation |
| --- | --- |
| V | `(u64[T+98] & M) XOR 23c7e4b4853b50c4` |
| W | `(u64[T+d8] & M) XOR 5629ca6fff2637b4` |
| J | `(u64[T+68] & M) XOR e95d80091182118a` |
| U | `u64[P] XOR V` |
| COMP | `u64[P+10] XOR J` |
| E | `u64(U + COMP + 1)` |
| OLD | `(u64[T+a0] & M) XOR u64[P+30] XOR 46ec7c7424bcc931` |

The default setup makes X8=W. For arbitrary incoming encoded Q, the entire shared store reduces to:

```text
u64[P] = u64(U + (Q XOR W)) XOR V
```

Its eight-byte store is at `0xfffffe000a5243d0`. Q=W gives an identity store of the original encoded word. The common arithmetic is proved as object/input XOR deltas, their sum and a final carry-network inverse; no assumption about concrete random/seed values is required. [CA2,CA4-CA5]

The greater arm computes D=`u64(C-OLD)` and compares it unsigned with E. D<=E selects `0x3de` with the default Q. D>E selects `0x876`. The advancing arm computes:

```text
increment = u64(C - OLD - E)
Q = increment XOR W
```

Its carry-aware biased comparison and final CSEL return this same Q for every u64 increment, including wrapping intermediates. Joining the source components with the common store gives:

```text
if OLD == 0:
    object30 = encode_clock(C)       # preceding report's exact source store
    increment = 0
elif unsigned(C) <= unsigned(OLD):
    increment = 0
else:
    D = C - OLD
    increment = (D > E) ? D - E : 0  # unsigned comparison
U_next = u64(U + increment)
object0_next = U_next XOR V
```

This pseudocode covers the selected local update, not its unknown outer caller or callee effects. The clock-read status/returned length are not newly validated: the preceding source has a prezeroed output and no local status/length gate before this partition. [CA3-CA7]

The initialization writer's separately retained source identity is:

```text
object10_initial = object0_initial XOR ((seed98 XOR seed68) & M)
                   XOR 35659b426b46beb1
COMP_initial = bitwise_NOT(U_initial)
BASE = U_initial
E = u64(U - BASE)
```

Under matched stable seeds, unchanged COMP and returning calls preserving the tracked state, the selected local rule is E_next=`max_unsigned(E,D)` on the C>OLD arm and E_next=E on the other arms. E starts at zero. Because C is u32 and the greater arm requires C>OLD, D fits u32 even when OLD is initially treated as arbitrary u64. Induction gives `0 <= E <= 0xffffffff` and nondecreasing E within that epoch. This bound concerns the recovered integer projection, not seconds or calibrated hardware time. A sample below/equal to OLD, including a truncated-clock wrap below a nonzero baseline, makes no local progress. [CA4-CA6]

U itself can wrap because BASE is arbitrary. A SAT control, with both elapsed and clock delta constrained to u32, supplies a model where elapsed increases and U decreases unsigned. It rejects attributing ordinary unsigned monotonicity to the decoded accumulator. E is the elapsed view; whole-system monotonicity still requires provider, epoch and call-preservation evidence.

## Fresh-pointer release preparation

After storing the accumulator, `0xfffffe000a5243d4..a52441c` reloads P from the declared global cell, reads `u64[P+8]` as the self pointer, reads the current encoded word through it, and freshly loads the embedded pointer from `P+18`. It also reloads seed qwords `+c0/+98` through the declared seed/flag cells. This fresh global read can select a different publication unless CA4 is established.

Let R=FP`-b0`. Source `0xfffffe000a52441c..a524460` writes:

```text
Krel32 = u32((low32(R) XOR dfb9786f) * 1e2776fd)
u32[R+0] = Krel32 + 1d3
u64[R+8] = freshly_loaded_embedded_pointer
```

This producer identity holds for all u64 R; it does not require the earlier acquisition producer's even-address premise. The record is compatible with the known explicit-pointer release selector `0x1d3`. Call `0xfffffe000a5244b8` supplies X0=R and discriminator `0x84cc`; its first/second bank pointers are saved at SP`+140/+138`, key `0x58`, additive `0x984`. Their reaching roots and the target are unknown. Neither the discriminator nor a compatible record establishes an actual `IORWLockUnlock` call or balanced ownership. [CA2-CA4,CA7]

## Context operands and continuation-record ABI

On a returning release-shaped call, `0xfffffe000a5244bc..a5244c8` forms `current_object0 XOR ((seed98 XOR seedc0)&M)`. The following lifted slice through `0xfffffe000a5245cc` constructs these operands:

| Operand | Exact u64 value |
| --- | --- |
| X24 | `current_decoded_U + 081864b3` |
| X26 | `u64[context_root+178] + ab53c9aef42360b8` |
| W11 | `unsigned(X24) < 081864b3` |
| W21 | `unsigned(X26) < 081864b3` |

The context root is loaded from SP`+1f8`; its upstream provenance is unknown. The remaining final predicate/result is not recovered, so no expiry/admission role is assigned to these operands. [CA2,CA4,CA7]

The source then reuses R for another helper record. Define K64=`u64((R XOR 4c2e944469e35e3f) * 7a59c441)` and k=low32(K64). Stores `0xfffffe000a52461c..a524654` cover exactly 36 B in a 40 B envelope:

| Offset from R (hex) | Width (B) | Source value |
| --- | ---: | --- |
| `00` | 8 | K64 |
| `08` | 4 | `u32(392d87ef - k)` |
| `0c` | 4 | `k XOR f6074dc1` |
| `10` | 4 | No write in this producer slice; later signed continuation result |
| `14` | 4 | `k XOR f6074dd4` |
| `18` | 4 | k |
| `1c` | 4 | `u32(f6074c82 - k)` |
| `20` | 8 | `u64(seed98 - K64)` |

Call `0xfffffe000a5246ac` supplies X0=R, discriminator `0x2971`, frame bank pointers SP`+188/+180`, key `0x2f`, additive `0x9fe`. Its target and record-result contract are unknown. On return, source `0xfffffe000a5246b0..a5246bc` performs:

```text
index64 = sign_extend_64(u32[R+10])
slot = u64(TABLE + (index64 << 3))
target = u64[slot]
BRAA target, discriminator=af5e   # at 0xfffffe000a5246c0
```

A SAT control for index `ffffffff` yields TABLE-8. This demonstrates why a callee range/initialization contract is necessary; it does not establish a reachable invalid index, attacker control or a native defect. The locally unwritten four bytes cannot be assumed zero or callee-initialized. No new Mach port, Mach-message emission or daemon-kext transaction is established by this private continuation interface. [CA3,CA7]

## IDA corroboration and evidence limits

Read-only MCP access spot-checked 64 B each at reader `0xfffffe000a517624` and advancing fragment `0xfffffe000a534e34` in the loaded FairPlayIOKit database. Both match the original KC exactly; the artifact freezes the returned bytes, database handle and capture time. Its replay checks this frozen readback against original bytes, not a new live IDA session. Function-info queries describe IDA's fragment boundaries; they do not establish compiler function boundaries or incoming frame provenance.

Two exact scoped IDA-memory queries, one in the kext database and one in fairplayd, returned zero matches without truncation. This says nothing about differently phrased prior notes. No IDB mutation or native target execution occurred. Attempts to join compatible upstream fragments did not establish the actual reader phase/bank roots; those remain explicit frontiers rather than inferred edges. [CA1-CA3,CA8]

## Assumption register

| ID | Assumption and dependent claims | Stress test / falsification probe |
| --- | --- | --- |
| CA1 | Original KC, normalized image and retained predecessor inputs identify this build. Source addresses and provenance depend on it. | Rehash both images, compare every retained byte and reparse original chained slots; preserve all three supplied inputs. |
| CA2 | Selected entry has phase 6e3, flag=255, stated table/seed/object/frame roots and valid extents. Conditional offsets/flow depend on it. | Recover reaching definitions through the actual incoming edge; test alternate phases/flags and mismatched roots rather than treating these premises as observed. |
| CA3 | Private calls return with the declared preserved registers/cells and valid result storage. Composed flow and continuation consumption depend on it. | Resolve actual byte-bank roots/callees and their effects, including initialization/range of R+10 and clock output/status/length. |
| CA4 | Initialization, read, update and fresh reload use matched object/self/seed epochs, with stable COMP and nonaliasing storage. Elapsed interpretation/induction depend on it. | Match publications, intervening calls/writes and concurrent ownership; a different global/self pointer breaks the join. |
| CA5 | Decoded A64 scalar widths, loads, CSEL/carry tests and fixed-cell model match source semantics. Identities depend on it. | Re-lift component slices, replay all 34 queries and both SAT controls; compare retained bytes and exact store footprint. This is not unrestricted alias analysis. |
| CA6 | E starts from the proved initializer relation and calls preserve the tracked elapsed state. u32 bound and repeated nondecrease depend on it. | Replay both writer certificates and the induction queries; inject changed COMP/seeds or an unmatched initial object to falsify the epoch premise. |
| CA7 | Outer result, admission, ownership and IPC require additional joins; none is assumed. Attribution stops at local source contracts. | Resolve both helper targets, final context predicate, record result, outer handler and actual fairplayd request/reply identity. |
| CA8 | Frozen readback and scoped recall have exactly their recorded extent. IDA corroboration depends on it. | Repeat live byte reads and broader memory queries when needed; do not equate two zero-match searches with a complete memory inventory. |

## Bounded continuation

| Impact | Question | Required evidence |
| --- | --- | --- |
| High | Which daemon/kext operation reaches this high-water update? | Actual incoming phase/frame/global/seed producers and an outer handler/request lineage. |
| High | Who initializes and bounds the signed continuation result? | Resolve the 2971 helper bank and exact writes to R+10, including every returning path. |
| High | What does the context comparison decide? | Complete the final predicate, helper result and consumers before assigning expiry/admission semantics. |
| Medium | Can fresh reload observe another publication or seed epoch? | Global/self-pointer stores, lock target/ownership and intervening call effects; record compatibility alone is insufficient. |
| Medium | What physical time behavior reaches this integer projection? | Matched provider selection, successful output and native samples near zero/wrap; the local u32 bound does not establish calibration. |

## Reproduction and scoped quality gates

Run `recover_lskd_clock_accumulator.py --verify` with `triage_evidence`, Z3 and the existing source dependencies on the Python module path. It re-extracts original/normalized bytes, checks the advancing fixup, replays source component proofs/controls and validates frozen IDA bytes. The publication audit replays predecessor reader, initialization and release-selector certificates, preserves original input hashes, checks the exact manifest delta and scans raw/decompressed owned content for analyst paths. Substantial JSON is published as a verified Zstandard archive.

Extraction costs O(B+I) time/space plus original chain decoding, with B retained bytes and I decoded instructions. Scalar expression construction costs O(I); solver complexity is separate with a 10 s limit per query. Arithmetic is exact at u32/u64 widths; offsets/extents use bytes. Native clock units, calibration/error bounds and latency are unknown.

- **QG1** passes for factual source/interface analysis.
- **QG2** passes with CA1-CA8, dependent claims and falsification probes.
- **QG3** passes for this increment's conditional elapsed update, record layouts, source edges and scoped IDA corroboration; the broad goal remains active.
- **QG4** passes with explicit modular widths, u32 elapsed bound, byte footprints and no invented physical units.
- **QG5** passes with conditional roots/phase, epoch/call preservation, u64 wrap, unwritten result bytes and unresolved callees explicit.
- **QG6** passes with original bytes/fixups, pinned dependencies, replayed certificates, frozen IDA bytes and preserved supplied inputs.
- **QG7** passes with impact-ranked request, result-range, context-predicate, publication-epoch and provider questions.
