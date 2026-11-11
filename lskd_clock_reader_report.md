# SecureTime stored-clock reader and conditional comparison contract

The original instructions at `0xfffffe000a517624` contain a clock reader whose selected phase decodes the exact `+0x30` relation written by [SecureTime initialization](lskd_clock_completion_report.md). A zero decoded value selects a source arm that writes the fresh four-byte sample using the same relation. A nonzero value selects a comparison whose complete unsigned predicate is `fresh_clock > decoded_stored_clock`. Its opposite selects a shared object-processing continuation. Neither destination is established as acceptance, rejection or an externally visible result. The actual incoming phase, reader frame roots, helper-bank bindings and request lineage remain **unknown**. [CR1-CR7]

This is a conditional local contract, not a recovered complete request path. Phase `0x6e3` is derived as the unique input compatible with the previously established acquisition-record selector `0x2d2`, for this producer and an even record address. The selected table base and flag=255 remain explicit premises. The report does not infer that the first indirect call actually reaches that acquisition adapter merely from its record form or authentication discriminator. [CR2-CR4]

[Original source and certificates](triage_evidence/lskd_clock_reader_checks.json.zst), the [extractor](triage_evidence/recover_lskd_clock_reader.py) and the [publication audit](triage_evidence/verify_lskd_clock_reader_publication.py) retain five spans / 840 instructions / 3,360 B, sixteen operand anchors and five original authenticated continuation slots. Fifteen UNSAT queries cover 220 lifted instruction instances; two SAT controls reject an unrestricted-address codec and a reversed comparison. Two follow-on spans are captured without a complete semantic lift. No target, native clock, allocator, lock or IDA execution occurred.

```text
conditional entry: phase=6e3, table/root/flag/extent premises
  -> record R=FP-b0: embedded pointer + encoded phase
  -> first indirect helper [bank roots and target unknown]
  -> prezero u32 output; request kern.monotonicclock, length64=4
  -> second indirect helper [bank roots and target unknown]
  -> reload output; decode OLD from object+30
       OLD=0: 180 -> A517898 -> rewrite object+30 -> 3de
       OLD!=0: 1f5 -> A521AA8
                         FRESH>OLD: 7e6 -> A5271B8
                         FRESH<=OLD: 3de -> A524054
  -> later object processing / result / unlock / IPC remain open
```

Addresses and offsets in this diagram are hexadecimal. Its edges are source relationships under CR2-CR6, not an observed transaction.

## Primary provenance and supplied-reference census

The original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; the normalized FairPlay image SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every captured instruction byte is compared between them. Original chained-format-8 slots, their chain membership, target, authentication flag and diversity are checked separately. No hardware pointer authentication is exercised. The three original supplied inputs are preserved. [CR1]

The supplied C at lines 25528-25659 exposes the lock-member read, name construction and stored-relation branch. It does not fully express the fresh-output arithmetic and live register handoff visible in the original instructions. The original source therefore supplies the additional evidence needed for the conditional formulas below. These are shared continuation fragments, not newly asserted compiler-bounded source functions.

An exact census of `strcpy(...,"kern.monotonicclock")` in the supplied C finds ten occurrences. The artifact retains the enclosing supplied heading, line numbers and nearby text for each. This census excludes computed names and other representations; it is not a complete KC call census. Only the initialization site and the selected reader receive the semantic attribution stated here. [CR1,CR8]

| Supplied routine heading address | Literal-copy line | Attribution in this report |
| --- | ---: | --- |
| `0xfffffe000a511804` | 20906 | Previously recovered initialization query |
| `0xfffffe000a517624` | 25635 | Selected conditional reader |
| `0xfffffe000a525f4c` | 39002 | Additional literal query site; full role unknown |
| `0xfffffe000a532528` | 50127 | Additional literal query site; full role unknown |
| `0xfffffe000a533864` | 51475 | Additional literal query site; full role unknown |
| `0xfffffe000a534418` | 52523 | Additional literal query site; full role unknown |
| `0xfffffe000a54e6d8` | 71710 | Additional literal query site; full role unknown |
| `0xfffffe000a554140` | 75939 | Additional literal query site; full role unknown |
| `0xfffffe000a575fb0` | 99740 | Additional literal query site; full role unknown |
| `0xfffffe000a5bf640` | 149759 | Additional literal query site; full role unknown |

## Phase, record layout and unresolved helper bindings

Let S be incoming W12 and R=FP`-0xb0`. The source freshly reads `u64[incoming_X9+0x18]`, writes that pointer to R`+0` and writes an encoded u32 selector to R`+8`. For even R, its exact relation is:

```text
K32(R) = u32((low32(R) XOR 0x1D65DAD0) * 0xE9655F4D)
R.u64[0] = freshly_loaded_embedded_pointer
R.u32[8] = K32(R) + u32(S - 0x411)
decoded_record_phase = u32(S - 0x411)
decoded_record_phase == 0x2D2  iff  S == 0x6E3
```

The first identity is lifted over arbitrary S, FP and pointer values under `(R & 1)==0`. A separate u32 identity proves the equivalence. The producer's address mixer discards bit zero: removing the alignment premise admits a checked odd-address counterexample. This condition belongs to this producer; it does not alter the earlier adapter decoder's all-address identity. The minimum accessed record footprint is twelve bytes; no size or initialization claim is made for its gaps. [CR3-CR5]

At the compatible S, source-derived W25=`0x180`, saved u32 SP`+0x1b8`=`0x3de` and W23=`0x3de`. The call at `0xfffffe000a517710` supplies X0=R and discriminator `0x560f`. Its bank uses frame pointers at SP`+0x130/+0x128`, key `0x27`, additive `0x94d`. The later named query call at `0xfffffe000a5177d0` uses frame banks at SP`+0x100/+0x108`, key `0x20`, additive `0x9a7`, discriminator `0x6e7d`. The actual reaching values of these bank roots are unknown. No exhaustive bank or concrete helper binding is claimed for either call. [CR2-CR4]

The record phase/key and first discriminator are consistent with the established acquisition interface, but consistency does not establish the target. Likewise, the query name and five arguments identify a sysctl-shaped read interface; a concrete `_kernel_sysctlbyname` binding still requires the bank roots. The previously recovered initialization query has its own established bank/import chain. It cannot substitute for this missing join.

## Fresh sample, stored relation and zero-value update

The reader prezeroes u32 SP`+0x20c`, writes 4 to u64 SP`+0x200`, and constructs the name in a 21 B region at FP`-0xf5`. It supplies:

| Register | Source value |
| --- | --- |
| X0 | FP`-0xf5`, the name |
| X1 | SP`+0x20c`, four-byte output |
| X2 | SP`+0x200`, initially-four u64 length |
| X3 | 0, new pointer |
| X4 | 0, new length |

After the returning call, the source clears the first twenty name bytes; the final extra zero was already written. It reloads the four-byte output into W11. It does not read incoming X0/W0 before overwriting X0 at `0xfffffe000a517834`, or explicitly reload the returned length before its first clock partition. Actual output writes, status and call preservation remain CR4 premises. A zero output can represent an unchanged prezeroed cell; it does not prove successful clock access. [CR4,CR6]

Under flag=255 and the declared frame roots, the seed accesses select these qwords:

| Byte offset from seed pointer | u32 indices | Selected role |
| --- | --- | --- |
| `+0xd8` = 216 B | 54, 55 | Pre-query saved seed; staged in a live value for later processing |
| `+0x10` = 16 B | 4, 5 | Fresh-clock fold |
| `+0xa0` = 160 B | 40, 41 | Stored-clock decoding and zero-arm rewrite |

Let A=`u64[T+0xa0]`, B=`u64[T+0x10]`, F=`u64[P+0x30]`, M=`0x7fffffffffffffff`, and C the zero-extended fresh u32 output. Original instructions reduce to:

```text
FOLD = (B & M) XOR 0x5E129968B0F85B1F
X0 = FOLD
X13 = FOLD XOR C
OLD = (A & M) XOR F XOR 0x46EC7C7424BCC931
first_index = (OLD == 0) ? 0x180 : 0x1F5
```

All seed qwords and F are otherwise arbitrary. The source uses a sign-extended flag for the `+0xa0` mask and unsigned flag for `+0x10`; flag=255 makes the stated offsets exact. This is not an arbitrary-flag theorem. [CR2,CR5]

The preceding initialization writer proves F=`(A & M) XOR 0x46ec7c7424bcc931 XOR zero_extend_u64(INITIAL32)`. Substitution therefore yields OLD=`zero_extend_u64(INITIAL32)` for every seed qword and initial u32 value. Joining the two source formulas requires matched object/seed epochs; it does not establish actual source reachability between them. A mutated or differently encoded F need not decode to a u32 value. [CR6]

On the zero arm at `0xfffffe000a517898`, the complete selected field slice writes:

```text
u64[P+0x30] = (A & M) XOR 0x46EC7C7424BCC931 XOR C
next_index = 0x3DE
```

The eight-byte store is at `0xfffffe000a5178dc`. Its exact relation matches initialization's field encoding. Thus this local arm replaces a decoded zero with the fresh sample under the stated premises. It does not itself validate that the sample was produced successfully or return an external result.

## Nonzero comparison and exact continuation mapping

The nonzero arm `0xfffffe000a521aa8` constructs two biased u64 operands. Original-source identities prove:

```text
LHS = u64(C + 0x5BD8BE02)
RHS = u64(OLD + 0x5BD8BE02)
next_index = unsigned(C) > unsigned(OLD) ? 0x7E6 : 0x3DE
```

The complete original comparison suffix uses the two carry-under-bias tests and an unsigned comparison, then CSEL. Its certificate holds for every u32 fresh sample and arbitrary u64 OLD, including wrapped RHS values. It does not reduce to comparing the two wrapped operands directly. Two source operand identities compose with the normalized suffix; this avoids repeated mixed-Boolean arithmetic expressions without omitting an instruction from the compared suffix. An initial direct composed query timed out at 10 s and is excluded, as is the initial direct composed phase-equivalence query; the replacement certificates prove the same claims. [CR5]

| Selected index | Original slot | Original target | Diversity | Conditional role |
| --- | --- | --- | --- | --- |
| `0x737` | `0xfffffe000846fdd8` | `0xfffffe000a517624` | `0x30e7` | Reader entry pointer; upstream edge unknown |
| `0x180` | `0xfffffe000846d020` | `0xfffffe000a517898` | `0xb39c` | Decoded stored value zero |
| `0x1f5` | `0xfffffe000846d3c8` | `0xfffffe000a521aa8` | `0xb39c` | Decoded stored value nonzero |
| `0x3de` | `0xfffffe000846e310` | `0xfffffe000a524054` | `0x4c8d` | After zero-arm rewrite, or nonzero OLD with C<=OLD |
| `0x7e6` | `0xfffffe0008470350` | `0xfffffe000a5271b8` | `0x4c8d` | Nonzero OLD with C>OLD |

Slots use the conditional table base `0xfffffe000846c420`. Original fixups corroborate each target/diversity. The evidence retains both follow-on blocks through their next indirect transfers; their full transformations and later results are not semantically established here. In particular, C<=OLD is not demonstrated to reject a request, and C>OLD is not demonstrated to accept one. Lock release, update of other object fields, serialization, outer transport and Mach-message emission remain open. No newly established Mach port or emission point follows from these local clock calls. [CR2,CR4,CR7]

## Assumption register

| ID | Assumption and dependent results | Stress test or falsification probe |
| --- | --- | --- |
| CR1 | Pinned original KC, normalized image and supplied C identify this build. All addresses/census/provenance depend on it. | Rehash, compare every captured byte, reparse five original chained slots and preserve supplied input hashes. |
| CR2 | Actual entry has the stated table base, flag=255 and declared seed/object/frame roots. Offsets, slots and conditional reader interpretation depend on it. | Recover reaching producers and actual values, including SP+198/+1a0 and X13/X9; do not infer them from similar start frames or a compatible phase. |
| CR3 | This producer's record address is even, and its intended selector is the previously established acquisition phase. Phase 6e3 attribution depends on it. | Re-lift arbitrary-S producer, compose decoder identity, replay odd-address SAT control, and recover the actual source-produced phase and target. |
| CR4 | Calls return with the declared ABI-preserved roots and valid output/record extents. Fresh sample and composed local flow depend on it. | Resolve both byte banks, inspect full callees/call effects and check actual output/status/length epochs. Neither helper binding is recovered here. |
| CR5 | Scalar A64 widths, SXTW, signed indexed loads, CSET/CSEL and modular arithmetic follow the decoded source semantics. Exact formulas depend on it. | Check all operand anchors, re-lift selected slices, re-solve fifteen queries and reject the reversed-predicate control; distinguish captured from lifted code. |
| CR6 | Initialization and reader use the same stable object/seed/publication epoch with valid nonaliasing storage. Writer-reader and initial-u32 joins depend on it. | Replay the original writer certificate, match reaching stores/loads and competing publications, and test unmatched epochs separately. Arbitrary field64 remains allowed in the comparison proof. |
| CR7 | Later processing must establish admission, ownership and externally visible results. No such join is assumed here. | Recover both follow-on blocks, release/result consumers, outer caller and actual daemon-kext request identity before assigning an accept/reject meaning. |
| CR8 | The exact literal-copy pattern defines this supplied-C census. The count ten depends on this scope. | Re-run against unchanged C and inspect computed names, other copy forms and whole KC callers separately; do not equate ten sites with ten independent source-level routines. |

## Bounded continuation

| Impact | Question | Evidence required |
| --- | --- | --- |
| High | Which request actually reaches this phase and frame? | Reaching definitions of W12, X28, X9/X13 and all bank/seed cells; an outer handler/daemon lineage. |
| High | What do C>OLD and C<=OLD ultimately do? | Full semantics of A5271B8/A524054, object updates, unlock and result serialization; the first branch is insufficient to classify admission. |
| High | Can partial initialization reach this reader? | Nonnull object/embedded-pointer gates, allocator/constructor outcomes and stable publication epochs, including zero or unavailable clock output. |
| Medium | How do four-byte truncation and nonincreasing samples interact with later state? | Matched provider selection and samples near zero/wrap plus the complete follow-on state updates. The nominal provider discards high tick bits; a native monotonic guarantee is unestablished. |
| Medium | Are the other eight newly inventoried literal sites related variants? | Their frame/phase/bank contracts and exact field consumers; shared strings alone do not establish roles. |

## Reproduction and scoped quality gates

Run `recover_lskd_clock_reader.py --verify` with `triage_evidence` and Z3 available on the Python module path. It re-extracts original/normalized source, checks slots and operands, reruns the exact supplied-C census and re-solves all certificates/controls. The publication audit additionally rechecks the retained writer/adapter queries, the exact manifest delta and all raw/decompressed owned content for analyst-machine paths. Substantial JSON is published only as a verified Zstandard archive.

Extraction/census costs O(B+I+L) time/space plus original chain decoding, for captured bytes B, instructions I and supplied-C length L. Scalar expression construction costs O(I); SMT complexity is separate with a 10 s per-query limit. This extractor does not evaluate a byte bank, despite retaining their source operands. Arithmetic is exact at explicit u32/u64 widths; offsets and extents are bytes. Physical clock units, native latency and error bounds are unknown.

- **QG1** passes for factual source/interface analysis.
- **QG2** passes with CR1-CR8, dependent results and falsification probes.
- **QG3** passes for this report's conditional field reader, zero-arm write, unsigned comparison, five slots and ten-site census. The broad goal remains active.
- **QG4** passes with explicit widths, byte extents, seed indices and wrap-aware comparison; no physical measurement is invented.
- **QG5** passes with alignment, conditional roots/phase, unbound helpers, arbitrary field64 and captured-only follow-ons explicit. Timed-out direct queries are excluded.
- **QG6** passes with original bytes/fixups, supplied C, dependency hashes, checked certificates and retained predecessor rechecks.
- **QG7** passes with impact-ranked request lineage, full result, partial-object and clock-boundary questions.

The [elapsed high-water and continuation-record report](lskd_clock_accumulator_report.md) reduces the selected reader to a conditional unsigned elapsed high-water update. Thirty-four UNSAT certificates cover 754 lifted instruction instances; two SAT controls distinguish decoded-accumulator wrap from elapsed nondecrease and expose the missing signed-result range contract. Fresh embedded-pointer release preparation and a 40 B continuation envelope with 36 B locally written are recovered. Actual phase/frame roots, concrete helper targets, final context predicate, native epoch and daemon-kext lineage remain unknown.

The [context-comparison report](lskd_context_compare_report.md) corrects the continuation operand to the carry-flag XOR, recovers the complete comparison-record leaf and conditionally proves the final local gate: decoded accumulator < normalized context value and saved control low byte = 1. Twenty-two UNSAT certificates and two SAT controls cover the corrected handoff and carry-aware predicate. A 256-slot census retains three matching-diversity helper candidates; actual bank roots, saved phase, context/control producers and daemon-kext lineage remain unknown.
