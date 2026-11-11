# Operation 1/5 byte spans, short copy and prefix/suffix transfer

The operation 1/5 threshold test selects two implementations. Below 32 bytes for original W1=1, or below 16 bytes for W1=5, the short arm prepares the entire low32 original-X4 count for copying and preloads the established re-encoding continuation. After the bounded copy helper publishes private zero, that continuation gives a conditional zero outer result. The earlier [preflight report](lskd_operation_preflight_report.md) called this test an admission requirement; that wording is corrected here. The source accepts a short-copy route under the stated frame/return premises. [BS1-BS8]

At or above those thresholds, the other arm prepares a prefix of 16 bytes for W1=1 or zero bytes for W1=5, an aligned middle span, and a suffix of 0-15 bytes. Original X2 is the source and original X3 is the destination for the explicit byte-copy passes. Original X4 is truncated to u32 and supplies their byte-span count. The middle-span frontier receives adjusted pointers and an aligned byte count; its complete operation remains **unknown**. [BS2-BS8]

[Evidence](triage_evidence/lskd_byte_spans_checks.json.zst), [extractor](triage_evidence/recover_lskd_byte_spans.py) and [publication audit](triage_evidence/verify_lskd_byte_spans_publication.py) retain exact source cuts, original chained fixups and solver obligations. The increment retains 24 spans / 545 instructions / 2,180 B and 30 original chained slots, including 25 actually loaded slots. Its 156 UNSAT obligations cover 32 source pieces / 11,351 lifted instruction instances; one wrong-direction control is SAT. The copy matrix covers lengths 0 through 31 in both source-selected directions with one alias-aware byte memory. It proves per-pass snapshot copying; it does not prove a complete operation's overlap contract or native buffer validity. No new target execution, IDA lookup, IDB mutation, provider call or Mach-port emission occurs.

```text
N = low32(original X4), H = (original W1 == 1 ? 16 : 0)
source = original X2; destination = original X3

N < H+16:
  small arm A51A934 -> shared builder A55B624
  -> copy N bytes -> private zero -> saved A527B24 re-encoding route
  -> conditional outer zero [normal guard/PAC, release and D=0 premises]

N >= H+16:
  block-split arm A57F8E8 -> shared builder A55B624
  -> copy H prefix bytes
  -> A55DB14 -> copy R=N mod16 suffix bytes at offset F=N-R
  -> A535784 -> A518008: middle span [H,F), length B=F-H
  -> A5722B8 [further operation effects open]
```

All byte counts are decimal; address suffixes are hexadecimal. Control-flow and memory claims apply to the matched named-wrapper source template, not an observed daemon transaction.

## Assumption register and primary provenance

| ID | Assumption / bound | Dependent claims | Stress test / falsification probe |
| --- | --- | --- | --- |
| BS1 | Original KC and normalized image identify the pinned build | Code, literals, table entries and source addresses | Rehash every span and original fixup; compare the actual native image separately |
| BS2 | Preflight succeeds and the named-wrapper phase, outer record/key and original W1/X2/X3/X4 inputs match the recovered template | Short/full split, argument identities and phase joins | Replay preflight and reader-lineage certificates; bind actual reaching caller/frame epochs |
| BS3 | Source scalar, modular arithmetic, conditions, variable shifts and byte-memory semantics describe the retained instructions | Count partition, offset decoders and copy certificates | Recompute fail-closed lifts; replay source queries, exact read/write orders and the wrong-direction SAT control |
| BS4 | Borrowed byte ranges are accessible with nonwrapping endpoints and separate from the live frame/control storage | Per-pass snapshot-copy result | Verify actual backing, bounds and frame aliases; the array model permits source/destination overlap but does not establish native validity |
| BS5 | Original table/continuation roots and working context retain their identities | Dispatch, context+134 address and later re-encoding selection | Verify original chained entries and reaching roots; source addresses do not prove native authentication or lifetime |
| BS6 | Earlier preflight calls return with required frame state preserved; short-arm scratch reads are valid even where their producers remain unknown | Composition through the builder | Trace reaching stores and aliases; retain arbitrary scratch contents instead of replacing them with zero |
| BS7 | Prior normal guard/PAC, cached RW release and zero outer displacement D premises apply | Short-copy zero reaching outer W0 | Replay the conditional return certificate; prove actual cursor preservation and release ownership separately |
| BS8 | Each copy uses its own entry snapshot; complete operation semantics and native transport remain outside these cuts | Interpretation and completeness limits | Check cross-pass aliases, middle-span consumers, concurrent buffer users and actual daemon/IOKit serialization |

Original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized image SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every retained span matches both. Supplied C excerpts 28791-28800, 79137-79193 and 109621-109695 corroborate the short arm, shared builder and full-split arm; they omit substantial register/memory semantics visible in the original instructions. The original three supplied inputs remain unchanged. [BS1,BS3]

## Threshold correction and exact byte partition

Let N=`low32(original X4)`, H=16 for original W1=1 and H=0 for W1=5, R=`N & 15`, F=`N & 0xfffffff0`, and B=`F-H`. On the full-split arm, N>=H+16. Therefore B>=16, B is divisible by 16, F<=N and the disjoint half-open index ranges `[0,H)`, `[H,F)`, `[F,N)` cover `[0,N)`. These are arithmetic index ranges; native access to them remains a separate premise. [BS2-BS4]

| Source arm | Original W1 | N condition | First copy count | Next saved continuation |
| --- | ---: | --- | ---: | --- |
| Short | 1 | N<32 | N bytes | `TABLE[11b] -> a527b24`, re-encoding |
| Short | 5 | N<16 | N bytes | Same |
| Full split | 1 | N>=32 | H=16 bytes | `TABLE[11e] -> a55db14`, suffix preparation |
| Full split | 5 | N>=16 | H=0 bytes | Same |

Both arms select `TABLE[0x262] -> 0xfffffe000a55b624`, diversity `0x2ba3`. A shared builder does not imply the same subsequent continuation: it preserves the arm selector until source `a52dfcc` preloads the next target from index `0x11b` or `0x11e`. The threshold itself is not a rejection test. [BS1-BS3,BS5]

Source `a57f8f0..a57f93c` writes these full-arm frame cells:

| Body SP offset | Width | Value | Meaning within this source phase |
| --- | ---: | --- | --- |
| `+24` | 4 B | H+R | Bytes outside the aligned middle span |
| `+74` | 4 B | B=N-H-R | Middle-span byte count |
| `+98` | 8 B | zero_extend32(F) | Suffix offset |
| `+18` | 8 B | zero_extend32(H) | Prefix/middle boundary |

The short arm writes none of those four cells. Their reaching contents remain arbitrary valid scratch inputs to the builder; they must not be initialized from the full-arm formulas when proving the short path. Its X9 payload independently encodes N and its saved continuation returns after that first copy. [BS3,BS6]

## Builder, pointer roots and suffix offset decoders

The builder loads original outer record `+0x10`, which the named wrapper filled from original X3. It combines this with original X2 saved at SP`+0x1e8`. Its final handoff restores X14=source and X15=destination, saves original X3 at SP`+0x1b8`, and restores phase through the selected `a52e530 -> a5237d8 -> a52dfc4` chain. [BS2-BS3,BS5]

For the full arm it constructs suffix metadata:

| Frame cell | Encoded value, modulo 2^64 | Decoded use |
| --- | --- | --- |
| SP`+170` | `0x4360c2459cc8eba4 + F` | Source displacement F after additive cancellation |
| SP`+178` | `0x7ed6766d7e6951b1 + F` | Destination displacement F after additive cancellation |
| SP`+168` | `C + R - ((2*R) & 0x2f6e8e66)` | Suffix copy count R |

Here C=`0xc9e6da8e97b74733`; count decoding is `low32(encoded) XOR low32(C)`. The count relation is proved for every u32 input, while the suffix uses R in 0..15. At `a52dfc4`, the two pointer masks cancel to zero for the first pass and to F for the suffix pass. This makes the unsigned direction comparison apply to the effective source and destination addresses. [BS3-BS5]

The builder also saves context`+0x134` at SP`+0x90`. This is an address publication, not a write to that context byte. Other scratch cells retain earlier phase values; recovering their producers is still necessary for complete operation reconstruction. [BS3,BS5-BS6]

## Byte-copy direction, overlap and finite completeness

The dispatch chooses backward copying when effective source <= effective destination and forward copying when source > destination. The backward implementation has a one-byte remainder loop and a six-byte unrolled loop; the forward implementation has a two-byte loop and an optional last byte. For each tested length L, both perform exactly L byte loads and L byte stores, with these exact offsets:

| Direction | Source/destination offset order |
| --- | --- |
| Backward | L-1, L-2, ..., 0 |
| Forward | 0, 1, ..., L-1 |

The evidence lifts source instructions with one symbolic byte-addressed array, allowing source/destination aliases. Each source read is relationally normalized to the pass-entry array. Two general array read-over-write lemmas justify that substitution after a separate ordering obligation proves every required inequality against earlier writes from direction and nonwrapping endpoint premises. Exact source read/store value pairing is checked. This is a decomposed proof, not a single monolithic array-execution query. A separate byte-identity obligation then establishes `destination_after[j] = source_at_pass_entry[j]` for every j in 0..L-1. Destination write offsets cover exactly that range; no extra borrowed-buffer write is introduced. Fixed frame/control accesses have their own validity/separation premise. [BS3-BS4]

The length set 0..31 completely covers short-arm counts, the full-arm prefix count and every suffix remainder. It is not a proof for arbitrary unbounded L. An arbitrary common byte displacement is retained in the copy model, supporting the suffix-offset instantiation as well as the zero-offset first pass. The SAT control applies the backward helper with the opposite ordering and exhibits changed snapshot-copy behavior; it establishes why the direction premise matters, not a native target state. [BS3-BS4,BS8]

Every copied/zero-length pass reaches `0xfffffe000a545d44`, whose source publishes private status `0x06371ecc`. The short arm's preloaded target is `a527b24`; the established re-encoding/release/result path then adds `0xf9c8e134`, yielding outer u32 zero under BS7. Thus the short source route copies N bytes unchanged and returns conditional numeric zero. The operation's public name and externally documented contract remain unknown. [BS2-BS7]

Per-pass snapshot copying does not establish a whole request's overlap behavior. A prefix write can affect a region consumed by a later suffix or middle pass. The source may impose additional caller constraints or ordering invariants; those have not been proved here. [BS4,BS8]

## Middle-span frontier and pointer high-bit handling

After the full arm's prefix and suffix passes, the builder's middle count is divisible by 16 and nonzero. Its saved private status is zero-basis `0x06371ecc`; the post-suffix gate selects index `0x963 -> 0xfffffe000a518008`. That frontier initializes SP`+0x6c` to zero, publishes the prepared destination/source pointers at SP`+0xd8` / SP`+0xe0`, passes B in W0 and context`+0x134` in X14, and selects `TABLE[0x4a6] -> 0xfffffe000a5722b8`. No complete middle-span transform or provider transaction is inferred from this handoff. [BS2-BS6,BS8]

The pointer preparations add H to original X2/X3. If that addition changes any bit selected by mask `0xffc0000000000000`, source replaces the resulting pointer's high 16 bits with `0xc8a2`; otherwise it keeps the computed pointer. The mask test and high16 replacement are source contracts. The native pointer-tag, address-validity and authentication interpretation remains unknown. The copy certificates' valid effective byte ranges do not certify these prepared pointers for later middle-span access. [BS3-BS5,BS8]

## Reproduction, bounded follow-up and quality gates

The extractor's `--verify` regenerates the source certificates and compares exact evidence. The publication audit replays new source obligations and the frozen preflight/return certificates, checks original bytes and fixups, checks case coverage and byte orders, preserves all supplied inputs, and checks the exact manifest delta and path scrub. The audit rechecks 156 new and 67 prior UNSAT obligations, one new and three prior SAT controls, all 64 length/direction cases, and 992 byte loads plus 992 byte stores. Counts are recorded in the evidence's `verified_counts`; native execution and IDB state are untouched.

Extraction/expression work uses O(Nsource+I+M) time and space for consumed source/index bytes Nsource, lifted instruction instances I and retained memory events M. Solver complexity is separate. Each copied pass uses O(L) target time and O(1) auxiliary target storage; its symbolic proof retains O(L^2) earlier-write/read inequalities. Byte counts, field widths and offsets are explicit, with modular32 count arithmetic and modular64 pointer arithmetic. Comparisons for count/direction are unsigned at the recovered source tests.

| Impact | Bounded follow-up | Discriminating evidence |
| --- | --- | --- |
| High | Recover the middle-span operation | Extend `a5722b8` through actual record/provider calls and bind source/destination/count consumers |
| High | Establish whole-operation overlap constraints | Join prefix, suffix and middle accesses across a single input snapshot and actual caller alias constraints |
| High | Match these buffers to daemon/IOKit arguments | Trace the actual named-wrapper caller, serialization and returned status under the pinned image |
| Medium | Recover short-arm scratch producers | Resolve valid reaching values at SP18/24/74/98 and the auxiliary frame cells, without importing full-arm formulas |
| Medium | Resolve native pointer high-bit handling | Match address/tag conventions and authentication state to the source replacement branch |
| Medium | Establish actual return and lock epochs | Prove D=0, guard/PAC success and cached RW ownership for the matched operation |
| Low | Census helper aliases | Compare original slot-specific diversities before merging same-target roles |

**QG1**: No normative claim is required. **QG2**: BS1-BS8 state assumptions, dependent claims and falsification probes. **QG3**: The increment covers threshold correction, short-copy return, full byte partition, source/destination identity, prefix/suffix copy and the middle-span frontier; complete operation/transport recovery remains open. **QG4**: Byte units, widths, truncation, nonwrapping ranges, modular arithmetic and bounded algorithm costs are explicit. **QG5**: Short/full scratch phases, per-pass versus whole-operation snapshots, native validity and conditional outer return remain distinct. **QG6**: Original bytes/fixups, supplied C, dependency hashes and replayable source certificates provide primary provenance. **QG7**: Impact-ranked follow-up bounds remaining data-flow, control-flow, environmental and architectural interfaces.

The [middle-span hardware-staging analysis](lskd_hardware_staging_report.md) now follows A5722B8 through a 16-byte P+134 context window, working IV staging, 81920-byte capped copy chunks and `performHWAESOnBuffer`. Its nominal typed provider ABI receives key-data pointer P+184, IV at bodySP+270, numeric operation 1 and the saved total middle count; copy calls instead receive the current chunk count. The loop and conditional outer 0/-22 status paths are certified. Native descriptor bounds, provider effects, whole-operation overlap and daemon request lineage remain open.
