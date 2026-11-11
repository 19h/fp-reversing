# CoreFP1201 signed shift and encoded-integer queries

Routine 0x5a600c dispatches a signed bit shift on an encoded-limb descriptor. Its positive route calls 0x5a6774; its nonpositive route calls 0x4be1cc. Complete private returns, independent instruction replay and integer oracles establish left shifts and magnitude right shifts on the retained canonical inputs, with signed count metadata preserved. The two dependencies 0x624ff0 and 0x5dcd08 classify sign and test zero. Universal source obligations establish the dispatch partition and amount encodings; the complete arbitrary-size algorithm is not universally proved.

In eight continued caller cases, the original scalar-one initializer is followed through the complete shift. A one-limb controlled context produces 2^32 in the first temporary; the zero-count control leaves scalar 1. All eight cases then stop before call 0x14f94c4 -> 0x649430. Complete arithmetic-child return, successful protected processing and native daemon/kext lineage remain unknown. The broader investigation remains active.

## Source and evidence

Addresses use reference CoreFP arm64e preferred base 0, SHA-256 `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; universal SHA-256 `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`. Five fresh read-only IDA spans equal both IDA original bytes and matching reference-file bytes:

| Recovered role | Compiler-bounded interval | Size | SHA-256 |
| --- | --- | --- | --- |
| Signed-shift dispatcher | 0x5a600c..0x5a6514 | 1288 B | `9b0ee7feb7754e64c5f466d1feffea6bbc9ea09ab01a53b495616074186c7000` |
| Left-shift path | 0x5a6774..0x5a6e6c | 1784 B | `cfaacf2d67fc5e4f2b2481576de05782da8b128499a7280e5fc58d70522e58ec` |
| Right-shift path | 0x4be1cc..0x4be7a8 | 1500 B | `914e642cc8d11350f59596c1b932292ffbcbe16abc8a5d788e0396d788ff38c0` |
| Sign query | 0x624ff0..0x625294 | 676 B | `1857d98bb07b4a7c16e556671c3bdf690816481260281597563a3e2d63a5c9a5` |
| Zero query | 0x5dcd08..0x5dcecc | 452 B | `5bdfabeda0e73097f6141097f1887bfc40e0a23840118b55df24eabf29a14cb8` |

The 5700 B increment brings selected code to 19552 B. Independent source correspondence also checks the predecessor's 85464 B parent, 3072 B banks, 79512 original fixup words and 1602 compiler starts. IDA's initial function ends are respectively 0x5a61e4, 0x5a6a08, 0x4be460, 0x625230 and 0x5dce44; these end at early indirect continuations. Compiler starts supply the retained intervals. A knowledge-store lookup returned no matching stored analysis for this dispatcher. No IDB edits or native target/API executions occur.

Artifacts: [producer](triage_evidence/recover_fpsd1201_shift.py), [checks and private states](triage_evidence/fpsd1201_shift_checks.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_shift.py), [audit receipt](triage_evidence/fpsd1201_shift_audit.json.zst), [IDA readback](triage_evidence/fpsd1201_shift_ida_readback.json.zst), [publication verifier](triage_evidence/verify_fpsd1201_shift_publication.py). The [operand report](fpsd1201_operand_report.md) establishes the preceding coefficient, distinct descriptors and scalar-one initializer. Its stop-before-shift boundary is historical; this increment continues the stated backed controls.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SH1 | Pinned bytes and compiler starts describe this snapshot. All addresses and source meaning depend on identity. | Fresh IDA/current/original hashes, independent universal-file parsing and compiler-bound checks agree. Native image selection remains unknown. |
| SH2 | Dispatcher state 0xc215 and recovered child controls select the described entries. ABI and route claims depend on these controls. | Independent record decoding checks every profile; universal amount-constructor and signed-partition obligations pass. Other entry controls remain outside this contract. |
| SH3 | Isolated descriptors contain canonical signed counts and sufficient private backing. Complete shift-oracle claims depend on these inputs. | Zero, positive and negative magnitudes, carry boundaries and seventeen shifts are checked. Word +0 is preserved, but its native meaning and allocation bounds remain unknown. No arbitrary native descriptor admission is inferred. |
| SH4 | Continued context patches have the predecessor's declared timing. Caller conclusions depend on this fixture epoch. | Eight cases independently reconstruct patches applied at operand-wrapper entry after import. Earlier metadata reads retain the old context count. Native context production and whole-call epoch consistency remain unknown. |
| SH5 | Original decoded pointers, sequential globals and explicit PAC models define private control flow. Replay depends on this model. | Every retained read/write/PAC frame and final RAM byte is compared independently. Hardware authentication, concurrent epochs and native loader behavior remain unknown. |
| SH6 | Source codecs preserve the recovered limb and signed count representation. Arithmetic interpretation depends on these equations. | Fifteen retained UNSAT obligations and five independent source-constructor obligations pass. Integer oracles check complete finite returns; no universal proof of the complete arbitrary-size loop is claimed. |
| SH7 | Query outputs are local classification markers and descriptor identities stay distinct. Data-flow conclusions depend on this separation. | The zero predicate returns 0x660d9bbd/0x660d9bbe and sign query returns three distinct markers. Queries preserve descriptors in these profiles; candidate P+0x880..P+0x8ff is never read or written. |
| SH8 | Stopping before 0x649430 bounds the continued caller result. Architectural conclusions depend on this boundary. | All eight frontier records, original slots and CPU frames agree. Root status/output seeds remain unchanged; protected-operation completion, port emission and native transport lineage remain unknown. |

## Dispatcher record and signed control [SH1,SH2,SH5,SH6]

For record R and p=low32(R), with all word arithmetic modulo 2^32:

```text
M = ((p XOR 0x309487ae) * 0x87cfdb29) mod 2^32
s = signed32((MEM32[R] - M + 0xa2eae272) mod 2^32)
control = (MEM32[R+4] - M) mod 2^32 = 0xc215
D = MEM64[R+8]
```

| Record offset | Width | Recovered role |
| --- | --- | --- |
| +0x00 | 32 bits | Pointer-keyed signed shift amount |
| +0x04 | 32 bits | Pointer-keyed entry control |
| +0x08 | 64 bits | Encoded-integer descriptor pointer |

The source pointer mask uses OR/AND/ORN at 0x5a6138..0x5a6158 and reduces to M. LDP at 0x5a615c loads both encoded words. The range test is `unsigned32(s-1) < 0x7fffffff`, universally equivalent to signed s>0. Thus zero selects the right route with magnitude zero. This is a sign partition over every u32 word; it does not prove that every amount has suitable backing or is admitted by native callers.

| Original call | Original slot | Target | IA modifier |
| --- | --- | --- | --- |
| Caller 0x14f9408 | 0x1d03860 | 0x5a600c | 0xdd63 |
| Positive 0x5a63e8 | 0x1d05a38 | 0x5a6774 | 0xa989 |
| Nonpositive 0x5a64d8 | 0x1d05370 | 0x4be1cc | 0x3870 |
| Left query 0x5a69d0 | 0x1d04610 | 0x624ff0 | 0x9c78 |
| Sign query 0x625200 | 0x1d04fa8 | 0x5dcd08 | 0xfb9a |
| Right query 0x4be414 | 0x1d04fa8 | 0x5dcd08 | 0xfb9a |

Selected pointer rows have address diversity 0. Both dispatcher branches continue through shared state 0x3e70 to 0x5a64e8 and return at RETAB 0x5a650c under the private PAC model.

## Child records and limb effects [SH1-SH3,SH5,SH6]

Both child records are 24 B views with encoded state at +0x00, descriptor pointer at +0x08 and encoded amount at +0x10. For child record pointer r:

```text
P = ((low32(r) XOR 0x542fbf9b) * 0x4386951d) mod 2^32
```

The positive leaf's arithmetic mask and the nonpositive leaf's OR/ORN mask both equal P for every pointer word. An earlier provisional high-bit-difference hypothesis failed a universal query and was rejected before publication.

| Child | Decoded control | Decoded amount A | Whole-limb displacement | Within-limb shift |
| --- | --- | --- | --- | --- |
| Left | MEM32[r]+P = 0xe598 | MEM32[r+0x10]+P = s XOR 0x86b3c60e | (A>>5) XOR 0x04359e30 = s>>5 | (A AND 31) XOR 14 = s AND 31 |
| Right | MEM32[r] XOR P = 0x8ddd | MEM32[r+0x10]+P = (-s) XOR 0x5092d4e4 | (A>>5) XOR 0x028496a7 = unsigned32(-s)>>5 | (A AND 31) XOR 4 = unsigned32(-s) AND 31 |

The long positive amount constructor at 0x5a61e4..0x5a633c is lifted from original instructions. Four byte obligations prove its complete output word. The nonpositive constructor is independently lifted through 0x5a6428 and its final arithmetic is checked separately. Producer and auditor use textual and structured Capstone operand decoders respectively. The mathematical identities cover all word values; whole-shift execution uses only the declared bounded inputs.

Descriptor D retains word +0x00 and the payload pointer at +0x08. Its count is signed32(MEM32[D+4]-0x4b0cf050). Payload limbs are little-endian in order and decode by XOR 0x1ac70ef2. The left path copies higher limbs toward higher addresses, carries bit fragments and fills new low limbs with encoded zero. The right path moves lower-address output forward, combines neighboring fragments and updates the signed normalized count. The complete finite contract is:

```text
v = nonnegative magnitude decoded from abs(count) limbs
sign = -1 if count < 0 else +1
if s > 0: out = v << s
else:     out = v >> (-s)
count' = sign * ceil(bit_length(out) / 32)
MEM32[D+4] = (0x4b0cf050 + count') mod 2^32
```

For negative inputs, this right-shifts the magnitude and preserves sign metadata; it corresponds to truncation toward zero. For example, magnitude 0xffffffff with negative count and shift -1 yields negative magnitude 0x7fffffff. This differs from a two's-complement arithmetic right shift of a negative integer. Zero uses count 0; the two diagnostic sign labels for zero have identical input descriptor bytes and do not establish a negative-zero representation.

For n input limbs and k whole limbs of left displacement, the compact arithmetic operation uses O(n+k) time and O(1) auxiliary limb storage, assuming adequate in-place backing. Right shift uses O(n) time and O(1) auxiliary limb storage. These are semantic-loop bounds; evidence generation retains instruction journals and has the larger costs documented in its scripts. Native bounds, exceptional metadata and all possible alias patterns remain unknown.

## Zero and sign queries [SH1-SH3,SH5-SH7]

| Routine | Record +0x00 | Control field | Output field | Selected meaning |
| --- | --- | --- | --- | --- |
| 0x5dcd08 | u64 descriptor | +0x0c, additive pointer codec; decoded 0x3f22 | +0x08, u32 | 0x660d9bbd + is_zero |
| 0x624ff0 | u64 descriptor | +0x08, additive pointer codec; decoded 0x9746 | +0x0c, u32 | 0x77458d7f + sign(value) |

Zero-query pointer mask is M as above. Sign-query mask is `((low32(r) XOR 0x341dc0b1)*0xdb676c6f) mod 2^32`. The zero query reads count, selects its absolute magnitude and scans encoded limbs from high to low until a nonzero encoded word or exhausted count. Its payload load is 0x5dce8c and marker store is 0x5dcec0. Canonical zero-count cases return without a payload-word read; canonical nonzero inputs encounter their nonzero highest limb first. Noncanonical leading-zero count representations are visible in the source loop but are outside the retained finite input matrix.

The sign query calls that zero predicate first. For nonzero values it tests the signed count and writes 0x77458d80 for positive or 0x77458d7e for negative at 0x62525c; zero returns 0x77458d7f. These markers are local query results, distinct from outer operation status. Although descriptor bytes remain unchanged, the routines update obfuscation globals; they are not side-effect-free functions in the complete memory model.

## Continued caller and next boundary [SH1,SH4-SH8]

The source caller prepares shift amount `signed32(a<<5)`, where a is the absolute context limb-count word selected by its preceding arithmetic. A universal word identity verifies the obfuscated staging reduction; the actual continued controls have a=0 or a=1. The mod-2^32 staging and signed dispatcher partition must remain explicit when analyzing larger count words.

```text
context first limb -> earlier negative-inverse coefficient -> Q+0x10
pair first descriptor -> scalar 1 -> complete signed shift
                                  -> 1 << (32*context_limb_count)
                                     [observed counts 0 and 1]
  -> original caller resumes at 0x14f940c
  -> stop before 0x14f94c4 -> 0x649430
```

| Controlled context | Shift | First temporary after return | Encoded count |
| --- | --- | --- | --- |
| One limb, seven retained cases | +32 bits | limbs [0,1], magnitude 2^32 | 0x4b0cf052 |
| Zero count, one retained case | 0 bits | limb [1], magnitude 1 | 0x4b0cf051 |

The first temporary's word +0 remains 130 and its payload pointer is unchanged. The imported descriptor and second temporary remain distinct and unchanged through this selected stage. Root status remains diagnostic 0xa5a5a5a5 and the outer output cell retains its seed. The next call uses original slot 0x1d039b8, IA modifier 0x8dc5, address diversity 0. Its retained record begins with context descriptor C+0x290 at +0x00, word 0x313baf8d at +0x08 and a private stack pointer at +0x10; the encoded grammar and complete effects are unknown. The call is not executed.

No selected executed path emits an incoming or outgoing Mach right or calls a Mach API. This adds local arithmetic context to the CoreFP request1201 caller; it does not establish a new port, native daemon endpoint identity or a kext transaction. Existing emission and endpoint evidence remains in the [Mach-port report](mach_ports_report.md).

## Validation, limits and continuation

The independent auditor passes 144 configurations: eight continued caller cases and 136 isolated signed-shift cases. The latter cover magnitudes 0, 1, 0xffffffff and 0x123456789abcdef012345678, two diagnostic sign labels, and shifts -129, -65, -64, -63, -33, -32, -31, -1, 0, 1, 31, 32, 33, 63, 64, 65 and 129 bits. Removing duplicate zero-sign input representations leaves 119 distinct isolated value/sign/shift inputs.

The audit checks 168717 original visits, 25418 reads, 6815 writes, 5871 PAC models, 7377 full CPU frames, 862 shift checkpoints and 21823488 B of final RAM. All 144 complete shift results match the independent integer oracle. It checks 71 left-child records, 73 right-child records, 144 zero-query returns and 71 sign-query returns. Eight prior imports and scalar-one initializers remain independently checked. Fifteen retained UNSAT queries and five independently reconstructed source-constructor queries pass; source proofs are distinct from finite complete-shift validation.

| Impact | Bounded continuation / context | Probe and boundary |
| --- | --- | --- |
| High | Determine how 0x649430 combines context and the newly produced radix power. | Recover its record grammar and original return before assigning a larger modular-arithmetic identity. The coefficient plus radix-power preparation motivates this next join; algorithm identity remains unknown. |
| High | Restore source-produced context and whole-parent stack epochs. | Replace diagnostic post-import patches with original reaching definitions and confirm actual count/payload/temporary ownership. Current complete primitive returns do not prove whole-operation reachability. |
| High | Join completed request1200 outputs to request1201 emission and native daemon/kext activity. | Carry the actual endpoint, session and payload identities across retained consumers and matched transport events. Arithmetic similarity supplies no port identity. |
| Medium | Qualify modular amount staging and descriptor representation preconditions. | Prove native count/allocation limits and alias constraints from callers. Large abstract words can change the signed route; no native admission or fault is established here. |
| Low | Extend query contracts to noncanonical representations. | Add leading-zero and empty/null-payload diagnostic fixtures separately; preserve the distinction between representation normalization and numeric zero. |

Quality gates: **QG1** no normative content is required. **QG2** SH1-SH8 state assumptions, dependent results and falsification probes. **QG3** routine functions, record/call contracts, data/control flow, port consequences and continuation are covered. **QG4** byte sizes and modulo-word equations are reproducible; shifts use bits and limbs use 32 bits. **QG5** finite, universal and native claims are separated; rejected codec and duplicate-zero cases are explicit. **QG6** pinned original bytes, compiler boundaries, independent source parsing/replay and source-constructor proofs support claims. **QG7** impact-ranked continuation remains bounded. The full investigation remains active.

## CoreFP1201 working-copy and comparison continuation

The [working-copy/comparison continuation](fpsd1201_comparison_report.md) continues the eight caller cases through 0x649430 and two 0x33abec comparisons, reaching the unexecuted 0x14f9d74 -> 0x5e8158 call. It establishes a separate working context and resolves seed-dependent wrapper padding. This supersedes this report's stop-before-copy boundary for those controls; native context production, complete arithmetic-child return and IPC lineage remain unknown.
