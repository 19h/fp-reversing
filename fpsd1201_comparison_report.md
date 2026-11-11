# CoreFP1201 working-context copy and signed comparison

Original routine 0x649430 copies an encoded integer's signed count and raw limbs into an existing descriptor, preserving destination word +0 and its payload pointer. Original routine 0x33abec compares two canonical signed encoded integers and writes a three-valued biased result. Complete private returns and independent byte/integer oracles establish both local contracts across the retained inputs. Four noncanonical zero controls establish a representation boundary: count-based ordering can distinguish representations whose decoded numeric values are both zero.

The caller copies context C+0x290 into a separate working descriptor, compares the original context with its newly prepared radix power, and compares the working copy with the same radix descriptor. Eight continued cases then stop before 0x14f9d74 -> 0x5e8158. A further source check resolves cursor-seed-dependent stack padding, explaining two different working-descriptor addresses in otherwise comparable controls. Complete arithmetic-child return, native context production and daemon/kext lineage remain unknown. The full investigation remains active.

## Source and evidence

Addresses use reference CoreFP arm64e preferred base 0, SHA-256 `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; universal SHA-256 `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`. The following fresh read-only IDA bytes equal IDA original bytes and the matching reference file:

| Recovered role | Compiler-bounded interval | Size | SHA-256 |
| --- | --- | --- | --- |
| Encoded-integer copy | 0x649430..0x6496b8 | 648 B | `4fc734824e3d897552bd476e2d40183021699b197e3d0c31d188baea0e313542` |
| Signed comparison | 0x33abec..0x33b11c | 1328 B | `2687f36941289d3d85276683c914e7eaa28ac1b05cd791a83e602704be2fc8d8` |

The 1976 B increment brings selected code to 21528 B. Independent reference correspondence also checks the retained 85464 B parent, 3072 B banks, 79512 original fixup words and 1602 compiler starts. IDA's initial function ends are 0x649548 and 0x33ad50, at early indirect continuations; compiler starts supply the retained full intervals. A knowledge-store lookup returned no matching analysis for 0x649430. No IDB edits or native target/API executions occur.

Artifacts: [producer](triage_evidence/recover_fpsd1201_comparison.py), [checks and private states](triage_evidence/fpsd1201_comparison_checks.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_comparison.py), [audit receipt](triage_evidence/fpsd1201_comparison_audit.json.zst), [IDA readback](triage_evidence/fpsd1201_comparison_ida_readback.json.zst), [publication verifier](triage_evidence/verify_fpsd1201_comparison_publication.py). The [shift report](fpsd1201_shift_report.md) establishes the preceding radix-power preparation; its stop-before-copy boundary is historical for the eight continued cases.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CP1 | Pinned bytes and compiler starts describe this snapshot. All addresses and source claims depend on identity. | Fresh IDA/current/original hashes and independent reference-file parsing agree. Native image selection remains unknown. |
| CP2 | Decoded copy state 0x2f63 and comparator state 0x69d6 select these contracts. Record and branch claims depend on those controls. | Every retained record is independently decoded; original pointer rows and source instructions are checked. Other entry states remain outside the contract. |
| CP3 | Canonical signed counts describe normalized numeric magnitudes for integer-comparison claims. | Positive/negative, equal, unequal-length and 64-limb low-difference cases pass. Four noncanonical all-zero controls falsify an unconditional numeric interpretation; they are reported separately. |
| CP4 | Distinct isolated payloads have sufficient diagnostic backing. Copy and comparison returns depend on this fixture. | Counts 0..64, both count signs, two copy patterns and same-object controls are checked. Zero-count distinct copies use NULL payload pointers without limb accesses. Native capacity meaning, allocation extent and partial overlap remain unknown. |
| CP5 | Continued context patches retain the predecessor's declared timing and values. Caller data-flow claims depend on those inputs. | Eight cases reconstruct post-import controls independently and preserve the separate imported/temporary identities. Source-produced context and whole-call epoch consistency remain unknown. |
| CP6 | Original decoded pointers, sequential mutable globals and explicit PAC models define private execution. | All retained visits, reads, writes, PAC frames and final RAM are compared independently. Native authentication, concurrent epochs and hardware/API effects remain unknown. |
| CP7 | Cursor seeds and source padding arithmetic determine the selected private frame geometry. | All eight actual copy-frame addresses match the seed formula. Universal u64 padding bounds/alignment and source instructions pass; a fixed offset from the outer wrapper frame was rejected. Native seed production remains unknown. |
| CP8 | Stopping before 0x5e8158 bounds the caller result. Architectural conclusions depend on that boundary. | All eight original next-call records/slots agree; root status and output seeds remain unchanged. No completed protected result, port lineage or daemon/kext transaction is inferred. |

## Copy record and exact effects [CP1,CP2,CP4-CP6]

For record R and p=low32(R), all word arithmetic is modulo 2^32:

```text
M = ((p XOR 0x309487ae) * 0x87cfdb29) mod 2^32
(MEM32[R+8] + M) mod 2^32 = 0x2f63
source = MEM64[R]
destination = MEM64[R+0x10]
```

| Copy record offset | Width | Role |
| --- | --- | --- |
| +0x00 | 64 bits | Source descriptor pointer |
| +0x08 | 32 bits | Encoded additive entry control |
| +0x10 | 64 bits | Destination descriptor pointer |

The source's OR/subtract pointer expression at 0x649488..0x6494c0 reduces universally to M. The consumed prefix spans 24 B; retained 32 B snapshots include neighboring reused bytes without assigning them additional copy-ABI roles.

The descriptor count word decodes as signed32(MEM32[D+4]-0x4b0cf050). Let n be its absolute magnitude for the retained counts. If source and destination descriptor pointers are equal, the selected path returns without reading their count/payload fields or writing the descriptor/limbs. Mutable obfuscation globals still change.

For distinct descriptors, 0x649568 loads the source count and 0x649588 copies the encoded word unchanged into destination+4. Payload words are then copied in descending index order n-1 through 0. Odd n first copies the highest word through 0x649624/0x64962c; the paired loop at 0x649678..0x649694 handles the remaining descending words. The exact finite contract is:

```text
if source != destination:
    destination.count_word = source.count_word
    for i = abs(decoded_source_count)-1 .. 0:
        destination.payload[i] = source.payload[i]
```

Destination word +0, destination payload pointer, untouched payload tail, complete source descriptor/payload and argument-record bytes remain unchanged in the declared nonoverlapping fixtures. The raw copy does not transform limb words and does not normalize a count whose payload contains only encoded zeros. Five distinct zero-count cases perform the count-word store and no limb access; four isolated cases have NULL source/destination payload pointers. Fifty-two same-descriptor cases bypass count/payload reads and writes.

The compact copy uses O(n) time and O(1) auxiliary limb storage. No capacity, growth, allocator or general overlapping-buffer contract is established by this body. Word +0 is preserved; its native meaning remains unknown.

## Comparator record and result orientation [CP1-CP3,CP5,CP6]

For comparator record R:

```text
N = ((low32(R) XOR 0x302a1e77) * 0xcae5b081) mod 2^32
(MEM32[R+0x18] + N) mod 2^32 = 0x69d6
```

| Comparator record offset | Width | Role |
| --- | --- | --- |
| +0x00 | 64 bits | First descriptor A |
| +0x08 | 32 bits | Result code, overwritten on completion |
| +0x10 | 64 bits | Second descriptor B |
| +0x18 | 32 bits | Encoded additive entry control |

The consumed view spans 28 B; the retained 32 B includes four neighboring bytes. Original store 0x33b0f8 writes only the result word within that record. The result orientation is:

| Canonical integer relation | Result at R+8 |
| --- | --- |
| A > B | 0x312bc2c0 |
| A = B | 0x312bc2c1 |
| A < B | 0x312bc2c2 |

Equivalently, result = 0x312bc2c1 + sign(B-A). This is a biased local comparison code, distinct from a transport or outer-operation status.

The selected source first orders signed counts. For equal counts it scans decoded limbs from highest to lowest, adapting magnitude order to the count's sign. Original loads at 0x33af18/0x33af20 fetch second/first limb words; equal words continue through a one-index decrement at 0x33b018. Both descriptor/payload views remain unchanged in the retained profiles. Equal and low-difference 64-limb inputs exercise a complete descending scan.

Each decoded limb is `v = encoded_word XOR 0x1ac70ef2`. The two long comparison phases contain different arithmetic expressions that both reduce to `v + 0xe538f10e mod 2^32`. Sixteen source-lifted byte obligations prove both operands in both phases. Producer and independent auditor use textual and structured operand decoders respectively.

Adding phase-specific biases gives rotated unsigned words. The source compares the rotation-wrap indicators before comparing rotated words. A universal bit-vector obligation establishes:

```text
rx = (x + bias) mod 2^32
ry = (y + bias) mod 2^32
if (rx < bias) != (ry < bias): x_greater = (rx < bias)
else:                         x_greater = (rx > ry)
x_greater == unsigned(x > y)
```

This source arithmetic proof is distinct from a universal proof of the complete arbitrary-size comparator. The complete finite numeric oracle is checked for canonical inputs. Its compact scan uses O(max(nA,nB)) time and O(1) auxiliary limb storage; differing signed counts may return before payload reads.

## Representation boundary [CP2-CP4,CP6]

The copier preserves count representation, and the comparator uses count ordering before limb scans. Consequently, numeric equality alone is insufficient when counts are noncanonical:

| Decoded count A | Decoded count B | Decoded numeric values | Observed result |
| --- | --- | --- | --- |
| +1, encoded-zero limb | 0 | A=0, B=0 | 0x312bc2c0 |
| 0 | +1, encoded-zero limb | A=0, B=0 | 0x312bc2c2 |
| -1, encoded-zero limb | 0 | A=0, B=0 | 0x312bc2c2 |
| 0 | -1, encoded-zero limb | A=0, B=0 | 0x312bc2c0 |

These four controls falsify an unconditional numeric-comparator contract. They establish a local representation precondition; native admission, normalization or rejection policy remains unknown. They do not establish a native comparison discrepancy reachable from an external input.

## Dynamic frame geometry and working-context identity [CP1,CP5-CP7]

Let S be SP at outer operand-wrapper entry 0x14fac64 and seed be its caller output-cell value. The original wrapper reads seed at 0x14fad54 and computes:

```text
mixed = (seed * 0x2e9d + 1) mod 2^64
top = mixed >> 60
padding = ((top << 4) + 0x1f) AND 0x1f0
        = 16 * (top + 1) bytes
```

Padding ranges from 16 B to 256 B, always a multiple of 16 B. Three universal u64 obligations establish the exact formula, bounds and alignment. Wrapper fixed storage consumes 0x40 B; the child consumes a further 0x360 B. Thus the child-frame SP T at the copy call is `T = S - 0x3a0 - padding` in these executions.

| Identity | Address relative to its producing frame | Meaning in this stage |
| --- | --- | --- |
| Original context descriptor | C+0x290 | Source of working count and limbs |
| Working descriptor | T+0xa0 | Copy destination; initial word +0 = 130 |
| Working payload | T+0xc0 | Separate copied limbs |
| Radix descriptor | S+0xa0 | Earlier first temporary, containing 2^32 or 1 |
| Imported descriptor | S+0x90 | Earlier 128-byte import, preserved |
| Second arithmetic temporary | S+0x80 | Separate earlier pair member, preserved |

Seeds 0, 1 and 0x0123456789abcdef select 16 B padding in the retained cases; seed 0xffffffffffffffff selects 256 B. The working-descriptor addresses consequently differ by 240 B. A provisional fixed `S-0x310` address matched six cases but failed the two maximum-seed controls and was rejected. The invariant address is T+0xa0. This is a frame-geometry result; native seed production, whole-parent frame epochs and completed cursor publication remain unknown.

## Caller comparisons and next boundary [CP1,CP2,CP5-CP8]

| Original call | Original slot | Target | IA modifier |
| --- | --- | --- | --- |
| 0x14f94c4 | 0x1d039b8 | 0x649430, copy context into working descriptor | 0x8dc5 |
| 0x14f955c | 0x1d03da8 | 0x33abec, original context versus radix | 0x3d56 |
| 0x14f9c6c | 0x1d03da8 | 0x33abec, working copy versus radix | 0x3d56 |
| 0x14f9d74 | 0x1d03920 | 0x5e8158, not executed | 0x6144 |

Selected rows have address diversity 0. Both comparisons return 0x312bc2c2 in every continued profile: the controlled one-limb values are below 2^32; the zero-count control is below scalar 1. The first comparison's result overwrites record+8, formerly used by the copy control. The caller then replaces the first descriptor pointer with the working copy for the second comparison. Reused record addresses therefore require per-call field lifetimes.

```text
original context C+0x290 -----> compare with radix descriptor
             |
             +--> raw count/limb copy --> working descriptor T+0xa0
                                          |
                                          +--> compare with same radix
                                                 |
                                                 +--> stop before 0x5e8158
```

The final unexecuted record places the working descriptor pointer at +0x08 and radix descriptor pointer at +0x10; its encoded grammar and complete effects remain unknown. Root status remains diagnostic 0xa5a5a5a5 and the outer output cell retains its seed. Candidate P+0x880..P+0x8ff remains untouched. No selected executed path emits a Mach right or calls a Mach API. Native request1200/request1201 endpoint continuity and daemon/kext/deeper pairing remain open; existing emission evidence remains in the [Mach-port report](mach_ports_report.md).

## Validation and bounded continuation

Independent replay passes 243 configurations: eight continued caller cases, 104 isolated copy cases and 131 isolated comparison cases. Copy controls cover counts 0, 1, 2, 3, 4, 5, 7, 8, 31, 32, 33, 63 and 64, both signs, sequence/all-zero patterns and same/distinct descriptor pointers. Canonical comparison controls include an 11-by-11 signed-value matrix and six equal/low-difference 64-limb pairs; four additional cases cover noncanonical numeric zero.

The audit checks 176644 original visits, 20274 reads, 5377 writes, 6012 PAC models, 9070 full CPU frames, 224 copy checkpoints, 294 comparison checkpoints, 1644 limb checkpoints and 36827136 B of final RAM. It checks 112 complete copy outcomes, 1019 raw limb copies in exact descending order, 52 same-descriptor bypasses, 147 complete comparison outcomes, 143 signed-integer comparison oracles and four separately classified noncanonical controls. Eight seed-dependent frame geometries and the preceding imports, coefficients and shifts remain checked. Twenty-three retained UNSAT queries and twenty independently reconstructed source obligations pass; the full arbitrary-size algorithms and native execution remain unproved.

| Impact | Bounded continuation / context | Probe and current boundary |
| --- | --- | --- |
| High | Recover how 0x5e8158 updates the working/radix operands after the two comparisons. | Establish record grammar, original arithmetic dependencies and complete return before assigning a larger algorithm. |
| High | Establish source-produced context and canonical-count invariants. | Trace writers of C+0x290/count/payload and normalization policy; current patches and four noncanonical controls do not prove native admission. |
| High | Recover whole-parent frame/cursor epochs and request1201 payload production. | Preserve seed-dependent padding and per-call record field lifetimes while following source reaching definitions to the candidate 128-byte buffer. |
| High | Join local arithmetic completion to real endpoint/right ownership and daemon/kext activity. | Track actual session, message, data and status identities across source consumers and matched transport evidence. Current local comparisons supply no native port identity. |
| Medium | Determine copy allocation, capacity and overlap contracts. | Trace descriptor constructors and callers; word +0 preservation and bounded private backing do not establish native ownership or memmove semantics. |
| Low | Extend compact proofs to complete bounded loops and exceptional representations. | Source word identities and finite complete returns are distinct; avoid promoting either to an unrestricted arbitrary-size algorithm proof. |

Quality gates: **QG1** no normative content is required. **QG2** CP1-CP8 state assumptions, dependent results and probes. **QG3** routine roles, record/call ABIs, source data/control flow, environmental frame context, port consequences and continuation are covered. **QG4** B denotes bytes; limbs are 32 bits; u32/u64 modular arithmetic and padding alignment are reproducible. **QG5** noncanonical zero, same-object/zero-count cases, rejected fixed-offset inference and finite/universal/native boundaries are explicit. **QG6** primary binary bytes, independent source parsing/replay, original slots and distinct source lifters support claims. **QG7** impact-ranked continuation remains bounded. The full investigation remains active.
