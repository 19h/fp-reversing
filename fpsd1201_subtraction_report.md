# CoreFP1201 signed subtraction and magnitude dependencies

Original routine 0x5e8158 performs in-place signed subtraction, B := B - A, on the recovered encoded-integer representation. Its original magnitude-difference and magnitude-addition dependencies are 0x1ec40 and 0x443bf4. Complete private returns, independent canonical-integer oracles and alias controls establish the local contracts for the retained inputs. This increment continues all eight caller profiles through the subtraction return and stops before executing 0x14f9d78. Complete arithmetic-child return, successful request1201 processing and native daemon/kext lineage remain unknown. The full investigation remains active.

## Source and evidence

Addresses use reference CoreFP arm64e preferred base 0, SHA-256 `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; universal SHA-256 `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`. Fresh read-only IDA bytes equal IDA original bytes and the independently parsed matching reference:

| Recovered role | Compiler-bounded interval | Size | SHA-256 |
| --- | --- | --- | --- |
| Signed in-place subtraction | 0x5e8158..0x5e8640 | 1256 B | `be97c57e32760b5f02cae70b276df86be518c247480c857d6005c7c95e2e293e` |
| Signed magnitude difference | 0x1ec40..0x1f388 | 1864 B | `6c21bbed8d1d561774fed007ad99ffaca5f69cd05c7404b192266b01fff41fbc` |
| Signed magnitude addition | 0x443bf4..0x4441c4 | 1488 B | `d3e326d70ee9a966cdc4b2ab125386832e0aa83ff98a293bebd1268ae79a0b1f` |

The 4608 B increment brings selected code to 26136 B. Reference correspondence also checks the retained 85464 B parent, 3072 B banks, 79512 original fixup words and 1602 compiler starts. Initial IDA function ends are 0x5e8324, 0x1ef14 and 0x443ea0, respectively, at indirect continuations; compiler starts define the retained intervals. A knowledge-store lookup for 0x5e8158 returned no matching analysis. No IDB edits or native target/API executions occur.

Artifacts: [producer](triage_evidence/recover_fpsd1201_subtraction.py), [checks and private states](triage_evidence/fpsd1201_subtraction_checks.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_subtraction.py), [audit receipt](triage_evidence/fpsd1201_subtraction_audit.json.zst), [IDA readback](triage_evidence/fpsd1201_subtraction_ida_readback.json.zst), [publication verifier](triage_evidence/verify_fpsd1201_subtraction_publication.py). The [comparison report](fpsd1201_comparison_report.md) establishes the preceding working copy, comparisons and seed-dependent frame geometry. Its stop-before-subtraction boundary is historical for these eight continued cases.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SU1 | Pinned binary bytes and compiler starts identify this snapshot. All source/address claims depend on identity. | Fresh IDA current/original hashes and independent reference parsing agree. Native image selection remains unknown. |
| SU2 | Entry states 0xf136, 0x5c71 and 0x99bf select the reported contracts. | Every original entry record is independently decoded; original pointer rows, call modifiers and source instructions are checked. Other entry states remain outside the contract. |
| SU3 | Signed counts and payloads are canonical numeric representations. Integer semantics depend on this condition. | Signed matrix, cancellation, borrow/carry chains and canonical count normalization pass. The prior comparison report's noncanonical-zero counterexamples prevent extending these contracts to arbitrary representations. |
| SU4 | Private payloads have sufficient backing for complete input/output limbs. Capacity and alias results depend on this fixture. | Inputs extend to 64 limbs; one carry can require 65 output limbs. Each isolated backing spans 512 B. Distinct output, output=first, output=second and root self-subtraction pass. Partial overlap and native allocation limits remain unknown. |
| SU5 | Continued context patches retain the predecessor's declared timing and values. Caller data-flow results depend on those controls. | Eight independent reconstructions preserve import, coefficient, shift, working-copy and comparison checkpoints. Source-produced native context remains unknown. |
| SU6 | Decoded pointer rows, mutable global state and explicit PAC models define private execution. | Full visits, reads, writes, PAC/CPU frames and final RAM agree on independent replay. Native authentication and concurrent epochs remain unknown. |
| SU7 | Zero and nonzero descriptor branches follow the source count representation. | Root A=0 returns without executing the B-pointer load, including one NULL-B control. B=0 with nonzero A reaches the original raw-copy dependency and count-sign inversion. Direct magnitude-leaf inputs are nonzero; direct zero-leaf admission is unestablished. |
| SU8 | Stopping immediately after the complete subtraction return bounds this increment. | All eight caller cases stop before 0x14f9d78; root status/output seeds and candidate input remain unchanged. Larger algorithm, native protected result and transport continuity are not inferred. |

## Records and local contracts [SU1-SU4,SU6,SU7]

Let BASE=0x4b0cf050 and K=0x1ac70ef2. Descriptor signed limb count is s32(MEM32[D+4]-BASE); magnitude limbs at MEM64[D+8] are little-order u32 words decoded by XOR K. Canonical zero has count 0; canonical nonzero has a nonzero most-significant decoded limb. Descriptor word +0 and payload pointer are preserved by these retained arithmetic outcomes. Their native capacity/ownership meanings remain unknown.

For record R, p=low32(R), all control-word arithmetic is modulo 2^32:

```text
W = ((p XOR 0x7043a3fa) * 0x4ecee2ad) mod 2^32
M = ((p XOR 0x309487ae) * 0x87cfdb29) mod 2^32
```

| Entry | Record offset | Width | Role / selected condition |
| --- | --- | --- | --- |
| 0x5e8158 | +0x00 | 32 bits | Encoded control; MEM32[R] XOR W = 0xf136 |
| 0x5e8158 | +0x08 | 64 bits | First input A descriptor |
| 0x5e8158 | +0x10 | 64 bits | Second input and output B descriptor |
| 0x1ec40 | +0x00 | 64 bits | First input X descriptor |
| 0x1ec40 | +0x08 | 64 bits | Second input Y descriptor |
| 0x1ec40 | +0x10 | 32 bits | Encoded control; (MEM32[R+0x10]-M) mod 2^32 = 0x5c71 |
| 0x1ec40 | +0x18 | 64 bits | Output descriptor |
| 0x443bf4 | +0x00 | 64 bits | First input X descriptor |
| 0x443bf4 | +0x08 | 64 bits | Output descriptor |
| 0x443bf4 | +0x10 | 64 bits | Second input Y descriptor |
| 0x443bf4 | +0x18 | 32 bits | Encoded control; MEM32[R+0x18] XOR M = 0x99bf |

The root consumes a 24 B prefix; the difference leaf consumes 32 B; the addition leaf consumes a 28 B prefix. Retained 32 B snapshots include neighboring bytes without assigning unused padding new roles. In particular, +0x08 is the addition leaf's output pointer, whereas +0x10 is its second input pointer.

| Entry | Retained canonical integer semantics | Output alias controls |
| --- | --- | --- |
| 0x5e8158 | B := B - A | B is the second input; 11 additional same-descriptor cases yield zero |
| 0x1ec40 | output := sign(X) * (abs(X)-abs(Y)) | Distinct output, output=X, output=Y |
| 0x443bf4 | output := sign(Y) * (abs(X)+abs(Y)) | Distinct output, output=X, output=Y |

The signed count and active output limbs encode the canonical result in every numeric case. Nonoutput input descriptors and payload snapshots remain unchanged. Exact descriptor identity is tested; arbitrary partially overlapping payload ranges are not tested. Diagnostic descriptor word +0 remains 64 even in a 65-limb carry result, so these executions do not establish a checked capacity bound from that word.

## Branches, call sites and carry data flow [SU1-SU4,SU6,SU7]

The root reads A's count at 0x5e8298. A=0 bypasses the B-pointer load at 0x5e8334 and all arithmetic dependencies. With nonzero A and B=0, it copies A into B using the original copy routine, then inverts the encoded signed count at 0x5e8440. For nonzero operands, equal count signs take the magnitude-difference route with X=B, Y=A, output=B; opposite signs take magnitude addition with X=A, Y=B, output=B. These routes both realize B-A on retained canonical inputs.

| Call location | Original pointer slot | Target | IA modifier | Local purpose |
| --- | --- | --- | --- | --- |
| 0x14f9d74 | 0x1d03920 | 0x5e8158 | 0x6144 | Caller signed subtraction |
| 0x5e8428 | 0x1d039b8 | 0x649430 | 0x8dc5 | Raw copy for zero second operand |
| 0x5e8558 | 0x1d03f90 | 0x1ec40 | 0xc137 | Same-sign magnitude difference |
| 0x5e8600 | 0x1d04af8 | 0x443bf4 | 0x6693 | Opposite-sign magnitude addition |
| 0x1eea0 | 0x1d04610 | 0x624ff0 | 0x9c78 | Query sign of difference's first input |
| 0x443e3c | 0x1d04610 | 0x624ff0 | 0x9c78 | Query sign of addition's second input |

All selected rows have address diversity 0. Original sign/zero query routines execute and return; no arithmetic result or authentication verdict is supplied. The sign result uses bias 0x77458d7f; the zero predicate uses bias 0x660d9bbd. The preceding [shift report](fpsd1201_shift_report.md) documents those dependency records.

For u32 decoded limbs u,v and carry c in {0,1}, the common addition step at 0x443ee0..0x443f00 computes a 64-bit T=u+v+c, stores (low32(T) XOR K), then propagates T>>32. The difference step at 0x1ef68..0x1ef8c computes T=u+c-v+0xffffffff. The extra term is the zero-extended value written by `mov w0, #-1` at 0x1ef38; treating it as signed u64 -1 loses the no-borrow flag. The low word equals u-v-(1-c) modulo 2^32; T>>32 equals 1 exactly when u+c >= v+1.

The encoded store identity is universally checked:

```text
(t - (0x358e1de4 AND (t << 1)) + K) mod 2^32 = t XOR K
```

The difference routine also uses 0xe538f10d=NOT K to decode complemented limbs, conditionally complements/adds one for negative magnitude difference, removes high zero limbs and stores the signed count at 0x1f348. Addition stores its signed count at 0x444184 and can append a carry limb. These whole-loop interpretations are supported by complete finite executions; the retained universal word identities do not constitute a proof of arbitrary-size algorithm equivalence.

## Continued caller and architectural boundary [SU5,SU6,SU8]

```text
context C+0x290 --raw copy--> working A
                                  |
radix B = 2^32 (or 1 at count 0) -+--> 0x5e8158
                                         |
                                         +--> same-sign difference leaf
                                         |       X=B, Y=A, output=B
                                         +--> B = radix - A
                                         +--> return; stop before 0x14f9d78
```

The working copy is input A and remains unchanged; the radix descriptor is output B. For controlled context n in {1,3,5,7,2,0x80000000,0xfffffffe}, B becomes 2^32-n. At n=0, the radix remains scalar 1 and the subtraction bypasses its arithmetic leaves. The seven nonzero nested cases use the difference leaf, while the isolated matrix covers the addition route and zero-second copy route.

All eight stop before `mov w8, #-0xec` at 0x14f9d78. This is a declared analysis boundary after a completed local return, not an unretained call. The parent arithmetic child has not returned. Root status remains diagnostic 0xa5a5a5a5; the outer output cell retains its seed; candidate P+0x880..P+0x8ff remains untouched. No selected executed path emits a Mach right or invokes a Mach API. Native request1200/request1201 endpoint identity, port-right ownership and daemon/kext/deeper pairing remain unknown; established emission sites remain in the [Mach-port report](mach_ports_report.md).

## Validation and bounded continuation

Independent replay passes 197 profiles: eight continued caller profiles, 141 isolated root profiles, 24 direct magnitude-difference profiles and 24 direct magnitude-addition profiles. Root inputs cover the prior 11-by-11 signed matrix, eight wide carry/borrow/cancellation cases, 11 same-descriptor cases and one zero-A/NULL-B case. Direct leaves cover eight signed/boundary input pairs with each of three output alias relationships. Inputs reach 64 limbs and outputs reach 65 limbs.

The audit checks 252548 original visits, 42868 reads, 11501 writes, 9822 PAC models, 14903 full CPU frames, 841 arithmetic checkpoints, 712 dependency checkpoints, 2676 carry checkpoints and 29855744 B of final RAM. It checks 196 canonical integer outcomes and the separate NULL-B bypass, 475 common carry/store steps, 173 sign-query returns, 173 zero-query returns, ten zero-second raw-copy returns, 11 self-subtraction zeros and 201 preserved nonoutput input snapshots. All eight preceding imports, coefficients, shifts, copies, comparisons and seed-dependent frame geometries remain independently checked. Eleven retained UNSAT queries and ten separately reconstructed word obligations pass; 23 selected source instructions are pinned independently.

| Impact | Bounded continuation / context | Probe and current boundary |
| --- | --- | --- |
| High | Recover post-subtraction caller control and larger arithmetic-child contract. | Continue from 0x14f9d78 with bounded loop accounting and exact frame/record lifetimes; one subtraction does not identify the whole algorithm. |
| High | Establish source-produced context and canonical-count admission. | Trace writers of C+0x290/count/payload and normalization; private post-import patches are explicit controls. |
| High | Join completed local arithmetic to request1201 payload and endpoint provenance. | Follow reaching definitions into the candidate 128-byte input and real message/session consumers. No native transport or daemon/kext join is supplied by these leaves. |
| Medium | Recover backing extent and overlap/alias contracts. | Trace constructors and payload allocation independently of preserved descriptor word +0; direct zero-leaf and partial-overlap behavior remain unknown. |
| Medium | Replace repeated execution with a bounded arithmetic-loop proof. | Use source-pinned carry/borrow identities and canonical normalization invariants; distinguish universal word results from finite complete returns. |
| Low | Recover exceptional environmental exits. | Stack-canary failure branches are retained source but not executed under the diagnostic canary fixture. |

Quality gates: **QG1** no normative content is required. **QG2** SU1-SU8 state assumptions, dependent results and falsification probes. **QG3** routine roles, record/call ABIs, data/control flow, external controls, environmental context, port consequences and continuation are covered. **QG4** B denotes bytes; limbs are 32 bits; u32/u64 arithmetic and no-borrow encoding are reproducible. **QG5** zero/NULL, cancellation, signed counts, tested aliases, capacity uncertainty and finite/universal/native boundaries are explicit. **QG6** primary binary bytes, original slots, independent parsing/replay and separate integer/word oracles support claims. **QG7** impact-ranked expansion remains bounded. The full investigation remains active.
