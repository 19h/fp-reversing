# CoreFP1201 reduction, Montgomery squaring and complete precomputation return

Original arithmetic child 0x14f8d28 completes Montgomery-context precomputation for the retained positive one-word odd moduli. With R=2^32, the pair's first descriptor becomes R mod n, its second becomes R^2 mod n, and pair+0x10 receives -n^-1 modulo R. The second result uses five original Montgomery squarings through wrapper 0x9dd7e4 and implementation 0x9dc6d4. Twelve positive controls return from the complete child and its outer cursor wrapper; nine are odd and three are explicitly classified even controls. Zero stops after 64 subtraction returns. Complete request1201 processing and native daemon/kext lineage remain unknown. The full investigation remains active.

## Source and evidence

Addresses use reference CoreFP arm64e preferred base 0, SHA-256 `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; universal SHA-256 `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`. Fresh read-only IDA current/original bytes equal the independently parsed reference:

| Recovered role | Compiler-bounded interval | Size | SHA-256 |
| --- | --- | --- | --- |
| Square cursor wrapper | 0x9dd7e4..0x9dd9fc | 536 B | `e0d3fe32053709a848e6f14922e29c0ccc02aaf34959c111806be478eeb11bff` |
| Montgomery square implementation | 0x9dc6d4..0x9dd7e4 | 4368 B | `096c10d3221c94a15dac5a16b4e1051d2e41b8316480ff8a0912a871caa44666` |

The 4904 B increment brings selected code to 31040 B. Independent reference correspondence includes the retained 85464 B parent, 3072 B banks, 79512 original fixup words and 1602 compiler starts. IDA's initial square-implementation end is 0x9dc8ec, before indirect continuations; compiler starts define the complete interval. Its wrapper's IDA end already matches the compiler boundary. A knowledge-store query for 0x9dd7e4 returned no matching analysis. No IDB edits or native target/API executions occur.

Artifacts: [producer](triage_evidence/recover_fpsd1201_reduction.py), [checks and private states](triage_evidence/fpsd1201_reduction_checks.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_reduction.py), [audit receipt](triage_evidence/fpsd1201_reduction_audit.json.zst), [IDA readback](triage_evidence/fpsd1201_reduction_ida_readback.json.zst), [publication verifier](triage_evidence/verify_fpsd1201_reduction_publication.py). The [subtraction report](fpsd1201_subtraction_report.md) establishes the independently replayed prefix. Its stop-after-first-subtraction boundary is historical for the continued profiles.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RF1 | Pinned bytes/compiler starts identify this snapshot. All source/address claims depend on identity. | Fresh IDA/current/original hashes and independent reference parsing agree. Native image selection remains unknown. |
| RF2 | Recovered entry controls select these local contracts. | Every principal entry record, original pointer row and full CPU/journal is checked independently. Other entry states remain outside the contract. |
| RF3 | Context modulus is a canonical positive one-word integer for the complete-return controls. | Twelve positive inputs return; the zero-count control is separately bounded. Multi-limb, negative and noncanonical admission remain unknown. |
| RF4 | Odd n supplies an inverse modulo R. Montgomery and R^2 claims depend on this condition. | Nine odd inputs pass inverse and R/R^2 oracles. Three even controls use the literal arithmetic recurrence; n=0xfffffffe falsifies an unconditional R^2 interpretation. |
| RF5 | Private post-import context/seed controls and diagnostic backing retain their declared timing. | Thirteen prefix reconstructions agree. Native context, mutable-global initialization and backing ownership remain unknown. |
| RF6 | Original decoded pointers, sequential mutable globals and explicit PAC models define private execution. | All visits, reads, writes, PAC/CPU frames and both prefix/final RAM snapshots agree independently. Native authentication and concurrent epochs remain unknown. |
| RF7 | Cursor/stack arithmetic determines local frame accounting. | Sixty square-wrapper/child pairs match seed-dependent padding and cursor restoration; both wrapper layers emit zero adjustment. Native allocation/ownership is not inferred. |
| RF8 | The next unretained call and bounded zero stop define the investigation boundary. | Twelve profiles stop before 0x9819c4 -> 0x1142c08; zero stops after 64 subtraction returns. Whole-request completion, infinite execution and native transport are not inferred. |

## Records and recovered precomputation [RF1-RF6]

The encoded descriptor uses signed count s32(MEM32[D+4]-0x4b0cf050) and little-order u32 magnitude limbs decoded by XOR 0x1ac70ef2. The context controls have count 1 for positive n and count 0 for zero. Existing descriptor word +0 and payload pointers remain backing/representation context; their native capacity and ownership meanings remain unknown.

| Pair Q offset | Width | Recovered role on retained odd inputs |
| --- | --- | --- |
| +0x00 | 64 bits | Descriptor pointer for R mod n |
| +0x08 | 64 bits | Descriptor pointer for R^2 mod n |
| +0x10 | 32 bits | c=-n^-1 modulo R |

Child 0x14f8d28 and outer wrapper 0x14fac64 use record+0x08 for Q and record+0x10 for the modulus descriptor. Argument X1 points to a separate cursor cell. The [operand report](fpsd1201_operand_report.md) recovers their encoded entry control and the original inverse recurrence; the current complete returns establish the resulting descriptor roles.

For square record S and p=low32(S), the selected entry satisfies:

```text
H = ((p XOR 0x8b4ea7c9) * 0x0bcb7857) mod 2^32
MEM32[S] XOR H = 0xcb58
```

| Square record offset | Width | Role |
| --- | --- | --- |
| +0x00 | 32 bits | Encoded entry control |
| +0x08 | 64 bits | Modulus descriptor |
| +0x10 | 64 bits | Pair Q; its +0x10 word supplies c |
| +0x18 | 64 bits | Input descriptor x |
| +0x20 | 64 bits | Output descriptor |

Both square functions receive this 40 B prefix unchanged. All 60 retained invocations alias input and output. Distinct outputs, arbitrary partial overlap and wider moduli are not established by this increment. Return-register semantics are not assigned; the caller consumes record/cursor outputs.

The independent one-word arithmetic oracle is:

```text
T = x*x
m = ((T mod R)*c) mod R
t = floor((T + m*n)/R)
result = t-n if t >= n else t
```

For retained odd n this equals x^2*R^-1 modulo n, with the n=1 result defined as 0. All observed inputs satisfy 0 <= x < n. The literal recurrence also checks the even controls without assuming an inverse. It is a separate arithmetic oracle, not a supplied target result or an unrestricted proof of the multi-limb implementation.

## Reduction and five-square sequence [RF3-RF6]

The caller starts from scalar 1 shifted left by 32, copies n into a working descriptor and continues comparisons, subtraction and shifts. Its completed first output equals R mod n in all twelve positive controls. The repeated subtraction count varies with n; the earlier 50000-visit recorder limit was insufficient for small inputs and is replaced here by a declared 500000-visit limit. No target arithmetic result is injected to cross that limit.

The first square input equals 2R mod n. Five invocations then use the previous output as their next input. For odd n, the exponent recurrence e_next=2e-32 explains the second result:

```text
first descriptor: R mod n

second descriptor:
  2^33 mod n --square/R--> 2^34 --square/R--> 2^36
                                         --square/R--> 2^40
                                         --square/R--> 2^48
                                         --square/R--> 2^64 mod n
```

| n | Caller subtraction returns | Final first value | Final second value | Classification |
| --- | --- | --- | --- | --- |
| 0x1 | 33 | 0x0 | 0x0 | Odd complete return |
| 0x3 | 45 | 0x1 | 0x1 | Odd complete return |
| 0x5 | 43 | 0x1 | 0x1 | Odd complete return |
| 0x7 | 39 | 0x4 | 0x2 | Odd complete return |
| 0x0 | 64, then bounded stop | unknown | unknown | Zero control; no child return claimed |
| 0x2 | 32 | 0x0 | 0x0 | Even diagnostic control |
| 0x80000000 | 2 | 0x0 | 0x0 | Even diagnostic control |
| 0xfffffffe | 1 | 0x2 | 0x140aa03d | Even counterexample to unconditional R^2 |
| 0x11 | 39 | 0x1 | 0x1 | Odd complete return |
| 0x10001 | 16 | 0x1 | 0x1 | Odd complete return |
| 0xffffffff | 1 | 0x1 | 0x1 | Odd complete return |
| 0x80000001 | 1 | 0x7fffffff | 0x4 | Odd complete return |
| 0x7fffffff | 2 | 0x2 | 0x4 | Odd complete return |

For n=0xfffffffe the literal coefficient is 0x55555555, which is not a modular negative inverse. The final second value differs from R^2 mod n = 4. This is evidence for an odd-modulus precondition on the mathematical interpretation; it does not establish a native admission defect. For zero, all 64 retained subtraction-return checkpoints preserve modulus value 0 and first-descriptor value 1. Neither eventual return nor infinite execution is established beyond that finite boundary.

## Cursor wrappers and exact call boundaries [RF1,RF2,RF5-RF8]

| Call site | Original pointer slot | Target | IA modifier | Role |
| --- | --- | --- | --- | --- |
| 0x14fa518 | 0x1d04298 | 0x9dd7e4 | 0xb7d3 | Repeated square wrapper; five calls per positive profile |
| 0x9dd9d4 | 0x1d05a30 | 0x9dc6d4 | 0xde9d | Square implementation |
| 0x9819c4 | 0x1d056a0 | 0x1142c08 | 0x4032 | Next unexecuted caller dependency |

All selected rows have address diversity 0. Original copy, comparison, shift, subtraction and sign/zero dependencies remain executed code. Square wrapper 0x9dd7e4 passes the arithmetic record unchanged, redirects X1 to a private dynamic-stack cursor cell and calls 0x9dc6d4.

For incoming cursor seed s, all 64-bit operations wrap modulo 2^64. The raw cursor unit has unknown native meaning; the emitted adjustment is measured in bytes:

```text
mix = (s*0x2ecd + 1) mod 2^64
padding = 16*((mix >> 60)+1) B                 # 16..256 B
square-child entry SP = square-wrapper entry SP - 0x40 - padding
child cursor entry = s - 80; child restores it by adding 80
wrapper adjustment = 16*((u32(child_cursor_after)-u32(s)) mod 2^16) B
                   = 0 B
```

The child writes its cursor increment at 0x9dc808. The wrapper emits the 64-bit adjustment at 0x9dd9e4; caller 0x14fa524 adds it to SP. All 60 invocations match the seed-dependent frame geometry and emit zero. Initial cursor/global bytes are declared private fixtures; later seed values include original global-state writes. Their native initialization remains unknown.

The enclosing precomputation child also restores its separate incoming cursor epoch. It returns at 0x14f99e0 to outer wrapper 0x14fac64. That wrapper writes a zero adjustment at 0x14fae48 and returns at 0x14fae5c. All twelve positive profiles execute both returns. Local stack adjustment and arithmetic output are distinct channels; zero adjustment does not encode an authorization or operation-success verdict.

Every positive profile next stops before 0x9819c4 -> 0x1142c08. Root status remains diagnostic 0xa5a5a5a5 and the outer output seed remains preserved. Candidate P+0x880..P+0x8ff remains untouched. Complete request1201 payload production and return, actual endpoint/right ownership, native daemon/kext activity and deeper pairing remain unknown. No selected executed path emits a Mach right or invokes a Mach API; existing emission-site evidence remains in the [Mach-port report](mach_ports_report.md).

## Independent validation and bounded continuation

Thirteen profiles pass independent replay, covering twelve complete positive child/wrapper returns and one explicitly bounded zero control. The audit checks 1163611 original visits, 185439 reads, 61248 writes, 35672 PAC models, 41365 full CPU frames and 4752 family checkpoints. Prefix RAM and continued final RAM are checked separately at 1970176 B each. All thirteen predecessor imports, inverse recurrences, shifts, initial copies/comparisons and first-subtraction returns remain independently verified.

Principal-call oracles check 468 shifts, 127 raw copies, 1148 comparisons and 323 subtractions. The caller reaches 318 subtraction-return checkpoints, including 64 zero-control checkpoints. Sixty complete square implementations pass the literal one-word REDC oracle; 45 odd-modulus invocations additionally pass the modular-inverse oracle, while 15 even invocations remain separately classified. Nine complete odd profiles pass both R and R^2 results. Sixty square and twelve outer wrappers emit zero adjustment. Five retained UNSAT cursor/padding queries, five separately reconstructed obligations and 23 selected source instructions pass. Full arbitrary-size algorithm equivalence and native execution remain unproved.

| Impact | Bounded continuation / context | Probe and current boundary |
| --- | --- | --- |
| High | Recover the 0x1142c08 record and complete subsequent operand consumer. | Follow original reaching definitions from the new unexecuted call; request1201 input consumption and full return remain open. |
| High | Establish source-produced modulus and admission invariants. | Trace context writers and validation for positive, odd, canonical counts. Zero/even diagnostic outcomes do not prove native admission. |
| High | Connect complete precomputation to real IPC and daemon/kext lineage. | Match session, endpoint, payload, status and ownership identities across actual consumers and transport evidence. No native join is supplied by local arithmetic. |
| Medium | Extend the square contract to wider moduli and independent destinations. | Recover loop bounds, capacity and source-normalization invariants before interpreting multi-limb behavior. Current oracles cover one-word in-place calls. |
| Medium | Establish native cursor/global initialization and concurrent epochs. | Trace initializers and source lifetimes; diagnostic RAM and sequential original writes are explicit environmental controls. |
| Low | Prove complete bounded reduction/square loops. | Current universal cursor identities and finite whole-call results remain separate evidence classes. |

Quality gates: **QG1** no normative content is required. **QG2** RF1-RF8 state assumptions, dependent results and probes. **QG3** routine roles, data/control flow, record/call ABIs, external/environmental controls, stack channels, port consequences and continuation are covered. **QG4** B denotes bytes; limbs are 32 bits; R=2^32; u32/u64 operations, cursor units and the exponent recurrence are reproducible. **QG5** odd/even/zero distinctions, finite bounds, tested aliases and native/equivalence limits are explicit. **QG6** primary binary bytes, original pointer rows, independent source parsing/replay and separate arithmetic oracles support claims. **QG7** impact-ranked expansion remains bounded. The full investigation remains active.

## CoreFP1201 post-precomputation consumer handoff

The [consumer handoff continuation](fpsd1201_consumer_report.md) resumes the twelve positive checkpoints through 0x9819c4 -> 0x1142c08 and stops before 0x114245c -> 0x74fd0c. It establishes subsequent records and cursor staging while preserving this report's bounded zero/even classifications and native-evidence limits.
