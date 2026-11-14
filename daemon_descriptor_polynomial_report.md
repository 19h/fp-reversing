# Descriptor polynomial and conditional 77-byte allocation request

The source block at `0x100bd9408..0x100bd9534` evaluates a degree-ten polynomial over u32 arithmetic. Its argument is the preceding encoded-node walk's XOR accumulator. Obfuscated square and parity operations reduce to `power*=argument` and `sum+=coefficient*power`, modulo 2^32. This identifies the local arithmetic function; a conventional checksum, cryptographic primitive, complete helper identity or native acceptance policy remains unknown. [DP1-DP5; DP-A1-DP-A5]

With a separately supplied initializer-compatible terminal node, the walk produces argument `0xd2b92e63`; the polynomial evaluates to zero. Four new 5,151-instruction continuations cover all 152 inherited states and reach `0x100d640ac` before a 77 B `libSystem/_malloc` request. The model supplies no allocation result and executes no target API. Actual initializer/current-caller epoch continuity remains unknown. [DP2-DP5; DP-A2-DP-A5]

```text
152 inherited conditional walk exports, 104 B root definitions each
  + 12 B terminal-node fields, separate premise; 4 B gap undefined
  -> one node contribution b5caf0c6, next=0
  -> XOR argument d2b92e63
  -> 11-term u32 polynomial, result=0
  -> further original control flow and one internal helper call
  -> encoded extent: observed 57 B -> requested 77 B
  -> STOP before BLRAA at 100d640ac, libSystem/_malloc, IA 6aa4

No malloc return, replacement buffer or external IPC emission is modeled.
```

| Evidence | Primary artifact and scope |
| --- | --- |
| DP1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; retained source words, coefficient bytes and original authenticated pointer records. |
| DP2 | [Walk report](daemon_descriptor_walk_report.md), [walk checks](triage_evidence/daemon_descriptor_walk_checks.json.zst), [walk replay](triage_evidence/daemon_descriptor_walk_replay.json.zst) and [initializer report](daemon_constructor_descriptor_report.md) qualify the inherited states and separately recovered producer format. |
| DP3 | [Extractor](triage_evidence/recover_daemon_descriptor_polynomial.py) and [checks](triage_evidence/daemon_descriptor_polynomial_checks.json.zst): explicit node premises, four new intervals and 152 member-specific terminal exports. |
| DP4 | [Independent auditor](triage_evidence/replay_daemon_descriptor_polynomial.py) and [receipt](triage_evidence/daemon_descriptor_polynomial_replay.json.zst): full replay, admissions, source obligations, exact ring normalizations and polynomial iteration checks. |
| DP5 | [Publication verifier](triage_evidence/verify_daemon_descriptor_polynomial_publication.py): fresh complete replay/proof reconstruction, original-word checks, exact manifest delta, original-input preservation and decoded path hygiene. |

## Entry premises and node consumption

The node address is `b=0x6800060ae0=outer_SP+0x9e0`. The new entry defines only the following fields; neither is inferred to exist in the native daemon. [DP2-DP4; DP-A2]

| Field | Separately supplied bytes / interpretation |
| --- | --- |
| b+0 / 4 B | `a6fbd0b5`, little-endian `u32(b+0xb5caf0c6)` |
| b+4..b+7 / 4 B | Undefined; no new read, write or incoming demand overlaps this gap |
| b+8 / 8 B | `e00a060068000000`, little-endian q=b, hence decoded next=q-b=0 |

These fields match the separate aligned initializer with decoded input word zero. The current initializer epoch is unjoined. The inherited 104 B of conditional roots plus 12 B of new node fields give **116 B of conditional entry definitions per parent**; the new node bytes are not additional root fields. No second node or allocation-return premise is introduced. [DP2-DP5; DP-A2-DP-A4]

The first node step computes `u32(word-low32(q))=0xb5caf0c6`, hence `0x6773dea5 XOR 0xb5caf0c6=0xd2b92e63`. Cursor 1 increments to 2, and the zero-next condition selects the source exit into the polynomial block. These are conditional execution results for this declared node; other actual descriptor contents remain unknown. [DP2-DP4; DP-A2-DP-A3]

## Compact polynomial contract

At this block's entry, W9=sum=0, W15=power=1, W10=argument, X12=10 and X11=0. The phase sets W8=`(0 XOR 7)*0x14fe=0x92f2`. The body preserves the argument, zero comparator, pool/table roots and mutable selector-root addresses, and performs no memory stores. Its compact equivalent is: [DP1, DP3-DP4; DP-A3-DP-A4]

```text
sum = 0; power = 1
for index = 10 down to 0:
    sum   = u32(sum + C[index]*power)
    power = u32(power*argument)
return sum                         # local arithmetic result W9

P(a) = u32(sum(C[10-j]*a**j for j=0..10))
```

The coefficient base is `0x100eee6f0`, spanning 44 B. The original source resolves it through inherited mutable selector values `0x3b4adb7c` at `0x1010c4eb8` and `0x031150f4` at `0x1010c4670`, two byte banks, and chained-rebase slots `0x1010a7a50`, `0x1010a3ba0`, `0x1010a83b0`. The mutable values differ from initial-image bytes; they are phase inputs. All eleven source resolutions select the same bank in each continuation. Other root states' selections remain unknown. [DP1, DP3-DP4; DP-A1-DP-A4]

| C index | Original address | u32 coefficient | Power of a |
| --- | --- | --- | --- |
| 0 | `0x100eee6f0` | `0x00000001` | 10 |
| 1 | `0x100eee6f4` | `0x79abd8f8` | 9 |
| 2 | `0x100eee6f8` | `0xe7d8eeb8` | 8 |
| 3 | `0x100eee6fc` | `0xf49094b4` | 7 |
| 4 | `0x100eee700` | `0xefaba0b6` | 6 |
| 5 | `0x100eee704` | `0x3648e94c` | 5 |
| 6 | `0x100eee708` | `0x38ea9d4c` | 4 |
| 7 | `0x100eee70c` | `0x7f84c8ec` | 3 |
| 8 | `0x100eee710` | `0x7df6dbe1` | 2 |
| 9 | `0x100eee714` | `0x8330fe1c` | 1 |
| 10 | `0x100eee718` | `0xfa5ed964` | 0 |

For t=`u32(power*argument)`, the source forms h=`ASR32(t,1)` and parity bit r. Because `t=u32(2*h+r)`, its square expression `(h+k)^2-h^2+k*r` equals `u32(k*t+k^2)`, where k=`0x03c473bb`. Multiplication by `0x054c5973` and addition of `0xfc3b8c45` recover t: the multiplier is k's inverse modulo 2^32 and the additive terms cancel exactly. The proof retains the ASR/parity obligation, two original-source square normalizations and the composed original affine update. [DP1, DP4-DP5; DP-A3-DP-A4]

For coefficient z and old power s, the source's sum increment is `odd(s)*z+odd(z)*s+(z&0x7ffffffe)*(s&0xfffffffe)-odd(s)*odd(z)`. Dropping z's high bit from a product with the even component of s has no effect modulo 2^32. Four exact parity-case ring expansions then give z*s. Source-expression matching, even/parity decomposition, mask splitting and the discarded-bit product are separate checked obligations. This composed proof does not claim a monolithic nonlinear SMT equivalence result. [DP1, DP4-DP5]

| Countdown condition | Table index / original slot | Original target / logical authentication |
| --- | --- | --- |
| Old X12 != 0 | `0x77ec` / `0x101075e50` | `0x100bd9408`; IA `0x0957`, address diversity 0 |
| Old X12 == 0 | `0xaefd` / `0x1010916d8` | `0x1009e4018`; IA `0x0957`, address diversity 0 |

The source decrements X12, copies the new power to X15 and branches through X0 at `0x100bd9534`. Initial counter 10 gives exactly eleven passes, ten back edges and one exit; the final counter wraps to `0xffffffffffffffff` after selecting the exit. In the supplied-node continuation, every power and partial sum agrees with the compact algorithm, P(`0xd2b92e63`)=0, and final power=`0x4f26eb1b`. This establishes local value computation; its complete acceptance/error meaning remains unknown. [DP1, DP3-DP5; DP-A3-DP-A5]

## Buffer-related continuation and allocation frontier

The subsequent original path calls `0x10045f984` from `0x1009d0fc8` with logical IA `0x0290`. X0 is the private local record `0x6800060028` and X5 is U=`0x6600060000`. The retained call arguments and full instruction frames establish this local call interface; a complete function name or native object type is not assigned. The source returns from that call before reaching the allocator frontier. [DP3-DP4; DP-A4-DP-A5]

| Quantity / source location | Established phase value or equation |
| --- | --- |
| Prior encoded extent W22/W23 | `0x10ecc44a`; `u32(raw+0xef133bef)=57` B |
| Extent-update entry at `0x100c05638` | W8=`0x74c239e7`, W21=`0x4c`, W22=old raw extent |
| Source `0x100c05638..0x100c05648` | New raw=`u32(old_raw-0x74c239e7+0x4c+0x74c239af)=u32(old_raw+20)` |
| Current new raw W8 | `0x10ecc45e` |
| Allocator phase W10 at `0x100d64014` | `0xc4eb`; derives W25=`0x9436`, W28=`0xa10b` |
| Source `0x100d64024..0x100d64050` | X0=`zero_extend64(u32(new_raw+0xef133bef))=77` B |
| Pending import load | `0x100d640a4` reads original authenticated bind slot `0x10109ff58` |
| Pending emission site | `0x100d640ac`: `BLRAA X8,X17`, `libSystem/_malloc`, IA `0x6aa4`, address diversity 0 |

The two extent equations are proved for every u32 raw extent under their separately stated recovered phase constants. They describe modulo-2^32 counts; they do not assert that arbitrary inputs describe valid native allocations. The pending import pointer retains its exact original-slot origin across replay. The model address `0x7c009800` represents the import and is not a native allocator address. [DP1, DP3-DP5; DP-A3-DP-A5]

S/64 B, U/48 B, F/57 B and J/552 B preserve their inherited bytes and unknown-byte masks in all 152 exports; no new interval store overlaps them. The prior buffer F is still 57 B. A requested count of 77 B does not establish successful allocation, ownership transfer, replacement, payload copying, file emission or a Mach/IOKit message. No new incoming/outgoing Mach-port name, transferred right or external transport emission is established. [DP3-DP5; DP-A4-DP-A5]

## Verification and assumptions

Four classes of sizes 68/68/8/8 each execute 5,151 original instructions: 20,604 total, 2,224 reads, 780 writes, 400 logical edges and four internal calls. Full independent replay checks 659,456 GP/SP values, 659,456 Q values, 20,608 NZCV frames, 11,132 read bytes, 4,372 write bytes and 396 authenticated pointer edges; four return edges account for the remaining logical edges. All 152 admissions check 167,032 incoming byte demands and 3,192 incoming register demands. Sixteen missing/changed node-field controls, four changed-SP controls and four changed-owner controls are rejected; four unused-Q0 preservation controls pass. Nine nonvacuous source queries are UNSAT and seven exact ring normalizations have zero remainder. [DP3-DP5]

Time is O(visits*frame state + parents*demands + proof DAG), excluding solver search complexity and publication input I/O. Storage is O(receipts + parent maps + largest interval + proof DAG). The compact polynomial takes O(n) time and O(1) working storage for n=11 coefficients. Counts, exponents and indices are dimensionless; addresses, offsets and field/buffer extents are bytes. Arithmetic wraps at explicit u32/u64 widths; no native ASLR mapping is inferred. Receipts are published using `zstd --ultra -22 -q -T1` and decoded round-trip checks. Retained primary evidence suffices; IDA is not accessed. [DP1-DP5]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| DP-A1: Pinned image, fixups, inherited states and dependencies apply | Source semantics, tables and logical targets | Check hashes, all visited source words, original coefficient bytes, pointer-format fields and exact parent receipts. |
| DP-A2: Twelve new node bytes are explicitly conditional entry definitions | Terminal-node execution and pending allocator path | Reject missing/changed word/q bytes; retain undefined gap, unjoined initializer epoch and absence of malloc-return input. |
| DP-A3: The admitted phase, selector values and register constants apply | Polynomial, eleven-pass bound and extent equations | Check all 152 demands/exports, every power/sum/coefficient load, phase anchors and source invariants; test full-width source obligations and ring identities. |
| DP-A4: Sequential instruction semantics and logical pointer authentication apply | Numeric replay, no-overlap statements and pending call target | Independently replay complete frames and effects; carry original pointer custody from the parent prefix; native PAC, scheduling and mutation order remain unknown. |
| DP-A5: Local arithmetic/interface evidence does not determine complete native identity | Function naming, allocation and cross-layer interpretation | Require actual initializer/ownership/lifetime evidence, allocation results, subsequent buffer uses and real Mach/IOKit transaction joins. |

| Impact | Bounded next evidence | Present limit |
| --- | --- | --- |
| High | Recover the pending allocation's NULL/success paths and requested-byte uses | Neither allocator return nor any 77 B owner is supplied here. |
| High | Trace polynomial result consumers to the helper's complete return contract | P(a)=0 is established for the conditional node; native acceptance/error policy remains unknown. |
| High | Establish the actual initializer epoch and descriptor chain provenance | The node fields agree with a separate producer; native existence and lifetime remain unknown. |
| High | Join U/F/local-record identities to actual daemon-kext IPC buffers | No new Mach port, right transfer or native transaction pairing is established. |
| Medium | Recover other selector-root phases and coefficient-bank domains | The present coefficient bank is qualified by inherited mutable selector values. |

**QG1**: factual source and ABI analysis. **QG2**: DP-A1-DP-A5 state dependencies and falsification probes. **QG3**: this polynomial/allocation-frontier increment is covered; the full interface goal remains active. **QG4**: widths, byte extents, arithmetic, counts and complexity are explicit. **QG5**: separate node premises, mutable roots, composed proofs and pending allocation are distinguished. **QG6**: fresh complete replay, exact admissions, source proofs, ring normalizations, fixups and publication checks qualify primary evidence. **QG7**: impact-labeled adjacent interfaces and unknowns are explicit.
