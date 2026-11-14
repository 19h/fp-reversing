# fairplayd: halfword reader, scalar increment and regenerated field

The earlier writer of the scalar-2 stack cell is now established in retained source journals. The reader at `0x100ae22e0` decodes old buffer F+15, whose stored bytes `56ee` represent scalar **1**. The arithmetic at `0x100d7ef80` prepares that scalar's increment; `0x100a68318` stores **2** at `0x680005fe24`. The consumed two bytes survive the allocation/free continuations and become the scalar later encoded at H+15 as `60b3`. This resolves the immediate scalar-cell provenance left open by the [halfword report](daemon_packed_halves_report.md). Native field names, admission and daemon-kext buffer identity remain unknown. [HU1-HU5; HU-A1-HU-A5]

The new evidence joins existing journals without adding a target interval, guest input, owner, root definition or API-return premise. Four source classes retain the earlier read/update; 152 exported cell values and the two later growth classes establish the scalar's conditional model custody. Their 304 non-NULL members use pinned prior admissions, which are not rerun. [HU2-HU5]

| Evidence | Primary source and scope |
| --- | --- |
| HU1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; exact reader/update instructions and authenticated dispatch slots. |
| HU2 | [Polynomial checks](triage_evidence/daemon_descriptor_polynomial_checks.json.zst), decoded SHA-256 `a43e977f7a9b786f44427b67e8152ba8e64ad940014c6cf821a800b9479b60c6`, and [replay](triage_evidence/daemon_descriptor_polynomial_replay.json.zst), `7acd16ed49134447d3588f8c2d4a00b0adfb0cd734217f8b939af82d03fd954c`; [growth checks](triage_evidence/daemon_descriptor_growth_checks.json.zst), `b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2`, and [replay](triage_evidence/daemon_descriptor_growth_replay.json.zst), `bee4ab3224710559fefdd8bca070110e48c03ab52d01c92b617988b9b3d5bd67`; [halfword checks](triage_evidence/daemon_packed_halves_checks.json.zst), `12d8bf65c7c1140e5a842764cc68e850eccbdc7a6075304059ec01f8f8ca7fe4`, and [audit](triage_evidence/daemon_packed_halves_audit.json.zst), `1a0bf1c95a128654d1e20469bd88c710f7871fef0d5b9853c0635b6fe8de3f53`. |
| HU3 | [Extractor](triage_evidence/recover_daemon_halfword_update.py) and [checks](triage_evidence/daemon_halfword_update_checks.json.zst): four reader/update classes, 152 exported u32 values and two later field joins, including byte-level overwrite/invalidation checks. |
| HU4 | [Independent auditor](triage_evidence/audit_daemon_halfword_update.py) and [receipt](triage_evidence/daemon_halfword_update_audit.json.zst): 43 nonvacuous UNSAT obligations, sixteen exact u16 ring normalizations, three SAT controls and fresh selected replay. |
| HU5 | [Publication verifier](triage_evidence/verify_daemon_halfword_update_publication.py): fresh extraction/audit, query/normalization checks, exact manifest delta, input preservation and decoded path hygiene. |

## Reader contract and writer inverse

Let o be the u32 byte offset, B the u64 buffer base and m(o) the existing two-byte writer mask. The fixed source interface uses SP=`0x680005fb70`, D/E/K bank pointers and bytes from the [append-field contract](daemon_append_fields_report.md), phase word `0xabb1` at SP+0xf4 and the buffer-pointer cell reached through SP+0x268. Input bytes must be readable and disjoint from those fixed bank/pointer/phase cells so their symbolic values describe coherent memory. [HU1-HU4; HU-A2]

```
stored0 = byte[B + zero_extend64(o)]
stored1 = byte[B + zero_extend64(u32(o+1))]
V = BE16(stored0 XOR m0(o), stored1 XOR m1(o)) XOR 0x534c
n = V >> 12
D = V AND ((1 << n) - 1)
reader_exit_W8 = zero_extend32(D) XOR 0x7390
```

The byte-reader inverse covers every u32 offset, u64 base and pair of input bytes under these premises. Sixteen low-offset partitions retain symbolic upper 28 bits, including u32 offset wrap for the second byte. The arithmetic decoder handles every 16-bit V, including count nibble 0. Its interpretation as an inverse of the earlier producer's scalar field requires the producer bounds `1 <= n <= 12` and `D < 2^n`. No native memory validity or admission claim follows. [HU4; HU-A2-HU-A3]

| Original source interval, end exclusive | Composed contract |
| --- | --- |
| `0x100ae22e0..0x100ae2398` | Read the buffer pointer, two bytes and D/E/K banks. The low bytes of W10/W8 form V after undoing the writer masks and XOR. Upper temporary bits are not assumed to be zero. |
| `0x100ae2398..0x100ae23c0` | Assemble low16(W10:W8); low16(W8) becomes `V XOR 0x8cc9`, and low16(W9) becomes V. |
| `0x100ae23c0..0x100ae2478` | Recover shift `s=16-n`, with 1..16 possible values. |
| `0x100ae2478..0x100ae248c` | Form `u32((0x433fd6d7 << (s&31))*low16(W9))`. |
| `0x100ae248c..0x100ae24c0` | For input product x, W10 becomes `(x*0x7ce7)&0xfffe`; W9 becomes phase `0x59aa`. |
| `0x100ae24c0..0x100ae24dc` | Recover `D XOR 0x7390` from the normalized shifted payload; W16 becomes `0x7390`. |

For each of sixteen shifts, the exact modulo-2^16 identity is `V*((0x433fd6d7<<s) mod 2^16)*0x7ce7 = V*2^s`. The normalized value has bit 0 clear because s>=1, so the source's `&0xfffe` loses no further bit. Right shifting by s leaves the low n scalar bits. Each coefficient difference normalizes to the exact 16-bit zero; each original extraction tail is separately proved for its count nibble. These are explicit composed proofs, not a monolithic decoder SMT claim. [HU4]

The fragment obligations also check the carried phase interfaces: W14=`0xabb1` through assembly/count/product, W9=`0x59aa` through scalar extraction, W16=`0x7390` and the raw low halfword through increment preparation, and W11 through the gate/dispatch. These preserved values are explicit composition checks. [HU4]

## Increment, branch and concrete data flow

With the recovered W9 phase `0x59aa`, the arithmetic at `0x100d7ef80..0x100d7efec` transforms encoded input H into `W11=zero_extend32(low16(H) XOR 0x7390)-0x7390`. If the subsequent store block is reached, its addition of `0x7391` writes `zero_extend32(D)+1` as a four-byte value at SP+0x2b4. The retained W11 is unchanged between the arithmetic exit and that addition. [HU1, HU3-HU4; HU-A3]

The intervening source gate distinguishes D=0 from D!=0. Therefore this report establishes an increment/store on the retained nonzero path; it does not claim unconditional read/modify/write behavior for every decoder input. [HU4]

| Predicate | Original index / slot | Selected target | Logical authentication |
| --- | --- | --- | --- |
| D != 0 | 0x59aa / `0x101066c40` | `0x100a682e4`, retained store route | IA diversity 0xfd0f, address diversity 0 |
| D = 0 | 0x6732 / `0x10106d880` | `0x100a6e76c`, separate route | Same |

Original pointer-format-12 records and source `BRAA X9,X17` at `0x100d7f008` qualify both targets. All four retained nonzero edges match the first slot. The zero route's later effects, native relocated pointer values and hardware authentication remain unknown here. [HU1, HU3-HU4; HU-A1-HU-A3]

| Stage | Exact local representation |
| --- | --- |
| Old owner F, offsets 15/16 | Read stored bytes `56ee` at `0x660007000f/0x6600070010`. |
| Undo writer mask / XOR | `56ee XOR 1c95 = 4a7b`; `4a7b XOR 534c = 1937`. |
| Decode old V=0x1937 | Count 1, scalar 1, retained auxiliary value 0x49b. |
| Reader exit | W8=`0x7391` = `1 XOR 0x7390`. |
| Increment preparation | W11=`0xffff8c71`; source addition `u32(W11+0x7391)=2`. |
| `0x100a68318` | Store `02000000` at `0x680005fe24`, four bytes. |
| Later `0x1009a308c` | Read low two bytes `0200`; scalar preparation encodes K=`0x0dfa`. |
| Regenerated H+15 | Scalar 2, count 2, auxiliary value 0x3da; V=`0x2f6a`, mixed halfword `0x7c26`, stored bytes `60b3`. |

This is regeneration with the established later auxiliary input, rather than a claim that all old packed bits survive. The native semantic name of D is unknown. The evidence supports a scalar increment and field replacement; it does not establish a record-count, version-number or transaction-counter type. [HU2-HU4; HU-A5]

```
F+15: 56ee -> undo masks/XOR -> V=1937 -> scalar 1
                                                   |
                                 nonzero branch -> +1
                                                   |
                                  u32 stack cell = 2
                                                   |
             polynomial export -> malloc/free premises -> growth journals
                                                   |
                                      u16 stack read = 2
                                                   |
                 later auxiliary bytes -> producer -> H+15: 60b3
```

The four earlier classes have 68/68/8/8 cohort members. All 152 polynomial exports contain the exact four stored bytes. Their last relevant source write is `0x100a68318`. The later non-NULL growth classes have 272/32 inherited members and use polynomial classes 0/1 and 2/3, respectively. Across their four representative intervals and declared API invalidation lists, neither consumed byte is overwritten or invalidated before the later read. This checks byte custody across existing interval boundaries; the full admission, allocation and byte-writer corpora are not rerun. [HU2-HU4; HU-A4]

## Width bounds and interpretation controls

For every possible V, the reader's count nibble is 0..15, hence D<=32767. The composed proof establishes that `D+1` survives the subsequent u16 read exactly. A hypothetical loss at 65535+1 is outside this reader's output range. This source bound does not establish a broader native admission policy. [HU4]

| SAT control | Verified arithmetic / control result | Evidence limit |
| --- | --- | --- |
| Maximum decodable D=32767, V=0xffff | u32 increment and later u16 read both equal 32768. | This packed value lies outside the producer's guaranteed 12-bit scalar format; native admission is unknown. |
| Largest canonical scalar D=4095 | Increment gives 4096; the later minimum bit count would be 13. | The increment can leave the guaranteed producer format domain; intervening caller acceptance is unknown. |
| D=0 | Original gate selects index 0x6732 and target `0x100a6e76c`. | The retained nonzero store route cannot be generalized to zero. |

These controls distinguish the source bound, the narrower writer-format bound and the conditional store route. They introduce no target input and establish no externally reachable defect. [HU4; HU-A3-HU-A5]

## Verification and assumption register

Fresh selected replay checks **656 original instructions**, twelve spans, 21,376 GP/SP values, 668 NZCV frames, 60 reads, eight writes and four logical edges. The 43 nonvacuous UNSAT obligations comprise sixteen byte-reader offset partitions, four assembly/count/product contracts, sixteen scalar-extraction tails, increment/store/gate contracts, two dispatch contracts, the paired scalar inverse and the composed increment-width bound. Sixteen exact ring normalizations and three SAT controls pass. Fresh export checks cover 152 u32 cell values, totaling 608 B; two subsequent field joins use the existing 304-member admission scope. [HU3-HU5]

Time is O(parent receipt bytes + selected visits*32 + exports*state bytes + custody scans + proof DAG); storage is O(parent receipts + selected evidence + proof DAG). Solver search is separate and bounded at 30 s/query. Arithmetic widths are u32/u64 with explicit u16 projections; count fields and scalar values are dimensionless, and storage extents/offsets use B. JSON archives use `zstd --ultra -22 -q -T1` with decoded round-trip checks. [HU3-HU5]

No new Mach name, right disposition, emission site or native daemon-kext transaction is established. Pending malloc97, the NULL-route undefined S+0x30 frontier and the separate initializer/caller epoch remain unresolved. No native target API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation executes. The retained reference data suffice for this increment. [HU2-HU5; HU-A5]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| HU-A1: Original image, dependencies and pinned journals apply | Concrete values, replay and dispatch metadata | Verify hashes, source words, original authenticated rebases and fresh exact extraction. |
| HU-A2: Fixed reader banks/phase and readable coherent input cells apply | Universal byte-reader inverse | Keep upper offset bits symbolic across all sixteen residues, include u32/u64 wrap, and exclude overlap with fixed pointer/bank/phase cells. Replay every retained source read. |
| HU-A3: Fragment interfaces and observed nonzero route apply | Scalar decoder, increment/store and branch interpretation | Prove all sixteen count-nibble tails, exact ring reductions, the full decoded-value bound, the original zero gate and both dispatches. Do not substitute an arbitrary u16 scalar for the decoder's bounded output. |
| HU-A4: Pinned export/admission and API invalidation semantics apply | Cross-interval custody into H+15 | Check all 152 exported u32 values and every representative growth write/invalidation overlapping the two consumed bytes; map each admitted cohort to its earlier source class. |
| HU-A5: Local read/update does not establish native field identity or reachability | Native meaning, admission, caller epoch, ownership and transport | Require actual initializer/caller and complete native transaction joins; trace the zero route and any admission gates before extending the behavior claim. |

| Impact | Bounded continuation | Current evidence limit |
| --- | --- | --- |
| High | Recover the earlier producer of old F+15 and its native semantic role | Paired reader/writer scalar inverse and current 1->2 transition are established. |
| High | Establish the zero route and intervening admission/capacity gates | The original zero target is known; its complete effects are not covered here. |
| High | Join regenerated fields and the pending next allocation to native daemon-kext buffers | Only conditional local custody is established; no new native transaction. |
| Medium | Compare other reader phases and bank families | This inverse explicitly depends on the current bank/phase interface. |

**QG1**: factual technical analysis. **QG2**: HU-A1-HU-A5 state dependent results and falsification probes. **QG3**: the scalar read/update/custody increment is covered; the full interface goal remains active. **QG4**: widths, exact source counts, units and complexity are explicit. **QG5**: decoder bounds, writer-format bounds, conditional control flow, prior admissions and native unknowns are separated. **QG6**: primary bytes/fixups, fresh selected replay, composed proofs, ring reductions and publication checks establish provenance. **QG7**: adjacent interfaces and limits have impact labels.
