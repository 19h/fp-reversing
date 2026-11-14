# fairplayd: constructor extent/header coupling and earlier word producer

The constructor changes its decoded allocation extent by **operand minus old header scalar**. Its new header scalar is **operand plus old header minus saved header**. When the register and saved header copies agree, the new header becomes the operand and the numeric difference between allocation extent and header is preserved. The retained 21 B -> 57 B constructor instance therefore preserves its original gap of one: header 20 -> 56. This establishes a source-level relationship beyond the previous snapshot correlation; the native field name and native buffer identity remain unknown. [EH1-EH5; EH-A1-EH-A6]

The earlier four-byte producer at `0x100618764` also reduces to the recovered count/scalar/auxiliary format. Its writer at `0x1006bd140` uses the common periodic scalar mask. These results qualify local representation and allocation arithmetic; no additional Mach port, right disposition, emission site or daemon-kext transaction is established. [EH1-EH6]

| Evidence | Primary source and scope |
| --- | --- |
| EH1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; exact selected original instruction bytes are retained in EH3. |
| EH2 | [Constructor checks](triage_evidence/daemon_constructor_buffer_checks.json.zst), decoded SHA-256 `fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07`; [replay](triage_evidence/daemon_constructor_buffer_replay.json.zst), `61f012a43cbae9cf2ff8a5207603a30b9bbf82c7b2d92811e0c1a2ff7505c107`; [audit](triage_evidence/daemon_constructor_buffer_audit.json.zst), `47108bdf5bedbb6a9aec1397ae777d6317a689cdea625638da5fb94a3c86e252`. These qualify the inherited owner, ABI and admission premises; their full corpora are pinned, not rerun. |
| EH3 | [Extractor](triage_evidence/recover_daemon_constructor_extent.py) and [checks](triage_evidence/daemon_constructor_extent_checks.json.zst): four prefix classes, eight successful continuation classes, source slices and custody joins, and 152 freshly decoded successful export headers. |
| EH4 | [Independent auditor](triage_evidence/audit_daemon_constructor_extent.py) and [receipt](triage_evidence/daemon_constructor_extent_audit.json.zst): 27 nonvacuous UNSAT obligations, two SAT interpretation controls and independent selected source replay. |
| EH5 | [Scalar serialization checks](triage_evidence/daemon_scalar_serialization_checks.json.zst), decoded SHA-256 `93e4930867d43d4daf701fca44736ccac31ff8a678e2df479a792669b243e017`; [audit](triage_evidence/daemon_scalar_serialization_audit.json.zst), `7896c81d547255b4e2b63e17ea39b5e370b2c5b65c2a0ea1d9a2b0fe80add001`; [report](daemon_scalar_serialization_report.md). These qualify the prior reader/decoder, common mask and 532 snapshot comparisons. |
| EH6 | [Publication verifier](triage_evidence/verify_daemon_constructor_extent_publication.py): fresh extraction/audit, canonical query comparison and solver checks, exact manifest delta, original input preservation and decoded path hygiene. |

## Allocation and header equations

Let p be the old decoded scalar in W20, q its decoded saved copy, a the caller operand, r the old raw extent word, and C the decoded allocation extent. All expressions below operate modulo 2^32. The malloc argument is the zero-extension of the resulting u32 count into X0. Scalar operands are numeric u32 values; the allocation count measures bytes. Assigning a byte-offset or used-length type to p/a still requires native schema evidence. [EH1-EH4; EH-A2-EH-A3]

```
C  = u32(r + 0xef133bef)
r' = u32(r + a - p)
N  = u32(r' + 0xef133bef) = u32(C + a - p)
D' = u32(a + p - q)
K' = D' XOR 0x8b3dc651

if p == q:
    D' = a
    u32(N - D') = u32(C - p)
```

| Source interval, end exclusive | Interface / proved reduction |
| --- | --- |
| `0x100709a64..0x100709ad4` | W14=`0x6cf4`, W20=`p XOR 0x8b3dc651`, W8=r, u32 a at SP+0x312c; stores r' at SP+0x3b80. |
| `0x10083dd08..0x10083dd10`, then `0x10083dd18..0x10083dd20` | Fixed W25/W26/W9/W12 phase `0x5f29/0x9717/0x37ee/0xef1233cf`; X0=`zeroExtend64(u32(raw+0xef133bef))`. The two intervening table-load instructions do not supply this count arithmetic. |
| `0x1006886ac..0x100688778` | u64 phase `0x6cf4` at SP+0x9d0; W20 encoded p, a at SP+0x312c and encoded q at SP+0x70b4; produces W8=a, W11=`p+0x74c239af`, W12=`q+0x74c239af`. |
| `0x100688778..0x1006888d8` | Arbitrary u32 inputs W8=a, W11=u, W12=t; W23=`u32(a+u-t) XOR 0x8b3dc651`. |

These separate universal source contracts compose into the equations above. The earlier fixed-p reduction `r+a-20` is their retained p=20 instance. Treating a as an append byte count would omit the subtraction of the old header. The source establishes a as the requested new header scalar under copy agreement; whether that scalar denotes a last-byte offset, used extent or another native quantity is unknown. The modular invariant does not itself prove absence of wrap or native acceptance. [EH2-EH4; EH-A2-EH-A3]

| Interpretation control | Old C / p / q / a | New N / D' | Established limit |
| --- | --- | --- | --- |
| Nonunit gap | 24 / 20 / 20 / 56 | 60 / 56 | Gap four is also preserved; a unit gap is not unconditional. |
| Unequal saved copy | 21 / 20 / 21 / 56 | 57 / 55 | Header-copy agreement is material to D'=a and gap preservation. |

Both controls are SAT checks of the equations, without admitted target states or native acceptance claims. [EH4; EH-A3]

## Earlier packed-word producer and writer

For raw auxiliary W19=A, encoded scalar K read from SP+0xab28, and u32 count n read from SP+0xab2c, the composed source contract is: [EH1, EH3-EH5; EH-A2-EH-A4]

```
R = A XOR 0x6703cce9
D = K XOR 0x8b3dc651
V = u32(((u32(R << (n&31)) AND 0x07ffffff) OR u32(n << 27)) + D)
producer_exit_W12 = V XOR 0xc12b4f72
caller_exit_W12   = V XOR 0xe4b5bf34
stored[j] = BE_bytes(V)[j] XOR M[(o+j)&15], j=0..3
M = d9 8c 93 17 49 8b 22 11 82 b3 19 85 70 dd 90 4f
```

| Source interval, end exclusive | Proved composition component |
| --- | --- |
| `0x100618764..0x100618880` | W8=`packed_high+0xe0d06e54`, where packed_high is the auxiliary/count portion of V. |
| `0x100618880..0x100618960` | W8=`input+(K XOR 0x8b3dc651)+0x7d9e4176`; entry X13=SP+0x9000. |
| `0x100618960..0x100618c18` | Composed W12=`(input-0x5e6eafca) XOR 0xc12b4f72`, using the cancellation cut below. The prior two biases sum to `0x5e6eafca` modulo 2^32. |
| `0x100615414..0x100615420` | Caller XOR converts `0xc12b4f72` to `0xe4b5bf34`. |
| `0x1006bd150..0x1006bd294` | Source scratch-base store followed by four byte stores using the common mask; sixteen offset-residue obligations prove values and actual addresses. |

The final producer reduction uses an explicit source cut. Four instructions at `0x100618b5c..0x100618b6c` generate a quotient in X11 and have no other destination or memory effect. The next five instructions prove, for arbitrary u32 quotient z and word w: [EH4]

```
u32(z*0x3000 + (w-48*z)*256) = u32(w*256)
```

The suffix is therefore composed with W11=`w<<8`; only W8/W9/W10/W12/W15 pass from the prefix to the suffix. This is a proof by source fragments and a quotient-independent identity, rather than a monolithic SMT run over the entire producer. Complete selected concrete replay includes the omitted instructions. [EH3-EH4; EH-A2]

The writer has u64 base B in X9, W11=`u32(o-0xae20ac2a)` and mixed word W12=`V XOR 0xe4b5bf34`. It first stores B at SP+0x9220, then reloads it after the first byte store. The first byte uses B/C/A banks via SP+0x3e8/0x3e0/0x3d8; the remaining bytes use D/E/K via X3/X1/X0. The sixteen source proofs keep the upper 28 offset bits, all 64 base bits and all 32 packed bits symbolic. Output addresses are `B+zeroExtend64(u32(o+j))`, with u64 addition wrap. Output bytes must be disjoint from the fixed bank/pointer cells and the eight-byte scratch cell. These exclusions preserve actual load/store coherence in the composed memory model. [EH1, EH4; EH-A2]

The prior complete decoder in EH5 inverts V to D under `1 <= n <= 27` and `D < 2^n`, as independently checked for this composed format. This increment checks the earlier count store and its observed value six, but does not supply a universal contract for the earlier count loop. The longer producer's distinct loop proof is not transferred to this code. Outside the stated format domain the arithmetic equation still applies; a canonical scalar interpretation and native admission are unknown. [EH3-EH5; EH-A4]

## Concrete custody and exported state

Four retained prefix classes supply the pre-allocation side. Their last selected old-word reader decodes T+1..4=`a2b5113d` to p=20. W20 remains encoded 20 through the old-copy store and raw growth. Original `0x100709a18` saves encoded q=20 as `45c63d8b` at SP+0x70b4; `0x100765f24` stores a=56 as `38000000` at SP+0x312c. Raw r=`0x10ecc426` changes to `0x10ecc44a`, giving C=21 B and N=57 B. [EH2-EH4]

On the successful side, the copied F+1..4 still contains the old serialized 20 when read. Its decoder supplies p=20 to header preparation. Both preparation reads match the earlier operand/copy stores byte for byte, with no local writer or declared malloc-return invalidation. Thus p=q=20 follows from retained source custody, rather than assuming agreement from numeric output alone. The sixteen cross-API cell joins cover the two reads in each of eight success classes. [EH2-EH4; EH-A5]

The preparation produces W23=`0x8b3dc669`, preserved to the scalar spill at `0x1008f3940`. The count store at `0x100a78a6c` supplies n=6. All four bytes of each producer read trace to its scalar/count store: sixteen producer-cell joins. The raw auxiliary is A=`0xb9141cae`, giving R=`0xde17d047`. These inputs produce V=`0x35f411f8`, producer W12=`0xf4df5e8a`, and caller W12=`0xd141aecc`. The writer stores F+1..4=`b96706b1`, which decodes to scalar 56. [EH3-EH4]

```
T header20 ----> p20 -----> raw extent21 + (56-20) -----> malloc57
    |              |
    +--> saved q20 +--> prepare(56+p-q) --> scalar56 --> packed V
    |                                                        |
    +--> copied F header20 --> p20                            |
                                                             v
                               producer --> caller XOR --> F header56
```

All 152 inherited successful exports are freshly decoded at F+1..4 and checked against the conditional F/57 B owner entry: `152*4 B = 608 B`. Pinned prior admissions justify class membership; the full admission/allocation corpus is not rerun. The 532 T/F/H snapshots of EH5 remain a separate prior result; this increment establishes the general coupling for the selected constructor source, without transferring it to every later resize routine. [EH2-EH5; EH-A5-EH-A6]

## Verification, limits and assumptions

Independent replay checks 6,580 original instructions across 100 slices, 213,760 GP/SP values, 6,680 NZCV frames, 572 read events and 68 write events. Q registers remain unchanged in these slices, and the decoded instructions are checked for absence of vector-register access. The 27 nonvacuous UNSAT obligations comprise five allocation/header contracts, five producer/caller contracts, one canonical inverse and sixteen writer residues. Two SAT controls check interpretation limits. Source authentication and native PAC are not newly proved or executed. [EH3-EH4]

Extraction/replay time is O(parent receipt bytes + selected visits*32 + custody scans + decoded export bytes); storage is O(parent receipts + largest decoded state + selected evidence). Symbolic construction adds O(proof DAG) time/space; solver search is separate and bounded to 30 s/query. Arithmetic widths are u32/u64, counts are dimensionless, and allocation extents and serialized offsets use B. Archives use `zstd --ultra -22 -q -T1`, verified by decoded round trip. [EH3-EH6]

No new target interval, guest input, conditional root/owner definition or API-return premise is added. No native target API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation executes. Original references suffice for this increment. Native initializer/caller epoch, complete daemon-kext transport identity, the pending malloc97 result and the NULL-route undefined S+0x30 remain unknown. The four-byte node gap remains undefined. [EH2-EH6; EH-A5-EH-A6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| EH-A1: Original image and pinned journals apply | Exact source and selected instances | Verify original SHA, each visited word, parent pins and fresh exact extraction/replay. |
| EH-A2: Stated phases, fragment interfaces and coherent cells apply | Universal allocation/header/producer/writer contracts | Prove each source fragment; check cancellation destinations, symbolic offsets/base/value and all sixteen writer residues; exclude output overlap with fixed and scratch cells. |
| EH-A3: Header-copy equality is an explicit premise for the invariant | D'=a and gap preservation | Prove general p/q preparation first; check actual copy custody; use nonunit-gap and unequal-copy controls. Preserve modular wrap semantics. |
| EH-A4: Canonical count/scalar bounds apply only to inverse interpretation | Decoded scalar meaning | Retain `1 <= n <= 27`, `D < 2^n`; check the actual n=6 spill/read; do not transfer a distinct count-loop proof or infer native acceptance. |
| EH-A5: Pinned owner/admission/ABI premises qualify retained exports | Cross-API custody and 152 F/57 B headers | Check all export headers and owner extents, source last writers and absence of declared invalidation. Full prior admission/allocation replay is not rerun. |
| EH-A6: Local arithmetic/representation does not establish native schema or exposure | Byte-offset interpretation, ownership and daemon-kext identity | Require continuous native caller/initializer and actual buffer/transport joins; compare other resize implementations before generalizing the invariant. |

| Impact | Bounded continuation | Evidence boundary |
| --- | --- | --- |
| High | Compare the later H-header producer and resize equation | Its 76/77 snapshot relationship is pinned; this constructor contract alone does not prove the later routine. |
| High | Join these headers to actual daemon-kext payload consumers | Local serialization and allocator count are established; native transaction identity remains unknown. |
| High | Recover native caller bounds and the earlier count-loop contract | Actual operand 56/count six and canonical inverse are checked; universal input admission remains unknown. |
| Medium | Track the raw auxiliary's preceding producer | Its exact value and retained bit contribution are known; complete provenance and randomness are unknown. |
| Medium | Compare duplicate header copies across other caller epochs | Agreement is checked here; native concurrency and lifetime behavior are unobserved. |

**QG1**: factual source/interface analysis. **QG2**: EH-A1-EH-A6 list assumptions, dependencies and falsification probes. **QG3**: the constructor extent/header increment is covered; the full interface goal remains active. **QG4**: widths, byte extents, numeric interpretation, modular equations, counts and complexity are explicit. **QG5**: source contracts, copy agreement, canonical format, conditional states and native unknowns are separated. **QG6**: original bytes, pinned journals, fresh extraction, independent selected replay, source queries and publication checks establish provenance. **QG7**: bounded continuation opportunities have impact labels and evidence limits.

The [local record-span follow-up](daemon_record_spans_report.md) proves the constructor span calculation 4*count+20 and its addition to the old header, decodes four payload scalars 0/1/0/1, and joins the later 97 B request to the scalar20 at offset57 rather than the enclosing scalar76 at offset1. Contiguous span endpoints and the record-start+14 values support a nested record and child-count interpretation; complete native schema and daemon-kext identity remain unknown. Twenty-three nonvacuous obligations, 20,112 independently replayed instructions and 3,192 field checks across 456 exports qualify this increment. No new target interval or API-return premise is added; the full goal remains active.
