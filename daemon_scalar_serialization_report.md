# fairplayd: shared scalar byte mask and constructor word decoding

The recovered four-byte and two-byte scalar writers use one common 16 B periodic XOR mask after their phase-specific intermediate XORs are removed. The earlier word reader at `0x1008c6110` follows the same stored format. Its constructor input at T+1..4, `a2b5113d`, decodes to scalar **20**. That value reaches the encoded stack word read by the [constructor zero-branch gate](daemon_constructor_halves_report.md). This resolves the immediate source of q; the native field type remains unknown. [SS1-SS6; SS-A1-SS-A5]

Across 532 retained T/F/H snapshots, the scalar at offset 1 is respectively 20/56/76 and equals the modeled owner extent minus one, 21/57/77 B minus one. This is an exact relationship in those snapshots. A general native extent-minus-one type or native acceptance rule is not established. The word decoder also has a count-zero case caused by 32-bit variable-shift masking; its full arithmetic contract includes that case. [SS2-SS5; SS-A3-SS-A5]

| Evidence | Primary source and scope |
| --- | --- |
| SS1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; exact word-reader/decoder/spill bytes and original authenticated dispatch records. |
| SS2 | [Constructor checks](triage_evidence/daemon_constructor_buffer_checks.json.zst), decoded SHA-256 `fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07`; [constructor halfword checks](triage_evidence/daemon_constructor_halves_checks.json.zst), `801ca3b1a59a9017a3f9b42f32b35956b91d16fa506b3a85548d2f914d3e97b8`; [growth checks](triage_evidence/daemon_descriptor_growth_checks.json.zst), `b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2`. Their pinned replay/admission receipts qualify the inherited states; full prior admission and allocation corpora are not rerun. |
| SS3 | [Extractor](triage_evidence/recover_daemon_scalar_serialization.py) and [checks](triage_evidence/daemon_scalar_serialization_checks.json.zst): 32 fixed-mask identities, four word-to-gate joins, 76 exported stack words and 532 owner/header snapshots. |
| SS4 | [Independent auditor](triage_evidence/audit_daemon_scalar_serialization.py) and [receipt](triage_evidence/daemon_scalar_serialization_audit.json.zst): 20 nonvacuous obligations, two format controls and fresh selected replay. |
| SS5 | [Packed-word checks](triage_evidence/daemon_packed_words_checks.json.zst), decoded SHA-256 `e8d3a4ffe60b0a28944a5d4a47227f6d313c609e00ab8dcc304c38fc00734554`; [audit](triage_evidence/daemon_packed_words_audit.json.zst), `fc68105796266bb76dbf92fa3c8efc35fed3d970b4bd6aa11ed08aedd4bd2aaa`; [packed-halfword report](daemon_packed_halves_report.md) and [constructor halfword report](daemon_constructor_halves_report.md) qualify the producer phases and format domains. |
| SS6 | [Publication verifier](triage_evidence/verify_daemon_scalar_serialization_publication.py): fresh extraction/audit, query verification, exact manifest delta, input preservation and decoded path hygiene. |

## One periodic mask for the recovered scalar formats

Let o be the u32 byte offset, V the packed scalar word/halfword before its phase XOR, and j its byte index. The common stored format is: [SS3-SS5]

```
stored[j] = BE_bytes(V)[j] XOR M[(o+j)&15]
M = d9 8c 93 17 49 8b 22 11 82 b3 19 85 70 dd 90 4f
```

The source uses u32 offset wrap before zero-extension into u64 address arithmetic. The mask index has period 16 B. This result concerns the recovered scalar fields; it does not establish that every byte in a buffer uses this transform. The mask is a fixed representation component, with no demonstrated native cryptographic secrecy or randomness property. [SS3-SS4; SS-A2-SS-A5]

| Existing writer interface | Normalization to the common mask |
| --- | --- |
| Four-byte caller input `V XOR 0xe4b5bf34` | XOR each of its four byte masks with `e4 b5 bf 34`. |
| Two-byte writer input `V XOR 0x534c` | XOR each of its two byte masks with `53 4c`. |
| Earlier constructor halfword input `V XOR 0x0df8` | Its separate `0xc6/0x33` writer phase gives the same stored halfword format, as proved in SS5. |

All sixteen offset residues are checked for both four-byte and two-byte writer masks: 32 identities, totaling 96 normalized mask bytes. The first byte of the four-byte writer uses a different bank family and a `33*k` expression; the other bytes use D/E/K and `31*k`. For the actual fixed banks, their normalized results agree with M at every residue. This fixed-bank identity is not generalized to arbitrary bank contents. [SS3-SS4; SS-A2]

## Earlier word reader and complete scalar decoder

The reader uses SP=`0x6800060100`, bank pointers at SP+0x420/0x418/0x428 and D/E/K bytes from the constructor interface. Its entry has u64 base in X9 and W8=`u32(o-0xbddaaacc)`. The fixed logical dispatch phase uses table index `0x1305`. Sixteen universal source queries retain symbolic upper 28 offset bits, u64 base and four independent input bytes; they prove all four actual load addresses and the common-mask output. Coherent readable bytes disjoint from the fixed pointer/bank/dispatch cells are required. [SS1, SS4; SS-A2]

```
V = BE32(stored[j] XOR M[(o+j)&15], j=0..3)
reader_exit_W9 = V XOR 0x8b3dc651
reader_exit_W8 = 0x8b3dc651
n = V >> 27
D = V                         if n == 0
    V AND ((1 << n) - 1)       otherwise
decoder_exit_W20 = D XOR 0x8b3dc651
```

The count-zero branch is necessary. AArch64 32-bit variable shifts mask the shift count modulo 32, so a conceptual shift by 32 acts as a shift by zero. For count 0, V has its top five bits clear and the source returns V rather than zero. The source contract covers every u32 V, with `D <= 0x7fffffff`. The paired producer inverse is proved separately under canonical bounds `1 <= n <= 27` and `D < 2^n`. The already recovered producer count loop has minimum count one; that prior loop proof is pinned, not rerun. [SS4-SS5; SS-A3]

| Source branch | Original index / slot | Target | Logical authentication |
| --- | --- | --- | --- |
| `0x1008c629c` | `0x1305` / `0x101043718` | `0x10076c4b8`, scalar decoder | IA diversity `0x1890`, address diversity 0 |
| `0x10076c570` | `0x0941` / `0x10103e8f8` | `0x10080d8bc`, retained continuation | IA diversity `0x7eeb`, address diversity 0 |

The original pointer-format-12 records and all eight retained edges agree. Fresh replay checks the consumed target register, X10 or X8, and X17 modifier at each edge. Hardware authentication and native relocated values are not observed. [SS1, SS3-SS4]

| SAT control | Verified decoder result | Limit |
| --- | --- | --- |
| V=`0x01234567`, n=0 | D=`0x01234567` | Outside the canonical minimum-count producer domain; native admission unknown. |
| V=`0xffffffff`, n=31 | D=`0x7fffffff` | Establishes that the unconditional decoder bound is tight; native admission unknown. |

## Word-to-gate custody and snapshot relationship

For the retained constructor input, `a2b5113d XOR 8c931749 = 2e260674`. Its count is 5 and scalar is 20. The decoder sets W20=`0x8b3dc645`; original `0x100855534` writes that encoded value as `45c63d8b` to SP+0x64a8=`0x68000665a8`. W20 is unchanged between decoder exit and the store. The gate's read at `0x10084db2c` has that exact source store as the last writer of all four bytes. All 76 exported prefix states retain the same encoded stack word, totaling 304 B checked. [SS2-SS4]

```
T+1..4: a2b5113d -> XOR mask -> V=2e260674 -> D=20
                                                        |
                                              XOR 8b3dc651
                                                        |
                             W20=8b3dc645 -> stack 45c63d8b
                                                        |
                              gate load -> XOR key -> q=20
                                                        |
                                     zero route: q<21 passes
```

The word gate's unsigned q<21 contract remains the SS2 result. The new evidence joins q to a particular serialized word, rather than assigning q a type from the comparison constant. [SS2-SS4]

| Snapshot cohort | Checked snapshots | Stored header at offset 1 | Packed V | Count | Scalar D | Model extent / B | D+1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T | 76 | `a2b5113d` | `0x2e260674` | 5 | 20 | 21 | 21 |
| F | 152 | `b96706b1` | `0x35f411f8` | 6 | 56 | 57 | 57 |
| H | 304 | `b7151d05` | `0x3b860a4c` | 7 | 76 | 77 | 77 |

The check reads all 532 header words and verifies the matching owner entry and extent in each retained state: `532*4 B = 2128 B`. These are conditional model owner extents, not native allocator measurements. The exact snapshot equality supports an extent-minus-one or last-byte-offset interpretation. Proving a general type requires the corresponding header producer, allocation-size derivation and native buffer identity. The 36 B and 20 B successive extent increases do not establish a fixed per-entry size. [SS2-SS5; SS-A4-SS-A5]

## Verification and assumption register

Fresh independent replay checks 592 original instructions across twelve slices, 19328 GP/SP values, 604 NZCV frames, 96 reads, four writes and eight logical edges. Twenty nonvacuous obligations comprise sixteen byte-reader residues, the complete word-decoder arithmetic, its unsigned bound, the original spill and the paired producer inverse. Two SAT controls check count-zero behavior and the tight upper bound. Full prior admissions, constructor/growth replay and allocation/free behavior are not rerun. [SS3-SS4]

Time is O(parent receipt bytes + selected visits*32 + custody scans + decoded exported-state bytes + proof DAG); storage is O(parent receipts + largest decoded state + selected evidence + proof DAG). Solver search is separate and bounded at 30 s/query. Arithmetic widths are u32/u64, byte indices and extents use B, and scalar/count fields remain dimensionless before native type recovery. The equality D+1=extent is a numeric comparison against the model extent measured in bytes, not a newly inferred native unit. JSON archives use `zstd --ultra -22 -q -T1` with decoded round-trip checks. [SS3-SS6]

No new Mach name, right disposition, emission site or native daemon-kext transaction is established. Native field meaning, initializer/caller epoch, pending malloc97, the NULL-route S+0x30 frontier and complete transport identity remain unresolved. No new target interval, guest input, root/owner definition or API-return premise is added. No native API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation executes. Retained references suffice for this increment. [SS2-SS6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SS-A1: Original image and pinned journals apply | Exact source, data flow and dispatch | Verify hashes, original words/rebases and fresh exact extraction/replay. |
| SS-A2: Fixed banks/phases and coherent readable cells apply | Common scalar masks and universal word reader | Check all sixteen fixed-bank residues; prove four actual addresses with symbolic upper offsets/base/bytes, including u32 wrap; exclude input overlap with fixed cells. |
| SS-A3: Canonical producer bounds apply only to the paired inverse | Scalar interpretation and decoder completeness | Prove the full decoder separately, test count zero and count 31, and retain explicit count/scalar premises for the producer inverse. |
| SS-A4: Pinned owners/admissions and retained source custody apply | 76 stack exports and 532 header/extent pairs | Check every export/header and owner extent; trace all four gate-load bytes to the original spill. Prior admission/allocation corpora are not rerun. |
| SS-A5: Representation agreement does not establish a native schema | Extent-minus-one hypothesis, units, auxiliary meaning and daemon-kext identity | Recover header producers and allocation-size derivations, compare independent operations, and require complete native caller/transport joins. |

| Impact | Bounded continuation | Evidence boundary |
| --- | --- | --- |
| High | Join the offset-1 producer to allocation-size derivation | Exact T/F/H snapshot relationship and q custody are established; general native type is unknown. |
| High | Match packed scalar fields across daemon/kext consumers | A common scalar mask and word/halfword formats are established; complete native transaction identity remains unknown. |
| Medium | Normalize other recovered scalar readers/writers using M | Agreement is proved for these fixed banks/phases, not arbitrary routines or all buffer bytes. |
| Medium | Check count-zero handling in other source decoders | The earlier word decoder's shift behavior is complete; other decoder phases require their own contracts. |

**QG1**: factual technical analysis. **QG2**: SS-A1-SS-A5 state assumptions, dependencies and falsification probes. **QG3**: the scalar-mask/word-to-gate increment is covered; the full interface goal remains active. **QG4**: widths, storage units, counts and complexity are explicit. **QG5**: canonical producer format, unconditional decoder behavior, snapshot equality, prior admissions and native unknowns are separated. **QG6**: primary bytes/rebases, fresh extraction, selected independent replay, proof queries and publication checks establish provenance. **QG7**: bounded next steps and interpretation limits have impact labels.

The [constructor extent/header follow-up](daemon_constructor_extent_report.md) proves the generic allocation update N=C+a-p and prepared header D=a+p-q. Equal old-header copies make D=a and preserve the numeric extent/header gap; the retained 21/20 -> 57/56 instance has gap one. The earlier packed-word producer and sixteen writer residues share the recovered scalar format. Twenty-seven nonvacuous obligations, two interpretation controls and 6,580 independently replayed instructions qualify the result; all 152 successful exported headers are checked. Native schema, caller epoch and daemon-kext identity remain unknown; the full goal remains active.
