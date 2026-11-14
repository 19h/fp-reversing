# fairplayd: constructor halfword format and zero-branch update

The constructor's earlier halfword routines implement the same scalar format recovered in the [later producer](daemon_packed_halves_report.md) and [reader/update](daemon_halfword_update_report.md). The old T+15 bytes `5589` decode to scalar **0**. The retained constructor route writes an encoded scalar **1** into a stack cell and then regenerates F+15 as `56ee`. A separate field at F+35 encodes scalar **0**. This establishes the source of the scalar-one header consumed by the later update. The constructor's two fields have different scalar inputs; they are not two copies of the same scalar. Native field types and daemon-kext buffer identity remain unknown. [CH1-CH6; CH-A1-CH-A5]

The original zero branch also has a distinct gate. A nonzero decoded scalar selects the increment block directly. A zero scalar first tests another decoded u32 word q: `q < 21` selects the increment block; `q >= 21` selects `0x1008f2a1c`. The retained case has q=20. The alternate target's downstream effects are not established here. These are source contracts and original authenticated dispatch records, not a native execution observation. [CH1, CH3-CH4; CH-A2-CH-A5]

| Evidence | Primary source and scope |
| --- | --- |
| CH1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; exact source spans and original authenticated rebases. |
| CH2 | [Constructor checks](triage_evidence/daemon_constructor_buffer_checks.json.zst), decoded SHA-256 `fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07`; [replay](triage_evidence/daemon_constructor_buffer_replay.json.zst), `61f012a43cbae9cf2ff8a5207603a30b9bbf82c7b2d92811e0c1a2ff7505c107`; [audit](triage_evidence/daemon_constructor_buffer_audit.json.zst), `47108bdf5bedbb6a9aec1397ae777d6317a689cdea625638da5fb94a3c86e252`. Prior full admission/allocation/cleanup validation is pinned and is not rerun. |
| CH3 | [Extractor](triage_evidence/recover_daemon_constructor_halves.py) and [checks](triage_evidence/daemon_constructor_halves_checks.json.zst): four prefix classes, eight successful branch classes, sixteen fields, saved-register and auxiliary-byte custody, and 152 constructor exports. |
| CH4 | [Independent auditor](triage_evidence/audit_daemon_constructor_halves.py) and [receipt](triage_evidence/daemon_constructor_halves_audit.json.zst): 43 nonvacuous source/composition obligations, two boundary controls and fresh selected replay. |
| CH5 | [Later update checks](triage_evidence/daemon_halfword_update_checks.json.zst), decoded SHA-256 `5f53bea42c88b3bdc516321e318f4ca5da94c4e2a6eff64e51c12b349726f9d4`; [later producer checks](triage_evidence/daemon_packed_halves_checks.json.zst), `12d8bf65c7c1140e5a842764cc68e850eccbdc7a6075304059ec01f8f8ca7fe4`. These qualify the comparison with the subsequent scalar 1->2 transition. |
| CH6 | [Publication verifier](triage_evidence/verify_daemon_constructor_halves_publication.py): fresh extraction/audit, query verification, manifest delta, input preservation and decoded path hygiene. |

## Common format across different source phases

Let o be a u32 byte offset and B the u64 buffer base. For byte j=0/1, set k=`u32(o+j)&15`. The existing common halfword mask is:

```
m_j(o) = low8(D[k] XOR E[k+4] XOR K[k+1] XOR (31*k) XOR c_j)
c_0 = 0x98; c_1 = 0x87
V = BE16(stored0 XOR m_0(o), stored1 XOR m_1(o)) XOR 0x534c
n = V >> 12
D_scalar = V AND ((1 << n) - 1)
```

The constructor reader `0x100755878..0x1007559a0` returns `D_scalar` directly in W9. The later reader returns `D_scalar XOR 0x7390` in W8. Their internal phases differ while their decoded scalar agrees. The sixteen residue proofs retain symbolic upper 28 offset bits, u64 base and both input bytes. They check the actual source read addresses, including u32 wrap at o+1. [CH1, CH4-CH5; CH-A2]

The earlier producer `0x10095c7f8..0x10095cc30` consumes two auxiliary bytes A in big-endian order, encoded scalar K20 in W20 and count n in W21. Its recovered low-halfword contract is:

```
D_scalar = u16(K20 XOR 0x0df8)
V = u16((((A << (n&31)) & 0x0fff) | u16(n << 12)) + D_scalar)
producer_exit_low16_W8 = V XOR 0x0df8
```

Its caller at `0x100878944` uses writer phase constants `0xc6/0x33`. The resulting stored bytes equal `BE16(V XOR 0x534c)` XOR the common mask above. Thus this producer/caller pair and the later producer/caller pair share the stored scalar format despite different intermediate register encodings. This is an arithmetic/representation equivalence, not a claim of identical complete routines. [CH4-CH5]

| Source interval, end exclusive | Independently proved low-halfword contract |
| --- | --- |
| `0x10095c81c..0x10095c840` | Recover the assembled auxiliary A. |
| `0x10095c840..0x10095c85c` | `((A << (n&31)) XOR 0x318) & 0xfff`. |
| `0x10095c85c..0x10095c884` | Merge the count field and XOR `0x8c27`; composition with the preceding row gives the pre-scalar packed value XOR `0x8f3f`. |
| `0x10095c884..0x10095ca2c` | For entry x, compute `u16((x XOR 0x8f3f) + u16(K20 XOR 0xdf8) + 0x92b)`. |
| `0x10095ca2c..0x10095cc2c` | For entry x, return `u16(x-0x92b) XOR 0xdf8`. |

The arithmetic producer contract accepts the source's masked shift/count behavior. Interpreting its scalar/count fields separately, and using the paired scalar inverse, requires `1 <= n <= 12` and `D_scalar < 2^n`. The observed fields have n=1 and scalar 0/1. No new universal bit-count-loop contract is asserted; the retained count inputs and their saved/restored values are checked. [CH3-CH4; CH-A3]

| Model field | Stored bytes | V | Count | Scalar | Retained auxiliary value |
| --- | --- | --- | --- | --- | --- |
| T+15, old constructor input | `5589` | `0x1a50` | 1 | 0 | `0x528` |
| F+35, separately generated field | `0689` | `0x11c0` | 1 | 0 | `0x0e0` |
| F+15, regenerated header field | `56ee` | `0x1937` | 1 | 1 | `0x49b` |
| H+15, later update from CH5 | `60b3` | `0x2f6a` | 2 | 2 | `0x3da` |

The F+35 auxiliary bytes are `a0e0`; F+15 uses `e49b`. The retained auxiliary column is the low `12-n` bits after packing. H+15 is a prior result included to expose the shared representation; this increment does not rerun all intervening journals between constructor export and that later consumer. [CH2-CH5; CH-A4]

## Zero branch, word gate and encoded increment

The earlier reader's phase uses outer SP=`0x6800060100`, fixed bank pointers at SP+0x420/0x418/0x428, W10=`0x9512`, offset in W12, twice that offset in W9, and the buffer pointer through U+8. The fixed banks are D=`0x100f21190`/16 B, E=`0x100fa38b0`/20 B, K=`0x100ffc9e0`/17 B. The byte contracts require coherent readable input cells; the writer additionally excludes overlap with its fixed pointer/bank cells. [CH3-CH4; CH-A2]

`0x1008c881c` saves the old scalar as a u16 at SP+0x868e and prepares the increment interface. Its original branch at `0x1008c8890` uses IA diversity `0x62ce`, address diversity 0. The zero target reads the word at SP+0x64a8, interprets `q = raw XOR 0x8b3dc651`, and compares it unsigned with 21. Source `CMN`/`CSET LO` reduces to this exact predicate, including u32 wrap. [CH1, CH4]

| Source branch / condition | Original index | Original slot | Target |
| --- | --- | --- | --- |
| `0x1008c8890`, scalar != 0 | `0xa05f` | `0x10108a1e8` | `0x10083629c`, increment/store |
| `0x1008c8890`, scalar = 0 | `0xa085` | `0x10108a318` | `0x10084db18`, word gate |
| `0x10084dbb8`, q < 21 | `0xa05f` | `0x10108a1e8` | `0x10083629c`, increment/store |
| `0x10084dbb8`, q >= 21 | `0xbc52` | `0x101098180` | `0x1008f2a1c`, effects unknown here |

All three slots have original pointer-format-12 records with the stated logical authentication. Four retained prefix classes use the zero route and q=20. Two SAT boundary controls check q=20 and q=21; they do not execute either native path. The nonzero direct route and q>=21 target are source/fixup results rather than newly executed model intervals. [CH1, CH3-CH4]

For any u16 decoded scalar D, the arithmetic at `0x10083629c..0x100836348`, when reached with the proved interface, stores:

```
u32_cell[SP + 0x46b4] = (zero_extend32(D) + 1) XOR 0x28e36a4a
```

The concrete old scalar is 0, so the four stored bytes are `4b6ae328` at `0x68000647b4`. Later `0x1006615c0` reads its low halfword `0x6a4b`; `0x1006615c8` XORs `0x67b2` to form producer key `0x0df9`. Decoding that key with `0x0df8` yields scalar 1. These two XORs combine to the stack cell's low-halfword key `0x6a4a`. [CH3-CH4]

Every possible halfword decoder output is <=32767. The composed proof therefore establishes exact survival of D+1 through the later u16 read, not merely correct behavior at D=0. The branch/header premises still qualify whether this increment block is reached. Canonical producer-format admission remains a separate question. [CH4; CH-A3-CH-A5]

```
T+15: 5589 -> earlier reader -> scalar 0
                                  |
                        zero route, q=20 < 21
                                  |
              encoded stack cell: 4b6ae328
                                  |
                 low16 XOR 67b2 -> key 0df9
                                  |
       saved/restored scalar and count + auxiliary e49b
                                  |
             producer + phase writer -> F+15: 56ee

separate auxiliary a0e0 + scalar 0 -> F+35: 0689
```

The original constructor's 21 B T->57 B F copy/extension and declared malloc/free boundaries remain qualified by CH2. This increment checks that neither declared API invalidation nor source writes in the intervening success intervals overlap the two consumed stack bytes before the scalar read. For each produced field, the last auxiliary-byte writers are `0x100a0ca74`. Saves at `0x100add598/0x100add59c` and restores at `0x100add7f0/0x100add7f4` establish 32 scalar/count register bridges. No hardware PAC operation is included in the selected arithmetic replay. [CH2-CH4; CH-A4]

## Verification and interpretation limits

Fresh independent replay checks **6092 original instructions** in 88 selected slices: 197760 GP/SP values, 6180 NZCV frames, 424 reads, 104 writes and eight retained zero-route logical edges. There are four prefix classes and eight successful allocation/ABI classes, with two fields per successful class. All 152 successful constructor exports retain the two checked fields, totaling `152*2*2 B = 608 B`. Prior full admission, allocation, free and intervening corpora are not rerun. [CH3-CH4]

The 43 nonvacuous obligations comprise sixteen reader residues, sixteen writer residues, five producer fragments, the zero dispatch/interface, the unsigned word gate, the encoded increment store, scalar-key preparation, the composed width bound and the paired scalar inverse. Two SAT controls check the word-gate boundary. Symbolic byte bindings are accompanied by proofs of their actual source read addresses; matching is not assumed from expression spelling. Output/bank aliasing is explicitly excluded for the writer's fixed-bank contract. [CH4]

Time is O(parent receipt bytes + selected visits*32 + selected reads*writes + exported states + proof DAG); storage is O(parent receipts + one unpacked branch + selected evidence + proof DAG). Solver search is separate, bounded at 30 s/query. Arithmetic widths are u16/u32/u64, storage sizes use B and offsets are byte offsets. Scalars, counts, q and gate threshold 21 are dimensionless until native types are established. Archives use `zstd --ultra -22 -q -T1` and decoded round-trip checks. [CH3-CH6]

**Candidate interpretation, not an established native type:** two header-scalar transitions 0->1->2, each associated with separately produced scalar-zero fields, support an appended-unit count interpretation. Unit identity, complete update policy and native serialized meaning are unknown. The constructor extends 21 B to 57 B, whereas the next retained extension reaches 77 B; the unequal increments do not establish an affine buffer-size formula. q=20 in the 21 B predecessor is one observation and does not prove q is extent-minus-one. [CH2-CH5; CH-A5]

No new Mach port, right disposition, emission site or native daemon-kext transaction is established. The pending malloc97, NULL-route undefined S+0x30 frontier, native initializer/caller epoch and complete daemon-kext pairing remain unresolved. No new target interval, guest input, root/owner definition or API-return premise is added. No native API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation executes. Retained references suffice for this increment. [CH2-CH6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CH-A1: Original image and pinned journals apply | Source addresses, concrete fields and metadata | Verify hashes, original source bytes, three authenticated rebases and fresh exact extraction/replay. |
| CH-A2: Fixed phases/banks and coherent readable cells apply | Reader/writer contracts and dispatch interface | Retain symbolic upper offset bits/base/bytes across sixteen residues; prove actual addresses; exclude output overlap with fixed banks/pointers and input overlap with fixed cells. |
| CH-A3: Fragment interfaces and canonical format bounds apply where used | Packed inverse, increment arithmetic and width survival | Prove the five producer fragments, u16 increment store, all decoder outputs and paired inverse under explicit count/scalar bounds; distinguish route reachability from arithmetic. |
| CH-A4: Pinned admission/ABI invalidation and source custody apply | Scalar-one provenance and 152 exported field pairs | Check intervening writes/invalidations for the two consumed stack bytes, auxiliary last writers, all scalar/count bridges and each exported field. Full prior admissions are not rerun. |
| CH-A5: Source/model representation does not establish native type or exposure | Counter hypothesis, q meaning, ownership and daemon-kext identity | Trace independent append operations and q producers; falsify count/extent hypotheses with divergent updates; require complete native caller/transaction joins before assigning native semantics. |

| Impact | Bounded continuation | Evidence boundary |
| --- | --- | --- |
| High | Identify q's original producer and semantic role | Its XOR decoding and unsigned threshold are proved; q=20 alone does not establish a size type. |
| High | Classify `0x1008f2a1c` and the later reader's distinct zero target | Original destinations are known; downstream effects remain separate investigations. |
| High | Test the appended-unit count interpretation against independent source operations | Two conditional increments and separate zero fields support the hypothesis, not a complete native schema. |
| Medium | Use phase-normalized stored formats to match further obfuscated readers/writers | The constructor/later pairs agree under explicit bank/phase premises. |

**QG1**: factual technical analysis. **QG2**: CH-A1-CH-A5 identify dependencies and falsification probes. **QG3**: the constructor reader/branch/update/producer increment is covered; the full interface goal remains active. **QG4**: arithmetic widths, storage units, exact counts and complexity are explicit. **QG5**: concrete observations, universal contracts, branch conditions, inherited validation and native unknowns are separated. **QG6**: primary source/fixups, fresh extraction, selected independent replay, proof queries and publication checks establish provenance. **QG7**: bounded extensions and interpretation risks have impact labels.

The [scalar serialization follow-up](daemon_scalar_serialization_report.md) proves the common periodic mask for recovered word/halfword fields, traces the gate word q to T+1..4 and checks header-scalar/extent agreement across 532 model snapshots. The word decoder includes its count-zero shift case; native field types and daemon-kext identity remain unknown.
