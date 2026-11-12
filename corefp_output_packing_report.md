# CoreFP canonical-byte output packing

Subsequent preparation evidence: the [late-preparation report](corefp_late_preparation_report.md) extends the first-block transfer to arbitrary late prepared bytes under each fixed earlier entry state. It proves inverse-H word encoding and identity preparation XOR at output, with an explicit canonical-result interface cut. Earlier phase construction and whole-caller raw-input admission remain unresolved.

The original region `[0x1bb5a8,0x1bbff4)` maps the previous consumer's sixteen canonical bytes to sixteen message-output bytes by a fixed byte permutation, a common invertible binary-linear byte map and a captured-state XOR vector. All eight retained packing domains share the permutation and linear map. In each domain, the source lift proves the output relation for arbitrary values of all sixteen canonical bytes simultaneously, with every other entry/read interface fixed. This joins the [consumer network](corefp_workspace_consumers_report.md) to the actual private output stores. Native input admission, general preparation semantics and the complete transform remain unknown.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_output_packing.py), [checks archive](triage_evidence/corefp_output_packing_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_output_packing.py), [audit archive](triage_evidence/corefp_output_packing_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_output_packing_publication.py) retain original source bytes, complete entry/end states, regional read/write journals, solver queries, transfer coefficients and reaching-write provenance. Four parent receipts and the frozen readers are SHA-256 pinned. The three originally supplied inputs are unchanged.

CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. All source PCs are preferred-base-zero offsets; B denotes bytes. The 2636 B packing region contains 659 four-byte instructions. The preceding preservation gap contains 515 instructions/2060 B. Both are subsets of the already retained 59120 B caller/allocator/retirement bodies; their sizes do not increase disjoint source coverage.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PK1 | The pinned original image, fixups, source readers and four parent receipts describe this target. All source claims depend on these bindings. | Compare the complete retained bodies and each regional instruction; verify hashes and preserve the original supplied inputs. A different image requires new bindings. |
| PK2 | The existing private caller/context/pool/malloc/PAC/sequential-CASAL premises apply. Whole-caller continuity depends on them. | Reconstruct six initial CPU/RAM states, replay 488136 visits and compare every retained read/write and final page. Native context admission, pointer ownership and concurrency remain unknown. |
| PK3 | The sixteen incoming canonical u8 values use the parent's exact q144..q159 encoding and locations. The gap-to-packing join depends on it. | Check all sixteen values in every packing entry; census every gap register write and store to reject any intervening overwrite. |
| PK4 | In each of eight packing domains, non-result CPU/stack/read inputs are fixed to that captured entry; byte-table windows are the original immutable source bytes. Universal transfer claims depend on these explicit interfaces. | Independently interpret every instruction and original read/write; check 32768 component executions against the original bytes. A changed surrounding input creates a new domain and does not inherit this proof. |
| PK5 | Typed private stack/output backing is valid and disjoint. Concrete pointer and scatter-store claims depend on that backing. | Check all effective addresses, 1312 B stack snapshots, sixteen one-byte output writes and the sole u32 scratch write. No arbitrary native address is accessed. Native pointer ranges require separate validity and nonwrapping proofs. |
| PK6 | Captured bias differences establish conditional component relations between those domains. General preparation/chaining interpretations are unknown. | Compare first- and second-block controls; prove upstream preparation-to-field encodings and all input-prefix/loop-update semantics before generalizing to arbitrary preparation, context or native calls. |

## Preserved consumer results and packing interfaces [PK1-PK5]

Let `g[0..15]` be the canonical u8 values corresponding, in order, to q144..q159 from the consumer report. At consumer end and packing entry their stored u32 values are:

```text
encoded_q[144+i] = (u32(g[i]) << 8) XOR 0x65 XOR Q_phase
```

Four are in W14/W15/W17/W6; twelve occupy the parent's stack slots between SP+`0x324` and SP+`0x35c`. Writes to W registers zero-extend to u64. The parent workspace oracle supplies Q_phase separately for each of the five retained encoding classes.

The gap `[0x1bad9c,0x1bb5a8)` has no branch or call, does not write SP/FP or those four result registers, and has exactly one memory store: `0x1bb0d0: str x26,[sp,#0x318]`. Its 8 B footprint ends before the result slots. Thus it preserves all sixteen encoded q values under completed typed-load execution. The independent audit checks the source census and all 128 retained entry values. The gap's other computations are not reduced to a general context/ARX algorithm here.

The packing region also has no branch, call or flag-writing instruction. Each block performs 102 reads and seventeen writes: sixteen one-byte output stores plus a u32 scratch store at `0x1bb7a0`, to SP+`0x364`. Its write extent is `16*1 + 1*4 = 20 B`; eight blocks write 128 output B and 32 scratch B. It does not write its source byte tables. Forty instructions are LDRB: sixteen use free-g-dependent table indices, while twenty-four are fixed-read interfaces in the partial lift. The other 62 read values include the two results of one LDP.

```text
consumer: ten substitution layers
                 |
       encoded q144..q159
                 |
     515-instruction preservation gap
                 |
      659-instruction output packing
                 |
       permute g -> H -> XOR B_domain
                 |
      sixteen private byte stores
```

## Exact byte transfer and output scatter [PK1,PK3-PK5]

For each retained domain d and output index j, the proven relation is:

```text
out_d[j] = H(g[P[j]]) XOR B_d[j]
H(x)     = XOR_{k=0..7, bit_k(x)=1} column[k]
```

Bits are numbered least significant first. H is linear over GF(2); each operation acts on u8 values. Its complete 256-value table is a permutation of 0..255. The inverse columns reconstruct x from H(x), also over GF(2).

| Bit k | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| H column, hex u8 | bc | 44 | 35 | 7d | da | cc | bf | ff |
| H inverse column, hex u8 | 27 | 66 | c2 | cc | 94 | 75 | c0 | ee |

The output address in row j is the block's output base plus j. Each STRB obtains its pointer from an immediately preceding u64 stack load, at store-PC minus 4 B. The last reaching pointer stores below are the same source sites in all eight blocks. They establish local pointer provenance, not a native allocation/ownership contract.

| Output j | Source g index P[j] | Read ID | STRB PC | Pointer slot | Last pointer store PC |
| --- | --- | --- | --- | --- | --- |
| 0 | 9 | q153 | `0x1bb950` | `[SP+0x318]` | `0x1bb0d0` |
| 1 | 7 | q151 | `0x1bbd44` | `[SP+0x3d8]` | `0x1b9d08` |
| 2 | 1 | q145 | `0x1bbb40` | `[SP+0x380]` | `0x1b9de8` |
| 3 | 5 | q149 | `0x1bbb04` | `[SP+0x378]` | `0x1b9e1c` |
| 4 | 15 | q159 | `0x1bbbc0` | `[SP+0x3c0]` | `0x1b9c98` |
| 5 | 10 | q154 | `0x1bbff0` | `[SP+0x3e0]` | `0x1b9c6c` |
| 6 | 13 | q157 | `0x1bba70` | `[SP+0x3a0]` | `0x1b9bdc` |
| 7 | 12 | q156 | `0x1bbad8` | `[SP+0x390]` | `0x1b9ce0` |
| 8 | 3 | q147 | `0x1bbce0` | `[SP+0x3c8]` | `0x1b9d54` |
| 9 | 11 | q155 | `0x1bbbf8` | `[SP+0x368]` | `0x1b9f14` |
| 10 | 0 | q144 | `0x1bb7e8` | `[SP+0x370]` | `0x1b9b84` |
| 11 | 4 | q148 | `0x1bbb90` | `[SP+0x3d0]` | `0x1b9c24` |
| 12 | 14 | q158 | `0x1bbd08` | `[SP+0x3b8]` | `0x1b9db0` |
| 13 | 6 | q150 | `0x1bbdb8` | `[SP+0x388]` | `0x1b9f5c` |
| 14 | 2 | q146 | `0x1bbd84` | `[SP+0x3a8]` | `0x1b9e58` |
| 15 | 8 | q152 | `0x1bbde4` | `[SP+0x3b0]` | `0x1b9ea8` |

The partial lift symbolically executes all 659 instructions with sixteen independent free u8 variables. It models stack writes bytewise and binds each free-index byte read to all 256 original table bytes. The four source-window bases are `0x15dbc70`, `0x1749120`, `0x17d0240` and `0x1ac0f60`. Sixteen address obligations per block establish `base+zero_extend_u8(index)` over u64 modular arithmetic. Sixteen output obligations per block reject any difference from the affine expression above. These output obligations quantify all 128 incoming result bits jointly; they are not inferred from one-byte perturbation tests alone. An additional obligation proves H inverse composition.

## Captured bias domains and conditional relations [PK2,PK4,PK6]

B_d is the output when all canonical g bytes are zero under that domain's fixed surrounding inputs. It is a sixteen-byte vector in output-address order.

| Profile | Block index | B_d, hex bytes |
| --- | --- | --- |
| separate_ramp16 | 0 | `dc015a0bb2eab1c3d1294b89c42c5765` |
| separate_zero16 | 0 | `dc005808b6efb7c4d9204182c821596a` |
| separate_flip16 | 0 | `5c015a0bb2eab1c3d1294b89c42c5765` |
| separate_ramp32 | 0 | `dc015a0bb2eab1c3d1294b89c42c5765` |
| separate_ramp32 | 1 | `3c39c227779679eb06ed46e4d9860085` |
| separate_zero32 | 0 | `dc005808b6efb7c4d9204182c821596a` |
| separate_zero32 | 1 | `3c39c227779679eb06ed46e4d9860085` |
| separate_clobber | 0 | `dc015a0bb2eab1c3d1294b89c42c5765` |

Consequently, for a common arbitrary g vector in the paired fixed domains, ramp/zero first-block outputs differ by `00 01 ... 0f`; the flip domain differs from ramp only by `80` at output byte 0; and the two second-block domains are identical. The clobber/ramp domains also coincide. This strengthens the prior observed output differences to universal-in-g conditional component relations. It does not quantify arbitrary preparation or derive the upstream fields from preparation. The observed second-block equality alone establishes neither a general chaining mode nor the absence of preparation dependence elsewhere.

Using the parent's actual first-block canonical bytes `30103254cea096d11bd42b7aab598412`, the ramp16 output is `732780382ca3157581b95dc50e78053a`; zero16 is `7326823b28a6137289b057ce02750b35`. The original-instruction checks independently reproduce both.

## Scalar-field origins and loop epochs [PK1,PK2,PK6]

The producer records the last reaching writes for twelve initial u32 packing fields. The audit independently selects the latest writer for each byte of each field, without importing the new producer. These are reaching definitions within the retained whole-caller journals. They are not full mathematical derivations of the fields or their native producers.

| Initial field | First-block reaching store PC | Second-block reaching store PC |
| --- | --- | --- |
| `[SP+0x1e0]` | `0x1b9a58` | `0x1b9a58` |
| `[SP+0x1e4]` | `0x1b9a44` | `0x1b9a44` |
| `[SP+0x1e8]` | `0x1b9a50` | `0x1b9a50` |
| `[SP+0x1f0]` | `0x1b9a20` | `0x1b9a20` |
| `[SP+0x1f4]` | `0x1b9a10` | `0x1b9a10` |
| `[SP+0x2e4]` | `0x1b4464` | `0x1b4464` |
| `[SP+0x204]` | `0x1b9a24` | `0x1b9a24` |
| `[SP+0x208]` | `0x1b99bc` | `0x1b99bc` |
| `[SP+0x364]` | `0x1b8b0c` | `0x1bc0dc` |
| `[SP+0x3ec]` | `0x1b99d4` | `0x1bc0c8` |
| `[SP+0x3f0]` | `0x1b8a64` | `0x1bc104` |
| `[SP+0x3f4]` | `0x1b8b4c` | `0x1bc0f0` |

The four changed writer sites distinguish the retained second-block loop epoch. The scratch write at `0x1bb7a0` occurs inside packing after entry; it does not replace the entry provenance listed above. All 96 field-origin records and 128 output-pointer-origin records are independently verified.

## Validation, scope and continuation

Capture and independent audit each freshly execute the six complete original private caller profiles. The audit reconstructs six initial CPU frames and 3313664 B of initial RAM, checks 488136 visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM. These totals contain the packing visits and accesses; they are not disjoint additional work.

An independent scalar interpreter checks all 5272 packing instruction visits, 816 reads, 136 writes, 10496 B of final stack snapshots, complete ending CPU states and 128 output B. The new partial lift separately checks every modeled read, every ending GPR and the stack against each actual g vector. The artifact field `source_table_reads=128` counts only the sixteen expanded free-g-dependent byte-table interfaces per block: total original LDRB execution count is 320, including 192 fixed byte reads.

A separate Unicorn component fixture runs the unchanged original 659 instructions for all 256 values of each of sixteen canonical bytes, holding the other fifteen at zero. Across eight domains this is `8*16*256 = 32768` executions, `32768*659 = 21594112` instructions and `32768*16 = 524288` checked output B. The all-zero case repeats sixteen times per domain, so each domain covers `1+16*255 = 4081` distinct g vectors. Eight additional actual-entry executions match the complete CPU/stack/output snapshots. The tests assemble explicit private component entries with captured non-result read/CPU/stack inputs; they do not claim whole-caller reachability for every varied byte. The simultaneous all-g claim comes from the source-lift obligations. The auditor does not import the new producer.

All 257 new obligations are freshly UNSAT: 128 byte-address contracts, 128 output-byte contracts and one common inverse. The audit also rechecks 363 frozen obligations, for 620 total. Each solver has a 30 s query limit. Finite tests and SMT have distinct coverage; neither establishes native input admission. No source instruction is altered, no native target/API/IPC executes and no IDB is accessed or mutated. No new Mach port/right, descriptor, emission site, daemon/kext pairing or wire-format field is established.

For C profiles, N blocks, V source visits, J retained per-visit state/journal size, P mapped pages, F page/frame payload size, B pinned source bytes and R other retained bytes, whole replay is conservatively `O(C*(B+V*J+P*F+R))` time/space. Scalar interpretation takes `O(N*659)` time with bounded private memory. Finite component tests take `O(N*16*256*659)` time and bounded per-domain mapped memory; only aggregate counts and ordered-output digests are retained. The recovered affine transfer takes `O(16*8)` bit tests/XORs per block, with sixteen-byte input/output storage. Solver complexity is bounded separately by query limits.

| Impact | Remaining investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Derive preparation/context-to-packing scalar encodings and biases. | Prove all upstream field definitions and their phase constraints; establish or reject an arbitrary-preparation XOR relation. |
| High | Reduce the input prefix and loop-update fields to a compact complete caller oracle. | Join message/preparation/context producers to consumer inputs and the four changed second-block writer sites; account for all side effects. |
| High | Establish native selector/holder/context initialization and upstream record producers. | Require source-produced valid backing, matching object epoch and ownership before assigning native admission or lifetime. |
| Medium | Relate the canonical nonlinear/linear network to a named algorithm. | Require complete checked input/output transformations and context/schedule evidence; ten layers and an affine output map do not identify a cipher. |
| Low | Connect these local output bytes to a cross-process/kernel consumer. | Require an actual serializer/consumer handoff with a matched endpoint/right epoch. Local output stores provide no new Mach emission evidence. |

- **QG1**: No normative premise is required.
- **QG2**: PK1-PK6 identify assumptions, dependent results and falsification probes.
- **QG3**: Result preservation, original packing data/control flow, scatter pointers, scalar origins, phase domains and external-interface limits are covered.
- **QG4**: u8/u32/u64 widths, bit order, modular arithmetic, byte extents, finite cardinalities and complexity are explicit and checked.
- **QG5**: Captured biases are separated from arbitrary preparation; fixed byte reads are separated from free-index tables; loop epochs and repeated zero cases are explicit.
- **QG6**: Pinned original bytes/fixups, fresh complete replay, independent scalar interpretation, unchanged-instruction component tests and retained solver queries supply reproducible provenance.
- **QG7**: Impact-ranked expansion retains the input prefix, scalar/context initialization, native admission and cross-level handoffs. The full investigation remains active.
