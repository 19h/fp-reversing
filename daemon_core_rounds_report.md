# fairplayd: nine main AES-prefix layers and the interleaved source schedule

The core's four main word tables compose into nine complete forward substitution/ShiftRows/MixColumns layers. Their source consumers implement the required column XORs and byte selections, including a layer interleaved with its predecessor. Eight consecutive recovered offset vectors equal AES-128 expanded keys 1 through 8 from one backderived seed. With an explicit input whitening, the nine layers equal the AES-128 encryption prefix ending immediately before round-9 AddRoundKey. All sixteen terminal word-table indices are also recovered. Terminal table semantics, final decoding, complete encryption equivalence and native daemon-kext pairing remain unknown. [CR1-CR5; CR-A1-CR-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| CR1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`: the core instructions and original table bytes. |
| CR2 | [Core lookup](daemon_core_lookup_report.md), [affine-table contracts](daemon_core_affine_report.md), [block staging](daemon_block_staging_report.md), and their pinned checks/audits. Their entry contexts, address/exit admissions, complete replay and initial byte projections remain dependencies. They are not rerun in full here. |
| CR3 | [Extractor and state model](triage_evidence/recover_daemon_core_rounds.py), [checks](triage_evidence/daemon_core_rounds_checks.json.zst): every word-read coordinate, normalized predecessor quartet, source XOR, state offset, round offset vector and explicit terminal-index cut. |
| CR4 | [Auditor](triage_evidence/audit_daemon_core_rounds.py), [audit](triage_evidence/daemon_core_rounds_audit.json.zst): independent source equations, 288 nonvacuous UNSAT queries, original-table checks, byte-array state model, independent key expansion and 64 vector comparisons with the source-derived DAG. |
| CR5 | [Publication verifier](triage_evidence/verify_daemon_core_rounds_publication.py): fresh extraction/audit, query comparison/re-solving, exact manifest delta, original-input preservation and decoded path hygiene. |
| CR6 | [FIPS 197-upd1](https://doi.org/10.6028/NIST.FIPS.197-upd1), sections 5.1 and 5.2, Algorithm 2 and Appendix A.1; [pinned reference capture](triage_evidence/daemon_core_affine_reference.json.zst). The standard defines the reference operations and expansion; it supplies no claim about the target. |

Decoded checks SHA-256: `483171e5eac9b0986b2df25160bbacb803fa78f364766e169f897cb9ff765e5d`. Decoded audit SHA-256: `959f187b700cd067d5b2e8d63f93d6813bb1d06f7da1318d1fd058caf5763949`. The official NIST PDF retains SHA-256 `62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1`, size 1184436 B. This increment checked the pinned local PDF and its Algorithm 2/Appendix A.1 content. The offline auditor regenerates the S-box, validates the independent expansion against Appendix A.1 checkpoints and checks the source constants; it does not refetch the PDF. [CR3-CR6]

## Exact source-composition equation

Let `I_j` be a source word-read index and `Y_j` its raw u32 return value. Let H_b be the bank-specific word normalizer established in CR2. For every word read after the first sixteen, a source-derived record identifies exactly four preceding reads and one row r:

```text
I_j = zero_extend64(byte_r(H_b0(I_k0,Y_k0) XOR
                         H_b1(I_k1,Y_k1) XOR
                         H_b2(I_k2,Y_k2) XOR
                         H_b3(I_k3,Y_k3))) XOR c_j

byte_0 is bits31..24; byte_3 is bits7..0.
```

Every quartet contains one contribution from each of rows 0, 1, 2 and 3 of the preceding semantic layer. In column-major state order `p=4*column+row`, the quartet's predecessor positions satisfy `(input_column-row) mod 4 = destination_column`. This is the forward ShiftRows selection. The 288 queries establish the source equations for both retained contexts with arbitrary original input bytes and arbitrary lookup-return values, without added value premises. They prove the removal of syntactic dependencies outside the quartet; they do not rely on sampled vector agreement. [CR1-CR4; CR-A1-CR-A4]

The first sixteen index codecs and the four finite table normalizations are inherited from CR2. The auditor freshly checks all 1024 original main-table rows against the normalized forward S-box/MixColumns identities. Together, those identities and the new universal source equations compose into the state recurrence below. [CR2-CR4; CR-A1-CR-A4]

## Nine complete layers and their offsets

Let A be the 16 B staged input. Define V[0]=A and, for t=0 through 8:

```text
V[t+1] = MixColumns(ShiftRows(SubBytes(V[t] XOR Q[t])))
```

All state arrays use column-major byte order. SubBytes uses the forward FIPS S-box; MixColumns uses GF(2^8), polynomial `0x11b`, with the forward matrix from CR2. These are semantic states; the source represents them through the recovered affine byte encodings. Every layer uses all sixteen state offsets exactly once and produces all four columns. [CR2-CR4; CR-A1-CR-A4]

| t | Q[t], 16 B hexadecimal in state order |
| --- | --- |
| 0 | `db30b1aef1a66666a2609a87f09227f7` |
| 1 | `72ade2258492da09885aba60b4355b20` |
| 2 | `e69455a862068fa1ea5c35c15e696ee1` |
| 3 | `1b0badf0790d225193511790cd387971` |
| 4 | `14bd0e4d6db02c1cfee13b8c33d942fd` |
| 5 | `31915a8e5c217692a2c04d1e91190fe3` |
| 6 | `c5e74b0f99c63d9d3b067083aa1f7f60` |
| 7 | `45359ba3dcf3a63ee7f5d6bd4deaa9dd` |
| 8 | `42e65a409e15fc7e79e02ac3340a831e` |

For later main layers, each encoded offset removes the byte of the XOR of the four normalized table biases. Applying the corresponding inverse byte matrix and XORing the bank's S-box input delta gives Q[t][p]. This explicitly accounts for the table constants; reading source XOR immediates directly as round keys would produce different values. [CR2-CR4]

The source does not perform these semantic layers in uninterrupted blocks of sixteen reads:

| Semantic layer | Word reads | First..last lookup ordinal | First read PC | Last read PC |
| --- | --- | --- | --- | --- |
| 1 | 16 | 16..31 | `0x10010f2e0` | `0x10010f608` |
| 2 | 16 | 32..47 | `0x10010f628` | `0x10010f860` |
| 3 | 16 | 48..63 | `0x10010f884` | `0x10010fa3c` |
| 4 | 16 | 64..79 | `0x10010fa5c` | `0x10010fc8c` |
| 5 | 16 | 80..95 | `0x10010fcb0` | `0x10010ff80` |
| 6 | 16 | 96..112 | `0x10010ffbc` | `0x100110268` |
| 7 | 16 | 100..127 | `0x100110020` | `0x10011045c` |
| 8 | 16 | 128..143 | `0x100110480` | `0x10011070c` |
| 9 | 16 | 144..159 | `0x100110760` | `0x100110a10` |
| Terminal word inputs | 16 | 160..179 | `0x100110b30` | `0x100110fbc` |

Lookup ordinals count all data-table reads, starting at zero; the first sixteen are byte-table reads. The ordinal ranges above are bounds, not claims that every included read belongs to the layer. [CR2-CR4]

```text
96..99: four layer-6 reads complete one shifted column
   |
100 at 100110020: layer 7 consumes those four contributions
   |
101..112: remaining layer-6 reads, interleaved after that consumer
   |
113..127: remaining layer-7 reads

160..163: first four terminal word reads
164 at 100110c4c: output-side byte-table read
...
179 at 100110fbc: last terminal word read
```

This ordering is recovered from actual instruction/data dependencies. No additional branch or native call is introduced: it remains the parent's fixed core phase with its separately established outgoing authenticated-branch operands. [CR1-CR4; CR-A1-CR-A2]

## AES-128 expansion subsequence and input whitening

Inverting expansion round 1 from Q[1] gives the 16 B seed K=`db55ebcef63f382c0cc860693c6fe140`. Independent FIPS AES-128 expansion from K exactly produces Q[1] through Q[8] at expansion indices 1 through 8, respectively. The eight vectors are checked byte-for-byte in both contexts. This is a recovered expansion identity, not a claim that the daemon receives or stores K as an exposed native key object. [CR3-CR6; CR-A3-CR-A5]

Q[0] differs from K. Define W=`00655a6007995e4aaea8faeeccfdc6b7`; then `Q[0]=K XOR W`. Consequently the nine-layer recurrence equals the standard AES-128 forward prefix on `A XOR W`, under K, through MixColumns of round 9 and before AddRoundKey of round 9. Q[0] itself, used directly as a seed in the same byte convention, fails all eight later vector comparisons. That rejected direct-seed hypothesis does not contradict the established backderived expansion subsequence. [CR3-CR6; CR-A3-CR-A5]

```text
staged A -- XOR W -- AES-128 prefix under K
                         |
                 nine main rounds through round-9 MixColumns
                         |
                 sixteen encoded terminal word indices
                         |
                 terminal semantics / final decoding: unknown
```

Expansion indices 9 and 10 are retained as predictions only; no source claim about their use is established here. Native key origin, lifetime, caller selection and cross-component material correspondence remain unknown. Prior external-input staging retains its own input mask and premises; W is the new core-coordinate whitening, not a replacement for that external mask. [CR2-CR6; CR-A1-CR-A2,CR-A5-CR-A6]

## Terminal index interface

Let M_r be the row encoder from CR2 and V[9] the canonical state after the nine main layers. Each terminal word index is exactly `M_r(V[9][p]) XOR q[p]`. The encoded q vector in input-offset order is `7dbd42bfa1a10d61974a0bfa6806b39b`. All sixteen p values occur once. [CR3-CR4]

| Input row r | Terminal word bank | State offsets p |
| --- | --- | --- |
| 0 | `0x100ed3a70` | 0, 4, 8, 12 |
| 1 | `0x100f400e0` | 1, 5, 9, 13 |
| 2 | `0x10101ab70` | 2, 6, 10, 14 |
| 3 | `0x100f2e680` | 3, 7, 11, 15 |

Every terminal read PC, original ordinal, p, source XOR and corrected encoded q is retained in CR3. This terminal interface constrains subsequent decoding without assuming that the final banks have the same S-box delta or word normalization as the main banks. Output-side byte lookups are interleaved with the terminal word reads; complete output equivalence is outside this increment. No new Mach right, message-emission site, IOKit selector or native daemon-kext transaction correspondence is established. [CR1-CR4; CR-A5-CR-A6]

## Verification, assumptions and limits

The fresh audit checks 288 universal source equations, all 1024 original normalized main-table rows, 64 vector comparisons across the two source contexts, 10240 word-index comparisons and 640 canonical-state comparisons. A separately arranged byte-array state implementation uses xtime columns; the extractor uses generic finite-field multiplication. Both agree with all 160 word-read addresses in each tested source-derived DAG execution. The retained original outputs also match the pinned parent outputs. Vector agreement supplements the compositional source/table proof; it does not replace it. The prior complete instruction replay and entry/address/exit admissions are pinned rather than rerun. [CR2-CR5]

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| CR-A1: Pinned source, parent contexts and source-lift semantics apply | Original coordinates and source equations | Rehash dependencies, freshly lift all source cuts and re-solve arbitrary-return equations; compare the parent lift against another ISA implementation. |
| CR-A2: Retained literals, placements and table bytes apply | Conditional nine-layer semantics | Recover authentic caller/controller epochs, runtime mappings and table preservation beyond the two contexts. Declared image protection does not establish live immutability. |
| CR-A3: State order, row encoders and FIPS field/schedule convention apply | Layer identification and expansion subsequence | Independently arrange ShiftRows/MixColumns, regenerate all S-box bytes, check original finite tables and Appendix A.1 expansion checkpoints. |
| CR-A4: Every source composition cut is established, including interleaving | Complete nine-layer recurrence and terminal indices | Verify all 160 records, all preceding quartets, each 16-position permutation and all 288 source queries. A contiguous-sixteen-read heuristic fails at ordinal 100. |
| CR-A5: Prefix equivalence is distinguished from terminal/full-key semantics | AES-128 prefix under K on whitened A | Decode the four terminal banks and output byte maps; prove final source consumers and compare complete encryption vectors before claiming whole-cipher equivalence. Expansion indices 9/10 remain predictions. |
| CR-A6: Core component state is distinguished from native transport/material lineage | No new native key object, Mach endpoint or daemon-kext pairing | Join authentic consumers, object lifetimes and matched port/right/IOKit transaction histories to the recovered state. |

Reproduction uses the established Python/Z3 environment: run `recover_daemon_core_rounds.py`, then `audit_daemon_core_rounds.py`; after manifest refresh run `verify_daemon_core_rounds_publication.py`. Nontrivial JSON uses `zstd --ultra -22 -q -T1`, with decoded hash and roundtrip verification. The fixed prefix uses nine 16 B states, with O(9*16) byte/field work and O(10*16) retained state/index storage; key expansion uses 176 B and O(176) byte operations. Source lifting, DAG evaluation and solver search are additional; source queries use the explicit QF_BV solver with a 30 s limit per query. No native target, API/IPC, hardware PAC or IDB mutation occurs. [CR3-CR5]

| Impact | Bounded continuation | Required evidence |
| --- | --- | --- |
| High | Establish complete encryption and output semantics | Terminal-bank factorization, output byte-map identities, universal final-consumer equations and complete independent vectors. |
| High | Establish material and daemon-kext correspondence | Authentic caller objects, selection/lifetime evidence and matched IPC/IOKit exchanges. |
| Medium | Generalize the source environment | Controller selection and table/mapping preservation outside retained contexts. |
| Medium | Avoid false round boundaries in related routines | Data-dependency reconstruction; the observed layer and output-lookup interleaving falsifies contiguous-block assumptions here. |

**QG1**: Factual technical scope. **QG2**: CR-A1 through CR-A6 register dependent results and falsification probes. **QG3**: Nine main layers, all terminal word indices, interleaved control/data order, expansion subsequence and transport limits are covered; the full goal remains active. **QG4**: u8/u32/u64 widths, column-major state order, GF polynomial, byte extents, counts and complexity are explicit. **QG5**: Source order versus semantic layers, raw versus corrected offsets, prefix versus full encryption, predicted final keys versus source evidence and core versus external whitening are distinguished. **QG6**: Pinned original bytes, universal solver queries, independent field/state/schedule checks and the official standard provide provenance. **QG7**: Impact-labelled continuation is bounded above. All gates pass for this increment; final decoding and native interaction lineage remain unknown.
