# CoreFP late preparation and first-block output transfer

Subsequent phase evidence: the [preparation-scans report](corefp_preparation_scans_report.md) resolves the forty earlier prepared-byte reads into two bounded split scans with one common state recurrence and equal XOR deltas. It retains the split-dependent scratch residues and their source kills. Complete propagation into phase/workspace parameters and general raw-input admission remain unresolved.

The late preparation window converts sixteen prepared bytes into four big-endian words using exactly the inverse of the previously recovered output byte map. One temporary word has an additional `0xab` XOR, canceled before packing. Across six retained first-block domains, the composed transfer is:

```text
out[j] = H(g[pi[j]]) XOR p[j] XOR c[j]
c      = 405d850bd17f414f2d5b9ae4907df42b
```

Here p is the sixteen-byte late prepared interface, g is the canonical final consumer interface, and pi/H are the [output-packing report's](corefp_output_packing_report.md) fixed permutation and binary-linear map. Source obligations quantify all 256 bits of p and g jointly, with the earlier entry/read interfaces fixed and an explicit canonical-result interface cut. The original source also preserves its actual consumer results for arbitrary p under those fixed entry premises. This establishes the late data path; it does not establish a whole-caller arbitrary-raw-preparation contract, native entry admission or the complete transform identity.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_late_preparation.py), [checks archive](triage_evidence/corefp_late_preparation_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_late_preparation.py), [audit archive](triage_evidence/corefp_late_preparation_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_late_preparation_publication.py) retain source bytes, six entry/end states, intermediate words, complete regional accesses, PAC records and queries. Six parent receipts and nine frozen source readers/producers are SHA-256 pinned. The original supplied inputs are unchanged.

CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. PCs are preferred-base-zero offsets; B denotes bytes. The region `[0x1b87dc,0x1bbff4)` is 14360 B/3590 four-byte instructions, inside the existing 59120 B caller/allocator/retirement source coverage. It overlaps the prior consumer and packing regions and is not additional disjoint source coverage.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| LP1 | Pinned source, fixups, six parent receipts and frozen dependencies describe this image. All source claims depend on these bindings. | Compare all retained original bodies, every regional instruction and dependency digest; retain all three supplied inputs unchanged. |
| LP2 | Existing private caller/context/pool/malloc/PAC/sequential-CASAL fixtures apply. Whole-caller continuity depends on them. | Reconstruct six initial CPU/RAM states and freshly replay all 488136 visits. Native context production, object admission and concurrency semantics remain unknown. |
| LP3 | At late entry, p occupies SP+`0x498`..SP+`0x4a7`; all other entry CPU/stack/read interfaces are fixed to the selected retained domain. Universal p claims depend on that separation. | Replace all sixteen bytes independently in the source model; interpret every actual access and test 24576 component cases. Forty earlier preparation reads remain outside this quantified entry and require separate dependency proofs. |
| LP4 | Original immutable byte-table windows, typed private stack/output backing and the retained relocated pointer-read interface apply. Load/store and PAC-target contracts depend on them. | Expand every selected table to all 256 original bytes, prove effective-address bounds and compare all reads/writes. Require valid disjoint backing; no arbitrary native address is accessed. Native PAC authentication is not executed. |
| LP5 | At `0x1bad9c`, the sixteen result slots may be treated as a typed canonical-g interface. The joint p/g theorem is an interface composition. | First prove the original q144..q159 values independent of p under LP3, then substitute sixteen free encoded g bytes at this proof cut. Actual-instruction tests use the original consumer's actual g; no source instruction or IDB is patched. |
| LP6 | The first-block entry and captured earlier phase describe the claimed domains. General raw-input and later-block contracts remain unknown. | Count the single late-window entry per complete profile and distinguish the four later loop-update stores. Prove earlier phase/history coherence and loop updates before extending the theorem to arbitrary raw preparation or later blocks. |

## Source epochs and control flow [LP1-LP4,LP6]

The prepared bytes are read at three separate epochs in each retained profile. Their initial source-to-prepared transform is already proven in the [workspace report](corefp_workspace_report.md). This increment freezes state after the first two epochs and quantifies the bytes only at the late epoch.

| Prepared-byte epoch | Source load sites | Read instances per complete profile | Role established here |
| --- | --- | --- | --- |
| Earlier epoch 1 | `0x1b536c`, `0x1b5380`, `0x1b5390`, `0x1b53a0`, `0x1b53cc`, `0x1b544c` | 20 | Outside the late-entry quantifier; prior state/phase input |
| Earlier epoch 2 | `0x1b6530`, `0x1b6544`, `0x1b6554`, `0x1b6560`, `0x1b65ac`, `0x1b6628` | 20 | Outside the late-entry quantifier; prior state/phase input |
| Late epoch | Sixteen distinct sites, listed below | 16 | Reversible encoding into four u32 words, followed by output XOR |

The late entry `0x1b87dc` occurs once in each of six complete profiles, including both 32 B controls. The first output-packing end occurs 3590 source visits later. Each 32 B control has a second packing end without another late entry. A first-block theorem therefore does not silently describe a second invocation of the late window.

| Contiguous source interval | Instructions | B | Treatment |
| --- | --- | --- | --- |
| `[0x1b87dc,0x1b8b50)` | 221 | 884 | Sixteen late p loads and four reversible encoded words |
| `[0x1b8b50,0x1ba0c0)` | 1372 | 5488 | Remaining prefix/state and pointer preparation; one declared PAC interface |
| `[0x1ba0c0,0x1bad9c)` | 823 | 3292 | Original consumer network; actual final results proven p-independent |
| `[0x1bad9c,0x1bb5a8)` | 515 | 2060 | Preserves the result slots/registers; original computations retained |
| `[0x1bb5a8,0x1bbff4)` | 659 | 2636 | Original scatter packing; joint p/g affine transfer |

The sole control-transfer instruction in this interval is `0x1b9b34: braa x8,x17`, targeting the immediately following `0x1b9b38`. For each domain, separate obligations establish the target and modifier `0x1410` independently of free p. Parent authenticated-fixup records supply the relocated pointer interface. Component execution checks the computed target/modifier and models this one PAC instruction by advancing to that target. Cryptographic PAC acceptance, failures and native branch execution remain unknown. There is no call, conditional branch or API boundary within the region.

## Late byte loads and reversible word encoding [LP1,LP3,LP4]

p[j] is one u8 at SP+`0x498+j`, equivalently FP-`0x88+j` because FP=SP+`0x520`. Every p byte is loaded once in the window, in the following source order.

| p index | LDURB PC | p index | LDURB PC |
| --- | --- | --- | --- |
| 7 | `0x1b87dc` | 1 | `0x1b8868` |
| 14 | `0x1b8890` | 2 | `0x1b88bc` |
| 9 | `0x1b8910` | 15 | `0x1b893c` |
| 4 | `0x1b897c` | 3 | `0x1b8994` |
| 8 | `0x1b89c8` | 13 | `0x1b89e8` |
| 0 | `0x1b8a2c` | 5 | `0x1b8a68` |
| 6 | `0x1b8a98` | 10 | `0x1b8abc` |
| 11 | `0x1b8aec` | 12 | `0x1b8b10` |

Define E=H inverse, a binary-linear u8 permutation. Its columns, least-significant input bit first, are `27 66 c2 cc 94 75 c0 ee`. All 256 values are distinct and H(E(x))=x for every u8 x. Let BE4(a,b,c,d) mean the u32 value `(a<<24)|(b<<16)|(c<<8)|d`; memory stores remain little-endian AArch64 stores.

| Word | Initial store PC | Initial slot | Exact u32 value at `0x1b8b50` | Slot at packing entry |
| --- | --- | --- | --- | --- |
| 0 | `0x1b8a64` | `[SP+0x3f0]` | `BE4(E(p0),E(p1),E(p2),E(p3))` | `[SP+0x3f0]` |
| 1 | `0x1b8ab8` | `[SP+0x284]` | `BE4(E(p4),E(p5),E(p6),E(p7)) XOR 0xab` | `[SP+0x3ec]`, after XOR cancellation |
| 2 | `0x1b8b0c` | `[SP+0x364]` | `BE4(E(p8),E(p9),E(p10),E(p11))` | `[SP+0x364]` |
| 3 | `0x1b8b4c` | `[SP+0x3f4]` | `BE4(E(p12),E(p13),E(p14),E(p15))` | `[SP+0x3f4]` |

For word 1, the original instructions `0x1b99cc: ldr w8,[sp,#0x284]`, `0x1b99d0: eor w11,w8,w11` with W11=`0xab`, and `0x1b99d4: str w11,[sp,#0x3ec]` remove the temporary XOR. The later overwrite of SP+`0x284` at `0x1b9a3c` is a separate epoch and does not alter the already transferred word.

Four u32 obligations per domain prove these word equations for all sixteen free p bytes simultaneously. The source lift handles the original table accesses, masked arithmetic, rotations, bit-field insertion and flag-dependent CNEG sequence. It does not infer the equations merely from observed word values.

The sixteen late-encoding byte-table reads use original windows based at `0x1676d40`, `0x19b4b00`, `0x1a32cb0` and `0x1b40a00`. Sixteen later free-g-index reads use the four windows already established in the output-packing report. All 32 expanded interfaces per domain bind complete 256 B source windows. Address obligations cover both page-aligned and nonaligned bases using u64 modular arithmetic and zero-extended u8 indices.

## Consumer independence and joint output theorem [LP3-LP5]

The lift follows the unchanged original region through the consumer end. Sixteen obligations per domain establish that every q144..q159 destination contains its retained original encoded value independently of all p bytes. Thus late p variation does not alter these actual consumer results under the fixed earlier entry/read premise. This does not assert independence from the forty earlier preparation reads or from arbitrary context/message state.

At the explicit proof cut `0x1bad9c`, q144..q159 are then replaced in the symbolic state by `(u32(g[i])<<8) XOR 0x65 XOR Q_phase`, using the exact four-register/twelve-stack-slot interface established by the parent reports. g is free and independent of p. This substitution is a mathematical interface cut; it is not an executed instruction, source patch, new native entry or altered IDB.

The remaining source computes:

```text
pi = [9,7,1,5,15,10,13,12,3,11,0,4,14,6,2,8]
H columns, least-significant bit first:
     [bc,44,35,7d,da,cc,bf,ff]

out[j] = H(g[pi[j]]) XOR p[j] XOR c[j]
c      = 405d850bd17f414f2d5b9ae4907df42b
```

Sixteen output obligations per domain quantify all sixteen p bytes and all sixteen g bytes jointly. The same c holds in all six domains: ramp16, zero16, flip16, ramp32 first block, zero32 first block and clobber. These domains retain five earlier storage-encoding classes. For the actual unchanged source, substitute the original consumer's retained g vector; the theorem then describes arbitrary late p under each domain's fixed earlier state.

The parent preprocessing stage proves `p[j]=raw_preparation[j] XOR m[j]`, where `m=9c5ddd036790f68bf47bdb66585cad41`. Algebraic substitution gives the conditional raw-interface expression:

```text
out[j] = H(g[pi[j]]) XOR raw_preparation[j] XOR k[j]
k      = c XOR m = dc005808b6efb7c4d9204182c821596a
```

This is conditional on the earlier entry state/read premises and the preprocessing binding. A complete original-caller theorem for arbitrary raw preparation still requires proof that the intervening forty earlier preparation reads establish a coherent admissible state for the late component. The six retained classes alone do not cover every possible earlier phase. The algebraic substitution does not supply that missing proof.

## Validation and remaining interface boundaries

Capture and independent audit each freshly execute six complete original private caller profiles. The audit reconstructs six initial CPU frames and 3313664 B of initial RAM; it checks 488136 source visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM. Regional counts are contained within those totals.

The independent scalar interpreter checks all 21540 regional visits, 3816 reads, 948 writes, 7872 B of final stack snapshots, complete ending CPU states and 96 output B. Each actual region reads 2438 B and writes 660 B; six regions therefore read 14628 B and write 3960 B. The new partial lift independently compares every actual modeled read, write-before/write-after value, ending GPR, NZCV and stack byte. Four intermediate preparation words are checked in every domain.

A separate original-byte component fixture tests all 256 values of each late p byte, holding the other fifteen at zero and retaining the actual original consumer g. There are `6*16*256=24576` cases, `24576*3590=88227840` source visits, 24576 explicitly modeled PAC instructions and `24576*3589=88203264` emulated instructions. All 98304 intermediate preparation words and 393216 output B match independent integer/byte oracles. The zero vector repeats sixteen times per domain; each domain covers `1+16*255=4081` distinct p vectors. Six additional actual-entry component executions match complete CPU/stack/output snapshots. The finite tests do not exhaust the simultaneous 256-bit p/g domain; source obligations establish that joint interface theorem.

All 420 new obligations are independently rechecked as UNSAT: 192 byte-address contracts, 96 preserved consumer values, 24 preparation-word equations, twelve PAC target/modifier equations and 96 joint output equations. Rechecking 620 frozen obligations yields 1040 total, each with a 30 s solver limit. The auditor imports frozen dependencies and does not import the new producer.

No native target/API/IPC or cryptographic PAC authentication executes, and no IDB is accessed or mutated. Original reference bytes suffice. There is no new Mach port/right, descriptor, emission site, daemon/kext endpoint match or wire-format assignment. The sixteen stores and pointer slots remain exactly those in the output-packing report. The full interface investigation remains active.

For C profiles, N first-block regions, V source visits, J per-visit state/journal size, P touched pages, F page/frame payload size, B pinned source bytes and R other retained bytes, whole replay is conservatively `O(C*(B+V*J+P*F+R))` time/space. Scalar interpretation takes `O(N*3590)` time with bounded private memory. Finite component tests take `O(N*16*256*3590)` time and bounded per-domain private maps; only aggregate counts and ordered-output digests are retained. Each component run has one PAC model and one four-word checkpoint. The reduced transfer takes `O(16*8)` bit tests/XORs per block and sixteen-byte input/output storage. Solver resource limits are separate from these finite algorithms.

| Impact | Remaining investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Prove the earlier preparation-dependent phase construction. | Recover all forty earlier reads' downstream definitions and establish coherent phase families; then prove or reject the whole-caller arbitrary-raw-preparation expression. |
| High | Reduce message/context input staging and later-block state updates. | Derive consumer input words and all four loop-update definitions at `0x1bc0c8`, `0x1bc0dc`, `0x1bc0f0`, `0x1bc104`; distinguish message input from late preparation. |
| High | Establish native selector, holder, context and upstream record production. | Require source-produced backing, matching epochs and ownership before native admission or lifetime claims. |
| Medium | Identify the complete transform, if evidence permits. | Require complete checked input/output and context/schedule mappings; the H/E cancellation alone assigns no cipher identity. |
| Low | Connect local results to cross-process/kernel consumers. | Require an actual serializer/consumer handoff and matched endpoint/right epoch. Local source equivalence does not establish a Mach emission. |

- **QG1**: No normative premise is required.
- **QG2**: LP1-LP6 identify assumptions, dependent results and falsification probes.
- **QG3**: Late byte reads, reversible word encoding, temporary XOR cancellation, original consumer preservation, joint output composition, control flow and external-interface limits are covered.
- **QG4**: u8/u32/u64 widths, bit/byte order, byte extents, quantifier domains, PAC accounting, repeated zero cases and complexity are explicit.
- **QG5**: Earlier and late preparation epochs, actual source and symbolic interface cuts, first and later blocks, finite and universal evidence remain distinct.
- **QG6**: Pinned original bytes/fixups, fresh whole-caller replay, independent scalar interpretation, original-byte component tests and retained solver queries supply reproducible provenance.
- **QG7**: Impact-ranked continuation retains the earlier phase, message/context staging, loop updates, native admission and cross-level handoffs. The full goal remains active.
