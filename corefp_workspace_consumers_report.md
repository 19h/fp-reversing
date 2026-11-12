# CoreFP workspace consumers and canonical substitution network

The straight-line region `[0x1ba0c0,0x1bad9c)` reduces to ten layers of sixteen byte substitutions, with 36 intervening mixed-word nodes. The first nine substitution layers use the first workspace's affine word expansion; the final layer uses the second workspace's byte expansion. The compact network reproduces every workspace read and all sixteen final private destinations in eight blocks across six complete caller profiles. It does not identify the whole transform or its native input contract.

This extends the [workspace constructor report](corefp_workspace_report.md). Under the retained controls, changing preparation bytes changes stored representations but preserves the decoded first-block inputs, all 36 canonical XOR offsets and the final sixteen canonical substitution values. These cross-profile equalities are finite observations. The source contracts instead quantify over the component's register/load interfaces, with explicit frame, shift and encoding premises.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_workspace_consumers.py), [checks archive](triage_evidence/corefp_workspace_consumers_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_workspace_consumers.py), [audit archive](triage_evidence/corefp_workspace_consumers_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_workspace_consumers_publication.py) retain the source lift, complete network, queries, eight entry/end states and all regional reads/writes. Parent receipts are pinned by their decoded SHA-256 values; parent journals are reused without modification.

CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses are preferred-base-zero offsets; B denotes bytes. The 3292 B consumer region is a subset of the 59120 B complete caller/allocator/retirement bodies, not additional disjoint source coverage. Its 823 instructions are all 4 B wide.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| WC1 | Pinned source, fixups, parent journals and frozen readers describe this image. All source claims depend on them. | Compare all three original bodies, dependency hashes and every byte of the consumer region; retain the three supplied inputs unchanged. |
| WC2 | Existing private entry/context/pool/malloc/PAC/sequential-CASAL premises apply. Complete paths depend on them. | Independently reconstruct six initial CPU/RAM states and replay all 488136 visits. Native context initialization, native object admission and concurrency semantics remain unknown. |
| WC3 | FP=SP+`0x520`; typed stack slots and two 1024 B workspaces are disjoint and backed. Component memory contracts depend on these interfaces. | Interpret every original load/store independently, compare all regional accesses and 1312 B final stack snapshots; require nonwrapping valid backing before any native address-range interpretation. No arbitrary native pointer is accessed. |
| WC4 | The two masked variable shifts have sum 24, and one of the five captured storage-encoding classes applies. The compact byte network depends on these premises. | Check both source shift loads in every block; prove the split-shift extraction under that premise and each class's canonicalization. Other native phases remain unclassified. |
| WC5 | The fixed G/L constructor relation and absence of workspace writes hold at the read epoch. Canonical substitutions depend on that binding. | Reconstruct all 256 source entries, recheck both complete workspaces through the parent oracle, and compare all 1280 regional table reads. The generic source lift treats each read result as an arbitrary u32 before this binding. |
| WC6 | Equal canonical values across the retained controls describe those eight blocks. Cross-profile invariance depends on that finite scope. | Compare preparation ramp/zero/byte-flip, clobber and both message extents. A general preparation-output or input-admission claim requires the missing prefix/tail proofs. |

## Component input, state and memory contracts [WC1-WC4]

The component begins after the message/state-encoding prefix. Four u32 values in W8, W13, W14 and W16 supply its first sixteen byte indices. Initial W3/W24/W26/W30 and stack words supply XOR terms in the mixed-word nodes. The complete 36-node wiring and every stack/register term are retained in the checks archive. These are private component interfaces; the words' native key or payload meanings remain unknown.

| Interface | Exact binding |
| --- | --- |
| First workspace pointer | `[FP-0xf8]`, equivalently `[SP+0x428]`; retained value `0x64002f60` |
| Second workspace pointer | `[FP-0xf0]`, equivalently `[SP+0x430]`; retained value `0x64002b34` |
| First workspace reads | 144 distinct original load sites per block, from `0x1ba0c8` through `0x1bac80` |
| Second workspace reads | 16 distinct original load sites per block, from `0x1bac8c` through `0x1bad94` |
| Lookup address | Selected base + `4*index_u8`; one u32 read per lookup |
| Split-shift fields | `[SP+0x1fc]` and `[SP+0x1a0]`, loaded at `0x1ba1f8` / `0x1ba200` |
| Split-shift premise | `(first_u32 AND 31) + (second_u32 AND 31) = 24`, with a nonwrapping sum in 0..62 |
| Independent status | `[SP+0x360] = u32([SP+0x3f8] < 0x44506381)`, unsigned comparison; store at `0x1ba33c` |
| Restored pointers | Stores at `0x1bac0c` / `0x1bad90` restore the original first/second bases in the two stack slots |

The retained shift pairs are `(0,24)`, `(24,0)` and `(16,8)`. A source obligation proves that the sequential logical shifts select bits 31..24 under the stated masked-sum premise. It does not assume that arbitrary source fields select that byte.

Pointer cancellation is reduced in the u64 modular ring. Five universal ring identities support associative addition, additive inverses, shift distribution, shifted negation and coefficient combination. The lift then proves all 160 normalized effective-address contracts. It separately proves a flag-dependent arithmetic sequence to be an XOR/byte-rotation combination. The independent concrete interpreter executes the original CMP/TST/CSET/CNEG sequence and checks the complete ending CPU state, including NZCV.

## Compact network and canonical form [WC1,WC3-WC5]

Let q_j denote a workspace read's u32 result, numbered by source execution order, and let `byte_s(w)` select u8 lane s of a u32 word, with lane 0 least significant. Each mixed word has this form:

```text
W_n = offset_n XOR XOR_j ROR32(q_j, 8*r_j)
```

Each node uses four q values, with rotations r_j being exactly a permutation of `{0,1,2,3}`. The source's stack/register XOR terms determine offset_n. Four subsequent substitutions select its four byte lanes. The complete graph has four mixed words in each of nine layers, hence 36 mixed words and 144 table-expanded substitutions, followed by sixteen final byte-expanded substitutions.

Source order is interleaved: read q15 at `0x1ba20c` already belongs to the second substitution layer, while q16 at `0x1ba238` completes the first layer. A naive grouping of each consecutive sixteen reads therefore assigns these two reads incorrectly. Dependency depth gives exactly sixteen reads in each of ten layers. The audit checks this topology and all 160 source-index equalities.

Use the constructor report's fixed permutation G, affine expansion L and storage maps. Define T without its final XOR, and D as the word decoding map:

```text
T(w) = BR_r(w XOR ((w AND M)<<1)), modulo 2^32
D(w) = T^-1(w XOR repeat_u8(b))
first_workspace[pi(i)]  = T(L(G(i))) XOR K
second_workspace[pi(i)] = (G(i)<<8) XOR 0x65 XOR Q
pi(i) = low8(T(i)) XOR b
```

For all five retained classes, `M AND 0x80808080 = 0`. Consequently T acts separately and identically on each u8 lane, is XOR-linear and commutes with whole-byte word rotations. Its inverse is the lane rotation inverse followed by the previously proven triangular inverse. Five additional source-model obligations prove inversion, byte/index decoding, the four-term mixing identity and final byte extraction.

For a mixed node whose encoded XOR term is offset_n, define:

```text
DeltaK = XOR_{r=0..3} ROR32(K,8*r)
C_n    = T^-1(offset_n XOR DeltaK XOR repeat_u8(b))
D(W_n) = C_n XOR XOR_j ROR32(L(G(i_j)),8*r_j)
```

Thus the compact model runs directly on G/L and the 36 canonical XOR offsets C_n. It uses decoded initial W8/W13/W14/W16 values and the retained graph's byte selections. It reconstructs each encoded address and read result for comparison with original execution. At the final layer it emits G(i), then reconstructs the source value `(G(i)<<8) XOR 0x65 XOR Q` for the destination checks. The model does not infer a native key schedule from these XOR offsets.

```text
four encoded u32 component inputs
                |
            decode D
                |
      16 substitutions G followed by L
                |
      +-- 9 layers of four mixed words --+
      |   canonical offsets C_n         |
      |   four rotated terms per word   |
      |   byte selection -> G           |
      |   L after layers 1..8           |
      +---------------------------------+
                |
        16 final canonical bytes
                |
     second-workspace word encoding
                |
       12 stack slots + 4 registers
```

## Final private destinations [WC1,WC3-WC5]

The table gives source read IDs/PCs and their locations at `0x1bad9c`. Each location contains the encoded final u32 value; register writes zero-extend to u64. All stack offsets are relative to the unchanged SP. The [output-packing continuation](corefp_output_packing_report.md) now joins these values to all sixteen later output stores, with simultaneous arbitrary-result proofs under each captured non-result input/read premise.

| Read ID | Original load PC | Destination at component end |
| --- | --- | --- |
| q144 | `0x1bac8c` | `W14` |
| q145 | `0x1bac9c` | `[SP+0x348]` |
| q146 | `0x1baca8` | `[SP+0x35c]` |
| q147 | `0x1bacb8` | `W15` |
| q148 | `0x1bacc0` | `W17` |
| q149 | `0x1bacc8` | `[SP+0x338]` |
| q150 | `0x1bacd4` | `[SP+0x358]` |
| q151 | `0x1bace0` | `[SP+0x328]` |
| q152 | `0x1bad54` | `[SP+0x354]` |
| q153 | `0x1bad5c` | `[SP+0x324]` |
| q154 | `0x1bad64` | `[SP+0x344]` |
| q155 | `0x1bad6c` | `W6` |
| q156 | `0x1bad70` | `[SP+0x340]` |
| q157 | `0x1bad78` | `[SP+0x33c]` |
| q158 | `0x1bad88` | `[SP+0x350]` |
| q159 | `0x1bad94` | `[SP+0x334]` |

The component has fifteen stack writes per block: twelve final u32 values, one u32 status and two u64 pointer restorations, totaling `12*4 + 4 + 2*8 = 68 B`. It writes neither workspace. Exact entry/end register states, stack bytes, all 204 reads and all fifteen writes are compared with an independent scalar interpreter for every retained block.

## Retained canonical invariants [WC2,WC4-WC6]

All eight retained blocks have the same 36 canonical XOR offsets. Their little-endian u32 concatenation is 144 B with SHA-256 `2ff2cdf425505ad399c66f1430ab0c9f373735d24bc34e2a37ed9b5c05043016`. The complete vector is in the audit archive. This establishes a fixed vector in the retained controls, not its native origin, secrecy, schedule or universality.

| Retained block | Decoded W8, W13, W14, W16 | Final canonical bytes, read-ID order |
| --- | --- | --- |
| First block, six profiles | `8f2dcc03 7c2f1537 16eb16d8 ccdd8dd4` | `30103254cea096d11bd42b7aab598412` |
| Second block, two 32 B profiles | `1bb95897 e8bb81a3 827f824c 58491940` | `edc841629239fe868524fe64711d0994` |

The preparation ramp/zero/one-byte changes therefore preserve this component's decoded first-block inputs, offsets and outputs, while the preceding report observes changed final message output. This localizes the retained difference outside the canonical consumer component. The [output-packing continuation](corefp_output_packing_report.md) locates all later output stores and reduces their transfer to a common affine byte map plus a captured-state bias. A general preparation/chaining contract and the input prefix remain explicit work.

## Validation and interface limits

Two fresh executions of the retained original-byte fixtures were used for capture and independent audit. The auditor reconstructs six initial CPU frames and 3313664 B of initial RAM, checks 488136 visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM. All six original private caller paths return completely. These totals include the regional counts below; they are not additional disjoint visits.

The independent scalar interpreter checks 6584 regional instructions, 1632 reads, 120 writes and 10496 B of final stack snapshots across eight blocks. The canonical oracle checks 1280 table reads, 288 mixed-word instances and 128 final destinations. The source lift covers all 823 instructions/3292 B. New proof counts are 330 source/ring/network obligations plus five phase obligations, totaling 335; 28 frozen obligations are freshly UNSAT, yielding 363 in total. Universal obligations quantify the lifted equations under the typed-load premises. Source binding is checked by independent original-byte replay and scalar interpretation in the retained profiles. Every solver query has a separate 30 s limit.

For C profiles, N regional blocks, V original visits, J retained per-visit state/journal size, P touched pages, F page/frame payload size, B pinned source bytes and R additional retained bytes, replay/capture is conservatively `O(C*(B+V*J+P*F+R))` time/space. The scalar regional interpreter is `O(823*N)` time with bounded private memory. The compact network uses 160 substitutions and 36 four-term word combinations per block, hence `O(N*(160+36))` time and `O(160+36)` auxiliary words; each affine expansion has eight conditional XOR terms. SMT is bounded separately from these finite algorithms.

No new native API, IPC, Mach port/right, descriptor, daemon/kext pairing or emission site is established. The component reads private stack/workspace state; its only writes in the retained region are to the same private stack. No native target is executed and no IDB is accessed or mutated in this increment. Original file/fixup evidence suffices. No public input type, native key schedule or complete transform identity is assigned.

| Impact | Next investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Join the input prefix and packing-bias producers to record/message/preparation fields. | The output-packing continuation supplies the final-byte-to-output map; field-to-word derivations and the general preparation-XOR relation remain open. |
| High | Establish source context, selector and holder initialization plus upstream record producers. | Require reaching stores and valid same-epoch backing before native admission or ownership claims. |
| High | Reduce context/ARX preparation and loop-update fields. | The packing continuation accounts for every local output store; a compact complete caller oracle still requires the upstream computations and loop epochs. |
| Medium | Classify the canonical nonlinear/linear component more broadly. | Require explicit checked transformations and complete-domain equality; round count or differential uniformity alone is insufficient. |
| Low | Connect decoded local words to cross-process/kernel messages. | Require an actual producer/consumer handoff and port/right epoch; local equivalence alone supplies no wire meaning. |

- **QG1**: No normative premise is required.
- **QG2**: WC1-WC6 state assumptions, dependencies and falsification probes.
- **QG3**: The consumer's data/control flow, typed interfaces, encoding phases, stores and external-interface limits are covered.
- **QG4**: Byte extents, u8/u32/u64 widths, masked shifts, lane numbering, rotations, modular arithmetic and complexity are explicit.
- **QG5**: Dependency layering handles interleaved reads; status/pointer effects remain in scope; canonical invariance is bounded to retained controls.
- **QG6**: Pinned original source/fixups, fresh whole-caller replay, an independent scalar interpreter, canonical oracle and retained solver queries supply provenance.
- **QG7**: Impact-ranked continuation retains the missing prefix, tail, initialization, ownership and cross-level handoffs. The full investigation remains active.
