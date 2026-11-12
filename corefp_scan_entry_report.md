# CoreFP scan initializers, shared stack fields and fold-value handoff

Both scan initializers implement one u64 mixer with three u32 XOR outputs. Their incoming bank XOR is preserved when their u64 seeds agree and the first initializer's variable shift equals two. Three earlier stack encoding/decoding pairs independently explain the literal bank difference `0xeb3e515b`. The arithmetic passes between those pairs and the initializers remain an unresolved universal join.

The downstream phase-mixer seeds have a more direct origin: W5 after the first scan and W12 after the second hold the scans' final folded value before the common bias is added. The common scan recurrence therefore gives equal seeds, regardless of the incoming accumulator triples. A source register census preserves the first carrier across the intervening interval, conditional on normal execution staying within that interval. This discharges the shared-seed part of the [phase-parameter contract](corefp_phase_parameters_report.md) under the existing scan/control premises; it does not establish arbitrary native input admission.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_scan_entry.py), [checks archive](triage_evidence/corefp_scan_entry_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_scan_entry.py), [audit archive](triage_evidence/corefp_scan_entry_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_scan_entry_publication.py) retain five source regions, two tail slices, a register-access census, thirty complete region frames/journals, twelve scan ends, control-flow records and queries. Twelve parent receipts and fifteen frozen dependencies are SHA-256 pinned. The three supplied inputs are unchanged.

CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses below are preferred-base-zero offsets; B denotes bytes. Primary source coverage is 218 instructions/872 B. Two tail slices contain 52 instructions/208 B. The preservation interval contains 1143 instructions/4572 B and overlaps some other retained regions; these extents must not be added as disjoint coverage. All are within the existing 59120 B caller/allocator/retirement bodies.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SE1 | Pinned original bodies, parent receipts and dependencies identify this image. Source claims depend on those bindings. | Compare every source instruction, tail slice and census row, dependency hashes and the three original inputs. |
| SE2 | Existing private caller/context/pool/malloc/PAC/sequential-CASAL fixtures apply. Full replay continuity depends on them. | Reconstruct six initial CPU/RAM states and replay 488136 visits. Native object admission, backing, ownership and synchronization remain unknown. |
| SE3 | The frame is backed with FP=SP+`0x520`; declared store/load epochs refer to the same owned bytes. Stack joins depend on these interfaces. | Prove source addresses and full store widths; check eighteen field epochs and six control epochs for intervening overlapping writes. Universal native alias/lifetime conditions remain unproved. |
| SE4 | The first initializer shift normalizes to two. The common u64 initializer requires this premise. | Prove its control expression and the original control writer; retain six original-byte counterexamples outside the premise. Earlier production of W11=`0x8568` remains a separate input condition. |
| SE5 | Both initializers have equal u64 seeds and corresponding incoming words differ by `0xeb3e515b`. The bank join into the scans depends on these premises. | Prove common-mixer preservation and compare all six original entries. Earlier encoded fields alone do not prove preservation through the intervening arithmetic passes. |
| SE6 | The two scans share the declared preparation bytes, recurrence seed/biases and bounded dispatch contracts; execution stays within the writer-free interval until its end. Downstream carrier equality depends on these premises. | Recheck the frozen scan obligations, tail carrier equations, every register alias and seven branch sites; compare all 130 retained interval branches. Native exceptions or transfers outside the interval do not inherit this preservation result. |

## Common u64 scan-entry mixer [SE1-SE5]

| Component | Source interval | Instructions / B | Data interface |
| --- | --- | --- | --- |
| Earlier encoding | `[0x1b4790,0x1b47c0)` | 12 / 48 | three u32 fields to three stores/encoded registers |
| Control writer | `[0x1b4dec,0x1b4e10)` | 9 / 36 | W11 to one zero-extended u64 stack store |
| First initializer | `[0x1b51d4,0x1b536c)` | 102 / 408 | X7 seed, W6/W5/W1, one u64 control load |
| Later decoding | `[0x1b55f0,0x1b5620)` | 12 / 48 | three u32 stack loads to decoded registers |
| Second initializer | `[0x1b63e4,0x1b6530)` | 83 / 332 | X1 seed, W15/W6/W14; no memory read |

The initializer outputs are W26/W30/W22 and W15/W10/W11 respectively. Neither initializer writes memory. The five regions execute once each per retained caller, yielding 1308 visits, 24 reads and 24 writes across six callers. Each caller reads 20 B (one u64 plus three u32) and writes 20 B (one u64 plus three u32), totaling 120 B each across the six profiles. The regions contain no control transfer; the arithmetic passes between them have separate control flow.

Define u64 `A_n(x)=x+(x>>n)` and `S_n(x)=x-(x>>n)`. Every add/subtract wraps modulo 2^64 before its result is reused; shifts are logical. All literals below are hexadecimal u64 values:

```text
a = A_2(A_11(A_31(seed + 57591561cfca294a)))
b = A_1(S_14(S_29(a + 9801c171577bca01)))
c = A_3(A_10(A_29(b + 6edf733dd7daa684)))
d = A_4(S_14(A_30(c XOR a4ee2625fd04e1d5)))
e = A_2(S_13(S_30(d + 115191787f9f5c08)))
f = A_2(A_11(A_24(e + e8445ed68b2a859b)))
g = S_7(A_10(S_31(f + 745ace6e274e4c6c)))
h = S_7(A_10(A_25(g + e3d0b888f4003be8)))
j = A_5(S_15(A_26(h + 0680844d79c49795)))

T64(seed) = (low32(a XOR d XOR g),
            low32(b XOR e XOR h),
            low32(c XOR f XOR j))
output_bank = input_bank XOR T64(seed), componentwise
```

The source ends the final addition at u32 width; extracting low32 after the displayed u64 addition gives the same result. The generic source obligations cover arbitrary u64 seeds and arbitrary u32 input words. Under a common seed, applying the same T64 preserves any componentwise XOR difference; `0xeb3e515b` is the retained upstream encoding difference, not a constant built into T64.

| Retained message extent | Common initializer seed | Raw left input words | Raw right input words |
| --- | --- | --- | --- |
| 16 B, all preparation/clobber controls | `7651b2bf6eff9a8a` | `0bf10612 71b3635e e09d6fcd` | `e0cf5749 9a8d3205 0ba33e96` |
| 32 B, both preparation controls | `65e683634cf8c95c` | `db575a38 a6dd2f44 b7e4d057` | `30690b63 4de37e1f 5cda810c` |

Each of the three left/right pairs XORs to `eb3e515b`. These are actual source-entry observations, not a universal reduction of the preceding arithmetic passes.

## Shift control produced and consumed at separate epochs [SE3,SE4]

At `0x1b4dec..0x1b4e0c`, source arithmetic stores:

```text
store_u64(SP+348, zero_extend_u32(10*(W11 XOR 82d1)))
```

The factor 10 is decimal; the XOR literal and offset are hexadecimal. The multiply is represented by add-with-shift and LSL, with u32 wrap before zero extension. Every retained source entry has W11=`0x8568`, producing u64 `0x4d3a`. The original u64 store at `0x1b4e0c` reaches the original u64 load at `0x1b529c` without an intervening overlapping write in all six profiles.

The first initializer computes, at u32 width:

```text
control = (low32(load_u64(SP+348)) + 32f291f3) AND cd0d6df7
shift64 = (control - 4d23) AND 63
```

Here 63 is decimal; other literals are hexadecimal. Retained `0x4d3a` gives control=`0x4d25` and shift64=2. More generally, shift64=2 implies the first scan tail's `(control-0x4d1d) AND 31 = 8`. This implication concerns arithmetic normalization; it does not establish that arbitrary control values address the seven original scan dispatch cells. Those cell bindings retain the separate control premises in the [scan report](corefp_preparation_scans_report.md).

The second initializer uses a fixed right shift of two at the corresponding site. Original-byte tests with an off-premise first control load of zero produce a different shift and reject the fixed-two candidate in every retained initializer domain. The audit retains the exact seeds, inputs and results of these controls.

## Three shared stack fields and the origin of the bank XOR [SE1,SE3,SE5]

| Field | Earlier source store | Earlier encoded word | Later source load | Later decoded word |
| --- | --- | --- | --- | --- |
| A | `0x1b47a8`, SP+`0x410` | W6=`A XOR 9f6cb307` | `0x1b5618` | W15=`A XOR 7452e25c` |
| B | `0x1b47b8`, SP+`0x3f8` | W5=`B XOR a473e160` | `0x1b55f8` | W6=`B XOR 4f4db03b` |
| C | `0x1b4798`, SP+`0x400` | W1=`C XOR d0824f19` | `0x1b5608` | W14=`C XOR 3bbc1e42` |

These are u32 stores/loads and distinct register lifetimes. Every pair of XOR constants differs by `eb3e515b`; seven source obligations cover the stores, encoded words, three load addresses, decoded words and paired difference. The auditor verifies that each read sees its named preceding store with no intervening overlapping write in all eighteen retained field epochs. SP+`0x410` is subsequently reused for a u64 control value at `0x1b56ac`; that later write occurs after the field read and must not be assigned the same data role.

The encoded triples then pass through `[0x1b47c0,0x1b51d4)` and `[0x1b5620,0x1b63e4)` before reaching the initializers. Those regions update words and produce the u64 seeds. Their general paired transfer remains unreduced. The full retained callers establish the bank difference and equal seeds at both initializer entries, but the earlier encoding equality alone is insufficient to derive those later facts for arbitrary inputs.

## Fold-value carriers into the phase mixer [SE1,SE6]

Let H be a scan's final recurrence h and a its common u32 bias. Both selectors yield splits in 1..15, so each tail executes at least once. Two new source obligations, over arbitrary initial registers and an arbitrary u8 load value, prove:

| Tail source interval | Final-fold carrier | Source relation at tail end |
| --- | --- | --- |
| `[0x1b5444,0x1b54ac)` | W5 | `W14 = W5 + W0`, modulo 2^32 |
| `[0x1b6620,0x1b6688)` | W12 | `W4 = W12 + W0`, modulo 2^32 |

The preceding scan theorem establishes equal final h for shared preparation, initial h and recurrence parameters, independently of the three accumulator seeds and split positions. Thus both carriers equal `H-a`. No equality assumption about the accumulator triples is needed for this seed result.

The source census of `[0x1b54d0,0x1b66ac)` checks all 1143 instructions/4572 B. No instruction writes W5/X5, W26/X26, W30/X30/LR or W22/X22. There are no calls or returns; its seven control transfers are BRAA sites. Under interval-confined normal execution, the first carrier and three first-scan accumulator outputs survive until the second scan ends and the phase mixer begins. The retained 16 B/clobber profiles execute 21 interval branch models each; the two 32 B profiles execute 23 each, totaling 130. Every recorded target stays within the interval or reaches its end. This finite control observation does not establish confinement for arbitrary native control fields.

At the joined phase entry, the audit verifies first W5=second W12=`H-0xdecc2544`, modulo 2^32, and checks both scan-end frames against the frozen scan receipts. The [phase-parameter report](corefp_phase_parameters_report.md) can therefore consume the shared-seed result whenever the scan and interval premises apply. Universal production of the earlier bank XOR and shared u64 initializer seed remains open.

```text
three source fields
   |                               |
encode with first constants    decode with second constants
   |                               |
earlier arithmetic pass        later arithmetic pass
   |      paired transfer still unreduced      |
   +---------- common T64 initializer ---------+
                   |
       two common preparation scans
                   |
       equal final h -> equal H-a carriers
                   |
       writer-free interval -> phase mixer
```

## Validation and continuation

The independent auditor does not import the new producer. It reconstructs six initial CPU frames and 3313664 B of initial RAM, freshly checks 488136 source visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM. It compares all thirty complete region CPU/stack frames and the scan/phase joins, original table workspaces and preparation controls.

Each initializer domain executes 2048 seed-byte cases (`8*256`) plus 3072 accumulator-byte cases (`3*4*256`), giving 5120 cases per domain and 61440 across twelve domains. An independent integer u64 oracle checks 184320 output words against unchanged original instructions. Separate stable-field component cuts execute both original encoding/decoding slices for 3072 cases per profile, yielding 18432 pairs/55296 paired words. Original control-writer tests add 1024 cases per profile, yielding 6144 zero-extended u64 stores. These are explicit component cuts and finite corpora, not native caller-admission tests or a distinct-input count.

Finite source visits are `5120*(102+83)*6 + 3072*24*6 + 1024*9*6 = 6180864`. Six off-premise initializer controls add 612 visits. The actual thirty frame checks and whole-caller replay are separate. Aggregate digests cover the finite ending frames, word vectors or stack snapshots as labeled; individual finite frames are not retained.

All 23 new obligations are independently UNSAT: twelve initializer/control/bank contracts, seven field-encoding contracts, two control-writer contracts and two carrier contracts. Rechecking 1121 frozen obligations gives 1144 total, with a 30 s/query limit. Source contracts, their composition, finite control observations and native behavior retain distinct scopes.

Replay time/space is conservatively `O(C*(B+V*J+P*F+R))` for C profiles, source extent B, visits V, per-visit journals/state J, touched pages P, page/frame payload F and other retained bytes R. The compact u64 mixer is fixed-size arithmetic. Component testing takes `O(C*(10240*102+3072*24+1024*9))` time with bounded private maps; SMT costs/limits are separate.

No new incoming/outgoing Mach port, right, descriptor, emission site or daemon/kext pairing is established. These source intervals provide local register, stack, table-control and normal-control-flow interfaces. No native target/API/IPC, IDA access or IDB mutation occurs. Original file evidence suffices. The full investigation remains active.

| Impact | Remaining investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Reduce the two earlier arithmetic passes to paired word/seed transfers. | Prove preservation of the encoded bank XOR and equality of their produced u64 seeds over shared typed load interfaces; retained vectors alone are insufficient. |
| High | Join arbitrary raw preparation to canonical first-block inputs and all consumers. | Compose the scan/carrier/phase contracts with original table/backing and same-epoch input-word producers. |
| High | Establish native selector/context/holder ownership and admission. | Require original initialization, coherent backing and entry reachability. |
| Medium | Reduce control W11 production and interval confinement. | Replace the remaining control input/target premises with original producer and target-set proofs. |
| Low | Connect local mathematics to daemon/kext transport. | Require actual serializer/consumer and endpoint/right epoch joins. |

- **QG1**: No normative premise is required.
- **QG2**: SE1-SE6 identify dependencies and falsification probes.
- **QG3**: Initializers, control production, stack fields/epochs, carrier lifetimes, bounded control observations and external-interface limits are covered.
- **QG4**: U32/u64 widths, modular arithmetic, masked shifts, zero extension, extents and exact finite counts are explicit.
- **QG5**: Earlier encoding identities are separated from unreduced intervening passes. The shared downstream carrier result retains scan and interval premises; native admission remains unknown.
- **QG6**: Original bytes, pinned receipts, fresh replay, independent integer arithmetic, unchanged-byte component runs, epoch checks and retained queries provide reproducible provenance.
- **QG7**: Impact-ranked continuation retains earlier paired transfers, arbitrary raw inputs, controls, native owners and cross-level transport. The full goal remains active.
