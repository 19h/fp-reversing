# fairplayd selector 26 stack input producers

In the pinned thin arm64e image, a conditional same-frame sequence sets all three inputs previously traced backward from the phase-`0xb22f` gate and seven-field stack writer. It copies a live register word, processes two adjacent bytes to produce a halfword, then processes four adjacent bytes to produce a separate word. The two byte groups use different address expressions. Their owning objects and any relationship to an external message remain unknown. Neither saved all-nonnull class profile records these branches. [Gate and stack writer](daemon_selector26_stack_producer_report.md)

## Conditional path and field origins

At entry to `0x1006ae330`, assume X21 = `0x101039ef0` and u32 at SP+0x26c B = `0xb22f` (A1). The contiguous fragments below preserve SP. All addresses are unslid.

| Branch PC | Original slot | Target | IA diversity |
| --- | --- | --- | --- |
| `0x1006ae358` | `0x101047760` | `0x1006a0e20` | `0x41bd` |
| `0x1006a119c` | `0x10103ad98` | `0x10064adec` | `0x5d22` |
| `0x10064ae18` | `0x10104b850` | `0x100907aac` | `0x4276` |
| `0x100907abc` | `0x10105fca8` | `0x1009736fc` | `0xe6e3` |
| `0x100973ed0` | `0x10103d968` | `0x10064f0e0` | `0x8cfa` |

| Destination | Store PC | Register source and immediate provenance |
| --- | --- | --- |
| SP+0x86c B, 4 B | `0x1006ae334` | Incoming W14 at `0x1006ae330`. The caller-side definition is unknown. |
| SP+0x872 B, 2 B | `0x10064adf4` | Low 16 bits of W19 produced at `0x1006a1194`. The two byte loads at `0x1006a0e44` and `0x1006a0ff0` address SP+0x250 B and SP+0xb0 B **contents** added together, plus `0x864f69af3c097da8` and its successor, modulo 2^64. Each byte is XORed with a selected byte of an address-dependent word before the two results are combined. `0x10064ae08` copies the full W19 to SP+0x1f4 B. |
| SP+0x874 B, 4 B | `0x10064f0ec` | W14 from `0x100973ec8`, where it is derived from four byte loads at `0x100973934`, `0x100973998`, `0x100973cf4`, and `0x100973ea0`. The first address is the sum of the contents of SP+0xa0 B and SP+0x250 B plus `0x99e5a6f4cfd4506a`, modulo 2^64. The other three addresses are consecutive. |

The signed table indices on the five edges are `0x1b0e`, `0x1d5`, `0x232c`, `0x4bb7`, and `0x74f`. The first block forms the second index by subtracting `0xb05a` from the phase. The halfword store block forms the last index in W16 by subtracting `0xaae0` from the phase. It loads X19 and X14 from SP+0xa0 B and SP+0x250 B before the four-byte fragment. The intervening block at `0x100907aac` leaves both registers live.

After the SP+0x874 B store, the block computes an unsigned address comparison using the two 8 B words at SP+0x68 B and SP+0x70 B. It adds `u32(W19 XOR 0x8ec35f08)` to the latter word modulo 2^64, stages the sum at SP+0x878 B, and compares the sum against the former word. The low bit of `0xb22f - 0x9f9a = 0x1295` inverts the unsigned comparison bit before dispatch. When the sum is above the limit, index `0xb8c8` uses slot `0x101096530` and reaches `0x100967f08`, the same block as the prior stack writer's null continuation, with W5 = `0x74c29d8f`. When the sum is at most the limit, index `0xb8cd` uses slot `0x101096558`, reaches `0x1006526c0`, and then reaches `0x10063f0dc` via `0x101063840`. The load at `0x10063f108` and the comparison at `0x10063f10c` use the signed low halfword of SP+0x1f4 B and the immediate `-0x2f12`. The subsequent join into the earlier gate or writer remains unknown.

## Assumptions and evidence limits

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Entry phase `0xb22f`, original table identity and live SP establish the local joins. | Track the predecessor of `0x1006ae330` and check X21, SP and the reaching phase store in the same invocation. |
| A2 | The six computed byte addresses are readable and retained stack slots describe one frame. Local address expressions depend on those premises. | Compare all six effective addresses and object extents against a captured invocation with its allocation identities. |
| A3 | The retained profiles cover their recorded post-helper paths only. The absence result is restricted to those paths. | Record block and memory-write histories for the same call from an independent ordinary run and compare last writers for the consumer's frame. |

The audit decodes the pinned image, checks nine original chained-fixup words, and evaluates 16 modeled paths with distinct sentinel inputs covering both comparison outcomes at each of eight byte alignments. It also checks branch-PC absence from the two saved class profiles. Each modeled path takes O(I) instruction operations for I instructions. Scanning E saved edges takes O(E) time and O(E) space for decoded evidence. [Offline audit](triage_evidence/audit_daemon_selector26_stack_input_origins.py)

| Impact | Open evidence |
| --- | --- |
| High | Observe a successful native daemon-to-kext exchange and identify the matched service, connection and selector invocation. |
| High | Establish whether this candidate producer reaches the gate and signed halfword load in the same frame. |
| Medium | Identify the two byte groups' allocations and the original definition of W14. |
