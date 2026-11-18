# fairplayd selector 26 private record consumer

Both retained all-nonnull class profiles reach the signed halfword load at `0x10094326c`. Regenerating their instruction effects finds no store overlapping either byte of SP+0x916 B, and both bytes are absent from the replay's memory map. The original block can still be analyzed with the missing fields left symbolic. It derives private comparison and data cells, then dispatches to `0x100651b1c`, where it reloads the pointer just published by the successful 14 B allocation path. All PCs are unslid in the pinned arm64e image. [Retained class profiles](daemon_selector26_helper_consumers_report.md)

## Reaching writes and branch state

| Frame field | Width | Reaching write in both profiles |
| --- | --- | --- |
| SP+0x86c B, SP+0x872 B, SP+0x874 B | 4 B, 2 B, 4 B | Absent from both modeled memory maps. The conditional stack input sequence is outside these histories. |
| SP+0x910 B, SP+0x916 B, SP+0x918 B, SP+0x91c B | 4 B, 2 B, 4 B, 4 B | No overlapping modeled writes. The candidate writer at `0x1009dcfcc` is outside these histories. This consumer reads the last three fields. |
| SP+0x9ee B, SP+0x9f0 B, SP+0x9f4 B | 2 B, 4 B, 4 B | `0x1009b83b4`, `0x1009b83b8`, `0x1009b83bc`, respectively. |
| SP+0x26c B | 4 B | `0x100a6305c` saves `0xb22f`. |

After the allocator call at `0x100a2fc00`, `0x100a2fc08` stores the returned pointer at X20+0x18 B. The nonnull replay branch at `0x100a2fc30` uses slot `0x10107ec68` (IA diversity `0xc345`) to reach `0x1009d0ac0`, where `ADD X16, X20, #0x18` retains that field's address. The next dispatch computes W22 as `(W26 - 0x10cc) OR 0xb024`, modulo 2^32. W26 is `0x12d7`, giving W22 = `0xb22f` and table index `(W22 XOR 0xb8ca) + W26 = 0x1dbc`. Branch `0x1009d0af8` uses slot `0x101048cd0` (IA diversity `0xbb52`) to reach `0x100943260`. SP stays fixed across these fragments. [Candidate stack writer and gate](daemon_selector26_stack_producer_report.md)

## Field transformations and successor

All arithmetic below is modulo the destination width. `s16` sign extends to 32 bits. `M = 0x01263f51`.

| Input and load | Width | Derived frame cells and stores |
| --- | --- | --- |
| SP+0x916 B at `0x10094326c` | 2 B | `s16(input)` at SP+0x1fc B (`0x1009432b8`), and the same word XOR `0xffffcbf9` at SP+0x1f4 B (`0x1009432c0`). |
| SP+0x918 B at `0x100943278` | 4 B | Equality to `0x8b3dc655` as a 32-bit 0 or 1 at SP+0x180 B (`0x100943290`). Input XOR M at SP+0x1e0 B (`0x100943310`). |
| SP+0x91c B at `0x1009432a0` | 4 B | Input XOR M at SP+0x170 B (`0x1009432b0`). |
| SP+0x9ee B at `0x1009432d0` | 2 B | `s16(input)` at SP+0x1f8 B (`0x1009432d8`), and the same word XOR `0xffff9da3` at SP+0x1e8 B (`0x1009432e0`). |
| SP+0x9f0 B at `0x100943308` | 4 B | Input at SP+0x188 B (`0x100943314`) and input XOR M at SP+0x1d8 B (`0x10094331c`). |
| SP+0x9f4 B at `0x1009432e4` | 4 B | Input XOR M at SP+0x178 B (`0x1009432ec`). |
| SP+0x478 B, SP+0x2d0 B, SP+0x300 B, SP+0x5b8 B | 8 B each | Each input plus 24 B is staged at SP+0x248 B (`0x10094329c`), SP+0x250 B (`0x1009432cc`), SP+0x240 B (`0x1009432f8`), SP+0x228 B (`0x100943304`), respectively. The replay has bytes for SP+0x2d0 B. The other three inputs are absent. |

For the equality, `W22 - 0x7b3f = 0x36f0`, and `0x36f0 XOR 0x8b3df0a5 = 0x8b3dc655`. The block ORs the two differences `input - constant` and `constant - input`. Inverting that result and taking bit 31 is equivalent to equality over all 32-bit input words.

The missing fields affect data stores. The branch at `0x1009434b0` uses index `0x36f0` in the table at `0x101039ef0`. It reaches `0x100651b1c` through slot `0x101055670` (IA diversity `0xf9ab`) for every modeled value of the missing fields. At the successor, `0x100651b1c` loads the table word at slot `0x1010435a8`. The load at `0x100651b20` reads the X16 field written at `0x100a2fc08`, yielding the modeled 14 B allocation's pointer. The table word's subsequent use and the role of the allocated data remain open.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The two replays use modeled constructor inputs, allocator results and opaque helper returns. Reaching-write absence applies to those modeled histories. | Record the same class path with byte-overlap store events, including writes made in called routines, and compare the last writes to the consumed fields. |
| A2 | Analysis of the consumer preserves the replay's live table base, W22 and SP. Six missing inputs have unrestricted bit vectors. The next edge and 14 field relations are conditional on that frame and branch state. | Compare the live table base, W22, SP, and defined inputs at entry to `0x100943260`, then evaluate each captured input against the documented stores. |
| A3 | The two post-allocation fragments retain the allocation field address in X16. The modeled reload uses the same cell as the publication. | Compare the original store address and value against X16 and the loaded X17 in one ordinary invocation. |

The audit matches all 280 saved authenticated-edge records per class, plus their allocation, helper-call and return records. It checks four original chained-fixup words and tests the 14 relations per class by ruling out a counterexample. The byte-overlap check is O(S) time for S recorded stores and a fixed number of queried fields. Solver inputs contain 80 unavailable record bits and 192 unavailable address-word bits. [Offline audit](triage_evidence/audit_daemon_selector26_record_consumer.py)

| Impact | Open evidence |
| --- | --- |
| High | Locate the producer of SP+0x916 B on an ordinary class path and determine whether it shares a frame with the conditional candidate writer. |
| High | Correlate an observed method exchange with the kext invocation. The recovered continuation stays within the daemon. |
| Medium | Establish the ownership of the three unavailable address words and trace the use of the reloaded allocation. |
