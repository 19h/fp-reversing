# fairplayd selector 26 post-allocation byte writes

In both modeled class profiles, the continuation after `malloc(14)` initializes offsets 0 through 9 of the same allocation. It reuses one four-byte writer at two offsets and uses a separate two-byte writer between those visits. Three reloads obtain the pointer from the same field of the earlier 32 B allocation. The continuation next compares the signed halfword from SP+0x9ee B with a phase-derived signed constant. These are private daemon operations in the pinned arm64e image. [Private record consumer](daemon_selector26_record_consumer_report.md)

## Pointer provenance and writes

`0x100a2fc08` publishes the 14 B pointer into the 32 B object's +0x18 B field. The initial writer reloads it through X16 at `0x100651b20`. The intervening two-byte writer reloads it through SP+0x250 B at `0x1006574d0`. The repeated four-byte writer also uses SP+0x250 B, via X16 set at `0x100908b30`. The producer at `0x1009432cc` derives SP+0x250 B by adding 24 B to the 32 B object pointer from SP+0x2d0 B in both replay fixtures.

| Store PC | First visit offset, B | Second visit offset, B |
| --- | --- | --- |
| `0x100651d1c` | 0 | 6 |
| `0x100651ec0` | 1 | 7 |
| `0x1006520bc` | 2 | 8 |
| `0x100652170` | 3 | 9 |
| `0x100657668` | 4 | |
| `0x1006577e8` | 5 | |

Each store writes 1 B. The four-store block derives its addresses by adding to the allocated pointer the sum of X11 and a per-store constant, with 64-bit wraparound. The first sum is zero on its first visit. `0x100908b34` through `0x100908b40` rebuild X11 with a value 6 higher before the second visit. The four-store block mixes each aligned destination address and then combines the selected byte with the corresponding byte of W28, highest byte first. The first visit uses W28 produced at `0x1009d0ae0` from the old SP+0x250 B word. The second uses the word at SP+0x1d8 B loaded at `0x100908b44`, which is SP+0x9f0 B XOR `0x01263f51` from the prior consumer. The two-store block uses the previously staged word at SP+0x1e8 B, which is derived from the second signed halfword. The original instructions in this prefix perform no loads from the allocated 14 B payload itself.

## Control flow

| Branch PC | Original slot | Target |
| --- | --- | --- |
| `0x100652184`, first visit | `0x1010435a8` | `0x1006d4db0` |
| `0x1006d4dd8` | `0x1010698b8` | `0x1006574d0` |
| `0x1006577f0` | `0x10103a038` | `0x100908b18` |
| `0x100908b4c` | `0x10104f740` | `0x100a18e10` |
| `0x100a18e20` | `0x101055670` | `0x100651b1c` |
| `0x100652184`, second visit | `0x101043888` | `0x1009e1914` |
| `0x1009e1920` | `0x101074de0` | `0x10070c470` |

At `0x10070c478`, the original block compares the signed word at SP+0x1f8 B against the sign-extended low halfword of SP+0x1c0 B. The first operand is the sign extension of SP+0x9ee B. At phase `0xb22f`, the second is `0x9546`, or −27,322, from `(phase - 0x90cc) XOR 0xb425`. This report's modeled effects stop at entry to that block. Offsets 10 through 13 have no modeled writes in this prefix, and the byte range's eventual interface use remains unknown.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Both modeled allocator successes retain the published pointer in the 32 B owner's field. This supplies all ten effective write addresses. | Compare the field's store and three reload addresses and values with the original allocation result in an ordinary invocation. |
| A2 | Both continuations retain their table and phase state. The seven branch joins apply to that state. | Compare SP, the live index registers, the table base and the branch targets over both writer visits. |
| A3 | Opaque shared-helper outputs and unavailable earlier fields remain symbolic in the audit. The store addresses and branch destinations in the prefix resolve without choosing values for them. | Track those inputs and any additional aliasing writes through to the ten store instructions. |

The audit regenerates both retained profiles, verifies seven original chained fixups, checks each individual store's width and offset, and checks the three pointer reloads. For a fixed seven-edge prefix, the bookkeeping scans O(I + L + S) instruction visits, reads and stores, excluding the prior replay and bit-vector simplification costs. [Offline audit](triage_evidence/audit_daemon_selector26_allocation_prefix.py)

| Impact | Open evidence |
| --- | --- |
| High | Locate the first consumer of the initialized allocation and determine whether the 14 B object contributes to the method request. |
| High | Correlate an observed fairplayd method exchange with the kext invocation. |
| Medium | Resolve the continuation after the signed test and the reaching writes to offsets 10 through 13. |
