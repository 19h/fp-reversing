# lskdd selector 19 status and predecessor staging

The installed arm64e daemon has a candidate frame path into the selector 19 predecessor. One authenticated edge carries the predecessor's table index into a block that stores its code pointer at S+0x7f48 B. A later block reads that exact frame slot and branches with the matching authentication discriminator. It also loads the status governing selector 19 from S+0xecb0 B. A static store to that status slot exists. Reaching definitions across the intervening frame blocks remain unknown. [Selector 19 entry](live_lskdd_selector19_entry_report.md)

## Code pointer and status slots

S denotes the fixed SP. P is the u32 state at S+0x5b94 B. Under the earlier initializer fixture, P = `0x45b9`. The table base at S+0x5ff8 B is `0x100e2ce30`.

| Instruction or block | Frame transfer or control |
| --- | --- |
| `0x1004c0de4`–`0x1004c0e10` | Computes W10 = P − `0x4356` = `0x263`. Branches through index P + `0x1830` = `0x5de9`, slot `0x100e5bd78`, to `0x1004db0dc` using IA discriminator `0xc10f`. |
| `0x1004db0fc`–`0x1004db108` | Uses unchanged W10 to load the authenticated target from table slot `0x100e2e148` and stores its pointer at S+0x7f48 B. The slot authenticates to `0x1008eda8c` with IA discriminator `0xb9a3`. |
| `0x10040424c`–`0x100404254` | Stores W24 to S+0xecb0 B. W24 is an input to this block. |
| `0x100562ce8`–`0x100562d18` | Decrements the frame cursor at S+0xd7f8 B by 48 B, loads W26 from S+0xecb0 B, and loads the code pointer from S+0x7f48 B into X9. Branches through X9 with IA discriminator `0xb9a3`. |
| `0x1008edac0`–`0x1008edae8` | Compares W26 with `0x2ee02eab`. With P = `0x45b9`, equality selects the selector 19 entry. The other result selects `0x1004decf4`. |

After storing the code pointer, `0x1004db0dc` allocates 48 B from the frame cursor and writes the NUL-terminated string `com_apple_driver_FairPlayIOKit` before its next indirect transfer. It assigns W24 = `0x2ee02eab` at `0x1004db204`–`0x1004db208`. The later W24 store to S+0xecb0 B has the right width and offset for the selector 19 predicate. Whether this particular W24 definition reaches that store or whether another status producer intervenes remains unknown. The exact class string establishes a relationship to service matching. It does not identify the reaching X20 connection pointer.

## Checks on other frame edges

The initializer writes W21 − `0x2d6e` to S+0x3840 B at `0x1005bdfc4`. With W21 = `0x45b9`, `0x1006eb44c` would branch through index `0x184b`, slot `0x100e39088`, to `0x100a8b78c` with discriminator `0xe28d`. That particular definition does not reach selector 19 on this edge.

The initializer also writes W21 − `0x437c` to S+0x3fd0 B at `0x1005bb5dc`. Under the same W21 and P, the branch at `0x1009ce468` uses index `0x23d` for W25 unequal to `0x2ee02eab` and `0x6e1f` for equality. Both corresponding slots have discriminator `0xb9a3`, and their targets are `0x10070a088` and `0x10070715c`, respectively. These composed definitions identify alternative continuations and leave the stored-pointer path at `0x100562d18` as a candidate for further provenance.

## Assumptions and verification

| Premise and dependent result | Falsification check |
| --- | --- |
| The pinned image and the original table base describe these instruction windows. This qualifies target and slot calculations. | Recompute the slice digest and compare the key, address-diversity bit, modifier, target and bytes at each listed slot and branch. |
| P is `0x45b9` at the pointer producer, and the compared frame references are from the same fixed SP. | Follow the stack cursor and SP through the intervening blocks and observe the last writer of S+0x7f48 B at the branch that reads it. |
| The candidate W24 constant reaches the status store without an intervening definition. This is a condition for the proposed source of W26. | Trace W24 and S+0xecb0 B together through the authenticated continuation and compare the value at the W26 load. |

High impact for linking the service-class construction block to a candidate selector 19 code-pointer publication. Medium impact for distinguishing stored status from the live IOKit handle. The intervening path, final connection definition, and native port names remain unknown. [Instruction and fixup receipt](triage_evidence/live_lskdd_selector19_status_audit.json.zst)
