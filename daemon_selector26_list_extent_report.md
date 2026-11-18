# fairplayd list extent and buffer dispatch upstream of selector 26

The byte count supplied to the selector 26 allocation guard is the sum of a linked list's 32-bit node extents on the recovered `0x8934` path. The post-allocation block reloads the same list head. An empty list enters the previously recovered header writer directly. A nonempty list enters a second traversal, with a zero-length skip and a positive-length byte-transfer setup. [Allocation and padding](daemon_selector26_padding_report.md)

The source is the original arm64e Mach-O, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. PCs are unslid virtual addresses. The evidence includes the instruction spans, original format-12 fixups, six finite profiles and four bit-vector proofs. [Audit generator](triage_evidence/audit_daemon_selector26_list_extent.py) [Compressed evidence](triage_evidence/daemon_selector26_list_extent_audit.json.zst)

## Phase and count producers

At the selected entry `0x1000c6b94`, W28=`0x8934` and W16=`0x8b3dc651` select `0x100011ef4`. This start is consistent with the earlier constructor's phase and status encoding. The preceding branch that reaches this entry from the constructor remains unknown. [Constructor frame](daemon_selector26_record_origin_report.md) [Constructor continuation](daemon_selector26_decode_report.md)

| Original PC | Read or effect | Continuation |
| --- | --- | --- |
| `0x1000c6bd0` | Selects phase/status pair above and derives W23=`0x0b11`. | Slot `0x10106a660`, IA `0x8041`, to `0x100011ef4`. |
| `0x100011efc`, `0x100011f2c` | Loads the 8 B list owner pointer from FP−0xb8 B into X20. | For a nonnull owner, slot `0x101084d50`, IA `0xfdf3`, to `0x1000bfd58`. |
| `0x1000bfd58`, `0x1000bfd80`, `0x1000bfdac` | Zeros W8 and loads the 8 B head pointer from owner+0 B into X9. | Empty goes to `0x1000ee4e8` via `0x101080598`. Nonempty goes to `0x10020f0c8` via `0x101080660`. Both use IA `0x92ed`. |
| `0x10020f0d8`, `0x10020f0dc`, `0x10020f104` | Reads the u32 extent at node+0x10 B and checks carry from its sum with W8. | Fits u32 via `0x101069e70` to `0x1000c0898`. Carry via `0x101069f68` to `0x100013334`, with W16=`0x74c29d8f`. Both use IA `0x8041`. |
| `0x1000c08c0`, `0x1000c08c4`, `0x1000c08ec` | Adds the extent to W8 and loads the 8 B next pointer from node+0 B into X9. | Uses the same null/non-null partition and slots as the head check. On list exhaustion W8 holds the sum and W10=`0x6246`. |

Starting at zero, the accepted recurrence adds one unsigned 32-bit extent per node after checking the widened sum against `0xffffffff` B. By induction on a stable finite acyclic list, W8 holds the exact sum when the scan ends. The separate size guard then applies the padding equation and bounds from the allocation audit. The count pass writes no memory in the finite profiles. Its two node-field widths and offsets match the constructor's next pointer and extent fields. Its owner pointer comes from the frame slot the constructor uses to save its list allocation. These correspondences establish the consumer-side layout. The executed constructor-to-entry handoff remains open. [Node construction and links](daemon_selector26_node_report.md)

## Post-allocation dispatch

On ordinary nonnull allocator return, let B be the returned allocation pointer. At `0x100085a14`, the daemon reloads owner+0 B through X20, and at `0x100085a48` it reloads the dispatch pointer from SP+0x90 B. The list count path leaves that stack word untouched. The earlier constructor stores its incoming caller record in the same stack slot. That source remains conditional on the unresolved frame handoff.

| Stable list state | Branch and target | Effect |
| --- | --- | --- |
| Empty | `0x100085a60`, slot `0x101046b08`, IA `0x9dfb`, to `0x1000fe08c` | The count is 0 B, allocation extent is 16 B, and the header-first path writes 6 B of padding. |
| Nonempty | `0x100085a60`, slot `0x101046b78`, IA `0x9dfb`, to `0x100083e80` | Loads the first node's u32 extent at `0x100083e9c`. A zero total can still follow this route if the head is nonnull. |
| Nonempty with first extent zero | `0x100084058`, slot `0x10107dd78`, IA `0x8f7b`, to `0x100034ec8` | Advances through node+0 B at `0x100034ef0` without reading node+0x18 B on this step. |
| Nonempty with first extent positive | `0x100084058`, slot `0x10107dda0`, IA `0x8f7b`, to `0x1000e661c` | Loads the 8 B source pointer S from node+0x18 B. Branch `0x1000e66bc` then uses slot `0x10104dea8`, IA `0x17c9`, to reach `0x100090998`. |

For first-node extent `n > 0` B, the positive branch supplies X12=S, X13=`u64(n)-1`, X14=`B+n-1` and X15=`(S+n-1)<<3` to `0x100090998`, with register arithmetic modulo `2^64`. This fixes the starting source and destination offsets for a nonempty list. The byte recurrence, final header placement and nonempty-list handoff into the selector 26 records remain open for this route. An independent component already has a verified reverse transfer with the same field offsets. [Separate list flattener](daemon_list_output_report.md)

The follow-up proves the byte recurrence and trailer placement, then verifies the handoff to both selector 26 caller records. [List serialization](daemon_selector26_list_transfer_report.md)

The two-node fixture with 14 B per node supplies T=28 B, P=10 B and N=48 B. It reaches the positive-node setup with first index 13 and destination B+13 B. The one-node zero-length fixture supplies T=0 B, P=6 B and N=16 B, then takes the nonempty zero-length skip. These cases supersede the earlier independently seeded combination of positive T and an empty list head for this producer. [Earlier input model](daemon_selector26_padding_report.md)

## Assumption register

| Assumption | Dependent result and falsification probe |
| --- | --- |
| A1. Original instruction bytes and format-12 fixups match the pinned Mach-O. | PCs, field reads and logical authenticated edges. Recompute source spans and decode the original words for the consumed slots. |
| A2. Entry at `0x1000c6b94` has the selected phase/status pair, live table root and compatible frame slots. | The owner load, initial phase transform and count scan. Check the exact slot, phase and status. Trace the preceding branch to establish whether the earlier constructor gives this entry state. |
| A3. The owner is nonnull and the list is readable, finite, acyclic and stable across both traversals. | The scan terminates with the full sum and the post-allocation split sees the same head. Check the unsigned addition and next-pointer step symbolically. Replay empty, zero-length and positive-length lists with multiple nodes. Native lifetime and concurrency behavior remain unknown. |
| A4. The prior allocator bank pair and ordinary fresh, disjoint nonnull return apply. | The connection from the counted size to B and the second traversal. See the prior allocation proof. Replay the bank and ABI return and validate the source and destination setup independently with symbolic pointers. |

For m visited nodes the counting pass takes O(m) time and O(1) auxiliary state. The post-allocation branch and first-node setup take O(1) time and auxiliary state. The audit covers the guard's carry partition, the no-wrap recurrence, zero-length dispatch and positive transfer initialization. The retained emulator trace still ends at the failed IOKit open. Native selector 26 transfer and its port rights remain unknown. [Trace coverage](zut_trace_report.md)

| Impact | Open evidence |
| --- | --- |
| High | Resolve the producer of the phase/status pair at `0x1000c6b94` and the matching constructor frame and dispatch record. |
| High | Complete the nonempty transfer through its byte loop, header placement and selector 26 argument handoff. |
| High | Correlate a successful Mach 2865/2965 exchange with one of the recovered routes. |

QG1–QG7 cover the source scope, conditional frame, exact widths and bounds, branch partitions, provenance and remaining interface evidence.
