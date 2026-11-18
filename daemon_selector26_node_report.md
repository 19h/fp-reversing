# fairplayd selector 26 constructor node handoff

For the audited `0x8934` route, the daemon fills a 14 B local buffer, places its node in both pointer fields of the 16 B object, and allocates and fills a second 14 B buffer. It then retrieves the **first** buffer pointer from that object. The linkage to either recovered selector 26 call site remains unknown. [Constructor entry and allocations](daemon_selector26_constructor_report.md) [Selector 26 call sites](daemon_selector26_return_report.md)

```text
first node + 24 B -> first 14 B buffer
        |
        +-> SP+0xd8 -> object pointers at +0 B and +8 B
                                   |
                             second node filled
                                   |
object + 0 B -> first node + 24 B -> X0
                           |
                           +-> first node saved at SP+0x80
```

| Stage | Original instruction evidence |
| --- | --- |
| Initialize one buffer | `0x10006d3ec` loads node+24 B on three visits. Byte stores at `0x10006d5c8`, `0x10006d76c`, `0x10006d960` and `0x10006da78` cover offsets 0–3, 6–9 and 10–13 on those visits. The intervening block reloads node+24 B at `0x10003c674` and writes offsets 4 and 5 at `0x10003c7b4` and `0x10003c91c`. Each pass writes 14 distinct byte offsets in ascending order. |
| Publish first node | `0x1000d4810` saves the node at SP+0xd8 B. The first load at `0x10007ff3c` sees the object's zero field at +0 B. The load at `0x100081d80` sees zero at +8 B. After reloading the node into X22 at `0x100081da0`, `STP X22, X22, [X13]` at `0x100057484` writes it into both fields. |
| Allocate and fill second node | The continuation calls `malloc(32)` at `0x10001bc9c` and `malloc(14)` at `0x100015af4` again. The same 14-store sequence initializes the second buffer and the constructor replaces the SP+0xd8 B staging cell with the second node. |
| Retrieve first buffer pointer | The next visit to `0x10007ff3c` reads the first node. Branch `0x10007ff60` selects `0x10006e1cc` via slot `0x1010630e8` with IA modifier `0xf000`. `0x10006e1d4` loads the first node's buffer pointer into X0. `0x10006e1e8` saves the first node at SP+0x80 B. |
| End of recovered interval | The lift reaches the instruction preceding `LDR X16, [SP,#0xf8]` at `0x100054958`. The reaching definition for this 8 B stack word is unknown. Through that point the local walk records zero payload loads from the first buffer. |

The audit replays the entry and both passes from original instruction bytes under three paired global-word and heap layouts. It checks 67 source spans and independently decodes 43 original chained fixups. The modeled calls assume five disjoint aligned nonnull allocations with ordinary ABI register preservation. The first buffer retains its 14 initialized bytes through pointer retrieval in each profile. W1 at entry to `0x100134830` receives an arbitrary 32-bit SP+0x13c B live-in. Both routes through the audited interval resolve with that value symbolic. [Audit](triage_evidence/audit_daemon_selector26_node.py) [Compressed receipt](triage_evidence/daemon_selector26_node_audit.json.zst)

The RAX capture still ends at IOKit open request 2862 and reply 2962 with status `0xe00002c2` and a null connection. It contains no request 2865. The source interval contains only local allocation and data movement, with no Mach send or port handoff. Native reachability, native PAC behavior and the transport-buffer identity remain unknown. [Trace and port attribution](zut_trace_report.md) [Mach port inventory](mach_ports_report.md)

## Assumption register

| Assumption | Dependent result and falsification probe |
| --- | --- |
| A1. The audited image has SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. | All instruction and branch mappings. Re-read source spans and decode the original format-12 words, including each continuation whose pointer was spilled to a stack cell. |
| A2. The caller enters with decoded phase `0x8934` and a nonnull context. | Node and buffer sizes and selected traversal. Recheck the phase and context producers in the entry audit. |
| A3. Each allocator returns disjoint aligned writable storage and preserves callee-saved values. | Field identity and absence of aliasing. Vary all five allocation addresses and invalidate caller-clobbered registers and flags at each return. |
| A4. Incoming X25 and the SP+0xe0 B and SP+0x13c B words are symbolic live-ins. | Traversal through the SP+0xf8 B load boundary. Recheck uses and all branch targets without concrete values for those live-ins. SP+0xf8 B requires a separate reaching definition. |

For a fixed number of profiles, the lift and access journals use O(I) time and space in I instruction visits, excluding symbolic simplification and fixup decoding. Each buffer fill writes 14 B in 14 single-byte stores.

| Impact | Open evidence |
| --- | --- |
| High | Find the reaching definition of SP+0xf8 B and continue tracking X0 and the two saved node references to a call argument or retirement. |
| High | Correlate a successful device open and selector 26 request to a native daemon call PC and Mach right identities. |
| Medium | Determine whether the two pointer fields continue to serve distinct roles after the first insertion. |

QG1–QG7 cover the bounded static interval, exact offsets and widths, fixture premises, original-source provenance and the transport evidence boundary.
