# fairplayd header writer upstream of selector 26

A source-checked predecessor at `0x1000859ec` copies its incoming X0 to X7. The selected continuation writes a ten-byte header through X7 and reaches the dispatch that selects either selector 26 argument record. Both records receive that same buffer pointer. The producer of the incoming X0 and its identity relative to the constructor buffers remain unknown. [Selector 26 caller records](daemon_selector26_callers_report.md) [Constructor buffer readback](daemon_selector26_readback_report.md)

| Original PC | Source-derived effect |
| --- | --- |
| `0x1000859f8`, `0x100085a48` | Set X7 from incoming X0 and X6 from the pointer at SP+0x90 B. |
| `0x100085a60` | With W24=`0x1983` and a zero u64 at [X20], branches via slot `0x101046b08`, IA `0x9dfb`, to `0x1000fe08c`. W11 reaches that block as `0x662a`. |
| `0x1000fe0a8`, `0x1000fe0c0`, `0x1000fe0dc`, `0x1000fe0fc` | Zero the 32-bit first field, one byte at a time at buffer+0–3 B. |
| `0x1000fe150`, `0x1000fe16c` | Write the big-endian 16-bit span tag `0x50db` at buffer+4–5 B. |
| `0x1000fe308`, `0x1000fe328`, `0x1000fe348`, `0x1000fe364` | Write the big-endian 32-bit field at buffer+6–9 B. Its value is `u32(0x37c30c43 - incoming_W19)`. |
| `0x1000fe3d8` | When incoming X22 is zero, branch via slot `0x10106d138`, IA `0xa57c`, to `0x1000c62f0` with W10=`0xa4c7`. |
| `0x1000c62f0`, `0x1000c634c` | Load the dispatch byte through X6 and save X7 at SP+0xa8 B. |
| `0x1000f2180`, `0x1001116e4` | The direct structure caller saves X7 at record+0 B. The descriptor caller saves it at record+24 B. |

The ten stores define a header with the same field widths and byte order as the independently recovered FairPlay record format. The header's last field comes from incoming W19. The caller's encoded total extent instead comes from SP+0x130 B. The source checked here provides no relation between those values. The prior caller audit covers the full adjusted-byte partition. Under that partition, `0x2d` selects the descriptor, and the remaining byte values select the direct structure record. The new audit composes both records with the header stores and checks their pointer identity under two data placements. [Record format](daemon_xpc_records_report.md) [Audit](triage_evidence/audit_daemon_selector26_header.py) [Compressed receipt](triage_evidence/daemon_selector26_header_audit.json.zst)

At the new upstream boundary, original slot `0x101060830` carries IA modifier `0xf6ab` and points to `0x1000859ec`. Its executed branch producer remains unknown. The caller record proof reuses the established bank cells and extent decoder. It establishes the local handoff under those premises. The retained RAX trace ends at failed IOKit open 2862 and provides no matched selector 26 exchange or associated connection and reply rights. [IOKit call sites and transport](daemon_selector26_return_report.md) [Trace and port attribution](zut_trace_report.md)

## Assumption register

| Assumption | Dependent result and falsification probe |
| --- | --- |
| A1. The original Mach-O bytes and format-12 words match the pinned image. | Instruction and logical authentication mappings. Recompute the load addresses and decode the original slot words. |
| A2. Entry W24 is `0x1983`, [X20] holds zero and incoming X22 is zero. | The selected control route. Recheck W11/W10 and both authenticated edges. Test the X22 comparison symbolically over all u64 values. |
| A3. Incoming X0 points to writable nonaliasing storage for at least 10 B. | Exact write footprint and the origin of the caller record pointer. Change the data placement and compare store offsets and both record pointer fields. |
| A4. The caller context, dispatch byte pointer and descriptor bank cells are valid and match the selected frame contract. | Reaching both caller records and their helper calls. Check the original byte load and separately replay the `0x2c` and `0x2d` controls with the bias zero. |
| A5. The incoming length word and caller extent can be modeled independently. | The last header field and both record codecs. Give each its own symbolic input, then check the negation of each equation. The original common producer and any coupling remain unknown. |

The writer stores 10 B with ten byte stores. This local path and either record handoff take O(1) time and auxiliary state. The audit builds O(I) instruction and access records for I visits, excluding solver and fixup-decoding costs. Four profiles and seven unsatisfiability checks cover the documented conditional scope.

| Impact | Open evidence |
| --- | --- |
| High | Find the authenticated branch that reaches `0x1000859ec` and recover its X0, W19 and SP+0x90 B producers. |
| High | Determine whether the header length and caller extent share a producer, then correlate the buffer to a live selector 26 request and its port rights. |
| Medium | Follow the nonzero X22 continuation and identify which header or payload fields it updates. |

QG1–QG7 cover the source-bounded header, exact widths, explicit assumptions, both caller records and the trace boundary.
