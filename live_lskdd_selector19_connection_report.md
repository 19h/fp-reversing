# lskdd selector 19 connection-cell provenance

The original arm64e instruction and fixup evidence identifies a conditional route that loads the same connection cell as selector 18. At `0x10087de78`, X20 receives `0x100e82af8`. The next authenticated transfer enters `0x100562ce8`, which can dispatch to the selector 19 predecessor. On the route that carries the matching frame status, X20 survives until the 32-bit connection name is loaded at `0x100474dcc`. The handle value and whether an open populated the cell before this route on a native invocation remain unknown. [Selector 18 open and connection](live_lskdd_selector18_connection_report.md) [Selector 19 predecessor](live_lskdd_selector19_entry_report.md)

## Shared cell and preserved register

Let S denote the fixed SP, with P = `0x45b9` at S+0x5b94 B and the original table base `0x100e2ce30` at S+0x5ff8 B. The writer at `0x1004db108` stages a pointer to `0x1008eda8c` at S+0x7f48 B. The class-string block then compares the byte at the pointer selected into X23 with `(W22 + 0x76) & 0xfe`, which is zero with P = `0x45b9`. When the byte is nonzero, it takes the status-store path below and carries W24 = `0x2ee02eab`. [Earlier frame-slot evidence](live_lskdd_selector19_status_report.md)

| Site | Computed slot or data transfer |
| --- | --- |
| `0x1004db210` | Nonzero byte selects index `0x338f`, slot `0x100e46aa8`, to `0x10040423c`. |
| `0x100404254`, `0x100404298` | Writes W24 into S+0xecb0 B and branches through slot `0x100e40800` to `0x100ab02dc`. |
| `0x100ab02f8` | W9 derives from W22 = `0x98a`. Index `0x4392` selects slot `0x100e4eac0` and `0x100a3b8fc`. |
| `0x100a3b924`–`0x100a3b930` | Loads slot `0x100e31a80`, which authenticates to `0x100562ce8` with modifier `0xcb78`. Stores a copy at S+0xe420 B and leaves the pointer in X10. |
| `0x100a3b974` | The fixed values X8 = `0x2f87da8a` and X4 = `0x2f87da69` select `0x100454898` via slot `0x100e56338`. The 33 B clearing loop exits through `0x100a45f20` and reaches `0x10087de14` with X10 restored from S+0xe420 B. |
| `0x10087de78` | Loads X20 from pool slot `0x100e77350`, rebased to the selector 18 connection cell `0x100e82af8`. |
| `0x10087dea8` | Branches through the preserved X10 to `0x100562ce8` with IA modifier `0xcb78`. |
| `0x100562d04`–`0x100562d18` | Loads W26 from S+0xecb0 B and branches through the pointer from S+0x7f48 B to `0x1008eda8c`. |
| `0x1008edae8`, `0x100474dcc` | Matching W26 reaches the selector 19 block. It loads the 32-bit word at X20 into W0 before the IOKit call at `0x100474e38`. |

At the X20 load, the banks at `0x100e07090` and `0x100cb47e0` yield `0x9b` for every byte input with key `0x1f`. Adding bias `0x5eb` gives pool index `0x686`. The original slot rebase supplies the cell address. The intervening branch windows contain no X20 write, and the one preparatory call inside the method block resolves to the return-only leaf. [Table and preparatory binding](live_lskdd_selector19_binding_report.md)

## Main-port acquisition branch

The zero-byte outcome at `0x1004db210` selects slot `0x100e61008` and `0x100455a94`. The banks published at S+0x5800 B and S+0x5808 B give byte `0x5f` for all 256 inputs under key `0xa2`. Adding `0x8ce1` selects `0x100e73830`, an authenticated binding to `IOMainPort`. The call at `0x100455b1c` takes bootstrap argument zero and a u32 output cell at S+0xc784 B.

| IOMainPort result | Resulting transfer |
| --- | --- |
| Zero | Slot `0x100e46a80` leads to `0x1005146f8`, which supplies the constructed class string in X0 to an authenticated call at `0x10051476c`. The published banks resolve this call to `IOServiceMatching`. [Service acquisition](live_lskdd_selector19_open_report.md) |
| Nonzero | Slot `0x100e46aa8` leads to the same status store with W24 set to `0x2edf8807`. On the compatible shared-cell continuation, the selector 19 predecessor's matching-status test then takes its other edge. |

The installed framework maps the selector 19 structure call through this connection to outbound Mach ID 2865 at `0x184ebe090` and incoming reply ID 2965. A full-width transfer uses 3,172 B outbound and 3,140 B inbound. This static join establishes the task-local cell used for the destination name. The fresh-open output address and native name values remain unverified. [Method transport](live_iokit_mach_transport_report.md) [Selector 19 layout](live_lskdd_selector19_binding_report.md)

## Assumptions and verification

| Premise and dependent finding | Falsification check |
| --- | --- |
| The installed slice and recovered table and banks describe the frame. The cell and import names depend on this. | Recompute image identity, original fixups and both 256-input equations. |
| The sampled branch has P = `0x45b9`, the class-block flag byte is nonzero, and the recovered register definitions reach the clearing loop. These conditions qualify the continuous static route. | Trace the flag and the compared registers, then check the clearing-loop targets against the original authenticated slots. |
| A successful earlier open wrote the cell in the same process lifetime. This qualifies the runtime name and provider attribution. | Correlate the open copyout with the connection load and the port used by the method send in a passive native trace. |

High impact for establishing the selector 18 and 19 connection-cell alias. Medium impact for distinguishing acquisition and status branches. The static audit checks two sets of 256 byte inputs, the original code slots and the associated instructions. [Compressed evidence](triage_evidence/live_lskdd_selector19_connection_audit.json.zst)
