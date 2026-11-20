# lskdd selector 19 open copyout

The installed arm64e slice supplies a static route from selector 19 buffer preparation to the fresh `IOServiceOpen` call. The route sets X20 to the shared connection cell at `0x100e82af8`. The call at `0x10046f98c` passes that same address in X3. On successful acquisition, the later method loads its destination name from the same cell at `0x100474dcc`. Native invocation and numeric port names remain unknown. [Service acquisition](live_lskdd_selector19_open_report.md) [Method destination load](live_lskdd_selector19_connection_report.md)

## Connection-cell address before open

Let S denote the fixed SP and P the u32 at S+0x5b94 B. For P = `0x45b9`, the buffer preparation block at `0x100a35be0` writes the output buffer address at S+0x89f8 B and prepares two passages through the same 3,088 B output-buffer clear. Both passages use the table base `0x100e2ce30` at S+0x5ff8 B and share dispatch through `0x100ab02dc`, `0x100a3b8fc`, `0x100454898`, `0x100a45f20` and `0x10087de14`.

| Pass | W22 at code-pointer load | Saved authenticated pointer at S+0xe420 B | Continuation after address load |
| --- | --- | --- | --- |
| Buffer preparation at `0x100a35be0` | `P - 0x3c15 = 0x9a4` | Slot `0x100e31b50` with IA discriminator `0xcb78` | `0x1008d0364` reloads the output buffer from S+0x89f8 B. |
| Output-buffer clear from `0x1008d0364` | `P - 0x3c33 = 0x986` | Slot `0x100e31a60` with IA discriminator `0xcb78` | `0x1004c0de4` starts the route into class-string construction. |

In both passes W9 enters `0x100ab02dc` with P. The subtraction by `0x227` selects index `0x4392`. The comparison at `0x100a3b948` sees X8 = `0x2f87e679` and X4 = `0x2f87da69`. Their difference is `0xc10` B, which selects the clearing block and its byte-store count. Each pass clears offsets 0–3,087 B within the selector 19 output buffer. At exit `0x100a45f2c` restores X10 from S+0xe420 B. The lookup at `0x10087de78` selects pool slot `0x100e77350` for every byte input of the recovered bank pair. It rebases to `0x100e82af8` and loads that address into X20 before the branch through X10.

The second pass carries the address through the class-string block and successful main-port, matching and iteration continuations. The audited instruction windows contain no intervening X20 definition before `0x10046f984` copies it to X3. The IOKit calls on this route preserve X20 under the arm64 calling convention. The instantiated open branch depends on the acquisition flag being zero, successful matching, and a nonzero service name. [Flag, arguments and acquisition checks](live_lskdd_selector19_open_report.md)

After open succeeds, the separate status path sets W22 to `0x98a` on the recovered frame and uses a 33 B clear of the temporary class string before loading the cell again. The earlier output-pointer audit describes that distinct post-open edge and the excluded counterfactual in which only its W22 changes. [Earlier dispatch audit](live_lskdd_selector19_open_output_report.md)

## Assumptions and verification

| Premise and dependent result | Falsification probe |
| --- | --- |
| The pinned arm64e slice and recovered banks describe both passes. This qualifies the branch targets and cell address. | Check the slice hash, original fixup slots and 256 byte inputs, then compare both clear-loop exits. |
| P remains `0x45b9` and the buffer and continuation slots belong to the same fixed frame. This qualifies the two-pass route. | Record the W22 values, S+0x89f8 B and S+0xe420 B across both passes. Compare X20 at the second address load and X3 at open. |
| The acquisition flag is zero and the relevant IOKit calls succeed. This qualifies the proposed fresh open and its copyout. | Correlate the open output with the connection name passed to the method and the destination in the ordinary Mach exchange. |

High impact for establishing the static alias between the copyout and the method destination. Medium impact for identifying the two buffer clears and the shared control-flow blocks. Native copyout values and the caller path into buffer preparation remain unverified. [Compressed instruction and fixup receipt](triage_evidence/live_lskdd_selector19_open_copyout_audit.json.zst)
