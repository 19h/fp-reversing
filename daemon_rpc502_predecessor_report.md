# RPC 502 early continuation selector

The original bank-pointer producer at `0x100de6bac` lies on a path to the branch at `0x100de6c30`. That branch can name the continuation at `0x100de7878` through table slot 2. The original selector rules out this branch as the direct predecessor for the W19 = `0x25` continuation observed in the earlier private replay. The branch selector is derived from the thin daemon identified in the wrapper report. The result assumes the same table base `T = 0x1010ab1a0` at the producer and consumer. [Original image and prior replay](daemon_rpc502_wrapper_frame_report.md)

| Site | Original operation | Effect |
| --- | --- | --- |
| `0x100de6aa8`, `0x100de6b10` | Add `0x7701b734` to W19, then load a table entry using signed W20 | Supplies a continuation pointer to the later local call frame. |
| `0x100de6bc4` | Store X11 at SP+`0x78` | Establishes a context-pointer writer immediately after the original bank-pair store. X11 is assigned X29 minus `0xf8` B at `0x100de6b1c`. |
| `0x100de6bf4` | Move the calculated stack pointer into SP | The meaning of the saved offset depends on the local call at `0x100de6be4`. |
| `0x100de6c08–0x100de6c24` | Compare the caller-frame word with W20 XOR `0xd1c48a30` and calculate the destination index | `u32(W19 + 0x7701b73b) XOR (0x81 * E)`, where E is the equality flag materialized as 0 or 1. |
| `0x100de6c28–0x100de6c30` | Load from the table and branch with IA modifier `0x900e` | Slot 2 names `0x100de7878`. |
| `0x100de788c` | Load a continuation pointer at `T + 8 * s32(W19)` | This use occurs before the later selector at `0x100de79c4`. |

The early selector has exactly one W19 solution for each equality outcome because modular addition and fixed XOR are bijective. For each result, the table offsets below are calculated in bytes. The later addresses are written as 64-bit virtual-address arithmetic.

| Equality E | W19 for slot 2 | Earlier signed W20 index | Later effective address at `0x100de788c` |
| --- | --- | --- | --- |
| 0 | `0x88fe48c7` | −5, a rebase word at `0x1010ab178` preceding T | `0xfffffffd48fcf7d8` |
| 1 | `0x88fe4948` | 124, an authenticated entry for `0x100de832c` at `0x1010ab580` | `0xfffffffd48fcfbe0` |

Neither case carries W19 = `0x25`. With the audited base T, both later addresses lie outside the pinned daemon image. This bounds the slot 2 explanation for the prior replay. It is a static result about original image address formation. The native contents of those effective addresses and any native execution are unknown.

The previous report identified two additional table entries for `0x100de7878`. Slot `0x4d` uses modifier `0x36b3`, and slot `0xb4` uses `0xf57a`. The later census checks branches using all three modifiers and identifies the remaining candidate routes. The mapped context writer narrows the lineage of the pointer supplied in the earlier private continuation. Its observed custody across the intervening SP change remains open. [Continuation predecessor census](daemon_rpc502_branch_selectors_report.md)

## Assumption register

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| P1. The observed call-site instructions and original table fixups belong to the same pinned build. | High. All exact mappings depend on image identity. | Rehash the thin Mach-O and disassemble the instruction words. Independently check the raw chained slot word at `0x1010ab1b0`, stored as bytes `78 78 de 00 0e 90 08 80`. |
| P2. The local call preserves X19, X20 and X22 across the continued path as prescribed for these registers, and the later SP+`0x58` slot supplies T. | High. This binds the early register definitions to the subsequent reads. | Observe the pre- and post-call register values and the table reload at `0x100de7888` in an intact original-code trace. |
| P3. The result covers dispatch from `0x100de6c30` through slot 2. | Medium. Other routes remain independent. | Trace the original writers and constraints for branches with the other two table modifiers. |

The calculation enumerates two equality outcomes using 32-bit modular arithmetic, sign-extends each index, scales by 8 B, and adds the 64-bit base. This arithmetic takes O(1) time and space after resolving the instructions and fixups. [Prior authenticated dispatch audit](daemon_rpc502_dynamic_dispatch_report.md)
