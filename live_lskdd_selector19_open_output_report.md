# lskdd selector 19 open output pointer

The type-zero `IOServiceOpen` at `0x10046f98c` takes its connection output address from X20, copied to X3 in the call block. The established route that loads the shared connection-cell address after service acquisition carries an authenticated continuation to `0x100562ce8`. Entry to the fresh-acquisition block requires a different continuation to `0x1004c0de4`. The reaching definition of the fresh open's X20 and its alias with the shared cell are unknown. [Acquisition ABI](live_lskdd_selector19_open_report.md) [Connection-cell provenance](live_lskdd_selector19_connection_report.md)

## Authenticated transfers

S denotes the fixed SP and P is the u32 at S+0x5b94 B. The previously profiled frame has P = `0x45b9` and the pointer table at S+0x5ff8 B has base `0x100e2ce30`. The arm64e fixup list has one authenticated rebase to the fresh-acquisition entry and one ordinary rebase to the shared connection cell.

| Role | Site or slot | Observed transfer |
| --- | --- | --- |
| Fresh-acquisition entry | `0x100e31a60` | Index `0x986`, IA discriminator `0xcb78`, target `0x1004c0de4`. |
| Connection-cell address | `0x10087de78`, `0x100e77350` | Loads X20 with the address `0x100e82af8` on the previously established route. |
| Post-acquisition dispatch | `0x100a3b924`, `0x10087dea8` | W22 = `0x98a` selects slot `0x100e31a80`. The block branches through X10 to `0x100562ce8` with discriminator `0xcb78`. |

For P = `0x45b9`, `0x1004db0f0` computes W22 as `(P + 0x7b1f1816) AND 0x84e0abba = 0x98a`. Replacing that W22 with `0x986` at the status-store block changes the earlier dispatch too. Its actual arithmetic `((((W22 + 0x3b7e) OR 0xb1) - 0x1709) XOR W22)` returns `0x272a`. The selected slot `0x100e40780` carries IA discriminator `0x41d6` and target `0x10079310c`. The branch at `0x100404298` requires `0x81ba`. This counterfactual rules out reusing the established route by changing W22 alone.

## Other fixed-frame dispatch sites

These four local branch forms use IA discriminator `0xcb78` and require the input shown to transfer through `0x100e31a60`.

| Branch | Required input or constraint |
| --- | --- |
| `0x10043551c` | W8 = `0x986` at the table load at `0x100435514`. Its reaching value in the profiled frame is unknown. |
| `0x1004cb0b0` | Its index is `(byte * 0x2c9e) XOR frame_word`. The byte comes from S+0xbfb3 B and the frame word from S+0x492c B. The initializer's store at `0x1005bdf98` sets that word to `P - 0x3bd3 = 0x9e6` when its W21 equals P. On that definition the product would have to equal `0x60`. No byte value in 0–255 has this product modulo 2^32. |
| `0x1004de2b0` | W9 = `0x986` at the table load at `0x1004de2a8`. Its reaching value in the profiled frame is unknown. |
| `0x10080b534` | S+0xa130 B must hold the authenticated pointer. `0x100930a9c` stores an indexed table pointer there, consuming W8 at `0x100930a90`. Its reaching index is unknown. The similar store at `0x100b0eaac` writes S+0xd980 B. |

## Assumptions and verification

| Premise and dependent result | Falsification probe |
| --- | --- |
| The observed code, table and fixups belong to the same pinned arm64e slice. This qualifies the address and discriminator comparisons. | Verify the SHA-256, UUID, original instruction bytes and chained fixup records. |
| The known post-open continuation has P = `0x45b9` and carries W22 from `0x1004db0f0` to the continuation load. This qualifies the `0x98a` result. | Recompute the two dispatch equations and trace the reaching W22 at `0x100a3b924`. |
| The initializer's S+0x492c B store survives with its W21 equal to P. This qualifies the byte-dispatch exclusion. | Check the last writer of the frame slot and enumerate the 256 byte inputs. |
| A write to S+0xa130 B reaches `0x10080b528` in the same frame. This is necessary for that stored-pointer path. | Identify the reaching writer and compare its index and live X20 with the fresh-open call arguments. |

High impact for distinguishing the open's output pointer from the later method destination load. Medium impact for identifying a possible stored-pointer source at S+0xa130 B. The incoming X20 value, full native route and Mach port names remain unknown. [Compressed instruction and fixup receipt](triage_evidence/live_lskdd_selector19_open_output_audit.json.zst)

A follow-up establishes the reaching X20 on the route from selector 19 output-buffer preparation. The additional producer supplies the required index without changing the post-open route. [Selector 19 open copyout](live_lskdd_selector19_open_copyout_report.md)
