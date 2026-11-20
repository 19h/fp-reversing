# fairplaydeviceidentityd selector 26 caller evidence

In the installed arm64e image, the block at `0x1000748fc` writes the exact ordered pair of byte tables that lets the record call at `0x1000504a0` reach the selector 26 adapter. With X26 equal to the image's dispatch table base and those two stack values intact at the call, every byte of lookup input selects authenticated slot `0x1005e7990`, whose target is `0x1001f7e68`. The complete same-frame route from the writes to the call, the originating connection port and a native method request from this client remain unknown. [Adapter and IOKit argument mapping](live_fpdi_selector26_route_report.md) [Registry observations](live_fairplay_additional_clients_report.md)

## Stack cells and call selection

All PCs are preferred virtual addresses. The original signed adjustments below apply to the dyld rebase targets. X21 is set to `0x1005e7c80` at `0x10007492c–0x100074930`.

| Store PC | Stack cell | Rebase slot | Rebase target | Signed adjustment | Table |
| --- | --- | --- | --- | --- | --- |
| `0x100074a38` | SP+296 B | `0x1005e9138` | `0x1674b0a97` | `-0x66efef57` | `0x1005b1b40` |
| `0x100074a4c` | SP+288 B | `0x1005e7ff8` | `0x15da8732f` | `-0x5d4cb0ff` | `0x1005bc230` |

The call reads SP+296 B as the left table and SP+288 B as the right table. For input byte `b`, it computes `i = 0x4d3f + (b XOR right[left[b] XOR 0xd6])`. The term in parentheses is `0xa3` for all 256 values. The effective address is `0x1005c0a80 + 8 * 0x4de2 = 0x1005e7990`. The original fixup uses IA, discriminator `0x132e` and no address diversity, matching the call at `0x1000504a0`. The separate stores at `0x1000f1758` and `0x1000f176c` put the same pointers in the opposite order. That order produces `0x45`, selecting `0x1005e76a0` with discriminator `0xaa88` at the same base.

The auditor enumerates all 469,313 possible starts of a 256 B window in the 469,568 B `__TEXT,__const` section. A table pair that produces a constant XOR for all 256 input bytes requires each table to be a permutation. Of the 523 permutation windows and four in-range fixups with the required key, discriminator and diversity, exactly one ordered pair supplies a fixed compatible slot. This is a census of file-backed section windows and constant compositions. Runtime-built tables or a different base could produce other results. [Compressed audit receipt](triage_evidence/live_fpdi_selector26_caller_audit.json.zst)

## Predecessor and continuation

Under assumption F1, the producer at `0x1000748fc` saves the table at FP−200 B, writes its X7 input to SP+56 B, and calls `0x10020b5f0` with X0=16 B. The ordinary nonnull path makes a second call to the same helper with X0=32 B and reuses the same ordered byte tables for a third call to that helper. The third result is stored at offset 24 B in the object returned by the second call. This object reaches `0x100017b8c` in X7, where the code loads that pointer. The third call's X0 is a computed word. Its meaning and the helper's implementation are outside this result. [Other caller of the helper](live_fpdi_xpc_report.md)

| Original branch PC | Selected PC | Condition or data transfer |
| --- | --- | --- |
| `0x100074a60` | `0x1001523f8` | W19=`0x1410`, first helper result nonnull |
| `0x100152458` | `0x100147ce8` | First result receives two 8 B stores. W20=`0x61a` selects the next block. |
| `0x100147d7c` | `0x10007c2a8` | The comparison to the address adjustment is unequal for a nonnull result. |
| `0x10007c33c` | `0x100072a88` | Computed word `4` selects the block that calls the helper with 32 B. |
| `0x100072b5c` | `0x100012da8` | Second helper result nonnull |
| `0x100012eb4` | `0x1000c70b0` | Third helper result nonnull and stored at object+24 B |
| `0x1000c71e8` | `0x100017b8c` | Object pointer forwarded in X7 |

A separate candidate at `0x100054d00` reloads X26 from FP−200 B. Its branch at `0x100054d18` selects `0x1001286d8` when the computed index is `0x2a4c` and the saved base is `0x1005c0a80`. At `0x1001286d8`, incoming W8=`0xc0d` produces W20=`0x3d8b`. If the comparison there is false, the unchanged index `0xc0d` selects `0x1000503c4` with discriminator `0x20cd`. This W20 decodes to the adapter's structure-call dispatch value `0x3f8d`. The alternative precomparison index `0xc1a` can also reach the same entry if the comparison is true, but produces W20=`0x3da8` and therefore dispatch value `0x3faa`. The two routes require different reaching state. [Record encoding and adapter gate](live_fpdi_selector26_route_report.md)

After the call, `0x1000504a8` loads the record result from offset 4 B. With W20=`0x3d8b` and the same saved table base, the authenticated return branch at `0x1000504b4` reaches `0x100152828`. That block compares the full 32-bit result to `0x965c5dd5`. Equality selects `0x1000304f4` and inequality selects `0x10011e544`. The comparison consumes the adapter's published record word. A numeric success meaning for either destination remains unknown.

## Assumption register

| ID | Premise and dependent claim | Falsification probe |
| --- | --- | --- |
| F1 | The producer enters with W19=`0x1410`, X12=`0x1005c0a80` after relocation, valid live data and ordinary nonnull helper returns. The predecessor sequence is conditional on these values. | Trace the incoming authenticated branch at `0x100204b08` or another predecessor and verify the reaching state and returns. |
| F2 | Both producer stack values survive to the record call in the same frame, and X26 still names the original table. This qualifies the adapter edge and the result continuation. | Join `0x100017b8c` forward to `0x1001286d8` and check intervening stores and table restores. |
| F3 | The actual block receives W20=`0x3d8b` and the record has ordinary 8 B alignment. The selector 26 dispatch is conditional on that state and the adapter's existing nonnull gates. | Trace W8 and the comparison into `0x100128744`, then check the record's two pointer operands. |
| F4 | The record's connection container names the FairPlayIOKit user client and the extent is 16 B. Those claims qualify the inline request with Mach ID 2865. | Trace the object written at SP+56 B back to its producer and match the open and request in the same task. |

High impact for narrowing the control-flow and data-flow gap to a specific producer and candidate predecessor. Medium impact for identifying how the caller consumes the adapter result. The producer's 16 B helper argument is a distinct value from the method record's extent at FP−120 B. The latter depends on W28 at `0x1000503c4`. No Mach port numeric value or additional IPC emission follows from this static result. [Mach request and reply locations](live_iokit_mach_transport_report.md)

## Reproduction

The primary source is the installed arm64e slice, UUID `0a404c50-4901-312f-9e36-04565d30f305`, SHA-256 `f73ababfd9265e1bdacde11467d5a3701cec634c49ce3a65f5769cf5ccd843f0`. The auditor uses the same slice for raw instruction windows and dyld fixups. The enumeration maintains a 256-entry histogram across consecutive windows, then constructs the required right table for each left permutation and candidate fixup. For section bytes N, permutation windows P, compatible slots F and byte alphabet size A=256, the census uses O(N + PFA) time and O(N + PA) space. [Auditor](triage_evidence/audit_live_fpdi_selector26_caller.py)

    python3 -B triage_evidence/audit_live_fpdi_selector26_caller.py DAEMON
