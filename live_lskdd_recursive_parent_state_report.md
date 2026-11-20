# lskdd recursive parent state and return dispatch

The installed arm64e `lskdd` image supplies a producer for each scalar in the recursive child context and resolves the preparatory call to a 32 B copy. The parent reads the child's status separately from the wrapper's stack adjustment. Its return dispatch tests the status together with a 64-bit word addressed from the adjusted stack pointer. These operations establish a daemon-local contract relevant to the recovered selector 19 call. The continuous path from the request entry through recursion to selector 19 remains unknown. [Recursive caller and child context](live_lskdd_large_frame_caller_report.md) [Selector 19 binding and frame](live_lskdd_selector19_binding_report.md)

## Child inputs

Let S be the fixed-frame parent SP, C be the child context at S+0x1c968 B, and R be the 32-bit address-derived residue computed at `0x1008d582c`–`0x1008d585c`. All scalar state arithmetic below is modulo 2^32.

| Parent write or call | Value or transfer | Recursive consumer |
| --- | --- | --- |
| `0x1005bb164`–`0x1005bb16c` | Stores incoming W21 minus `0x2a03` at S+0x3b8c B. | `0x1008d5760` loads it into W20. `0x1008d5890` stores W20 plus `0x2a03 + R` at C+0x28 B. The child's decoder subtracts R, so this producer and consumer preserve the original W21 when the definition reaches the call. |
| `0x1008daf08` | Stores incoming W9 at S+0x9574 B. | `0x1008d5824` reads the slot. `0x1008d5898` writes the value XOR R to C+0x00 B. |
| `0x1008daf14` | Clears the 8 B cell at S+0x9f48 B. | `0x1008d5878` passes the address in C+0x20 B. |
| `0x1008daf20`–`0x1008daf3c` | Reads the source pointer at S+0x65b0 B and destination pointer at S+0x8ae0 B. Copies 12 B and appends 4 zero bytes. | `0x1008d5818` loads the destination pointer and `0x1008d5868` passes it in C+0x18 B. |
| `0x1008d580c` | Calls `0x10034e248` with X0 from S+0x9d80 B, X1 from the value at S+0xb330 B plus 0x50 B, and W2 = 32 B. The helper copies from X0 to X1. | `0x1008d586c` stores that destination pointer in C+0x08 B. |

The preparatory call reads the banks published at `0x1005b3e8c` and `0x1005b3ea4`. The pool rebases at `0x100e76568` and `0x100e75ef0` are adjusted by -8 B and -4 B, giving bank bases `0x100e06f90` and `0x100d3f720`. For every byte b, `b XOR bank_right[bank_left[b] XOR 0x62]` equals `0xe6`. Adding bias `0x8c44` yields index `0x8d2a` and slot `0x100e73780`. Its IA fixup names `0x10034e248` with discriminator `0x81d1`. The original helper copied all 32 B for each of the 64 source and destination alignment pairs modulo 8, preserving the source and the destination guard bytes in those disjoint-buffer cases.

The preparation block's entry fixup is at `0x100e30a90` with IA discriminator `0xdb1d`. Its outgoing transfer at `0x1008daf64` depends on the state word at S+0x5b94 B and on whether the pointer at S+0x54d0 B is zero. With the earlier initializer fixture value `0x45b9`, nonzero selects slot `0x100e48aa8` and target `0x10093054c`. Zero selects slot `0x100e48c30` and target `0x10051f214`. Both use IA discriminator `0xa11f`. The producer of incoming W9 and the reaching path from these writes to `0x1008d5760` remain unknown.

## Parent return

| Site | Return data or control |
| --- | --- |
| `0x1008d577c`, `0x1008d595c` | Writes and later reloads W12 = `(W20 << 1) XOR 0x1b98` at S+0x5ff0 B. The reload precedes the SP adjustment. |
| `0x1008d5964`–`0x1008d596c` | Sets SP to S plus the 64-bit adjustment returned through the wrapper's X1 cell at S+0x10c88 B. |
| `0x1008d5970`–`0x1008d5988` | Loads the 32-bit status from C+0x2c B and the 64-bit marker from the adjusted SP+0xa4c0 B. The marker load executes for either status result. |
| `0x1008d5998`–`0x1008d59ac` | Sets M to 0 if status is `0x2ee02eab` and marker is `0x7c36115800000001`, and to 1 otherwise. Computes `W20 XOR ((W12 - 0x2c83) * M)`. |
| `0x1008d59b0`–`0x1008d59c0` | Uses the result as a signed index in the preserved table at `0x100e2ce30` and transfers with IA discriminator `0x0637`. |

In the fixture whose state producer starts with W21 = `0x45b9`, the parent reads W20 = `0x1bb6` and computes W12 = `0x2cf4`.

| Predicate in that fixture | Index | Fixup slot | Target |
| --- | --- | --- | --- |
| Both status and marker match | `0x1bb6` | `0x100e3abe0` | `0x1009a7a48` |
| Either comparison fails | `0x1bc7` | `0x100e3ac68` | `0x1005474cc` |
| Status is `0x2edf880f`, tested again in the mismatch continuation | `0x2cf4` | `0x100e435d0` | `0x10051f214`, discriminator `0xf71d` |

The last target is also reachable from the preparation block's null-pointer fixture, via a different slot and discriminator. The two transfers establish shared code at `0x10051f214`. The incoming register state on a continuous native route remains unknown.

## Verification and evidence limits

The auditor checks the slice digest, records 377 original instructions and 10 chained fixups, and executes isolated windows with Unicorn. It verifies one state-publication and context-encoding composition, two preparation cases, 64 copy alignment pairs, and eight post-return cases. The post-return matrix crosses adjustments of 0 B and 32 B with both status and marker predicates. The nonzero cases place opposite marker values at the old and new SP-relative locations. Modeled table slots contain resolved targets and execution stops at the authenticated branches after checking the target register and discriminator. The status `0x2edf880f` comes from the earlier wrapper replay, the other status and the nonzero adjustment are input fixtures. No native IPC was observed in this audit. [Auditor](triage_evidence/audit_live_lskdd_recursive_parent_state.py) [Compressed receipt](triage_evidence/live_lskdd_recursive_parent_state_audit.json.zst) [Prior wrapper replay](live_lskdd_large_frame_caller_report.md)

```sh
uv run --no-project --with unicorn==2.1.4 --with capstone python \
  triage_evidence/audit_live_lskdd_recursive_parent_state.py
```

| Assumption and dependent finding | Falsification check |
| --- | --- |
| A1. Preferred addresses and fixups refer to the pinned installed arm64e slice. Applies to the whole report. | Recheck UUID `28d510e5-3b91-3916-97ab-b765a3a7ba21` and the recorded SHA-256, bytes and fixups before transferring findings to another image. |
| A2. The producer and consumer use the same fixed-frame epoch and the cited definition survives. Applies to child input provenance. | Trace the authenticated predecessors and check for intervening stores and changes to SP before the parent block. |
| A3. Caller buffers are disjoint and valid in the 32 B helper tests. Applies to the alignment evidence. | Compare the observed pointer ranges in a legitimate call and check exact bytes from entry to return. |
| A4. Supplied return data exercises both predicates for the recorded W21. Applies to the destination table. | Capture the original child status, X1 cell and adjusted-SP marker at the return boundary. The observed W21 determines the indices. |

High impact for interface attribution. The resolved preparatory call is a local copy and the recursive return carries two separate values. Medium impact for continued route recovery. The marker producer, upstream W9 definition, selector 19 connection provenance, and native pipe and port identity remain unknown.

A follow-up identifies a fixed-frame writer for the marker slot and traces additional consumers. The word at the adjusted runtime address still needs a reaching definition. [Marker and frame staging](live_lskdd_recursive_marker_report.md)
