# FairPlay RPC 502 audit-token provenance on the installed build

On macOS build `26C5035r`, the kernel RPC transport selects a trailer template containing eight zero audit words. The ordinary 64-bit CoreFoundation receive path requests the full 68 B AV trailer. The matching daemon stub copies the 32 B audit token into its application arguments, and the installed libbsm routine projects token word 5 into the daemon's requested PID output. Under ordinary matched delivery, that output is 0. The originating transport's identity, the token already in the message, and the receiver's context are separate fields. A native RPC 502/602 exchange remains unobserved.

| Input | Pinned identity |
| --- | --- |
| Current boot fileset | SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126` |
| Embedded and running kernel | `90195379-954d-3ca3-baac-327341f14211` |
| Embedded FairPlayIOKit | `316464f8-eade-30ca-938e-2f430b1ed5bc` |
| Installed arm64e dyld cache | `8b1e17c6-72d6-3017-91a4-916022e3612e` |
| Installed libbsm | `ccdec355-884e-36f6-a571-7291f637b936` |
| Reference daemon arm64e | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67772d4ac36ffb63e` |

The previous installed daemon slice audit ties the reference code and fixups to the running process's matched slice. The current audit rechecks the kernel UUID, both binary hashes, the exact daemon bind and the installed libbsm export. Addresses below are unslid. [Installed slice and request ABI](live_fairplay_rpc_abi_report.md) [Installed CoreFoundation receive](live_fairplay_cf_receive_report.md)

## End-to-end source data flow

| Boundary | Current source evidence | Effect |
| --- | --- | --- |
| Kernel RPC right conversion | `0xfffffe000bd3da34` to `0xfffffe000bd0eacc` | The kernel RPC wrapper enters kernel-form copyin after inserting the thread reply endpoint. |
| Kernel trailer initialization | `0xfffffe000bd0ece4` and `0xfffffe000bd0ece8` | X1 is null at the initializer call. The null-task branch at `0xfffffe000bd0c178` selects the template path. The separate nonnull-task branch sources credentials through task +0x320. |
| Populate the trailer | `0xfffffe000bd0c1e8` through `0xfffffe000bd0c200` | Copy the 64 B template at `0xfffffe0007010af8` and clear its last 4 B in the 68 B destination. Template offsets +0, +4 and +8 contain type 0, initial extent 8 B and sequence 0. The security words at +12 are `(0, 1)`. The eight audit words at +20 are all zero. |
| Supply receiver-side metadata | `0xfffffe000bd24df4`, `0xfffffe000bd24e1c`, `0xfffffe000bd24e90` | Read the receiving destination object's +0x78 context before right conversion. On normal header/body copyout success, pass that context, the map and the receive options to the packer. |
| Finish the 64-bit trailer | `0xfffffe000bd0e7d4`, `0xfffffe000bd0e84c` through `0xfffffe000bd0e85c`, `0xfffffe000bd0e424` through `0xfffffe000bd0e458` | AV selector 7 requests 68 B for a map maximum offset of at least `0xf0000001`. The packer writes extent at +4, receive sequence at +8, context at +52 and zero at +60. These stores leave +20 through +51 intact. |
| Copy to user | `0xfffffe000bd0e624` and `0xfffffe000bd0e628` | For the normal 88 B kernel request, the 64-bit packed request is 80 B. The 148 B footprint fits the 3,072 B CF capacity. The contiguous branch makes one copy at `0xfffffe000bd0e6c4`. The split branch copies the header and the remaining body-plus-trailer at `0xfffffe000bd0e678` and `0xfffffe000bd0e68c`. |
| Copy into the application ABI | Daemon `0x1000051cc`, `0x1000051d0`, `0x1000051f8` | Copy the two 16 B audit-token halves from trailer +20 and +36. X6 points to that copy at the application entry. The RPC's separate origin scalar comes from its inline arguments. |
| Project the PID | Daemon `0x1007fc754`, libbsm `0x206c3f7b0` and `0x206c3f7b4` | The daemon passes X6 as its only nonnull output pointer to `_audit_token_to_au32`. The installed routine reads a 32-bit word from token +20 and stores it through X6. The daemon reloads that output at `0x1007fc75c` for its local branch. |

For the packed user message, the audit token lies at offsets `[100, 132)` B and the PID word at `[120, 124)` B. The latter follows from 80 B inline + 20 B audit field offset + 5 × 4 B. The daemon's original authenticated import at `0x1010a0500` names libbsm's `_audit_token_to_au32` with IA discriminator `0xdc55`. The previously recovered branch consumes the PID word. This audit carries the source evidence through the installed libbsm implementation and establishes no downstream policy outcome. [Daemon application and prior PID proof](daemon_rpc502_report.md) [Earlier copyout contracts](kernel_user_copyout_report.md)

## Native diagnostic coverage

The `2026-11-19T05:09:01Z` to `2026-11-19T05:54:01Z` retained unified-log query included all processes named `fairplayd` and senders whose image path ends in `FairPlayIOKit`. It returned a metadata row and zero event rows at info visibility. `ktrace info` exited with status 1 and reported “Too many levels of remote in path.” The local decoder resolved the following IDs without obtaining a trace session.

| Debug ID | Local decoder label |
| --- | --- |
| `0x0120000c` | `MACH_IPC_msg_send` |
| `0x01200010` | `MACH_IPC_msg_recv` |
| `0x01200028` | `MACH_IPC_kmsg_info` |
| `0x0120002c` | `MACH_IPC_kmsg_link` |

The decoder proves these numeric labels. Event emission and argument availability on this build remain unknown. A native match would require lifecycle evidence for the request and reply, the service destination used for RPC 502, and the particular outstanding kernel wait satisfied by RPC 602. A kernel reply receive binding can persist across multiple exchanges. [Native XPC observation](fairplay_native_xpc_observation_report.md) [Reply binding and transaction identity](live_fairplay_reply_rights_report.md)

## Assumption register

| ID | Assumption and dependent result | Falsification evidence |
| --- | --- | --- |
| A1 | The current fileset and cache correspond to the code executing on the host. This supports use of the identified kernel, CF and libbsm routines. | Check the running kernel UUID, daemon slice and live cache mappings and compare their bytes or image UUIDs. |
| A2 | The designated message arrives through the established kernel RPC send and ordinary receive copyout. This connects the null-task token producer to the daemon. | Correlate send and receive of the same message in a native trace, including the service member and reply right. |
| A3 | The receiving map selects the 64-bit branch and CF delivers the ordinary successful receive buffer to the installed callback. This supports the 80 B and 68 B extents and PID offset. | Compare receive options, receiver map width, returned extents and callback buffer identity. |
| A4 | The daemon preserves the copied token through its application frames and resolves the authenticated import to the inspected libbsm image. This supports PID 0 for the kernel token. | Verify the token at the MIG copy and again at the libbsm call, and compare the resolved target with the installed export. |
| A5 | The retained log query and ktrace inspection cover the stated scope. This supports the negative diagnostic result for that scope. | Repeat the bounded query while the interval is retained and verify that results contain actual events. Decode a captured correlation record to extend coverage. |

**High impact.** The installed kernel and libbsm independently establish the producer and consumer of the PID word. The receive sequence and destination context have receiver-side origins, which distinguishes them from the eight preserved audit words.

**Medium impact.** The distinct contiguous and split copy branches identify where the same logical trailer can cross the kernel/user boundary. The storage class used for a live FairPlay request remains unknown.

## Reproduction

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_audit_token.py \
  "$KERNEL_COLLECTION" "$DAEMON_IMAGE"
z3 triage_evidence/rpc502_pid_gate.smt2
```

The optional `--diagnostics START_UTC END_UTC` switch reads retained diagnostic metadata. The static audit saves five compiler-bounded kernel ranges, selects 43 kernel instruction pins, verifies seven direct call targets and records the exact libbsm function. For B total input bytes, N symbol and fixup records, and L scoped log records, time and space are O(B + N + L). No FairPlay traffic was generated and no target or IDB was modified. [Audit script](triage_evidence/audit_live_fairplay_audit_token.py) [Compressed evidence](triage_evidence/live_fairplay_audit_token_audit.json.zst)
