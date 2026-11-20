# Arcade subscription reply and launch outcome

The kernel reads the process’s executable file offset for Arcade request `61471`. When `fairplayd` replies with `61571`, the kernel client validates the response and reads the decision only on status zero. Decision `1` leads to termination of the current task. Two specific errors restart endpoint acquisition. Other errors lead to the same task-termination routine through a separate diagnostic path. These paths are established for macOS build `26C5035r`, kernel UUID `90195379-954d-3ca3-baac-327341f14211`. The archived RAX trace has zero Arcade headers among 44 parsed Mach messages. Native port names, delivery and task outcome remain unknown. [Process launch and AST](live_arcade_ast_report.md) [Endpoint registration](live_arcade_registration_report.md) [Instruction receipt](triage_evidence/live_arcade_subscription_outcome_audit.json.zst)

```text
process record -> executable offset -> kernel client -> 61471 -> fairplayd
                    launch handler <- kernel client <- 61571 <- fairplayd
                          |
                          +-> return, reacquire endpoint, or terminate task
```

## Executable offset and subscription transport

| Transition | Original evidence | Data |
| --- | --- | --- |
| Select the process | `0xfffffe000bd29c28` calls the current-thread-related accessor. `0xfffffe000bd29c2c` loads the process pointer from accessor result +`0x18`. A fallback supplies a kernel-global pointer when that slot is null. | X27 is the base used for path preparation and the executable-offset load. |
| Read and send the offset | `0xfffffe000bd29c94` loads X3 from `[X27 + 0x5a0]`. The call at `0xfffffe000bd29cb0` passes X3 to `0xfffffe000bdda298`. The client stores X3 at `0xfffffe000bdda304`. | An 8 B executable byte offset [A2]. The trailing field starts at internal +`0x40` and user +`0x38`. The 72 B internal and 64 B user records therefore both end at the field’s final byte. |
| Submit RPC | `0xfffffe000bdda31c` loads the header literal containing request ID `61471`. `0xfffffe000bdda33c` calls the common kernel RPC helper. | The destination is the acquired anonymous daemon send reference. The request carries the 4,096 B out-of-line path and the separate executable offset. The transport receives into a buffer with 56 B internal capacity. |
| Receive and reply in `fairplayd` | Stub `0x1000054d8` supplies the offset to the application wrapper. The shared callback uses demultiplexer `0x1000055ac`, which inlines validation and calls the same wrapper. Shared server send is at `0x100035184`. | The wrapper stores the offset at +`0x18` in its 40 B primary record. The reply destination comes from the request’s reply right. The selected prior daemon traces leave this input slot unread before the downstream XPC send [A3]. |

The `p_textoff` attribution is source-correlated. Apple’s Arcade call reads `proc_getexecutableoffset(p)`, whose body returns `p_textoff`. The process declaration describes the field as an `off_t` offset in the executable vnode. The MIG definition transports it as `uint64_t`. The compiled path performs a single 64-bit load and store, preserving all 8 B. [XNU Arcade call](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/arcade.c#L285-L304) [XNU getter](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L2168-L2172) [XNU process fields](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_internal.h#L351-L357) [XNU MIG definition](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/arcade_upcall.defs#L37-L48) [Daemon argument record](arcade_subscription_report.md) [Daemon reply emission](daemon_receive_interface_report.md)

## Reply validation and launch action

The caller initializes a 4 B decision cell to `1` at `0xfffffe000bd29c98` and passes its address in X4. The RPC client returns a nonzero transport status directly. With transport status zero, it recognizes notification ID `71` as `MIG_SERVER_DIED` (`-308`) and an unexpected ID as `MIG_REPLY_MISMATCH` (`-301`). For `61571`, it requires a simple reply and a null remote object in the received kernel header. The original checks distinguish the two reply sizes below. The generated client returns `MIG_TYPE_ERROR` (`-300`) when the shape fails its checks. Received error paths reach the buffer cleanup call at `0xfffffe000bdda3b8`. [Kernel client instructions](triage_evidence/live_arcade_subscription_outcome_audit.json.zst) [Prior daemon reply construction](live_arcade_registration_report.md)

| Kernel / user size | Payload offsets in kernel / user representation | Client result |
| --- | --- | --- |
| 48 B / 40 B | Status `0x28` / `0x20`. Decision `0x2c` / `0x24`. | Status zero stores the decision at `0xfffffe000bdda3f8` and returns zero. Nonzero status is returned without decision writeback. |
| 44 B / 36 B | Status `0x28` / `0x20`. | Nonzero status is returned without decision writeback. Status zero reaches `MIG_TYPE_ERROR`. |

The launch handler releases its temporary daemon endpoint send reference at `0xfffffe000bd29ce0` before interpreting the returned status. The branch tests operate on W26 for status and W8 for the decision. [XNU outcome handling](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/arcade.c#L299-L331)

| Condition | Kernel branch or call | Effect |
| --- | --- | --- |
| `MIG_SERVER_DIED` (`-308`) | `0xfffffe000bd29cf4` | Restart endpoint acquisition at `0xfffffe000bd29a38`. |
| `MACH_SEND_INVALID_DEST` (`0x10000003`) | `0xfffffe000bd29d0c`, `0xfffffe000bd29d1c` | Discard the out-of-line map copy and restart at the same entry. |
| Other nonzero status or endpoint refresh failure | `0xfffffe000bd29dc4` or `0xfffffe000bd29d5c` to diagnostic call `0xfffffe000bd29d80` | Enter the current-task termination path. Refresh failure contributes local status `5`. |
| Status zero, decision equals `1` | `0xfffffe000bd29dcc` and `0xfffffe000bd29dd0` | Enter the same current-task termination path without the transport-failure diagnostic. |
| Status zero, decision differs from `1` | `0xfffffe000bd29dd4` | Return from the Arcade handler. The established private daemon success case supplies `0`. |

At `0xfffffe000bd29d88`, the handler converts its current thread to a task and passes that task to `0xfffffe000bd86d1c` at `0xfffffe000bd29da0`. The callee independently obtains the current task and compares it to the argument. Its regular termination path clears task state and traverses the task’s thread list, calling a per-thread routine at `0xfffffe000bd86e60`. Those instruction sequences and the source call corroborate `task_terminate_internal` [A2]. Final process exit and UI effects are unknown. [XNU task termination](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/task.c#L2876-L2975) [Prior private policy and receipt outcomes](arcade_policy_report.md)

## Assumptions and verification

| Assumption | Dependent claim | Falsification probe |
| --- | --- | --- |
| A1. The boot UUID and fileset identify the build under study. | Unslid addresses and decoded branches. | Compare the running UUID and build with the collection entries and recheck the function hashes. |
| A2. Pinned XNU is a semantic reference for the inspected code. | `p_textoff`, `should_kill` and `task_terminate_internal` names. | Compare exact-build type and symbol records or independently identify the writer of process +`0x5a0` and other callers of the termination entry. A discrepancy changes the names without invalidating the recorded instructions. |
| A3. The archived trace and private daemon runs cover their recorded invocations. | No observed subscription exchange in the archive and no offset read in the retained pre-send paths. | Reparse the archived headers and inspect other native transactions or downstream paths for the same field. |

High impact attaches to the closed static join between the daemon decision and the launch handler’s task action. Medium impact attaches to identifying the trailing request scalar and separating retry, validation failure and daemon decision. The report adds evidence for the kernel proper’s Arcade channel. A transaction-linked FairPlayIOKit call remains unknown.

The audit checks 70 instruction anchors and 13 direct calls and records 750 instructions across four compiler-bounded functions. It rechecks the archive hash and all 44 printed Mach headers. Hashing and parsing take O(B + T + I) time and space in fileset bytes B, trace bytes T and retained instructions I. All reported sizes are exact byte or instruction counts. [Verifier](triage_evidence/audit_live_arcade_subscription_outcome.py) [Compressed instruction receipt](triage_evidence/live_arcade_subscription_outcome_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_arcade_subscription_outcome.py \
  "$BOOT_FILESET" "$ANNOTATED_TRACE"
```
