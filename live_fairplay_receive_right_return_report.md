# FairPlay receive-right return on the current kernel

On build `26C5035r`, the installed launchd check-in path retains a send right to the service port and requests notification 69 before handing the receive right to the job. The installed kernel has a destruction branch that consumes the backup destination and emits a complex notification carrying that receive right. Launchd validates the message and uses the descriptor's receive name to find the registered dispatch source. A native control on private ports confirms that a retained send right in the receiving task can preserve the numeric name across receive-right return. Native FairPlay notification delivery and subsequent check-in remain unobserved. [Current service check-in](live_fairplay_checkin_report.md) [Earlier return analysis](port_destroyed_return_report.md)

```text
launchd holds the service send right -> launchd requests notification 69
                                      -> check-in moves the receive right to the job

eligible receive-right retirement -> kernel sends notification to backup port
                                  -> descriptor carries service receive right
                                  -> launchd looks up descriptor name
                                  -> launchd merges event 69 into the record source
```

## Registration, emission, and incoming dispatch

All addresses are unslid. The audit matched PID 1's CodeDirectory hash and universal slice offset to the installed arm64e launchd image, then verified both original call instructions and the authenticated notification callback fixup. The boot collection hash, running kernel UUID, and running dyld cache UUID were checked before using the kernel and libsystem_kernel addresses.

| Transition | Current location | Established operation |
| --- | --- | --- |
| Arm during service activation | launchd `0x100046ef8` | Invokes setup with notification ID 69 on the ordinary check-in activation path. |
| Retain service send name | launchd `0x100045c54`, `0x100045d4c` | Stores the service name at notification-record +16 B. Calls `mach_port_insert_right` with the same name in both name arguments and disposition 20, `MAKE_SEND`. |
| Register the backup destination | launchd `0x100045d5c` through `0x100045d84` | Reads the notification destination from `0x10008af20`. The non-null branch requests ID 69, sync 0 and `MAKE_SEND_ONCE` (21). The null branch passes disposition 18. The previous right is returned separately. |
| Insert the notification record | launchd `0x100045dbc`, `0x100045f44` | Inserts a record indexed using the saved service name. |
| Enter the kernel | libsystem_kernel `0x18054ab50`, `0x180548cd0`, `0x18054cd90` | Calls trap 77 first. A return of `0x10000003` takes the MIG fallback. The fallback emits a 60 B request with ID 3213. |
| Converge and register | kernel `0xfffffe000bd2401c`, `0xfffffe000bdd08b0`, `0xfffffe000bd27360`, `0xfffffe000bd2738c` | Trap and MIG reach the same routine. The selected direct layout stores the signed backup at port +96 B. The extended layout stores it at +16 B of the object reached through the port field. |
| Consume and emit | kernel `0xfffffe000bd15b58` through `0xfffffe000bd15b80`, `0xfffffe000bd1607c` | The direct branch authenticates the saved backup destination, clears its field, and passes a 52 B internal message to the send helper at `0xfffffe000bd3d4d0`. The message uses that destination and carries the service port object. The kernel constant at `0xfffffe000700dd38` supplies ID 69 and descriptor count 1. |
| Select and validate on arrival | launchd `0x100049adc`, fixup `0x100083690`, validator `0x1000498c0` | Selects the ID 69 handler, which requires the complex bit, 40 B inline extent, one descriptor and receive disposition 16, type 0. |
| Gate and look up the service | launchd `0x100045908`, `0x10004592c`, `0x10004593c` | Requires zero in the current context word also read by the XPC reply's `req_pid` path at `0x1000467bc`. The validator supplies header local name and descriptor name. The handler uses the descriptor name for its kind-1 lookup and merges 69 into the matching record's source. |

The static zero check identifies a decision in the handler. The provenance of the context value for a specific native FairPlay notification remains unknown. The next dispatch stage, including the source callback, recovery and possible reactivation, belongs to the service lifecycle investigated separately. [Audit-context provenance](launchd_audit_context_report.md) [Endpoint job lifecycle](endpoint_job_lifecycle_report.md)

## Task-local native control

The audit allocated a watched receive port and a separate notification receive port. It registered ID 69 with sync 0 and `MAKE_SEND_ONCE`, then removed the sole watched receive user reference. It polled the private notification port with a 128 B buffer and a zero timeout. Both runs returned a 40 B notification with bits `0x80001200`, remote name zero, local name equal to the notification destination, and one type-0 descriptor with receive disposition 16. The old name was queried before receipt, while the receive right was in transit.

| Case | Old name before notification receipt | Descriptor name at receipt | Right counts after receipt |
| --- | --- | --- | --- |
| No retained send right | `KERN_INVALID_NAME` (15) | Different numeric name | One receive reference |
| One retained send reference | Send only, one send reference | Same numeric name | One send reference and one receive reference |

In both cases the previous notification right was null, and cleanup succeeded. The test keeps the receiving namespace fixed across the two cases. In the second case, the send right stayed valid while the receive right was in transit, and the receive right joined that existing name at copyout. This behavior accounts for how launchd's retained name can match the descriptor name used for its record lookup. The experiment used ordinary Mach APIs on ports owned by the audit task. It recorded no FairPlay traffic. [Earlier static receive-name and guard analysis](receive_name_guard_report.md)

## Assumption register

| ID | Assumption and dependent inference | Falsification probe |
| --- | --- | --- |
| A1 | The captured collection and selected user-space images correspond to the audited running build. The reported locations depend on this match. | Recompute the collection digest, check the live kernel and cache UUIDs, and reselect launchd by live CDHash and file offset. |
| A2 | The validated lookup uses the descriptor name and can match a record indexed by the retained right. | Check the descriptor load at +28 B, its register at the lookup call, the record store at +16 B and the independent key load at insertion. |
| A3 | A live FairPlay return would follow an eligible kernel backup branch and arrive while launchd still holds the retained reference. The private observations support the mechanism. The FairPlay conditions remain unknown. | Correlate naturally occurring receive-right retirement, notification delivery, record lookup and the next check-in for one service lifetime. |
| A4 | An unchanged numeric name can identify continuity only within the same receiving namespace and right lifetime. Slot 17 continuity is unknown. | Compare object identity at publication, backup return and the next ordinary check-in. Include an observation that distinguishes an intervening slot replacement from continuity. |

**High impact.** The registration and copyout findings give a testable causal chain for a native return. The relevant name for the launchd record is the descriptor name in the launchd namespace. The numeric name previously observed in the daemon belongs to a separate namespace.

**Medium impact.** The direct and extended backup storage branches affect which field needs inspection during a passive lifecycle capture. Guard status, delivery timing, job state and live host-slot identity remain open.

## Reproduction and quality gates

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_receive_right_return.py \
  "$KERNEL_COLLECTION" "$LAUNCHD_IMAGE"
```

The script verifies three image identities, checks original instruction and fixup anchors, compiles the installed SDK's Mach layout assertions, and executes two private test cases. With B input bytes, F fixups, N symbols, and I stored instruction words, time and working space are O(B + F + N + I). The number of private-port operations is constant.

| Gate | Verified item |
| --- | --- |
| QG1 | Statements describe observed behavior, decoded control flow, or explicitly conditional inference. |
| QG2 | A1 through A4 specify a separate falsification probe for each dependent claim. |
| QG3 | The report covers the incoming notification, its kernel emission site, the outgoing registration fallback, and launchd's lookup. |
| QG4 | Byte extent and descriptor offsets agree with SDK assertions and both captured private messages. The 52 B kernel envelope and 40 B user message are measured in their respective layouts. |
| QG5 | Native private copyout, static launchd behavior, and native FairPlay restart coverage are independently stated. |
| QG6 | The receipt preserves original instruction words, image identities, the notification fixup, and both private outcomes. |
| QG7 | The impact bounds identify where namespace identity and storage layout affect a native correlation. |

[Audit script](triage_evidence/audit_live_fairplay_receive_right_return.py) [Compressed receipt](triage_evidence/live_fairplay_receive_right_return_audit.json.zst)
