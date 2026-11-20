# Kernel send-once notification on the ADID legacy reply path

On build `26C5035r`, deallocation of the live send-once right received by `adid` can cause the kernel to send Mach notification ID 71 to the original `fairplayd` reply port. The selected kernel branch constructs this notification using the same destination port object and calls the common send path. If the waiting Mach call receives ID 71 successfully, the original daemon wrapper returns `MIG_SERVER_DIED` (-308). Private replays of the outer helper return `0xffff5028` on the first attempt and after the invalid-destination lookup and retry. Native delivery and the actual endpoint state remain unknown. [Original-byte audit and replay](triage_evidence/audit_adid_send_once_notification.py) [Compressed receipt](triage_evidence/adid_send_once_notification_audit.json.zst)

```text
fairplayd               adid / libxpc                 kernel
    |-- Mach 1200 ------->|                              |
    |   make send-once   |-- destroy received message ->|
    |                    |   deallocate reply name      |
    |                    |                         retire name
    |<-------------------- ID 71 if notification sent --|
    |   Mach success -> MIG_SERVER_DIED (-308)
    |   legacy helper -> 0xffff5028
```

The incoming legacy request carries an application-level 20 B out-of-line record in the retained case. The return edge examined here is a header-only kernel notification. The installed libxpc receive path destroys the ordinary user request before constructing an application reply. The separate successful ADID XPC `data` reply has its own peer connection and remains outside this trace. [Receiver audit](adid_legacy_mach_receive_report.md) [Direct XPC request/reply](live_fairplay_adid_ipc_report.md)

## Port origin, native entry and right release

| Transition | Original site | Contract |
| --- | --- | --- |
| Select the sender's reply receive name | `fairplayd` wrapper call `0x100de9f54`, libkernel `0x180548f00` | `mig_get_reply_port` reads the thread cache at TPIDRRO_EL0+16 B. On zero, it calls `mach_port_construct` at `0x180548f4c` with source flags `0x1000` (`MPO_REPLY_PORT`) and initial context zero, then stores the returned name at `0x180548f58`. The fast construction SVC is `0x180548b14`, signed selector -24. |
| Transfer a reply right | `fairplayd` `0x100de9fac` | Combined send and receive uses options 3, a 56 B request and 64 B receive capacity. The local field of the outgoing header uses MAKE_SEND_ONCE. The request destination is the cached `com.apple.adid` service send name. The reply receive argument is the daemon's distinct thread-cached name. |
| Release the received right | libxpc `0x184bc697c`, libkernel `0x180549be4` and `0x180549e08` | `mach_msg_destroy` takes the received remote name and disposition and reaches `mach_port_deallocate` for a valid send-once name. This name belongs to `adid`'s namespace. It identifies a right to the same underlying port as the daemon's receive name under the stated transaction premise. |
| Enter the kernel | `0x180548acc`, kernel dispatcher `0xfffffe000bebfcc8` | The library executes SVC `0x80` with X16 = -18. The checked table at `0xfffffe0007f07018` uses 24 B records and selects row 18. Its authenticated handler slot at `0xfffffe0007f071d0` resolves to `0xfffffe000bd23738`. The parallel original name row declares `_kernelrpc_mach_port_deallocate_trap`. |
| Resolve the task and entry | `0xfffffe000bd23754`, `0xfffffe000bd26468`, `0xfffffe000bd2648c` | The trap's two arguments are task and name. The ordinary task conversion authenticates its IPC space. The deallocation front end resolves the name and hands the entry to the right-type dispatcher. |
| Remove a live send-once entry | `0xfffffe000bd1bc34`, `0xfffffe000bd1bd3c`, `0xfffffe000bd1beb0` through `0xfffffe000bd1bec0` | Entry flags masked with `0x1f0000` equal `0x40000` (`MACH_PORT_TYPE_SEND_ONCE`). The right path authenticates the object, checks whether its state still permits live-right handling, removes the namespace entry and unlocks the space. It passes the retained destination object to `0xfffffe000bd110f4`. |

If task conversion fails with `0x10000003`, libkernel selects its separate task-port RPC 3206. The current fallback emitter is `0x18056d99c`. The kernel entry and notification chain above apply to the successful fast-trap path. [Prior namespace operation comparison](kernel_membership_removal_report.md)

## Kernel notification emission

The helper at `0xfffffe000bd110f4` clears the 32-bit word at port+0x3c B and checks the low three bits of port+1 B. Zero selects a release path at `0xfffffe000bd11144`. Values 1 and 2 additionally compare the authenticated pointer at port+0x48 B against the pointer in `0xfffffe0007e6eb68`. Equality selects the path at `0xfffffe000bd111c4`, which decrements the send-once count and releases a reference without assembling the notification. The remaining path requires the 16-bit word at port+0x38 B to be below `0xfffe`; otherwise it takes the same release path as the state-zero branch. These are source predicates on kernel port state. The report assigns no native values to those fields.

| Boundary | Original site | Source output |
| --- | --- | --- |
| Assemble notification | `0xfffffe000bd11180` through `0xfffffe000bd11194` | A 32 B kernel-form header with bits 18 (MOVE_SEND_ONCE), the retained port object at +8 B, zero local reply pointer and voucher, and ID 71 at +28 B. The size field starts zero. The constant at `0xfffffe000700dd20` supplies the voucher/ID pair. |
| Request actual send | `0xfffffe000bd111b0` | Calls the send-only helper at `0xfffffe000bd3d4d0` with the header, explicit 32 B length, raw options `0x50001`, timeout zero and NULL optional output. |
| Prepare kernel message | `0xfffffe000bd3d510`, `0xfffffe000bd3d520` | Allocate and normalize the copied message, then transfer the existing send-once destination into it. Earlier studies establish the format and common helper roles. |
| Queue toward sender | `0xfffffe000bd3d578`, `0xfffffe000bd0f208` | Selected common send issues the queue call with the queue at destination+0x28 B and the prepared message. Admission and a matching receive on the daemon thread remain unobserved. |

The SDK's user-space notification has a 24 B header and no body, plus a separate 20 B format-0 receive trailer in the declared type. The 32 B kernel-form length excludes a trailer. This increment uses the existing kernel copyout and queue studies to interpret the interface and does not execute a kernel send. [Current common transport and queue](live_iokit_mach_transport_report.md) [Current reply rights and user copyout](live_fairplay_reply_rights_report.md)

## Sender result

The original wrapper checks Mach transport status before parsing. With status zero, it reads the ID from the received header at `0x100dea000`. ID 71 selects `0x100dea060` and sets W21 to -308. It calls `mach_msg_destroy` on the receive buffer at `0x100dea0dc` and returns that status. The ID 71 branch does not reach the pointer/count output stores or the transport-error reply-port helper calls.

| Private receive case | Wrapper status | Outer helper status | Destination state |
| --- | --- | --- | --- |
| ID 71 on first send | `MIG_SERVER_DIED` (-308) | `0xffff5028` | Initial cache preserved. No lookup. |
| ID 71 on retry after invalid destination | `MIG_SERVER_DIED` (-308) | `0xffff5028` | Successful lookup publishes refreshed cache. |
| Header-only control with ID 72 | `MIG_REPLY_MISMATCH` (-301) | `0xffff5028` | The same per-attempt destination behavior. The fixture isolates the ID comparison. |

All 32 cases complete to the same original outer return consumer at `0x100701a7c`. They cover eight retained caller states, two IDs and first send versus retry, for 68,720 original instruction visits. The original helper requests free of the 20 B request buffer and 24 B record at `0x100e24fdc` and `0x100e2507c`. Only the initial invalid-destination transport return in the retry profile reaches `mig_put_reply_port`. The installed implementation of that helper at `0x18054e1d8` is a bare return. The scalar status `MIG_SERVER_DIED` indicates the wrapper's interpretation of ID 71. It does not establish that `adid` exited.

The pinned RAX annotation contains zero parsed guest sends or receives and zero bridge host receives of IDs 71, 1200 or 1300. The private receive model supplies the successful return and 24 B header at the existing transport boundary. Process launch, service messaging and kernel queueing are absent from that replay. [Input trace provenance and client emission](daemon_adid_mach_fallback_report.md)

## Assumptions and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The installed shared cache and selected boot kernel qualify the reported sites. The sender uses the pinned daemon slice. | Match the selector table, name row and authenticated handler against the collection, compare the kernel UUID with boot selection, verify the loaded cache UUID, and verify the daemon SHA-256 and stub binding. |
| A2 | ADID's destroyed message carries a live send-once name to the reply port that the sender is waiting on. | Compare the received disposition and task-local name with an ordinary transaction's namespace conversion and reply object. Stale or inactive right state takes a different branch. |
| A3 | The current port state admits notification construction, and send and receive finish successfully. | Check each gate preceding `0xfffffe000bd111b0` and correlate queue admission, sender wait and returned header. No native port state or delivery is inferred from the fixture. |
| A4 | The prior replay inputs reach the same original transport wrapper. | Recheck all eight ordered request prefixes, exercise the immediate first-send and lookup/retry routes, and compare ID 71 and ID 72 before the shared original cleanup. |

High impact for connecting provider-side disposal of the reply right to the sender's distinct error status. Medium impact for identifying the eligible kernel send boundary and separating service-name refresh from reply-name retention. Native scheduling, notification delivery, and transaction-linked FairPlayIOKit activity remain unknown. The original files resolved this increment without IDA.

The audit preserves the three trap rows, seven complete kernel code bodies around the release/send branch, selected source windows, eight SDK assertions, and the 32 private results. It uses O(B + F + I + V + T) time and space as an upper bound for collection bytes, fixup records, retained instructions, CPU visits and trace bytes. QG1 covers factual scope, QG2 the premises, QG3 the port lifecycle and return path, QG4 the message geometries and decimal/signed values, QG5 the alternate gate and control cases, QG6 the binary/SDK/trace provenance, and QG7 the stated impacts.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_adid_send_once_notification.py \
  "$CURRENT_COLLECTION" "$ANNOTATED_RAX_TRACE"
```
