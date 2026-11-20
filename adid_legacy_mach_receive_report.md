# ADID listener disposition of legacy Mach message 1200

The [send-once follow-up](adid_send_once_notification_report.md) identifies the conditional kernel notification path and the daemon's `MIG_SERVER_DIED` status after ID 71. It records the reply port's constructor, emission and queue sites, and conditions on the live port state.

On macOS build `26C5035r`, the installed `com.apple.adid` XPC listener registers libxpc's `_xpc_connection_mach_event` as its Mach-channel callback. A delivered request with ID 1200 enters libxpc's Mach notification demultiplexer before XPC decoding. For an ordinary user-space sender with a nonzero audit-trailer PID, libxpc destroys the received message before assembling a reply. The provider's XPC request adapter is outside this path. A native delivery of the legacy request and the sender's resulting wakeup or return status remain unknown. [Read-only audit](triage_evidence/audit_adid_legacy_mach_receive.py) [Original-byte receipt](triage_evidence/adid_legacy_mach_receive_audit.json.zst)

```text
fairplayd                 launchd                       adid / libxpc
    |-- lookup 5/207 ------->|<------ check-in 3/805 ---------|
    |<-- service send right-|------- service receive right ->|
    |                                                        |
    |-- Mach 1200 + OOL + send-once reply right ------------>|
    |                                  reason 2 -> pass2mig  |
    |                                   nonzero PID -> destroy
    |                              no application reply 1300 |
```

The diagram joins source-verified operations by the launchd name in the ordinary service namespace. Numeric Mach names are task-local. The cached client name can outlive a service generation, and the two operations have distinct request and reply objects. The static join identifies the expected route after successful acquisition, activation and delivery.

## Service rights and emission boundaries

| Operation | Source boundary | Right or state |
| --- | --- | --- |
| Refresh client's destination | `fairplayd` call `0x100e2320c`, `_bootstrap_look_up` at `0x184bc16b0` | A failed first legacy send with status `0x10000003` selects lookup of the name `com.apple.adid`. The output is the u32 cache cell at `0x1010ca318`. |
| Ask launchd for a send right | libxpc `0x184bb92f8` | Default lookup branch calls the shared XPC broker routine with interface 5 and routine 207. PID1 selects case `0x10002e27c`, reads `name` at `0x100038324`, calls the lookup worker at `0x1000383dc` and on the selected success branch puts its port object under `port` at `0x100038470`. |
| Publish client's send name | libxpc `0x184bb9338`, `0x184bb9358`, `0x184bb9368` | Extract the name from the reply's Mach-send object, request one additional send user reference in the client task, then write the u32 output. This is the path for the ordinary bootstrap configuration. A separate libxpc mode takes a legacy lookup transport. |
| Register the provider channel | `adid` `0x10001a7b4`, libxpc `0x184bce294` | The provider supplies listener flag 1. libxpc sets bit 3 of connection+0x108 B and passes the connection and signed callback `0x184bbdfa0` to `dispatch_mach_create_4libxpc`. It saves the channel at connection+0xa8 B. |
| Ask launchd for the receive right | `adid` activation `0x10001a980`, libxpc `0x184bbc724` | The listener branch calls XPC interface 3, routine 805. The request carries `name`, `type=6`, `handle=0` and `flags`. PID1 selects case `0x10002e030`, reads `name` at `0x100032738`, calls the endpoint activation worker at `0x100032794` and publishes the receive name under `port` via `xpc_dictionary_set_mach_recv` at `0x1000327cc`. |
| Adopt the receive right | libxpc `0x184bbc810` through `0x184bba53c` | The reply extraction callback atomically takes the receive name from the XPC object at `0x184bc2d00`. The listener stores it at connection+0x44 B, sets receive attributes and guards it. It inserts a local send right from that name at `0x184bbca78` and stores the send name at +0x4c B. The ordinary completion path passes the saved channel, receive name and send name to `dispatch_mach_connect`. |
| Emit and receive directly | `fairplayd` `0x100de9fac`, retry from `0x100e232dc` | The 56 B Mach request uses the cached service name as COPY_SEND and a distinct MIG local name as MAKE_SEND_ONCE. The wrapper waits for a reply on the latter. The request includes one type-1 OOL descriptor whose extent is 20 B in the retained client case. |

The two broker calls share libxpc's `__xpc_interface_routine` at `0x184bb66f0`. On the checked launchd side, successful handler outputs feed the broker reply at `0x1000467e4` through `_xpc_pipe_routine_reply`. Routine 805 is the activation path for this XPC listener. The older FairPlay receive-right check-in investigation established a separate public bootstrap path at interface 5, routine 206. [Broker dispatch and reply transport](live_fairplay_checkin_report.md) [Client fallback and sender ABI](daemon_adid_mach_fallback_report.md) [Provider listener and application adapter](live_fairplay_adid_ipc_report.md)

## Delivery and cleanup

| Condition or effect | Original site | Recovered contract |
| --- | --- | --- |
| Hand dispatch message to the registered callback | libdispatch `0x1855b1f14` through `0x1855b1f80`, authenticated call at `0x1855af5e4` | Loads the stored handler and context, authenticates the handler, and forwards the callback reason and Mach-message object. |
| Dispatch reason 2, message ID 1200 | libxpc `0x184bbe04c`, `0x184bbe2fc`, `0x184bbe4b4` | Retrieves the message via `dispatch_mach_msg_get_msg` and reads the ID at H+20 B. ID 1200 takes the default branch after the signed cutoff and three reserved-ID comparisons. It calls `_xpc_connection_pass2mig` before the listener/XPC decoding branches. |
| Audit-trailer gate | `0x184bc6940` through `0x184bc6954` | From header H, compute T = H + ((size + 3) & 0x1fffffffc). Read PID at T+40 B. The SDK places the audit token at T+20 B and cached `audit_token_to_pid` reads token+20 B. For a 56 B request, this reads H+96 B. |
| Nonzero PID | `0x184bc697c` | Tail-calls `mach_msg_destroy(H)` via authenticated veneer `0x18806d240`. There is no reply-envelope construction on this branch. |
| PID zero and ID 1200 | `0x184bc69cc` through `0x184bc6a4c` | Builds a 36 B stack-local MIG reply template with ID 1300 and the received reply name at H+8 B. The notification table excludes 1200. The code writes `MIG_BAD_ID` (-303) to the template, logs the invalid ID, destroys H and clears its per-thread context. The template is never passed to a transport. |
| Retire received reply right | libsystem_kernel `0x180549be4`, tail branch `0x180549e08` | `mach_msg_destroy` passes H+8 B and the decoded remote disposition to `mach_msg_destroy_port`. A valid received send-once name with disposition 18 reaches `mach_port_deallocate`. This operates on the provider's right, independently of the sender's receive name. |
| Retire received OOL storage | `0x180549c74` through `0x180549cd8` | The complex-message loop recognizes type 1. A nonzero descriptor deallocation byte and nonzero extent call `mach_vm_deallocate` with the receiver-local address and extent. The sender's outgoing deallocate field is a different field epoch. Native copyout flags, actual allocation lifetime and kernel return values for this message remain unknown. |

The source callback returns after the destruction path, with an optional XPC transaction-end call at `0x184bbe710`. The libxpc path emits no application reply 1300. Kernel-generated notification delivery on the sender's reply port, and the wrapper's resulting status and retirement behavior, require separate evidence.

For the PID-zero branch, the table is indexed only when unsigned addition of 9 to `(id - 73) mod 2^32` produces a carry. The nine admitted values are exactly 64 through 72. The recorded original table starts at `0x1e240c820` with a 40 B stride. The demultiplexer reads the following entries.

| Mach ID | Table target |
| --- | --- |
| 64, 66, 67, 68 | Empty |
| 65 | `0x184bf4848` port deleted |
| 69 | `0x184bc6a98` port destroyed |
| 70 | `0x184bc73f4` no senders |
| 71 | `0x184bc837c` send once |
| 72 | `0x184bf4888` dead name |

## Assumptions and verification

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The pinned provider, PID1 slice and dyld shared cache characterize this installed build. | Check PID1 CodeDirectory and slice offset against the on-disk image. Check cache UUID against the running reader, hash the provider slice and plist, and resolve each veneer through its actual slide chain. A distinct cache or service generation limits the join. |
| A2 | Successful lookup and activation refer to the same service namespace and endpoint generation. The named send/receive pairing depends on that premise. | Compare both broker name paths. A naturally occurring transaction with a stale send right, redirected lookup or a different receive object would falsify runtime pairing. |
| A3 | An ordinary delivered message reaches the registered reason-2 callback with a valid kernel audit trailer. | Recheck dispatch registration and invocation, then compare the SDK trailer layout and the cached PID accessor with the original gate. Native reason, PID and port names for 1200 remain unknown. |
| A4 | The received header and descriptor carry the kernel's copyout dispositions. Cleanup depends on those received fields. | Cross-check the original receive header fields with the destruction predicates. A zero descriptor extent or deallocate byte skips OOL deallocation. A kernel notification caused by right retirement is outside the application reply path. |

High impact for distinguishing the legacy Mach path from the normal XPC request/reply adapter and for explaining why a valid legacy reply cannot be attributed to this installed listener. Medium impact for separating launchd's send-right lookup, receive-right handoff and per-message reply-right disposal. A legacy receive on a different build, successful native delivery on this build and any transaction-linked FairPlayIOKit activity remain unknown. The earlier pinned RAX archive contains no message with ID 1200 or 1300. The original binaries, cache and SDK resolve this increment without an IDA lookup. [Trace and modeled sender boundary](daemon_adid_mach_fallback_report.md)

The audit uses the original Mach-O instructions, SDK layout assertions, slide-chain membership for 12 veneers and five nonempty notification slots, original image UUIDs, and carry checks at boundary and interior values. The carry argument covers the u32 domain without enumeration. File and symbol processing take O(B + F) time and space for inspected binary bytes B and indexed symbol/fixup data F. Table verification adds O(N) for N notification rows. QG1 is factual scope, QG2 the assumption register, QG3 named rights and emission/disposal locations, QG4 byte offsets and unsigned arithmetic, QG5 alternate broker and PID branches, QG6 original receipts and SDK assertions, and QG7 bounded impact. No native ADID message was sent by this audit.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_adid_legacy_mach_receive.py
```
