# Archived FairPlayIOKit open and port retirement

After the FairPlayIOKit open returned a null connection and application result `0xe00002c2`, the guest released the service name `0x1903` and then the iterator name `0x1803`. Each release was immediately followed in the log by a 36 B host Mach message with ID 65, `MACH_NOTIFY_PORT_DELETED`, on host receive name `0x1c03`. The archived log records the receive name and the event order. The retiring host names in the two message bodies and the receive name's bridge registration remain unknown. [Archived trace report](zut_trace_report.md) [Apple notification ABI](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/notify.h#L76-L105) [Audit receipt](triage_evidence/archived_iokit_open_retirement_audit.json.zst)

## Observed namespace and message flow

Six guest message headers and their descriptors were decoded from the trace's hex bytes. The bridge send and receive records give the host names at the bridge boundary. Names are local to their respective IPC spaces.

| Role | Guest name | Host name | Capture evidence |
| --- | --- | --- | --- |
| IOKit main destination | `0x1703` | `0xf03` | Class matching request 2881 at lines 1699–1707 contains `IOProviderClass` and `com_apple_driver_FairPlayIOKit`. |
| Iterator send right | `0x1803` | `0x1103` | Reply 2981 supplies the guest descriptor at lines 1709–1713. The bridge sends iterator-next request 2802 to the paired host name at lines 1715–1718. |
| Service send right | `0x1903` | `0x1503` | Reply 2902 supplies the guest descriptor at lines 1720–1724. The bridge sends open request 2862 to the paired host name at lines 1726–1734. |
| RPC reply receive right | `0x507` | `0x1603` | All three requests use a send-once reply. Replies 2981, 2902 and 2962 arrive on the same host and guest reply names. |
| Task argument | `0x203` | Unknown in this exchange | The first descriptor of request 2862 carries the guest task with `COPY_SEND`. The host send log omits descriptor contents. |
| Connection output | Null | Unknown in this exchange | Reply 2962 has a 52 B body and declares one descriptor. The guest descriptor name at +28 B is zero. |
| Notification receive name | No guest delivery recorded | `0x1c03` | Lines 1744 and 1746 each record ID 65, 36 B, zero descriptors. |

Request 2862 has an 80 B body. The destination uses `COPY_SEND` and the reply uses `MAKE_SEND_ONCE`. The OOL properties descriptor has zero address and extent and the connection type at +64 B is zero. The guest's reply contains the application result at +48 B. The Mach transport returns zero at line 1742 with trap PC `0x180547c20`. The guest and bridge observations establish the shape of the failed open. The historical provider return site remains unknown. [Current open path and two status channels](live_fairplay_iokit_open_report.md) [Candidate owning-task translation](archived_iokit_task_translation_report.md)

```text
1742  guest Mach trap returns success after complex reply 2962
1743  guest deallocate(task 0x203, service  0x1903) -> 0
1744  host bridge receives ID 65 on 0x1c03
1745  guest deallocate(task 0x203, iterator 0x1803) -> 0
1746  host bridge receives ID 65 on 0x1c03
1747  guest exit(0)
1748  emulator reports status 0
```

Both deallocation traps report PC `0x180547ad0` on guest thread `0x2de300001`. The full 1,748-line capture has exactly these two host ID 65 records, zero guest receive records with ID 65, and zero request 2865 sends among 22 printed guest sends. The sequence precedes the recorded exit. The trace provides no historical event timestamps for measuring the release-to-receive intervals. [Audit receipt](triage_evidence/archived_iokit_open_retirement_audit.json.zst)

## Candidate host emission and receive locations

| Boundary | Location | Source-established behavior |
| --- | --- | --- |
| Host send right imported into guest | RAX `bridge/translate.rs:628–689`, `bridge/mod.rs:240–254` | The generic host send-right branch obtains a guest proxy. A new proxy owns a host reference and the bridge caches a weak reference to the guest port. A null host name yields no guest right. |
| Outbound notification registration | RAX `bridge/mod.rs:226–251`, `bridge/host.rs:307–327` | Allocates a host control receive right in the bridge port set and records `Import::Control`. A new proxy requests `DEAD_NAME` (72), sync 1, for the imported host name. The notification destination uses `MAKE_SEND_ONCE` from that control receive right. The proxy creation path does not inspect the registration result. |
| Guest-to-host reference release | RAX `syscall/mach/port.rs:146–174`, `mach/ipc.rs:790–814`, `bridge/mod.rs:83–103`, `bridge/host.rs:274–278` | Guest deallocation subtracts one reference. At zero, a send-only guest entry is removed and its send right is released. When the final strong reference to a valid same-epoch host right drops, its destructor invokes host `mach_port_deallocate`. |
| Host notification emission | XNU `osfmk/ipc/ipc_right.c:1075–1125`, `osfmk/ipc/ipc_notify.c:115–123` | On the selected active send-entry path, the final user reference cancels the pending name request. With a retained notification destination, `ipc_right_dealloc` calls `ipc_notify_port_deleted(request, name)`. The emitter targets the request's send-once destination and puts the retiring **host-space** name in the payload. |
| Host receive and disposition | RAX `bridge/translate.rs:550–599` | The bridge logs the header's local name at +12 B and ID at +20 B before its import lookup. The control branch handles ID 72 and leaves ID 65 without a guest enqueue. The ordinary port-import branch translates and enqueues. |

The XNU wire structure is 24 B of header + 8 B of NDR + 4 B of retiring name = 36 B. The name is at +32 B. ID 65 denotes deletion of a name in the requesting space. ID 72 denotes the requested name becoming dead and ID 70 denotes a receive-side no-senders event. The current collected kernel's ordinary ID 65 emitter writes the name at expanded +40 B at `0xfffffe000bd10ebc`, installs the request destination at `0xfffffe000bd10ecc`, and submits at `0xfffffe000bd10ef4`. Those unslid addresses describe the current collection. [Apple notification ABI](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/notify.h#L76-L105) [Apple final-send deallocation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_right.c#L1075-L1125) [Apple message emitter](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_notify.c#L115-L123) [Collected kernel emitter](live_iokit_task_owner_teardown_report.md)

The candidate bridge can account for all four tail records if its final host user reference to `0x1503` and then to `0x1103` drops with the requests still armed and their shared control receive name is `0x1c03`. The corresponding bodies would contain `0x1503` and `0x1103` at +32 B. The host log is emitted before the import-map lookup and omits the body, so the two payload values and control classification are conditional. The immediate evidence concerns discovery-object name retirement. The reply contains a null connection and supplies no successful user-client lifecycle for comparison. [RAX registration and ownership](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/mod.rs#L220-L254) [RAX receive dispatch](https://github.com/19h/rax/blob/4748a6ae8bd285369fe1413787b35587832f4dd3/src/user/darwin/bridge/translate.rs#L550-L599)

## Daemon image and release attribution

The archived thin arm64e image is byte-identical to the 17,668,912 B slice at universal-container offset 3,407,872 B. Its UUID is `204741e9-b89f-32b4-9321-51f3975c7cac` and its SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The static open is at unslid daemon PC `0x100176a0c`. Its failure path can reach `0x1002c99a0`, then the service and iterator release calls at `0x1001dcab8` and `0x100205980`. Both release calls bind `IOKit/_IOObjectRelease` through the original IA-authenticated import slot `0x1010a0240`. Constructor rejection can also reach the same release sequence. The capture gives trap PCs without the daemon return address, so static call-site attribution and the branch taken at runtime remain unknown. [Static open handoff](daemon_selector26_open_report.md) [Static release proof](daemon_selector26_class_retry_report.md) [Image receipt](triage_evidence/archived_iokit_open_retirement_audit.json.zst)

## Assumptions and evidence gaps

| ID | Dependent inference | Falsification probe | Impact |
| --- | --- | --- | --- |
| A1 | The historical capture producer and host IPC implementation match the candidate paths above. | Compare producer image identity to the pinned source and identify the historical kernel build. | High for source-to-runtime attribution. |
| A2 | At the two releases, each host entry has one remaining user reference and an armed request, and `0x1c03` is the bridge control receive name. | Capture host registration, deallocation result, receive-map hit and the ID 65 payload at +32 B in the same ordinary run. | High for identifying the exact host emitters and payloads. |
| A3 | The archived daemon followed the candidate open and its release continuation. | Record the caller PC or return address at `IOServiceOpen` and both `IOObjectRelease` calls, plus the original open status. | Medium for connecting the observed traps to specific obfuscated blocks. |

The audit pins the trace, the two daemon containers and the immutable RAX revision. It reuses the repository's Mach-O and descriptor decoders, verifies six message headers, checks eight bridge records and rechecks five source files at 23 line anchors. Guest packet bytes and host log records are retained separately in the receipt. The verifier uses O(N) time and O(N) space for N total input bytes. Historical notification payloads, the import map, and the native open failure gate remain unknown. [Audit generator](triage_evidence/audit_archived_iokit_open_retirement.py) [Compressed receipt](triage_evidence/archived_iokit_open_retirement_audit.json.zst)
