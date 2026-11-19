# FairPlay RPC 502 through the installed CoreFoundation receive path

On build `26C5035r`, the installed arm64e CoreFoundation code receives on a run-loop mode's Mach port set and routes an ordinary service message using the **destination receive name returned in the message header**. The named `fairplayd` registration supplies the expected service name and requests the RPC callback. CoreFoundation asks for a format-0 AV trailer and passes the buffer and its inline message size to the callback. The FairPlay MIG stub reads the audit token beyond that inline extent and the daemon emits its own RPC 602 reply. These are source-level joins. The live daemon's membership, dispatch, and request-reply pairing remain unknown.

| Original input | Identifier |
| --- | --- |
| Installed arm64e dyld cache | `8b1e17c6-72d6-3017-91a4-916022e3612e` |
| Installed CoreFoundation | `14db37b1-11f1-31ad-9c07-74bed59a8036` |
| Installed libsystem_kernel | `780a6c1f-be02-34cc-84dd-00e05f61c89b` |
| Reference fairplayd arm64e | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Previously matched installed fairplayd slice | `204741e9-b89f-32b4-9321-51f3975c7cac` |

The cache UUIDs come from original headers and load commands. The prior daemon slice audit matched the running process's code-directory hash and localized differences between the installed and reference slices to CMS signature bytes. The current capture reads the installed cache and rechecks the reference daemon's instructions, service-name decoding and original chained fixups. All PCs below are unslid. [Daemon slice and current RPC ABI](live_fairplay_rpc_abi_report.md)

## Service registration and receive facilities

| Edge | Current source evidence | Effect |
| --- | --- | --- |
| Check in the named service | Daemon `0x10044038c`, fixup `0x1010a17c8` | `bootstrap_check_in` supplies the receive name for the `com.apple.unfreed` record. After success the name is forwarded at `0x1003ad1c8`. |
| Wrap the name | Daemon `0x100001fdc` to CF `0x184772fc8` | The daemon requests callback `0x100425f78` and passes a zero 40 B context. CF's fresh-object path stores the name at object +0x14 and the callback at +0x30 at `0x184858328` and `0x18485832c`. |
| Attach a version-1 source | Daemon `0x10031733c`, `0x100315264`, `0x100315300` | The daemon requests a CFMachPort run-loop source, obtains the main loop and adds the source to the default mode. It stores the CF object at `0x1010c4cf0` in the normal registration sequence. |
| Establish source operations | CF `0x184773274` through `0x1847732a4` | The context supplies get-port `0x18482e904` and perform `0x1847ca030`. Get-port returns the 32-bit name at object +0x14. In the source these callbacks occupy +0xa0 and +0xa8, respectively. |
| Construct the mode's port set | CF `0x184877834` through `0x184877848` | `mach_port_allocate` receives right flavor 3, checks the result, then stores the resulting name at mode +0x88. The cache stub resolves to libsystem_kernel `0x18054aee0`. |
| Schedule the service | CF `0x184773bc8`, `0x184773be0`, `0x184773bf8` | For a nonzero get-port result, insert the name-to-source dictionary entry at mode +0x80, then call `mach_port_insert_member` with that name and the port set. The cache stub resolves to `0x18054af50`. The next instruction starts source-lock handling without testing the insertion return. |

A matching valid cached CFMachPort follows the retain-and-return path at `0x18485851c` through `0x184858560`, preserving the existing object's callback and context. The static route to `0x100425f78` therefore depends on the effective object state. A populated mode dictionary also leaves the actual kernel membership unresolved. The earlier native bootstrap audit supplied a send right in the inspection task and associated `com.apple.unfreed` with host slot 17. That capture gives no daemon-local receive name or native equality with the kernel slot object. [Daemon registration](daemon_registration_report.md) [Native bootstrap service audit](fairplay_live_service_rights_report.md)

```text
FairPlayIOKit -> kernel RPC 502 send -> slot 17 service (object equality unknown)
                                          |
com.apple.unfreed check-in -> service receive name -> CF mode port set
                                          |
                       returned local name -> source dictionary -> fairplayd
                                                                  |
kernel thread reply receive endpoint <- separate RPC 602 send <---+
```

## Receive, dispatch and reply

| Transition | Current site | Data carried |
| --- | --- | --- |
| Choose receive name | CF `0x18479d138`, `0x18479d2ec` | Load mode +0x88 and pass its port-set name to the receive helper. |
| Receive | CF `0x18479eaa4` | The authenticated cache stub at `0x188076b70` resolves to `_mach_msg` at libsystem_kernel `0x180548f94`. The helper starts with 3,072 B of capacity and zero send length. |
| Pass the returned service name | CF `0x18479eb54`, `0x18479eb7c` | On success write the 32-bit local name from message +0x0c to the helper's output. The ordinary service path uses that name to look up its source at `0x18479d6d4`. |
| Pass the message | CF `0x18479d6e4` through `0x18479d6f8` | Forward the receive buffer and inline size from buffer +4. The trailer remains in the same buffer. |
| Invoke the configured callback | CF `0x18479ed78`, `0x18479eed8`, `0x1847ca11c` or `0x1847ca14c` | Read the authenticated source perform field and invoke it. CFMachPort perform calls the callback in object +0x30 with the object, message pointer, inline size and context. |
| Enter RPC 502 application | Daemon `0x10000511c`, `0x1000051cc`, `0x1000051d0`, `0x1000051f8` | The resolved MIG route uses the trailer at message +0x50. The stub copies both 16 B halves of its audit token and passes a pointer to the 32 B copy in X6. X0 passes the 32-bit service receive name after loading message +0x0c. |
| Emit RPC 602 | Daemon `0x100035184` | The daemon's `_mach_msg` call sends the reply to the request's reply send-once name. CF perform returns NULL at `0x1847ca1b0`, causing the caller to skip its generic send at `0x18479d724`. |

The prior daemon routing evidence joins `0x100425f78` through `0x10006d214` and `0x100264b4c` to the demultiplexer at `0x100005274`, RPC 502 stub at `0x1000050c8` and application at `0x100422d48`. The service receive name, the mode's port-set name and the send-once name are distinct roles. Their native values remain unknown. [Daemon callback and MIG dispatch](daemon_receive_interface_report.md) [Kernel reply right lifecycle and emitters](live_fairplay_reply_rights_report.md)

## Trailer and buffer contract

The current helper composes `0x07000806` from `MACH_RCV_MSG`, `MACH_RCV_LARGE`, `MACH_RCV_VOUCHER`, format 0 and AV element selector 7. A timeout argument other than the helper's `0xffffffff` sentinel adds `MACH_RCV_TIMEOUT`, yielding `0x07000906`. The arm64e SDK declares the AV trailer as 68 B with the 32 B audit token at offset 20 B. Its header layout puts the inline size at offset 4 B and local name at offset 12 B. The compiled assertions pin these facts for the arm64e target without running the compiled code.

| Normal RPC 502 buffer region | Half-open offsets, B |
| --- | --- |
| Inline request | [0, 80) |
| Requested AV trailer | [80, 148) |
| Audit token within that trailer | [100, 132) |
| Spare initial capacity after the requested footprint | 3,072 B - 148 B = 2,924 B |

The receive helper's large-message branch adds 68 B and rounds up to a multiple of 4 B at `0x18479eb04` through `0x18479eb0c`. That branch is unnecessary for the normal footprint above. Actual trailer contents, voucher state and sender attribution remain unknown without a matching receive observation. [Earlier exact-byte receive and voucher evidence](cf_receive_voucher_report.md)

## Assumption register and impact

| Assumption | Dependent result | Falsification evidence |
| --- | --- | --- |
| A1. The live daemon resolves these imports to the pinned installed cache images. | Installed PCs describe the active implementation after sliding. | Compare the live image UUIDs and resolved import targets with the pinned cache and daemon slice. |
| A2. The active host-slot object is the service checked in by the named record, and the service is a member of the mode set. | The kernel send reaches this run-loop receive facility. | Correlate endpoint identity, membership and the returned local name in one task and service lifetime. |
| A3. The effective CF object is valid and carries the requested callback. | Version-1 source dispatch reaches the recovered MIG demultiplexer. | Compare the effective callback and context when the object is returned from the cache and again at dispatch. |
| A4. The nominal receive succeeds and the kernel delivers the requested format-0 AV trailer. | The calculated footprint and audit-token offsets describe that message instance. | Compare received inline size, trailer type and size, and the exact buffer instance at callback entry. |
| A5. The RPC completes through the daemon reply emitter and the kernel's pending wait. | RPC 602 closes the same native transaction. | Correlate both message IDs with the same reply endpoint and kernel wait episode in existing diagnostic data. |

**High impact.** A single receive observation can distinguish the identity of the task-local service member from the receiving port set, and can link the request to the kernel reply wait using the outgoing right.

**Medium impact.** The constructor can reuse an earlier callback and mode-dictionary publication precedes kernel membership. Both are useful control-flow distinctions when interpreting lifecycle logs. Actual reuse and membership failures are unknown.

## Reproduction

The audit reads local original files and retained receipts. It verifies cache symbol names and function starts, selected A64 words, eleven immediate call targets, three authenticated cache stubs, daemon fixup identities and all 256 inputs of each of six selector banks. Nine static assertions check the SDK interface. The original RPC and registration reports supply the earlier kernel and daemon joins. The audit reads evidence without sending messages, executing the target or changing the IDB.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_cf_receive.py \
  "$DAEMON_IMAGE"
```

For F decoded instructions, N cache nlist rows, C cache metadata rows, and D daemon bytes, collection uses O(F + N + C + D) time and space for the fixed twelve-symbol set and six banks. The retained instruction and branch bytes permit independent checks of the addresses and offset arithmetic. [Audit script](triage_evidence/audit_live_fairplay_cf_receive.py) [Compressed source receipt](triage_evidence/live_fairplay_cf_receive_audit.json.zst)
