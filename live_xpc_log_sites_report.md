# Live XPC check-in and Mach no-senders notification

The installed `libxpc` maps the two logged offsets from the native `akd` to `adid` capture to different phases. Offset `0xb358` follows the activation log and precedes connection initialization. Offset `0x164c8` follows the log in the Mach no-senders handler, after the peer cancellation call reports success. The 141 attributed server invalidations therefore give native evidence of notification handling on `adid` peer connections. The exact kernel send site, task-local port names, and FairPlayIOKit RPC 502/602 delivery remain unknown. [Native event capture](fairplay_native_xpc_observation_report.md)

| Event | Logged image-relative PC | Unslid logging call | Installed function |
| --- | ---: | ---: | --- |
| Client activation | `0xb358` | `0x184bbc354` | `__xpc_connection_activate_if_needed` |
| Server peer activation | `0xb358` | `0x184bbc354` | `__xpc_connection_activate_if_needed` |
| Server peer invalidation | `0x164c8` | `0x184bc74c4` | `__Xmach_notify_no_senders` |

The arm64e cache UUID is `8b1e17c6-72d6-3017-91a4-916022e3612e`. The `libxpc.dylib` image has unslid base `0x184bb1000` and UUID `94e40b03-44c5-3636-aa1a-c64a5d6b6bbb`, which matches all three recorded event classes. Each event PC is the instruction after a BL to the same authenticated stub, whose installed chain resolves to `libsystem_trace.dylib` `__os_log_impl`. Both literal formats resolve at their respective log calls. [Cache audit receipt](triage_evidence/live_xpc_log_sites_audit.json.zst)

## Check-in and the two directions of the connection

```text
client activation log
  -> connection initialization -> check-in via service send right
      -> adid listener receives and checks the two port descriptors
          -> creates named peer -> event handler -> peer activation
              -> requests MACH_NOTIFY_NO_SENDERS for peer receive name
                  -> delivered ID 70 -> cancel peer -> invalidation log
```

This is the installed source path. The native records cover the activation and invalidation points. On the ordinary activation path, the common log at `0x184bbc354` precedes either call into `__xpc_connection_init` at `0x184bbc364` or `0x184bbc37c`. Thus a client activation log can precede the named connection setup and the check-in send. A 202 us median between recorded client and server activation includes work at both ends and has unknown transport-latency error. [Native timestamp pairing](fairplay_native_xpc_observation_report.md)

| Check-in field | Client-side source | Received peer side |
| --- | --- | --- |
| Header destination at +8 | Object +0x48, disposition 19 (`COPY_SEND`), complex bit set. Header store at `0x184bba5a0`. | The listener receives the check-in on its service endpoint. The received namespace name is unknown. |
| First port descriptor at +28 | Object +0x4c, disposition 16 (`MOVE_RECEIVE`). Name and disposition stores at `0x184bba5d8` and `0x184bba5e4`. | Requires received type 16 and port descriptor type 0. The name becomes peer +0x44 at `0x184bbe5a8`. |
| Second port descriptor at +40 | Object +0x44, disposition 20 (`MAKE_SEND`). Name and disposition stores at `0x184bba5d0` and `0x184bba5c4`. | Requires received type 17 and port descriptor type 0. The name becomes peer +0x4c at `0x184bbe5b0`. |
| Message ID and extent | The producer writes ID `0x77303074` when object +0x90 is NULL and `0x77494e74` otherwise. Both have a 52 B fixed prefix. The latter accepts an extension in the receiver. | The event handler recognizes both IDs at `0x184bbe36c` and `0x184bbe37c`. The former requires exactly 52 B, and the latter requires at least 52 B. The per-event native variant is unknown. |

The check-in producer at `0x184bba4e0` hands the prepared message to `_dispatch_mach_connect` at `0x184bba668` or `_dispatch_mach_reconnect` at `0x184bba6b0`. Its direct `_mach_msg` branch at `0x184bba68c` passes a 52 B send extent. These are static emission boundaries. The telemetry does not choose among them. The receiver at `0x184bbdfa0` calls the peer requirement, check-in evaluation, and service validation helpers before creating the peer at `0x184bbe598`. The constructor and consumer addresses refer to this installed `libxpc` image.

The receiver forms the peer name with `%s.peer[%d]`, taking the PID from offset +0x28 of the Mach trailer after rounding `msgh_size` up to a 4 B boundary. The peer constructor appends `.%p` with its own object address. The receive path also stores the accompanying credentials at peer +0x68 via `0x184bbe608`, invokes the listener event handler at `0x184bbe874`, and can resume that peer via `0x184bbe8d0`. The PID argument therefore has a concrete trailer source on this path. An independent installed `_audit_token_to_pid` reads token +0x14, which agrees with trailer +0x28 given the SDK token offset of +0x14. The log's hex suffix belongs to a user-space object.

## Notification registration and receive

| Boundary | Site | Established contract |
| --- | ---: | --- |
| Register on the peer | `0x184bbc940` | `mach_port_request_notification` examines peer +0x44, requests ID 70 with sync 0, and uses the same receive name as destination with `MAKE_SEND_ONCE` (21) when nonzero. The separate client check-in request at `0x184bba638` uses ID 69. |
| Enter MIG dispatch | `0x184bbe4b4` | For receive reason 2, the event handler passes the received ID 70 message to `__xpc_connection_pass2mig`. The helper requires the audit PID word at aligned trailer +0x28 to be zero and sets the thread context at `0x184bc6994`. |
| Dispatch ID 70 | `0x184bc69fc` | Table address `0x1e240c818 + 40 × id - 0x9f8` gives slot `0x1e240c910` for ID 70. The installed authenticated pointer resolves to `__Xmach_notify_no_senders` at `0x184bc73f4`. |
| Receive and cancel | `0x184bc7444` | Generated handler requires a simple 36 B record. It retrieves the connection from the current thread context and calls the peer cancellation helper. The log is conditional on the helper's nonzero result. |
| Invalidate | `0x184bc74c4` | Log includes the connection object's stored peer PID at +0x7c, along with its object address. The library cancellation path calls `_dispatch_mach_cancel` at `0x184bd8e50`. |

The registration destination is a peer receive name for the XPC transport. The earlier kernel audit independently establishes the source shape of a 44 B kernel-form ID 70 notification with a send-once destination. The installed 36 B consumer uses the user-form header. Those producer and consumer shapes agree after the header size difference of 8 B. The evidence identifies a native consumer and the message class. The exact kernel emitter for each log record and the initiating client-side event remain unknown. [Earlier kernel notification producer](kernel_send_right_lifecycle_report.md) [Kernel send preparation](kernel_notification_send_report.md)

## Assumptions and verification

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | Logged sender offsets refer to the installed image of matching UUID. This supports both PC assignments. | Require UUID equality, original function boundaries, the exact BL immediately before each logged PC, and the original literal arguments. |
| A2 | The peer label describes the checked receive path. This supports the trailer PID and object suffix provenance. | Scan all 288,084 B of installed `libxpc` `__text` for adjacent ADRP+ADD references. The two naming literals each have one such reference. Computed references and native per-record instruction history remain outside this scan. |
| A3 | The observed invalidation text comes from the mapped no-senders handler. This supports the native receive milestone. | Require unique adjacent references to the original logging literals, check the installed ID 70 dispatch pointer, and validate notification ID, record layout and port dispositions against the arm64e SDK. |
| A4 | The earlier kernel model and current libxpc consumer share ordinary notification semantics. This supports the 44 B to 36 B layout comparison. | Match the IDs, trailer requirements and header extents independently. A correlated native kernel send would test the runtime producer assignment. |

The audit uses original cache bytes, the prior log receipt, and compile-time SDK assertions. For B text bytes and M parsed cache metadata bytes, the literal scan takes O(B) time after reading O(M) metadata. Its working space is O(B + M). It prints path-scrubbed evidence without observing new live traffic. [Audit script](triage_evidence/audit_live_xpc_log_sites.py) [Compressed evidence](triage_evidence/live_xpc_log_sites_audit.json.zst)

High impact attaches to the native notification receive milestone and its separation from application delivery. The registration and check-in path have medium impact because they identify which Mach rights create that milestone. A further native observation of FairPlayIOKit's slot-17 request, the `fairplayd` MIG entry, and the reply to the waiting kernel client is still required for the RPC 502/602 join. [Separate FairPlay RPC contract](live_fairplay_rpc_abi_report.md)
