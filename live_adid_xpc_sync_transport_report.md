# Synchronous fairplayd and adid XPC Mach transport

The installed arm64e transport sends the ordinary `fairplayd` request to the established `adid` peer and supplies a send-once reply right derived from the calling thread's special reply receive port. The provider moves the incoming right through the request dictionary into its reply. Both send paths converge on libdispatch's Mach send at `0x1855b487c` and libsystem_kernel's trap -47. The client waits in a separate receive operation at `0x1855b0d50`. The addresses are unslid for macOS build `26C5035r`. This is a static join of original instructions and authenticated bindings. Native delivery, numeric names and the causal link to a particular FairPlayIOKit operation remain unknown. [Application endpoint bindings](live_fairplay_adid_ipc_report.md) [Peer establishment](live_xpc_log_sites_report.md)

```text
fairplayd thread                            adid peer
  COPY_SEND destination -----------------> channel receive port
  MAKE_SEND_ONCE from thread reply port --> request dictionary
                                                      |
                                             create_reply moves right
                                                      |
  thread reply receive port <-------------- MOVE_SEND_ONCE destination
  decode reply and return
```

## Port and emission map

| Stage | Original sites | Port role or control |
| --- | --- | --- |
| Client request | fairplayd `0x100e21718`, retry `0x100e218dc`, libxpc `0x184bbd4dc` | The same connection and `data` dictionary enter `xpc_connection_send_message_with_reply_sync`. The first pack writes zero into both names at `0x184bbd838`. This branch selects remote disposition 19 at `0x184bbd824`. |
| Client header finalization | libxpc `0x184bbd4fc`, `0x184bbd50c`, `0x184bbd528` | Local disposition 21 is added. The serializer initializes ID `0x10000000` at `0x184bb7124`. Connection +0xd0 equal to zero selects `0x40000000` at `0x184bbd50c`, and a global byte equal to 1 restores `0x10000000`. Both IDs reach the same ordinary peer receive branch. Actual variant is unknown. |
| Client reply receive name | libxpc `0x184bbd590` via authenticated veneer to `0x1855b10b8`. libdispatch `0x1855b0be4` through `0x1855b0c14` | With a zero packed local name, the waiter loads TLS +0x40. If empty it calls `thread_get_special_reply_port` at `0x1855b0bec` and stores the result in TLS. It writes the selected name into header +0xc at `0x1855b0c14`. The allocation entry uses trap -50 at `0x180548c40`. |
| Request destination | libdispatch `0x1855b45ec` and `0x1855b45f0` | For the ordinary non-check-in send, reads the channel's active send name from channel state +0x5c and writes it to header +8. Dispositions 19 and 21 occupy the low header lanes as `0x1513`. Voucher and complex flags occupy separate lanes. |
| Request emission | libdispatch `0x1855b487c`, libsystem_kernel `0x18055b960`, SVC `0x180548c1c` | The Mach2 call packs the two names in X3 and uses the send option. The kernel derives the send-once right for delivery from the request's local receive name. |
| Provider receive | libxpc `0x184bbe310` or `0x184bbe360`, `0x184bbe3fc`, `0x184bbe410` | Ordinary IDs select a non-listener connection whose status byte is zero. The unpacker checks peer requirements at `0x184bbde40`. On the successful decode branch `0x184bb816c` loads the received header's remote name and `0x184bb8170` clears it. The local name identifies the server receive endpoint. The remote name carries the reply right in the provider's namespace. |
| Application handoff | libxpc `0x184bb88e8` through `0x184bb8908`, adid `0x100029fc8` then `0x1000aa0ec` | Successful dictionary decoding moves the receive context to dictionary +0x58 and copies trailer audit data to +0x78. The installed peer block reaches the reply adapter. The adapter reads audit data and the `data` field. |
| Reply ownership transfer | adid `0x1000aa3f0`, libxpc `0x184bc689c` through `0x184bc68c0` | `xpc_dictionary_create_reply` copies the mode-1 request context from +0x58 into the mode-2 reply at +0x60, clears the original context, and retains the associated peer in reply +0x58. The peer pointer and the reply name have separate fields. |
| Provider reply | adid `0x1000aa9fc` and `0x1000aaa70`; libxpc `0x184bdbd58`, `0x184bb6d0c`, `0x184bb6d10`, `0x184bbd818` | After setting reply `data`, the ordinary `xpc_dictionary_send_reply` branch uses the associated peer. Packing takes and clears the context name, writes ID `0x20000000`, and selects MOVE_SEND_ONCE (18). The header has the extracted remote name and zero local name. |
| Reply emission | libxpc `0x184bbf218`, libdispatch `0x1855b0978` or queue drain at `0x1855b409c`, then `0x1855b487c` and trap -47 | Local disposition zero selects `dispatch_mach_send_with_result`. The destination type 18 selects the branch at `0x1855b4580`, which bypasses the channel send-name store and preserves the request-derived destination. |
| Client wait and decode | libdispatch `0x1855b0d50`, libsystem_kernel `0x180548fa8` and `0x180551a24`, libxpc `0x184bbd60c` and `0x184bbd6cc` | The wait calls `mach_msg` with send size zero and the same selected special reply name in X4. This reaches Mach2 with receive selected. The successful path checks the received local name for the internally selected-port case, clears it at `0x1855b0f8c`, wraps the result, and returns to the sync caller. Libxpc admits ID `0x20000000` and unpacks the returned object. |

Libdispatch clears the thread cache while the internally selected reply port is in use. The send worker can clear it during waiter setup at `0x1855b47e0`; the outer worker also clears a matching cached value at `0x1855b0c74`. On the ordinary matching receive path it can return the name to TLS at `0x1855b1044`. A later attempt can therefore use the same receive name with a new send-once right. The send and receive are separate Mach operations. The receive starts with options `0x0700000e`, optionally adds `0x4000` and `0x200`, and can grow its receive buffer on the reported too-large path. Actual scheduling, voucher choice and queue state are unknown.

The caller's reply port belongs to the thread's synchronous wait. The channel receive and send rights arise from the connection handshake. Libxpc passes connection +0x44 and +0x4c as W1 and W2 at `0x184bba668`. Libdispatch stores them in its receive reference at `0x1855afa84` and the channel send state at `0x1855afa88`. The accepted peer's receive name comes from the first handshake descriptor at `0x184bbe5a8`. The standalone legacy path has its own message ID 1200, service lookup and MIG reply-port acquisition. [Connection handshake](live_xpc_log_sites_report.md) [Legacy send](daemon_adid_mach_fallback_report.md) [Legacy receiver](adid_legacy_mach_receive_report.md)

## Archived trace

The five guest receives with ID `0x20000000` at lines 1516, 1557, 1591, 1625 and 1659 belong to the bootstrap service-name sequence. Their preceding requests at lines 1500, 1541, 1575, 1609 and 1643 use ID `0x400000ce`, bootstrap destination `0x707` and guest reply name `0xb03`. The decoded request payloads identify five named services and the decoded replies carry receive rights. The bridge reports host reply name `0xc03` for these transactions. Both names are scoped to their own IPC namespaces. The archive has zero guest sends of either ordinary request ID in the table. The shared reply ID alone cannot identify an ADID exchange. [Archived service-name control](zut_trace_report.md)

## Assumptions and falsification checks

| Assumption | Dependent result | Stress test |
| --- | --- | --- |
| A1. The two application slices and three cache images match the pinned originals. | All sites and cross-image bindings. | Require image hashes or UUIDs, recheck application fixups, and decode authenticated cache veneers and their chained pointers. |
| A2. The ordinary active-peer branch passes policy and decodes a dictionary. | Application callback and context transfer. | Check both admitted request variants, listener and cancellation gates, peer requirement result, decoder success, and request-to-reply context clears. A failed predicate invalidates the successful-path join for that event. |
| A3. The synchronous request enters with no caller-supplied local name. | TLS reply-port acquisition and separate wait. | Check the pack argument and initial header store, TLS hit and miss branches, receive arguments, and matching-name/cache restoration path. |
| A4. The archived message annotations identify the bootstrap sequence. | Five reply-ID controls. | Hash the archive, decode raw headers, and check matching guest names and bridge records. Native ADID transaction attribution would require endpoint-correlated evidence. |

High impact attaches to the special-reply right lineage and the two send sites' convergence. Medium impact attaches to reuse of the receive name across calls, and to the reply-ID false match in the archive. Native authorization, payload outcomes and linkage to FairPlayIOKit remain open.

The read-only audit records original instruction words, named cache targets, authenticated fixups and the archived control headers. It checks site evidence against the explicitly stated successful-path predicates. The archive scan takes O(n) time and O(n) space for n input bytes. QG1 and QG3 cover descriptive scope and both directions, QG2 and QG5 cover the branch predicates and alternatives above, QG4 covers byte offsets and disposition lanes, QG6 covers image and archive provenance, and QG7 covers the stated impact boundaries. [Audit source](triage_evidence/audit_live_adid_xpc_sync_transport.py) [Audit receipt](triage_evidence/live_adid_xpc_sync_transport_audit.json.zst)
