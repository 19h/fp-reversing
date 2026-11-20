# fairplayd legacy Mach transport to com.apple.adid

The installed provider receive path is now resolved statically. A delivered 1200 reaches the libxpc notification demultiplexer, which destroys the ordinary user-space request without emitting 1300. Native pairing and the sender-visible outcome remain unknown. [ADID listener follow-up](adid_legacy_mach_receive_report.md)

The destination of the `fairplayd` Mach 1200/1300 wrapper is the cached `com.apple.adid` send name on the recovered XPC-error path. The daemon calls the wrapper at `0x100e23104` and emits through `mach_msg` at `0x100de9fac`. If the first attempt returns `MACH_SEND_INVALID_DEST`, the daemon calls `bootstrap_look_up("com.apple.adid")` at `0x100e2320c` and retries at `0x100e232dc` with the returned name. Both transports use the same source-produced 20 B buffer on this path. The installed provider declares that service and has a verified XPC listener. A native receiver for the legacy Mach envelope remains unknown. [Previous transport census](daemon_iokit_retirement_report.md) [Installed XPC pairing](live_fairplay_adid_ipc_report.md)

```text
original 20 B request buffer
  |
  +-> XPC dictionary data -> com.apple.adid -> generic XPC error
  |
  +-> cached name -> Mach 1200 at 0x100de9fac
        |
        +-> invalid destination -> bootstrap_look_up(com.apple.adid)
                                     |
                                     +-> same cache -> retry Mach 1200
                                                            |
                                                 local MIG reply name
                                                            |
                                      1300 -> OOL pointer and u32 extent
```

## Port origins and control flow

All addresses are unslid. Eight retained caller states reproduce the original request construction and the first XPC send at `0x100e21718`. Each replay supplies an opaque generic error, distinct from the interrupted singleton. Original code issues `xpc_release` for the queue, connection, dictionary and reply at `0x100e22df0`, `0x100e22e40`, `0x100e22f08` and `0x100e22fac`. The two private request allocations remain available at the first legacy send. The request buffer is the one previously written by the local serializer and supplied as the XPC `data` argument. Its 20 B include three BE32 words followed by the eight-byte caller value. [Pinned request provenance](daemon_adid_request_origin_report.md)

| Boundary | Original site | Port, data or state |
| --- | --- | --- |
| First destination read | `0x100e23080` | W0 = u32 at `0x1010ca318`. This cell is in the daemon's zero-fill `__DATA,__common` section. |
| First wrapper call | `0x100e23104` | W0 cached destination, X1 original data pointer, W2 byte count, X3 pointer output at parent SP+0x188 B, X4 count output at parent SP+0x19c B. Canonical slot `0x1010b1398` selects `0x100de9f08` with IA diversity `0x57e4`. |
| Acquire another destination | `0x100e2320c` | W0 is read from imported `_bootstrap_port` storage, X1 points to the original literal at `0x101033900`, X2 points to the same cache cell. Binding `0x1010b1678` is `bootstrap_look_up`. |
| Retry | Load at `0x100e23274`, call at `0x100e232dc` | Only lookup success takes the selected retry. W0 reloads that cell, and the data and both output addresses match the first attempt. |
| Per-attempt reply name | `0x100de9f54` | Calls `mig_get_reply_port` and stores the returned u32 name in the local header field at +12 B. |
| Message emission | `0x100de9fac` | Sends to the W0-derived name at header+8 B and receives on the separate MIG reply name. |

The first transport-status gate at `0x100e2313c` compares against `0x3c2e08d2` with the retained W20=`0xb9`. Its value is computed as `(s XOR 0xadef2fef) + ((s << 1) AND 0x5bde5fde) + 0x7e3ed827 + 0xb9` modulo 2^32. The mask equals the left shift of the XOR constant. The first two terms sum to `s + 0xadef2fef` modulo 2^32. Across all u32 status values, equality is equivalent to `s == 0x10000003`. Source replay selects `0x100e2315c` for that value and `0x100e23324` for the tested alternate. An independent bit-vector query finds no counterexample.

| Initial cache fixture | First transport status | Lookup / retry | Helper result in private replay |
| --- | --- | --- | --- |
| 0 | `0x10000003` | Lookup succeeds. Retry returns `0x10000004`. | `0xffff5028` at original caller. |
| Nonzero | `0x10000004` | No lookup or retry. | `0xffff5028` at original caller. |
| Nonzero | `0x10000003` | Lookup returns 5. No retry. | `0xffff5027` at original caller. |
| Nonzero | `0x10000003` | Lookup succeeds. Retry returns `0x10000003`. No additional lookup in the observed path. | `0xffff5027` at original caller. |
| 0 | `0x10000003` | Lookup succeeds. Retry returns a valid modeled complex 1300 reply. | W0=0 and both reply outputs written at the parent cut `0x100e23324`. |

All four failure profiles free the original buffer at `0x100e24fdc` and its 24 B record at `0x100e2507c`. The successful lookup writes directly over the previous cache value. No deallocation of the prior cached name appears in the selected path. Native ownership, port generation and races with another cache writer remain unknown. A separate branch at `0x100e294ac` selects the same wrapper with the recorded queue banks and dispatch table. Its preceding `bootstrap_look_up` candidate at `0x100e293f4` and the reaching cache state were outside the composed replay. [Slot and replay evidence](triage_evidence/daemon_adid_mach_fallback_audit.json.zst)

## The 1200/1300 envelope

| Field | Byte offset or register | Source value or role |
| --- | --- | --- |
| Request header dispositions | +0 B | `0x80001513`. Complex, remote COPY_SEND 19, local MAKE_SEND_ONCE 21. |
| Remote name and local reply name | +8 B and +12 B | Cache read and `mig_get_reply_port` return. |
| Voucher and message ID | +16 B and +20 B | Zero voucher in the weak voucher-hook-absent profile. Request ID 1200 from `0x101032d74`. |
| Descriptor count | +24 B | One. |
| OOL descriptor | +28 B | Eight-byte request pointer, flag word `0x01000100` at +36 B, u32 extent at +40 B. Flags specify deallocate=0, virtual copy=1 and descriptor type=1. |
| NDR and repeated extent | +44 B and +52 B | Eight bytes from imported `NDR_record` and another copy of the extent. Both extent fields are 20 B in the replay. |
| Transport sizes | W2 and W3 at `0x100de9fac` | Inline send 56 B, receive capacity 64 B. The original wrapper supplies the send size as an API argument. |
| Accepted complex reply | ID 1300, inline 56 B | Requires one type-1 descriptor, zero received remote name, and equal u32 OOL extents at +40 B and +52 B. The wrapper copies pointer and extent to the parent at `0x100dea0b4` and `0x100dea0b8`. |

On `0x10000003`, the wrapper requests `mig_put_reply_port` at `0x100de9fe0`. On `0x10000004`, it requests `mig_dealloc_reply_port` at `0x100dea044`. Both receive the local reply name, independently of the cached service name. All numeric names in the replay are fixture values. The current path also has a weak `voucher_mach_msg_set` call site at `0x100de9f84`. Its active behavior was outside the modeled case.

CoreFP independently uses a 56 B request 1200 to `com.apple.adid`, using the same outer OOL envelope with a different inner request and a different cache. The 64 B request 1200 to `com.apple.fpsd` has a distinct certificate payload and reply shape. The request ID alone cannot identify either destination. The active FairPlayIOKit connection uses a separate type-`0x27` IOKit ABI. [CoreFP client comparison](corefp_client_paths_report.md) [IOKit connection ABI](live_fairplay_connection_report.md)

## Provider and evidence boundaries

The installed `adid` arm64e slice matches SHA-256 `b9e0043fbbc4525ad1a78545155c6c096422688de2ce3a3fc0144ab6adab9895`. Its MachServices declaration is `com.apple.adid`. The audited imports include `xpc_connection_create_mach_service` and have no direct `mach_msg*`, `mig_*` or `bootstrap_*` binding. These observations identify the named XPC listener and bound the direct import census. A legacy receive path inside a dependency, another registration branch, or rejection by the listener remains possible. The pinned RAX archive contains zero guest messages 1200/1300. IDA MCP exposed only an unrelated database during this pass. No native ADID request was sent. [Provider listener and peer setup](adid_startup_report.md) [Provider request handling](adid_receiver_report.md)

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The pinned thin daemon, provider slice and launchd plist identify the reported code and service. | Rehash the images, compare the service literal with MachServices, and check original import stubs and authenticated words. |
| A2 | The retained clock-success, request and generic XPC error states enter the composed fallback. | Match all eight prior request instruction streams, vary private controller/stack inputs, and recover an ordinary continuous native predecessor before extending the claim. |
| A3 | Modeled returns represent the stated status, name and descriptor branches. | Vary cold/warm caches, lookup rejection, repeated invalid destination and valid complex reply. Inspect the actual selected names and copy operations in each replay. |
| A4 | The scope ends after OOL pointer/count writeback in the success case. | Follow its original caller into reply consumption and storage retirement, and correlate a native receive with the lookup name and reply right. |

The audit records 40 private cases, 82,664 original instruction visits, 64 Mach call boundaries, 32 lookup boundaries, six bank reductions over all 256 input bytes, and six authenticated fixup readbacks. High impact for joining the legacy emission to its service and for identifying the shared request buffer. Medium impact for separating reply-port reuse from destination refresh. The legacy provider reception and any downstream FairPlayIOKit transaction remain unknown. QG1 covers factual scope, QG2 the register, QG3 boundaries and control, QG4 sizes and modular arithmetic, QG5 competing routes and cutoffs, QG6 original bytes and retained evidence, and QG7 impact. Extraction and replay use O(B + F + T + V + 256K) time and space as an upper bound for input bytes B, fixups F, archive bytes T, visits V and K bank pairs. One bit-vector solver query is separate. [Audit script](triage_evidence/audit_daemon_adid_mach_fallback.py) [Compressed receipt](triage_evidence/daemon_adid_mach_fallback_audit.json.zst)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_daemon_adid_mach_fallback.py \
  "$ADID_BINARY" "$ADID_LAUNCHD_PLIST" "$ARCHIVED_TRACE"
```
