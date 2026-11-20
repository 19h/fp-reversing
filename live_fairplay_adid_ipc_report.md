# Direct FairPlay daemon to CoreADI IPC

The ordinary synchronous transport is traced through the client special reply port, the provider dictionary context, and the Mach emission and receive boundaries. [Ordinary ADID synchronous Mach transport](live_adid_xpc_sync_transport_report.md)

The arm64e code selected by the running `fairplayd` process creates an XPC client for `com.apple.adid` and contains a synchronous request/reply path on that connection. The request and reply each use an XPC dictionary field named `data`. The installed `adid` listener and peer adapter have matching service and field names. A separate notification path runs in the opposite direction. Process identities were observed on macOS build `26C5035r`. The paths and the correspondence between endpoints are established statically. A native exchange and its Mach port names remain unknown. [Live slice identification method](fairplay_live_slice_identity_report.md)

```text
fairplayd -- XPC request "data" --> com.apple.adid listener / peer
fairplayd <- XPC reply   "data" --- adid request/reply adapter

fairplayd <- notifyd counters <---- adid notify_post(name)

fairplayd ---- IOUserClient ------> FairPlayIOKit
adid --------- IOUserClient ------> FairPlayIOKit
```

The two IOKit edges are independently observed registry connections. The downstream relation between a particular XPC request and either IOKit connection remains unknown. The kernel-to-daemon RPC 502/602 has its own request and reply endpoints. [IOKit registry and process identity](fairplay_live_slice_identity_report.md) [Kernel/daemon RPC ABI](live_fairplay_rpc_abi_report.md)

## Client path and request provenance

The known obfuscated helper at `0x100e1e5ec` stores the address of the service name at frame `SP+0x10` and the selected dispatch table at `SP+0x148`. The name comes from slot `0x1010b1800` and is the NUL-terminated literal at `0x101033900`. Its dispatch table starts at `0x1010abb60`. The helper also implements the four-output environment/cache and notification checks from the earlier reports. The origin of the record entering the XPC branch at `0x100e21294` and continuous reachability from the helper root are unknown. [Earlier helper control flow](daemon_environment_outputs_report.md) [Notification registration](daemon_notification_registration_report.md)

| Operation | fairplayd PC | Established inputs or outputs |
| --- | --- | --- |
| Allocate request dictionary | `0x100e21370` | `xpc_dictionary_create_empty`. Result remains in X0 for the field setter and is saved to `SP+0xe8` at `0x100e2143c`. |
| Put request bytes | `0x100e21448` | `xpc_dictionary_set_data`. X1 points to `data` at `0x101032f80`. X2 is the pointer loaded at `0x100e21390`. W3 is a decoded 32-bit extent, zero-extended in X3. |
| Create dispatch queue | `0x100e214ac` | Label `com.apple.adid`, attribute NULL. NULL return selects `0x100e22fc0`. |
| Create client connection | `0x100e21578` | X0 is `com.apple.adid`, X1 is the new queue, X2=0. NULL return selects `0x100e22fc0`. |
| Set event handler | `0x100e21678` | Same connection and global block `0x1010abb40`. Its invoke entry is `0x100dfde94`. |
| Activate connection | `0x100e216c8` | Same object held in X25. |
| Send request and wait for reply | `0x100e21718` | Same connection in X0, saved dictionary in X1. Return is preserved in X25. |
| Retry once on interruption | `0x100e218dc` | Reloads the exact connection and dictionary from `SP+0x98` and `SP+0xe8`. Return is again preserved in X25. |
| Read reply bytes | `0x100e21a08` | `xpc_dictionary_get_data` receives the reply object, the same `data` key and the `size_t *` at `SP+0x1b0`. The borrowed pointer is stored at `SP+0x318`. |

In the ordinary-record branch at `0x100e21294` with entry W8=0, X21 loaded from `SP+0x1c0` determines both input memory addresses. The additions use the two raw 64-bit constants `0x822a30ef8f61a867` and `0x822a30ef8f61a873`. The loads retrieve an 8 B pointer and a 4 B encoded length 12 B apart. `0x100e213b8` adds `0x9aa4ac59` to the length word modulo 2^32 under that entry state. This is an encoding relation for the XPC setter arguments. Record allocation, the legal extent range, the inner request schema and the consumer after the reply read remain unknown.

Both sends select import slot `0x1010b1568` and use IA discriminator `0x57e4`. After the first send, `0x100e21770` obtains the reply type. A non-error type continues at `0x100e21980`; the error type reaches the singleton check at `0x100e21830`. Equality with `_xpc_error_connection_interrupted` selects the second send. A different error goes to `0x100e22d44`. After the retry, the error type goes to `0x100e22d14`; the non-error path rejoins at `0x100e21988`. Both successful type cuts pass the preserved X25 to the getter. These comparisons establish the selected error branches and objects. The source type comparison admits the non-error branch without an explicit dictionary identity comparison in the inspected cut.

## Server and emission boundaries

| Interface boundary | Image and PC | Port or object role |
| --- | --- | --- |
| Bind the named service | adid `0x10001a7b4`, activate `0x10001a980` | Listener flag 1 for launchd service `com.apple.adid`. Accepted peers receive distinct connection objects. |
| Send request and await reply | fairplayd `0x100e21718`, retry `0x100e218dc` | Destination is the named-service connection. Both calls delegate the actual Mach header and reply receive ownership to libxpc. |
| Receive via peer callback | adid `0x100029fc8`, adapter `0x1000aa0ec` | Per-peer callback installed at `0x100000d00`. The adapter calls reply creation at `0x1000aa3f0`. |
| Read request bytes and caller metadata | adid `0x1000aa598`, audit token at `0x1000aa4c0` | `data` with pointer/size output, and a 32 B audit token consumed by the adapter. Effective policy and authorization for this caller remain unknown. |
| Emit XPC reply | adid `0x1000aa9fc` then `0x1000aaa70` | Sets reply `data`, then calls `xpc_dictionary_send_reply` using the request-derived reply object. |
| Publish invalidation | adid `0x100219198` | `notify_post(name)` uses the libnotify route to the broker. |

Installed images establish the ordinary request and reply dispositions, the libdispatch Mach emission sites and the current kernel reply binding. Native task-local names, kernel object identity and delivery remain unknown. The archived replies with the ordinary reply ID pair with bootstrap requests. [Ordinary ADID synchronous Mach transport](live_adid_xpc_sync_transport_report.md) [Kernel special reply path](live_adid_xpc_special_reply_kernel_report.md)

## Notification path

The provider post fragment, four selector pairs, eight chained words and three names were independently matched in the current `adid` slice. A selected name is passed to `notify_post` at `0x100219198`. The earlier daemon registration report established all three subscriber names in the pinned `fairplayd` text and pointed out the provider's differing whole-slice hash. The current byte-level comparison resolves the build question for this specific provider path. [Provider selector and predecessor conditions](adid_notification_report.md) [Daemon token registration](daemon_notification_registration_report.md)

| Name | adid string | fairplayd registration PC | fairplayd token |
| --- | --- | --- | --- |
| `com.apple.adid.midchangedV1` | `0x1002941f0` | `0x100e1fe88` | `0x1010ca2c0` |
| `com.apple.adid.midchangedV1.5` | `0x1002a16b0` | `0x100e1ff5c` | `0x1010ca31c` |
| `com.apple.adid.midchangedV3` | `0x1002ad240` | `0x100e20054` | `0x1010ca324` |

The reference libnotify implementation looks up the Mach service `com.apple.system.notification_center`. Its check registration can return a broker-maintained counter slot. Polling a successfully mapped slot reads the counter without emitting a Mach message. The broker port and the direct XPC service port are independently named endpoints. [Notification transport and shared counters](notify_ipc_report.md)

## Assumption register and validation

| ID | Premise and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | Current process identity selects the checked application slices. | Compare process CodeDirectory hash and file offset independently, bracket them with repeated reads, and recheck the registry. The pinned `fairplayd` comparison has 262 differing bytes confined to the CMS signature. |
| A2 | Frame slots at the XPC cut retain the root's service, table and bank values. The branch analysis begins at `0x100e21294` with W8=0 and a non-sentinel record. | Check root stores and XPC-cut reads against original instructions. Vary the selector byte over all 256 values per reduction. An intervening writer to a used slot or a predecessor with another W8 value would invalidate the stated composition. |
| A3 | API callees return normally and preserve AArch64 callee-saved registers. | Check object register and frame handoffs. Evaluate both results at each of the five post-call gates, including NULL, error type and interrupted-singleton comparisons. |
| A4 | Retained provider branch roles apply where the current arm64e slice reproduces their bytes and bindings. | Compare the listener, peer setup, callback, adapter and notification fragment byte-for-byte with the retained evidence. Check current dyld fixups for the named API calls and reproduce each notification selector pair. |
| A5 | The two named endpoints are statically compatible. | Check both `data` literals, the client/listener flag pair, and the request-derived reply path. A naturally occurring exchange with matched Mach message and port provenance would test native pairing, authorization and ownership. |

On the provider, 6,224 B match across five original code windows, including the 492 B notification fragment. The audit checks 17 daemon selector expressions and four provider expressions, or 5,376 one-byte evaluations, and verifies 11 daemon authenticated branch outcomes, including the assumed entry branch. It uses Capstone instruction checks, Apple `dyld_info`, prior original-byte evidence, and read-only live identity queries. File parsing and fixup indexing use O(B+F) time and space for B input bytes and F fixup rows. K selector reductions use O(256K) time and O(256) scratch space. Addresses are unslid preferred virtual addresses. Where static and live results meet, A1-A5 mark the relevant limits. [Audit script](triage_evidence/audit_live_fairplay_adid_ipc.py) [Compressed audit receipt](triage_evidence/live_fairplay_adid_ipc_audit.json.zst)

## Remaining joins

| Impact | Missing evidence |
| --- | --- |
| High | Trace the record producers for `SP+0x1c0` and the decoded request. This would identify which helper inputs reach `adid` and whether they originate in a FairPlayIOKit RPC. |
| High | Correlate a naturally occurring XPC exchange with its named service, reply context and task-local Mach rights. A matching peer audit token and payload extent would test the cross-process relation. |
| Medium | Recover the client event handler and the consumer of `SP+0x318` and `SP+0x1b0` to establish lifetime, error handling and return-output ownership. |
| Low | Assign the adjacent `vmtohostmsg` literal only after establishing its own load and consumer. |
