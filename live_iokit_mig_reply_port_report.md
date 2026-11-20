# IOKit MIG reply-port cache and archived guest names

The installed IOKit discovery and open stubs obtain their synchronous reply name from a thread-local MIG cache. The archived `fairplayd` run uses guest name `0x507` in 16 of 22 complete Mach exchanges, including all five from IOKit main-port acquisition through FairPlayIOKit open. A native verifier on build `26C5035r` observed two simultaneous threads with separate receive names, each stable across an ordinary `IOMainPort` call and replaced after explicit retirement.

## Installed reply-port lifecycle

The addresses below are unslid. The auditor checks cache UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`, libsystem_kernel UUID `780a6c1f-be02-34cc-84dd-00e05f61c89b` and IOKit UUID `82be1de5-91c4-3152-b63b-81db4c5e7992`. Apple's public XNU source identifies port construction flag `0x1000` as `MPO_REPLY_PORT` and provides source-level counterparts for the cache helpers. [XNU MIG reply-port helpers](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/mach/mig_reply_port.c#L39-L98) [XNU port options](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/port.h#L451-L481)

| Operation | Installed sites and data flow |
| --- | --- |
| Bootstrap sentinel | `_mach_init` calls its initializer at `0x18054ec20`. The initializer calls `mach_reply_port` at `0x18054ec54` and stores its returned name in process-global cell `0x1ed9028b4` at `0x18054ec5c`. |
| Cache hit | `_mig_get_reply_port` reads `TPIDRRO_EL0` at `0x180548f14`, loads the 32-bit name at thread base +16 B, and returns it when nonzero. |
| Cache miss | `0x180548f4c` calls `mach_port_construct` on the current task, with a 24 B options buffer containing `MPO_REPLY_PORT` and otherwise zero bytes, zero context, and a stack address for the output name. On success `0x180548f58` stores the zero-extended result in the thread slot. Failure goes to the trap at `0x180548f90`. |
| Put | `_mig_put_reply_port` at `0x18054e1d8` returns immediately. |
| Retire | `_mig_dealloc_reply_port` returns early for a zero or sentinel slot. Otherwise `0x18054bf8c` temporarily puts the sentinel in that slot and `0x18054bfa4` invokes `mach_port_mod_refs(task, cached_name, MACH_PORT_RIGHT_RECEIVE, -1)`. If the supplied name differs, `0x18054bfb8` also calls `mach_port_deallocate` on that name. `0x18054bfbc` then zeroes the slot. |

The discovery stubs and extended open call the reply-name getter before assembling the Mach header. In the open stub, `0x184ebdc20` gets the local name, `0x184ebdc30` stores the service and reply names together at message +8 B, and `0x184ebdc6c` emits 2862. Header bits `0x80001513` request COPY_SEND (19) for the service and MAKE_SEND_ONCE (21) for the reply. Each send uses the thread's receive right to make a send-once right for that exchange. The connection name returned in a successful open resides in the reply's descriptor. [IOKit discovery](live_iokit_discovery_report.md) [Open transport and copyout](live_iokit_open_reply_copyout_report.md) [Mach dispositions](triage_evidence/xnu_osfmk_mach_message.h)

The kernel-side follow-up resolves receive-right publication for the constructor and measures the cached queue's sequence number across a native FairPlayIOKit discovery. [Kernel reply queue](live_iokit_reply_queue_report.md)

In the open stub, selected send-side transport failures call `_mig_put_reply_port` at `0x184ebdca0`. Other nonzero transport returns call `_mig_dealloc_reply_port` at `0x184ebdcf0`. The archived open exchange completed its transport with status zero and decoded a null connection and provider result `0xe00002c2`. On the installed decoder the equivalent provider failure follows complex reply copyout, with the cached reply name eligible for later reuse. [Open transport and copyout](live_iokit_open_reply_copyout_report.md)

## Archived request and reply census

All 44 guest headers in `annotated-strace-rax-user.txt` belong to thread `0x2de300001`. The auditor checks their packed fields against the printed headers, confirms the send and receive names and dispositions, and checks the completed `mach_msg2_trap` argument words. Every completed pair uses the same local name on both sides, and every received header has remote name zero. The five bootstrap exchanges use reply ID 536870912. The remaining 17 replies use request ID + 100.

| Guest reply name | Complete pairs | Traffic |
| --- | ---: | --- |
| `0x603` | 1 | Startup host information, 200/300 |
| `0x507` | 16 | Clock, task and host operations, then all five IOKit pairs |
| `0xb03` | 5 | launchd bootstrap check-ins, 1073742030/536870912 |

| Operation | Request/reply | Guest request destination | Guest reply name | Host bridge reply name | Guest send/receive lines |
| --- | --- | --- | --- | --- | --- |
| Main-port acquisition | 205/305 | `0xc03` | `0x507` | Guest-emulated | 1677/1681 |
| IOKit version | 2877/2977 | `0x1703` | `0x507` | `0x1603` | 1687/1692 |
| Service matching | 2881/2981 | `0x1703` | `0x507` | `0x1603` | 1699/1709 |
| Iterator next | 2802/2902 | `0x1803` | `0x507` | `0x1603` | 1715/1720 |
| Extended open | 2862/2962 | `0x1903` | `0x507` | `0x1603` | 1726/1736 |

The trace prints `mach_reply_port()` returns of `0x303` and `0x403` at lines 2 and 1126. Successful construct calls at lines 1136 and 1150 precede the first visible use of `0x603` and `0x507` respectively. These lines show output addresses and success, leaving the values written to those addresses unknown. The current implementation and archived reuse support the MIG cache interpretation of `0x507`. Connecting that name to a specific historical constructor output would require the historical slot or output word. The bridge independently pairs `0x1603` with `0x507` at the four forwarded IOKit exchanges. [RAX bridge namespace audit](archived_iokit_reply_import_report.md)

## Native observations and limits

Two verifier threads each read the reply name four times, including after `mig_put_reply_port` and after `IOMainPort` plus release of the main send right. Both threads held their original names simultaneously while the verifier measured type `0x20000` and one receive user reference for each name. Each worker then retired its cached name, obtained a different replacement, and retired the replacement. All four lookups after explicit retirement returned `KERN_INVALID_NAME` (15) while the issuing threads were still running. The receipt records return statuses and equality relations since the native numeric names can vary by run. The experiment exercised the ordinary IOKit discovery entry point in the verifier process. Production `fairplayd` use, historic constructor output, and thread-exit cleanup remain unknown.

| Premise and dependent result | Falsification probe |
| --- | --- |
| The cache UUID and slide-chain entries identify the installed IOKit and MIG call targets. This qualifies the unslid PCs. | Replay the byte and chain checks against the mapped cache and compare the three UUIDs. |
| Alternating guest send and receive headers represent completed transactions for the captured thread. This qualifies the 22-pair census. | Compare each pair with its packed header, ordering and subsequent completed trap. Require matching receive selectors and reply IDs. |
| The historical `0x507` name came from the ordinary MIG reply cache. This qualifies the inference about its producer. | Capture the historical construct output and TLS +16 B at construction and the first IOKit request. A distinct allocator or cache value would falsify the attribution. |
| The exercised names coexist and are scoped to the worker threads. This qualifies the native lifetime observation. | Sample both rights before releasing either worker, then check the replacements and query the retired names before the issuing threads exit. |

High impact for separating per-thread reply endpoints from service, iterator and connection send names in a trace. Medium impact for identifying bootstrap replies and ADID's separate libdispatch special-reply mechanism during cross-interface attribution. A later native capture that records the request destination and thread reply name at each boundary could test the production join. [ADID special reply mechanism](live_adid_xpc_special_reply_kernel_report.md)

Run `python3 -B triage_evidence/audit_live_iokit_mig_reply_port.py "$TRACE" --observe` under the pinned native build with Capstone available. Archive parsing takes O(n) time and O(n) space in the trace length because the auditor loads the trace and scans bounded send-to-reply intervals. The installed instruction checks and two-thread probe use fixed-size fixtures. [Auditor](triage_evidence/audit_live_iokit_mig_reply_port.py) [Compressed receipt](triage_evidence/live_iokit_mig_reply_port_audit.json.zst)
