# Arcade registration, anonymous CF Mach port and kernel subscription upcall

The independent `CFMachPortCreate` call belongs to an arcade registration handshake. The matching kernel collection sends daemon message **41471** through **host special port31**, carrying a registration kobject send right. The daemon checks the receiving service against its `com.apple.arcade.fpsd` CF registration,creates another CF Mach port,makes a send right,and supplies that name to kernel message **51471**. The kernel can store the supplied send right and subsequently use it for daemon subscription-validation RPC **61471**. This is a separate endpoint path from the conditionally recovered FairPlayIOKit host-slot17 / RPC502 path. Correction:an earlier version of this report incorrectly wrote slot24;the original [port-selection evidence](kernel_port_resolution_report.md) establishes17/34 under its stated protocol,with mode1 selecting17.

These are original-byte static results plus bounded private fixtures. There is no native handshake, entitlement, namespace-object, PAC, CF cache or scheduling attestation. The broad interface investigation remains active and incomplete.

```text
kernel subscription consumer 0xfffffe000bce1a64
  |
  +-- usable cached send right at 0xfffffe000cb5fe18 ------------------+
  |                                                               |
  +-- missing right: mark registration pending                     |
       host_get_special_port(...,31,&port)                         |
       send41471 [registration kobject COPY_SEND; no reply port]    |
                    |                                             |
                    v                                             |
       daemon com.apple.arcade.fpsd                                |
       compare received service name with CF header+0x30           |
       invalidate/clear old anonymous CF object at header+0x38     |
       CFMachPortCreate(callback0x100425f78,zero context)            |
       mach_port_insert_right(task,name,name,MAKE_SEND)             |
       RPC51471(kobject,name COPY_SEND), expect51571                |
                    |                                             |
                    v                                             |
       kernel kobject type43 + current-caller policy + pending     |
       release old send; store new send at 0xfffffe000cb5fe18        |
       wake registration waiters                                  |
                    |                                             |
       daemon: main/default-mode source; publish CF header+0x38    |
       deallocate incoming kobject send name                      |
                    |                                             |
       kernel registration wait finishes -------------------------+
                                                                  |
       RPC61471 [4096-byte OOL record + opaque u64] <---------------+
                    |
       daemon implementation0x1000057c0
       reply61571 [status + u32 result on success]
```

## Evidence and identity

| Evidence | Identity and limit |
| --- | --- |
| Daemon original thin image | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; UUID `204741e9-b89f-32b4-9321-51f3975c7cac` |
| Matching collection | `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`; SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; kernel UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84` |
| Current IDA readback | Eight original windows match, including the full328-byte51471 client,41471 demultiplexer/application wrapper and creation/publication blocks; no IDB mutation |
| Static recovery | 27 daemon spans, eight complete compiler-bounded kernel functions,15 exhaustive256-input bank selections,22 daemon and28 kernel instruction assertions, six full-domain bit-vector checks |
| Private fixtures | 30 original-instruction cases;648 explicit checks; original visited instructions/page hashes checked; private CF/Mach API models; explicit PAC bypass; logging disabled and registered arcade CF state seeded |
| ABI compilation | Installed SDK `mach`/MIG types and manual partial kernel records compile for ARM64e; no target executable is run |
| Supplied RAX trace | Previously preserved discovery/open-failure evidence; it does not demonstrate this41471/51471/61471 exchange |

Primary evidence is [original contracts](triage_evidence/created_port_contracts.json), [fresh IDA bytes](triage_evidence/created_port_live_ida_bytes.json), [private profiles](triage_evidence/created_port_profiles.json), [explicit fixture checks](triage_evidence/created_port_profile_checks.json), and [layout assertions](triage_evidence/created_port_layouts.c). Protocol constants are checked against the installed SDK and the separately pinned [Mach header](triage_evidence/xnu_osfmk_mach_message.h) and [MIG error header](triage_evidence/xnu_osfmk_mach_mig_errors.h). Those headers establish nomenclature; they are not an assertion of exact target source revision.

## Message and emission contracts

All offsets and sizes below are bytes. A Mach name is an unsigned32-bit task-local name; it is not a kernel pointer or CF object. `C` denotes `MACH_MSGH_BITS_COMPLEX`.

| Direction / ID | Emission or receive site | Inline ABI and transferred data |
| --- | --- | --- |
| Kernel -> named daemon service,41471 | Build `0xfffffe000bce1c00..1c64`; send call `0xfffffe000bce1c68` | Internal52 bytes -> user40; C; one port descriptor; kernel supplies registration kobject with COPY_SEND19, received descriptor validated as MOVE_SEND17/type0. Destination comes from host special slot31. Local/reply port is null. |
| Daemon41471 dispatch | `0x1000053c8`; application call `0x100005450` -> `0x100006944` | Requires ID41471,C,count1,size40,16-bit descriptor disposition/type17. W0=request local/service name at+12; W1=descriptor name at+28. Prepares36-byte41571 status buffer. The kernel trigger's null reply destination means this is not an observed outer reply emission. |
| Daemon -> kernel,51471 | Protected call `0x100503cec` -> client `0x1000043b4`; libSystem emission `0x100004428` -> stub `0x100e2ab00` -> `_mach_msg2_internal` | User40 -> internal52; header bits `0x80001513`; remote=received kobject name; local=`mig_get_reply_port()`; voucher0; ID51471; count1; descriptor name=new CF receive name with COPY_SEND19/type0. |
| Kernel51471 server | Subsystem `0xfffffe0007e688d8`; lookup `0xfffffe000bd92600`; stub `0xfffffe000bd92510`; application `0xfffffe000bce1864` | Original subsystem range[51471,51472), max reply44 internal bytes. Internal request guard:size52,C,count1,received disposition17/type0. Destination kobject type43 can supply payload to the implementation. |
| Kernel -> daemon,51571 | Kernel stub/application return through generic server; daemon client validation `0x100004470..44fc` | Simple user36/internal44 status reply. Daemon receive capacity44 includes room beyond36-byte inline status. Generic kernel server's final send site and actual transaction remain outside this increment. |
| Kernel -> anonymous daemon endpoint,61471 | Client `0xfffffe000bd923a4`; common RPC call `0xfffffe000bd92448` -> `0xfffffe000bcf59e0` | Internal72 -> user64; C; one OOL descriptor; selected caller passes4096 bytes; NDR, repeated u32 count and opaque u64. Internal OOL address is PAC signed using discriminator`0x5d4f`. Transport receive capacity56 bytes. |
| Daemon61471 receive /61571 response | Stub `0x1000054d8`; application call `0x100005540` -> `0x1000057c0` | Requires C,count1,size64,descriptor type1 and repeated count equality. Args:service u32,OOL pointer,count u32,opaque u64,output-u32 pointer. Success reply40 bytes; status-only form36. No explicit incoming OOL deallocation in this stub. |

The original51471 client packs arguments as follows. This is the function's call into libSystem, before any runtime hook/retry changes described in the [trap report](user_trap_interface_report.md).

| Register | Value / meaning |
| --- | --- |
| X0 | Request/reply buffer |
| X1 | `0x200000003`: send,receive and KOBJECT send class |
| X2 | `(40 << 32) | 0x80001513` |
| X3 | `(reply_name << 32) | destination_name` |
| X4 | `(51471 << 32) | 0` |
| X5 | `(reply_name << 32) | 1` |
| X6 | 44-byte receive capacity |
| X7 | 0 |

The collection contains exactly one aligned original `[51471,51472)` byte-pair match, at file offset`0xe648e0`. This search is a locator. Original format8 chain membership independently resolves subsystem lookup and routine pointers to the functions above, and their instructions establish the message ID and guards. It is not a claim that an ID pair alone proves endpoint identity.

## Daemon control flow and ownership

The application wrapper's original control literal is`0x6cf4`. Its protected route reaches a service-name comparison: `CFMachPortGetPort(header+0x30)` at`0x100526018`, compared with the incoming service name. Prior [registration recovery](daemon_registration_report.md) identifies that field as `com.apple.arcade.fpsd`, with absolute CF cell`0x1010c4d08`. Mismatch returns status5 in the inspected logging-disabled route. This is a task-local name comparison, not independent caller authentication.

The anonymous CF cell is header+`0x38`, absolute`0x1010c4d10`. If nonnull, the original replacement block calls `CFMachPortInvalidate` at`0x1004ace70`, clears the cell at`0x1004ace78`, then continues to creation. There is no explicit old-object `CFRelease` in that block or its selected complete fixture path. Actual framework reference counts/cache effects remain unknown.

Creation at`0x100575840` resolves to wrapper`0x100001f50`, which calls `CFMachPortCreate` with null allocator, callback`0x100425f78` and a zero40-byte context. Nonnull output reaches `CFMachPortGetPort` at`0x100503c04`; the obfuscated name codec is an identity for every unsigned32-bit name. `mach_port_insert_right(task_self,name,name,MAKE_SEND20)` follows at`0x100503c98`. Its return value is neither tested nor propagated before the51471 call; the destination name replaces W0 at`0x100503ce4`.

After51471 returns zero, source creation occurs at`0x10050a710`. A nonnull source enters the main run loop/default mode at`0x1004a94d0`; local source release occurs at`0x1004a9510`; the CF object is published at`0x1004a951c`. The received kobject send name is deallocated with `mach_port_deallocate(task_self,peer)` at`0x100494310`. A null source instead invalidates/releases the new CF object at`0x100800b0c`/`0x100800b50`, then deallocates the peer name through the same continuation.

| Selected condition | Prepared41571 status | Anonymous CF field | Explicit local actions after condition |
| --- | --- | --- | --- |
| Service mismatch | 5 | Unchanged | No creation; no peer-name deallocation in selected application path |
| Existing object before creation | Depends on later result | Cleared before replacement | Invalidate old object; no explicit old-object release |
| `CFMachPortCreate` returns null | 0 | Zero after any prior clearing | No nested call or peer-name deallocation in selected application path |
| Insertion returns modeled5 or-1, nested RPC succeeds | 0 | New object | Continue through source/publication; insertion status ignored |
| Nested transport, validation or server status is nonzero | Same32-bit status | Zero after any prior clearing | No source construction, new-object invalidate/release or peer-name deallocation in selected application path |
| Nested status0; source returns null | 0 | Zero | Invalidate/release new CF object; deallocate peer name |
| Nested status0; source nonnull | 0 | New object | Add source,release source,publish CF object,deallocate peer name |

These are explicit instructions and modeled paths, not a native resource-leak conclusion. CF internal ownership, generic message-body destruction, kernel descriptor cleanup, concurrency, failed API effects and eventual teardown remain separate obligations. The41471 kernel trigger is one-way; a zero prepared status does not establish that the kernel observes a successful registration. The kernel waits on the published send endpoint instead.

The encoded status stored by`0x100528ddc` and decoded by the application wrapper is an exact32-bit round trip. The six solver checks include that identity, created-name identity, creation/source branch indices, default-mode import-addend cancellation and transport reply-cache partition. Each proof concerns the lifted arithmetic, not PAC, scheduling or native reachability.

## Nested51471 reply and error behavior

| Result class | Original client behavior |
| --- | --- |
| Transport status`0x10000002`,`0x10000003`,`0x10000010` | Call `mig_put_reply_port`,return transport status |
| Other nonzero transport statuses in full local arithmetic partition | Call `mig_dealloc_reply_port`,return transport status |
| Transport0,reply ID71 | Return-308 (`MIG_SERVER_DIED`),destroy received reply |
| Transport0,other unexpected ID | Return-301 (`MIG_REPLY_MISMATCH`),destroy received reply |
| Expected51571 but complex,size other than36,or nonzero remote port | Return-300 (`MIG_TYPE_ERROR`),destroy received reply |
| Expected structurally valid51571 with nonzero server status | Preserve server status,destroy received reply |
| Expected valid51571,status0 | Return0; no explicit put/dealloc call in this client's ordinary success path |

The client does not separately compare the received local port or NDR bytes in these instructions. Framework/libSystem/kernel checks may impose additional conditions. Model inputs returning a zero or maximum32-bit CF name demonstrate arithmetic behavior only; they do not establish that CF can produce those states natively.

## Kernel admission, publication and consumer

Initialization function`0xfffffe000c629780` calls allocator`0xfffffe000bcf4a5c` at`0xfffffe000c629844` with X0=address of cell`0xfffffe0007e5c540`,W1=`0x12b`,X2=0,W3=1,then publishes the returned port with `STLR` at`...9848`. The allocator uses the low8-bit kind in its payload-signing discriminator; the51471 stub checks kind`0x2b`=43 and authenticates the payload at port+`0x50` with modifier tag`0x71`. This ties the trigger's port cell to the receiver's kobject-kind contract without assuming a source-level enum name.

Application`0xfffffe000bce1864` rejects null registration object with status4. It obtains the current task through the original thread/task helper, rejects the exact `_kernel_task` object, requires a nonnull `_get_bsdtask_info` result, and calls a runtime policy function through table cell`0xfffffe0007f818e8`,function offset`0x1c8`,with the process and string `com.apple.arcade.fpsd`. A zero policy result reaches registration; other inspected admission failures return18. The original string supports an arcade-specific policy interpretation. The callback implementation, entitlement/key semantics, initialization and effective native result are unknown.

This policy observes the task making51471,which is the daemon in the recovered sequence. It does not directly identify the sender of the earlier41471. The daemon invalidates its previous anonymous object before the nested registration result is available. Those ordering and identity boundaries make upstream service access,sender provenance and replacement admission a high-impact continuation; no unauthorized native reachability or denial-of-service condition is established.

Under the inspected lock/control sequence, pending word`0xfffffe000cb5fe10` must be nonzero. Zero returns5 without publication. On the pending path, the implementation releases a previous valid stored send right via exact symbol `_ipc_port_release_send` at`0xfffffe000bce1950`,then stores the supplied right at`0xfffffe000bce1954` into`0xfffffe000cb5fe18`. It releases the lock and reaches a hashed wakeup operation. Lock slow paths and wait/wakeup scheduling are retained as original code; they were not natively executed or fully modeled here.

The consumer`0xfffffe000bce1a64` attempts to obtain a usable send right from that global. If missing, it coordinates registration using the pending word, looks up host special slot31 through exact symbol `_host_get_special_port`, builds41471 with the registration kobject cell and calls the kernel send helper. It releases the temporary named-service send reference, then waits for registration using the endpoint's address and a computed deadline. Thus the named-service right, transferred registration-kobject right and cached anonymous endpoint right have different lifetimes.

With a usable endpoint, the consumer builds the selected4096-byte OOL input and invokes client`0xfffffe000bd923a4` at`0xfffffe000bce1dbc`. Original diagnostic strings explicitly identify this as a "subscription validation upcall" and retain `arcade.c` / `arcade_upcall_refresh(get fairplayd)`. Those strings corroborate function, but do not recover an exact stripped symbol. The4096-byte record schema, opaque64-bit argument, application algorithm and result meaning remain unknown. Following a zero transport/status result, a returned word equal to1 selects a further task-related action; its full semantics remain open.

The immediate direct caller at`0xfffffe000bce2090` handles bit11 (`0x800`) of a merged pending-event word and atomically clears that bit in thread+`0x43c` before calling the consumer. The merged word incorporates thread+`0x43c` and another pending field at `[thread+0x1c0]+0x4c`. Writers, event naming, user-return context and complete call-in prerequisites remain unresolved; an AST-like interpretation is a candidate, not an exact symbol claim.

## Assumption register and falsification probes

| ID | Assumption / dependency | Stress test or falsification probe | Status |
| --- | --- | --- | --- |
| P1 | Addresses describe the preserved daemon/collection; all static mappings depend on identity | Rehash inputs; rerun original fixup/LC assertions; compare eight fresh IDA windows | Verified for recorded inputs; runtime module identity unknown |
| P2 | Compatible daemon/kernel message contracts describe a possible pair; cross-layer diagram depends on this | Compare loaded runtime UUIDs, port kind, generic kernel server dispatch and transaction packets | Static ID/layout/kobject linkage established; native pairing unknown |
| P3 | Private path begins with a registered arcade CF object, zero initial anonymous field unless specified, and logging disabled | Mismatched service and preexisting object cases; inspect runtime CF cache and logging-enabled continuation | Finite alternate service/replacement cases pass; runtime cache and logging-enabled path unknown |
| P4 | API models return explicit names/statuses; all private behavior depends on these models | Insertion5/-1,zero/max name,CF/source null,ten transport statuses and malformed replies | 30 cases pass; no native API-success/right-object claim |
| P5 | Explicit PAC bypass and normalized fixups preserve selected control targets | Original tag/chain checks and instruction/page hashes; execute on authenticated native mappings for hardware proof | Static PAC metadata verified; hardware authentication unknown |
| P6 | Runtime policy callback is initialized and may authorize registration | Recover writers/callee of table+`0x1c8`; inspect effective process policy and null/nonzero results | Local zero/nonzero gate established; callback semantics/result unknown |
| P7 | Local explicit calls are only one part of ownership; resource interpretation depends on wider lifecycle | Trace CF invalidation/references, message-body cleanup,kobject failure cleanup,lock races,old endpoint destruction and timeout paths | Explicit local actions established; native lifetime/reachability unknown |
| P8 | Subscription record/opaque word have not been semantically typed | Recover producer helper,4096-byte schema,implementation`0x1000057c0`,output meaning and event writers | Layout and caller constants established; deeper semantics unknown |

## Bounded continuation opportunities

| Impact | Next investigation | Information resolved |
| --- | --- | --- |
| High | Recover daemon`0x1000057c0` through its protected control record, service gate,parser and output publication | Subscription predicate,record schema,result1 meaning and actual deeper FairPlay interfaces |
| High | Recover current-caller policy callback table initialization and function+`0x1c8` | Effective authorization contract; distinguish service-name routing from authenticated registration |
| High | Establish who can send41471 to host-slot31's service and how sender identity is admitted before old-object invalidation | Separate kernel trigger provenance,daemon-mediated51471 policy and externally reachable replacement behavior |
| High | Trace generic kobject51471 descriptor ownership and CF invalidation/finalization | Precise transferred send-reference ownership,failed-registration disposal and old/new endpoint lifetime |
| High | Resolve writers of pending-event bit`0x800` and the4096-byte producer | External control,task/exec/environment inputs and trigger reachability |
| Medium | Complete registration wait/deadline/retry and invalid-destination recovery | Startup races,blocking/reentrancy,stale endpoint replacement and timeout semantics |
| Medium | Inspect logging-enabled handler route and unregistered/null arcade CF field | Additional environment/control dependencies outside current private seeds |
| Medium | Match live slot31,slot17,CF objects and task namespaces to actual modules | Native topology; preserve names,rights,objects and framework handles as different identities |

## Reproduction and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_created_port.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_created_port_delivery.py
```

The first command executes original instructions only inside private Unicorn mappings, with explicit named API models and no target host operations. The second re-extracts original contracts,reruns six SMT checks,compiles SDK/manual layouts,verifies all30 profiles and refreshes the owned manifest. Extraction costs O(B+F+I) time/space for binary bytes,fixups and retained instructions; fixed-pattern searches are O(B),each bank checks256 bytes,and solver cost is separate. A profile is bounded by50000 instructions with O(B+S+V) private space for mapped image,stack and visited instructions. Full architecture/native lifecycle remains outside this increment.

QG1 factual scope passes. QG2 P1-P8 include dependencies/probes. QG3 passes for this registration/subscription-interface increment,not for the broad goal. QG4 widths,byte extents,layouts and complexity are explicit. QG5 one-way trigger/status,namespace/CF/kernel identities and partial ownership are distinguished. QG6 original bytes/fixups/SDK/IDA,arithmetic proofs and private models retain separate provenance. QG7 bounded impact-labeled continuation is included. See [machine-readable gates](triage_evidence/created_port_quality_gates.json) and [current manifest](triage_evidence/interface_manifest.json).

The subsequent [subscription/XPC report](arcade_subscription_report.md) identifies the4096-byte producer as a process-path routine and follows daemon application0x1000057c0 through path copying,80-byte record construction and a serialized `data` dictionary sent synchronously to `com.apple.fpsd.arcadeservice` in CoreFP. Count/opaque slots are not read before send in selected fixtures. Actual XPC response,final decision,policy and full ownership remain open; earlier "record/application unknown" entries above are now narrowed by that report.
