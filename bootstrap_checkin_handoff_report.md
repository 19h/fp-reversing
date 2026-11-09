# Bootstrap check-in and receive-right handoff

Both original launchd slices map interface5/routine206 to a handler that places a service port in an XPC reply as a receive right. The cached `_bootstrap_check_in` implementation selects an XPC route or a legacy MIG route; the supplied RAX trace contains five request/reply pairs matching the XPC contract, including the five daemon service names and disposition16 reply descriptors. The ordinary server path shares the endpoint factory/send-object machinery recovered previously. This closes a static protocol/data-flow gap between [endpoint construction](launchd_service_endpoint_report.md) and [daemon CF registration](daemon_registration_report.md). It does not establish a native receive-right handoff or kernel object identity. [Source capture](triage_evidence/bootstrap_checkin_handoff_source.json), [checks](triage_evidence/bootstrap_checkin_handoff_checks.json).

## Provenance and evidence boundaries

Launchd universal SHA-256 is `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`. Slice UUIDs are `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71` and `62af2b7d-327e-334a-a1d7-83777efc3c12`. Original cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. The original trace at `/Users/___/Downloads/zut/annotated-strace-rax-user.txt` has SHA-256 `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`. File/slice/library/tool/header/dependency identities and original bytes are retained in the [capture](triage_evidence/bootstrap_checkin_handoff_source.json).

This increment captures 26 launchd and20 cache bodies: 46 complete compiler-bounded spans, 3,765 instructions and15,060 B. Twenty-four x1 words use the byte-checked LLVM fallback described in the [variant report](launchd_variant_binding_report.md). Both sets of2,447 launchd fixups independently match `dyld_info`. The trace reader independently reconstructs all44 printed Mach headers from their raw hex and decodes ten selected packets. No check-in, target IPC emission, receive-right movement, recovered callback or native policy operation was invoked. SDK compilation and static inspection ran locally. [Validation](triage_evidence/bootstrap_checkin_handoff_checks.json).

The historical RAX packets are guest observations. Matching the installed cache's contract does not attest that these exact cached instruction bytes produced the historical packets. Daemon binary/CF-field mapping is inherited from the source-pinned [registration report](daemon_registration_report.md), not newly executed here. Native loaded-image pairing, PID1 slice selection and actual endpoint objects remain unknown [BH1,BH2].

## Client routes and message-family distinction

| Route | Original cached entry / call | Request | Expected reply | Output mechanism |
|---|---|---|---|---|
| Public wrapper | `_bootstrap_check_in` at `0x184b7f884`, call at `0x184b7f8ac` | Calls `_bootstrap_check_in3` with flags0 and a scratch16 B UUID output | Shared callee result | Caller-provided u32 receive-name output |
| XPC check-in | `_bootstrap_check_in3` at `0x184b7f8d8`; interface call at `0x184b7f9e4` | Interface5, routine206 (`0xce`), dictionary | XPC reply ID `0x20000000` in the five trace pairs | Type-checked `"port"` receive wrapper, atomic right extraction |
| Legacy MIG branch | Same callee, `_mach_msg` call at `0x184b7fab8` | ID402 (`0x192`),168 B | ID502 (`0x1f6`),64 B complex success reply | Receive descriptor at+28 and16 B instance UUID at+48 |
| FairPlayIOKit path, prior reports | Different peer/application contract | Daemon-directed request502 | Its own family-specific reply handling | Separate service, direction and payload semantics |

The legacy bootstrap reply ID502 is not the FairPlayIOKit request502. An integer message ID alone does not identify an interface; direction, destination, request/reply relationship and layout are required. The preserved five check-ins use the XPC IDs, not legacy402/502. [Client branch instructions and constant](triage_evidence/bootstrap_checkin_handoff_source.json), [prior daemon interface map](daemon_receive_interface_report.md).

The public wrapper forwards its three caller arguments and supplies flags0 plus scratch UUID storage. `_bootstrap_check_in2` forwards its caller's flags; `_bootstrap_check_in3` exposes both receive-name and instance outputs. An imported mode byte equal1 selects the legacy branch; its other branch builds the XPC request. The legacy path obtains task special port4 through `_task_get_special_port` before forming its fixed request. Runtime mode and the reason for selecting a particular branch in a native process remain unknown. [Three wrapper bodies](triage_evidence/bootstrap_checkin_handoff_source.json).

## XPC request construction and transport

The request constructor `__bootstrap_create_request` at `0x184b736a0` preserves its incoming bootstrap name and inserts these fields; check-in then adds the name and flags. [Original string literals and setters](triage_evidence/bootstrap_checkin_handoff_source.json).

| Key | Client value / type | Original producer |
|---|---|---|
| `type` | uint64 7 | Request constructor |
| `handle` | uint64 0 | Request constructor |
| `domain-port` | XPC Mach send wrapper for the caller's bootstrap name | Constructor calls `_xpc_dictionary_set_mach_send`; setter requests disposition19 |
| `name` | Caller-supplied service string | Check-in calls `_xpc_dictionary_set_string` |
| `flags` | uint64 caller flags; public wrapper supplies0 | Check-in calls `_xpc_dictionary_set_uint64` |

The interface routine at `0x184b706f0` receives X0=5, X1=206, X2=request, X3=reply-output address, W4=0, W5=1. It performs initialization/state checks, routine encoding, a pipe routine call, error extraction and reply-context checks before returning a reply object. These are bounded original bodies; no complete native peer-authentication result is inferred [BH3].

`__xpc_interface_encode_routine` can place subsystem/routine fields in the dictionary under one mode. In the other selected pack path, `__xpc_pipe_pack_message` combines a message-class prefix with the routine value. It contains `0x40000000`, `0x10000000` and reply-class `0x20000000` branches; the trace's request is exactly `0x400000ce`. A returned reply-port extraction path changes packing to the reply class. This report does not claim every mode emits the same ID. The final captured pipe Mach-message helper calls the import-bound `_mach_msg`. [Packing and transport bodies](triage_evidence/bootstrap_checkin_handoff_source.json).

## Five trace pairs and flat dictionary evidence

| Service | Request / reply trace lines | Request bytes | Reply bytes | Guest receive name |
|---|---|---|---|---|
| `com.apple.unfreed` | 1500 /1516 | 172 | 72 | `0xe03` |
| `com.apple.fairplayd` | 1541 /1557 | 172 | 72 | `0x1303` |
| `com.apple.fpsd` | 1575 /1591 | 168 | 72 | `0x1403` |
| `com.apple.arcade.fpsd` | 1609 /1625 | 176 | 72 | `0x1503` |
| `com.apple.fpsd.sim` | 1643 /1659 | 172 | 72 | `0x1603` |

All five requests have remote `0x707`, local/reply name `0xb03`, message ID `0x400000ce`, and one port descriptor at+28 containing `0x707` with disposition19. Each dictionary has exactly the five keys above, `type=7`, `handle=0` and `flags=0`. All replies have ID `0x20000000`, local `0xb03`, one descriptor at+28 with disposition16, and one dictionary key `"port"`. Those numbers belong to the historical guest namespace; no current host name or kernel pointer is assigned from them [BH2]. [Raw messages and decoded entries](triage_evidence/bootstrap_checkin_handoff_source.json).

The selected payload begins at offset40 after a24 B user Mach header,4 B descriptor count and12 B port descriptor. Its observed prefix has magic `0x40585043`, version5 and dictionary tag `0xf000`. The dictionary length counts bytes beginning with its entry-count word. Keys and strings use four-byte alignment. Observed uint64 tag is `0x4000`, string tag `0x9000`, Mach-send tag `0xd000`, and Mach-receive tag `0x15000`. The latter two consume the corresponding descriptor; the selected wire values contain no additional numeric-name payload. [Bounded decoder and offsets](triage_evidence/recover_bootstrap_checkin_handoff.py).

The decoder is deliberately limited to these flat five-entry requests and one-entry replies. It requires one port descriptor, checks full dictionary extent and key uniqueness, consumes all selected bytes/descriptors, and rejects unsupported tags. It is not a general XPC parser, schema, serialization implementation or historical producer attestation. Field values and byte extents are independently compared with the earlier trace extraction. Ten evidence/parser alterations test sensitivity; no altered packet is emitted [BH2,BH6].

## Launchd interface registration and role correspondence

| Analytical role | arm64e start | arm64e.x1 start |
|---|---|---|
| Interface registration caller | `0x10002d3a8` | `0x10002ca6c` |
| Group/callback array writer | `0x100045930` | `0x100044c60` |
| Interface5 dispatcher, routine window200..211 | `0x10002e16c` | `0x10002d830` |
| Audit/domain context resolver | `0x10002eb50` | `0x10002e1d8` |
| Dictionary domain decoder | `0x10005b1dc` | `0x10005a200` |
| Routine206 check-in handler | `0x100038158` | `0x100037690` |
| Endpoint lookup/check-in core | `0x100059640` | `0x1000586a0` |
| Internal-to-bootstrap status mapper | `0x100059a64` | `0x100058ac4` |
| Endpoint activation / unguard path | `0x100046e3c` | `0x100046100` |
| Conditional send-object getter | `0x100047360` | `0x100046624` |
| Port-destroyed notification setup | `0x100045bec` | `0x100044f10` |
| Shared send-object helper | `0x10005cb6c` | `0x10005bb3c` |
| Shared send-name helper | `0x100046c28` | `0x100045ef8` |

Correspondence follows actual signed callback literals, call edges, import bindings and a signed relative jump table. It does not use a constant address adjustment. Initialization passes group5 and the dispatcher pointer to the array writer, which stores callbacks and group IDs in parallel arrays. The dispatcher subtracts200 from the u32 routine and bounds the resulting index to0..11. Entry6 selects the check-in handler in both slices. Native registration/execution of the callback array remains unknown. [Derived role/table records](triage_evidence/bootstrap_checkin_handoff_source.json).

The context resolver obtains a32 B audit token through `_xpc_dictionary_get_audit_token`, decodes dictionary domain fields and attempts domain/context resolution. The domain decoder can copy a send right from `"domain-port"`, correlate it with a launchd object, and release the temporary send reference. The dispatcher has additional context/state gates and supplies a pointer to a fixed global audit-shaped record to the endpoint core. This increment does not trace the writer establishing that global's current request identity. Thus the local token read is not promoted to proof of the core's effective native authorization context [BH3].

## Handler flags, endpoint activation and reply production

The handler requires a reply-capable dictionary and a nonnull `"name"` string, then reads uint64 `"flags"`. Its three instruction operations form:

```text
internal_mode = (((flags & 1) << 1) | ((flags >> 6) & 1)) XOR 1
```

Only input bits0 and6 contribute; input0 produces mode1. A full64-bit proof verifies the two output bits. It initializes an eight-byte output-object slot toNULL and invokes the shared endpoint core with X4=0 (no supplied registration object), X5=&output and X6=0. After translating the returned status, nonzero skips reply creation. On zero it creates an XPC reply, obtains a numeric name through `_xpc_mach_send_get_right(output)`, sets `"port"` through `_xpc_dictionary_set_mach_recv`, releases the temporary send-object reference, and publishes the reply pointer. A zero status or nonnull reply does not independently establish a valid/live receive right [BH3,BH4]. [Handler checks](triage_evidence/bootstrap_checkin_handoff_checks.json).

The endpoint core contains caller/job lookup, named-service matching, owner equality, endpoint-flag gates and sandbox-check branches. Some branches create/register an endpoint rather than check in an existing one. This report follows selected existing-endpoint and shared output edges while retaining the entire body. It does not replace those gates with an unconditional name lookup or infer native caller admission. Its sandbox API calls receive a copied32 B caller record; the writer/lifetime of the dispatcher-supplied record remains an explicit gap.

On the selected ordinary existing-endpoint path, activation runs before checked-in state and output publication. The activation helper obtains the send name with creation mode1; on its ordinary non-alternate branch it requests port-destroyed notification setup, then calls `_mach_port_unguard(task_self,name,service+0x70)`. The last argument is the same stored context produced by the earlier [construction factory](launchd_service_endpoint_report.md). The unguard return is not tested before a branch to the common return0/active-bit store. A notification-setup failure reaches a diagnostic and then the unguard path. These are static control facts; no failure was induced, and no native acceptance or resource-loss consequence is established [BH4].

| Handoff-related operation | arm64e site | arm64e.x1 site |
|---|---|---|
| Handler invokes endpoint core | `0x1000381e0` | `0x100037718` |
| Ordinary core invokes activation | `0x100059a04` | `0x100058a64` |
| Activation calls `_mach_port_unguard` | `0x100046ef4` | `0x1000461b8` |
| Core gets send object for output | `0x100059a40` | `0x100058aa0` |
| Handler sets receive wrapper in reply | `0x100038218` | `0x100037750` |

The core's selected success suffix sets job+`0x180` bit13 and endpoint+`0x58` bit2, obtains the shared send object with mode4, retains it, and stores it to the output-object address. The getter can returnNULL for `(u16(endpoint_flags) & 5) == 4`; otherwise it tails into the prior send-object helper. Captured control flow and SDK-like API names do not by themselves prove nonnull output or actual right existence. The mode/field operation names are analytical, not recovered structure declarations. [Both original bodies](triage_evidence/bootstrap_checkin_handoff_source.json).

## Port-destroyed notification boundary

The setup helper accepts notification ID69 (`MACH_NOTIFY_PORT_DESTROYED` in the installed SDK). Its selected path creates/activates a dispatch source and an associated48 B local record, attempts `mach_port_insert_right(task,name,name,MAKE_SEND20)`, then invokes `_mach_port_request_notification`. The local source uses a separate imported type; this report does not infer that it is the previous Mach-receive source.

| Request-notification argument | Recovered carrier/value |
|---|---|
| Task | Imported `_mach_task_self_` value |
| Monitored name | The endpoint name |
| Notification ID | 69 |
| Sync | 0 |
| Notify name | u32 from global `0x10008af20` in both slices |
| Notify disposition | 21 (`MAKE_SEND_ONCE`) when notify name is nonzero;18 (`MOVE_SEND_ONCE`) otherwise |
| Previous notification right | Initialized u32 output; nonzero result is explicitly deallocated |

The helper retains the request-notification status as its return value; some earlier failures are only logged. The activation caller logs a nonzero status and continues. The global notify-name cell is also used by the previously recovered fixed-slot22 publication caller, establishing a static shared producer/consumer location; it does not establish a native name/object or notification delivery. The event/cancellation callbacks, eventual destroyed-port notification, receive-right return/reacquisition and complete lifecycle are not newly traced here [BH5]. [Setup body](triage_evidence/bootstrap_checkin_handoff_source.json), [earlier fixed-slot call](host_special_registration_report.md).

## Receive-wrapper serialization and client extraction

| Original cached routine | Address | Selected operation |
|---|---|---|
| `_xpc_dictionary_set_mach_recv` | `0x184b89130` | Allocate48 B receive wrapper; for its accepted name domain, store the name at+`0x18` and+`0x1c`; insert under the key |
| `__xpc_mach_recv_serialize` | `0x184b89250` | Atomic exchange at+`0x18` with `0xffffffff`; retain old name as serializer argument |
| `__xpc_serializer_append_port` | `0x184b73bfc` | Append a12 B descriptor; name low word, zero pad word, disposition shifted into descriptor+8 |
| `__xpc_mach_recv_deserialize` | `0x184b7cc3c` | Request a disposition16 port from the deserializer; build a receive wrapper |
| `_xpc_mach_recv_extract_right` | `0x184b7ccc8` | Type check; atomic exchange of owned name with `0xffffffff`; return old u32 name unless the sentinel triggers a diagnostic |
| `__xpc_mach_recv_dispose` | `0x184b7cd28` | Byte+`0x20` flag can bypass disposal; otherwise exchange name with0 and conditionally call `_mach_port_destruct` |

Serialization emits wire tag `0x15000` and calls the append-port helper with W5=16, the SDK value of `MACH_MSG_TYPE_MOVE_RECEIVE`. The append helper places that disposition in the actual descriptor bytes. For serialization/extraction, an old name of `0xffffffff` reaches a diagnostic path. The name is atomically removed from the wrapper before the later operation; this establishes local ownership-state mutation, not successful kernel transfer or concurrency correctness [BH4,BH5].

The client check-in code retrieves `"port"` through a recognized dictionary class and expected receive-wrapper class, then dispatches the extraction function through an authenticated function pointer. It stores W0 into the caller's receive-name output. A wrong/missing value can produce0 through the helper's ordinary failure path. If an `"instance"` UUID exists, it copies16 B to its separate output. The public wrapper uses scratch UUID storage. A nonnull reply object is processed before returning the interface status; no independent nonzero/live-name check is added here. [Client and dictionary-helper bodies](triage_evidence/bootstrap_checkin_handoff_source.json).

The receive destructor's direct port API is `_mach_port_destruct(task,name,0,0)`, unlike the [send wrapper's `_mach_port_deallocate`](launchd_service_endpoint_report.md). The latter operates on a send reference; the former is a selected receive-object cleanup request. This difference does not prove the entire runtime object lifetime, final right balance, or that either cleanup occurred in the trace. Type mismatches, sentinel names, failed serialization, pending notifications and other callers remain separate cases.

```text
launchd endpoint send object (same numeric name can name multiple rights)
       |
activation -> notification request -> unguard request
       |
reply receive wrapper -> serialize MOVE_RECEIVE16
       |
historical RAX reply: disposition16, guest name
       |
client receive wrapper -> extract u32 name
       |
prior daemon bootstrap helper -> CFMachPortCreateWithPort
       |
CF object/source publication -> common callback (cache-history caveat)
```

The static contracts and historical packet observation occupy different evidence scopes. They do not create a verified single native epoch through this entire diagram. The daemon CF wrapper's requested callback, cache reuse and source insertion remain governed by the prior [registration](daemon_registration_report.md) and [CF receive](cf_receive_report.md) reports [BH1,BH2,BH5].

## Status translation and legacy layout

The mapper uses signed32 comparisons and maps its complete input domain as follows. Four full-domain bit-vector proofs cover this mapping, routine-window bounds, handler flags and getter NULL gating. All33 mapper instructions in each slice are explicitly checked. [Queries and results](triage_evidence/bootstrap_checkin_handoff_checks.json).

| Internal status | Returned value | SDK nomenclature where available |
|---|---|---|
| 0 | 0 | `BOOTSTRAP_SUCCESS` |
| 151 | 151, unchanged | No bootstrap status name assigned here |
| 1 or159 | 1100 | `BOOTSTRAP_NOT_PRIVILEGED` |
| 56 | 1101 | `BOOTSTRAP_NAME_IN_USE` |
| 3 or145 | 1102 | `BOOTSTRAP_UNKNOWN_SERVICE` |
| 37 | 1103 | `BOOTSTRAP_SERVICE_ACTIVE` |
| All other signed/unsigned32 bit patterns | 1105 | `BOOTSTRAP_NO_MEMORY` |

The fallback label `BOOTSTRAP_NO_MEMORY` does not prove that the original cause was an allocation failure. Internal numeric errors and public bootstrap labels are different interfaces. The handler treats any nonzero mapped result as failure.

The legacy client uses a168 B request: user header24 B, NDR8 B, name128 B at+32 and flags8 B at+160. Its64 B successful complex reply has a receive descriptor at+28, NDR at+40 and instance UUID16 B at+48. These are derived layouts checked against actual SDK field types, not recovered generated server declarations. The branch validates reply ID502, descriptor count1, size64 and disposition/type16/0 before storing the output name. Error replies and Mach transport errors take separate paths; the full legacy launchd server was not recovered in this increment. [SDK compilation and client checks](triage_evidence/bootstrap_checkin_handoff_checks.json).

## Assumption register and bounded continuation

| ID | Assumption / dependent result | Stress test or falsification probe | Status |
|---|---|---|---|
| BH1 | Pinned launchd/cache/daemon evidence identifies the relevant implementations | Rehash files and original spans; resolve imports and4894 fixups; independently attest loaded images and a common runtime epoch | Static identities verified; native pairing/epoch unknown |
| BH2 | Preserved RAX bytes support the named five check-ins | Reparse all44 headers and ten packet bodies, compare prior extraction and exact names/fields; guest execution/producer attestation could refine attribution | Raw packet correlation verified; native identity and historical exact producer unknown |
| BH3 | Interface registration, domain context and core arguments describe the applicable server path | Check both slices' callback registration, routine table, handler and domain/core data flow; trace the global audit-record writer and per-request identity | Static contracts verified; effective native admission unknown |
| BH4 | Selected activation and wrapper operations inform receive-right handoff | Check unguard context/order, state writes, MOVE_RECEIVE descriptor construction and extraction; observe native API statuses and names/objects separately | Requested operations verified; native success and right existence unknown |
| BH5 | Notification and send/receive wrapper cleanup have distinct ownership roles | Trace callback producers, complete source teardown, generic destructor dispatch and destroyed-port return; count actual rights across one native epoch | Selected operations verified; complete lifetime/balance unknown |
| BH6 | Scalar models and bounded flat decoder faithfully represent their stated scope | Match instruction/width records, four full-domain proofs, SDK layouts and ten altered evidence/parser records; independent architecture/native tests could falsify execution assumptions | Scoped checks passed; no whole-path/hardware proof |

| Impact | Remaining question | Discriminating evidence |
|---|---|---|
| High | Who writes the audit-shaped global consumed by the endpoint core? | Trace receive/dispatch callback setup and per-request overwrite/clear boundaries; distinguish dictionary token acquisition from later record consumption |
| High | How does a destroyed receive right return to launchd after daemon exit? | Follow notification69 receiver, request record/source callbacks and receive-right reinsertion, retaining native/private evidence separation |
| High | Which live service/host slot receives RPC700? | Correlate named check-in, endpoint handoff and host-special publication with read-only port identity evidence; packet IDs/numeric names alone are insufficient |
| Medium | How do generic XPC release and failed-send cleanup reach receive disposal? | Trace dynamic type-table dispatch and serialization rollback before any final right-balance claim |
| Medium | What checks apply in the legacy402 server branch? | Recover that separate server implementation and admission path; do not substitute the XPC206 handler |

## Reproduction and quality gates

From the extracted directory: `/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_bootstrap_checkin_handoff.py`. Validation statically recaptures original files/cache, reconstructs supplied-trace packets, checks254 instruction assertions, compiles26 SDK assertions, runs four scalar proofs and rejects ten altered evidence/parser cases. No target request is emitted. Capture/checking are O(B+F+I+T) time and space for original bytes B, fixups F, selected instructions I and trace bytes T; the five dictionaries have fixed small cardinality. [Recovery](triage_evidence/recover_bootstrap_checkin_handoff.py), [validator](triage_evidence/validate_bootstrap_checkin_handoff.py).

QG1: Factual interface analysis; no normative judgment required.

QG2: BH1-BH6 state assumptions, dependent results and falsification probes.

QG3: This increment covers two client routes, XPC registration/handler, selected activation/output, receive wrapper operations and five historical pairs. Native handoff/admission, full notification lifetime, slot34/RPC700 and successful daemon/kext processing remain unknown; the full goal is active.

QG4: Names/statuses/descriptor fields are32 bit, flags64 bit, audit token32 B and UUID16 B. Packet/record extents and all offsets are B; both derived legacy layouts compile against primary SDK types.

QG5: Legacy bootstrap reply502 versus FairPlay request502, static versus guest observation, copied-send versus moved-receive, name versus object, global audit context and requested versus successful unguard/handoff remain distinct.

QG6: Original bytes, exact nlist/export names, authenticated bindings, SDK/tool/file hashes, raw trace packets and proof queries are retained. A match does not attest a historical producer or current native port object.

QG7: The impact-labeled continuation table preserves admission, notification return, legacy-server and lifetime gaps.

Publication: [prior manifest](triage_evidence/bootstrap_checkin_handoff_prior_manifest.json), [preservation seal](triage_evidence/bootstrap_checkin_handoff_delivery.json), [scoped gates](triage_evidence/bootstrap_checkin_handoff_quality_gates.json), [seal script](triage_evidence/seal_bootstrap_checkin_handoff.py), [independent audit](triage_evidence/verify_bootstrap_checkin_handoff_publication.py), [current corpus manifest](triage_evidence/interface_manifest.json). `full_goal_complete=false`.
