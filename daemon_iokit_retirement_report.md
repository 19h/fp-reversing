# fairplayd connection close and Mach name release

The pinned arm64e daemon has no direct `IOServiceClose` or `io_service_close` binding. The captured FairPlayIOKit open returns a null connection, followed by release of its service and iterator. The direct `mach_port_deallocate` call confirmed in daemon code releases the peer name received by the arcade registration handler. Whether native `fairplayd` closes a successfully opened FairPlayIOKit connection explicitly, or releases it through another lifetime path, remains unknown. [Discovery call-site capture](daemon_iokit_callsite_capture_report.md) [Arcade port ownership](created_port_report.md)

```text
FairPlayIOKit discovery
  service -> IOServiceOpen -> 2862 -> 2962 -> connection output
      |                                      |
      |                           captured 0, status e00002c2
      +-> IOObjectRelease(service)           |
      +-> IOObjectRelease(iterator)          +-> native close path unknown

Arcade registration
  41471 port descriptor -> peer name -> 51471 destination
                                     -> mach_port_deallocate at 0x100494310
```

## Original daemon bindings and call arguments

The input is `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. Addresses are preferred, unslid virtual addresses. The audit checks the original import list, chained fixup walk, and byte strings. It finds neither a binding nor a case-insensitive ASCII occurrence of `IOServiceClose`, `io_service_close`, `IOConnectRelease`, or `IOConnectAddRef`. The same lists identify `IOServiceOpen`, `IOObjectRelease`, `mach_port_deallocate`, `mach_msg`, `mach_msg2_internal`, `dlopen`, and `dlsym`. A name census cannot detect synthesized names or calls through pointers returned by helpers. [Audit](triage_evidence/audit_daemon_iokit_retirement.py) [Compressed receipt](triage_evidence/daemon_iokit_retirement_audit.json.zst)

An aligned scan of the original 14,849,960 B `__text` searches for an unshifted `MOVZ X17,#modifier` or `MOVZ W17,#modifier` immediately before `BRAA` or `BLRAA` using X17. The five sites with `0xf00f` are all `BLRAA X8,X17`. Four address-independent IA fixups carry that modifier. Raw chained words establish three rebases within the daemon and one binding to `mach_port_deallocate`. For each tested bank pair, the loader-independent selector `L[i] XOR key` feeds the second lookup, and `i XOR R[L[i] XOR key]` is constant across all 256 values of the source byte. The constant plus the instruction's additive selects an eight-byte table entry. This proves the result under the bank and table inputs in the table. [Audit](triage_evidence/audit_daemon_iokit_retirement.py)

| Call site | Source argument setup | Selected fixup and role |
| --- | --- | --- |
| `0x100090094` | X0 = SP+0x50 B, after staging a stack record. | Original bank roots at `0x1010a7fa0` and `0x1010a59a8` select `0x1010a1110` on the canonical table. The local routine `0x10044ada4` reads u32 at X0+0x1c B and two u64 fields from X0+8 B. |
| `0x100261070` | X0 = SP+0x28 B. The caller stores three u64 fields and a u32 control field before the call, then reads the u32 result at record+0x18 B. | A candidate bank pair at `0x101031da0` and `0x100e99900` also selects `0x1010a1110`. The live definitions of SP+8 B, X23 and X25 remain unknown. |
| `0x100383608` | X0 = SP+0x10 B. The caller subsequently reads record+8 B. | Original bank roots at `0x1010a7a50` and `0x1010a3ba0` select `0x1010a11a0` on the canonical table. The local leaf `0x100418e28` reads u64 at record+0x10 B, transforms it with the record address, then writes u64 at record+8 B at `0x100418ec4`. |
| `0x100494310` | W0 is loaded from task-self storage at `0x1004942f0`. W1 is loaded from the saved incoming peer-name cell at SP+0x9d0 B. | `0x1010a11e0` binds `mach_port_deallocate` on the recovered 41471 handler path. Both run-loop source creation outcomes reach this release. |
| `0x1004ecebc` | X0 = SP+0x10cb8 B. On return the caller reads the u32 at record+0x10 B and compares it with `0x8b3dc651`. | The bank pair at `0x100e99a00` and `0x100f4e390` selects `0x1010a1190` when present in the saved frame. Its target `0x10041ac7c` reads a pointer-sized field and u32 control field through X0. The live bank and table definitions remain unknown. |

The deallocation API takes two u32 Mach names. The four stack-record forms above supply stack addresses in X0. The separately recovered peer cleanup supplies both names in W0 and W1. The peer comes from a port descriptor in the kernel's request 41471. Before release, the daemon uses that peer as the destination of request 51471 at `0x100004428`, while the descriptor in 51471 carries the new receive endpoint with a send-right disposition. The IOKit connection output cell is `0x1010b6384` in the earlier source-selected open path. No demonstrated flow joins that cell to the peer cleanup argument. [Arcade registration and request bytes](created_port_report.md) [IOKit output and releases](daemon_iokit_objects_report.md)

The analogous `0xbe7e` scan yields 12 sites. Four previous joins identify the releases at `0x1001dcab8`, `0x100205980`, `0x100478c2c` and `0x100483cc0` as service or iterator cleanup under their recovered discovery paths. The same modifier also binds `xpc_dictionary_get_data` and is used at `0x100ad12bc` and `0x1008ed748`. Another three sites pass stack-record addresses, and `0x100d659e8` passes a three-argument pattern resembling the dictionary getter. Two remaining sites, `0x1009c3ad0` and `0x100a21dd8`, pass u32(SP+0x2a58 B) + `0xbde79011` modulo 2^32 in W0. Their selected bindings and reaching name definitions remain unknown. The nine direct branches to the separate address-diverse `IOObjectRelease` stub at `0x100e2a940` are all registry-network iterator, service or parent releases. [Discovery releases](daemon_iokit_objects_report.md) [Class retry](daemon_selector26_class_retry_report.md) [XPC payload](daemon_xpc_payload_report.md) [Arcade XPC reply](arcade_reply_report.md) [Registry network identity](daemon_network_identity_report.md)

## Direct sends and dynamic lookup

| Path | Daemon emission site | Destination and message |
| --- | --- | --- |
| Protected callback via `mach_msg` import at `0x1010a1288` | `0x100035184` | The callback sends a MIG reply to the disposition and reply name taken from the admitted incoming message. The verified FairPlay RPC 502 case emits reply 602. |
| Direct branch to `mach_msg2_internal` stub `0x100e2ab00` | `0x100004428` | Request 51471 to the port received from the arcade kernel registration message. |
| Direct branch to `mach_msg` stub `0x100e2aaf0` | `0x100de9fac` | Request ID 1200 comes from u32 at `0x101032d74`. The wrapper takes destination name in entry W0 and pairs it with its MIG reply name at `0x100de9f58`. Caller provenance for the destination remains unknown. |
| Installed IOKit close wrapper | Framework `0x184ec1a44` | Request 2816 to a type-`0x27` connection using COPY_SEND. Reply 2916 is handled before the wrapper deallocates the name at `0x184ec19c8`. No call from the inspected daemon was established. |

The newly indexed 1200 wrapper starts at `0x100de9f08` and is referenced by original rebase `0x1010b1398`. It stages a complex 56 B request with one OOL descriptor, accepts a receive capacity of 64 B, and compares the reply ID with 1300 at `0x100dea00c`. The 56 B complex success path checks the descriptor count and type and the repeated OOL extent, then writes the pointer and u32 extent at `0x100dea0b4` and `0x100dea0b8`. The wrapper and message prepare an addressable service exchange, with service identity unknown until the caller's W0 is traced. The ID alone cannot distinguish services that implement request 1200. [Daemon reply path](daemon_receive_interface_report.md) [Other request 1200 clients](corefp_client_paths_report.md) [Installed close wrapper](live_fairplay_connection_report.md)

Three additional `0x67eb` branch candidates pass through obfuscated adapters. The two explicit bank expressions before `0x1004ad334` resolve to local `0x1004aca80`. The tested incoming bank/table frames at `0x10013ec8c` and `0x1005ec5e8` resolve to local `0x100422bcc` and `0x1004263f4`, respectively. The latter two pass records on the stack and read a record result after return. This census covers immediate branches to the named import stubs and the specified adjacent PAC form. Nonadjacent modifiers, address-derived pointer authentication, direct traps, tail calls through other registers, and later transports of local callees require separate coverage. [Compressed receipt](triage_evidence/daemon_iokit_retirement_audit.json.zst)

The `0x19ad` scan yields five calls and 15 tail branches. The previous CoreKE analysis identifies `0x100de1ab0` as `puts` and two `dlsym` calls at `0x100de1c2c` and `0x100de1d30` that resolve named obfuscated CoreKE exports. The remaining two call sites, `0x100de7a8c` and `0x100de8540`, pass a frame address in X0 and read u32 at frame+4 B after return. Their exact pointer targets remain unknown. The five `0xc052` candidates include known `sysctlbyname` at `0x100de1794` and `dlopen(CoreKE,5)` at `0x100de1b58`. The matched IDA database was unavailable through the current MCP connection, so the auxiliary sites were checked from the original binary and prior reports. No dynamic lookup for a close API was established. [CoreKE interface and export names](rpc502_runtime_report.md)

## Captured deallocations and kernel lifetime

The audit scans all 32 trap records across three RAX traces. Only eight traps include a daemon frame. The baseline ends before the IOKit open. Both the retry and the supplied archive contain 2862 and 2962 on the guest and host. Their 52 B guest reply contains a zero connection name and application status `0xe00002c2` at +48 B. None of these traces shows 2816, 2916, 2865 or 2965. [Capture provenance and output status](daemon_iokit_callsite_capture_report.md) [Archived wire exchange](archived_iokit_open_retirement_report.md)

| Retry trace lines | Guest name | Daemon call | Deallocation boundary |
| --- | --- | --- | --- |
| 15537, 15772, 15902, 16032, 16162 | `0x707` on each call | `0x10044038c` | Within the shared-library bootstrap check-in stack, before IOKit discovery. Repeated numeric names alone do not establish shared kernel object identity. |
| 16276 | `0xc03` | `0x100461cc4` | Inside IOMainPort after the host-to-IOKit main-port acquisition. The separately returned IOKit main name is `0x1f03`. |
| 16356 | `0x2103` | `0x100478c2c` | Service name returned by IteratorNext and used as the destination of 2862. |
| 16365 | `0x2003` | `0x100483cc0` | Iterator name returned by matching services and used as the destination of IteratorNext. |

The archive logs the corresponding service and iterator deallocations at lines 1743 and 1745 for guest names `0x1903` and `0x1803`, respectively. These roles come from the preceding port descriptors and request destinations. The archive lacks daemon frames for those traps. [Archived name lineage](archived_iokit_open_retirement_report.md)

The kernel can retire the type-`0x27` client through the explicit `clientClose` branch, the IOMachPort no-senders callback and `clientDied`, or a task-exit hook that removes the last eligible owner. The installed connection policy invokes a kernel callback for its no-senders path. A successful user-reference deallocation alone does not identify a final kernel send right, a no-senders event, or client termination. To establish the native path, correlate the 2962 descriptor, daemon IPC name and generation, subsequent close or final drop, and the kernel callback on the same connection object. [Connection retirement](live_fairplay_connection_retirement_report.md) [Task owner teardown](live_iokit_task_owner_teardown_report.md)

## Assumption register and checks

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| DR1 | The thin binary identity governs the bindings, source addresses and negative symbol findings. | Rehash the image and its executable section, read LC_UUID, check seven positive imports, and decode original fixup words for selected targets. |
| DR2 | The declared incoming table and banks apply on a selected continuation. This qualifies the protected target assignments. | Evaluate all 256 values at each bank expression and compare raw slot words. For conditionally assigned sites, recover reaching definitions of the bank and table arguments before extending the claim to an entire route. |
| DR3 | Trap arguments and frames belong to the named capture and first matching daemon frame. This qualifies the port-role joins. | Hash each source, reconstruct the relevant guest messages from bytes, compare host IDs and verify the frame return PCs and four-byte name arguments. |
| DR4 | The aligned immediate and branch patterns bound static coverage. The absence of 2816 is scoped to captured traffic. | Seek other pointer and transport forms, then correlate a positive native open with a close, last send-right drop, or owner teardown using the same object identity. |

High impact for identifying service and iterator cleanup independently from a successful connection lifetime. Medium impact for disambiguating targets that share a PAC modifier and locating another direct daemon transport. The significance of the 1200 destination and the native close path depends on the unresolved associations.

The audit uses O(B + F + T + 256K) time and space as an upper bound for B image bytes, F fixups, T trace bytes and K tested bank pairs. It compares original bytes, byte extents, four-byte names, frame arguments, and ABI roles. It does not run the daemon or alter an IDB. QG1 covers factual scope, QG2 the register, QG3 the scoped close and transport coverage, QG4 widths and selector arithmetic, QG5 competing targets and unobserved paths, QG6 original Mach-O and captures, and QG7 impact. [Audit script](triage_evidence/audit_daemon_iokit_retirement.py)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_daemon_iokit_retirement.py \
  "$DAEMON_SLICE" "$ARCHIVED_TRACE" "$BASELINE_TRACE" "$RETRY_TRACE" "$AUDIT_JSON"
```
