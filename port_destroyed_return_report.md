# Receive-right return through MACH_NOTIFY_PORT_DESTROYED

The selected launchd check-in path has a statically connected receive-right return mechanism. Launchd registers notification 69 before handing out an endpoint's receive right. Both trap -77 and fallback MIG RPC 3213 reach the kernel notification core. A qualified kernel port-destruction branch consumes the registered backup destination and emits a complex ID69 message carrying the endpoint as a MOVE_RECEIVE descriptor. Launchd's original notification table binds ID69 to a 40 B validator and a PID-zero-gated handler; that handler uses the transferred name to find a record and merges event 69 into its DATA_ADD source. The saved endpoint callback, notification-record cancellation, unlink and eventual free are separate stages. These are original static interfaces, not an observed native return cycle. [Source](triage_evidence/port_destroyed_return_source.json), [checks](triage_evidence/port_destroyed_return_checks.json).

This extends the [check-in handoff](bootstrap_checkin_handoff_report.md), [endpoint construction](launchd_service_endpoint_report.md), [audit-context provenance](launchd_audit_context_report.md) and [kernel notification transport](kernel_notification_send_report.md) reports. It explains endpoint ownership infrastructure relevant to fairplayd lifecycle. It does not establish a direct FairPlayIOKit notification69 call, a successful FairPlay transaction, actual receiver-name identity, or native daemon exit/restart behavior.

## Source identity and coverage

The original `/sbin/launchd` universal SHA-256 is `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`. Slice UUIDs are `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71` and `62af2b7d-327e-334a-a1d7-83777efc3c12`. The kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. The capture records original cache library UUID, exports/nlist, fixups, used-file hashes, SDK headers and inspection-tool identities. Kernel/private analytical roles without original nlist names remain analytical labels. [Identity records](triage_evidence/port_destroyed_return_source.json).

There are 51 complete compiler-bounded bodies, 3179 instructions and 12716 B: 42 launchd bodies, six kernel bodies and three libsystem_kernel bodies. Forty selected launchd words require LLVM decoding, including x1 pointer/authentication instructions. The two slices are separately decoded; hardware PAC, ADDPT and ISA equivalence are not established [PR6]. No recovered target operation, IPC send/receive, port teardown, emulation, IDB mutation or service mutation ran. Static inspection tools, scalar checks and SDK compilation ran.

## Static sequence and ownership boundaries

```text
launchd endpoint activation
  -> retain a send name with MAKE_SEND20
  -> register notification69, sync0, destination global 0x10008af20
       -> fast trap -77 or conditional MIG3213 fallback
       -> kernel core -> backup destination field
  -> prior check-in path hands out MOVE_RECEIVE16

qualified kernel port-destruction branch
  -> take/clear backup destination
  -> notification69: MOVE_SEND_ONCE18 destination + MOVE_RECEIVE16 endpoint
  -> common kernel message transport
  -> user ABI: 40 B complex notification

launchd raw dispatcher -> notification MIG table -> ID69 validator
  -> current audit PID word == 0
  -> lookup transferred task-local name, record kind1
  -> dispatch_source_merge_data(source,69)
  -> event block -> saved endpoint-reset block -> endpoint callback(reason1)
  -> cancel source -> unlink record
  -> later cancel block: conditional name deallocation, release source, free record
```

The diagram is conditional on matching object/registration and callback epochs [PR1-PR5]. A task-local name is not a kernel-object address or a cross-task identity. The MAKE_SEND operation supplies a static reason for retaining a name while the receive right is elsewhere; whether copyout returns the same numeric name in a native IPC space remains unknown [PR2].

## Recovered launchd roles

| Analytical role | arm64e start | arm64e.x1 start |
|---|---|---|
| Notification69 setup | `0x100045bec` | `0x100044f10` |
| Notification table initializer | `0x100045a14` | `0x100044d44` |
| Notification demultiplexer | `0x100049a7c` | `0x100048ca4` |
| ID69 MIG validator | `0x1000498bc` | `0x100048ae4` |
| PID-gated ID69 application handler | `0x1000458e4` | `0x100044c14` |
| Name/kind record lookup | `0x10005c56c` | `0x10005b548` |
| Record insertion | `0x100045f1c` | `0x100045228` |
| Record unlink | `0x10005c6e8` | `0x10005b6b8` |
| DATA_ADD event block | `0x100045de0` | `0x100045104` |
| Mandatory cancellation block | `0x100045e60` | `0x100045178` |
| Explicit record cancellation | `0x100045fa0` | `0x1000452ac` |
| Endpoint cancellation caller | `0x100047908` | `0x100046ba8` |
| Endpoint-reset block | `0x100047838` | `0x100046ae4` |
| Strict-guard attribute assertion | `0x10000cf4c` | `0x10000cda8` |
| Optional receive drain | `0x10005ced8` | `0x10005bea8` |

The allocator helper at `0x100013fb0` / `0x100013ca4` binds `_malloc_type_calloc` with count1 and the requested extent. Setup requests 48 B. This supports initially zero record fields under the original allocator contract, rather than assuming byte+0x29 was explicitly initialized by setup. [Bodies and authenticated API bindings](triage_evidence/port_destroyed_return_source.json).

## Registration ABI and kernel backup field

Setup accepts notification kind69 only, creates a DATA_ADD source with handle0/mask0 on the queue pointer at `0x10008b160`, installs the record as context, captures the saved endpoint block and source in an event block, installs a mandatory cancellation block, then activates the source. The original chained import at `0x100086cf8` is `__dispatch_source_type_data_add`; this source is distinct from the raw Mach ingress channel.

The `mach_port_request_notification` call receives task-self, watched name, msgid69, sync0, notification destination from `0x10008af20`, disposition21 when that destination is nonzero and18 otherwise, plus an initialized previous-right output. Setup deallocates a nonzero previous output. Both MAKE_SEND insertion failure and previous-right deallocation failure have diagnostic/continuation paths. Setup retains the request-notification status while still storing/inserting the record; the activation caller's diagnostic/continuation behavior was established in the handoff report. Registration success cannot be inferred from record existence alone [PR1].

| Registration layer | Original location / value | Established contract |
|---|---|---|
| Launchd notification request | arm64e call `0x100045d64` | Seven API arguments; notification69/sync0 |
| Cached public wrapper | `0x180549b18` | First calls trap wrapper; falls back only on `0x10000003` |
| Cached trap wrapper | `0x180547ccc` | X16=-77, SVC0x80 |
| Original trap-table slot77 | `0xfffffe0007efb750` | Seven arguments; handler `0xfffffe000bcdc050` |
| Trap handler core call | `0xfffffe000bcdc128` | Calls common core `0xfffffe000bcdf1ec` |
| Cached fallback MIG routine | `0x18054bd00` | Request3213, user request60 B; successful descriptor reply40 B |
| Original MIG registry | subsystem `[3200,3243)`, row3213 | Stub `0xfffffe000bd888d0`, internal request72 B, internal success reply52 B |
| MIG stub core call | `0xfffffe000bd889bc` | Calls the same core |
| Notification69 core branch | `0xfffffe000bcdf25c` onward | Requires sync0; resolves watched receive name; admission/policy helpers precede store |
| Ordinary backup store | `0xfffffe000bcdf46c` | Store authenticated notification destination at port+0x60 |
| Extended-layout backup store | `0xfffffe000bcdf498` | Auxiliary object+0x10, selected by the port flag |

Internal kernel ABI extents differ from user ABI extents because header/descriptor representations differ. They must not be treated as inconsistent packet sizes. The selected core's success path writes previous output0. Its backup-admission helper has a branch returning5 for an already occupied ordinary/extended backup field; the complete helper also has object-kind and policy-dependent branches. This is not a general claim that every notification kind replaces an old request, or that every port class uses a direct+0x60 field [PR1,PR3].

## Kernel ID69 emission and user packet mapping

The compiler-bounded port-destruction routine starts at `0xfffffe000bccdbb4`. Its ordinary-layout path authenticates the pointer at port+0x60 into X26 and writes authenticated NULL back. The extended-layout branch uses that field as an auxiliary pointer and extracts its+0x10 member. Backup presence, active state and additional object/control gates precede the selected sender branch; no claim is made that every port destruction emits ID69.

| Field / operation | Original location | Recovered value |
|---|---|---|
| Ordinary backup extraction/clear | `0xfffffe000bccdc64` .. `0xfffffe000bccdc8c` | Port+0x60, PAC data tag0x78bc, X26 destination, then NULL |
| Receive-object descriptor | `0xfffffe000bcce128` .. `0xfffffe000bcce150` | Port X20 at internal message+36, authenticated tag0x1ab; disposition16/type0 tail |
| Header disposition/complex bit | `0xfffffe000bcce154` .. `0xfffffe000bcce160` | `0x80000012`; backup destination X26 at internal+8 |
| ID/count literal | `0xfffffe000700dcb0`, loaded at `0xfffffe000bcce168` | `4500000001000000`: ID69 and descriptor count1 |
| Kernel send call | `0xfffffe000bcce188` | Common helper `0xfffffe000bcf55dc`; extent52 B, options0x50001, remaining arguments0/NULL |
| User notification body | SDK and launchd validator | Header24 B, count4 B, port descriptor12 B; extent40 B excluding trailer |

Pre-preparation `msgh_size` is zero in the stack construction; the send helper receives explicit extent52. The [common notification transport](kernel_notification_send_report.md) establishes the separate preparation/normalization boundary. The user packet has complex bit set, count1, MOVE_RECEIVE16/type0, transferred name at+28. Reply/local and voucher fields are initialized NULL in this sender. The generated MIG reply structure (nominal ID169,36 B) does not establish an actual request/reply transaction for this one-way notification [PR2,PR5]. No unique-producer census or actual send success is claimed.

## Launchd receiver, PID gate and record dispatch

Both slice metadata headers at `0x1000835c0` declare notification subsystem `[64,73)` and max reply36 B. Nine 40 B rows have nonnull stubs for IDs65,69,70,71,72; rows64,66,67,68 are holes. The initializer places this demultiplexer in the first raw callback slot. The demultiplexer checks the unsigned range and loads a stub through `8 + 40*(ID-64)`; a full u32-domain scalar proof verifies that index expression and range. A missing/out-of-range stub produces MIG_BAD_ID (-303).

The ID69 validator checks complex bit, count1, exact user extent40 and MOVE_RECEIVE16/type0. It passes header local name+12 as argument0 and transferred descriptor name+28 as argument1. The application handler ignores argument0, rejects a nonzero current global PID word at `0x10008b41c` with status5, then looks up argument1 with kind1. The prior [audit report](launchd_audit_context_report.md) names this PID word through original libbsm accessors and identifies raw/XPC writers. PID0 is a static gate, not independent proof of kernel sender authenticity; metadata fallback, carrier validity and intervening-writer questions remain separate [PR4].

An existing record yields `dispatch_source_merge_data(record.source,69)`; a missing record returns0 without merging. The record is not keyed by header local-name argument0. DATA_ADD merge can coalesce pending data according to dispatch's contract; this report does not prove one callback per notification.

| Record offset, B | Width, B | Established use |
|---|---|---|
| +0 | 8 | Forward link |
| +8 | 8 | Backlink / head-cell pointer |
| +16 | 4 | Exact watched task-local name |
| +24 | 8 | DATA_ADD source pointer |
| +40 | 1 | Lookup kind, initialized1 |
| +41 | 1 | Bit0 set by explicit cancellation; suppresses cancellation-time name deallocation |

Insertion/lookup hash the little-endian u32 name from seed5381, applying `h=33*h+b` for at most four bytes and stopping before the first zero byte. The reciprocal arithmetic computes `h mod53`; buckets start at `0x10008b438`. A bound certificate covers all four-byte hash values, and 65543 finite name inputs independently match integer division/remainder. Lookup then compares both complete u32 name and kind; hash collisions do not establish endpoint equality. Insertion is O(1), lookup O(k) for bucket-chain length k, unlink O(1); hashing uses O(1) time/space. No table collision or runtime input distribution conclusion is drawn.

## Callback, guard and cleanup epochs

The event block obtains its record through `dispatch_get_context`, checks source-pointer equality, invokes the captured endpoint block, cancels the source and tail-calls record unlink. The later mandatory cancel block rechecks the source pointer, conditionally deallocates the watched name, releases the source and frees the record. Unlink writes -1 link sentinels and has a double-unlink diagnostic. Ordering through callback scheduling and absence of intervening cancellation remain explicit premises [PR3,PR5].

Explicit cancellation is a separate path: lookup(name,1), cancel source, set record byte+41 bit0, unlink. Its original endpoint caller is recovered at `0x100047908` / `0x100046ba8`. The cancellation callback tests that bit: clear calls `mach_port_deallocate`; set logs and skips that call. There is exactly one STRB-immediate+0x29 writer candidate in the bounded text locator per slice, but aliases, wider stores and indirect writers are outside that census. The flag denotes an observed cleanup branch; it is not a notification-received flag.

The endpoint-reset block's bit4-clear branch obtains the service name, passes saved context endpoint+0x70 to a helper, then calls `mach_port_set_attributes(task,name,MACH_PORT_TEMPOWNER,NULL,0)`. The helper calls `mach_port_assert_attributes` with MACH_PORT_GUARD_INFO8, context extent8 B/count2; a nonzero result reaches BRK1. The SDK describes strict-guard assertion and reassignment intent for these flavors. This is an assertion of existing guard attributes, not a recovered operation that installs/restores the guard. Native guard state remains unknown [PR3]. The bit4-set branch clears endpoint+0x68 and schedules a captured asynchronous block; its deeper job body is not recovered here.

The shared suffix clears endpoint flag bit0 and sets bit6. If the old bit8 was set, it calls the receive-drain helper and rereads/clears bit8. It then tail-calls endpoint+0x90 with X0=endpoint, W1=1, X2=cookie from+0x98. The ordinary Mach-source receive callback used W1=0 in the endpoint report. The scalar suffix proof assumes helpers do not change unrelated flag bits [PR5]; actual callback/job semantics remain unknown.

The drain helper at `0x10005ced8` / `0x10005bea8` issues `_mach_msg` with options0x102=MACH_RCV_MSG|MACH_RCV_TIMEOUT, send size0, receive size32 B, endpoint receive name, timeout0 and notify0. It stops on MACH_RCV_TIMED_OUT0x10004003 or after at most20 attempts. On success it logs the received ID and calls `_mach_msg_destroy`. This is an incoming drain site, not an outgoing-message emission. Extent32 is receive capacity; it does not assert every queued packet has that size or establish native queue effects [PR2,PR5].

## Assumption register and falsification probes

| ID | Assumption / dependent result | Static stress test / falsification probe | Remaining boundary |
|---|---|---|---|
| PR1 | Selected activation, registration and port-destruction epochs refer to one admitted endpoint | Follow original status branches, core/store linkage, direct/extended fields and port-kind/policy branches; failed setup still inserts a record | Native registration/admission and same-object history unknown |
| PR2 | Transferred receive right resolves to the watched launchd name | Distinguish kernel object pointer, destination right, user descriptor name and lookup key; check retained MAKE_SEND path and user/internal layouts | Native namespace coalescing/name identity and right balance unknown |
| PR3 | Record/source/endpoint objects remain live through callbacks | Check calloc contract, pointer assertions, cancel/unlink/free separation, byte41 producer and guard assertion | Queue synchronization, races, native ownership and guard state unknown |
| PR4 | Current global PID belongs to the notification at the handler read | Reuse both original token writers and field accessor; check exact PID0 branch and ignored local-name argument | Authenticity, carrier/trailer validity, aliases and intervening writes unknown |
| PR5 | Relevant flags/registration have no intervening callback mutation | Preserve exact instruction/call order, separate event/cancel/async stages, condition the flag proof | Native ordering, helper effects and deeper job callback unknown |
| PR6 | Captured versions/selected bodies are applicable to the investigated environment | Pin original hashes/UUIDs, decode both slices, independently compare 4894 fixups and SDK layouts | Runtime slice, cross-version behavior, hardware PAC/ADDPT unknown |

## Bounded continuation context

| Impact | Interface question | Established anchor / bounded next analysis |
|---|---|---|
| High | Receive right returns under the original watched name | Join the descriptor copyout namespace logic to the retained-send entry; static object/name provenance remains separate from actual runtime identity |
| High | Service guard state across handoff and return | Trace the service-port move/guard implementation through backup extraction and copyout; distinguish assertion from installation |
| High | Return causes fairplayd relaunch / readiness | Follow saved endpoint callback+0x90 and bit4 asynchronous block through job lifecycle; no relaunch result inferred from reason1 |
| Medium | Registration/cancel balance | Join endpoint explicit cancellation to kernel backup-request cancellation and send-once cleanup paths |
| Medium | Sender/epoch provenance | Complete raw-notification channel wiring and shared audit-token lifetime; PID0 alone is insufficient evidence |
| Low | Notification kind coverage | Extend table-row analysis to65/70/71/72 without conflating their payloads or cleanup branches |

## Validation and quality gates

Original source recapture matches the saved capture. Validation passes 246 selected instruction assertions, 28 SDK assertions in one arm64 compilation, two full-domain scalar proofs, a bounded reciprocal certificate, 65543 finite name-hash inputs and six rejected evidence alterations. Both slices' 4894 fixups are independently compared with dyld_info. All 3179 instruction bytes are contiguous and agree with their recorded decode; the selected LLVM-only words remain explicit. [Recovery](triage_evidence/recover_port_destroyed_return.py), [validator](triage_evidence/validate_port_destroyed_return.py), [delivery](triage_evidence/port_destroyed_return_delivery.json), [quality gates](triage_evidence/port_destroyed_return_quality_gates.json).

QG1: Descriptive static interface analysis; no normative premise required.

QG2: PR1-PR6 list assumptions, dependent claims, falsification probes and unknowns.

QG3: Registration, emission, incoming names, routine roles, control/data flow and bounded continuation are reported for the selected path. The full investigation remains active.

QG4: Byte/bit widths, user/internal extents, SDK layouts, hash bound and scalar domains are explicit; static algorithms state complexity.

QG5: Direct/extended backup layouts, failed-registration continuation, PID0 versus authenticity, incoming drain versus send, notification versus explicit cancellation, guard assertion versus installation, and callback epochs remain distinct.

QG6: Claims use original pinned binaries/fixups, original cache symbols, installed primary SDK headers, recapture and checked instruction/layout evidence; no private role is promoted to an unverified original symbol.

QG7: Continuation questions have bounded scope and impact labels. No native notification, identity, guard-state or FairPlay-success conclusion is asserted.
