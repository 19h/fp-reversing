# Shared-state daemon/CF descriptor callback and invalidation

Original fairplayd initializer/setup components now create and register the
actual CF descriptor/source used by the public run-loop execution. CF invokes
the original daemon callback with that same reference. Original daemon code
calls original CF descriptor lookup/rearm, invalidation, GetMain and Stop bodies;
the callback returns to its original CF caller without replacing its CPU state.
This removes the declared callback-return boundary from the
[preceding public-wrapper investigation](cf_public_runloop_report.md).

The initializer/setup entries and their caller-state joins remain explicit.
They share one private memory epoch with CF and the callback; they do not prove
whole-main startup reachability. POSIX events, runtime/retention, locks, dispatch,
hash/array storage, main/TSD registration and Mach results retain declared lower
contracts. No native daemon, CF, IOKit, thread, file or IPC operation executes.

Six selected SIGTERM-like cases execute original descriptor/source invalidation,
mode removal, GetMain/Stop and original outgoing wake SVC. Five other event
variants return without that path. Source invalidity, detached fields and close
requests are established privately; native handle retirement and a successful
daemon/kext transaction remain unknown. The broader goal remains active.

## Primary evidence and reproduction

Retained records: [source, logical binds and native export identities](triage_evidence/daemon_cf_descriptor_bridge_source.json),
[11 private cases](triage_evidence/daemon_cf_descriptor_bridge_profiles.json),
[independent checks](triage_evidence/daemon_cf_descriptor_bridge_checks.json),
[preservation seal](triage_evidence/daemon_cf_descriptor_bridge_delivery.json),
and [quality gates](triage_evidence/daemon_cf_descriptor_bridge_quality_gates.json).
The [probe](triage_evidence/probe_daemon_cf_descriptor_bridge.py) and
[replay](triage_evidence/replay_daemon_cf_descriptor_bridge.py) implement new
component entries, event/API contracts and cancel-delivery checks separately.
The replay does not import the new probe; frozen loaders/models remain shared.

Daemon thin arm64e SHA-256 is
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`,
UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. Cache UUID is
`2bd06591-e751-3e84-963f-b08dab6af23a`; CF UUID is
`7fe5392e-ff16-31e1-8552-3a45c6b68224`. Nine cache files are freshly hashed.
The capture includes133 complete cache routines and28 inherited stubs,
totaling12348 instructions, plus13 selected daemon static ranges. Every executed
daemon instruction is checked directly against the pinned image, including
continuations outside those13 ranges. Four new16-byte lower stubs, their
original chained pointers and exact owning exports are checked separately.
No new IDA queries or database changes were needed.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_cf_descriptor_bridge.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_cf_descriptor_bridge.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_cf_descriptor_bridge.py
```

The new engine instance uses an explicit150000-instruction cap rather than the
inherited30000 cap; original initializer plus callback exceeds the old cap.
No global parent code is modified. Current dependencies include Unicorn2.1.4,
Capstone5.0.7 and the local arm64e compiler/SDK. Seven direct headers are pinned;
the entire toolchain/transitive SDK is not hashed.

## Assumption register

Execution-derived results depend on BC1-BC8 as applicable. Static identity
depends on BC1; native facts outside the stated bounds remain unknown.

| ID | Assumption / dependent conclusions | Stress test / falsification probe |
| --- | --- | --- |
| BC1 | Pinned images and logically normalized original import chains identify the static pairing. | Recapture bytes, nine hashes, nine CF bind/export pairs, original default-mode addend cancellation and every executed instruction. Hardware authentication/loader selection remain unknown. |
| BC2 | Initializer and setup are entered with explicit typed-state/stack/register fixtures; caller CPU is restored at their declared joins while memory effects persist. | Record full tracked frames, fixture bytes and original returns/boundaries. These are not whole-main control-flow or native caller-reachability proofs. |
| BC3 | Raw heap and CF runtime/hash/retention/array effects satisfy the selected private contracts. | Zero/A5 heap variants,100 record tails/guards, actual registry/source removal and ten altered records. Native allocation, reference counts, retirement and populated-record work remain unknown. |
| BC4 | Warm TSD/main registration maps the actual constructed loop to the declared current/main cells. | Execute original GetMain, GetCurrent/public wrappers and current-mode publication; verify the daemon's Stop argument. Native thread identity and initial registration are not proved. |
| BC5 | Kqueue/signal/kevent, readiness, mutex/once, dispatch and POSIX close/replacement calls have supplied results. | Check original parameters, event variants, registration error, no/error output and close/cancel ordering. Native event feasibility, syscall success and ownership remain unknown. |
| BC6 | Nonpositive-kevent cases have explicit preexisting output bytes; the opaque Mach-object variant supplies an unconstructed CF reference. | Retained-signal/error fixture versus zero-output variants; record the conditional CFMachPortInvalidate request. No native stale-output history or Mach-port retirement is established. |
| BC7 | Cancel requests do not automatically deliver handlers; one variant explicitly invokes their original copied blocks after public return. | Verify actual block44 B, saved source/duplicate captures, original handler code and close11/12 requests. Native scheduling/ordering/completion remain unknown. |
| BC8 | PAC, raw SVC return and other inherited clock/pending-work contracts remain logical/private. | Full tracked CPU/read/write/final RAM replay,16 SDK assertions and ten rejected alterations. No native IPC, hardware PAC, successful FairPlay round trip or whole lifecycle follows. |

## Shared object and control flow

```text
explicit original initializer entry (typed state0x267e)
  -> malloc contract -> original100-record/header writes
explicit original setup component (saved state0x3a74)
  -> kqueue7 -> SIGTERM/kevent change
  -> original descriptor wrapper -> captured CF Create
  -> header+0x50 = actual descriptor
  -> original Enable / SourceCreate / GetMain / AddSource(default) / Release
explicit public CF entry, retaining all setup memory
  -> original source0 scheduler -> descriptor Perform
  -> original fairplayd callback0x10044f23c
     -> actual CF GetNativeDescriptor -> kevent(fd7)
     -> actual CF Enable before event-filter inspection
     -> selected signal15:
        context handling -> actual descriptor/source invalidation/removal
        -> actual GetMain -> actual Stop -> original Wake/-47 SVC
  -> original callback returns to CF0x1847b7e04
  -> original CF/public cleanup and return
optional explicit post-return copied cancel-handler delivery
```

Only initializer/setup joins restore a declared caller CPU frame. The actual
daemon callback uses its incoming CF reference and original return linkage;
no CPU replacement occurs at callback return. Setup's stack/register fixture
and its stop boundary0x100093518 remain explicit rather than being presented
as a recovered whole-main caller. Original CF constructor and source bodies
execute through the logically bound daemon import slots.

| Daemon logical slot | Original symbol | Captured CF target |
| --- | --- | --- |
| `0x1010b1c30` | CFFileDescriptorCreate | `0x1847b566c` |
| `0x1010a1448` | CFFileDescriptorCreateRunLoopSource | `0x1847b5cd0` |
| `0x1010a0798` | CFFileDescriptorEnableCallBacks | `0x1847b607c` |
| `0x10109fea0` | CFFileDescriptorGetNativeDescriptor | `0x1847b802c` |
| `0x1010a0a88` | CFFileDescriptorInvalidate | `0x1847c9690` |
| `0x1010a08f8` | CFRunLoopGetMain | `0x18471bb78` |
| `0x1010a0690` | CFRunLoopStop | `0x184784250` |
| `0x1010a0c08` | CFRunLoopAddSource | `0x18472d934` |
| `0x1010a02e0` | CFRelease | `0x1846e1278` |

These are logical bindings into captured original code, not hardware-authenticated
dyld execution. CFRelease retains its declared primitive contract at that target;
its full runtime body does not execute. The default-mode data import separately
retains its original nonzero addend and original caller cancellation, then reads
the declared default-name cell. Neither addend is silently discarded.

| Original daemon location | Observed role in this epoch |
| --- | --- |
| `0x100437c18` | Initializer entry;100*896 B record arena and shared header |
| `0x10009689c` | Explicit setup component entry |
| `0x100097b60` / `0x100001f2c` | Descriptor creation call / original wrapper |
| `0x10002f0d0` / `0x10002f124` | Read-enable / source creation requests |
| `0x1000934d0` | Actual default-mode AddSource request |
| `0x10044f23c` | Actual CF-dispatched daemon callback entry |
| `0x10044f4d4` / `0x10044f574` | Descriptor lookup / supplied kevent result boundary |
| `0x10044f5ec` | Original reenable request before local event-field branching |
| `0x1003c12a8` / `0x1003c12ec` / `0x1003c132c` | Invalidate / GetMain / Stop requests on selected signal route |
| `0x1847b7e04` | Actual daemon callback return to original CF Perform continuation |

The same identity appears in header+0x50, descriptor Create's return, source
context info+0x70 and callback x0. Descriptor lookup executes its original field
read and supplies7 to the daemon's kevent call. The encoded setup fd at
header+0x48 is a separate32-bit representation, fd+0x060ed969 modulo2^32.

Original initialization writes20 B per896-byte record: word0x4577df49 and16 zero
bytes at offsets876..895. All first876 bytes retain the supplied zero/A5 backing
in these cases. This is2000 B of original tail initialization in an89600-byte
arena; it is not full-record initialization or populated-record processing proof.

## Invalidation, event data and outgoing Mach emission

Original descriptor invalidation changes its state byte from 0 through 1 to 2.
Its original synchronous block requests cancellation of the read and write
dispatch sources, resumes suspended sources where required, clears their stored
references and detaches the cached CF source. With close-on-invalidate set, the
original code requests shutdown(7,2), open("/dev/null",0), dup2(13,7), close(13)
and close(7), then stores signed fd -1. Results 13/7 and successful status are
declared POSIX contracts. These are original call arguments and ordered private
effects; native descriptor replacement/closure is unknown (BC3, BC5).

Original CFRunLoopSourceInvalidate clears validity bit 3, clears timestamp+0x58
and detaches bag+0x60. Original bag application and RemoveSource bodies remove
the source from the registered default-mode source0 set and process the common
mode path. Mode enumeration, one-element array access and hash-storage mutation
remain declared lower contracts derived from the actual private registry. The
source is version 0: there is no source1 getPort call or member-port deletion in
this removal path. Root/timer/wake names 0x607/0x707/0x807 remain members of set
0x507 in the retained model. The source's detached bag storage still exists under
the primitive CFRelease contract; actual reference-count retirement is unknown.

The daemon then calls original GetMain, Stop and Wake code on the actual loop.
GetMain reads the explicitly warm main registration, while public RUN has
published the indexed current mode and depth 1. Stop writes the selected stop
byte and reaches the original wake emitter and lower -47 trap wrapper. Six
original SVC visits carry the existing wake wire contract. SVC results are
supplied; this increment does not execute kernel ingress or establish delivery.
The earlier [kernel wake ingress report](kernel_wake_send_ingress_report.md)
retains separate component/namespace evidence. A CF reference, a POSIX fd and a
Mach name remain distinct values throughout these joins.

The optional opaque-Mach variant supplies header+0x18 with an unconstructed CF
reference and checks the daemon's conditional CFMachPortInvalidate request.
That API remains modeled in this increment: neither its full CF body nor native
Mach right retirement follows. Header+0x50 still holds the descriptor reference
after invalidation; a retained numeric reference alone proves neither a native
leak nor a dangling access.

Cancellation requests and cancellation-handler execution are separate events:

```text
original descriptor invalidation
  -> cancel(read), cancel(write) requests
  -> original fd shutdown/replacement/close requests
  -> source0 removal -> Stop/wake -> callback return -> public return
one explicit post-return delivery fixture only:
  -> original copied read cancel block -> release(source), close(11)
  -> original copied write cancel block -> release(source), close(12)
```

The copied blocks are 44 B, with invoke pointer+0x10, saved source+0x20 and
duplicate fd+0x28. Their original handler bodies execute in the delivery case;
dispatch release and POSIX close remain lower models. Deliveries are explicit
analyst entries after public return, with the public observation CPU restored
afterward. Their order is not a native scheduler observation (BC7).

## Finite cases and ABI distinctions

Each case executes exactly one original daemon callback and returns to original
CF address 0x1847b7e04. The six stop cases enter the public void CFRunLoopRun
wrapper: residual x0=2 is the internal stopped result, not a public return value.
The other cases use the exported specific-mode wrapper with stop-after-handle
true; its result 4 denotes handled source. All values below are conditional on
BC1-BC8, with explicitly supplied event bytes/statuses.

| Case | Original instruction visits | Stop/wake SVC | Final descriptor/source | Close requests |
| --- | ---: | ---: | --- | --- |
| signal15 | 32436 | 1 | invalid / removed | 13,7 |
| other_signal | 26488 | 0 | valid / registered | none |
| process_event | 31894 | 0 | valid / registered | none |
| other_filter | 26471 | 0 | valid / registered | none |
| no_event | 26471 | 0 | valid / registered | none |
| error_event | 26471 | 0 | valid / registered | none |
| retained_signal_on_error | 32436 | 1 | invalid / removed | 13,7 |
| signal15_opaque_mach | 32476 | 1 | invalid / removed | 13,7 |
| signal15_poison | 32436 | 1 | invalid / removed | 13,7 |
| signal15_drain_cancel | 32464 | 1 | invalid / removed | 13,7,11,12 |
| signal15_registration_error | 32436 | 1 | invalid / removed | 13,7 |

Setup requests kevent(7,change,1,NULL,0,NULL), with a 32-byte change record
ident=15/filter=-6/flags=1. The callback requests
kevent(7,NULL,0,output,1,NULL), reads the native descriptor through original CF
code and reenables read callbacks before inspecting event fields. Its process
event route reaches a second Enable request. During callback rearm, declared
pselect readiness is false; no second readiness delivery is implied.

For return 0/-1, the lower kevent model does not write event output. The zero
output fixtures return without stopping. A separately declared preexisting
signal15 output with return -1 takes the stop path: this establishes dependence
on supplied output fields in that component, not a native stale-stack history.
The registration-error case supplies setup result -1 and later event result 1;
its original handling of that setup status does not prove native delivery after
failed registration. The poisoned-heap case verifies untouched record prefixes
and original initialized tails, not populated context processing.

## Independent checks and reproducible bounds

Fresh source capture verifies 133 cache routines, 12348 captured instructions,
nine CF slot/export mappings, 13 daemon static ranges, four new lower stub/export
identities and nine cache-file hashes. Seven SDK headers are hashed and 16
arm64e compiler assertions pass. The independent combined replay checks:

| Measurement | Count |
| --- | ---: |
| Original instruction visits | 332479 |
| Original daemon visits in the CF epochs | 286641 |
| Remaining original CF/library visits | 45838 |
| Complete tracked CPU frames | 6881 |
| Ordered memory reads / bytes read | 47701 / 306674 B |
| Ordered writes and after-images / bytes written | 23324 / 168825 B |
| Daemon/CF identity and component CPU frames | 558 |
| Original callback returns to original CF | 11 |
| Explicit synchronous original block entries and returns | 62 |
| Original invalidation/removal/GetMain/cancel visits | 3292 |
| Original intercepted wake SVC visits | 6 |

Per epoch, CF private memory is 3145728 B and additional daemon mutable regions
total 2441216 B. The disjoint checked final-memory total is therefore
11 * (3145728 + 2441216) B = 61456384 B. Cache-global fixture/journal checks are
additional; this is not a snapshot of every mutable page in the shared cache.
Tracked CPU frames use the retained register set; hardware PAC and native
exception/syscall state are outside that set.

Ten independently altered records are rejected: logical CF binding, callback
instruction, callback-return CPU, GetMain context, kevent output, source invalid
bit, final heap tail, cancel-block capture, setup descriptor reference and main
registration. The replay recomputes ordered lower effects and complete final
regions; shared frozen loaders/models limit independence. Positive finite cases
and rejected alterations establish the specified contracts, not universal paths.

Validation time is O(S + V*F + J + H*R) and space O(S + J + R), where S is pinned
source/capture bytes, V executed visits, F fixed tracked-frame extent, J journal
bytes, H finite case count and R per-case RAM. Publication additionally hashes
all owned artifact bytes and validates report links. Neither stage issues target
operations or changes an IDA database.

## Bounded continuation opportunities

| Impact | Unresolved interface | Concrete falsification or extension |
| --- | --- | --- |
| High | Successful daemon/user-client/kext/deeper-facility transaction | Reconcile existing selectors, Mach RPC and context contracts with a source-pinned successful request/reply trace; the supplied ZUT trace has failed IOServiceOpen and no demonstrated selector26/RPC502/700 exchange. |
| High | Whole-main setup and actual main-loop registration | Recover original callers/state transitions into the two explicit component entries and initial main/TSD registration; compare actual loop identity before event dispatch. |
| High | Populated daemon records and service-object lifecycle | Recover producers/owners of live 896-byte records and the real header+0x18 object, then validate actual record-dependent cleanup and CF Mach invalidation contracts. |
| Medium | Retention, cancellation and concurrent lifetime | Extend primitive CFRelease/hash/dispatch contracts into original destruction and scheduling bodies; distinguish request order, handler delivery and reference retirement. |
| Medium | Event-output validity and setup failure feasibility | Recover producer/syscall semantics for return0/-1, partially written output and registration failure before attributing a native event path. |
| Medium | Native wake send versus receive continuity | Join this emitter to the separately checked kernel receive/delivery and next CF iteration using preserved task/right/queue epochs. |
| Low | Queue readiness and multiple sources | Add write-readiness and competing source0/mode cases while retaining the same actual descriptor and original public context. |

## Quality gates

QG1: Pass for factual technical analysis; no normative conclusion is required.

QG2: Pass for this increment: BC1-BC8 state dependencies and falsification probes.

QG3: Pass for the bounded daemon/CF initializer, descriptor, callback, removal,
Stop/wake and cancellation interfaces. Full interface-goal completion is false.

QG4: Pass: exact byte extents, signed32 fd, u32 encoding, void/result distinction,
SDK assertions, disjoint RAM arithmetic and algorithm bounds are reproducible.

QG5: Pass within scope: separate fixture joins, actual callback return, empty
record tails, setup/event failure cases, cancel requests/deliveries and warm main
identity are explicit. Broader native/lifetime gaps remain unknown.

QG6: Pass: pinned original instructions/imports/exports, fresh capture and hashes,
SDK/compiler checks, independent journals and rejected alterations are retained.

QG7: Pass: bounded high/medium/low continuation opportunities are listed above.
