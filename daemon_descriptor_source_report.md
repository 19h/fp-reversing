# fairplayd descriptor event source, shutdown and CF wake linkage

Original daemon instructions connect a kqueue descriptor to a CFFileDescriptor,
SIGTERM registration, the main run loop's default mode and callback
`0x10044f23c`. The callback has separate signal and process-event paths. In the
selected SIGTERM path it conditionally invalidates the object stored in the
first Mach-service CF cell, enters shared-context handling, invalidates the
descriptor wrapper and requests main-run-loop stop. These are local call/data
contracts under explicit private entry, API, event and context premises.

The named daemon Stop import matches the captured CoreFoundation Stop export.
Separate original CF execution shows its current-mode gate: with a non-NULL
current mode it writes the indexed stop byte and tail-calls WakeUp; without a
current mode it unlocks and returns without wake emission. The active private
case reaches the original outgoing mach_msg call and intercepted Mach -47 SVC.
The daemon and CF component states are separate; this is not a native or
continuous daemon-to-CF exception/IPC crossing.

Additional established boundaries concern output validity and initialization:
registration kevent status is unused in the selected setup continuation;
callback kevent return count does not gate the subsequent local event-field
read; and the context initializer writes only 20 bytes per 896-byte record.
Explicit zero/nonzero backing and event-output fixtures discriminate these
contracts without asserting native failure feasibility, stale-output history,
ownership, successful FairPlay processing or whole-startup reachability.
The broader investigation remains active.

## Primary evidence and reproduction

Retained records: [source and original binds](triage_evidence/daemon_descriptor_source_source.json),
[private executions](triage_evidence/daemon_descriptor_source_profiles.json),
[independent checks](triage_evidence/daemon_descriptor_source_checks.json),
[IDA byte/locator readback](triage_evidence/daemon_descriptor_source_ida.json),
[preservation seal](triage_evidence/daemon_descriptor_source_delivery.json) and
[quality gates](triage_evidence/daemon_descriptor_source_quality_gates.json).
The [probe](triage_evidence/probe_daemon_descriptor_source.py) and
[independent replay](triage_evidence/replay_daemon_descriptor_source.py) implement
new external contracts separately. The replay does not import the new probe;
both use the previously frozen original-image loader and fresh Unicorn CPUs.

Daemon addresses refer to original thin arm64e SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`,
UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. The capture pins 13 selected original
ranges / 973 instructions, including the complete compiler interval of the
244-instruction callback entry body, the nine-instruction descriptor wrapper and
its four-instruction import stub. The callback's logical routes extend into
other original continuation intervals; the 244 instructions alone are not the
whole logical callback. All executed instructions, including continuations,
are independently checked against the original image.

The selected CF Stop body is 53 original instructions at `0x184784250`, matched
to the previous cache capture and current named export. Nine cache files are
freshly hashed. Cache UUID `2bd06591-e751-3e84-963f-b08dab6af23a` and CF UUID
`7fe5392e-ff16-31e1-8552-3a45c6b68224` identify this static pairing; native loader
selection and slides remain unknown. Prior CF constructor/member/kernel-return
oracles remain explicitly imported component inputs.

Original references did not identify the logical descriptor caller routes, so
read-only IDA queries supplied locators. An initially ambiguous selection was
resolved with an explicit target; IDA reports database `fairplayd`, short hash
`6b117c693e3b`. Four requested ranges, totaling 1600 B, match the original daemon
file exactly. This is selected-byte agreement, not whole-IDB equivalence.
Decompiler output with inherited registers, apparent 61-argument continuation
prototypes, a one-argument callback rendering, and analysis diagnostics is not
used as the actual ABI or as native execution evidence. No database mutation
is performed by this investigation.

Run from `/Users/___/dev/dylex/extracted`:

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_descriptor_source.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_descriptor_source.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_descriptor_source.py
```

The validator compiles inline ABI assertions against three pinned local SDK
headers and runs z3 with a 30 s limit per local proof. It executes no host daemon,
signal, kevent, CF, IOKit or Mach operation.

## Assumption register

Original byte/table results depend on DS1 and exact query scope. Execution
results depend on DS1-DS8; SDK names/layouts additionally use the pinned headers.
These premises do not establish native endpoint, descriptor or thread identity.

| ID | Explicit premise / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| DS1 | Pinned daemon/cache/SDK bytes identify these analyzed implementations. Effective native pairing is unknown. | Rehash inputs, recapture ranges/binds/export, check 1600 IDA bytes and nine cache hashes; reject changed source identities. |
| DS2 | Original initializer entry uses a declared canonical record state0x267e; setup enters a continuation with inherited state0x3a74 and explicit pointer/register/stack cells. Whole-startup admission is unknown. | Retain every entry patch, all GPR/SP/NZCV/SIMD state and complete mutable-memory copies; prove signed descriptor admission locally; do not treat a fragment as a standalone function. |
| DS3 | pthread_once returns0 without executing initializer0x10040ebd4; rwlock and stack-probe effects are declared. Native initialization, locks and concurrency are unknown. | Check every original call tuple and before/after CPU; special stack probing preserves all registers while other API models clobber volatile registers. Actual once/lock lifecycle needs separate recovery. |
| DS4 | malloc supplies 89600 B of raw private backing, initially zero or0xa5. Ownership and native allocation history are unknown. | Execute original initialization, verify exact 2000-byte write footprint and all untouched bytes; compare SIGTERM/process paths and complete final CPU across both fills. |
| DS5 | Descriptor, signal and CF APIs return declared scalar/object results; opaque CF references are distinct from int32 descriptors and Mach names. | Test descriptor7/0/-1, NULL wrapper/source and registration error; validate all relevant argument widths/bytes, publication fields and release/invalidation requests. Native FD closure and CF destruction are not executed. |
| DS6 | Callback event records and output preservation on zero/error results are explicit fixtures. Native event generation and prior stack contents are unknown. | Test signal15/other signal/process/other filter/empty/error/explicit preexisting output; verify original event reads and absence of original prequery initialization. No native uninitialized-memory consequence is inferred. |
| DS7 | Separate CF factory/wait/Stop cases use declared entry and current-mode publication at runloop+0xa60. API name/bind/export agreement does not identify the daemon's native CF object. | Test dormant, waiting-without-mode and waiting-with-mode states; execute original mode test/stop-byte store/wake/wrapper, check full CPU/RAM and intercepted SVC; reject altered mode/flag records. |
| DS8 | Original chained imports/rebases are logically normalized; PAC is interpreted logically and lower SVC results remain supplied. | Verify raw binds, all256 selector inputs, nonzero-addend cancellation, original bytes/branches and complete journals. Native authentication, Mach IPC and scheduler effects remain unknown. |

## Interface and event sequence [DS1-DS8]

```text
original context initializer 0x100437c18
  -> declared once/lock/malloc -> original100-record metadata initialization
       |
       | complete private state copy + explicit inherited setup entry
       v
original kqueue call 0x1000968f4
  -> encoded int32 descriptor at global header+0x48
  -> signal(SIGTERM,SIG_IGN)
  -> kevent(change={ident15,filter-6,flags1})
  -> wrapper0x100001f2c -> CFFileDescriptorCreate(callback0x10044f23c)
  -> CF reference at global header+0x50
  -> enable read1 -> create source -> GetMain -> AddSource(default) -> Release
       |
       | explicit callback entry; no native event/source dispatch
       v
original callback0x10044f23c
  -> GetNativeDescriptor -> kevent(output32,capacity1) -> enable read1
  -> filter/ident dispatch
       +-- signal15: optional first-service invalidation -> context handling
       |      -> descriptor invalidation -> GetMain -> Stop
       +-- process: second read enable -> context handling, no tested loop stop
       +-- other selected records: original return

named Stop bind/export pairing, separate private CF state
  CFRunLoopStop -> current mode NULL? return
               -> current mode non-NULL: indexed stop byte1
                    -> WakeUp -> original mach_msg -> intercepted SVC
```

The [five-service registration report](daemon_registration_report.md) maps header
`0x1010c4cd8`+0x18 to the unfreed CF-object cell. That establishes which stored
cell the selected callback reads; the nonzero object value in callback tests is
an explicit fixture. Five-service native registration, effective object history,
CF event delivery and the complete enclosing startup route remain separate.

## Original routine and emission locations

| Original location | Evidence-backed role in the selected paths |
| --- | --- |
| `0x100437c18` | Shared-context preparation; modeled once/locks/malloc followed by original record metadata stores |
| `0x10009689c` / call `0x1000968f4` | Inherited setup fragment; kqueue call, encoded descriptor publication, signed admission |
| `0x100097a74` | Original signal request: number15, handler1/SIG_IGN |
| `0x100097b08` | Original kevent registration: one32-byte change, no event output |
| `0x100097b60` | Original call of descriptor wrapper with descriptor and close-on-invalidate1 |
| `0x100001f2c` | Original wrapper: allocatorNULL, descriptor, Boolean close flag, signed callback literal, contextNULL |
| `0x100001f4c` / `0x100e2a8c0` | Tail branch and original authenticated import stub for CFFileDescriptorCreate |
| `0x100097b64` | Store returned CFFileDescriptorRef in header+0x50 before checking NULL |
| `0x10002f0d0` / `0x10002f124` | Enable read callbacks; create CF run-loop source with allocatorNULL/order0 |
| `0x10009342c` / `0x1000934d0` | Get main loop; AddSource with the default-mode object |
| `0x100093514` | Release the local source reference after AddSource |
| `0x10044f23c` | Descriptor callback entry; SDK signature has three arguments, though selected code consumes only the reference |
| `0x10044f4d4` / `0x10044f574` | Get native descriptor; kevent with no changes and one32-byte output slot |
| `0x10044f5ec` | Re-enable read callbacks before local event filter dispatch |
| `0x1001f4d0c` | Conditional CFMachPortInvalidate using the first stored service CF reference |
| `0x1002656cc` | Additional read-callback re-enablement on the tested process-event route |
| `0x1003c12a8` / `0x1003c132c` | Descriptor invalidation and main-run-loop stop requests on selected SIGTERM route |
| `0x184784250` | Captured CFRunLoopStop export; original current-mode/stop-byte/wake logic |
| `0x1847842c0` / `0x1847842e8` | Indexed stop-byte store and tail branch to CFRunLoopWakeUp |
| `0x18473af30` / `0x180547c1c` | Original outgoing mach_msg call and intercepted signed Mach -47 SVC in the active CF case |

The run-loop Stop call is void. Remaining X0 values at a callback return are not
interpreted as operation status. Descriptor7 in the fixtures is a BSD int32
file descriptor, not Mach name7 or a kernel port pointer.

## Record, event and binding contracts [DS1-DS8]

| Object / offset | Width | Established representation |
| --- | ---: | --- |
| Header+0 | 8 B | Returned raw record-buffer pointer |
| Header+8 | 8 B | Selected count/capacity value100 |
| Header+0x18 | 8 B | First stored service CF reference; registration maps this cell to unfreed |
| Header+0x48 | 4 B | Descriptor bits plus0x060ed969 modulo2^32 |
| Header+0x50 | 8 B | CFFileDescriptorRef, stored before NULL-result check |
| Slot+0x36c | 4 B | Initial word0x4577df49; semantic meaning unresolved |
| Slot+0x370 | 8 B | Initial zero |
| Slot+0x378 | 8 B | Initial zero |

The selected allocation is89600 B =100*896 B. Original initialization writes
exactly2000 B =100*20 B, the contiguous tail[876,896) of each slot. Initial
payload bytes[0,876) remain unchanged in both zero and0xa5 backing cases. The
selected SIGTERM/process paths and complete final CPU state agree across both
fills; this establishes independence for those empty initialized-slot paths,
not arbitrary populated-slot semantics. No full native slot type is recovered.

Three full32-bit-domain local SMT proofs establish:

```text
kqueue-result store: encoded32 = descriptor32 + 0x060ed969 (mod 2^32)
callback argument:   recovered32 = descriptor32
setup admission:     signed descriptor32 >= 0, under declared control0x3a74
```

The actual original expressions, not just these reduced formulas, are retained
as proof queries. Descriptor0 is admitted in the private setup case; -1 stops
before signal registration and CF creation. This does not establish validity
of every nonnegative native descriptor.

The SDK callback type is
`void (*)(CFFileDescriptorRef, CFOptionFlags, void *)`. The original wrapper
passes allocatorNULL, int32 descriptor, close-on-invalidate1, callback literal
`0x10044f23c` and contextNULL. Creation of the CF source itself remains a lower
API model; its native source object/version, dispatch-source/block production,
notification delivery and CF retention are not executed here.

| 32-byte kevent offset | Width | Setup change / selected callback meaning |
| --- | ---: | --- |
| 0 | 8 B | Setup ident15; callback ident interpreted after filter dispatch |
| 8 | 2 B signed | Setup-6/EVFILT_SIGNAL; tested process filter-5/EVFILT_PROC |
| 10 | 2 B | Setup EV_ADD=1 |
| 12 | 4 B | Setup fflags0; callback fixtures supply0 |
| 16 | 8 B | Setup data0; callback fixtures supply0 |
| 24 | 8 B | Setup udataNULL; callback fixtures supplyNULL |

The local arm64e SDK compile checks size32, alignment4, all five nonzero field
offsets, SIGTERM15, filter constants-6/-5, EV_ADD1, read-callback mask1,
CFFileDescriptorContext size40 and CFOptionFlags size8:14 assertions. The signal
header defines SIG_IGN as handler value1. Exact target-source revision
compatibility is not asserted from this installed SDK alone.

Original setup kevent arguments are `(fd,change32,1,NULL,0,NULL)`. Callback
arguments are `(fd,NULL,0,event32,1,NULL)`. After callback kevent returns, the
original code re-enables read callbacks and loads the signed filter. No original
store initializes this output slot before the query in the tested callback
paths. The modeled zero/error cases leave the explicitly zero-seeded record
unchanged and return through the nonmatching path. A separately initialized
signal15 record with declared result0 still takes the SIGTERM path. This is a
local output-validity dependency under an explicit fixture, not a native
stack-history or error-consequence observation.

The setup case with declared registration result-1 has identical original
instruction sequence, complete final mutable memory and final CPU to result0.
Its selected caller does not branch on that result before descriptor creation.
The requested signal-handler return is also supplied; actual signal disposition
and kernel registration remain unknown.

The default-mode data lookup uses a nonzero chained-import addend. The original
arithmetic adds signed `-0x7ed8f1f2`, canceling import addend`+0x7ed8f1f2` before
the pointer-cell read. Omitting that addend would misidentify the mode lookup.
The source capture retains the exact slot, raw word, import record, arithmetic
and resolved logical cell. Eleven selected daemon binds plus the separate Stop
bind are checked; nine selector banks are exhaustive over256 input bytes each.

| Selected bind | Original slot | Import-table addend |
| --- | --- | ---: |
| `_CFFileDescriptorGetNativeDescriptor` | `0x10109fea0` | 0 |
| `_CFRelease` | `0x1010a02e0` | 0 |
| `_CFFileDescriptorEnableCallBacks` | `0x1010a0798` | 0 |
| `_CFRunLoopGetMain` | `0x1010a08f8` | 0 |
| `_CFFileDescriptorInvalidate` | `0x1010a0a88` | 0 |
| `_CFRunLoopAddSource` | `0x1010a0c08` | 0 |
| `_kevent` | `0x1010a0f20` | 0 |
| `_signal` | `0x1010a1198` | 0 |
| `_CFFileDescriptorCreateRunLoopSource` | `0x1010a1448` | 0 |
| `_kqueue` | `0x1010a17c0` | 0 |
| `_CFFileDescriptorCreate` | `0x1010b1c30` | 0 |
| `_kCFRunLoopDefaultMode` | `0x1010a7f60` | 2128146930 |
| `_CFRunLoopStop` | `0x1010a0690` | 0 |

## Private cases, failure boundaries and independent checks

| Case | Original visits | Selected outcome |
| --- | ---: | --- |
| context_initializer | 22292 | Original metadata initialization; modeled once/lock/malloc |
| context_initializer_poison | 22292 | Same initialization with0xa5 backing |
| setup_fd7 | 307 | Register signal, create/publish wrapper and add default-mode source |
| setup_fd0 | 307 | Descriptor0 admitted |
| setup_negative_fd | 47 | Original failure-continuation boundary before signal/CF calls |
| setup_null_CF | 159 | NULL wrapper remains stored; no source creation |
| setup_null_source | 242 | Release request for wrapper; no source insertion |
| setup_kevent_error | 307 | Same final state/path as setup_fd7 despite supplied error |
| setup_poison | 307 | Setup from poisoned-allocation initializer |
| signal15 | 5214 | Conditional first-service invalidation, descriptor invalidation and loop stop |
| signal15_no_mach | 5174 | No first-service invalidation; descriptor invalidation/stop remain |
| other_signal | 355 | Re-enable read callback, return |
| process_event | 5599 | Second read enable, shared context, no tested loop stop |
| other_filter | 338 | Re-enable read callback, return |
| empty_event | 338 | Zero-seeded output, return |
| error_event | 338 | Zero-seeded output, return |
| empty_with_declared_output | 5214 | Explicit preexisting signal15 output selects shutdown despite result0 |
| signal15_poison | 5214 | Same original path/final CPU as signal15 |
| process_event_poison | 5599 | Same original path/final CPU as process_event |
| CF_Stop_dormant | 1139 | Current modeNULL; stop byte0, no WakeUp/SVC |
| CF_Stop_waiting_without_mode | 1338 | Waiting fixture/current modeNULL; no WakeUp/SVC |
| CF_Stop_waiting_active_mode | 1589 | Current mode supplied; stop byte1, one original wake/SVC |

The NULL-source path requests CFRelease on the wrapper but leaves the stored
header+0x50 value present at the retained boundary. The selected SIGTERM path
also leaves that field present after its CFFileDescriptorInvalidate request.
The native retain count, object destruction, descriptor-close result, later
field clearing and caller behavior after failure remain unknown.

Original CF Stop validates type43 and the selected initialization/diagnostic
flags, locks runloop+0x10 and reads current mode at+0xa60. If non-NULL, it reads
the index byte at+0x54, writes1 to+0x55+index, unlocks and tail-branches to WakeUp.
The tested index is0. Current-mode publication is a declared premise; the
original outer run-loop publication path is not executed by these CF cases.
Existing wake suppression, exact24-byte header stores, libkernel packing and
SVC handling then execute. The active case produces copy-send header
`<6I>(0x13,24,0x807,0,0,0)` and original eight-slot scalar trap ABI
`[header,0x400000011,0x1800000013,0x807,0,0,0,0]`. SVC result0 is supplied.
No new original-kernel send/delivery replay or native IPC is claimed here;
its previously checked component is in the [kernel wake-ingress report](kernel_wake_send_ingress_report.md).

Independent replay checks79643 original daemon visits,3399 original writes,
9900 original reads,139 modeled external-call contracts and335 complete CPU
frames across19 daemon components. Three CF cases add4066 original visits and
9437184 B of final private RAM checks. Total positive visits are83709; complete
final private RAM checked is55820288 B. Negative-control visits are excluded.
The daemon's five retained mutable regions total2441216 B per component:
original DATA_CONST/DATA copies, stack, raw heap and private import/data arena.
Readonly executable bytes are checked against the original separately.

Eight altered records are rejected: original callback instruction, registered
callback argument, event patch, inherited setup pointer, final descriptor field,
origin snapshot digest, CF current-mode premise and final stop flag. Complete
source bytes, GP/SP/NZCV/SIMD, ordered reads/writes, before/after model effects,
component-entry patches, whole mutable snapshots and final fields are checked.
Copying an earlier producer's bytes is not itself proof of native shared state;
the producer is independently replayed first and the entry remains explicit.

Probe/replay cache decoded instructions: O(I+V+J+H*R) time and O(I+J+R) space
for image bytes I, visits V, journal size J, full-memory operations H and mutable
RAM R. The inherited CF interval searches additionally cost O(V_CF*F) time
for V_CF visits and F captured intervals. Source hashing adds linear input-byte
cost. Each private execution has a
100000-hook cap. The three fixed32-bit SMT queries have separate30 s limits;
no general SMT complexity or native timing claim is made.

## Bounded next work and architectural implications

| Impact | Discriminating evidence still required |
| --- | --- |
| High | Recover the enclosing descriptor setup caller and its inherited state0x3a74 from a verified original startup path, including native initialization, IOKit/environment gates and actual descriptor origin. Component entry does not prove whole-startup admission. |
| High | Recover original CFFileDescriptor source construction/dispatch blocks and kernel kqueue/signal production, connecting actual notifications to effective callback/reference history. Generic CF signal/wake helper behavior is covered separately in the [source/wake caller report](cf_source_wake_callers_report.md). |
| High | Recover populated896-byte slot semantics, marker meaning, process-event registration/PID matching and associated object/port retirement. Empty initialized slots are insufficient for nonempty lifetime behavior. |
| High | Continue the successful daemon/kext request/reply and user-client-selector/deeper-facility pairing; this shutdown/event path does not establish successful FairPlay processing. |
| Medium | Recover actual pthread_once initializer, lock epochs, descriptor/CF source retention, close-on-invalidate effects and subsequent clearing/reuse of the stored CF reference. |
| Medium | Establish actual current-mode/stop-index publication and stopped-loop consumption across repeated runs, including concurrent wake and timer/service activity. |
| Low | Extend modifier-pattern candidates only after decoding their actual target banks; matching PAC diversity alone does not identify a callee or prove an exhaustive caller census. |

The [historical ZUT trace](zut_trace_report.md) remains a separate startup and
unsuccessful FairPlayIOKit-open observation. This work neither reruns that target
nor adds native signal/event/port observations. Original supplied inputs remain
preserved. The full daemon/kext/deeper-interface objective is incomplete.

QG1: Descriptive binary/interface analysis requires no normative judgment.
QG2: DS1-DS8 state assumptions, dependent results and falsification probes.
QG3: This increment covers descriptor source/callback/control context, exact
calls/fields/failure boundaries, CF stop-to-wake linkage, ABI and retained reports;
whole-goal completion is explicitly not claimed.
QG4: All byte extents, record arithmetic, case/visit/RAM totals, local32-bit
proofs and arm64e layout assertions are reproducible. No native timing inferred.
QG5: Descriptor, CF reference and Mach name; request and native effect; component
entry and caller reachability; initializer writes and raw backing; event bytes
and API status; and current-mode gate and wake emission remain distinct.
QG6: Original daemon/cache/import bytes, selected IDA byte agreement, SDK layout,
full-domain local proofs and independent original execution supply provenance.
QG7: High/medium/low bounded extensions identify concrete missing interface,
lifetime, caller and native-state evidence. All gates pass for this increment.
