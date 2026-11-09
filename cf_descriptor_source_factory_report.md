# CoreFoundation descriptor factory, source-0 registration and daemon callback ABI

Original CoreFoundation instructions now connect the descriptor API used by
fairplayd to duplicated descriptors, copied dispatch handlers, a version-0
CFRunLoopSource, readiness rechecks and the three-argument daemon callback.
This replaces the whole descriptor/source API models used at the corresponding
boundaries of the [daemon investigation](daemon_descriptor_source_report.md)
with separately executed original CF components. The components have distinct
private object identities; matching contracts do not establish a continuous
native daemon/CF execution epoch.

The descriptor source joins the run loop's source-0 collection. Dispatch event
handlers signal that source and request wakeup through the existing control
port; they do not create a descriptor-specific incoming service Mach port in
the selected execution. The registered Perform routine rechecks readiness
before calling fairplayd. Stale readiness and nonretryable EIO suppress that
callback in the retained private cases. These results explain an event/shutdown
interface surrounding the daemon; successful daemon-to-kext processing remains
unknown.

## Primary evidence and reproduction

Retained evidence: [original source and import identities](triage_evidence/cf_descriptor_source_factory_source.json),
[16 private cases](triage_evidence/cf_descriptor_source_factory_profiles.json),
[independent validation](triage_evidence/cf_descriptor_source_factory_checks.json),
[preservation seal](triage_evidence/cf_descriptor_source_factory_delivery.json),
and [quality gates](triage_evidence/cf_descriptor_source_factory_quality_gates.json).
The [probe](triage_evidence/probe_cf_descriptor_source_factory.py) and
[replay](triage_evidence/replay_cf_descriptor_source_factory.py) implement the new
boundary contracts separately; the replay does not import the new probe.
They share previously published loaders and inherited component contracts.

Static identities remain: daemon thin arm64e SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`,
UUID `204741e9-b89f-32b4-9321-51f3975c7cac`; dyld cache UUID
`2bd06591-e751-3e84-963f-b08dab6af23a`; CF UUID
`7fe5392e-ff16-31e1-8552-3a45c6b68224`. Nine cache files are freshly hashed.
The capture contains 104 complete CF/cache routines and 28 inherited import
stubs, totaling 10906 captured instructions. It additionally pins 22 lower
16-byte stubs, their original chained pointers, owning library and exact export
names; those 88 stub instruction words are outside that 10906 total. Five
named CF exports and two native dispatch type data pointers are retained.
Original source suffices for this increment; no additional IDA queries or
database mutations were needed.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_descriptor_source_factory.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_descriptor_source_factory.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_descriptor_source_factory.py
```

The current replay environment uses Unicorn 2.1.4 and Capstone 5.0.7. SDK layout
checks compile inline C for arm64e against the local MacOSX SDK. Six direct
headers are pinned; transitive headers and the entire toolchain are not hashed.
No host daemon, CF, dispatch, POSIX descriptor, signal or Mach operation is
executed by these private component probes.

## Assumption register

All execution-derived results below depend on DF1-DF8 as applicable. Static
identities depend on DF1; the exhaustive scalar result additionally depends
on DF8. Native behavior outside those bounds is unknown.

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| DF1 | Captured daemon and cache images form the static API pairing; runtime slides and native loader selection are unknown. | Recapture complete ranges, raw stubs/fixups/exports and hash all nine cache files; compare original daemon import bindings. |
| DF2 | Private raw descriptor storage is 112 B and source storage is 184 B, initially zero; type IDs 60/46 and retained runtime effects are declared. | Null descriptor/source storage cases; inspect requested extra sizes 96/168 B, original field stores and boundary guards. Native allocator size/type registration remains unknown. |
| DF3 | fstat returns a declared 144-byte stat image for original fd7; fcntl duplication returns declared 11/12 or failure. Native kqueue mode bits are unknown. | Exercise mode0, owner-read, owner-write and both bits; fstat failure, first-duplicate failure and storage failure. These are API variants, not observed host stat results. |
| DF4 | dispatch queue creation, source creation, copied block storage, suspend/resume and synchronous invocation are declared external contracts. | Copy original descriptor-sized event/cancel blocks; validate full CPU at sync entry/return and caller restoration; reject changed captures and invoke frames. Deliver a handler only after its source is resumed. Native queues, races and ownership remain unknown. |
| DF5 | Readiness, errno and raw fdset backing are supplied lower results; actual helper instructions and retry branches execute. | Ready/stale, EINTR4, EAGAIN35 and EIO5 cases; compare timespec, fdset writes, allocation requests and duplicate/original fd use. Native readiness/event feasibility remains unknown. |
| DF6 | Version-0 registration executes original AddSource and schedule; dispatch handler and saved Perform entries are explicitly invoked by the harness. | Inspect actual stored context version/info/schedule/cancel/perform, source-0 membership and control-port set; compare pending bytes, timestamps and callback arguments. The real source-0 scheduler and its timestamp clearing do not execute. |
| DF7 | The type once predicate is privately set to completed (-1), phase to the inherited initialized state, and collection/hash/retention effects remain declared. | Retain before/after global bytes and original 63-instruction once body; reject altered final queue state. Native first-use limits, retention, cancellation and invalidation remain unknown. |
| DF8 | Original ARM instructions run privately; PAC operations are interpreted logically, SVC results supplied, and daemon producer/consumer states use separate explicit entries. | Independent ordered instruction/read/write/full CPU/final RAM replay, all-u16 four-instruction slice, SDK assertions, and eight altered-record rejections. No native PAC, exception crossing, scheduler or whole-startup proof follows. |

## Architecture and recovered locations

```text
daemon kqueue fd7 / SIGTERM change
  -> CFFileDescriptorCreate(0,7,true,0x10044f23c,0)
     -> fstat -> read/write duplicate policy -> fcntl(...,67,3)
     -> dispatch queue + copied event/cancel handlers
  -> EnableCallBacks(ref,1)
  -> CreateRunLoopSource(0,ref,0)
     -> source version0, info=descriptor, schedule/cancel/Perform saved
  -> AddSource(main,source,kCFRunLoopDefaultMode)
     -> source-0 collection + run-loop bag + schedule -> WakeUp

declared dispatch readiness delivery (explicit entry)
  -> copied original read/write handler
     -> pending byte=1 -> suspend dispatch source
     -> SourceSignal -> timestamp -> source bag -> WakeUp
        -> existing wake port -> mach_msg -> intercepted -47 SVC

registered Perform (explicit entry; source-0 scheduler not executed)
  -> sync original block -> clear pending -> pselect recheck
     +-- stale / EIO: return without daemon callback
     +-- ready: callback(descriptor, read|write mask, context.info)
                -> 0x10044f23c entry boundary
```

| Original address | Recovered role / decisive location |
| --- | --- |
| `0x1847b566c` | Exported CFFileDescriptorCreate, 142 instructions; fstat call at `0x1847b56f8`, duplicate calls at `0x1847b5728` / `0x1847b5754` |
| `0x1847b5700`-`0x1847b570c` | Four-instruction mode/read policy slice; all65536 u16 inputs checked |
| `0x1847b58a4` | Queue getter/creation; original CAS publishes queue at `0x1eb159d50` |
| `0x1847b58fc` | Original create block: runtime allocation, field initialization, native read/write dispatch type pointers and handler captures |
| `0x1847b607c` / `0x1847b6190` | Exported enable wrapper / original enable block; immediate-readiness and resume decisions |
| `0x1847b5cd0` / `0x1847b5f10` | Exported source wrapper / original source creation or cached-valid-source reuse block |
| `0x18472d31c` | Exported CFRunLoopSourceCreate; actual version-0 context copying, mutex setup requests and valid/timestamp stores |
| `0x1847b5fe4` / `0x1847b5fec` | Call original SourceCreate / cache returned source in descriptor+0x38 |
| `0x1847b6074` | Two-instruction schedule callback: move run-loop argument to x0, branch WakeUp |
| `0x1847c968c` | Cancel callback is RET in this image; not a dispatch cancel-handler execution |
| `0x1847b7954` | Read event block: pending store `0x1847b7970`, suspend call `0x1847b7980`, Signal `0x1847b7994`, branch bag-wake helper `0x1847b79b8` |
| `0x18480fa1c` | Write event block: analogous stores/calls at `0x18480fa38`, `0x18480fa48`, `0x18480fa5c`, `0x18480fa80` |
| `0x1847b7ca0` / `0x1847b7ef4` | Original Perform / sync snapshot-and-recheck block; clear read/write pending at `0x1847b7f5c` / `0x1847b7f9c` |
| `0x1847b62cc` / `0x18480fb04` | Local exact nlist `_cffd_is_readable` / `_cffd_is_writeable`; pselect call at `0x1847b638c` / `0x18480fbc4` |
| `0x1847b7e00` | Original BLRAAZ to saved descriptor callback, with x0=descriptor, x1=mask, x2=context.info |
| `0x1847b802c` | Original exported GetNativeDescriptor; returns descriptor+0x14 value7 in successful private cases |
| `0x1847b5bd4` | Captured once body; deliberately bypassed by explicit completed predicate in these cases |

The [daemon report](daemon_descriptor_source_report.md) locates its wrapper
`0x100001f2c`, setup call `0x100097b60`, read enable `0x10002f0d0`,
source creation `0x10002f124`, default-mode AddSource `0x1000934d0`,
callback entry `0x10044f23c` and callback GetNativeDescriptor `0x10044f4d4`.
Fresh independent replay of the original daemon initializer, successful setup
and SIGTERM callback verifies those producer/consumer contracts again.
The CF ready case reaches the callback entry but stops before daemon code;
the separate daemon callback case executes with its prior private CF identity.

## Descriptor and source layouts

These are observed private object fields for this image, not public C layouts
or proof of a native allocator's actual allocation extent.

| Descriptor offset | Width (B) | Original operation / selected value |
| --- | --- | --- |
| +0x08 | 8 | Runtime/flags word; close-on-invalidate bit1 set for argument true |
| +0x10 | 4 | Invalid flag, zero in successful retained cases |
| +0x14 | 4 | Original descriptor7, returned by GetNativeDescriptor |
| +0x18 / +0x1c | 4 each | Read/write duplicates11/12, or -1 when not requested |
| +0x20 / +0x28 | 8 each | Read/write dispatch source references, NULL when absent |
| +0x30 / +0x31 | 1 each | Read/write suspension state; initial value1 |
| +0x32 / +0x33 | 1 each | Pending read/write event bytes; cleared in Perform recheck block |
| +0x38 | 8 | Cached CFRunLoopSource reference |
| +0x40 | 8 | Saved daemon callback0x10044f23c |
| +0x48 / +0x50 | 8 each | Context version / info; zero for selected NULL context |
| +0x58 / +0x60 / +0x68 | 8 each | Context retain / release / description; zero for selected NULL context |

| Source offset | Width (B) | Original version-0 state |
| --- | --- | --- |
| +0x08 | 8 | Valid bit3 |
| +0x50 | 8 | Order0 |
| +0x58 | 8 | Signal timestamp0, then declared clock tick100 after signaling |
| +0x60 | 8 | Bag associating the registered run loop |
| +0x68 / +0x70 | 8 each | Context version0 / descriptor info reference |
| +0x78 / +0x80 / +0x88 | 8 each | Retain0x1846db030 / release0x1846e1278 / description0x18480f8a4 |
| +0x90 / +0x98 | 8 each | Equal / hash, both NULL |
| +0xa0 / +0xa8 / +0xb0 | 8 each | Schedule0x1847b6074 / cancel0x1847c968c / Perform0x1847b7ca0 |

The public input CFRunLoopSourceContext is80 B, with info at8 B, schedule at56 B,
cancel at64 B and perform at72 B. These offsets and CFFileDescriptorContext40 B
are independently compiled SDK assertions. A second source request with order17
returns the same valid cached source: original SourceCreate runs once and order0
survives. This is the selected live-cache reuse path, not invalid-cache lifecycle
or general ownership proof.

## POSIX, dispatch and environmental boundaries

| Owner read/write bits in st_mode | Requested duplicates | All-u16 mode values |
| --- | --- | --- |
| neither | read fallback | 16384 |
| read only | read | 16384 |
| write only | write | 16384 |
| both | read and write | 16384 |

The original scalar test computes read-request as
`((mode & 0x180) == 0) || ((mode & 0x100) != 0)`; write-request follows bit0x80.
The four actual ARM instructions, including condition flags and CSINC, were
executed for every u16 input. Combining the first two rows gives32768 read-only
outcomes; write-only and both each give16384. No input yields neither request.
This complete scalar domain does not establish native kqueue st_mode values,
success of duplication or reachability of every full constructor path.

The named lower fcntl is called with fd7 and F_DUPFD_CLOEXEC67; the variadic
minimum-descriptor argument3 occupies the Darwin stack argument slot. Duplicate
allocation order is independent of native source kind. The original chained
data pointers resolve to read type0x1e24b2250 and write type0x1e24b2290, with exact
libdispatch export identities. A write-only policy therefore creates a write
source for first duplicate11. Event blocks copy48 B and cancel blocks44 B, as
read from their original block descriptors. Original block captures and invoke
pointers execute under the declared dispatch_sync/copy contracts.

The read/write helpers allocate `((fd + 8) >> 3) + 7` B of fdset backing for
these nonnegative selected descriptors:8 B for fd7,9 B for fd11/12. Original
bzero and bit-setting instructions execute; allocation and overflow-check
results remain supplied. The exact named import is
`pselect$DARWIN_EXTSN`, not select. It receives nfds=fd+1, one read or write set,
NULL exception set, NULL signal mask and original timespec `(0,1000)`:
`0 s + 1000 ns = 1e-6 s = 1 us`. This is an argument value, not a measured
duration or a guarantee about Darwin timer resolution.

Readiness errors EINTR4 and EAGAIN35 retry in original helper instructions.
EIO5 returns false in the selected case. The original event handler first marks
pending and suspends its dispatch source; Perform clears pending and rechecks
the duplicate. A stale or EIO recheck therefore does not call the daemon in the
retained state. Native race feasibility, recovery, future reenable and closure
are unknown. The daemon's observed static request is read mask1; masks2/3 here
are CF API variants, not claims that this daemon setup requests write events.

The original once predicate at0x1eb159db0 is zero in the cache capture and -1 in
the explicit private overlay. Its captured 63-instruction body includes lower
resource/environment calls but does not execute here. Native first-use process
limits and their consequences remain unknown; no host limit changes occur.

## Mach emission and scheduling limits

The actual source-0 registration leaves the inherited control members607/707/807
in set507 and places the source in the source-0 collection and the run loop in
its bag. It does not insert service name303 or a source-specific getPort result.
The schedule callback tail-calls WakeUp; the constructor's private run-loop gate
suppresses that emission during registration. Later explicitly delivered event
handlers traverse original Signal, bag-copy/unlock/apply and WakeUp.

The original outgoing CF call at0x18473af30 constructs header24 B
`<bits=0x13,size=24,remote=0x807,local=0,voucher=0,id=0>`, options0x11,
send size24 B and timeout0. Original libkernel wrappers pack the -47 trap
arguments and reach original SVC0x180547c1c. Only its result is supplied here;
eleven original SVC visits are independently checked. These are run-loop control
wakes, not daemon-to-kext RPCs. The
[previous kernel wake investigation](kernel_wake_send_ingress_report.md)
separately establishes downstream private kernel contracts; its native execution
and real queue epochs are not implied by this new component chain.

No real source-0 scheduler calls Perform in these probes. The harness reads the
actual stored Perform/info fields and enters that function explicitly, after
the original handler returns. Thus source timestamp100 remains at the boundary;
real scheduler clearing, callback order and stop/cancel races remain unknown.
The enable-already-ready case has pending work before registration and enters
Perform directly, avoiding the inherited no-pending-source0 premise of RUN.
The other RUN cases enter while timestamp is0, then use a separate declared
waker stack. This distinction prevents a pending source from silently crossing
that inherited scheduler boundary.

## Validation and finite cases

| Case | Original CF visits | Callback mask | Original wake SVC visits |
| --- | --- | --- | --- |
| read_ready | 2938 | 1 | 1 |
| read_stale | 2948 | none | 1 |
| write_ready | 2944 | 2 | 1 |
| both_ready | 3711 | 3 | 2 |
| read_retry_EINTR | 2963 | 1 | 1 |
| read_retry_EAGAIN | 2967 | 1 | 1 |
| read_error_EIO | 2956 | none | 1 |
| fstat_failure | 707 | none | 0 |
| duplicate_failure | 735 | none | 0 |
| descriptor_storage_null | 834 | none | 0 |
| source_storage_null | 1407 | none | 0 |
| source_reuse | 3128 | 1 | 1 |
| enable_already_ready | 2255 | 1 | 0 |
| mode_no_owner_bits | 2014 | none | 0 |
| owner_read_only | 2873 | 1 | 1 |
| owner_write_only | 2878 | 2 | 1 |

Sixteen CF cases check38258 original visits and50331648 B complete final private
RAM (`16 * (1+2) * 1048576 B`). Three separate daemon prerequisite/consumer
epochs check27813 visits and7323648 B complete mutable RAM. Combined:
`38258 + 27813 = 66071` visits and
`50331648 B + 7323648 B = 57655296 B`. The additional four-instruction scalar
sweep executes `65536 * 4 = 262144` visits; it is reported separately and not
added to the component-case total. Negative-control executions are also outside
the positive totals.

The independent CF replay checks5266 complete CPU frames,9765 ordered reads,
9836 ordered writes and53 original synchronous block entries/returns. It
recomputes lower contracts and checks the entire 3 MiB private final RAM per
case, copied blocks, global queue/once bytes, object layouts and guard bytes.
These guard extents are declared raw storage boundaries, not native allocator
proof. Eighteen arm64e SDK assertions cover stat/mode, fcntl, errno, timespec,
CF context layouts and callback bits. Eight independent altered-record controls
are rejected: instruction bytes, saved callback, source Perform pointer, sync
capture, sync entry CPU, copied event-handler patch, callback arguments and
final queue global.

The fstat-failure case returns NULL without duplicates. First-duplicate failure
still obtains the second duplicate12 and requests its close before NULL return;
runtime storage failure requests closes11/12. Source storage failure returns
NULL after descriptor creation. These are original cleanup requests under
declared lower results, not native leak, close completion or resource-exhaustion
claims. Second-duplicate failure, cancellation, invalid-source replacement,
dispatch-source allocation failure and actual invalidation remain untested.

The validator's time is `O(S + V*F + J + H*R + 2^16)`, with S source bytes,
V component visits, F captured function intervals scanned per hook, J ordered
journal volume, H whole-memory handoffs and R private RAM bytes. Space is
`O(S + J + R)` plus retained per-case records. The scalar sweep uses constant
emulator memory and O(2^16) time; there is no unbounded search or native event
generation.

## Bounded extensions and remaining context

| Impact | Next evidentiary boundary / consequence |
| --- | --- |
| High | Execute original source-0 scheduler and perform dispatch to replace the explicit Perform entry; verify timestamp clearing and callback order before claiming continuous run-loop delivery. |
| High | Continue the successful daemon/kext request/reply pairing and selector/deeper-facility path. This descriptor event interface alone does not establish successful FairPlay processing. |
| Medium | Recover original descriptor invalidation, dispatch cancel handlers and close-on-invalidate completion; current close requests and cached refs do not establish ownership or native closure. |
| Medium | Replace completed-once and fstat/duplicate premises with original first-use/resource-limit and native-environment evidence; mode-bit policy can select different dispatch sources. |
| Medium | Join the actual CF callback identity to daemon callback execution in one private memory epoch, then distinguish this from native scheduler/PAC/IPC validation. |
| Low | Extend source reuse to invalid cached source and non-NULL context retain/release callbacks; current order reuse is limited to a valid cached source and NULL context. |

The original supplied analysis, C, calls and annotated RAX trace remain
preserved. The trace's failed user-client open remains evidence of that run's
boundary; these new private CF cases do not turn it into an observed successful
IOKit transaction. Current artifact hashes and report links are published in
[the interface manifest](triage_evidence/interface_manifest.json).

## Quality gates

QG1: Factual interface and execution analysis; no normative premise is required.

QG2: DF1-DF8 state assumptions, dependent claims and falsification probes.

QG3: This increment covers descriptor/source construction, version-0 registration,
handler captures, readiness, wake emission and callback ABI. Broad-goal gaps are
explicit; full_goal_complete remains false.

QG4: Exact byte widths, signed descriptors, errno values, 1 us argument conversion,
SDK compilation, totals and bounded algorithm complexity are reproducible.

QG5: Mode fallback, write-only allocation order, stale/error readiness, pending
source0 entry, cached order and cleanup-request edge cases are distinguished;
no unresolved contradiction is used as a positive conclusion.

QG6: Original file/cache/stub/export/fixup bytes, separate independent replay,
SDK assertions and finite/exhaustive scopes are recorded. No new IDA or native
target execution is claimed.

QG7: Impact-labeled extensions identify the remaining scheduler, environment,
lifetime, shared-epoch and successful daemon/kext boundaries.
