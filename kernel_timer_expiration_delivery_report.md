# Original timer arming, expiration message and delivery to CF

Original kernel instructions now arm the created timer, construct and enqueue
its expiration message, receive it through the common port set, then deliver
the queued service request. Four original CF consumers use the checked timer
return bytes and route the first message into timer handling before the service
source. The timer control packet is produced by original instructions rather
than supplied as the earlier synthetic control fixture. [TE1-TE8]

The produced user message is 48 bytes: a 24-byte header and 24 zero payload
bytes, followed by the selected 68-byte trailer. Its local name is `0x707`,
message ID0 and raw bits `0x1100`. Original callback call site
`0xfffffe000bd13524` reaches the send wrapper; wrapper call
`0xfffffe000bcf57a0` reaches original queue-send code. Native clock/scheduler
delivery, authentication, runtime epochs and successful FairPlay processing
remain unknown. The full investigation remains active.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| TE1 | Pinned original kernel/daemon/cache corpus is the selected implementation | Addresses, trap binding, header and call-chain identity | Recapture175 complete kernel functions and43 cache bodies/25 stubs, reread cache bytes and hash nine files; attest native image pairing separately |
| TE2 | Prior source-produced zones, zeroed raw storage, service queue and declared receiver/task/namespace epochs apply | Construction, rights, membership and ordered receives | Freshly replay timer startup, three fixed zones and four receiver loans; check all source transfers and final objects; native bootstrap/allocator/task identity remains unknown |
| TE3 | The implementation-specific counter read returns raw100, CPU offset0 and thread conversion flag0 | Deadline comparison and immediate scheduler-helper path | Verify original MRS bytes and complete CPU frames, test deadlines0 and100, reject altered counter; native counter units/rate and conversion branch remain unknown |
| TE4 | Scheduler helper returns0 and the harness delivers the newly queued registered callback once | Pending/count state and expiration entry | Check original pending/count stores, helper arguments, registered callback/context and full CPU/RAM function-entry handoff; native scheduler/clock dispatch is unexecuted |
| TE5 | Send tag/preflight helpers return0; inherited keyed-hash/VM/copy/PAC contracts apply | Original send/enqueue and receive/copyout continuation | Recompute declared returns and all original arguments/reads/writes/queues/buffers, reject altered stores/packet; native MAC/authentication, allocation and hardware PAC remain unknown |
| TE6 | Task+0x3d0 points to declared per-CPU send counters, thread CPU index0 and file-value instrumentation flag0 apply | Send accounting and original fast spinlock paths | Check pointer/index loads, 16 KiB stride calculation and original atomic counter0 ->1; native per-CPU/instrumentation epochs remain unknown |
| TE7 | Exact original-kernel timer and service return contracts can be paired with original CF objects/runtime contracts | Timer route and unchanged daemon suffix | Check116 timer bytes then service148+OOL29 bytes, source-set cardinalities, timer routing and complete final CF buffers/objects; native shared maps, CF ownership and wake producer remain unknown |
| TE8 | Harness orders original public handler/callback/receive entries and stop boundaries delimit observation | Common-state composition and completion scope | Check complete handoffs without internal PC/frame/header edits; extend delayed/repeated/cancelled/concurrent timer and successful application/reply paths before full-transaction claims |

## Source, arming ABI and environment

[Source capture](triage_evidence/kernel_timer_expiration_delivery_source.json)
recaptures175 complete kernel functions /22589 instructions from kernel
SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.
The nested CF corpus contains43 original functions,25 stubs and3498 instructions,
with nine full cache-file hashes and fresh byte comparisons. No additional IDA
query was required. [TE1]

Original Mach trap-table entry93 binds `mk_timer_arm_trap` to
`0xfffffe000bd13808`, signed selector -93. The handler loads u32 name from
argument slot+0 and u64 deadline from slot+8, sets leeway/options to0 and tail
calls `0xfffffe000bd13824`. The tested16-byte argument record contains timer
name `0x707` and raw deadline0 or100. No SVC or native dispatcher executes.
[TE1,TE3,TE8]

| Original site | Address | Recovered operation / contract |
| --- | --- | --- |
| Arm handler | `0xfffffe000bd13808` | Name/deadline extraction;147-instruction core at `0xfffffe000bd13824` |
| Single-name receive lookup | `0xfffffe000bd13888` | Original lookup resolves existing timer name in the shared namespace |
| Pending-byte store | `0xfffffe000bd1396c` | Set timer+0x91 to1 |
| Counter read | `0xfffffe000bd13980` | Original `mrs x9,s3_4_c15_c10_6`; declared raw result100 |
| Deadline comparison | `0xfffffe000bd139bc` / `0xfffffe000bd139c0` | Unsigned deadline <= counter+offset selects immediate path |
| Scheduler-helper call | `0xfffffe000bd13a14` | Args `(timer+0x10,0)`, declared result0 |
| Callback-count store | `0xfffffe000bd13a24` | Original increment at timer+0x94 to1 |
| Registered expiration callback | `0xfffffe000bd13480` | Original entry from created callback/context fields |
| Pending clear | `0xfffffe000bd13544` | Clear timer+0x91 when count equals1 |
| Send-counter update | `0xfffffe000bcc8228` | Original atomic u64 increment through task per-CPU counter pointer |

The original arm path produces pending byte1/count1. The callback entry uses
that source-produced state and the original callback/self pointers, above a
declared scheduler-delivery handoff. The callback clears pending, sends once
and decrements count back to0. No timer-state bytes are patched to force this
path. Original uncontended timer spinlock acquire/release instructions execute;
no native concurrency or lock-progress claim follows. [TE3-TE6,TE8]

The new send path requires task field+0x3d0, absent from the earlier receive-only
fixture. It loads a counter base, loads u16 CPU index from thread+0x1b8 and adds
`index <<14` bytes. The explicit fixture provides disjoint64-byte counters,
index0 and initial counter0. Original code increments its first u64 to1.
Counter storage and native ownership are separate claims. Thread flag+0x6b1 and
CPU-data offset+0x58 are explicitly provided for the selected clock path.
[TE3,TE6]

## Emission sites and message construction

| Original site | Operation | Bytes / destination |
| --- | --- | --- |
| `0xfffffe000bd1350c` | Store zero u64 at internal header+0x30 | Final8 payload bytes |
| `0xfffffe000bd13514` | Store two zero vectors at header+0x10 | Zero32 bytes |
| `0xfffffe000bd13518` | Store original constant from `0xfffffe000700dd10` | Raw bits0x13, internal size56 |
| `0xfffffe000bd1351c` | Store timer's kernel-held port pointer at header+8 | Actual private timer-port object |
| `0xfffffe000bd13524` | Call `0xfffffe000bcf5754` | Original expiration send-wrapper entry |
| `0xfffffe000bcf57a0` | Call `0xfffffe000bcc7040` | Original send path reaches queue sender `0xfffffe000bcc7c34` |
| First set receive | Original frontend | Timer member selected; user local name0x707 |

These four store instructions cover all56 bytes of the internal message, not
just a prefix. The validator reconstructs every byte from original store journals
and compares the complete before-send header/payload. Header construction does
not depend on untouched raw-storage zeros. Source tag/preflight and keyed-hash
contracts remain declared; native authentication is not established.
[TE1,TE4,TE5]

| Field | Before original send | After original user receive |
| --- | --- | --- |
| Header width | 32 bytes, with64-bit port pointers | 24 bytes, with32-bit names |
| Message size | 56 | 48 |
| Raw bits | `0x13`; original copy-in changes it to `0x11` | `0x1100` |
| Destination / local | Timer-port pointer in outgoing destination field | Remote0, local0x707 |
| Voucher / message ID | Zero /0 | Zero /0 |
| Payload | 24 explicit zero bytes | Same24 zero bytes |
| Selected trailer | Constructed by original lower receive/send paths | 68 bytes; raw u32 words `[0,68,0,0,1,0,...,0]` |

The exact116 returned bytes are retained in
[checks](triage_evidence/kernel_timer_expiration_delivery_checks.json).
Trailer words are byte observations under the declared task/header environment;
no native credential, audit identity or authorization conclusion is inferred.
No OOL descriptor is present in the timer message. [TE2,TE5]

## Ordered receives and CF continuation

```text
original creation + root/timer membership
  -> original Mach -93 arm handler
       pending=1, callback count=1
  -> declared scheduler dispatch at original registered callback entry
       original stores build complete56-byte internal message
       original send/enqueue promotes timer member to ready
       pending=0, callback count=0
  -> original service membership
       timer and service members are ready
  -> first original set receive: timer local0x707, message48 + trailer68
  -> second original set receive: service local0x303/0x403
       original ready-head rotation selects the service member
  -> checked return contracts feed original CF
       timer receive -> DoTimers(NULL array) -> ArmNextTimer
       mode remains nonempty because source1 is registered
       next receive -> source dictionary -> daemon/application suffix
```

After the two receives, both drained timer/service links retain their ready bits,
and the ready head has rotated back to the timer. Only the root remains in the
inactive ring. This interval does not reach a later cleanup attempt on those
stale-ready links. [TE2,TE5,TE8]

The registered original callback is entered at its function entry with unchanged
private memory; scheduler delivery is an explicit boundary. Kernel arming here
is issued by the harness through the original handler. The selected CF case has
a NULL timer array and does not itself demonstrate a native CF caller arming
this timer. No internal branch, saved frame or constructed message is replaced.
[TE3-TE8]

| Receive-side comparison | Earlier control fixture | New original-kernel producer/receiver |
| --- | --- | --- |
| Message / selected trailer | 24 /68 bytes | 48 /68 bytes |
| Payload | None | 24 zero bytes |
| Raw received bits | 0 | `0x1100` |
| Local name / ID | Private0x707 /0 | Private0x707 /0 |
| Provenance | Declared synthetic input | Original callback stores, send/enqueue and actual private set receive |

The earlier [control-dispatch report](cf_control_port_dispatch_report.md)
explicitly scoped its fixture as synthetic. This increment supplies the
original producer's bytes for the timer route without rewriting historical
records. Original CF call `0x18475730c` receives the paired result; timer-name
comparison at `0x184757594` reaches original `___CFRunLoopDoTimers` via call
`0x1847575b4`. The NULL timer array produces no fired CF timer, then original
rearming and mode-nonempty checks permit another iteration. [TE7,TE8]

Each CF case receives116 timer bytes, then the prior148-byte service return
and29 OOL bytes. It performs one service dictionary lookup/source invocation,
not a daemon dispatch for the timer packet. Generic reply-send site
`0x184757744` is unvisited. The daemon instruction suffix, complete receive/OOL/
reply buffers, mode/queue bytes and collection state match the baseline.
Application records match for the two application-boundary cases. [TE7]

The reusable kmsg flag byte at+0x32 is1 before expiration,3 after send, and1
after timer receive. Pending/count return to0, timer associations remain, port
reference/send-bookkeeping words return to their checked values, and namespace
entry7 remains receive-only `0x04020000`. These finite return-state observations
do not establish native lifetime or indefinite reuse. [TE2,TE5,TE8]

## Independent checks and bounded observations

[Profiles](triage_evidence/kernel_timer_expiration_delivery_profiles.json),
[independent replay](triage_evidence/replay_kernel_timer_expiration_delivery.py)
and [checks](triage_evidence/kernel_timer_expiration_delivery_checks.json)
retain the evidence:

| Phase | Cases | Original visits | Complete final private snapshots |
| --- | --- | --- | --- |
| Arm/expire/send/timer receive/service receive | 5 | 44090 | 5242880 bytes /5 MiB |
| Original CF timer/service consumers | 4 | 14128 | 12582912 bytes /12 MiB |
| Fresh timer startup | 1 | 170 | 1048576 bytes /1 MiB |
| Fresh fixed zones22/23/24 | 3 | 618 | 3145728 bytes /3 MiB |
| Fresh receiver loans | 4 | 216 | 4194304 bytes /4 MiB |
| Aggregate | 17 | 59222 | 26214400 bytes /25 MiB |

Four kernel cases use deadline0 and different queued service variants. The
fifth uses deadline100 equal to the declared counter; both comparison cases
select the original immediate path and produce the same timer wire. Delayed
(deadline greater than100), conversion/leeway, cancellation, coalescing and
concurrent paths are untested. Snapshot sums are not peak memory or exhaustive
coverage. [TE3,TE8]

The independent replayer imports no new probe. It recomputes counter/scheduler/
tag/preflight/cardinality contracts and complete function-entry arguments;
checks every original instruction/read/write, relevant CPU/object/queue/wire
observation and final private RAM; and rejects six altered records covering
counter, scheduler result, callback header store, first actual receive wire,
CF timer-packet patch and CF wire extent. Fresh prerequisites replay original
source; their native epoch coupling remains an assumption. [TE1-TE8]

For the fixed source corpus, instruction/body lookup extents are constants.
Recovery costs O(image + source + symbol data + cache bytes hashed); replay
costs O(image + visits + journals + snapshots) time and space. Publication
rehashing costs O(published bytes + links) time with O(manifest + largest parsed
JSON) space. Exact comparisons require no statistical error bound. Raw counter
values are not assigned seconds or nanoseconds.

## Bounded continuation

| Impact | Remaining interface / pattern | Discriminating next evidence |
| --- | --- | --- |
| High | Timer wire producer and CF route now compose conditionally | Replace declared scheduler/counter delivery with matched native clock/callback evidence before native timing/reachability claims |
| High | Wake port remains modeled outside the common kernel graph | Recover original wake-port creation/membership/send and compare its actual packet |
| High | Successful daemon-to-kext transaction remains unknown | Correlate user-client opening, selector routing, daemon exchange and original application outputs |
| Medium | Reusable kmsg flags and held references change across send/receive | Follow rearm, cancel, coalescing and teardown to establish ownership under repeated events |
| Medium | Source CF path has no registered CF timers | Recover a nonempty timer-array caller that reaches original kernel arming, with callback/deadline provenance |
| Medium | Two receives leave drained timer/service links marked ready | Check the next selection/poll before inferring cleanup or scheduler waiting |
| Medium | Task send statistics and CPU counter offsets are environmental prerequisites | Establish native task/per-CPU/instrumentation epochs and compare those fields |
| Low | Future deadlines, leeway and timebase conversion remain untested | Extend finite cases when they resolve a specific timing/ABI question |

## Quality gates

QG1: No normative premise is required; claims concern original byte behavior.

QG2: TE1-TE8 identify assumptions, dependent results and falsification probes.

QG3: Arming/send/receive routine roles, emission sites, incoming/outgoing port
fields, wire widths, environmental prerequisites and original CF control flow are covered.

QG4: Widths, offsets, raw counters, branch comparisons, byte extents, aggregate
sums and fixed-corpus algorithm costs are reproducible; native time units are unknown.

QG5: Synthetic fixture versus produced wire, scheduler delivery versus source
arming, finite reuse state versus lifetime, and private versus native execution
remain explicit; untested timing/concurrency/transaction paths remain unknown.

QG6: Original trap/function/constant bytes, complete original store reconstruction,
cache hashes, independent CPU/RAM/wire oracles and six altered controls provide provenance.

QG7: High/medium/low continuation scope is bounded by the table above.

[Preservation seal](triage_evidence/kernel_timer_expiration_delivery_delivery.json),
[quality record](triage_evidence/kernel_timer_expiration_delivery_quality_gates.json)
and [investigation status](interface_investigation_status.md) retain publication
checks and the active broader goal.
