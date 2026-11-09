# CF Mach-port invalidation, ownership and deferred right cleanup

Original CFMachPortCreate, CreateWithPort, IsValid, Invalidate, destructor and
deallocation-record bodies now execute in private finite sequences. Newly created
ports set receive/send ownership bits; newly wrapped names do not. Invalidate
detaches CF state and requests monitor cancellation. The destructor and monitor
cancel callback coordinate before selected Mach right-release requests occur.
This explains a previously opaque boundary in the
[daemon descriptor callback](daemon_cf_descriptor_bridge_report.md).

The callback's header+0x18 object is not joined to this new constructor epoch.
Native CFRelease-to-destructor selection, dispatch scheduling, reference counts,
right ownership, kernel effects and successful FairPlay exchange remain unknown.
All native target-effect flags are false. The full interface goal remains active.

## Evidence, identity and reproduction

Primary artifacts are [original CF/cache/daemon captures](triage_evidence/cf_mach_port_retirement_source.json),
[287 private execution cases](triage_evidence/cf_mach_port_retirement_profiles.json),
[checks and SDK assertions](triage_evidence/cf_mach_port_retirement_checks.json),
[preservation seal](triage_evidence/cf_mach_port_retirement_delivery.json) and
[quality gates](triage_evidence/cf_mach_port_retirement_quality_gates.json).
The [engine](triage_evidence/probe_cf_mach_port_retirement.py) executes original
instructions; the [checker](triage_evidence/replay_cf_mach_port_retirement.py)
combines fresh shared-engine repetition with a separately written compact
state/record/ownership model. Repetition is not an independent emulator or lower
runtime implementation. Complete ordered journals and final regions are compared.

Daemon SHA-256 remains
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
CF UUID is `7fe5392e-ff16-31e1-8552-3a45c6b68224`; cache UUID is
`2bd06591-e751-3e84-963f-b08dab6af23a`. Fresh capture checks 17 complete CF
routines/1155 instructions, 18 lower import stubs, three daemon binds and three
original daemon windows. Six additional libkernel routines are captured as
static evidence and are not entered by these cases. Cache files and four direct
SDK headers are hashed. No new IDA queries or database mutations were needed.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_mach_port_retirement.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_mach_port_retirement.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_mach_port_retirement.py
```

Each explicit component call has a 20000-instruction limit. Components retain
one private memory epoch but receive declared entry registers and stack state.
The installed Unicorn/Capstone and local arm64e SDK/compiler are dependencies;
hashing selected headers does not pin the entire transitive toolchain.

## Assumption register

All execution claims depend on MR1-MR8 as applicable. Broader native behavior
outside these bounds is unknown.

| ID | Assumption / dependent result | Stress or falsification probe |
| --- | --- | --- |
| MR1 | Pinned images, raw chained stubs, exports and symbols identify this CF/daemon pairing. | Fresh recapture and source hashes; check all original executed bytes, three daemon binds and six static libkernel bodies. Native loader/PAC selection remains unknown. |
| MR2 | Explicit component calls share declared private memory with correctly supplied public/internal arguments. | Full tracked entry/return frames, journals and final regions; both event orders and preexisting states 1/2/3. This does not establish native reachability or valid concurrent destruction. |
| MR3 | Runtime creation supplies a zeroed 128-byte object with declared type36 header; allocation/retention/collections follow the listed models. | Original constructor writes, cached reuse with a different requested callback, monitor-null and runtime-failure cases. Actual reference counts and native destruction selection remain unknown. |
| MR4 | Locks, once/fork state and dispatch handler copying satisfy the private lower contracts. | Warm fork/once fields, balanced lock ledger, copied44/36-byte blocks and explicit cancel entry. Native lock ownership, race feasibility and handler scheduling remain unknown. |
| MR5 | Mach allocate/insert/type/cleanup statuses and names are supplied at resolved CF import boundaries. | Failure statuses, receive/send/send-once type masks, high-bit name and cleanup error5. Native rights, syscall success and kernel namespace effects remain unknown. |
| MR6 | CF array/set storage, record retain/free and optional source invalidation/callouts use explicit models. | Original record flags/key operations, repeated invalidation, optional context/source callbacks and record retirement. The full source 1 removal body and native backend/free effects do not execute here. |
| MR7 | Direct internal record/NS/deadness calls and seeded states represent component inputs, with opaque record tail preserved. | Four CF ownership masks in both orders, two NS sequences and all 256 cleanup flag bytes. Native producer history, legal-state coverage and fairplayd use of NSMachPort remain unknown. |
| MR8 | PAC instructions are logically bypassed; repeat shares the engine/lower models, while semantic oracles are independently written. | Complete repeat equality, independent phase/cleanup predictions,16 SDK assertions and ten rejected alterations. Hardware authentication, native execution and universal equivalence are not established. |

## Daemon touch points and original routines

The [registration report](daemon_registration_report.md) identifies named-service
bootstrap receive-name wrapping, with requested callback 0x100425f78 and zero
40-byte context. The [created-port report](created_port_report.md) separately
identifies creation/replacement of the anonymous endpoint at header+0x38.
Header+0x18 invalidation in the signal callback, anonymous endpoint replacement
and source-creation failure are separate daemon control paths.

| Daemon slot / site | Original interface / role |
| --- | --- |
| `0x1010b1c40` / wrapper `0x100001f50` | CFMachPortCreate for a new endpoint |
| `0x1010b1c48` / wrapper `0x100001f9c` | CFMachPortCreateWithPort for an existing numeric name |
| `0x1010a0188` / call `0x1001f4d0c` | Conditional first-service object invalidation in the signal route |
| `0x1004ace70` | Anonymous old-object invalidation before replacement |
| `0x1001ce8cc` | Invalidate on named-service source-creation failure; separate release follows |

| Original CF address | Symbol / established role |
| --- | --- |
| `0x184752484` / `0x184812774` | Public create / __CFMachPortCreate4; allocate receive, insert send, set ownership bits |
| `0x18472cfe8` / `0x1848121b0` | Public with-port / __CFMachPortCreateWithPort4; type check, registry reuse or construction |
| `0x18472cff0` | CFMachPortIsValid; state and type-query predicate |
| `0x184779fe8` | CFMachPortInvalidate; registry/monitor/source/context transition |
| `0x18477a54c` | __CFMachPortDeallocate; destructor and ownership record request |
| `0x184751868` | _cfmp_record_intent_to_invalidate; selected 8-byte record creation |
| `0x184812c64` / `0x18477a448` | Copied cancel handler / _cfmp_source_invalidated |
| `0x18477a700` / `0x18477a854` | _cfmp_record_deallocation / _cfmp_cleanup |
| `0x184810424` | _cfmp_source_record_deadness; clears recorded receive-cleanup bit |
| `0x18476d9ac` / `0x18477a2d0` | NSMachPort interest / deallocation-record interfaces |
| `0x184751a00` / `0x18477a6ac` | Record retain flag / release-free callback bodies, captured statically |

These image-specific symbols/offsets are not public object-layout guarantees.
The selected raw object extent is 16-byte runtime prefix + 112 requested extra
bytes = 128 B. Public CFMachPortContext is 40 B, confirmed by the SDK.

## Ownership, invalidation and the cancellation rendezvous

Original Create allocates a receive name and requests MAKE_SEND20 insertion.
After successful object construction it atomically ORs header-word+0x08 with
0x02 and 0x04. The destructor reads bit 2 as send ownership and bit 1 as receive
ownership. New CreateWithPort objects leave those bits clear under MR3's runtime
header; same-name cache reuse retains the existing object's callback, context
and ownership. A cached Create-owned object does not become borrowed merely
because a later caller requests CreateWithPort.

With-port admission requires successful mach_port_type and some bit in0x70000.
SEND/SEND_ONCE bits 0x50000 additionally select monitor initialization. A wrapped
receive-only name skips that branch in these cases. Monitor construction first
records intent, then requests a dispatch Mach-send source with mask 1. Its copied
cancel/event blocks are 44/36 B, with invoke pointer+0x10. The cancel block saves
dispatch source+0x20 and u32 name+0x28; the event block saves u32 name+0x20.
Copying and delivering are modeled dispatch operations, not native scheduling.

```text
newly created name -> CF object owns receive + send
wrapped new object -> CF ownership bits clear
monitor path      -> intent record keyed by (u32 name,u8 tag)

Invalidate(object):
  state 0 -> state 1; remove registry entry; cancel monitor; detach cached source
  unlock -> optional invalidation callback / source request / context release
  state 2

Destructor(object):
  if state 0: cancel/detach/callouts, then state 2
  state 3 -> report receive/send ownership
                |
                +-- wait if monitor cancel not yet reported
monitor cancel -+-- otherwise remove record -> cleanup requests
```

The original public invalidator contains no direct Mach right-release call.
Destruction is a distinct internal entry, not an automatic consequence of the
modeled CFRelease. A live-object destructor does not perform the invalidator's
registry-removal loop in the captured body; the private live-destructor case
retains that registry entry. Native cache/backend lifetime remains unresolved.

In the optional context/source case, original code invokes the invalidation
callback with (object,info), requests source invalidation/release and invokes the
context release with (info), outside the object lock. Those callouts are modeled
boundaries. A second public invalidation omits those transitions after state 2.
Preexisting states 1/2/3 are diagnostic component fixtures, not demonstrations of
legal native concurrent destruction or repeated destruction.

## Packed record and compact semantics

| Record offset | Width | Meaning established by original instructions |
| --- | ---: | --- |
|0 |4 B | u32 numeric name |
|4 |1 B | u8 lookup discriminator/tag |
|5 |1 B | flags below |
|6 |2 B | opaque tail, copied during cleanup packing; not established as a reference count |

| Flags bit / mask | Observed role |
| --- | --- |
|0 /0x01 | Record retain marker; selected backend model sets it |
|1 /0x02 | A deallocation report is pending |
|2 /0x04 | Source invalidation/cancellation has been reported |
|3 /0x08 | CF send-deallocation request |
|4 /0x10 | CF receive-reference removal request |
|5 /0x20 | NSMachPort interest/cleanup selection |
|6 /0x40 | NS send-deallocation request |
|7 /0x80 | NS receive-reference removal request |

The original record lookup uses name plus the low8 bits of the discriminator.
Selected calloc supplies eight zero bytes. The set backend's retain/free effects
remain declared; the original retain/release helpers are captured as provenance,
not entered as part of that backend. Record removal is distinct from a verified
native free. The compact CF-side model used independently of instruction replay
is:

```text
report_deallocation(send,receive):
  rights = (send & 1)*0x08 | (receive & 1)*0x10
  no record: cleanup(rights)
  record without source-invalid bit:
    flags = (flags & 0xe3) | rights | 0x02
  record with source-invalid bit:
    saved = (flags & 0xe7) | rights
    remove record; cleanup(saved)

report_source_invalid():
  if flags & 0x02: save flags; remove record; cleanup(saved)
  else: flags |= 0x04

cleanup(flags):
  if flags & 0x10: remove one receive reference
  if flags & 0x08: deallocate one send reference
  if flags & 0x20:
    if flags & 0x80: remove one receive reference
    if flags & 0x40: deallocate one send reference
```

Deadness clears 0x10 on a found record. The sequence
intent/deallocation/deadness/source-invalid therefore requests send deallocation
without the recorded receive decrement. The helper is entered explicitly here;
the full copied dispatch event handler/checker and its native producer history
are not executed. NS sequences check the separate0x20/0x40/0x80 roles without
establishing that fairplayd invokes NSMachPort interfaces.

## Outgoing API, fast trap and fallback IPC contracts

Original cleanup passes the entire packed record in X1 at the selected calls.
The Mach API name is W1, the low32 bits. For example,
X1=0x00001b0000000303 still denotes name 0x303. The upper bits are record data,
not part of a Mach name. The high-name fixture separately uses u32 name 0x80000303
and verifies that the sign bit is preserved as unsigned name data.

| CF emission site | Resolved original stub / export | Request |
| --- | --- | --- |
| `0x18477a89c` | `0x188076bb0` -> `0x180548320` mach_port_mod_refs | W0=task, W1=name, W2=RECEIVE1, W3=-1 |
| `0x18477a8ac` | `0x18806c480` -> `0x18054906c` mach_port_deallocate | W0=task, W1=name |
| `0x18477a8dc` | Same mod_refs export | Optional NS receive removal |
| `0x18477a908` | Same deallocate export, tail call | Optional NS send deallocation |

The private task argument is 0x103, supplied by the declared task-self cell.
Nothing establishes that this value is a live host task name. Cleanup results
0 and 5 are modeled; the original helper still processes later selected requests.
Record removal does not establish successful kernel right retirement.
Here, send-deallocation labels identify the recorded ownership and the
mach_port_deallocate request. That API does not itself select a right class;
actual send/send-once/dead-name effects require the kernel namespace state.

The six captured libkernel routines establish the following static routes:

| Public wrapper | Fast trap emitter | Fallback on result0x10000003 | RPC send call / request ID |
| --- | --- | --- | --- |
| mach_port_deallocate `0x18054906c` | `0x180547acc`, X16=-18, SVC0x80 | `0x18056c8a4` | `0x18056c918` -> mach_msg2_internal;3206 |
| mach_port_mod_refs `0x180548320` | `0x180547ad8`, X16=-19, SVC0x80 | `0x18056c9c0` | `0x18056ca34` -> mach_msg2_internal;3208 |

These bodies are recaptured and hashed, not executed in this increment. Nineteen
original instruction assertions and five constant records check the listed wire
widths, emission sites, fallback branches and reply identities. The
fallback clients use remote=task argument, local=mig_get_reply_port(), voucher0,
simple header bits 0x1513 and options0x200000003. Deallocate sends 36 B with NDR 8
and u32 name; mod_refs sends 44 B with NDR 8, u32 name/right and signed32 delta.
Both offer 44 B receive capacity and validate a simple 36-byte status reply with
IDs 3306/3308 respectively. NDR is captured as0000000001000000. The request names
are stored with original W-register stores even when incoming X1 is packed.

The [user-library trap report](user_trap_interface_report.md) supplies existing
lower transport context. Actual fallback selection, reply-port identity, kernel
dispatch/right effects and receive/retry behavior for these retirement RPCs
remain unexecuted. The Mach API interception is the executed boundary here.

## Case coverage and validation

The 31 non-sweep cases cover fourteen constructor/lifecycle variants, six direct
record sequences, four ownership masks in both orders and three preexisting
object states. A further256 cases exhaust all cleanup flag bytes with fixed
high-bit name, tag 0x73 and opaque tail 0xa55a. That is exhaustive flag coverage at
the stated fixture values, not exhaustive callers, names or native lifetimes.

| Selected case | Original visits | Final pending records | Right-release requests |
| --- | ---: | ---: | --- |
| Wrapped receive-only |348 |0 | none |
| Created, cancel before destruction |615 |0 | receive then send |
| Created, destruction before cancel |606 |0 | receive then send |
| Live-object destruction then cancel |542 |0 | receive then send |
| Created object reused through with-port |740 |0 | receive then send; callback/context preserved |
| Wrapped send / send-once monitor |520 /529 |0 | none from CF cleanup |
| Null monitor after intent |468 |1 | none during this interval |
| Context/source and repeated invalidation |675 |0 | receive then send |
| Insert failure |69 |0 | receive only |
| Allocate failure |59 |0 | none |
| Runtime object failure |155 |0 | receive then send |
| Deallocation then deadness then source-invalid |217 |0 | send only |

The null-monitor interval ends with a pending record. Native allocation failure,
later checker/restart behavior and full retention are not established, so this
is not a native leak conclusion. Optional cached-source invalidation is a
checked request boundary; the full source 1 removal/de-membership body is not
executed here. Prior source 0 removal evidence remains in its separate report.

Fresh repetition checks 15793 original visits, 4854 ordered reads, 3504 ordered
writes/after-images and 3287 tracked CPU frames. The compact semantic model checks
350 phase transitions, 59 record key/flag observations and 426 cleanup request
arguments. Final private RAM is 287 * (262144 + 3*4096) B = 78761984 B; this covers
the declared arena and three writable global pages, not all mutable cache pages.
PAC is logical and native exception state is not part of the tracked CPU set.

Five cache files, four direct SDK headers and 16 arm64e compile assertions are
checked. The manual 8-byte record layout is an analyst layout checked against
the original access offsets; it is not a public SDK declaration. Ten alterations
are rejected: constructed fields, cached callback substitution, deferred flags,
name argument, request ordering, final RAM, record retirement, copied cancel
capture, component-return CPU and source capture. Repetition shares lower models;
the compact semantic checks and SDK/source recapture provide different checks
but do not create native evidence.

Validation costs O(S + V + J + H*R) time and O(S + J + R) space for source S,
visits V, journal bytes J, finite cases H and per-case RAM R. Original registry
scanning is linear in the registered-array count; set backend costs and native
contention are outside the recovered instruction-only bound. The compact
single-key state transition is constant work apart from declared map operations.

## Bounded continuation opportunities

| Impact | Remaining interface | Concrete next evidence |
| --- | --- | --- |
| High | First-service object in the actual daemon callback | Construct/register the actual service CF object, carry its identity into header+0x18 and invoke original invalidation from the existing combined epoch. |
| High | Kernel receive/send-right retirement | Execute the captured wrappers and preserve trap/RPC task/name/ownership epochs into matching kernel handlers; distinguish status from actual namespace change. |
| High | Successful daemon/kext/deeper transaction | Retain selector/RPC/application contracts and obtain source-pinned successful flow; ZUT's failed-open trace still does not demonstrate that exchange. |
| Medium | Native reference-count and cache/destructor selection | Replace primitive CF retention/array/set destruction boundaries with original selected bodies; preserve ownership through cache reuse. |
| Medium | Monitor event/checker and pending records | Extend from the copied event target to original deadness/checker scheduling, including monitor-null and later deallocation histories. |
| Medium | Source1 removal and native dispatch ordering | Carry actual cached version1 source/mode/port-set state through invalidation and cancellation; distinguish removal from Mach right retirement. |
| Low | Discriminator and NS producer census | Trace callers of the tag-bearing record interfaces and NS facade; avoid assigning semantic names to opaque bytes without producer evidence. |

## Quality gates

QG1: Pass for factual technical analysis; no normative conclusion is required.

QG2: Pass for this increment: MR1-MR8 identify dependencies and falsification probes.

QG3: Pass for the bounded CF ownership, invalidation, cancellation-record and
retirement emission interfaces. The broader interface goal remains incomplete.

QG4: Pass: exact byte layouts, u32 names versus packed X1, signed32 delta,
flag-domain coverage, SDK compilation, RAM arithmetic and algorithm bounds agree.

QG5: Pass within scope: invalidation/destruction/cancel/report/request/native
effects are separate; opaque tail, shared-engine repeat, source 1 boundary,
preexisting-state diagnostics and null-monitor pending interval remain explicit.

QG6: Pass: original CF and libkernel bytes, chained imports/exports, daemon binds,
cache/SDK hashes, fresh repetition, independent semantic oracles and rejected
alterations are retained. No native kernel or hardware PAC claim is made.

QG7: Pass: bounded high/medium/low continuation opportunities are listed above.
