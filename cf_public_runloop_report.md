# Public run-loop entry, indexed context, TSD and Stop/wake return

Original CF wrappers now acquire the selected run-loop/mode locks, publish the
current mode and indexed run depth, enter the recovered source0 scheduler and
restore context during cleanup. This replaces the assumed caller-held lock
premise of the [internal-entry investigation](cf_source0_scheduler_report.md)
for the selected public-entry paths. Lock calls remain declared successful
lower effects; native ownership and thread scheduling are unknown.

Five declared daemon-callback contracts request original CFRunLoopStop in this
same private CF state. Original public entry supplies the current-mode value
and depth consumed by Stop; Stop writes the indexed flag and executes WakeUp,
original libkernel packing and an intercepted -47 SVC. The actual daemon
callback body and CFRunLoopGetMain do not execute in this CF epoch.

The result distinguishes stop request from return status. Specific/RunInMode
with returnAfterSourceHandled=true returns handled4 even after this Stop request;
the selected false-argument paths return stopped2. CFRunLoopRun uses false and
exits after the internal stopped result. Its public ABI is void: a residual x0
value is not a public status return. Successful daemon/kext processing remains
unknown, and the broader investigation remains active.

## Primary evidence and reproduction

Retained records: [original bodies, exports and daemon binds](triage_evidence/cf_public_runloop_source.json),
[21 private cases](triage_evidence/cf_public_runloop_profiles.json),
[checks, normalization and TSD helper cases](triage_evidence/cf_public_runloop_checks.json),
[preservation seal](triage_evidence/cf_public_runloop_delivery.json),
and [quality gates](triage_evidence/cf_public_runloop_quality_gates.json).
The [probe](triage_evidence/probe_cf_public_runloop.py) and
[independent replay](triage_evidence/replay_cf_public_runloop.py) implement new
entry/effect/field/receive contracts separately; the replay does not import the
new probe. Frozen loaders and prior component models are shared dependencies.

Daemon thin arm64e SHA-256 remains
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`,
UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. Cache UUID is
`2bd06591-e751-3e84-963f-b08dab6af23a`; CF UUID is
`7fe5392e-ff16-31e1-8552-3a45c6b68224`. Nine cache files are freshly hashed.
The capture contains125 complete cache routines and28 inherited stubs,
totaling11864 instructions. Three original daemon binds pair CFRunLoopRun,
CFRunLoopStop and CFRunLoopGetMain with named CF exports. That static pairing
does not establish a native loader slide, caller reachability or current/main
thread identity. No new IDA queries or database changes were needed.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_public_runloop.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_public_runloop.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_public_runloop.py
```

Current dependencies include Unicorn2.1.4, Capstone5.0.7 and the local arm64e SDK
compiler. Three direct headers are pinned; transitive SDK headers and the entire
compiler are not hashed. No host CF, thread, signal, IOKit or Mach operation is
executed. Source instructions execute privately with logical PAC semantics.

## Assumption register

Execution-derived conclusions depend on PR1-PR8 as applicable. Static identity
depends on PR1. Native facts outside those bounds remain unknown.

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| PR1 | Recorded daemon/cache pairing and original unslid bodies identify the static contracts. | Recapture complete bodies, original exports/binds and nine file hashes; reject changed instruction records. Native loader choice/slides/callers remain unknown. |
| PR2 | The original constructed run loop is pre-registered in private TSD slot10 through an explicit warm-table fixture. | Execute original GetCurrent/GetTSD/table load from TPIDRRO_EL0+0x1b8 and reject an altered slot. This does not prove native registration, thread identity or GetCurrent==GetMain. |
| PR3 | Prior raw runtime/hash/retention, descriptor/readiness, dispatch, ObjC and trace contracts remain declared; mode-name equality is a selected opaque-identifier contract. | Actual registry lookup, source0 selection/Perform and original cleanup execute; missing/common/NULL names and empty-mode metadata differ. Native string/hash/lifetime effects remain unknown. |
| PR4 | Pthread calls return modeled success; ownership levels start0 at public entry. | Recompute ordered lock/unlock levels. Twenty cases have no unmatched request; the diagnostic empty-mode case has one extra mode-unlock request. Native ownership/error results are not established. |
| PR5 | Callback body is a declared void return, optionally containing an explicit original Stop operation. | Execute original Stop/Wake/wrappers in the same CF state; check before/after depth/current-mode/stop byte, original packet, CPU restoration and SVC status-only return. Actual daemon callback/GetMain bodies remain unknown here. |
| PR6 | Indexed depth, previous-mode pointer, deallocation/fork/type and empty-source fields are explicit diagnostic fixtures. | Check before/after bytes, depth253 admission versus254/255 boundaries, prior-mode restoration and original guard helpers. Native nesting/fork/failure feasibility is not proved. |
| PR7 | Nonblocking receive returns declared timeout without memory effects; idle receive stops before its effect. Warning-once predicate is privately completed. | Derive receive buffer from actual wrapper/RUN stack layout; compare options/result and unchanged warning predicate. No native queue emptiness, IPC, first warning or observer callback execution is established. |
| PR8 | Private original ISA execution and isolated helper cases test stated domains only; logical PAC and raw table storage remain declared. | Independent full tracked CPU/RAM/journal replay,11 SDK assertions,256-input normalization, all70 TSD slot round trips, two invalid-index diagnostics and eight alterations. Hardware PAC, native allocation/destructor execution and whole-process behavior remain unknown. |

## Exported entry and context transitions

```text
RunSpecific: normalize Boolean -> WithOptions
RunInMode: GetCurrent -> TSD slot10 -> normalize Boolean -> WithOptions
Run: GetCurrent -> default mode,1e10s,false -> WithOptions

WithOptions
  -> type/fork/name/deallocation gates
  -> lock run loop -> original mode lookup -> nonempty test -> lock mode
  -> reject old depth>=254
  -> depth++ -> clear indexed stop/wake bytes -> store per-depth option
  -> save previous current mode -> publish selected mode
  -> original internal RUN -> source0 collection/clear/Perform
     -> optional declared callback request:
        original Stop -> indexed stop store -> WakeUp -> original -47 SVC
  -> cleanup: depth-- -> unlock/release mode -> restore previous mode
              -> unlock run loop -> original wrapper return
```

| Original location | Source-backed role |
| --- | --- |
| `0x1847568e8` | Exported CFRunLoopRunSpecific: CMP/CSET normalize w2, then branch WithOptions |
| `0x184756870` | Exported CFRunLoopRunInMode: save name/seconds/Boolean, GetCurrent and tail-call WithOptions |
| `0x1847cf374` | Public CFRunLoopRun: default mode, duration1e10 s, optionfalse; repeat unless internal result1 or2 |
| `0x1848319f8` | Local WithOptions body; validate type43 and admission, publish indexed run context |
| `0x184831b3c` / `0x184831b88` | Run-loop / mode lock requests on nonempty normal entry |
| `0x184831b90` / `0x184831b94` | Compare old depth with0xfe / branch to limit helper when unsigned depth>=254 |
| `0x184831b9c` | Store new depth at runloop+0x54 |
| `0x184831ba4` / `0x184831bac` | Clear stop at+0x55+index / wake gate at+0x153+index |
| `0x184831bb4` | Store option at+0x258+8*index |
| `0x184831bb8` / `0x184831bbc` | Save previous+0xa60 / publish selected current mode |
| `0x184831c0c` | Call original internal RUN with run loop, mode, option and D0 seconds |
| `0x184832a04` | Cleanup helper: decrement depth, unlock/release mode, restore current mode and unlock run loop |
| `0x184832a28` / `0x184832a48` | Depth decrement store / previous-mode restore store |
| `0x184784250` | Original CFRunLoopStop; current-mode/indexed-stop/Wake path now runs inside this published context |
| `0x1848d407c` | Stop before original depth-limit diagnostic helper |
| `0x1848d460c` / `0x1848d4034` | Stop before original type-mismatch / fork diagnostic helpers |

The local SDK declares Run as void and RunInMode with mode, seconds and Boolean
arguments; compiled type assertions verify both. RunSpecific's exported wrapper
ABI is recovered from original instructions; the pinned current CFRunLoop header
does not declare it. Its two CMP/CSET instructions are separately executed for
all256 u8 inputs, producing0 only for0 and1 otherwise. That is512 separately
counted visits, not256 complete run-loop executions.

The Run duration at0x184951c40 is exactly10000000000 s as binary64. The captured
internal comparison threshold at0x184951c58 is504911232 s. The selected greater
branch bypasses deadline-source creation. This is an argument/branch result,
not a measured wait, native timeout promise or general CF maximum duration.

## Stop, wake, return and cleanup contracts

Public publication makes runloop+0xa60 non-NULL before the declared callback
requests Stop. The actual Stop body reads the active depth, sets its stop byte,
and reaches WakeUp with the existing name0x807. Each of five cases emits the
original24-byte header `<0x13,24,0x807,0,0,0>` at CF call0x18473af30, options0x11,
then executes original wrappers and SVC0x180547c1c with selector-47. The SVC
result0 and its status-only/no-memory-effect contract remain supplied. No native
kernel ingress or message delivery occurs in this increment.

| Selected callback-stop path | Internal RUN result | Indexed stop byte after return | Public status meaning |
| --- | --- | --- | --- |
| Specific, optiontrue | 4 | 1 in popped record | handled |
| RunInMode, optiontrue | 4 | 1 in popped record | handled |
| Specific, optionfalse | 2 | 0 | stopped |
| Run, optionfalse | 2 | 0 | public return is void |
| Specific, old depth253 / optiontrue | 4 | 1 at index254 | handled |

The popped record's flag/option cells are not all restored by cleanup. Current
mode and depth are restored. These are selected original writes/return paths;
native stop races, reentry and subsequent resource lifecycle remain unknown.
Depth253/254/255 and prior-mode values are explicit context diagnostics, not
observed nesting history.

The original wrapper stack changes receive-buffer placement. The probe derives
the internal RUN frame as entrySP-0xd50 and the receive buffer as frame+0xd0.
RunSpecific/RunInMode and Run can therefore have different concrete buffer
addresses. The original nonblocking options0x07000906/capacity3072 B/timeout0
receives a declared MACH_RCV_TIMED_OUT0x10004003 result. Idle options0x07000806
with timeout0xffffffff stop before API effects. No incoming message is injected.

Conditional ownership accounting now starts at zero at public entry rather than
assuming internal locks held. Twenty cases have no unmatched unlock request;
callback levels are zero and completed normal cleanup returns tracked levels
to zero. Depth-limit boundaries stop while the mode/run-loop levels are1.
These levels derive from modeled successful calls and do not prove native
ownership or mutual exclusion.

The diagnostic empty-mode case additionally requests mode unlock at
0x184831b6c, returning to0x184831b70, without a matching recorded mode lock.
Its raw count/backend removal was explicitly supplied after registration;
retention/hash and native mutex results remain modeled. This observation is
preserved separately and excluded from the20 sequences without unmatched unlock.
Native
ownership, the actual unlock result and native reachability of that fixture
are unknown; no native failure conclusion follows from it.

## Thread-specific data interface

| Original address | Recovered operation |
| --- | --- |
| `0x184717c88` | GetCurrent requests TSD index10; a non-NULL result returns directly |
| `0x1846dbbb8` | GetTSD supplies create-if-needed1 and branches to accessor |
| `0x1846dbbc0` | Getter checks unsigned w0<70, obtains table, reads value |
| `0x1846dbc30` | Table helper reads TPIDRRO_EL0, then pointer at TLS+0x1b8 |
| `0x1846ddde4` | Setter checks index<70, returns prior value and stores value/destructor |
| `0x1848d34d8` / `0x1848d3500` | Invalid getter/setter index diagnostic boundaries |

For index i in0..69, the original getter/setter use:

```text
table+0x008 + 8*i : value
table+0x238 + 8*i : destructor pointer
```

The two70-entry arrays occupy560 B each, following8 B of header:
`8 B + 70*8 B + 70*8 B = 1128 B = 0x468 B`.
The original table helper's allocation request in its NULL-table branch is
also0x468 B, but that allocation branch does not execute here. A pointer equal
to0x1000 takes a special NULL-result branch; native teardown/sentinel history
and fallback loop creation are unknown.

Public RunInMode/Run cases execute the present-table path and read the declared
slot10 reference to the original private loop. Main-thread identity and equality
with GetMain are not established. Three daemon binds refer separately to Run,
Stop and GetMain; their native thread/global identities are not unified by this
TSD fixture.

Seventy isolated fixtures execute original set/get/restore on every valid index,
with distinct prior values/destructors, full-table comparisons and guard bytes.
Each setter returns the old value; the getter returns the new value; restoration
recovers all1128 original bytes. Two index70 fixtures stop before the original
error helper and leave the table unchanged. These72 scenarios make212 original
helper calls and8073 separately counted instruction visits. Destructor pointer
values are stored; destructor functions are not invoked. Native table creation,
thread exit, allocation failure and destructor ownership remain unknown.

## Finite cases and verification

| Case | CF visits | Original boundary / result |
| --- | --- | --- |
| specific_ready | 3351 | wrapper return4 |
| specific_stale | 3325 | wrapper return4, no daemon callback |
| specific_EIO | 3333 | wrapper return4, no daemon callback |
| specific_stop | 3632 | wrapper return4, original Stop/wake |
| inmode_ready | 3425 | wrapper return4 |
| inmode_stop | 3706 | wrapper return4, original Stop/wake |
| Run_stop | 3721 | public void return after internal2 |
| no_pending | 2587 | before blocking receive, depth1/current mode active |
| missing_mode | 2205 | finished1 |
| common_mode | 2104 | finished1, warning once declared complete |
| null_mode | 2100 | finished1, warning once declared complete |
| deallocating | 2090 | finished1 under changed raw flag |
| depth1_previous | 3351 | return4, restore depth1/opaque previous mode |
| depth253_stop | 3632 | return4, Stop/wake at index254 |
| depth254 | 2252 | before original depth-limit helper |
| depth255 | 2252 | before original depth-limit helper |
| wrong_type | 2057 | before original type-mismatch helper |
| fork_diagnostic | 2060 | before original fork diagnostic helper |
| boolean2 | 3351 | normalized true, return4 |
| boolean0_stop | 3645 | normalized false, return2 after Stop/wake |
| empty_mode | 2300 | finished1; extra unlock observation separated |

Twenty-one CF cases check60479 original instruction visits and66060288 B complete
final private RAM (`21 * (1+2) * 1048576 B`). Three freshly replayed separate
daemon initializer/setup/callback epochs check27813 visits and7323648 B complete
mutable RAM. Component totals are
`60479 + 27813 = 88292` visits and
`66060288 B + 7323648 B = 73383936 B`.
The8073 TSD-helper and512 normalization visits are separate and outside those
totals and their complete-final-private-RAM claim. Negative controls are also
outside the positive totals.

Independent CF replay checks8510 tracked register frames,15706 ordered reads,
14168 ordered writes,74 original sync block entries/returns,335 public-context
snapshots and five original outgoing SVC visits. Tracked register frames include
31 GP registers,32 Q registers, SP and NZCV, not every architectural system
register. The new frames include full2720-byte run-loop,512-byte mode and
1128-byte TSD snapshots; all3 MiB final private RAM per component is checked.
Selected cache globals, warning predicate and guards are checked separately;
the claim does not cover every mutable cache page.

Eleven arm64e SDK assertions cover Boolean/time/index/context widths, Run and
RunInMode signatures, result constants and Mach timeout constants. Eight altered
records must be rejected: public instruction bytes, TSD current reference,
published mode, saved previous mode, dynamic receive pointer, Stop-entry context,
callback-resume CPU and final warning predicate. Static source and all saved
dependencies are checked independently of the execution journals.

The normal entry lock context is now produced by original wrapper instructions.
Runtime allocation/registration, name/hash/retention, successful mutex/tracing,
dispatch/POSIX/ObjC effects, warm TSD registration, callback body/effect handoffs,
logical PAC, SVC status and receive timeout remain explicit lower contracts.
The pending-block/clock, empty-observer and single-source premises retain their
previous scope. Original multi-source sorting, actual observer callbacks and
native event/ownership/error behavior are not established.

Time is `O(S + V*F + J + H*R + K)`, with source bytes S, component visits V,
function intervals F scanned per hook, journal volume J, whole-memory handoffs H,
private RAM R and isolated helper visits K. Space is `O(S + J + R + K)` for
retained evidence. The256-input normalization and70-slot round trips are bounded
domains, not searches over process histories or all64-bit pointer values.

## Bounded continuation context

| Impact | Remaining interface / consequence |
| --- | --- |
| High | Join the original daemon callback/GetMain body to this actual CF identity and published context, then complete successful daemon/kext request/reply and deeper-facility pairing. |
| High | Continue original multi-source array/sort and observer paths; these public-entry cases retain one descriptor source and empty observer activity. |
| Medium | Establish native thread/main-loop/TSD registration and first-use/fallback behavior; warm slot10 does not prove GetMain identity. |
| Medium | Replace raw hash/retention and mutex results to resolve ownership interpretation of the empty-mode diagnostic's extra unlock request. |
| Medium | Feed actual kernel-produced wake/service receives into this public-entry state; current receives are timeout contracts or pre-effect boundaries. |
| Medium | Execute TSD first allocation, sentinel teardown and destructor callbacks before making lifetime or thread-exit claims. |
| Low | Recover common/NULL-mode first-warning and cold diagnostic effects; current warning predicate and helper boundaries are explicit. |

Original supplied analysis/C/call files and annotated RAX trace remain preserved.
The [trace report](zut_trace_report.md) records failed UserClient opening; these
private CF paths do not establish a successful selector26 or RPC502/700 exchange.
Current report hashes and links are in
[the interface manifest](triage_evidence/interface_manifest.json).

## Quality gates

QG1: Factual source, ABI and conditional execution analysis requires no normative
premise.

QG2: PR1-PR8 identify dependent claims, diagnostic fixtures and falsification tests.

QG3: Public/exported entry, current-mode/depth publication, selected cleanup,
TSD storage and same-CF-epoch Stop/wake are covered for this increment. Broad-goal
gaps remain explicit and full_goal_complete remains false.

QG4: Byte widths, indexed offsets, seconds-valued arguments, statuses, RAM/visit
totals, isolated domains and algorithm complexity are reproducible.

QG5: Void versus status return, handled-versus-stopped priority, idle context,
depth/type/fork diagnostics and the empty-mode extra unlock are distinguished.
The latter is not used as native ownership/failure evidence.

QG6: Original daemon/cache bytes, binds/exports, independent replay, SDK assertions
and original helper execution provide primary evidence. Native caller identity,
GetMain equivalence, scheduling, IPC and hardware PAC are not claimed.

QG7: Impact-labeled extensions cover shared daemon state, multiple sources,
thread registration, hash/lock ownership, kernel receive and TSD lifetime.
