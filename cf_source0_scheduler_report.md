# Original source-0 collection, dispatch and descriptor callback control flow

Original CF run-loop instructions now select the descriptor's registered
version-0 source, clear its signal timestamp, invoke its stored Perform/info
pair, complete the descriptor readiness recheck and return through the original
source-0/run-loop paths. This replaces the explicit Perform entry of the
[preceding factory investigation](cf_descriptor_source_factory_report.md).
The private entry remains the internal run-loop function; its outer public
wrapper, native thread scheduling and caller-held locks are not established.

The selected scheduler returns handled even when descriptor Perform suppresses
the daemon callback because readiness is stale or EIO. A NULL Perform diagnostic
also returns handled. With returnAfterSourceHandled=1 and a declared timeout for
the subsequent zero-time Mach receive, original RUN returns4, independently
checked as kCFRunLoopRunHandledSource. This result is not evidence that fairplayd
processed a signal/event, that a Mach packet arrived or that a kext transaction
succeeded. The daemon callback body is an explicit void-return model here;
three separate original daemon epochs verify its producer/consumer ABI again.

## Primary evidence and reproducibility

Retained records: [source identities and complete bodies](triage_evidence/cf_source0_scheduler_source.json),
[16 component cases](triage_evidence/cf_source0_scheduler_profiles.json),
[independent checks and comparator cases](triage_evidence/cf_source0_scheduler_checks.json),
[preservation seal](triage_evidence/cf_source0_scheduler_delivery.json),
and [scoped quality gates](triage_evidence/cf_source0_scheduler_quality_gates.json).
The [probe](triage_evidence/probe_cf_source0_scheduler.py) and
[independent replay](triage_evidence/replay_cf_source0_scheduler.py) implement new
lower contracts separately; the replay does not import the new probe. Frozen
loaders and prior component contracts remain shared dependencies.

The daemon thin image remains SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`,
UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. Cache UUID is
`2bd06591-e751-3e84-963f-b08dab6af23a`; CF UUID is
`7fe5392e-ff16-31e1-8552-3a45c6b68224`. Nine cache files are freshly hashed.
The source capture contains115 complete cache routines and28 inherited stubs,
totaling11478 captured instructions. Five additional16-byte lower stubs and
their original chained pointers/export owners are checked separately; their20
words are outside that total. No new IDA queries or database changes were needed.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_source0_scheduler.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_source0_scheduler.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_source0_scheduler.py
```

Current dependencies include Unicorn2.1.4, Capstone5.0.7 and the local arm64e
SDK/compiler. Three direct SDK headers are hashed; the entire SDK/compiler and
transitive headers are not hashed. This process does not run the host daemon,
native CF/ObjC/dispatch/thread/descriptor APIs or target Mach operations.

## Assumption register

Execution-derived conclusions depend on S01-S08 as applicable. Static identities
depend on S01. Comparator results additionally depend on the explicit S08 FP
context. Native facts outside these bounds remain unknown.

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| S01 | Recorded daemon/cache pairing and unslid addresses identify the static API contract. Runtime loader selection/slides remain unknown. | Recapture complete bodies and original RUN callsite; hash all nine cache files, raw stub pointers and exact native exports. |
| S02 | Descriptor/source raw storage, type registration, once completion, strings, retained collection/runtime effects and API results retain prior explicit premises. Source storage now carries declared runtime type46 in header bits8..17. | Execute original CFGetTypeID and its non-ObjC path; check raw0x2e00 header plus valid bit3 and reject a changed runtime header. Native allocation/registration/lifetime remain unknown. |
| S03 | The source0 hash-add backend supplies physical count1 and bucket-index metadata; bucket extraction returns the registered source. | Execute original CFSetGetCount, BasicHashGetCount, SetApply, BasicHashApply and callback trampoline; compare full state and raw set64 B. Real hash allocation/layout/retention are not proved. |
| S04 | Internal RUN is entered with mode/run-loop ownership assumed once; pthread lock/unlock and tracing return modeled success without native effects. | Resolve exact mutex exports and derive a conditional lock ledger from every recorded call after entry. Check callout at zero levels and final held levels on RUN return; actual ownership/exclusion and the outer public wrapper remain unknown. |
| S05 | Original descriptor enable sees declared immediate readiness; later pselect readiness/errno are supplied. Daemon callback returns through a declared void contract. | Ready/stale, read/write/both, EINTR/EAGAIN/EIO and NULL Perform cases; compare x0/x1/x2, original saved targets, timestamp and complete tracked register/journal state. The daemon callback body does not execute in this CF epoch. |
| S06 | Diagnostic source/version/signal/pool changes occur at explicitly recorded boundaries after original registration or collection. | Check exact before/after bytes and late-change frames. These discriminate field/branch contracts; they do not establish a native race, version1 AddSource path or reachable corruption. |
| S07 | Original nonblocking receive returns declared MACH_RCV_TIMED_OUT without memory effects; blocking receives are observation boundaries. ObjC pool push/pop provide one declared token. | Verify original arguments/options, timeout/result constants, pool token ordering and reject altered statuses/tokens. Native receive, SVC, pool allocation/reclamation and scheduling remain unknown. |
| S08 | Instructions execute in private MAX-feature ARM CPUs; PAC is logical. Comparator probes use enabled FP, FPCR0 and raw signed64 orders/unsigned64 ticks. | Independent instruction/read/write/CPU/final RAM replay,11 SDK assertions,14 isolated comparator cases and eight rejected alterations. No hardware PAC/FP or exhaustive64-bit ordering claim follows. |

## Executed control flow and architectural boundaries

```text
original descriptor Create -> Enable(ready) -> SourceCreate -> AddSource
  -> explicit internal RUN entry (outer wrapper/lock ownership assumed)
     -> original BL at0x1847571b8
        -> DoSources0(runloop,mode,stopAfterHandle)
           -> SetGetCount -> SetApply -> CollectSources0
              version0 && valid && timestamp!=0 -> retained source head
           -> unlock mode; unlock runloop
           -> DoSource0: lock source
              timestamp!=0 -> clear timestamp -> read validity -> unlock
              valid -> saved Perform + info -> source0 callout wrapper
                 -> original descriptor Perform -> pselect recheck
                    -> ready: declared daemon callback return
                    -> stale/EIO: no daemon callback
              -> original pool-wrapper cleanup -> handled1
           -> release retained head; relock runloop; relock mode
     -> original nonblocking receive, declared timeout
     -> original internal RUN return4

ineligible source / changed signal / invalidated after collection
  -> DoSources0 returns0 -> original blocking receive entry boundary
```

The source0 scheduler is application/framework control flow around the daemon,
not a kernel scheduler and not a separate incoming Mach service. These cases
use immediate readiness during original Enable; they do not invoke a copied
dispatch handler. No outgoing wake SVC executes. The selected registration
schedule's WakeUp remains suppressed; control members607/707/807 stay in set507.
Dispatch-handler wake and kernel delivery contracts remain separately retained
in the [factory report](cf_descriptor_source_factory_report.md) and
[kernel wake report](kernel_wake_send_ingress_report.md).

The explicit internal RUN entry sets x0=runloop, x1=mode, x2=1 and D0 to positive
infinity under the inherited component contract. Original code forwards x2 to
DoSources0's stop-after-handled test. This does not recover every argument or
prerequisite of the outer public API; clock and other pending-work helpers
retain their prior declared returns.

| Original address | Exact source identity / decisive operation |
| --- | --- |
| `0x184756e7c` / `0x1847571b8` | Internal original RUN entry / BL to DoSources0 |
| `0x184758504` | Local nlist `___CFRunLoopDoSources0`; count, collection, single-head dispatch or multi-source array branch |
| `0x1847586e4` | `___CFRunLoopCollectSources0`; check source+0x68 version0, flags bit3 and +0x58 timestamp before retaining first source |
| `0x18471c38c` / `0x18471c6e0` | Original CFSetApplyFunction / original block callback translating bucket value into CollectSources0 arguments |
| `0x1847585c4` / `0x1847585cc` | Mode/run-loop unlock requests before source dispatch |
| `0x1847587d4` | `___CFRunLoopDoSource0`; second timestamp/validity checks and source-local locking |
| `0x184758804` / `0x184758808` | STLR zero to source+0x58 / subsequent validity load sequence |
| `0x184758820` / `0x184758864` | Load/authenticate source+0xb0 Perform / load source+0x70 info |
| `0x184758904` / `0x18475891c` | `___CFRUNLOOP_IS_CALLING_OUT_TO_A_SOURCE0_PERFORM_FUNCTION__` / BLRAAZ; move info to x0 before call |
| `0x1847b7ca0` / `0x1847b7e00` | Descriptor Perform / saved three-argument daemon callback call |
| `0x184758684` / `0x18475868c` | Relock run loop / mode after dispatch and retained-head release |
| `0x1846f7d14` | Original CFGetTypeID reads bits8..17 of declared source header; returns46 under explicit non-ObjC result0 |
| `0x1846e13d0` / `0x18471445c` | Original CF autorelease pool Push / Pop wrappers |
| `0x184832a70` | Original per-callout pool-end helper; selected normal path calls CF Pop only for non-NULL token |
| `0x184794e44` | Local `___CFRunLoopSourceComparator`, separately checked in14 isolated cases |

| Original lower stub | Resolved exact export | Owner / selected model |
| --- | --- | --- |
| `0x1880773c0` | `_pthread_mutex_lock` | libsystem_pthread; declared success |
| `0x1880773e0` | `_pthread_mutex_unlock` | libsystem_pthread; declared success |
| `0x188076ab0` | `_kdebug_trace` | libsystem_kernel; declared no effect |
| `0x188076e60` | `_objc_autoreleasePoolPush` | libobjc; declared token |
| `0x188076e50` | `_objc_autoreleasePoolPop` | libobjc; matching declared token |

The original descriptor/source layouts remain those documented in the preceding
report. Added raw source header0x2e00 supplies runtime type46; original SourceCreate
sets valid bit3, yielding0x2e08 in valid cases. This is a runtime-storage contract,
not proof that a native allocator returned that byte sequence. Original type
decoding executes rather than substituting a complete CFGetTypeID return.

The conditional lock ledger begins with mode/run-loop level1 and source level0
at internal RUN entry. Its original calls reduce mode/run-loop levels to0 for
callout, with source unlocked before Perform. They restore both levels to1
on the handled RUN-return paths. Idle-receive boundaries have both levels0.
These are consequences of modeled successful calls and an assumed entry state;
the probe does not acquire native locks or establish caller identity/exclusion.

The per-callout byte at runloop+0xa99 is1 after original construction. DoSource0
requests an autorelease pool when that byte is nonzero; the original wrappers
pass the declared push token through to matching pop after callout. A diagnostic
zero byte skips push/pop and preserves callback arguments/handled result.
Native autorelease ownership, exceptions and cold cleanup paths remain unknown.

## Receive, handled result and diagnostic field variants

| Selected original Mach API arguments | Nonblocking path | Idle boundary |
| --- | --- | --- |
| Receive facility | Existing set0x507 | Existing set0x507 |
| Options | 0x07000906 | 0x07000806 |
| Receive capacity | 3072 B | 3072 B |
| Timeout argument | 0 | 0xffffffff |
| Send size / notify | 0 / 0 | 0 / 0 |
| Lower behavior in probe | Declared0x10004003, no memory effects | Stop before API effect |

The option difference0x100 and status0x10004003 are compiled SDK assertions for
MACH_RCV_TIMEOUT and MACH_RCV_TIMED_OUT. The original CF caller returns to
0x184758ac8. Actual Mach API/wrapper/SVC execution and queue emptiness are not
established by this timeout contract. No message bytes are injected in this
increment. The full original receive branch and subsequent RUN status decision
execute after the supplied result.

| Case | CF visits | Source0 handled | Daemon mask | Boundary / final timestamp ticks |
| --- | --- | --- | --- | --- |
| read_ready | 3055 | 1 | 1 | RUN4 / 0 |
| read_stale | 3029 | 1 | none | RUN4 / 0 |
| write_ready | 3060 | 1 | 2 | RUN4 / 0 |
| both_ready | 3329 | 1 | 3 | RUN4 / 0 |
| read_EINTR | 3080 | 1 | 1 | RUN4 / 0 |
| read_EAGAIN | 3084 | 1 | 1 | RUN4 / 0 |
| read_EIO | 3037 | 1 | none | RUN4 / 0 |
| no_pending | 2342 | 0 | none | idle receive / 0 |
| invalid_source | 2451 | 0 | none | idle receive / 100 |
| version1_diagnostic | 2447 | 0 | none | idle receive / 100 |
| cleared_signal | 2454 | 0 | none | idle receive / 0 |
| null_perform | 2779 | 1 | none | RUN4 / 0 |
| pool_disabled | 3028 | 1 | 1 | RUN4 / 0 |
| cached_source | 3245 | 1 | 1 | RUN4 / 0 |
| invalidated_after_collection | 2519 | 0 | none | idle receive / 0 |
| cleared_after_collection | 2515 | 0 | none | idle receive / 0 |

Eligibility requires version0, valid bit3 and nonzero timestamp during collection.
DoSource0 repeats the timestamp and validity tests. Its original timestamp clear
precedes the second validity decision. Thus the late-invalidation diagnostic
clears100 to0 and skips Perform; late unsignaling sees0 and returns unhandled.
There is no assertion that these declared interleavings occurred natively.

The version1, NULL Perform, invalid-bit, signal-clear and pool-disable changes
are explicitly recorded field diagnostics after the actual descriptor source
was registered. Version1 here is not a legitimate version1 registration: the
object remains in the source0 set. The finite cases prove filtering and callout
behavior under those exact changed fields, not a native API lifecycle or
reachable failure. The cached-source case performs two original source requests
and retains the valid cached source/order0 as previously established.

Original descriptor rechecks retry EINTR4/EAGAIN35 and suppress the callback for
EIO5 or stale readiness. The source0 timestamp has already been cleared in all
these dispatched cases. NULL Perform also counts as handled because the callout
wrapper returns without invoking a function and DoSource0 subsequently returns1.
Pending descriptor bytes may remain set when Perform is absent; future recovery,
reenable, invalidation and closure are unknown.

## Isolated comparator context

The captured multi-source branch converts a single retained head into an array,
sorts it with0x184794e44 and iterates sources. That array branch has not executed
in these one-source cases. Fourteen separate original comparator executions
test signed64 orders first, then unsigned64 timestamp conversion/comparison in
binary64 under FPCR0. Original function results, input fields and instruction
visits are retained; there is no complete multi-source sorting claim.

| Equal-order timestamp pair (raw ticks) | Original comparator result |
| --- | --- |
| 100, 200 | -1 |
| 200, 100 | +1 |
| 2^53, 2^53+1 | 0 |
| 2^53+1, 2^53 | 0 |
| 2^53+1, 2^53+2 | -1 |
| 2^64-2, 2^64-1 | 0 |

These observed ties follow the selected binary64 conversion. They do not prove
native timing, a sorting failure, stability of equal elements or an alternate
tie-breaker elsewhere. The timebase and relevant native timestamp ranges are
unknown; raw ticks are not converted to SI time. Signed order extremes and
unequal-order precedence are included in the14 cases. Eleven SDK assertions
cover CFIndex signed64, binary64 size/precision, context80 B, receive constants
and the four public run-loop status values.

## Validation and evidence bounds

Sixteen original CF component cases check45454 visits and50331648 B complete
final private RAM (`16 * (1+2) * 1048576 B`). Three freshly replayed separate
daemon initializer/setup/callback epochs check27813 visits and7323648 B
complete mutable RAM. The component totals are
`45454 + 27813 = 73267` visits and
`50331648 B + 7323648 B = 57655296 B`. The14 isolated comparator cases add170
visits, reported separately; they are not included in the component totals or
their complete-final-RAM claim. Negative controls are also outside the totals.

Independent CF replay checks6414 tracked register frames,11792 ordered reads,
10535 ordered writes,58 original sync block entries/returns and342 scheduler
CPU/object/set/pool snapshots. A tracked frame contains31 GP registers,32 Q
registers, SP and NZCV; this is not the entire architectural system-register
file. All final private RAM and ordered journal entries are checked, along with
raw source/set/descriptor state, pool token ordering and original RUN callsite.
The standalone comparator explicitly enables FP and uses FPCR0. Native hardware
or all possible FP control contexts are not validated.

The previously modeled whole DoSources0/no-pending-source0 return is absent
from every new case. Original CFSetGetCount/BasicHashGetCount, SetApply,
BasicHashApply, collection callback, source0 scheduler, callout wrapper,
descriptor Perform and selected pool wrapper instructions execute. Raw hash
storage/bucket extraction, runtime validation/retention, dispatch/POSIX,
mutex/tracing, ObjC effects, daemon callback returns and nonblocking receive
remain declared. Source0 dispatch success does not replace those boundaries.

Eight deliberately altered records are rejected: scheduler instruction,
runtime type header, post-clear timestamp, callout Perform argument, pool token,
daemon callback mask, receive timeout result and late source-change bytes.
The conditional internal-entry lock ledger is checked for every case. Complete
static source and five lower export identities are recaptured independently of
the saved execution journals.

Replay/validation time is `O(S + V*F + J + H*R)`, with source bytes S, visits V,
function intervals F scanned per hook, journal volume J, whole-memory handoffs H
and private memory R. Space is `O(S + J + R)` plus retained per-case records.
The isolated comparator work is O(C) time for C bounded cases and constant
emulator memory. No exhaustive64-bit domain, native timing or unbounded search
is claimed.

## Bounded continuation context

| Impact | Remaining interface / consequence |
| --- | --- |
| High | Execute original public run-loop wrapper, thread-specific/current-mode setup and caller lock ownership before claiming a continuous public-entry event lifecycle. |
| High | Execute the multi-source collection/array/sort/stop-after branches; present cases establish one registered source and only isolate the comparator. |
| High | Join original daemon callback body with this actual CF identity in the same memory epoch, then continue successful daemon/kext request/reply and deeper-facility pairing. |
| Medium | Resume an actual kernel-produced wake receive into this scheduler state after copied dispatch-handler execution; current cases use immediate Enable readiness and no incoming packet. |
| Medium | Replace raw hash/retention and ObjC/dispatch/lock/receive results with original lower components; native ownership, cancellation and closure remain unknown. |
| Low | Determine native tick/timebase ranges and multi-source tie handling before assigning runtime relevance to the isolated binary64 comparator ties. |

The supplied analysis/C/call reference files and annotated RAX trace remain
preserved. The [trace report](zut_trace_report.md) still records unsuccessful
UserClient opening rather than a successful selector26 or RPC502/700 exchange.
Current hashes and report links are in
[the interface manifest](triage_evidence/interface_manifest.json).

## Quality gates

QG1: Factual source, ABI and conditional execution analysis requires no normative
premise.

QG2: S01-S08 identify dependent claims, explicit diagnostic entries and stress
tests, including the internal-entry ownership premise.

QG3: This increment covers original one-source scheduler selection/clearing,
callout, handled result, pool wrappers, receive return and comparator context.
Broad-goal gaps remain explicit; full_goal_complete is false.

QG4: Byte widths, signed/unsigned64 values, status constants, raw ticks, finite
FP context, totals and complexity are reproducible. No unknown timebase is
silently converted into seconds.

QG5: Stale/error/NULL Perform handled results, pre/post-collection invalidation,
version diagnostics and conditional lock ownership are distinguished. No
unresolved contradiction supports a positive conclusion.

QG6: Original source/stubs/fixups/exports, independent replay, SDK assertions and
finite helper cases provide primary evidence. Native scheduler/IPC/PAC/ownership
and daemon body execution are not claimed.

QG7: Impact-labeled extensions cover outer wrapper, multiple sources, actual
wake delivery, shared CF/daemon state, lifetime and timestamp relevance.
