# ADID notification classes, OTP cache, time and capacity interfaces

Original akd client code and an original ADID provider block use the same three notification classes. The client polls a selected token before a cache lookup; a changed flag or failed check can cause another synchronous ADID request. The provider's local block chooses the matching name and reaches `_notify_post` at `0x100219198`. Full-width proofs establish the matching DSID partitions. Successful full-request predecessors into that provider block remain unknown.

The client has two 40-byte cache records and distinct timestamp arithmetic on publication and lookup. Controlled variable-length replies also establish a capacity prerequisite: existing private cached MID/OTP buffers can be reused for larger lengths without an observed resize. Three synthetic witnesses cross their original malloc request extents; two overwrite a live model request pointer and stop before an unowned `_free`. **Native accepted reply lengths, allocator capacity/layout and a native defect remain unknown.**

```text
adid original local block [explicit frame/record/status fixtures]
  encoded-status gate -> DSID class -> notify_post(name)
                                      |
                         conditional named-event model
                         native delivery/admission unknown
                                      |
akd OTP client: register_check(name) -> integer token
  initial check baseline -> later selected notify_check(token)
      changed/error -> XPC refresh -> caller outputs + private cache copies
      unchanged     -> two-record lookup -> clock gate -> copied cache outputs

atexit registration -> original callback -> cancel V1, V1.5, V3
```

This extends the [named akd/ADID request/reply ABI](akd_adid_client_report.md). The separate [Avp packet interface](adid_avp_packet_report.md) and primary FairPlayIOKit/fairplayd interfaces retain their prior evidence boundaries. No new native Avp-to-primary-kext coupling is established here.

## Primary sources and retained evidence

All addresses are unslid addresses of the selected original arm64e subtype `0x80000002`. Client and provider occupy separate image namespaces even where numerical addresses coincide.

| Source | Identity / scope |
| --- | --- |
| Original co-installed akd | `/System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/Support/akd`; selected SHA-256 `097f11648c43cb0e360dcee4be9aa87d46153779f0ae21ea318883310a5a552a`; UUID `43016122-1388-34e5-a9aa-208d90ed00f8` |
| Original co-installed adid | `/System/Library/PrivateFrameworks/CoreADI.framework/adid`; selected SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`; UUID `4d24325f-3529-39b1-bbf8-64bbcf406049` |
| Original client entries | Named OTP proxy `0x10010db80`, C target `0x100308278`, registered exit callback `0x1002dcbec` |
| Provider local block | `0x100218fbc..0x1002191a8`, inside the larger protected routine; explicit local entry, record/status/register fixtures |
| SDK declarations | Installed MacOSX SDK `notify.h`, `sys/time.h`, `stdlib.h`; exact hashes and arm64e compile command retained |

Evidence: [complete contracts, original windows, bank reductions, proofs and SDK pins](triage_evidence/adid_notification_contracts.json); [85 stateful client sequences](triage_evidence/adid_notification_profiles.json); [23 explicit provider fragments](triage_evidence/adid_notification_post_profiles.json); [independent checks and conditional capacity witnesses](triage_evidence/adid_notification_checks.json); [scoped quality gates](triage_evidence/adid_notification_quality_gates.json). The [client producer](triage_evidence/probe_adid_notifications.py), [provider producer](triage_evidence/probe_adid_notification_posts.py), [recoverer](triage_evidence/recover_adid_notifications.py) and [verifier](triage_evidence/validate_adid_notifications.py) reproduce the increment without native target/API execution.

## Three-name notification ABI and source emission sites

The full-width partition is:

| DSID64 bit pattern | Notification name |
| --- | --- |
| Signed representations of -8, -6, -5, -4, -3, -2 | `com.apple.adid.midchangedV3` |
| Signed representation of -1 | `com.apple.adid.midchangedV1.5` |
| Every other 64-bit pattern | `com.apple.adid.midchangedV1` |

Client code `0x100308edc` first tests unsigned `(DSID+6) mod2^64 <5`, then separately tests -1 and -8 at `0x100308fe0`/`0x100308fe8`. Provider code uses the encoded nested+8 DSID field, modular addition, an unsigned eight-value range and bit mask `0xeb`. A full64 proof establishes both partitions and their equality. This is a local selection proof; DSID zero does not become a warm cache hit in the retained complete-client sequence.

| Name suffix | Client name address | Provider name address | Client token-output cell | Register site | Initial baseline-check site | Warm selected-check site | Exit cancellation site |
| --- | --- | --- | --- | --- | --- | --- | --- |
| V1 | `0x100347d23` | `0x1002941f0` | `0x100450548` | `0x100309b14` | `0x100309efc` | `0x100309070` | `0x1002dcda0` |
| V1.5 | `0x100347d05` | `0x1002a16b0` | `0x1004505a4` | `0x100309be8` | `0x100309e4c` | `0x100309124` | `0x1002dce18` |
| V3 | `0x100347d3f` | `0x1002ad240` | `0x1004505ac` | `0x100309ce0` | `0x100309d80` | `0x100308f64` | `0x1002dceb4` |

The last cancellation is an original authenticated tail branch. Its emission site is `0x1002dceb4`; LR points to the private call boundary in the guest and is not used to fabricate a source site.

The SDK and compile-only [ABI source](triage_evidence/adid_notification_layouts.c)/[arm64e assembly](triage_evidence/adid_notification_layouts.s) establish int32 token/check outputs and uint32 API statuses. `notify_register_check` establishes polling tokens without active notification delivery. The SDK also specifies an initially true check and permits coalescing/false positives. The default model therefore returns true on each newly registered token's first successful check; a separate zero-baseline control produces the same observed cache continuation.

These integers are not assigned Mach port-name meanings. The underlying libnotify registration transport, shared-memory mechanism, notifyd admission, native rights and Mach emission sites remain unknown. Matching the strings and local flag behavior establishes a conditional feedback interface, not actual native delivery or who may post the names.

## Provider post block and explicit predecessor boundary

Under the retained original request-frame checkpoint, state W21=`0xd5b` and bank/table inputs, the local block tests frame+`0x1648` against encoded marker **`0x59248f`**:

| Marker relation | Original table selection | Local result |
| --- | --- | --- |
| Equal | Index `0x27f1` -> `0x100218ff0` -> `0x100219008` | Select name and reach `_notify_post` at `0x100219198` |
| Unequal | Index `0x46d` -> `0x1002191a8` | Bypass the observed post |

The marker is an encoded local condition; its complete upstream application meaning remains unknown. The same continuation index `0x46d` supplies the immediate post-return target. Explicit post-result controls 0, 1 and `ffffffff` reach that same continuation; no subsequent behavior or native post result is inferred.

Original byte banks reduce the name/import selections independently over all256 byte inputs. The retained pointer members plus original addends resolve the three source strings and imported `_notify_post`. The original field reader composes the encoded holder pointer and nested pointer to read nested+8. The local record fixture supplies DSID XOR `da8ca8cae5dfbd2d` at that field.

The provider profiles begin at `0x100218fbc` with declared frame/status/record inputs and two declared register restorations. They do not execute the unproved predecessors after the earlier request checkpoint. Sixteen DSID controls, four nonmatching marker controls and three post-result controls retain this boundary. The three exact-name bridges join those conditional post observations to complete client changed-flag sequences; they execute no native post or delivery.

## Client registration, polling and exit lifecycle

The first retained successful OTP reply causes registrations in order V1, V1.5, V3. Original code then checks the new tokens in reverse order V3, V1.5, V1, establishes the baseline, and calls `_atexit` at **`0x100309fa4`** with callback **`0x1002dcbec`**. Store **`0x100309fb4`** publishes ready byte **`0x1004505a8=1`**.

Subsequent calls with the same nonzero DSID can poll only its selected token and return cache copies without dispatch queue construction, connection creation or synchronous XPC send. A changed flag, nonzero check status, DSID mismatch or failed clock gate causes the observed XPC refresh. Unselected notification names do not cause refresh in the controlled cases. Supplying `ffffffff` as a nonboolean changed value also causes refresh for the selected class; that is an explicit ABI stress control, not a documented notify output.

Registration failure stops the remaining registration suffix and leaves ready zero in the retained paths. Repeated calls retry the successful prefix. Successful prefix tokens remain in the explicit token model without an observed `_notify_cancel` or `_atexit` in those calls; complete native resource consequences remain unknown. A modeled `_atexit` failure still leaves ready one and permits a later cache hit, although the explicit exit model has no registered callback. This source status-consumption observation does not establish a native resource leak.

Invoking the original callback after successful modeled registration cancels V1, V1.5, V3 in order. Its last API call is a tail call. In both retained cancellation-result controls, the callback leaves the observed cache region unchanged and emits no `_free` for its cache buffers. Normal process-exit reclamation, concurrent invocation and any other cleanup path remain unknown. Incidental callback X0 values are not assigned a void callback return contract.

## Two-record cache and output ownership

The observed array starts at **`0x100450550`**, with two records of **40 bytes**. Record1 starts at `0x100450578`; the end is exclusive `0x1004505a0`.

| Offset, bytes | Width, bytes | Recovered role |
| --- | --- | --- |
| 0 | 8 | DSID64; zero is used as an empty key in these paths |
| 8 | 8 | Private cached MID pointer |
| 16 | 4 | MID byte count |
| 20 | 4 | Meaning unknown |
| 24 | 8 | Private cached OTP pointer |
| 32 | 4 | OTP byte count |
| 36 | 4 | Published unsigned32 time bucket |

Under the retained publication prefix, slot index is 1 exactly when `DSID != record0.DSID && record0.DSID !=0`; otherwise it is 0. Source `0x10030a094..0x10030a09c`, a full64 local proof and complete sequences establish this predicate. Sequence DSIDs 1,2,1 emits XPC for the first two calls and returns the last call from cache. Sequence 1,2,3,1 replaces record1's key2 with key3 while key1 remains cached. This is not evidence of an LRU policy.

Caller MID/OTP allocations and private cached copies are distinct in the retained executions. Cache hits allocate fresh caller output spans. The experimental caller leaves previous returned outputs allocated; those retained guest allocations are not labeled native leaks. Private cached pointers and lengths can be reused and updated on refresh. A controlled one-time changed flag refreshes the selected record without clearing the other record; the other DSID can subsequently hit its cache. The application meaning of cross-DSID event invalidation remains unknown.

## Different clock arithmetic on publication and lookup

The SDK compile verifies a 16-byte timeval: signed64 seconds at offset0 and 32-bit microseconds at offset8. These are explicitly supplied API values; native `_gettimeofday` is never called.

| Source | Exact recovered equation |
| --- | --- |
| Publication `0x10030bb20` | `published = floor((seconds64 mod2^32)/30)` using unsigned W-register division |
| Lookup `0x100308b14..0x100308b38` | `now = low32(trunc_toward_zero(signed_seconds64/30))` using signed high multiplication and shift/sign correction |
| Gate `0x100308b3c..0x100308b44` | Accept iff unsigned `published >= now` and `published-now <300` |

The lookup proof covers the signed64 domain and proves the intermediate sum remains representable. A separate BV proof establishes the low32 equivalence of the source logical shift and arithmetic-shift formulation. Publication and lookup agree for nonnegative seconds through `2^32-1`; a separate proof establishes that bounded equality. Negative seconds and larger positive values are not folded into that equivalence: retained controls expose their different narrowing behavior.

For the reference priming value **1700000000 s**, published bucket is **56666666**. The accepted current-bucket interval is 56666367 through 56666666. For this phase, current seconds **1699991010 through 1700000009** satisfy the bucket equation: relative offsets **-8990 through +9 s**. Retained adjacent controls -8991 s and +10 s refresh. This is a quantized, asymmetric wall-clock predicate; it is not a conventional elapsed-time TTL. A microseconds-only change to999999 preserves the tested hit; clock API failure instead falls through to refresh in its retained case.

## Conditional cache-capacity witnesses

Priming with synthetic successful reply MID=`abc` and OTP=`WXYZ` gives separate private cached malloc requests of 3 and 4 bytes. A changed-flag refresh with larger supplied spans reuses those private cached pointers and updates counts. The original common copy stores include **`0x100309618`**, **`0x100309624`**, **`0x100309634`**, **`0x100309838`**. No resize of those two destinations occurs in the retained refresh paths.

| Refresh MID / OTP lengths, bytes | Stores beyond intended original requests | Observed continuation |
| --- | --- | --- |
| 7 / 9 | 9 bytes | Returns zero; next cache hit reads nine bytes outside those original nominal requests and copies them to correctly sized new caller outputs |
| 17 / 17 | 27 bytes | Crosses adjacent live model allocations; reaches guarded `_free` argument `0x7b008071` |
| 33 / 33 | 59 bytes | Crosses adjacent live model allocations; reaches guarded `_free` argument `0x7877767574737271` |

The original free API site is **`0x10030ec68`**. The independently reconstructed request-pointer cell exactly equals each emitted unowned pointer. The API model stops before performing an unowned free; no host free or native fault occurs.

```text
Explicit model allocator layout, not native heap layout:

0x7b008060  private cached MID, requested3 bytes
0x7b008070  private cached OTP, requested4 bytes
0x7b008080  later live24-byte request record; data pointer starts here
              original pointer: 0x000000007b0080a0

17-byte OTP refresh reaches byte0 of that request-pointer cell:
              resulting pointer: 0x000000007b008071
33-byte OTP refresh reaches all eight pointer bytes:
              resulting pointer: 0x7877767574737271
```

The independent ledger tracks intended copy-object extent as well as all live allocation owners. A write can remain inside another live allocation while exceeding its intended destination; those are not treated as valid cache writes. All179 client calls have complete retained heap write/read and lifetime checks. These witnesses depend on **synthetic variable-length replies** and the explicit model allocator's sizes, alignment and placement. Valid provider MID/OTP length invariants, native usable capacity, adjacent objects, runtime serialization and native feasibility remain unknown. The evidence establishes a conditional capacity contract and model pointer corruption, not an exploitable native defect.

## Assumption register

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| N1 | Selected original arm64e slice underlies all addresses | Fresh SHA/UUID/chain readback; attest native slice before runtime mapping claims |
| N2 | Explicit import/PAC/vector/atomic models permit local code execution | Original instruction and pointer membership; hardware PAC/concurrency could select different outcomes |
| N3 | SDK declarations describe modeled API widths and baseline behavior | Compile exact headers; inspect actual libnotify implementation and runtime API/error behavior |
| N4 | Supplied zero-status replies are client-reader experiments | Recover provider-generated accepted MID/OTP grammar and sequence invariants before native success/capacity claims |
| N5 | Original complete client calls preserve guest state as retained | Independent pre/post cache/token/heap ledger and fresh full sequence replay; investigate native interleaving separately |
| N6 | Provider entry has explicit local frame/record/status/register fixtures | Recover feasible full-request predecessors and real marker producer before native post reachability claims |
| N7 | Original byte banks and source table members resolve the local post block | All1024 bank inputs and fixup readback; falsify with another source context/image before broader dispatch assignment |
| N8 | Time equations retain their distinct widths and signedness | Seven proof scopes and negative/large/boundary clock controls; inspect all error/default writers |
| N9 | Model malloc request size is a nominal object extent, not native usable capacity | Establish native allocation policy and accepted variable-length replies; different layout/capacity can falsify native consequences |
| N10 | Explicit token registration/cancellation ownership models match stated experiments | Inspect libnotify token reuse/reference semantics, failure output and process cleanup before resource-defect claims |
| N11 | Registered original exit callback can be invoked as a complete local function | Source callback address and tail-branch attribution; attest actual exit registration/delivery/lifetime separately |
| N12 | Exact-name provider/client bridge supplies a conditional changed flag | Recover notifyd per-name admission, IPC/shared-memory transport and actual delivery/order; name equality alone does not establish peer identity |
| N13 | Retained copy/lookup epochs and finite errors bound the current conclusions | Independent intended-object/lifetime/byte ledger and fresh replay; test complete accepted schemas, all errors, aliasing and concurrency |

## Validation, quality gates and bounded continuation

The current verifier checks 85 client sequences /179 original calls, 23 explicit provider fragments, 518932 source visits, 10551 heap writes, 6654 heap reads, 1988 cache reads, 760 API output effects, 1021 source gate observations, seven source windows,1024 byte-bank inputs and seven new unsat proofs. Fresh runs replay fifteen complete client sequences /36 calls plus five provider fragments. Source, SDK, pointer, model, finite-case and full-domain evidence remain separately labeled. All 85033 assertions pass, including the independent allocation/byte ledger and corrected tail-branch attribution.

Workflow complexity is O(B+F+V+W+R) time/space for source bytes B, fixups F, visited instructions V, writes W and reads R, plus bounded guest runs and seven30 s solver caps. Client runs have400000-hook caps, at most64 bounded allocation requests and8192-byte per-allocation/data extents in an owned heap region. Provider fragments have10000-hook caps. Normal retained cache-copy work is linear in copied MID/OTP bytes; the inspected array has two records. Complete native resource/worst-case bounds remain unknown.

| Impact | Next evidence | Interface consequence |
| --- | --- | --- |
| High | Actual provider MID/OTP lengths and successful reply sequences, including lifetime/type invariants | Establishes whether the conditional capacity prerequisite can occur with native accepted responses |
| High | Feasible full-request path into provider `0x100218fbc`, marker producer and surrounding operation | Connects the local post to actual provisioning/erasure/state transitions |
| High | Native libnotify/notifyd name admission, token/check transport and Mach/shared-memory boundaries | Establishes external invalidation authority, actual port emissions and feedback delivery |
| Medium | Partial registration failure and exit-registration failure through actual library semantics | Resolves token/resource accounting and cleanup guarantees |
| Medium | Multi-record event consumption, accepted DSID semantics and concurrency/locking | Resolves invalidation scope, replacement and stale-record prerequisites |
| Low | Complete clock error/default behavior and extreme-time narrowing across versions | Tests portability of the source clock/cache model |

QG1-QG7 pass for this stated increment: descriptive technical content; N1-N13 assumptions and probes; explicit local requirement coverage; reproducible widths/units/arithmetic; resolved source/model/tail-call/clock contradictions with remaining unknowns labeled; original sources, independent ledgers, SDK and fresh proofs/replays; impact-labeled continuation. No native target, loader, Mach, IOKit, notification, time or target-side file/environment/synchronization API was executed. The broader investigation remains active and incomplete.

The [preservation readback](triage_evidence/adid_notification_preservation.json) checks all827 prior artifacts:821 remain byte-identical;only five root indexes/status files and the manifest aggregator change. All three supplied inputs remain unchanged.
