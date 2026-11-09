# AES synchronous wait: original event, saved caller and reclamation contract

The NULL-callback path now reaches original command-gate/workloop sleep code and the `_lck_mtx_sleep` boundary with event equal to the same source-leased carrier. Completion reaches original command-gate/workloop wakeup and `_thread_wakeup_prim` with that event. Three explicit resumptions of the saved caller establish status propagation, pool reclamation and the nonzero sleep-result assertion branch. Native wait registration, scheduling, hardware results and constructor/daemon continuity remain unknown. [SW1-SW8]

```text
fresh source-constructed 32-carrier pool
  -> original provider configuration/binding
  -> performAES(NULL callback) -> lease/pack/queue same carrier C
  -> declared submission return, no hardware effects
  -> commandSleep(gate,C,0) -> inGate -> event-source/workloop sleep
  -> save and clear owner/depth bookkeeping
  -> _lck_mtx_sleep(lock,0x10,C,0) [SAVE caller registers + 280-byte stack]

declared completion event/status on C
  -> completeAESQuantum -> descriptor complete models
  -> commandWakeup(gate,C,false) -> workloop wakeup
  -> _thread_wakeup_prim(C,false,0) [BOUNDARY / no-effect model]

explicit object transfer + exact saved caller context
  -> declared sleep result -> original owner/depth restoration
  +-> result == 0: read C.status -> return C to pool -> public return status
  `-> result != 0: assertion frontier before status read/reclamation
```

[Original source and five bindings](triage_evidence/aes_synchronous_wait_source.json), [12 profiles](triage_evidence/aes_synchronous_wait_profiles.json), [independent replay/oracles](triage_evidence/aes_synchronous_wait_checks.json), [preservation](triage_evidence/aes_synchronous_wait_delivery.json) and [scoped gates](triage_evidence/aes_synchronous_wait_quality_gates.json) retain the evidence. The external pool snapshot is case 15 of the [carrier initialization profiles](triage_evidence/aes_carrier_initialization_profiles.json), with original base-constructor word+8=1. This increment propagates that refreshed state into the later interface components. The [earlier completion report](aes_completion_contract_report.md) remains the asynchronous/common-consumer context.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SW1 | The pinned collection supplies all captured source, symbols and chained slots. | Rehash it; recapture 50 functions / 4629 instructions and five authenticated bindings. Different runtime builds require remapping. |
| SW2 | The refreshed source-constructed pool transfers exactly into a declared candidate provider instance; full subclass construction and native provider identity are unknown. | Match actual service/class/resources and carry authentic object identities through initialization and submission. |
| SW3 | Key metadata, descriptor API results and submission return remain declared no-effect models; no device output is generated. | Recover authentic descriptor backing, key data, driver resources and submission/result before applying the path to hardware. |
| SW4 | Completion enters directly with declared u32 status and event state. Its causal relation to the suspended native thread is unproved. | Establish authentic completion producer, carrier epoch and kernel event registration. Object equality in the private components alone is insufficient. |
| SW5 | Resumption copies the exact saved registers/NZCV/SP/stack and completed object images, then supplies a declared sleep result. | Match an actual blocked thread, wake result and restored context. No model claims to run a scheduler or register/wake a native waiter. |
| SW6 | TPIDR_EL1 is a declared private thread identity, raw workloop lock depth starts at 3, and lock operations remain no-effect models. | Match native thread/owner/recursive-lock state and physical exclusion. Bookkeeping restoration is not proof of native unlock/relock balance. |
| SW7 | Logical PAC and inactive statistics premises carry forward. Event-source/workloop statistics pointers are null in the executed branch. | Match hardware PAC and live instrumentation state; recover clock/system-register paths before applying timing/statistics behavior. |
| SW8 | Kernel wake execution stops before wait-queue lookup; sleep execution stops at the kernel boundary or substitutes a declared return. | Recover actual wait-queue globals, event membership, scheduler and lifetime/epoch correspondence before claiming eventual wakeup or full constructor continuation. |

## Primary identity and dispatch

Primary collection: `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Exact nlist names, complete compiler function ranges, original bytes and chained records are captured. Source recapture and replay use the original file without IDB changes.

| Receiver / offset from vptr | Original slot | Exact decoded target | Diversity |
| --- | --- | --- | --- |
| Gate `0xfffffe0007f3fbb0` +0x200 | `0xfffffe0007f3fdb0` | `IOCommandGate::commandSleep(void*,unsigned int)`, `0xfffffe000c51e1d4` | 0x6db9 |
| Same +0x208 | `0xfffffe0007f3fdb8` | `IOCommandGate::commandWakeup(void*,bool)`, `0xfffffe000c51e19c` | 0xf36c |
| Workloop `0xfffffe0007f3f638` +0x158 | `0xfffffe0007f3f790` | `IOWorkLoop::inGate() const`, `0xfffffe000c51a38c` | 0x0f09 |
| Same +0x1b0 | `0xfffffe0007f3f7e8` | `IOWorkLoop::sleepGate(void*,unsigned int)`, `0xfffffe000c519a8c` | 0xa662 |
| Same +0x1b8 | `0xfffffe0007f3f7f0` | `IOWorkLoop::wakeupGate(void*,bool)`, `0xfffffe000c519a78` | 0x0dec |

All five original records are format 8, authenticated, key=0/IA and address-diversity=1. These records and source modifiers establish logical call targets; hardware authentication remains untested. [SW1,SW2,SW7]

## Original sleep and wake interfaces

`IOCommandGate::commandSleep` calls the attached workloop's `inGate` method, tests returned bit 0 and reaches an assertion-handler call if it is clear. The captured `inGate` source compares the original lock-owner field with emulated TPIDR_EL1. In the declared non-owner case, execution stops at `0xfffffe000c62a2b0` before that handler. No sleep backend executes in this case.

With the owner premise satisfied, commandSleep tail-branches to `IOEventSource::sleepGate(void*,unsigned int)`, `0xfffffe000c51c928`. That method calls attached-workloop virtual +0x1b0. Statistics branches are bypassed under the retained null statistics pointers; their clock/system-register source is captured but not exercised.

| Ordered workloop event | Exact PC / resulting ABI |
| --- | --- |
| Read mutex pointer from workloop+0x10 | `0xfffffe000c519b14` |
| Save u32 depth from mutex+0x20 in W23 | `0xfffffe000c519b18` |
| Clear depth bookkeeping | `0xfffffe000c519b1c` |
| Clear owner bookkeeping at mutex+0x18 | `0xfffffe000c519b20` |
| Call `_lck_mtx_sleep` | `0xfffffe000c519b34`; X0=mutex, W1=0x10, X2=carrier event, X3=0 |
| Read emulated current thread after declared return | `0xfffffe000c519b38` |
| Restore owner, then saved u32 depth | `0xfffffe000c519b3c`, `0xfffffe000c519b40` |

Clearing these fields is original workloop bookkeeping. It does not itself demonstrate native mutex release. The `_lck_mtx_sleep` body at `0xfffffe000bd0c8f4` is captured statically and contains an `_assert_wait` call at `0xfffffe000bd0c940`; kernel blocking/lock code is unexecuted in the profiles. Raw action 0x10 and interruptibility 0 are reported without assigning an unmatched source-enum name. [SW5-SW8]

The common NULL-callback finalizer tail-calls commandWakeup with gate, carrier and false. Original commandWakeup loads its attached loop, dispatches virtual +0x1b8, and workloop wakeup maps arguments to `_thread_wakeup_prim(event,bool,0)` at `0xfffffe000bd2b480`. The third argument is explicitly zero. The carrier pointer remains the event identity throughout.

Two kernel prefixes execute only through Boolean/count selection and stop at `0xfffffe000bd2b4ac`, before any wait-queue global read or lookup:

| Declared wake Boolean | Raw W4 before lookup |
| --- | --- |
| false / 0 | 0xffffffff, equal to -1 when interpreted as signed32 |
| true / 1 | 1 |

The later event hash, wait-queue helper and return translation are captured source context; no wait queue is constructed or manipulated. Two separate completion-return components substitute a no-effect result at the kernel wake entry, allowing the original common continuation to return. These models do not assert that a waiter existed. [SW4,SW8]

## Exact saved-context continuation and result ownership

The 32-byte synchronous request reaches the kernel sleep boundary after original provider configuration/binding, metadata/descriptor checks, pool acquisition, carrier packing and queue/quantum publication. Candidate submission supplies only an arbitrary ignored return register, 0x1122334455667788, with no device or memory effects. The active carrier remains outside the outer pool, provider busy is 1, gate packed state is 0x100, and source workloop owner/depth bookkeeping is zero at the sleep boundary.

The profile saves all 31 X registers, NZCV, SP and exactly 280 stack bytes from the kernel-call boundary through the original caller's stack arguments. This includes caller frames generated by the original source; no frame is reconstructed from an inferred C layout. Resumption restores that exact context while explicitly transferring the completion component's final object images. It then substitutes the declared kernel sleep return at the same callee boundary.

| Continuation event | Exact source PC | Established behavior |
| --- | --- | --- |
| Test sleep result | `0xfffffe000abfd3f8` | Nonzero branches to cold assertion entry `0xfffffe000abff924`; profiles stop before its body. |
| Read carrier status | `0xfffffe000abfd3fc` | Only after zero sleep result; reads u32 +0x78 into W21. |
| Return carrier to outer pool | `0xfffffe000abfd428` | Original pool/gate/list code reclaims the same carrier after status is cached. |
| Return cached result | `0xfffffe000abfd42c` | X0 receives zero-extended status. Original runAction bookkeeping restores packed gate state and returns it. |

Original `performAES` tail-calls runAction at `0xfffffe000abff8f0`. The successful declared sleep-result cases therefore reach the public caller with X0 exactly 0 or 0xe00002bc, rather than a sign-extended 64-bit negative value. Carrier status is transferred from the declared completion component; the resumed source does not rewrite it. The source returns the carrier only after reading that status, restoring outer-pool capacity from 31 to 32 in these cases.

The nonzero sleep-result case restores workloop owner/depth bookkeeping but reaches the assertion frontier with the carrier still leased and gate packed state 0x100. This is a bounded terminal assertion path, not evidence of a native leak, returned IOReturn or recovered error policy. Sleep result and carrier result are separate channels. The completion routine's own raw returned X0 is the provider pointer in its completed components and is not the synchronous result status. [SW3-SW6]

## Finite cases and verification

| Cases | Component | Verified boundary / result |
| --- | --- | --- |
| 0-2 | Fresh constructed pool -> hardware configuration slice -> common limits -> action binding | Original component boundaries; all 32 base words +8=1 preserved. |
| 3 | NULL-callback request, raw lock depth fixture 3 | Original kernel-sleep boundary; same carrier event and exact 280-byte stack captured. |
| 4 | Declared status 0 completion | Original kernel false-wake prefix; stops before wait-queue lookup. |
| 5-6 | Declared status 0 / 0xe00002bc completion, kernel-wake no-effect return | Common source returns; carrier remains leased for the waiter. |
| 7-8 | Exact saved caller + completed objects; declared sleep result 0 | Original status read, carrier pool return and public X0=0 / 0xe00002bc. |
| 9 | Same saved caller; declared sleep result 1 | Stops before nonzero-sleep assertion body; no status read or pool return. |
| 10 | Declared missing lock owner | Original inGate check reaches assertion-handler boundary; no kernel sleep. |
| 11 | Direct wake Boolean true | Original kernel prefix gives W4=1; stops before lookup. |

Fresh independent A64 replay checks 1572 original instruction visits, 209 writes (1616 bytes), 407 reads (3177 bytes), 95 logical authentication steps, 53 indirect edges, 29 no-effect API models, 12 boundaries and 588 final object images. Additional oracles check exact refreshed-pool transfer, 384 preserved base words, 11 object transfers, three exact saved-context resumptions, two read-before-reclaim/public-result orders, ownership/assertion frontiers and both raw wake counts.

Run from the extracted directory: `PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_aes_synchronous_wait.py`. Complexity is O(image bytes + instruction visits + journal events + carriers) time and O(image bytes + journals + private RAM) space. Offsets/addresses are hexadecimal; byte counts and operation counts are exact integers; one byte is 8 bits. No duration or native scheduling latency is inferred.

## Bounded continuation and scoped quality gates

| Impact | Remaining evidence | Purpose |
| --- | --- | --- |
| High | Authentic IRQ/job status producer and complete hardware submission | Connects declared event/status inputs to actual driver output. |
| High | Matching native waiter registration, queue membership and scheduler result | Establishes causal sleep/wakeup and actual caller resumption. |
| High | Actual provider/descriptor/key identity through the original FairPlayIOKit constructor | Connects this public API contract to authentic warm-state publication and subsequent daemon RPC. |
| Medium | Runtime statistics/clock branches and real lock/reference accounting | Establishes enabled instrumentation and synchronization effects beyond the current premises. |
| Medium | Carrier epoch and wake-event lifetime under multiple pending requests | Resolves ownership across reuse and scheduling; no concurrency conclusion follows from these serial components. |
| Low | Broaden valid lengths and queued-command counts under the established local ABI | Extends finite coverage without implying hardware execution. |

QG1: The increment requires descriptive technical evidence only.

QG2: SW1-SW8 enumerate assumptions, dependent results and falsification probes.

QG3: The increment covers refreshed pool propagation, synchronous caller/event ABI, original workloop bookkeeping, wake prefix, saved-context result/reclamation and assertion frontiers. Full native daemon/kext recovery remains active.

QG4: Pointer/status widths, u32 extension, exact stack extent, byte units and finite counts are explicit and reproducible.

QG5: Hardware status, kernel sleep result, wake return, public result and bookkeeping are separated. Native event causality, actual waiter membership, timing and resource epochs remain explicitly unknown.

QG6: Original bytes, exact symbols/fixups, source-produced stack/object state and fresh CPU/read/write replay provide provenance. No native device, descriptor, scheduler, Mach IPC, PAC or IDB mutation executes.

QG7: The bounded continuation table identifies unresolved architectural joins and their impact. Scoped gate passage does not establish authentic hardware completion, native wakeup or full constructor/daemon continuity.
