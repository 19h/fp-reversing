# Two command gates: original workloop attachment and gate lifecycle

`IOWorkLoop::addEventSource` and `removeEventSource` use the workloop's internal gate at loop+0x20. That gate has owner=workloop and default action=`IOWorkLoop::_maintRequest`. The AES provider has a distinct gate with owner=provider and NULL default action; it supplies `_queueLocked` explicitly to `runAction`. Original maintenance and `setWorkLoop` instructions now produce the provider gate's loop pointer, list insertion, removal and disable effects. The previous attachment-write model is not used. Native allocation, reference counts, locks, workloop threads and hardware remain unknown. [WA1-WA8]

```text
AES provider
  +0xb8 -> provider gate G: owner=provider, default=NULL
  +0xf0 -> explicit _queueLocked action
  +0xc0 -> workloop L
                 +0x20 -> internal gate I: owner=L, default=_maintRequest

provider start fragment -> L.addEventSource(G)
  -> I.runCommand(mode=0, G, 0, 0)
  -> I.runAction(_maintRequest, mode=0, G, 0, 0)
  -> _maintRequest(L, mode=0, G, 0, 0)
  -> retain request -> G.setWorkLoop(L) -> source list publication

L.removeEventSource(G)
  -> same internal gate, mode=1
  -> source unlink -> G.setWorkLoop(NULL) -> disable -> release request

G.runAction(_queueLocked, command, 0, 0, 0)
  -> _queueLocked(provider, command, 0, 0, 0) [STOP]
```

[Original source](triage_evidence/workloop_gate_attachment_source.json), [profiles](triage_evidence/workloop_gate_attachment_profiles.json), [fresh independent replay/oracles](triage_evidence/workloop_gate_attachment_checks.json), [preservation](triage_evidence/workloop_gate_attachment_delivery.json) and [scoped gates](triage_evidence/workloop_gate_attachment_quality_gates.json) retain the evidence. This extends the [action/owner ABI report](aes_command_gate_report.md). The [constructor hardware boundary](kext_startup_hardware_bridge_report.md) remains unexecuted; this increment does not establish successful AES or constructor-to-daemon continuity.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| WA1 | The pinned collection supplies the analyzed original provider/kernel implementations. All static bindings depend on it. | Rehash the collection, recapture 25 complete functions and all 12 additional slots, and compare exact symbols. A runtime build or vptr mismatch invalidates runtime application. |
| WA2 | Provider, two gates, workloop, extensions, lock and command are disjoint private reservations with nominal vptrs. Native extents and constructors are unproved. | Match actual allocation/class/vptr/epoch; inspect all accesses against declared reservations and original requested extents. |
| WA3 | The loop-init fragment starts at 0xfffffe000c51af98 with X19=workloop and preexisting extension+0x40, optional extension object NULL and nominal gate-metaclass state. Earlier init and thread creation are not executed. | Recover the complete preceding initialization, runtime metaclass and thread creation before assigning full native initialization. The original file gate-metaclass vptr is zero. |
| WA4 | Instrumentation flag bit 0 is explicitly inactive. Original registerEventSource source supplies NULL under this premise. The runtime flag value is unknown. | Recover the unnamed flag's writers and runtime epoch; examine the enabled branch with authentic class/auxiliary state. File zero is not runtime attestation. |
| WA5 | Gate allocation, extension allocation, provider gate factory and pool factory results are modeled. Source-created objects transfer exactly between components. | Replace these results with authentic constructors/allocator outputs; compare object identity and complete ownership. No attachment write is supplied by an API model. |
| WA6 | Workloop close/onThread/open and OSObject retain/release effects are modeled. Native serialization and lifetime remain unknown. | Match native lock/thread/reference state and execute the same lifecycle with real ownership; operation requests alone do not prove their effects. |
| WA7 | Logical PAC/stripping and an emulated TPIDR_EL1 value represent explicit CPU premises. The lock owner is an explicit matching cookie. | Verify original pointer provenance and actual PAC acceptance; compare native lock owner and thread-context register before asserting exclusion. |
| WA8 | These source components and the RAX trace are separate epochs; no Mach, hardware or successful constructor result is inferred. | Match provider/daemon/hardware identities and capture one authentic lifecycle/exchange. The broad interface goal remains active. |

## Original source and exact interfaces

Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Twenty-five complete functions contain 1786 instructions, including the previously captured gate/provider bodies and fourteen additional kernel bodies plus `inGate`. Twelve additional original format-8 authenticated slots have key=0/IA and address-diversity=1. Runtime pointer authentication is not executed. Installed `IOWorkLoop.h` and `IOCommandGate.h` are hashed corroborating context; no new SDK compilation is performed.

| Nominal vptr / offset or direct target | Exact symbol-backed method |
| --- | --- |
| Workloop vptr `0xfffffe0007f3f638` +0x138 | `0xfffffe000c51a604`, `IOWorkLoop::_maintRequest(void*,void*,void*,void*)`; diversity `0xf4d9`. |
| Same vptr +0x168 | `0xfffffe000c51a1fc`, `IOWorkLoop::removeEventSource(IOEventSource*)`; both add/remove return `IOReturn` in the captured SDK. |
| Same vptr +0x158 | `0xfffffe000c51a38c`, `IOWorkLoop::inGate() const`. This is distinct from `onThread() const` at +0x150. |
| Gate vptr `0xfffffe0007f3fbb0` +0x148 | `0xfffffe000c51e844`, `IOCommandGate::setWorkLoop(IOWorkLoop*)`. |
| Same vptr +0x188 | `0xfffffe000c51bd64`, `IOEventSource::getWorkLoop() const`. |
| Same vptr +0x150 / +0x158 | `0xfffffe000c51be58`, `setNext(IOEventSource*)` / `0xfffffe000c51be4c`, `getNext() const`. |
| Same vptr +0x140 | `0xfffffe000c51beb8`, `IOEventSource::checkForWork()`. |
| Same vptr +0x178 | `0xfffffe000c51e744`, `IOCommandGate::disable()`. |
| Same vptr +0x20 / +0x28 | `0xfffffe000c445200`, `OSObject::retain() const` / `0xfffffe000c4451d0`, `release() const`. |
| Gate metaclass vptr `0xfffffe0007f3fe28` +0xa8 | `0xfffffe000c51eb40`, `IOCommandGate::MetaClass::alloc() const`; allocation is modeled. |

Original `IOWorkLoop::init` resolves its virtual +0x138 action, authenticates using the slot-derived modifier and signs for generic action domain `0xbd41`. It passes owner=workloop and that action to original gate init, stores the internal gate at loop+0x20 at `0xfffffe000c51b050`, calls its original `setWorkLoop(loop)` and calls original `addEventSource` on it. The fragment stops at `0xfffffe000c51b0a8` before the thread-start path. It is a component of initialization, not a successful `IOWorkLoop::init` return. [WA3, WA5-WA7]

`addEventSource` at `0xfffffe000c51a244` selects the internal gate and tail-calls `runCommand` with X1=0, X2=event source, X3/X4=0 in the tested fast path, whose loop+0x30 policy pointer is NULL. The alternate non-NULL policy path is unexecuted. `removeEventSource` selects mode 1; maintenance compares the low 32 bits of its mode argument. `runCommand` obtains the internal gate's non-NULL default action; `runAction` substitutes its workloop owner as X0. Six maintenance frames independently verify `(L, mode, eventSource, 0, 0)` and internal packed gate state 0x100 at action entry. This resolves the apparent NULL-default issue from the provider-gate report: the workloop invokes a different gate.

## Source-produced object relationships

| Object / field | Established role and evidence boundary |
| --- | --- |
| Provider gate +0x18 / +0x20 | Original owner=provider / default=NULL. |
| Internal gate +0x18 / +0x20 | Original owner=workloop / default `_maintRequest`, created by the init fragment. |
| Workloop +0x20 | Internal gate pointer, original store at 0xfffffe000c51b050. |
| Workloop +0x40 | Extension pointer supplied as a preexisting fragment premise. |
| Workloop +0x18 | One event-source list head; remains NULL in the retained gate cases. |
| Workloop extension +8 | Second list head; receives the provider gate in these cases. Complete original structure/type names are not assigned. |
| Gate +0x10 | Next-event-source link accessed through original getNext/setNext. |
| Gate +0x30 | Workloop pointer; original non-NULL store at 0xfffffe000c51e868, detach clear at 0xfffffe000c51e9a4. |
| Gate +0x28 | Enabled byte; detach writes zero through original disable, and non-NULL setWorkLoop does not set it. |
| Gate +0x48 | Packed action/teardown state; normal maintenance returns restore zero. The provider dispatch frontier retains 0x100. |
| Gate extension +0 | Optional auxiliary pointer; original inactive instrumentation branch supplies NULL. |

The maintenance source chooses between the two lists using event-source flags and a comparison of `checkForWork` implementations. Both nominal gates use the same default implementation in these cases, selecting extension+8 for the provider gate. The internal gate is already attached when its self-add runs: `getWorkLoop()` returns non-NULL and the maintenance source returns zero before a retain or list insertion. No native list classification/capacity invariant is inferred beyond these source paths.

## Attach, detach, reattach and duplicate-add

```text
attach:
  retain request -> source setWorkLoop(L) -> source list-head publication

detach:
  source list-head removal -> source disable/clear loop
                           -> source clear next -> release request

reattach:
  loop pointer restored; list membership restored; enabled stays 0

duplicate-add while attached:
  source getWorkLoop is non-NULL -> return 0; no new retain/list publication
```

Three attach paths verify retain-request-before-setWorkLoop-before-list-publication ordering. The detach path verifies list-unpublish-before-loop-clear-before-release-request. These are operation orders and private source writes, not native reference or lock effects. The duplicate-add case preserves all ten final object images from the attached producer. Two modeled `onThread` values produce identical final object images during provider attachment.

`IOCommandGate::setWorkLoop(NULL)` requests workloop closure, sets pending state and calls `disable` on the tested zero-active-count branch. `disable` calls exact `inGate()` before clearing enabled. Original `inGate` loads loop+0x10, then that lock object's +0x18 owner field, reads `TPIDR_EL1`, compares the two and returns a Boolean. The private lock-owner cookie and emulated register are explicitly equal; fresh replay executes this MRS and comparison. This is an emulated context read, not a privileged host-register read or proof that modeled `closeGate()` acquired a lock. Deferred/active teardown branches remain untested. [WA6, WA7]

## Auxiliary role and environment predicate

The unnamed routine `0xfffffe000c57b280..0xfffffe000c57b3d0` references original diagnostics `IOStatistics::registerEventSource - bad metaclass %p` and `IOStatistics::registerEventSource: cannot find parent class...`, plus `IOStatistics.cpp`. Its role is therefore diagnostic-string-correlated with `IOStatistics::registerEventSource`; it still has no exact nlist symbol. No exact private C++ prototype is assigned.

The routine loads the byte at `0xfffffe000cb5b6e0` and tests bit 0. When clear, original code returns NULL without entering the allocation/class-registration branch. File byte is 0; runtime value and writer provenance remain unknown. Source gate initialization executes this original inactive branch, replacing the previous auxiliary-NULL result model. Standalone cases with bytes 0x02 and 0xfe also return NULL with no external models, distinguishing bit 0 from a whole-byte zero test. Enabled instrumentation remains unexecuted.

The association/removal helpers at `0xfffffe000c57b898` and `0xfffffe000c57b9a4` are captured and execute their NULL-optional-object branches in these components. The workloop extension's optional object is a NULL fixture from the unexecuted earlier init interval; this is distinct from the original event-source registration result proved under the inactive flag. [WA3-WA5]

## Verification and reproduction

| Case | Original instruction visits | Boundary/result |
| --- | --- | --- |
| Provider gate init, inactive flag | 78 | Original return 1; auxiliary NULL comes from original helper. |
| Workloop internal-gate init/attachment fragment | 341 | Stops at 0xfffffe000c51b0a8 before thread-start path. |
| Provider start fragment, onThread model 1 | 368 | Stops after original action/gate/pool stores; attachment is original source. |
| Attached provider gate explicit dispatch | 58 | Stops before `_queueLocked(provider,command,0,0,0)`. |
| Remove provider gate | 340 | Return 0; unlinked, loop pointer NULL, enabled=0. |
| Reattach removed provider gate | 270 | Return 0; attached/listed, enabled remains 0. |
| Duplicate-add attached provider gate | 170 | Return 0; final objects unchanged, no new retain/release. |
| Provider start fragment, onThread model 0 | 370 | Same final objects as the paired onThread=1 case. |
| Inactive nonzero flag 0x02 / 0xfe | 16 / 16 | Original helper returns NULL, no API model. |

Ten independent fresh replays verify 2027 original instruction visits, 578 reads / 4517 B, 350 writes / 2739 B, 78 logical indirect edges, 168 logical authentication/stripping steps, 33 declared API models, six maintenance frames, one provider action frame, one emulated system-context read and 100 final object images. Seven exact source-produced object transfers are checked. The only model memory effect is the nominal internal-gate allocation's 8 B vptr store; no model writes a workloop attachment or list link.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_workloop_gate_attachment.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_workloop_gate_attachment.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_workloop_gate_attachment.py
```

Run producers sequentially in a separate evidence-tree copy for reproduction; published artifacts remain preserved. Complexity is O(image bytes + symbols + source visits + effects) time and O(image + retained journals + fixed private RAM) space. No solver, target daemon, native allocator/reference/lock, Mach operation, hardware AES or hardware PAC is executed. Original inputs, IDBs and memory files remain unchanged. No new Mach port/right/message is established; the supplied RAX trace still ends at failed UserClient open.

## Bounded continuation and quality gates

| Impact | Remaining question | Evidence needed |
| --- | --- | --- |
| High | Complete workloop/provider construction and native object identity remain unproved. | Recover preceding extension/lock/metaclass initialization, authentic allocation and thread creation in the same epoch. |
| High | Accepted AES carrier construction, queue processing and hardware completion remain uncomposed. | Preserve original descriptors, action ownership and actual provider outputs through the constructor's hardware boundary and later RPC. |
| Medium | Detachment with active actions, sleeping callers and pending state is untested. | Trace normal deferred teardown/wakeup producers and their reference/exclusion contracts. |
| Medium | Reattachment preserves disabled state in these paths. | Recover the native caller's enable policy and later enable requests before concluding restored operation. |
| Medium | Instrumentation flag writer, enabled auxiliary records and class-tree ownership remain unknown. | Identify initialization/writer provenance and authentic optional-object lifetimes; file zero does not settle runtime state. |
| Low | onThread and inGate describe different predicates. | Retain their separate slots, register/lock-owner inputs and modeled versus original execution evidence. |

- QG1: Factual interface and source analysis; no normative conclusion required.
- QG2: WA1-WA8 register assumptions, dependencies and falsification probes.
- QG3: Two-gate construction fragment, original attach/list/detach/readd paths, auxiliary inactive predicate and thread-context interface are covered. The broad objective and native lifecycle remain incomplete.
- QG4: Byte/register widths, 8 B model effect, fixed source counts, flag bit and emulated context are explicit; no native timing or capacity bound is inferred.
- QG5: Two gate owners/default actions, two lists, source/model/native effects, file/runtime state, exact/diagnostic-correlated symbols and frontier/returned execution remain distinct.
- QG6: Pinned collection/functions/slots, diagnostics, SDK hashes, fresh independent instruction/effect replay and separate lifecycle/order oracles support the scoped claims.
- QG7: Additional questions are bounded and impact-labeled above.
