# AES provider action registration and command-gate owner ABI

The original provider start fragment derives `provider+0xf0` from virtual `_queueLocked`, creates its gate with a NULL default action, attaches that gate to its workloop and stores a workloop-backed command pool. Original gate initialization supplies the owner that `runAction` later passes as callback X0. The normal explicit-action path therefore has a source-established owner/command handoff. It does not require a non-NULL gate default action. Native provider initialization, workloop registration, locking, queue processing and hardware AES remain unknown. [CG1-CG8]

```text
provider vptr+0x8d0 -> _queueLocked -> provider+0xf0 (explicit action)
provider --------------------------> commandGate(owner, NULL default)
                                       |
                       original init -> gate+0x18 = owner
                                     -> gate+0x20 = NULL
                                     -> gate+0x28 = enabled
provider.getWorkLoop() -> addEventSource(gate) [attachment model]
                      -> withWorkLoop() -> provider+0xf8 pool

runAction(gate, provider+0xf0, command, 0, 0, 0)
  -> workloop.closeGate() [model]
  -> workloop.onThread()  [model]
  -> explicit action(gate+0x18, command, 0, 0, 0) [STOP or result model]
  -> workloop.openGate()  [model, on tested returned continuations]

runCommand(gate, command, 0, 0, 0)
  -> gate+0x20 default is NULL -> runAction(NULL action) -> 0xe00002c2
```

The diagram combines original source components through declared object transfers and API premises. It is not a continuous native execution. [Source](triage_evidence/aes_command_gate_source.json), [profiles](triage_evidence/aes_command_gate_profiles.json), [independent replay/oracles](triage_evidence/aes_command_gate_checks.json), [preservation](triage_evidence/aes_command_gate_delivery.json) and [scoped gates](triage_evidence/aes_command_gate_quality_gates.json) retain the evidence. The [startup-to-hardware report](kext_startup_hardware_bridge_report.md) ends at the provider AES method; this increment resolves its downstream registration/dispatch interface without supplying a hardware result or advancing that constructor execution.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CG1 | The pinned original collection supplies the analyzed provider and kernel bodies. All address and symbol claims depend on it. | Rehash the collection, recapture ten complete compiler-bounded functions and 15 original pointer slots, and compare exact symbols. A different runtime build/vptr invalidates runtime application. |
| CG2 | Provider, gate, workloop, pool and command are disjoint private object fixtures with nominal vptrs. Actual constructors/extents are not established. | Match native class, allocation size and vptr before applying these field contracts to live objects; reject any fixture access outside its declared reservation. |
| CG3 | Original `IOCommandGate::init` executes with a declared allocation result and NULL auxiliary result from an unnamed callee. The source-produced gate state depends on these API outcomes. | Recover the unnamed callee and non-NULL auxiliary lifetime; compare real allocation and extension contents. The 8 B request does not establish native allocation success. |
| CG4 | The recovered provider start interval is entered with X19=provider, cached workloop and original-initialized gate state. It is a source component, not a full start proof. | Recover and execute all preceding initialization and authentic gate factory construction; verify original caller and callee-saved state. |
| CG5 | Factory, pool and workloop attachment results are modeled. Only attachment writes gate+0x30 in these components. | Execute/recover actual addEventSource/setWorkLoop and pool initialization with a matching runtime epoch before assigning live attachment or ownership. |
| CG6 | PAC, stripping and authenticated branches use logical decoded pointers, not hardware authentication. Action identity remains conditional on the nominal receiver. | Compare original chain key/diversity/address binding and actual runtime authentication. Static discriminators alone do not identify a receiver or guarantee acceptance. |
| CG7 | Workloop close/onThread/open and two action results are explicit no-effect/result models. Normal enabled paths and their continuations depend on these outcomes. | Establish native workloop/thread identity, locking, disabled sleep/wakeup and teardown semantics; no queue or hardware effect follows from the declared results. |
| CG8 | NULL default action, explicit provider action and the historical RAX/open-failure epoch are separate interfaces. No native pairing or causal relation is assumed. | Capture one matched provider/daemon/port epoch and authentic call sequence. Equal error numbers across components do not establish equal causes. |

## Exact source and bindings

The collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Ten complete functions contain 859 instructions. Fourteen nominal/import slots plus one pool-seeding import are recaptured with original format-8, auth=1, key=0/IA and address-diversity=1. The installed `IOCommandGate.h` is hashed corroborating context; no new SDK compilation is performed. All VAs below are original unslid collection addresses and offsets are bytes.

| Slot or call | Exact target / role |
| --- | --- |
| AES vptr `0xfffffe0008588380` +0x8d0, slot `0xfffffe0008588c50` | `0xfffffe000abfd2d8`, `IOAESAccelerator::_queueLocked(IOAESAcceleratorCommand*)`; diversity `0x1430`. |
| Same vptr +0x6b8, slot `0xfffffe0008588a38` | `0xfffffe000abfcd54`, `IOAESAccelerator::getWorkLoop() const`; cached field +0xc0, lazy factory branch otherwise. |
| Import slot `0xfffffe000858a5f0`; provider call `0xfffffe000abfc64c` | `0xfffffe000c51f3f0`, `IOCommandGate::commandGate(OSObject*, Action)`; provider owner and NULL default action. |
| Import slot `0xfffffe000858a5f8`; call `0xfffffe000abfc700` | `0xfffffe000c520c24`, `IOCommandPool::withWorkLoop(IOWorkLoop*)`. |
| Import slot `0xfffffe000858a610` | `0xfffffe000c442054`, `OSMetaClassBase::_ptmf2ptf(...)`; conditional member-function conversion branch, not taken by the nominal replay. |
| Gate vptr `0xfffffe0007f3fbb0` +0x1d8 | `0xfffffe000c51e6e8`, `IOCommandGate::init(OSObject*, Action)`. |
| Same vptr +0x160 | `0xfffffe000c51bdf0`, `IOEventSource::setAction(void (*)(OSObject*, ...))`. |
| Same vptr +0x1e8 / +0x1e0 | `0xfffffe000c51e408`, `IOCommandGate::runAction(...)` / `0xfffffe000c51e680`, `runCommand(...)`. |
| Workloop vptr `0xfffffe0007f3f638` +0x160 | `0xfffffe000c51a244`, `IOWorkLoop::addEventSource(IOEventSource*)`. |
| Same vptr +0x1a0 / +0x150 / +0x198 | `0xfffffe000c519c7c`, `closeGate()` / `0xfffffe000c51a3a8`, `onThread() const` / `0xfffffe000c519d24`, `openGate()`. |
| Pool vptr `0xfffffe0007f40058` +0x150 | `0xfffffe000c51fe7c`, `IOCommandPool::returnCommand(IOCommand*)`; static seeding-loop context. |
| Import slot `0xfffffe000858a598`, stub `0xfffffe000abff9e4` | `0xfffffe000c4458c4`, `_OSObject_typed_operator_new`; size argument 144 B in the later seeding loop. |

The exact nominal action is virtual, so a different valid receiver can select a different implementation. Startup authenticates the loaded function using its slot-derived `0x1430` modifier, then signs it for the generic action domain `0xbd41` before storing provider+0xf0. `runAction` invokes the explicit function with modifier `0xbd41` at `0xfffffe000c51e4f8`. The logical replay verifies both modifier values and the action word; hardware acceptance is unknown. The conditional conversion branch uses the `_queueLocked` vfpthunk at `0xfffffe000abfcb1c`, which dispatches through the receiver's +0x8d0 slot. That branch is captured statically and unexecuted. [CG1, CG2, CG6]

## Object and action channels

| Object field | Width | Established source use |
| --- | --- | --- |
| Provider +0xb8 | 8 | Gate factory result, store at `0xfffffe000abfc654`. |
| Provider +0xc0 | 8 | Cached workloop used by original getter. |
| Provider +0xf0 | 8 | Explicit action, store at `0xfffffe000abfc640`; nominal `_queueLocked`. |
| Provider +0xf8 | 8 | Workloop-backed pool result, store at `0xfffffe000abfc708`. |
| Gate +0x18 | 8 | Owner stored by `IOEventSource::init` at `0xfffffe000c51bee0`; callback X0 comes from this field. |
| Gate +0x20 | 8 | Default action stored through `setAction` at `0xfffffe000c51be3c`; NULL for actual provider startup arguments. |
| Gate +0x28 | 1 | Enabled byte set to 1 at `0xfffffe000c51bf10`. |
| Gate +0x2a | 2 | Source action-storage flags; complete semantics unknown. |
| Gate +0x30 | 8 | Attached workloop; populated by the explicit attachment model. |
| Gate +0x40 | 8 | Extension pointer. Original type view `0xfffffe0007e55c58` requests 8 B; model supplies private storage. |
| Extension +0 | 8 | Result of unnamed `0xfffffe000c57b280(owner)`; modeled NULL, exact symbol unknown. |
| Gate +0x48 | 8 | Packed state word; source adds 0x100 before callback, subtracts 0x100 afterward in tested normal paths. Full packed semantics unknown. |

Original gate initialization calls original `IOEventSource::init` at `0xfffffe000c51bec4`; the factory capture independently shows it forwards its owner/default action as init arguments X1/X2. The source-created owner/default/enabled state is transferred to the registration component. The factory model returns that same initialized gate without writing those fields. This verifies local consistency of factory arguments with the source-produced object; actual metaclass allocation and full factory execution remain unestablished. [CG2-CG5]

`runAction` preserves its four opaque argument slots and substitutes owner X0:

| API position | At `runAction` entry | At explicit action entry |
| --- | --- | --- |
| X0 | Gate | Gate's owner field +0x18 |
| X1 | Explicit action | Original X2: command |
| X2 | Command | Original X3: 0 |
| X3 | 0 | Original X4: 0 |
| X4 | 0 | Original X5: 0 |
| X5 | 0 | Outside the five-argument callback contract |

Source at `0xfffffe000c51e4dc..0xfffffe000c51e4f8` performs this mapping. At that boundary, gate+0x48 is 0x100 in all four cases. Modeled action results 0 and 4 return unchanged through the tested original continuation; its state word returns to 0 and it requests `openGate()`. The two frontier cases stop with the packed state still 0x100 and do not request `openGate` because callback execution has not completed. No native lock-balance claim follows. [CG7]

`runCommand` reads +0x20 and, for non-NULL defaults, converts the stored `0x7c11` action domain to `0xbd41` before tail-dispatching through `runAction`. The actual startup NULL default skips that conversion and returns the original NULL-action error. This does not contradict explicit-action success at the dispatch boundary.

## Source pool context and retained unknowns

The later source loop initializes W25=32, supplies size 0x90=144 B to `_OSObject_typed_operator_new`, writes nominal `IOAESAcceleratorCommand` vptr `0xfffffe0008588d98`, and requests pool `returnCommand`. Its subtract/branch repeats 32 times under normal returning, callee-saved-register-preserving calls. The nominal aggregate request is `32 * 144 B = 4608 B`, excluding allocator/pool overhead. The loop and lower construction are static context only; no 32 successful native allocations, pool capacity guarantee or bounded runtime queue depth is inferred. The original provider fragment executed here stops before this loop.

The earlier [AES handoff report](kext_aes_handoff_report.md) establishes carrier fields and conditional sleep/wakeup/completion source. This increment identifies the action producer and owner-forwarding contract. It does not execute `_queueLocked`, `performAES`, descriptor preparation/completion or a hardware driver. The prior constructor remains stopped before its actual hardware AES method, with bridge-warm still zero. No new Mach port, right, message emission or daemon endpoint is established.

## Independent checks and reproduction

| Case | Original source visits | Verified result/boundary |
| --- | --- | --- |
| Gate initialization | 62 | Return 1; owner/default/enabled/extension source stores. |
| Provider registration fragment | 98 | Stops at `0xfffffe000abfc70c`; action/gate/pool stores checked. |
| Explicit action, onThread=1 | 58 | Stops before `_queueLocked`; owner and four arguments checked. |
| Explicit action, onThread=0, enabled=1 | 60 | Same action boundary via enabled-byte branch. |
| Action result model 0, onThread=1 | 83 | Return 0, state restored, openGate request. |
| Action result model 4, onThread=0 | 85 | Return 4, state restored, openGate request. |
| runCommand, NULL default | 43 | Return `0xe00002c2`; no workloop API/action call. |
| runAction, missing workloop | 26 | Return `0xe00002d8`; no workloop API/action call. |
| runAction, NULL explicit action | 23 | Return `0xe00002c2`; no workloop API/action call. |

Nine fresh independent replays check 538 original source visits, 149 reads / 1168 B, 119 writes / 939 B, 21 logical indirect edges, 33 logical authentication/stripping steps, 17 external models and four callback frames. One declared attachment effect writes 8 B. Eight exact source-produced object transfers and 54 final object images are verified. Reads/writes to the extension stay inside its requested 8 B. The private fixtures reserve larger disjoint areas; these reservations are not native allocation extents.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_aes_command_gate.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_aes_command_gate.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_aes_command_gate.py
```

Producers must run sequentially. Published outputs are preserved; independent reproduction belongs in a separate evidence-tree copy. Time is O(image bytes + symbols + visits + effects), space O(image + retained journals + fixed private RAM). No solver, native target, allocator, IOKit, Mach, credential, key or hardware operation is executed; no IDB or memory file is changed.

## Bounded continuation and quality gates

| Impact | Next interface question | Resolving evidence |
| --- | --- | --- |
| High | Actual gate/workloop/pool construction and attachment remain modeled. | Recover full factory/metaclass and addEventSource/setWorkLoop ownership in the same authenticated object epoch. |
| High | Provider AES input guards, carrier construction and queue action are not composed dynamically. | Trace original accepted normal input through carrier publication and this action boundary, preserving descriptors and explicit premises. |
| High | Hardware completion remains the predecessor of constructor warm/RPC progression. | Establish authentic command submission/result/output and the same constructor state; do not substitute an arbitrary successful result. |
| Medium | Disabled-gate sleep, pending state bits, auxiliary object and teardown are untested. | Recover their producers and ownership, then verify normal lifecycle sequences separately from the enabled paths. |
| Medium | Runtime virtual override may change action identity. | Match actual receiver vptr and stored action with original authenticated slot provenance. |
| Low | Default and explicit action domains differ. | Preserve the +0x20 versus +0xf0 distinction and PAC modifiers in subsequent lifts. |

- QG1: Factual interface/source analysis; no normative conclusion required.
- QG2: CG1-CG8 identify premises, dependent results and falsification probes.
- QG3: Action production, gate owner/default initialization, nominal factory/workloop/pool bindings and nine source components are covered. Full native lifecycle and broad goal remain incomplete.
- QG4: Register/field widths, source/requested/private extents, packed 0x100 state and pool byte calculation are explicit; no scheduling latency is inferred.
- QG5: Explicit/default actions, frontier/returned state, source-produced/model/native effects and exact/unknown symbol identities remain distinct.
- QG6: Pinned original bytes, compiler bounds, 15 original slots, exact symbols, SDK hash, independent CPU/event replay and separate interface oracles support the scoped claims.
- QG7: Further questions are bounded and impact-labeled above.
