# AES command pool: third gate, carrier seeding, leases and wait boundary

The original pool factory initializes a third command gate with owner=pool and NULL default action. Pool get/return wrappers supply explicit gated actions. Original provider startup seeds 32 distinct 144 B carrier reservations; original list operations then lease them in reverse allocation order. Returning a leased carrier restores the complete prior object state in the tested cycle. Empty nonblocking get returns NULL; empty blocking get reaches `commandSleep` and stops before its body. Allocation, C++ construction, references, locking and scheduling remain modeled; native queue/hardware behavior is unknown. [CP1-CP8]

```text
workloop L
  -> maintenance gate I: owner=L, default=_maintRequest
  -> provider gate G:    owner=provider, explicit _queueLocked
  -> pool gate P:        owner=pool, default=NULL
       getCommand  -> runAction(gatedGetCommand, &out, block, 0, 0)
       returnCommand -> runAction(gatedReturnCommand, carrier, 0, 0, 0)

original provider loop -> 32 carriers -> pool circular list
                                     -> original get -> same carrier identity
                                     <- original return
empty + nonblocking -> internal 0xe00002be -> public NULL
empty + blocking    -> commandSleep(P, pool+0x20, 0) [STOP]
```

[Source](triage_evidence/aes_command_pool_source.json), [profiles](triage_evidence/aes_command_pool_profiles.json), [independent replay/oracles](triage_evidence/aes_command_pool_checks.json), [preservation](triage_evidence/aes_command_pool_delivery.json) and [scoped gates](triage_evidence/aes_command_pool_quality_gates.json) retain the evidence. The source-produced external starting objects are case 2 of the [workloop attachment profiles](triage_evidence/workloop_gate_attachment_profiles.json). They are component transfers, not an uninterrupted native provider start. No AES input/key fields or cryptographic output are recovered here.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CP1 | The pinned collection identifies these original pool/provider/kernel bodies. | Rehash it, recapture 33 complete functions and 11 pool/construction/wait slots, and compare exact symbols. A different runtime build/vptr invalidates runtime application. |
| CP2 | Published source-produced workloop/provider/gate objects seed a new private component. Stack state is fresh and object identities are retained. | Compare every transferred object byte and all subsequent original reads/writes; establish actual caller/stack/object epochs before asserting native continuity. |
| CP3 | Pool/gate metaclass vptrs are nominal runtime premises; their original file words are zero. Allocation results are declared disjoint reservations. | Recover authentic metaclass initialization and native allocations/class identity. File zero and nominal vtables do not prove runtime object state. |
| CP4 | Command allocation, base constructor and class-bookkeeping outcomes are modeled. Original source supplies the derived vptr and pool links. | Execute/recover authentic constructors and object/reference initialization. Untouched fixture bytes and reservation sizes are not native layout/extent proof. |
| CP5 | Gate closure/onThread/open and one pool-gate retain are modeled. Instrumentation remains explicitly inactive as in the producer. | Establish actual lock/thread/reference/feature state; these models do not prove serialization, lifetime or instrumentation state. |
| CP6 | Logical PAC and decoded pointers represent source flow, not hardware authentication. | Match original slot/tag/address-diversity and authentic runtime receiver/PAC state. |
| CP7 | The retained carrier cycles and drain calls are sequential source components, not concurrent execution. Blocking stops before sleep. | Observe a real wait/wake/return cycle, teardown and scheduling before claiming concurrency, fairness or a guaranteed eventual pointer. |
| CP8 | Current SDK declarations are corroborating context, with no matched historical SDK or new compilation. Machine ABI claims come from original instructions. | Match the original build headers/compiler; preserve binary X0 results separately from current OSPtr/consumed-pointer declarations. Native constructor/hardware/daemon continuity remains unknown. |

## Exact source interfaces

Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Thirty-three complete functions contain 2102 instructions. Eleven recaptured original slots have format 8, auth=1, key=0/IA and address-diversity=1. Three original import stubs connect provider construction calls to their kernel targets. Runtime authentication is not executed.

| Original slot / call interface | Exact target |
| --- | --- |
| Pool vptr `0xfffffe0007f40058` +0x138 | `0xfffffe000c52006c`, `IOCommandPool::initWithWorkLoop(IOWorkLoop*)`. |
| Same vptr +0x148 / +0x150 | `0xfffffe000c51ff48`, `getCommand(bool)` / `0xfffffe000c51fe7c`, `returnCommand(IOCommand*)`. |
| Same vptr +0x158 | `0xfffffe000c51fd90`, `gatedGetCommand(IOCommand**,bool)`; diversity `0x0b30`. |
| Same vptr +0x160 | `0xfffffe000c51fcec`, `gatedReturnCommand(IOCommand*)`; diversity `0xa4a6`. |
| Pool metaclass vptr `0xfffffe0007f40218` +0xa8 | `0xfffffe000c5203c4`, `IOCommandPool::MetaClass::alloc() const`; modeled allocation. |
| Pool factory entry | `0xfffffe000c520c24`, `IOCommandPool::withWorkLoop(IOWorkLoop*)`; original body executed. |
| Import `0xfffffe000858a598`, stub `0xfffffe000abff9e4` | `0xfffffe000c4458c4`, `_OSObject_typed_operator_new`; modeled. |
| Import `0xfffffe000858a648`, stub `0xfffffe000abffb44` | `0xfffffe000c51fb58`, `IOCommand::IOCommand(OSMetaClass const*)`; modeled base construction. |
| Import `0xfffffe000858a678`, stub `0xfffffe000abffba4` | `0xfffffe000c4434ec`, `OSMetaClass::instanceConstructed() const`; modeled bookkeeping. |
| Gate vptr `0xfffffe0007f3fbb0` +0x200 / +0x208 | `0xfffffe000c51e1d4`, `commandSleep(void*,unsigned int)` / `0xfffffe000c51e19c`, `commandWakeup(void*,bool)`; sleep boundary observed, wake path static only. |

The original factory resolves its metaclass allocation, invokes original `initWithWorkLoop`, and returns the pool pointer on true init result. Original init creates a gate, invokes original gate initialization with owner=pool/default=NULL, stores it at pool+0x28 and calls original workloop attachment. The workloop maintenance gate attaches this separate pool gate after the provider gate in the tested event-source list. The factory's returned object identity matches the provider's retained pool pointer. [CP2-CP6]

## Pool fields and callback ABI

| Object field | Width | Original use |
| --- | --- | --- |
| Pool +0x10 | 8 | Free-list head object pointer; also the sentinel address when the list is empty. |
| Pool +0x18 | 8 | Free-list tail object pointer. |
| Pool +0x20 | 4 | Waiting bookkeeping word, incremented on the observed empty blocking path. Complete concurrent accounting remains unknown. |
| Pool +0x28 | 8 | Pool's own command gate. |
| Carrier +0x10 / +0x18 | 8 each | Next/previous object pointers; both cleared when removed by gatedGetCommand. |
| Pool gate +0x18 / +0x20 | 8 each | Owner=pool / default=NULL, supplied by original gate init. |
| Pool gate +0x30 / +0x48 | 8 each | Workloop pointer / packed action state, 0x100 at gated action entry. |

The circular-list sentinel is the address `pool+0x10`; links otherwise identify carrier objects, not addresses of their embedded link fields. An independent walk verifies next/previous consistency, tail identity, unique membership and exact order in every case.

| Method/action boundary | Original machine contract |
| --- | --- |
| getCommand entry | X0=pool, low32(X1)=ordinary Boolean 0/1 in the retained cases. |
| Its runAction call | Gate from pool+0x28; explicit action selected through pool vptr+0x158; argument0=&private output slot, argument1=block value, other slots zero. |
| gatedGetCommand entry | X0=pool owner, X1=output-pointer slot, W2=block, X3/X4=0. |
| returnCommand entry | X0=pool, X1=carrier pointer. |
| gatedReturnCommand entry | X0=pool owner, X1=carrier, X2/X3/X4=0. |

Both pool actions are authenticated from their original virtual slots and converted to generic action domain `0xbd41` for explicit `runAction`. The pool gate's NULL default does not prevent these explicit actions, just as for the provider gate. Sixty-eight action frames independently verify owner/argument mapping and packed state; 67 completed action statuses are checked. No get/return path requests a carrier retain/release in these retained normal cycles. This is a source operation census, not a native reference-count invariant.

## Source seeding and lease identities

The executed provider interval is `0xfffffe000abfc704..0xfffffe000abfc7ac`. It derives the count 32 from its original MOV instruction, requests 144 B per carrier, calls the modeled base constructor/bookkeeping, writes nominal derived vptr `0xfffffe0008588d98` at `0xfffffe000abfc74c`, and calls original pool return 32 times. The loop stops before the subsequent provider startup continuation.

The aggregate modeled request is `32 * 144 B = 4608 B`, excluding allocator overhead. Private carrier reservations are 256 B apart for disjointness; that spacing is not an allocator/alignment result. The 144 B request and original vptr stores do not establish complete native construction. No source maximum pool size or runtime queue-depth bound follows from a 32-object startup seed.

`gatedReturnCommand` inserts at the head; `gatedGetCommand` removes from the head. The 32 source-allocated identities are therefore acquired in reverse allocation order. Each successful removal clears its two link words and writes the same carrier pointer to the wrapper's source-created output slot. In the retained return cycle, all 44 final object images become byte-identical to the seeded producer. Nonempty block=false and block=true cases also have byte-identical final objects. [CP4-CP7]

## Empty pool, status conversion and scheduling boundary

After 32 distinct leases the original sentinel points to itself in both directions. A subsequent nonblocking gated get returns zero-extended status `0xe00002be`. The public wrapper initializes its output slot to NULL, tests low32 of the gate result and selects NULL on nonzero status. Thus the public pointer result and internal status are different channels; the caller does not receive this status as its pointer.

The empty blocking case increments the 32-bit word at pool+0x20 to 1, then reaches original `IOCommandGate::commandSleep` with X0=pool gate, X1=pool+0x20, W2=0. Its packed gate state is still 0x100 at this frontier. The sleep body, scheduler, wakeup and eventual lease are unexecuted. The later return-action source contains a conditional `commandWakeup(...,true)` request and waiting-word decrement, but that branch is static context here. No concurrency, accounting balance, fairness or eventual-wakeup conclusion is made.

The hashed installed SDK expresses get as `OSPtr<IOCommand>`, public return as void with a consumed-pointer annotation, and the two gated methods as `IOReturn`. Those declarations are context rather than a matched historical ABI proof. Original get instructions establish the X0 pointer/error-fold contract; original provider seeding does not consume returnCommand's X0. The observed internal zero statuses are not assigned a separate guaranteed public return-status API. [CP7, CP8]

## Verification and reproduction

| Component/cases | Original visits | Established result |
| --- | --- | --- |
| Pool factory/init/gate attachment | 463 | Original factory returns modeled pool identity; third gate owner/loop/default fields are source-written. |
| Original provider seeding loop | 5801 | 32 unique modeled allocations and original derived-vptr/list stores. |
| Nonempty block=true lease | 160 | Last allocated carrier, 31 remain. |
| Return that lease | 137 | Exact seeded object state restored. |
| Nonempty block=false lease | 160 | Same pointer and final objects as the paired block=true case. |
| Next 31 nonblocking leases | 4960 | All remaining identities returned exactly once, in reverse allocation order. |
| Empty nonblocking get | 147 | Internal `0xe00002be`, public NULL. |
| Empty blocking get | 125 | Stops before sleep; waiting word 1, gate state 0x100. |

Thirty-eight independent fresh CPU replays verify 11953 original visits, 2926 reads / 23242 B, 1750 writes / 13969 B, 486 logical indirect edges, 814 logical authentication/stripping steps, 306 declared API models, 68 pool-action frames, 67 action statuses and one sleep frontier. One workloop-maintenance frame verifies the pool gate's source attachment. All 1672 final object images, 37 intra-increment object transfers and one external producer are checked. The two model memory effects are nominal pool/gate vptr stores totaling 16 B. Source list operations are not supplied as API effects.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_aes_command_pool.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_aes_command_pool.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_aes_command_pool.py
```

Run producers sequentially in a separate evidence-tree copy for reproduction; published outputs remain preserved. Complexity is O(image bytes + symbols + visits + effects + cases * carriers) time and O(image + retained journals + fixed private RAM) space. The independent list walk is O(carriers) time/space per case, bounded to 32 retained identities. Original bytes, API clobbers, every source read/write, logical authentication/branch records, final RAM and final objects are independently checked. No solver, native allocator/constructor, real reference/lock/thread, target daemon, Mach operation, AES operation or hardware PAC is executed. Original inputs, IDBs and memory files remain unchanged.

## Interface consequences and bounded continuation

The [earlier AES handoff report](kext_aes_handoff_report.md) statically identifies provider+0xf8 and `getCommand(true)` before carrier packing. This increment supplies original pool construction, seeding and lease identities for that interface. It does not execute provider key/input policy, complete descriptor preparation, `_queueLocked`, hardware submission or completion. The [constructor](kext_startup_hardware_bridge_report.md) remains at its hardware-method boundary; no successful context token, bridge-warm store or daemon RPC is produced.

| Impact | Remaining question | Resolving evidence |
| --- | --- | --- |
| High | Native allocation/base construction/reference state remain unestablished. | Recover authentic metaclass/object initialization and allocator results before applying reservation-level layouts to live objects. |
| High | Leased carrier identity is not yet composed through accepted provider packing and queue submission. | Track the same original leased object and descriptors through the provider's normal data-flow contract, preserving opaque fields and provenance. |
| High | Completion, actual wait/wake and return ownership remain uncomposed. | Establish one authentic completion and scheduling cycle; separate synchronous wake from asynchronous callback/pool-return ordering. |
| Medium | Pool exhaustion and teardown concurrency are untested. | Recover normal waiting/deferred teardown producers and reference/exclusion contracts; do not infer them from sequential drains. |
| Medium | The 32-object seed does not establish capacity or throughput. | Recover additional object producers, pool destruction and live outstanding-command accounting. |
| Low | Current OSPtr annotations and historical machine results are different evidence. | Match build headers/compiler before assigning exact historical C++ ownership/return-type declarations. |

- QG1: Factual interface/source analysis; no normative conclusion required.
- QG2: CP1-CP8 record premises, dependent claims and falsification probes.
- QG3: Original pool factory/init/attachment, source seeding, sequential identity-preserving lease/return/drain and empty wait boundary are covered. The broad goal and native lifecycle remain incomplete.
- QG4: Pointer/status/Boolean widths, link/sentinel geometry, 144 B requests, 4608 B sum and fixture spacing are explicit; no native capacity or timing bound is inferred.
- QG5: Three gates, public/internal result channels, source/model/native effects, component/native continuity and completed/frontier paths remain distinct.
- QG6: Pinned functions/slots/stubs, SDK hash, independent CPU/effect replay and separate list/identity/status oracles support the scoped claims.
- QG7: Further interface questions are bounded and impact-labeled above.
