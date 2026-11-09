# Endpoint return, activation counts and conditional job restart

The selected launchd endpoint callback is now connected to a job/service-owner record and its activation-count, pending-launch and teardown paths in both original slices. Notification69's reason1 callback deactivates an activation; selected suffixes can rearm endpoints and consume a pending launch reason through a gated start path. Reason0 requests a start directly. Neither reason implies unconditional relaunch. The asynchronous reset block separately calls `mach_port_destruct(task,name,0,saved_context)`; fast trap-25 and fallback MIG3232 converge on a kernel core that can reach the previously recovered port-destruction routine. [Original source](triage_evidence/endpoint_job_lifecycle_source.json), [checks](triage_evidence/endpoint_job_lifecycle_checks.json).

This extends [notification69 return](port_destroyed_return_report.md), [name/guard restoration](receive_name_guard_report.md), [coalition admission](coalition_service_gate_report.md) and [endpoint construction](launchd_service_endpoint_report.md). Native callbacks, pending-demand history, job identity, process creation, receive-right ownership and guard state remain unknown. No target callback, emulation, spawn, destruct API, IPC, service mutation or IDB mutation executes.

## Identity and scope

Launchd universal SHA-256 is `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`; slice UUIDs are `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71` and `62af2b7d-327e-334a-a1d7-83777efc3c12`. Kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. The capture pins library/tool/SDK identities, original exports/nlist and pointer bindings.

There are51 complete compiler-bounded bodies,7950 instructions and31800 B:42 launchd, six kernel and three cache bodies. Fifty-two launchd words require byte-checked LLVM decoding. Both slices and4894 fixups are independently checked; x1 ISA/PAC semantics and runtime slice identity remain separate. Capturing a complete body does not imply all-branch reachability or complete semantic recovery of its policy, allocator and native process dependencies [EJ1-EJ6].

```text
selected job factory -> callback table -> job J
  J+0x220 = demand gate; J+0x230 = endpoint factory wrapper
  J+0x258 = domain cookie D

endpoint wrapper -> endpoint E { callback, cookie=J }
  reason0 -> start gate -> launch core -> demand gate(J,reason,D)
                                      -> defer: J.pending_reason = reason
                                      -> admitted path: conditional posix_spawnp API

notification69 -> E reset -> callback(E,1,J)
  -> activation deactivation(D,J)
       +-> counts remain -> return
       +-> selected final deactivation -> endpoint/source rearm
       |    -> eligible nonzero pending reason -> clear + start gate
       +-> record removal / other cleanup paths

optional async reset -> clear E send-object cell -> scheduled block
  -> mach_port_destruct(task,name,0,C) -> trap-25 or MIG3232
  -> receive/guard checks -> kernel port destruction
```

The flow is conditional on the selected object/factory, current flags, count and callback epochs. It does not identify an effective native FairPlay job or demonstrate a daemon exit/restart cycle.

## Role correspondence

| Analytical role | arm64e start | arm64e.x1 start |
|---|---|---|
| Selected job factory | `0x100029b84` | `0x1000292a8` |
| Factory bridge | `0x1000044c0` | `0x100004484` |
| Record clone/creation helper | `0x100050fac` | `0x1000500d8` |
| Base record initializer | `0x100005094` | `0x10000504c` |
| Endpoint constructor wrapper | `0x10002a6a8` | `0x100029d9c` |
| Fixed endpoint callback | `0x10002a950` | `0x10002a038` |
| Demand/pending-reason gate | `0x10002a35c` | `0x100029a50` |
| Start gate | `0x100021eb4` | `0x1000217dc` |
| Launch core / spawn frontier | `0x10001ee14` | `0x10001e76c` |
| Activation deactivation | `0x10005aaac` | `0x100059b0c` |
| Pending-reason consumption | `0x10005af54` | `0x100059f90` |
| Endpoint-group rearm | `0x100030778` | `0x10002fd7c` |
| Single-endpoint rearm | `0x100047600` | `0x1000468b8` |
| Additional source restoration | `0x100022174` | `0x100021a78` |
| Endpoint removal | `0x10002fd84` | `0x10002f3b8` |
| Job-record removal | `0x100029818` | `0x100028f48` |
| Asynchronous destruct block | `0x100047a2c` | `0x100046cb4` |

Roles are analytical labels supported by original instructions, import bindings and diagnostic literals, not unverified original nlist names. The source records one direct caller of each endpoint constructor, eight exact-address wrapper literals and eight demand-gate literals per slice. Literal sites occupy seven distinct producer functions per slice; one function has two sites. Only the selected factory's full installation flow is joined here. Three immediate STR-w+0x120 candidates per slice are retained, including the selected pending writer and consumer clear; aliases/wider stores and other images are outside that locator [EJ1,EJ6].

## Factory table and callback cookie

The selected factory constructs a72 B stack contract: eight authenticated function pointers (64 B) followed by an8 B domain cookie. It passes that address through the bridge and clone/creation helpers. Base initialization copies all64 callback bytes to record+0x218 and stores the trailing cookie at+0x258. The launch core later loads record+0x220 as its demand callback and record+0x258 as argument2. This resolves the selected indirect callback to the pending-reason producer without treating an arbitrary function-pointer value as an executed call [EJ1].

| Index / record field | arm64e literal target | arm64e.x1 target | Recovered role |
|---|---|---|---|
| 0 / +0x218 | `0x100029f84` | `0x1000296a8` | Unknown here |
| 1 / +0x220 | `0x10002a35c` | `0x100029a50` | Demand/pending-reason gate |
| 2 / +0x228 | `0x10002a510` | `0x100029c04` | Unknown here |
| 3 / +0x230 | `0x10002a6a8` | `0x100029d9c` | Endpoint constructor wrapper |
| 4 / +0x238 | `0x10002a70c` | `0x100029e00` | Unknown here |
| 5 / +0x240 | `0x10002a714` | `0x100029e08` | Unknown here |
| 6 / +0x248 | `0x10002a7f8` | `0x100029eec` | Unknown here |
| 7 / +0x250 | `0x10002a850` | `0x100029f38` | Unknown here |

The endpoint wrapper passes a fixed signed callback in X3 and its incoming job/owner pointer in X5. The original endpoint constructor stores incoming X0 at endpoint+0x60 and callback/cookie at+0x90/+0x98. The selected job factory also has an endpoint-cloning branch that directly stores the same fixed callback and new owner cookie into cloned endpoints. Thus the single direct-constructor wrapper census is not an exhaustive census of callback-field writers.

For the callback ABI, X0=endpoint E, W1=reason and X2=job/service-owner J. The original reason1 diagnostic says `Deactivated abandoned endpoint: %s`; the downstream count diagnostics explicitly identify service activation count. These are activation counts, not kernel port reference counters. Domain D is loaded from J+0xf8 and checked again by deactivation. Native record identity/lifetime and all other writers remain assumptions [EJ1-EJ3].

## Reason0, pending demand and conditional launch

Reason0 selects start reason8 when endpoint flags+0x58 bit3 is set, otherwise1, then calls the start gate. Other nonzero callback reasons apart from1 return through the ordinary epilogue. The callback normalizes raw status36/37 to0 using `(status & ~1)==36`; installed SDK definitions identify EINPROGRESS/EALREADY. Its later literal status37 diagnostic comparison cannot be selected by this normalized scalar reason0 flow. The full u32 normalizer proof does not claim that arbitrary alternate entries or native callbacks are unreachable [EJ4,EJ6].

The start gate has separate checks of J+0x128, a byte at+0x1b8, flags and another u32 at+0x490. Original literals name launch-already-in-progress and penalty-box conditions. The +0x128 field remains a raw discriminator here; some diagnostics use a managed/unmanaged label, but its complete producer/type meaning is not established. The successful gate tail-calls the launch core.

The core first invokes the selected callback at J+0x220 with `(J,start_reason,J+0x258)`. The recovered demand gate checks domain flags and reason-dependent domain conditions. Its selected deferral branches include owner flag+0x180 bit1 and a nonzero activation count at+0x12c; they store the requested u32 reason at J+0x120 and return36. Other branches consult additional domain/reason policy and can store the same field or a separate+0x124 reason. No complete launch-policy predicate is inferred from those selected branches.

The launch core contains an authenticated import call to `_posix_spawnp` at `0x10001f7c0` / `0x10001f118`. Arguments include a local pid-output address, executable/path, file actions, attributes, argv and environment. It checks both API status and positive pid output, with additional setup, error cleanup and later publication paths. The core also calls indirect policy helpers and many attribute builders. Capturing this frontier does not prove native process creation, a particular executable, successful admission or that these objects belong to fairplayd [EJ1,EJ4].

## Reason1 and activation-count transitions

Reason1 loads D=J+0xf8, optionally logs, checks endpoint state and either clears endpoint+0x58 bit2 or runs endpoint removal according to another endpoint flag. It then tail-calls deactivation(D,J). Deactivation checks that J+0xf8 equals D, decrements/stores the signed16 activation count at J+0x12c, and has separate overflow/underflow diagnostics.

For old signed count n and the zero/nonzero class m of J+0x128, the selected scalar control is:

```text
store u16(n-1) before diagnostic checks
bad count: n <= 0
ordinary early return: n > 1 + (m != 0)
cleanup candidate: n == 1, or (m != 0 and n == 2)
```

The minimum signed16 input reaches the first diagnostic guard; other nonpositive inputs reach the subsequent count guard. The131072 finite scalar cases cover every count bit pattern and both discriminator classes. They are arithmetic/control checks, not execution with manipulated target records or demonstrations of a native failure.

The cleanup region has further flags, running/unmanaged distinctions, group/reply state and endpoint-list conditions. The branch with a nonzero+0x128 discriminator checks dynamic/pid endpoint pointers, logs inactive unmanaged removal, fills the fixed0x590 B record prefix with0xcc and frees it. This is a selected removal branch, not an inferred object-lifetime guarantee. The other suffix can rearm endpoints unless domain/job flags choose removal. Only when domain+0xb0 is zero and J+0x120 is nonzero does it tail-call pending-reason consumption. That helper loads the reason, clears J+0x120 and tail-calls the same start gate. A queued reason is therefore necessary for this selected restart edge; endpoint return alone is insufficient [EJ2-EJ4].

Deactivation also has an outgoing XPC reply frontier: it clears a nonnull object from J+0x110, calls `_xpc_pipe_routine_reply`, checks the raw status against a mask tolerating0/32, then releases the object. Dispatch-group leave/release operations are separate. Reply object construction, its endpoint identity and actual reply delivery are not newly established.

## Endpoint rearm and asynchronous destruction

The endpoint-group helper walks lists rooted at J+0x98, J+0xb0 and J+0xb8 and invokes single-endpoint rearm after checking endpoint flags. It separately walks another list and restores additional sources. Those source bodies are captured, but their native registration/timer delivery and complete readiness policy are not proved.

Single-endpoint rearm has assertions for affiliation/flags and an optional asynchronous-reset request. After that optional helper and its reread, its selected flag formula is:

```text
new_flags = (flags & 0xffbd) | 0x0002
if u32(owner_field_0x478) >= 2: new_flags |= 0x0400
```

It conditionally tail-calls the previously recovered Mach receive-source constructor when a send-object exists and bit10 is clear. The formula clears bit6 and sets bit1; its native object/source epoch remains unknown. The optional helper can schedule destruction, so the scalar proof begins after its reread and does not assume that helper leaves earlier flags unchanged [EJ2,EJ3].

Asynchronous preparation extracts endpoint+0x68's XPC send-object pointer and endpoint+0x70's saved context, clears+0x68, retains/checks the endpoint and submits a block to the queue loaded from `0x10008b160`. The block captures the XPC object at+32, context at+40 and endpoint at+48. It gets the numeric name through `_xpc_mach_send_get_right` and calls `mach_port_destruct(task_self,name,0,context)`. A nonzero result takes a diagnostic path and then rejoins XPC release and endpoint release. Enqueueing, block execution and the synchronous reason1 callback are distinct epochs; native scheduling order is unknown [EJ2,EJ5].

| Destruction layer / site | Original contract |
|---|---|
| Launchd destruct emission | `0x100047a60` / `0x100046ce8`; task/name, signed32 delta0, u64 saved guard |
| Cached public wrapper | `0x1805496a8`; fast trap then fallback only on0x10000003 |
| Cached trap wrapper | `0x180547b1c`; selector-25, SVC0x80 |
| Original trap25 handler | `0xfffffe000bcdbe64`; registry slot `0xfffffe0007efb270`, four arguments/five u32 words |
| Cached fallback MIG routine | `0x18056e0a4`; RPC3232, simple48 B user request |
| Original MIG3232 stub | `0xfffffe000bd87740`; simple56 B internal request; calls `0xfffffe000bce0714` |
| Common destruct core | `0xfffffe000bce0714`; entry lookup then tail-call to right destruction |
| Right destruction | `0xfffffe000bcd4ab0`; receive flag, delta and guarded-context checks; selected call to port destruction |
| Port-destruction call | `0xfffffe000bcd4d18` -> `0xfffffe000bccdbb4` |

The user request is header24 B, NDR8 B, name4 B, signed delta4 B and guard8 B. The installed SDK verifies offsets32/36/40 and total48 B, plus a36 B status reply. Kernel header expansion accounts for the56 B internal request. These layouts describe captured code; no request packet is constructed or emitted.

Right destruction requires the entry's RECEIVE bit17. Nonzero delta has additional send-right/count requirements; positive deltas are rejected by the selected signed test. For a guarded port (live port flag bit10), it compares the supplied64-bit context with port+0x78. The selected successful suffix changes namespace state and calls the original port-destruction routine used by notification69. Delta0 means no requested send-user-reference adjustment; it does not prove absence of namespace/right/reference effects. Backup-notification state, lower locking, retirement and native ownership remain separate prerequisites. The same destruction routine appearing in both paths does not establish a native notification loop [EJ2,EJ5].

## Additional architectural touchpoint

The captured endpoint-removal body has a conditional `_exclaves_daemon_notification_deregister` call. It requires selected endpoint flags, obtains an affiliation context through endpoint+0x60 then+0x570, obtains a valid-looking send name, and supplies the endpoint's name string. Actual Exclaves registration, this context's producer and any connection to FairPlay's protected processing remain unknown. This is an original import/call touchpoint, not evidence that a FairPlay job uses it. It supplies a concrete register/deregister pairing lead for later analysis.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Static stress test / falsification probe | Remaining boundary |
|---|---|---|---|
| EJ1 | Selected factory/table/job/endpoint instances share one callback lineage | Check all72 table bytes by installation operations, cookie propagation, clone callback write and fixed wrapper; record other literal producers separately | Effective FairPlay instance, generic dispatch and runtime factory choice unknown |
| EJ2 | Activation counts, pending reason and endpoint objects remain valid through callbacks | Verify signed16 precheck store/guards, threshold, pending write/clear, owner/domain equality and rearm/remove branches | Other writers, nested callbacks, interleavings and native lifetime unknown |
| EJ3 | Rearm and queued destruction have the applicable source/object epochs | Preserve optional helper/reread, source conditions, captures, queue cell and release order | Native queue serialization, execution order, source uniqueness and complete balance unknown |
| EJ4 | The pending restart passes all start/policy/process prerequisites | Link table slot+0x220/+0x258, demand deferral, start gate and original spawnp frontier; retain other policy branches | Admission, executable/argv/environment, actual process creation and readiness unknown |
| EJ5 | Asynchronous destruct refers to the intended guarded receive right | Follow name/context capture, delta0, trap/MIG convergence, receive/guard checks and port-destruction call | Native name/object/guard identity, backup epoch and retirement unknown |
| EJ6 | Captured versions and bounded searches support only their stated domains | Pin hashes/UUIDs, decode both slices, compare4894 fixups, compile SDK and reject altered byte/decode/table evidence | Runtime slice, hardware authentication/ISA and exhaustive caller/writer census unknown |

## Bounded continuation context

| Impact | Remaining interface question | Concrete next anchor |
|---|---|---|
| High | Which factory/table instance owns fairplayd's endpoints? | Join actual job parsing and endpoint publication to the selected callback table; distinguish constructor versus clone writers |
| High | Remaining job policy callbacks and launch input production | Analyze the six table entries with unknown roles and actual executable/argv/environment/attribute producers |
| High | Exclaves endpoint registration context | Pair the original deregister call with register producer and affiliation+0x570; do not infer a protected-core connection from the import alone |
| Medium | Queue/source/activation lifetime | Join pending-reason writers, async block order, source cancellation and right/record retirement for one object epoch |
| Medium | Deactivation reply delivery | Recover J+0x110's producer, reply object/port identity and caller-visible completion |
| Low | Scalar diagnostic reachability | Keep the normalized status37 comparison separate from a global all-entry reachability claim |

## Validation and quality gates

Fresh source recapture matches the capture. Checks pass155 selected instruction assertions,15 SDK assertions in one arm64 compilation, four full-domain scalar proofs,131072 activation-count inputs and seven rejected evidence alterations. Both slices'4894 fixups independently match dyld_info. All7950 instruction bytes/decodes are contiguous; the52 LLVM-only words are checked against their byte, mnemonic and operand records. Sixteen wrapper literals,16 demand-gate literals, two direct constructor callers and six immediate pending-offset candidates remain scoped locators. [Recovery](triage_evidence/recover_endpoint_job_lifecycle.py), [validator](triage_evidence/validate_endpoint_job_lifecycle.py), [delivery](triage_evidence/endpoint_job_lifecycle_delivery.json), [quality gates](triage_evidence/endpoint_job_lifecycle_quality_gates.json).

Capture/search is O(B+F+I) time/space for original bytes B, fixups F and instructions I. List rearm is O(n) in visited endpoints; scalar status/count/flag decisions are O(1). The finite bank explicitly covers131072 cases; fixed-width solver queries do not prove general solver complexity, object bounds, callbacks or native execution.

QG1: Descriptive interface analysis; no normative premise required.

QG2: EJ1-EJ6 register assumptions, dependent claims, falsification probes and unknowns.

QG3: Selected callback production/consumption, activation/pending state, launch frontier, asynchronous destruct ABI and additional touchpoints are reported; the full goal remains active.

QG4: Callback pointers/context64 bit, reasons/statuses/delta32 bit and activation count16 bit; byte extents and full scalar domains are explicit and checked.

QG5: Activation count differs from port reference count; return differs from unconditional restart; scheduling, source rearm, queued destruction, raw discriminators and native process success remain distinct.

QG6: Pinned original bytes, exports/fixups, diagnostics, installed primary SDK, recapture and checked instruction/scalar evidence supply provenance; private labels remain analytical.

QG7: Further opportunities have bounded anchors and impact labels. Native callbacks/relaunch/ownership/guard effects and FairPlay processing remain unknown.
