# Special IPC-space bootstrap and kernel-thread reply-port lifetime

Original code now produces the special IPC-space input used by the kernel reply-port creator, initializes and binds a kind0x0b reply port, links it to a destination and publishes its send-once right into the recipient namespace. Linked header copyout releases the destination-object and send-turnstile holds separately. The last turnstile hold reaches original lock destruction and96-byte zeroing before a modeled raw retirement request. Unbind and replacement prefixes clear the binding/owner and stop before port destruction.

Independent checks pass for three original zone producers and35 lifetime components:110 complete functions /14746 instructions,12252 original instruction visits,38 full-memory replays and three bounded scalar proofs. The actual transport between constructor, send and receive remains unjoined. Raw storage/retirement, separate initialization/call/CPU epochs, logical PAC, keyed hashes and the internal RPC representation remain explicit premises. Native IPC and a complete FairPlay exchange remain unknown; RPC700's actual recipient is still unknown.

## Provenance and assumption register

Primary KC SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Kernel addresses are preferred VAs; private0x6500... addresses belong to the component model. Offsets, extents and capacities are bytes, little-endian. Original inputs, IDBs and memory stores are unchanged. Existing original KC evidence sufficed; no new IDA query was needed.

| Artifact | Evidence |
| --- | --- |
| [Source](triage_evidence/kernel_special_reply_source.json) | 110 complete bodies, exact symbols,29 added role words, selected startup records and a bounded reference scan |
| [Profiles](triage_evidence/kernel_special_reply_profiles.json) | Three zone producers and35 lifetime components; full RAM/global origins, source reads/writes, regional imports and raw primitive contracts |
| [Checks](triage_evidence/kernel_special_reply_checks.json) | Complete-record and source-origin oracles, fresh producer/CPU replay, hold/state/type-cell proofs and zeroing/order checks |
| [Recovery](triage_evidence/recover_kernel_special_reply.py), [probe](triage_evidence/probe_kernel_special_reply.py) | Source capture and explicit component construction |
| [Replay](triage_evidence/replay_kernel_special_reply.py), [validator](triage_evidence/validate_kernel_special_reply.py) | Independent executor and semantic validation; no probe executor import |
| [Delivery](triage_evidence/kernel_special_reply_delivery.json), [quality gates](triage_evidence/kernel_special_reply_quality_gates.json) | Preservation, owned reporting updates and scoped gates |

The [reply namespace report](kernel_reply_namespace_report.md) previously exercised an ordinary type1 reply object; this increment executes the original creator's special kind0x0b path. The [kernel transport report](kernel_rpc_transport_report.md) supplies the original caller/endpoint context. The [namespace report](kernel_namespace_report.md) provides earlier state-union/source correlations; its deeper hold/turnstile models are replaced on the selected paths here. The [zone startup report](kernel_zone_startup_report.md) supplies the retained startup implementation and catalog. Separate [kext constructor fields](kext_constructor_request_report.md) still enter through an explicit representation import.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| SK1 | Pinned KC identity, compiler bounds, logical fixups and exact symbols identify the source epoch. | Rehash/recapture bodies, role words, catalog records, constant bytes, reference windows and every executed instruction. |
| SK2 | Zone startup uses declared bootstrap count40, raw per-CPU/magazine storage and primitive lock results. Dynamic ipc-space zone40 is conditional on that count. | Execute actual startup registration/order and allocator/storage producers; vary the dynamic allocation epoch. Slot40 is not asserted to be the native runtime identifier. |
| SK3 | Three complete zone records and their disjoint private statistics/cache/magazine records are transferred from separate source producers. | Join the full registry/cache/page/bootstrap epoch. These regional imports establish consumed values, not a completed native allocator lifetime. |
| SK4 | Raw allocators return declared zeroed128-byte space,144-byte port and96-byte turnstile storage; raw retirement returns under its declared contract. | Execute original allocation, backing/zero guarantees, failure and reclamation paths. Original zeroing and retirement requests do not establish native reclamation. |
| SK5 | Receiver owner, embedded BSD-task wrapper, task-associated record and metadata cells are valid private context records. | Recover their real producers and complete extents. Original helpers validate/read them, but the supplied PID values4242/77 are fixtures, not observed process identities. |
| SK6 | Fresh kernel-thread and receiver calls transfer full RAM/globals while resetting explicit entry CPU/call frames; authentication is logical. | Establish actual caller stacks, scheduling/event order, native signed pointers and hardware authentication. Equal memory does not establish native control continuity. |
| SK7 | Source kmsg container and constructor fields form a declared internal RPC502/700 header with the produced reply object. Keyed hash outputs remain modeled. | Join original constructor, preparation/copyin/send/receive and actual keyed validation; preserve all ownership and bytes across that join. |
| SK8 | Inline storage, one descriptor, zero selected ancillary/inheritor work and the retained process/state paths bound coverage. | Continue descriptor/VM conversion and daemon dispatch, nonzero inheritance/workloop/group paths and complete port destruction. A native FairPlay round trip remains unknown. |

## Newly captured routine roles

Nineteen additions contribute2184 instructions. Complete capture does not mean every branch executes. Common RPC transport and port-destruction bodies are retained as static context; lifetime runs stop before destruction entry.

| Address | Instructions | Role / coverage |
| --- | ---: | --- |
| 0xfffffe000c63222c | 16 | Zone startup callback; original specification decode and optional publication |
| 0xfffffe000bd772b4 | 568 | Zone creator; fixed22/28 and dynamic40 paths execute |
| 0xfffffe000bd77bb0 | 77 | Per-CPU cache initialization; selected ipc-port cache executes |
| 0xfffffe000c2ba130 | 36 | Exact `_proc_pid`; typed BSD-wrapper validation and declared PID read execute |
| 0xfffffe000c629780 | 89 | Special IPC-space bootstrap; prefix initializes/publishes two spaces, then stops |
| 0xfffffe000bcf8e14 | 73 | Kernel reply-port creator, binding and old-binding replacement prefix |
| 0xfffffe000bccef30 | 119 | Destination linkage; destination object retain and reply-state/union publication |
| 0xfffffe000bcced98 | 102 | Destination send-turnstile preparation and primary hold acquisition |
| 0xfffffe000bcceadc | 68 | Send-turnstile primary hold release and final completion |
| 0xfffffe000bcce310 | 97 | Select/update port-associated turnstile inheritor; selected null-inheritor path |
| 0xfffffe000bd68354 | 35 | Typed turnstile object-reference acquisition |
| 0xfffffe000bd683e0 | 37 | Turnstile object-reference release, lock destruction, zeroing and raw-free ABI |
| 0xfffffe000bcc927c | 19 | Safe destination object-reference release |
| 0xfffffe000bd7deec | 30 | Exact `_get_bsdtask_info`; typed embedded-task wrapper and association flag |
| 0xfffffe000bd6d488 | 28 | Queue/turnstile lock destruction adapter |
| 0xfffffe000bd0aa54 | 24 | Ticket-lock destruction; original clear executes |
| 0xfffffe000bcf837c | 21 | Kernel thread reply unbind; owner/binding clear and held destruction boundary |
| 0xfffffe000bccdbb4 | 471 | Port destruction; captured, stopped before entry |
| 0xfffffe000bcf59e0 | 274 | Common kernel RPC transport; static binding/reuse/send/link context |

Other names are recovered roles rather than exact original symbols. Existing captured bodies supply port/turnstile initialization, make-send-once, namespace allocation/publication, actual ticket locks, header conversion, ordinary completion and `_bzero`. [SK1-SK8]

## Bootstrap source of the special spaces

The original file cell0xfffffe0007e63348 is zero. A scan of2540432 kernel `__TEXT_EXEC` words selects five ADRP-to-page/100-byte offset-mention windows. Their matched accesses include reads in0xfffffe000bccfa90,0xfffffe000bccfbe0,0xfffffe000bcf5d70 and0xfffffe000bcf8e6c, plus the bootstrap store at0xfffffe000c629828. Original windows and decoded instructions are retained. This is a bounded direct syntactic scan, not proof that arbitrary indirect writers do not exist.

The startup catalog identifies an `ipc spaces` callback with requested identifier0xffff and an optional publication slot0xfffffe0007e5c470. With the declared reserved-slot count40, original creator code chooses zone40 and the callback publishes its pointer. Fixed ipc-port and turnstile startup records use identifiers22/28. The three runs use disjoint declared per-CPU storage addresses; statistics/cache identities are not silently shared across their separate epochs.

| Original specification | Requested ID / produced private ID | Element extent | Page-start adjustment | Zone-record address |
| --- | --- | ---: | ---: | --- |
| ipc ports | 22 /22 | 144 | 112 | 0xfffffe000caec500 |
| turnstiles | 28 /28 | 96 | 64 | 0xfffffe000caec980 |
| ipc spaces | 65535 /40 | 128 | 0 | 0xfffffe000caed280 |

Complete192-byte records are transferred, together with source statistics records and the selected port-cache/magazine records. The ipc-port cache has two declared empty magazine observations; turnstile and ipc-space runs take the no-cache path. This replaces the earlier partial eight-byte class22 validation import for these calls, while retaining raw backing and overall bootstrap-order premises. [SK2-SK4]

Original0xfffffe000c629780 loads the callback-published ipc-space zone view and requests two raw allocations with flags0x8004. It writes both128-byte special-space records from original constants, initializes the selected lock/token/word fields and publishes:

| Original store | Destination global | Produced private pointer |
| --- | --- | --- |
| 0xfffffe000c6297ec | 0xfffffe0007e62b68 | Kernel special space0x6500054000 |
| 0xfffffe000c629828 | 0xfffffe0007e63348 | Reply special space0x6500054100 |

The two records have identical source-initialized bytes: original constant at+0, ticket word0x144 at+8, original constant at+0x0c, logically signed16 at+0x58 and word3 at+0x68; remaining bytes stay zero under the raw-storage premise. No full private-space type layout is inferred from these fields. Execution stops at0xfffffe000c62982c before unrelated kernel-object/map initialization. The global's zero file state is therefore an initialization-epoch fact, not evidence that the native runtime lacks a reply space. [SK2-SK4,SK6]

## Bound reply-port creation and endpoint directions

In the private kernel-thread context0x650002c000, original creator code reads thread+0x3f0. On the new-binding path it obtains class22 storage, calls the actual initializer with `(port,reply_space,0x10b,0,0,1)`, temporarily retains the object, stores the thread binding, signs/stores the owner, unlocks and drops the allocation-side reference. The selected type policy produces object word0x20b: low-byte kind0x0b with the source-produced active-state bits.

| Interface | Original location | Produced role |
| --- | --- | --- |
| Bound reply port | 0xfffffe000bcf8ec4 | thread+0x3f0 =REPLY |
| Owner publication | PACDA0xfffffe000bcf8ed0; store0xfffffe000bcf8ed4 | reply+0x40 =logical kernel-thread pointer, discriminator0xf4d6 |
| Reply-space receiver | Initializer0xfffffe000bccd170 | reply+0x48 =bootstrap-produced reply space |
| Internal receive-name field | Initializer store0xfffffe000bccd224 | reply+0x34 =1; this is not an observed user-task name |
| Creator result | 0xfffffe000bcf8f00 | X0=0; the endpoint is read through the thread field |

Reference count1 after initialization becomes2 for binding publication and returns1 after original unlock/release. Original make-send-once then yields reference2 / send-once1. The complete144-byte port record and both1536-byte thread records are independently checked; the receiver's own binding field is not substituted for the kernel caller's field. [SK4-SK6]

Static common transport reads the thread binding at0xfffffe000bcf5a6c/5a90/5aa0, calls the creator at0xfffffe000bcf5aa8 only when absent, and stores the bound object into internal header+0x10 at0xfffffe000bcf5b2c. Its existing send emission remains0xfffffe000bcf5ba8 ->0xfffffe000bcc7040. The later reply/destination linkage call is0xfffffe000bcf5c14. These source edges corroborate endpoint direction; this increment calls the lifetime helpers as separate components and does not execute that uninterrupted transport.

The generated endpoint receives the kernel caller's reply. The daemon-side request obtains a send-once name for that endpoint; it is distinct from the service receive name. Original header publication here generates recipient name0x207 for REPLY and leaves the declared service name0x303 in the local slot. Actual native task-local names and RPC700's recipient remain unknown. No new message emission is established. [SK6-SK8]

## Destination linkage and two different holds

Original0xfffffe000bcced98 locks and validates the destination. When no live send turnstile exists it unlocks, runs original turnstile allocation/initialization, reacquires the port and prepares the turnstile at destination+0x70. Original initialization and null-inheritor update execute; only the raw96-byte allocation result is modeled. The helper increments turnstile+0x58 as a primary hold.

Original link0xfffffe000bccef30 then locks the special reply port, requires sync-state0 and no inheritor, increments destination+4, signs/stores the destination into reply+0x58 with discriminator0xa1c0 and sets sync-state1. An optional bootstrap argument sets flags+0x10 bit15. These actions leave the original owner/thread binding intact.

| Resource | Field | Link effect | Header copyout cleanup |
| --- | --- | --- | --- |
| Destination object hold | destination+4 | Reference3->4 | Linked hold released separately from message destination consumption; final reference2 |
| Message destination send hold | destination+0x88 | Existing send count2 | Conversion consumes one; final send count1 |
| Send-turnstile primary hold | turnstile+0x58 | First link0->1; shared case1->2 | First case1->0; shared case2->1 |
| Turnstile object reference | turnstile+0x50 | Source initializer produces1 | Last primary completion eventually releases1->0 before zero/free request |
| Reply namespace right | reply+0x8c / entry bit18 | Existing send-once1 | Namespace publication preserves count1 and one user reference |

The shared case obtains its first hold through an additional original prepare call before link. No primary count is patched. Header copyout releases the link's hold while the outer hold keeps destination+0x70 and the full turnstile record alive. A subsequent original completion call releases the outer hold, detaches the last turnstile and reaches destruction/zeroing. [SK3-SK8]

## Header publication, state transition and diagnostic context

The internal RPC representation imports the original constructor's body/ID, sets the generated bound port as its reply object and uses destination disposition17 / reply disposition18. The recipient namespace has the retained declared free slot2. Original header copyout, reply-state query, entry allocation and right publication now execute with the special0x20b port, rather than an ordinary type1 stand-in.

On an unlinked port, publication's completion adapter simply unlocks; sync-state0 and diagnostic word0 remain. On a linked port, publication invokes original adjust0xfffffe000bcce5b8 with flags2 in the receiving-thread context. The helper clears the destination union, transitions state1->4, records diagnostic context, releases the send-turnstile hold and drops the linked destination reference. Later destination conversion consumes the message's send/object reference. Reply reference2 / send-once1 and the kernel thread binding remain after both paths.

| Case | Header-boundary sync state | Destination send-turnstile after header | Diagnostic word | Owner / thread binding |
| --- | ---: | --- | ---: | --- |
| Unlinked new port | 0 | NULL | 0 | Preserved |
| First link | 4 | Detached;96 bytes zeroed before raw retirement | 4242, fixture BSD PID | Preserved |
| Shared hold | 4 | Present; primary count1 | 77, fixture task-record value | Preserved |
| Bootstrap link | 4; bit15 remains set | Detached and zeroed | 4242 | Preserved |

The diagnostic data comes from the receiver's current task, not the constructor's `origin` scalar or the kernel message's audit token. Two original routes execute:

| Source route | Validated/read representation | Fixture output |
| --- | --- | ---: |
| `_get_bsdtask_info` -> `_proc_pid` | Task pointer embedded at wrapper+0x7c0; class26 wrapper extent0xe90; task+0x6c8 bit0 set; `_proc_pid` reads wrapper+0x60 | 4242 |
| No BSD association -> task-associated record | The association flag is clear; original code authenticates task+0x320 and reads u32 at that record+0x18 | 77 |

Four linked headers execute original `_proc_pid`; one uses the alternate record path. The exact native type/name and producer of that alternate record remain unknown. Both process/context records are explicit private inputs. Their PID values do not attest a running process, initiating user, privilege or FairPlay policy decision. [SK5-SK8]

The type metadata index is `(pointer>>10)&0xffffffff0`, so objects in the same16-KiB page share a metadata cell within the private arena. Independent checks place the56-byte receiver-owner record in a type3 cell, the3728-byte BSD wrapper in a separate type26 cell, and ports/turnstiles/special spaces in their corresponding distinct cells. The selected raw object offsets satisfy the source-produced zone reciprocal/element geometry. This avoids inconsistent typed fixtures; it does not establish native allocation validity.

## Last send-turnstile hold and raw retirement

Original0xfffffe000bcceadc decrements the primary count. On zero it removes the sole turnstile from destination+0x70, calls original completion with an output pointer, unlocks and releases the returned object's reference through0xfffffe000bd683e0. Source object-reference release1->0 enters queue-lock destruction0xfffffe000bd6d488 and ticket destruction0xfffffe000bd0aa54, then calls exact `_bzero`0xfffffe000c6480c0.

All five selected final-release paths execute original stores clearing the complete96-byte turnstile. Independent checks require exact96-byte coverage, zero after-values, zeroing before the raw-free request and preservation of the following0xa5 guard byte. The raw free ABI is `(zone28,source_stats,SNDTS,96)` at0xfffffe000bd74fcc. Its allocator effect remains modeled; private mapped zero storage is not native reclamation evidence.

The shared case reaches this sequence only after its explicit outer hold is dropped. No turnstile is allocated or retired in the unlinked family. Port references and send counts are separate from both turnstile counters throughout. [SK3,SK4,SK6,SK8]

## Reuse, reset, unbind and replacement

The common transport reuses a nonzero thread field without calling the creator. Calling the creator directly with an existing valid binding instead follows its old-binding cleanup path. These are different source entry contracts.

After bootstrap-linked publication, an actual port lock followed by original adjust flags1 resets sync-state4->0 and clears the diagnostic word. Owner/thread binding and bootstrap bit15 remain. This exercises the source reset operation; it does not establish the native caller/event causing it.

Original unbind0xfffffe000bcf837c clears thread+0x3f0 at0xfffffe000bcf839c and calls adjust flags4, which clears owner+0x40. The creator's replacement prefix performs the corresponding clear at0xfffffe000bcf8e44. Both then lock again and reach0xfffffe000bccdbb4 with the port argument and a held ticket. Execution stops before that destruction body; reference2/send-once1 and the published namespace entry still exist at the prefix boundary. Complete port death, native capability invalidation and final retirement are unestablished.

```text
source zone callbacks (separate initialization components)
  -> exact zone/private-record imports; ipc-space zone publication
  -> original special-space bootstrap prefix
       -> kernel-space global + reply-space global
  -> fresh kernel-thread call: original reply creator
       -> thread+0x3f0 and signed owner+0x40
       -> original make-send-once
       +-> unlinked -------------------------------------+
       +-> original destination prepare/link              |
            +-> optional original outer primary hold      |
                                                          v
full RAM/globals + explicit receiver call + internal RPC representation
  -> original special reply namespace publication
       +-> unlinked: state0; binding preserved
       +-> linked: state1 ->4; union cleared; receiving-task diagnostic
            -> linked object/turnstile holds released
                 +-> primary remains1: retain turnstile until outer completion
                 +-> primary reaches0: original lock destroy + zero96
                                           -> modeled raw retirement
  -> STOP before descriptor copyout
       +-> original reset: state4 ->0, owner and bootstrap bit preserved
       +-> original unbind/replacement prefix: binding/owner cleared
             -> STOP before port destruction
```

No native scheduling, send/receive event ordering or user-visible descriptor delivery follows from these component transfers. [SK6-SK8]

## Independent validation and reproduction

Validation recaptures110 complete functions /14746 instructions,29 added role words, three startup records/specifications/fixups and five original reference windows. All three192-byte zone records have independent full-record oracles, including dynamic-zone selection/publication, size/reciprocal/page geometry, disjoint storage and selected empty-cache/magazine records. The prior destination send-reference component and two original kext packet producers are freshly replayed.

Thirty-five main components independently check complete port, reply, turnstile, kernel-thread, receiver-thread, special-space, recipient-space, entry, header and global records. Ordered private/global overlay before images and canonical overlapping observation windows distinguish source-region transfers from declared context fixtures. Source frames verify binding retain/release, published owner, linked references and completion stages. Both diagnostic routes, reset, two held destruction prefixes and all five96-byte zeroing sequences are checked.

Fresh CPU replay covers12252 source visits,2247 writes /14982 bytes,2862 reads /17402 bytes and38 final1-MiB RAM images /39845888 bytes. It checks96 special-space/binding/linkage/completion frames,60 namespace frames,23 raw storage contracts, five raw retirement contracts and12 opaque hash-input records. It verifies48 logical data signatures,48 logical data authentications and449 logical return-PAC steps. Executors share Unicorn's ISA implementation; independent record, provenance, geometry and scalar oracles add separate checks, not cross-engine verification.

The60 API models consist of20 zone-startup storage/lock contracts and40 main contracts:12 raw special-space results, six raw reply-port results, five raw send-turnstile results,12 keyed hashes and five raw retirement results. Main port/space/turnstile locks, namespace creation/publication, process helpers and zeroing execute original instructions.

Three scalar counterexample queries are UNSAT: within the declared1-MiB arena, metadata-cell equality is exactly16-KiB-page equality; paired destination-object/primary-hold increment/decrement restores the initial bounded counters without wrap; and sync-state field replacement preserves all other bits, including bootstrap bit15. These are arithmetic/field results, not proofs of genuine native objects, lifetime, liveness or concurrency.

```sh
cd /Users/___/dev/dylex/extracted

env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_special_reply.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_special_reply.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_special_reply.py
```

Expected output includes three UNSAT records,35 passing component records and `all_checks_pass:true`. Recovery is O(image+source+kernel instruction words) time and O(image+source+windows) space. Execution/replay is O(image+visits+RAM+effects) time and O(image+RAM+journals) space; scalar solver cost is separate. No native IPC latency, contention or allocation guarantee follows.

## Bounded expansion and quality gates

| Impact | Further evidence | Interface resolved |
| --- | --- | --- |
| High | Actual common transport preparation/copyin/send/receive using these produced bindings | Replace separate calls and the internal packet representation import |
| High | Descriptor/VM conversion and daemon forwarding from these produced headers | Connect special-port namespace output to actual work/reply payload |
| High | Complete original port destruction and namespace-right invalidation | Extend the held unbind/replacement prefix to final lifetime effects |
| High | Raw zone allocation/backing, actual bootstrap order and reclamation | Replace storage, dynamic-slot and retirement premises |
| Medium | Nonzero turnstile inheritors, workloop/knote and group tracking | Extend priority/ownership control beyond selected null-inheritor paths |
| Medium | Original receiver owner/BSD-wrapper and task-associated-record producers | Establish real diagnostic-context identity and its native invariants |
| Medium | Actual reset and exceptional-unbind callers/events | Establish when the verified local transitions occur in an authentic RPC |
| Low | Exact symbols/private types and additional indirect global writers | Refine source roles and reference coverage without changing the preserved evidence |

QG1: All conclusions are descriptive technical analysis; no normative conclusion is required.

QG2: SK1-SK8 identify assumptions, dependent results and falsification probes.

QG3: The increment covers source zone/view and special-space producers, actual kernel special reply creation/binding, destination and turnstile holds, namespace publication, process-context interfaces, zeroing, reset and held unbind/replacement boundaries. Full transport/descriptor/native completion is not claimed.

QG4: All fields/lengths use byte extents or fixed-width integers. Complete records, selected element offsets,3728-byte embedded-task bounds,96-byte zero coverage and scoped arithmetic domains are independently checked. No physical timing result is asserted.

QG5: Distinct thread/task/namespace roles, object versus primary counters, regional initialization imports, raw allocator effects, bootstrap-bit preservation, diagnostic fixtures and held destruction prefixes are separated. Native invariants and unexecuted paths remain unknown.

QG6: Primary KC identities/bodies/symbols/roles, startup catalog/fixups/constants, five reference windows and every executed word are recaptured. Fresh producer/CPU replay and independent complete-record/input-origin oracles pass. Reference sources are not substituted for exact target behavior.

QG7: The impact table bounds remaining transport, descriptor, destruction, allocator, environment and inheritance interfaces. The full interface-investigation goal remains active.
