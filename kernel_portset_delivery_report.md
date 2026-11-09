# Original kernel port-set construction, membership and delivery to CF

Original kernel instructions now allocate a port-set object, publish its namespace
name, construct membership and ready-ring links, select the queued member, and
deliver the original request through a port-set receive. The generated facility
name is0x507. The returned local message name is the member's0x303 or0x403, which
is the key used by the original CF source dictionary. [KP1-KP8]

Four paired private CF compositions use the generated facility and the checked
kernel membership/receive returns. Their original daemon/application paths
remain unchanged. This replaces the earlier direct-receiver packet assumption
with an original port-set producer/consumer execution under explicit lower
contracts. Native runtime epochs, CF object construction and a successful
FairPlay round trip remain unknown. The broad investigation stays active.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| KP1 | Pinned original kernel/daemon/cache corpus is the selected implementation | Source addresses, table bindings and cross-component composition | Recapture163 kernel bodies,28 cache bodies/ten stubs, original trap entries and nine cache hashes; attest actual loaded-image pairing separately |
| KP2 | Frozen queued-request/receiver-loan state and declared receiver/free-entry epochs apply | Namespace allocation and delivery of the original message | Freshly replay all four loans; check complete imported RAM/globals, unchanged queued bytes, existing service entries and original output name/entry; native task/namespace epoch remains unknown |
| KP3 | Source-produced192-byte psets zone record, zeroed56/48-byte raw storage and task-name conversion contracts apply | Original object/link construction and namespace access | Freshly replay zone startup23, check exact allocation arguments, guards, task/space loads and all original stores; native allocator, full boot epoch and task-reference effects remain unknown |
| KP4 | Prior lock/SMR/map/VM and file-value hashed-waitqueue contexts apply | Queue selection, copyout and drained-set wait frontier | Replay every original read/write and final global; identify ticket-lock and queue-head words separately; recover actual bootstrap/concurrency/protection epochs independently |
| KP5 | Harness enters original allocation, insertion and receive functions in sequence with valid argument records | Continuous kernel state across those operations | Check complete CPU/RAM handoffs with only declared arguments/record writes; no internal PC/frame/packet edits; native SVC entry/dispatch and caller ordering remain separate |
| KP6 | Exact kernel scalar/status/message contracts can be paired with the declared CF objects and mode | Original CF registration/lookup/daemon consumer uses facility0x507 | Check task/member/set tuple, source kernel return observations and148+29 transferred bytes; native address-space, source-cache and endpoint identity remain unknown |
| KP7 | Prior CF backends/helpers, clocks/no-work, stack/library/VM-retirement and logical PAC contracts apply | Remaining CF/daemon/application continuation | Independently replay all original suffixes, CPU/model frames, records and final memory; replace lower models and attest hardware authentication separately |
| KP8 | Frontend return, pre-results short receive, duplicate return and pre-scheduler boundaries delimit observations | Return, resource and processing scope | Check complete final objects/links/global state and exact boundary; continue scheduler, ownership/removal and successful application/reply paths before claiming a complete transaction |

## Primary source and execution scope

[Source](triage_evidence/kernel_portset_delivery_source.json) recaptures163
complete kernel functions /21506 instructions from the original collection
SHA-256 d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe.
The nested CF corpus recaptures28 complete cache functions, ten16-byte stubs,
2309 instructions and nine full cache-file hashes. Existing daemon/libbsm
source and binding evidence remain separately inherited. Original Mach dispatch
table entries16 and22 are rechecked through their format8 pointer chains.
[KP1,KP7]

[Profiles](triage_evidence/kernel_portset_delivery_profiles.json) retain eight
kernel cases and four paired CF consumers. [Independent checks](triage_evidence/kernel_portset_delivery_checks.json)
recapture source and replay those cases plus four predecessor loans and psets
zone startup. No new probe is imported by the independent replay implementation.
No native kernel, IPC, allocator, scheduler block, CF runtime or hardware PAC
executes. Original binaries, trace and IDBs are preserved. [KP1-KP8]

The [source-scheduling report](cf_source_scheduling_report.md) previously proved
the original CF registration/lookup calls but modeled membership and supplied
a packet from direct receive. This increment executes the original kernel
port-set object, namespace, membership and ready-selection path that produces
the paired return contracts. The CF objects/mode/hash backing remain declared
fixtures. No complete native daemon startup is inferred. [KP2,KP5-KP7]

## Trap and construction ABI

All offsets/extents below are bytes. Mach names are u32; original kernel handler
argument slots are eight bytes apart. The allocation output address is64 bits.
Original dispatch table names identify the public operation; compiler boundaries
and instruction/data-flow evidence identify the unnamed internal routines.
[KP1,KP3,KP5]

| Original function / site | Address | Recovered operation |
| --- | --- | --- |
| Mach -16 allocation handler | 0xfffffe000bcdb7a4 | Loads u32 task at record+0, u32 right at+8, u64 output address at+16 |
| Allocation core | 0xfffffe000bcde264 | Right3 selects the port-set allocation branch |
| Port-set constructor | 0xfffffe000bcd23ec | Raw zone allocation, namespace entry,56-byte object/header/queue initialization, name and pointer outputs |
| Namespace allocator | 0xfffffe000bcbc250 / 0xfffffe000bcbc0f0 | Consumes declared free entry5, updates generation and publishes name0x507 |
| Allocation name copy | 0xfffffe000bcdb824 | Copies exactly4 output bytes through the inherited user-copy contract |
| Mach -22 membership handler | 0xfffffe000bcdbcc4 | Loads u32 task/member/set at record+0/+8/+16 |
| Membership core | 0xfffffe000bcdfec8 | Allocates link, resolves both names, links member queue and releases unused raw link if necessary |
| Pair lookup/type admission | 0xfffffe000bcc936c | Requires receive-right bit17 for member, port-set bit19 for set; locks validated objects |
| Link construction | 0xfffffe000bd6d744 | Creates member/set rings in original48-byte link; detects an existing membership |
| Ready promotion | 0xfffffe000bd6d864 | Moves link to ready ring and marks member readiness |
| Port-set receive selection | 0xfffffe000bd6bfb0 | Selects/locks ready member queue; removes stale-ready state when drained |
| Queue receive kind switch | 0xfffffe000bcc8550..0xfffffe000bcc857c | Kind5 uses set selector; selected member queue replaces facility queue for dequeue |
| Member receive-name read | 0xfffffe000bcca2ec | Reads four bytes at member object+0x34 during header copyout |

The handlers are entered at their original function boundaries in private CPUs;
there is no native SVC or exception entry. Their original table argument count
is3. The allocation record's third slot is a pointer, so the count is not
interpreted as proof that all three64-bit-path arguments are u32. Task-name0x103
is explicitly converted to the declared receiver task by a lower model. Original
handler instructions then load/authenticate its space field at task+0x318.
Native task translation, references and authorization remain unknown. [KP3,KP5]

## Produced object, namespace and membership

The complete original queued-request state is imported from the prior receiver
loan case. The queued message is not reconstructed or patched. A declared free
entry5 links to the existing free entry2, leaving entry2 available for the reply
right's later original publication. Original namespace code produces0x507 from
index5 and its updated generation. Entry5 contains the source-created port-set
object and bits0x04080000. These are private namespace values. [KP2,KP3]

The psets zone's192-byte source-produced record is transferred from independently
replayed startup identifier23. Its entire bootstrap RAM is not transferred.
The raw allocator returns zeroed56-byte storage; the original constructor writes
the object, waitqueue and namespace fields. Raw48-byte links are separate,
guarded allocations. Zone-type metadata23, raw storage and allocator/task effects
remain declared rather than native allocation proof. [KP2-KP4]

| Produced state | Original-source result |
| --- | --- |
| Port-set header / reference word | 0x200 /1 after allocation returns |
| Waitqueue flags at object+0x10 | 0xad = original low flags13 plus namespace index5 shifted5 |
| Inactive / ready heads after allocation | Both NULL |
| Link+0 | Set waitqueue pointer; low bit1 marks ready membership |
| Link+8 / +16 | Member-membership ring links; singleton points to link+8 |
| Link+24 / +32 | Set inactive/ready ring links; singleton points to link+24 |
| Link+40 | Member waitqueue pointer, service object+0x10 |
| Member object+0x20 | Membership ring head, link+8 |
| Set object+0x20 / +0x28 after promotion | Inactive head NULL; ready head link+24 |

The original ready promotion sets the member waitqueue's bit4. The original set
selector returns that member waitqueue. Dequeue switches back to its service
object and consumes the source-created message. The set's namespace name is
therefore the receive facility, while the copied message's local name identifies
the member receive right. [KP2-KP4]

## Kernel-to-CF contract pairing

```text
kernel private CPU, original queued request retained
  allocation(-16) -> original pset object + namespace name0x507
  insertion(-22)  -> original link + ready member
  receive(0x507)  -> selected member -> dequeue -> exact user/OOL copyout
       |
       | checked scalar/status and byte contracts; not native SVC/task coupling
       v
CF private CPU, declared source/object/mode construction
  original AddSource/getPort/dictionary wrappers
    -> member call(task0x103, member0x303/0x403, set0x507)
       <- checked original-kernel membership result0
  original run-loop receive(facility0x507)
       <- checked original-kernel result0 + USER148 + OOL29
  lookup(returned local member name) -> original source/perform/daemon
```

These are separate private CPU executions joined at explicit operation return
contracts. The kernel task, VM map and namespace are not asserted to be the
actual CF process's native address space. The exact scalar tuple and delivered
bytes are matched; native caller scheduling, address-space transitions, actual
source cache history and effective image pairing remain unverified. [KP5-KP7]

Four accepted kernel cases return0 through the original frontend. Their complete
8192-byte user observations and16384-byte OOL observations are byte-for-byte
identical to the prior direct-receiver cases. The actual message is80 bytes,
followed by a68-byte trailer; OOL content is29 bytes. Header local name is0x303
for RPC502 and0x403 for RPC700, never0x507. Original instruction0xfffffe000bcca2ec
reads exactly that u32 from the selected member object+0x34 during copyout.
[KP2,KP4,KP6]

The paired CF code still normalizes kernel header0x80111112 to0x80001112 using
the original voucher callbacks. Original dictionary wrappers consume the
association produced by original AddSource calls. Source name and produced
facility name are independently checked at the actual wrapper/trap-call
boundaries. Exact original CF/daemon/application instruction suffixes match
the preceding scheduling cases. [KP6,KP7]

RPC502 reaches the original application/libbsm code and stops before pthread
identity acquisition. RPC700 remains unrecognized by the daemon callback and
returns through CF with null generic reply and run-loop result4. Neither result
establishes successful FairPlay processing, authentic reply or a completed
transaction. [KP7,KP8]

## Capacity, duplicate and drained-set controls

| Kernel case group | Cases | Original visits per case | Observed result |
| --- | ---: | ---: | --- |
| Allocation -> insert -> accepted set receive | 4 | 3793 | Original frontend returns0; message/OOL bytes match prior direct receive; member queue empty |
| Capacity147 with RCV_LARGE | 2 | 1793 | Stop before receive-results processing; original queue/count remain intact and user observation stays unchanged |
| Repeat original membership operation | 1 | 1505 | Second insertion returns raw11; existing link topology unchanged; unused second raw link reaches declared retirement |
| Drain then receive again | 1 | 4648 | Original selector demotes stale-ready link, publishes wait state and reaches pre-scheduler boundary |

Accepted receives restore the port-set reference word to1. Short controls stop
with that word2 while the receive-results path still holds its temporary
reference. This is an outstanding operation boundary, not a completed native
resource loss. The duplicate control preserves the queued request and original
link; the newly allocated second48-byte raw record remains zero and is passed
to the modeled retirement boundary. All raw allocation guard bytes remain0xa5.
[KP3,KP8]

After an accepted dequeue the service queue is empty and its readiness bit4 is
clear, while the set may still retain the link on its ready ring. The next
original set selector observes that state, clears the link's ready bit, moves
it to the inactive ring and finds no ready member. The drained control then
executes the original wait-publication path. The scheduler function at
0xfffffe000bd28f6c is not executed. [KP4,KP8]

At that boundary the stored receive-status word is0x10004001 and thread-state
word+0x1f8 is13. These are stored intermediate values, not a completed receive
return. The port-set reference word is2 while the operation is pending. Native
thread scheduling, wakeup and eventual receive completion remain unknown.
[KP4,KP8]

Two original-image global words are tracked explicitly in the private copy:
ticket-lock word0xfffffe000cbca62c (four bytes) and hashed-waitqueue head
0xfffffe000cbca630 (eight bytes). Both begin with their original file values.
The drained control publishes the declared receiver pointer into that queue
head. Original global writes are journaled and independently checked; these
file-value contexts are not proof of actual waitqueue bootstrap, native bucket
type/state or concurrent safety. The lock word is not labeled as an IPC
accounting counter. [KP4,KP8]

## Verification and reproduction

| Independently replayed phase | Original visits | Complete final private bytes |
| --- | ---: | ---: |
| Eight new kernel cases | 24911 | 8388608 |
| Four paired CF/daemon cases | 10108 | 12582912 |
| Four prerequisite receiver loans | 216 | 4194304 |
| Prerequisite psets zone startup | 157 | 1048576 |

The new kernel/CF phases total35019 original visits and20971520 private bytes
(20 MiB). Including prerequisite replays gives35392 visits and26214400 private
bytes (25 MiB). Kernel replay checks5971 reads /38602 bytes and5395 writes
/34107 bytes; CF replay checks2164 reads /12366 bytes and1312 writes /9334 bytes.
Seventeen complete kernel function-entry CPU/RAM handoffs and150 new kernel CPU
frames are checked, alongside636 CF CPU-frame checks. Existing receive and
descriptor/VM handoff checks are retained separately. [KP1-KP8]

All object/name/ring/queue/wire oracles pass. Four altered-evidence controls are
rejected: namespace object, ready link, receive-facility argument and the
kernel-packet patch supplied to CF. Source capture and checks retain the exact
generator/dependency hashes. [KP1,KP5,KP6]

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_portset_delivery.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_portset_delivery.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_portset_delivery.py
```

Run from the extracted directory with the pinned corpus and existing private
Unicorn/Capstone environment. Source, profiles and checks are written; validation
requires `all_checks_pass=true`. Time/space are O(image+source+visits+RAM+journals),
with streamed full-cache hashing and bounded symbol scans. Lower runtime
contracts remain explicit even when the original surrounding instructions replay.

## Bounded continuation

| Impact | Remaining interface evidence | Discriminating next step |
| --- | --- | --- |
| High | Actual CF object/source/mode construction in the matching startup epoch | Continue original creation and cache lookup into the existing CF scheduling path; establish how its mode obtains the constructed kernel set |
| High | Effective native task, endpoint, image and namespace identity | Correlate actual loaded slices and rights/object identity; numeric names alone do not identify a shared native object |
| High | Recognized request processing and authentic reply/ownership completion | Continue original thread/environment/output/disposal paths and correlate reply right, ID and payload with the kext receiver |
| Medium | Multiple ready members and removal/reentry | Produce several original member queues; test actual selection/rotation, extraction, cancellation and object lifetime with consistent epochs |
| Medium | Fast-trap fallback and alternate transport | Recover the special0x10000003 user-wrapper fallback into MIG message construction and dispatch |
| Medium | Raw backing and waitqueue bootstrap/scheduler state | Replace allocation/task/VM/retirement contracts; recover initialized hashed-bucket and wakeup state before claiming native blocking behavior |
| Low | Additional source-produced metadata reuse | Reuse complete zone/runtime state only when address ownership and epochs match; a192-byte zone-record transfer is not a whole-bootstrap transfer |

## Scoped quality gates

QG1: Descriptive source/ABI and state-flow analysis requires no normative premise.

QG2: KP1-KP8 state assumptions, dependent results and falsification probes.

QG3: This increment covers original allocation/membership/set receive, returned
member name, CF return contracts and respective reports. The broad goal remains
incomplete and active.

QG4: Names/widths, eight-byte handler slots, four-byte output,56/48-byte records,
147/148-byte capacity partition and exact replay/memory totals reproduce.

QG5: Facility name, member name, object pointer, stored wait status, completed
return, source-handled state and successful FairPlay processing remain distinct.
Pending references and raw retirement are not promoted to native leak findings.

QG6: Original bytes/table chains, complete functions, fresh zone/loan replays,
exact object/wire/ring oracles, full journals and independent kernel/CF replay
support the bounded claims. Effective native pairing and runtime effects remain
explicit unknowns.

QG7: High/medium/low follow-ups delimit construction, identity, alternate IPC,
ownership, scheduling and bootstrap evidence without claiming native execution.

[Preservation seal](triage_evidence/kernel_portset_delivery_delivery.json),
[quality gates](triage_evidence/kernel_portset_delivery_quality_gates.json) and
[current manifest](triage_evidence/interface_manifest.json) retain publication
provenance. The full interface goal remains active.
