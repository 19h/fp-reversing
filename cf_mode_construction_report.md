# Original CF mode construction and dispatch control-port interfaces

Extent correction: the [original kernel root-port construction report](kernel_root_port_construct_report.md) establishes a 24-byte options structure. This increment recorded its 16-byte constant prefix as `original_options16_hex`; original caller code additionally zeros the final eight bytes, and the kernel copies all 24. Historical execution records retain their original scope.

Original `___CFRunLoopCopyMode` now executes its missing-mode construction and
publication path before original source registration, port-set receive and
daemon dispatch. Original instructions store the source-kernel-produced port-set
name `0x507` at `mode+0x88`. Previously that field was supplied by the fixture.
The mode additionally registers dispatch-root, kernel-timer and run-loop wake
ports. Their numeric names and successful kernel effects remain declared
contracts; only the service membership and service-message receive are paired
with original-kernel executions. [MC1-MC8]

Fifteen private CPU cases cover construction, repeated lookup/registration,
NULL returns, checked failure branches, timer callback and a thread-local word
variation. Four fresh kernel cases supply allocation/membership/receive return
oracles. These are functional compositions between separate private CPUs.
Native task/address-space identity, scheduling and successful FairPlay output
remain unknown. The full interface investigation remains active.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| MC1 | The pinned original daemon/kernel/cache corpus is the selected implementation | Addresses, symbols, layouts and composition | Recapture 39 complete cache functions, 24 stubs, 2834 instructions and nine cache-file hashes; attest native loaded-image identities separately |
| MC2 | The prior frozen service queue, receiver and namespace epochs apply | Port-set allocation name and delivered request | Freshly replay four original-kernel paths; compare allocation status/name, service insertion arguments, receive facility, message and OOL bytes; native epoch coupling remains unknown |
| MC3 | Runtime helpers return valid zeroed mode/queue storage, immutable name and working locks | Original construction stores and continuation | Check allocation arguments, complete final RAM, object guards and failure controls; replace allocator, type/header, string-copy and mutex models before asserting native object lifetime |
| MC4 | Registry and source collections implement the selected declared backend | Mode miss/hit/publication and source lookup | Recompute every collection transition; repeat lookup and duplicate registration; registry matching uses name-pointer equality, with full CFString equality/hash semantics unknown |
| MC5 | Root-port construction, timer creation, auxiliary membership and timer APIs obey their declared contracts | Additional control ports and timer setup | Check original call arguments, option bytes, stores and checked failure branches; original-kernel construction/delivery for these three auxiliary ports remains unexecuted |
| MC6 | The modeled Block runtime copies and relocates the literal/byref records | Callback access after CopyMode returns | Verify original descriptor size 40 bytes, byref size 32 bytes, exact relocated records and original six-instruction callback; native copy/dispose/ownership and pointer authentication remain unknown |
| MC7 | Private TPIDRRO_EL0, queue serial/fork globals and prior logical PAC/no-work/clock contracts apply | Dispatch queue fields and subsequent consumer | Check original atomic/global/TSD calculations, altered TLS word and fork-flag control; native TSD, concurrent ownership, priorities and hardware PAC remain unknown |
| MC8 | Function-entry harness handoffs and reported stop boundaries delimit execution | Construction-to-consumer composition and failure interpretation | Check complete CPU/RAM handoffs and full final state; no native SVC or scheduler execution, complete startup, successful application processing or transaction completion is inferred |

## Source and reproducibility

The primary sources are the original bytes and exact nlist entries in
[source capture](triage_evidence/cf_mode_construction_source.json). The source
contains 39 complete functions and 24 import stubs, totaling 2834 instructions.
The original cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`; nine full
cache-file hashes are recorded. The daemon slice and kernel identities are
retained by the [kernel port-set report](kernel_portset_delivery_report.md).
No additional IDA query was needed because the file corpus sufficed. [MC1]

[Profiles](triage_evidence/cf_mode_construction_profiles.json) and
[independent checks](triage_evidence/cf_mode_construction_checks.json) record
private Unicorn execution of original AArch64 instructions. The independent
[replayer](triage_evidence/replay_cf_mode_construction.py) imports no new probe.
It recomputes declared lower contracts, compares source reads/writes, CPU/model
frames and complete final private memory, and rejects altered records. PAC
instructions use the inherited logical-pointer treatment; no hardware PAC,
native daemon, Mach IPC, kernel, allocator or scheduler is executed. [MC1-MC8]

## Construction and control flow

```text
original AddSource
  -> original CopyMode: registry lookup
       +-- hit ----------------------------> retained existing mode
       +-- miss, create=0 ------------------> NULL
       +-- miss, create=1
             -> runtime storage/name/mutex contracts
             -> original mach_port_allocate wrapper
                  -> checked original-kernel allocation return: 0x507
             -> original root-queue create/init/get-port
                  -> declared mach_port_construct return: 0x607
             -> declared timer source and copied event block
             -> original checked membership calls: root, timer, wake
             -> mode registry publication
  -> original source sets/dictionary creation and registration
  -> original run loop receives on mode+0x88
  -> dictionary lookup by returned local member name
  -> original daemon callback / MIG dispatch / application frontier
```

The harness enters original functions at their entries. Its legacy journal field
`public_handoffs` also contains internal `CopyMode` and run-loop entries; that
field does not establish a public API or native caller sequence. [MC8]

| Original routine | Address | Recovered role |
| --- | --- | --- |
| `___CFRunLoopCopyMode` | `0x1848316fc` | 190 instructions: registry lookup, conditional mode allocation, fields/ports/timer setup, checked membership and publication |
| `CFSetGetValue` selected body | `0x184718000` | 52 instructions: original set/bucket lookup above declared Linear backend |
| `__dispatch_runloop_root_queue_create_4CF` | `0x18554a160` | 72 instructions: queue fields, serial, TLS-derived field, handle initialization and queue-state update |
| `__dispatch_runloop_queue_handle_init` | `0x1855221f4` | 53 instructions: fork-state check, option selection, port construction and handle publication |
| `__dispatch_runloop_root_queue_get_port_4CF` | `0x18552296c` | 15 instructions: vtable/type check and u32 handle load |
| `__dispatch_fork_becomes_unsafe_slow` | `0x185522f20` | Original atomic flag transition and diagnostic branch |
| `_____CFRunLoopCopyMode_block_invoke` | `0x1848329a8` | Six instructions: follow captured byref forwarding record and set mode timer flag to 1 |

Exact symbols establish library routine identity. They do not assign a new
meaning to an unrelated obfuscated FairPlay routine. The original daemon and
application suffixes are compared with the prior checked paths. [MC1,MC8]

## Port acquisition, registration and emission sites

Mach names below are u32 values in private fixtures; they are not observed
native daemon port numbers. Addresses are unslid original cache virtual
addresses. All offsets and extents are bytes. [MC1-MC5]

| Interface / site | Original PC | Arguments / destination | Evidence boundary |
| --- | --- | --- | --- |
| Mode allocation request | `0x184831854` | `mach_port_allocate(task=0x103,right=3,&name)` | Original wrapper executes; trap boundary at `0x180547abc` supplies fresh original-kernel result |
| Mode facility store | `0x184831868` | Store u32 `0x507` at `mode+0x88` | Original store, initially zero destination |
| Dispatch root queue request | `0x184831880` | Label and second argument 0; result stored at `mode+0xa0` | Original queue create/init executes above storage/kernel models |
| Root port construction | `0x185522278` | Task `0x103`, 24-byte options, queue pointer as opaque guard/context, output pointer | Original wrapper executes; trap `0x180547b10` modeled successful output `0x607` |
| Root handle store | `0x185522290` | Eight-byte store at `queue+0x20`; getter returns low u32 | Original store/getter; native guard enforcement unknown |
| Root membership | `0x184831940` | `(task=0x103,member=0x607,set=0x507)` | Declared kernel result; original nonzero check executes |
| Kernel timer request / store | `0x184831948` / `0x184831950` | `mk_timer_create`, modeled name `0x707` stored at `mode+0xac` | Zero result checked before membership |
| Kernel timer membership | `0x184831960` | Member `0x707` into set `0x507` | Declared result; original nonzero check executes |
| Wake-name load / membership | `0x184831968` / `0x184831978` | Load u32 from `runloop+0x50`, modeled name `0x807`, insert into set `0x507` | Wake producer remains outside this increment; zero and result checks are original |
| Mode registry publication | `0x184831988` | Add constructed mode to set at `runloop+0xa68` | Original call with declared collection mutation |
| Later service membership | Original AddSource path | Member `0x303` or `0x403`, same facility `0x507` | Exact original-kernel insertion return oracle |
| Later receive | `0x18475730c` call path | Receive on facility `0x507`; returned local name is service `0x303` or `0x403` | Exact kernel-produced 148-byte message/trailer plus 29 OOL bytes |

These sites request or register facilities; no new outbound FairPlay application
message is observed here. The three auxiliary member effects exist only in the
CF model state, not in the separately replayed kernel membership graph. Their
numeric agreement cannot establish common native objects. [MC2,MC5,MC8]

## Object fields and timer/environment contracts

| Object / offset | Original behavior in tested path | Qualification |
| --- | --- | --- |
| Mode `+0x50` | Immutable-name pointer | String copying is modeled |
| Mode `+0x60,+0x68,+0x80` | Source0 set, source1 set, source dictionary, created by later AddSource | Collection storage/backends modeled |
| Mode `+0x88,+0x98,+0xa0,+0xac` | u32 set name, timer-source pointer, root-queue pointer, u32 kernel-timer name | Original stores above stated lower contracts |
| Mode `+0xa8` | Initial byte 0; timer callback sets 1 | Callback follows copied byref record |
| Mode `+0xb8,+0xc0` | Two u64 `UINT64_MAX` stores | No physical allocation-size inference |
| Runtime allocation arguments | Type 44, extra 184 bytes, final argument 0 | Header/ISA/native allocator effects unexecuted; fixture guard at byte 200 |
| Root queue `+0x40` | Prior serial 22 stored; original global counter becomes 23 | Original file-value counter, private update |
| Root queue `+0x50` | u32 `0x40001` | Raw field value; semantic flags not inferred |
| Root queue `+0x54` | TLS word 0 gives 0; private `0x1501` gives `0x101` | Original bit operations from `TPIDRRO_EL0+0x20`; native QoS meaning unknown |
| Root construct options | `310000000000000000000000000000000000000000000000` | Full 24-byte caller record: 16-byte constant prefix plus zero u64 tail; see extent correction above |
| Fork-state global `0x1ed8999d0` | Original 0 becomes 1; controlled 2 becomes 3 before diagnostic boundary | Original atomic byte operation, no fork performed |
| Root-handle global `0x1ed899b90` | Original code stores byte 1 | Full global memory journal checked |
| Timer parameters call | `0x184831928`: source, u64 -1, u64 -1, raw `0x141` | No time unit assigned to the raw final argument |
| Event handler call | `0x184831914` | Block copy/relocation effects declared |
| Block descriptor `0x1e2330700` | Reserved u64 0, size u64 40 | Original 16 bytes recaptured |
| Byref record | 32 bytes; forwarding at `+8`, mode-flag pointer at `+0x18` | Size 32 encoded in original template `0x18494e130` |
| Callback store | `0x1848329b8`: byte 1 to captured `mode+0xa8` | Original six-instruction body independently replayed |

The event-handler contract copies 40 and 32 bytes into separate private storage
and relocates the block capture and forwarding pointers. Original Block copy
helpers, retain counts, disposal, cancellation and concurrent callback delivery
are not executed. Callback reachability after a modeled copy is established;
its native lifecycle is unknown. [MC3,MC6,MC7]

## Variations and independent validation

| Cases | Checked result | Boundary |
| --- | --- | --- |
| Four service variants | Construct once, publish, register service and consume original kernel return data | Two application pre-pthread frontiers; two run-loop returns with raw value 4 |
| Repeated AddSource | Registry miss then hit; one mode/queue allocation; duplicate source preserved | Original run-loop return |
| Missing mode, create false | NULL; no facility allocation | Original CopyMode return |
| Runtime storage NULL | NULL; no port request | Original CopyMode return |
| Port-set status 4 | No `mode+0x88` store, no root creation | Before original failure routine `0x1848d3ee4` |
| Root membership status 4 | No mode publication | Before `0x1848d3fd0` |
| Timer membership status 4 | Root membership retained; no publication | Before `0x1848d3fe4` |
| Wake membership status 4 | Root/timer memberships retained; no publication | Before `0x1848d3ff8` |
| Kernel timer returns 0 | Root membership retained; no publication | Before `0x1848d400c` |
| Timer callback | Original byte transition 0 to 1 through relocated byref | Original callback return |
| Initial fork flag 2 | Original atomic 2 to 3; no port construct/publication | Before diagnostic path `0x185522f38` |
| TLS word `0x1501` | Original queue `+0x54` becomes `0x101`; consumer suffix unchanged | Original run-loop return |

Failure observations stop before diagnostic routines. They do not establish
native fatal termination or cleanup. Root construct failure, zero wake name,
wrong queue type, mutex failures, nonzero root-create second argument and
concurrency interleavings are captured or identifiable branches but untested.
No all-path coverage claim is made. [MC3-MC8]

The fifteen new compositions independently check 19208 original instruction
visits and 47185920 bytes (45 MiB) of complete final private RAM. Four fresh
kernel replays check 15172 visits and 4194304 bytes (4 MiB), giving 34380 visits
and 51380224 bytes (49 MiB) across both phases. These are aggregate snapshot
extents, not peak resident memory or exhaustive execution coverage. Five altered
records test allocation output, member status, byref forwarding, final facility
and callback store. Source/hash recapture and whole-state replay supplement the
semantic oracles; mutual agreement alone cannot validate lower contracts.
[MC1-MC8]

Source recovery costs O(source bytes + symbol data + cache bytes hashed) time;
replay costs O(image + instruction visits + RAM snapshots + journals) time and
space. Full publication rehash costs O(published bytes + links) time with
O(manifest + largest parsed JSON) space. No numerical uncertainty model is
applicable to exact byte comparisons; unexecuted behaviors remain unknown.

## Bounded continuation

| Impact | Remaining interface / opportunity | Discriminating evidence |
| --- | --- | --- |
| High | Auxiliary ports share a CF set in model state but not original-kernel replay | Execute original root construct, timer and wake producers against a common original namespace/set epoch; compare actual membership graph |
| High | Timer firing and wake/root receive branches remain outside this selected service path | Recover original message formats and original branch conditions for each auxiliary local name; trace timer flag and root drain behavior |
| High | Native daemon-to-kext round trip remains unknown | Correlate successful user-client opening, selector routing and original daemon request/reply evidence with the existing kext reports |
| Medium | Block ownership and mode teardown are unexecuted | Recover original copy/dispose/cancel, source invalidation and port removal/destruction ordering |
| Medium | Registry equality is name-pointer equality in this backend contract | Recover original CFString hash/equality callbacks and compare distinct equal strings |
| Medium | TLS and fork flags change source-visible queue construction | Establish native TSD layout, global initialization and concurrency epoch before assigning priority/ownership meaning |
| Low | Untested diagnostic branches have exact original call sites | Extend finite controls only where they resolve a stated interface question |

## Quality gates

QG1: No normative premise is required; observations concern byte-level behavior.

QG2: MC1-MC8 identify dependent results and falsification probes.

QG3: Mode routine roles, port acquisition/registration sites, data/control flow,
external contracts, environment, ABI and bounded next steps are reported.

QG4: Addresses, widths, offsets, byte extents, exact aggregate sums and algorithm
complexities are explicit; raw timer/TLS values receive no unsupported units.

QG5: Private kernel service membership and modeled auxiliary memberships are
separate; diagnostic stops, finite controls, header/storage and lifecycle gaps
remain explicitly unknown rather than contradicted by completion claims.

QG6: Original bytes/nlist, nine full cache hashes, independent CPU replays,
semantic state/wire oracles and five rejected altered records provide provenance.

QG7: High/medium/low continuation scope is bounded in the table above.

[Preservation seal](triage_evidence/cf_mode_construction_delivery.json) and
[quality record](triage_evidence/cf_mode_construction_quality_gates.json) record
this increment's hashes and gates. The
[investigation status](interface_investigation_status.md) retains the broader
open questions.
