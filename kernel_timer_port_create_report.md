# Original kernel timer creation, receive right and shared-set membership

Original startup and kernel instructions now create the mode's kernel-timer
facility before original service delivery. The startup callback publishes a
dynamic 168-byte `mk_timer` zone; Mach trap -91 creates a timer object, prepares
kernel-message storage, creates receive name `0x707`, retains a separate kernel
send reference and inserts the timer port into set `0x507`. The same private
kernel namespace also contains root `0x607` and the queued service member.
Four original CF callers consume the checked timer-name and membership returns.
[MT1-MT8]

The timer namespace entry contains a receive right. A distinct kernel-held send
reference is associated with the timer object. Creation and callback setup do
not establish arming, expiration or timer-message emission. Wake-port creation,
native allocation/ownership/scheduling and a successful daemon-to-kext
transaction remain unknown. The full interface investigation remains active.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| MT1 | The pinned original kernel/daemon/cache corpus is the selected implementation | Trap binding, startup specification, object fields and composition | Recapture 171 complete kernel functions and 43 cache bodies/25 stubs; reread all cache bodies and hash nine files; attest native image pairing separately |
| MT2 | Declared bootstrap next-slot, registry/zone locks and per-CPU statistics contracts apply | Dynamic timer-zone creation/publication | Independently execute original specification with requested ID65535 under next-slot40 and41; verify original publication store, extent and counter increment; native bootstrap order remains unknown |
| MT3 | Source-produced zone records and zeroed raw timer/kmsg/port/link storage apply | Original object and membership initialization | Freshly replay fixed zones22/23/24, check allocation order/arguments, source-record transfer, all stores and guards; native allocator/backing epochs remain unknown |
| MT4 | Frozen service queue/receiver/task/namespace and free-entry epochs apply | Names, rights, current-task lookup and later service receive | Freshly replay four receiver loans and original namespace operations; verify chain5 ->6 ->7 ->2, type/owner observations and unchanged queued service bytes; native task/space identity remains unknown |
| MT5 | Function-entry harness order joins set/root/timer/service operations in one private CPU | Common namespace/ring and resource state | Check complete CPU/RAM handoffs with only argument-record patches; native SVC dispatch and caller/scheduler ordering remain separate |
| MT6 | Inherited logical PAC, locks/SMR/VM/copy and source/helper contracts apply | Kernel reference/association and receive paths | Independently check all original reads/writes, CPU frames, recomputed new models and final RAM; hardware PAC, native reference lifetime and VM effects remain unknown |
| MT7 | Exact timer-name/member returns can be paired with original CF objects and prior runtime contracts | Original CF mode construction and daemon continuation | Compare return name/status distinction, insertion tuple and complete original paths/buffers/objects; native shared maps/source epochs, wake port and CF ownership remain modeled or unknown |
| MT8 | Startup/constructor/member/receive/application boundaries delimit observation | Prepared callback/message and completion scope | Reject altered publication/context/rights/link/CF records; execute actual arming/expiration/send/teardown before claiming timer delivery or a complete FairPlay transaction |

## Primary source and startup identity

[Source](triage_evidence/kernel_timer_port_create_source.json) recaptures 171
complete kernel bodies /22373 instructions from kernel SHA-256
`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.
The nested CF corpus retains 43 original functions, 25 stubs and 3498
instructions, reread from the original cache; nine full cache hashes are checked.
No new IDA query was required. [MT1]

The original startup catalog entry at `0xfffffe000cbeb088` binds callback
`0xfffffe000c63222c` to the 48-byte specification at `0xfffffe000cbc9498`.
The original name string is `mk_timer`, requested size is 168 bytes, flags are
`0x02000000`, requested identifier is u16 `65535`, and publication address is
`0xfffffe0007e64000`. That publication cell is zero in the original file image.
The catalog does not give a fixed-zone address for this specification. [MT1,MT2]

| Declared next dynamic slot | Original returned zone | Original size field | Publication / next counter |
| --- | --- | --- | --- |
| 40 | `0xfffffe000caed280` | u16 168 at zone+0x34 | Same zone pointer /41 |
| 41 | `0xfffffe000caed340` | u16 168 at zone+0x34 | Same zone pointer /42 |

Original startup instruction `0xfffffe000c63225c` publishes the eight-byte zone
pointer. Both cases retain requested identifier65535 in the original
specification. Observed zone addresses follow array base
`0xfffffe000caeb480 + 192 * selected_slot`; the declared bootstrap counter,
locks and raw statistics storage determine the selected private epoch.
Component startup executions do not attest a common native boot. [MT2,MT3]

## Creation ABI and original routine roles

Mach trap-table entry91 is `mk_timer_create_trap`, signed selector -91, zero
arguments and a port-valued return. Unlike a status-plus-output-pointer API,
this call returns the u32 name directly. The tested return is `0x707`.
Original CF call `0x184831948` reaches user entry `0x180547cfc`, then stores the
name at `mode+0xac` at `0x184831950` and checks zero before membership. [MT1,MT7]

| Original entry/site | Address | Recovered operation |
| --- | --- | --- |
| Timer-create handler | `0xfffffe000bd13314` | Current-thread/task/space lookup, allocations, callback/storage association, port creation and direct name return |
| Current thread load | `0xfffffe000bd13328` | `TPIDR_EL1` supplies the private receiver-thread fixture |
| Dynamic-zone load | `0xfffffe000bd1335c` | Reads the source-produced publication at `0xfffffe0007e64000` |
| Timer raw allocation call | `0xfffffe000bd13368` | Source timer-zone/stats and flags `0x8004`; declared zeroed 168-byte storage |
| Callback association | `0xfffffe000bd133a4` | Stores callback `0xfffffe000bd13480` and self-context at timer+0x68/+0x70 |
| Kmsg raw allocation call | `0xfffffe000bd133cc` | Source fixed zone24/stats; declared zeroed 256-byte storage |
| Port allocation call | `0xfffffe000bd13414` | Existing original allocator `0xfffffe000bccd000`, type word `0x109`, timer context, no namespace send-right insertion |
| Kernel send-reference acquisition | `0xfffffe000bd1342c` | Calls original `0xfffffe000bccfc94` on the created port |
| Timer send-reference store | `0xfffffe000bd1344c` | Stores port pointer at timer+0x98 |
| Direct name return load | `0xfffffe000bd13460` | Loads generated u32 name for return |
| Timer membership | Original Mach -22 path | `(task=0x103,member=0x707,set=0x507)` |
| CF membership call | `0x184831960` | Consumes checked original-kernel status before later mode publication |

Original format-8 trap pointer bytes bind entry91 to the handler. The handler
has 91 captured instructions, send-reference helper has 28, and registered
callback body has 113. Internal callback/helper nlist names are absent; roles
come from original call arguments, fields and executed instructions. No native
trap or timer executes. [MT1,MT4-MT8]

## Object and rights contracts

All offsets/extents are bytes; names/flags are u32, opaque pointers are u64.
Private object addresses are fixtures, not native object correspondences.
[MT3-MT7]

| Object / field | Original result in tested paths | Evidence scope |
| --- | --- | --- |
| Timer at `0x65000c4000`, extent168 | Initialized lock word+8 = `0x11`, state word+0x50 = `0x02000001` | Original stores above raw allocation |
| Timer+0x68/+0x70 | Callback `0xfffffe000bd13480`, self pointer | Logical PAC; no expiration callback invocation |
| Timer+0x98 | Port pointer `0x65000cc000` | Original kernel send-reference acquisition/store |
| Timer+0xa0 | Kmsg pointer `0x65000c8000` | Original association with prepared256-byte storage |
| Namespace entry7+0 | Port pointer | Original namespace publication |
| Namespace entry7+8 | `0x04020000` | Receive-right bit set, no namespace send right/uref in this entry |
| Timer port+0 | Header word `0x209` | Original initializer/type path |
| Timer port+8 | Timer object pointer | Original object association |
| Timer port+0x34 | Local name `0x707` | Original generated-name association |
| Timer port+4 | Reference word 1 before helper, 2 after | Original atomic increment; native ownership/lifetime unknown |
| Timer port+0x84/+0x88 | Both 0 before helper, both 1 after | Separate kernel-held send bookkeeping, not a namespace send right |
| Timer port queue | Head0, count0, default limit5 | Empty member before service receive |
| Prepared kmsg | u16 +0x30 =0, byte +0x32 =1, masked byte +0x3f =0 under zero-storage premise | No completed Mach message or emitted wire inferred |

The zero-filled 256-byte raw fixture ends with only byte+0x32 equal to1 in
these cases. Its untouched zeros are allocation premises, not evidence of native
message/header defaults. No message ID, emitted destination or timer wire format
is established by creation. [MT3,MT8]

## Shared namespace and data/control flow

```text
original startup spec (ID65535, size168)
  -> original dynamic zone creation -> published zone pointer
                                        |
original set/root construction          v
  -> set0x507 + root0x607          original mk_timer_create
                                        |
                              timer object + prepared kmsg
                                        |
                              receive name0x707
                              kernel-held send reference
                                        |
             original root/timer membership in set0x507
                 inactive ring: root link <-> timer link
                                        |
             original service membership -> ready service link
                                        |
             original set receive -> service local name0x303/0x403
                                        |
             exact kernel returns -> original CF -> daemon suffix
```

The declared namespace free chain is 5 ->6 ->7 ->2, retaining entry2 for later
reply publication. Original code publishes set/root/timer entries; service
membership uses a third distinct 48-byte link. Root and timer links have their
ready bits clear and form the two-member inactive ring. The service link is in
the ready ring and is selected for delivery. Post-dequeue readiness retains the
previously established lazy-cleanup boundary. [MT3-MT6]

Legacy inherited fields `final_link48_hex` and `final_unused_link48_hex` hold
root and timer links here. The latter is not unused. The new
`final_service_link48_hex` holds the third link; complete link/object bytes and
all four new raw-storage guards are checked. [MT3,MT5]

Four CF compositions replace both the timer-name model and timer-membership
status model with original-kernel observations. Root construction/membership,
set allocation, service membership and receive retain their checked kernel
contracts. CF mode fields, original instruction sequences, receive/OOL buffers,
queue bytes, collection state and boundaries match the root-construction
baseline; application records match for the two application-boundary cases.
Wake name `0x807` and its membership remain a CF model outside the kernel graph.
[MT7,MT8]

The [control-dispatch report](cf_control_port_dispatch_report.md) separately
establishes receive-side timer-name routing with synthetic control packets.
This increment establishes creation/membership and does not replace those
synthetic packets with actual timer expiration output. [MT7,MT8]

## Independent validation and boundaries

[Profiles](triage_evidence/kernel_timer_port_create_profiles.json),
[independent checks](triage_evidence/kernel_timer_port_create_checks.json) and
[independent replay](triage_evidence/replay_kernel_timer_port_create.py) retain:

| Phase | Cases | Original visits | Complete final private snapshots |
| --- | --- | --- | --- |
| Dynamic timer startup, slots40/41 | 2 | 340 | 2097152 bytes /2 MiB |
| Set/root/timer/service kernel paths | 4 | 23380 | 4194304 bytes /4 MiB |
| Original CF/daemon consumers | 4 | 12356 | 12582912 bytes /12 MiB |
| Fresh receiver loans | 4 | 216 | 4194304 bytes /4 MiB |
| Fresh fixed zones22/23/24 | 3 | 618 | 3145728 bytes /3 MiB |
| Aggregate | 17 | 36910 | 26214400 bytes /25 MiB |

Each kernel case checks exact service wire/OOL observations against the prior
root-port cases. No root or timer control message is enqueued. Two CF cases
stop before the original application pthread-identity boundary; two return from
the original run loop with raw value4. Neither result proves successful
FairPlay processing. Snapshot totals are not peak memory or exhaustive path
coverage. [MT1-MT8]

The independent replay imports no new probe. It recomputes dynamic-zone lower
contracts, timer/raw-link allocations, function-entry arguments, name/status
pairing and model effects; executes original bytes in fresh CPUs; and checks
all relevant CPU, read/write, object, namespace, ring, service-buffer and final
RAM observations. Six altered-record controls are rejected: dynamic publication,
timer callback context, timer namespace rights, ready service link, CF timer name
and CF timer-membership tuple. [MT1-MT8]

The registered callback at `0xfffffe000bd13480` is captured completely but is
not invoked. Its call at `0xfffffe000bd13524` targets `0xfffffe000bcf5754`;
this is a static continuation site for further investigation, not observed
message emission. Timer arming/deadlines, clock advancement, expiration,
callback concurrency, send return, cleanup and resource lifetime remain unknown.
[MT8]

For the fixed source corpus, instruction/body lookup extents are constants.
Recovery costs O(image + source + symbol data + cache bytes hashed); replay
costs O(image + visits + journals + snapshots) time and space. Publication
rehashing costs O(published bytes + links) time with O(manifest + largest parsed
JSON) space. Comparisons are exact. No native timing unit, statistical error
bound or hardware-authentication claim is inferred.

## Bounded architectural continuation

| Impact | Finding / remaining interface | Discriminating next evidence |
| --- | --- | --- |
| High | Creation returns a receive name while the kernel retains a send reference | Follow expiration/send and teardown to establish how those references and rights are consumed |
| High | Timer control messages still lack original producer bytes | Execute original arming/expiration and compare actual output with the existing receive-side routing evidence |
| High | Wake port remains modeled outside the common kernel graph | Recover its original producer, membership and actual wake send |
| High | Successful daemon-to-kext transaction remains unknown | Correlate user-client opening, selector routing, daemon exchange and original application outputs |
| Medium | Dynamic-zone publication is required before constructor entry | Establish native boot/counter/allocator epoch before identifying actual native objects with these component records |
| Medium | Timer callback pointer/body and prepared kmsg are now pinned | Follow callback call0xfffffe000bd13524 and the original send target; distinguish static target identity from emitted wire |
| Medium | Namespace entry omits a send right despite kernel send bookkeeping | Recover rights transfer/destruction and reference ownership without inferring them from a single counter |
| Low | Failure returns, resource pressure and alternate timer state are untested here | Extend finite contract cases when needed to resolve a stated interface question |

## Quality gates

QG1: No normative premise is required; claims concern original byte behavior.

QG2: MT1-MT8 identify assumptions, dependent results and falsification probes.

QG3: Startup/constructor routine roles, trap/name ABI, object/reference fields,
membership, service data flow, environmental prerequisites and next steps are covered.

QG4: Exact byte widths, offsets, slot calculations, counts, aggregate sums and
fixed-corpus algorithm costs are stated; unsupported timer units are absent.

QG5: Receive namespace rights, kernel-held send reference, prepared kmsg storage,
actual emission and native ownership remain distinct; wake/expiry gaps are explicit.

QG6: Original specification/trap/function bytes, cache hashes, source-produced
zone transfers, independent CPU/state oracles and six altered controls provide provenance.

QG7: High/medium/low continuation scope is bounded in the table above.

[Preservation seal](triage_evidence/kernel_timer_port_create_delivery.json),
[quality record](triage_evidence/kernel_timer_port_create_quality_gates.json)
and [investigation status](interface_investigation_status.md) retain publication
checks and the active broader goal.
