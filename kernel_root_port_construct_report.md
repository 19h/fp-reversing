# Original dispatch-root port construction and common kernel namespace

Original kernel instructions now construct the dispatch-root port, publish its
receive/send rights, store the queue pointer as guard context, set guarding bits
and insert the port into the same original port set used for service delivery.
The private generated names are set `0x507` and root `0x607`. Four original CF
callers consume the checked construction and root-membership returns before
service registration and daemon dispatch. [RP1-RP8]

The complete port-options ABI is 24 bytes. The earlier mode report recorded
only its 16-byte constant prefix; original caller instruction `0x18552221c`
zeros the final eight bytes, and the kernel handler copies all 24. The earlier
report's options extent is corrected and its historical prefix-only evidence
remains identifiable. Native address-space identity, allocator/ownership,
auxiliary-message production and a successful daemon-to-kext transaction remain
unknown. The full interface investigation remains active.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| RP1 | Pinned original kernel/daemon/cache corpus is the selected implementation | Addresses, trap binding, fields and composition | Recapture 168 complete kernel functions, 43 cache bodies/25 stubs and nine cache-file hashes; attest native loaded-image pairing separately |
| RP2 | Frozen queued-service/receiver and declared namespace/free-entry epochs apply | Generated set/root names, rights and later service delivery | Freshly replay four receiver loans; check original queued bytes, free chain 5 -> 6 -> 2, task conversion and all namespace mutations; native task/space epoch remains unknown |
| RP3 | Original source-produced port-zone22 and set-zone23 records, raw 144/56-byte storage and link storage apply | Original port/set initialization and membership | Freshly replay both zone records, check 144-byte port extent and guards, exact allocation arguments and all original stores; component records do not attest common native bootstrap/allocator epochs |
| RP4 | Declared task-name conversion, exact options user-copy and inherited locks/SMR/VM/PAC contracts apply | Kernel construction, namespace access and service receive | Recompute helper arguments/bytes/statuses, test copy-in failure, compare complete CPU/RAM and independent original reads/writes; native mapping validation, task references and hardware PAC remain unknown |
| RP5 | Harness orders original set allocation, root construction/root membership and service membership/receive at function entries | One private kernel namespace across all operations | Check full CPU/RAM handoffs and limited argument-record patches; native SVC dispatch and original caller/scheduler order remain separate |
| RP6 | Original CF root call and kernel result can be composed by exact options/context/name/status contracts | CF queue handle and original daemon consumer | Check all 24 options bytes, queue context, kernel output name, root/service insertion tuples and unchanged CF suffix/buffers/objects; equal numeric pointers do not attest shared native maps |
| RP7 | Prior CF storage, string, collection, mutex, timer/wake, Block and no-work/clock contracts apply | Remaining mode initialization and run-loop continuation | Independently replay four consumers and full final private memory; timer/wake kernel producers/memberships, lifecycle and concurrent work remain modeled or unknown |
| RP8 | Finite normal/non-strict/copy-in-error paths and return/application boundaries delimit evidence | Guard-bit variation, error mapping and completion scope | Reject altered context/rights/link/options/name records; continue native guard enforcement, teardown and successful application/reply paths before claiming a complete transaction |

## Primary sources and correction provenance

[Source capture](triage_evidence/kernel_root_port_construct_source.json)
recaptures 168 complete kernel functions /22141 instructions from kernel
SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.
The original trap-table entry 24 resolves through its format-8 pointer to
`0xfffffe000bcdbda4`; signed user selector is -24. Exact trap name is
`_kernelrpc_mach_port_construct_trap`. Internal routine roles below are derived
from original instructions; absent nlist names remain absent. [RP1]

The nested CF corpus contains 43 original cache functions, 25 stubs and 3498
instructions, with nine full cache-file hashes. Cache UUID is
`2bd06591-e751-3e84-963f-b08dab6af23a`. The validator independently rereads each
function/stub from the original cache and rehashes the full files. No new IDA
query was required. [RP1,RP6,RP7]

The `root_caller_options` record reconstructs the complete 24 bytes from original
CF write journals before the construct call. Only original producer sites
`0x18552221c` (zero u64) and `0x18552222c` (store q0, journaled as two u64 writes)
cover the range. The bytes are `31` followed by 23 zero bytes. Original kernel
instruction `0xfffffe000bcdbde4` supplies copy length `0x18`. [RP1,RP4,RP6]

The local SDK primary declaration is
[/Library/Developer/CommandLineTools/SDKs/MacOSX27.0.sdk/usr/include/mach/port.h](/Library/Developer/CommandLineTools/SDKs/MacOSX27.0.sdk/usr/include/mach/port.h).
Its hash, compiler command and C assertions are retained in
[independent checks](triage_evidence/kernel_root_port_construct_checks.json).
Clang targeting arm64 confirms size 24 and offsets flags=0, mpl=4, reserved=8.
SDK equivalence to the kernel revision is unknown; original transfer widths and
bit operations provide independent implementation evidence. [RP1,RP4]

| Selected option | Value | SDK nomenclature | Original implementation evidence |
| --- | --- | --- | --- |
| Context guarding | `0x01` | `MPO_CONTEXT_AS_GUARD` | Bit 0 selects guard helper with queue pointer as context |
| Insert send right | `0x10` | `MPO_INSERT_SEND_RIGHT` | Bit 4 becomes allocation send-right argument |
| Strict guarding | `0x20` | `MPO_STRICT` | Bit 5 becomes guard-helper strict argument |
| Caller combination | `0x31` | Above three bits | Full 24-byte caller record independently reconstructed |

The [mode report](cf_mode_construction_report.md) now identifies the complete
24-byte extent and links this correction. Its immutable historical model field
`original_options16_hex` contains the prefix only. No historical execution
record is rewritten to pretend it checked the omitted tail. [RP1,RP6]

## Original interfaces and widths

Offsets/extents below are bytes. Mach names/flags are u32; kernel handler slots
are eight bytes apart. User addresses and opaque context values are 64 bits.
[RP1,RP4-RP6]

| Original entry/site | Address | Recovered operation |
| --- | --- | --- |
| CF root construction call | `0x185522278` | Task `0x103`, 24-byte options pointer, queue pointer `0x65000b6000`, output-name pointer |
| Original user wrapper / trap boundary | `0x180548e9c` / `0x180547b10` | Wrapper executes; separate kernel replay supplies checked return contract |
| Kernel trap handler | `0xfffffe000bcdbda4` | Task u32 at args+0, options address at +8, context at +16, output address at +24 |
| Options copy call | `0xfffffe000bcdbde8` | Copy exactly 24 bytes into kernel stack; declared user-copy primitive |
| Construct core | `0xfffffe000bce00b8` | Validates/selects options, allocates/publishes port and applies context guarding |
| Send-right selection | `0xfffffe000bce0414` | Extract bit 4 into W3 for lower allocator |
| Port allocation | `0xfffffe000bccd000` | Raw port-zone storage, namespace entry, initialization and rights publication |
| Port field initializer | `0xfffffe000bccd170` | Header/queue/space/name and selected send bookkeeping initialization |
| Namespace rights publication | `0xfffffe000bccb548` | Publishes object pointer, receive/send type bits and urefs in entry |
| Guard call | `0xfffffe000bce04e4` | Generated name, original port, queue context and strict-bit argument |
| Guard helper | `0xfffffe000bce0624` | Stores context at port+0x78; sets guard bit 0x400 and selected strict bit 0x800 |
| Name output copy | `0xfffffe000bcdbe44` | Copies exactly four bytes through inherited user-copy contract |
| Root membership | Original Mach -22 path | Task `0x103`, root `0x607`, set `0x507`; original lookup/link code executes |
| Service membership/receive | Original Mach -22 and receive frontend | Same set; original queued service member is selected and delivered |

No SVC, native trap dispatcher, native allocator or native Mach IPC executes.
Original kernel functions run in private Unicorn CPUs. Original CF/kernel
functions are joined by checked scalar/status/byte contracts across separate
CPUs; native task/map/source epoch coupling is unknown. [RP2-RP7]

## Common namespace, context and membership state

```text
source zone23 + raw set storage     source zone22 + raw port storage
                 |                                  |
original set allocation           original port construction
                 |                                  |
       entry5 / name0x507           entry6 / name0x607
                 |                  receive+send rights
                 |                  context = queue pointer
                 |                  guard + strict bits
                 +--------------------------+
                 | original root membership |
                 +--------------------------+
                   inactive root queue link
                 |
                 +-- original service membership
                       ready service link -> original set receive
                                              |
                                      service local name0x303/0x403
```

The declared free-entry chain is 5 -> 6 -> 2, retaining entry2 for later reply
publication. Original code generates set name `0x507` and root name `0x607`.
The namespace generation bits are part of the original entry encoding; index6
is not a claim that generation equals6. [RP2,RP5]

| Checked field | Normal result | Qualification |
| --- | --- | --- |
| Root entry6 object pointer | Private 144-byte port at `0x65000be000` | Raw backing storage is declared |
| Root entry6 rights/urefs word at +8 | `0x04030001` | Includes receive/send bits and one send uref in tested encoding |
| Root header at +0 | u32 `0x101` | Original initializer value |
| Root reference word at +4 | u32 1 | Native ownership/reference lifetime remains unknown |
| Root local name at +0x34 | u32 `0x607` | Original name-to-port association |
| Root context at +0x78 | u64 `0x65000b6000` | Queue pointer value stored as opaque context; no kernel dereference of that user queue is inferred |
| Root flag word at +0x10 | Guard mask `0xc00` under options `0x31` | Stored guard and strict bits; enforcement operations are unexecuted |
| Root send bookkeeping at +0x84/+0x88 | Two u32 values 1 | Original inserted-send path stores |
| Root queue head/count/limit | +0x28=0, u16 +0x38=0, u16 +0x3a=5 | Empty queue, original default limit in tested path |
| Root link first word | `pset+0x10`, ready bit clear | Original inactive membership link |
| Set inactive / ready heads | Root link+24 / service link+24 | Distinct links in one original private set |
| Returned service local name | `0x303` or `0x403` | Root name and set name do not replace the delivered member name |

The root member remains empty while the service member carries the queued
request. Original set selection delivers the service message and preserves
its complete 8192-byte receive and 16384-byte OOL observations. The service
ready link is subject to the previously established lazy-ready cleanup after
dequeue. No root control message is created or delivered here. [RP2-RP5]

## Finite controls and CF composition

| Cases | Input / variation | Original visits | Checked result |
| --- | --- | --- | --- |
| Kernel 0-3 | Original 24-byte caller options, four queued service variants | 4867 each | Root constructed/inserted, service delivered |
| Kernel 4 | Valid non-strict flags `0x11` | 4867 | Same root object bytes except strict flag bit `0x800` is clear |
| Kernel 5 | Declared options copy-in failure, helper status 1 | 370 | Original handler returns raw 10 before raw port allocation; name output unchanged |
| CF 0-1 | Original mode construction above kernel return pairing | 4390 each | Original application pre-pthread boundary |
| CF 2-3 | Same pairing, alternate service variants | 1788 each | Original run-loop return, raw value 4 |

The non-strict control changes only options bit `0x20`; complete final root
object comparison isolates its effect to port flag `0x800`. This establishes
the selected stored-bit calculation, not guarded-port enforcement. The copy-in
failure is a declared helper outcome; native mapping failure feasibility and
probability are unknown. [RP4,RP8]

Four CF cases now consume exact original-kernel root construction/name and root
membership status observations. Their original instruction sequences, complete
receive/OOL buffers, mode/queue bytes, collection state and observed boundaries
match the earlier mode-construction cases. Application records also match for
the two application-boundary cases. Timer/wake creation/membership and remaining
CF runtime contracts remain modeled. [RP6,RP7]

Legacy inherited fields `final_link48_hex` and `final_unused_link48_hex` now
hold root and service links respectively; the latter field name does not mean
the second link is unused in these new cases. Every final link byte and guard
is checked against fresh execution. [RP3,RP5]

[Profiles](triage_evidence/kernel_root_port_construct_profiles.json) and
[independent replay](triage_evidence/replay_kernel_root_port_construct.py) retain
six kernel and four CF cases. Independent source recapture and replay check
24705 kernel visits plus 12356 CF visits, totaling 37061 new-phase visits and
18874368 bytes (18 MiB) of final private snapshots. Four fresh receiver loans
add 216 visits/4 MiB; two fresh zone paths add 394 visits/2 MiB. Aggregate
validation is 37671 visits and 25165824 bytes (24 MiB). These are snapshot sums,
not peak resident memory or exhaustive path coverage. [RP1-RP8]

The independent replayer imports no new probe. It recomputes options copy/raw
allocation effects and function-entry argument patches; checks original CPU,
read/write, namespace, link, wire and whole-RAM observations; and rejects five
altered records covering context, namespace rights, inactive link, complete CF
options and CF root-name patch. No original input/IDB/memory-store mutation or
native target execution occurs. [RP1-RP8]

For the fixed source corpus, instruction/body lookup extents are constants.
Recovery costs O(image + source + symbol data + cache bytes hashed) time;
replay costs O(image + visits + journals + snapshots) time and space. Full
publication hashing costs O(published bytes + links) time with O(manifest +
largest parsed JSON) space. Exact byte comparisons require no statistical
error bound; native time, concurrency and ownership remain outside these sums.

## Bounded continuation

| Impact | Remaining interface / pattern | Discriminating next evidence |
| --- | --- | --- |
| High | Root construction/membership now shares a kernel namespace with service delivery | Recover the original root wake/message producer and its actual wire format/delivery through this graph |
| High | Queue pointer acts as opaque guard context | Follow original guard comparisons, teardown and reference/port destruction ordering before claiming lifetime enforcement |
| High | Kernel-timer and run-loop wake producers remain modeled | Recover those original constructors/memberships in the same namespace and pair their real return contracts |
| High | Successful daemon-to-kext transaction remains unknown | Correlate user-client opening, selector routing, kernel/daemon exchange and original application outputs |
| Medium | Original callback delivery remains separated from empty root drain | Recover nonempty dispatch work-item/Block execution and timer-flag ordering |
| Medium | Full option extent exceeded earlier recorded prefix | Audit other pointer-to-struct contracts against original kernel copy lengths and caller initialization spans |
| Medium | Zone records are source-produced components from separate startup cases | Establish a common native bootstrap/allocator/task epoch before asserting native object correspondence |
| Low | Other port types, queue-limit options and native fault returns are untested here | Extend finite valid contract cases where they resolve a specific interface question |

## Quality gates

QG1: No normative premise is required; claims concern original byte behavior.

QG2: RP1-RP8 state assumptions, dependent results and falsification probes.

QG3: Kernel/CF routine roles, trap and argument ABI, construction/membership,
context/guard fields, service data flow, external contracts and next steps are covered.

QG4: Exact widths, offsets, flags, byte extents, aggregate sums, compiler assertions
and fixed-corpus algorithm costs are reproducible; unsupported native units are absent.

QG5: The 16-byte-prefix/24-byte-structure distinction is corrected explicitly;
stored guard state, enforcement, component epochs and native completion are separate.

QG6: Original kernel/cache bytes and trap pointer, caller write reconstruction,
SDK hash/compiler assertions, independent CPU/state oracles and negative controls
provide primary provenance.

QG7: High/medium/low continuation scope is bounded in the table above.

[Preservation seal](triage_evidence/kernel_root_port_construct_delivery.json),
[quality record](triage_evidence/kernel_root_port_construct_quality_gates.json)
and [investigation status](interface_investigation_status.md) retain publication
checks and the active broader goal.
