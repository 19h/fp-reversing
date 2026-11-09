# Registered-port consumers, bootstrap initialization and FairPlay forwarding

The captured cache joins spawn-time registered cells to fixed-three-port lookup, selected libxpc initialization consumers and an exported atfork preparation routine. Ordinary libxpc initialization retrieves task bootstrap selector 4 instead. The captured FairPlay image lacks the three role-marker sections and has no declared `mach_ports_lookup` or `mach_ports_register` import; its existing obfuscated service helper does load the imported `bootstrap_port` before check-in. This establishes a conditional bootstrap-data path, not the daemon's effective native initialization branch or port identity [RC1-RC5]. [Original capture](triage_evidence/registered_port_consumers_source.json), [checks](triage_evidence/registered_port_consumers_checks.json).

This extends the [spawn port-action contracts](spawn_port_actions_report.md), [bootstrap handoff](bootstrap_checkin_handoff_report.md) and [daemon registration](daemon_registration_report.md). The [notification/host-publication shared cell](spawn_port_actions_report.md) remains a static correspondence; the retrieved names and their rights can change across spawn, initialization and fork epochs.

## Identities and evidence scope

Cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. Kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. FairPlay arm64e SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. All addresses are preferred static addresses; no native loaded-image pairing is established [RC1].

Twenty-seven complete bodies contain 2671 instructions / 10684 B: eighteen cached and nine kernel bodies. Two additional daemon fragments contain 44 B. The capture retains original library UUIDs, exports/nlist entries, used cache-file hashes, eight authenticated stub bindings, four data-pointer bindings, three MIG records, primary SDK/tool hashes, 243 independently compared daemon imports and 29 independently compared sections. Private labels without original nlist names remain analytical.

```text
launchd spawn actions -> task registered cells[0..2]
                            |
                            v
registered lookup -> three send-pointer copies -> reply descriptors
  -> user name array -> selected libxpc branch -> runtime fields

task bootstrap selector 4 -> separate special-port getter -> runtime bootstrap
  -> global bootstrap_port -> FairPlay biased import/cancellation -> check-in
  -> named bootstrap-pipe helper -> reference request + pipe publication
  -> exported atfork preparation -> one-name registration -> registered cells

Each edge requires its recorded branch, image, namespace and ownership epoch.
```

## Initializer registration and selection inputs

| Original role | Address | Selected contract |
|---|---|---|
| libSystem initializer, original `_libSystem_initializer` | `0x2cbbed264` | Registered by the original 4 B `__init_offsets` section |
| Libkernel initializer | `0x18054d9f0` | Runtime callbacks, task/Mach initialization and XBS/chroot state producer |
| Libxpc initializer | `0x184b6c360` | Role/configuration inputs, runtime record, bootstrap/registered consumers |
| `_getsectbyname` / `_getsectbynamefromheader_64` | `0x2cdb1f93c` / `0x2cdb1f97c` | Named section lookup using the selected executable-header source |
| `__NSGetMachExecuteHeader` | `0x1805a6020` | Load the initialized-header cell at `0x1ed84eda0` |

LibSystem's original initializer-offset word is `0x1264`, relative to its image base. On the selected normal path, its call at `0x2cbbed2ac` binds to libkernel initialization before the call at `0x2cbbed360` binds to libxpc initialization. Both authenticated shared-stub chains are verified. This is a registered initializer and conditional call ordering, not evidence of native invocation [RC1,RC2].

Libxpc tests named `__TEXT` sections `__launchd`, `__xpcproxy`, `__launchctl` and `__libxpcunittest`, and reads configuration including `XPC_FLAGS`, `XPC_NULL_BOOTSTRAP` and `XPC_SERVICES_UNAVAILABLE`. Its numeric-parser call receives base 16 for `XPC_FLAGS`; selected code stores the result in the runtime record. Complete parser/environment policy and effective input values remain dependencies. A launchctl marker is recorded separately; its presence alone does not select registered-port lookup.

The selected runtime record is obtained through `__os_alloc_once_table` and an allocation frontier requesting 216 B. Fields used here are analytical partial fields: role bytes+0..+4, flags word+8, primary name+0x10, secondary name+0x14, bootstrap pipe+0x18 and a separate wrapper+0x20. These are not canonical private structure declarations [RC2].

| Initializer branch predicate | Selected root-port behavior | Original sites |
|---|---|---|
| Role byte0 bit0 or unavailable byte4 bit0 set | Skip the selected bootstrap-initialization block | `0x184b6c8d0` through `0x184b6c8dc` |
| Xpcproxy byte1 ==1 | Lookup registered names; require nonzero count and admitted first name; store names0/1 at runtime+0x10/+0x14 when present | Lookup `0x184b6c918`; stores `0x184b6c934` / `0x184b6c94c` |
| Mode byte3 ==1 | Retrieve task bootstrap selector 4; flags bit 2 additionally selects lookup of registered name 0 into a separate wrapper | Bootstrap `0x184b6c9bc`; lookup `0x184b6ca00` |
| Remaining selected branch | Retrieve task bootstrap selector 4 and publish it to the bootstrap global | Getter `0x184b6caac`; global store `0x184b6cac0` |

The xpcproxy branch conditionally publishes its primary name to the bootstrap global when flags bit 8 is set. Its port-name test accepts the full u32 domain except 0 and UINT32_MAX. The mode branch's extra registered-name wrapper is separate from its bootstrap getter. No selected initializer consumer here reads registered name 2. Other library code and later epochs remain outside that statement [RC2,RC4].

Libxpc data-pointer chains bind task-self to `0x1ed83e960`, the bootstrap global to `0x1ed83e95c`, the once table to `0x1ed83e968` and `__os_xbs_chrooted` to `0x1eb065e20`. File-default zero cells are retained as file evidence, never native values. Libkernel's XBS input names include `XBS_IS_CHROOTED` and `/AppleInternal/XBS/.isChrooted`; its selected inputs and path-check result can set the compatibility byte. Current runtime initialization remains unknown.

## Registered lookup/register and compatibility contracts

| Cached original routine | Address | Selected behavior |
|---|---|---|
| `_mach_ports_lookup` | `0x180553a14` | Request 12 B via allocation helper; use fixed-three or compatibility adapter; publish array/count on success |
| `__kernelrpc_mach_ports_lookup3` | `0x180573710` | RPC3404; strict fixed-three descriptor validation and three u32 outputs |
| Original `_mach_ports_lookup_legacy` | `0x18055cec0` | Same RPC ID; adapt selected one-OOL-descriptor or inline-three reply representation |
| `_mach_ports_register` | `0x18054f880` | Reject count >3; pad unused name slots with zero; call fixed-three registration |
| `__kernelrpc_mach_ports_register3` | `0x1805735e4` | RPC3403; three COPY_SEND19 descriptors |
| Original `_mach_ports_register_legacy` | `0x18055cdd4` | Selected OOL-array compatibility request representation |

For the normal lookup path, success publishes an array pointer and count 3. Allocation and error deallocation requests use the incoming task argument; the selected libxpc calls supply its imported task-self name. Actual allocation placement, memory validity, copyout, error cleanup and ownership remain dependencies. The returned 12 B name array is distinct from the Mach reply's descriptor storage [RC3,RC4].

Lookup selects the legacy adapter when the compatibility byte equals1. Registration first attempts fixed-three RPC3403; only status -304 (`MIG_BAD_ARGUMENTS`) together with compatibility bit0 selects its legacy tail. This differs from `MIG_BAD_ID` (-303). The legacy routines are captured compatibility code, not proof that the captured kernel accepts their alternative representation or that any native call selected them.

| Interface / direction | User request | User success reply | Kernel internal request / reply | Client receive capacity |
|---|---:|---:|---:|---:|
| Fixed-three register3403, caller -> task service | 64 B; three port descriptors | 36 B simple status | 84 /44 B | 44 B |
| Fixed-three lookup3404, caller -> task service | 24 B simple | 64 B; three port descriptors | 32 /84 B | 72 B |
| Task bootstrap getter3409 | 36 B; selector scalar | 40 B; one port descriptor | 44 /52 B | 48 B |
| SDK legacy array types | Register request 56 B | Lookup reply 56 B | Captured modern stubs require their separate fixed-three geometry | Not inferred from these SDK types |

The fixed-three client header uses destination COPY_SEND19 and a reply-port role. Lookup success requires reply ID3504, complex state, descriptor count 3, size 64 B and MOVE_SEND17/type0 port descriptors. The kernel lookup builder emits internal size 84 B with three signed pointer descriptors. Header widening contributes 8 B and three descriptor widenings contribute 12 B: total 20 B. Receive capacities and trailer allowance are separate from message sizes. These are source/SDK framing contracts, not observed byte continuity or native delivery [RC3].

| Message-helper call frontier | Caller site | Selected request ID |
|---|---|---:|
| Fixed-three registration | `0x180573668` | 3403 |
| Fixed-three lookup | `0x18057378c` | 3404 |
| Bootstrap special-port getter | `0x180548230` | 3409 |
| Compatibility registration | `0x18055ce68` | 3403 |
| Compatibility lookup | `0x18055cf40` | 3404 |

All five call the captured common helper at `0x18055a894`. On the kernel reply side, lookup pointer-descriptor stores occur at `0xfffffe000bd9734c`, `0xfffffe000bd97364` and `0xfffffe000bd9737c`; bootstrap's single-pointer store occurs at `0xfffffe000bd96f10`. These are conditional call and reply-assembly locations. Subsequent generic reply sending is separately covered by the [reply-send report](kernel_reply_send_report.md); no native message emission or receipt is observed here.

## Kernel cells, copied pointers and runtime consumers

| Analytical kernel role | Original address | Selected connection |
|---|---|---|
| RPC3403 server stub | `0xfffffe000bd973ac` | Three internal port descriptors; call the same registered-store routine used by spawn |
| Registered store | `0xfffffe000bcfa5fc` | Task-relative+0x2f8/+0x300/+0x308, with separate old-pointer release |
| RPC3404 server stub | `0xfffffe000bd97250` | Task conversion, three output pointers, internal descriptor publication |
| Registered lookup | `0xfffffe000bcfa80c` | Read the same three cells under state/lock/PAC gates |
| Selected send-copy helper | `0xfffffe000bccffa4` | Qualified port+0x88 increment and object-reference increment; sentinel/error branches retained |
| RPC3409 server stub | `0xfffffe000bd96e7c` | Separate special-port request and one descriptor reply |
| Special-port front / core | `0xfffffe000bcf9eec` / `0xfffffe000bcf9750` | Caller/task conversion and policy; selected selector 4 reads task-relative+0x2d8 |

The registered getter reads cells in order0,1,2, passes each selected value through the send-copy helper, and publishes corresponding output pointers. Its task-state bit+0x6c8 bit5 and lock/PAC paths remain admission dependencies. The helper's role label is analytical: its captured nlist has no recovered original name. Its selected counter/reference effects establish a local copy frontier, not native reference balance [RC3,RC4].

RPC3404 turns the returned pointers into three internal MOVE_SEND17 descriptors, sets complex state/count 3 and size 84 B. Actual pointer-to-name copyout and namespace correspondence are lower dependencies. The same registered-store address in spawn preparation and RPC3403 establishes a common selected backend, without proving that their invocations share one task epoch.

Original named `__xpc_create_bootstrap_pipe` at `0x184b6ce64` loads runtime+0x10, calls `mach_port_mod_refs(task_self,name,MACH_PORT_RIGHT_SEND,1)`, then calls original named `__xpc_pipe_create` at `0x184b880b8` with the name and selected flag 4. It stores the returned pointer at runtime+0x18. The reference-call status is not tested by that selected sequence before pipe creation. This establishes arguments and publication intent, not successful reference acquisition, queue identity or pipe lifetime [RC4].

Original exported `_xpc_atfork_prepare` at `0x184b85a84` has a separate selected path: obtain runtime state, skip its registration branch when role byte0 bit0 is set, copy runtime+0x10 to a local u32 cell, and call `_mach_ports_register(task_self,&name,1)` at `0x184b85ad0`. Unused fixed-three slots are zero-filled by the wrapper. Actual atfork callback registration, fork execution, inheritance and child cleanup remain unknown. The call demonstrates a later stash producer; it does not establish that spawn's original notification/registered values persist until fork.

## FairPlay applicability and bootstrap forwarding

The original thin image contains29 sections and243 chained import records. Independent `otool -l` and `dyld_info -imports` output agrees with those inventories. It contains no `__TEXT,__launchd`, `__TEXT,__xpcproxy` or `__TEXT,__launchctl` section and no declared `_mach_ports_lookup` / `_mach_ports_register` import. These are bounded inventory statements; library calls, dynamic resolution and other images remain outside them [RC1,RC2,RC5].

The current plist remains SHA-256 `ca21543400f3ead9e96d2434f968184b6acd2e1e3de57322ca3da663831eae3c`. Its declared environment contains `DYLD_PAGEIN_LINKING=0`, without `XPC_FLAGS`, `XPC_NULL_BOOTSTRAP`, `XPC_SERVICES_UNAVAILABLE` or XBS inputs. Effective environment, overrides, runtime flags, selected main-header pointer and actual executable slice remain unknown. File declarations and absent sections do not establish the native default branch.

The daemon's selected bootstrap data binding is source slot `0x1010a3278`, import ordinal 19, symbol `_bootstrap_port`, library `/usr/lib/libSystem.B.dylib`, import addend `0x7da61013`, pointer addend 0. Its exhaustive 256-input bank gives constant 0x87, then index 0x323 from additive 0x29c and pool `0x1010a1960`. The original raw slot and all bank bytes are reread. LibSystem's original reexport commands include libsystem_kernel; the captured libkernel bootstrap export and libxpc data-pointer chain both identify cell `0x1ed83e95c`. Runtime interposition and matching loaded-image identity remain RC1 dependencies.

At daemon `0x1004402cc` / `0x1004402d0`, the instructions construct adjustment `0xffffffff8259efed`; the subsequent ADD cancels the import addend modulo 2^64, and `0x1004402d8` loads the u32 name into W0. The previously recovered service helper reaches `_bootstrap_check_in` at `0x10044038c`. Fresh data-forward and call fragments retain44 B; the earlier [registration contract](triage_evidence/daemon_registration_contracts.json) supplies the surrounding private-frame and dispatch linkage. The full-domain cancellation proof is checked again. This connects initialized cache data to the daemon's selected argument under the same binding/frame assumptions; native startup and actual bootstrap value remain unknown [RC1,RC5,RC6].

## Assumption register and bounded continuation

| ID | Assumption / dependent result | Stress test / falsification probe | Remaining boundary |
|---|---|---|---|
| RC1 | Captured daemon/cache/kernel interfaces form the applicable image family | Pin all identities, reexports, original initializer-offset word, authenticated stubs and data aliases | Loaded images, actual slice/header, interposition and native initializer execution unknown |
| RC2 | Selected header, role bytes and configuration inputs belong to one initialization epoch | Compare marker strings and 29 original sections; retain exact branch predicates, environment names and file-default versus initialized state | Effective environment, overrides, once/callback state and native branch unknown |
| RC3 | Message/descriptor/array representations obey their required conversion contracts | Match client literals, RPC IDs, server records, exact extents, three pointer outputs, SDK types and status branches | Native copyin/copyout, delivery, memory validity and policy admission unknown |
| RC4 | Names, imported/copied pointers, runtime fields and reference requests retain object/namespace identity | Preserve ordered cells, sentinels, reference calls, pipe publication and distinct spawn/init/atfork phases | Native right balance, actual task identity, scheduling, fork/inheritance and teardown unknown |
| RC5 | The earlier daemon private-frame/bank contract applies to the selected bootstrap helper | Fresh imports/sections, 256 bank inputs, raw slot and 44 B forwarding/call fragments; compare prior source-pinned registration evidence | Whole-main reachability, other indirect consumers, native arguments and protected processing unknown |
| RC6 | Layout/scalar checks support only their stated operations | Fresh source recapture/decoding, two primary SDK compilations, three full-domain scalar identities and altered-evidence rejection | Canonical private record types, hardware PAC, runtime effects and full-goal completion unknown |

| Impact | Remaining interface | Concrete anchor |
|---|---|---|
| High | Main-header and runtime-role correspondence | Trace the producer of libc header cell 0x1ed84eda0 and actual initialization inputs before assigning FairPlay a branch |
| High | Native bootstrap/registered-name identity | Bind the task selector 4 result, runtime+0x10, global bootstrap cell and imported daemon load to one namespace/epoch |
| High | Complete right lifetime | Join copied getter pointers, reply copyout, user name retention, reference calls, pipe ownership, atfork replacement and teardown |
| Medium | Allocator/once and pipe completion | Interpret runtime callback initialization and lower pipe/conversion consumers without replacing their effects with returned objects |
| Medium | Shared launchd cell production | Continue creation/replacement of the previously linked registered/notification/host-publication cell |
| Low | Matching alternate image variants | Compare explicit identities and layouts; equal API names or field offsets do not establish build equivalence |

## Validation and quality gates

Fresh capture matches saved source. Checks cover 27 contiguous original bodies, 102 selected instruction occurrences, eight authenticated stub/export bindings, four data-pointer bindings, two initializer edges, three MIG bindings, 243 import and 29 section comparisons, 256 bank inputs, two daemon fragments, 32 SDK assertions in two compilations, three scalar proofs and six rejected evidence alterations. Proofs cover the full u32 name predicate, bounded descriptor-size growth and full-u64 bootstrap addend cancellation. They do not execute recovered code, construct native requests or prove initialization, ownership or delivery. [Recovery](triage_evidence/recover_registered_port_consumers.py), [validator](triage_evidence/validate_registered_port_consumers.py), [delivery](triage_evidence/registered_port_consumers_delivery.json), [quality gates](triage_evidence/registered_port_consumers_quality_gates.json).

Recovery is O(B+F+I+M) time/space for retained original bytes B, fixups F, selected instructions I and import/section metadata M, excluding compiler/solver costs. Scalar size/name/address operations are O(1); the source-pinned selector bank has a fixed 256-input domain. No recovered target execution, target emulation, native IPC/fork, service/port change, dynamic loading or IDB mutation occurs.

QG1: Descriptive interface, ownership-frontier and control-flow analysis requires no normative premise.

QG2: RC1-RC6 identify assumptions, dependent claims, stress tests and unknowns.

QG3: Registered lookup/register, initialization and role selection, task bootstrap retrieval, runtime pipe/atfork consumers and FairPlay forwarding are covered. The full investigation remains active.

QG4: User/internal header 24/32 B and port descriptor 12/16 B produce the three-port 20 B growth. Message size, receive capacity, allocated name-array size and kernel pointer width remain distinct. Code 2671*4=10684 B excludes the additional 44 B daemon fragments.

QG5: Role-marker detection differs from branch selection; absent imports differ from whole-program non-use; file defaults differ from native state; fixed-three and OOL compatibility representations differ; spawn/init/atfork epochs and requested versus effective references remain separate.

QG6: Original bytes, exports/nlist, authenticated chains, initializer registration, SDK types/definitions, independent Mach-O tools and checked scalar identities provide provenance. Native loaded-image and port identity remain unknown.

QG7: Remaining interfaces have explicit anchors and impact labels. Native bootstrap provenance, complete right balance and successful FairPlay daemon/kext processing remain unproved.
