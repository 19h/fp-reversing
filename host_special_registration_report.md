# Host-special-port publication: launchd, Mach library and kernel

The selected original launchd arm64e slice connects integer `HostSpecialPort` properties to a service's u32 field+0x54, then to a `host_set_special_port` call. The original Mach library marshals routine413; the kernel registry routes it through host conversion, range/task/port/caller/policy gates to slot replacement. Slot34 passes the index checks but has no established publisher or receiver. A successful local cache update is not evidence of successful kernel registration: the recovered publisher stores its cache entry after both zero and nonzero setter returns. Runtime slot contents, actual launchd slice selection, native rights balance and RPC700 delivery remain **unknown**.

This extends the [publication census](rpc700_publication_report.md), [RPC700 namespace](rpc700_namespace_report.md) and [kernel send-right lifetime](kernel_send_right_lifecycle_report.md) reports. It recovers a registration interface, not a receiver for service RPC700.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| HS1 | Pinned kernel/cache and selected launchd arm64e slice delimit the corpus | Addresses, bindings and instruction contracts | Rehash sources; establish actual mapped launchd subtype/UUID separately, including the alternate arm64e.x1 slice |
| HS2 | SDK declarations and explicitly derived kernel layouts describe the displayed field geometry | Size/offset and message-right interpretation | Compile actual generated user types and Kernel SDK message types; compare original stubs; actual transport execution remains separate |
| HS3 | Reviewed W/X widths, carry and signed/unsigned branches match the scalar translations | Index, parser, cleanup and sentinel domains | Check original instructions and rerun all full-width SMT queries |
| HS4 | Host, task, service and message objects satisfy native mapping/tag/PAC prerequisites | Conditional conversions, callback arguments, storage and reference requests | Inspect actual objects and authentication; no such operations run here |
| HS5 | Reference XNU terminology supplies context, not exact build identity | Names for unnamed conversion/policy/storage routines | Retain original addresses and commit/hash metadata; do not infer complete target-build equivalence |
| HS6 | Disk bytes and saved publication observations are time/scope-limited | Original zero words, configured indices and earlier endpoint listing | Observe native slot state and registration history separately; zero file words do not imply runtime vacancy |
| HS7 | The recovered property block and publisher can participate in the stated object flow | Conditional configuration-to-call linkage | Establish whole-job reachability, object identity and native call outcomes independently; local cache writes are insufficient |
| HS8 | Aligned branch scans cover only their declared text ranges | Direct-call candidate inventory | Inspect indirect dispatch, other slices/kexts and dynamic callers before asserting registration absence |

## Corpus and provenance

The [source artifact](triage_evidence/host_special_registration_source.json) pins the original kernel collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84`. The cached Mach library is read from cache UUID `2bd06591-e751-3e84-963f-b08dab6af23a`; its image UUID and two consumed cache-file hashes are retained.

`/sbin/launchd` has universal-file SHA-256 `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`. The selected arm64e slice has UUID `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71`, SHA-256 `c8593a95e0937884b71e014c38b27f84db2c292f6a5e904a452d69a9a365bdb6`. The file also contains arm64e.x1; its metadata/hash are recorded, but its code and the live process's selected subtype are not established [HS1].

Reference nomenclature comes from pinned XNU commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`: [host implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/host.c), [host-port conversion](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ipc_host.c), and [MAC policy interface](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/security/mac_policy.h). URL, commit, content hash/length and reference scope are retained; validation does not silently refresh these external files. Target claims below derive from the original instructions. Reference names are identified as such [HS5].

## Configuration, object field and publication call

```text
properties object (conditional XPC dictionary path)
  -> launchd block setup at0x100047124
  -> xpc_dictionary_apply at0x100047148
  -> property callback0x10005c840
  -> integer HostSpecialPort:8..36 -> service+0x54
  -> publisher0x10003012c
       +-> slot24: exception-port route
       +-> other eligible slot: service send-name -> host_set_special_port
  -> Mach library routine413
  -> kernel conversion and authorization
  -> policy check -> locked slot replacement -> old-send release request

Whole-job/native reachability and slot34 receiver: UNKNOWN
```

The block at caller `0x100047064` captures a newly allocated service-shaped object and a caller-context value at block+32/+40 and passes the properties object to bound `_xpc_dictionary_apply`. Callback `0x10005c840` reads those captures and compares the value's XPC type. `HostSpecialPort` and `TaskSpecialPort` are original literals, with separate service fields [HS7].

| Path | Original instruction evidence | Resulting local contract |
| --- | --- | --- |
| Integer HostSpecialPort | Int64 getter at0x10005c90c; signed lower check8 and unsigned upper check36; store0x10005c924 | Accepted values8..36 stored as u32 at service+0x54 |
| Integer TaskSpecialPort | Separate branch to helper0x1000479cc | Helper stores low32 values7..11 or signed-negative low32 values at service+0x50; mixed signedness is distinct from the host guard |
| String HostSpecialPort | Named host-special lookup at0x10005cae0; positive result reaches0x10005cb14 | Reaches the same helper that stores+0x50, rather than the integer path's+0x54; intended/native string semantics unknown |
| Ordinary publisher | Signed field load0x100030498; zero skips; duplicate-index cache checked | Conditional service-index publication attempt |
| Index24 publisher | Special branch at0x1000304ac; helper0x100043fd0 | Uses bound host exception-port setter, not the ordinary host-special setter at this site |

The string path is a static routing difference, not a reproduced configuration failure or vulnerability. The prior931-plist census's19 declarations are integer-valued; this increment creates or changes no configuration.

For the ordinary route, `0x10003053c` requests `_mach_host_self`, and `0x10003054c` calls service-name helper `0x100046c28` with W1=1. That helper obtains an XPC object through `0x10005cb6c` and tail-dispatches `_xpc_mach_send_get_right`. Its object producer has a call to `_xpc_mach_send_create_with_disposition` with W1=17. Full port construction, object retention and receive-owner identity are not recovered here; the outgoing value is a name, not a kernel pointer [HS4].

At `0x10003055c`, X0 is the host name, X1 the selected index and X2 the service name. A nonzero return branches to bound `__os_assumes_log`, then rejoins the cache store at `0x100030564`. Both return classes write the service pointer into the local index cache and reach the routine's ordinary W0=0 return. Local cache and service flag updates therefore record this path's handling, not a proven successful host-slot mutation.

Before the ordinary publication tail, the routine applies additional admission and override logic. Helper `0x100003708` selectors2 and3 share original jump-table target `0x100003750`. Their result is `(byte[0x100089ab8] != 1) OR bit6(owner+0x586)`. On the inspected route, a nonzero host field survives the validation block only if that predicate is true and the selected domain's+0x68 pointer equals original global address `0x1000895c8`. Otherwise, diagnostics identify a non-system service and the code clears service+0x54 at `0x100030348`. These object roles are analytical; native values and full caller constraints remain unknown.

An earlier service flag can also override host+0x54 to24 when the domain matches, or assign task+0x50 the special value128 otherwise. Consequently, the numeric parser's acceptance is distinct from retention of its value, and the task-helper's range is not a complete inventory of all writes to the task field. Earlier endpoint conflict/shadow paths can return before this tail. The report does not equate a parsed declaration with an executed setter call.

## Publication and cleanup emission sites

All94420 aligned words of this selected launchd `__text` were searched for B/BL encodings targeting the verified setter stub. Four candidates occur in complete captured compiler bodies [HS8]:

| Setter call site | Selected index / port-name source | Recovered role |
| --- | --- | --- |
|0x10002d498 | W1=22; W2 from a global field | Fixed-slot startup path; whole reachability unknown |
|0x10002fec8 | W1 from service field; W2=0 | Cleanup clears kernel slot only when `(index AND 0xfffffffb)==25`, namely25 or29 |
|0x10003055c | Index from service+0x54; name from service helper | Ordinary publication path with cache behavior above |
|0x100035a04 | W1=16; W2 from a global field | Conditional fixed-slot publication |

Cleanup clears its local index-cache cell beyond that conditional setter call. Thus the inspected routine does not implement a universal kernel-slot clear for every service teardown. Other teardown and transitive behavior remain unknown. Fixed indices16/22 and special24 are recorded as actual numbers; SDK names are contextual labels.

## Mach ABI and emission boundaries

| Contract | Userspace geometry | Kernel geometry | Original linkage |
| --- | --- | --- | --- |
| Getter request412 |40 B; node+32, index+36 |48 B; node+40, index+44 | Library0x180548a54; emission call0x180548acc; stub0xfffffe000bd83f84 |
| Getter success reply, expected ID512 |40 B complex reply with one port descriptor |52 B complex reply | SDK declarations and original stub/receiver checks agree |
| Setter request413 |52 B; descriptor+28, NDR+40, index+48 |64 B; descriptor+36, NDR+52, index+60 | Library0x18056895c; emission call0x1805689e4; stub0xfffffe000bd83eb8 |
| Setter reply, expected ID513 |36 B; result+32 |44 B; result+40 | Original library validates ID513 and reads the u32 result |

User message headers are24 B and port descriptors12 B. Kernel headers are32 B and descriptors16 B. Actual generated user SDK types are compiled directly. Kernel rows are explicitly derived structures using actual Kernel SDK types and pack4, checked against original stub accesses; they are not claimed as a recovered generated kernel header [HS2]. The stubs receive the scalar payload separately: setter loads the index at payload+8, getter at payload+12.

The public setter's header bits are `0x80001513`: destination COPY_SEND19, reply MAKE_SEND_ONCE21 and the complex flag. Its embedded service-name descriptor has COPY_SEND19 and type0. The kernel stub validates received descriptor disposition17/type0 and reads a pointer-sized field. Header destination, reply port and embedded service port are distinct interface objects. The source retains original constants and exact marshaling instructions; no request is built or sent here.

The cached common transport target is original `_mach_msg2_internal`, `0x18055a894`. The getter writes its returned service name with a W-register store through the caller's output pointer. A status0 result does not alone imply a non-null/live service endpoint, as established in the earlier getter report. Node is unused by the recovered kernel getter path.

## Kernel conversion, caller gates and replacement

| Original routine | Address | Recovered role |
| --- | --- | --- |
| Host-private converter |0xfffffe000bcf334c | Input port must equal current task's cached host-port pointer at+0x2d0; then byte+1 low-three-bit, type-byte0x19 and stable-object checks; rejects toNULL |
| Setter front |0xfffffe000bcf2330 | Non-NULL host and index8..36; task flag predicate; candidate-port acceptance predicate; then policy wrapper |
| Setter authorization/policy wrapper |0xfffffe000bcf23cc | Caller identity/exception gates, policy dispatch and zero/nonzero result normalization |
| Slot replacement core |0xfffffe000bcf2194 | Internal index guard, slot26 rejection, host locking, authenticated pointer replacement and old-send release request |
| User getter wrapper |0xfffffe000bcf24b0 | Getter index/task gates before exported getter |
| Exported host_get_special_port |0xfffffe000bcf258c | Existing slot selection and reference-copy path |
| Policy dispatcher |0xfffffe000c617964 | Enumerates policy entries and calls operations-table member+0x3f0 |

The converter's stable object must be the original host identity `0xfffffe000cad0238`; a different non-NULL stable object reaches a fatal consistency path. Original `_current_task` at `0xfffffe000bd41ac4` tail-calls owner lookup `0xfffffe000bd7e9c4`. These links support the task interpretation; actual objects and PAC are not observed [HS4].

The setter front returns4 for its rejected host/index guard,8 for its task-state rejection and53 when its candidate-port predicate returns0. The raw task test masks task+0x4d8 with `0x000f000000000000` and compares to `0x0007000000000000`. Reference source calls this a driver-task gate; target field layout/name is not independently exported. The candidate predicate accepts NULL and dead sentinels locally before its nontrivial object checks. Reference source describes the corresponding eligibility test for stashing a send reference; no native eligibility result is inferred.

The next wrapper compares the current task with exact `_kernel_task`, or its associated-process result with an authenticated global at `0xfffffe000cb51668`. Reference source identifies the latter role as init-process authorization; native process identity remains unknown. Another branch is specific to index20 and original entitlement string `com.apple.private.xpc.launchd.event-monitor`. A separate configuration-byte bit2 can also admit the caller to the next gate. Slot34 does not take the index20-only entitlement branch. No configuration/entitlement changes are performed or prescribed.

The dispatcher builds callback arguments: credential-shaped X0, index in X1 and candidate kernel port pointer in X2. Its original callback slot is+0x3f0. The pinned reference policy structure places `mpo_proc_check_set_host_special_port` at pointer index126, matching that byte offset and argument shape; runtime registration, selected callbacks and decisions are unknown. Nonzero aggregate policy result becomes8; zero continues to replacement [HS5].

The storage core accepts internal indices0..3 or8..36, and rejects26 with46 before slot storage. Public setter callers already have the narrower8..36 guard. Slot34 is in neither rejection. The host slot address is `host+0x10+8*index`; for the recovered host identity, selected cells are:

| Index | Original cell | Runtime object |
| --- | --- | --- |
|17 |0xfffffe000cad02d0 | unknown |
|31 |0xfffffe000cad0340 | unknown |
|34 |0xfffffe000cad0358 | unknown |

All three captured file words are zero. The earlier launchd observation reports active associations for17 and31, demonstrating why file initialization bytes cannot be equated with live slot contents [HS6].

The core acquires the host lock, authenticates the old non-NULL entry, signs/stores the new pointer at `0xfffffe000bcf2250`, unlocks, and requests `_ipc_port_release_send` for a valid old entry at `0xfffffe000bcf22d0`. No new send-copy call appears in this core. This is consistent with storing the supplied reference and releasing the replaced reference; actual transport cleanup and balanced native ownership remain unproven. Slot33 has a separate notification branch; it is not assigned to slot34.

## Direct kernel callers and remaining limits

The aligned scan covers2540432 words of the original kernel `__TEXT_EXEC`, excluding other collection members and indirect calls. Seven candidates target the setter front, policy wrapper or core. Three fixed-slot initialization calls select1,2 and3; another forwarding window selects10; the remaining candidates are the captured wrapper/MIG links. The fixed-slot10 forwarder belongs to an additional interface whose complete ABI is outside this increment. No selected immediate window establishes a slot34 publisher [HS8].

The saved census still has no34 declaration in its four roots, and the saved native observation remains the timestamped12:12:31 UTC snapshot. This work explains how an eligible numeric declaration can reach registration; it does not add a declaration, prove a native call succeeded, or identify RPC700's receiver.

## Verification and bounded continuation

[Recovery](triage_evidence/recover_host_special_registration.py) retains27 complete original bodies:14 kernel, eleven launchd and two cached Mach-library functions, totaling2114 instructions/8456 B. Its scans cover2540432 kernel and94420 launchd aligned instruction words; candidates are validated against original bytes and compiler bounds, with reachability left separate. All2447 selected launchd-slice chained fixups independently match read-only `dyld_info -fixups`. Thirteen bound launchd stubs, two MIG records, five selected SDK header hashes and three reference-source hashes are recorded.

[Validation](triage_evidence/validate_host_special_registration.py) recaptures the original sources and checks141 instruction assertions. Thirty-two SDK assertions pass in two compilation modes: actual generated user types and derived layouts using actual Kernel SDK message types. Six timeout-bounded queries are unsat over their full declared scalar domains: setter u32 range, storage u32 range, host-property integer64 range, task-slot helper32 mixed-signedness domain, cleanup indices32 and port sentinels64. Ten altered-evidence controls reject changes to conversion type, range, policy callback, service field, cache failure branch, descriptor disposition, MIG binding, reply geometry, release request and native-effect scope.

These checks establish the stated static contracts and layouts, not complete native equivalence of2114 instructions. Original locks, policy state, object identity, PAC, message transport and loaded-image selection are not executed or attested. Native host port APIs, service changes and test declarations are not introduced.

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_host_special_registration.py
python3 triage_evidence/verify_host_special_registration_publication.py
```

Extraction is O(B+F+I+W) time and space in source bytes B, fixups F, selected instructions I and scanned words W; SDK compilation and solver costs are separate, with each scalar query limited to10 s. Widths are u32/u64 or explicit SDK `int` fields; all message extents and object offsets are in bytes. Source identities, copied right requests and native ownership remain separate evidence classes.

| Impact | Remaining gap / pattern | Discriminating continuation |
| --- | --- | --- |
| High | Slot34 publisher and receiving implementation unknown | Recover effective registration history or an original caller that supplies34; retain absent declaration and absent runtime object as different findings |
| High | Alternate arm64e.x1 and actual launchd mapping unknown | Recover that slice's corresponding property/publisher bodies and obtain mapped-image identity before extending these addresses to the live process |
| Medium | Send-name factory and ownership beneath0x10005cb6c | Recover its private construction flags, context and name/right lifetime; current XPC wrappers alone do not establish a receive owner |
| Medium | String/numeric and task/host property routes differ | Recover upstream conversion and caller constraints; preserve mixed signedness and destination-field distinctions without assigning native failure or vulnerability |
| Medium | Local cache survives a nonzero setter return | Trace cache consumers and diagnostics; local cache state must not stand in for an observed kernel mutation |
| Medium | Actual policy callbacks unknown | Establish registered policy table entries, current credentials and decisions independently |

QG1: Factual technical analysis; no normative conclusion.

QG2: HS1-HS8 state assumptions, dependent results and falsification probes.

QG3: Configuration block/property fields, ordinary and special publication routes, library messages, kernel conversion/gates/replacement, direct caller inventory and lifetime requests are covered for the stated corpus. The full interface investigation remains active.

QG4: User/kernel layouts, 32/64-bit guards, mixed signedness, byte offsets, pointer/name widths, six complete scalar domains and extraction complexity are explicit.

QG5: Integer/string paths, host/task fields, slot24 exception routing, selective cleanup, cache versus kernel outcome, reference-source naming, alternate slice and zero disk words versus runtime state are separated.

QG6: Pinned original bytes/UUIDs, compiler boundaries,2447 independent fixup comparisons, actual SDK compilation, complete scalar queries and commit-pinned reference metadata provide provenance; runtime unknowns remain explicit.

QG7: Impact-labeled continuation remains bounded to concrete interface and provenance gaps.

[Delivery checks](triage_evidence/host_special_registration_delivery.json) and [quality metadata](triage_evidence/host_special_registration_quality_gates.json) apply to this increment. Original inputs and prior evidence remain preserved except for explicitly owned report/index/publisher updates.
