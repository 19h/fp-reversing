# Spawn port actions, task publication and frame-origin frontiers

The previously unclassified spawn descriptor pair at +0x20/+0x28 carries port actions from private attribute +0xc8. Seven original libkernel setters construct 24 B entries; launchd conditionally supplies importance-watch names and two registered names. The captured kernel copies the array, imports ordinary names using COPY_SEND 19, separates application from cleanup, and publishes registered pointers into three task-relative cells [PA1-PA4]. [Original capture](triage_evidence/spawn_port_actions_source.json), [checks](triage_evidence/spawn_port_actions_checks.json).

The frame-origin pass extends the previous literal-SP census. It resolves 362 memory sites, records one indexed site, 19 calls with frame-derived arguments and three pointer escapes. The final Conclave pair has two overlapping resolved stores and no overlapping resolved load. The indexed cleanup site is bounded separately under initialized-record and no-external-mutation assumptions. Opaque calls/loads, escaped objects and arbitrary aliases remain outside the locator domain; Conclave consumption and whole-kernel non-use remain unknown [PA4-PA6].

This extends the [spawn descriptor report](spawn_conclave_abi_report.md), [Exclaves control boundary](exclaves_notification_contract_report.md) and [job/endpoint lineage](job_factory_lineage_report.md). No target execution, native request, port mutation or IDB change occurs.

## Primary identities and scope

Launchd SHA-256 is `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`; both original arm64e and arm64e.x1 slices are checked. Cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. Kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The capture retains complete bytes, compiler bounds, original exports/nlist entries where present, pointer bindings, library identities, used cache-file hashes and SDK/tool hashes [PA1,PA6].

Twenty-six bodies contain 7541 instructions / 30164 B: four launchd bodies, nine cached bodies and thirteen kernel bodies. Five selected launchd words use byte-checked LLVM decoding. Both slices' 4894 fixups independently agree with `dyld_info`. Private kernel names below are analytical role labels unless an original name is explicitly given.

```text
launchd attribute handle
  +-> importance-watch setter: repeated kind3 records
  +-> registered-port setter: selected two-name array -> kind4 records
      |
      v
attribute+0xc8 -> {capacity,count, 24 B actions[]}
  -> spawn descriptor pair2 -> BSD244 -> kernel copy-in
     -> first pass: classify/count/check limits
     -> second pass: COPY_SEND name import, selected application/retention
        +-> special-port receiver -> task-relative slot replacement
        +-> exception pairs -> later receiver -> clear retained pointer on success
        +-> registered[3] -> task cells +0x2f8/+0x300/+0x308
        +-> importance array / audit-session / virtual-environment frontiers
     -> separate selected cleanup -> ipc_port_release_send

Conclave: descriptor pair8, separate object and interval
  -> resolved stores observed; no resolved load in the locator domain
  -> opaque/escaped-object access remains unknown
```

## Producer and private record contract

| Field | Entry offset | Width / producer meaning |
|---|---|---|
| Kind | +0 | u32, 0 through 6 in the recovered setters |
| Exception mask | +4 | u32; used by kind1 |
| Port name | +8 | u32 in the caller's namespace |
| Exception behavior | +12 | u32; used by kind1 |
| Thread-state flavor | +16 | u32; used by kind1 |
| Special-port selector | +20 | u32; used by kind0 |

The entry is 24 B. The array prefix contains two u32 words, capacity then count, totaling 8 B. The common append routine at `0x180553694` loads attribute+0xc8, initially requests 56 B for capacity 2, copies all 24 entry bytes, then increments count. Its growth path requests a larger allocation through initialized runtime callbacks and republishes the pointer. Handle validation, arithmetic/error gates and callbacks are retained as original code; allocation success and native ownership are not observed [PA2].

The public spawn wrapper emits the pair using the array address and selected size `8 + 24*n` B. The kernel copy-in uses descriptor offsets +0x20/+0x28, locally SP+0x270/+0x278, and publishes the allocated copy at image-parameter object+0x2f0. User names and kernel pointers have distinct widths and ownership stages. These are BSD syscall records, not Mach message port descriptors [PA2,PA3].

| Kind | Original setter | Original setter address | Selected kernel preparation |
|---|---|---|---|
| 0 | `_posix_spawnattr_setspecialport_np` | `0x180553b08` | Import name; pass pointer and selector to special-port receiver |
| 1 | `_posix_spawnattr_setexceptionports_np` | `0x180554578` | At most 14 admitted entries; retain 16 B pointer/record pairs |
| 2 | `_posix_spawnattr_setauditsessionport_np` | `0x18055365c` | Import name; call separate audit-session receiver |
| 3 | `_posix_spawnattr_set_importancewatch_port_np` | `0x18055e484` | At most 128 admitted entries; retain pointer array |
| 4 | `_posix_spawnattr_set_registered_ports_np` | `0x18055e520` | At most 3 admitted entries; retain three inline pointers |
| 5 | `_posix_spawnattr_set_ptrauth_task_port_np` | `0x18055e5bc` | Selected duplicate gate; imported pointer reaches send-release call |
| 6 | `_posix_spawnattr_set_virtual_env_np` | `0x18055e5f4` | Selected duplicate gate; retain pointer at temporary+0x38 |

Five original 8 B literals at `0x18057d328` through `0x18057d348` contain `{kind,0}` for kinds 2 through 6. Kinds0/1 are constructed directly. The importance and registered setters enforce per-call count limits 128 and 3; their repeated append loops return on the first nonzero status. Earlier successful appends are not rolled back by those selected return paths. Kernel cumulative counts and per-call user limits are separate contracts. Kind5's setter name establishes its user-facing identity; the captured selected release path does not establish a native pointer-authentication effect [PA2,PA3].

## Launchd sites and port provenance

| Role | arm64e call site | arm64e.x1 call site | Selected arguments |
|---|---|---|---|
| Importance-watch attribute preparation | `0x1000237a0` | `0x10002305c` | Same attribute handle; count from X23, name array from X22 |
| Registered-port attribute preparation | `0x10001f778` | `0x10001f0d0` | Same handle at SP+0x38; two u32 names on local stack |
| Subsequent spawnp frontier | `0x10001f7c0` | `0x10001f118` | Prepared handle, file actions, path, argv, environment |

The selected registered path first reads job+0x2ec; if zero, it may read the same field through job+0x100. Its unsigned name gate precedes the setter. The first name comes from global cell `0x10008af20`, and the second from that job-field selection. Current values, native namespace correspondence and FairPlay-specific use of these two names remain unknown [PA1,PA4].

The first cell has a verified static cross-interface correspondence. Eight freshly reread ADRP/LDR fragments, 64 B across both slices, join the new registered input to earlier verified notification and host-publication paths:

| Use of global 0x10008af20 | arm64e load / emission | arm64e.x1 load / emission |
|---|---|---|
| First registered-port input | `0x10001f764` / setter `0x10001f778` | `0x10001f0bc` / setter `0x10001f0d0` |
| Notification69 destination | `0x100045d3c` / request `0x100045d64` | `0x100045060` / request `0x100045088` |
| Fixed host-special slot22 path | `0x10002d490` / setter `0x10002d498` | `0x10002cb54` / setter `0x10002cb5c` |
| Fixed host-special slot16 path | `0x1000359fc` / setter `0x100035a04` | `0x100034fc4` / setter `0x100034fcc` |

The [notification-return report](port_destroyed_return_report.md) establishes the notification destination role; the [host-registration report](host_special_registration_report.md) and [two-slice bindings](launchd_variant_binding_report.md) establish the fixed-slot calls. These are uses of the same static storage cell. They do not prove common live values across epochs, successful host registration, inherited native right identity or execution of every path. The cell's creation, replacement and child lookup consumers remain further interfaces [PA1,PA3,PA4].

The local setters and append routine emit no Mach message. Their names become syscall input and, conditionally, kernel send-right pointers. No new live port number or successful daemon/kext exchange is established.

## Kernel import, application and cleanup

| Analytical role | Original address | Selected interface |
|---|---|---|
| Port-action preparation | `0xfffffe000c2a5724` | Image-parameter object plus 64 B temporary record |
| Name-import wrapper | `0xfffffe000bcc9658` | Namespace/name/disposition/flags plus output pointer |
| Special-port front / store | `0xfffffe000bcfa548` / `0xfffffe000bcfa334` | Recipient object, selector, imported pointer; policy/lock/PAC gates |
| Registered-port store | `0xfffffe000bcfa5fc` | Recipient object plus three imported pointers |
| Exception receiver | `0xfffffe000bcfc69c` | Recipient, mask, pointer, behavior, flavor |
| Importance receiver frontier | `0xfffffe000bd4ff08` | Selected task/context/count/pointer-array arguments; deeper policy not fully interpreted |
| Audit-session receiver frontier | `0xfffffe000c25a0ec` | Selected recipient/context/imported-pointer arguments |
| Virtual-environment frontier | `0xfffffe000c2a5b04` | Configuration/policy gate and separate object conversion |
| Original `_ipc_port_release_send` | `0xfffffe000bcd0448` | Separate selected send-reference release requests |

At `0xfffffe000c2a59bc`, preparation calls the name-import wrapper with W2=19, W3=1, W4=7, X5=0 and an output address at local SP+0x20. SDK corroboration identifies disposition 19 as COPY_SEND. Names0 and UINT32_MAX take a separate sentinel path. This establishes the static import contract, not actual lookup success, reference creation, namespace identity or right balance [PA3,PA4].

For kind0, the selected receiver tail-calls the store routine after policy/port gates. Selector 4 reaches task-relative+0x2d8, matching the SDK task bootstrap selector; selected replacement code signs/stores the new pointer and releases a qualified old send pointer. Other admitted selectors use distinct cells and gates. A task bootstrap selector 4 is separate from host-special slot 17 and from a local port name.

The registered receiver checks its three pointer arguments and task state, then stores signed pointers at task-relative+0x2f8/+0x300/+0x308. It subsequently calls the named release routine for the three previous pointers. The syscall's selected application call is `0xfffffe000c2a3fa4`. Full lock behavior, effective PAC, policy admission, input ownership and native publication remain dependencies.

Exception preparation retains `{imported_pointer, action_record_pointer}` pairs. The syscall loads the mask/behavior/flavor from the original copied record and calls the exception receiver at `0xfffffe000c2a508c`. On selected status0, it clears the retained pointer before later cleanup. Separate exception, importance, registered and virtual-pointer cleanup calls occur at `0xfffffe000c2a36b4`, `0xfffffe000c2a3718`, `0xfffffe000c2a377c` and `0xfffffe000c2a37ac`. These local transitions establish cleanup intent and ownership frontiers; complete native reference balance is unknown [PA3,PA4].

## Frame-origin analysis and bounded indexed read

The static locator seeds entry SP as local-frame+0x3f0, derives FP as local-frame+0x3e0, and propagates explicit MOV/ADD/SUB/CSEL origins through the complete syscall CFG. Its finite domain keeps at most 16 offsets per tracked register, widens other arithmetic to an unknown frame origin, tracks monotone 8 B spill candidates and records unsupported operations. Both conditional branches are retained without feasibility pruning. All 2556 instructions receive a CFG state; this does not mean all instructions execute in one native invocation [PA5].

Unknown input pointers, unknown loads, call return values, hidden call effects, escaped-object reloads and arbitrary aliases do not become disjointness facts. Calls clobber tracked caller-saved origins; calls with tracked X0-X7 arguments are emitted as frontiers. Two opaque authenticated calls remain in the original syscall body. The analysis is a locator with explicit limitations, not an end-to-end alias proof.

| Result | Exact captured evidence | Limit |
|---|---|---|
| Frame accesses | 363 sites: 362 resolved, one indexed | Covers explicit tracked origins only |
| Resolved final-pair overlap | Store 32 B at `0xfffffe000c2a2bc0`, starting SP+0x2c0; store 16 B at `0xfffffe000c2a2d14`, starting SP+0x2d0 | Initial zeroing and compatibility expansion; no overlapping resolved load |
| Descriptor-base call arguments | `0xfffffe000c2a2d84`: copy-in destination; `0xfffffe000c2a4d4c`: MAC helper input | Opaque/internal callee effects outside selected interpretation remain unknown |
| Pointer escape1 | `0xfffffe000c2a2c5c`: SP+0x2e8 stored at image object+0x2a8 | Pointee begins after Conclave interval; escaped-object access not recursively followed |
| Pointer escape2 | `0xfffffe000c2a2efc`: SP+0x150 stored at image object+0x2e0 | Base-attribute prefix, separate from descriptor+0x80 |
| Pointer escape3 | `0xfffffe000c2a4180`: SP+0x150 stored at another object+0x798 | Object epoch and downstream uses remain dependencies |
| Spill candidates | Two stores to SP+0xc8, one tracked slot | Monotone candidates may include overwritten/path-infeasible values |
| Unsupported tracked arithmetic | Zero in this capture | Unknown loads/calls remain frontiers regardless |

The indexed site at `0xfffffe000c2a3774` reads `[SP+0x110 + 8*i]` and conditionally calls send-release. The count is the u32 field at temporary+8, hence SP+0xf8. The caller zeroes that field before the preparation call. In the preparation routine, the only direct store to that field follows an increment and immediately tests against 3: continuation admits at most 3; the first failing increment stores 4 before the error suffix. The subsequent processing pass does not increment that count. With this initialization, selected control flow and no external mutation, the count is bounded by 4 even on the partial-error path [PA4,PA5].

Consequently the conservative read envelope is `[SP+0x110,SP+0x130)`, disjoint from Conclave interval `[SP+0x2d0,SP+0x2e0)`. This envelope includes the possible fourth read; it does not assert that four registered pointers are admitted. The scalar step invariant and all i<4 offsets are solver-checked. Foreign writes, different input epochs, hidden aliases and native execution remain unknown. The conclusion does not establish whole-kernel non-use of Conclave.

## Assumption register and bounded continuation

| ID | Assumption / dependent results | Stress test / falsification probe | Remaining boundary |
|---|---|---|---|
| PA1 | The captured image family is applicable to the path being described | Pin launchd/cache/kernel identities; compare both slices and original bindings/fixups | Native slice, effective kernel, interposition and FairPlay launch epoch unknown |
| PA2 | Initialized attributes/arrays and allocator callbacks preserve one object epoch | Join handle setup, append pointer/count publication, selected growth/errors and descriptor copy-in | Allocation success, concurrent mutation, caller buffer lifetime and full ownership unknown |
| PA3 | Imported names and application pointers refer to the intended namespace/recipient | Preserve COPY_SEND 19 arguments, sentinel path, recipient selection, stores, status branches and release frontiers | Native namespace identity, lookup/admission, locks/PAC and right balance unknown |
| PA4 | Temporary fields begin zero and no external writer changes the selected record | Check caller zero stores, single count store, immediate count gate, receiver arguments and partial-error cleanup | Hidden writes, pointer aliases, asynchronous changes and native epoch unknown |
| PA5 | Locator results are used only within the explicitly tracked origin domain | Recompute all states/sites; independently check 336 literal SP/FP accesses; retain indexed/call/escape frontiers | Unknown loads/returns, indirect calls, escaped-object reloads, arbitrary aliases and whole-kernel non-use unknown |
| PA6 | Reconstructed geometry/scalar models match their stated operations | Fresh capture/decoding, 4894 fixups, SDK compilation, full-domain scalar identities and altered-evidence rejection | Canonical private types, complete policy semantics, native effects and full-goal completion unknown |

| Impact | Remaining interface question | Concrete anchor |
|---|---|---|
| High | Native FairPlay port correspondence | Bind the shared registered/notification/host-publication cell and selected job+0x2ec name to one launch/namespace epoch; follow child registered-port lookup consumers |
| High | Conclave access through escaped/opaque paths | Follow the three captured pointer escapes and call effects with object/field provenance; preserve separate descriptor and attribute intervals |
| High | End-to-end right ownership | Join import success, recipient stores, cleared retained pointers, old-pointer release and later cleanup within one epoch |
| Medium | Importance/audit/virtual-environment policy | Interpret the captured complete receiver bodies and their lower conversion/policy frontiers |
| Medium | Launchd importance-array source | Trace the count/name-array producers supplied to attribute preparation, with per-call versus cumulative limits |
| Low | Alternate matching images | Compare the same contracts in an independently identified image without inferring equivalence from offsets or API names alone |

## Validation and quality gates

Fresh recapture matches saved source. Validation checks all contiguous function bytes/decodes, 112 selected instruction occurrences, seven setter/export bindings, eight shared-cell fragments, five original kind literals, 4894 fixups, the finite frame-origin result, an independent 336-access SP/FP certificate, 26 SDK assertions in one arm64 compilation, three scalar proofs and six rejected evidence alterations. The scalar proofs cover the count-step bound, cleanup interval and admitted `24*n+8` size formula. They do not execute recovered code or establish native policy/ownership effects. [Recovery](triage_evidence/recover_spawn_port_actions.py), [frame locator](triage_evidence/analyze_spawn_port_frame.py), [validator](triage_evidence/validate_spawn_port_actions.py), [delivery](triage_evidence/spawn_port_actions_delivery.json), [quality gates](triage_evidence/spawn_port_actions_quality_gates.json).

The locator records 6117 worklist visits across two spill rounds and 2928 CFG edges. With W visits, bounded per-state register-domain size D, instruction count I and spill map M, work is O(W*(D+M)+I) and storage O(I*D+M), excluding the retained source bytes. Selected array preparation is O(n) plus allocation, namespace lookup, policy and receiver/backend costs. Scalar size/offset calculations are O(1). No recovered target execution, target emulation, native spawn/IPC, service/port change or IDB mutation occurs.

QG1: Descriptive ABI, ownership-frontier and control-flow analysis requires no normative premise.

QG2: PA1-PA6 record assumptions, dependent results, stress tests and unknowns.

QG3: Port-action producer/serialization/import/application/cleanup, launchd emission sites, frame aliases and explicit remaining frontiers are covered. The complete investigation remains active.

QG4: Entry 24 B, prefix 8 B, temporary 64 B, user name 4 B, kernel pointer 8 B, descriptor 144 B, base-attribute copy 200 B and code 7541*4=30164 B are distinct. Reconstructed private layouts are explicitly identified.

QG5: Per-call and cumulative limits differ; count 4 is a partial-error bound, not admitted capacity; pointer publication differs from native ownership; zero resolved reads differs from whole-kernel absence. Equal offsets in task, image and descriptor objects do not establish identity.

QG6: Original binary/cache bytes, exports/nlist, used-file hashes, compiler-bounded code, primary SDK headers and checked scalar identities supply provenance. Current native effects remain unknown.

QG7: Remaining interfaces have concrete anchors and impact labels. Native FairPlay/Conclave attribution, successful daemon/kext interaction and complete interface coverage remain unproved.
