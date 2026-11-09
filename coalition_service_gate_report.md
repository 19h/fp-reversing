# Jetsam-coalition privilege in service-port construction and return

The receiver metadata prerequisite in the [receive-name/guard report](receive_name_guard_report.md) is now identified: task+0x608 is the jetsam-coalition pointer, and coalition byte+0x28 bit0 is its privilege predicate. Original construction code produces that bit; task adoption publishes the pointer through an indexed store; original service-port construction and receive publication consume it. This replaces an unnamed field/feature assumption for the selected binary. It does not establish native launchd/fairplayd membership, actual admission, guard state or a FairPlay round trip. [Capture](triage_evidence/coalition_service_gate_source.json), [checks](triage_evidence/coalition_service_gate_checks.json).

The producer was not among the six immediate STR+0x608 candidates: it stores through `task+0x600+8*type`. The exact object provenance, typed callback table and original diagnostic names supply the connection. This is a coalition membership/privilege condition; PID1 identity, task role, code-signing status and a direct entitlement lookup are distinct predicates.

## Source identity and interpretation boundary

The collection SHA-256 remains `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Its original version string reads `Darwin Kernel Version 27.2.0: Wed Oct  7 23:15:14 PDT 2026; root:xnu-13432.41.4~3/RELEASE_ARM64_T6041`. Sixteen complete compiler-bounded bodies contain2633 instructions/10532 B. All are decoded from original bytes. No target, emulation, coalition operation, native membership query, service/guard API, IPC or IDB mutation executes.

Public naming is cross-checked against Apple XNU commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`. Its coalition structure calls bit0 `privileged`; the creation signature separates type, role, privilege and efficiency. Those names correspond to the original binary's distinct stores/arguments. Exact source/build equivalence with the inspected xnu-13432.41.4 is unknown. [Apple coalition implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/coalition.c).

The pinned public header names RESOURCE0/JETSAM1, creation privilege bit0, efficiency bit1, type bits4..7 and role bits8..11. The binary independently implements those numeric fields. These are semantic correspondence facts, not copied target-private SDK layouts. The installed `kern/coalition.h` contains no private definitions. [Apple coalition header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/coalition.h), [pinned file hashes and identifier locations](triage_evidence/coalition_service_gate_primary_context.json).

```text
coalition creation (type, role, privileged, efficient)
  -> type-specific init callback
  -> coalition byte+0x28 bit0 = privileged != 0

task adoption
  -> type-specific adopt callback
  -> task.coalition[type] = coalition
       type0: task+0x600; type1: task+0x608

current_task export -> original thread/task resolver
  -> task+0x608 -> jetsam coalition -> byte+0x28 bit0
       +-> selected service-port construction gate
       +-> selected receive-publication/guard-restoration gate
```

Every arrow describes a static data/control interface under the corresponding valid-object/call-epoch premises [CG1-CG6].

## Original roles and bindings

| Role | Original start | Naming evidence |
|---|---|---|
| Current task accessor | `0xfffffe000bd41ac4` | Original kernel nlist `_current_task` |
| Thread/task resolver | `0xfffffe000bd7e9c4` | Actual target of current-task tail branch |
| Task-to-BSD-process accessor | `0xfffffe000bd7deec` | Original kernel nlist `_get_bsdtask_info` |
| Jetsam task-role membership check | `0xfffffe000bce7758` | Original `coalition.c` / `i_coal_jetsam_set_taskrole` diagnostics |
| Coalition adoption | `0xfffffe000bce8fa0` | Type checks, operation table, indexed task-slot stores |
| Coalition creation | `0xfffffe000bce7304` | Constructor/callback/stores; public-source correspondence |
| Coalition initialization | `0xfffffe000bce9d14` | Original `coalitions_init` diagnostic |
| Coalition syscall dispatcher | `0xfffffe000c309a4c` | Flags/operation dispatcher; public-source correspondence |
| Service-port construction | `0xfffffe000bce00b8` | Prior construct ABI and original privilege predicate |
| Receive publication | `0xfffffe000bcd5e24` | Prior namespace/guard path and same predicate |
| Task creation/adoption caller | `0xfffffe000bd41e68` | Explicit, inherited, init and corpse coalition-array call sites |
| Task coalition release | `0xfffffe000bce955c` | Both task slots and independent reference releases |

Private analytical labels are not asserted to be original nlist names. The role helper's diagnostic name is an original literal, not an added symbol. A captured original Objective-C task encoding also contains `[2^{coalition}]`; it corroborates the two-element field type without independently proving an offset or C-layout equivalence.

The named `_current_task` is a three-instruction accessor: BTI, read TPIDR_EL1, tail-branch to the previously unnamed resolver. This establishes the resolver's task result through an original exported caller. Its internal range/metadata/backpointer checks remain captured; actual native pointer/authentication/allocator state remains unknown [CG1].

## Field and callback correspondence

| Object / field | Width | Selected meaning / evidence |
|---|---|---|
| Coalition+0 | 8 B | Created ID |
| Coalition+8 | 4 B | Type0/1, constructor and adoption checks |
| Coalition+12 | 4 B | Role argument, separate from privilege |
| Coalition+16 | 4 B | Reference counter operations |
| Coalition+20 | 4 B | Active membership counter operations |
| Coalition+40 bit0 | 1 bit | Privilege Boolean, produced from constructor argument2 |
| Coalition+40 bit5 | 1 bit | Efficiency Boolean, produced from argument3 |
| Task+0x600 | 8 B | RESOURCE coalition slot0 |
| Task+0x608 | 8 B | JETSAM coalition slot1 |
| Task+0x620/+0x628 | 8 B each | Jetsam membership list links |

The coalition constructor preserves role separately in X23 and privilege in X20. It stores type/role as adjacent u32 fields at+8/+12. After successful type-specific initialization, its byte expression is:

```text
new_flags = (old_flags & 0xde)
          | (privileged != 0 ? 0x01 : 0)
          | (efficient  != 0 ? 0x20 : 0)
```

This exact scalar formula is proved over all u8 old flags/u32 inputs. It assigns neither privilege to role value1 nor role to privilege bit1. Other byte flags survive the mask. Constructor admission, allocation and callback success remain separate premises [CG2,CG3].

| Type index | Operation row | Init pointer slot -> target | Adopt pointer slot -> target |
|---|---|---|---|
| 0, RESOURCE | `0xfffffe0007e5c8e0` | `0xfffffe0007e5c8e8` -> `0xfffffe000bce7fb8` | `0xfffffe0007e5c8f8` -> `0xfffffe000bce7de4` |
| 1, JETSAM | `0xfffffe0007e5c920` | `0xfffffe0007e5c928` -> `0xfffffe000bce7a64` | `0xfffffe0007e5c938` -> `0xfffffe000bce79cc` |

All four pointers are members of original authenticated chained-fixup records, with their format8 fields preserved. Callback bodies and calls are captured. The jetsam adopt callback adds the task's+0x620/+0x628 links to a coalition queue. The outer adoption helper increments active/reference counters and stores the coalition at `task+0x600+8*type` at `0xfffffe000bce90fc` / `...9218`, after the applicable callback succeeds. The first resource entry is required; jetsam is a separately checked optional second entry. Rejection/rollback paths and full reference/lock effects remain distinct from successful publication [CG2,CG3].

The role helper compares its coalition argument against task+0x608 and has an original diagnostic for a nonmember task attempting a role change. This independent consumer anchors slot1 to jetsam, rather than deriving its structure type from offset coincidence alone.

## Initialization, inheritance and external control

| Original initializer output | Global output slot | Type | Role | Privilege argument |
|---|---|---|---|---|
| Init resource coalition | `0xfffffe000cacee88` | 0 | 1 | 1 |
| Init jetsam coalition | `0xfffffe000cacee90` | 1 | 1 | 1 |
| Corpse resource coalition | `0xfffffe000cacee78` | 0 | 1 | 0 |
| Corpse jetsam coalition | `0xfffffe000cacee80` | 1 | 1 | 0 |

The initializer's four direct constructor calls use efficiency0. Original diagnostics distinguish init and corpse outputs. Passing the system-role value1 to both sets does not make the corpse set privileged. The raw image's global cells and constructor output intent are not evidence that native startup ran or that a particular process belongs to one of these coalitions [CG2,CG5].

The captured task-creation body has adoption calls using an explicit supplied array, parent task+0x600, init array at `...cee88`, or corpse array at `...cee78`, according to its control path. The parent jetsam slot is separately consulted afterward. Caller flags, allocator/task epochs, callback results and complete ownership transfers are not synthesized or executed. Task release separately visits both slots and their reference counters.

The recovered syscall dispatcher reads type from flags bits4..7, rejects types above1, then tests the caller's existing coalition pointer and privilege bit before operation dispatch. In its process-relative addressing, the slots begin at process+0xdc0. The named `_get_bsdtask_info` accessor establishes a task-to-process subtraction of0x7c0 on its checked path; `0x7c0+0x600=0xdc0` and slot1 is process+0xdc8. A full64-bit modular proof checks the two address formulas, excluding native pointer validity [CG1,CG3].

For operation1, the binary rejects flags outside0xff3 and passes type, role, privilege and efficiency separately to construction. The public BSD implementation names this privileged-caller check and flag extraction in the same interface family. No syscall is invoked and no creation/admission outcome is tested. [Apple BSD coalition interface](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/sys_coalition.c).

Five aligned direct constructor call sites are found in the searched kernel text: four in initialization and one in the syscall dispatcher. This excludes indirect callers, other images and runtime-generated code. The syscall caller's membership requirement precedes its requested privilege flag; requested creation privilege is not independently sufficient admission [CG4,CG5].

## Service-port and return-path consumers

At `0xfffffe000bce01f0`, the selected service construct path resolves the current task, loads task+0x608, requires it nonnull, loads coalition byte+0x28 and requires bit0. It then continues through additional task/options/service-info/label conditions already bounded in the [endpoint report](launchd_service_endpoint_report.md). A privileged coalition is one prerequisite, not the complete construction policy.

At `0xfffffe000bcd5edc`, the selected receive-publication branch resolves the current task and checks the same coalition pointer/bit. This branch already requires the relevant object classes and receiver state6. Saved-name equality and context restoration follow. Thus the earlier unexplained receiver metadata gate is specifically a jetsam-coalition privilege condition. The complete object/label/name epoch and actual native membership remain open [CG1-CG5].

This condition matters to the daemon/kext interaction as part of service endpoint creation and receive-right return infrastructure. It does not identify slot34's receiver or prove that a FairPlayIOKit request reached fairplayd. Public service name, process identity and effective coalition membership remain different evidence obligations.

## Search scope, assumptions and falsification

The locator scans2,537,551 aligned instruction words in the kernel's10,150,204 B `__TEXT_EXEC,__text`, finding64 immediate64-bit loads and six stores at encoded offset0x608. The store hits include unrelated debug-register storage, globals, network objects and self-linked records. Indexed adoption stores at `...90fc`/`...9218` are absent by definition. Paired/vector/unscaled accesses, aliases, other sections/images and runtime writers are outside this census. Constructor callers use a separate aligned direct B/BL scan. Neither search proves a complete writer/caller inventory.

| ID | Assumption / dependent result | Static stress test / falsification probe | Remaining boundary |
|---|---|---|---|
| CG1 | The current-task result, process-relative alias and membership pointer refer to valid matching objects | Verify original named accessor, exact tail target, checked BSD accessor and both slot formulas | Actual task/process epoch, runtime identity, authentication and object validity unknown |
| CG2 | Constructor/adoption success publishes the captured coalition and flag | Follow callback bindings, return-dependent stores, privilege/role separation, init/corpse distinctions and rollback boundaries | Native initialization/allocation/callback success unknown |
| CG3 | Membership, reference and list state remain consistent until consumer reads | Preserve complete bodies, separate indexed slot, task-role list links, counters and release paths | Locks, concurrent changes, retirement and complete native ownership unknown |
| CG4 | Public nomenclature corresponds to the selected binary mechanisms | Pin three source hashes/commit, compare fields/arguments/diagnostic names with independently recovered instructions | Exact public-source/build equivalence unknown; source layout is not substituted for binary offsets |
| CG5 | The required coalition condition is the relevant caller/receiver's effective membership at use | Trace consumer current-task loads and all captured task adoption choices; preserve further object/options/name gates | Native launchd/fairplayd membership, syscall admission and service/guard outcome unknown |
| CG6 | Bounded locator and compiler-body capture reflect their stated scope | Recompute text hash, aligned locators, direct callers and full body decodes; reject altered evidence | Aliases, wider/indexed stores, indirect callers, other images and runtime code excluded |

## Bounded continuation context

| Impact | Remaining interface question | Concrete next anchor |
|---|---|---|
| High | Effective native launchd/fairplayd coalition membership | Correlate existing read-only environment evidence with the relevant task/coalition epoch; numeric IDs alone do not expose this private privilege bit |
| High | Endpoint callback causes job readiness/relaunch | Follow launchd callback+0x90/reason1 and asynchronous reset block after notification69 |
| High | Retained send name and label remain associated through actual handoff | Join reverse-map insertion/removal, port-label lifetime and task-space ownership for the same object |
| Medium | Complete membership/coalition lifetime | Extend type callback removal, rollback and final release/retirement while preserving active and reference counters separately |
| Medium | Spawn/cohort selection and external policy | Correlate supplied/inherited coalition arrays with their actual producer and caller predicates; keep creation privilege distinct from requested task role |
| Low | Public-source correspondence coverage | Extend additional fields only after original-byte consumers/producers support each name |

## Verification and quality gates

Source recapture matches the capture. Checks pass62 selected instruction assertions, four original authenticated type-operation bindings, six installed SDK width assertions in one arm64 compilation, three full-domain scalar proofs,8192 numeric flags inputs and six rejected evidence alterations. The numeric bank accepts128 flag patterns under the selected scalar operation1 predicate; this excludes caller privilege and native admission. Three immutable public-source files were fetched/hash-checked during the explicit metadata capture; ordinary validation is offline and does not refetch them. [Recovery](triage_evidence/recover_coalition_service_gate.py), [validator](triage_evidence/validate_coalition_service_gate.py), [delivery](triage_evidence/coalition_service_gate_delivery.json), [quality gates](triage_evidence/coalition_service_gate_quality_gates.json).

Capture/search complexity is O(B+F+I) time/space for original bytes B, fixups F and selected instructions I; each bounded text scan is linear in its section extent. Slot selection and scalar flag predicates are O(1) time/space. Fixed-width solver queries state their domains and do not prove target execution, unbounded concurrency or general solver runtime complexity.

QG1: Descriptive interface and provenance analysis; no normative premise required.

QG2: CG1-CG6 register assumptions, dependent claims, falsification probes and unknowns.

QG3: The previously unnamed metadata field/flag is connected to original task, coalition, constructor, membership, initialization, syscall and service consumers; the full goal remains active.

QG4: Pointers/IDs are64 bit, types/roles/counters32 bit and the tested field is a byte bit. SDK widths, indexed slot arithmetic and scalar formulas are explicit.

QG5: Privilege, role, PID identity, requested flags, current membership and complete native admission remain distinct. Immediate-offset scans are not promoted to exhaustive writer inventories.

QG6: Original pinned bytes/exports/fixups/diagnostic strings, source recapture, three pinned primary naming references and checked instructions supply provenance; exact source/build equivalence remains unknown.

QG7: Continuation anchors are bounded and impact-labeled. No native membership, service admission, guard state, ownership or FairPlay-success conclusion is asserted.
