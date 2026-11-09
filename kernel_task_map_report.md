# Named task/map accessors, send source map and replacement handoff

Exact original nlist symbols identify `_current_task` at `0xfffffe000bd41ac4` and `_get_task_map` at `0xfffffe000bd7e658`. The first tail-calls the validated thread-owner lookup already used by the copyin predicate. The second reads/authenticates task+`0x28` with modifier incorporating field address and `0x5ef8`. This establishes that the preceding predicate's R/A chain is the current task and its task map; complete private structures and lifetime guarantees remain unknown. [TM1-TM4]

The original Mach send prefix instead takes its source map from thread+`0x428`, with modifier incorporating `0x9e54`. Task map and thread current map are separate fields that can alias or differ. Original map replacement `0xfffffe000bd7e78c` updates the task field and one selected thread field, returns the old map, and conditionally requests lower map switching and new-map cleanup. The inspected direct caller publishes the returned pointer at caller-record+`0x2f8`. No native map switch, VM retirement or complete lifetime is established. [TM3-TM8]

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| TM1 | The original hash-pinned collection is the relevant static build | Symbols, fields, instructions and direct references | Rehash, recapture and verify actual loaded UUID/slide separately |
| TM2 | Exact symbol names describe their original public accessor roles | Current-task and task-map type identities | Compare original accessor semantics/callers; names do not recover complete private type definitions |
| TM3 | Owner range/placement/tag3/backlink fixtures are valid | Original task lookup and replacement's task/thread association check | Validate native metadata, object lifetimes and all writers; private validity is not native provenance |
| TM4 | Valid task/map/thread objects have the supplied fields and do not overlap unexpectedly | Alias/distinct-map cases and pointer stores | Establish native object identity, aliases and epochs; old/new aliasing is not tested here |
| TM5 | Task lock is initially0, thread identifier7, private lock-control global0 and pending-work flags0 | Uncontended acquire/release and normal return | Exercise contended paths, real identifiers, callbacks and concurrent changes independently |
| TM6 | Lower switch, lock and removal calls return normally; logical PAC applies | Final private state and source-control continuation | Inspect native hardware/VM/reference effects and authentication; these calls are modeled |
| TM7 | Raw task+`0x6c8` bit4 and map flags have the stated values | Conditional cleanup branch and preservation of bit25 | Recover bit writers/meaning; null replacement is tested only for a remote recipient with bit4 set |
| TM8 | Finite CPU/oracle cases and bounded scans support only their stated domains | Counts, caller publication and candidate writer inventory | Rebuild/replay, inspect indirect calls and alternative signature constructions; no closed call graph or native synchronization proof follows |

Primary image: `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. [Source capture](triage_evidence/kernel_task_map_source.json) retains six compiler-bounded functions /329 instructions,11 exact role checks, named symbols and bounded caller/signing windows. No IDB mutation or native target operation is performed. [TM1,TM2]

## Two map roots and sender context

```text
current thread (TPIDR_EL1)
    |
    +0x420 -> validated owner node -- +0 backlink must equal thread
    |                                  |
    |                                  +0x28 -> task
    |                                             |
    |                                             +0x28 -> task map
    |                                             |       DA modifier0x5ef8
    |                                             +0x318 -> IPC space
    |
    +0x428 -> thread current map -> Mach send source map
              DA modifier0x9e54

task map == current map: one object's bit25 supplies both views
task map != current map: distinct source-map and task-map policy inputs
```

| Original accessor / slice | Site | Established local contract |
| --- | --- | --- |
| Exact `_current_task` | `...bd41ac4`-`...bd41ad0` | MRS TPIDR_EL1; tail-call `...bd7e9c4` |
| Owner lookup | `...bd7e9c4`-`...bd7ea54` | Validate thread+`0x420` node and backlink; return node+`0x28` |
| Exact `_get_task_map` | `...bd7e658`-`...bd7e680` | Load task+`0x28`; null returns0; otherwise authenticate and return pointer |
| Send prefix task/space | `...bcdd380`-`...bcdd39c` | Original task lookup then task+`0x318` space load/authentication |
| Send prefix source map | `...bcdd3a0`-`...bcdd3b0` | Thread+`0x428` load/authentication |
| Pre-allocation boundary | `...bcdd458` -> `...bcc24a4` | Private contexts pass send bytes384, auxiliary0, descriptor count2, flag0; no allocation/send executes |

The accessor normal paths acquire no additional task/map reference: the task-map accessor has no source memory write; current-task lookup writes only its saved frame. The caller must supply lifetime context; the returned pointer is not thereby established as an independently owned reference. These facts strengthen the type interpretation in the [copyin policy report](kernel_copyin_policy_report.md). [TM2-TM6]

Eight shared contexts combine original current-task, task-map and send-prefix components. Two contexts alias task/current map; four use distinct nonnull maps; two have a null task-map field while the current source map is nonnull. These are explicit private states, not observed native scheduling states. In all eight, the send prefix selects the thread current map and task IPC space. When maps alias, differing bit25 values would be contradictory fixtures; those combinations are excluded. [TM3-TM5,TM8]

## Replacement ABI, lock and cleanup split

The stripped routine at `0xfffffe000bd7e78c` consumes X0=task, X1=recipient thread, X2=new map. It validates the recipient's owner node and requires its task value to equal X0. Its fast path acquires task+8 using CASA, updates the map fields under a private preemption counter, and releases the lock using CASL. Slow/contended and pending-work branches remain outside the fixtures. [TM3-TM6]

| Original site | Established contract |
| --- | --- |
| `...bd7e81c`-`...bd7e824` | Recipient's owner-associated task must equal supplied task |
| `...bd7e840` | Fast acquire of task+8; fixture owner identifier7 |
| `...bd7e85c`-`...bd7e874` | Load/authenticate old task map and preserve it in X22 |
| `...bd7e888` /`...bd7e8c4` | Store signed new map or null at task+`0x28` |
| `...bd7e8a0`-`...bd7e8d0` | Sign/store new map or null at recipient+`0x428` with field-specific modifier |
| `...bd7e8d8`-`...bd7e8e8` | Call lower switch helper only when recipient equals current thread |
| `...bd7e91c` | Fast release of task+8; final private lock word0 |
| `...bd7e92c`-`...bd7e934` | Raw task+`0x6c8` bit4 clear selects new-map helper `...bdd0208` |
| `...bd7e938` | Return old map in X0; no explicit old-map release in this normal path |

The private replacement cases yield:

```text
task.map := new_map
recipient.current_map := new_map
if recipient == current_thread: request lower switch(current_thread,new_map)
if task_bit4 == 0:
    new_map.flags |= 0x100
    new_map.field_b8 := 0
    request range removal(new_map,min_offset,max_offset,0,0,...)
return old_map
```

The final branch modifies the new map, not the returned old map. All tested bit4-clear cases have a nonnull new map. They preserve bit25 while setting bit8 and clear new-map+`0xb8`. The task bit's semantic name is unknown from this evidence. The lock/flag/owner/range pattern is source-correlated with `vm_map_terminate` in the [archived VM reference](triage_evidence/xnu_osfmk_vm_vm_map.c); the helper has no exact nlist name, and that separately versioned reference does not establish the complete native type layout. [TM4-TM8]

The eight current-recipient cases issue lower-switch requests; remote-recipient cases leave the current thread's private map unchanged. No native hardware switching, inter-thread coordination, locking correctness under concurrency, or reference-transfer convention is proven. Native caller preconditions may exclude some private states. [TM4-TM8]

## Caller publication and bounded writer inventory

The direct A64 BL scan finds one call to this replacement routine, at `0xfffffe000c29edb4`. Original preceding instructions supply task from SP+`0x38`, recipient from X22 and new map from X26. The original following store at `...c29edb8` writes X0 into caller-record+`0x2f8`, before the next helper call. This establishes immediate return publication; the record's complete type, later consumer and old-map retirement remain unknown. [TM1,TM8]

The scan covers15,490,987 instruction words. A separate filter selects MOVK of`0x5ef8` into high16 followed by PACDA within16 instructions; it yields seven candidate windows. Candidates can include nearby authentication and stores for another field, so seven is not a count of established task-map writers. [TM8]

| Store / candidate | Native observation | Evidence boundary |
| --- | --- | --- |
| `...bd7e888` /`...bd7e8c4` | Task-map replacement / null store | Typed by validated association and named accessor; full local path executed |
| `...bd7e8d0` | Recipient current-map store | Full local path executed |
| `...bd41e34` | Store after signing with`0x5ef8` | Inherited object/register provenance remains unresolved |
| `...bd420a0` | Store at object+`0x28` after signing | Inherited object/register provenance remains unresolved |
| `...bd4210c` | Store through signed-field address | Inherited object/register provenance remains unresolved |
| `...bd54da8` | Signed-field read followed by current-map-shaped store using`0x9e54` | Candidate initialization relation; complete caller/type context not established |

Alternative PAC constructions, indirect calls and arbitrary pointer aliases are excluded from the scan's completeness claim. The original [map-context report](kernel_reply_copyout_report.md) separately captures temporary current-map save/restore. Together, these show why task-map identity, thread current-map identity and copy-object/mapped-region ownership must remain distinct. [TM4,TM8]

## Validation and remaining interfaces

[Profiles](triage_evidence/kernel_task_map_profiles.json) retain42 components: eight current-task accessors, eight task-map accessors, eight original send prefixes and18 map replacements. Replacements vary current/remote recipient, null/nonnull old map, new-map bit25 and raw task bit4. Two remote-recipient cases use null replacement with bit4 set; no null replacement is passed to the modeled lower switch. [TM3-TM8]

[Checks](triage_evidence/kernel_task_map_checks.json) recapture original source/scans and independently replay3,118 visits,784 reads /5,070 bytes,420 writes /3,112 bytes and42 final boundaries. They check18 acquire/release pairs, eight lower-switch requests, eight new-map range-removal requests,47 logical data-authentication steps and32 logical signing steps. The independent state oracle verifies task/recipient/current map results, old-map returns, cleanup flags and unchanged source contexts. All24 lower VM/switch/lock callbacks are explicit models. [TM5,TM6,TM8]

Reproduce in order:

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_task_map.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_task_map.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_task_map.py
```

Time is O(instruction words + candidate windows + source visits); space is O(collection metadata + captured profiles + one private CPU map). No native target, IPC, VM removal, hardware switching/PAC, IDB mutation or saved-memory update is performed. Original inputs remain preserved. The full interface investigation remains active. [TM1-TM8]

| Impact | Remaining bounded interface | Evidence needed |
| --- | --- | --- |
| High | Real sender map alias / policy inputs | Attest daemon sender's task map, current map, field flags and context epoch together |
| High | Old-map retirement | Trace caller-record+`0x2f8` readers, error paths and releases |
| High | FairPlay mapped-region lifetime | Connect record0's mapped bytes to context publication, page callbacks and close/unwire/free |
| Medium | Replacement synchronization | Inspect slow locks, other threads, pending work, old/new aliasing and lower switch semantics |
| Medium | Additional signed-field writers | Establish full register/type provenance for the four candidate store families |

- QG1: Pass. Factual accessor, ABI and lifecycle analysis.
- QG2: Pass. TM1-TM8 identify assumptions, dependencies and falsification probes.
- QG3: Pass for named roots, sender source map and local replacement; native lifetimes and full exchange remain open.
- QG4: Pass. u32/u64 widths, field offsets, instruction/byte counts and complexity are explicit.
- QG5: Pass for scope. Aliased/distinct map contexts, null cases, old/new cleanup targets, fast-lock and modeled effects are separated.
- QG6: Pass. Original symbols/bytes, fresh scans/replay, separate state oracle and source-correlation limits are retained.
- QG7: Pass. Impact-labeled continuation covers immediate unresolved map/pager interfaces.

Publication checks: [preservation](triage_evidence/kernel_task_map_delivery.json), [scoped gates](triage_evidence/kernel_task_map_quality_gates.json).
