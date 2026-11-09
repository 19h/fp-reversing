# Original free-page gate, PID-1 publication and adaptive zone quotas

The previously supplied cache-fill control now has original producer evidence. A PID-1-associated setup routine clears the byte; a zone-policy routine subsequently sets it to the unsigned comparison `page_free_count <= vm_page_free_reserved`. The same policy routine writes the active local quota at zone `+0x7c`. New component joins consume these source-produced values in original refill without overriding the gate or quota. Original uncontended lock helpers replace the earlier lock-result models. Native process creation, page backing, policy scheduling, authentication and full FairPlay transport remain unknown. [CG1-CG8]

Evidence: [original functions, collection-wide reference scan and counter registrations](triage_evidence/kernel_cache_gate_source.json), [20 CPU components and their memory-transfer graph](triage_evidence/kernel_cache_gate_profiles.json), [fresh startup producer, independent replay/state oracles and three scalar proofs](triage_evidence/kernel_cache_gate_checks.json), [delivery seal](triage_evidence/kernel_cache_gate_delivery.json), [quality gates](triage_evidence/kernel_cache_gate_quality_gates.json). Original KC SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Local reference bytes suffice; no new IDA access, IDB/memory-store write, target process, native VM/IPC or sysctl operation occurs.

## Original routines, stores and counter identity

| Address | Established role / exact symbol where available |
|---|---|
| `0xfffffe000ca92380` | Signed-negative initial sentinel and ordinary nonzero cache-fill gate; original file byte `0xff` |
| `0xfffffe000c266258` | Anonymous PID-1-associated setup/publication routine; two original branches clear the gate |
| `0xfffffe000c2662bc` / `...62f0` | Original zero-byte stores after non-NULL / NULL PID-1 lookup results |
| `0xfffffe000bd7b938` | Anonymous zone-policy routine: gate recomputation, filtered inventory/event state, active quota updates and selected followup request |
| `0xfffffe000bd7b984` | Original store of the unsigned free/reserved-page comparison result |
| `0xfffffe000bd7bb18` / `...bc6c` / `...bb5c` | Original quota growth, decrement and capacity-forced-zero stores |
| `0xfffffe000bd76a6c` | Anonymous allocation-selection cursor perturbation; opaque step result followed by modulo element-count arithmetic |
| `0xfffffe000bd0ae78` | Original uncontended ticket acquisition without changing thread nesting |
| `0xfffffe000bd0aab4` | Original uncontended ticket acquisition with thread nesting increment |
| `0xfffffe000bd0ab18` | Original owner-byte release, nesting decrement and pending-work checks |
| `0xfffffe000c2b9748` | Exact exported symbol `_proc_find`; original setup supplies PID 1 |
| `0xfffffe0007f8c250` | Exact exported symbol `_kernproc`; original setup reads its pointer |
| `0xfffffe000bd5d120` | Exact exported symbol `_thread_call_enter1`; selected policy exits request followup work |

The six newly captured routines have no exact symbols in the original symbol table. Static capture adds 433 instructions to the retained 19 functions, giving 25 complete functions / 3944 instructions. Their role descriptions do not assert recovered source names. [CG1]

| Policy input | Original registration record | Original name / handler association |
|---|---|---|
| u32 at `0xfffffe000cb510e0` | `0xfffffe0007f25360` | `page_free_count`; description identifies the number of free pages |
| u32 at `0xfffffe000cb2a2b8` | `0xfffffe0007f159d0` | `vm_page_free_reserved` |

Both original 80-byte records link their counter pointer, name, `IU` format and authenticated `_sysctl_handle_int` handler. Raw records, fixups, labels and handler symbols are independently recaptured. This identifies the policy's counter inputs without guessing their names from addresses. Counters are compared as unsigned page counts; no byte conversion is performed. Live values, registration/access permissions and native handler authentication were not tested. [CG1,CG4]

## Initial sentinel, publication and pressure-sensitive gate

The earlier [refill report](kernel_zone_refill_report.md) used "phase" as a descriptive fixture label. The original producers now support a more precise operational interpretation:

| Byte state | Established original behavior |
|---|---|
| Negative as signed i8, including file value `0xff` | Policy returns before updating zones or the gate; selected slow-allocation callers request cursor perturbation; deeper cache fill sees nonzero and supplies no current entries |
| 0 | Policy can run; deeper fill is admitted subject to its other prerequisites |
| 1 | Policy can run and normalize the gate again; deeper cache fill supplies no current entries |

Original policy reads the byte with LDRSB and exits on a negative value. Otherwise it writes exactly 0 or 1 from an unsigned comparison. Nonnegative values 2 through 127 are also normalized by that instruction path; no native writer of those values is established. Exact source-level identifier and complete native state lifecycle remain unknown. [CG1,CG3]

The setup routine first invokes an opaque setup call with `(0,0,kernproc,2)`, then `_proc_find(1)`. The non-NULL branch logically signs/publishes the returned process pointer at `0xfffffe000cb51668`; the NULL branch publishes zero. Both clear the gate, store 1 at `0xfffffe000ca92370` and store byte 1 at `0xfffffe000cb81100`. Two CPU prefixes stop before the next original followup call, with its actual `(process_or_NULL,0)` arguments. They do not complete the setup routine or prove native PID-1 creation/lookup behavior. The additional global names remain unknown. [CG2]

The policy transition is:

```text
negative gate -> preserve gate and policy state

nonnegative gate:
  free_pages > reserved_pages  -> gate 0
  free_pages <= reserved_pages -> gate 1
```

Equality and the unsigned boundary `0x80000000 > 0x7fffffff` are tested separately. A fixed-width proof checks comparison equivalence under u32 zero extension. The gate changes cache-prefill behavior; it does not itself establish a failed allocation. The selected nonzero-gate constructor reaches the deeper original zone fallback with nesting held. Existing full magazines can still supply the earlier fast path without this deeper fill. [CG3,CG6]

## Source-written active quota and filtered policy state

The [startup report](kernel_zone_startup_report.md) established a separate bound at zone `+0x7e`; the [refill report](kernel_zone_refill_report.md) identified active quota `+0x7c`. The original policy now connects them. For a source-created zone with a cache, it updates low-water/filter state, evaluates capacity and event-score comparisons, and grows, holds or decreases the active quota. [CG3-CG5]

| Selected field | Recovered policy use |
|---|---|
| Zone `+0x64` / `+0x68` | Shared full-magazine low-water sample / filtered state |
| Zone `+0x6c` / `+0x70` | Shared empty-magazine low-water sample / filtered state for the cached-zone path |
| Zone `+0x74` / `+0x78` | Current event sample / prior filtered event score |
| Zone `+0x7c` / `+0x7e` | Active local quota / startup-computed bound |
| Zone `+0x84` / `+0x8c` | Bound/current capacity-comparison inputs; exact source-level field names unknown |
| Zone `+0x3c`, bit 2 | Set by selected quota reduction/forced-zero paths; leads to a followup request |

The selected score calculation uses u32 operations:

```text
score = (((events << 8) / (15 * CPU_instances)) + 3 * prior_score) >> 2
```

Shifts/products/additions retain source u32 wrap semantics. The tested CPU-instance count is 1, event samples are 0 or 400 and no arithmetic overflow occurs. Original upper/lower thresholds are 1280/128; selected quota changes reset the filter to their midpoint 704. Native sample interval and event rate are unknown; these scores are not measurements per second. [CG4,CG5]

| Admitted selected condition | Original quota update |
|---|---|
| Capacity current is at least its bound, quota nonzero | Set quota to 0 and request selected maintenance followup |
| Capacity below bound, score above upper threshold, quota below startup bound | `min(quota == 0 ? 2 : ((3*quota+2)>>1), startup_bound)` within the tested admitted width |
| Score at/below lower threshold, quota nonzero | Decrement quota by 1 and request selected maintenance followup |
| Other selected conditions | Hold quota while updating filtered state |

Observed updates include 0 to 2, 2 to 4, 200 to the source-created bound 256, 2 to 1, 1 to 0, and capacity-forced 5 to 0. A bounded scalar proof checks that the admitted growth rule increases quota and respects its bound for `quota < bound <= 32767`. It does not establish native trigger reachability. [CG3,CG5]

Hysteresis is source-state dependent: after the actual growth component produces quota 2 and score 704, a linked zero-event policy call produces score 528 and holds quota 2. Zero current events alone therefore do not imply an immediate reduction. In contrast, the separate zero-prior-score probe decrements quota 2 to 1. Inventory filters, event filters, active quota and deferred maintenance request are distinct outputs. [CG5]

Three selected exits request `_thread_call_enter1(0xfffffe000cb7f1f0,0)`. Enqueue results remain models; the worker is not executed. An original authenticated reference to the policy routine exists at `0xfffffe000ca90640`. Its surrounding bytes are retained, including untyped numeric values 60 and 15; the actual callback consumer, invocation cadence and units are unknown. No scheduling interval is inferred from these numbers. [CG1,CG7]

## Original lock ABI and writer-to-refill memory joins

All three uncontended lock helpers execute original instructions in this increment. They increment the ticket byte, compare the previous ticket with the owner byte and follow the original uncontended path. Owner release and nesting changes also execute original instructions. There is no whole-lock result model in any of the 20 cases. [CG4,CG6]

| Lock helper | Thread context on selected path |
|---|---|
| `...bd0aab4` | Increment nesting before ticket acquisition |
| `...bd0ae78` | Acquire a ticket without changing nesting |
| `...bd0ab18` | Increment owner byte, decrement nesting, check declared pending state |

Policy calls balance both zone lock words and restore nesting to 0. Constructor/refill calls preserve the previously established asymmetry: the fast allocator already holds nesting, so deeper acquisition does not add another increment. Contention, instrumentation, pending-work handling and native synchronization guarantees remain untested; relevant control globals are their pinned file-zero values and pending state is declared empty. Original instructions in a private CPU replay do not establish hardware synchronization. [CG4,CG6]

```text
original PID1-associated publication prefix
  -> complete RAM/global transfer + new policy call ABI
       -> original gate comparison and quota growth
            -> complete RAM/global transfer + new constructor call ABI
                 -> original refill -> original bitmap/page fill
                      -> original zero check -> original constructor return

policy produces gate 1
  -> same kind of memory transfer + new constructor call ABI
       -> original fill preserves supplied page/bitmap
            -> original held zone-fallback entry
```

These are explicit component memory joins with new call epochs, not an observed native call stack spanning all components. Every private RAM transfer is the complete 1048576 bytes, and every recorded image-global region is imported. Input plans and all 194 before images are checked. The policy test registry preserves the source-produced count 40, withdraws the earlier synthetic slot-2 allocation-context self marker and verifies that only the selected ID-24 record is created within the scanned policy range. Native registry contents remain unknown. [CG2-CG6]

The three allocator joins patch no gate or quota field. One consumes gate 0 directly from the publication prefix. Another consumes gate 0/quota 2 from the linked policy growth. Both execute original 16-entry bitmap-backed fill, cache pop, complete 256-byte zero check and constructor return. The pressure case consumes source-produced gate 1, preserves its supplied page metadata/bitmap and stops at the deeper fallback with nesting 1. The raw page arena, biased metadata/bitmap bases and page ownership epoch remain explicit fixtures. No process, enqueue, step, lock or whole-allocation return model occurs inside these allocator joins. [CG4,CG6]

## Components and evidence boundaries

| Cases | Tested behavior | Outcome |
|---|---|---|
| 0-1 | Non-NULL / NULL PID-1 lookup model | Both original publication prefixes clear the gate; stop before followup |
| 2 | Original-file `0xff` sentinel | Policy returns without changing gate/zone state |
| 3-7 | Free pages above/equal/below reserve, prior gate 1, unsigned boundary | Gate follows unsigned comparison; re-enable transition verified |
| 8-10 | High event score, quotas 0/2/200 | Quotas become 2/4/256 |
| 11-13 | Low score, quotas 2/1; capacity-bound quota 5 | Quotas become 1/0/0; selected followup calls requested |
| 14 | Source case-8 output, new zero-event interval | Score 704 to 528; quota 2 retained |
| 15-16 | Declared opaque steps 2/8 and cursors 0/63 | Original cursor modulo results 2/7 |
| 17-18 | Source publication/policy output plus admitted raw page fixture | Original constructor returns using source gate/quota |
| 19 | Source policy gate 1 plus the same raw page fixture | Page/bitmap unchanged; held fallback |

The cursor helper requests `(perCPU_state,perCPU_state+40,2,8)` from an opaque lower routine, then updates the u32 cursor modulo the zone's u16 elements-per-granule field. Supplied step results test its ABI/arithmetic. Native randomness, distribution and lower helper semantics remain unknown. The original negative-gate callers are captured statically; these two cursor components are separate call probes. [CG7,CG8]

No new incoming/outgoing Mach port, namespace conversion or native Mach emission is established. PID 1 is a process identifier; the published pointer is a process-lookup result, not an identified Mach right. Existing static RPC emission sites and historical zut trace bounds remain unchanged. This report adds environmental and allocator-control context to the existing original kmsg/notification facilities; it does not establish a fresh notification send or authentic daemon/kext round trip. [CG7]

## Reference-scan scope

The reproducible scan covers 15490987 aligned instruction words in deduplicated executable sections across the original kernel collection. It retains all 1441 ADRP references to the gate's page and 128-byte source windows, then tracks bounded register-derived addresses. Twelve distinct memory sites resolve syntactically to the gate: nine reads and three stores in two writer routines. Three direct calls target the new setup/cursor routines; the policy has an authenticated data reference. [CG1,CG8]

A raw `#0x380` mention at `0xfffffe000bd65024` is unrelated to the gate: its base register does not derive from the gate's page. Offset-text matches alone therefore overstate references. The bounded scan does not prove arbitrary indirect writer/caller completeness, execution ordering or native callback reachability. All claims about the three stores additionally rest on complete original bodies and CPU/effect replay. [CG1,CG8]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
|---|---|---|
| CG1 | Pinned KC bytes, fixups, symbols and counter records identify this build | Rehash input; recapture complete bodies, registration records, pointer targets, strings, code windows and store sites; compare other builds separately |
| CG2 | Opaque initial setup and PID-1 lookup returns are admitted prefix inputs | Replace the models with their original producers and actual process/global context; verify native lookup/creation guarantees and later followup before claiming complete setup |
| CG3 | The supplied page counts, event samples, capacity fields and selected zone registry are component epochs | Recover their producers and actual policy callback consumer; measure native values/cadence before attributing any particular trigger frequency |
| CG4 | Source-created zone/cache metadata, declared current-thread/pending state and uncontended lock control epochs admit selected paths | Replace source-file/pending prerequisites with runtime provenance; separately test contention, instrumentation and pending-work paths; native lock guarantees remain unknown |
| CG5 | Independent filtered-state/quota oracles cover selected policy contracts | Check full zone bytes; test equality/unsigned thresholds, growth/clamp/reduction/forced zero and a linked hysteresis cycle; retain u32 wrap and bound domains |
| CG6 | Complete RAM/globals plus explicit new call ABIs establish component value continuity | Verify parent DAG, exact transfers and patch plans; prohibit child gate/quota overrides; recover actual page creation, registry contents and native callers before claiming full runtime continuity |
| CG7 | Logical PAC and opaque process/step/enqueue results do not establish native authentication, entropy or deferred work | Validate actual keys, process identity, lower step routine, callback scheduling, work completion, backing/retirement and authentic IPC separately |
| CG8 | Complete capture, finite replay and bounded ADRP scanning have distinct scopes | Extend indirect/long-distance reference recovery when justified; retain unexecuted setup, callback, bitmap and lock branches as unknown rather than observed |

## Bounded additional context

| Impact | Finding / remaining opportunity | Consequence |
|---|---|---|
| High | Source writers explain the previously supplied gate and active quota | Gate/quota premises are removed from three constructor joins; native counter/page/registry provenance remains unresolved |
| High | Free-page reserve gates prefill rather than proving allocation failure | Preserve the held fallback and inspect its actual supply path before interpreting pressure as an error |
| Medium | PID-1-associated publication clears a negative initial sentinel | Process setup and allocator policy touch the same global; actual native ordering remains unknown |
| Medium | Filtered score carries state across policy calls | Low current sample count can coexist with unchanged quota; source-produced hysteresis is verified |
| Medium | Original lock variants differ in nesting behavior | Preserve caller-held nesting when composing policy, refill and fallback components |
| Medium | Counter registration metadata identifies otherwise anonymous globals | Names/descriptions/handler pointers provide stronger role evidence than proximity or offsets |
| Low | Callback container values lack established scheduling units | Recover the actual consumer instead of assigning a period from numeric constants |

## Reproduction, independent checks and quality gates

```sh
cd /Users/___/dev/dylex/extracted
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_cache_gate.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_cache_gate.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_cache_gate.py
```

Independent replay imports no probe executor. It checks 7898 original visits, 1689 reads / 10447 bytes, 719 writes / 4627 bytes, nine declared process/step/enqueue models, 98 gate/policy/allocation frames, 12 allocation frames, 20 final boundaries, 640 SIMD registers, 20 system-register values, 5184 final global bytes and 20971520 final RAM bytes. All 20 components have independent full-zone/gate/statistics/cache oracles. Three source-produced gate/quota joins include two complete 256-byte zero-check coverage checks and one held fallback. Thirty-six policy lock-helper entries execute original code; joined allocators also execute their actual lock helper calls. Three bounded scalar queries return `unsat`.

Recovery/recapture costs O(image + instruction words + bounded windows + captured source) time and O(image + windows + source) space. CPU/effect validation costs O(image + visits + RAM + effects) time and O(image + one RAM map + journals) space. Exact solver domains/queries are retained; no solver-complexity bound is asserted.

QG1: no normative conclusion required. QG2: CG1-CG8 record assumptions, dependencies and falsification probes. QG3: new anonymous routines, gate/counter/quota/process/lock interfaces, source-memory joins and Mach-emission boundary covered for this increment; full investigation remains active. QG4: page counters, byte extents, integer widths, score scaling, ticket bytes and modulo arithmetic are explicit; callback/sample time units remain unknown. QG5: initial sentinel versus pressure gate, gate versus failure, active quota versus bound, current versus filtered sample, process pointer versus Mach right and prefix versus returned call remain distinct. QG6: original bytes/fixups/symbols/metadata, exact transfer plans, independent state oracles and CPU/effect replay provide verified local provenance. QG7: bounded extensions and impact labels are recorded above. Scoped gates pass; native complete FairPlay continuity remains unknown.
