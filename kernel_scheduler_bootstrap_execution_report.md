# Original-main scheduler, processor-set and bootstrap processor initialization

The next original-main call reaches two different outcomes under two explicit inputs. The unchanged missing-`cluster-type` input preserves the complete 831956-visit predecessor prefix, then reaches the original invalid-CPU-class diagnostic. A separate tree containing u32 `cluster-type=0x45`, declared before main starts, produces CPU type 1, initializes processor-set type 0 and the bootstrap processor, and returns to main at `0xfffffe000c639e48`. No scheduler leaf-result model or midexecution topology repair is introduced. Independent replay checks 1674616 visits across the two cases. Native tree admission, actual scheduling, hardware PAC and matched FairPlay transport remain unknown. [SB-A1-SB-A7]

```text
original main c639a40 -> original DT parser -> CPU/cache/context setup
  -> c639e44 BL bd17314
       locks -> bd16d94 CPU-class partition
         missing property -> class 0 -> original diagnostic c62a2b0
         declared E=45 -> class 1 -> set type 0
           bd170dc -> queues -> set dictionary
       select bootstrap set -> root-node list / membership masks
       five self-linked queue heads
       tail B bd174a4(processor, ordinal, set)
         original diagnostic -> processor fields -> four callouts
         locks -> membership / state -> processor list / ordinal array
  -> c639e48, original main frame and callee-saved registers
```

All shortened kernel addresses in the diagram have prefix `0xfffffe000`. Primary evidence is the pinned collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, [captured source and records](triage_evidence/kernel_scheduler_bootstrap_execution_checks.json.zst), [two complete cases and audit](triage_evidence/kernel_scheduler_bootstrap_execution_audit.json.zst), [CPU predecessor](kernel_cpu_initialization_execution_report.md) and [topology/identity analysis](kernel_boot_cpu_identity_report.md). The [recovery](triage_evidence/recover_kernel_scheduler_bootstrap_execution.py), [producer](triage_evidence/probe_kernel_scheduler_bootstrap_execution.py), [independent replay](triage_evidence/replay_kernel_scheduler_bootstrap_execution.py), [audit](triage_evidence/audit_kernel_scheduler_bootstrap_execution.py) and [delivery verifier](triage_evidence/verify_kernel_scheduler_bootstrap_execution_delivery.py) reproduce this increment. Pinned references were sufficient; no IDB access or modification was required. [SB-A1]

| Input / result | Missing property | Declared E property |
| --- | --- | --- |
| Serialized tree length | 812 B | 852 B |
| Property bytes | absent | `45 00 00 00` |
| Original CPU-record type | u32 0 | u32 1 |
| Scheduler entry visit | 831956 | 833924 |
| Scheduler-interval visits | 91 | 8645 |
| Complete main-case visits | 832047 | 842569 |
| Reads / writes | 194871 / 121182 | 197119 / 124199 |
| Scheduler helper entries / returns | 2 / 0 | 23 / 23 |
| Final mapped pages / bytes | 1083 / 4435968 B | 1089 / 4460544 B |
| Boundary | original diagnostic entry | original main PC `0xfffffe000c639e48` |
| Inherited API models / added models | 2 / 0 | 2 / 0 |

The E case is a fresh run from the original main entry, not an extension of the class-0 trace. The only private input changes are the complete serialized tree at `0x6500010000` and its u32 extent at boot argument address `0x6500004068`. The audit compares the whole initial 1048576 B private RAM against the predecessor with precisely those replacements. Original entry PC, SP, NZCV, all GPRs/vectors, initial logical system state, image fixtures and architectural input profile match. The producer does not repair a CPU record after main starts. The E input adds 1968 visits before scheduler entry, so predecessor-prefix equality is claimed only for the missing-property case. [SB-A2-SB-A5]

The original parser first clears CPU-record+0x14 at `0xfffffe000be83808`. In the E case it subsequently stores u32 1 at `0xfffffe000be838b8`. The common instruction at `0xfffffe000be838e0` clears a stack slot; it is not the class store. The audit checks both actual E-case stores and the single missing-case store, including PCs, widths and values. [SB-A1-SB-A2]

| Property / source classification | CPU-record type | Scheduler processor-set type | Evidence scope |
| --- | ---: | ---: | --- |
| `E`, `0x45` | 1 | 0 | Original source and returning E case |
| `P`, `0x50` | 2 | 1 | Captured source and classifier branch proof; no complete P case |
| `M`, `0x4d` | 3 | 2 | Captured source and classifier branch proof; no complete M case |
| Missing / unrecognized | 0 | invalid admission | Missing-property case reaches original diagnostic |

The classifier's accepted CPU values and processor-set values are distinct domains. In particular, a valid E CPU produces set type 0; CPU type 0 is rejected by this classifier. Missing-property execution stops before the original diagnostic body at `0xfffffe000c62a2b0`, with format X0=`0xfffffe000704e91b`, invalid W14=0 and stack arguments `[u64 0, file pointer 0xfffffe000704e865, line 0x833]`. The decimal source line is 2099. All three 16896 B set-storage regions remain unchanged there, and no processor ordinal-array publication occurs. No native panic or diagnostic output is claimed. [SB-A1-SB-A3]

| Routine interval, end exclusive | Words | Source-established role / actual ABI |
| --- | ---: | --- |
| `0xfffffe000bd17314..0xfffffe000bd174a4` | 100 | Scheduler bootstrap; called by BL at main `0xfffffe000c639e44` |
| `0xfffffe000bd16d94..0xfffffe000bd170dc` | 210 | Partition cluster CPU membership by CPU type; W0=boot-cluster index, X1=topology base |
| `0xfffffe000bd170dc..0xfffffe000bd17314` | 142 | Processor-set initialization and dictionary publication; X0=set |
| `0xfffffe000bd174a4..0xfffffe000bd17900` | 279 | Bootstrap processor initialization; X0=processor, W1=ordinal, X2=set |
| `0xfffffe000bd212b0..0xfffffe000bd21468` | 110 | Paired queue-descriptor construction; X0=set+0x858, X1=set |
| `0xfffffe000bd2d3cc..0xfffffe000bd2d448` | 31 | Nested queue-record initialization; six actual queue pointers |
| `0xfffffe000bd2507c..0xfffffe000bd25208` | 99 | Processor/set class-byte exchange; actual X0=processor, W1=0, old byte all ones |
| `0xfffffe000bd2173c..0xfffffe000bd219c8` | 163 | Set membership-dependent update; actual X0=set, W1=0, selected quick return |
| `0xfffffe000bd67f08..0xfffffe000bd6809c` | 101 | Callout idle fields and pointer handling; X0=processor, W1=slot 0..3 |
| `0xfffffe000bd0bfa4..0xfffffe000bd0c004` | 24 | Preemption-guarded lock acquisition; actual global bootstrap lock |
| `0xfffffe000bd0c2cc..0xfffffe000bd0c340` | 29 | Lock release, preemption decrement and restoration |
| `0xfffffe000bd33474..0xfffffe000bd3373c` | 178 | Locked processor-state update; actual processor, mode 0, enable 1 |
| `0xfffffe000be7c458..0xfffffe000be7c550` | 62 | Exact original symbol `_lck_spin_assert`; actual expected-held argument 1 |

These 13 added bodies contain 1528 words, or 6112 B. Retained capture totals 224 functions /19678 words /78712 B. Exact original symbols for the other 12 new entry points are unknown in the pinned symbol table; the listed roles describe source behavior. The E case calls the set initializer twice. The first call occurs before bootstrap-set publication and performs full queue construction. The second observes that the selected set equals the now-published bootstrap set and skips that work while retaining common setup and dictionary publication. They are different caller epochs in one original execution. [SB-A1-SB-A3]

The bootstrap CPU ordinal is u32 0. The classifier reads the original topology arrays: CPU record `0xfffffe0007ef8260`, 136 B stride; cluster record `0xfffffe0007ef8ae0`, 88 B stride; topology base `0xfffffe0007ef8be8`. Scheduler entry loads the boot-cluster pointer through base+0x38, then passes its u32 index and the original topology base to the classifier. Cluster index 0 has CPU membership bit 0. Captured mixed-type logic uses topology cluster count when allocating additional set IDs; this is not the maximum-cluster-index field. Mixed/multiple clusters remain outside these two complete cases. [SB-A1-SB-A2]

In the E case, set storage starts at `0xfffffe000cad0800`, with 16896 B (`0x4200`) stride. Its u8 set ID and cluster ID are both 0, u32 type at+0x3f60 is 0, and u64 CPU membership at+0x50 is 1. The bootstrap selection scans the three candidate set records for the ordinal bit. Type selects a root node with 64 B stride at `0xfffffe000cad0118`; original high-bit checking and pointer poisoning remain part of the captured source. Only the valid type-0 path executes here. [SB-A1-SB-A3]

| Publication / field | Width | Returning E-case value / producer |
| --- | --- | --- |
| Bootstrap set `0xfffffe0007e644b8` | u64 | set pointer; store PC `0xfffffe000bd173b8` |
| Selected root `0xfffffe0007e644c8` | u64 | node pointer; store PC `0xfffffe000bd173e0` |
| Root+0 / +0x10 | u64 / u32 | set pointer / type 0; stores `0xfffffe000bd17418` / `0xfffffe000bd17414` |
| Root+0x18 / +0x20 / +0x38 | 3*u64 | set-ID mask 1 / CPU mask 1 / online-set mask 1 |
| Set+0x3f50 / +0x3f58 | 2*u64 | next set 0 / root pointer |
| Set-ID mask `0xfffffe000cbc9618` | u64 | 1 |
| Set count `0xfffffe0007e66d8c` | u8 | popcount 1 |
| Set dictionary `0xfffffe0007e66da0` | u64 | set pointer at index 0 |
| Cluster summary `0xfffffe000cad05a0` | u8, u32, 3*u64 | index 0, CPU type 1, masks `[1,0,0]` |
| Set+8 / +0xc / +0x10 | 3*u32 | minimum CPU 0 / maximum CPU 0 / count 1 |
| Set+0x58 / +0xa0 / +0xa8 | 3*u64 | processor masks 1 /1 /0 |
| Ordinal array `0xfffffe0007ef8f20` | u64 | processor pointer; store PC `0xfffffe000bd178b8` |
| Processor-list head / last | 2*u64 | `0xfffffe0007e644d0` / `0xfffffe0007e64008`, both processor pointer |
| Processor count `0xfffffe0007e6a414` | u32 | 1 |

The independent queue oracle starts from incoming original bytes, applies source layout formulas and compares every byte of each selected record, including padding. It checks 31 priority records at set+0x460+32*j, each `[u64 self, self, all ones, 0xffffffff00000000]`. Twelve 1112 B (`0x458`) records form six base queues at set+0xaf8 and six class queues at set+0x2508. The nested leaf helper receives class-record+8; its clear therefore reaches class-record+0x328, with preceding untouched holes retained. Six pinned per-class table pointers at `0xfffffe000cb628a0` supply record+0x448. Five additional queue-head pairs are self-linked at `0xfffffe000cb0bca0`, `0xfffffe000cadd5a8`, `0xfffffe000cb0c6c8`, `0xfffffe000cadd658` and `0xfffffe000cadd768`. Total whole-record comparison is `31*32 B +12*1112 B +5*16 B =14416 B`. [SB-A1-SB-A3]

The bootstrap processor is `0xfffffe000cac6e18`. Its selected final fields are u64 set pointer+0x20, u32 ordinal+0x64=0, u8 state+4=1, u32+0x690=1, u8+0x6fa/+0x6fb/+0x6fc=0, u8+0x6fd=1 and u32+0x700=`0xffffffff`. The +0x6fd field follows a base adjustment by+0x64 and byte displacement+0x699; calling it processor+0x699 would be incorrect. Processor next+0x678 is zero. Two global lock records finish with u64 owner 0 / state `0x11`; source lock ownership assertions execute. Thread preemption count is 0 before and after, and final logical system state equals scheduler-entry state. Single-CPU atomics do not establish concurrent behavior. [SB-A3-SB-A4]

| Slot | Callback pointer field | Original target | Pointer store PC | Context field |
| --- | --- | --- | --- | --- |
| 0 | processor+0xf0 | `0xfffffe000bd15b88` | `0xfffffe000bd17658` | processor+0xf8 |
| 1 | processor+0x170 | `0xfffffe000bd2df7c` | `0xfffffe000bd17698` | processor+0x178 |
| 2 | processor+0x1f0 | `0xfffffe000be3f2ac` | `0xfffffe000bd176d4` | processor+0x1f8 |
| 3 | processor+0x270 | `0xfffffe000bd2e064` | `0xfffffe000bd17710` | processor+0x278, stored at `0xfffffe000bd17714` |

Each context is the processor pointer. Each callout begins at processor+0xa0+0x80*j, has owner 0/state `0x11`, idle field+0x30 all ones and+0x70 zero. Original PACIA/AUTIA instructions use modifier `0x73d8`; the independent replay checks all four AUTIA operand pairs. PAC remains an explicit logical identity projection. These callbacks are installed and inspected, not invoked by this interval. Exact native signatures, callback behavior, scheduling and timer delivery remain unknown. [SB-A1-SB-A4]

The E case retains 1029 registry callback returns and all six earlier FairPlay lifecycle-pointer stores. It adds the original 82 B processor diagnostic to the prior 207 B character stream, giving 289 callbacks. Four source-proved early logging joins cover 36 original words in that case; the missing-property case retains three joins /27 words. Native console emission is not inferred from private ring-character execution. The processor initializer restores its frame and returns using the LR inherited by the scheduler tail branch: original main SP `0x65000eff40`, X19..X29 unchanged, next PC `0xfffffe000c639e48`. [SB-A3-SB-A5]

Ten nonvacuous QF_AUFBV source queries cover 49 distinct original PCs: topology argument forwarding, the E/P/M classification gates, bootstrap membership selection, root-node addressing/high-bit branch, poison construction, empty-root publication, five queue pairs and bootstrap-processor/ordinal arguments. Five retained logging obligations are also rebuilt. These are local source relations, not a universal proof of the full scheduler. Independent whole-case replay checks every original visit/read/write, logical effect, modeled API event, helper edge, checkpoint, final private RAM, 32 vector registers and all final mapped pages. The host oracle contributes 85 checks across the two cases. [SB-A1-SB-A5]

For the missing case, all 831956 predecessor visits and all earlier read/write/logical journals match exactly. At scheduler entry, whole private RAM, GPRs, SP, NZCV, vectors, system map and all 1069 old mapped-page hashes match. Twelve newly mapped entry pages contain unchanged original bytes; two more pages are acquired later before the diagnostic. No field masking is needed. For E, all inherited initial image pages are exact and newly admitted pages are original; full replay checks its different pre-scheduler path. [SB-A2-SB-A5]

Two controls replace one original word with NOP, keep all declared initial fields identical and still reach the normal scheduler return after 842569 visits. Omitting root-head store `0xfffffe000bd17418` fails root publication; omitting ordinal-array store `0xfffffe000bd178b8` fails processor publication. Both retain only the two inherited API models. Return-PC equality alone is therefore insufficient; the host oracle detects the lost side effect. The delivery verifier rebuilds source, both producers/replays, all 15 source queries and both controls. [SB-A1-SB-A5]

| Artifact | Decoded length | Logical SHA-256 |
| --- | ---: | --- |
| `kernel_scheduler_bootstrap_execution_checks.json` | 3524571 B | `b6e86123edba4ba393d4bd15ed71d28728c62889bae1f702a4df9a2d76736ac1` |
| `kernel_scheduler_bootstrap_execution_audit.json` | 447725571 B | `b1335280cef30c5e4ab08c40288829d21c082fe85e9125a9ac5d941e8e170e73` |

No incoming/outgoing Mach port, right-transfer descriptor, message ID or port-emission site is newly established. Processor pointers, set IDs, callout contexts and CPU masks are in-kernel interfaces; there is no newly established source edge from a daemon request to this interval. FairPlay lifecycle invocation, OSMetaClass runtime state and matched daemon/provider/kext request/reply identity remain open. The full goal stays active. [SB-A6-SB-A7]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SB-A1: Pinned collection/source metadata define this corpus | Routine roles, layouts, store PCs and source queries | Rehash source words, records and dependency artifacts; reject drift |
| SB-A2: Explicit initial fixtures and inherited register profile define each private case | Missing/E branch selection and setup | Compare complete initial RAM and image custody; decode input tree; native tree capture can falsify admission |
| SB-A3: Stable storage and one private CPU delimit atomics | Queue, lock, bitmap and publication effects | Whole-record formulas and independent replay; two altered-source controls; contention requires separate evidence |
| SB-A4: PAC and privileged registers are logical dependencies | Pointer operands, restoration and return edges | Exact operand/system journals; native PAC and privileged execution required for hardware claims |
| SB-A5: Two finite inputs bound continuous execution | Missing diagnostic and selected E return | Rebuild both full cases and controls; no complete P/M/multicluster execution is claimed |
| SB-A6: Installed pointers do not establish callback invocation | Callout and FairPlay lifecycle boundaries | Require actual indirect call plus argument/context provenance before assigning invoked behavior |
| SB-A7: Earlier interface reports do not supply transaction identity | Mach/daemon/kext conclusions | Match concrete port/right/buffer/request/reply epochs before asserting transport continuity |

| Bounded continuation | Impact | Discriminating evidence |
| --- | --- | --- |
| Actual admitted tree and CPU-type encoding | High | Native/loader input provenance; distinguish missing-property diagnostic from authentic hardware topology |
| Original-main continuation after `0xfffffe000c639e48` | High | Continue original source without substituted return; retain declared input and full replay |
| Invocation of the four installed callouts | Medium | Actual timer/scheduler caller, PAC modifier, context and lifetime; installation alone is insufficient |
| P/M and mixed/multiple clusters | Medium | Original ID allocation, topology cluster count, 16896 B set stride and per-root masks under fresh complete cases |
| Producer of inherited CPU+0x240/+0x250 poison | High | Earlier source initialization and authentic register-input provenance, not modeled consumption alone |
| Source diagnostic versus observable output | Low | Preserve exact character stream separately from console and scheduling claims |

Capture, journal reconstruction, host formulas and replay are linear in retained source/events/bytes, with memory proportional to retained journals/pages. The inherited collection walker can rescan child commands quadratically. SMT search is separate, with 30 s per query. Source words are 4 B; all record sizes and arithmetic widths are explicit. No native timing or performance inference is made.

**QG1**: Technical source/ABI analysis requires no normative conclusion.

**QG2**: SB-A1..SB-A7 register assumptions, dependencies and falsification probes.

**QG3**: Routine roles, input control, data/control flow, architectural touch points, Mach evidence boundary and reproducible publication artifacts are covered for this increment; full scope remains active.

**QG4**: Byte widths, queue totals, source words, visits and input replacement are reproducible from pinned bytes and journals.

**QG5**: CPU/set type domains, default/E store PCs, input-dependent prefix differences, interior-base offsets and installed/uninvoked callbacks are explicitly distinguished.

**QG6**: Pinned primary bytes and artifact hashes anchor claims; local nonvacuous source queries, two full replays, independent formulas and two controls check the reported effects.

**QG7**: Native admission, main continuation, callout invocation, additional topology and CPU-field producers are bounded and impact-ranked; no matched FairPlay transaction is inferred.
