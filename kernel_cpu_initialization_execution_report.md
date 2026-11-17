# Continuous early-main CPU, cache and context initialization

The original early-main CPU call now executes cache discovery, mode-0 context-record initialization and the register-installation tail before returning to main at `0xfffffe000c639e44`. The private case adds 10125 source visits to the exact 821831-visit published prefix, for 831956 visits. No new leaf-result model is introduced. Five initial architectural-register values and one banked CCSIDR value are explicitly declared; their native values are unknown. The two inherited API models, logical PAC semantics, startup fixtures and source-proved early logging joins remain premises. Native CPU/cache behavior, FairPlay class invocation and matched daemon/kext IPC remain unestablished. [CI-A1-CI-A7]

```text
published original main / module-pointer signing / phase-3 callbacks
  -> previous frontier: c639e40 BL be780f8
       CPU-data lookup through TPIDR_EL1 -> thread+1c0
       bootstrap identity -> forced MIDR field -> capability table
       be79c6c: MPIDR record -> atomic class bit -> CLIDR/CCSIDR
         -> descriptor fields -> original formatter -> ring characters
       be95490(mode0, CPU): ten context/lock records + statistics
       tail B be487e8(mode0, ordinal, CPU+238, CPU+2d8, 1)
         -> two uncontended locks -> empty context registry
         -> DAIF restoration -> 10 register loads/writes
         -> be94f4c(default literal): 3 masked register writes
         -> 8 register clears + 128 B CPU-field clear
  -> c639e44, original SP/callee-saved registers
  -> scheduler initializer BL: not executed in this case
```

Primary evidence is the collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, [source/profile/records](triage_evidence/kernel_cpu_initialization_execution_checks.json.zst), [complete case and independent audit](triage_evidence/kernel_cpu_initialization_execution_audit.json.zst), [published main predecessor](kernel_main_pointer_signing_report.md) and [earlier CPU identity analysis](kernel_boot_cpu_identity_report.md). The [recovery](triage_evidence/recover_kernel_cpu_initialization_execution.py), [producer](triage_evidence/probe_kernel_cpu_initialization_execution.py), [independent replay](triage_evidence/replay_kernel_cpu_initialization_execution.py), [audit](triage_evidence/audit_kernel_cpu_initialization_execution.py) and [delivery verifier](triage_evidence/verify_kernel_cpu_initialization_execution_delivery.py) reproduce the increment. Reference bytes were sufficient; no IDB query or mutation was required. Original input files and predecessor evidence JSON remain unchanged. [CI-A1-CI-A3]

| Routine / call site | Source-established role / ABI |
| --- | --- |
| Main BL `0xfffffe000c639e40` | Calls `0xfffffe000be780f8` on the existing main frame; next PC `0xfffffe000c639e44` |
| `0xfffffe000be780f8..0xfffffe000be78280` | CPU-data bootstrap/reset; follows TPIDR_EL1 to thread+0x1c0 |
| `0xfffffe000be79c6c..0xfffffe000be7a094` | CPU-class cache discovery and diagnostic; `do_cacheid()` appears in original diagnostic text |
| `0xfffffe000be95490..0xfffffe000be957d4` | Signed mode dispatch; actual call W0=0, X1=CPU-data |
| `0xfffffe000be487e8..0xfffffe000be48bd8` | Context-register tail; actual X0=0, W1=ordinal 0, X2=CPU+0x238, X3=CPU+0x2d8, W4=1 |
| `0xfffffe000bd0c1cc..0xfffffe000bd0c238` | Preemption-guarded owner lock using original atomic acquisition; called twice |
| `0xfffffe000be81fa8..0xfffffe000be82048` | DAIF mask validation/restoration; actual W0=0 |
| `0xfffffe000be94f4c..0xfffffe000be9501c` | Masked register installation from X0 context; actual literal `0xfffffe0007013bf8` |

Exact original symbols for these entry points remain unknown where the pinned symbol table gives no name. Roles are source-derived descriptions, not renamed binary symbols. Six newly admitted bodies contain 846 words; total retained capture is 211 functions, 18150 words, 72600 B. The CPU initializer was already captured but is newly executed continuously in this main case. All source words are checked against the pinned collection. [CI-A1]

| Declared input | Value | Source consumer |
| --- | --- | --- |
| `MIDR_EL1` | `0x410fd0c1` | `0xfffffe000be7816c` |
| `MPIDR_EL1` | `0x100` | `0xfffffe000be79c8c`; low16 matches the inherited CPU record |
| `ID_AA64DFR0_EL1` | `0` | `0xfffffe000be7819c`; low4 zero skips debug-count update |
| `CLIDR_EL1` | `4` | `0xfffffe000be79d54`; one unified L1 |
| `DAIF` | `0x3c0` | Context tail `0xfffffe000be48844` and restore `0xfffffe000be81fc0` |
| `CCSIDR_EL1`, bank CSSELR=0 | `0x3007e01a` | `0xfffffe000be79d74` and `0xfffffe000be79e14` |

The five named registers are present before main starts, not repaired at the CPU call. CCSIDR reads select the separately declared bank using source-written CSSELR. An undeclared bank/register or uncaptured code path stops the producer. MSR, ISB and related effects are recorded as logical state transitions; this does not establish hardware acceptance, cache coherence, interrupt timing, instruction barriers or exception levels. The universal early-phase logging relation is rebuilt for arbitrary incoming DAIF: its nine-word join does not read or supply DAIF. This case nevertheless has the explicitly declared initial DAIF value. [CI-A2-CI-A4]

The bootstrap CPU-data object is `0xfffffe000cac7520`; the inherited thread is `0xfffffe000cbc9d08`. The initializer compares CPU+4 against u32 `0x0100000c`. On inequality it installs this marker, forms the CPU+0x118 self-linked pair, copies the eight-byte literal at `0xfffffe000700dc58` to CPU+0x140, clears CPU+0x128 and writes `0x144`/all ones at CPU+0x148/+0x150. Equality skips that setup and cache/config work; that branch is captured, not newly executed here. Bootstrap-address equality bypasses the SPTM CPU-init call at `0xfffffe000be78164`. The original MIDR update replaces bits16..19 with `0xd`, writes `0x410dd0c1` to `0xfffffe0007ef81c8`, sets three u32 globals to one, and obtains capability 2 from table `[1,2,12]` at `0xfffffe00070135c8`. [CI-A1-CI-A3]

The cache routine scans 136 B CPU records, comparing record+4 with MPIDR low16, then reads class at record+0x14. Class0 selects the 168 B descriptor at `0xfffffe000cb8a810`. LDSETALB at `0xfffffe000be79d18` changes the class byte at `0xfffffe000cb8a808` from 0 to 1. The previous class bit gates repeat initialization. The source has 32-bit shift, signed-offset checks and poisoned pointer alternatives; the successful class 0 case does not establish admission of arbitrary classes or unmatched MPIDRs. With the previous entire class byte zero, it publishes the first-descriptor pointer at `0xfffffe0007ef81d0`; this case avoids the alternate wake-queue call. [CI-A1-CI-A3]

| Cache descriptor offset | Width | Actual field result under the profile |
| --- | ---: | --- |
| +0x00 / +0x04 | u32 / u32 | initialized 1 / unified 1 |
| +0x08 / +0x10 | u32 / u32 | I-labelled and D-labelled capacity 16384 B each |
| +0x18 | u32 | source policy-table code 4, diagnostic `Unknown` |
| +0x1c / +0x20 | u32 / u32 | line 64 B / ways 4 |
| +0x24 | u32 | zero; no selected L2/L3 profile |
| +0x28 / +0x2c | u32 / u32 | 16384 /16384 |
| +0x30 | u64 | zero-extended CLIDR low32 =4 |
| +0x38, seven entries | 7*u64 | all zero instruction-bank snapshots |
| +0x70, seven entries | 7*u64 | first `0x3007e01a`, remaining six zero |

The source formula is line=`16 B << (CCSIDR&7)`=`64 B`; ways=`((CCSIDR>>3)&0x3ff)+1`=`4`; sets=`((CCSIDR>>13)&0x7fff)+1`=`64`; capacity=`64 B *4*64`=`16384 B`. Source arithmetic wraps in u32 where applicable; these declared values do not overflow. The original summary adds the two I/D-labelled fields, emitting 32768 B for the unified profile. This is an exact source diagnostic, not evidence of two independent 16384 B caches. The new original ring stream is 113 B, appended to the preceding 94 B timer diagnostics. The full case has 207 character callbacks and three proved logging joins. Native console emission is unknown. [CI-A3-CI-A5]

Mode0 creates ten records with 144 B stride: u64 owner0 at CPU+0x358+144*j and u64 state `0x11` at CPU+0x360+144*j for j=0..9. Ten original LDADD operations change `0xfffffe000cab3218` from u32 1 to 11; the audit checks every intermediate store. The preceding 1 is source-produced earlier in main. The statistics sign flag is clear, so the alternate counter/slow path is not entered. Modes1..5 and other signed values remain captured branches; allocations, timer install and other register paths in those modes are not claimed executed. [CI-A1-CI-A3]

The common reset clears CPU+0x890/+0x8a0/+0x8b0, sets CPU+0x69 to1, copies u32 CPU+0x1dc to+0x1e0 and clears+0x1dc. It restores its frame and tail-branches to the context helper with the original main LR. The helper requires DAIF bit9, conditionally sets the `0x1c0` mask, increments thread preemption, acquires the global lock at `0xfffffe000cb0bce0` and CPU+0x358 lock, observes an empty context list, releases both and restores preemption/DAIF. Original atomics execute in one private CPU. Contention, debug callbacks, scheduling and concurrent list mutation remain untested. [CI-A2-CI-A4]

| CPU input field | First MSR target | First write PC |
| --- | --- | --- |
| CPU+0x240 | `s3_2_c15_c0_0` | `0xfffffe000be48a8c` |
| CPU+0x250 | `s3_2_c15_c1_0` | `0xfffffe000be48a94` |
| CPU+0x260 | `s3_2_c15_c2_0` | `0xfffffe000be48a9c` |
| CPU+0x270 | `s3_2_c15_c3_0` | `0xfffffe000be48aa4` |
| CPU+0x280 | `s3_2_c15_c4_0` | `0xfffffe000be48aac` |
| CPU+0x290 | `s3_2_c15_c5_0` | `0xfffffe000be48ab4` |
| CPU+0x2a0 | `s3_2_c15_c6_0` | `0xfffffe000be48abc` |
| CPU+0x2b0 | `s3_2_c15_c7_0` | `0xfffffe000be48ac4` |
| CPU+0x2c0 | `s3_2_c15_c9_0` | `0xfffffe000be48acc` |
| CPU+0x2d0 | `s3_2_c15_c10_0` | `0xfffffe000be48ad4` |

The zero current-context pointer selects the original 216 B default literal. Its u64 first word `0x3403` is ANDed with `0xffffffffbffffeff`; its second word `0x30300` is ANDed with `0x3000003ff00`. The helper writes second result `0x30300` to `s3_1_c15_c1_0` at `0xfffffe000be94f88` and `s3_1_c15_c7_2` at `0xfffffe000be94f8c`, then first result `0x3403` to `s3_1_c15_c0_0` at `0xfffffe000be94f90`. Flag bytes+0xd0/+0xd1 are zero, excluding timer helpers and the optional nine-register path. [CI-A1-CI-A4]

The tail then clears its last eight S3_2 destinations at `0xfffffe000be48b10..0xfffffe000be48b2c` and the contiguous 128 B CPU interval+0x258..+0x2d8. The first two destinations retain `0xa5a5a5a5a5a5a5a5`, loaded from inherited poison in CPU+0x240/+0x250. No claim about their intended native meaning or valid hardware value follows. The independent oracle derives all 21 context-register writes in order from incoming field bytes and the literal; it compares the complete final logical system map. [CI-A2-CI-A4]

Validation checks the complete original source/read/write prefix, all fixture records, both inherited API records and all earlier callback/lookup/logging records. At the previous frontier, private RAM, GPRs, SP, NZCV and vectors exactly match the frozen predecessor. All1058 predecessor page hashes match there. The only permitted logical-state projection removes the five newly declared register keys from system dictionaries; no memory or instruction values are masked. The new independent replay covers every visit, read/write, register event, call/return, logging join, whole final private RAM and final mapped page. [CI-A3-CI-A5]

The host oracle reconstructs state from initial pages, fixtures and the prefix, independently computes CPU/cache/context outputs, and compares complete declared regions rather than seeding from output bytes. It derives cache geometry, capability, ten statistics transitions and the register-write sequence. Five existing nonvacuous logging source obligations are rebuilt to justify the DAIF-independent join. No new universal CPU-body SMT proof is claimed. Three controls replace one original word with NOP, preserve all declared inputs and reach the original CPU return, but fail the independent oracle: capacity store `0xfffffe000be79e94`, context-state store `0xfffffe000be95524`, default register write `0xfffffe000be94f90`. The delivery verifier repeats source reconstruction, the positive producer/replay and all three controls. [CI-A1-CI-A5]

| Validation measure | Result |
| --- | ---: |
| Source visits / retained exact prefix | 831956 / 821831 |
| Reads / writes checked by independent replay | 194863 / 121150 |
| Independent CPU semantic checks | 26 |
| CPU helper entries / returns | 8 / 8 |
| Architectural-register reads in the new interval | 131, including logging reads |
| Context-register MSR events | 21 |
| Complete independently computed output regions | 3197 B |
| Final mapped pages / bytes | 1069 / 4378624 B |
| Whole private RAM / vector registers checked | 1048576 B / 32 |
| Retained registry callback returns | 1029 |
| Remaining inherited result models / new models | 2 / 0 |
| Rejected original-word controls | 3 |

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_cpu_initialization_execution_checks.json` | `8245e0bb6e497e585d217800e1a832b0c143610bf4e6d41b4fc64f29b16f8310` |
| `kernel_cpu_initialization_execution_audit.json` | `cd858a7c7983aad79f4db153aaf8d1f2aaaf10464c3577ffa8c14cbafff01b92` |

No incoming/outgoing Mach port, right-transfer descriptor, message ID or port-emission site is newly established. These CPU helpers expose architectural register and in-kernel ownership interfaces, without a source edge tying this interval to a daemon-originated request. The six FairPlay lifecycle-pointer stores and 1029 registry callback returns remain in the unchanged prefix; FairPlay lifecycle-target invocation and matched request/reply identity remain open. The full interface goal stays active. [CI-A6-CI-A7]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CI-A1: Pinned collection/source metadata define this corpus | Routine roles, widths and call sites | Rehash every captured word, original record and predecessor dependency; reject drift |
| CI-A2: Existing boot image/fixtures plus declared profile define private entry | CPU branch, cache class and register values | Preserve fixture records and prefix bytes; reject undeclared register/bank reads; native capture can falsify profile |
| CI-A3: Single-CPU original atomics and stable storage apply | Cache bit, ten counters, lock/return effects | Independent replay and full-region formulas; three changed-source controls; test contention separately |
| CI-A4: Logical PAC and system registers represent dependencies only | Return edges, MSR operands and masks | Preserve explicit event journals; native PAC/privileged execution required for hardware claims |
| CI-A5: Finite positive case and controls bound this execution | Declared-profile correctness and regression relation | Rebuild producer/replay; compare exact prefix and all output regions; other profiles remain unexecuted |
| CI-A6: Empty registries/default context delimit the exercised path | No alternate context/debug/wake calls | Check incoming globals and literal flags; populated-state capture falsifies the selected-path premise |
| CI-A7: Earlier interface evidence does not supply transaction continuity | FairPlay/daemon/Mach conclusions | Require source-matched port/right/request/reply epochs before asserting interaction |

| Bounded continuation | Impact | Discriminating evidence |
| --- | --- | --- |
| Actual CPU-field producers, especially +0x240/+0x250 | High | Trace source initialization before consuming poison; correlate with native register/input evidence |
| Scheduler initializer after `0xfffffe000c639e44` | High | Continue original main without a substituted return; retain current profile and prefix checks |
| Populated context registry and secondary cache class | Medium | Recover actual list/queue ownership and remaining original callees; compare different cache banks |
| Nonzero DFR and alternate configuration modes | Medium | Derive flags/inputs from actual callers; qualify optional helper and timer branches |
| Cache diagnostic aggregation | Low | Retain double-counted source text separately from independently derived unified capacity |

Recovery/capture is linear in source/record size. Prefix reconstruction, oracle and independent replay are linear in journal entries and mapped bytes, with memory proportional to retained pages/journals. The inherited module walker can rescan child commands quadratically. SMT search is separate and bounded to 30 s per retained query. Sizes are bytes; source words are 4 B; arithmetic widths are explicit. No hardware timing or native performance measurement is inferred.

**QG1**: Technical source/ABI analysis requires no normative conclusion.

**QG2**: CI-A1..CI-A7 list dependencies and falsification probes.

**QG3**: Routine roles, data/control flow, architectural interfaces, Mach evidence boundary, reproducible artifacts and publication checks are covered for this increment; the full goal remains active.

**QG4**: Byte widths, u32 wrapping, geometry, counts and complexity are reproducible from pinned source and journals.

**QG5**: Unified-cache aggregation, poison inputs, native register uncertainty, finite-case limits and unexecuted alternate paths are explicit.

**QG6**: Primary bytes and artifact digests anchor claims; independent replay, host formulas and three source controls check effects. Exact unknown symbols remain unknown.

**QG7**: Further CPU-field, scheduler, context and cache investigations are bounded and impact-ranked; matched daemon/kext IPC is not inferred.
