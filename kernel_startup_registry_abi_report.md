# Kernel startup registry, callback ABI and mach_ipc registration

The original kernel initialization registry contains 3519 records and 115 distinct callback targets. Original main now executes the complete registry sort, invokes its first original tunable callback, returns into the dispatcher and publishes the next cursor. Entry 123 registers the previously analyzed kernel MIG hash initializer at phase 14, named `mach_ipc`, rank zero, with a null argument. This establishes its startup registration; phase 14 is not executed in this increment. [SR1-SR7]

```text
original main, copied bootargs, original initialized topology alternative
  platform -> clock/options -> CPU topology -> bootstrap thread
  preserved boundary 0xfffffe000c639dd8
  publish timebase callback -> original ratio calculation
  checked label copy -> startup trace record
  original full sort of 3519 records
  tail-dispatch phase threshold 3
    first phase-1 record -> original tunable initializer
      device-tree property -> boot-option override -> actual return
    original cursor += 24; publish cursor
    stop before 0xfffffe000c63037c

later registered phase 14 "mach_ipc"
  entry 123 -> MIG hash initializer 0xfffffe000c62a46c, argument 0
  execution and native startup lifetime remain unknown
```

| Claim | Established result | Dependencies |
| --- | --- | --- |
| SR1 | Original section, all pointer records, callback bodies and phase names | SR-A1 |
| SR2 | Preserved bootstrap state and continuous original main continuation | SR-A1-SR-A3 |
| SR3 | Timebase calculation and two source-produced trace records | SR-A1-SR-A4 |
| SR4 | Full registry permutation/order and callback/cursor ABI | SR-A1-SR-A5 |
| SR5 | All 22 tunable descriptors and selected property/option precedence | SR-A1-SR-A6 |
| SR6 | Independent contracts, source obligations, replay and controls | SR-A1-SR-A6 |
| SR7 | MIG registration, Mach boundaries and bounded continuation | SR-A1-SR-A7 |

Primary provenance is collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, original instruction/data bytes, compiler function starts, nlist queries and format-8 pointer metadata. The preserved normalized kext has SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Reference data sufficed; no IDB was read or modified. Native startup, authentic PAC bits and a matched fairplayd transaction remain unknown. [SR1,SR7]

Artifacts: [capture producer](triage_evidence/recover_kernel_startup_registry_abi.py), [private executor](triage_evidence/probe_kernel_startup_registry_abi.py), [independent contracts/replay](triage_evidence/replay_kernel_startup_registry_abi.py), [source audit](triage_evidence/audit_kernel_startup_registry_abi.py), [delivery verifier](triage_evidence/verify_kernel_startup_registry_abi_delivery.py), [source capture](triage_evidence/kernel_startup_registry_abi_checks.json.zst), [audit](triage_evidence/kernel_startup_registry_abi_audit.json.zst). [SR6]

## Registry and phase inventory

The original `com.apple.kernel/__BOOTDATA/__init_entry_set` interval is `[0xfffffe000cbea1d0,0xfffffe000cbfebb8)`: 84456 B / 24 B = 3519 records, exactly. Each record is `{u32 phase, u32 rank, callback_pointer, argument_pointer}`, with pointers at offsets 8 and 16. There are 88 null arguments. All 115 distinct callback targets belong to `com.apple.kernel`; none has an exact-address nlist name in the retained query. Behavioral names below describe recovered roles. The inventory retains every index, original raw record, logical record, pointer metadata, owner, body hash, source interval and direct BL edge. Capturing a callback body does not establish its complete semantics or execute it. [SR1]

All 3519 callback fixups have format 8, authentication bit 1, diversity `0x2abe`, address diversity 0 and key field 0. For this collection the logical target is `0xfffffe0007004000 + (raw & 0x3fffffff)`; cache-level bits 30..31 are zero. Diversity occupies bits 32..47, address diversity bit 48, key bits 49..50, chain delta bits 51..62 and authentication bit 63. Raw and logical tables are separately hashed. Logical record permutation does not attest runtime PAC bits or loader signing. The initial cursor slot `0xfffffe000cbc9a48` points logically to the section base. [SR1,SR-A4]

| Phase u32 | Original label | Records |
| ---: | --- | ---: |
| 1 | tunables | 392 |
| 2 | timeouts | 10 |
| 3 | locks | 627 |
| 4 | kprintf | 1 |
| 5 | pmap_steal | 4 |
| 6 | kmem | 13 |
| 7 | zalloc | 136 |
| 8 | ktrace | 1 |
| 9 | percpu | 104 |
| 10 | sched | 2 |
| 11 | event | 1 |
| 12 | codesigning | 1 |
| 13 | oslog | 5 |
| 14 | mach_ipc | 45 |
| 15 | thread_call | 9 |
| 16 | sysctl | 2152 |
| 18 | null | 1 |
| 19 | early_boot | 14 |
| 4294967295 | outside label table | 1 |

The phase-name array at `0xfffffe0007e64530` contains 20 slots and 17 nonnull names; slots 0, 17 and 18 are null. No registry record has phase 0 or 17. The phase-event helper treats 17 and 18 specially rather than dereferencing their null name slots. Phase 4294967295 remains an original unsigned record; it is not silently excluded from sorting or interpreted as a callback terminator. [SR1,SR4]

## Original control flow and callback custody

The closure captures 156 distinct functions, 13275 words / 53100 B, including all 31 prior bootstrap functions with matching bytes/ends and all 115 callback bodies. Registered bodies comprise 6589 words, overlapping the closure where applicable. Five opaque words are preserved and unexecuted. Exact nlist names identify `___strncpy_chk`, `_strnlen` and `_memset`; the newly described registry/timebase/tunable routines have no exact-address names. [SR1]

| Original half-open interval | Words | Recovered role |
| --- | ---: | --- |
| 0xfffffe000c62f4e4..0xfffffe000c6302c4 | 888 | Specialized initialization-record sorting and dispatch tail |
| 0xfffffe000c61b4ec..0xfffffe000c61c630 | 1105 | Recursive sorting helper with authenticated comparator calls |
| 0xfffffe000c630754..0xfffffe000c630790 | 15 | Unsigned phase/rank comparator |
| 0xfffffe000c6302c4..0xfffffe000c6303d4 | 68 | Phase-threshold callback dispatcher |
| 0xfffffe000bd3ad04..0xfffffe000bd3ae10 | 67 | Phase advancement, name copy and trace event |
| 0xfffffe000be8b80c..0xfffffe000be8b8c4 | 46 | Timebase validation and reduced-ratio publication |
| 0xfffffe000c26ad94..0xfffffe000c26af10 | 95 | Bounded early trace-record producer |
| 0xfffffe000c6303d4..0xfffffe000c630544 | 92 | Tree/boot-option tunable initialization |

The default run preserves the previous [bootstrap experiment](kernel_bootstrap_state_composition_report.md), component `initialized_page_default_thread`, exactly at `0xfffffe000c639dd8`: visits, reads, writes, declared returns, tracked API entries/returns, full private RAM, fourteen mutable regions, GPR31, SP, NZCV and SIMD state. Common ten logical system inputs match; the new timestamp register input is explicit. Registry/ratio/trace/phase storage and previously untracked tunable destinations receive original logical image contents before main entry. They are independently checked unchanged at the preserved boundary. There is no state reset, callback result injection or call-frame epoch. Original initialized-data lifetime remains a premise. [SR2]

Main calls the sorter at `0xfffffe000c639e38`. The comparator first compares u32 phase, then u32 rank, returning -1/0/+1. Equal pairs have no tertiary key; no stable order is inferred. All three complete original sorts produce an ascending unsigned key sequence and an exact multiset permutation of all 3519 logical 24 B records. The recursive helper's comparator BLRAA uses X19 and X17=`0xe4fe`. Its authenticated transfers retain logical targets under the declared PAC envelope. [SR4]

At `0xfffffe000c630240` the sort tail selects W0=3, restores its frame, then branches to dispatcher `0xfffffe000c6302c4` at `0xfffffe000c630260`. The dispatcher loads the cursor and admits records whose phase is unsigned <= W19. Its debug flag's bit zero is clear in the selected original state. It stores phase-1 to u32[`0xfffffe0007f8b5f0`], calls the phase-event helper, loads X8=callback and X0=argument at `0xfffffe000c630368`, sets X17=`0x2abe`, then emits the callback BLRAA at `0xfffffe000c630370`. [SR4]

The first sorted record is phase 1, rank 0, callback `0xfffffe000c6303d4`, argument `0xfffffe000ca898b8`. Its actual source body returns to `0xfffffe000c630374`, preserving the dispatcher SP. Original ADD advances X24 by 24 and STR at `0xfffffe000c630378` publishes it to the cursor slot. The final cursor is `0xfffffe000cbea1e8`. Execution stops before CMP at `0xfffffe000c63037c`. No next record is admitted. Under unchanged phase/cursor contracts, 1028 other phase<=3 records remain before later phases; their completion and effects are unknown. Main's later helper at `0xfffffe000c639e3c` and CPU initializer call at `0xfffffe000c639e40` have not been reached. [SR4,SR7]

## Timebase and trace data flow

Main constructs callback target `0xfffffe000be8b80c`, applies logical PACIA with X17=`0x2abe` at `0xfffffe000c639de4` and stores it at `0xfffffe000cba4138` at `0xfffffe000c639dec`. It loads u64 frequency from `0xfffffe000cb5c5f8`, pairs it with source-retained X25=1 on its stack, and calls the original callback at `0xfffffe000c639e00`. The diagnostic string explicitly names `rtclock timebase_callback` and `rtclock.c`. [SR3]

For u64 inputs F,D, the helper requires 1<=D<=4 and F>=D, otherwise taking its original diagnostic path. It computes P=(D*1000000000) modulo 2^64 and Euclidean gcd G=gcd(P,F). Its 16 B block at `0xfffffe000ca8c000` stores u32 floor(F/D), u32 `((low32(floor(F/D))*0x431bde83)>>50)`, u32 P/G and u32 F/G. Selected F=24000000,D=1 produces reduced ratio 125/3; F=48000000,D=1 produces 125/6. These are exact source arithmetic words. Native oscillator calibration, physical accuracy and valid-input behavior outside selected paths are unknown. [SR3]

Main uses original checked copy with requested size and capacity both 32 to construct `kernel_startup_bootstrap`, then trace helper call `0xfffffe000c639e34` emits event ID `0x07020010`. The phase helper later emits the same event ID with label `tunables` and publishes u32 last phase 1 at `0xfffffe000cb62ec8`. The selected source mode byte at `0xfffffe0007f1260c` is zero, record counter at +4 starts zero, and source thread low16 ordinal equals global boot ordinal. [SR3]

| Trace-record offset | Width | Source value |
| --- | ---: | --- |
| +0x00 | 8 B | Logical s3_4_c15_c10_6 plus current-CPU+0x58 word, modulo 2^64 |
| +0x08,+0x10,+0x18,+0x20 | 4 * 8 B | X1-X4, carrying the padded 32 B label |
| +0x28 | 8 B | Zero |
| +0x30 | 4 B | Event ID 0x07020010 |
| Other bytes | 12 B | Retained original contents |

Records use 64 B stride at `0xfffffe000cbc0000`; the source counter gate admits indices 0..255. A CPU+0x58 reread loop requires a stable offset. The private timestamp input is `0x123456789`; the CPU offset retains the preceding declared private bytes. Neither is a native time measurement. Six records across three runs are compared independently, including retained bytes. [SR3,SR6]

## Tunable descriptor ABI and external inputs

The original 48 B descriptor contains pointers path+0, property+8, option+0x18 and destination+0x20; path-flags byte+0x10, u32 size+0x28 and normalization byte+0x2c. The initializer performs original tree lookup and property lookup, requires the property's returned length to equal the descriptor size, then calls original memcpy. A nonnull option pointer subsequently invokes the original boot-option parser on the already copied bootargs, with destination, requested size and zero flags. A present option overwrites property data. Absence retains the preceding destination. [SR5]

All 22 registered descriptors have path flags and normalization byte zero. Source paths for a flagged relative lookup under `chosen`, and low-byte Boolean normalization after a present option, remain dormant for those descriptors. Empty option strings in the last two rows are nonnull pointers and remain distinct from null pointers. A property-size mismatch reaches the original diagnostic branch; malformed property/option inputs are not exercised here. [SR5]

All destination addresses in this table share prefix `0xfffffe000`; the printed suffix completes the exact address. Sizes are bytes. [SR5]

| Tree path | Property | Boot option | Destination suffix | Size |
| --- | --- | --- | --- | ---: |
| /defaults | kern.sideband-panic | sideband_panic | 7ef8f18 | 4 |
| /defaults | kern.max_task_pmem | max_task_pmem | cb2a78c | 4 |
| /defaults | kern.swap_min_capacity | kern.swap_min_capacity | 7e69db0 | 8 |
| /defaults | kern.vm_compressor | vm_compressor | 7f275d0 | 4 |
| defaults | kern.gpu_pmem_selector | gpu-pmem-selector | 7f19bf8 | 4 |
| /defaults | kern.entitled_max_task_pmem | entitled_max_task_pmem | cb2a760 | 4 |
| /defaults | kern.entitled_dev_max_task_pmem | entitled_dev_max_task_pmem | cb2a764 | 4 |
| /defaults | kern.memstat_fg_sort_order | memstat_fg_sort_order | 7f1a328 | 4 |
| /defaults | kern.memstat_critical_mb | memorystatus_critical_threshold_mb | 7f1a32c | 4 |
| /defaults | kern.memstat_idle_mb | memorystatus_idle_threshold_mb | 7f1a330 | 4 |
| /defaults | kern.memstat_pressure_mb | memorystatus_pressure_threshold_mb | 7f1a334 | 4 |
| /defaults | kern.memstat_reaper_mb | memorystatus_reaper_threshold_mb | 7f1a338 | 4 |
| /defaults | kern.memstat_ballast_mb | memstat_ballast_offset_mb | 7f1a33c | 4 |
| /defaults | kern.memstat_reaper_minage_secs | memorystatus_reaper_minimum_age_seconds | 7f1a344 | 4 |
| /defaults | kern.memstat_reaper_minapp_secs | memorystatus_reaper_minimum_age_apps_seconds | 7f1a348 | 4 |
| /defaults | kern.memstat_reaper_rescan_secs | memorystatus_reaper_rescan_delay_seconds | 7f1a34c | 4 |
| /defaults | kern.memstat_reaper_enabled | memorystatus_reaper_enabled | 7f1a350 | 4 |
| /product/iopm | aot-mode | aot_mode | cb5c098 | 4 |
| /product/iopm | aot-linger-time-ms | aot_linger_time_ms | 7f89130 | 4 |
| /product/iopm | low-power-wake | low_power_wake | cb5c0a0 | 8 |
| /chosen | esdm-fuses | empty string | 7f8b5c0 | 4 |
| /defaults | vmm-present | empty string | 7f8b5c4 | 4 |

The selected first descriptor supplies `/defaults`, `kern.memstat_pressure_mb`, `memorystatus_pressure_threshold_mb`, destination `0xfffffe0007f1a334`, size 4. The independent contract decodes the original serialized fixture and copied bootargs rather than supplying tree/parser results to execution. Default input preserves zero; property 7 produces 7; property 7 with boot option 13 produces 13. Direct fairplayd control over any boot input is unknown. The `defaults` path without a leading slash in the GPU descriptor is retained exactly. [SR5]

## Mach registration and evidence limits

Original registry row `0xfffffe000cbead58` (index 123) has phase 14, rank 0, callback `0xfffffe000c62a46c`, argument 0. Phase label 14 is `mach_ipc`; the callback's complete bytes/end match the previously captured [kernel MIG initializer](kernel_vm_mig_report.md). That earlier private initializer constructs the kernel MIG hash registry. Registration here supplies a source-supported startup caller relationship; it does not attest native execution, complete all preceding phases, resolve equal-rank ordering, or execute the initializer again. [SR7]

The callback-emission instruction at `0xfffffe000c630370` is a function transfer. No new incoming/outgoing Mach port, port right or Mach-message emission PC is established by this increment. Existing [Mach evidence](mach_ports_report.md) remains authoritative for endpoint inventories. The 3519-row registry is kernel-owned; this capture does not identify FairPlayIOKit kext startup through this section. A daemon/user-client/provider/kernel transaction with matching epochs, payloads, rights and statuses remains unknown. [SR7]

## Verification receipts

Decoded source capture: 6210041 B, SHA-256 `45762fcf5f360ac4e3e96dcf34900c775f96748cd9e2974f0c69c48226881812`. Decoded audit: 295580251 B, SHA-256 `3bec297b43e93af8f51535729e74a4b97afcc305762daadc6780b0fb256fca1a`. The independent registry decoder checks 7056 pointer records and passes 21492 static contracts, including full record/body/descriptor/name evidence. [SR6]

Fourteen new nonvacuous QF_AUFBV queries are UNSAT over 56 distinct source PCs, 64 instruction instances and 50 linked-edge obligations. Premises are SAT before negated contracts are added. Queries establish unsigned comparator paths, threshold admission, callback argument/modifier/LR, cursor advance/publication, phase-minus-one, timebase callback/argument custody, checked-copy capacity, sort tail target, property-size equality, option ABI and conditional low-byte normalization. Eleven prior bootstrap queries are rebuilt against the matched closure. Whole-sort correctness is established for the three finite original runs by complete permutation and order contracts; no general sorting termination proof is claimed. [SR6]

| Private input | Original visits | Timebase F/D | Reduced words | First tunable result |
| --- | ---: | --- | --- | ---: |
| Default property/option absent | 248090 | 24000000/1 | 125/3 | 0 |
| Tree property 7, option absent | 248843 | 24000000/1 | 125/3 | 7 |
| Tree property 7, boot option 13 | 256589 | 48000000/1 | 125/6 | 13 |

The three components pass 4892 independent semantic checks across 753522 visits and 3565 distinct PCs. Independent formulas compare 2061660 mutable checkpoint bytes and 3132672 nonstack private bytes. Thirty-seven finite mutable regions total 137444 B per case. The excluded 4352 B stack guard is checked by full replay. Each case retains exactly three declared earlier no-RAM returns: vector registration, early registration and selector0e wrapper. There is no tunable callback result model. [SR6]

Fresh replay imports no executor. It checks 208983 reads / 1326879 B, 126311 writes / 1007329 B, 994 logical PAC/return steps, 12700 additional logical effects, all nine declared return/clobber contracts and 96 final SIMD values. API tracking retains 13646 entries, 13640 returns and six deliberately unfinished outer sort/dispatch entries at the final boundary. Complete private checkpoint comparisons total 31457280 B; prior-region, bootstrap-extra-region and registry-extra-region comparisons total 998400 B, 77088 B and 2422848 B respectively. Final checks compare 3145728 private bytes and 1036288 mapped-image bytes. Counts overlap across checkpoints/cases and do not imply disjoint native objects. [SR6]

Two privately altered source words are rejected: replacing callback-pointer publication `0xfffffe000c639dec` with NOP violates the pre-sort callback slot, and replacing ratio publication `0xfffffe000be8b868` with NOP violates the pre-sort ratio block. Both complete the same selected continuation and fail independent output contracts. Controls are excluded from positive totals; finite controls do not establish universal decoder/emulator correctness. The delivery verifier rebuilds the complete source/audit, compares all private components and canonical SMT queries, checks publication ownership and original-input hashes, and scans decoded/nested artifacts for analyst paths. [SR6]

## Assumption register and quality gates

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SR-A1: Pinned original bytes/fixups identify this collection | SR1-SR7 | Rebuild 156 intervals, all 3519 raw/logical records, 115 body hashes, 22 descriptors and phase-name pointers; reject other-build reuse |
| SR-A2: Original logical registry/data are explicit pre-entry fixtures | SR2-SR7 | Exact prior bootstrap checkpoint comparison; full new-storage comparison before continuation; native loader/signing/lifetime unknown |
| SR-A3: Selected well-formed trees and copied bootargs define the finite input domain | SR2-SR7 | Independent tree/option/copy contracts, absent/property/override cases; malformed inputs and prior admission unknown |
| SR-A4: PAC/system transfers preserve logical values; earlier leaves have declared no-RAM returns | SR3-SR7 | Exact operands/modifiers, source target/argument/return/SP checks, full journals; no native authentication or clock claim |
| SR-A5: Sort/dispatch contracts use logical records and unsigned u32 keys | SR4,SR6,SR7 | Full permutation/order checks and exact callback/cursor checkpoints; tie ordering remains unspecified |
| SR-A6: Independent formulas, source obligations and fresh replay support selected private behavior | SR5-SR7 | Nonvacuous SMT queries, complete read/write/register replay, source-word controls; shared decoder/emulator limits and unexecuted callback paths retained |
| SR-A7: Registration does not establish a FairPlay transaction or native phase completion | SR7 | Continue original dispatch and pair a matched daemon/provider/kernel epoch; neither is newly observed |

Capture costs O(K+I+R*E+N) time and O(K+I+R+N) space in collection bytes K, source I, registry/data R, scanned owner segments E and symbols N. Source-proof construction costs O(I+Q) in source/formula DAG Q; SMT search is separate, limited to 30 s/query. Execution/replay cost O(V+J+M) in visits V, journals J and mapped bytes M, plus decoding/copy work; independent timeline sorting adds O(J log J), and the multiset/order check costs O(R log R) time and O(R) space. Bounds describe analysis algorithms, not a proven worst-case complexity of the original generic sorter. All calculations use exact little-endian widths and stated modular arithmetic. Nontrivial JSON uses `zstd --ultra -22 -q -T1`, decoded roundtrip comparison and decoded/nested path hygiene. [SR6]

| Impact | Next discriminating work | Evidence sought |
| --- | --- | --- |
| High | Continue original dispatch with actual preceding callbacks and cursor | Establish source-produced state beyond one callback and close the later-main/CPU-initializer gap |
| High | Recover initialized-section/fixup producer and lifetime | Replace private pre-entry data premises with an original loader/entry contract |
| High | Join phase-14 dispatch to the captured MIG hash producer | Establish an uninterrupted startup-to-IPC-registry path while preserving prior phase effects |
| High | Pair a daemon/user-client/provider/kernel transaction | Determine observed FairPlay relevance and actual Mach-right/message custody |
| Medium | Classify remaining callback bodies by their registry arguments and direct calls | Recover additional obfuscated roles without treating section membership as semantic proof |
| Medium | Follow tunable destinations and trace/timebase consumers | Establish downstream effects and physical units beyond raw source words |

**QG1**: Factual technical analysis; no normative content required. **QG2**: SR-A1-SR-A7 state dependencies and falsification probes. **QG3**: Registry/callback ABI, input precedence, timebase/trace flow, MIG registration and Mach limits covered for this increment; full goal remains active. **QG4**: Exact widths, extents, modular arithmetic, provenance and algorithmic bounds stated. **QG5**: Registration versus execution, logical versus native pointers, selected versus all callbacks, tie classes and pre-entry fixtures distinguished. **QG6**: Original bytes, independent contracts, rebuilt source obligations, replay and controls retained. **QG7**: Bounded impact-ranked continuation included. All gates pass for this finite increment; native startup, remaining callbacks and matched daemon/kernel effects remain unknown.


## Continuous tunable batch and formatter boundary follow-up

The [tunable batch execution report](kernel_tunable_batch_execution_report.md) preserves the preceding first-callback state and establishes 368 continuous original callback returns: all 237 compact boot-option descriptors, all 22 tree/option descriptors, 87 per-CPU pointer adjustments and 17 SFI registrations. Original Mach-O UUID lookup enters `_uuid_unparse_upper` and stops before `_snprintf`, with all 16 variadic slots checked. Three private cases pass 14 new source proofs, 14 registry rechecks, 16127 semantic checks and fresh replay; two altered-source controls are rejected. SFI handler invocation, formatter output, phase-14 MIG execution, native startup and a matched FairPlay/Mach transaction remain unknown; the full goal remains active.
