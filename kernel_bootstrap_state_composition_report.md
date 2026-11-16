# Initialized topology data and continuous bootstrap-thread composition

Original main now executes its input copies, platform/environment/clock initialization, timer/options, topology enumeration, post-helper and bootstrap-thread copy/setter continuously in five private cases. The run stops at `0xfffffe000c639dd8` before later main callback setup, with no call-frame epoch. This composition requires a separately declared original initialized topology page. The previous experiment's zero-page fixture is preserved: its recorded pre-enumeration memory, GPRs, SP, NZCV and source history match exactly, then continuation stops before a null record store. Native initialized-data lifetime and startup remain unknown. [SC1-SC7]

```text
same original main inputs and entry registers
  original platform + tree/clock/identity + timer/options
  pre-enumeration PC 0xfffffe000c639cb8
    prior zero topology page
      original pointer load -> count=1, record destination=0
      stop before store 0xfffffe000be83324
    original logical initialized topology page, declared before entry
      original enumeration -> actual main return 0xfffffe000c639cbc
      original post-helper -> actual main return 0xfffffe000c639cc0
      original 1472 B template copy + thread setter
      stop before callback setup 0xfffffe000c639dd8
```

| Claim | Established result | Dependencies |
| --- | --- | --- |
| SC1 | Pinned source, initialized data, logical pointers and exact symbol evidence | SC-A1 |
| SC2 | Exact preservation of the prior private handoff and isolated initialized-page alternative | SC-A1-SC-A3 |
| SC3 | Continuous original enumeration, admission, selected ordinal and return to main | SC-A1-SC-A4 |
| SC4 | Original post-helper default, diagnostic gate and register write | SC-A1-SC-A4 |
| SC5 | Original CPU-map, template/thread fields and setter custody | SC-A1-SC-A5 |
| SC6 | Source obligations, independent byte formulas, fresh replay and controls | SC-A1-SC-A6 |
| SC7 | Mach/lower-facility limits and bounded continuation | SC-A1-SC-A7 |

Primary provenance is original collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, compiler function starts, instruction bytes, nlist and format-8 pointer metadata. The preserved normalized kext remains SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Supplied references sufficed; no IDB was read or modified. These are kernel startup prerequisites; direct fairplayd control over the selected inputs is unknown. [SC1,SC7]

Artifacts: [source producer](triage_evidence/recover_kernel_bootstrap_state_composition.py), [private executor](triage_evidence/probe_kernel_bootstrap_state_composition.py), [independent formulas/replay](triage_evidence/replay_kernel_bootstrap_state_composition.py), [source audit](triage_evidence/audit_kernel_bootstrap_state_composition.py), [delivery verifier](triage_evidence/verify_kernel_bootstrap_state_composition_delivery.py), [capture](triage_evidence/kernel_bootstrap_state_composition_checks.json.zst), [audit](triage_evidence/kernel_bootstrap_state_composition_audit.json.zst). Decoded capture: 780298 B, SHA-256 `69a2cd26f90adf9b35c6a048772d5e36e66e4175c4ab6c041c11e0c3cdc62f4a`. Decoded audit: 76403142 B, SHA-256 `b8a611019e85f0a0aa225907fadb7f52e6e4aee481f1b36bd326c9d51db359cf`. [SC6]

## Source closure and initialized-data prerequisite

Thirty-one intervals contain 4265 words / 17060 B. All 31 match prior captured bytes and interval ends. The closure combines the [platform/environment](kernel_platform_environment_execution_report.md) bodies with five original bodies already captured in the [topology](kernel_cpu_topology_handoff_report.md) and [option execution](kernel_boot_option_execution_report.md) investigations. Sixty exact NUL-terminated strings, four literal blocks, seven initialized-data blocks and three pointer records are retained. The five original routine names below remain unknown: exact-address nlist queries returned no names. Role names describe recovered behavior. [SC1]

| Original half-open interval | Captured words | Recovered role | Executed unique PCs |
| --- | ---: | --- | ---: |
| 0xfffffe000be83068..0xfffffe000be83f8c | 969 | CPU/cluster topology enumeration and boot-record publication | 588 |
| 0xfffffe000be83f8c..0xfffffe000be8408c | 64 | Scalar property reader and width/default checks | 33 |
| 0xfffffe000bc9c7f0..0xfffffe000bc9c824 | 13 | Thread/system-register setter and CPU backpointer | 13 |
| 0xfffffe000be85a48..0xfffffe000be85ad0 | 34 | Post-enumeration option/control helper | 34 |
| 0xfffffe000c620ec4..0xfffffe000c620f00 | 15 | Selector0e lower wrapper; body remains modeled | 0 |

Five opaque words are preserved and unexecuted: the three previously retained words plus two wrapper words. No UDF padding executes. Unique-PC coverage is finite selected-path evidence, not exhaustive coverage of the 969-word enumerator. [SC1,SC6]

The earlier platform experiment deliberately supplied a zero-filled 4096 B region at `0xfffffe0007ef8000`. It established a conditional pre-enumeration boundary, not preservation of all native static initialization. This page also contains the topology descriptor and post-helper control. Its original logical contents differ from zero, including these three slots. [SC2]

| Slot | Original source / logical value | Previous private value | Consumer |
| --- | --- | --- | --- |
| u64[0xfffffe0007ef8c08] | Raw 0x0010000000ef4260; format-8 target 0xfffffe0007ef8260 | 0 | CPU-record array base loaded at 0xfffffe000be832fc |
| u64[0xfffffe0007ef8c10] | Raw 0x0450000000ef4ae0; format-8 target 0xfffffe0007ef8ae0 | 0 | Cluster-record array base loaded at 0xfffffe000be839d0 |
| u32[0xfffffe0007ef8e98] | Original bytes 02 00 00 00; value 2 | 0 | Post-helper fallback when siq_realtime_thread_mode is absent |

The third retained pointer is slot `0xfffffe000ca908b0`: raw `0x00c0000005b5efe0`, format-8 logical target `0xfffffe000cb62fe0`. Main loads that slot at `0xfffffe000c639db4` and stores the new thread pointer through it at `0xfffffe000c639db8`. All three records are unauthenticated format-8 pointers in the captured metadata; loader execution and native relocation lifetime are not observed. [SC1,SC5]

The first case reproduces the previous published component `defaults_with_original_platform_return`: every prefix source visit/read/write, registration model, tracked API entry/return, final private RAM, nine mutable image regions, Q0-Q31, GPR31, SP and NZCV matches at `0xfffffe000c639cb8`. Common logical system registers match; five additional logical system-register inputs are explicitly declared for the later continuation. The prior decoded audit is independently pinned by SHA-256 `e5080b7cd0d7fd243a614f887f038a92cbc270b9fb03b2d3102486bbcec45269`. [SC2]

The paired positive case has identical initial private RAM, entry GPRs and logical system inputs. Its only initialized image-content difference is the original logical topology page, supplied before main entry. Additional demand-mapped pages are verified against the original logical image. The two cases have identical source visits, private RAM, GPR31, SP, NZCV, SIMD values and logical system state at the enumeration boundary. No state, argument or stack reset occurs there. The topology-page alternatives remain different initial-state premises; this is not an unchanged-state continuation from the prior zero page into successful enumeration. [SC2,SC-A2]

On the zero-page path, ordinal zero loads array base zero. Original stride/address code derives record destination zero, increments the admitted-count global to one at `0xfffffe000be83320`, and reaches `0xfffffe000be83324` with X26=0. Execution stops before that store; no null write executes. A nonvacuous source obligation establishes this partial state. This is a fixture limitation, not evidence of a native null-destination condition. [SC2,SC6]

## Continuous topology and post-helper return

Original main's BL at `0xfffffe000c639cb8` enters enumeration. Original serialized-tree lookup/property/iterator/named-scan/string routines and original boot-option scanner/converter supply all tree and option values. Independent decoding and option formulas verify those values; no tree/parser output is injected into execution. The [established admission and field contracts](kernel_cpu_topology_handoff_report.md) remain applicable within these selected trees and counts. [SC3]

Defaults are cpus=16 and cpumask=all u64 bits. Each compared child consumes a mask bit; nonrunning children obey mask/reserved-slot/count gates, while a running match can select a CPU with a clear mask bit. CPU records have 136 B stride and cluster records 88 B stride. Every admitted running match overwrites the boot-record pair, so the last admitted running node selects the boot ordinal. Ordinal is admission order, distinct from physical reg32 and its affinity bytes. [SC3]

| Private case | Source visits | Completed CPU records | Selected ordinal | Post-helper control | Boundary |
| --- | ---: | ---: | ---: | ---: | --- |
| Preserved prior zero page | 9447 | 0 | None | Not reached | Before null record store |
| Original initialized page, paired defaults | 14480 | 1 | 0 | 2 | Thread setup complete |
| Three clusters, running middle | 32201 | 3 | 1 | 2 | Thread setup complete |
| cpus=2, cpumask=0x4, explicit control | 38560 | 2 | 0 | 3 | Thread setup complete |
| Sixteen CPUs, running last | 117477 | 16 | 15 | 2 | Thread setup complete |
| Explicit control 4 | 22032 | 1 | 0 | 4 | Original post-helper diagnostic |
| No running CPU | 15336 | 1 | None | Not reached | Before missing boot-record dereference |
| cpus=0 | 13716 | 0 | None | Not reached | Before missing boot-record dereference |
| Identity/options and mixed P/M cluster | 52314 | 2 | 1 | 3 | Thread setup complete |

Six original enumeration returns reach main `0xfffffe000c639cbc` with the actual main frame restored. The original BL there enters helper `0xfffffe000be85a48`; its parser call at `0xfffffe000be85a84` requests four bytes into `0xfffffe0007ef8e98`. Absence preserves original default 2; selected explicit 3 is admitted. Unsigned control>=4 branches to the original diagnostic target `0xfffffe000c62a2b0`, retaining the already-produced topology and preceding the implementation-defined register write. [SC4]

Five admitted post-helper returns reach `0xfffffe000c639cc0`, with logical s3_4_c15_c10_4=0 and the original main SP. The no-running and cpus=0 cases stop at `0xfffffe000be83d2c` before dereferencing the null selected boot record. Their partial/full topology output is checked independently; no default boot record is supplied. [SC3,SC4]

The enumerator invokes the selector0e wrapper 26 times with zero-extended stored physical reg32. Each call retains a declared no-RAM return and caller-saved clobbers. The wrapper's original emission/receiver effects remain outside execution. Selector0e is a lower-facility selector, not a Mach port name. [SC3,SC7]

## CPU-map and thread custody

Let n be the source-selected ordinal, V=u64[bootargs+8], Pbase=u64[bootargs+16], CPU=`0xfffffe000cac7520`, MAP=`0xfffffe000cb0c760` and THREAD=`0xfffffe000cbc9d08`. For the selected 0<=n<16 domain, main stores CPU at MAP+16*n+8 and `(Pbase+CPU-V) modulo 2^64` at MAP+16*n. The latter is exact bootarg translation arithmetic; authentic physical mappings and address-space ownership are not inferred. New source obligations establish both table slots and the modular expression. [SC5]

Main publishes n as u32 at `0xfffffe0007f8b4f0` and low16 at CPU+0. It constructs CPU+0x10 and CPU+0x20 pointer pairs using targets `0xfffffe000cbb4000` and `0xfffffe000cbbc000`. The logical PACDA events retain their input target and address-derived modifiers: low48(CPU+0x10)|0xe94d<<48 and low48(CPU+0x20)|0x0467<<48. Captured events retain X16/X17. Actual PAC bits, authentication and pointer dereferences remain unknown. [SC5,SC-A5]

| Source operation | Destination / exact result |
| --- | --- |
| Clear before copying | 16 B at template 0xfffffe0007e66610+0x328 become zero |
| Original memcpy call at 0xfffffe000c639da4 | X0=THREAD, X1=template, W2=1472; complete original copy body executes |
| Thread flags | u16[THREAD+0x214]=0x005f; u32[THREAD+0x518]=0x000fffff |
| Original slot-pointer indirection | u64[0xfffffe000cb62fe0]=THREAD |
| Thread CPU binding | u64[THREAD+0x1b8]=zero-extended CPU low16; u64[THREAD+0x1c0]=CPU |
| Setter CPU backpointer | u64[CPU+0x30]=THREAD |
| After original setter return | u32[THREAD+0x1c8]=0 |

The 13-word setter runs completely. It logically sets TPIDR_EL1=THREAD; replaces TPIDR_EL0 low48 from u64[CPU+0xa38] while retaining its high16; sets TPIDRRO_EL0 from u64[THREAD+0x148]; and sets CONTEXTIDR_EL1 from u64[THREAD+0x510]. These values come from the source-produced CPU/thread state, original template and declared prior mutable CPU contents. The producer/lifetime of CPU+0xa38 remains unknown; this increment does not convert its retained private value into a native hardware claim. [SC5]

In the selected ordinal 0/1/15 cases, thread+0x1b8 is exactly the source admission ordinal and its signed ASR16 offset is zero while unchanged. Later main callbacks, intervening thread mutation and the CPU initializer are not entered. No new later CPU-caller epoch is introduced. [SC5,SC7]

## Independent verification and assumptions

Eleven new nonvacuous source-composition queries are UNSAT over 60 distinct PCs, 70 instruction instances and 59 linked-edge obligations. Premises are SAT before each negated contract is added. They cover zero/original array-slot behavior, the two actual main calls, bounded map slots, modular bootarg translation, thread flags/slot/status and logical PAC pointer/modifier custody. Thirty platform and 24 topology source obligations are rebuilt against the matched current closure, 54 retained queries total. [SC6]

Nine private components pass 12302 independent semantic checks, including retained prefix contracts and full tree/option/copy contracts. Original API tracking records 5557 entries, 5553 matched returns and four deliberately unfinished outer entries at the four stop boundaries. There are 26 completed records, six enumeration returns, five post-helper returns and five complete 1472 B copies. Eighteen earlier registration returns and 26 selector0e returns remain declared, 44 total. [SC6]

The independent topology/post-helper/thread formulas compare 729840 B over 20 mutable-state checkpoints. The fourteen declared mutable regions total 36492 B per case: the previous 33280 B plus 3212 B for template, thread, CPU map, slot and ordinal storage. Copy contracts compare 26519 destination bytes cumulatively. Nonstack private formulas compare 9398016 B across the nine continuations; the 4352 B stack guard is excluded only from that formula and checked by replay. Retained prefix checks separately cover the earlier environment state. Extents are private model regions, not native object ownership evidence. [SC6]

Fresh replay imports no executor. It verifies 315563 source visits / 2439 distinct PCs, 60471 reads / 275341 B, 24858 writes / 188456 B, 3637 logical PAC/return steps and 209 additional logical effects. It checks all 44 return contracts/clobbers, all tracked entries/returns/unfinished chains, nine final GPR/SP/NZCV boundaries and 288 final SIMD values. Source words, read values, write addresses/lengths/results and initial image pages are checked against the original image and declared fixtures. [SC6]

Replay compares 39845888 private bytes and 1264640 prior-region image bytes over 38 checkpoints, plus 64240 additional-region bytes at 20 checkpoints. Final checks compare 9437184 private bytes and 1462272 mapped image bytes. Counts overlap across cases/checkpoints and do not describe disjoint native memory. The largest case uses 117477 source visits under the explicit 300000-step execution limit. [SC6]

Five selected source words replaced privately with NOP are rejected: reg store `0xfffffe000be834b8`, membership store `0xfffffe000be83244`, post-helper MSR `0xfffffe000be85a94`, thread flags store `0xfffffe000c639dc0` and setter TPIDR_EL0 MSR `0xfffffe000bc9c80c`. Controls are excluded from positive totals. They check sensitivity of output/control contracts; finite controls do not prove an emulator or lifter universally correct. [SC6]

Capture costs O(K+I+D+N) time/space in collection bytes K, source I, initialized/literal/string data D and symbols N. Proof construction costs O(I+Q) in source/formula DAG Q; SMT search is separate with a 30 s/query limit and no polynomial claim. Execution, independent formulas and replay cost O(V+J+M) time/space in visits V, journals J and mapped bytes M; event sorting adds O(J log J), plus bytes examined by individual tree/string/copy calls. Arithmetic uses exact little-endian u8/u16/u32/u64 and stated modular operations; no physical-rate calibration or statistical uncertainty is asserted. Nontrivial JSON uses `zstd --ultra -22 -q -T1`, exact decoded roundtrips and decoded/nested path hygiene. [SC6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SC-A1: Pinned original bytes and format-8 metadata identify this build | SC1-SC7 | Rehash 31 intervals, all prior matches, 60 strings, four literals, seven initialized-data blocks and three pointer records; no cross-build equivalence |
| SC-A2: Initialized topology page is a declared pre-entry alternative, not attested native state | SC2-SC7 | Preserve the prior audit handoff exactly; paired identical input/register/source/RAM comparison; isolate one differing logical image page; verify all additional demand pages against the image |
| SC-A3: Well-formed serialized trees, copied bootargs and guard-zero main entry define selected cases | SC2-SC7 | Original input copies, independent tree/option decoding, masked/reserved/16-CPU/zero-limit/no-running paths; native admission, malformed-input behavior and earlier entry unknown |
| SC-A4: Registration/selector0e returns and logical system behavior remain conditional | SC3-SC7 | Forty-four no-RAM returns and clobbers; source call/return/SP custody; control 2/3/4 gate and pre-dereference stops; native receiver/hardware/ordering unknown |
| SC-A5: PACDA preserves logical targets in the model, and original template/CPU bytes supply later fields | SC5-SC7 | Two exact X16/X17 modifiers, five full copies, all 13 setter PCs, low16 ordinal and low48/high16 formulas; native PAC, CPU+0xa38 lifetime and later thread mutation unknown |
| SC-A6: Source proofs, independent formulas and replay establish selected finite private behavior | SC6,SC7 | Eleven nonvacuous composition queries, 54 rebuilt queries, 12302 semantic checks and five controls; 588/969 enumerator-PC coverage, shared decoder/emulator limits and all unexecuted paths retained |
| SC-A7: Kernel startup composition does not establish fairplayd control or a Mach transfer | SC7 | Correlate matched daemon/user-client/provider/kernel epochs, payloads, rights and statuses; no such transaction newly observed |

No new incoming/outgoing Mach port, right or message-emission PC is established. The [Mach inventory](mach_ports_report.md) retains established endpoint evidence. The source selector0e call at `0xfffffe000be83250` crosses a modeled lower-wrapper boundary; its receiver and effects remain unobserved. A matched fairplayd/FairPlayIOKit/kernel transaction remains unknown. [SC7]

| Impact | Next discriminating work | Evidence it could establish |
| --- | --- | --- |
| High | Continue original main after 0xfffffe000c639dd8 through callback/registration bodies toward the CPU initializer | Remove the remaining later caller-epoch gap while retaining the exact source-produced thread and globals |
| High | Establish initialized-page/fixup producers and guard/cache lifetime from original entry/loader context | Replace explicit private initialization premises with a stated source-supported lifetime boundary |
| High | Recover selector0e wrapper pre/post-call effects and its receiver | Establish custody beyond the declared no-RAM return without confusing selector values with Mach names |
| High | Pair an actual daemon/user-client/provider/kernel transaction | Determine observed relevance of these kernel prerequisites to FairPlay interaction |
| Medium | Trace CPU+0xa38 and later thread+0x1b8 producers | Establish the lifetime of the setter low48 payload and later lower-block selection |
| Medium | Follow CPU-map translation words and the cached range anchor into consumers | Establish address-space meaning beyond exact raw arithmetic |

**QG1**: Factual technical analysis; no normative content required. **QG2**: SC-A1-SC-A7 register dependencies and falsification probes. **QG3**: Initialized-data prerequisite, preserved prior-state boundary, original continuous topology/post-helper/thread composition, IPC limits and reporting covered for this increment; full goal remains active. **QG4**: Exact widths, byte extents, hashes, arithmetic domains and complexity stated. **QG5**: Zero-page versus original initialized state, demand mapping versus state mutation, selected ordinal versus physical reg, source versus native effects, and completed versus deliberately unfinished API chains distinguished. **QG6**: Original bytes/fixups/nlist, rebuilt source obligations, independent formulas, replay and controls retained. **QG7**: Bounded impact-ranked continuation included. All gates pass for this increment; native startup, later callbacks/CPU initialization and matched daemon/kernel effects remain unknown.


## Startup registry and mach_ipc registration follow-up

The [startup registry ABI increment](kernel_startup_registry_abi_report.md) captures all 3519 original initialization records and 115 distinct kernel callback bodies, their authenticated pointer metadata, phase names and 22 tree/boot-option tunable descriptors. Original main now continues through timebase/trace, complete sorting, its first actual tunable callback/return and cursor publication. Three private runs establish absent/property/option precedence; entry 123 registers the previously analyzed MIG hash initializer at phase 14 (`mach_ipc`), rank zero, argument zero. Phase-14 execution, remaining callback effects, native startup/PAC lifetime and a matched FairPlay/Mach transaction remain unknown; the full goal remains active.
