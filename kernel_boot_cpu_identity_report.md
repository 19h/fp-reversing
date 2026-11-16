# Boot CPU identity, bootstrap thread production and register interfaces

Original source distinguishes three CPU-related values: the admitted logical ordinal, the device-tree `reg` value, and the signed offset encoded in thread+0x1b8 for lower SPTM state. The bootstrap producer copies a 1472 B thread template and writes only a zero-extended 16-bit ordinal into that 64-bit thread field. Its signed shift by 16 therefore yields zero. A separate original CPU initializer recognizes the bootstrap CPU-data address and skips its direct SPTM CPU-initialization call. These are source contracts with selected private instruction witnesses; complete startup continuity, hardware state, actual device-tree contents and a matched daemon/kext/kernel transaction remain unknown. [BC1-BC7]

```text
original CPU topology enumerator [captured; local blocks proved]
  SecureDT /cpus children -> state comparison with running
  admitted record: ordinal+0, reg+4, cluster index+8
  comparison returns0 -> paired boot CPU/cluster pointer publication
  final source -> TPIDR_EL0 = ordinal[11:0] | cluster[7:0]<<12
       |
       | explicit private boot-record input; whole enumerator not executed
       v
original main cut -> fixed bootstrap CPU-data + CPU-map entries
  original memcpy(thread, template,1472 B)
  thread+1b8 = zero-extended u16 ordinal; thread+1c0 = CPU-data
  original thread setter -> TPIDR registers + CPU current-thread pointer
       |
       | same complete private RAM; explicit new caller epoch
       v
original CPU initializer
  magic already0100000c -> common reset/tail
  otherwise bootstrap CPU-data address -> synthesized MIDR global
            other CPU-data address -> declared SPTM initializer return
  declared cache/context helper returns -> original reset/tail ABI
```

| Claim | Established result | Dependencies |
| --- | --- | --- |
| BC1 | Original function/data/fixup custody and recovered routine roles | BC-A1 |
| BC2 | CPU ordinal/record geometry, state-selected boot pointer and topology register encoding | BC-A1,BC-A2 |
| BC3 | Original template copy, fixed CPU binding and bootstrap thread field widths | BC-A1-BC-A4 |
| BC4 | Original system-register setter and conditional zero lower-block offset | BC-A1,BC-A3-BC-A5 |
| BC5 | CPU magic/address gates, direct SPTM call selection and tail ABI | BC-A1,BC-A3-BC-A5 |
| BC6 | Local source proofs, independent byte formulas, fresh replay and controls | BC-A1-BC-A6 |
| BC7 | Environmental/control/Mach boundaries and bounded continuation | BC-A1-BC-A7 |

Primary provenance is the pinned collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`: original instruction/data bytes, compiler starts, nlist and chained-fixup records. The preserved normalized kext remains SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Reference data sufficed; no IDB was read or changed. Exact nlist names for the recovered routines below are unknown except the copy aliases `_memcpy`/`_memmove`. Role descriptions follow source operations, not recovered original names. [BC1]

Artifacts: [extractor](triage_evidence/recover_kernel_boot_cpu_identity.py), [private executor](triage_evidence/probe_kernel_boot_cpu_identity.py), [independent replay and formulas](triage_evidence/replay_kernel_boot_cpu_identity.py), [source audit](triage_evidence/audit_kernel_boot_cpu_identity.py), [delivery verifier](triage_evidence/verify_kernel_boot_cpu_identity_delivery.py), [source capture](triage_evidence/kernel_boot_cpu_identity_checks.json.zst), [audit receipt](triage_evidence/kernel_boot_cpu_identity_audit.json.zst). Decoded capture:388529 B, SHA-256 `0be41bdc2408ffec19951dcf7bd475fd640a35a1633fbffb9625a308fa7c4b81`. Decoded audit:18634812 B, SHA-256 `7254143093c9dbbe31972461211b0ac2834973c4c97473d0354cce54ec537ecd`. [BC6]

## Original routines and CPU-record producer

All intervals are half-open; each source word is4 B. Ten captured functions contain2459 words/9836 B, four identical to prior captures. The capture includes119 direct BL sites,25 exact strings,10 logical data blocks and three original pointer fixups. Three undecoded words remain raw bytes and are never executed: one in the captured main continuation and two in the lower wrapper. [BC1]

| Original interval | Words | Source-supported role / execution boundary |
| --- | ---: | --- |
| 0xfffffe000be83068..0xfffffe000be83f8c | 969 | CPU/cluster topology enumeration, property decoding and boot-record publication; local blocks proved, full body unexecuted |
| 0xfffffe000be83f8c..0xfffffe000be8408c | 64 | Scalar property with full64-bit fallback; selected original body executed around declared property outputs |
| 0xfffffe000bc9c7f0..0xfffffe000bc9c824 | 13 | Thread-register setter and CPU current-thread back-pointer; original body with logical system effects |
| 0xfffffe000be780f8..0xfffffe000be78280 | 98 | CPU initialization magic/address gates, common reset and tail ABI; selected paths with declared helpers |
| 0xfffffe000c639a40..0xfffffe000c63a3e0 | 616 | Main continuation; selected cut0xfffffe000c639cc0..0xfffffe000c639dd8 |
| 0xfffffe000c647f10..0xfffffe000c6480c0 | 108 | Original _memcpy/_memmove; complete copy implementation executes |
| 0xfffffe000be734f0..0xfffffe000be73684 | 101 | Previously recovered SPTM CPU initializer; local field-to-block proof, private caller leaf here |
| 0xfffffe000be79c6c..0xfffffe000be7a094 | 266 | Cache/topology-related helper; captured, explicit no-RAM private return |
| 0xfffffe000be95490..0xfffffe000be957d4 | 209 | CPU context configuration helper; captured, explicit no-RAM private return |
| 0xfffffe000c620ec4..0xfffffe000c620f00 | 15 | Lower wrapper called with record `reg`; captured with two undecoded words, unexecuted |

The original pointer fixup at0xfffffe0007ef8c08 targets CPU-record array0xfffffe0007ef8260;0xfffffe0007ef8c10 targets cluster array0xfffffe0007ef8ae0. CPU records use136 B/0x88 strides and cluster records88 B/0x58 strides. CPU count/max ordinal live at0xfffffe0007ef8bec/+4; cluster count/max index at+8/+12. The CPU record's u32+0 is the admitted ordinal, u32+4 receives the low32 bits of mandatory `reg`, and u32+8 is the cluster index. The physical-processor interpretation of `reg` is a role inference from its property name, byte decomposition and lower wrapper use; no native MPIDR value is observed. [BC1,BC2]

Source defaults `cpus` to16 and `cpumask` to0xffffffffffffffff before parser calls at0xfffffe000be830cc/0xfffffe000be830f0. It looks up `/cpus`, iterates children through0xfffffe000c5e4550 and obtains `state` through0xfffffe000c662110. The comparison call at0xfffffe000be832b0 uses `running` and the supplied property length. A zero comparison result selects branch0xfffffe000be83248, leading to paired store0xfffffe000be833ac of CPU/cluster record pointers at0xfffffe0007ef8c18/+8. These globals are originally zero and have no chained fixup. This is length-dependent comparison behavior, not proof of an exact whole-string equality or a unique running node. Each selected publication overwrites the pair; native node order and admission remain unknown. [BC2,BC-A2]

At0xfffffe000be83300..0xfffffe000be8331c, record offset equals zero-extended ordinal times136. The source checks whether that 64-bit offset equals its signed32 extension; mismatch constructs a pointer with high16 bits0x2bad. The next block stores count+1 modulo2^32, the ordinal and unsigned maximum. The final source at0xfffffe000be83d28..0xfffffe000be83d44 writes `TPIDR_EL0=(ordinal&0xfff)|((cluster_index&0xff)<<12)` and `TPIDRRO_EL0=0`. These local source contracts do not prove complete array bounds, admitted counts, tree validity or successful native enumeration. [BC2,BC6]

## Device-tree property ABI

The following exact strings and store instructions establish an environmental input surface. Scalar fields accept1/2/4/8 B values and store low32 bits where the destination is u32. Optional scalar paths below initialize the selected value to zero on absence. Paired properties, when present, require16 B and copy two u64 words; absence bypasses those stores. The scalar helper independently supplies its explicit fallback on absence and enters the original diagnostic if that fallback is0xffffffffffffffff. Original `reg` uses this mandatory sentinel. [BC1,BC2,BC6]

| Property | Destination | Relevant source store/call PC |
| --- | --- | --- |
| die-id | CPU record u32+0x0c; unsigned maximum global0xfffffe0007ef8bfc | 0xfffffe000be833e4 |
| soc-die-id | CPU record u32+0x10; maximum global0xfffffe0007ef8c00 | 0xfffffe000be8348c |
| reg | CPU record u32+4; mandatory scalar helper | 0xfffffe000be834b4/0xfffffe000be834b8 |
| l2-cache-size / l2-cache-id | CPU record u32+0x1c/+0x20 | 0xfffffe000be8354c/0xfffffe000be835e0 |
| l3-cache-size / l3-cache-id | CPU record u32+0x24/+0x28 | 0xfffffe000be83674/0xfffffe000be83708 |
| cpu-uttdbg-reg | CPU record u64+0x50/+0x58 | 0xfffffe000be83754/0xfffffe000be8375c |
| cpu-impl-reg | CPU record u64+0x38/+0x40 | 0xfffffe000be837a8/0xfffffe000be837b0 |
| coresight-reg | CPU record u64+0x68/+0x70 | 0xfffffe000be837fc/0xfffffe000be83804 |
| cluster-type | CPU record u32+0x14: numeric P/0x50 ->2, E/0x45 ->1, M/0x4d ->3; absent/other ->0 | 0xfffffe000be83808..0xfffffe000be838e0 |
| cluster-power-down | Nonzero value sets u32 global0xfffffe0007ef8c58=1 | 0xfffffe000be83984 |
| acc-impl-reg | Cluster record u64+0x30/+0x38 | 0xfffffe000be83b24/0xfffffe000be83b2c |
| cpm-impl-reg | Cluster record u64+0x48/+0x50 | 0xfffffe000be83b78/0xfffffe000be83b80 |
| die-cluster-id | Helper fallback=`(reg>>8)&0xff`; low32 to CPU+0x78 and cluster+0x20 | 0xfffffe000be831f8/0xfffffe000be831fc/0xfffffe000be83200 |
| cluster-core-id | Helper fallback=`reg&0xff`; low32 to CPU+0x7c | 0xfffffe000be83214/0xfffffe000be83218 |

The capture also preserves `chip-revision`, `enable_skstb`, `enable_skstsct` and `cluster_power` references in the final enumeration body. Their native configuration effects are not executed here. The source groups clusters using byte1 of stored `reg`, populates CPU/cluster type counts and a 64-bit CPU membership mask, and calls0xfffffe000c620ec4 with the stored `reg` at0xfffffe000be83250. These are static touch points, not observations of hardware power/cache behavior. [BC1,BC2,BC7]

## Bootstrap thread and register production

At0xfffffe000c639cc4, main loads the published CPU-record pointer; LDRSW at0xfffffe000c639cc8 reads signed32 ordinal at offset0. It stores low32 ordinal to0xfffffe0007f8b4f0 and low16 ordinal to fixed bootstrap CPU-data0xfffffe000cac7520. It fills16 B CPU-map records at0xfffffe000cb0c760: virtual CPU-data pointer at ordinal*16+8, physical expression `(bootargs_u64[+0x10]+CPU_data-bootargs_u64[+8]) mod2^64` at ordinal*16. The bootargs source is the previously copied structure0xfffffe0007e6d1e0. No physical ownership follows from this arithmetic. Stack-top pairs at CPU-data+0x10/+0x20 use0xfffffe000cbb4000/0xfffffe000cbbc000 and logical PACDA envelopes; native signed pointer bits remain unknown. [BC3,BC-A3,BC-A4]

The template is0xfffffe0007e66610. Source clears16 B at template+0x328, then calls original memcpy at0xfffffe000c639da4 with destination0xfffffe000cbc9d08, that template and0x5c0=1472 B. After the full copy, the following original stores establish the thread fields. [BC3]

| Original PC | Exact effect |
| --- | --- |
| 0xfffffe000c639dac | u16[thread+0x214]=0x5f |
| 0xfffffe000c639db8 | u64[0xfffffe000cb62fe0]=thread; destination comes from original fixup0xfffffe000ca908b0 |
| 0xfffffe000c639dc0 | u32[thread+0x518]=0x000fffff |
| 0xfffffe000c639dc8 | Paired u64 stores: thread+0x1b8=zero-extended u16[CPU-data], thread+0x1c0=CPU-data |
| 0xfffffe000c639dd0 | Original setter(thread) call |
| 0xfffffe000c639dd4 | u32[thread+0x1c8]=0 |

The original 13-word setter writes the following interface. BFXIL preserves the previous high16 bits of TPIDR_EL0 and replaces its low48 bits. It does not preserve the topology encoding in those low bits. Original file CPU-data+0xa38 and template+0x148/+0x510 are zero; runtime contents can differ. The bootstrap witnesses declare zero CPU-data+0xa38, while separate setter cases exercise arbitrary high bits, low48 input, read-only thread ID and context ID. [BC4,BC-A3,BC-A5]

| Original PC | System/memory effect |
| --- | --- |
| 0xfffffe000bc9c7f4 | TPIDR_EL1=thread |
| 0xfffffe000bc9c7fc | u64[CPU-data+0x30]=thread |
| 0xfffffe000bc9c80c | TPIDR_EL0=(old&0xffff000000000000) \| (u64[CPU-data+0xa38]&0x0000ffffffffffff) |
| 0xfffffe000bc9c814 | TPIDRRO_EL0=u64[thread+0x148] |
| 0xfffffe000bc9c81c | CONTEXTIDR_EL1=u64[thread+0x510] |

The lower initializer at0xfffffe000be73518..0xfffffe000be73528 forms `0xfffffe000cac8000 + ASR64(u64[thread+0x1b8],16)`. Substituting the bootstrap producer's zero-extended 16-bit field makes that offset zero for every u16 ordinal. This theorem is conditional on the field remaining unchanged until that consumer. The earlier [mapping-context fixtures](kernel_mapping_context_report.md) deliberately encoded additional block-offset bits; those fixtures were private inputs, not evidence of the actual bootstrap producer. No contradiction exists between that general consumer formula and the newly recovered bootstrap-specific value. [BC4,BC6]

## CPU initialization gates and explicit epochs

The main continuation contains BL0xfffffe000c639e40 to initializer0xfffffe000be780f8. The new witness stops main at0xfffffe000c639dd8 after the original thread setup, retains every mapped byte and logical system value, then starts an explicit new caller epoch at the initializer. Original instructions and callbacks between those addresses are captured in main but bypassed in this witness. Four such memory-preserving epochs establish conditional composition; they do not establish native startup continuity. [BC3,BC5,BC-A4]

The initializer obtains CPU-data from TPIDR_EL1->thread+0x1c0 and checks u32[CPU-data+4] against0x0100000c. Equality branches to common reset at0xfffffe000be7821c. Otherwise it writes the magic, queue/self pointers and literals, then compares CPU-data to fixed bootstrap address0xfffffe000cac7520 at0xfffffe000be78158. Equality enters the bootstrap body; inequality loads u16[thread+0x1b8] into W0 and calls SPTM initializer0xfffffe000be734f0 at0xfffffe000be78164. Thus source identity of the data pointer, not ordinal equality with zero, selects this direct call. [BC5]

The bootstrap body reads MIDR_EL1, replaces bits16..19 of its low32 value with0xd and stores the synthesized value at0xfffffe0007ef81c8. It does not write MIDR_EL1. It also stores three u32 ones at0xfffffe000cb8ab70. Following a declared cache-helper return, source conditionally derives two u32 fields at0xfffffe000cb8ab68 from ID_AA64DFR0_EL1 and selects capability table `[1,2,12]` using nibble `(u32[0xfffffe0007ef81c8]>>16)&15` minus12. An unsigned index>=3 enters the original diagnostic before context helper/common reset. Bootstrap synthesis selects table index1/value2. [BC5,BC6]

After a declared context-helper return, or directly on the magic fast path, source clears u64 CPU-data+0x890/+0x8a0/+0x8b0, sets byte+0x69=1, copies u32+0x1dc to+0x1e0 and clears+0x1dc. The original tail branch at0xfffffe000be78260 reaches0xfffffe000be487e8 with X0=0, W1=u16[CPU-data], X2=CPU-data+0x238, X3=CPU-data+0x2d8 and W4=1. That target is a stopping boundary here. Direct SPTM, cache and context helpers are explicit no-RAM contracts with volatile-register/NZCV clobbers, not executed native implementations. [BC5,BC6]

## Verification and assumption register

Nineteen nonvacuous source queries are UNSAT over97 distinct PCs/instruction instances and78 linked-edge obligations. The model explicitly adds LDRSW signed32 extension, the exact zero-vector operation used before copy, and logical MRS/MSR assignments. Queries cover record geometry/counts, state branch and paired pointer publication, topology register encoding, signed ordinal load/widths, original1472 B copy request/clear, thread binding, setter interface, conditional zero lower-block offset, CPU gates/MIDR-global synthesis and scalar loads/sentinel. They are local contracts, not a proof of the complete969-word enumerator. [BC6]

Twenty-one private components pass954 independent semantic checks: four original bootstrap-copy-to-initializer epochs, five standalone initializer cases, ten scalar-property cases and two independent setter cases. Fixtures decouple ordinal/`reg`/cluster, exercise ordinals0/1/15, initialization/magic fast paths, non-bootstrap data, capability diagnostics, SIMD feature lanes, property sizes1/2/4/8 and invalid0/3/16, absent optional/mandatory properties, and high16/low48 register preservation. Four altered-source controls are rejected: thread store0xfffffe000c639dc0, bootstrap branch0xfffffe000be7815c, setter MSR0xfffffe000bc9c80c and scalar load0xfffffe000be84054. Controls are excluded from positive totals. [BC6]

Fresh replay, which does not import the executor, checks2804 source visits/287 PCs,959 reads,1067 writes,26 declared API/helper returns,99 logical system/PAC effects and four complete-RAM caller epochs. All3608576 mapped bytes match final replay snapshots; independent semantic formulas separately check3522560 nonstack bytes. Stack bytes also match fresh replay. Four original1472 B copies execute; code identity is checked against pinned source for every positive visit. All three undecoded words remain unexecuted. [BC6]

Extraction costs O(K+F+I+D+N) time/space in collection K, fixups F, captured instructions I, data D and symbol inventory N. Formula construction costs O(I+Q) in source and formula DAG Q; solver search is separate with30 s/query and no polynomial claim. Execution, independent byte formulas and replay cost O(V+J+M) time/space in visits V, journals J and mapped bytes M. Components have65536 B declared private RAM plus lazily mapped original pages, a 10000-visit limit and exact little-endian modular integer arithmetic. There is no statistical error estimate. Receipts use `zstd --ultra -22 -q -T1`, decoded roundtrip validation and decoded/nested path hygiene. [BC6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BC-A1: Pinned collection, bounds, fixups and source bytes identify this build | BC1-BC7 | Rehash originals, ten functions/four prior matches,25 strings, three fixups and zero/non-fixup runtime pointer pair; preserve three opaque words; no cross-build equivalence |
| BC-A2: Original topology blocks describe admitted records under the shown call contracts | BC2,BC7 | Prove136 B stride/poison gate, modular count, ordinal store, comparison-zero branch, paired pointers and register pack; complete mask/limit/node order, duplicate/missing running states and array admission remain unknown |
| BC-A3: Private boot-record/bootargs, original logical template and CPU inputs select these cuts | BC3-BC7 | Decouple ordinal/physical/cluster; poison thread destination; execute full1472 B copy; check every nonstack byte and CPU-map arithmetic; native template relocation and input ownership unknown |
| BC-A4: Same RAM plus explicit new caller epoch and no-RAM helper contracts support conditional composition | BC3-BC7 | Four complete-RAM epochs,26 independently reconstructed returns with clobbers, magic/bootstrap/non-bootstrap branches and diagnostic stops; intervening native startup/callback/helper effects unexecuted |
| BC-A5: Logical system/PAC envelopes model register values while source thread fields remain unchanged | BC4-BC7 | Setter high16/low48 tests, original MSR/MRS byte checks, full-width formulas and conditional zero ASR16 theorem; native PAC bits, architectural visibility and later thread mutation unknown |
| BC-A6: Local source lifting, Unicorn execution, independent formulas and fresh replay cover only this increment | BC6,BC7 |19 nonvacuous queries,21 components,954 semantic checks, complete snapshots/journals and four altered-source controls; shared decoder/emulator limitations remain, no universal native proof |
| BC-A7: Boot/CPU contracts do not establish daemon control or a Mach transfer | BC7 | Seek a matched daemon/user-client/provider/kernel transaction with rights, payload, return status and epoch; no such transaction newly observed |

No new incoming/outgoing Mach right, endpoint or message-emission site is established. These CPU addresses, property values and TPIDR fields are not Mach port names. The [Mach inventory](mach_ports_report.md) retains endpoint evidence, and the [prior header handoff](kernel_boot_header_handoff_report.md) retains root/header-copy custody. Actual daemon influence over these early boot inputs remains unknown. [BC7]

| Impact | Next discriminating work | Evidence it could establish |
| --- | --- | --- |
| High | Execute the original complete topology enumerator with measured or explicitly modeled SecureDT iterator/property outputs | Actual admitted count/order, boot-node uniqueness, mask/limit handling and CPU/cluster records |
| High | Execute the main interval between thread setup and original initializer call, then actual cache/context helpers | Native-order constraints, thread/global mutation and replacement of the explicit caller epoch |
| High | Trace writes to CPU-data+0xa38 and later thread+0x1b8 changes across startup/thread switches | Meaning/lifetime of low48 TPIDR_EL0 payload and later SPTM block offsets |
| High | Recover lower wrapper0xfffffe000c620ec4 and native selector15/0x13/0x32 receiver behavior | `reg` conversion, root/header/result ownership and hardware-level contract |
| Medium | Correlate actual DT state lengths, duplicate/missing running nodes and parser settings with source admission | Boundary between comparison-zero publication and an authentic unique boot CPU |
| High | Pair daemon/user-client/provider traffic with a measured kernel transaction | Cross-layer payload/right/status correlation beyond boot prerequisites |

**QG1** Pass: factual technical analysis. **QG2** Pass: BC-A1-BC-A7 give dependencies and falsification probes. **QG3** Pass for this increment: routine roles, environmental inputs, CPU/thread ABI, data/control flow, lower/Mach boundaries and reporting covered; full investigation remains active. **QG4** Pass: exact widths, byte units, offsets, arithmetic, algorithmic bounds and reproduction artifacts stated. **QG5** Pass: ordinal versus `reg` versus block offset, previous fixtures versus actual producer, synthesized global versus hardware MIDR, complete RAM versus native continuity and length-dependent comparison distinguished. **QG6** Pass: pinned primary target bytes/metadata, reconstructed source proofs, independent byte formulas/fresh replay and controls; native gaps explicit. **QG7** Pass: bounded impact-ranked continuation above. `full_goal_complete=false`. [BC1-BC7]


## Source-produced topology handoff follow-up

The [CPU topology handoff increment](kernel_cpu_topology_handoff_report.md) replaces the previously injected boot-record selection with original enumeration and uninterrupted returns through the intervening configuration helper into thread construction. It adds admission/cluster formulas, length-bounded state comparisons and complete nonstack checkpoint checks. The opaque-word location wording above is corrected without changing any prior source capture or receipt.
