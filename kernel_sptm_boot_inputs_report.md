# SPTM boot inputs and nested CPU initialization

Original source establishes the versioned record that publishes the converter pointers, VA bounds and transport-selection byte. Its caller checks header magic0xd00f000000000000 and passes the embedded record at header+0x1a0. The pmap context initializer's formerly modeled leaf now executes as original pool/shared-storage initialization followed by an original tail call to CPU initialization. Seven private chains carry the source-published converter state and nested CPU outputs into the earlier mapping consumers. Native boot-record origin, physical backing ownership, SPTM receiver behavior and daemon transaction identity remain unknown. [SB1-SB7]

```text
declared header and embedded versioned record
  original magic gate -> original record publication -> converter globals
    exact state transfer -> original ARM root conversion/publication cut
      exact state transfer -> original ARM context-initializer call
        root/geometry/count stores
        original pool initializer
          original /defaults helper [explicit absent-property leaf models]
          original pool allocation/zero/link stores
          shared base publication + 524288 B reservation
          restore caller frame -> original CPU initializer, tail call
            original converters + declared SPTM identifier/pointer returns
            CPU result-pointer store -> return to context initializer
        original bitmap allocation/zero and remaining context stores
      new declared admission call -> source descriptor -> declared backend call
        source-published transport flag retained at opaque request boundary
```

Primary provenance is the pinned original collection, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, compiler starts, file-backed segment bounds, exact bytes, chained fixups, nlist records and original strings. The preserved normalized kext SHA-256 remains `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. The reference files sufficed; this increment did not use or mutate an IDB. Native effects are not inferred from a static model. [SB1]

| Claim | Established result | Dependencies |
| --- | --- | --- |
| SB1 | Complete source custody, final-function CFG and bounded reference/call scan | SB-A1,SB-A2 |
| SB2 | Header magic, embedded record, version gates and exact publication layout | SB-A1,SB-A3 |
| SB3 | Converter/transport-flag input provenance and topology chained fixup | SB-A1-SB-A4 |
| SB4 | Original pool allocation/clear/link/shared reservation and CPU tail call | SB-A1,SB-A4,SB-A5 |
| SB5 | Original nested context execution and exact state joins to mapping consumers | SB-A1,SB-A3-SB-A6 |
| SB6 | Source proofs, independent field/byte oracles, fresh replay and controls | SB-A1-SB-A7 |
| SB7 | Environmental/control/Mach boundaries and bounded continuation | SB-A1-SB-A7 |

Artifacts: [extractor](triage_evidence/recover_kernel_sptm_boot_inputs.py), [private executor and field oracles](triage_evidence/probe_kernel_sptm_boot_inputs.py), [independent replay](triage_evidence/replay_kernel_sptm_boot_inputs.py), [source audit](triage_evidence/audit_kernel_sptm_boot_inputs.py), [delivery verifier](triage_evidence/verify_kernel_sptm_boot_inputs_delivery.py), [source capture](triage_evidence/kernel_sptm_boot_inputs_checks.json.zst), [audit receipt](triage_evidence/kernel_sptm_boot_inputs_audit.json.zst). Decoded capture:936696 B, SHA-256 `17cdafee8a80c5098d46f13fa41dc0a62b7cfb502af30a55d8512c7e6bad5020`. Decoded audit:82657054 B, SHA-256 `b02d6b8b7ecfabde8b9536d3991ccac373b18128693e62feaca74bec41347099`. [SB6]

## Source custody and bounded discovery

| New complete interval, end exclusive | Words | Bytes | Established role |
| --- | ---: | ---: | --- |
| 0xfffffe000c66054c..0xfffffe000c66058c | 16 | 64 | Header magic check, embedded-record call and WFE failure loops |
| 0xfffffe000c662920..0xfffffe000c662b04 | 121 | 484 | Versioned SPTM input publication; special last-function boundary below |
| 0xfffffe000be71258..0xfffffe000be71450 | 126 | 504 | Pool/shared initialization and restored-frame CPU tail call |
| 0xfffffe000be71450..0xfffffe000be715d0 | 96 | 384 | Device-tree PV-control helper; original body, explicit property leaf contracts |
| 0xfffffe000be780f8..0xfffffe000be78280 | 98 | 392 | Additional CPU initialization caller; captured, unexecuted here |
| Fifteen byte-identical retained functions | 3826 | 15304 | ARM/context/CPU/converter/clear and mapping source |
| Total, twenty intervals | 4283 | 17132 | Four undecoded words preserved in the two CPU SPTM wrappers |

The versioned publisher is the last LC_FUNCTION_STARTS entry. There is no subsequent compiler-start address to supply an end. Its file-backed __TEXT_BOOT_EXEC segment ends at0xfffffe000c662b04, immediately after the second RET. The independent syntactic CFG checks all121 words,130 direct successor edges and both RET sites0xfffffe000c662af8/0xfffffe000c662b00. No call or indirect branch leaves this interval. This establishes a complete decoded source interval using the segment boundary; it does not establish native entry reachability or valid input-object lifetime. [SB1,SB6]

The bounded locator rehashes725 previously recorded executable sections and scans15490987 aligned4 B words. It uses3910 relevant ADRP seeds, at most512 fallthrough instructions per seed, immediate ADD/SUB/MOV propagation and register/caller-clobber kills. Unlike an exact-address-only locator, its access footprints include both words of LDP/STP. It retains324 candidate references and34 candidate store sites. No candidate store targets boot root0xfffffe0007e6d838; its original8 B are zero. This negative result is limited to the locator's encodings/windows: indexed/distant writes, bulk copies, other code and external initialization remain open. [SB1,SB3,SB7]

| Direct source edge | Opcode class | Target | Coverage here |
| --- | --- | --- | --- |
| 0xfffffe000c65c098 | BL | 0xfffffe000c66054c | Located outer boot caller; source before this edge remains outside the executed cuts |
| 0xfffffe000c66056c | BL | 0xfffffe000c662920 | Original header-to-record call executes |
| 0xfffffe000be609b8 | BL | 0xfffffe000be71258 | Original call inside complete context initializer executes |
| 0xfffffe000be71298 | BL | 0xfffffe000be71450 | Original device-tree helper call executes |
| 0xfffffe000be7142c | B | 0xfffffe000be734f0 | Original restored-frame CPU tail call executes |
| 0xfffffe000be78164 | BL | 0xfffffe000be734f0 | Additional CPU caller captured, unexecuted |

The earlier BL-only initializer inventory omitted the B tail call; the B/BL scan now locates it explicitly. Exact nlist aliases name ___bzero/_bzero at0xfffffe000c6480c0 and _SecureDTLookupEntry at0xfffffe000c662324. Other captured starts and property helper0xfffffe000c662110 have no exact nlist names. Descriptive pool/SPTM roles do not assign unknown exported symbol names. [SB1]

## Header and versioned publication ABI

Header caller0xfffffe000c66054c reads u64[X0] and compares it with0xd00f000000000000. Mismatch enters the original WFE/self-branch loop at0xfffffe000c66057c. A match passes `X0+0x1a0` modulo2^64 to the original publisher. Raw return0 restores the caller frame; nonzero enters the other WFE loop at0xfffffe000c660574. Private tests stop before WFE; hardware waiting/progress is not executed. Header length, object bounds, origin and lifetime are not validated by these source instructions. [SB2,SB7]

The publisher accepts X0=record. Null returns raw2 without global publication. Every nonnull selected version path returns raw0 and writes feature byte0xfffffe0007f8c718=1 after its field copies. The u32[record] is a version selector, not copied into a global. There is no minimum-version rejection here: versions0/1/2 take the common baseline, and unsigned0xffffffff takes all later fields. A raw zero return establishes source publication, not successful native boot or valid pointer ownership. [SB2]

Let G=0xfffffe0007f8c718. The following are exact source offsets and widths; u32 stores preserve the following four bytes. Only the converter count/table pointers and VA bounds have consumer-derived roles in this increment. Other field roles remain unknown unless separately identified. [SB2,SB3]

| Minimum version | Record offset | Width | Global offset from G | Consumer role established here |
| --- | --- | ---: | --- | --- |
| Baseline | +0x08 | u64 | +0x08 | Pointer to u32 conversion-range count |
| Baseline | +0x10 | u64 | +0x10 | Pointer to24 B conversion-range records |
| Baseline | +0x18 /+0x20 | 2*u64 | +0x18 /+0x20 | Unknown |
| Baseline | +0x28 /+0x30 | 2*u64 | +0x28 /+0x30 | VA-to-PA table-path lower/upper VA bounds |
| Baseline | +0x38 /+0x40 | 2*u64 | +0x38 /+0x40 | Unknown in selected converter path |
| Baseline | +0x48 /+0x50 | 2*u64 | +0x48 /+0x50 | Unknown |
| Baseline | +0x58 | u64 | +0x58 | Unknown |
| Baseline | +0x60 | u32 | +0x60 | Unknown |
| Baseline | +0x68 /+0x70 /+0x78 | 3*u64 | +0x68 /+0x70 /+0x78 | Unknown |
| 3 | +0x80 | u64 | +0x80 | Unknown |
| 4 | +0x88 | u64 | +0x88 | Unknown |
| 5 | +0x90 /+0x98 | u64 /u32 | +0x90 /+0x98 | Unknown |
| 6 | +0xa0 | u64 | +0xa0 | Unknown |
| 7 | +0xa8 | u64 | +0xa8 | Full flags/raw field retained |
| 7 | Bit6 of u32[+0xa8] | u8 output | +0xb0 | Transport-selection byte at0xfffffe0007f8c7c8 |
| 8 | +0xb0 /+0xb8 | u64 /u32 | +0xb8 /+0xc0 | Unknown |
| 8 | +0xc0 /+0xc8 | u64 /u32 | +0xc8 /+0xd0 | Unknown |
| 9 | +0xd0 | u64 | +0xd8 | Unknown |
| 10 | +0xd8 | u64 | +0xe0 | Unknown |
| 11 | +0xe0 /+0xe8 /+0xf0 | 3*u64 | +0xe8 /+0xf0 /+0xf8 | Unknown |
| 12 | +0xf8 | u64 | +0x100 | Unknown |

There are31 copied fields:27 u64 and4 u32, totaling232 B, plus the derived flag byte and feature byte. The retained global span is264 B; remaining bytes are preserved. The highest source reads imply minimum accessible extents0x80/0x88/0x90/0x9c/0xa8/0xb0/0xcc/0xd8/0xe0/0xf8/0x100 B for baseline/version3/4/5/6/7/8/9/10/11/12 respectively. These are access extents, not a recovered advertised struct-size field. [SB2,SB6]

Optional fields are preserved when their version is absent. With initial globals0xa5, older versions preserve unadvertised flag bytes and padding. A declared reinitialization from version12/flag1 to version2 preserves the earlier transport-selection byte1, while rewriting common fields. A subsequent null record also preserves enabled state. Native invocation count/order is unknown; these are conditional preservation results. [SB2,SB3,SB6]

The earlier [transport report](kernel_mapping_transport_report.md) and [context report](kernel_mapping_context_report.md) establish the consumers: original converters read G's feature/count/table/bounds, and SPTM wrappers test the byte at G+0xb0. Re-solved selector2 dispatch proves that zero selects word0x00201420 at0xfffffe000c620bd8 and nonzero selects0xd4e00000 at0xfffffe000c620be0. The new publisher supplies bit6 as0/1 for version>=7. No opaque word executes here, and its instruction name/receiver semantics remain unknown. [SB3,SB5]

Topology pointer0xfffffe0007ef8c08 is an original format-8 chained fixup targeting0xfffffe0007ef8260. Its static pointer provenance is established without inventing a runtime writer. The new CPU executions leave that pointer unchanged and seed only the first three descriptor records' hardware/topology contents as explicit private inputs. The136 B record contents, CPU admission and native topology population still require their own producers. [SB3,SB5]

## Original pool/shared initialization inside the context call

The context initializer calls0xfffffe000be71258 after publishing root/geometry and the initial count/budget, before its bitmap allocation. That routine publishes u32 values629 and0x3b00 at0xfffffe0007e6d0a0/+4. It calls original helper0xfffffe000be71450, which uses _SecureDTLookupEntry with device-tree entry `/defaults` and queries `pmap-pv-count`, `pmap-kern-pv-count`, and `pmap-kern-pv-min`. This is a device-tree entry, not an analyst-machine path. Each present-property branch requires size4 before copying a u32 to its original control global. The private lookup/property leaves supply no output/absent status and no RAM effects; the complete helper body executes, leaving original defaults unchanged. Native device-tree contents and lookup/property implementations remain open. [SB4,SB5]

Source also copies u64/u32 fields from the structure at u64[0xfffffe0007f8b5e0]+0x330/+0x338/+0x340/+0x348 into original globals0xfffffe0007ef81f0/+8 and0xfffffe0007e6d0a8/+8. These raw fields remain explicitly declared inputs. The memory-size input is u64[0xfffffe000cb2fb68], whose earlier producer is recorded in the [boot-input study](kernel_zone_boot_inputs_report.md). [SB4]

Let M be that64-bit memory-byte input and A the old bump pointer. Source arithmetic is exact unsigned bit-vector arithmetic. It performs the following two multiply/shift stages; no universal replacement with integer division is asserted. [SB4,SB6]

```text
u32_units = low32(M >> 24) & 0xfffffffe
q64 = (zero_extend(u32_units) * 0x6830d6e5) >> 40
objects32 = (low32(q64) * 629) mod 2^32
pages64 = (zero_extend((objects32 + 629) mod 2^32) * 0x6830d6e5) >> 40
pool_bytes32 = (low32(pages64) << 14) mod 2^32
aligned_A = (A + 16383) & 0xffffffffffffc000
pool_end = (aligned_A + zero_extend(pool_bytes32) + 16383) & 0xffffffffffffc000
```

The first round-up checks carry from A+16383. The second checks carry from the final+16383, after an unflagged pool-byte add. Source converts aligned_A to a virtual pool base, converts old A separately, then sends `(alias(old A),pool_end-A)` to original bzero. Thus the clear includes any alignment prefix between old A and aligned_A. Native wrap exclusion and conversion-table coverage are premises, rather than effects of these equations. [SB4]

| Selected memory input | u32_units | q64 | objects32 | pages64 | Pool bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0 B | 0 | 0 | 0 | 1 | 16384 B |
| 268435456 B (256 MiB) | 16 | 0 | 0 | 1 | 16384 B |
| 17179869184 B (16 GiB) | 1024 | 1 | 629 | 2 | 32768 B |
| 68719476736 B (64 GiB) | 4096 | 6 | 3774 | 7 | 114688 B |

For the selected link-loop domain, each16384 B pool page stores its previous head at offset628*24=15072 B, advances the page address by16384 B and decrements the u32 remaining-page count. The final head publishes at0xfffffe000cb890a8; u32 total629*pages publishes at0xfffffe000cb890b0. The modular CMN guard skips the loop only when objects32>0xfffffd8a. Private cases cover one/two/seven pages, not every possible budget or termination domain. The original fixed pair at0xfffffe000cb890b8 is{0,0x11}. No complete native24 B object layout is inferred from the link stride. [SB4,SB6]

At0xfffffe000be713f4 source stores pool_end as shared physical base0xfffffe0007e6d0b8. It adds524288 B without an overflow flag check and publishes the advanced bump and end0xfffffe0007e6d0c0. It does not clear that reserved shared region. All524288 private bytes retain their initial guards; the pool and later bitmap clears are separately checked. Since the CPU shared index has a32768 B stride, this extent has16 such slots (`524288 B / 32768 B = 16`). This arithmetic does not establish that native SPTM identifiers are admitted only in0..15. [SB4,SB5,SB7]

The routine then reads low16[TPIDR_EL1+0x1b8], restores its caller's frame and branches to original CPU initializer0xfffffe000be734f0 at0xfffffe000be7142c. The CPU initializer's return reaches0xfffffe000be609bc inside the context initializer. There is no fresh declared CPU call between these two original source bodies. Original VA-to-PA/PA-to-VA calls, identifier/result-pointer models and CPU stores therefore execute before the context's ASID bitmap allocation and its small-count diagnostic. Counts1/63 still initialize pool/shared/CPU state before reaching that later diagnostic. [SB4,SB5]

The earlier context report deliberately modeled this leaf and called CPU initialization in a separate component. Its conditional results remain valid for that model; this increment establishes the actual nested source order and shared-base producer. Boot root, range-record contents, raw memory/topology/device inputs and opaque identifier/result-pointer/status returns remain declared. The new source execution replaces the leaf model, not those native ownership premises. [SB5]

## Verification, assumptions and continuation

Thirty-five new nonvacuous source queries are UNSAT over184 distinct PCs/instruction instances and149 linked-edge obligations. They cover the magic/record/status gates, all31 copied fields and ten version thresholds, bit6 flag production, feature publication, pool budget/guard/clear/link/count/reservation arithmetic and restored-frame CPU tail-call ABI. Six prior root/bounds/identifier/request/result/selector contracts are re-solved. The separate closed-CFG check retains121 reachable words,130 edges and two returns. [SB6]

Seventy-three components pass387 independent semantic checks. They comprise28 version/flag profiles, fresh null/bad-magic cases, two inherited downgrade/null cases, and nine producer-to-consumer chains: seven complete loader/root/context/admission/backend chains and two chains stopping at the small-count diagnostic. 34 byte-exact state joins retain all predecessor private RAM and tracked globals; each new component's register/stack/input changes remain declared. Within each of the nine context components, the original context -> pool -> device-tree helper -> CPU -> context sequence executes continuously. The remaining full gateway-to-backend path and native boot epoch remain open. [SB5,SB6]

Fresh replay checks45709 source visits/1007 captured PCs,3549 reads/24820 B,3093 writes/22756 B,73 final boundaries,76546048 whole-private-RAM bytes and3665695 recorded-global bytes. It reconstructs99 original conversion entries,18 original bzero entries,25 opaque transport-model entries and27 original nested entry events. It independently checks119 leaf contracts,320 logical PAC steps and7389 logical64 B DC ZVA effects. All recorded globals and every nonstack private byte also match independent field/byte formulas. The original topology-pointer fixup is read unchanged. [SB6]

Four source-NOP controls are rejected: derived flag store0xfffffe000c662a44 and u32 field store0xfffffe000c6629a0 fail global-byte oracles; shared-base store0xfffffe000be713f4 changes the original conversion-address sequence; CPU tail branch0xfffffe000be7142c prevents the expected nested execution/second clear. Negative controls are excluded from positive replay counts. Captured-but-unexecuted PCs remain explicit. No opaque word, native hardware PAC/cache/translation effect or Mach transaction executes. [SB6]

Extraction costs O(K+W+S*512+I+F) time/space in collection bytes K, scanned words W, seeds S, source I and fixups F. Local formula construction costs O(I+Q) in source/formula DAG Q; solver search is separate with30 s/query and no asserted polynomial bound. Private execution/oracle/replay costs O(V+J+R) time/space in visits V, journals J and checked RAM R. Each component has1048576 B private RAM and a60000-instruction limit. Arithmetic is exact little-endian u8/u16/u32/u64 bit-vector arithmetic; no statistical error estimate applies. JSON uses `zstd --ultra -22 -q -T1` with decoded roundtrip checks. Delivery reconstructs extraction/proofs/components/replay, checks decoded/nested content for analyst-local paths and verifies exact owned publication/original-input custody. [SB6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SB-A1: Pinned bytes/compiler starts/segment bounds/fixups identify this build | SB1-SB7 | Rehash original inputs,20 intervals,15 prior captures and725 scanned sections; retain4 opaque words and special final-function boundary; no cross-build equivalence |
| SB-A2: Bounded constant propagation and ordinary caller-clobber ABI locate candidates | SB1,SB3,SB7 | Paired-access footprints, register kills and explicit3910 seeds; extend to indexed/bulk/indirect writes before claiming all references or a missing native writer |
| SB-A3: Declared header/record storage and version profiles are readable and disjoint | SB2,SB3,SB5-SB7 | Versions0..12/0xffffffff, both flag bits, poisoned padding/globals, bad magic, null and inherited downgrade/null; native bounds/lifetime and call count remain unknown |
| SB-A4: Boot root/table contents, memory/device/topology inputs and backing extents select the stated paths | SB3-SB7 | Original converter execution, fixed topology fixup, three CPU records,0/256 MiB/16 GiB/64 GiB memory inputs, alignment offsets and all region guards; native ownership/domain admission remains open |
| SB-A5: SecureDT/property/lock/parser/capability/validation and opaque-return leaves obey explicit private contracts | SB4-SB7 |119 independent leaf-contract checks, original helper bodies, full/low16/low32 identifier distinction, both source-published flags and four statuses; original implementations/receiver-side record writes remain open |
| SB-A6: Exact state transfer permits composition across declared new-call epochs | SB5-SB7 |34 whole-state joins, original nested CPU return PC, source descriptor/result-pointer consumption and three CPU blocks; complete native loader/startup/gateway epoch remains unproved |
| SB-A7: Finite source execution, local proofs and logical PAC/DC establish only this increment | SB6,SB7 |35 nonvacuous queries, six prior rechecks, closed CFG, fresh journals/RAM, four source controls and explicit false native/full-goal flags; native exclusion/progress remains open |

The recovered interfaces are internal boot, pmap and SPTM contracts. Their record pointers, selectors, pool heads and transport words establish no additional incoming/outgoing Mach right, receive/send endpoint, right transfer or Mach message-emission site. The [Mach-port inventory](mach_ports_report.md) retains the actual endpoint evidence. Environmental data now has a concrete publication ABI, while direct daemon control of those boot inputs and a matched daemon/provider transaction remain unknown. [SB7]

| Impact | Next discriminating work | Evidence it could establish |
| --- | --- | --- |
| High | Recover outer boot path at0xfffffe000c65c098 and actual header/record/root/table writers | Native record/root origin, startup order, version/extent admission and ownership |
| High | Recover receiver-side SPTM selectors0x13/0x32/2 and actual result-record writer | Identifier admission, pointer lifetime, native status/translation effects and record layout |
| High | Join complete gateway/category/expansion and original validation | Continuous mapping request beyond current admission/backend call boundary |
| Medium | Replace original SecureDT/property/lock/parser/capability leaves | Actual boot/device-tree controls and their state/visibility effects |
| Medium | Prove upstream nonwrapping budget/shared reservation and count/identifier domains | Whether large/zero/wrapping inputs are excluded before these routines |
| Medium | Recover topology record producers, additional CPU caller and epoch readers | Native CPU admission/order, readiness, lifetime and exclusion |
| High | Pair daemon/user-client/provider traffic with kernel effects in one observed transaction | Actual cross-layer payload, rights, status, ownership and epoch correlation |

**QG1** Pass: factual technical analysis. **QG2** Pass: SB-A1-SB-A7 identify assumptions/dependencies and falsification probes. **QG3** Pass for this increment: routine roles, versioned ABI, original nested data/control flow, environmental producers and lower/Mach interface boundaries covered; full investigation remains active. **QG4** Pass: exact widths, offsets, byte extents, modular/carry arithmetic, units and algorithmic costs explicit. **QG5** Pass: prior modeled versus new original nested order, final-function boundary, fixed pointer versus runtime contents, absent/downgrade fields and reserved/cleared extents separated. **QG6** Pass: pinned primary bytes/metadata/strings, reconstructed proofs, independent byte oracles/replay and controls; native origin/ownership/receiver gaps explicit. **QG7** Pass: impact-ranked bounded continuation above. `full_goal_complete=false`. [SB1-SB7]


## Collection entry and copied-header follow-up

The [boot-header handoff](kernel_boot_header_handoff_report.md) advances the outer boot path to the original collection LC_UNIXTHREAD entry and resolves the missing root producer through the later856 B header copy. Its source header+0x1d8 equals embedded record+0x38, while the following pointer publication supplies the copied device structure. Snapshot equality across selector15 remains a preservation assumption; native callback/receiver effects and ownership remain unknown.


## CPU identity and initialization-order follow-up

The [boot CPU identity report](kernel_boot_cpu_identity_report.md) locates original boot CPU/cluster pointer publication and main continuation thread construction. Source binds the bootstrap thread to fixed CPU-data, installs thread registers, and distinguishes bootstrap versus non-bootstrap initialization by CPU-data pointer identity. Nineteen source contracts and independently checked private paths narrow prior thread fixtures, without proving complete topology enumeration, native startup continuity or opaque receiver behavior.


## Source-produced topology handoff follow-up

The [CPU topology handoff increment](kernel_cpu_topology_handoff_report.md) traces source-produced boot selection through original main and thread construction before the later CPU-initializer epoch. It recovers mask/reservation, affinity prefixes, type bookkeeping and the post-enumeration parser/system-register gate. Receiver effects, actual boot environment and a matched daemon/kext/kernel transaction remain unknown.
