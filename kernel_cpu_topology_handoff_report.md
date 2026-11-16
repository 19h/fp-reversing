# Source-produced CPU topology and original thread handoff

The original CPU enumerator now supplies the boot-record pointer consumed by original thread construction in selected private executions. Main calls enumeration at 0xfffffe000c639cb8, receives its return at 0xfffffe000c639cbc, executes the intervening 34-word configuration helper and continues directly into the original 1472 B thread-template copy and register setter. No boot-record pointer or ordinal is injected between those source operations. Environmental lookup/iterator/property/parser outputs remain explicit models; complete startup, authentic device-tree contents, hardware effects and a matched daemon/kext/kernel transaction remain unknown. [TH1-TH7]

```text
original main BL at c639cb8
  original topology enumerator
    declared lookup / iterator / property / boot-option outputs
    original _strncmp, scalar decoding, CPU and cluster record stores
    original count, membership, boot-pointer and TPIDR publication
    declared no-RAM selector0e wrapper returns
  original return to c639cbc [record checkpoint; no state reset]
  original post-enumeration helper
    declared siq_realtime_thread_mode parser output
    original unsigned control gate and logical system-register write
  original return to c639cc0 [record checkpoint; no state reset]
  original CPU-map stores, memcpy, thread binding and register setter
  explicit same-complete-RAM new caller epoch at c639dd8
    original CPU initializer with declared cache/context helper returns
```

Diagram suffixes share prefix 0xfffffe000. Twenty-three private cases produce 39 completed CPU records, 46 original comparison entries, 13 original enumeration-to-main return checkpoints and 12 post-helper returns/thread constructions. Cases also cover original diagnostic prefixes and stop before a null boot-record load; no native fault is triggered. [TH2-TH6]

| Claim | Established result | Dependencies |
| --- | --- | --- |
| TH1 | Pinned routine/data/fixup custody, exact API aliases and corrected opaque-word locations | TH-A1 |
| TH2 | Source admission, slot reservation, length-bounded state comparison and boot selection | TH-A1-TH-A3 |
| TH3 | Original CPU/cluster properties, masks, merge bookkeeping and affinity prefixes | TH-A1-TH-A3 |
| TH4 | Original post-enumeration configuration gate and uninterrupted source path into thread construction | TH-A1-TH-A5 |
| TH5 | Lower selector0e call/emission boundaries and remaining environmental/native contracts | TH-A1-TH-A5 |
| TH6 | Local proofs, independent record/byte algorithms, fresh replay and altered-source controls | TH-A1-TH-A6 |
| TH7 | Mach/daemon boundaries and impact-ranked continuation | TH-A1-TH-A7 |

Primary provenance is collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, original compiler starts, nlist, chained fixups and exact source/data bytes. The preserved normalized kext remains SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Reference files sufficed; no IDB was read or modified. [TH1]

Artifacts: [extractor](triage_evidence/recover_kernel_cpu_topology_handoff.py), [private executor](triage_evidence/probe_kernel_cpu_topology_handoff.py), [independent record formulas and replay](triage_evidence/replay_kernel_cpu_topology_handoff.py), [source audit](triage_evidence/audit_kernel_cpu_topology_handoff.py), [delivery verifier](triage_evidence/verify_kernel_cpu_topology_handoff_delivery.py), [source capture](triage_evidence/kernel_cpu_topology_handoff_checks.json.zst), [audit receipt](triage_evidence/kernel_cpu_topology_handoff_audit.json.zst). Decoded capture: 509708 B, SHA-256 `19aaee1b05784059be3759ece2f2be885199ad37637bdaf45fd27887dca1bf0a`. Decoded audit: 48350396 B, SHA-256 `e89a176ac14cb56abd6fbe993080960652deda0132b9358e104f640cb03275d5`. [TH6]

## Source custody and environmental ABI

Seventeen captured routines contain 3356 words/13424 B; ten intervals exactly match the [previous CPU-identity capture](kernel_boot_cpu_identity_report.md). The new capture contains 28 exact strings, 18 logical data blocks and three retained pointer fixups. Exact target nlist identifies `_strncmp`, `_SecureDTLookupEntry` and `_SecureDTIterateEntries`; the boot-option parser, property-reader, named-node lookup and post-enumeration helper retain role descriptions rather than invented original names. [TH1]

| Original interval | Words | Exact name or role | Witness treatment |
| --- | ---: | --- | --- |
| 0xfffffe000be83068..0xfffffe000be83f8c | 969 | CPU/cluster enumerator; exact name unknown | Original source, selected entry-to-return/diagnostic paths |
| 0xfffffe000bc9dbf0..0xfffffe000bc9dd7c | 99 | _strncmp | Original source; 17 PCs exercised |
| 0xfffffe000c5e48a4..0xfffffe000c5e4ca8 | 257 | Boot-option parser | Explicit output writes and result/clobber model |
| 0xfffffe000c662324..0xfffffe000c6625bc | 166 | _SecureDTLookupEntry | Explicit CPU-node lookup output model |
| 0xfffffe000c5e4550..0xfffffe000c5e46d4 | 97 | _SecureDTIterateEntries | Explicit ordered child/output model |
| 0xfffffe000c5e40f0..0xfffffe000c5e4318 | 138 | Named-node lookup | Explicit name/arm-io result model |
| 0xfffffe000c662110..0xfffffe000c6622b8 | 106 | Property-reader role | Explicit pointer/length outputs; original consumers execute |
| 0xfffffe000be85a48..0xfffffe000be85ad0 | 34 | Post-enumeration option/system-register helper | Original source; all 34 PCs exercised across cases |

The prior report's opaque-word location description is corrected: one word is in captured main at 0xfffffe000c63a3c0, while two are in lower wrapper 0xfffffe000c620ec4 at+0x20/+0x28. All three remain preserved raw bytes and are never executed. The correction changes no source capture, count or prior receipt hash. [TH1]

Private fixtures provide 65536 B base RAM plus 131072 B tree/output storage and separately mapped original image pages. Tree bounds are supplied as base/extent/end globals 0xfffffe0007f8b508/+8/+16 and initialized flag+24; 0xfffffe0007f8b6e8 supplies the bootargs pointer. The output storage contains opaque node anchors and property bytes, not a claimed authentic serialized Apple device tree. Models validate original call arguments, output locations, source-requested widths and logical tree bounds; original parser/lookup/iterator internals are captured but unexecuted. [TH2,TH5,TH-A2]

The iterator model returns ordered child anchors and writes only the requested output pointer. It preserves the 40 B iterator state produced by original source. Fresh replay checks that state on each call: initialized lookup success uses two root pointers followed by three zero words, lookup absence uses tree-base fallback, and an uninitialized tree leaves the state zero. These are explicit private iterator contracts, not recovered native internal mutation semantics. The lookup-absent case establishes source fallback construction under that contract; it does not establish authentic child discovery after a failed lookup. [TH2,TH5]

## Admission and boot-record selection

Source defaults `cpus` to 16 and `cpumask` to 0xffffffffffffffff before parser calls. Each child must supply `state`; original `_strncmp` compares its bytes against `running` for the supplied u32 length. A zero result means the selected running path. The following algorithm expresses the recovered admission behavior; all counters/limit arithmetic is u32 and mask arithmetic is u64. [TH2]

```text
for each child returned by the declared iterator:
    comparison = original_strncmp(state, "running", supplied_length)
    running = (low32(comparison) == 0)
    bit = mask & 1; mask >>= 1
    if running and bit == 0: byte825c = 0
    if not running and bit == 0: continue
    if not running and count >= ((limit - 1) mod 2^32)
                   and boot_record_pointer == 0: continue
    if count >= limit: finish enumeration
    construct CPU record at CPU_array + count*136
    construct/update cluster state
    if running: publish CPU/cluster record pointer pair
    call declared selector0e wrapper with zero-extended stored reg32
```

The reserved-slot test precedes the count-limit finish test and applies only to nonrunning children. The source uses a length-bounded comparison, not exact whole-string identity. In private cases, `run` with length 3 and `runningX` with length 7 compare equal; length 0 selects zero without loading a byte. `runningX` with length 8 does not compare equal. Every admitted matching node overwrites the boot pointer pair, so the last such node determines the selected ordinal in those cases. Native state lengths, uniqueness and parser admission remain unknown. [TH2,TH6]

Source CPU records retain the previously established 136 B stride, ordinal at+0, low32 `reg` at+4 and cluster index at+8. Ordinal is admission order, distinct from `reg` and physical affinity bytes. The private sixteen-CPU case admits fifteen nonrunning children before a matching final child, publishes ordinal 15 and then consumes that source-produced ordinal in original thread construction. The resulting zero-extended u16 thread+0x1b8 still gives zero under the signed ASR16 lower-block formula while unchanged. [TH2,TH4]

## Cluster and environmental data flow

The [previous property matrix](kernel_boot_cpu_identity_report.md#device-tree-property-abi) remains the static field mapping. The new independent algorithm checks every nonstack byte after complete or partial property processing, including scalar truncation, 16 B pairs, first-CPU cluster fields, type counters, masks and boot pointers. It separately checks partial records at missing-state, missing mandatory reg, malformed scalar/pair and malformed chip-revision diagnostics. [TH3,TH6]

| State | Source field(s) | Established behavior |
| --- | --- | --- |
| Physical cluster grouping | Byte 1 of stored reg32; CPU record+8 | Maps selected physical affinity bytes 0/1/2 to encounter-order cluster indices |
| Cluster CPU membership | Cluster u32+8 and u64+0x10 | Count increments modulo 2^32; mask sets `1 << (ordinal&63)` |
| CPU type counts | 0xfffffe0007ef8c30 + type*4 | Increment for every processed CPU of that type |
| Cluster creation type counts | 0xfffffe0007ef8c44 + initial_type*4 | Increment on cluster creation; later type merges do not migrate this counter |
| Cluster aggregate type | Cluster u32+4 | P/2 and M/3 combinations merge to 4 in either order; selected incompatible P/E case produces 0xffffffff |
| Per-affinity core bound | Original local array | Signed maximum of previous bound and low8 reg byte; initialized zero |
| Affinity prefix positions | 0xfffffe0007ef8c78/+8/+16 | Present affinity positions accumulate earlier maxima+1; absent positions remain 0xffffffffffffffff |
| Chip revision | u32 global 0xfffffe0007ef8c28 | Optional scalar truncated to low32; absent lookup/property or uninitialized tree selects 0xff |
| Cluster-power word | u32 global 0xfffffe0007ef8c58 | File value 0; nonzero cluster-power-down sets 1; present enable_skstb/enable_skstsct clears 0; later cluster_power output can overwrite all 32 bits |

Sparse physical core values make prefix positions differ from CPU counts. A three-cluster case uses core bytes 4, 2, 1, giving positions 0, 5, 8 for three admitted CPUs. A P/M/P case yields one final aggregate type 4 cluster, while the creation counter still records one initial P cluster and zero initial M clusters. The reverse M/P case checks the opposite creation attribution. These are source/fixture semantics, not observations of actual hardware topology. [TH3]

| Private case | Admitted CPUs | Clusters | Selected boot ordinal | Affinity positions 0/1/2 |
| --- | ---: | ---: | ---: | --- |
| Three physical clusters, running middle | 3 | 3 | 1 | 0 / 5 / 8 |
| Prefix matches and P/M merge | 3 | 1 | 2 | absent / 0 / absent |
| Reserved slot, cpus=1 | 1 | 1 | 0 | absent / absent / 0 |
| Sixteen CPUs, final child running | 16 | 1 | 15 | 0 / absent / absent |

When tree initialization is set, original source also writes the tree base to 0xfffffe000cba40e8 before the named arm-io lookup. A complete property case exercises 1/2/4/8 B scalar widths, all five 16 B register pairs, explicit die/core IDs, chip revision and configuration precedence: cluster-power-down sets 1, enable_skstb clears it, then cluster_power writes 7. The full byte formulas check that ordered result and preserved surrounding data. [TH3]

## Original return path, post-enumeration helper and lower boundary

For 13 cases, original main's BL 0xfffffe000c639cb8 enters enumeration and original RETAB returns to 0xfffffe000c639cbc. This location is a recorded checkpoint only; registers, SP and memory are not reset. The following original BL enters helper 0xfffffe000be85a48. It asks the modeled parser for `siq_realtime_thread_mode`, bootargs+0x6c, output 0xfffffe0007ef8e98 and width 4 B. The original file control word is 2. [TH4,TH6]

| Original PC | Exact contract |
| --- | --- |
| 0xfffffe000be85a84 | Parser call with X0=bootargs+0x6c, X1=option string, X2=0xfffffe0007ef8e98, W3=4, W4=0 |
| 0xfffffe000be85a88..0xfffffe000be85a94 | Load control u32; unsigned value>=4 selects diagnostic body 0xfffffe000be85aa8 |
| 0xfffffe000be85a94 | Admitted control path writes zero to implementation-defined system register s3_4_c15_c10_4 |
| 0xfffffe000be85aa4 | Original logical authenticated return to main 0xfffffe000c639cc0 |
| 0xfffffe000be85acc | Invalid-control body calls original diagnostic target 0xfffffe000c62a2b0 |

Default 2 and explicit 3 reach thread setup; explicit 4 enters that diagnostic with the already-produced topology retained and before the system-register write. Register naming comes from the decoded operand; its hardware meaning and effects remain unknown. Native parser semantics and execution of that system instruction are not claimed. Twelve source returns reach 0xfffffe000c639cc0, execute original CPU-map stores, full 1472 B memcpy, thread fields and register setter, and stop at 0xfffffe000c639dd8. Only then does an explicit new caller epoch preserve complete RAM/system state and invoke the previously recovered CPU initializer, bypassing later main callbacks. [TH4,TH-A4,TH-A5]

The enumerator calls lower wrapper 0xfffffe000c620ec4 at 0xfffffe000be83250 with X0 equal to zero-extended stored reg32. The wrapper itself remains a no-RAM return model in execution. A separate local source proof establishes X16=0x0e and flag-selected raw emission words at 0xfffffe000c620ee4/0xfffffe000c620eec. These words are respectively 0x00201420 and 0xd4e00000. Its earlier call to 0xfffffe000bc9c090 and later call to 0xfffffe000bc9c0fc, opaque return behavior and receiver semantics remain unexecuted; propagation of incoming X0 through those effects is not established here. [TH5,TH6]

## Verification, assumptions and continuation

Twenty-four new nonvacuous source queries are UNSAT over 99 distinct PCs/instruction instances and 75 linked-edge obligations. Four prior thread-binding/setter/block-offset/bootstrap-address contracts are re-solved against unchanged captured source. New obligations cover mask consumption, running/nonrunning admission, modular reserved-slot arithmetic, low32 reg storage and wrapper ABI, 88 B cluster geometry, membership shifts, count/max updates, signed core maximum, pair size/copy, chip/power publication, post-helper parser/control/system ABI, selector0e emission selection and bounded comparison. The model explicitly handles post-index LDRB, UMULL and signed GT; CCMP replaces the preceding SUBS condition state before subsequent branches. The SP+0x80 local bound slot has an explicit 8 B owned region. [TH6]

Twenty-three components pass 3114 independent topology/post-helper checks and 1104 thread/caller checks, 4218 total. They include all 23 case configurations in the executor, 39 completed records, 46 original comparisons, 13 source boot-record return checkpoints, 12 post-helper returns and 12 complete-RAM caller epochs. There are 12 original 1472 B copies. Five altered-source controls are rejected: reg store 0xfffffe000be834b8, boot-pointer store 0xfffffe000be833ac, reservation branch 0xfffffe000be832f0, membership store 0xfffffe000be83244 and post-helper MSR 0xfffffe000be85a94. Controls are excluded from positive totals. [TH6]

Fresh replay does not import the executor. It checks 29359 source visits/1062 unique PCs, 6936 reads, 6816 writes, 929 declared environmental/helper returns, 599 logical system/PAC effects and all 7901184 final mapped bytes. Independent record/formula comparisons separately check 7806976 topology bytes, 4468736 post-helper checkpoint bytes and 4128768 thread/caller bytes, cumulatively across cases/checkpoints. These byte counts overlap across phases; they are not disjoint physical memory. All private stack bytes also match fresh replay. [TH6]

Execution coverage is 760/969 enumerator PCs, 17/99 comparison PCs and 34/34 post-helper PCs. Original source is executed from actual selected entry/return sites, but this is not exhaustive coverage of every path or a universal proof of the 969-word routine. Private inputs use at most 16 nodes and physical affinity bytes 0..2; original count/array admission beyond those cases remains unproved. The execution limit is 10000 source visits/component; the largest selected case uses 7408. All three captured undecoded words remain unexecuted. [TH6]

Extraction costs O(K+F+I+D+N) time/space in collection bytes K, fixups F, source I, data D and symbol inventory N. Proof construction costs O(I+Q) in source/formula DAG Q; SMT search is separate with 30 s/query and no polynomial claim. Execution/replay/formulas cost O(V+J+M+P) time/space in visits V, journals J, mapped bytes M and fixture properties P; phase materialization sorts journal/model effects, adding O(J log J) time. Arithmetic is exact little-endian u8/u16/u32/u64 or stated modular arithmetic; no statistical uncertainty estimate applies. Archives use `zstd --ultra -22 -q -T1`, decoded roundtrip validation and decoded/nested path hygiene. [TH6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| TH-A1: Pinned bytes, compiler starts, symbols, fixups and source identities identify this build | TH1-TH7 | Rehash originals, 17 functions/ten prior matches, 28 strings, 18 data blocks and three fixups; distinguish one main/two wrapper opaque words; no cross-build equivalence |
| TH-A2: Declared environmental outputs select the modeled caller paths | TH2-TH7 | Independently reconstruct 929 returns/clobbers/output writes and 40 B iterator state; lookup absence, initialization flag, scalar/pair errors and options exercised; authentic tree format and native iterator mutation unknown |
| TH-A3: Private node/order/width/affinity/count inputs are valid within the stated model domain | TH2-TH7 |23 cases, ordinals0/1/2/15, mask/reservation, prefixes/zero lengths, sparse affinities, both P/M orders, absent type, malformed/missing properties and before-load null stops; native admission/control unknown |
| TH-A4: Selected original main entry cut has the declared readable bootargs/stack and native-independent logical return behavior | TH4-TH7 | Original BL/RETAB sequence through enumeration and 34-word helper, 13/12 checkpoints, twelve full copies and full journals; earlier main prologue/caller and later registration interval remain unexecuted |
| TH-A5: Logical system/PAC envelopes and explicit later CPU-caller epoch permit only conditional composition | TH4-TH7 | Default 2/control 3/control 4 gate, all 34 helper PCs, zero register write and 12 complete-RAM epochs; actual PAC bits, synchronization, hardware effects and intervening thread mutation unknown |
| TH-A6: Local lifting, independent record algorithm, byte checks and fresh replay support only this increment | TH6,TH7 |24 nonvacuous proofs, four prior rechecks, 4218 checks, five controls and explicit 760/969 coverage; decoder/emulator commonality and unexecuted native effects remain limits |
| TH-A7: CPU/boot contracts do not establish a Mach transfer or daemon-originated transaction | TH7 | Correlate actual daemon/user-client/provider payloads, rights, statuses and kernel epochs; no such transaction newly observed |

No new incoming/outgoing Mach right, endpoint or message-emission site is established. Selector0e is a lower wrapper selector, not a Mach port name. The [Mach inventory](mach_ports_report.md) retains endpoint evidence. Direct fairplayd influence over the modeled boot options or CPU properties, and a matched FairPlayIOKit transaction through these kernel effects, remain unknown. [TH7]

| Impact | Next discriminating work | Evidence it could establish |
| --- | --- | --- |
| High | Build authenticated tree fixtures and execute original lookup/property/iterator/parser implementations | Replace environmental output contracts with original format parsing and internal state transitions |
| High | Execute the remaining main interval after thread setup and original cache/context helpers | Replace the remaining explicit caller epoch; establish thread/global mutation and initialization order |
| High | Recover CPU-data+0xa38 and later thread+0x1b8 producers | Native lifetime of TPIDR_EL0 low48 payload and later SPTM block selection |
| High | Recover selector0e pre/post-call effects and its receiver together with selector15/0x13/0x32 | Incoming reg propagation, returned state ownership and lower-facility interaction |
| Medium | Correlate sparse physical core IDs and mixed cluster types with downstream prefix/counter consumers | Distinguish cardinalities, affinity spans and creation-time classifications in native data |
| High | Pair a real daemon/user-client/provider transaction with kernel traffic | Cross-layer payload/right/status/epoch correlation beyond boot prerequisites |

**QG1** Pass: factual technical analysis. **QG2** Pass: TH-A1-TH-A7 register dependencies and falsification probes. **QG3** Pass for this increment: original routine roles, environmental/API ABI, topology/control flow, source-produced thread handoff, lower/Mach boundaries and reporting covered; full investigation remains active. **QG4** Pass: widths, byte units, exact arithmetic, extents, complexity and reproducible artifacts stated. **QG5** Pass: running prefixes versus literal identity, affinity spans versus counts, creation counters versus merged type, original return checkpoints versus later call epoch, source versus native execution and opaque-word locations distinguished. **QG6** Pass: pinned primary target bytes/metadata, reconstructed proofs, independent records/bytes, fresh replay and controls; coverage/native limits explicit. **QG7** Pass: bounded impact-ranked continuation above. `full_goal_complete=false`. [TH1-TH7]


## Original serialized-tree execution follow-up

The [serialized-tree execution increment](kernel_secure_dt_execution_report.md) replaces the declared lookup/property/iterator/named-node outputs with original routines on serialized private fixtures. It recovers finer miss/exhaustion statuses and output/state mutation, a real initializer publication and recursive cursor effects. Boot-option outputs, the explicit initializer-to-main and later CPU-caller epochs, native effects and daemon pairing remain conditional.


## Original boot-option execution follow-up

The [boot-option execution increment](kernel_boot_option_execution_report.md) supplies original parser-produced cpus/cpumask/power/thread-mode values to original enumeration and its post-helper. The independent option map is used only for verification and is not injected into execution. Original tree readers and eight full thread copies compose; actual startup/receiver effects remain unknown.
