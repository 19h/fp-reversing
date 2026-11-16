# Memory and logical CPU inputs to the zone capacity policy

The original ARM/SPTM initializer publishes `_sane_size` through a strict unsigned subtraction gate. The other policy input is the same u32 returned by the exported `_ml_get_max_cpu_number`, maintained by the logical CPU descriptor setter. Thus maximum CPU number plus one is a numbering bound; identifying it with the active CPU count requires additional evidence. The located producer is in the ARM/SPTM initializer rather than the previously proposed VM bootstrap helper. This increment establishes source contracts and independent private source-cut executions; it does not establish a continuous native producer-to-policy epoch. [BI1-BI6]

```text
ARM/SPTM argument prefix
  +-> base-like B, aligned extent, optional override -> _max_mem
  +-> separate +0x478 words U1/U2 -> other publications
  |
  +-> intervening ARM initialization [captured; not executed]
  |
  +-> delta = (A - B) mod 2^64
      strict unsigned _max_mem > delta -> _sane_size = _max_mem - delta
                                         |
                                         +-> high u32 -> small-count policy

CPU descriptor admission [captured; not executed]
  +-> descriptor index i, count = i+1, maximum = unsigned max(old, i)
                                         |
                        +----------------+----------------+
                        |                                 |
                  exported getter                 policy count = max+1
```

## Primary provenance and claim register

Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original collection bytes and original nlist entries provide the primary evidence. No external header layout or contemporary source version is substituted for the pinned image. Original reference data sufficed; no new IDA access or mutation was required.

| Complete compiler interval, end exclusive | Instructions | Bytes | Identification |
| --- | ---: | ---: | --- |
| 0xfffffe000be7400c..0xfffffe000be75924 | 1606 | 6424 | ARM/SPTM initializer; descriptive name supported by original `arm_init_sptm.c` diagnostic |
| 0xfffffe000be83068..0xfffffe000be83f8c | 969 | 3876 | CPU/topology initializer; descriptive role supported by original keys, device-tree traversal and descriptor writes |
| 0xfffffe000be843d0..0xfffffe000be843e0 | 4 | 16 | Exact nlist `_ml_get_max_cpu_number` |
| 0xfffffe000c631f9c..0xfffffe000c6321a8 | 131 | 524 | Retained capacity policy; exact byte match with preceding capture |
| Total | 2710 | 10840 | Seven selected blocks contain83 instructions |

| Claim | Established result | Dependencies |
| --- | --- | --- |
| BI1 | Pinned producer candidates, exact symbols and complete source capture | BI-A1, BI-A2 |
| BI2 | Memory prefix offsets, modular alignment and separate override publications | BI-A1-BI-A3 |
| BI3 | Strict positive `_sane_size` publication and conditional high-word composition | BI-A1, BI-A3, BI-A5 |
| BI4 | Logical descriptor/count/maximum stores, exported getter and policy numbering bound | BI-A1, BI-A3, BI-A4, BI-A5 |
| BI5 | Source proofs, finite semantic oracles, independent replay and altered-source rejection | BI-A1-BI-A4, BI-A6 |
| BI6 | External-control, architectural and native-epoch evidence boundaries | BI-A1-BI-A6 |

Artifacts: [extractor](triage_evidence/recover_kernel_zone_boot_inputs.py), [source audit and private executor](triage_evidence/audit_kernel_zone_boot_inputs.py), [independent existing replay](triage_evidence/replay_kernel_magazine_bootstrap.py), [delivery verifier](triage_evidence/verify_kernel_zone_boot_inputs_delivery.py), [capture](triage_evidence/kernel_zone_boot_inputs_checks.json.zst), [audit receipt](triage_evidence/kernel_zone_boot_inputs_audit.json.zst). Decoded capture SHA-256: `a92b185dd904bffaae386d64b8f25a0792d38016cebb3f3e49e03f69d013245d` (659108 B). Decoded audit SHA-256: `b5e4f5d47373e861310659fd2669ce1854d5d1e39ba1932d225491c2a667523b` (486832 B).

## Candidate discovery and original storage

The locator rehashes725 executable-section spans and scans15,490,987 aligned words. It finds2215 ADRP seeds for the target pages, decodes at most512 instructions per seed, and records80 candidate references and3 candidate store sites. It follows source fallthrough even after branches, propagates literal ADRP/immediate ADD/SUB/register MOV constants, kills written register aliases and volatile constants across calls, and preserves nonvolatile constants under the ordinary ABI. The CPU maximum store uses a long-lived X24 base, explaining why an adjacent-instruction address search is insufficient. This is a bounded candidate generator: indexed accesses, other encodings, more distant definitions, path feasibility and every possible native writer are not exhausted. [BI1]

| Storage / routine | Address | Width | Naming evidence |
| --- | --- | --- | --- |
| `_sane_size` V | 0xfffffe000cb29cb0 | u64 | Exact original nlist |
| Policy feature F | 0xfffffe000cb29cb4 | u32 | High half of V in little-endian storage |
| `_max_mem` M | 0xfffffe000cb5bb90 | u64 | Exact original nlist |
| `_mem_size` | 0xfffffe000cb2fb68 | u64 | Exact original nlist |
| Base-like B | 0xfffffe0007f36958 | u64 | Argument offset+0x10 publication; physical-base role inferred |
| Boundary-like A | 0xfffffe0007e6da98 | u64 | Input to sane-size subtraction; available/reserved-boundary role inferred |
| Early quantity E | 0xfffffe0007ef8228 | u64 | Input to prefix arithmetic; exact field meaning and native units unknown |
| Accepted descriptor index/count C | 0xfffffe0007ef8bec | u32 | Original increment/store and descriptor-index publication |
| Maximum logical CPU number L | 0xfffffe0007ef8bf0 | u32 | Original unsigned maximum update and exact exported getter |
| `_ml_get_max_cpu_number` | 0xfffffe000be843d0 | Function | Exact original nlist; returns zero-extended L |

The three located stores are `_sane_size` at0xfffffe000be752c4, C at0xfffffe000be83320 and L at0xfffffe000be83334. Their source contracts below are stronger than the locator's fallthrough candidates, but do not prove absence of other writers. [BI1]

## Memory prefix and distinct structure words

At entry X0 is the raw override and X1 is an argument pointer. Define all intermediate arithmetic modulo2^64 unless an unsigned comparison is stated:

```text
B      = u64[X1 + 0x10]
E      = u64[0xfffffe0007ef8228]
extent = ((((B + E) mod 2^64) & ~0x3fff) - B) mod 2^64
O      = X0 & ~0x3fff
U1     = u64[X1 + 0x478]
```

The prefix stores u64[X1+8] at0xfffffe0007f36920, B at0xfffffe0007f36958, E at0xfffffe0007e6daa0, extent into `_mem_size` and0xfffffe0007f36960, and U1 at0xfffffe000cb1e2c0. Low14-bit clearing implements16384-address-unit alignment; a physical16384 B interpretation requires byte-addressed physical inputs with the inferred roles. [BI2]

| Source condition | `_mem_size` / `_max_mem` after successful prefix | 0xfffffe000cb51650 | Qualification |
| --- | --- | --- | --- |
| O=0 or extent<=O, unsigned | extent / extent | U1 | No override clamp |
| O!=0 and extent>O and U2>=E, unsigned | O / O | (U2-E+O) mod2^64 | U2 is loaded through another pointer |
| O!=0 and extent>O and U2<E, unsigned | Initial extent / unchanged `_max_mem` | Unchanged | Branch to original diagnostic before final publications |

Here `root=u64[0xfffffe0007ef9168]` and `U2=u64[root+0x478]`. The source does not establish root=X1 or U2=U1. One private case deliberately supplies different U1/U2 values. The copy at0xfffffe0007f36960 retains the original extent even when `_mem_size` and `_max_mem` are clamped. No recovered header definition independently identifies offset+0x478; it is not assigned a physical-memory field name here. [BI2]

The rejection at0xfffffe000be75900 uses original filename `arm_init_sptm.c` at0xfffffe00070621f9 and diagnostic at0xfffffe0007062748: `memory override is too small to boot; check the maxmem/memsize boot-args @%s:%d`. This supports memory-override/boot context, but neither native caller control of X0 nor the exact parser-to-entry relationship is established by this cut. Execution stops before diagnostic handling; native termination is unknown. [BI2,BI6]

## `_sane_size` writer and high-word composition

The original nine-instruction cut at0xfffffe000be752a4..0xfffffe000be752c8 loads A, B and M, computes delta=(A-B) mod2^64, then executes `SUBS M-delta; B.LS diagnostic`. The branch at0xfffffe000be752bc rejects M<=delta unsigned. Only the admitted path publishes V=M-delta at0xfffffe000be752c4; V is strictly positive. Equality, zero and unsigned underflow reject. [BI3]

The source does not separately test A>=B. A private width control uses A=B-2 and M=2^64-1: delta=2^64-2 and V=1, so the source admits it. A physical interpretation as maximum memory minus a nonnegative reservation therefore depends on valid address ordering and input units; the modular source contract does not. [BI3]

Under M>delta unsigned, the following equivalence is proved with65-bit threshold arithmetic:

```text
F != 0
  iff V >= 2^32
  iff zero_extend_65(M) >= zero_extend_65(delta) + 2^32
```

Using a65-bit sum prevents an overflowing64-bit threshold from changing the statement. This refines the small-count capacity branch in the [boot-order report](kernel_zone_boot_order_report.md) and [magazine-bootstrap report](kernel_magazine_bootstrap_report.md). It is a conditional same-value composition, not evidence that intervening initialization or a later writer preserves the native value. The formerly proposed VM helper0xfffffe000c637698 is not the writer located here; the producer is in the earlier ARM/SPTM interval. [BI3,BI6]

## Logical CPU descriptor publication and environmental inputs

Original0xfffffe000be831a0..0xfffffe000be831a8 establishes X24=0xfffffe0007ef8bec. The selected setter cut loads its descriptor-array base from u64[X24+0x1c]. For incoming index i, it computes d=136*zero_extend_64(i). If d equals sign_extend_64(low32(d)), the selected pointer is base+sign_extend_64(low32(d)); otherwise it selects base+d with its top16 bits replaced by0x2bad. Private cases exercise only small indices selecting the ordinary pointer; native admission or dereference of the alternative is unknown. [BI4]

| Original PC | Effect |
| --- | --- |
| 0xfffffe000be83320 | C=(i+1) mod2^32 |
| 0xfffffe000be83324 | u32[descriptor]=i |
| 0xfffffe000be83328..0xfffffe000be83334 | L=unsigned max(old L,i) |
| 0xfffffe000be843d8 | Getter returns zero_extend_64(u32[L address]) |
| 0xfffffe000c631fbc..0xfffffe000c631fc8 | Policy count N=(L+1) mod2^32 |

C and L both have zero initial file bytes. With sequential accepted indices and no other writers, the maximum plus one can equal the accepted descriptor count. That requires the admission/initialization epoch; the source setter and getter alone establish a logical numbering bound. They do not establish the number of online, active or physically present CPUs. L=0xffffffff gives N=0 as a width control, not a valid native topology assertion. [BI4]

| Original string | Address | Surrounding source context |
| --- | --- | --- |
| `cpus` | 0xfffffe00070de859 | Parser call at0xfffffe000be830cc, declared4 B output |
| `cpumask` | 0xfffffe000706412a | Parser call at0xfffffe000be830f0, declared8 B output |
| `/cpus` | 0xfffffe00070ea8de | Device-tree CPU-root traversal |
| `state` | 0xfffffe00070ea8e4 | CPU-node property lookup |
| `running` | 0xfffffe00070ea8ea | Original state comparison |

The full captured topology body contains earlier mask, limit and state checks. The selected setter starts after those decisions and declares i explicitly. Device-tree helpers0xfffffe000c662324/0xfffffe000c662110 and enumeration helper0xfffffe000c5e4550 are not executed here. These are environmental touch points, not proof that a fairplayd client can alter boot arguments or CPU topology. [BI4,BI6]

## Validation and exact scope

Nine nonvacuous source queries are UNSAT: memory offset/alignment publications, the rounded-zero override gate, the sane-size gate and linked admitted store, CPU store tail/base/getter, policy count and policy high-word branch. One additional nonvacuous composition query proves the65-bit equivalence; two prior byte-separation lemmas are rechecked. Coverage is52 distinct source PCs/59 instruction instances,50 linked-edge obligations and48 checked read-over-distinct-store rewrites. Formal coverage is not asserted for every selected or captured instruction. [BI5]

| Independent finite components | Cases | Covered distinctions |
| --- | ---: | --- |
| Memory prefix including original prologue | 8 | Absent/rounded-zero/smaller/larger override, unaligned B, diagnostic, u64 wrap, distinct U1/U2 |
| Sane publication | 6 | Positive values, exact zero boundary, underflow rejection, zero input, backward-address modular admission |
| CPU setter | 5 | Indices0/1/9/2, existing larger maximum, maximum0xffffffff |
| Exported getter | 4 | Maximum0/1/9/0xffffffff |
| Total | 23 | 96 independent semantic checks |

The positive components execute454 source visits over73 captured PCs. They use no callee API models and no logical call envelopes. Eight prefix PACIBSP steps use the existing logical PAC treatment; native hardware authentication is untested. Components are independent source cuts with explicitly seeded memory/register inputs, not a continuous execution of ARM initialization, topology enumeration and capacity policy. The prefix intentionally stops with its original frame still active; no full-function return is asserted. [BI5]

Fresh CPU replay uses the unchanged existing replayer, which does not import the new executor/audit. It checks454 source visits,179 writes/1372 B,72 reads/540 B,23 boundaries,24117248 final private-RAM bytes and1768 recorded final-region bytes. The latter include private descriptor storage, despite the inherited receipt field name `global_bytes_checked`. Whole nonstack private RAM and exact declared region/guard bytes are checked by the semantic oracle; complete private RAM is checked by replay. A NOP at the sane-size store0xfffffe000be752c4 and a NOP at the maximum store0xfffffe000be83334 each fail the independent semantic oracle. These negative cases are rejection controls; they are not included in positive replay counts. [BI5]

Extraction costs O(collection bytes + scanned words + seeds*512 + captured source) time, with O(collection bytes + candidates + captured source) space. Each private CPU has1048576 B RAM and a1000-instruction limit per cut, plus source pages/journals. Proof construction costs O(source + formula DAG), and finite execution/replay O(visits + journals + mapped state); solver search is separate with30 s per query. All arithmetic is exact little-endian u32/u64 bit-vector arithmetic; no statistical error estimate applies. The alignment, storage widths and136 B descriptor stride are exact source constants. Native physical units and actual boot values remain unknown. [BI5]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BI-A1: Pinned input identities, compiler intervals, original symbols and byte decoding | BI1-BI6 | Rehash source/collection and725 spans; recapture4 functions and compare the retained policy; changed bytes invalidate the pin |
| BI-A2: Bounded locator constant propagation and ordinary nonvolatile call ABI | BI1, BI6 | Reconstruct each candidate instruction/address; extend to indexed/distant accesses and callee effects before asserting complete references; locator alone cannot prove a path |
| BI-A3: Declared source-cut register/storage inputs, disjoint owned regions and logical PAC | BI2-BI6 | Nonvacuous premises, separation lemmas, exact regions/guards, whole-RAM replay and both NOP controls; native aliasing/PAC failures invalidate a native join |
| BI-A4: Selected CPU indices follow earlier admission and choose ordinary descriptor storage | BI4-BI6 | Recover full mask/state/limit traversal and actual descriptor allocation; test the signed-displacement alternative separately; finite small indices do not establish native bounds |
| BI-A5: Same-value producer-to-consumer epoch; physical interpretations additionally require ordered, consistently dimensioned inputs | BI3, BI4, BI6 | Locate intervening writers and join original calls in one epoch; A=B-2 width control defeats an unstated nonnegative-reservation assumption; U1!=U2 defeats a shared-structure assumption |
| BI-A6: Independent CPU replay and semantic oracles cover only recorded cuts and fixtures | BI5, BI6 | Replay original bytes/read/write journals and final complete private RAM; reject source-store mutations; full native ARM/topology execution remains a separate obligation |

## Architectural boundary and bounded continuation

These producers refine the kernel startup environment supporting recovered IPC-zone and allocation paths. They establish no new process-local Mach name, receive/send right, right transfer, endpoint or message-emission location. The [Mach-port report](mach_ports_report.md) and [ABI report](interface_abi_report.md) retain the actual daemon/kext interface evidence. Native boot success, allocator backing/ownership, synchronization and matched fairplayd/provider transactions remain unknown. [BI6]

| Impact | Bounded continuation | Required evidence |
| --- | --- | --- |
| High | Join ARM memory/topology producers to capacity-policy consumption in one unchanged epoch | Actual initialization call chain, intervening writes, native input roles/units and admission |
| High | Replace magazine and IPC callback return models with original bodies in one continuous startup execution | Complete raw cache/statistics backing, setup callbacks, prerequisites, publication and ownership |
| Medium | Recover original VM helper and its phase/cursor prerequisites before phases6/7 | Full0xfffffe000c637698 body, actual phase/cursor state and helper effects |
| Medium | Resolve rank1 startup effects before selected IPC-zone constructors | Original callbacks0xfffffe000c636524 and0xfffffe000c637f1c; native allocation, publication and dynamic-ID effects remain to be integrated |
| High | Correlate the daemon/user-client/provider/kernel boundary in one observed transaction | Matching image identities, request/response bytes, rights, status, ownership and epoch evidence |

## Quality gates

**QG1** passes: factual source analysis requires no normative content. **QG2** passes: BI-A1-BI-A6 declare dependencies and falsification probes. **QG3** passes for this increment: memory/CPU producer contracts, environmental touch points and Mach-interface boundaries are covered; the full investigation remains active. **QG4** passes: byte extents, raw units, modular widths, unsigned gates,65-bit composition and complexity are explicit. **QG5** passes: U1/U2 identity, signed descriptor alternative, backward-address arithmetic, zero-count wrap and independent epochs are separated. **QG6** passes: original bytes/nlist, fresh extraction/proofs, independent semantic checks/replay and mutation controls provide provenance. **QG7** passes: bounded impact-ranked continuation is recorded. `full_goal_complete=false`.


## Permanent storage and initialization prerequisites

The [permanent-storage report](kernel_permanent_storage_report.md) advances the raw backing frontier with original32/64 B allocator calls, fixed setup records and source creator/cache joins. It does not join ARM/topology producers to these consumers in one native epoch. Ready-page and cache-count preservation demonstrate an additional zero-initialization prerequisite; original refill, complete startup, native ownership and daemon transaction pairing remain unknown.


## Context and CPU initialization follow-up

The [mapping context report](kernel_mapping_context_report.md) extends the captured ARM initializer with its original boot-root conversion/publication cut and original call to the complete pmap context initializer. The call rounds its declared SP+0x30 input to32 MiB before passing X0. Actual geometry/bounds/root stores and CPU result-pointer publication replace selected downstream fixtures in byte-exact declared call epochs. Full ARM/topology initialization, native range ownership and a continuous boot-to-consumer epoch remain open.


## SPTM boot record and nested initialization follow-up

The [SPTM boot-input report](kernel_sptm_boot_inputs_report.md) extends the environment frontier with the original versioned converter-state publisher and actual pool/shared/CPU initialization inside the pmap context call. It retains exact memory-budget arithmetic with both u32 truncations and0x6830d6e5 multiply/shift stages. The original topology pointer is a fixed chained target; descriptor contents and native CPU admission still require producer evidence. Boot root has no writer candidate in the bounded locator, which does not establish absence of a native writer.
