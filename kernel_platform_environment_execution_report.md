# Original platform return, clock state and pre-enumeration main continuation

Original main now executes both input copies, the complete mode-0 platform initializer, its original tree/clock/identity helpers and diagnostic tail, then returns to main's actual call site. Eight private cases continue through timer setup and four original option-parser calls to `0xfffffe000c639cb8`, immediately before CPU enumeration. There is no separate generic tree-initializer call or initializer-to-main fixture epoch. Two earlier registration returns and logical PAC/system effects remain conditional; native startup and a matched daemon/kernel transaction remain unknown. [PE1-PE7]

```text
original main input copies
  actual platform call, mode 0 + copied bootargs
    original environment and inline tree publication
    original range-anchor/cache helper
    original CPU-property clock derivation
    original target/product/chosen property copies
    original assertions/statistics/diagnostic and cpu-factor tail
  original platform return to main 0xfffffe000c639b9c
    original wfe_events_sec calculation
    logical system-register effects
    original icdsb/user_ts_jop/diversify_user_jop/sptm_stability_hacks calls
  stop before original enumeration call 0xfffffe000c639cb8
```

| Claim | Established result | Dependencies |
| --- | --- | --- |
| PE1 | Pinned source closure, literals, strings and exact aliases | PE-A1 |
| PE2 | Continuous private main/platform return without the prior initializer epoch | PE-A1-PE-A4 |
| PE3 | Original range-anchor cache and CPU-derived clock-field contracts | PE-A1-PE-A4 |
| PE4 | Target/product/chosen copy widths, diagnostic mask and cpu-factor policy | PE-A1-PE-A4 |
| PE5 | Timer arithmetic and four later main parser outputs before enumeration | PE-A1-PE-A5 |
| PE6 | Source proofs, independent tree/option/copy/byte checks, replay and controls | PE-A1-PE-A6 |
| PE7 | IPC limits, remaining boundaries and impact-ranked continuation | PE-A1-PE-A7 |

Primary provenance is collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, original compiler starts, nlist, instruction bytes, 37 NUL-terminated strings and four literal blocks. The preserved normalized kext remains SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Supplied references sufficed; no IDB was read or modified. [PE1]

Artifacts: [capture producer](triage_evidence/recover_kernel_platform_environment_execution.py), [private executor](triage_evidence/probe_kernel_platform_environment_execution.py), [independent contracts and replay](triage_evidence/replay_kernel_platform_environment_execution.py), [source audit](triage_evidence/audit_kernel_platform_environment_execution.py), [delivery verifier](triage_evidence/verify_kernel_platform_environment_execution_delivery.py), [capture](triage_evidence/kernel_platform_environment_execution_checks.json.zst), [audit](triage_evidence/kernel_platform_environment_execution_audit.json.zst). Decoded capture: 560704 B, SHA-256 `0991eb84747f495b3ae55d83cfb6784f15138d6b30f4023e319cb765ca73b19d`. Decoded audit: 47450421 B, SHA-256 `e5080b7cd0d7fd243a614f887f038a92cbc270b9fb03b2d3102486bbcec45269`. [PE6]

## Original routines and continuation

Twenty-six captured intervals contain 3170 words / 12680 B. Twenty exactly match retained [environment-publication](kernel_boot_environment_publication_report.md) or [option-parser](kernel_boot_option_execution_report.md) captures. Six additions supply the following bodies; role names are descriptive and their exact original names remain unknown. [PE1]

| Original half-open interval | Words | Recovered role | Executed unique PCs |
| --- | ---: | --- | ---: |
| 0xfffffe000c5e5894..0xfffffe000c5e5c70 | 247 | CPU-property clock-state derivation | 247 |
| 0xfffffe000c5e5c70..0xfffffe000c5e5d98 | 74 | Named arm-io lookup and range-anchor cache | 72 |
| 0xfffffe000c5e507c..0xfffffe000c5e5238 | 111 | Diagnostic-option mask and cpu-factor tail | 111 |
| 0xfffffe000be854e0..0xfffffe000be85598 | 46 | Timer-event divisor and parameter derivation | 46 |
| 0xfffffe000be864d8..0xfffffe000be8654c | 29 | ACTLR read/mask continuation | 12 |
| 0xfffffe000bc9cea8..0xfffffe000bc9ceb8 | 4 | ACTLR write/barrier leaf | 4 |

Existing bodies additionally execute 158/616 main PCs and 302/319 guarded-publisher PCs. Exact aliases for string/copy/tree routines are retained in the capture. The three opaque words and strlen UDF padding remain unexecuted. The anchor's two unexecuted PCs are the early return for an uninitialized tree; these fixtures publish a nonnull serialized-tree base first. The alternate ACTLR entry path remains unexecuted. Unique-PC coverage does not establish exhaustive path coverage. [PE1,PE6]

| Boundary | Original PC | Established behavior |
| --- | --- | --- |
| Platform call | 0xfffffe000c639b98 | X0=0; X1=original 1152 B bootargs-copy destination |
| First new helper call | 0xfffffe000c5e674c | Original BL to clock routine after inline tree publication |
| Platform tail | 0xfffffe000c5e6af8 | Original B to diagnostic/cpu-factor body after restoring the platform frame |
| Actual platform return | 0xfffffe000c639b9c | Original return restores main SP; saved bootargs remain available |
| Timer helper call | 0xfffffe000c639bb8 | Original BL to timer-event calculation |
| ACTLR helper call | 0xfffffe000c639c10 | Original BL, masked value, tail to write/barrier leaf and original return |
| Enumeration call boundary | 0xfffffe000c639cb8 | Original control flow arrives here; enumeration body is not entered in this increment |

All nine components start at actual main `0xfffffe000c639a40`. The prefix, platform return and final boundary each retain complete mutable-state evidence. The two earlier calls at `0xfffffe000c621194` and `0xfffffe000c47cce0` still have declared no-RAM returns with caller-saved clobbers. No tree, parser, string/copy, range, clock, diagnostic or timer output is supplied by a return model. The earlier external entry/callback/opaque handoff into main remains outside this experiment. [PE2,PE-A3,PE-A4]

## Range anchor and clock state

The anchor routine requires initialized tree state and searches for property `name=arm-io`. A failed search returns zero. A successful search with nonzero cache pointer at `0xfffffe000cba40f8` returns cached u64[`0xfffffe000cba4120`]. On a cache miss it reads `device_type` and `ranges`, executes original strlcpy with capacity 32 B into `0xfffffe000cba4100`, publishes that buffer pointer at the cache slot, then returns and caches u64[`ranges data`+8]. [PE3]

The retained range anchor is a raw u64. Its later interpretation as a physical or bus-address base requires the unexecuted mapping consumers; this report does not infer address-space ownership from its numeric value. Selected fixtures supply a NUL-terminated device type and at least 16 B of ranges data. Native property presence, cache lifetime and malformed-input behavior remain unknown. [PE3,PE-A2]

The clock routine returns early when the anchor is zero. Otherwise it initializes a 200 B clock-state block C=`0xfffffe000cb5c5b0`, uses original lookup `/cpus` and original iteration/property/strncmp bodies, and processes children whose `state` compares equal to `running` over the property's recorded byte length. The independent checker uses the actual recorded bytes; source names alone do not determine admission. [PE3]

| Property | Raw u64 destination | Replicated u64 offsets from C | Additional result |
| --- | --- | --- | --- |
| timebase-frequency | C+0x48 | +0x10 | Default raw value 24000000 before CPU processing |
| bus-frequency | C+0x60 | +0x68, +0x70 | C+0=min(raw, 0xffffffff) |
| memory-frequency | C+0xa8 | +0xb0, +0xb8 | No u32 cap in this source path |
| peripheral-frequency | C+0x90 | +0x98, +0xa0 | No u32 cap in this source path |
| fixed-frequency | C+0xc0 | None | Missing property retains current word |
| clock-frequency | C+0x78 | +0x80, +0x88 | C+8=min(raw, 0xffffffff) |

The source tests property length against eight: the eight-byte branch loads u64, and the other captured branch loads u32 with zero extension. Executed scalar fixtures use lengths 4 B and 8 B only. A missing property retains the current raw word. Processing continues over every admitted child, so a later admitted child's present values replace earlier values, while its absent values retain the earlier words. [PE3]

Original literals initialize C+0=100000000 and C+8=400000000, with the adjacent pair zeroed. Much of C+0x20..C+0xc8 is explicitly zeroed, followed by the timebase default at +0x48. With zero admitted CPUs, the literal bus/CPU pair remains intact. An admitted CPU lacking bus/clock properties replaces that pair with the current zero raw words. These are distinct executed cases. [PE3,PE6]

After iteration, the source stores C+0x18=C+0, C+0x20=1, C+0x28=UDIV((2*u64[C+8]) modulo 2^64, u64[C+0]), literal pair 2/1 at C+0x30/+0x38, and C+0x40=UDIV(u64[C+0],u64[C+0x10]). AArch64 UDIV returns zero for a zero divisor; independent formulas and replay check that result in selected default cases. These are exact raw arithmetic contracts. The binary does not encode physical units in the property values, and authentic clock rates are not established. [PE3,PE6]

## Identity, chosen properties and diagnostic policy

The publisher uses original named scans for `device-tree` and `product`, and original lookup `/chosen`. The following destination/width mapping is corroborated by source, original copy execution, per-copy contracts and complete mutable-byte formulas. [PE4]

| Node / property | Destination | Maximum copied bytes | Termination behavior |
| --- | --- | ---: | --- |
| device-tree / target-type | 0xfffffe000cb5c404 | 16 | Copy min(length,16); overwrite last copied byte with NUL |
| product / unique-model | 0xfffffe000cb5c414 | 16 | Same; first destination byte cleared before property lookup |
| product / sub-product-type | 0xfffffe000cb5c424 | 32 | Copy min(length,32); overwrite last copied byte with NUL |
| chosen / debug-enabled | 0xfffffe0007f8b5c8 | 4 | Raw prefix copy; adjacent bytes retained |
| chosen / system-firmware-version | 0xfffffe000cb5c300 | 128 | Copy min(length,128); overwrite last copied byte with NUL |
| chosen / firmware-version | 0xfffffe000cb5c380 | 128 | Same |
| chosen / unique-chip-id | 0xfffffe000cb5c444 | 8 | Raw prefix copy |
| chosen / dram-vendor-id | 0xfffffe000cb5c44c | 4 | Raw prefix copy |

Target/product string paths clear the first destination byte after finding the containing node. The string formulas apply only to nonempty selected properties. Zero-length firmware strings and broader malformed-tree behavior are excluded from the executed domain; no general buffer-admission guarantee is inferred. The 128-byte examples use 140-character source strings plus NUL and establish the capped final-byte replacement. [PE4,PE-A2]

The diagnostic tail clears u32[`0xfffffe0007f8b524`], reads original bootargs+0x6c through the published pointer, and derives these bits with original parser calls. [PE4]

| Bit | Input rule |
| --- | --- |
| 0 / value 1 | `assertions` is present and its parsed u32 is nonzero |
| 1 / value 2 | `statistics` is present and its parsed u32 is nonzero |
| 2 / value 4 | u32[chosen debug destination] is nonzero, and `diagnostic_api` is absent or parsed nonzero |

When the debug destination is zero, the source skips the diagnostic_api parser call and leaves bit 2 clear even if the text requests it. Partial debug copies preserve the destination's other bytes; the fixture initializes that destination to zero explicitly. Native initial contents are not inferred. [PE4]

For `cpu-factor`, a present parsed value is stored as u32 at `0xfffffe000caac7d0`. When the option is absent, root property `target-is-fpga` selects value 10; otherwise the global's prior value is retained. The local stack default 1 is not unconditionally copied to that global. Private fixtures explicitly start the global at 3, so the retained, overridden (17/9) and FPGA (10) cases are distinguishable. [PE4,PE6]

## Main timer and option continuation

The timer helper reads `wfe_events_sec` as an eight-byte option. Absence supplies divisor 1000000; presence computes d=max(1,min(parsed_u64,1000000)). It divides raw timebase word C+0x48 by d to obtain q. For the proved domain 1<=q<=2^32 and the corresponding nonzero frequency/divisor ordering, the stored u32 timer parameter is max(0,ceil(log2(q))-1). The source uses CLZ, word shifts and conditional selection; the formula is not extended beyond that explicit quotient domain. [PE5,PE6]

| Selected input | Raw timebase | d | q | Stored parameter |
| --- | ---: | ---: | ---: | ---: |
| Absent option | 24000000 | 1000000 | 24 | 4 |
| Later running CPU supplies 48000000 | 48000000 | 1000000 | 48 | 5 |
| `wfe_events_sec=0` | 24000000 | 1 | 24000000 | 24 |
| `wfe_events_sec=20` | 24000000 | 20 | 1200000 | 20 |
| `wfe_events_sec=999999999` | 24000000 | 1000000 | 24 | 4 |

For example, q=24 has ceil(log2(24))=5, yielding parameter 4. Ratios and bit counts are dimensionless raw quantities; no physical-rate calibration is claimed. Main stores the parameter at `0xfffffe0007ef8c60`, checks it against 64, then logically ORs `(parameter<<4)|15` into its system-register value. The missing-arm-io case stops at the actual platform return before this timer path; zero-q behavior is outside the stated formula. [PE5]

The ACTLR continuation retains the original read, constant mask and tail to the write leaf. Its logical value is old_ACTLR & `0xfffffffffffff1ff`, clearing bits 9/10/11 while preserving bit 0. Logical CNTKCTL is ORed with 3. Original system instructions and barriers are captured and replayed as explicit logical effects; hardware execution, synchronization and authentication are unknown. [PE5,PE-A4]

The four later main calls identified in the [publisher report](kernel_boot_environment_publication_report.md) now execute continuously: `icdsb` writes up to 4 B at `0xfffffe0007ef9164`; `user_ts_jop` uses a stack u32 default of 1 and a resulting zero sets bit 61 in u64[`0xfffffe0007e6d650`]; `diversify_user_jop` writes 4 B at `0xfffffe0007e6d154`; `sptm_stability_hacks` writes 1 B at `0xfffffe0007e6d159`. Widths are original caller requests, not inferred capacities. Main also publishes u32 value 14 at `0xfffffe0007e6d9c0` and `0xfffffe000cb502c0` before the enumeration boundary. [PE5]

## Verification, assumptions and limits

Thirty new nonvacuous source queries are UNSAT over 88 distinct PCs/instruction instances and 58 linked-edge obligations. Nineteen unchanged publisher queries are re-solved. New proofs cover anchor cache/return words, twelve frequency-load cases, bus/CPU caps, chosen copy limits, nonempty string terminators, timer clamp/default/formula and logical ACTLR values. Every new premise set is SAT before the negated contract is added. [PE6]

Nine components pass 3254 independent semantic checks. The independent tree decoder feeds per-call contracts; the independent option grammar derives outcomes from actual copied input bytes. Original copy/strlcpy calls have source-byte and return/output checks. The whole-state oracle first validates the original publication prefix, then independently derives the platform-return state and final pre-enumeration state. It does not inject any derived value into execution. [PE6]

| Original API family | Entries / matched returns |
| --- | ---: |
| Serialized-tree APIs | 1558 |
| Option/scalar/string-length APIs | 156 |
| memcpy / strlcpy | 84 |
| Platform/clock/anchor/diagnostic/timer helper entries | 44 |
| Tracked API total | 1842 |

Copy contracts compare 19401 destination bytes cumulatively, including nested calls. Full mutable formulas compare 898560 B across the prefix, platform return and final checkpoints. The nine declared mutable-region sets total 33280 B per case; these are private model extents, not native ownership evidence. Nonstack private checks compare 9398016 B cumulatively, with the explicit 4352 B stack guard excluded from that formula and checked by replay instead. [PE6]

Fresh replay imports no executor. It checks 126264 source visits / 1749 distinct PCs, 27970 reads, 12077 writes, 18 declared registration returns, 155 logical address-PAC/callback/system/barrier effects, 1701 logical PAC/return steps, 1842 paired API entries/returns and nine final SP/NZCV/GPR boundaries. Initial Q0-Q31 are zero and all final SIMD registers are compared (288 checks). [PE6]

Replay compares 18874368 private bytes and 599040 mutable image bytes at two checkpoints per case, plus 9437184 final private bytes and 1085440 final mapped image bytes. Counts overlap across cases and checkpoints; they do not describe disjoint native storage. Six NOP controls are rejected: bus-cap store `0xfffffe000c5e5ab8`, cached-anchor store `0xfffffe000c5e5d78`, target terminator `0xfffffe000c5e67f4`, timer publication `0xfffffe000be85588`, assertion-mask store `0xfffffe000c5e50e8` and cpu-factor store `0xfffffe000c5e51c0`. Controls are excluded from positive totals. [PE6]

Capture costs O(K+I+D+N) time/space in collection bytes K, source I, literals/strings D and symbols N. Proof construction costs O(I+Q) in source/formula DAG Q; SMT search is separate with a 30 s/query limit and no polynomial claim. Private execution/replay and full-byte checks cost O(V+J+M) time/space in visits V, journals J and mapped bytes M. Per-call timeline sorting adds O(J log J) time; tree/string work adds bytes examined over calls. Arithmetic is exact little-endian u8/u32/u64, with explicit modular operations and quotient premises. Nontrivial JSON uses `zstd --ultra -22 -q -T1`, decoded roundtrip verification and decoded/nested path hygiene. [PE6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PE-A1: Pinned source intervals, literals, strings and exact aliases identify this build | PE1-PE7 | Rehash 26 intervals, twenty prior matches, 37 strings and four literals; no cross-build equivalence |
| PE-A2: Bounded serialized trees and nonempty strings instantiate the selected input domain | PE2-PE7 | Independent decoder, 4/8-byte frequency cases, capped/absent strings, raw-prefix copies, anchor cache/miss and no-arm-io case; malformed properties and native units/extents unknown |
| PE-A3: Guard-zero main entry and declared mutable initial state support only conditional startup | PE2-PE7 | Original full copies and inline publication, exact prefix/return/final byte states and all API-return pairs; earlier entry/callback/opaque transition and native guard lifetime unknown |
| PE-A4: Registration returns and logical PAC/system/barriers do not establish native effects | PE2-PE7 | Eighteen checked no-RAM returns, original register custody, callback target/modifier, SIMD/SP/NZCV and full-memory replay; native authentication/hardware/ordering unknown |
| PE-A5: Timer formula assumes 1<=q<=2^32 and no claim beyond the enumeration call boundary | PE5-PE7 | Nonvacuous source formula, zero/large option clamp cases and no-arm-io stop before timer; zero/out-of-domain quotient, later enumeration and physical calibration remain open |
| PE-A6: Independent contracts, local source lifting and fresh replay validate this increment | PE6,PE7 | Thirty new proofs, nineteen rechecks, 3254 semantic checks and six altered-source rejections; finite path coverage and shared decoder/emulator limits retained |
| PE-A7: Platform/boot-option contracts do not establish daemon control or a Mach transfer | PE7 | Correlate matched daemon/user-client/provider/kernel epochs and rights; no new such transaction observed |

No new incoming/outgoing Mach port, right or Mach-message emission PC is established. The newly recovered calls are internal kernel function edges. The [Mach inventory](mach_ports_report.md) remains authoritative for established endpoints, and direct fairplayd influence over these boot inputs remains unknown. The earlier [topology/thread composition](kernel_boot_option_execution_report.md) starts at the same enumeration call site using an explicit fixture epoch; this report reaches that site continuously but does not claim the two state histories have already been joined. [PE7]

| Impact | Next discriminating work | Evidence it could establish |
| --- | --- | --- |
| High | Continue the exact new pre-enumeration state through original enumeration and post-helper/thread setup | Remove the remaining state-history split with original control and data continuity |
| High | Trace actual guard/cache initial-state producers and earlier registration/feature callbacks | Replace remaining startup/helper premises within a stated source boundary |
| Medium | Follow the cached range anchor into mapping/context consumers | Establish address-space interpretation and ownership beyond the raw second range word |
| Medium | Correlate these environment-derived values with a matched daemon/user-client/kernel transaction | Establish observed relevance to FairPlay interaction rather than assuming daemon control |
| Low | Compare this recovered contract with a separately identified build | Separate stable fields from build-specific layout and initialization behavior |

**QG1**: Factual technical analysis; no normative content required. **QG2**: PE-A1-PE-A7 list dependencies and falsification probes. **QG3**: Actual platform return, clock/cache/identity/diagnostic fields, timer and later parser continuation covered for this increment; full goal remains active. **QG4**: Exact widths, extents, hashes, arithmetic domain and algorithmic costs stated; physical units remain unestablished. **QG5**: Cached/missing anchor, no admitted CPU, partial copies, predicate widths, timer domain and native boundaries separated. **QG6**: Original bytes, literals/nlist, source queries, independent contracts and replay retained. **QG7**: Bounded impact-ranked continuation included. All gates pass for this increment; native startup, later enumeration and matched daemon/kernel effects remain unknown.


## Initialized-data and continuous thread-handoff follow-up

The [bootstrap state-composition report](kernel_bootstrap_state_composition_report.md) preserves the prior zero-page fixture and establishes its pre-store null-destination boundary. A separately declared original initialized topology page permits continuous main/platform/timer/enumeration/post-helper/thread-copy/setter execution, without a call-frame epoch or later state repair. The paired input/register comparison, original pointer fixups, post-helper default 2, selected CPU ordinal, logical register custody and remaining selector0e/native/Mach boundaries are explicit.


## Startup registry and mach_ipc registration follow-up

The [startup registry ABI increment](kernel_startup_registry_abi_report.md) captures all 3519 original initialization records and 115 distinct kernel callback bodies, their authenticated pointer metadata, phase names and 22 tree/boot-option tunable descriptors. Original main now continues through timebase/trace, complete sorting, its first actual tunable callback/return and cursor publication. Three private runs establish absent/property/option precedence; entry 123 registers the previously analyzed MIG hash initializer at phase 14 (`mach_ipc`), rank zero, argument zero. Phase-14 execution, remaining callback effects, native startup/PAC lifetime and a matched FairPlay/Mach transaction remain unknown; the full goal remains active.


## Continuous tunable batch and formatter boundary follow-up

The [tunable batch execution report](kernel_tunable_batch_execution_report.md) preserves the preceding first-callback state and establishes 368 continuous original callback returns: all 237 compact boot-option descriptors, all 22 tree/option descriptors, 87 per-CPU pointer adjustments and 17 SFI registrations. Original Mach-O UUID lookup enters `_uuid_unparse_upper` and stops before `_snprintf`, with all 16 variadic slots checked. Three private cases pass 14 new source proofs, 14 registry rechecks, 16127 semantic checks and fresh replay; two altered-source controls are rejected. SFI handler invocation, formatter output, phase-14 MIG execution, native startup and a matched FairPlay/Mach transaction remain unknown; the full goal remains active.


## Original formatter and phase-one completion follow-up

The [UUID formatter execution report](kernel_uuid_formatter_execution_report.md) extends the preceding formatter-call boundary: original `_snprintf`, its generic engine and bounded byte callback produce the uppercase kernel UUID and NUL; all 392 phase-one callbacks actually return in each of four private startup cases. Twenty-one direct formatter cases cover three byte patterns and seven capacities, including NULL destination with zero capacity. Sixteen new source proofs, fourteen retained rechecks, independent formulas, fresh replay and two rejected source mutations support this finite result. The continuation also establishes requested stack size versus rounded masks, debugger-option parser status and four per-CPU object publications with phase-1/phase-7 registration pairs. Execution stops before the first phase-two call; phase-14 MIG execution, native startup and a matched FairPlay/Mach transaction remain unknown. Earlier boundaries in this report describe their original increments; the full goal remains active.


## Phase-two timeout execution follow-up

The [timeout execution report](kernel_timeout_execution_report.md) continues original main through all ten phase-two callbacks, reaching 402 actual callback returns after preserved phase-one/UUID state. It recovers nine timeout descriptors, the shared initializer diagnostic identity, root/chosen/boot precedence, cached scaling, modular multiplication and final saturation, plus selected lock-timeout preparation. Six private cases, twelve new source obligations, sixteen formatter rechecks, full helper/tree/parser/copy contracts, independent replay and two changed-source controls bound this result. The next call is the first phase-three lock initializer and remains unexecuted. Native startup, phase-14 MIG execution and matched FairPlay/Mach custody remain unknown; earlier boundaries describe their original increments and the full goal remains active.
