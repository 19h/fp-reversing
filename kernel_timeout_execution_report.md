# Phase-two timeout initialization and lock-timeout preparation

Original main now returns from all ten phase-two (`timeouts`) callbacks, after the 392 previously completed phase-one callbacks, without a new callback-result model or a call-frame epoch. Six private cases cover defaults, boot overrides, root/chosen-tree precedence, watchdog admission and saturation. The next boundary is before the first phase-three (`locks`) BLRAA at `0xfffffe000c630370`, target `0xfffffe000c62d618`, argument zero. Phase-three execution, native startup and a matched FairPlay transaction remain unknown. [TO1-TO7]

```text
original main -> original phase-one callbacks -> produced uppercase UUID
  preserved phase-two boundary, sorted index 392
  special wrapper ----+
  ordinary wrapper ---+-> shared timeout initializer
                         descriptor/default
                           -> root tree -> chosen tree -> boot option
                         local scale + cached/global scale
                           -> conversion -> wrapped scale -> saturated output
  lock-timeout preparation -> selected published timeout words
  402 callbacks returned; cursor 0xfffffe000cbec780
  original transition -> phase 3, fourth trace label "locks"
  STOP before first phase-three BLRAA

later phase 14 mach_ipc -> MIG hash initializer remains unexecuted
```

| Claim | Established result | Dependencies |
| --- | --- | --- |
| TO1 | Ten original registrations, nine descriptors, complete helper closure and diagnostic identity | TO-A1 |
| TO2 | Preserved preceding state and 402 continuous original callback returns | TO-A1-TO-A4 |
| TO3 | Admission, tree/boot precedence and descriptor destination custody | TO-A1-TO-A5 |
| TO4 | Conversion, scale caching, wrapping and final saturation | TO-A1-TO-A6 |
| TO5 | Selected lock-timeout arithmetic, clamp, copies and temporary option read | TO-A1-TO-A6 |
| TO6 | Independent formulas, source obligations, full helper checks, replay and controls | TO-A1-TO-A6 |
| TO7 | Mach relevance, external-control limits and bounded continuation | TO-A1-TO-A7 |

Primary evidence is kernel collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, original instruction/data bytes, compiler function-start records, original nlists and format-8 fixups. Preserved normalized FairPlayIOKit source SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Reference files suffice; no IDB is read or modified. All addresses and results are build-specific. [TO1]

Artifacts: [capture producer](triage_evidence/recover_kernel_timeout_execution.py), [continuous executor](triage_evidence/probe_kernel_timeout_execution.py), [independent contracts and replay](triage_evidence/replay_kernel_timeout_execution.py), [source audit](triage_evidence/audit_kernel_timeout_execution.py), [delivery verifier](triage_evidence/verify_kernel_timeout_execution_delivery.py), [capture](triage_evidence/kernel_timeout_execution_checks.json.zst), [audit](triage_evidence/kernel_timeout_execution_audit.json.zst). The report's two diagnostic strings are checked directly against the original collection by the delivery verifier, separately from the eleven strings in the capture. [TO1,TO6]

## Continuous state and next boundary

The default component preserves the preceding [UUID/phase-one experiment](kernel_uuid_formatter_execution_report.md) at the first phase-two dispatch: original visits, reads/writes, earlier leaf contracts, logical effects, call/API entries and returns, callback entries/returns, full private RAM, all preceding 208 mutable intervals, system state, GPR31, SP, NZCV and SIMD values. All previously mapped page hashes match; any additional pre-entry mapped page must equal its original logical page. Additional mutable storage is declared before original main entry, never repaired later. Native loader/initialized-section lifetime remains an explicit premise. [TO2,TO-A2]

The original sort still consumes 3519 records and orders unsigned phase/rank without a tertiary tie key. All ten phase-two registrations are retained with raw/logical records, original indices, argument pointers and authenticated callback metadata. Sorted positions 392..400 are rank zero; position 401 is rank `0x7fffffff`. Exact tied order below is observed in these private runs, not a stability guarantee for the sorter. [TO1,TO2]

| Sorted position | Original registry index | Descriptor name or callback | Argument / descriptor | Destination |
| ---: | ---: | --- | --- | --- |
| 392 | 625 | debug-ack, special wrapper | 0xfffffe000ca94260 | 0xfffffe0007ef8f10 |
| 393 | 147 | report-phy-write-delay | 0xfffffe000ca904f0 | 0xfffffe0007f30340 |
| 394 | 148 | trace-phy-read-delay | 0xfffffe000ca90530 | 0xfffffe0007f30398 |
| 395 | 616 | ticket-lock | 0xfffffe000ca94200 | 0xfffffe0007ef8248 |
| 396 | 146 | report-phy-read-delay | 0xfffffe000ca904b0 | 0xfffffe0007f302e8 |
| 397 | 149 | trace-phy-write-delay | 0xfffffe000ca90570 | 0xfffffe0007f303f0 |
| 398 | 611 | lock-panic | 0xfffffe000ca93eb0 | 0xfffffe0007ef81d8 |
| 399 | 615 | lock | 0xfffffe000ca941c0 | 0xfffffe0007ef8240 |
| 400 | 143 | dtrace-spin-threshold | 0xfffffe000ca90470 | 0xfffffe0007e636a0 |
| 401 | 620 | Lock-timeout preparation 0xfffffe000c63ab68 | Zero | See TO5 table |

Each actual return restores the dispatch SP and advances the original cursor by 24 B. The final cursor is `0xfffffe000cbea1d0 + 402 * 24 B = 0xfffffe000cbec780`. Original source publishes phase-minus-one u32[`0xfffffe0007f8b5f0`]=2 and last phase at `0xfffffe000cb62ec8`=3, and emits the fourth trace record with label `locks`, event ID `0x07020010`, counter 4 and the earlier logical timestamp envelope. This trace is a memory record, not a Mach message. The prepared phase-three callback has rank zero and receives X0=0, X8=`0xfffffe000c62d618`, X17=`0x2abe`; it is not called. [TO2]

## Shared routine identity, descriptor and call interfaces

| Original source interval, end exclusive | Words | Evidence |
| --- | ---: | --- |
| 0xfffffe000bd10980..0xfffffe000bd10994 | 5 | Ordinary wrapper; no exact nlist |
| 0xfffffe000bd12f7c..0xfffffe000bd12f90 | 5 | Special wrapper; no exact nlist |
| 0xfffffe000bd10994..0xfffffe000bd11150 | 495 | Shared body; no exact nlist |
| 0xfffffe000c63ab68..0xfffffe000c63ad8c | 137 | Lock-timeout preparation; no exact nlist |
| 0xfffffe000c6480c0..0xfffffe000c648170 | 44 | Exact nlists `_bzero` and `___bzero` |
| 0xfffffe000be3e1c4..0xfffffe000be3e268 | 41 | Exact nlist `_strlcat` |
| 0xfffffe000c61e5e8..0xfffffe000c61e5f0 | 2 | Stack-probe entry stub; no exact nlist |
| 0xfffffe000c61e5f0..0xfffffe000c61e61c | 11 | Stack-probe body; no exact nlist |

The original diagnostics identify `machine.c` at `0xfffffe000704e1fa` and function string `machine_timeout_init_with_suffix` at `0xfffffe000704e3df`. Several shared-body diagnostic branches reference them. This identifies a diagnostic function name for the recovered body; it is not an exact-address symbol-table name. Five new complete bodies extend the closure from 179 to 184 functions, 14962 words / 59848 B. All 179 preceding bodies match; five opaque words remain preserved and unexecuted. [TO1]

Both wrappers preserve X0=descriptor and the caller LR, set X1 to the original empty string at `0xfffffe00070eb2c9`, set W2 respectively to 0 or 1, and tail-branch to the shared body. The shared body uses W2 bit zero to select admission behavior. Its fixed frame is 192 B, with four further dynamic private stack allocations. The original stack-probe function pointer at `0xfffffe0007f95e28` is authenticated format 8, diversity zero, address-diversity one and key zero. Source BLRAA X16,X17 uses target `0xfffffe000c61e5e8`, X17=that slot address and X9=requested probe bytes. Actual stub/body instructions execute; no synthetic helper return is introduced. Native authentication remains unproved. [TO1,TO3,TO6]

| Descriptor offset | Width | Recovered role |
| --- | --- | --- |
| +0 | 8 B | Destination pointer, resolved from original fixup |
| +8 | 8 B | Default unsigned value |
| +0x10 | 8 B | Conversion divisor; zero in all nine registrations |
| +0x18 | 32 B | Embedded NUL-terminated descriptor name |
| +0x38 | 8 B | Optional admission callback; NULL in all nine registrations |

Ordinary admission first tests u64[`0xfffffe0007e63ff8`], the destination of the phase-one `wdt` option. Value `0xffffffffffffffff` selects a direct zero store through descriptor+0. Otherwise, a non-NULL filter would be called with X0=descriptor and logical modifier `0x307a`; nonzero W0 also selects zero publication. A NULL filter admits initialization. Special W2 bit zero set bypasses both ordinary gates. All registered filters are NULL, so non-NULL invocation is source-recovered but unexecuted. [TO3]

## Value precedence, scaling and conversion

For the registered empty suffix, the original bounded string helpers construct the descriptor name, name plus `-scale`, `ml-timeout-` plus name, and that boot key plus `-scale`. Requested buffer capacities are 26, 32, 37 and 43 B. Each original stack probe in the selected domain reads exactly one byte at entry SP minus its X9 size; it leaves SP unchanged. The subsequent original `_bzero`, `_strlcpy` and `_strlcat` bodies execute. Independent helper contracts reconstruct concatenated contents and attempted lengths, zeroed extents and probe read addresses; full copy contracts cover the additional original copies. General large stack-probe behavior is captured but not exercised. [TO3,TO6]

The original tree APIs receive the initialized serialized-tree extent from globals `0xfffffe0007f8b508` and `0xfffffe0007f8b518`. The full continuation checks original lookup/property outputs against the serialized private tree, including returned property extents. The shared initializer requires exactly 8 B for a value property and 4 B for a scale property; diagnostic branches for other widths remain unexecuted. Boot-option calls use capacity 8 B and W4=0. [TO3]

| Quantity | Exact precedence, lowest to highest | Presence effect |
| --- | --- | --- |
| Value | Descriptor default; `/machine-timeouts` name; `/chosen/machine-timeouts` name; `ml-timeout-` name | Tree/boot value marks an override; default alone does not |
| Local scale | 1; root name plus `-scale`; chosen name plus `-scale`; boot `ml-timeout-` name plus `-scale` | Tree scale is u32; boot scale is u64 |
| Global scale before cache admission | 1; root `global-scale`; chosen `global-scale`; boot `ml-timeout-global-scale` | An explicit property/option stores scale and cache byte 1 |
| Early cached global-scale path | u64[0xfffffe000cb62718] | This path requires byte[0xfffffe000cb62710] exactly 1 |

An admitted cache skips subsequent global property/option lookup. Without an explicit scale, default 1 is used without setting the cache byte, so later descriptors repeat global lookup. Root then chosen then boot processing still occurs within the first uncached callback, even after an earlier source stores the cache byte. Selected explicit global scales are 2, 5, 11 and u64 maximum; later callbacks observe the published cache. Source/data custody does not establish daemon control of these inputs. [TO3,TO4]

The later uncached fallback separately tests bit zero of the cache byte. Noncanonical bytes other than 0 or 1 are outside the selected fixtures; the early equality test is not a proof that all other bytes can never reuse a cached word. [TO4,TO-A5]

All nine original divisor fields are zero. For the selected nonzero overridden values below, the independently checked conversion is

```text
f = u32[0xfffffe000ca8c000] = 24000000 in these cases
C(x) = max(1, floor(floor(x / 1000) * f / 1000000000))

x=1000000:
  floor(x/1000)=1000
  floor(1000*24000000/1000000000)=24
  local=3, global=2 -> wrapped scale=6 -> published value=144

x=700000000:
  floor(x/1000)=700000
  converted=16800; local=4, global=5 -> published value=336000

x=1000000000:
  converted=24000; local=7, global=11 -> published value=1848000
```

The source implements the divisions using original unsigned reciprocal products and shifts. The formula is checked at the selected values, all below 2^32, with the actual produced nonzero timebase word and zero descriptor divisor; the entire u32 domain is not proved. A zero value suppresses override conversion; an unoverridden default also bypasses conversion. Nonzero divisors select an original UDIV path but are absent from these nine descriptors. Arbitrary large override inputs, other frequencies and a universal timeout-unit ABI are not proved. If f is interpreted in Hz, dimensional analysis gives 10^-12 s per override input unit, before integer truncation; this is a dimensional inference tagged TO-A6, not a recovered declaration of a universal ABI. Default values and override input units must not be equated. [TO4,TO-A6]

The local/global product wraps modulo 2^64 before final multiplication. For the resulting factor s and converted-or-default value v, original MUL/UMULH test the 128-bit product and publish `min(v*s, 2^64-1)` through descriptor+0. Saturation does not encompass the earlier scale product. For example, local=2 and global=2^63 yield wrapped factor zero, and therefore zero output; this follows from the source-proved modular scale contract, not an additional executed case. Monotonicity in arbitrary scale inputs is not established. [TO4,TO6]

| Descriptor | Default u64, before scaling |
| --- | ---: |
| debug-ack | 1440000 |
| report-phy-read-delay | 0 |
| report-phy-write-delay | 0 |
| trace-phy-read-delay | 0 |
| trace-phy-write-delay | 0 |
| ticket-lock | 3000000 |
| lock-panic | 12582912 |
| lock | 6000000 |
| dtrace-spin-threshold | 12 |

`wdt=-1` makes the eight ordinary descriptors publish zero, while special `debug-ack` retains its default in that case. With global scale u64 maximum and local scale 1, every nonzero default saturates at `18446744073709551615`; the four zero-default descriptors remain zero. Every intermediate callback output and cache word is compared sequentially, before the final lock-preparation callback can overwrite a destination. [TO3,TO4,TO6]

## Lock-timeout preparation

The rank-`0x7fffffff` callback consumes values already produced by earlier phase-two descriptors. Its boot options use the original parser, W4=0. Selected arithmetic is stated below using the actual frequency word f; physical timing and downstream lock-loop behavior are not native observations. [TO5]

| Option / condition | Source-supported selected effect |
| --- | --- |
| `slto_us`, 4 B, present | Publish floor(u32 option * f / 1000000) to u64[0xfffffe0007ef8240]; publish the original option value to u64[0xfffffe000cb0c4f8] |
| `slto_us`, absent | Keep preceding lock value; divide into quotient/remainder by f, convert to nanoseconds with original u64 wrapping, then divide by 1000 for u64[0xfffffe000cb0c4f8] |
| `tlto_us`, 4 B, present | Publish floor(u32 option * f / 1000000) to u64[0xfffffe0007ef8248] |
| `tlto_us`, absent, lock value nonzero | Publish unsigned lock value >>1 to u64[0xfffffe0007ef8248] |
| `tlto_us`, absent, lock value zero | Retain preceding ticket-lock word |
| `mtxspin`, 8 B, present | Unsigned clamp to 62500, then publish floor(clamped * f / 1000000) to u64[0xfffffe0007ef8250] |
| `mtxspin`, absent | Retain preceding u64[0xfffffe0007ef8250] |
| After `mtxspin` processing | Copy that word to u64[0xfffffe000cb0c500] and u64[0xfffffe000cb0c508] |
| `max_wfe_us`, 8 B | Parse into a stack word initialized to 500; remaining original callback body publishes no parsed value |

For absent `slto_us`, the exact independent arithmetic is `q,r=divmod(lock,f)`, `ns=(q*1000000000 + floor(r*1000000000/f)) modulo 2^64`, then `floor(ns/1000)`. This wrapping matters in the maximum-scale experiment and is not replaced by an unbounded rational conversion. [TO5]

The explicit option case uses `slto_us=10`, `tlto_us=8`, `mtxspin=999999`, `max_wfe_us=7`. At f=24000000 it produces lock=240, ticket=192 and spin=1500000, with the spin input clamped to 62500 before conversion; the copied words both equal 1500000. The side word at `0xfffffe000cb0c4f8` is 10, not 240. The original parser returns presence for `max_wfe_us`; its temporary value is 7, with no destination publication in the remaining body. Downstream use or a native wait-duration change remains unknown. [TO5]

## Validation and publication

Decoded capture: 2623443 B, SHA-256 `15e506a970376a31855eac50f79e3734b80dd509e33908f008d0b20b57c5926d`. Decoded audit: 612268967 B, SHA-256 `aa9e723c2dbd885fd59a3712fcda0f052dcb519742b1d437ab2abc3ae80872de`. Six positive components total 3098687 original visits and 5158 distinct executed PCs, passing 59467 independent semantic checks and 216 static contracts, with two additional diagnostic-string checks in delivery. [TO6]

| Private case | Original visits | Returned callbacks | Earlier declared leaf contracts |
| --- | ---: | ---: | ---: |
| continuous_default_phase_one_batch | 349876 | 402 | 3 |
| timeout_boot_options_and_lock_preparation | 842227 | 402 | 3 |
| timeout_tree_chosen_then_boot_precedence | 692700 | 402 | 3 |
| timeout_tree_then_chosen_without_boot_override | 381309 | 402 | 3 |
| timeout_watchdog_minus1_gate | 348493 | 402 | 3 |
| timeout_global_scale_saturates_nonzero_defaults | 484082 | 402 | 3 |

The continuation adds eight disjoint mutable intervals totaling 73 B after subtracting preceding regions. All 216 mutable intervals total 142085 B per case. The formulas compare 853716 callback-output/final-global bytes and 6265344 nonstack private bytes. All 736 admitted helper calls pass their selected contracts: four stack probes, four zeroing calls and eight concatenations for each of 46 admitted shared initializations; eight ordinary initializations are disabled in the watchdog case. These counts exclude preceding helpers and are not disjoint native object extents. [TO2,TO6]

Fresh replay checks 748304 reads / 3854812 B, 364861 writes / 2829833 B, 30680 logical PAC/return steps, 28935 other logical effects and all 18 retained earlier leaf contracts. Original API tracking has 42121 entries and 42109 returns, with two unfinished outer entries per case at the next dispatch boundary. No new callback-result model or frame epoch occurs. [TO6]

Replay compares 88080384 private checkpoint bytes, with earlier-region/bootstrap-extra/registry-extra/phase-one-extra/timeout-extra image totals 2795520/231264/7268544/328896/5256 B. Eager original-page checks total 675840 B at earlier boundaries, 311296 B at the formatter cut and 122880 B at the phase-two cut. Final comparisons cover 6291456 private bytes, 3936256 mapped-image bytes and 192 SIMD values. Counts overlap across checkpoints and cases. [TO6]


Twelve new nonvacuous QF_AUFBV queries are UNSAT across 42 distinct PCs, 42 instruction instances and 30 linked-edge obligations. Sixteen preceding formatter queries are rebuilt against the enlarged closure. Each checks SAT premises before requiring UNSAT for the negated contract or linked-edge violation, with a 30 s/query limit. New obligations cover both wrapper tail ABIs, special admission, the watchdog sentinel and zero store, boot value selection, modular scale product, zero-value conversion suppression, full unsigned final saturation, the early cache equality gate, unsigned clamp and default half-value. The selected reciprocal conversion remains finite formula/execution evidence, not a universal symbolic proof. [TO6]

Independent static checks rebuild all 184 original body bytes/hashes, all nine descriptors/destination fixups, all ten registry relationships, eleven captured strings, the authenticated stack-probe pointer and the preceding capture. Delivery separately checks the two diagnostic strings. Original tree/option/copy API contracts are repeated over the full continuation. Helpers are checked by an independent event timeline against original outputs and exact probe-read addresses. Formulas evaluate sequentially, comparing each callback output before later aliases can overwrite it and then every final declared mutable interval. [TO1,TO6]

Fresh replay imports no executor. It verifies original instruction visits, reads/writes, logical system/PAC effects, declared earlier leaf contracts, callback target/argument/SP/outputs, tracked original API entries/returns, fourteen full checkpoints, final private RAM, final mapped-image page hashes and all 32 SIMD values per case. Existing checkpoint page hashes match; additional eager mappings must equal original logical pages. Initial page snapshots containing incidental path strings use address plus original logical-page SHA-256 references. Hydration verifies the collection and page hash, restores identical bytes and roundtrips to the same publication row. No executed/read/written/checkpoint byte is changed. The source collection is required for reconstruction. [TO2,TO6]

Two controls replace one original word with NOP: `0xfffffe000bd10fbc` removes shared destination publication in the boot-option case; `0xfffffe000bd10cf0` removes the chosen-tree value load in the tree-only case. Every declared initial field matches the corresponding positive case. Both run to the phase-three boundary and the independent callback-output contract rejects them. Receipts retain exact patch bytes, initial-equality fields, rejection, boundary registers and canonical journal SHA-256; complete control journals are regenerated by the delivery verifier rather than duplicated in the archive. Controls are excluded from positive totals. Shared decoder/emulator defects remain possible. [TO6]

Capture is O(K+I+N+R) time/space in collection bytes K, captured source I, symbols N and registry records R. Proof construction is linear in source/formula DAG; SMT search is separate. Execution/replay are O(V+J+M) in visits V, journal events J and mapped/compared bytes M. API timeline ordering adds O(J log J); indexed helper read slices add O(H log J) for H probe calls plus compared reads. These describe analysis-tool construction, not a universal complexity bound for the original kernel routines. Arithmetic is exact little-endian bitvectors, with widths, wrapping, floors and saturation explicit. Nontrivial JSON uses `zstd --ultra -22 -q -T1`, exact decoded roundtrips and decoded/nested path checks. [TO6]

## Mach relevance, assumptions and bounded continuation

Startup BLRAA, stack-probe BLRAA and helper BL calls are function transfers. None establishes a Mach-message emission, new port, transferred right or daemon input. The [Mach-port report](mach_ports_report.md) and [kernel MIG report](kernel_vm_mig_report.md) retain their boundaries. The phase-14 `mach_ipc` registration for `0xfffffe000c62a46c` remains source-established but unexecuted. Timeout configuration can form environmental context for later kernel behavior; its consumption by a FairPlayIOKit transaction remains unknown. [TO7]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| TO-A1: Pinned original collection/fixups identify the build | TO1-TO7 | Rebuild all bodies, descriptors, registrations, pointer metadata, nlists and diagnostic strings; reject cross-build reuse |
| TO-A2: Original logical initialized data are declared pre-entry fixtures | TO2-TO7 | Exact preceding state and known-page preservation; additional pages must equal original contents; native loader/lifetime unproved |
| TO-A3: Private bootargs and well-formed serialized trees define selected inputs | TO2-TO7 | Default, option, root/chosen, watchdog and saturation cases; full original parser/tree contracts; malformed/native admission unproved |
| TO-A4: Logical PAC/system operations and earlier leaf contracts define the envelope | TO2-TO7 | Check operands/modifiers/LR/SP/system state and all retained clobber contracts; execute actual stack helpers; native PAC unproved |
| TO-A5: Sequential formulas cover selected descriptor/cache states | TO3-TO7 | Per-callback outputs, explicit cache/no-cache cases, chosen-load mutation and all final globals; noncanonical cache bytes/non-NULL filters remain outside fixtures |
| TO-A6: Selected arithmetic and produced timebase word define conversion context | TO4-TO7 | Nonzero overrides, default bypass, clamp, watchdog zero and saturation cases; source bitvector queries; other frequencies/large overrides and universal units remain unproved |
| TO-A7: Kernel initialization is not a matched FairPlay transaction | TO7 | Pair daemon/provider/kernel epochs, payloads, rights, statuses and message PCs; currently unknown |

| Impact | Next discriminating work | Evidence sought |
| --- | --- | --- |
| High | Execute original phase-three lock initialization and later phases | Actual object/state prerequisites before phase-14 MIG initialization |
| High | Recover original initialized-section/fixup producer and lifetime | Replace pre-entry initialized-data premise with original loader contract |
| High | Pair daemon/user-client/provider/kernel transaction | Observed FairPlay relevance, message custody and epoch correspondence |
| Medium | Follow timeout destination consumers and lock loops | Actual read sites, units, native observability and timing/control effects |
| Medium | Expand arithmetic/cache admission domain | Nonzero divisors, large override values, scale-product wrap and noncanonical cache states; no assumed monotonicity |
| Medium | Trace the temporary max_wfe_us value and source provenance | Establish whether another caller/version consumes it; this callback's remaining body has no publication |

**QG1**: Factual technical analysis; no normative content required. **QG2**: TO-A1-TO-A7 state dependencies and falsification probes. **QG3**: Registrations, shared routine identity, ABI, external inputs, arithmetic, helper custody, continuous state and Mach limits covered; the full goal remains active. **QG4**: Exact extents, widths, modular arithmetic, count/complexity and dimensional inference stated. **QG5**: Default/override units, wrapped/saturated products, early/fallback cache tests, intermediate/final aliases and private/native execution distinguished. **QG6**: Original bytes, independent formulas, nonvacuous source queries, fresh replay and controls retained. **QG7**: Impact-ranked continuation included. Gates apply to this finite increment; native startup and a matched FairPlay transaction remain unknown.
