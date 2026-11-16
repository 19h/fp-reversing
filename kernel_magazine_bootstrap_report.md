# Magazine capacity policy, zone creation and cache installation

The original image contains a capacity producer and a matching magazine allocation-zone producer. The file capacity is eight slots. A policy prefix selects ten or fourteen only when its `zc_mag_size` presence test fails and the corresponding count/feature conditions hold. A later body requests `zcc_magazine_zone` with extent `16 + 8*K` bytes, calls the original dynamic zone creator, and publishes its returned view at `0xfffffe0007e66f58`. Original cache initialization then requests two magazine objects per CPU instance through that view and installs their slot-array pointers. The private producer/consumer components retain the same capacity across each handoff. Native boot order, storage ownership, raw allocation effects, authentication, exclusion and daemon transaction identity remain unknown. [MB1-MB7]

```text
u32 policy input M -> N=(M+1) mod 2^32 -> instance-count global
boot input +0x6c -> original parser("zc_mag_size", NULL, 0, 0)
                              |
                    presence -> preserve K
                    absence  -> count/feature heuristic
                              |
                       capacity global K
                              |
            declared new-call epoch; exact N/K transfer
                              |
       extent=16+8*K -> original dynamic zone creator
                              |
       returned leading view -> global magazine view
                              |
            declared new-call epoch; exact view transfer
                              |
       original cache initializer -> two typed requests/CPU
                              |
        returned header+16 -> current/spare slot pointers
```

## Primary source and claim register

Collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Seven complete compiler intervals are captured; creator and cache-initializer bodies match the [startup report](kernel_zone_startup_report.md). Exact original nlist definitions are absent at the seven entries and three selected globals. Role names are descriptive; `zc_mag_size` and `zcc_magazine_zone` are original string bytes. Reference data sufficed; no new IDA access or mutation was required.

| Role | Complete interval, end exclusive | Instructions / bytes | SHA-256 |
| --- | --- | --- | --- |
| Capacity policy | 0xfffffe000c631f9c..0xfffffe000c6321a8 | 131 / 524 B | 510ff330a7513393d9a5d8e75effe5dd3dd1e89a6889397a6a6bf7d33cb22106 |
| Magazine-view bootstrap | 0xfffffe000c6324a0..0xfffffe000c632708 | 154 / 616 B | 1ff4987ccaf6695a708efe702806a9f9eac90827c802c3934011347c7ad097d9 |
| Zone creator, matched | 0xfffffe000bd772b4..0xfffffe000bd77b94 | 568 / 2272 B | 11cff061e6010d4dcd9b8f9468d82ad06debf5fa8c9407d12b117351abc6dc68 |
| Cache initializer, matched | 0xfffffe000bd77bb0..0xfffffe000bd77ce4 | 77 / 308 B | 50dfaedba0cf1617f50cd782fccb7b6658d5590e84f6521df891f3ce3b7c3031 |
| Shared token parser | 0xfffffe000c5e48a4..0xfffffe000c5e4ca8 | 257 / 1028 B | cd4a54d50dd84acca76238bdb6f49fd680c5a25270b4a2342c76e404fe57b17c |
| Numeric parser | 0xfffffe000c5e4d20..0xfffffe000c5e4f50 | 140 / 560 B | bc567a7b8e2cf40e3d4a2cdb7b937c11cb44c956657437612ec3642c09cbd7cb |
| Numeric terminator predicate | 0xfffffe000c5e4f50..0xfffffe000c5e4f88 | 14 / 56 B | 987b5df232baaf0b866d54bdb516a1d8c27479c01403c6747a5ee8387bd4a174 |

| Claim | Established contract | Dependencies |
| --- | --- | --- |
| MB1 | File default, count increment and capacity heuristic | MB-A1-MB-A3 |
| MB2 | Original parser's presence-only call ABI and tested token behavior | MB-A1-MB-A4 |
| MB3 | Exact dynamic magazine-zone request and size-admission bound | MB-A1-MB-A3, MB-A5 |
| MB4 | Original view publication, normalization and minimum-count update | MB-A1-MB-A3, MB-A5 |
| MB5 | Actual dynamic slot40 creation under declared bootstrap epoch | MB-A1-MB-A3, MB-A5 |
| MB6 | Source-created view consumed by original cache installation | MB-A1-MB-A3, MB-A5-MB-A6 |
| MB7 | Source certificates, fresh replay, semantic oracle and altered-store controls | MB-A1-MB-A6 |

Evidence: [extractor](triage_evidence/recover_kernel_magazine_bootstrap.py), [private execution and oracle](triage_evidence/probe_kernel_magazine_bootstrap.py), [fresh replayer](triage_evidence/replay_kernel_magazine_bootstrap.py), [source audit](triage_evidence/audit_kernel_magazine_bootstrap.py), [delivery verifier](triage_evidence/verify_kernel_magazine_bootstrap_delivery.py), [capture](triage_evidence/kernel_magazine_bootstrap_checks.json.zst), [audit receipt](triage_evidence/kernel_magazine_bootstrap_audit.json.zst). Decoded capture SHA-256: `27d60c643cb84226823882c7171cbfd32c73cc3eacc2997fa701cd13a5d960c5` (212,190 B). Decoded audit SHA-256: `f80b2b0799d44936992aaa92bd2ab9519ad6ba58fd966a9d5749238b39556a69` (2,721,874 B).

## Count/capacity policy and external input

| Object | Address / width | Source evidence |
| --- | --- | --- |
| Capacity K | 0xfffffe0007e6a248 / u16 | Original file bytes0800; stores at0xfffffe000c6320f4 and0xfffffe000c6321a0 |
| Instance count N | 0xfffffe0007e66f38 / u32 | Store at0xfffffe000c631fc8 of input+1 modulo2^32 |
| Policy input M | 0xfffffe0007ef8bf0 / u32 | Read at0xfffffe000c631fbc |
| Small-count feature word F | 0xfffffe000cb29cb4 / u32 | Read at0xfffffe000c632190; exact platform meaning unknown |
| Boot-input structure pointer | 0xfffffe0007f8b6e8 / u64 | Read at0xfffffe000c631fd0; parser receives pointer+0x6c |
| Original key | 0xfffffe0007053327 | `zc_mag_size` |

The count's use in per-CPU storage supports a CPU-instance role for M+1; the original variable name and native runtime value are unknown. The source arithmetic permits wrap: M=0xffffffff publishes N=0. No native admission or failure is inferred from this control. [MB1]

The parser request emitted at `0xfffffe000c631fec` is `(boot_structure+0x6c, key, NULL, 0, 0)`. There is no output buffer for a numeric capacity at this call. A nonzero parser return bypasses both capacity writes. Only zero selects this heuristic:

```text
N = (M + 1) mod 2^32
if parser_result != 0: preserve incoming K
else if unsigned N >= 10: K = 14
else if F != 0: K = 10
else: preserve incoming K
```

For an incoming file-default8, those branches produce8/10/14. A prior writer could supply another incoming value; the bounded locator below does not exclude indirect, distant or differently encoded writers. Thus neither file default nor these finite cases are a native runtime-capacity measurement. [MB1,MB2]

The original token parser, numeric parser and terminator predicate execute. Only `strncmp` and `strlen` use explicit standard semantic leaf models. Tests distinguish the exact key from `zc_mag_size_extra`, `xzc_mag_size` and `-zc_mag_size`; they cover empty/unrelated input, leading space/tab, multiple tokens and repeated matches. Bare `zc_mag_size`, `zc_mag_size=16`, `zc_mag_size=0`, `zc_mag_size=garbage` and `zc_mag_size=0xffff` all preserve the incoming capacity in the checked caller context. The parsed value is not assigned to K here. This is a presence control over the heuristic, not proof of a general numeric-setting API or all boot-input grammar. No native ability to supply or modify this input has been established. [MB2]

## Magazine allocation-zone producer

At `0xfffffe000c632618`, the retained bootstrap body calls the actual creator with:

| Register | Exact value |
| --- | --- |
| X0 | 0xfffffe000705354e, original `zcc_magazine_zone` string |
| X1 | 16 + 8*zero_extend(K) bytes |
| X2 | 0x2000000002000020 |
| W3 | 0xffff, dynamic identifier request |
| X4 | 0, no setup object |

The u16 capacity gives a nonwrapping requested extent16..524296 B. The creator compares that full u64 request against32768 B before proceeding. Therefore this particular size gate passes exactly K<=4094: `16 B + 8 B*4094 = 32768 B`; K4095 requests32776 B and selects the diagnostic path. This is a source size-admission contract, not proof that all other creator conditions admit every such capacity. [MB3]

| Capacity | Requested magazine extent | Status in this evidence |
| --- | --- | --- |
| 8 | 80 B | Original file-default policy result; executed producer/cache chain |
| 10 | 96 B | Small-count nonzero-feature result; executed producer/cache chain |
| 14 | 128 B | Count-at-least10 heuristic result; executed producer/cache chain |
| 16 | 144 B | Explicit controlled incoming-capacity epoch; executed producer/cache chain |
| 0 | 16 B | Controlled capacity, outside default heuristic outputs; executed source control |
| 4094 | 32768 B | Controlled upper size-gate boundary; executed creator/cache control |
| 4095 / 65535 | 32776 B / 524296 B | Controlled requests stop before original creator diagnostic |

The creator uses `ARRAY + 192*reserved_count`, ARRAY=0xfffffe000caeb480, for a fresh dynamic slot. Components declare reserved_count40, fresh slot40, created count0, phase0, ready slot2 statistics allocator and zero selected security metadata. Actual creator instructions produce slot40 at `0xfffffe000caed280`, advance the reserved count to41 and created count to1, preserve the original name, set rounded extent and geometry, publish the statistics pointer and finally store the self pointer. Raw32 B statistics storage and lock operations remain declared leaf models. The magazine zone takes no cache-initialization branch in these cases; its actual allocation body is not recursively executed. Slot40 is conditional on this bootstrap count, not an asserted native identifier. [MB5]

The source store at `0xfffffe000c632620` publishes the creator's exact X0 at the global view cell. That view points directly to the source-created zone, whose first two u64 fields are `(zone_self, statistics_base)`. This resolves the previously declared pair's local producer without equating it with the client allocation zone. [MB4,MB5]

The subsequent normalization treats returned addresses in the raw unsigned inclusive interval `[0xfffffe000caeb480,0xfffffe000cb0ba00]` as direct zones; outside it, the code loads the leading pointer. The inclusive upper test is literal source behavior, not a proof that its endpoint is an admitted zone. At `0xfffffe000c63265c`, LDUMAX updates u32[zone+0xb0] to `max_unsigned(old, ((N<<1) mod2^32)&0xfffe)` and returns the old word in W8. This is an even low16 floor, not an unrestricted mathematical2*N. The instruction is modeled/executed sequentially; native atomic ordering and synchronization remain unknown. [MB4]

## Cache installation through the source-created view

Original cache initialization reads the same K and client-zone u16 extent E. It stores `min(UDIV_u32(budget,K*E),32767)` at zone+0x7e, with the AArch64 UDIV zero-divisor result0 retained in the source formula and capacity-zero control. The selected client geometry is an explicitly declared source-compatible256 B IPC-zone record, not a newly executed IPC-zone constructor. [MB6]

The initializer requests raw per-CPU storage `(slot2_context,64,0x3f)` at `0xfffffe000bd77c0c`. For each of N instances at stride16384 B, calls at `0xfffffe000bd77c4c` and `0xfffffe000bd77c64` request `(magazine_view[0],magazine_view[1],0x8004)` from `0xfffffe000bd75c64`. That allocation call is a declared zero-storage model with the actual source-created magazine extent. The source stores each returned header+16 at cache+8/current and cache+0x10/spare. Source cuts also show that these local stores do not test the returned pointer for NULL; no native null allocation or resulting failure is established.

The original initializer sets cache header0x144, empty partition/list fields and the boundary cell, logically signs the cache base and publishes it at client-zone+0x40. Zero current/spare slot counts rely on the declared raw storage's zero origin. No fill, application-object constructor or bulk return executes in these components. In particular, source-created magazine geometry does not by itself supply a native raw allocation or populated slot array. [MB6]

Policy outputs transfer exactly into a new-call publication epoch, and its source-created view/zone/RAM outputs transfer into a new-call cache epoch. The capacity is not changed at either handoff. The selected publisher starts at the original suffix `0xfffffe000c6325ec` and stops before0xfffffe000c632660; it does not execute the bootstrap function's earlier allocation setup or later statistics migration. Policy components stop before the per-CPU descriptor/security/callback-registration tail. These are explicit cuts, not a complete native boot continuation.

This refines the [bulk-return report](kernel_magazine_bulk_return_report.md), [drain report](kernel_magazine_depot_drain_report.md), [retirement-magazine report](kernel_retirement_magazines_report.md) and [refill report](kernel_zone_refill_report.md). Their sixteen-slot/144 B inputs remain valid controlled fixtures; they are not the recovered file default. The earlier one-slot prefill remains a separate capacity-epoch control. Joining fill/drain/bulk to this actual source capacity without ownership/capacity overlays remains open.

## Reference inventory and validation

The extractor rehashes725 executable-section ranges and scans15490987 aligned words. Its bounded ADRP locator follows at most three subsequent instructions, stops on a base-register write or selected control transfer, and retains27 references to the two selected capacity/view globals. All27 retained references are adjacent ADRP/memory pairs. It finds the two capacity STRH sites and the view STR site above. Other encodings, distant dependencies, aliases and indirect accesses remain outside that inventory.

One direct B/BL encoding targets the policy entry: BL at `0xfffffe000c634f1c`. One original chained-pointer candidate targets the view-bootstrap entry, at slot `0xfffffe000cbebed0`, with preceding words7/0 and following u64 zero. These locate a caller/registration candidate; they do not prove startup-engine admission, callback execution order or native ordering between policy and view creation. [MB7]

Twenty-three source counterexample queries are UNSAT with satisfiable premises, covering all97 selected PCs/instruction instances and74 linked-edge obligations. Two generic separation lemmas are re-solved;256 typed read/store rewrites retain the owned, nonwrapping, disjoint-region domain. These local certificates do not constitute a universal proof of the complete captured functions or all parser grammar.

The47 components comprise29 policy prefixes, ten creator/publication suffixes and eight cache-initializer calls. They execute9370 source visits across553 of1341 captured PCs and pass220 independent state checks. The semantic oracle independently reconstructs capacity/count decisions, complete created-zone metadata, registry/global publication and every resulting cache/magazine pointer. It compares all selected image regions and every private RAM byte outside [entrySP-512 B,entrySP+256 B). Expected state is not obtained by replaying source stores. Valid, size-rejected, modular-count, zero-capacity and maximum-capacity controls retain distinct premises.

A fresh CPU/source replay, with no probe-executor import, checks9370 visits,1609 writes/11662 B,1871 reads/9624 B,47 final RAM snapshots totaling49283072 B and6562 global bytes. It rechecks34 string-model input/results,168 declared API models and56 logical signing/authenticated-call envelopes. It uses the same CPU library, not an independent ISA implementation; the separate semantic oracle and source queries supply the additional validation boundary. PAC and authenticated calls remain logical envelopes.

Changing the actual capacity14 store at `0xfffffe000c6320f4`, view-publication store at `0xfffffe000c632620`, or current-magazine pointer store at `0xfffffe000bd77c54` to NOP in separate private source copies causes oracle rejection. These are changed-source CPU controls, not SMT SAT, native feasibility or exploit claims. [MB7]

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| MB-A1: pinned build | Original collection/kext bytes, function bounds, strings and two predecessor matches supply MB1-MB7. | Rehash all seven bodies, globals, strings, scan ranges and chained-pointer metadata. |
| MB-A2: instruction semantics | Modular widths, memory cuts, sequential atomics and private CPU semantics qualify MB1-MB7's modeled results. | Reconstruct23 queries, re-solve two separation lemmas, replay every source/read/write boundary and reject three altered stores; validate native atomic ordering separately. |
| MB-A3: ABI/storage/PAC | Nonwrapping owned regions, ordinary call effects and logical authentication envelopes bound MB1-MB7. | Verify native mappings, aliases, signatures, nonreturning calls and concurrency; replace modeled storage/lock calls before extending native claims. |
| MB-A4: input/grammar | Declared readable NUL-terminated boot inputs and standard string leaf models bound MB2. | Run actual boot-input producer and full string callees; test omitted grammar and prior capacity writers; do not infer native input controllability. |
| MB-A5: bootstrap epoch | Fresh dynamic slot40, count40, phase0 and ready statistics context qualify MB3-MB5. | Execute actual registration/order, alternate reserved counts, duplicate slots and boot phases; verify raw storage and lifetime producers. |
| MB-A6: handoff/cache epoch | Exact policy/view transfer, new call frames, declared256 B client geometry and zero raw magazines qualify MB6-MB7. | Compose actual IPC-zone construction and raw magazine allocation with fixed capacity and ownership retained; then join fill/drain/bulk without overlays. |

Byte checks:1341*4 B=5364 B captured;97*4 B=388 B selected cuts. Header16 B plus K pointers of8 B gives the requested extent. The policy frame is80 B, token-parser frame144 B, numeric-parser frame96 B, creator frame144 B and cache frame80 B. Maximum nested policy/parser frames in these components total320 B, within the declared512 B lower stack exclusion. The publisher suffix starts with a fresh explicit SP and does not claim the original112 B bootstrap frame. Scan/extraction costs O(B+W+I+F) time/space for input bytes, aligned words, instructions and fixups. Finite cache installation is O(N) source time and O(1) additional source space, excluding allocation/locks. Formula/replay/oracle construction is O(I+Q+V+J+R) time/space for instructions, formula DAG, visits, journals and RAM; solver search is separate with30 s/query limits.

## Bounded continuation

| Impact | Next evidence | Remaining question |
| --- | --- | --- |
| High | Raw statistics/cache/magazine allocation and lifetime producers | Actual zero origin, extents and native ownership |
| High | Exact bootstrap caller/registration engine and prior capacity writers | Native count/capacity epoch and creation ordering |
| High | Fill/drain/bulk using a source-produced8/10/14 capacity and view | Coherent fixed-capacity producer/consumer chain without capacity overlays |
| High | Matching daemon/userclient allocation and event epoch | Transaction-level daemon/kext correlation |
| Medium | Nonempty observers and wake/reacquire bodies | Callback interference and native delivery/exclusion |
| Low | Indirect/distant references beyond the bounded ADRP locator | Broader writer/caller completeness |

No additional Mach port endpoint, transmitted right or message emission is established. The full interface investigation remains active.

## Scoped quality gates

- **QG1**: Factual binary, ABI, data/control-flow and provenance analysis only.
- **QG2**: MB-A1-MB-A6 register dependencies and falsification probes.
- **QG3**: Capacity policy/input, actual zone-view production, request sites and cache installation are covered within this increment.
- **QG4**: Widths, extent calculations, frame sizes and source/replay totals are reproducible.
- **QG5**: File default versus controlled16, presence versus numeric assignment, partial source cuts, direct-range endpoint and new-call/storage models are explicit.
- **QG6**: Pinned bytes, predecessor matches, queries, fresh replay, semantic state checks and altered-source controls provide provenance.
- **QG7**: Impact-ranked continuation identifies bounded remaining interfaces; native boot/allocation identity and full-goal completion are not asserted.


## Original caller and strict registration order

The [boot-order report](kernel_zone_boot_order_report.md) refines the feature word at0xfffffe000cb29cb4 to the high u32 of the exact nlist-defined `_sane_size` u64 at0xfffffe000cb29cb0. For one unchanged input word V, F!=0 iff unsigned V>=2^32. The complete policy now executes through descriptors,689 metadata updates and both128 B callback-object initializations before returning to its original caller. That caller requests phase6 and phase7 in order; the magazine bootstrap is unique phase7/rank0, while selected IPC-zone entries are rank3. The new continuous caller tests model all registered callback bodies, so they do not replace this report's original publisher/cache components with a continuous zone-creation execution. Native helper effects, units/value stability, allocation/ownership and transaction pairing remain unknown.


## Memory and logical CPU producer evidence

The [boot-input producer study](kernel_zone_boot_inputs_report.md) refines both policy input premises: the ARM/SPTM writer publishes strictly positive _sane_size under an unsigned modular subtraction gate; the exported _ml_get_max_cpu_number reads the same maximum-number word consumed by count=max+1. The65-bit threshold composition is proved conditionally in one value epoch. Neither active CPU count nor continuous native producer-to-policy initialization is established. Existing raw backing/ownership, authentication, exclusion and transaction-pairing limits remain.


## Permanent storage and initialization prerequisites

The [permanent-storage report](kernel_permanent_storage_report.md) supersedes the opaque32/64 B storage-return frontier for selected ready-page creator/cache components. The actual allocator uses its third argument as an alignment mask, updates metadata/accounting and returns a signed page-index-derived pointer. Fixed slot1/2 setup records and complete callbacks are recovered, without claiming full fixed-slot construction. Source-ready allocation preserves payload bytes, and cache counts at+4/+6 retain nonzero inputs; this confirms why the preceding zero-storage models are necessary premises for their empty-cache result. Native refill/zero origin, ownership and complete bootstrap remain open.
