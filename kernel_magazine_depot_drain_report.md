# Per-CPU magazine drain and prefill production

The original routine at `0xfffffe000bd7497c` supplies the two partitions consumed by [prefill](kernel_zone_prefill_callers_report.md): it removes existing full and empty magazines from per-CPU caches and links them into the caller's descriptor. It performs no allocation call. Prefill requests control zero; a second caller clears zone flag bit2 and requests the current u16 quota. Original cache acquire/unlock instructions now execute inside continuous drain/prefill/wait-arm components. Native cache production, pointer authentication, exclusion, scheduling, reclamation and daemon transaction identity remain unknown. [DD1-DD7]

```text
prefill: clear quota; set zone bit2        maintenance caller: test bit2
              |                             clear bit2; read quota
         drain(Z,0,D) <---------------------- drain(Z,quota,D)
              |
        cache[0], cache[1], ... ; stride 16384 B
              |
        original acquire(cache) -> detach full/empty prefixes
              |                     |
        original unlock(cache)      +-> D.full: append in cache order
                                    +-> D.empty: prepend each cache block
              |
        original prefill splices into shared depot
        consumes one full magazine if available
              |
        bulk slot processing -> bzero magazine -> retire magazine object
              |
        Boolean progress result -> original wait-arm early-return gate
```

## Primary source and claims

Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized predecessor kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Preferred addresses and compiler function boundaries identify the retained code. None of these entries or the cache-count global has an exact original nlist definition; role names are descriptive. Reference data sufficed, with no IDA access or mutation.

| Role | Complete interval, end exclusive | Instructions / bytes | SHA-256 |
| --- | --- | --- | --- |
| New drain | 0xfffffe000bd7497c..0xfffffe000bd74bec | 156 / 624 B | 412a056f22b37a40bfd17753223f752bb8342e4767530b773454824d30a667ee |
| Matched prefill | 0xfffffe000bd730f8..0xfffffe000bd7332c | 141 / 564 B | 8d65e179708af1b61ef3372310d16e0e5597e3ac790859790df19233a20285e3 |
| Matched wait-arm | 0xfffffe000bd7332c..0xfffffe000bd73458 | 75 / 300 B | ea0ce2c04c6fcd0aace40c0329960d1efddabbf503c3b5a36c1ca43cdbe7328c |
| Matched nesting acquire | 0xfffffe000bd0aab4..0xfffffe000bd0ab18 | 25 / 100 B | b62845881e90d83df723282f5653953999e0e2c6e6a480c711fa7c3613132894 |
| Matched nesting unlock | 0xfffffe000bd0ab18..0xfffffe000bd0ab80 | 26 / 104 B | 270d0acea36c72afbda7c759201b2708232fdf173802e063a84ed0cf388b81e6 |
| Matched refill | 0xfffffe000bd75e20..0xfffffe000bd76394 | 349 / 1396 B | 1b8d2d081dccb75ca16062e7b7ec8b390fd10724b53c1b84a19deb1ecfc1328d |
| Maintenance caller, complete capture | 0xfffffe000bd78004..0xfffffe000bd79158 | 1109 / 4436 B | 963b99710100a808e9c465be955b1a616b66ed76ad202585ab8e4aced1880ba9 |
| Bulk slot processing, complete capture | 0xfffffe000bd74bec..0xfffffe000bd74fcc | 248 / 992 B | 25b32ead83824f6e72457e4c1dc78dcd8c7c842b02b2410cd711e6ad87cee465 |

Five reused bodies match prior captures. In particular, [refill](kernel_zone_refill_report.md) already identifies these cache/shared lists as full-prefix/empty-suffix magazine inventories. The earlier prefill report's available/reserved partition labels are refined here to full/empty magazines. A full magazine contains cached object pointers; it is not itself a newly supplied application allocation.

| Claim | Established contract | Dependencies |
| --- | --- | --- |
| DD1 | Exact direct callers, descriptor ABI and per-cache iteration | DD-A1-DD-A3, DD-A6 |
| DD2 | Full/empty retention arithmetic and unsigned extraction gates | DD-A1-DD-A4 |
| DD3 | Remaining cache partitions, output partition order and boundary updates | DD-A1-DD-A4 |
| DD4 | Source flag bit2 pairing, zero versus quota control and u32 edge case | DD-A1-DD-A4, DD-A6 |
| DD5 | Continuous original drain/prefill/arm join with original uncontended cache locks | DD-A1-DD-A5 |
| DD6 | Bulk slot clear and available-count completion cuts; full bulk execution remains open | DD-A1-DD-A3, DD-A5 |
| DD7 | Fresh source queries, independent RAM/ABI oracle and changed-store controls | DD-A1-DD-A6 |

Evidence: [extractor](triage_evidence/recover_kernel_magazine_depot_drain.py), [source audit](triage_evidence/audit_kernel_magazine_depot_drain.py), [private CPU/oracle](triage_evidence/probe_kernel_magazine_depot_drain.py), [delivery verifier](triage_evidence/verify_kernel_magazine_depot_drain_delivery.py), [capture](triage_evidence/kernel_magazine_depot_drain_checks.json.zst), [audit](triage_evidence/kernel_magazine_depot_drain_audit.json.zst). Decoded capture SHA-256: `8e2af1639aa71551ace7227c9a9900d1420b91bacc5da9d54500112a47fcb860` (302,553 B). Decoded audit SHA-256: `da8642ed53c3b21da6c9d976e5037a43df02d078bbbe7dce274f34f8778fe9ec` (2,395,925 B).

## Direct calls and cache-array bounds

The drain receives X0=zone Z, W1=control K, X2=descriptor D, and saves an 80 B frame. Its only outgoing direct calls are acquire at `0xfffffe000bd74a88` and unlock at `0xfffffe000bd74b9c`; both receive the selected cache address. The routine has no call that creates a cache, magazine or page. [DD1]

| Containing compiler entry | Emission PC | Arguments and local admission |
| --- | --- | --- |
| Prefill / 0xfffffe000bd730f8 | 0xfffffe000bd73154 | Z, raw0, stack descriptor; nonzero admission quota was already cleared and flag bit2 set |
| Maintenance / 0xfffffe000bd78004 | 0xfffffe000bd78344 | Z, zero-extended u16[Z+0x7c], SP+0x70; flag bit2 is tested, then cleared before the request |

The direct-branch locator rehashes all 725 executable-section ranges from the preceding inventory and scans all 15,490,987 aligned words. Exactly two B/BL encodings target this entry; both decode as the BL sites above. Reachability, indirect callers and interior targets remain outside that encoding-domain inventory.

The drain authenticates the zone+0x40 cache-array pointer using the recovered 0x8b6b slot modifier, then reseals current/end pointers in stack slots with corresponding stack-slot modifiers. It reads N=u32[0xfffffe0007e66f38] and computes `end=base+(zero_extend(N)<<14) mod 2^64`. The original file count is zero; that is not a runtime count observation. Current addresses advance by 16,384 B. Each iteration proceeds only while the raw unsigned current is less than end. Source proofs cover the modular sum, unsigned comparison and zero-wrap step without inferring valid native storage.

With nonzero base, nonwrapping end and coherent contiguous caches, this visits exactly N cache instances. Those premises matter: a zero pointer with positive count reaches a request to acquire address zero; the corresponding component stops before executing that acquire. A declared high pointer whose end wraps to zero bypasses iteration. These are source-boundary controls, not established native states or faults. No source claim that N alone bounds a valid native allocation follows.

## Retention and partition ordering

The original arithmetic is:

```text
keep_full  = ((K + 1) mod 2^32) >> 1
keep_empty = K >> 1
take_full  = old_full - keep_full   if unsigned old_full > keep_full; else 0
take_empty = old_empty - keep_empty if unsigned old_empty > keep_empty; else 0
```

Each selected prefix contains the number taken, and the retained suffix stays in the cache. For K in0..65535, the two retentions are ceil(K/2) and floor(K/2), and their sum equals K. The source maintenance caller supplies precisely that u16 domain; prefill supplies zero. Individual caches below either retention threshold stay below it; the function does not synthesize missing magazines or force a cache total to equal K. [DD2]

| Structure | Count fields | Head | Full/empty boundary |
| --- | --- | --- | --- |
| Per-CPU cache | u32+0x18 / u32+0x1c | u64+0x20 | u64+0x28 |
| Output descriptor | u32+0 / u32+4 | u64+8 | u64+0x10 |
| Shared zone depot used by prefill/refill | u32+0x48 / u32+0x4c | u64+0x50 | u64+0x58 |

Boundary fields point to link cells, not unconditional tails. The drain removes full entries from the cache head. For zero K it resets the cache boundary to &cache+0x20 when it removes the full partition. For positive nonwrapping retention, the remaining full suffix retains its former last link cell as the boundary. Empty entries are removed immediately after that boundary.

Extracted full prefixes append after the output's existing full prefix, advancing D+0x10. Extracted empty prefixes insert immediately after the current output full boundary without advancing it. Therefore, for initial descriptor lists Fd/Ed and extracted lists Fi/Ei from cache i in increasing address order:

```text
output.full  = Fd ++ F0 ++ F1 ++ ... ++ F(n-1)
output.empty = E(n-1) ++ ... ++ E1 ++ E0 ++ Ed
```

Within each extracted block, source order is preserved. Across caches, only the empty blocks reverse their order. This holds under coherent finite counts, valid next/link cells and the stated source/ABI epoch. Both descriptor count additions are modulo 2^32; a valid native no-overflow invariant is not inferred. [DD3]

### Original-control versus derived-retention edge

At `0xfffffe000bd74adc`, the boundary-reset branch tests the original W20 control against zero. It does not test keep_full. For K=0xffffffff, the addition wraps so keep_full=0, while K remains nonzero and skips the reset. If a nonempty full prefix is removed, the old cache boundary can therefore still point into that removed prefix. Two source certificates separately prove the original-control gate and zero-control reset; the private oracle explicitly preserves the all-ones case's old boundary rather than imposing the usual partition invariant. [DD4]

This control is outside both observed direct-caller domains. No indirect caller accepting it, native admission or resulting native failure is established. The arithmetic edge narrows the domain of the coherent post-drain partition claim; it is not evidence of a reachable exploit.

## Bit2 pairing and downstream interpretation

The prefill producer clears its u16 quota and sets bit2 before requesting control-zero drain. The maintenance caller tests bit2 at `0xfffffe000bd7832c`, skips to `0xfffffe000bd784c4` if clear, otherwise clears only that bit at `0xfffffe000bd78334` and loads the then-current quota before requesting drain. The two source operations explain both observed control forms. Concurrent quota/flag updates, the complete maintenance admission and native ordering remain unknown; the entire 1,109-instruction caller is captured but not proved or replayed here. [DD4]

The actual drain output now flows into original prefill without a descriptor-output model or state reset. Prefill merges those lists into its shared full/empty depot, consumes one full magazine if available, and requests processing of its slot array at node+0x10 with the u16 capacity from global0xfffffe0007e6a248. It then requests bzero of the magazine object and retirement using the separately loaded magazine-allocation zone/accounting pair. The source Boolean reports whether a full magazine was consumed; the wait-arm early-return gate consumes this actual Boolean. This refines its meaning as progress in draining cached contents, not an application object-allocation result. [DD5]

The newly retained downstream body at `0xfffffe000bd74bec` is the bulk-processing frontier. The selected source certificates establish:

| Source cut | Exact local effect |
| --- | --- |
| 0xfffffe000bd74c10 | W1=0 bypasses slot processing and branches to completion |
| 0xfffffe000bd74c5c..0xfffffe000bd74c64 | Read u64[X2+X20*8] into X9, then clear that slot before metadata validation |
| 0xfffffe000bd74f78..0xfffffe000bd74f84 | Add W1 to u32[Z+0xa8] modulo2^32 at completion |

The complete body also contains object-range/zone checks, inline/external free-bit updates, metadata count/list transitions and a conditional observer/wake followup. Those bodies resemble separately recovered [deeper release](kernel_zone_bitmap_release_report.md) interfaces, but a whole-body equivalence or native execution is not asserted here. Full bulk execution, valid magazine slot-array capacity and the actual objects' lifetimes remain open. [DD6]

## Verification and assumption register

Sixteen source counterexample queries are UNSAT with satisfiable premises, covering all38 instructions in16 selected blocks and22 linked-edge obligations. One integer composition query proves the u16 retention sum. These are local source certificates; they are not whole-drain, whole-maintenance or whole-bulk universal proofs.

The38 private components execute10,238 original visits and pass241 independent checks. They cover150 of156 drain PCs, plus the selected original prefill/arm and cache lock instructions. The132 nonnull acquire/unlock entries execute the original uncontended bodies; their selected cache words finish at0x01010000 and declared thread nesting remains1. The null-cache control stops before its acquire. No whole-drain or list-provider return/effect model is used. [DD5,DD7]

The independent oracle reconstructs cache suffixes, extracted prefixes, output ordering, descriptor and shared-depot boundaries, source-produced prefill results, private RAM outside the declared stack/guard window and ordinary saved GP/SP restoration. The excluded window is [entrySP-512 B,entrySP+256 B); the comparison covers every other private byte. It does not replay source stores to obtain its expected state. Initial descriptor contents, empty and populated caches, 0/1/3 cache instances, multiple retention controls, the all-ones control, null-pointer/count combinations and wrapped-end behavior have separate cases. Changing either the original retained-full-count store or descriptor-full-count store to NOP in private source copies makes the independent RAM oracle reject the result. These are CPU mutation controls, not SMT SAT or native feasibility claims.

The six unexecuted drain PCs are `0xfffffe000bd749ec`, `0xfffffe000bd74a2c`, `0xfffffe000bd74b98`, `0xfffffe000bd74bb8`, `0xfffffe000bd74bbc`, `0xfffffe000bd74bc0`. They remain outside this component coverage; no native unreachability claim follows. PAC/AUTDA, authenticated returns and stored-pointer resealing are logical identity models. Native exclusion, contention, monitor/pending branches and effects of concurrent cache users remain unexecuted.

Joined cases retain the predecessor's deliberately declared preparation, 32 B zeroing and magazine-retirement models. Those fixtures check request/return and partition custody. They do not supply valid full-capacity magazine object arrays for native bulk processing, and the actual bulk body is not CPU-executed in these cases. In particular, the inherited capacity argument is an ABI fixture, not an assertion that the private node allocation has that capacity.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| DD-A1: image identity | Pinned bytes, compiler intervals, section hashes and five prior matches supply DD1-DD7. | Rehash/recapture all eight functions and all725 scan ranges; compare the five reused bodies. |
| DD-A2: instruction model | Modular arithmetic, flags, memory cuts and private CPU semantics supply DD1-DD7's modeled results. | Reconstruct/re-solve all17 queries, compare whole-state oracle results and reject both altered stores. |
| DD-A3: ABI/storage/authentication | Declared valid nonwrapping regions and ordinary callee return/custody apply; PAC is conditional. DD1-DD7 retain this limit. | Verify native mappings, aliases, stack frames, authentication and nonreturn/call effects separately; retain null/wrapped controls as bounded source observations. |
| DD-A4: partitions/control domain | Counts and link cells describe finite coherent partitions; the ordinary invariant requires no u32 all-ones retention wrap. DD2-DD4 are conditional. | Test full/empty thresholds, initial output contents, cache order, shared nodes, count overflow, cycles, concurrent changes and the explicit all-ones boundary exception. |
| DD-A5: thread/callee epoch | Private uncontended cache words, nesting1 and declared leaf models are the component epoch. DD5-DD7 do not establish native locks, bulk effects or lifetimes. | Recover actual cache producers and full-capacity slot arrays; compose original bulk processing, authenticate native pointers and correlate one thread's lock/wait/wake epoch. |
| DD-A6: coverage/caller domain | Aligned B/BL scan and selected source blocks define evidence bounds. Maintenance uses u16 quota; prefill uses0. DD1/DD4/DD7 do not close indirect callers or complete maintenance admission. | Recover indirect/interior references and the complete maintenance CFG before extending admitted controls or all-path conclusions. |

Extraction/branch scanning costs O(B+I+S) time/space for input bytes, instructions and symbols. Valid finite drain traversal costs O(n+a+b) time and O(1) additional source space for n caches and a/b extracted full/empty magazines, excluding lock implementations. Formula construction is O(I+Q) time/space; solver search is separate with30 s/query limits. Private replay/oracle is O(V+J+R) time/space for visits, journals and RAM. Byte checks:2129*4 B=8516 B;156*4 B=624 B; cache stride=16384 B; drain frame=80 B. Integer widths and overflow domains are stated explicitly.

## Bounded continuation

| Impact | Next evidence | Remaining question |
| --- | --- | --- |
| High | Original bulk-processing body at0xfffffe000bd74bec with coherent source-produced magazine slots | Actual per-object bitmap/list/accounting flow and original full-magazine retirement completion |
| High | Cache/magazine allocation, installation and lifetime producers | Native list validity and complete storage provenance |
| High | Matching daemon/userclient allocation and thread/event epoch | Transaction-level behavior and native wait/wake/reacquire |
| Medium | Complete maintenance CFG and quota/bit2 writers | Admission, publication order and all accepted caller contexts |
| Medium | Observer registration and metadata-queue consumers | Callback interference, physical reclamation and reuse |
| Low | Indirect caller inventory beyond the aligned direct-branch scan | Broader control-domain completeness |

No additional Mach port endpoint, transmitted right or message emission is established. The full interface goal remains active.

## Scoped quality gates

- **QG1**: Factual source, ABI, data/control-flow and provenance analysis only.
- **QG2**: DD-A1-DD-A6 identify dependencies and falsification probes.
- **QG3**: Drain production, caller controls/sites, cache locking, partition order, prefill join and selected bulk cuts are covered within the increment.
- **QG4**: Counts, byte extents, strides, frame sizes and modular widths are reproducible.
- **QG5**: Full versus empty ordering, original control versus retention, observed u16 versus general u32 domains, raw bounds, captured versus executed bodies and leaf fixture limits are explicit.
- **QG6**: Pinned source bytes, exact prior matches, fresh formulas, independent whole-state checks and two changed-source controls provide provenance.
- **QG7**: Impact-ranked continuation identifies bounded opportunities and remaining interfaces; full-goal completion is not claimed.
