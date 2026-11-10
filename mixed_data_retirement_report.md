# MixedData backing retirement and element clearing

The tagged retirement path recovers the original zone element base and extent before clearing and handing back a MixedData backing allocation. The owner passes its recorded 48-byte capacity. The retirement wrapper uses the zone's element extent for the clear. For the selected page-boundary allocation case, the allocator writes a displacement and the retirement lookup reads and clears the same field under matched metadata and pointer epochs. Both the direct and adjusted pointer cases recover the same logical element base under the stated conditions. [MT1-MT8]

The original capture contains eight compiler-bounded functions, 646 instructions and 2,584 B from kernel collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Four bodies match previous captures exactly. Original nlist records identify the clear routine as `_bzero` / `___bzero`. The validation rejects 11 SMT counterexample queries and five altered captures. The static scalar coverage check enumerates all 80 extents from 48 through 127 B.

Evidence includes the [original capture](triage_evidence/mixed_data_retirement_source.json.zst), [contracts and certificates](triage_evidence/mixed_data_retirement_checks.json.zst), [extractor](triage_evidence/recover_mixed_data_retirement.py), [validator](triage_evidence/validate_mixed_data_retirement.py), [preservation audit](triage_evidence/mixed_data_retirement_delivery.json), [quality gates](triage_evidence/mixed_data_retirement_quality_gates.json), [sealer](triage_evidence/seal_mixed_data_retirement.py) and [publication audit](triage_evidence/verify_mixed_data_retirement_publication.py).

Related evidence covers the [allocation and zero check](mixed_data_backing_report.md), [last-reference dispatch](mixed_data_release_report.md), [owner fields and accounting](mixed_data_lifecycle_report.md), [DMA record initialization](dma_map_constraints_report.md) and the [interface index](interface_abi_report.md).

## Retirement arguments and lookup

| Original source stage | Established operand correspondence |
| --- | --- |
| Private owner free at `0xfffffe000c539818` | X0 is the tagged backing descriptor, X1 is the published data pointer Q, and X2 is owner +0x20. The selected record has X2 = 48. |
| Raw retirement at `0xfffffe000bcfec48` | A null Q returns early. For a nonnull Q and request 48, the size tests select the small path. |
| Lookup call at `0xfffffe000bcfec9c` | X0 = Q, X1 = address of zone result, W2 = 1, X3 = address of offset result. The lookup returns the element extent E in X0. |
| Small retirement call at `0xfffffe000bcfecdc` | Requires nonzero E and offset + 48 <= E. X0 is the original tagged descriptor, X1 is the recovered base, X2 is 48, X3 is the zone, and X4 is E. |
| Exact clear call at `0xfffffe000bcfee78` | X0 is the recovered base and X1 is E. |
| Zone handoff at `0xfffffe000bcfeea4` | X0 = zone, X1 = selected accounting pointer, X2 = recovered base, X3 = E. |

The lookup first checks that Q through Q+7 lies inside the declared zone-map interval, with no carry from Q+8. It obtains the original zone index from the mapped metadata and uses the same 192-byte zone stride and +0x34 u16 extent field as the preceding allocation evidence. The zone retirement body independently derives and compares the zone from its input pointer. The actual zone-map bounds, table values, extent and accounting pointer are runtime premises. [MT2-MT4]

## Allocation displacement and retirement inverse

Let P be the original element base and E its checked extent. The selected request uses 48 B. In the unadjusted case, a lookup offset of zero makes Q = P and the size comparison reduces to 48 <= E.

For the admitted adjusted case, the element end P+E is 16 KiB aligned and 48 < E <= 16 KiB. The allocator records E - 48 and returns Q = P + E - 48. Both P and Q lie in the same page, so they use the same page metadata record. The offset write addresses the following record. The selected retirement branch addresses the equivalent field relative to the current record. The equality uses the 16-byte metadata stride and assumes the masked metadata index does not wrap at the boundary. The lookup must take that offset-bearing layout branch and observe the saved displacement. Its W2 = 1 path clears the field after reading it. [MT3-MT5]

The certificates establish that the displacement fits the original u16 store, Q+E reaches a different page without wrapping, and `Q - (E - 48) = P`. The recovered offset plus the requested 48 B equals E. Under the selected extent bound the signed 32-bit subtraction in the retirement wrapper preserves the recovered logical pointer. This covers the original layout branch for the declared geometry. Native selection of that branch remains unknown. [MT3-MT5]

## Clear and handoff

The small retirement body reclassifies the tagged descriptor using the same source flag word `0x61`. After its ordinary validation gates it calls the original `bzero(P, E)` and tails to the zone handoff with P and E. For E below 128 B, the clear partitions E into 8-byte stores and a remainder of 0 through 7 byte stores. For E from 128 B through 16 KiB, the first and final 64-byte ranges and the aligned interior spans cover the same element under the stated 64-byte `DC ZVA` premise. For example, E = 48 yields six 8-byte zero stores. No extent is inferred from the requested size. [MT4,MT6]

The selected populated-cache handoff adds E to the retirement-byte field and publishes the element pointer after the clear. Earlier source evidence checks the content of elements returned by the allocation path. Together these establish a conditional lifecycle from allocation checking through record use, full-element clearing and zone handoff. A later cache allocation requires its own cache state and content check. Full cache handling, native reuse, and the realized extent remain open. The selected source correspondence adds no Mach right emission. [MT6-MT8]

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| MT1 | The selected functions and symbols come from the pinned original collection and match the predecessor captures. | Re-extract from the pinned image and compare the bytes, boundaries and symbols. |
| MT2 | The owner passes a matching allocation's data pointer and the unchanged 48 B capacity. | Correlate its recorded fields with a single allocation and release epoch. |
| MT3 | Zone-map bounds and metadata select the same logical zone and extent on lookup and handoff. | Compare initialized bounds, indexed metadata and extent under a matched source or observed epoch. |
| MT4 | The logical addresses are valid and arithmetic stays within its declared unsigned domains. | Check address bounds and no-wrap conditions, including Q+8 and Q+E. |
| MT5 | The adjusted case uses the selected page-boundary layout, a nonwrapping metadata index and the preserved allocation displacement. The unadjusted case supplies zero displacement. | Compare the allocation and lookup field addresses and values. A changed metadata epoch invalidates the inverse. |
| MT6 | The clear receives the recovered base and extent. The large path uses 64-byte zeroing granules with ordinary completion. | Compare architectural zeroing granularity and the source store footprints for the admitted extent. |
| MT7 | Selected return and tail boundaries preserve required saved operands. Cache publication refers to the same cleared element and follows the clear. | Compare ABI preservation and any intervening pointer or element writes at the handoff. |
| MT8 | This correspondence covers selected source paths. | Establish native extent, actual release and cache behavior independently before assigning a runtime conclusion. |

## Continuation priorities

- **High.** Identify the initialized zone geometry and accounting pointer for the tagged allocation site.
- **High.** Join the completed descriptor teardown to prepare and complete epochs using matching object identity.
- **Medium.** Resolve how fresh zone elements receive their initial contents and how full-cache retirement preserves the clear contract.
- **Low.** Compare other backing allocation size classes and their independent layout contracts.

## Scoped quality gates

- **QG1** makes technical source and ABI claims.
- **QG2** records assumptions and falsification probes in MT1-MT8.
- **QG3** covers pointer and extent transfer, the selected inverse, clear and zone handoff.
- **QG4** accounts for 646 four-byte instructions and 2,584 B. Scalar range checking costs O(sum E) time for the enumerated extents and O(max E) space. Each SMT query has a 45 s solver timeout and a 50 s process bound.
- **QG5** distinguishes requested and element extents, null and nonnull returns, and selected metadata epochs.
- **QG6** links original instructions and symbols to 11 UNSAT results, 80 scalar extent checks and five altered-capture rejections.
- **QG7** ranks unresolved geometry, lifetime, refill and coverage boundaries.
