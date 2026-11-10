# MixedData backing allocation and zero-check contract

Startup refinement. The heap operand below describes the file-flag epoch. The original parser later publishes low16 0x8061 and selects the typed variable heap descriptor. Both selected initialized bias routes yield a 48-byte element under the matched startup conditions. [MixedData startup geometry](mixed_data_zone_geometry_report.md).

The original kernel allocator checks the element that supplies the fresh 48-byte MixedData record. For the captured request and the field and allocator epochs in MB1-MB8, both the cache path and the fallback zone path require a zero result from the same content check before returning a nonnull element. If the checked extent covers the request and the bytes remain stable until the helper writes the record, the ten unwritten bytes and the six preserved state bits enter the helper as zero. The record initializer itself writes 38 bytes, including its partial state-byte update. [MB1-MB8]

The source image and original fixups supply the evidence. Capture covers nine compiler-bounded bodies, 958 instructions and 3,832 B from kernel collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Nine SMT queries reject counterexamples to the stated scalar, vector, flag and span properties. Four altered captures fail fresh source comparison. Live zone state and native execution remain unknown.

Artifacts include the [original bytes and fixup](triage_evidence/mixed_data_backing_source.json.zst), [source graphs and certificates](triage_evidence/mixed_data_backing_checks.json.zst), [extractor](triage_evidence/recover_mixed_data_backing.py), [validator](triage_evidence/validate_mixed_data_backing.py), [preservation audit](triage_evidence/mixed_data_backing_delivery.json), [quality gates](triage_evidence/mixed_data_backing_quality_gates.json), [sealer](triage_evidence/seal_mixed_data_backing.py) and [publication audit](triage_evidence/verify_mixed_data_backing_publication.py).

Related evidence covers [owner construction and retirement](mixed_data_lifecycle_report.md), [DMA constraint fields](dma_map_constraints_report.md), [buffer construction](buffer_construction_flow_report.md), [other original zone allocation paths](kernel_kmsg_allocation_report.md) and the [interface index](interface_abi_report.md).

## Tagged view and small-zone dispatch

The creator's call at `0xfffffe000c537430` supplies X0 = `0xfffffe0007f94f99`, X1 = 48, W2 = `0x31004` and X3 = 0. The allocation wrapper at `0xfffffe000bcfe5b8` tests operand bit 0 and clears it to obtain the descriptor at `0xfffffe0007f94f98`. The original format-8 chain entry at descriptor +0x10 resolves to `site.struct ioGMDData.struct ioPLBlock`. The descriptor's +0x48 flags are `0x61`, selecting the ordinary heap operand `0xfffffe0007f36938` under the source field epoch. The selected bias comes from descriptor +0x20, the ordinary heap's +0x16 field, or the alternate bias global along the observed branch. The original zeros in those fields do not establish live values. [MB1-MB3]

| Source stage | Selected contract |
| --- | --- |
| Request flags | The wrapper forwards `0x31004` or adds bit 6, producing `0x31044`. Both preserve the same size and content-check gates. |
| Effective size at `0xfffffe000bcfe66c` | Bit 8 is clear, so the original X1 = 48 survives the conditional rounding. The 32,768 B upper comparison selects the small-allocation body. |
| Size class at `0xfffffe000bcfe6a8` | CLZ32(48 - 1) = 26, so the shift is 4 and the size term is 2 after the paired subtraction/addition of 52. Index = low16(bias + 2). |
| Zone operand at `0xfffffe000bcfe6b8` | `0xfffffe000caeb480 + 192 * index`. Both checked paths read the extent as u16 at zone +0x34. |
| Lower call at `0xfffffe000bcfe6d8` | X0 = zone, X1 = selected accounting operand, W2 = selected flags. The lower pair returns the element pointer and extent in X0 and X1. |

The zone address is a source expression. Which bias and live zone state are used, and the concrete extent, remain runtime premises. [MB2-MB4]

## Content check and return span

The populated-cache path calls `0xfffffe000bc9d9c0` at `0xfffffe000bd75d1c` with the popped element and the zone extent. The fallback path calls the same check at `0xfffffe000bd76754` with its selected element and the same kind of extent. Bit 14 is clear on both paths, so the selected flag values keep the check enabled. Bit 13 is clear, so the secondary per-CPU verification loop is outside this correspondence. The source graphs retain 95 cache states and 101 edges, and 393 fallback states and 430 edges. The cache graph has one checked ordinary return and a tail to the fallback. The fallback has a checked ordinary return and a distinct null return. Corruption branches lead to diagnostic paths with original panic provenance. [MB3-MB5]

For a positive 8-byte-multiple extent below 64 B, the scalar reduction ORs consecutive u64 loads, including all six words in a 48 B extent. At 64 B and above, the vector path covers the first 64 B, any required aligned middle blocks, and the final 64 B. The boundary windows may overlap. The vector OR and unsigned maximum return a zero indicator exactly when all loaded bytes are zero. This establishes the successful content check as a read contract. The earlier mechanism that supplies zero bytes lies outside this increment. [MB4-MB5]

The wrapper keeps the original 48 B request under the selected flags. If it returns the element base, the requested offsets 0 through 47 are within any checked extent E >= 48. If the page-boundary and metadata conditions select the adjustment, its logical offset is E - 48 and the requested offsets end at E - 1. This uses normal address and tag semantics and a stable, disjoint metadata epoch. The wrapper retains the 48 B source length on success, while the creator publishes the returned data pointer and sets its own capacity to 48. [MB4,MB6]

## Join into record initialization

The helper reloads the published backing pointer from owner +0x10. The predecessor's byte-store join leaves offsets 24 through 31 and 46 through 47 untouched and masks byte 45 with `0xfc`. Under the checked-return and stability assumptions, those ten bytes and the preserved bits start at zero, and the helper's mask produces zero at byte 45. A later use of the record requires its own field epoch. The nominal source route adds no Mach port emission. [MB6-MB8]

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| MB1 | The extraction uses the pinned collection, compiler bounds and original chain membership. | Re-extract the bytes, compare hashes and resolve the tagged view's +0x10 chain entry independently. |
| MB2 | The descriptor's original flag word describes the selected allocation epoch. | Compare a matched descriptor snapshot. A changed heap-selection bit invalidates the concrete ordinary heap operand. |
| MB3 | The creator enters the fresh 48 B branch and flags follow the recovered forwarding path. | Recheck request arguments, source flag writes, call saves and the branch gates at both lower returns. |
| MB4 | The selected zone and accounting pointers are valid. The u16 extent is at least 48 B and any scalar extent is an 8-byte multiple. | Compare initialized zone geometry to the calculated index and extent. The original descriptor alone supplies no extent witness. |
| MB5 | Modeled call returns preserve the required saved registers. The declared diagnostic frontiers do not return normally. | Check lower call conventions and original diagnostic paths. A return bypassing the zero-result edge invalidates the graph conclusion. |
| MB6 | Source pointers have valid address and tag semantics. Checked storage remains stable through wrapper and creator return. | Check the adjusted pointer's logical address and intervening call and store footprints for aliasing. |
| MB7 | The helper reads the same fresh data pointer without an intervening write to the checked bytes. | Trace owner publication, helper reload and any intervening mapping or bookkeeping call in one allocation epoch. |
| MB8 | The claim is restricted to successful source checks under the stated premises. | Obtain independent evidence for actual initialized zone state, successful return and later lifetime before assigning native observations. |

## Continuation priorities

- **High.** Establish the initialized zone index and extent from allocator startup evidence to remove the live geometry premise.
- **High.** Trace the last-reference path into private free and join its allocator handoff to the same object epoch.
- **Medium.** Resolve the lower provenance of zero-filled zone elements and the normal refill path.
- **Low.** Correlate the site's diagnostic label with the enclosing record type metadata.

## Scoped quality gates

- **QG1** makes source and conditional ABI claims.
- **QG2** records the premises and falsification probes in MB1-MB8.
- **QG3** covers the tagged view, selected small allocation, zero check, returned span and record join.
- **QG4** relates 958 instructions to 3,832 B and checks element-relative offsets in bytes. Graph exploration is linear in the size of the instruction-state product and its edges. Each SMT query has a 45 s solver timeout and 50 s process bound.
- **QG5** retains the null and diagnostic outcomes, distinguishes requested and checked extents, and scopes conclusions to the declared epochs.
- **QG6** ties nine UNSAT results, four rejected alterations and source graphs to original bytes and fixups.
- **QG7** ranks unresolved startup, ownership, refill and type provenance by impact.

The matching retirement path recovers the original element base and clears the element extent before zone handoff. In the selected adjusted-pointer case it reads the same displacement field that allocation wrote. [MixedData backing retirement](mixed_data_retirement_report.md).
