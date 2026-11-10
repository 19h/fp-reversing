# MixedData backing zone geometry from kernel startup

The captured startup code creates a 48-byte element class for the tagged MixedData backing request. It builds a shared 22-entry size table, creates the relevant heap families from that table, and publishes a family bias into the tagged view. The allocation adds size-class index 2 to that bias. With a matched startup and allocation epoch, the zone creator supplies element extent 48 for the requested 48 bytes, and the allocation wrapper returns the direct element pointer. The live family, zone ID and actual allocation remain unobserved. [MG1-MG8]

The post-startup heap selection refines the earlier file-epoch result. The original file contains view flags `0x61`. The parser sets bit 15 and preserves the low flags through the signature update, yielding low16 `0x8061`. With those flags the wrapper selects the typed variable heap descriptor at `0xfffffe0007e6a780`, then takes its zone bias from the view or the separately initialized early-heap route. [MG2-MG6]

Evidence includes the [original capture](triage_evidence/mixed_data_zone_geometry_source.json.zst), [size table and certificates](triage_evidence/mixed_data_zone_geometry_checks.json.zst), [extractor](triage_evidence/recover_mixed_data_zone_geometry.py), [validator](triage_evidence/validate_mixed_data_zone_geometry.py), [preservation audit](triage_evidence/mixed_data_zone_geometry_delivery.json), [quality gates](triage_evidence/mixed_data_zone_geometry_quality_gates.json), [sealer](triage_evidence/seal_mixed_data_zone_geometry.py) and [publication audit](triage_evidence/verify_mixed_data_zone_geometry_publication.py).

The report joins the [fixed-zone startup study](kernel_zone_startup_report.md), [backing allocation](mixed_data_backing_report.md), [retirement clear](mixed_data_retirement_report.md), [owner lifecycle](mixed_data_lifecycle_report.md) and [interface index](interface_abi_report.md).

## Original startup record and extent producer

The kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Fourteen compiler-bounded bodies contain 1,898 instructions and 7,592 B. The 24-byte startup entry at `0xfffffe000cbeaea8` lies in `__BOOTDATA,__init_entry_set`. Its two leading words are 7 and 2, its original authenticated callback at +8 targets `0xfffffe000c62a87c`, and the argument word is zero. The numeric entry records startup registration. Actual invocation is unobserved. [MG1-MG2]

| Stage | Source relationship |
| --- | --- |
| Size table producer at `0xfffffe000c62a8a0` | Seeds 16 and 32 B, then writes ten pairs at `0xfffffe000cbc8a40`. The initial pair state is size 32 and step 16. |
| Family constructor at `0xfffffe000c62cbf0` | Loads the indexed u32 size at `0xfffffe000c62cc6c` and passes it as X1 at `0xfffffe000c62cd58`. X3 = `0xffff` selects dynamic zone creation. |
| Original zone creator at `0xfffffe000bd772b4` | Uses the current dynamic cursor, computes the 192-byte metadata record address and advances the cursor. Selected extent stores at `0xfffffe000bd77520` and `0xfffffe000bd77590` use the same rounded W25. |
| Setup callback at `0xfffffe000bcfe21c` | Receives the zone pointer and the captured class ordinal. At ordinal 0 it derives the zone ID from the record address and publishes the family's start ID through the captured output pointer. |
| Allocation consumer at `0xfffffe000bcfe6b8` | Adds size-class index 2 for a request of 48 B to the selected bias and computes the record address with the same 192-byte stride. |

The ten iterations emit `size + step` and `size + 2*step`, then advance size by twice the step and double the step. This yields 22 entries from 16 through 32,768 B. Index 2 is 48 B. The creator rounds a request of 48 B to 48 B before publishing the u16 extent at zone +0x34. The source family join assumes successive successful dynamic creations with a stable cursor epoch, so class 2 uses family start +2. [MG2-MG4]

Apple's pinned public source corroborates the heap family loop, the bias publication and the separation of variable view and early heap selection. The exact startup rank and original 48-byte extent here come from the captured binary. Exact revision equivalence is unknown. The inspected public file SHA-256 is `3291bd41a6744d4ebc8fcb5ecf230ef12b5f10bb9cd712b339d271f7551afda8`. [Apple XNU allocator source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/kalloc.c)

## Tagged view assignment and consumer

The 80-byte descriptor at `0xfffffe0007f94f98` is index 372 in the kernel's 408-record `__DATA_CONST,__kalloc_var` section. Three original chained slots resolve the site string and its two signature literals. In variable mode the section reader selects precisely this Mach-O section interval and calls the original registration routine. Registration checks mask `0x60`, marks bit 15 and sends the two signatures to a helper that ORs upper-half information into the flag word. The low16 after those stores is `0x8061`. Bit 3 remains clear. [MG1,MG5]

At the original family count of 6, the variable initializer builds families 2 through 7 by calling the same 22-class constructor. The selected ordinary group branch uses families 4 or 5 from its permutation and may select family 6 at the split. The selector remains conditional on the original grouping, initialization and seed. The assigner at `0xfffffe000c62ab24` copies the chosen family's start ID to the view +0x20. It may also publish a separate accounting pointer at +8 under the accounting gate. The common typed accounting pointer is supplied by the startup allocation request and publication at `0xfffffe000c62bb54`. No pointer value is assigned to either allocation return. [MG3,MG5-MG6]

The initialized view bias feeds the normal allocation route. A separate per-CPU condition can select the bias at `0xfffffe0007e63366`. The startup call at `0xfffffe000c62a954` constructs that early family with the same size table and publishes the bias at class 0. Both source routes therefore select the 48 B extent at class 2 in the declared startup epoch. The exact family ID and actual statistics pointer remain unknown. [MG3,MG6-MG7]

## Consequences for the backing record

With element extent equal to the requested 48 B, the allocation wrapper skips its optional pointer adjustment for every page remainder. The previously analyzed adjusted-pointer retirement case remains a conditional allocator contract for other element geometries. For a matched 48 B allocation, the original zero check reads all six u64 words. The retirement clear also covers six u64 words after its lookup recovers the matching base and extent. This resolves the static extent premise for the source-matched path. Cache population, live zero contents, actual teardown and Mach IPC continuity are outside the observed evidence. The selected startup correspondence issues no Mach right emission. [MG4,MG7-MG8]

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| MG1 | The pinned kernel collection supplies the original functions, fixups and section bounds. | Recapture all selected bytes and decode the startup callback and variable view independently. |
| MG2 | The selected startup callback runs through the captured table producer and family constructors in the stated order. | Verify an independent startup trace or recover a competing writer to the size table. |
| MG3 | Successful dynamic family creation uses consecutive cursor values in the matched creation epoch. | Compare creation order, published start ID and third zone ID for a matched family. |
| MG4 | The zone creator uses the captured rounding stores and the resulting u16 extent stays stable until the consumer reads it. | Inspect any intervening writes to +0x34 or compare its initialized value. |
| MG5 | The selected kernel view is processed in variable mode with original flags, and the group and signature helper take their admitted return paths. | Compare section membership, parsed flags and selected group contents with matched startup evidence. |
| MG6 | The chosen bias belongs to an initialized family. The selected variable assignment uses the default family count and valid permutation values. | Read the active family count, selection and +0x20 publication. For the early route, check the separate class-0 publication. |
| MG7 | The allocation keeps request size 48 and consumes the published bias and extent in one allocator epoch. | Compare the size, flags, selected bias and original extent at allocation and retirement. |
| MG8 | The results establish the stated source correspondence. | Correlate initialized zone data, successful allocation, cache contents and retirement with independent runtime evidence. |

## Continuation priorities

- **High.** Resolve the exact matched family and accounting epoch from initialized zone evidence.
- **High.** Correlate prepare and complete with the descriptor's eventual cleanup and owner release.
- **Medium.** Recover how cache refill supplies the first zero-checked element.
- **Low.** Extend the same table and publication checks to neighboring tagged views.

## Scoped quality gates

- **QG1** makes source and conditional ABI claims.
- **QG2** records all scope premises with falsification probes in MG1-MG8.
- **QG3** covers startup membership, table generation, family construction, view flag updates and bias publication, and the matched allocation and retirement extent.
- **QG4** accounts for 1,898 four-byte instructions and 7,592 B. The size table is 22 u32 entries or 88 B. Its recurrence takes O(n) time and O(n) output space. Each SMT query has a 45 s solver timeout and 50 s process bound.
- **QG5** distinguishes file and post-startup flags, requested and element extents, and source-derived and live zone identities.
- **QG6** links original bytes, three view fixups, one startup entry, ten UNSAT checks and five rejected alterations.
- **QG7** ranks runtime, lifecycle, refill and neighboring-view gaps.
