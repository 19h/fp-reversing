# Descriptor preparation, completion and release

The captured FairPlay initialization requests `prepare(0)` twice on the nominal buffer descriptor. The first request comes from `IOGeneralMemoryDescriptor::initWithOptions()`, and the second comes from the kext after the factory returns. Both successful requests increment the descriptor's u32 preparation count at +0x88 on the selected type path. The kext cleanup may request one `complete(0)` before release. If the release enters the descriptor's private free route, the base free body then drains any remaining preparation count before releasing the MixedData owner at +0x90. This gives a source-level pairing for the selected success and teardown path. Actual wiring, runtime counts and final release remain unobserved. [PL1-PL8]

Evidence includes the [original bodies and kext slices](triage_evidence/descriptor_prepare_lifecycle_source.json.zst), [source contracts and proofs](triage_evidence/descriptor_prepare_lifecycle_checks.json.zst), [extractor](triage_evidence/recover_descriptor_prepare_lifecycle.py), [validator](triage_evidence/validate_descriptor_prepare_lifecycle.py), [preservation audit](triage_evidence/descriptor_prepare_lifecycle_delivery.json), [quality gates](triage_evidence/descriptor_prepare_lifecycle_quality_gates.json), [sealer](triage_evidence/seal_descriptor_prepare_lifecycle.py) and [publication audit](triage_evidence/verify_descriptor_prepare_lifecycle_publication.py).

Related work covers [buffer construction](buffer_construction_flow_report.md), [kext buffer call sites](kext_buffer_report.md), [DMA metadata](dma_map_constraints_report.md), [last-reference dispatch](mixed_data_release_report.md) and [initial backing geometry](mixed_data_zone_geometry_report.md).

## Preparation and receiver identity

The source capture includes 12 kernel bodies with 3,293 instructions and two kext slices with 41 instructions, or 13,336 B total. The kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Both kext slices match the normalized kext bytes. Six original authenticated format-8 entries identify the nominal methods and their diversity operands. [PL1-PL2]

| Source request | Receiver and result gate |
| --- | --- |
| `0xfffffe000c537ed0` | Base initializer's descriptor B. Uses slot +0x218 and W1 = 0. A nonzero status sends initialization to its false-result path. |
| `0xfffffe000a508108` | The returned factory descriptor B. The kext publishes it at `0xfffffe000ccceb10` and calls the same slot with W1 = 0. |
| `0xfffffe000a508630` | Cleanup loads B from the descriptor global and requests +0x220 with W1 = 0 when B and the cached byte pointer are both present. |
| `0xfffffe000a508654` | Cleanup requests slot +0x28 for the descriptor before clearing the global. |

For type/flags `0x11b`, both ordinary prepare calls select `wireVirtual(unsigned int)` at `0xfffffe000c535624`. The nominal `getDirection()` slot +0x1e8 projects B+0x20 with mask 7, yielding 3 for this flag word. The first successful wire return reaches the increment at `0xfffffe000c53548c`. A nonzero wire return bypasses that increment. The count update is a u32 load, add and store under the admitted synchronization epoch. The preparation count is separate from the descriptor and owner reference words at their respective +8 offsets. [PL2-PL4]

When the incoming preparation count is nonzero and flag bit 15 is clear, `wireVirtual` updates the record state byte, takes its short success return, and reaches the same increment. In the selected direction-3 first-wire success branch, the mode selector skips the separate bit-15 set. The constructor's intervening DMA operation and final length publication have their own source evidence. Carrying the successful first count and direction forward requires a stable descriptor and metadata epoch across those calls. Lower wire returns and VM effects remain explicit premises. [PL3-PL5]

## Completion and the MixedData record

For W1 = 0 and the selected type path, `complete()` checks the preparation count and the descriptor's metadata fields. With a nonzero count, a valid owner, nonzero used length and a backing pointer, it stores count minus 1 at `0xfffffe000c534b78`. An ordinary nonfinal completion returns through the early continuation after the decrement. When the count becomes zero, execution enters the final metadata branch, subject to its separate descriptor-state checks. [PL4-PL6]

The final completion computes the record-entry base as `data + 48 + 8*N`, where N is the u32 at record +0x28. For admitted used lengths, the loop count is `floor((used - 48 - 8*N) / 40)`. The original multiply-high followed by shift 5 implements the quotient. The proof covers the full unsigned numerator domain once the subtraction is valid. The loop visits 40-byte entries and makes its lower completion and release requests only for nonnull entry pointers. Those requests are source handoffs. [PL5-PL6]

The first-wire append fragment independently adds 40 to the owner's used length and writes a 40-byte entry. If the pre-append used length and capacity are both 48, it requests resize to 88 before publishing the entry. Thus the initial 48-byte allocator class does not fix the backing capacity at teardown. The last completion calls the used-length helper with 48. On the admitted nonnull backing and capacity-at-least-48 path, this updates owner +0x18 and retains owner +0x20 and the pointer. It clears the record qword at +0x20 and descriptor flag bit 15. Later owner free passes its then-current pointer and capacity to raw backing retirement. [PL5-PL7]

## Drains before owner release

The descriptor's last reference can dispatch to `IOBufferMemoryDescriptor::free()`, which calls the base free body. On the selected type branch, `IOGeneralMemoryDescriptor::free()` reads B+0x88 at `0xfffffe000c538174`, calls nominal `complete(0)` at `0xfffffe000c53819c` if nonzero, and branches back to reread the count. The source loop tests the count rather than the completion status. If each iteration satisfies the ordinary completion premises, the unsigned count strictly decreases. After it reaches zero, a separate side-object gate may request `complete(0x200)` at `0xfffffe000c5381dc`. This selects the auxiliary handler with W1 = `0x202` before the owner release at `0xfffffe000c538200`. Base reinitialization also has its own `complete(0)` drain before replacing descriptor configuration. [PL2,PL4,PL7]

| Admitted phase sequence from count 0 | Count path |
| --- | --- |
| First and second prepare succeed | 0 -> 1 -> 2 |
| Cached byte pointer present and the descriptor reaches final release | Kext complete makes 2 -> 1, base free makes 1 -> 0, then the owner release is requested. |
| Cached byte pointer absent and the descriptor reaches final release | Kext skips explicit completion, base free makes 2 -> 1 -> 0, then the owner release is requested. |
| Descriptor reference remains after the kext release | The kext can issue its conditional completion. Entry into the free drain requires a separate later final release. |

The table gives conditional source transitions for one stable descriptor and matching record. It does not establish when the cleanup runs, whether the cache pointer is null in a native execution, or that all completion iterations succeed. The selected source interfaces introduce no Mach right emission. [PL3,PL7-PL8]

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| PL1 | Original image bytes, compiler bounds, slot fixups and normalized kext slices identify the captured build. | Independently recapture the bodies and compare the selected slot and slice bytes. |
| PL2 | The nominal class, receiver and slot authentication agree across construction, kext publication and teardown. | Compare the actual receiver and authenticated targets in a matched epoch. |
| PL3 | The admitted initialization starts with count 0 and keeps the selected type and direction. Successful lower calls leave the required fields stable. | Check the preceding count and field writers, including those across the DMA and final-length calls. |
| PL4 | The selected prepare and complete paths have an admitted synchronization epoch and no overlapping count write. | Reconstruct lock and atomic handoffs or find a conflicting count writer. |
| PL5 | The metadata owner, used length, backing pointer and table counts are valid and stable through the selected record operations. | Compare pointer identity and verify the prefix and entry bounds from the current record. |
| PL6 | The normal final branch passes its descriptor-state gates and lower VM and used-length calls return ordinarily. | Identify a different gate result, return path or intervening backing replacement. |
| PL7 | Each admitted free-loop iteration decrements the count. The descriptor reaches last reference before entry to free. | Compare the count before and after completion, and correlate the preceding reference transition. |
| PL8 | The sequence concerns static source handoffs. | Establish native VM effects, actual release and backing extent independently before assigning runtime outcomes. |

## Continuation priorities

- **High.** Resolve the first successful `wireVirtual` VM branch and the matching final completion calls for the captured kernel-task and range configuration.
- **High.** Identify cleanup callers and the failure-unwind epochs after each initialization stage.
- **Medium.** Track backing resize capacity and the corresponding later retirement extent.
- **Low.** Compare the separate type-0x20 and auxiliary preparation and completion contracts.

## Scoped quality gates

- **QG1** makes source and ABI claims.
- **QG2** records assumptions and falsification probes in PL1-PL8.
- **QG3** covers the two prepares, kext cleanup, count and metadata changes, reinitialization and free drains.
- **QG4** accounts for 3,334 four-byte instructions and 13,336 B. Record scanning is linear in the number of complete 40-byte entries. Each solver query has a 45 s solver timeout and 50 s process bound.
- **QG5** separates reference and preparation counts, ordinary and auxiliary completion, and initial and later backing capacity.
- **QG6** links the selected source operations to 15 UNSAT results and six rejected altered captures.
- **QG7** ranks VM wiring, caller unwind, backing resize and other type paths.
