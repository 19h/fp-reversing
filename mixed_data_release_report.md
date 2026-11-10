# MixedData reference release and descriptor teardown

The captured kernel routes a last ordinary release of `_IOMemoryDescriptorMixedData` through the inherited `OSObject` reference methods to the class's private `free` slot. For the initial reference word of 1, the ordinary release uses a null tag and threshold 1. A successful 32-bit compare-and-swap publishes `0x0000ffff` and reaches the nominal private free target at `0xfffffe000c5397f0`. Five original call sites request the owner's release. They include the descriptor's teardown, the creator's backing-allocation failure branch, and the metadata helper's replacement branch. [MR1-MR8]

The kext cleanup first releases its `IOBufferMemoryDescriptor`. If that descriptor enters its nominal `free` and reaches the base implementation, the base implementation separately releases the MixedData owner at descriptor +0x90. Each release evaluates the reference word of its own receiver. Native receiver identities and reference counts at cleanup remain unknown. [MR2-MR7]

Evidence includes the [original capture](triage_evidence/mixed_data_release_source.json.zst), [release relations and SMT certificates](triage_evidence/mixed_data_release_checks.json.zst), [extractor](triage_evidence/recover_mixed_data_release.py), [validator](triage_evidence/validate_mixed_data_release.py), [preservation audit](triage_evidence/mixed_data_release_delivery.json), [quality gates](triage_evidence/mixed_data_release_quality_gates.json), [sealer](triage_evidence/seal_mixed_data_release.py) and [publication audit](triage_evidence/verify_mixed_data_release_publication.py).

The preceding evidence covers [owner initialization and private free](mixed_data_lifecycle_report.md), [backing allocation](mixed_data_backing_report.md), [DMA metadata publication](dma_map_constraints_report.md), [kext descriptor cleanup](kext_buffer_report.md) and the [interface index](interface_abi_report.md).

## Inherited slots and atomic update

The source capture contains 16 kernel functions with 949 instructions and a 26-instruction kext cleanup slice. Kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The kext slice agrees byte for byte with the normalized kext SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. The 25 original chained fixups are authenticated entries from the MixedData, OSObject and IOBufferMemoryDescriptor tables. Exact inherited names come from the original nlist. [MR1-MR2]

| MixedData slot | Nominal target | Source argument transfer |
| --- | --- | --- |
| +0x28 | `OSObject::release() const` at `0xfffffe000c4451d0` | Supplies X1 = 0 and tails through +0x50. |
| +0x50 | `OSObject::taggedRelease(void const *) const` at `0xfffffe000c444f78` | Preserves X1, supplies W2 = 1, tails through +0x58. |
| +0x10 | `OSObject::release(int) const` at `0xfffffe000c44523c` | Copies the threshold from W1 into W2, supplies X1 = 0 and tails through +0x58. |
| +0x58 | `OSObject::taggedRelease(void const *, int) const` at `0xfffffe000c444e18` | Applies the tag-dependent update and threshold, then may tail through +0xb0. |
| +0x20 and +0x48 | `OSObject::retain() const` and `OSObject::taggedRetain(void const *) const` | The untagged entry supplies X1 = 0. The tagged entry increments the reference word with a matching tag-dependent operand. |
| +0x18 | `OSObject::getRetainCount() const` at `0xfffffe000c445230` | Reads only the low 16 bits at receiver +8. |
| +0xb0 | MixedData private free at `0xfffffe000c5397f0` | Uses the same receiver after the release frame is restored. |
| +0x08 | MixedData deleting implementation at `0xfffffe000c539894` | Reached by the prior private-free correspondence. |

The dispatch instructions use the receiver-derived vptr modifier and the slot address with its original diversity. The last release transfer at `0xfffffe000c444ec0` uses diversity `0xedc5`. The same +0xb0 offset resolves to a different method for the descriptor receiver. Native pointer authentication is an explicit premise for the nominal joins. [MR2]

The update at `0xfffffe000c444e2c..0xfffffe000c444e88` compares X1 with the exact address of `OSCollection::gMetaClass`. An ordinary tag subtracts 1 from the 32-bit word. The matching collection tag subtracts `0x10001`. For admitted reference states the former changes the low half and the latter changes both halves. Matching retain operands are +1 and +`0x10001`. This explains why the source getter exposes the low half while the transition consumes the full word. The report does not infer the native distribution of tags or live owners. [MR3-MR4]

The active guard is `(~old & 0xfffe) != 0`. The method computes the candidate in 32-bit arithmetic. It compares the zero-extended candidate low half with signed W2 and chooses `0x0000ffff` if the candidate low half is below the threshold. At `0xfffffe000c444e6c`, `CASAL` attempts the replacement at receiver +8. A mismatch branches back to the load, so the failed attempt reaches neither private free nor the diagnostic. After a successful update, the source checks candidate low half >= candidate high half before testing the chosen replacement for equality to the finalization word. The failing consistency branch leads to a diagnostic with original `OSObject.cpp` and `_panic` provenance. [MR3-MR5]

For threshold 1, an admitted ordinary release with references remaining returns without dispatching private free. The last ordinary release, when the observed word is 1, commits the finalization word and dispatches. The matching collection-tag transition from `0x00010001` yields the same selected result. A subsequent attempt that reads the unchanged finalization word takes the early return. These are source transitions under the stated atomic and receiver premises. They leave live scheduling, actual counts, native ownership and complete retirement unobserved. [MR3-MR5,MR8]

## Owner release requests and the kext join

| Call site | Receiver and gate | Source continuation after ordinary return |
| --- | --- | --- |
| `0xfffffe000c537470` | Creator's newly allocated owner after the lower data request returns null and the creator writes null to owner +0x10 | Returns null to the creator's caller. The prior fresh-owner evidence supplies word 1, data null and capacity zero under stable fields. The raw backing retirement routine takes its null-return branch on that data argument. |
| `0xfffffe000c537074` | The helper rereads descriptor +0x90 after invoking the creator and releases the reread owner if present | Stores the creator's returned pointer at descriptor +0x90. |
| `0xfffffe000c538200` | `IOGeneralMemoryDescriptor::free()` loads descriptor +0x90 and releases it if nonnull | Clears descriptor +0x90 at `0xfffffe000c538204`. |
| `0xfffffe000c538c2c` | `IOGeneralMemoryDescriptor` deleting implementation loads descriptor +0x90 and releases it if nonnull | Clears descriptor +0x90 at `0xfffffe000c538c3c`. |
| `0xfffffe000c52551c` | `IOBufferMemoryDescriptor` deleting implementation loads descriptor +0x90 and releases it if nonnull | Clears descriptor +0x90 at `0xfffffe000c52552c`. |

All five use +0x28 with diversity `0x3a87`. The helper's first read can be null while its later read is nonnull in the source branch structure. The two reads are treated as distinct epochs. No intervening ownership change is asserted. The base free tail dispatches through +8 at `0xfffffe000c538378`. On that nominal free-to-delete sequence, clearing +0x90 in base free supplies a null guard input to the later deleting implementation if the field stays unchanged. The deleting implementations also cover teardown routes with a still-populated field. [MR2,MR6-MR7]

The original kext cleanup tests the descriptor global at `0xfffffe000ccceb10`, requests descriptor release at `0xfffffe000a508654` and clears the global after ordinary return. For a nominal buffer descriptor whose release reaches +0xb0, the original slot points to `IOBufferMemoryDescriptor::free()` at `0xfffffe000c525288`. Its body passes the preserved descriptor receiver to `IOGeneralMemoryDescriptor::free()` at call site `0xfffffe000c525374`. The base body's +0x90 receiver load then links to the third row above. If the owner passes its separate release gate, its private free passes owner +0x10 and +0x20 to the raw backing retirement boundary before proceeding to owner deletion. The selected source chain adds no Mach right emission. [MR2,MR5-MR8]

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| MR1 | Captures use the pinned images, compiler bounds and original chain membership. | Re-extract the selected bodies and verify original byte and fixup correspondence independently. |
| MR2 | The virtual calls use stable nominal receiver classes and their original slot targets. | Compare a matched receiver and authenticated vptr epoch with the source slot records. |
| MR3 | The equations use modular 32-bit operations, a signed threshold and unsigned halfword consistency. | Independently translate the arithmetic and branch flags and replay the solver assertions. |
| MR4 | Ordinary-release examples assume an active low half and a collection subcount strictly below the starting low half. Matching collection releases consume one count from each half. | Check the starting word and match the call's tag to the exact metaclass address. |
| MR5 | An admitted CAS success observes the expected word. Atomic mismatch follows the original retry edge. | Compare the CAS expected, observed and replacement values with a matched operation. |
| MR6 | The kext global and descriptor +0x90 identify the same descriptor and owner epochs across the selected calls. | Find an intervening replacement, field write or receiver substitution in the call and store sequence. |
| MR7 | Ordinary returns preserve the required saved registers and field clears are visible to later teardown. | Inspect the intermediate callee ABI and establish the later field value independently. |
| MR8 | The conditional chain establishes source handoffs. | Obtain independent runtime evidence for successful allocations, reference transitions, extent and actual retirement before assigning native behavior. |

## Continuation priorities

- **High.** Establish the live or initialized allocation extent and the backing retirement contract for the tagged data operand.
- **High.** Track descriptor ownership epochs across prepare, complete, kext cleanup and last reference.
- **Medium.** Resolve the metaclass and owner accounting after the private free tail in a matched lifetime.
- **Low.** Extend the source call census to other descriptor families with distinct owner fields or reference wrappers.

## Scoped quality gates

- **QG1** makes source and conditional ABI claims.
- **QG2** records premises and falsification probes in MR1-MR8.
- **QG3** covers the selected callers, vtable and argument transfer, atomic update, diagnostics, private free and kext join.
- **QG4** accounts for 975 four-byte instructions and 3,900 B. Byte and slot extraction are linear in the inspected captures and fixup traversal. Each SMT query has a 45 s solver timeout and 50 s process bound.
- **QG5** distinguishes the two receivers, the 32-bit word and 16-bit getter, and successful CAS, mismatch and diagnostic paths.
- **QG6** ties 14 UNSAT checks and five rejected alterations to original byte, slot and symbol provenance.
- **QG7** identifies remaining allocator, ownership, accounting and coverage questions.
