# AES initialization publication and protected cleanup continuation

The protected cleanup adapter at `0xfffffe000a62259c` can retire a separate 512-byte allocation after it calls `cleanupKernelAESHW()`. Original byte-bank selections and chained fixups connect the producer's `IOMallocData(512)` to the adapter's `IOFreeData(pointer, 512)` through the same global cell. The adapter clears that cell after the free call returns. This allocation has a distinct source lifetime from the AES descriptor's backing buffer and its MixedData owner. [AE1-AE8]

The initializer's local failure exits can retain published state. A null factory result follows provider publication and retain. A failed descriptor prepare follows publication of both the provider and descriptor. The protected cleanup path below establishes a separate source continuation, with the actual scheduling and pairing of those epochs still unknown. [AE2-AE6]

Evidence includes the [original capture](triage_evidence/aes_cleanup_epoch_source.json.zst), [source contracts and certificates](triage_evidence/aes_cleanup_epoch_checks.json.zst), [extractor](triage_evidence/recover_aes_cleanup_epoch.py), [validator](triage_evidence/validate_aes_cleanup_epoch.py), [preservation audit](triage_evidence/aes_cleanup_epoch_delivery.json), [quality gates](triage_evidence/aes_cleanup_epoch_quality_gates.json), [sealer](triage_evidence/seal_aes_cleanup_epoch.py) and [publication audit](triage_evidence/verify_aes_cleanup_epoch_publication.py).

Related reports cover [dispatch context](kext_aes_dispatch_report.md), [kext buffer calls](kext_buffer_report.md), [descriptor preparation and release](descriptor_prepare_lifecycle_report.md), [sample caller status](sample_caller_report.md) and [cached lock operands](sample_lock_report.md).

## Initializer and failure publications

The original capture includes ten complete bodies and four selected source spans, totaling 986 instructions or 3,944 B. The kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The kext instructions agree with the normalized image. Ten byte-bank identities cover all 2,560 input cases, and eight original authenticated continuation entries establish the selected destinations. [AE1-AE3]

| Local initializer exit | Status | Source publications in this invocation |
| --- | ---: | --- |
| Ready bit already set | 0 | Existing cells are retained by the fast return. |
| Waiter returns null | -40 | No provider, descriptor, byte-pointer or readiness store in the body. |
| Waiter returns a provider and factory returns null | -40 | Provider at `0xfffffe000ccceb08`, then null at descriptor cell `0xfffffe000ccceb10`. |
| Factory returns a descriptor and prepare returns nonzero W0 | -22 | Provider and descriptor cells have been published. |
| Prepare returns zero | 0 | Provider, descriptor, getter result at `0xfffffe000ccc7848`, then readiness 1. |

The factory's own failed-initialization path requests release of its allocated descriptor before returning null. That is a separate kernel call boundary from the kext's explicit prepare failure. On the provider path the waiter requests a release on the nonnull service result before returning the saved pointer. The initializer publishes that pointer and requests a retain. Actual reference ownership across those calls requires a matched provider epoch. [AE2,AE4]

The status helper at `0xfffffe000a508c78` returns the zero test of its original low32 argument on ordinary return. On the initializer's success branch, literal argument 0 makes it return 1, so the readiness publication follows the getter store. This branch publishes whatever pointer the getter returns. The table records direct writes and preserved cells under the stated call and field premises. It does not assert that a native getter can return null on a successful initialization. [AE2,AE4]

The source cleanup calls descriptor `complete(0)` only when descriptor and cached-byte cells are present, then clears the byte cell. It requests release for the descriptor and provider when present and clears their cells after ordinary return. It always clears the readiness byte. The sample coordinator's initialization-error suffix already establishes completion and release of its sample-size descriptor. That receiver comes from a separate cell and does not establish AES-global cleanup on that suffix. [AE4,AE6]

## Producer and cleanup adapter

The producer prefix at `0xfffffe000a66af38` reaches exact `IOMallocData` / `IOMallocData_external` at `0xfffffe000c4ba60c` through its call at `0xfffffe000a66b1e0`. W0 = `0x200` supplies 512 B. The return in X0 is stored by `0xfffffe000a66b230` through original pool entry `0xfffffe0008472a58` with its source displacement of -4, yielding cell `0xfffffe000cccba48`. The allocator wrapper uses the original data heap operand. Its result and extent remain runtime values. [AE3,AE5]

On the selected protected continuation, the core's saved W19 is `0x335`. The original record producer adds `0x451` to this control component, yielding decoded adapter state `0x786`. The prior caller and cleanup slot bindings are independently recaptured. After `cleanupKernelAESHW` returns, the adapter loads the same auxiliary cell using the same pool entry and displacement. The nonnull route calls exact `IOFreeData` at `0xfffffe000c4ba84c` with the loaded pointer and X1 = 512. It clears the cell after ordinary return. The null route joins the continuation without the free request. Both routes leave the same saved state for the second pointer check. The allocation and retirement wrappers use the same data heap operand. [AE3,AE5-AE6]

The second check loads cell `0xfffffe000ccceab8`, also identified as an operand in earlier RW acquisition and release paths. The null branch returns directly from the adapter. The nonnull branch writes an encoded control word at object +4 and the loaded pointer at object +8, then calls the helper at `0xfffffe000a6229c8`. The helper's arithmetic cancels the object-address expression and recovers the selected constant control. Its nonnull operand path selects `_kernel_lock_free`, whose original import resolves to exact `IOLockFree`. The helper stores status 0 on that ordinary path. The separate helper null path stores signed32 `-0xa427` if the helper reads a null operand. The capture identifies the called API and the shared cell. The concrete runtime type of the cell's object and a matched allocation for it remain unknown. [AE3,AE6-AE7]

The adapter's caller selects a continuation through the original slot for saved W19 and writes literal `0x31ae0066` to the output record +0x14 in the selected epilogue. That store uses a pointer loaded from the parent frame. The epilogue selects its own value independently of incidental X0 from the adapter. This proves a local source continuation under the saved-state and alias premises. It does not establish that this core state follows any particular native initializer failure. The selected path adds no Mach right emission. [AE6-AE8]

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| AE1 | Pinned bytes, compiler bounds and original fixups correspond to one captured build. | Independently recapture code, compare original and normalized kext bytes, and resolve the listed chains. |
| AE2 | Lower calls return normally and preserve the stated global epochs except for the direct writes in the initializer or cleanup. | Compare actual call footprints and check the guard and return operands. |
| AE3 | The selected bank, table and authenticated slot inputs match original source lineages. | Recompute all 256 inputs for each rule and independently compare the nominal target and modifier. |
| AE4 | The waiter, factory and prepared descriptor refer to valid objects in the appropriate ownership epochs. | Trace the native receiver, reference and publication values through each local return. |
| AE5 | The auxiliary producer's publication and adapter's retirement refer to the same allocation epoch. | Check pointer identity, publication order and any intervening cell writer. |
| AE6 | The selected core state and saved registers reach the captured adapter and its epilogue. | Trace the preceding frame definitions and check the return state against the captured slots. |
| AE7 | The helper receives the same object and loaded lock operand written by the adapter. | Verify the object +4 and +8 stores, later loads, native lock type and actual retirement effect. |
| AE8 | This is a source correspondence for selected local paths. | Join native caller epochs, return values and teardown scheduling before assigning lifetime or public reachability. |

## Continuation priorities

- **High.** Recover reaching definitions for the selected core cleanup state and compare it with each initializer and caller failure epoch.
- **High.** Establish the allocator and concrete type for the cached lock cell used by the selected cleanup and earlier lock paths.
- **Medium.** Trace the auxiliary allocation's successful producer continuation and later consumers under the same pointer epoch.
- **Low.** Expand the source census to other initializer, cleanup and continuation entries.

## Scoped quality gates

- **QG1** makes source and conditional ABI claims.
- **QG2** records assumptions and falsification probes in AE1-AE8.
- **QG3** covers local initialization outcomes, the producer/free pair, the selected adapter suffix and the caller return.
- **QG4** accounts for 986 four-byte instructions and 3,944 B. Bank checking costs O(256 times the number of rules) plus original byte and fixup extraction. Queries use a 45 s solver timeout and a 50 s process bound.
- **QG5** distinguishes descriptor, auxiliary allocation and lock operands. Selected source outcomes retain their caller and ownership premises.
- **QG6** links original instructions, ten bank identities, eight authenticated continuations and eight local proofs to the claims.
- **QG7** ranks caller reachability, lock identity, resource continuity and broader coverage.
