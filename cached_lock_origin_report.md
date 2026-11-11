# FairPlay cached lock publication and kernel API types

Provider startup has a selected path that stores the result of `IOLockAlloc` in `0xfffffe000ccceab8`. The sample adapters can load this same cell for `IORWLockWrite` and `IORWLockUnlock`. The protected AES cleanup suffix can load it for `IOLockFree`. Original fixups and instructions establish the common cell and the distinct kernel APIs. Whether those three paths act on the same native pointer during one lifetime is **unknown**. [CL1-CL5]

The [source capture and checks](triage_evidence/cached_lock_origin_checks.json.zst) retain original instruction bytes, chained pointers, symbol records, typed allocation views, six solver queries and four cases from the independently validated [provider startup evidence](kext_provider_initialize_report.md). The 1,368 captured instructions occupy 5,472 B across nine kext spans and ten kernel bodies. Ten bank rules cover all 2,560 byte inputs. The [publication audit](triage_evidence/verify_cached_lock_origin_publication.py) checks the owned delta and username paths. The [extractor](triage_evidence/recover_cached_lock_origin.py) has a recapture mode that compares the complete output with the retained artifact.

## Publisher and record ABI

| Stage | Original instruction and effect |
| --- | --- |
| Destination | `0xfffffe000a627b28..0xfffffe000a627b30` reads pool slot `0xfffffe00084725d0`, subtracts 4 from the resolved address, and stores the address of the cached cell at record +0. |
| Record control | `0xfffffe000a627ad4` stores a u32 at record +8. Under the retained caller state, the value is `0x229 XOR K(record)`. |
| Helper entry | `0xfffffe000a627b80` calls `0xfffffe000a616d58` via original slot `0xfffffe000847a6c0`, diversity `0xca0c`. X0 points to the record. |
| Allocation | `0xfffffe000a616f60` calls `_kernel_lock_alloc` via original slot `0xfffffe000847ab80`, diversity `0xa860`. The wrapper and stub lead to exact `IOLockAlloc` at `0xfffffe000c4bb23c`. |
| Publication | `0xfffffe000a616f98` stores X0 through the X20 cell address loaded at `0xfffffe000a616e8c`. |
| Status | `0xfffffe000a616fac` stores W11 at record +12. The allocation-success route sets it to 0. The null allocation route uses signed32 `-0xa42c` and skips publication. |

The address key is `K(p) = (low32(p) XOR 0x7abbf985) * 0xded29631`, modulo 2^32. The caller's and helper's arithmetic reduce to this same key over every u32 address component. The selected helper entry uses a nonnull destination address and selector `0x229`. After the allocator returns, nonzero X0 selects index `0xadc` and the store. Zero X0 selects index `0xaf3` and the status block. The destination address and the returned pointer are distinct record and register values. [CL2-CL3]

The four retained startup cases preserve the distinction between a local publication and successful startup. Three nonnull model returns produce a matching 8 B write at the same instruction. One of those cases subsequently returns a startup error after the 512 B allocation model returns null. The null lock allocation case leaves the initially zero cell unchanged. The repeated startup case retains the first cached-cell value in its second phase. The new checks match the retained effects to original instruction bytes and the prior independent validation ledger. The object addresses in these cases were model results. [CL3]

## Consumers and kernel type evidence

| Selected consumer | Cell read | Nominal endpoint |
| --- | --- | --- |
| Sample acquisition with null explicit operand and nonnull cached value | `0xfffffe000a5b4274` | `IORWLockWrite` / `lck_rw_lock_exclusive` |
| Sample release with null explicit operand and nonnull cached value | `0xfffffe000a5bfef8` | `IORWLockUnlock` / `lck_rw_done` |
| Protected AES cleanup with nonnull cached value | `0xfffffe000a6228e8` | `IOLockFree` / `lck_mtx_destroy`, then the typed deallocation tail on ordinary return |

All three selected load paths and the startup publisher use original slot `0xfffffe00084725d0` with displacement -4. The sample acquisition and release load the cell separately. The cleanup helper receives a copy of its load through the adapter record. The [sample lock](sample_lock_report.md), [RW lifecycle](rw_lifecycle_report.md) and [AES cleanup](aes_cleanup_epoch_report.md) reports retain the path premises for those consumers. [CL4]

The common IOKit group operand comes from `0xfffffe000cb52628`. The kernel allocation and retirement APIs use distinct typed views even though each view has a size metadata word of 16 B. The mutex path uses `site.lck_mtx_t` at `0xfffffe0007e42b98`. The RW path uses `site.lck_rw_old_t` at `0xfffffe0007e42bd8`. The mutex allocator writes top byte `0x22` to the first u32, while the RW allocator copies an initial 8 B constant whose first u32 has top byte `0x33`. The mutex destroy and RW free bodies use their respective tags on their nominal validation paths. The exact RW acquire prefix separately reads the halfword at object +0xa, and RW done loads the word at +8. A freshly initialized mutex has bit 6 clear in that halfword under both captured debug branches. The solver checks concern the fresh initialized bytes and the type-tag tests. Native object contents after intervening calls, the results of any actual cross-family use and native request reachability remain unknown. [CL4-CL5]

The later [LSKD construction report](lskd_lock_origin_report.md) resolves the earlier RW store's X20 from incoming record +8 under child phase `0x90d` and establishes a conditional preparer for the distinct LSKD cell `0xfffffe000ccc78a8`. Its free adapter's LSKD cell was already resolved in the LSKD continuation evidence. The mutex publication here concerns the sample-processing cell. Other writers and replacements between its producer, sample adapters and teardown remain open. The selected paths contain no Mach right operation. [CL4-CL6]

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| CL1 | The normalized kext and original collection represent the same captured build. | Compare all selected kext spans and independently decode the original chained slots. |
| CL2 | The retained startup state reaches the selected producer block with a valid record and preserved saved registers. | Recover the parent state and frame from the entry point, then compare record stores and helper entry registers. |
| CL3 | The allocator returns normally with the captured model outcome and the record is writable. | Inspect the returned X0, subsequent store or bypass, and outer status in the original paths. |
| CL4 | The selected banks, routes and nominal imported symbols identify these particular cell accesses and calls. | Recompute each bank over all byte inputs and compare instruction operands, original fixups and nlist entries. |
| CL5 | A type comparison uses freshly initialized bytes from the captured build and a valid group operand. | Compare both typed views and initialization writes, then identify intervening writes in the specific pointer epoch. |
| CL6 | A native join would require one live object and a stable pointer across the selected operations. | Establish all reaching writes, ownership and ordering between startup, use and teardown in a matched build. |

## Continuation priorities

- **High.** Establish other writers and the last reaching publication before each sample adapter and teardown read.
- **High.** Correlate provider startup and cleanup selection with matched caller and owner state.
- **Medium.** Resolve native callers and pointer epochs for the legacy LSKD construction and retirement paths, and the impact of explicit-pointer precedence on cached-cell use.
- **Low.** Extend the inventory to other cells published by the shared mutex allocation helper.

## Quality gates

- **QG1** covers source behavior and nominal type evidence.
- **QG2** records six assumptions and their falsification probes.
- **QG3** covers the selected producer, status, consumers and lower type contracts.
- **QG4** uses 32-bit modular address arithmetic, 8 B pointer transfers and 4 B instructions. Byte-bank verification is O(256 times the number of rules). Source capture is linear in the selected instruction and symbol counts. Each solver query has a 10 s limit.
- **QG5** keeps modeled returns, local source writes, kernel type evidence and native epochs distinct.
- **QG6** binds claims to original bytes, authenticated slots, exact symbols and typed views, then cross-checks retained startup effects against independent validation.
- **QG7** prioritizes ownership, caller reachability and additional producers.
