# fairplayd selector 26 late allocation ownership

After both earlier selector 26 constructor allocations succeed, the postprocessing caller can create a 128 B parent object with two owned 16 B allocations. The modeled 14 B allocation failure later frees the parent and its two children before returning to the established IOKit release path. The longer success profile still ends at an unresolved stack value. PCs below are unslid in the pinned arm64e image. [Original image and replay model](daemon_selector26_helper_consumers_report.md)

## Ownership and release

| Operation | Original instruction | Evidence |
| --- | --- | --- |
| Allocate the 128 B parent | `0x100a5f40c` | The caller saves the returned pointer at core SP+0x360 B at `0x100a5f414`. |
| Install the first 16 B child | `0x1006bfff8`, `0x100645aac`, `0x100645ab0` | On the nonnull continuation, the caller zeros both 8 B words in the child and stores its pointer at parent+8 B. |
| Install the second 16 B child | `0x100645b00`, `0x100934b08`, `0x100934b0c` | On the nonnull continuation, the caller zeros both 8 B words in the child and stores its pointer at parent+0 B. |
| Retire the 112 B temporary | `0x1006bcce4` | The caller frees this allocation before either 16 B allocation. |
| Unwind after a null 14 B allocation at `0x100a2fc00` | `0x1009e6608`, `0x100945d50` twice, `0x100902cbc`, `0x100a86f0c`, `0x100a2fe70` | The subsequent frees consume the 32 B temporary, the first child, the second child, the parent, the earlier 120 B object, then the earlier 8 B object. |

In this last case the core writes `0x74c29d85` at R+8 B. The adapter returns zero through F+0x80 B and restores outer SP=F. The existing release path calls `IOObjectRelease` for the service at `0x1001dcab8`, then for the iterator at `0x100205980`. With the fixture used for the fallback lookup, the Avp and primary profiles both eventually publish `0x74c29dee` at `0x1002bffa8` in their respective contexts. [Outer fallback and publication](daemon_selector26_class_retry_report.md)

## Reaching definitions

The 8 B load at `0x10064ff10` reads a child pointer in the 128 B parent. On the modeled 112 B allocation failure and the modeled first 16 B allocation failure, the load refers to parent+8 B. On the modeled second 16 B failure, a preceding free retires the first child and the load refers to parent+0 B. In each of these allocations the selected field lacks a reaching value in the replay. The nonnull profiles independently identify the matching stores. Native values and the continuation after the load are unknown.

| Stack consumer | Static writer | Reaching evidence |
| --- | --- | --- |
| Signed 2 B at SP+0x916 B, `0x10094326c` | `0x1009dd008`, `STRH W10, [SP,#0x916]` | One direct SP-relative unsigned-immediate STRH to this offset appears in the original `__TEXT,__text`. Its block is an authenticated target at slot `0x10109e140`, IA diversity `0xc2f0`. The all-nonnull replay does not visit this block. |
| Adjacent 4 B cells at SP+0x918 B and SP+0x91c B, loaded at `0x100943278` and `0x1009432a0` | `0x1009dd00c` and `0x1009dd014` | Both stores are in the same candidate producer block. The selected replay has no reaching writes to either cell. |
| Signed 2 B at SP+0x9ee B, `0x1009432d0` | `0x1009b83b4` | The all-nonnull replay visits this store. Its adjacent 4 B fields at SP+0x9f0 B and SP+0x9f4 B are also present. |

The earlier 4,097 B zero fill covers core SP+0xbaf B through SP+0x1baf B inclusive. The first signed halfword lies below this range. Register-relative aliases or a different producer history could still supply it. The local IDA connection listed a different binary during this pass. These observations use the pinned image, its original chained fixups, and the retained replay.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Allocator return values and class-selection inputs are modeled. Their concrete values establish the modeled ownership and release order. | Correlate allocation results, matching frees, and both service release arguments within one invocation. |
| A2 | The two zeroing stores and pointer publications use the same parent as the earlier allocation. | Check the saved pointer at SP+0x360 B against both store bases and the parent free argument. |
| A3 | Direct stack addressing identifies the candidate producer. It does not establish that a specific invocation reaches it. | Recover a control-flow path into the producer block and trace every store that aliases the frame offsets through to the loads. |

QG1–QG7 were applied to the factual scope, source and path premises, widths, observed release order, original image provenance, and open evidence. Scanning N aligned 4 B instruction words for one store encoding takes O(N) time; the audit reads the original section into memory. The bounded replay checks the selected allocation outcomes using opaque helper results.

| Impact | Open evidence |
| --- | --- |
| High | Join the candidate stack producer to the all-nonnull continuation and follow its eventual interface handoff. |
| High | Verify native ownership and release after an observed successful selector 26 method exchange. |
| Medium | Resolve the pointer provenance on the remaining allocation failure paths. |
