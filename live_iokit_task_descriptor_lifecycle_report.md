# Selector 26 task descriptor lifecycle

Selector 26 hands a virtual address range and its task to IOKit. On the successful path, IOKit prepares the range, records its VM page lists, translates descriptor-relative offsets into physical segments for the copy loop, and releases the page lists at final completion.

| Boundary | Installed address | Contract on the selected path |
| --- | --- | --- |
| Provider to factory | `0xfffffe000a546364` | Calls `withAddressRange` through import veneer `0xfffffe000a6e0374` with direction `3` and a task pointer. The nonnull-task factory path combines virtual type `0x10` with the direction to make options `0x13`. |
| Provider to descriptor | `0xfffffe000a54639c` | Invokes `prepare(0)` via slot `+0x218` and checks the status at `0xfffffe000a5463a0`. |
| Descriptor to VM | `0xfffffe000c585320` | Makes the task-map UPL request. Arguments include the map, aligned virtual address, in/out size, UPL output, page info, page count, flags and tag. |
| Copy loop to descriptor | `0xfffffe000c585958` | `getPhysicalSegment` accepts a descriptor-relative offset, a length output and option `0x800`. |
| Descriptor to segment walker | `0xfffffe000c585b18` | Invokes `dmaCommandOperation` via slot `+0x150` with operation `0x01000001` and a 64 B walk record. |
| Provider to descriptor | `0xfffffe000a54654c` | Calls `complete(0)` via slot `+0x220`, then `release()` at `0xfffffe000a546564`. |

## Preparation

The installed `IOGeneralMemoryDescriptor::prepare` at `0xfffffe000c584a08` calls `wireVirtual` at `0xfffffe000c584b44` on the virtual branch. `wireVirtual(0)` obtains direction through slot `+0x1e8`. The prepare count is a 32-bit field at descriptor `+0x88`. Its increment occurs at `0xfffffe000c584ae0` after successful wiring. The ordinary task-map path aligns the virtual address with a 16,384 B page mask and passes the page bias into its block metadata. The request target at `0xfffffe000be4734c` matches the argument shape of Apple's public `vm_map_create_upl` call. The installed callee name is unknown. [XNU virtual-range wiring](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/Kernel/IOMemoryDescriptor.cpp#L4095-L4164)

The metadata owner is reached through descriptor `+0x90`. Owner `+0x10` points to the backing bytes and owner `+0x18` gives their used length. Wiring appends a 40 B block at `0xfffffe000c585430`–`0xfffffe000c58543c`. Its descriptor-relative start is at block `+0x10` and its first-page bias at `+0x1c`. The UPL pointer returned via stack `+0x60` occupies block `+0x00`. The page-list field at `+0x08` has two interpretations. The inline path uses it as an entry index, and the external path uses it as a pointer.

## Segment lookup

The wrapper clears the caller's length output and checks the requested offset against descriptor extent. For option `0x800` on the virtual branch, it submits an unmapped walk. The descriptor vtable fixup at `0xfffffe0007f50fe8` resolves this call to `0xfffffe000c585c3c`. The first-segment operation reads the offset at walk record `+0x00` and the mapped selector at `+0x18`. On success it stores the address and length at `+0x08` and `+0x10`. It also records the next offset and block index at `+0x30` and `+0x38`. [XNU segment wrapper](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/Kernel/IOMemoryDescriptor.cpp#L3187-L3283)

The unmapped virtual walk checks the prepare count at `0xfffffe000c586230`–`0xfffffe000c586234`. The backing header stores the number of inline 8 B page entries at `+0x28`. The page entries start at `+0x30`. The blocks follow that array, each occupying 40 B. The walk selects the block containing the requested offset. The next block start or descriptor extent bounds the selected block. The ordinary nondevice branch reads a physical page number with `_upl_phys_page` and computes:

    relative = offset - block_start + first_page_bias
    page_index = low32(relative) >> 14
    byte_bias = relative & 0x3fff
    physical_address = (physical_page_number << 14) | byte_bias
    segment_length = min(bytes_in_consecutive_pages, block_end - offset)

The initial page index uses the low 32 bits of the block-relative offset plus page bias. For the selector 26 transfer sizes of 272 B and 288 B, adding a bias of at most 16,383 B stays below 16,671 B. The first page contributes `16,384 - byte_bias` B. Each successive consecutive page contributes 16,384 B. The installed computation is at `0xfffffe000c586478`–`0xfffffe000c586500`, and the address/length publication is at `0xfffffe000c586550`. The walk scans at most the candidate blocks and consecutive pages it inspects, using constant auxiliary storage. [XNU page-list walk](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/Kernel/IOMemoryDescriptor.cpp#L3095-L3185)

## Completion

The installed `complete` method at `0xfffffe000c584080` decrements descriptor `+0x88` at `0xfffffe000c5841cc`. Plain `complete(0)` reaches final record processing when the count reaches zero. Final processing checks the separate active-DMA count at descriptor `+0x34`. For an ordinary nonnull block UPL it has commit-family and deallocation calls at `0xfffffe000c584364` and `0xfffffe000c58436c`. Those installed callee names are unknown. The final cleanup requests a backing used length of 48 B at `0xfffffe000c5843dc`. [XNU final virtual-range completion](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/Kernel/IOMemoryDescriptor.cpp#L4560-L4569)

## Evidence and assumptions

| Scope | Evidence and falsification check |
| --- | --- |
| Installed image | Kernel UUID `90195379-954d-3ca3-baac-327341f14211`, FairPlayIOKit UUID `316464f8-eade-30ca-938e-2f430b1ed5bc`, collection SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. Recheck both fileset identities and the indicated instruction addresses before applying findings to another build. |
| Ordinary prepared, virtual, nondevice descriptor | The formulas depend on the type, prepare count, mapped selector and block flags. The installed branch tests and shifts supply these conditions and the page size. A different branch requires its own trace and interpretation. |
| Public XNU analogues | The linked XNU release supplies source-level corroboration. Installed instruction and fixup evidence controls address and register claims. Callee symbol recovery could confirm or falsify the two inferred VM/completion identities. |
| Native execution | The supplied RAX capture ends at service open before method 2865. Actual UPL results, task identity and page runs in a native selector 26 call remain unknown. A same-build capture at prepare, segment lookup and complete would test these in one request. |

This extends the [descriptor copy audit](live_iokit_descriptor_copy_report.md) by identifying the page-list producer, consumer and cleanup. The [earlier preparation lifecycle](descriptor_prepare_lifecycle_report.md) covers the separate kernel-side staging descriptor.

## Reproduction and next check

The [auditor](triage_evidence/audit_live_iokit_task_descriptor.py) checks the installed fileset identities, five descriptor vtable entries, the factory import, six direct call targets and 36 selected instructions. The [compressed receipt](triage_evidence/live_iokit_task_descriptor_audit.json.zst) preserves 1,675 instruction records across the provider, descriptor and VM handoff windows. Run the auditor with a decompressed collection and a receipt output path.

    python3 triage_evidence/audit_live_iokit_task_descriptor.py COLLECTION RECEIPT

- **High impact**. Correlate the task object and descriptor pointer from the IOKit method entry through prepare, copy and complete for one native request. This would tie the static VM contract to the daemon-side transaction.
- **Medium impact**. Resolve the installed VM call targets and verify their completion semantics against the shipped image. The receipt preserves the exact target addresses and call windows for that check.
