# Selector 26 task-descriptor copy and byte count

The installed `IOMemoryDescriptor::readBytes` and `writeBytes` bodies return the sum of the segment lengths processed by their copy loops. Each loop advances after the lower copy call without testing its return register. The FairPlayIOKit provider then overwrites the descriptor's returned byte count in both directions. The copy count and the core status are separate values throughout this path. [Provider ABI](live_kext_selector26_transfer_report.md) [Core return to the IOKit stub](live_fairplay_selector26_handoff_report.md)

| Boundary | Copy-in | Copy-back |
| --- | --- | --- |
| Provider call | `0xfffffe000a54647c` | `0xfffffe000a5464d4` |
| General descriptor slot | `+0x208` | `+0x210` |
| Slot target | `0xfffffe000c585828` | `0xfffffe000c585820` |
| Named body | `readBytes` at `0xfffffe000c580b0c` | `writeBytes` at `0xfffffe000c5808d8` |
| Physical segment lookup | `0xfffffe000c580c04` | `0xfffffe000c5809f0` |
| Lower copy call | `0xfffffe000c580bc0` | `0xfffffe000c5809ac` |
| Computed count | `0xfffffe000c580ca4` | `0xfffffe000c580acc` |

## Address and count flow

At each provider call, X0 holds the task descriptor, X1 is zero, X2 holds the kernel staging pointer and X3 holds the original zero-extended u32 extent in bytes. Each copy-method slot targets a `BTI C; B` thunk into the named body. Both bodies use the nominal `IOGeneralMemoryDescriptor::getPhysicalSegment` slot at vtable offset `+0x158`. Its installed authenticated fixup resolves to `0xfffffe000c585958` with address diversity and discriminator `0x649a`. The call passes the current descriptor-relative offset, a pointer to an eight-byte length cell initialized to zero, and W3 = `0x800`. The installed value matches the public `kIOMemoryMapperNone` constant. [Apple XNU descriptor options](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/IOKit/IOMemoryDescriptor.h#L85-L115)

The two bodies use the 64-bit descriptor length at object offset `+0x50`. They reject an offset past the length, overflow of offset plus requested extent, or an end past the descriptor length. An offset equal to the descriptor length returns zero. The read path rejects remote descriptors. The write path also rejects descriptors prepared read-only. The flag word is at object offset `+0x20`. If allowed to proceed, the body initializes the effective length from the lesser of the requested extent and the remaining descriptor length. [Apple XNU readBytes and writeBytes](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/Kernel/IOMemoryDescriptor.cpp#L2426-L2566)

For a nonzero physical segment and a nonnull staging pointer, each call uses the lesser of the segment length, remaining work and `0xffffc000` B. That cap is `2^32 - 16,384` B, or 4,294,950,912 B. The copy-in path passes the physical source, virtual staging destination and options `0x66`. Copy-back passes the virtual staging source, physical destination and options `0x75`. Both call the same installed address, `0xfffffe000bec4274`, which has no exact symbol in the retained collection index. The argument order and the virtual/physical role of each argument agree with the public `copypv` ABI. [Apple XNU arm64 copypv](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/osfmk/arm64/loose_ends.c#L842-L861)

A zero segment address terminates the loop. After a copy call returns normally, the descriptor reloads the chosen length from the stack, increments the staging pointer and descriptor offset, and subtracts the length from the remaining count. The return is the effective length minus the remaining count, in bytes. The callee's lower-layer return code has no data dependence on that arithmetic. The provider first replaces the copy-in count with the staging pointer at `0xfffffe000a546480`. It replaces the copy-back count with the staging descriptor at `0xfffffe000a546500`. The status retained in X21 comes from `PRnut72j9`. The task descriptor operates on the task's backing memory. The enclosing IOKit MIG reply carries the status and, on success, the outer output descriptor. [Mach transport and emitters](live_iokit_mach_transport_report.md)

## Replay and verification

The [auditor](triage_evidence/audit_live_iokit_descriptor_copy.py) compares both provider windows and nominal dispatch bindings with the earlier audited collection. It executes the original read and write bodies in an offline emulator with offset zero and the observed 272 B and 288 B request extents. The model supplies the segment address and length, performs each expected byte copy in private emulator memory and checks source, destination, length and options. A register-only control changes the lower copy return value from 0 to 5 while keeping the modeled memory effect identical. This isolates the descriptor's dependence on the segment length. Native copy errors remain outside this model.

| Modeled segment plan | Replay cases | Return in bytes |
| --- | ---: | --- |
| One segment spanning the request | 8 | 272 or 288 |
| Two segments with a 16 B first segment | 8 | 272 or 288 |
| First segment lookup returns zero | 4 | 0 |
| Second lookup returns zero after a 16 B prefix | 8 | 16 |

All 28 cases verify the copied bytes, final X0, restored SP and callee-saved integer registers through 2,494 instruction visits. The loop uses O(S) descriptor work for S segment lookups and O(1) local loop state. The modeled copies use O(N) byte work for N processed bytes. The [compressed receipt](triage_evidence/live_iokit_descriptor_copy_audit.json.zst) contains the instruction windows, fixup, call operands and outcomes. Collection SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. The boot collection's FairPlayIOKit UUID matches the loaded extension UUID `316464f8-eade-30ca-938e-2f430b1ed5bc` reported by `kmutil showloaded --list-only`.

```sh
uv run --no-project --python 3.14 --with capstone --with unicorn \
  python triage_evidence/audit_live_iokit_descriptor_copy.py "$CURRENT_COLLECTION" "$RECEIPT"
```

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The initialized task descriptor has the nominal class and entry bindings in the pinned collection. | The provider-to-descriptor call map. | Observe the receiver class and resolve its vtable entries in an ordinary transaction. |
| The replay models ordinary local descriptors with the thread-safe bit clear and logical pointer authentication. | The replayed call, loop and return states. | Compare descriptor flags and authenticated dispatch in a matched transaction. |
| Segment lookups and copies have the declared model results. | The 0 B, 16 B, 272 B and 288 B outcomes. | Correlate the native segment sequence, lower call outcomes and byte count in the same transaction. |

| Impact | Open evidence |
| --- | --- |
| High | Join a native selector 26 transaction to the task descriptor receiver, actual segment lookup results and staging bytes in both directions. |
| Medium | Establish the nominal task descriptor's segment and preparation lifecycle under the provider. |
