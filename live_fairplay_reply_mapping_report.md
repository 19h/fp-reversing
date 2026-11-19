# RPC 602 reply mapping and retirement in FairPlayIOKit

On the ordinary accepted RPC 602 path, FairPlayIOKit passes the first out-of-line copy object to `vm_map_copyout` for `kernel_map`. If the call succeeds and returns a nonzero address, the kext installs that address and the first descriptor's u32 extent in the security record. It discards the second copy object if present and attempts to wire the primary region. The normal close routine `_oh70aLVr` reads the same primary fields from the owner-linked record to request unwire and deallocation. The evidence is static and pinned to the collection identified for build `26C5035r`. [Image identity and message ABI](live_fairplay_rpc_abi_report.md) [Prior modeled constructor run](kext_constructor_reply_state_report.md)

## From Mach reply to constructor fields

The daemon's RPC 602 producer serializes two out-of-line descriptors and two fixed records. The kernel return path authenticates the memory descriptor pointers and writes raw copy objects into the client reply buffer. The generated client's accepted-reply path then publishes the objects and their extents. Let C be the constructor's scratch arena and P the first fixed-record destination. The stack argument offsets below are relative to SP at the call into the RPC client. [Daemon send, descriptor layout and kernel copyback](live_fairplay_rpc_abi_report.md)

| Reply output | Caller ABI at `0xfffffe000a64ca38` | Kext destination |
| --- | --- | --- |
| Fixed record0, 136 B | X6 loaded from SP+0x88 | P, also held at C+0x58 |
| Fixed record1, 172 B | X7 loaded from C+0x98 via X22 | Separate fixed-record storage |
| OOL0 copy object, 8 B | SP+0 holds X20 | C+0x90 |
| OOL0 extent, 4 B | SP+8 holds pointer loaded from SP+0x128 | u32 through the saved pointer |
| OOL1 copy object, 8 B | SP+0x10 holds X27 | C+0x40 |
| OOL1 extent, 4 B | SP+0x18 holds pointer loaded from SP+0x170 | u32 through the saved pointer |

The four stores at `0xfffffe000a5e3408`, `0xfffffe000a5e340c`, `0xfffffe000a5e3414` and `0xfffffe000a5e3418` execute in table order for the OOL pairs. The current RPC 700 caller stages the same output arguments at `0xfffffe000a64e52c` through `0xfffffe000a64e54c`. Its generated client expects reply 800 and shares the inspected downstream staging. The identity of a native RPC 700 producer remains unknown. [Current client comparison](live_fairplay_rpc_abi_report.md)

## Mapping and cleanup requests

| Condition on the ordinary branch | Kext site | Action |
| --- | --- | --- |
| Accepted reply and matching fixed-record marker | `0xfffffe000a64e6e4`, `0xfffffe000a64e7ac` | Compare P's first u32 with 0xbeefed02, then call `vm_map_copyout(*kernel_map, &FP[-0x80], C[0x90])` |
| Copyout status nonzero | `0xfffffe000a652920`, `0xfffffe000a6529cc` | Discard the primary copy object, then discard the auxiliary copy object if nonnull |
| Copyout status zero | `0xfffffe000a64e7e8` through `0xfffffe000a64e810` | Read and check the mapped VA separately |
| Nonzero mapped VA, auxiliary object nonnull | `0xfffffe000a6534c8`, `0xfffffe000a65355c` | Discard the auxiliary copy object |
| Nonzero mapped VA | `0xfffffe000a65359c` through `0xfffffe000a6535b0` | Store VA at P+0x48 and OOL0 u32 extent at P+0x50. Clear the secondary address and extent at P+0x58 and P+0x60 |
| Primary region installed | `0xfffffe000a653650` | Attempt `vm_map_wire_external(*kernel_map, start, end, 3, 0)`. The local continuation does not test its result |

The current kernel wrapper at `0xfffffe000be19724` explicitly handles a null input copy object by writing a zero VA and returning status zero. For a nonnull object it loads the copy object's u64 extent from +0x20, sets the consume argument to 1, and branches to the common mapper. The kext separately installs the descriptor extent supplied through the RPC client's u32 output. The null-result branch does not enter the primary installer. [Prior VM ownership and range recovery](kext_port_vm_report.md)

With A the mapped VA, L the zero-extended u32 extent, and M the u64 mask `UINT64_MAX << p` from runtime `_PAGE_SHIFT_CONST`, the wire call arguments are `start = A & M` and `end = (A + L + zext32(~low32(M))) & M`, with u64 additions. The source uses `MVN W13,W10` for the rounding term. This is a page-rounded covering span for valid page shifts through 32 and address arithmetic without wrap. At p=14, a page-aligned 4096 B extent gives a 16384 B span. Current file bytes do not establish this transaction's runtime page shift or wire outcome.

The current chained fixups lead from the selector slots through kext adapters and authenticated import stubs to these exact kernel entry points. The data slots resolve to the `_kernel_map` cell at `0xfffffe0007f92880` after a four-byte target adjustment, and `_PAGE_SHIFT_CONST` at `0xfffffe0007e799c0` directly.

| Operation | Function table index | Kernel symbol and entry |
| --- | --- | --- |
| Copyout | `0xf74` | `_vm_map_copyout`, `0xfffffe000be19724` |
| Discard | `0xf24` | `_vm_map_copy_discard`, `0xfffffe000be0e4b8` |
| Wire | `0xfb7` | `_vm_map_wire_external`, `0xfffffe000be17f1c` |
| Unwire | `0xf88` | `_vm_map_unwire`, `0xfffffe000be17f0c` |
| Deallocate | `0xedd` | `_vm_deallocate`, `0xfffffe000be75ee0` |
| Typed free | `0xf2b` | `_IOFreeTypeImpl`, `0xfffffe000c509988` |

## Owner and close interface

The current constructor writes the allocated record into C+0x58 at `0xfffffe000a64bce0`, stages the same pointer through SP+0x88 at `0xfffffe000a64bfd8`, and writes that slot into C+0x60 at `0xfffffe000a652268`. At `0xfffffe000a657778` it loads C+0x60 and stores it at owner+0x2e8, followed by a u32 word at owner+0x2f0 set to 152 for a nonnull pointer and zero otherwise. The earlier modeled run establishes the C+0x58/C+0x60 alias under its constructor premises. The current stores and matching close loads establish the interface, with the same owner epoch required for a lifetime join. [Record type and allocation](kext_security_record_report.md) [Modeled constructor alias](kext_constructor_reply_state_report.md)

| Close action | Current kext site | Consumed state |
| --- | --- | --- |
| Find child | `0xfffffe000a601f1c` | owner+0x2e8, checked for null |
| Unwire primary | `0xfffffe000a60210c` | `*kernel_map`, rounded interval based on P+0x48 and P+0x50, user_wire=0 |
| Deallocate primary | `0xfffffe000a602178` | `*kernel_map`, exact VA at P+0x48 and u32 extent at P+0x50 |
| Deallocate secondary if present | `0xfffffe000a60225c` | `*kernel_map`, exact VA at P+0x58 and u32 extent at P+0x60 |
| Free typed child | `0xfffffe000a602300` | 152 B `site.FPAppSecurityInfo` cleanup view at `0xfffffe0008492700` and P |

The secondary branch handles a child with a populated secondary VA. The ordinary installer above clears that slot, so this branch cannot account for OOL1 of the same undisturbed record. A separate producer or later writer would be necessary to observe it. The earlier reference-build close runs model primary and secondary presence independently. No further Mach emission occurs at these VM or allocator call sites. [Original close range and call proof](kext_mapped_cleanup_report.md) [Original close entry and private execution](kext_context_retirement_report.md)

## Assumptions and checks

| ID | Assumption and dependent conclusion | Falsification probe |
| --- | --- | --- |
| R1 | The collection and supported legacy correspondence identify the code for the current build. This governs addresses and symbol attribution. | Rehash the collections, recheck UUIDs, and verify their original instruction bytes and fixups. |
| R2 | The normal constructor frame is intact, its selected client returns an accepted reply, and its saved output slots retain their caller identities. This governs the field mapping and conditional local branches. | Compare the two caller argument setups with the MIG stores and independently check the selected dispatch slots. |
| R3 | The same allocated child and owner epoch reach normal close without intervening field replacement. This governs the mapping-to-retirement join. | Correlate the child and VA through install, owner publication, and close during one ordinary native transaction. |
| R4 | The mapped range has a valid runtime page shift and addition does not wrap. This governs the page-covering interpretation. | Compare actual map arguments with page shift and mapping extent, including aligned and unaligned ranges. |

High impact attaches to the distinction between the transmitted copy object, its mapped VA, and the persistent record fields used for retirement. Medium impact attaches to the separately guarded null VA, unchecked wire result, and the independent secondary branch. Native delivery, wire or unwire success, kernel VM effects, and ownership balance remain unknown.

The byte audit uses the original hashes of both collections, nlist symbols, format-8 chained fixups and selected A64 instructions. It checks the selector outputs for all 256 byte inputs per bank. For binary bytes B, fixups F, symbols N, retained instructions I and selector count S, audit work is O(B + F + N + I + 256S) time and O(B + F + N + I + 256S) space. QG1 and QG2 are covered by factual scope and the assumption register. QG3 covers output staging through close. QG4 covers byte widths and range arithmetic. QG5 distinguishes the guarded states. QG6 uses pinned primary binary evidence. QG7 records the bounded impact and unresolved native interfaces. [Audit](triage_evidence/audit_live_fairplay_reply_mapping.py) [Compressed receipt](triage_evidence/live_fairplay_reply_mapping_audit.json.zst)
