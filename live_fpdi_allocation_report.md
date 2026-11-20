# fairplaydeviceidentityd shared arena allocation

The installed arm64e image resolves the helper at `0x10020b5f0` to a daemon-local arena allocator through two wrappers. This is the helper used by the XPC worker's 128 B request and the candidate selector 26 predecessor's 16 B and 32 B requests. The allocator can take a chunk from an existing size class or request private anonymous memory through `mmap`. The known caller sizes concern storage inside the daemon. The IOKit record extent is a separate field. [XPC worker](live_fpdi_xpc_report.md) [Selector 26 predecessor](live_fpdi_selector26_caller_report.md)

## Authenticated calls and effects

| Preferred call PC | Dyld slot | Target | Key and discriminator |
| --- | --- | --- | --- |
| `0x10020b844` | `0x1005e72d0` | `0x10053c3ec`, middle wrapper | IA `0x7c87` |
| `0x10053c654` | `0x1005e7538` | `0x100539d2c`, allocator | IA `0xe204` |
| `0x10053a114` | `0x1005e7170` | `libSystem/_sched_yield` | IA `0x41e2` |
| `0x10053a9c8` | `0x1005e7aa8` | `libSystem/_mmap` | IA `0xf447` |

Sixteen paired-table selections were checked on all 256 possible byte inputs. The four calls use signed pointers with no address diversity. Both wrappers leave X0 intact through their internal dispatches. The arena entry captures it in X19 at `0x100539d50`. The outer wrapper returns the final X0 directly on the ordinary call path.

The outer wrapper reads the 8 B gate at `0x1005eddb0`. A zero read branches at `0x10020b740` to a null return at `0x10020b85c`. The installed file contains eight zero bytes there. The value after daemon initialization and the writer that enables this path are unknown. Another table selects the two candidate arena pointer cells at `0x1005edd60` and `0x1005edd68`. A null selection at `0x100539fb0` reaches a second null return at `0x10053a1f0`.

## Private wrapper argument

The outer wrapper puts the current 64-bit word from `0x1005ec0f8` in its stack slot and passes that slot by reference in X1. The middle wrapper saves the word as D, publishes `D * 0x2ebd + 1` modulo `2^64` to the same process-global location, and reserves an aligned stack area of 16–256 B using the high nibble of the published value. Its temporary word is initialized to `D - 0xe0` modulo `2^64`.

The allocator adds `0xe0` to that temporary word at `0x100539e5c` and stores the result through X1 at `0x100539e60`. On the ordinary return without other writes to the slot, the middle wrapper sees the original D. It extracts the low 16 bits of the difference from D and shifts left by four before writing the value into the outer wrapper's stack slot. Thus the ordinary composed path writes a stack adjustment of 0 B. The allocator's X0 return is independent of this stack word.

## Size classes and external boundary

With an available arena and its checks satisfied, requests of up to 224 B enter the small-size classes. Requests below 15 B use a fixed 32 B class. For the remaining requests in that branch, the code computes `(size + 31) & 0x1f0` in bytes. These are internal chunk sizes.

| Caller | Request | Internal chunk size |
| --- | ---: | ---: |
| Selector 26 predecessor, first call at `0x1000749a0` | 16 B | 32 B |
| Selector 26 predecessor, second call at `0x100072b00` | 32 B | 48 B |
| XPC worker at `0x1001f5288` | 128 B | 144 B |

The selected small-bin success branch updates the chunk's word at +8 B and returns the chunk address plus 16 B at `0x10053a8ec`. The third request at `0x100012e70` also passes its computed X0 to the allocator. Its presence establishes another allocation site. The intended business meaning and runtime result of that request remain unknown.

Arena state at +880 B has a lock-enable bit. With it set, acquisition exchanges the value 1 into the 32-bit lock word at +884 B. The wait loop can reach `sched_yield` on continued contention. The common return releases the word with a release store of zero when locking is enabled. The mapping branch calls `mmap` with a null address hint, computed length, `PROT_READ | PROT_WRITE`, `MAP_PRIVATE | MAP_ANON`, file descriptor −1 and offset 0 B. The flag values are from the installed macOS SDK's `sys/mman.h`. The immediate check after return tests the mapping failure sentinel −1. These are libc call sites in the daemon. Native VM and scheduler events remain unobserved for the investigated clients.

## Assumption register

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Preferred PCs refer to the pinned installed arm64e slice and original dyld fixups. The named callees depend on this identity. | Recheck the executable UUID, SHA-256, instruction words and fixups. |
| A2 | The outer gate and arena pointer are nonzero and the selected execution returns normally. The allocator path and chunk-size examples depend on these checks. | Establish the initialization writers and observe the reaching values for the original calls. |
| A3 | The inner stack word is still D at the middle wrapper's load. The zero adjustment depends on the paired subtract/add and this lifetime. | Inspect writes to the slot between allocator entry and wrapper return. |
| A4 | The known request widths reach the helper on their reported ordinary original paths. Site-specific allocation provenance is static. | Verify each reaching X0 and the returned pointer's continuation on the same running slice. |

High impact for identifying a shared allocator and separating buffer origin from connection provenance. Medium impact for locating allocator dependencies on scheduling and VM state. The connection container, its Mach port, the full same-frame route to the selector 26 adapter and a matching request remain unknown.

## Reproduction

The [read-only auditor](triage_evidence/audit_live_fpdi_allocation.py) checks the installed arm64e slice, UUID `0a404c50-4901-312f-9e36-04565d30f305`, and retains its SHA-256, 715 disassembled instruction records, 30 instruction assertions and 16 table selections in the [compressed evidence](triage_evidence/live_fpdi_allocation_audit.json.zst). With image size B, fixup count F, retained instruction count I, selections S and alphabet A=256, the audit costs O(B + F + I + SA) time and O(B + F + I + S + A) space.

    python3 -B triage_evidence/audit_live_fpdi_allocation.py DAEMON
