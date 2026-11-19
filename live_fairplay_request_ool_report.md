# Installed FairPlay RPC 502 filename buffer

On macOS build `26C5035r`, the FairPlayIOKit mode-1 constructor uses the kernel startup submap `ipc_kernel_map` to stage the filename for RPC 502. It passes the exact copied length and a VM copy object to Mach. On successful copyout, the kernel replaces the object in the descriptor with a virtual address in the receiving map. The installed `fairplayd` MIG stub checks the two length fields and passes that address and extent to its application call. The original images establish this path conditional on ordinary send and receive. The backing kind, port objects, addresses and contents for any actual transaction remain unknown. [Current constructor and route](live_fairplay_constructor_mode_report.md) [Current RPC ABI](live_fairplay_rpc_abi_report.md)

```text
kernel startup -> ipc_kernel_map
                       |
filename -> M B -> staging VA in ipc_kernel_map
                       |
                 vm_map_copyin(..., M, 0, &out)
                       |
            copy object + M -> RPC 502 send
                       |
            receive copyout in recipient map
                       |
             mapped VA + M -> fairplayd application
```

## Startup and kext staging

| Original instruction or fixup | Relation |
| --- | --- |
| `0xfffffe000c679144`, `0xfffffe000c67914c` | Load `*_kernel_map` and the startup range base from `0xfffffe000cc482a0`. |
| `0xfffffe000c679150` through `0xfffffe000c679168` | Call the suballocator at `0xfffffe000be09998` with size `0x4000000` B and publish the returned map pointer in `_ipc_kernel_map` at `0xfffffe0007f06638`. The cell's original 8 file bytes are zero. |
| `0xfffffe000be09a08` through `0xfffffe000be09a28` | Form the exclusive upper bound as base plus size and request map creation with page shift 14. The creator stores the shift at map+0x2c and the page-adjusted bounds at map+0x10 and +0x18. The caller copies the parent map's +0xc0 field to the submap. The native base and map pointer remain unknown. |
| `0xfffffe000a64c608` through `0xfffffe000a64c644` | The kext's two-bank reduction yields index 0x8a for each of the 256 input bytes. Pool slot `0xfffffe0008488df0` rebases to cell+4. The `-4` preindexed load reads `*_ipc_kernel_map` and leaves X21 pointing at the cell. |
| `0xfffffe000a64c6a8`, `0xfffffe000a64c798` | Call `_kmem_alloc` with the submap, the staging-address output at context+0x80 and the allocation extent A. Copy M bytes to the staging VA through the `_memcpy` / `_memmove` alias. |
| `0xfffffe000a64c8b0` through `0xfffffe000a64c910` | Save the cell address at SP+0x70, reload its pointer and call `_vm_map_copyin(map, staging, M, 0, &context[0x28])`. The function import resolves through authenticated slots `0xfffffe00084916a0` and `0xfffffe0008493000`. |
| `0xfffffe000a656ff8` through `0xfffffe000a657064` | A selected cleanup continuation reloads the map, staging VA and saved allocation extent, then calls `_kmem_free`. The copyin flag 0 gives this path independent custody of the staging allocation. |

The startup size is `0x4000000` B = 67,108,864 B = 64 MiB. Page shift 14 gives a 16,384 B startup map page. The previous collection's continuously replayed constructor computes M as the low 32 bits of `strlen(name) + 1` and A as M rounded up to the constructor's configured page quantum. For an ordinary bounded filename, M includes the terminating NUL. For example, a name of 28 B yields M=29 B and A=16,384 B when the configured quantum is 16,384 B. The current copy and transport sites supply M, and the selected staging cleanup supplies A. The numerical example is a carried-forward size calculation [O2]; native input and allocation extent have no runtime sample here. [Earlier length and staging proof](kext_constructor_request_report.md) [Earlier cleanup contract](kext_port_vm_report.md)

The bounded adjacent-instruction scan finds 12 64-bit loads and one 64-bit store to the named cell in 15,564,800 four-byte instruction slots across the boot collection's two executable segments. The kext's nonadjacent fixup-plus-bias path is a separate original reference. The scan excludes indirect aliases and nonadjacent instruction sequences [O3].

## Object construction and transport

The flag-normalizing `_vm_map_copyin` entry at `0xfffffe000be19744` forwards 0 to its common factory. The inline small-copy path checks M at `0xfffffe000be19878` against 32,768 B and has additional option, source-range and policy gates. The u32 policy cell at `0xfffffe0007e7601c` contains 2 in the file. Thread, owner and map state participate after the initial length gate. The effective boot-time selector and branch at an actual invocation remain unknown [O4]. The earlier kernel policy proof describes a corresponding decision in a separate collection. [Earlier policy evidence](kernel_copyin_policy_report.md)

On the small-copy success path, the allocator call at `0xfffffe000be1a044` obtains backing storage and the call at `0xfffffe000be1a064` transfers M bytes from the staging VA. The factory writes the u64 extent at object+0x20, kind 3 at +0x2d and the backing pointer at +0 after signing it with discriminator 0xb7af. It sees the clear destroy flag and publishes the object via the caller's output pointer at `0xfffffe000be1a0e8`. At this point the staging VA, the copy object pointer and its backing storage are three separate values.

At `0xfffffe000a5e3234`, the generated RPC 502 client puts the copy object into the type-1 Mach OOL descriptor. At `0xfffffe000a5e323c` and `0xfffffe000a5e3250` it writes the same u32 M into the descriptor and request scalar. It emits the 88 B internal request through the wrapper called at `0xfffffe000a5e3288` and the send at `0xfffffe000bd3da9c`. The kernel takes the raw-descriptor branch of its kernel-message import when option bit 37 is set. That branch calls the descriptor signer at `0xfffffe000bd0ea9c`. The type-1 case selects discriminator 0x5d4f at `0xfffffe000bd0a3b8`, signs against the destination descriptor address at `0xfffffe000bd0a350` and stores at `0xfffffe000bd0a354`. The generated client's import resolves to `_mach_msg_rpc_from_kernel_proper`, which sets X4 to `0x2000000000` at `0xfffffe000bd3dd24` before tail-branching to the common transport. [Current transport and destination-right audit](live_fairplay_reply_rights_report.md)

## Recipient mapping

The header copyout routine tail-branches at `0xfffffe000bd0d3d8` to the body converter, passing the recipient map as X3. In the type-1 case the converter authenticates the stored descriptor object at `0xfffffe000bd0d630` and loads the u32 descriptor extent at `0xfffffe000bd0d634`. The validator at `0xfffffe000be1963c` requires exact equality to the stored u64 extent for kind 3. Kind 2 has a distinct validator path that permits page-rounding adjustments. The normal kind-3 branch calls the recipient-map function at `0xfffffe000bd0d6a4` with `(recipient_map, &out_va, copy, M, 1)`.

For the kind-3 mapper's ordinary successful transfer, the final argument 1 reaches the backing and header release path. The helper authenticates the backing pointer at `0xfffffe000be14020`, zeroes its cell and calls the backing and copy-header retirement routines at `0xfffffe000be140cc` and `0xfffffe000be140fc`. If the mapper returns a failure, the descriptor converter's path through `0xfffffe000bd0d8b4` requests `_vm_map_copy_discard`. On success the converter reloads the mapped VA at `0xfffffe000bd0d89c`, stores it at descriptor+0 at `0xfffffe000bd0d570`, and writes the validated extent at descriptor+0xc at `0xfffffe000bd0d574`. These are static call and data-flow boundaries. The native daemon VA's final release falls outside this audit. [Earlier CPU receive and object lifecycle](kernel_request_receive_report.md)

| Field | Internal message | Packed daemon message | Exact daemon use |
| --- | ---: | ---: | --- |
| Object / address, 8 B | +0x24 | +0x1c | Load at `0x1000051b0` and pass in X1 at `0x1000051f4`. |
| Descriptor extent, 4 B | +0x30 | +0x28 | Load for the equality check at `0x1000050f4` and pass as W2 at `0x1000051b4`. |
| Repeated extent, 4 B | +0x3c | +0x34 | Load at `0x1000050f8` and compare at `0x1000050fc`. |

The daemon calls the application routine at `0x1000051f8` targeting `0x100422d48`. The installed receive packer accounts for the 8 B difference in internal and user offsets. This data path carries memory. The service destination and the thread-bound reply name are accounted for in the existing transport report. [Installed packing](live_fairplay_audit_token_report.md) [Port rights](live_fairplay_reply_rights_report.md)

## Assumptions and verification

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| O1 | The pinned collection and daemon slice match the installed build. All preferred addresses and cross-image joins depend on that identity. | Repeat the image and CodeDirectory comparisons and hash the original bytes. |
| O2 | The ordinary constructor path and bounded readable NUL-terminated filename satisfy the earlier size derivation. The M/A interpretation depends on those conditions. | In an ordinary native call, compare the length producer, allocation request extent and descriptor extent. |
| O3 | The writer inventory counts adjacent ADRP plus unsigned-offset u64 LDR/STR in the two named executable segments. Its uniqueness claim is confined to this instruction form. | A wider alias analysis may identify more references. Any second adjacent pair to the same cell falsifies the stated count. |
| O4 | A successful type-3 transfer reaches all the small-copy and mapper gates with valid object and map state. The exact-equality and retirement findings depend on that branch. | Correlate source map, M, copy kind, recipient map, mapper status and returned VA during one ordinary request. |
| O5 | The normal receive path packs the corresponding queued message into the verified arm64e daemon. The end-to-end logical join depends on ordinary delivery and matching message identity. | Correlate service-member delivery, RPC ID, descriptor extent and VA through application entry. |

The read-only audit verifies the current and previous boot collection hashes and fileset UUIDs, the daemon thin slice hash, the original chained pointers and the selected instruction bytes. It evaluates 256 byte inputs per kext selection and independently decodes the pinned direct branch immediates. The executable scan takes O(W) time with O(R) output storage for W instruction words and R matches. The existing loader uses O(B+F+S) space for B file bytes, F decoded fixups and S symbol records. Reproduction expects the repository's Python dependencies and takes the three original images as arguments.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_request_ool.py \
  "$CURRENT_COLLECTION" "$REFERENCE_COLLECTION" "$FAIRPLAYD_THIN"
```

High impact attaches to the startup provenance and VM custody join. Medium impact attaches to resolving the native backing kind and tracing the daemon's eventual VA release against the same request. The byte units, symbol identities, bounded scans and conditional ownership transitions are independently inspectable in the receipt. The full investigation remains active. [Audit script](triage_evidence/audit_live_fairplay_request_ool.py) [Compressed receipt](triage_evidence/live_fairplay_request_ool_audit.json.zst)

Quality gates QG1-QG7 were applied to the static increment. The report makes descriptive claims, registers five assumptions with falsification probes, covers the selected request through daemon argument delivery, states byte widths and rounding, distinguishes error and success continuations, identifies original-image provenance, and labels the bounded remaining questions by impact.

The installed daemon error-cleanup audit follows the mapped address through the selected request-destroy callback, libsystem_kernel and the task-self VM deallocation interface. The application-success mapping lifetime remains open. [Installed RPC 502 error cleanup](live_fairplay_request_release_report.md)
