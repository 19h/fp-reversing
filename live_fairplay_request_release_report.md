# Installed RPC 502 filename consumption and error cleanup

On macOS build `26C5035r`, the RPC 502 application starts reading the mapped filename at `0x100422edc`. For an application error that reaches the generic request-destroy branch, `fairplayd` clears the request's remote name and calls `mach_msg_destroy`. The installed library reads the filename address and extent from the packed descriptor and requests deallocation in the daemon's own task. The current kernel's Mach trap 12 leads to a page-aligned VM range removal. The original application-success path bypasses this generic destruction. Ultimate ownership of the successful request's filename mapping remains unknown. [Current filename handoff](live_fairplay_request_ool_report.md) [Earlier callback routing and reply ownership](daemon_receive_interface_report.md)

```text
kernel copyout -> packed request (type 1, deallocate 1)
                         |
                 fairplayd filename read
                         |
             simple error selected for destruction
                         |
             clear request remote name
                         |
                 mach_msg_destroy
                         |
                 mach_vm_deallocate(self, VA, M)
                         |
            trap -12 ----+---- status 0x10000003 -> Mach RPC 4801
                |
           VM range removal
```

## Filename pointer and descriptor custody

| Boundary | Preferred PC or request offset | Evidence |
| --- | --- | --- |
| Kernel 64-bit packer | `0xfffffe000bd0e530`, `0xfffffe000bd0e580` through `0xfffffe000bd0e598`, `0xfffffe000bd0e4b0` | Extract copy byte, mask internal flags with `0xff00ff00`, increment when copy byte is 1 and write the flags and extent. For RPC 502, `0x01000100` becomes `0x01000101`. |
| Packed descriptor | Request+0x1c, +0x24, +0x28 | u64 mapped VA, four flag bytes `01 01 00 01`, u32 extent M. Relative to descriptor start these fields are at +0, +8 and +0xc. |
| MIG application call | `0x1000051b0`, `0x1000051b4`, `0x1000051f8` | Pass mapped VA in X1 and M in W2. |
| First application consumer | `0x100422edc`, then `0x10008a958` on the nonempty scan route | The first load reads the byte at VA. Subsequent loads follow the string to its terminating NUL. The prior source analysis establishes the scan and the wrapper's argument record. |
| MIG application return | `0x1000051fc` and `0x100005200` | Nonzero status goes into simple reply+0x20. Zero takes the 384 B complex reply serialization. |
| Selected error retirement | `0x10006ce34` and `0x10006ce90` | Clear the u32 remote-name field at request+8, then pass the same request pointer to `mach_msg_destroy`. The 256-input reduction resolves the call to libSystem slot `0x1010a0e98` with IA discriminator `0xc429`. |

The recognized simple-error branch has a separate no-send exit for `MIG_NO_REPLY` (−305). The generic destroy branch covers other nonzero simple-error statuses. Clearing request+8 before destroy preserves the reply destination already placed in the reply header. It leaves the OOL descriptor present for the selected callback path. The earlier private callback runs verify that order for one declared application error and two reply-right dispositions. They stop at the request-destroy API boundary. [Application filename reader](daemon_rpc502_report.md) [Composed error reply and callback fixtures](rpc502_ownership_report.md)

The current libsystem_kernel export `_mach_msg_destroy` starts at `0x180549bbc`. It passes the remote and voucher names to its right-disposal helper before checking the complex bit. It then reads the descriptor count at request+0x18 and starts the array at request+0x1c. The type-1 branch requires a nonzero low flag byte and nonzero extent. The ordinary nonempty RPC 502 descriptor has deallocate byte 1 and supplies M bytes. At `0x180549cd0` and `0x180549cd4`, the library loads X1 from the descriptor and W0 from the `_mach_task_self_` cell at `0x1ed902920`. W2, loaded at `0x180549c84`, zero-extends M. The call at `0x180549cd8` is `mach_vm_deallocate(self_name, VA, M)`. This loop continues without reporting the VM call's status to the caller.

The application-success stub serializes its reply without calling an incoming-buffer deallocator. On the selected ordinary CF run-loop return, the free at `0x18479d7a4` applies to a nonnull heap receive buffer that differs from the stack receive-buffer pointer. That pointer designates inline message storage. The out-of-line VA has separate ownership. The current CF path therefore supplies no release of the successful RPC 502 filename mapping at this boundary. This finding leaves the protected application and other framework paths open. [CF receive and application dispatch](live_fairplay_cf_receive_report.md)

## VM release interfaces and ports

| Interface | Site | Arguments and port roles |
| --- | --- | --- |
| Fast call | `0x18054a7dc` to `0x180548a8c`, SVC at `0x180548a90` | X16 = −12. The recipient task's own name is the u32 name argument, followed by u64 VA and extent. The fast call has no outgoing Mach message. |
| Kernel trap dispatch | `0xfffffe000bebfbd4`, `0xfffffe000bebfcc8` | The row at `0xfffffe0007f07138` is index 12 in the table at `0xfffffe0007f07018`, which has 24 B entries. It encodes three arguments and five u32 words, with an authenticated handler slot at row+8 targeting `0xfffffe000bd233e0`. |
| Task-to-map handoff | `0xfffffe000bd233fc` through `0xfffffe000bd23448` | Look up the task name with second argument 0. A null lookup returns `0x10000003`. Otherwise authenticate the returned object's +0x28 map field and pass it with the original address and extent to the range leaf. |
| VM range removal | `0xfffffe000be0a058` through `0xfffffe000be0a09c` | The map page shift comes from map+0x2c. For a valid ordinary extent, round the start down and the exclusive end up and tail-call the VM range remover at `0xfffffe000be1302c`. |
| Fallback IPC | `0x18054a818`, `0x1805701f8`, SVC at `0x180548c1c` | Trap return `0x10000003` selects message 4801 to the task port. The 48 B request uses COPY_SEND and the MIG reply endpoint uses MAKE_SEND_ONCE. The stub expects reply ID 4901. These ports are distinct from the FairPlay service and RPC 602 reply endpoint. |

For the fast leaf, let P be the map's page size in bytes, VA the returned daemon address, and M the exact descriptor extent in bytes. On the ordinary nonempty range, the VM request is `[floor(VA/P)*P, ceil((VA+M)/P)*P)`. A zero extent returns success once the map passes the nonnull test. For example, a page-aligned VA, M=29 B and P=16,384 B request retirement of one 16,384 B page. The original leaf checks the address-plus-size sum and rejects an empty or reversed rounded range on the nonzero branch. The 29 B input comes from the earlier private constructor example. The current recipient P and runtime mapping outcome remain unknown. [Earlier filename extent example](live_fairplay_request_ool_report.md) [Earlier VM release contract](daemon_vm_cleanup_report.md)

## Recorded trace

The supplied annotated RAX trace has 1,748 lines, 64 formatted Mach message or bridge header records, and 19 printed VM deallocation trap calls. The header count includes transactions rendered in more than one trace layer. No decoded header record has ID 502 or 602. The 19 deallocation records provide evidence of trap activity in that emulation run without a dispatch or descriptor correlation to this RPC. The audit retains only the file digest and census. It does not republish trace lines.

## Assumption register and verification

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| R1 | The pinned build, cache UUIDs, daemon thin hash and installed import correspond to the process under study. The preferred addresses and cross-image branch targets depend on that identity. | Rehash the collection and slice, compare process UUIDs, and inspect the resolved import. |
| R2 | The filename request reaches the selected ordinary 64-bit copyout route. The exact flag bytes and descriptor offsets depend on this path. | Compare the same request before packing and at callback entry. |
| R3 | The application returns a nonzero simple-error status eligible for destruction, with a still-live incoming mapping and descriptor. The joined error-release interpretation depends on those conditions. | Observe the status and same mapping address at application return and callback destroy entry. |
| R4 | The task-self cell denotes the daemon's task and the trap resolves its map under ordinary execution. VM retirement depends on the observed call result and kernel map state. | Correlate the task name, selected map, range parameters and release outcome. |
| R5 | The census covers the formatted Mach/bridge header forms present in the supplied trace. Its absence result is scoped to those records. | Decode any additional record format or exhibit a parsed header with either RPC ID. |

The read-only audit recaptures the source windows, cache exports and original pointers, tests all 256 inputs of the destroy-call selector, and independently decodes immediate branch words. It pins the installed kernel and daemon bytes and reproduces the trace census. The trace pass takes O(N) time with O(N) input storage and O(U) counts for N input bytes and U distinct message IDs. No workload execution, runtime deallocation, or observed native RPC 502 exchange is claimed. The ordinary application-error retirement contract has high impact. Resolving the successful application's custody of the same mapping remains high impact. Distinguishing task-port fallback traffic from FairPlay reply traffic has medium impact.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_request_release.py \
  "$CURRENT_COLLECTION" "$FAIRPLAYD_THIN" "$ANNOTATED_RAX_TRACE"
```

Quality gates QG1-QG7 were applied to this static increment. The report registers five conditional assumptions, identifies early consumption and the verified error path, gives widths and range arithmetic, distinguishes independent owners and transport branches, cites original-image evidence, and records the bounded native and success-path gaps. [Audit script](triage_evidence/audit_live_fairplay_request_release.py) [Compressed receipt](triage_evidence/live_fairplay_request_release_audit.json.zst)

The archived daemon worker audit links the original pointer to stack-based pathname construction and makes a separate accounting of the worker release calls before the reported error. The callback remains the verified request deallocation frontier for that error branch. [Filename custody](rpc502_filename_custody_report.md)
