# Current FairPlay kernel RPC reply rights

The current kernel collection preserves the FairPlayIOKit RPC reply-port creation, copyin, namespace publication, and wait path. The kernel thread owns the reply receive endpoint. For RPC 502, `fairplayd` receives a send-once name for that endpoint and uses it as the destination of RPC 602. The service destination follows a separate chain through host slot 17. The installed code establishes these roles and emission sites. The actual slot object, per-task names, and a matched native transaction remain unknown. [Current slot lookup and emission sites](live_fairplay_kernel_rpc_report.md) [Bootstrap service evidence](fairplay_live_service_rights_report.md)

```text
Request: kext -> kernel send -> slot 17 service -> fairplayd RPC 502
                                    |
                     request carries reply send-once right
                                    |
Reply:   kext <- waiting kernel thread <- fairplayd sends RPC 602
```

## Creation and send ownership

| Boundary | Current site | Port and ownership effect |
| --- | --- | --- |
| Acquire service destination | `0xfffffe000a64be48` | The protected dispatcher gets a host-special send reference and stores it through X28+0x18. Slot 17 has the published `com.apple.unfreed` association. |
| Prepare RPC 502 or 700 | `0xfffffe000a5e325c` or `0xfffffe000a5e34cc` | Both kernel `mig_get_reply_port` calls resolve to `0xfffffe000bd3de0c`, which returns zero. The generated header stores disposition word `0x80001513` and the service destination. Kernel `mig_put_reply_port` and `mig_dealloc_reply_port` both return immediately. |
| Use or create reply endpoint | `0xfffffe000bd3d960`, create call `0xfffffe000bd3d99c` | Read current thread from `TPIDR_EL1` and binding at thread +0x3f0. A nonzero binding skips creation. The creator initializes a special reply port, stores it at thread +0x3f0, and publishes the signed owner at port +0x40. |
| Insert reply endpoint | `0xfffffe000bd3da20` | Write the reply object to internal header +0x10. The local disposition is `MAKE_SEND_ONCE` (21). The remote disposition is `COPY_SEND` (19). |
| Copy in rights | `0xfffffe000bd0eb7c` and `0xfffffe000bd0eb94` | The remote path increments destination send count at +0x88. The local path calls the make-send-once helper at `0xfffffe000bd1173c`, incrementing reply send-once count at +0x8c and object references at +4. The disposition table maps 19 to internal type 17 and 21 to internal type 18. |
| Hold destination and send | `0xfffffe000bd3da7c` and `0xfffffe000bd3da9c` | The transport takes a separate destination object reference at +4, then calls the common send with options `0x10001` and timeout argument 0. |

The reply space is stored in global `0xfffffe0007e6f348`. In 2,548,176 A64 words from kernel `__TEXT_EXEC`, an adjacent ADRP plus matching 64-bit access scan finds four reads and one write. The startup store at `0xfffffe000c67911c` publishes a separately allocated and initialized reply-space object. The creator loads that global at `0xfffffe000bd40d64` and passes it to the port initializer with kind input `0x10b`. The initializer stores the signed receiver-space pointer at port +0x48 and sets the internal name field at port +0x34 to 1. The global's file bytes are zero before startup. The scan covers the direct instruction form. Native pointer values and indirect accesses remain unknown. [Pinned reply-space initialization and lifetime](kernel_special_reply_report.md)

## Recipient namespace and reply emission

| Representation | Destination or service field | Reply capability |
| --- | --- | --- |
| Kernel request before recipient copyout | Internal remote object at +8 | Internal local object at +0x10, type 18 |
| Packed user request | Local service name at +0x0c | Remote send-once name at +8 |
| Generated daemon reply | Remote at +8 copies the received send-once name. Header construction masks the received remote disposition with `0x1f`. | Local field zero |
| Kernel reply wait | Destination is the thread-bound endpoint. The receive queue address is reply object +0x10. | The thread retains its receive binding on the ordinary successful path. |

Current header copyout at `0xfffffe000bd0ce54` routes internal reply type 18 through namespace name allocation at `0xfffffe000bd0d160` and right publication at `0xfffffe000bd0d1d0`. The special kind `0x0b` branch in publication calls the reply-state adjustment at `0xfffffe000bd1dba0`, then sets `0x00040001` in the entry word at +8. That word records a send-once right and one user reference for the allocated name. At `0xfffffe000bd0d398`, header conversion writes the converted reply and service values in that order. User packing narrows the two 64-bit lanes to 32-bit names at `0xfffffe000bd0e5f8` and stores them at `0xfffffe000bd0e608`. [Pinned namespace allocation and accounting](kernel_reply_namespace_report.md) [Pinned receive packing](kernel_user_copyout_report.md)

In the matching `fairplayd` image, `0x100005274` starts the reply header. It copies request +8 into reply +8 and increments the message ID by 100. The daemon sends at `0x100035184` through its authenticated `_mach_msg` binding. The received type 18 is the reply send disposition `MOVE_SEND_ONCE` (18). The separate service name at request +0x0c is the first RPC 502 application argument. The same kernel request-side lifecycle applies to RPC 700. Its receiver remains unknown. [Current daemon RPC ABI and binding](live_fairplay_rpc_abi_report.md)

## Wait and cleanup

The send-success path links the reply port to the destination at `0xfffffe000bd3db08` and receives at `0xfffffe000bd3db38`. The receive argument vector is `(reply + 0x10, 0, 1, current_thread, 0)` for this wrapper. The transport reads the result from thread +0x3a0 and the returned message pointer from thread +0x3b8. On successful receive it releases the temporary destination object hold at `0xfffffe000bd3dbd8` and continues to header conversion and copyback. The protected caller releases its separate send reference at `0xfffffe000a6570bc`. [Earlier transport contract](kernel_rpc_transport_report.md)

On the nonzero receive-status path, the kernel retries if thread +0x43c bit 5 is clear. If the bit is set, it releases the temporary hold and calls unbind at `0xfffffe000bd3db80`. The pre-wait interruption branch also calls unbind at `0xfffffe000bd3dc08`. Unbind clears thread +0x3f0 at `0xfffffe000bd40290` before transferring to downstream teardown. Success can reuse the same reply object for a later RPC on the thread. A port identity alone therefore does not identify a particular 502/602 exchange.

## Assumptions and checks

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | The collection and daemon identities select the intended images. This supports current preferred addresses. | SHA-256 both collections and the daemon reference, verify both embedded kernel and kext UUID pairs, and compare the current UUIDs with the boot kernel and loaded kext. The earlier slice audit ties the reference to installed daemon code. |
| A2 | The selected functions are corresponding compiler ranges. This supports the pinned ownership interpretation on the current build. | Compare all original words, retain every changed immediate, independently decode 17 selected calls, and recheck both disposition tables and 25 field instructions. |
| A3 | The accepted request traverses the ordinary namespace path with the current right types. This supports the role mapping and name transfer. | Check the SDK constants and the daemon header operations. A matched native observation could test the right type, receiving namespace, and emitted reply name. |
| A4 | The matched RPC proceeds through the selected receive status and cleanup route. This supports conditional reuse and unbind. | Check the success and failure branch sites and the exact binding field at teardown. Native scheduling and full retirement remain unknown. |

The audit compares 8,916 B across 16 compiler-bounded kernel functions in each collection. Of 2,229 aligned instructions, 2,023 match byte-for-byte. The 206 changes are confined to immediate fields in the decoded opcodes. They include one diagnostic `mov` from `0x9ac` to `0x9b3` on the IPC publication policy assertion branch. The audit verifies the selected call targets and data bindings individually. Uninspected addresses and unnamed callees are outside the equivalence check.

On a matching boot, pass the earlier collection, the current collection, and the audited thin daemon image to `triage_evidence/audit_live_fairplay_reply_rights.py` in that order. The work takes O(B + F + N + I + T) time and space for collection bytes B, chained records F, symbol records N, selected instruction words I, and scanned kernel text words T. The scan retains only matching locations. [Audit script](triage_evidence/audit_live_fairplay_reply_rights.py) [Compressed evidence](triage_evidence/live_fairplay_reply_rights_audit.json.zst)

High impact attaches to the distinction between the persistent thread receive port and the per-message send-once capability. The direct startup scan has medium impact because it anchors the reply-space producer. Native transaction identity still requires joining the slot-17 destination, 502 dispatch, send-once reply name, and outstanding wait epoch in a single observation.
