# Kernel boundary for the ADID XPC thread reply port

The installed kernel allocates the **user thread's special reply receive right** in the current task's IPC space. Trap -50 returns a task-local name with send and receive rights and binds the object at thread +0x450. The synchronous Mach2 receive can verify that binding and link the wait to the channel destination. The separate FairPlayIOKit RPC 502/602 path binds a kernel-owned reply object at thread +0x3f0 and uses the kernel reply space. Both use port kind `0x0b`. The addresses below are preferred virtual addresses for macOS build `26C5035r`. [ADID user-space transport](live_adid_xpc_sync_transport_report.md) [FairPlayIOKit reply rights](live_fairplay_reply_rights_report.md)

```text
fairplayd TLS +0x40 --> task IPC name --> receive object --> thread +0x450
                                           |
                           reply wait can link to channel destination

FairPlayIOKit kernel RPC --> reply-space object ------------> thread +0x3f0
```

## Reply-name production and ownership

| Stage | Installed site | Established result |
| --- | --- | --- |
| User trap | libsystem_kernel `0x180548c3c`, SVC `0x180548c40` | Loads X16 = -50. The kernel trap name table identifies `thread_get_special_reply_port`. Its zero-argument row binds the authenticated handler at `0xfffffe000bd40b94`. |
| Existing binding | `0xfffffe000bd40bac`–`0xfffffe000bd40c10` | Reads current thread and authenticates thread +0x450. A valid existing object is locked, detached from the thread field and sent through reply-state adjustment with flag 4, which clears port +0x40. The handler releases the binding reference before proceeding to allocation. A libdispatch TLS hit can reuse the name without entering this replacement path. The replacement prefix establishes release of the binding, and the former namespace entry requires a separate lifetime analysis. |
| Allocate in current task | `0xfffffe000bd40c14` through `0xfffffe000bd40c58` | Obtains the current thread's task, authenticates its IPC-space pointer at task +0x318, and calls `0xfffffe000bd14ef4` with input flags `0x10b`, NULL third argument, and fourth argument 1. Output slots are a 32-bit name and object pointer. |
| Publish receive entry | `0xfffffe000bd14f60`, `0xfffffe000bd15000`, `0xfffffe000bd1501c` | Allocation obtains a namespace entry and name, initializes the port with that space and name, and publishes send and receive type bits `0x30000` with one send user reference. The allocator's flag-0 control selects receive type `0x20000` and zero send user references. The kind table selects kind word `0x20b`. The initializer writes the generated name at port +0x34 and authenticated space at +0x48. |
| Bind and return | `0xfffffe000bd40c64`–`0xfffffe000bd40ccc` | Failure returns zero. Success takes a reference at port +4, stores the signed object at thread +0x450, signs the thread owner at port +0x40, and returns the generated name from the output slot. |
| Kernel RPC control | `0xfffffe000bd40d64`, `0xfffffe000bd40d98`, `0xfffffe000bd40db8` | The RPC creator reads the kernel reply-space global, passes internal name 1 and kind input `0x10b` to the same initializer, and writes its binding at thread +0x3f0. |

## Receive options and destination linkage

Libdispatch's wait calls `mach_msg` with send size zero, the special reply receive name in X4, and the channel send name in X6 when the channel name tests valid. The latter condition enables `MACH_RCV_SYNC_WAIT` (0x4000). In `mach_msg_overwrite`, the receive-only `0x4002` option-mask branch copies the notify argument into header +8 at `0x180551978` before packing Mach2 X3. Mach2 X5.high holds the reply receive name. This is a receive-side parameter transfer. The outbound request was already submitted by the send worker. [Libdispatch request and wait sites](live_adid_xpc_sync_transport_report.md)

| Stage | Installed kernel site | Established result |
| --- | --- | --- |
| Select receive path | `0xfffffe000bd2574c`, `0xfffffe000bd2596c`–`0xfffffe000bd25980` | Trap -47 uses the receive selector and routes into `0xfffffe000bd253d8`. It takes the receive name from packed X5.high, and supplies X3.low as the linkage argument only when the sync-wait bit is set. |
| Resolve reply receive name | `0xfffffe000bd25458` | Looks up the name in the current task's IPC space. A failed receive lookup returns before the wait setup. |
| Check kernel binding | `0xfffffe000bd2548c`–`0xfffffe000bd254e4` | A zero linkage argument skips the check. With a nonzero argument, the resolved receive object must equal the authenticated thread +0x450 binding and the argument must differ from `0xffffffff`. Otherwise the handler drops its lookup reference and returns `MACH_RCV_INVALID_NOTIFY` (0x10004007). |
| Resolve and link destination | `0xfffffe000bd25514`, `0xfffffe000bd112e8`, `0xfffffe000bd25560` | Tests for a send right in the namespace entry. A successful lookup calls the shared link helper with the receive object, the channel destination object and flag 0, then releases the temporary destination reference. On the eligible kind-0x0b branch, the helper takes its own destination hold, stores the signed link at reply +0x58 and writes state 1 to bits 12–14 of reply +0x10. If the destination lookup fails, the path joins receive setup without that link. |
| Receive queue entry | `0xfffffe000bd255a4`–`0xfffffe000bd255c4` | Records the resolved object and options in the thread receive record, then calls the queue receive routine with object +0x10 as its first argument. Queue scheduling and delivery of an actual ADID reply are unknown. |

## Archived control

The fixed RAX archive has one `thread_get_special_reply_port` return at line 1487. The returned guest name `0xb03` reappears in both the local-name lane and the receive-name lane of all ten trap records for five bootstrap requests and their bridge continuations. The low options include both send and receive, and these calls carry ID `0x400000ce`. This corroborates the role of the guest name in the bootstrap sequence. The separately submitted ADID request and wait belong to the installed static transport path. Native ADID port names and a transaction-linked FairPlayIOKit operation remain unknown. [Archived bootstrap controls](zut_trace_report.md)

## Assumptions and verification

| Assumption | Dependent result | Stress test |
| --- | --- | --- |
| A1. The collection and cache match the boot and installed UUIDs. | Trap table, pointers and original sites. | Check the SHA-256, both collection UUIDs, boot identity, cache UUID, function boundaries and two trap rows. |
| A2. Allocation succeeds in the current IPC space. | Receive entry, returned name and binding. | Check both result branches, the initializer output and namespace stores. Verify the separate RPC space and thread field as a control. |
| A3. The ordinary sync-wait route has a valid channel destination and a matching reply binding. | Destination linkage. | Verify the zero, all-ones and mismatched-binding branches, send-right test, failure join and eligible link stores. Runtime selection requires observed arguments. |
| A4. Archive records are limited to the recorded guest and bridge sequence. | Special reply name control. | Pin the trace digest and match the same thread, request ID, send/receive option bits and packed name lanes against bootstrap records. |

High impact attaches to distinguishing the two kernel thread bindings and to locating the synchronous receiver's destination linkage. Medium impact attaches to the archive control for the reused guest name. The read-only checks use original binary ranges, installed SDK constants and the archived trace. Collection and cache parsing, instruction capture and trace scanning are bounded by O(B + F + I + T) time and space for input bytes B, fixups F, retained instructions I and trace bytes T. QG1 and QG3 cover factual scope and interface coverage, QG2 and QG5 the stated branches, QG4 the field widths and option masks, QG6 the source pins, and QG7 the bounded impacts. [Verifier](triage_evidence/audit_live_adid_xpc_special_reply_kernel.py) [Audit receipt](triage_evidence/live_adid_xpc_special_reply_kernel_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_adid_xpc_special_reply_kernel.py \
  "$CURRENT_COLLECTION" "$ANNOTATED_RAX_TRACE"
```
