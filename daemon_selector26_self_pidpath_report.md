# fairplayd selector 26 self-process path query

The private routine at `0x10043fe84` queries the daemon's own process path. It loads a caller-provided output pointer, passes the PID returned by `_getpid` to `_proc_pidpath` with a 4,096 B capacity, and stores a result word at record offset 16 B. The two caller continuations depend on whether the signed path length is positive. The helper's own instructions leave the transformed child allocation untouched through this dispatch. [Prior aggregate and record handoff](daemon_selector26_followon_aggregate_report.md)

## Daemon ABI and control flow

All daemon PCs and chained slots are unslid in `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The record base is caller FP minus 160 B. The writable range begins at caller SP plus `0xbaf` B and spans 4,096 B, with a 1 B gap between that range and the record. The only record read in the callee is the pointer at offset 8 B.

| Daemon PC | Chained slot | Operation |
| --- | --- | --- |
| `0x10043ffc0` | | Loads the output pointer from record offset 8 B into X20 |
| `0x100440074` | `0x1010a0f70` | Calls `libSystem/_getpid` |
| `0x1004400e0` | `0x1010a0608` | Calls `libSystem/_proc_pidpath` with PID in W0, output pointer in X1, capacity 4,096 in W2 |
| `0x1004400fc` | | Writes a 4 B private status at record offset 16 B |
| `0x100440118` | | Restores control to caller PC `0x10064be88` through the saved logical return address |
| `0x10064be8c` | | Loads the private status from caller FP minus 144 B |
| `0x10064bebc` | | Dispatches through the slot selected by the status comparison |

| Signed 32-bit `_proc_pidpath` return | Private status | Slot | Caller destination |
| --- | --- | --- | --- |
| 1 or greater | `0x8b3dc651` | `0x10104b5f0` | `0x1009c0424` |
| Less than 1 | `0x74c29dee` | `0x101047988` | `0x10065f430` |

Before either import, the helper reads and rewrites two 8 B controller cells. Let `S` be the callee SP after allocating its frame and `D` be the XOR of the two old cell values with `S + 8`. The store arithmetic wraps modulo `2^64`. Later call selection reads the cells' low 32-bit words. [Related use of the second controller cell](daemon_feedback_roots_report.md)

| Store PC | Cell | New value |
| --- | --- | --- |
| `0x10043ffb8` | `0x1010b6760` | `D * 0x0a5cd4cf + 0x8c2fb9df71512e5a` |
| `0x10043ffbc` | `0x1010c4670` | `(D XOR 0x73d046208eaed1a6) * 0x0a5cd4cf` |

## BSD boundary and trace correlation

The reference XNU wrapper uses BSD syscall `proc_info` (336) with call number 2 (`PROC_INFO_CALL_PIDINFO`), flavor 11 (`PROC_PIDPATHINFO`), argument 0, the same buffer pointer and the same capacity. It derives its userspace result from the string length after a successful syscall. The reference kernel dispatch resolves the PID and applies process security policy, then obtains the path from the process's executable vnode and copies the resulting buffer out. This operation introduces a BSD syscall boundary in the audited span. The two imports carry no Mach port names or rights in their recovered interfaces. The reference revision is pinned for the ABI comparison. The historical kernel and userspace wrapper builds are unknown. [Apple syscall table](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/syscalls.master#L497-L499) [Apple libproc wrapper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.c#L249-L268) [Call number](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info_private.h#L250-L254) [Flavor and capacity](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info.h#L702-L705) [Kernel dispatch](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c#L2241-L2246) [Kernel vnode and copyout](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c#L1296-L1342)

The retained RAX trace records PID 11747 at lines 16 and 1176. At line 1461, its `proc_info` call uses that PID, call number 2, flavor 11, argument 0, and capacity 4,096 B. This matches the recovered syscall argument pattern. The log records the syscall PC and a raw return of zero. The path bytes, wrapper result, and daemon call site are unknown. The event occurs before the failed UserClient open at lines 1726–1740, so it cannot establish execution of this post-selector-26 path. [Capture identity and open chronology](zut_trace_report.md)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The four upstream cases retain their synthetic child inputs, helper outputs, distinct allocator returns and inherited controller state. The import identities and pointer provenance apply to those states. | Recheck the import bindings and argument registers from a normal request on the pinned daemon. |
| A2 | Two process IDs are modeled and the signed 32-bit `_proc_pidpath` return is symbolic. Imported memory writes are unmodeled. The result and branch proofs cover the return domain under the retained frame states. | Record the path bytes, library return and caller status on the matching runtime build. |
| A3 | The two controller cells are read and written without competing events in replay. PAC control flow uses logical targets and the saved link. | Capture their actual values and update order with concurrent requests, and compare the resolved branch and return destinations. |
| A4 | The pinned Apple source supplies the reference mapping from the wrapper to BSD syscall fields. The RAX capture supplies ordering and a matching argument pattern. | Match the captured wrapper image to the reference and record the daemon LR across the syscall, wrapper return and subsequent branch. |

The audit executes the original instruction bytes, proves the status and caller slot selection for every signed 32-bit return in each of the four replayed states, and checks 13 distinct chained words read by the selected paths. Memory journal checks take O(J) time and space for J recorded events, excluding instruction replay, fixup parsing and solving. [Replay audit](triage_evidence/audit_daemon_selector26_self_pidpath.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_self_pidpath.py
```

| Impact | Open evidence |
| --- | --- |
| High | Identify the first consumers of the process-path output and the transformed child on the positive-length continuation. |
| High | Match a successful native method request and reply to the pinned daemon and kext dispatches. |
| Medium | Trace the nonpositive continuation to establish its cleanup and status propagation. |
