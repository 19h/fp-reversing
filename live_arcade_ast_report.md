# Process launch schedules the kernel Arcade subscription upcall

The current kernel's `posix_spawn` and shared `execve`/`__mac_execve` paths each contain an atomic writer for `AST_ARCADE` (bit 11, mask `0x800`) on the new thread. At both sites, the writer runs when the selected task is non-platform and passes the kernel's Arcade entitlement query. On the inspected return-to-user path, the handler consumes the bit and calls the kernel Arcade handoff that can send Mach request 41471 through host slot 31 or use an already registered daemon endpoint for RPC 61471. This establishes the static event producer and consumer on build `26C5035r`. A native invocation and the resulting transaction remain unknown. [Current Arcade endpoint and message audit](live_arcade_registration_report.md) [Apple XNU Arcade AST definition](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ast.h#L116)

```text
BSD 244 posix_spawn ------------------------------+
BSD  59 execve -> shared exec implementation -----+-> target-task checks
BSD 380 __mac_execve -----------------------------+          |
                                                        AST 0x800
                                                             |
                                       new thread -> return-to-user handler
                                                             |
                                       kernel Arcade -> fairplayd
```

## BSD syscall binding and the writer sites

The audited kernel UUID is `90195379-954d-3ca3-baac-327341f14211`. At `0xfffffe000c48a94c` the dispatcher computes three times the selected index, then scales by 8 B for a 24 B row from `0xfffffe0007f39230`. At `0xfffffe000c48aafc` it loads the first pointer in that row and calls it at `0xfffffe000c48ab10` with authentication discriminator `0xbcad`. The three original row fixups use that discriminator. An independent name vector at `0xfffffe000cb1b0e8` supplies the names. Each name also agrees with the pinned public syscall declarations. [Apple XNU syscall declarations](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/syscalls.master) [Original rows, fixups and dispatch words](triage_evidence/live_arcade_ast_audit.json.zst)

| BSD number and name | Handler pointer slot | Handler target | Argument count / 32-bit argument footprint | Arcade writer |
| --- | --- | --- | --- | --- |
| 244 `posix_spawn` | `0xfffffe0007f3a910` | `0xfffffe000c2f09f4` | 5 / 20 B | `0xfffffe000c2f1c04` |
| 59 `execve` | `0xfffffe0007f397b8` | `0xfffffe000c2f5c74` | 3 / 12 B | Forwards at `0xfffffe000c2f5c98` to the 380 implementation |
| 380 `__mac_execve` | `0xfffffe0007f3b5d0` | `0xfffffe000c2f5ca8` | 4 / 16 B | `0xfffffe000c2f63e4` |

The 59 forwarder copies the first three 8 B arguments to its local record and appends a zero fourth field before calling the 380 implementation. The 24 B row widths above describe the dispatch table. The 12 B, 20 B and 16 B widths describe separate argument metadata for 32-bit callers.

| Stage | Spawn path | Shared exec path |
| --- | --- | --- |
| Load the target thread from launch image parameters at +0x2b8 B | `0xfffffe000c2f1bd8` into X21 | `0xfffffe000c2f63b8` into X25 |
| Ask `_task_get_platform_binary` about the selected task | `0xfffffe000c2f1be0`, task X19 | `0xfffffe000c2f63c0`, task X23 |
| Ask `_IOTaskHasEntitlement` about the same task | `0xfffffe000c2f1bf4` | `0xfffffe000c2f63d4` |
| Atomically OR `0x800` into thread +0x43c B | `0xfffffe000c2f1c04` | `0xfffffe000c2f63e4` |

Both entitlement calls use the original constant `com.apple.developer.arcade-operations` at `0xfffffe000704a90a`. A nonzero platform result skips the entitlement call and the write. For a zero platform result, a zero entitlement result skips the write and a nonzero result sets the bit. This predicate describes the two reached local blocks. The receiving `fairplayd` task, the task under launch and the CoreFP XPC peer have distinct roles. The public reference calls `arcade_prepare` with the new task and thread after launch image preparation, corroborating the task/thread interpretation of the compiled blocks. [Apple XNU spawn and exec call sites](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exec.c) [Separate CoreFP peer authorization](arcade_policy_report.md)

## Return-to-user consumption and pathname provenance

The return-to-user code reads the processor pending word through the current thread's processor field at +0x1c0 B. Its wrapper at `0xfffffe000bce4038` calls the AST handler at `0xfffffe000bce4040`, then branches back to the pending-word check. The handler at `0xfffffe000bd29e80` merges thread +0x43c B into the processor pending word at +0x4c B. The bit-11 test at `0xfffffe000bd29f1c` selects the Arcade arm. The arm atomically clears thread mask `0x800` at `0xfffffe000bd29f80` before the call at `0xfffffe000bd29f84`. Apple XNU calls this return-to-user handler `ast_taken_user` and associates its Arcade arm with `arcade_ast`; these names describe the matched roles in the stripped image. [Apple XNU AST processing](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ast.c) [Current return and handoff instructions](triage_evidence/live_arcade_ast_audit.json.zst)

On the subscription route, the kernel handoff reads the process-like pointer from the current thread's read-only record at `0xfffffe000bd29c2c`. It passes that pointer to the pathname producer at `0xfffffe000bd29c60` with a 4,096 B buffer capacity. The producer reads and authenticates the object field at +0x598 B and calls `_vnode_getwithvid` at `0xfffffe000c3bc530`. This places the pathname producer in the kernel-side process context that services the AST. The caller's eventual 4,096 B transport record, opaque scalar and daemon XPC serialization are covered by the existing subscription audits. The exact native vnode, pathname and policy result remain unknown. [Current 61471 call](live_arcade_registration_report.md) [Daemon pathname and subscription mapping](arcade_subscription_report.md)

## Scan boundaries and verification

The audit scans 15,556,608 aligned words in the root fileset's `__TEXT_EXEC` segment. It finds 25 adjacent `ADD #0x43c` / zero-shift `MOVZ W` / 32-bit `LDSET` or `STSET` triples with connected operand registers. Two set bit 11 and 23 set other masks. The bound covers this direct instruction form. A split address calculation, a computed mask or another store form could encode additional writers. The same scan independently finds the three selected immediate `B` or `BL` edges to the return wrapper, AST handler and Arcade handoff.

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The fileset and reference corpus identify the selected build and syscall names. | Mapping BSD 59, 244 and 380 to the original handler targets. | Rehash the fileset, verify dispatch address arithmetic and compare the original name and entry fixups. Use original layout whenever the public source differs. |
| A2. The two reached platform/entitlement blocks use the new task and its new thread. | Producer attribution to ordinary launch. | Recheck the target registers across the named calls, the thread field load, the two skip targets and the matching public call sites. A native launch capture would attest the actual objects. |
| A3. The writer census covers the specified adjacent form. | Two matching writers of bit 11 in this encoding. | Recheck source register flow and decode all 25 matched triples. A mask propagated through a helper or loaded from memory falls outside the census. |
| A4. The new thread reaches the inspected return-to-user route and its pending bit remains set. | Application of the source writer to the Arcade handoff. | Correlate thread identity across preparation, pending-word propagation, clearing and the kernel's send or cached-endpoint selection in one native event. |

High impact attaches to joining the Arcade Mach exchange to the kernel's ordinary process launch and return-to-user paths. Medium impact attaches to identifying the source of the path input and distinguishing launch-task eligibility from daemon-peer authorization. The audit checks three BSD rows, six associated chained pointers, two writer windows and five downstream windows. It reads source artifacts without launching a process to exercise the protocol. The scan is O(W) in executable words W, and retains O(M + C) comparison records for M matching instructions and C selected call edges, in addition to the fileset and its parsed metadata. The checked branch conditions, field widths, corpus identities and remaining runtime dependencies are recorded above. [Reproduction script](triage_evidence/audit_live_arcade_ast.py)

```sh
python3 -B triage_evidence/audit_live_arcade_ast.py "$BOOT_FILESET"
```
