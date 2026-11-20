# Task exit, Mach namespace teardown and FairPlayIOKit ownership

On macOS build `26C5035r`, IOKit receives a task-phase-one hook before Mach namespace teardown. That hook handles DriverKit tasks. Namespace teardown may then release a FairPlay connection's final send right and dispatch the kernel's no-more-senders callback. The regular task-deallocation path later issues the task-phase-two hook. For owners still registered at that point, this hook removes the departing task's records and can call the same FairPlay `clientDied` override without waiting for a no-more-senders event. [Pinned XNU task phase one](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/task.c#L3228-L3241) [Pinned XNU task deallocation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/task.c#L2109-L2174) [Pinned XNU task hooks](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L1820-L1904)

```text
Task termination
  -> IOKit task hook 1 [DriverKit class gate]
  -> destroy Mach namespace
       -> eligible last connection send right -> connection no-more-senders
  -> later task deallocation -> IOKit task hook 2
       -> unlink remaining owner records
       -> if client lost its last owner and passes close gate
            -> FairPlay clientDied -> base clientDied -> eligible clientClose
```

Addresses are preferred and unslid. Task hooks, IOService termination phases and Mach port retirement refer to different lifecycles. A task owner identifies an IOKit registration record. A send right belongs to a Mach namespace entry. Their respective last-owner and last-sender tests operate on different state. [Owner registration](live_iokit_open_owner_report.md) [IOService phase-one cleanup](live_iokit_reference_cleanup_report.md) [Mach connection retirement](live_fairplay_connection_retirement_report.md)

## Task entry and ordering

The phase dispatcher at `0xfffffe000c5b7f30` tests W1 against 1 and 2. Its unmatched-phase diagnostic begins with `iokit_task_terminate phase %d`. The phase-one path compares task +1240 B under mask `0x000f000000000000` against `0x0007000000000000`. The body of the installed `task_is_driver` symbol uses the same test. The selected branch snapshots owners and checks the `IOUserServer` metaclass before dispatch. [Pinned XNU DriverKit task hook](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L1820-L1849)

| Direct hook site | W1 | Evidence in the installed caller |
| --- | --- | --- |
| `0xfffffe000bd86ed4` | 1 | The regular task-termination continuation authenticates the task's space pointer at +792 B and calls the space terminator at `0xfffffe000bd86ef8`. |
| `0xfffffe000bd8cdc4` | 1 | The corpse-task continuation reaches the same space terminator at `0xfffffe000bd8cde8`. |
| `0xfffffe000bd8c27c` | 2 | The deallocation implementation reached through `task_deallocate` invokes the owner hook after the IPC-task teardown call at `0xfffffe000bd8c270`. |
| `0xfffffe000bd8dd6c` | 1 | The complete-halt path passes the phase before space termination at `0xfffffe000bd8dd90`. |
| `0xfffffe000bd8ddd0` | 2 | The same complete-halt path calls the phase-two hook after the VM-map termination call at `0xfffffe000bd8ddb4`. This is a tail branch. |

These are the direct branch sites found in the installed kernel text section. The caller identities follow from the surrounding task, IPC-space and VM-map operations matched to XNU source. [Pinned XNU corpse path](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/task.c#L2649-L2678) [Pinned XNU complete halt](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/task.c#L3516-L3581)

## Mach right and notification boundaries

The space-termination implementation makes one pass over receive rights, then a second over remaining occupied entries. Calls at `0xfffffe000bd1e838` and `0xfffffe000bd1e8a0` enter the same entry terminator at `0xfffffe000bd1b694`. On the send-right branch, it decrements the port's 32-bit send-right count at +136 B and prepares a no-senders event if the count reaches zero. This applies to the right in the task's IPC table. The later owner hook consumes IOKit owner records. [Pinned XNU space teardown](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_space.c#L399-L477) [Pinned XNU right termination](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_right.c#L753-L835)

| Event | Dispatch and emission sites | Port and payload |
| --- | --- | --- |
| Kernel-object no-more-senders for IOKit connection type `0x27` | Prepare `0xfffffe000bd1b7ec`, select `0xfffffe000bd1b824`, invoke `0xfffffe000bd110a4` | Passes the connection port in X0 and the captured u32 make-send generation in W1 to the registered callback. This is an in-kernel call. The callback can remove the association and owner records before its FairPlay death dispatch. |
| Ordinary no-senders, ID 70 | Select `0xfffffe000bd1b818`, set destination at `0xfffffe000bd11020`, submit at `0xfffffe000bd11048` | For an eligible requested notification destination, supplies that port in the expanded header at +8 B and the make-send generation at +40 B. This is the ordinary notification branch of the entry terminator. |
| Ordinary port-deleted, ID 65 | Dispatch `0xfffffe000bd1b834`, set destination at `0xfffffe000bd10ecc`, submit at `0xfffffe000bd10ef4` | Uses the separate request destination returned by the cancellation helper, when present and eligible. The retiring namespace's port name is at +40 B. |

Both ordinary emitters submit a 44 B expanded kernel message buffer. The ordinary notification destinations depend on previously registered requests. Their presence on a native `fairplayd` connection is unknown. The earlier audit identifies the registered IOKit callback and distinguishes it from ordinary ID 70 emission. [Pinned XNU notification dispatch](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_notify.c#L115-L177) [Connection callback and port publication](live_fairplay_connection_retirement_report.md)

## Owner drain and FairPlay class dispatch

| Step | Installed sites | Effect |
| --- | --- | --- |
| Read the departing task's owners | `0xfffffe000c5b80b0`–`0xfffffe000c5b80e0` | Takes the global owners lock via pointer slot `0xfffffe000cbd7898`, then reads the queue head at task +1616 B. An empty queue exits after unlocking. |
| Remove the record from both queues | `0xfffffe000c5b8118`–`0xfffffe000c5b81e0` | Loads the client from record +24 B. Unlinks task-side links at record +8 B and +16 B and client-side links at +32 B and +40 B. The latter queue head is at client +160 B. |
| Retain clients that lose their last owner | `0xfffffe000c5b81e4`–`0xfffffe000c5b824c` | On an empty client-side queue, retains the client and repurposes the two head words. Sets +160 B to null and stores the pending list link at +168 B. Deallocates removed 48 B owner records at `0xfffffe000c5b8108` using the same type descriptor contents as the registration site. |
| Drain the pending list after unlock | `0xfffffe000c5b8268`, `0xfffffe000c5b8444`–`0xfffffe000c5b8458` | Unlocks the owners lock, reads and clears the pending link, and selects the callback if the +152 B shared-instance byte is nonzero or the +153 B closed byte is zero. This path calls outside the owner lock. The direct call path has no per-client write-lock acquisition at this handoff. |
| Join FairPlay teardown | `0xfffffe000c5b8420`, `0xfffffe000a545638`, `0xfffffe000c5b2080` | Dispatches vtable +`0x928` with the client in X0. FairPlay sets the byte at +244 B and tail-calls the base handler. The base gate then selects vtable +`0x920` for `clientClose` on the shared-instance or successful closed-byte transition. The owner hook releases its retained client at `0xfffffe000c5b8438`. |

The no-more-senders route takes the per-client write lock around its `clientDied` dispatch. An eligible no-more-senders callback can remove the owner record before the task-phase-two walk reaches it. A surviving owner on the client queue skips the task-phase-two death list. These conditions describe separate ordinary routes to connection teardown. [Pinned XNU owner drain](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L1851-L1904) [No-more-senders and class dispatch](live_fairplay_connection_retirement_report.md)

## Assumptions and verification

| Premise | Dependent result | Falsification probe |
| --- | --- | --- |
| The fileset corresponds to the running kernel and kext. | Installed addresses and vtable bindings. | Rehash the collection and compare both fileset UUIDs with current identities. |
| The task is on the ordinary daemon exit path. | The task-phase-one DriverKit gate skips its owner snapshot. | Compare the exiting task's class with the driver predicate, and distinguish regular termination, corpse generation and complete halt. |
| The connection's affected send-right count drops to zero with the expected type and generation. | Namespace teardown can enter the IOKit no-more-senders callback. | Correlate the port type, current right count and generation with the same event in a passive trace. |
| A registered owner remains until task phase two, its removal empties that client's owner queue, and the client passes the close gate. | Owner cleanup can invoke FairPlay `clientDied` for that client. | Match the owner removal, remaining queue state, shared/closed values and callback for the same registry entry. |

High impact for attributing teardown to process lifetime, Mach right lifetime or explicit close. Medium impact for mapping ordinary notification emitters reachable from namespace teardown and distinguishing the last-owner hook from DriverKit shutdown. A matched native daemon exit, phase ordering, live destination names and final release remain unknown.

The read-only audit checks 128 instruction sites, both notification ID literals, both typed descriptor sites, and the vtable bindings. It scans 2,545,292 aligned kernel instruction words for direct branch targets. Verification takes O(B + F + I) time and space for B collection bytes, F fixups and I selected sites. The phase-two owner walk is O(N) for N records in the departing task's owner queue, excluding callback and deallocation internals, with a pending list stored in the existing client objects. [Audit script](triage_evidence/audit_live_iokit_task_owner_teardown.py) [Compressed receipt](triage_evidence/live_iokit_task_owner_teardown_audit.json.zst)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_iokit_task_owner_teardown.py "$CURRENT_COLLECTION" --observe
```
