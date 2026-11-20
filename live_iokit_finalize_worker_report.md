# IOKit phase-three finalization and FairPlay provider stop

On macOS build `26C5035r`, the kernel drains the finalization queue through `IOService::terminateWorker`. For a FairPlayIOKit user client, the finalization action resolves to inherited `IOService::finalize`. On its phase-three branch, that method can queue a client/provider stop pair. The stop worker checks the inactive client's finalized bit before it calls the FairPlay `stop` override. These bindings connect the prior close and reference-cleanup reports to the later provider-context cleanup. [Method locking and finalization admission](live_iokit_method_locking_report.md) [Phase-one reference cleanup](live_iokit_reference_cleanup_report.md) [Provider stop and context ABI](live_fairplay_provider_stop_report.md)

```text
Post-phase-two victim -> mark phase three -> no attached clients?
    yes -> scheduleFinalize(false) -> IPC count gate
        eligible now or last IPC exits -> append victim -> terminateWorker
            -> inspect queue head -> mark finalized -> actionFinalize
            -> IOService::finalize -> eligible provider -> append stop pair
            -> drain stop pair -> FairPlay stop -> close if open -> detach
```

All addresses are preferred and unslid. The audit verifies the collection digest and the kernel and kext UUIDs, then compares those identities with the running host.

## Queue producer and worker entry

| Transition | Installed sites | Recovered contract |
| --- | --- | --- |
| Mark phase three for a completed phase-two entry | `0xfffffe000c5200e4` through `0xfffffe000c520140` | On successful arbitration lock, sets `0x00800000` in the 32-bit state word at service +76 B, calls vtable +`0x6d0` for `getClient`, and saves whether the result is null before unlocking. |
| Request leaf finalization | `0xfffffe000c520228`–`0xfffffe000c5202fc` | Runs the termination action and, when requested, the did-stop action. The saved null-client result branches to the scheduling call with X0 = victim, W1 = 0. The prior locking audit establishes the IPC-count gate and last-exit reschedule. |
| Publish the victim | `0xfffffe000c51f708`–`0xfffffe000c51f7c8` | Under the jobs lock, calls `OSArray::setObject(victim)` on the array at global slot `0xfffffe000cc21fb0`. Increments the work count at `0xfffffe000cc21ff8` and wakes the worker when the previous count was zero. The queue element is the service object. |
| Call the worker | `0xfffffe000c537f9c`, `0xfffffe000c51f290` | The background loop calls `terminateWorker` while the work count is nonzero. The separate synchronous scheduler path also calls it. The direct-branch census found these two sites in the kernel `__TEXT_EXEC,__text`. |
| Supply callback options | `0xfffffe000c51f864`, `0xfffffe000c51f9dc`, `0xfffffe000c520994`, `0xfffffe000c520a00` | The worker preserves its own input, sets low bit `0x01` (`kIOServiceRequired`) in W22, and passes the resulting options to the finalization callback. The decoded queue insertion stores the victim without a per-entry option field. |

The background loop rechecks the work count at `0xfffffe000c537fa0` and waits on the same counter address at `0xfffffe000c537fd0`–`0xfffffe000c537fd8`. The worker subtracts its work snapshot at `0xfffffe000c51fa00`–`0xfffffe000c51fa04`. The published source names the background thread `IOServiceTerminateThread` and shows the distinct synchronous ownership path. [Pinned XNU thread creation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L698-L710) [Worker ownership and suspension](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L2828-L2898) [Finalize scheduling and phase-three admission](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L3293-L3338)

## Queue consumer and authenticated call

| Transition | Installed sites | Recovered contract |
| --- | --- | --- |
| Read head, then release queue lock | `0xfffffe000c520844`–`0xfffffe000c520898` | Calls `OSArray::getObject(0)` on the same array. A nonnull result goes into X25. Releases the jobs lock whose pointer slot is `0xfffffe000cc21f18`. |
| Claim finalization | `0xfffffe000c5208d0`–`0xfffffe000c52090c` | Takes victim arbitration. On success, tests `0x00010000` in the state word at +76 B. If clear, sets it before releasing arbitration and issuing the action. An already-finalized victim and a failed arbitration acquisition skip the action on this dequeue. |
| Select action context | `0xfffffe000c520930`–`0xfffffe000c520a10` | Calls inherited `getWorkLoop` through victim vtable +`0x6b8`. With a work loop, retains it and calls vtable +`0x1c0` with signed `actionFinalize` in X1, victim in X2, options in X3, and X4–X6 zero. Without one, calls `0xfffffe000c521da4` directly with victim in X0, options in X1, and X2–X4 zero. |
| Run the action | `0xfffffe000c569030`, `0xfffffe000c56904c`, `0xfffffe000c569078` | Base `IOWorkLoop::runAction` closes the gate, calls the same action with the supplied arguments, then opens the gate. The calling thread executes the callback on this route. |
| Call inherited finalizer | `0xfffffe000c521e58`–`0xfffffe000c521e90` | The action preserves the victim and options and tail-branches through vtable +`0x638`. The FairPlay client slot at `0xfffffe0008481940` resolves to `IOService::finalize` at `0xfffffe000c525d34`. |
| Retain for the worker pass and remove | `0xfffffe000c520a1c`–`0xfffffe000c520ab8` | Reacquires the jobs lock, calls `OSSet::setObject(victim)` on the temporary free list, removes finalization index zero, and repeats if the next head exists. The result of the action does not select the queue-removal path. |

The finalized bit records that the worker claimed the callback. The store precedes the callback and the queue removal. The selected queue and action calls use kernel object references. They add no Mach port descriptor or Mach message emission site to the close transaction. [Pinned XNU action](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L3128-L3142) [Pinned XNU work-loop dispatch](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L2513-L2528) [Mach close and right retirement](live_fairplay_connection_retirement_report.md)

## Finalizer to provider stop

| Interface | Installed sites | Recovered contract |
| --- | --- | --- |
| Enumerate providers | `0xfffffe000c525d94`, `0xfffffe000c525dc8`, `0xfffffe000c525e2c` | Calls inherited `getProviderIterator`, takes provider objects from the iterator, and tests the victim's phase-three flag at `0xfffffe000c525e38`–`0xfffffe000c525e3c`. |
| Phase-three provider handoff | `0xfffffe000c525f84`–`0xfffffe000c525fc4` | Takes provider arbitration. If held and the provider has no phase-three flag, calls the stop scheduler at `0xfffffe000c526018` with victim in X0 and provider in X1. Unlocks arbitration afterward. |
| Publish stop pair | `0xfffffe000c526144`, `0xfffffe000c526174`, `0xfffffe000c526184` | Under the jobs lock, appends client and provider to the arrays at `0xfffffe000cc21fa0` and `0xfffffe000cc21fa8`. Increments the same work count. The worker uses matching indices to recover the two objects. |
| Phase-three stop eligibility | `0xfffffe000c520454`–`0xfffffe000c5204f0` | For an attached stop pair with inactive client and successful client arbitration, the finalized bit determines whether to defer or reach `actionStop`. The dispatch reaches the FairPlay `stop` binding mapped in the provider report. |
| Compatibility branch | `0xfffffe000c525ef4`–`0xfffffe000c525f54`, `0xfffffe000c525e0c` | When the victim's phase-three bit is clear, the inherited finalizer directly calls `stop`, tests and conditionally closes the provider's open relationship, and calls `detach` for the provider. The FairPlay client `stop` slot selects the same kext override as the worker action. |

This establishes the static ordering from the close-associated phase-three path to the provider context handoff. The finalizer returns true at `0xfffffe000c525ff4`; final reclamation depends on remaining references. [Pinned XNU stop pair selection](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L3340-L3394) [Pinned XNU finalizer](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L3419-L3462)

## Assumptions and verification

| Premise | Dependent conclusion | Falsification probe |
| --- | --- | --- |
| The phased termination advances for the selected FairPlay client and reaches a null-client scheduling check or an equivalent leaf handoff. | The installed phase-three producer can request finalization of that client. | Correlate the arbitration result, attached-child state and scheduling call for the same registry entry. |
| That request is admitted immediately or requeued by the last IPC exit. | The matching victim enters the worker's finalization array. | Correlate the count and pending flag with the queue append for the same object. |
| The victim is the pinned FairPlay class and arbitration succeeds before its finalized bit is set. | The action dispatches inherited `IOService::finalize`. | Check the live class, arbitration result and state word before the authenticated call. |
| The provider is the selected FairPlay service and passes the phase-three provider predicate. | The finalizer can publish the traced stop pair. | Observe the provider class, arbitration result, state word and matched pair before stop. |

High impact for ordering connection retirement, provider-context cleanup and object lifetime. Medium impact for attributing finalizer execution to the background or synchronous worker and to the work-loop gate. The matched native enqueue, callback, provider pair and final release remain unknown.

The read-only audit decodes 160 installed instruction sites, verifies 19 authenticated vtable entries and scans 2,545,292 aligned instruction words (10,181,168 B) for direct `B`/`BL` encodings targeting the worker. The census covers this kernel text section and leaves indirect callers and other sections outside its scope. For B collection bytes, F fixups and I sampled instructions, verification uses O(B + F + I) time and space. [Audit script](triage_evidence/audit_live_iokit_finalize_worker.py) [Compressed receipt](triage_evidence/live_iokit_finalize_worker_audit.json.zst)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_iokit_finalize_worker.py "$CURRENT_COLLECTION" --observe
```
