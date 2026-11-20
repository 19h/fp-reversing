# FairPlayIOKit synchronous method locking and deferred finalization

On macOS build `26C5035r`, the kernel's synchronous IOKit method wrapper can take the user client's read/write lock in shared or exclusive mode. Explicit close uses the same lock exclusively. Both paths increment a separate active-IPC count and use one exit routine to decrement it. If a finalization request was deferred and the client is inactive, the last active IPC schedules finalization before releasing its per-client lock. This is installed-code evidence. Two live registry entries corroborate the default-locking property and leave the native mode of individual calls unknown. [Connection rights and close](live_fairplay_connection_report.md) [Provider startup and stop](live_fairplay_provider_stop_report.md)

## Policy initialized during open

The type-zero open starts the FairPlay client before kernel code initializes the locking policy. The open continuation tests and sets the first-open bit (bit 5 of the byte at client +155 B) at `0xfffffe000c5bdf40` and `0xfffffe000c5bdf48`. It records whether the object derives from `IOUserClient2022` in bit 1 at `0xfffffe000c5be028`. The original superclass rebases identify the chain `FairPlayIOKitUserClient -> IOUserClient -> IOService`. The inherited reservation routine passes client +176 B to the lock initializer at `0xfffffe000c5b7af0`. [Open attach and owner registration](live_iokit_open_owner_report.md) [Pinned XNU reservation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L1678-L1693)

For each property that is present, open compares the object returned by the inherited `IORegistryEntry::getProperty` slot (+0x2d8) with `kOSBooleanFalse`. It sets the corresponding bit if the comparison differs. The installed code gives each property its own lookup and store. [Pinned XNU policy initialization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L4470-L4522)

| Registry property | Bit at client +155 B | Value lookup call | Store |
| --- | ---: | --- | --- |
| `IOUserClientDefaultLocking` | 2 | `0xfffffe000c5be068` | `0xfffffe000c5be090` |
| `IOUserClientDefaultLockingSingleThreadExternalMethod` | 3 | `0xfffffe000c5be19c` | `0xfffffe000c5be1c0` |
| `IOUserClientDefaultLockingSetProperties` | 4 | `0xfffffe000c5be0f8` | `0xfffffe000c5be11c` |

The legacy fallback comes after the missing-properties check and the conditional IOSurface dependency check. At `0xfffffe000c5be29c` it sets bit 2 and clears bits 3 and 4. It then publishes `IOUserClientDefaultLocking = true` through the property setter at `0xfffffe000c5be2d0`. That published value is compatible with the fallback as well as with an explicitly supplied true property. [Pinned XNU fallback](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L4509-L4519)

## Method, close, and exit

Request 2865 reaches the installed MIG stub at `0xfffffe000be8152c`. The stub imports the type-`0x27` connection at `0xfffffe000be81644` and calls the implementation at `0xfffffe000be816b4`. The implementation invokes the synchronous wrapper at `0xfffffe000c5c0220` with the imported client, selector and arguments. The wrapper at `0xfffffe000c5bfe6c` decodes bits 2 and 3 of the byte at client +155 B. Bit 4 does not participate in the lock decision. [Method transport and reply emission](live_iokit_mach_transport_report.md) [Installed FairPlay selector map](live_kext_selector26_report.md)

| Bit 2 | Bit 3 | Mode | Installed side effect |
| ---: | ---: | ---: | --- |
| 0 | Either | 0 | Bypass acquisition at `0xfffffe000c5bfe9c`. |
| 1 | 0 | 1 | Call `IORWLockRead` at `0xfffffe000c5bfeb4` with client +176 B. |
| 1 | 1 | 2 | Call `IORWLockWrite` at `0xfffffe000c5bfed0` with client +176 B. |

All three paths atomically increment the 4 B IPC count at client +156 B at `0xfffffe000c5bfee0`. With bit 1 clear, the call at `0xfffffe000c5bff1c` uses vtable +0x880 and resolves to the inherited legacy `IOUserClient::externalMethod`. The wrapper passes zeros in X3, X4 and X5. The inherited external method reaches the FairPlay selector lookup through +0x970. After the virtual call, the wrapper saves the result, recomputes the mode from the same policy byte, calls the exit routine at `0xfffffe000c5bff5c`, and restores the method result at `0xfffffe000c5bff60`. For the selected normal return, the two mode computations agree when bits 2 and 3 retain their values across the callback. The wrapper applies the same policy to the selected legacy structure-admission error and normal return. [Pinned XNU method wrapper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L6582-L6596) [Error reply and result channels](iokit_sync_error_reply_report.md)

Explicit close request 2816 imports the same connection type before calling the implementation at `0xfffffe000be8555c`. For a non-shared instance the first-close transition is guarded by a byte compare and swap at `0xfffffe000c5be85c` on client +153 B. The accepted close branch acquires the same lock exclusively at `0xfffffe000c5be868`, increments the same IPC count at `0xfffffe000c5be874`, and calls FairPlay `clientClose` through +0x920 at `0xfffffe000c5be894`. It supplies mode 2 to the common exit routine at `0xfffffe000c5be8a0`. Shared method acquisitions can overlap at this wrapper and serialize with this exclusive close on the same object. Provider serialization remains a separate layer. [Pinned XNU close](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L4611-L4635) [Close and reply 2916](live_fairplay_connection_report.md)

## Deferred finalization

`scheduleFinalize(false)` calls the installed `finalizeUserReferences` implementation at `0xfffffe000c51f6d0`. For the selected IOUserClient branch, it takes the global port-object lock (pointer slot `0xfffffe000cc22240`) and reads the IPC count at `0xfffffe000c5b66cc`. It stores `count != 0` into the 1 B pending flag at client +154 B at `0xfffffe000c5b66dc`. A zero count allows the queue path immediately. A nonzero count defers the queue path until exit. [Pinned XNU reference check](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L673-L687)

| Exit condition or operation | Installed site | Effect |
| --- | --- | --- |
| Atomic decrement | `0xfffffe000c5b64f0` | Decrement the count and retain the old value. Only old count 1 reaches the inactivity check. |
| Test inactivity | `0xfffffe000c5b6520` and `0xfffffe000c5b6524` | Authenticate vtable +0x5d8, call `IOService::getState` and test bit 0 of the returned 4 B state. |
| Consume deferral | `0xfffffe000c5b6554` through `0xfffffe000c5b655c` on the selected lock path | Under the port-object lock, test the pending flag and clear it if set. |
| Schedule finalization | `0xfffffe000c5b658c` | After releasing the port-object lock, call `scheduleFinalize(true)`. This skips the deferral check. The queue path appends at `0xfffffe000c51f730`, increments the work count at `0xfffffe000c51f740`, and wakes the worker on the zero-to-one work transition at `0xfffffe000c51f7c8`. |
| Finish method or close exit | `0xfffffe000c5b65e0` through `0xfffffe000c5b6600` | Modes 1 and 2 release the lock at client +176 B via `_lck_rw_done`. Mode 0 returns directly. |

This ordering places the requeue request before the per-client unlock on the selected last-exit path. The worker consumes this array, marks the service finalized, and calls the selected finalizer through its own action. No additional Mach right or message emission occurs at the decoded lock or deferred-queue transition. Request and reply emission sites are in the transport and connection reports. [Pinned XNU IPC entry and exit](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L596-L647) [Pinned XNU finalization queue](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L2927-L2948) [Finalization worker](live_iokit_finalize_worker_report.md) [Mach transport](live_iokit_mach_transport_report.md)

## Native registry scope and verification

The collector matched macOS build `26C5035r`, the running kernel UUID `90195379-954d-3ca3-baac-327341f14211`, and loaded FairPlayIOKit UUID `316464f8-eade-30ca-938e-2f430b1ed5bc` against the boot fileset. At 2026-11-20 03:29:39 UTC, both read-only registry samples gave the following children of service `0x1000002fb`. The set-properties locking, single-thread external-method locking, and shared-instance keys were absent from both entries in these samples. [Prior creator and executable identity](live_iokit_open_owner_report.md) [Compressed receipt](triage_evidence/live_iokit_method_locking_audit.json.zst)

| Registry creator | PID | Client entry | Default locking property |
| --- | ---: | --- | --- |
| `adid` | 910 | `0x10000130b` | `true` |
| `fairplayd` | 3903 | `0x100001702` | `true` |

Both snapshots are consistent with the legacy shared-lock path. The initialization branch, dispatch-time flag bytes, per-call lock mode, and any native deferred finalization remain unknown. The static audit verifies 129 selected instruction words plus the existing MIG and legacy-dispatch checks, three locking-property literals, two superclass rebases, and the lock symbols and slot bindings. Exhaustive arithmetic reconstruction of all 256 flag-byte values yields 128 no-lock, 64 shared and 64 exclusive outcomes. The bounded per-call bookkeeping is O(1) in time and auxiliary space, excluding lock wait, callback work and the asynchronous finalizer. [Reproducible audit](triage_evidence/audit_live_iokit_method_locking.py)

| Premise | Dependent conclusion | Falsification probe |
| --- | --- | --- |
| The verified original fileset models the installed code and fixups. | All installed call-site, field and vtable mappings. | Check the fileset SHA-256 and both running UUIDs, and compare the original chained pointer records. |
| Both method and close operate on the same admitted client object, and the mode bits persist across the selected method callback. | Shared/exclusive synchronization on that client and a matched entry and exit mode. | Compare imported object identity and both policy reads on an observed native call. |
| The live registry properties describe the two reported clients during capture. | The sampled policy metadata and process labels. | Re-read both client IDs and selected properties in the same interval. A native dispatch trace would discriminate the actual modes. |
| A finalization request encounters active IPC and the last exit sees inactive state with the pending flag still set. | Deferred queue insertion before per-client unlock on that exit. | Correlate the last decrement, pending-flag clear and queue append on the same object in a native trace. |

High impact for attributing method and close ordering to the per-client lock and for identifying the finalization handoff. Medium impact for interpreting registry policy without an observed transaction. The pinned XNU source corroborates semantics and the installed image supplies addresses and layout. No native method or close was issued by the auditor.
