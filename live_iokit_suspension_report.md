# Application suspension notifications and FairPlayIOKit

On macOS build `26C5035r`, IOKit can deliver `kIOMessageTaskAppSuspendedChange` to registered user clients of a task. The installed FairPlayIOKit user client and provider both inherit `IOService::message`, which returns `kIOReturnUnsupported`. The suspension-interest property was absent from the provider and from the resident `fairplayd` and `adid` user clients in two consecutive registry snapshots. [Pinned XNU notification](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L1772-L1818) [Base message implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L8457-L8467)

```text
IOUserClient open -> presence of IOUserClientMessageAppSuspended
  -> owner registration -> task interest flag
  -> successful PID suspend or resume -> IOKit owner scan
  -> retain opted-in clients in a set -> release owner lock
  -> client->message(0xe0000800, NULL, NULL)
       FairPlay client slot -> IOService::message -> 0xe00002c7
```

All addresses are preferred and unslid. The audit checks the boot-collection digest, embedded kernel and kext UUIDs, and the corresponding running host identities.

## Property and task transitions

| Transition | Installed sites | Contract |
| --- | --- | --- |
| Initialize client interest | `0xfffffe000c5bdf38`–`0xfffffe000c5bdf8c` | First-open handling marks bit 5 of client +155 B and looks up the key at `0xfffffe00070e12de` through vtable +`0x2d8`. Bit 0 of the same byte stores whether the result is nonnull. Presence is sufficient even if the returned property is a Boolean false object. |
| Propagate through registration | `0xfffffe000c5b7c30`–`0xfffffe000c5b7c4c` | After linking the owner, tests the client interest bit. On interest, sets bit 7 of the 32-bit word at task +1736 B and writes one at task +23 B. |
| Recompute on connection-reference cleanup | `0xfffffe000c5b5d84`–`0xfffffe000c5b5dc0` | After an owner is removed through the reference-cleanup helper, scans remaining task owners for the same client bit. Sets or clears bit 7 and stores the result at task +23 B. |
| Suspend and notify | `0xfffffe000bd8ed40`, `0xfffffe000bd8ee78`, `0xfffffe000bd8ee8c`, `0xfffffe000bd8ef40` | The suspend path sets the task's suspend byte at +1090 B and clears it on hold failure. On the successful path, releases the task lock, tests the interest bit at task +1736 B, and calls the IOKit hook when set. |
| Resume and notify | `0xfffffe000bd87db0`, `0xfffffe000bd8efbc`–`0xfffffe000bd8efec` | Release of the PID-suspend hold clears the suspend byte on its selected branch. After task unlock, the successful resume path checks the same interest bit and calls the same hook. |

The exported `task_is_app_suspended` reads bit 0 of the byte at task +1090 B at `0xfffffe000bdc6dfc`–`0xfffffe000bdc6e00`. The notification itself carries no suspend/resume Boolean. This application-suspension path uses the owning task's state. [Pinned XNU open property lookup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L4471-L4485) [Task transitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/task.c#L4519-L4609) [Message definition](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/IOKit/IOMessage.h#L74-L79) [Owner registration](live_iokit_open_owner_report.md) [Reference cleanup](live_iokit_reference_cleanup_report.md)

## Recipient and delivery ABI

The hook at `0xfffffe000c5b7cb4` acquires the owners lock at pointer slot `0xfffffe000cbd7898`. It walks task +1616 B, loads the user client from each record +24 B, and filters on client +155 B bit 0 at `0xfffffe000c5b7d50`–`0xfffffe000c5b7d58`. The first eligible entry triggers creation of an `OSSet` with initial capacity four. The hook inserts eligible clients into the set and releases the owners lock before iterating. An empty owner list or failure to create the snapshot skips delivery. [Pinned XNU owner snapshot](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L1772-L1818)

| Interface | Installed address | Data and flow |
| --- | --- | --- |
| Iterate retained clients | `0xfffffe000c5b7df8` | Calls `OSCollection::iterateObjects` with the set in X0 and block at `0xfffffe0007f5d960` in X1. The block invoke pointer resolves to `0xfffffe000c5b7ee0`. |
| Dispatch the message | `0xfffffe000c5b7f0c`–`0xfffffe000c5b7f24` | Passes recipient X0, type W1 = `0xe0000800`, null provider X2, and null argument X3. Calls vtable +`0x760` and returns false to the set iterator after the virtual call. |
| FairPlay user-client method | Slot `0xfffffe0008481a68` | Resolves to `IOService::message` at `0xfffffe000c51cc10`. The original method returns `0xe00002c7`. |
| FairPlay provider method | Slot `0xfffffe0008482ad0` | Resolves to the same base method. The suspension hook selects user clients from owner records. |

On the verified FairPlay dispatch, the action stays inside the kernel and yields no Mach destination, message or port descriptor. This describes the owner callback and its class binding. [Pinned XNU collection iteration](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libkern/c++/OSCollection.cpp#L106-L142)

## Registry observation

| Instance | Registry ID | Creator PID | Interest property |
| --- | --- | --- | --- |
| FairPlayIOKit provider | `0x1000002fb` | n/a | Absent |
| FairPlayIOKit user client for `adid` | `0x10000130b` | 910 | Absent |
| FairPlayIOKit user client for `fairplayd` | `0x100001702` | 3903 | Absent |

The registry sample establishes property presence at observation. The initial lookup result, cached client bit, task aggregate bit and notification delivery are unobserved. The auditor made read-only identity and registry queries.

## Assumptions and verification

| Premise | Dependent conclusion | Falsification probe |
| --- | --- | --- |
| The audited fileset corresponds to the running kernel and loaded driver. | The addresses and authenticated bindings identify the installed methods. | Verify the fileset digest, both embedded UUIDs, and both running UUIDs. |
| The observed registry children are the sampled daemon clients. | Creator labels and property presence apply to the listed entries. | Compare class, service parent and creator across repeated registry snapshots. |
| Task transition succeeds with an interested registered client and the snapshot allocation succeeds. | The callback can be invoked for that client outside the owners lock. | Correlate task state, owner membership, client interest and callback on the same object in a passive native trace. |

High impact for determining whether this application-suspension event reaches FairPlay-specific logic through the installed class. Medium impact for distinguishing a task-state subscription from a Mach notification destination. Native open-time subscription state and callback execution remain unknown.

Verification covers 91 instruction sites, four authenticated vtable bindings, the authenticated block invoke pointer, the property literal, and two consistent registry snapshots per live audit run. Verification costs O(B + F + I) time and space for B collection bytes, F fixups and I checked sites, excluding host queries. The hook walks N owners, performs one set insertion per eligible owner and holds at most N references in the temporary snapshot. [Audit script](triage_evidence/audit_live_iokit_suspension.py) [Compressed receipt](triage_evidence/live_iokit_suspension_audit.json.zst)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_iokit_suspension.py "$CURRENT_COLLECTION" --observe
```
