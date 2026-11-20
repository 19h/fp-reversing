# Kernel IOKit service matching and iterator publication

On macOS build `26C5035r`, the IOKit server handles binary matching request 2881 by decoding a dictionary, querying the service registry, and wrapping the result in an `IOUserIterator`. The kernel exports that iterator in reply 2981. Request 2802 imports the iterator and returns the selected service in reply 2902. A verifier process using ordinary IOKit discovery obtained one FairPlayIOKit service with registry entry ID `0x1000002fb`. Independent registry enumeration returned the same entry ID and identified the publisher as the loaded FairPlayIOKit bundle. [Framework discovery and archived request bytes](live_iokit_discovery_report.md)

## From matching bytes to the iterator

| Stage | Installed kernel site | Data or control transfer |
| --- | --- | --- |
| MIG selection | Record `0xfffffe0007e78638`, authenticated slot `0xfffffe0007e78640` | Request 2881 selects stub `0xfffffe000be7fe24`. |
| Stub to implementation | `0xfffffe000be7feb0` through `0xfffffe000be7fec0` | The routine at `0xfffffe000c5b9628` receives the destination port object, inline byte pointer, u32 byte count and address of an iterator output word. That word starts at zero. |
| Main-port admission and decoding | `0xfffffe000c5b9650`, `0xfffffe000c5b9674` | Compare the destination with the kernel main-port cell. Call the sized `OSUnserializeXML` overload, then check that its returned object belongs to the `OSDictionary` metaclass hierarchy. |
| Registry query | `0xfffffe000c5b96f8`, `0xfffffe000c5b975c`, `0xfffffe000c5b9764` | The implementation sets a dictionary property through an authenticated slot, conditionally sets a compatibility property using task state, then calls `IOService::getMatchingServices(OSDictionary *)`. |
| Iterator wrapping | `0xfffffe000c5b97f0`, `0xfffffe000c5b9824`, `0xfffffe000c5b982c`, `0xfffffe000c5b9874` | Install the original `IOUserIterator` vtable, call its initializer and store the underlying iterator at wrapper +16 B. Publish the wrapper through the saved output pointer. The decoded dictionary's reference is released after use. |

The archived request has 64 B of dictionary data beginning at packed offset +36 B. The kernel stub loads the size from body +8 B and passes body +12 B as the data pointer. The same 64 B payload corresponds to a packed request of `36 B + 64 B = 100 B` and an expanded request of `44 B + 64 B = 108 B`. The first four dictionary bytes are `d3 00 00 00`, matching the binary signature literal at `0xfffffe000704562c`. The installed sized overload takes the binary-decoding branch to `0xfffffe000c4d8830` at `0xfffffe000c4d77e0` when that signature matches. [Archived discovery record](live_iokit_discovery_report.md)

The pinned public source identifies the ordinary dictionary augmentation as setting `gIOServiceNotificationUserKey` to true. It also contains the conditional setter for `gIOCompatibilityMatchKey`. Its compatibility predicate returns false in that source revision. The installed implementation tests the caller’s translated x86-64 state and the compatibility metaclass instance count before its second setter. Its outcome for the archived caller is unknown. [Installed registry compatibility](live_iokit_matching_compatibility_report.md) [Pinned XNU matching implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L2577-L2652) [Pinned dictionary augmentation and wrapper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L395-L445)

## Reply publication and reuse

| Transition | Installed kernel site | Port and ownership effect |
| --- | --- | --- |
| Iterator object to reply 2981 | Export call `0xfffffe000be7feec`, object release `0xfffffe000be7ff10`, descriptor store `0xfffffe000be7ff30` | Export the iterator through the IOKit object send-right helper at `0xfffffe000c5b07cc` with type `0x28`. Release the temporary object reference after export. Sign the port pointer for expanded reply +36 B using discriminator `0x01ab`. |
| Iterator name to kernel object in 2802 | Record slot `0xfffffe0007e77c60`, import call `0xfffffe000be86564` | Request 2802 enters stub `0xfffffe000be8651c`, imports the type-`0x28` destination through `0xfffffe000be7e18c`, and holds its object reference through the call. This is also the type of the service port consumed by open 2862. |
| Iterator object to service object | `0xfffffe000c5b92c0`, `0xfffffe000c5af550`, `0xfffffe000c5b9318` | Authenticate and call `IOUserIterator` vtable +0x170. The binding goes to the locking implementation of `copyNextObject`, which takes the wrapper lock, loads the underlying iterator at +16 B, calls its next-object slot, and retains a nonnull result. Publish that retained object to the stub output. |
| Service object to reply 2902 | Export call `0xfffffe000be865dc`, object release `0xfffffe000be86600`, descriptor store `0xfffffe000be86620` | Use the same type-`0x28` exporter and signed descriptor layout for the service object. Release the temporary result reference after export. |
| Descriptor to caller name | Receive copyout `0xfffffe000bd0d720`, framework stores `0x184ebd4b0` and `0x184ebd670` | The receive path resolves the in-kernel port into a name in the receiver's IPC space. The matching stub copies out the iterator name and the iteration stub copies out the service name. |

Each success envelope has one descriptor, with disposition 17 and descriptor type zero. The kernel stubs set the complex bit and length 52 B in expanded layout. The user representation is 40 B after the 8 B header and 4 B descriptor differences. The ordinary port registry compares both object and type before reuse. Type `0x28` denotes an IOKit object port for both iterator and service. The kind of underlying object is determined after import. The user-client connection returned by a later successful 2862 open uses type `0x27`. [Pinned iterator implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L2447-L2476) [Pinned object send exporter](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L656-L678) [Current connection publication](live_fairplay_connection_report.md)

A successful matching routine can publish a null iterator if the underlying registry query or wrapper initialization yields no wrapper. The stub then follows the complex-reply path with a null descriptor name. The captured reply 2981 instead contains a nonnull iterator. The kernel matching search cost depends on registry state. The ABI wrapper performs fixed-size port bookkeeping after the variable-length decode and registry query.

## Current registry observation

The verifier ran `IOMainPort`, `IOServiceMatching`, `IOServiceGetMatchingServices`, and `IOIteratorNext`. It queried the returned object's registry ID and class through public APIs and checked each held right in its own namespace. It released the service, iterator and main user references. Its observation ends at discovery.

| Role | Verifier name | RAX guest name | Verifier type bits and send user references |
| --- | --- | --- | --- |
| Main | `0x1c03` | `0x1703` | `0x10000`, 1 |
| Iterator | `0xd03` | `0x1803` | `0x10000`, 1 |
| FairPlayIOKit service | `0xe03` | `0x1903` | `0x10000`, 1 |

The names are transient values in two distinct namespaces. In the current registry row for `0x1000002fb`, `IOClass` is `com_apple_driver_FairPlayIOKit`, `CFBundleIdentifier` is `com.apple.driver.FairPlayIOKit`, `IOProviderClass` is `IOResources`, and `IOUserClientClass` is `com_apple_driver_FairPlayIOKitUserClient`. The request dictionary's `IOProviderClass = com_apple_driver_FairPlayIOKit` selects the class of the target service. The matched service's own registry property declares the provider class for that service's personality. The binding between the current service and a native daemon open, and the object identity behind archived guest `0x1903`, remain unknown. [Recorded observation](triage_evidence/live_iokit_matching_audit.json.zst)

## Assumption register and evidence

| Premise and dependent result | Falsification probe |
| --- | --- |
| The examined collection is the running kernel's build. This qualifies addresses and chained pointers. | Check the collection digest, `kern.uuid`, loaded kext UUID and cache UUID. |
| The archived wire request takes the identified main-port and dictionary path on a kernel with the same contract. This qualifies the comparison. | Compare the archival kernel image and use the same capture to join both right-bearing replies and the service registry ID. |
| The current verifier's service output and the registry snapshot refer to the same entry. This qualifies the native service identity. | Compare the 64-bit registry entry ID and class returned by both queries in the same boot. |
| The identified code path receives and exports ordinary held objects. This qualifies the ownership mapping. | Check the original constructor vtable, the locking next-object binding, the per-task rights and the copyout descriptor. |

High impact for joining discovery to the FairPlayIOKit registry entry and for distinguishing generic object rights from a connection right. Medium impact for explaining task-dependent matching and the wrapper's ownership. The audit checks 56 original instruction sites, six original symbols, five authenticated bindings and two literals. It rechecks the two archived request/reply pairs from the pinned trace. Current verifier calls and archived trap records supply distinct scopes of observation. [Auditor](triage_evidence/audit_live_iokit_matching.py) [Compressed receipt](triage_evidence/live_iokit_matching_audit.json.zst)

The open follow-up joins the service's client class to the inherited constructor, explains how the kernel places the creator label on its registry child, and locates owner registration before connection export. [Open attachment and owner registration](live_iokit_open_owner_report.md)
