# fairplayd network registry-parent Mach transport

The pinned `fairplayd` has one direct call to its `IORegistryEntryGetParentEntry` import stub. The input is an interface object obtained through BSD-name matching. The returned parent becomes the destination object for the `IOMACAddress` property lookup. Installed IOKit implements parent lookup as `2814/2914` to obtain a parent iterator, then `2802/2902` to fetch its first entry. The sole archived `2802/2902` pair instead belongs to the earlier FairPlayIOKit class match. Native invocation of the network parent path remains unknown. [Daemon network identity](daemon_network_identity_report.md) [Archived FairPlayIOKit discovery](zut_trace_report.md)

```text
network interface send name
    |    2814 / 2914
    v
parent iterator send name -- 2802 / 2902 --> parent entry send name
    |                                             |
    +-- release local send reference              +-- lookup IOMACAddress
```

## Daemon call and right custody

The direct branch census covers 3,712,490 aligned words in the pinned arm64e image’s original 14,849,960 B text section. `0x100004338` is its only immediate `B` or `BL` to the authenticated parent-entry stub at `0x100e2a960`. That stub resolves through `0x1010b1bc0` to the named IOKit import. The helper passes the interface object’s 32-bit Mach name in W0, the literal plane `IOService` in X1 and a 4 B output cell at SP+`0x0c` in X2. A zero status leads to `0x100004358`, which uses the returned name for `IOMACAddress`. Two other direct calls to the property stub query `IOBuiltin` on interface entries. Computed calls and other slices remain outside the census [A1]. [Pinned daemon and import evidence](triage_evidence/live_iokit_registry_parent_audit.json.zst) [Network cache and returned name releases](daemon_network_identity_report.md)

## Installed request and reply path

The verified kernel and FairPlayIOKit fileset matches build `26C5035r`. The IOKit framework UUID is `82be1de5-91c4-3152-b63b-81db4c5e7992` in dyld cache `8b1e17c6-72d6-3017-91a4-916022e3612e`. The records below describe the installed images [A2]. [Apple parent-entry wrapper](https://github.com/apple-oss-distributions/IOKitUser/blob/main/IOKitLib.c#L2541-L2560) [XNU parent iterator](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L3984-L3997)

| Transition | Installed location | Port and result |
| --- | --- | --- |
| Create parent iterator, `2814` | Framework `0x184ebee14` calls the stub at `0x184ebee70`. Send is at `0x184ebef44`. Kernel stub is `0xfffffe000be857f8`. | Sends to the input registry-entry name using `COPY_SEND`, with a local MIG reply name using `MAKE_SEND_ONCE`. The simple user request has 40 B before the string. The bounded copy counts `IOService` and its NUL as 10 B, aligned to 12 B, for a total of 52 B user and 60 B internal. |
| Build and return iterator, `2914` | Kernel imports a kind-`0x28` object at `0xfffffe000be858b8` and resolves the plane before the virtual call at `0xfffffe000c5bd7a0`. The base slot at `0xfffffe0007f51f90` resolves to `IORegistryEntry::getParentIterator`. | The implementation wraps the result in `IOUserIterator` when available. The success stub exports the iterator with kind `0x28` at `0xfffffe000be8591c`. The framework copies its descriptor name at `0x184ebf018`. |
| Read first entry, `2802` | Framework `0x184ebee28` calls the iterator stub at `0x184ebd530`. Send is at `0x184ebd59c`. Kernel stub is `0xfffffe000be8651c`. | Sends a 24 B user or 32 B internal simple request to the returned iterator. It obtains a MIG reply name for this exchange through the same thread-local getter. |
| Return the parent, `2902` | The kernel uses the `IOUserIterator` slot +`0x170` at `0xfffffe000c5b92c0`. Export is at `0xfffffe000be865dc`. Framework descriptor copy is at `0x184ebd670`. | A returned object is exported as kind `0x28`. The wrapper publishes its task-local name at `0x184ebee38`, then releases its local iterator send reference with `mach_port_deallocate` at `0x184ebee48`. |

The two generated stubs use 52 B internal or 40 B user replies for success, with one port descriptor. The client decoders read the returned port name at user +`0x1c`. Routine errors use the generic 44 B internal or 36 B user status form. The generic kernel server takes the reply right from the request and adds 100 to its ID. Both reply paths use shared queue submission at `0xfffffe000bd0f208`. The wrapper propagates the first RPC’s failure and skips iterator consumption on that branch. After a successful first RPC, the wrapper reports `kIOReturnNoDevice` (`0xe00002c0`) if the next call yields no usable parent. [XNU bounded string copy](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/mach/mig_strncpy.c#L53-L110) [XNU iterator-next result](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L2447-L2476) [Generic status header and queue send](live_arcade_registration_reply_report.md)

## Archived observation and scope

The 44 parsed Mach headers contain zero `2814` or `2914` and one `2802/2902` pair [A3]. The preceding `2881` request asks for `com_apple_driver_FairPlayIOKit`. Reply `2981` supplies guest iterator `0x1803`, which the next request uses as its destination. Reply `2902` supplies guest service `0x1903` on reply name `0x507`. These guest names identify the class-discovery exchange in this recording. The network parent helper operates on registry object rights, which use kind `0x28`. The separately audited connection-to-provider call takes a kind-`0x27` connection. [Class match and open trace](zut_trace_report.md) [Connection-to-provider query](live_iokit_connection_service_report.md)

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The thin daemon and authenticated import slot are the pinned inputs. | One direct caller and its following property boundary. | Rehash the daemon and verify the stub join. Extend the census to other slices or computed targets if their reaching states are recovered. |
| A2. The same-build framework and kernel are used for the static transport correlation. | Message sizes, import/export kinds and original call locations. | Check cache, kernel and kext identities and re-decode the instructions and pointer records. On a passive capture, match the actual provider class and reply. |
| A3. The archive contains all headers printed during the recorded run. | The sole iterator-next pair is the class-match continuation. | Re-decode all headers and compare the exact iterator descriptor with the following request destination. |

High impact attaches to attributing the archived iterator correctly and to bounding the direct daemon parent lookup to the network identity path. Medium impact attaches to identifying the two object-right transfers beneath one public call. The audit checks 29 framework and 15 kernel anchors, seven direct kernel calls, four kernel functions covering 383 instructions, five framework veneers and two class vtable bindings. The census and checks take O(B + T + I) time and space for image bytes B, trace bytes T and retained instructions I. Native network parent delivery and any network-identity linkage to a FairPlayIOKit method transaction remain unknown. [Verifier](triage_evidence/audit_live_iokit_registry_parent.py) [Compressed evidence](triage_evidence/live_iokit_registry_parent_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_iokit_registry_parent.py \
  "$BOOT_FILESET" "$PINNED_DAEMON" "$ANNOTATED_TRACE"
```
