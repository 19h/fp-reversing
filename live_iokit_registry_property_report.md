# fairplayd network registry-property Mach transport

The property lookup follow-up resolves direct, user-service and translated-process compatibility precedence before serialization. [Installed registry compatibility](live_iokit_matching_compatibility_report.md)

The network identity helper at `0x10000425c` issues three direct calls to `IORegistryEntryCreateCFProperty`. Installed IOKit can issue three different Mach RPCs for this API. The binary route selected by the on-disk flag values uses `2889/2989` and can copy serialized bytes directly into the framework’s 2,048 B stack buffer. The archive contains zero headers for any of the three routes. Native invocation, selected runtime route and linkage to a FairPlayIOKit method remain unknown. [Network helper](daemon_network_identity_report.md) [Registry parent](live_iokit_registry_parent_report.md) [Compressed evidence](triage_evidence/live_iokit_registry_property_audit.json.zst)

## Daemon call sites

The direct branch census covers 14,849,960 B of text in the pinned arm64e image [A1]. The three `BL` instructions use stub `0x100e2a950` and authenticated GOT slot `0x1010b1bb8`. An authenticated data binding to the same import at `0x1010a1630` leaves an additional indirect call path possible. All three direct calls pass the default allocator and options zero. [Verifier](triage_evidence/audit_live_iokit_registry_property.py)

| Daemon call | Key and destination send name | Result consumer |
| --- | --- | --- |
| `0x1000042bc` | `IOBuiltin`, interface entry in W19, filter enabled | On a non-null result, Boolean test at `0x1000042c8`, release at `0x1000042d4`. A false value advances the iterator. |
| `0x100004310` | `IOBuiltin`, interface entry in W19, filter disabled | On a non-null result, Boolean call at `0x10000431c` and release at `0x100004324`. The value has no effect on selection. |
| `0x100004358` | `IOMACAddress`, parent entry from SP+`0x0c` | On a non-null result, `CFDataGetBytes` at `0x100004370` with range `{0,6}`, then `CFRelease` at `0x100004378`. A null property skips the copy and leaves the successful parent status intact. |

## Request, transport and reply

Installed `IORegistryEntryCreateCFProperty` at `0x184ebd698` tail-branches to `IORegistryEntrySearchCFProperty` at `0x184ebd6ac` with a null plane and options zero. The framework converts the key to a C string. The binary RPCs receive an empty plane string. All three use the registry-entry name as the remote `COPY_SEND` destination and the thread-local MIG receive name as the local `MAKE_SEND_ONCE` reply endpoint. Request header bits are `0x1513`. They call the same `_mach_msg2_internal` veneer at `0x188088af0` [A2]. [Apple IOKit wrapper](https://github.com/apple-oss-distributions/IOKitUser/blob/main/IOKitLib.c#L2363-L2445)

| Request / reply | Framework selection / send instruction | Kernel MIG stub / success packing site | Successful property transport |
| --- | --- | --- | --- |
| `2805/2905` | Serialization bit 0 clear. Select `0x184ebd738`, send `0x184f5e424`. | `0xfffffe000be861dc` / `0xfffffe000be86310` | XML. One out-of-line descriptor and 32-bit byte count. 64 B kernel, 56 B user. |
| `2879/2979` | Serialization bit 0 set and `__os_xbs_chrooted == 1`. Select `0x184ebd778`, send `0x184ebda1c`. | `0xfffffe000be800a4` / `0xfffffe000be80260` | Binary. One out-of-line descriptor and 32-bit byte count. 64 B kernel, 56 B user. |
| `2889/2989` | Serialization bit 0 set and `__os_xbs_chrooted != 1`. Select `0x184ebd808`, send `0x184f62488`. | `0xfffffe000be7f184` / `0xfffffe000be7f348` | Binary. One out-of-line descriptor slot, 64-bit direct-buffer length and 32-bit out-of-line count. 72 B kernel, 64 B user. |

The framework reads the serialization byte at `0x1eb1ee3f8` and the kernel library’s `__os_xbs_chrooted` byte at `0x1eb0ede20`. Their respective file values are `1` and `0`. The in-process values during a call are unknown. In the kernel, all three MIG entries import a kind-`0x28` registry object. The property bodies validate the entry and check the property access policy before lookup. The common kernel reply builder adds 100 to the request ID at `0xfffffe000bd3c678` and uses the request’s send-once right. The queue submission is at `0xfffffe000bd0f208`. Routine errors use the shared status form, 44 B internally and 36 B in user space. [XML property routine](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L3538-L3577) [Binary property routines](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L3753-L3861) [Common reply builder and queue submission](live_arcade_registration_reply_report.md)

## Byte and object ownership

`2879` and `2889` reach the same binary implementation at `0xfffffe000c5bc984`. For `2879` the stub supplies zero for the buffer and its length pointer. For `2889` it passes the framework’s stack-buffer address and capacity. If the serialized extent is at most 2,048 B, the kernel updates the direct length, clears the out-of-line pointer and count, and copies bytes into the calling task at `0xfffffe000c5bcc2c`. For a larger extent it sets the direct length to zero and produces an out-of-line transfer at `0xfffffe000c5bcca4`. The kernel releases its serializer and property reference in both cases. [XNU serialization and copyout](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L3812-L3861)

```text
registry entry send name -> kernel property lookup -> serialized bytes
   -> direct user buffer + returned length -----+
   -> out-of-line mapping + returned count -----+-> IOCFUnserializeWithSize
                                                       |
                                                       v
                                             caller-owned CF object
```

After successful transport, the framework selects an out-of-line address and 32-bit extent if the address is nonzero. Otherwise it selects the stack buffer and the returned 64-bit extent. It calls `IOCFUnserializeWithSize` at `0x184ebd84c`. Any nonzero out-of-line address is passed to `vm_deallocate` at `0x184ebd890` after the decode attempt. The returned value is the local CF object pointer or null. The daemon releases that object with `CFRelease` and separately retires the parent and interface send references with `IOObjectRelease` at `0x100004380` and `0x100004388`. [Apple IOKit wrapper](https://github.com/apple-oss-distributions/IOKitUser/blob/main/IOKitLib.c#L2363-L2445)

## Evidence bounds

| Assumption | Dependent finding | Falsification probe |
| --- | --- | --- |
| A1. The pinned thin daemon supplies the original text and fixups. | Three direct callers and their property consumers. | Rehash and repeat the aligned branch census. Resolve uses of the additional authenticated data binding to extend coverage. |
| A2. The pinned cache and fileset describe the compared installed build. | Request selection, reply shape and ownership. | Verify both image identities and the matching stub slots. Compare flag values and actual reply form in a passive same-build capture. |
| A3. The archived file represents the headers recorded by this RAX run. | No recorded property RPC. | Rehash and reparse the trace. Check that the version `2877/2977`, class match `2881/2981` and iterator `2802/2902` exchanges still appear once each among the 44 headers. |

High impact attaches to distinguishing network registry traffic from FairPlayIOKit instance method traffic and to identifying when the bytes arrive through direct copyout. Medium impact attaches to the installed compatibility branch because it changes the expected request and reply pair. The verified registry destination is kind `0x28`. FairPlayIOKit method transport takes an IOKit connection of kind `0x27`. The report provides static image evidence and an archived header census [A3]. It leaves the native transaction and actual property values unknown. Verification uses O(B + T) time and space in pinned input bytes B and trace bytes T. [FairPlay connection transport](live_iokit_connection_service_report.md) [Archived IOKit traffic](zut_trace_report.md) [Verifier](triage_evidence/audit_live_iokit_registry_property.py)

```sh
python3 -B triage_evidence/audit_live_iokit_registry_property.py \
  "$BOOT_FILESET" "$PINNED_DAEMON" "$ANNOTATED_TRACE"
```
