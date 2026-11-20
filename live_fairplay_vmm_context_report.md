# VMM context used by FairPlay IOKit class selection

The installed kernel answers `kern.hv_vmm_present` by reading the `vmm-present` property at `/defaults` in the IODeviceTree plane and returning a normalized 4 B result. The current named and numeric reads both returned zero. The pinned daemon projects a successful query into a process-local byte used for the initial service-class lookup. The archived trace shows the primary-class query, with the historical sysctl value still unknown. [Daemon class gate](daemon_selector26_class_gate_report.md) [Provider personalities](live_fairplay_service_personality_report.md)

## Installed environmental interface

| Stage | Installed unslid site | Data or control transfer |
| --- | --- | --- |
| MIB registration record | `0xfffffe0007f2fd08` | Its parent points to `_sysctl__kern_children`, its leaf name is `hv_vmm_present`, and the authenticated handler pointer selects `0xfffffe000c3c5ff4`. The initial number is `OID_AUTO` (-1). |
| Sample the device tree | `0xfffffe000c3c6020` to `0xfffffe000c50f4f8` | The handler starts with a zeroed 4 B cell and passes its address, capacity and the property name to the helper. The helper resolves `/defaults` with the IODeviceTree plane at `0xfffffe000c50f53c` and calls the entry's property getter at `0xfffffe000c50f574`. |
| Check and copy data | `0xfffffe000c50f5e4` through `0xfffffe000c50f658` | The property must resolve to `OSData`. The helper checks its byte length against the 4 B capacity, obtains the backing bytes and copies that length into the zeroed cell. Absent node, absent property, type mismatch or over-capacity value leave the cell zero. |
| Publish the integer | `0xfffffe000c3c602c`, `0xfffffe000c3c6048` | Publish 1 for a nonzero word and 0 for zero. The call passes request, address and 4 B length to the request's `oldfunc` callback. |

The registered numeric name was `[1, 295]` on the observed boot. The registered kind `0x11e00002` and format `I` agree with the fileset. Successful read calls by name and by number each returned four zero bytes. A read-only IODeviceTree query exposed the `defaults` entry and did not list `vmm-present`. The absence claim is scoped to the exported snapshot. The zero-valued sysctl result alone cannot distinguish a missing property from a present zero-valued property. [XNU sysctl identifier and flag definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/sysctl.h#L96-L190) [XNU request and OID layouts](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/sysctl.h#L192-L269)

## Daemon and historical capture

| Evidence | Observation |
| --- | --- |
| Pinned daemon file | The 20 B NUL-terminated name is at `0x100ecc5c0`. The call at `0x10043df88` has zero new-value arguments. On a successful return the daemon stores the projected Boolean at `0x100130b30`. The consumer writes its encoded projection at `0x1003609bc`. |
| Archived sysctl lines | The trace has 15 printed `sysctl` calls and no printed `sysctlbyname` call. In lines 552/553, the sole 20 B input points to `0x10118ea64` outside the pinned daemon's unslid file-backed mapping. The next call uses the preceding output buffer as a four-component numeric name. The pair appears before shared-region mapping and provides neither the name bytes nor the return buffer. |
| Archived IOKit search | Request `2881` at line 1699 contains `IOProviderClass = com_apple_driver_FairPlayIOKit`. It goes to the guest IOKit main name `0x1703` with reply receive name `0x507`. Reply `2981` supplies iterator name `0x1803`. |
| Current class context | The returned zero and live IOResources topology agree with the recovered primary route when both daemon context bytes hold their file-initial values. The initial cache and those context bytes were not sampled in the running daemon. |

The name-length match in the archive is insufficient to identify the daemon's query. Syscall return zero attests success while the integer would be written through the output pointer. The class string establishes which lookup occurred, and a separate fallback path can also reach the primary class. [Recovered class selection and fallback](daemon_selector26_class_retry_report.md) [Discovery message bytes](live_iokit_discovery_report.md)

## Assumptions and verification

| Assumption | Dependent claim | Falsification probe |
| --- | --- | --- |
| A1. The fileset and live kernel identity agree. | The installed OID, handler and classifier input apply to the observed boot. | Rehash the collection, compare kernel UUID and recheck the OID fixups and the live kind/format bytes. |
| A2. The queried IODeviceTree snapshot reflects the visible `defaults` entry. | Property absence in the registry output. | Repeat the exact node query alongside the named and numeric reads. Kernel-only properties are outside this observation. |
| A3. The pinned daemon and original trace retain their file bytes. | Query address, event order and guest lookup string. | Check both digests, reparse the file-backed bounds and compare the trace call arguments and message bytes. A contemporaneous name and result buffer could resolve historical attribution. |

High impact for identifying the kernel source of the daemon's environment input and the point where it joins provider selection. Medium impact for separating the historical lookup from the historical environment reading. The auditor checks the OID and virtual bindings, 21 installed instructions, five daemon instructions and the matching packet. It reads B fileset bytes, D daemon bytes and T trace bytes in O(B + D + T) time and storage. [Auditor](triage_evidence/audit_live_fairplay_vmm_context.py) [Compressed audit](triage_evidence/live_fairplay_vmm_context_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_fairplay_vmm_context.py \
  "$BOOT_FILESET" "$DAEMON_SLICE" "$ANNOTATED_TRACE"
```
