# IOKit discovery from host right to service right

The installed IOKit framework obtains a main-port send right, uses the first call to probe the IOKit server version, then sends the matching request to the main port. The matching reply supplies the iterator send right, and the iterator reply supplies the service send right for the subsequent open. The archived `fairplayd` trace captures all four exchanges and the first host-right deallocation. Installed `lskdd` uses the same public APIs on the recovered selector 18 and 19 acquisition routes. [RAX capture analysis](zut_trace_report.md)

## Requests and rights

| Request / reply | Installed emission call | Outgoing destination | Accepted reply and installed output site | Archived guest destination and output |
| --- | --- | --- | --- | --- |
| 205 / 305 `host_get_io_main` | `0x18056b448` in libsystem_kernel | Host send name from `mach_host_self` | 40 B, main send name copied from +28 B at `0x18056b510` | `0xc03` -> `0x1703` (lines 1677 / 1681) |
| 2877 / 2977 `io_server_version` | `0x184ebc3cc` in IOKit | Main send name | 44 B, routine result at +32 B and u64 version from +36 B stored at `0x184ebc4c0` on success | `0x1703` -> version `0x134647a` (1687 / 1692) |
| 2881 / 2981 `io_service_get_matching_services_bin` | `0x184ebd3dc` in IOKit | Main send name | 40 B, iterator send name copied from +28 B at `0x184ebd4b0` | `0x1703` -> `0x1803` (1699 / 1709) |
| 2802 / 2902 `io_iterator_next` | `0x184ebd59c` in IOKit | Iterator send name | 40 B, service send name copied from +28 B at `0x184ebd670`. Public wrapper returns it in W0 on stub success. | `0x1803` -> `0x1903` (1715 / 1720) |
| 2862 / 2962 `io_service_open_extended` | `0x184ebdc6c` in IOKit | Service send name | 52 B on the complex path. Connection name is copied from +28 B at `0x184ebdd48`. | `0x1903` -> null connection, application status `0xe00002c2` (1726 / 1736) |

The four discovery requests have bits `0x1513`, zero voucher, COPY_SEND in the remote field, MAKE_SEND_ONCE in the local field and zero request descriptors. Each stub obtains its local name from `_mig_get_reply_port` and emits through `_mach_msg2_internal`. The IOKit call sites resolve through the authenticated veneer at `0x188088af0`. The first kernel trap call is `0x18055b960`, with the `svc` at `0x180548c1c`. The archived trap PC is `0x180547c20` and the archived local name is `0x507` across the four exchanges. The bridge sends version and matching to host-local `0xf03`, iteration to host-local `0x1103`, and receives those replies on host-local `0x1603`. These numerical values belong to the archived namespaces. The open request adds task and out-of-line descriptors. [Open transport](live_iokit_mach_transport_report.md) [Open reply validation](live_iokit_open_reply_copyout_report.md)

The three successful right-bearing discovery replies require the complex bit, a single descriptor, size 40 B, a zero received remote name and port descriptor halfword `0x0011` at +38 B. That halfword encodes received disposition PORT_SEND (17) and port descriptor type zero. The name at +28 B is written only after the validation. The 36 B simple error form returns a routine status without a name store. The public `IOIteratorNext` initializes its local output to zero, calls the stub at `0x184ebd514` and returns zero on error at `0x184ebd520`. Distinguishing a null result from an error requires the internal status before that selection.

## Version and dictionary flow

`IOMainPort` at `0x184ee2330` branches to `IOMasterPort` at `0x184ebc218`. The implementation preserves the caller's X1 output pointer, calls `mach_host_self` at `0x184ebc234` and passes the resulting name and caller pointer to `host_get_io_main` at `0x184ebc240`. The host-self trap executes at `0x180548b50`. The main-port request executes on each call through this path. The version probe is behind the `dispatch_once` call at `0x184ebc2dc`, whose block invokes the 2877 stub at `0x184ebc30c` with the name read from the caller's output word.

The installed serialization-flags cell `0x1eb1ee3f8` starts with bit 0 set. The once block clears that bit at `0x184ebc33c` when the version probe fails or yields an unsigned version at most `0x1335184`. The probe sets its private version cell to zero on error. The archived success value is `0x134647a > 0x1335184`. Under the inspected implementation, that value preserves bit 0 and enables the inline binary branch for the archived dictionary size.

| Wrapper flag and serialized extent N | Emission | Request characteristics and iterator output |
| --- | --- | --- |
| Bit 0 set, N <= 4,095 B | 2881 at `0x184ebd3dc` | Inline bytes begin at +36 B. A u32 at +32 B gives N. The packed request is `36 B + round_up(N, 4 B)`. Reply writes iterator at `0x184ebd4b0`. |
| Bit 0 clear, N <= 511 B | 2804 at `0x184f5e230` | Legacy inline form. The framework success decoder writes an iterator at `0x184f5e304`. The installed kernel returns `kIOReturnUnsupported` in the status-only `2904` reply. [Installed registry compatibility](live_iokit_matching_compatibility_report.md) |
| N above the selected inline limit | 2857 at `0x184f60898` | Complex 56 B request with one out-of-line region. Complex 52 B reply 2957 writes operation status and iterator at `0x184f6096c` and `0x184f60970`. |

The archived matching request gives N = 64 B, so its length is `36 B + 64 B = 100 B`. Its inline data contains `IOProviderClass = com_apple_driver_FairPlayIOKit`. The normal inline matching path is O(N) for copying the serialized bytes. Parsing the fixed-size discovery reply and publishing its port name are O(1) in time and auxiliary storage.

## Ownership at the call sites

- Main-port acquisition drops its temporary host name via `mach_port_deallocate(mach_task_self_, host)` at `0x184ebc2b4` after the version block or the once fast path. Line 1698 shows the archive dropping guest host name `0xc03` after the version exchange. The returned main name remains available to the caller.
- `IOServiceGetMatchingServices` passes a nonzero caller main name to the matching stubs. A zero input goes through `IOMasterPort` at `0x184ebd1b0`; the wrapper drops the resulting nonzero temporary name at `0x184ebd2a0` if it differs from the incoming name.
- `IOObjectRelease` forwards `mach_task_self_` and the supplied name to `mach_port_deallocate` at `0x184ebdb60`. The ordinary preference is the deallocation trap at `0x180548acc`. A trap result of `0x10000003` selects the RPC fallback, emitting request 3206 at `0x18056d99c`. The audit follows this local user-reference operation. The object or port's final retirement depends on other references and kernel state.

| Operation | Installed lskdd selector 18 route | Installed lskdd selector 19 route |
| --- | --- | --- |
| Main name out | `0x1006521e0` | `0x100455b1c` |
| Main name in, iterator name out | `0x100404584` | `0x1004362a8` |
| Iterator name in, service name out | `0x1006154c0` | `0x1003f2f7c` |
| Service release | `0x1003e9058` | `0x10046f9f8` |
| Iterator release | `0x1005e3c98` | `0x1005996dc` |

These entries describe the recovered acquisition routes. Native namespace names, invocation and call counts, final reference counts, and the identity of the object behind the archived service name remain unknown. [Selector 18 acquisition](live_lskdd_selector18_connection_report.md) [Selector 19 acquisition](live_lskdd_selector19_open_report.md)

## Assumption register and verification

| Premise and dependent result | Falsification probe |
| --- | --- |
| The cache and library UUIDs identify the installed code examined here. Absolute PCs are unslid addresses for these images. | Recheck the UUIDs, instruction words and authenticated pointer-chain membership against the installed cache. |
| The archived messages and the current stubs share the identified envelope and field interpretation. This qualifies the historical comparison. | Compare the historical framework image and call sites against the archived trap tuples and packed messages. |
| The active once state and version match the examined branch when comparing the archived 64 B dictionary to the installed code. | Observe the serialization-flags value before and after an ordinary version probe and check the ensuing request ID. |
| The recovered `lskdd` routes reach the installed imports with the identified caller arguments. This qualifies the static join. | Correlate output and input names at consecutive native discovery sites and query service identity in the same namespace. |

High impact for separating the host, main, iterator, service and reply names and attributing their transfers to concrete sites. Medium impact for explaining the matching-format branch and release lifetime. The auditor rechecks four archived wire records and their trap tuples against the original trace digest, verifies 71 instruction sites, ten data literals and seven original slide-chain bindings, and records the bytes in the compressed receipt. [Auditor](triage_evidence/audit_live_iokit_discovery.py) [Compressed audit receipt](triage_evidence/live_iokit_discovery_audit.json.zst)

The kernel follow-up resolves the iterator right in reply 2981, the service right in 2902, and the current FairPlayIOKit registry entry returned by an ordinary verifier. [Kernel IOKit matching](live_iokit_matching_report.md)

The main-port audit traces the boot-time publication, host getter and version reply to their installed kernel sites and records the verifier task’s send user references. [IOKit main-port publication](live_iokit_main_port_report.md)

The reply-port audit traces the installed thread-local cache and retirement paths, and follows guest reply name `0x507` across all five archived discovery and open exchanges. [IOKit MIG reply port](live_iokit_mig_reply_port_report.md)
