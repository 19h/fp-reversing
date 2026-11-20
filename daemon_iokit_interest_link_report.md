# fairplayd and IOKit interest registration

The dynamic-dispatch follow-up resolves one ambiguous `0x19ad` call to the local RPC 502 environment helper and identifies a second conditional edge to that helper. The two genuine symbol lookups in that cluster target CoreKE exports. [RPC 502 authenticated call targets](daemon_rpc502_dynamic_dispatch_report.md)

The archived `fairplayd` image and both installed ARM slices contain IOKit open and method bindings. Their import tables, chained binds and literal bytes provide no direct evidence of a call to register per-client interest. The supplied RAX capture reaches a failed FairPlayIOKit open and contains neither registration requests nor a Mach event 53. A native `fairplayd` registration on its FairPlayIOKit child remains unknown. The installed kernel does expose two identifiable dispatch marker pairs for such an investigation. [Native IOSurface delivery control](live_iokit_interest_notification_report.md) [Existing FairPlay registry attribution](daemon_iokit_native_registry_report.md)

## Daemon import and name evidence

| Input | Slice UUID | Chained bind slots checked | IOKit imports |
| --- | --- | ---: | ---: |
| Supplied `fairplayd.arm64e` | `204741e9-b89f-32b4-9321-51f3975c7cac` | 326 | 12 |
| Installed `arm64e`, build `26C5035r` | `204741e9-b89f-32b4-9321-51f3975c7cac` | 326 | 12 |
| Installed `arm64e.x1`, build `26C5035r` | `d4e1629f-019b-38c3-9f31-3f203e58d440` | 326 | 12 |

All three inputs have the same IOKit import names. The supplied and installed `arm64e` images also match on the selected bind slots, including `IOServiceOpen` at `0x1010a0b48`, `IOConnectCallStructMethod` at `0x1010a0640`, and the generic Mach send path. A previous process identity audit selected the installed `arm64e` slice by CodeDirectory hash and slice offset. That installed slice and the supplied thin file differ in the CMS signature slot. This turn audited the files on disk. The installed `arm64e.x1` slice was checked as a distinct image. [Process and slice identity](fairplay_live_slice_identity_report.md) [Import and wire receipt](triage_evidence/daemon_iokit_interest_link_audit.json.zst)

The nine literal probes include the interest and matching registration APIs, notification-port and dispatch entry points, two registry lookup APIs used by the native control, and the Mach port description API. Their ASCII names are absent from the checked imports, binds and raw slice bytes. The positive controls include `_dlsym`, `_dlopen`, `_mach_msg`, `_mach_msg2_internal`, and `_notify_register_check`. The recovered `_notify_register_check` sites take ADID names and token storage addresses. That ABI provides a libnotify token. IOKit interest registration takes a watched service right and a wake port. The remaining ways to reach IOKit include dependency code, dynamically constructed names and generic Mach transport. The current IDA MCP connection listed only an unrelated database, so the audit used Mach-O bytes and toolchain decoding. [Dynamic CoreKE bindings](rpc502_runtime_report.md) [ADID names and token fields](daemon_notification_registration_report.md) [Apple IOKit interest signature](https://github.com/apple-oss-distributions/IOKitUser/blob/323ead896d04424f87184d8f6ff0cce811aab106/IOKitLib.c#L750-L769)

## What the archived wire records cover

The audit redecoded the 24 B headers from all 44 printed guest message bodies, checked their annotations and separately counted RAX host bridge records. The only selected IOKit lifecycle transaction was request 2862 and reply 2962 at lines 1726 and 1736. The 52 B reply contains connection name zero and application status `0xe00002c2` at offset 48 B. The bridge also reports two ordinary port-deleted messages, ID 65, on host name `0x1c03` after the guest releases its service and iterator names. [Archived open and port retirement](archived_iokit_open_retirement_report.md)

| Transaction or event | ID(s) | Guest printed records | Host bridge records |
| --- | --- | ---: | ---: |
| Extended service open | 2862 / 2962 | 1 request, 1 reply | 1 request, 1 reply |
| Service interest registration | 2850 / 2950, 2869 / 2969 | 0 | 0 |
| IOKit notification envelope | 53 | 0 | 0 |
| Ordinary Mach port deletion | 65 | 0 | 2 receives |

The 1,748-line capture terminates after the failed open and the releases. The zero interest count applies to that observed interval. The native IOSurface control registers on the child only after a successful connection open. No post-success `fairplayd` interval is available in this capture. [Trace provenance](zut_trace_report.md) [IOKit event 53 layout](live_iokit_interest_notification_report.md)

## Installed dispatch and the proposed join

| Registration request / expected reply | Installed routine slot / stub | Sandbox index | Dispatch start / end |
| --- | --- | ---: | --- |
| 2850 / 2950, legacy | `0xfffffe0007e78260` / `0xfffffe000be82b9c` | 102 | `0xff000199` / `0xff00019a` |
| 2869 / 2969, LP64 | `0xfffffe0007e784c0` / `0xfffffe000be80da4` | 121 | `0xff0001e5` / `0xff0001e6` |

The marker values use `0xff000000 | (index << 2) | phase`, with phases 1 and 2. The auditor checked the populated routine slots, the Sandbox array and 49 dispatch instructions. Event 53 and replies 2950/2969 have no entries in the installed dispatch index array. The termination notification uses the separate kernel send at `0xfffffe000c5b15b8`. The marker pair brackets the registration routine. The registration reply, destination, interest name and descriptor establish separate parts of the join. [Installed MIG trace producer](live_iokit_mig_trace_report.md) [Pinned legacy registration](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/device/device.defs#L451-L465) [Pinned LP64 registration](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/device/device.defs#L631-L637)

For an authorized observation of successful startup, tie the registration's destination to the per-client registry object ID. Match the outgoing wake descriptor and the returned registration right to the incoming message's local and remote names within the same task generation. For termination, verify service-interest type `0xa0`, event `0xe0000010`, and the child identity in the received service descriptor. These criteria distinguish a per-client lifecycle event from activity on the provider, notification port reuse, and a generic termination envelope.

## Assumption register

| Assumption | Dependent result and impact | Falsification probe |
| --- | --- | --- |
| I1. The pinned binaries cover the daemon variants under comparison. | Medium. The direct binding result applies to the archived and installed ARM images. | Verify the file hashes and UUIDs in the receipt and compare a new runtime slice identity before projecting the result to another process or build. |
| I2. A direct API or embedded literal produces one of the checked names. | Medium. The checked import and literal paths show no registration. | Recover a resolved dynamic lookup, a dependency caller, or an outgoing raw registration. Each can establish behavior outside the census. |
| I3. The capture records the relevant guest and bridge operations during its bounded run. | High. The recorded run contains a failed open and no observed interest registration. | Recheck decoded bodies and bridge lines against the pinned trace. Evidence from a successful open is required to cover the later path. |
| I4. Sandbox initialization registered the indices and the kernel logger was enabled. | High. The two marker pairs can identify a registration routine's dispatch on the verified build. | Compare the installed table and dispatch instructions, then validate a known registration trace on the same build. Routine success requires a matched reply. |

The audit reads the daemon artifacts and host fileset, and parses the existing trace. It does not execute `fairplayd`, register interest or start tracing. For binary and fileset bytes B, emitted fixup records F and trace bytes T, the audit uses O(B + F + T) time and space with the fixed probe set, excluding system tool internals. Run `python3 -B triage_evidence/audit_daemon_iokit_interest_link.py "$ARCHIVED_DAEMON" "$INSTALLED_DAEMON" "$ANNOTATED_TRACE" "$BOOT_FILESET"`. [Auditor](triage_evidence/audit_daemon_iokit_interest_link.py) [Compressed receipt](triage_evidence/daemon_iokit_interest_link_audit.json.zst)
