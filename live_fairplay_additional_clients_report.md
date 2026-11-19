# Native lskdd and fairplaydeviceidentityd clients of FairPlayIOKit

The IOService registry on build `26C5035r` shows four attached FairPlayIOKit user clients. Two are attributed to `lskdd` and `fairplaydeviceidentityd` in addition to the previously observed `adid` and `fairplayd` entries. Both additional processes run installed `arm64e` slices that import the IOKit matching, open and structure-method APIs. Their launchd jobs also advertise active named endpoints. This expands the observed process-to-driver topology. An attachment entry does not record any individual call or identify its task-local IOConnect port. [Earlier registry capture](daemon_iokit_native_registry_report.md) [New capture](triage_evidence/fairplay_additional_clients.json.zst)

## Registry and running executables

The selected service is `com_apple_driver_FairPlayIOKit`, ID `0x1000002fb`, under provider class `IOResources`. Its `IOUserClientClass` and all four child class names are `com_apple_driver_FairPlayIOKitUserClient`. The snapshot ran on 2026-11-19 around 10:05 UTC.

| Creator label | PID | Client registry ID | Installed slice selected by live attributes |
| --- | ---: | --- | --- |
| `adid` | 910 | `0x10000130b` | Previously verified `arm64e`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049` |
| `fairplayd` | 3903 | `0x100001702` | Previously verified `arm64e`, UUID `204741e9-b89f-32b4-9321-51f3975c7cac` |
| `lskdd` | 80938 | `0x1001badf7` | `arm64e` at file offset `0x124000` B, UUID `28d510e5-3b91-3916-97ab-b765a3a7ba21` |
| `fairplaydeviceid` | 18554 | `0x1001bef3c` | `fairplaydeviceidentityd`, `arm64e` at file offset `0x4a0000` B, UUID `0a404c50-4901-312f-9e36-04565d30f305` |

For the last two entries, the same PID appears in the registry and the running launchd job. The process-reported Mach-O file offset and 20 B CodeDirectory hash independently select the same slice in the installed universal file. Repeated registry, job, process-start and code-signing checks agree within the capture. The first two rows use the earlier slice audit and the unchanged registry IDs. [Earlier slice identities](fairplay_live_slice_identity_report.md)

## Inbound services and outgoing driver interfaces

| launchd job | Active inbound endpoint label | Port value as reported by launchctl |
| --- | --- | --- |
| `com.apple.lskdd` | `com.apple.lskdd` | `0x1504ef` |
| `com.apple.lskdd` | `com.apple.lskdd.xpc` | `0x12f337` |
| `com.apple.fairplaydeviceidentityd` | `com.apple.fairplaydeviceidentityd` | `0xdbb03` |

These values describe launchctl's endpoint view during the capture. Each daemon's actual receive name, any peer send names and the kernel port objects remain unknown. The installed `fairplaydeviceidentityd` binary passes its service string, a dispatch queue and flags 1 to the `xpc_connection_create_mach_service` stub at preferred PC `0x1000022e4`. The success path installs the block with invoke PC `0x1000025a8` at `0x100002348` and activates the listener at `0x100002350`. The corresponding listener creation locations in `lskdd` remain unknown. The earlier Arcade companion evidence includes a signing requirement that admits the identifier `com.apple.lskdd`; that requirement and the two launchd endpoints establish separate architectural interfaces. No call across the Arcade edge was observed in this capture. [Arcade peer interface](arcade_service_report.md)

Both selected executable slices contain authenticated IOKit imports for `IOServiceMatching`, `IOServiceGetMatchingServices`, `IOServiceOpen` and `IOConnectCallStructMethod`. Their signed entitlements include `com.apple.private.FairPlayIOKitUserClient.access = true` and `AvpFairPlayUserClient.access = true`. The installed `lskdd` slice also lists the FairPlayIOKit, AvpFairPlay and KeyDelivery user-client classes in `com.apple.security.iokit-user-client-class`. These facts identify intended client facilities and authorization metadata. The registry establishes a live attachment specifically to FairPlayIOKit, while a given private call's provider can depend on the connection value it actually loads.

| Executable | Preferred PC of candidate driver call | W1 selector | X3 input extent | Current FairPlayIOKit table contract if routed there |
| --- | --- | ---: | --- | --- |
| `fairplaydeviceidentityd` | `0x1000159c4` | 26 | Inherited through X20 | `ucSendFPMessage`, 16 B input and 16 B output |
| `lskdd` | `0x100474e38` | 19 | 3088 B | `GetReEncryptionVault`, 3088 B input and 3088 B output |
| `lskdd` | `0x100584cc8` | 18 | 3096 B | `ProcessEncryptedData`, 3096 B input and 3096 B output |

At `fairplaydeviceidentityd` PC `0x100015948`, W0 loads a u32 from X15+4; the call takes an output-count pointer in X5 equal to SP. Its two source-resolved selector byte banks reduce `i XOR right[left[i] XOR 0xfd]` to `0xa5` for every byte i. With addend `0x4c6b`, this selects index `0x4d10`. If X23 is the candidate table base `0x1005c0a80`, the load selects original slot `0x1005e7300`, whose `IOConnectCallStructMethod` binding has the call's modifier `0xb0da`. The definition reaching X23 at the call remains unknown. For the two `lskdd` call sites the local operand values and import modifier `0x21c3` match the candidate interface. Their computed-slot lineage, output capacities and connection identities remain unknown. The exact matching kext records supply the contract column, which is conditional on the selected provider and target. [Current provider method table](live_kext_selector26_report.md)

## Direct RPC 502/602 observation limit

DTrace could not enumerate the requested Mach syscall probe under the current account. The native registry and launchd snapshots expose attachments and endpoint registration, while neither supplies a message event. The archived RAX trace has 44 recognized Mach message lines. It has one send of 2862 and one receive of 2962, ending the open with `0xe00002c2` and a null connection as independently decoded in the earlier report. Neither direction has 502, 602, 700, 800, 2865 or 2965 in the capture. Native reply delivery, mapping installation, and retirement of the same security record remain unknown. [RAX decode](zut_trace_report.md) [Static RPC 602 mapping and retirement](live_fairplay_reply_mapping_report.md)

## Assumptions and reproducibility

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| NC1 | The paired registry and process records name the same instances throughout the interval. This supports attribution of the two new attachments. | Compare entry IDs, process start, live Mach-O offset and hash before and after the endpoint queries. |
| NC2 | Both live attributes identify the same installed executable slice. This supports the preferred PCs and import interpretation. | Enumerate every slice and CodeDirectory, require a unique offset/hash match, and compare the signed hash with the original file. |
| NC3 | A candidate call uses the matching authenticated import and the FairPlayIOKit connection. This governs the conditional method-name column. | Recover the reaching table and port definitions or correlate the request selector with a live connection for the recorded child. |
| NC4 | Printed launchctl values refer to the endpoint records in the captured diagnostic view. This governs the endpoint-name table. | Compare with independently identified port objects and rights in the appropriate namespaces before joining their numeric names. |
| NC5 | The trace hash identifies the archived run and its message lines use the observed header format. This bounds the absence of messages of interest. | Check the trace hash, compare the counts with the independent raw-message decoder, and inspect any extra header format before broadening the claim. |

Run `python3 triage_evidence/audit_fairplay_additional_clients.py "$RAX_TRACE"` with the archived trace as `RAX_TRACE`. For executable bytes B, registry and launchd input R, input trace bytes T and selected instruction count I, the audit uses O(B + R + T + I) time and space, with an additional fixed 256-input bank check. The capture reads registry, job, process, signature and file metadata.

High impact attaches to the two newly attributed attachments and their distinct named service surfaces. Medium impact attaches to the candidate method routes because the call dataflow is still incomplete. QG1–QG3 cover factual scope, assumptions and the recorded IPC interfaces. QG4–QG5 cover byte widths, the exhaustive selector equation and the distinctions among three namespaces and between observed and candidate edges. QG6–QG7 cover runtime and original-binary provenance and the bounded open questions. [Audit](triage_evidence/audit_fairplay_additional_clients.py) [Compressed observation](triage_evidence/fairplay_additional_clients.json.zst)

The follow-up audit resolves the FPDI peer-handler install and protected worker ABI, including audit-token capture, `data` and `status` dictionary fields and an exact XPC send site. [FPDI receive and reply interfaces](live_fpdi_xpc_report.md)
