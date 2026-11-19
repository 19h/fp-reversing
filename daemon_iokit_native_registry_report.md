# Native FairPlayIOKit service and user-client attachment

A read-only IOService registry snapshot on the current macOS arm64 host shows one `com_apple_driver_FairPlayIOKit` service under the `IOResources` provider class and two attached user-client entries. The kernel registry attributes one client to the running `fairplayd` process and one to `adid`. That establishes a live service-to-client relationship on this host. The snapshot contains no selector call, reply bytes or task-local Mach port names.

| IOService entry | Runtime object class | Creator reported by the registry |
| --- | --- | --- |
| FairPlay service | `com_apple_driver_FairPlayIOKit` | Service entry |
| Child client | `com_apple_driver_FairPlayIOKitUserClient` | PID 3903, `fairplayd` |
| Child client | `com_apple_driver_FairPlayIOKitUserClient` | PID 910, `adid` |

Zero roots matched `AvpFairPlayDriver` in the same capture. The current host reports `kern.hv_vmm_present = 0`. This combination is consistent with the recovered daemon branch selecting the primary service, conditional on the pinned daemon's cached byte and context. The registry supplies no execution history for that branch. [Class gate](daemon_selector26_class_gate_report.md)

The supplied RAX log records a match against the same primary service class and an open that returns `0xe00002c2` with a null connection. The current snapshot establishes a later, separate host observation. The failed open remains the last event in that supplied transaction, and its cause remains unknown. [Trace report](zut_trace_report.md) [Open status channels](kernel_iokit_open_report.md)

## Correlation across registry, process and image

The two filtered IOService-plane snapshots agree. The service registry ID is `0x1000002fb`. Its `IOUserClientClass` property names the same class as the two captured child object classes. The `adid` child has ID `0x10000130b`, and the `fairplayd` child has ID `0x100001702`. Both creator PIDs had matching process names when queried. These IDs identify registry entries for the observation interval. Task-local Mach names and port types are absent from the registry output. In Apple's published XNU source, the common open implementation sets the creator property from the calling PID after successful construction and before its remaining admission checks and connection publication. This explains the property's role in that source. The running kernel's exact implementation is outside the source comparison. [Apple XNU open implementation](https://github.com/apple-oss-distributions/xnu/blob/main/iokit/Kernel/IOUserClient.cpp#L4181-L4338)

| Component | Current host or installed file | Pinned analysis | Correlation |
| --- | --- | --- | --- |
| Operating system | macOS 27.3, build `26C5035r`, arm64 | Historical RAX host build unknown | Runtime environment recorded for this snapshot |
| Kernel | `90195379-954d-3ca3-baac-327341f14211` | `9b65bd6e-027b-34d1-a22b-ac03dccffc84` | Distinct UUIDs |
| FairPlayIOKit kext | Version 72.19.0, `316464f8-eade-30ca-938e-2f430b1ed5bc` | `227f9df7-645d-39b8-b74a-685303d16b4b` | Distinct UUIDs |
| fairplayd arm64e file slice | `204741e9-b89f-32b4-9321-51f3975c7cac` | Same UUID | Code and data bytes match for this slice |
| fairplayd arm64e.x1 file slice | `d4e1629f-019b-38c3-9f31-3f203e58d440` | Pinned input is arm64e | Actual loaded slice unknown |

The two arm64e files with UUID `204741e9-b89f-32b4-9321-51f3975c7cac` each contain 17,668,912 B. The aligned comparison finds 262 differing bytes in four runs, all in the CMS signature slot `0x10000`, whose file range is `[0x10d54cb, 0x10d653d)`. Byte equality therefore covers the other signature slots, full file-backed `__TEXT`, `__DATA_CONST`, `__DATA`, exports and chained fixups. The installed file also contains the second arm64e CPU subtype and an x86_64 slice. The file comparison leaves runtime slice selection and loaded addresses unknown. [Capture and byte-comparison script](triage_evidence/audit_daemon_iokit_native_registry.py) [Apple code-signature slot definitions](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h#L76-L115)

The local `lsmp -p 3903` query returned exit status 1 with `task_for_pid() failed` and produced no port rows. A separate `PROC_PIDARCHINFO` query for both creator PIDs returned zero bytes with `EPERM`. No task-local port list or running CPU subtype was obtained. The earlier static report's 2862/2962 open and 2865/2965 call pairs still describe the pinned build. Numeric names from the historical RAX run belong to that run. [Pinned connection lifecycle](iokit_connection_lifecycle_report.md)

## Evidence and reproducibility

The [compressed observation](triage_evidence/daemon_iokit_native_registry_observation.json.zst) retains the UTC interval, selected registry properties, process names, kernel and kext UUIDs and exact file comparison. It contains no raw process list, Mach object addresses or machine-local paths. A fresh capture matched all retained fields apart from its timestamps. Independent `lipo`, `dwarfdump`, `otool` and `cmp` checks confirmed the file slice, signature command and all 262 differing byte offsets. The capture reads registry and image metadata. It issues no FairPlay user-client method calls. The audit compares N installed and pinned file bytes and R selected registry records in O(N + R) time and O(N + R) storage for this case. The decoded ranges use half-open file offsets in bytes.

```sh
python3 triage_evidence/audit_daemon_iokit_native_registry.py "$PINNED_DAEMON"
```

Set `PINNED_DAEMON` to the extracted arm64e input whose SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The observations are specific to the captured host interval. Changes in live processes, registry contents or the installed daemon can change a later result.

## Assumption register

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| NR1 | The two IOService-plane outputs describe the same live registry entries through the selected process queries. The attachment claim depends on that snapshot. | Requery both classes and compare service and child IDs, creator labels and process identities. |
| NR2 | The process executable path query names the current installed file for that daemon. The file comparison is conditional on that association. | Verify the running process metadata and compare a separately attested loaded image UUID with the installed slice UUID. |
| NR3 | The file slice and code-signature offsets are interpreted in the envelope parsed by the audit. The byte-difference classification depends on these bounds. | Independently decode the FAT and Mach-O headers, then enumerate all differing bytes and verify the signature sub-blob bounds. |
| NR4 | The historical capture and pinned binaries apply to the source-local reports. Only matching UUIDs and bytes support cross-build transfer. | Compare the observed runtime kernel, kext, daemon slice and cache UUIDs with the analysis inputs before transferring address or method claims. |

## Scope and impact

| Impact | Open evidence |
| --- | --- |
| High | Recover a source-backed method map for the live kext UUID before attributing selector 26 behavior on this host. |
| High | Correlate a passive open/method observation with the client registry ID, connection name, peer or reply right and reply result. |
| Medium | Identify the active daemon CPU subtype and IOKit shared-cache UUID. |
| Low | Determine whether the alternative provider appears under other host configurations. |

QG1–QG3 cover the factual snapshot, explicit premises, process correlation and file comparison. QG4–QG5 cover widths, file range geometry, alternate class absence within the inspected plane and the two distinct kernel/kext identities. QG6–QG7 cover the primary runtime outputs, source references, replayable audit and bounded remaining questions.

A subsequent snapshot finds two more clients attached to the same service. It identifies the running `lskdd` and `fairplaydeviceidentityd` slices, their active launchd endpoints, and candidate driver call sites. [Additional native clients](live_fairplay_additional_clients_report.md)
