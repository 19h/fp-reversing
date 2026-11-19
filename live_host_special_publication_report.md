# Host-special port publication on macOS 26C5035r

The running launchd selects the installed arm64e executable at universal file offset 16,384 B. That slice reads the integer `HostSpecialPort` into a service record, obtains the service's Mach send name, and calls `host_set_special_port`. The matching Mach library sends MIG request 413. The boot kernel's replacement routine and the getter used by FairPlayIOKit address the same indexed host table. Launchd prints active FairPlay associations for 17 and 31. The current kernel objects in those cells, their publication times, and the receiver assigned to slot 34 remain unknown. [Previous lookup audit](live_host_special_lookup_report.md) [Alternate-mode receiver investigation](live_rpc700_publication_report.md)

```text
launchd service -> cached send name -> libsystem_kernel -> MIG 413
                                                             |
                                                             v
                              host slot table <- kernel replacement
                                    |
                                    v
                       FairPlayIOKit kernel getter
```

## Source identity and running observations

| Component | Verified identity |
| --- | --- |
| PID 1 | CodeDirectory hash `b779f3aea3d6d43ec86b6df216b576a0af4d8f8c`. Selected slice offset 16,384 B |
| Installed launchd arm64e | UUID `96360fc3-2fde-3eee-a403-7dfca7b44ac3`. SHA-256 `d35f01f9669f314a1058e17acca27d3141ba8be1b0ca0d9e9d5edbb787607243` |
| Dyld shared cache | UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`, equal to the UUID queried in the audit process |
| libsystem_kernel | UUID `780a6c1f-be02-34cc-84dd-00e05f61c89b` |
| Boot fileset | SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126` |
| Embedded kernel and FairPlayIOKit | UUIDs `90195379-954d-3ca3-baac-327341f14211` and `316464f8-eade-30ca-938e-2f430b1ed5bc` |

The CodeDirectory hash and reported universal file offset independently select the same installed slice. The original registration report verified a different executable slice and shared cache. The call sites and table below use the current source addresses. The cache UUID query identifies the audit process's cache. PID 1's actual execution of the setter remains unobserved. [Earlier build](host_special_registration_report.md)

| Scope | Endpoint or selection | Host slot | Unslid table cell |
| --- | --- | ---: | --- |
| Live launchd FairPlay job | `com.apple.unfreed`, active | 17 | `0xfffffe000cb4c2d0` |
| Live launchd FairPlay job | `com.apple.arcade.fpsd`, active | 31 | `0xfffffe000cb4c340` |
| Installed kext mode 1 | RPC 502 destination lookup | 17 | `0xfffffe000cb4c2d0` |
| Installed kext alternate mode | RPC 700 destination lookup | 34 | `0xfffffe000cb4c358` |

FairPlayIOKit obtains the host handle at `0xfffffe000a64bd94` and calls its getter at `0xfffffe000a64be48`. The selected static route pairs slot 17 with RPC 502 and slot 34 with RPC 700. The slot 31 evidence in this capture is the launchd association. The kernel computes these cells as `0xfffffe000cb4c248 + 8 * index`. The offset for slot 34 is 272 B, giving `0xfffffe000cb4c358`. All three cells are zero in the boot file. Live launchd state and file-backed initial contents describe different storage. The launchd printout identifies the service declarations. It supplies no reference to the live kernel slot contents. [Kext call bindings](live_fairplay_kernel_rpc_report.md) [Kext mode selection](live_fairplay_constructor_mode_report.md) [Slot observations and public getter control](live_host_special_lookup_report.md)

## Endpoint acquisition and Mach emission

| Stage | Current source site | Data or control flow |
| --- | --- | --- |
| Parse configured index | `0x10005c910` through `0x10005c928` | XPC integer in the range 8 through 36 is written to service +0x54. |
| Read service index | `0x100030498` | Loads service +0x54 into X21. The zero branch skips the publication call. |
| Resolve service send name | `0x10003054c` to `0x100046c48` | Resolves the service's XPC port object. The normal successful helper return comes from the bound `xpc_mach_send_get_right` at `0x100046c78`. |
| Create if needed | `0x10005cc44`, `0x10000cde8`, `0x10005cc50`, `0x10005cc58` | Factory reaches `mach_port_construct`. The returned name enters `xpc_mach_send_create_with_disposition` with disposition 17, and the resulting XPC object is stored at service +0x68. |
| Call setter | `0x10003055c` | Destination name from `mach_host_self`, index from X21, and service send name from the helper. |
| Record in launchd | `0x100030560` through `0x100030598` | A nonzero setter status goes through the logging call at `0x100030594` and rejoins the same indexed cache store at `0x100030564` as status zero. |

The service factory sets the service-port option on its construct call. The earlier SDK-backed endpoint analysis establishes the meaning of the option bits, the disposition-17 XPC initializer, and the normal receive-source setup. The XPC wrapper's adopted send reference and the kernel's copied send reference at publication are distinct operations. [Factory and XPC ownership contract](launchd_service_endpoint_report.md)

The current library exports `host_set_special_port` at `0x1805699e0`. The call at `0x180569a68` reaches `mach_msg2_internal`. The 52 B user request carries the host destination in its header and one copy-send descriptor for the service. The index is the trailing 32-bit scalar. The kernel's internal 64 B form carries the converted descriptor. The reply parser checks ID 513, a noncomplex 36 B reply, and zero in the remote-name field before reading status. The request and reply byte counts are expressed at their respective user or kernel ABI boundary. [Original layout and conversion analysis](host_special_registration_report.md)

## Kernel custody

The kernel's original routine-413 record resolves to `0xfffffe000bdcbdac`. The stub converts the destination through the host conversion helper at `0xfffffe000bdcbe08`, loads the slot index at `0xfffffe000bdcbe10`, and calls the setter front at `0xfffffe000bdcbe50`. The front and subsequent policy wrapper reach the replacement core after their checks. The replacement core takes the host lock before loading the old cell.

| Operation | Current source site | Ownership or storage |
| --- | --- | --- |
| Compute indexed address | `0xfffffe000bd3a0ec` through `0xfffffe000bd3a104` | Host +0x10 plus eight bytes per index. |
| Replace the reference | `0xfffffe000bd3a108` through `0xfffffe000bd3a144` | Load and authenticate the old ordinary value, sign a nonzero replacement for the cell, and store. |
| Release previous ordinary send | `0xfffffe000bd3a1c4` | Invokes `ipc_port_release_send` after lock release. Null and dead sentinels skip the release. |
| Acquire for the getter | `0xfffffe000bd3a4fc`, `0xfffffe000bd3a56c`, `0xfffffe000bd3a578` | Reads the corresponding cell, calls the ordinary send-reference copy helper, then writes through the kernel output pointer. |

The ownership statements describe the successful ordinary branch and its retirement of a previous send reference. Error-path disposal outside the setter and native right counts were outside this capture. [Current kernel caller census](live_rpc700_publication_report.md)

## Assumption register

| ID | Assumption and dependent claim | Falsification probe |
| --- | --- | --- |
| A1 | CodeDirectory membership and file offset identify PID 1's installed slice. The launchd sites depend on this join. | Repeat both kernel process queries, compare process start, and independently recompute candidate CodeDirectory hashes. |
| A2 | The running kernel matches the pinned fileset and the audit process maps the identified cache. This underlies the addresses and ABI evidence. | Rehash the fileset, compare kernel and cache UUIDs, and decode each saved window from original bytes. |
| A3 | The checked blocks describe an ordinary service publication. Native custody and delivery require additional observations. | Correlate an ordinary publication's return, kernel port identity and receiver with the selected FairPlayIOKit lookup. |
| A4 | The inspected `launchctl print` output describes the queried system job during the capture. The active labels depend on this observation. | Repeat the query across ordinary service state changes and compare the endpoint labels and slot fields. |

**High impact.** The same indexed table connects a verified publisher and consumer at the code level. Slot 34's live publisher and receiver remain unknown.

**Medium impact.** The launchd cache store can follow a setter error. A printed association alone cannot establish successful kernel publication.

## Reproduction

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_host_special_publication.py \
  "$KERNEL_COLLECTION" "$LAUNCHD_IMAGE"
```

The audit reads the source images, uses read-only process and job metadata, and checks call targets and the kernel table join. With B mapped input bytes, F parsed fixups, N parsed symbols, and W checked instruction words, extraction takes O(B + F + N + W) time and O(B + F + N + W) space. [Audit script](triage_evidence/audit_live_host_special_publication.py) [Compressed receipt](triage_evidence/live_host_special_publication_audit.json.zst)
