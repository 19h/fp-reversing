# Current host-special Mach lookup for FairPlay RPC 700

On build 26C5035r, the public Mach getter for slot 34 returned status 4 and preserved the caller's output word. The installed kernel's MIG getter converts the destination port to a host-private handle before reaching the slot lookup. FairPlayIOKit obtains that handle inside the kernel. These paths explain how ordinary user-space queries can fail even when launchd reports a host-special service association. The live slot 34 port and RPC 700 receiver remain unknown. [Current FairPlay kernel RPC anchors](live_fairplay_kernel_rpc_report.md)

## Mach entry and kernel slot table

| Interface | Current source site | Observed contract |
| --- | --- | --- |
| Public getter | Mapped libsystem getter entry +0x78 | Emits request ID 412 with 40 B user send size, expects reply ID 512 |
| MIG getter | 0xfffffe000bdcbe78 | Accepts the 48 B internal request shape, converts header destination at 0xfffffe000bdcbec0 and calls the wrapper at 0xfffffe000bdcbecc |
| Getter wrapper | 0xfffffe000bd3a3a4 | Requires a non-null converted handle and an index in 1..36 before additional task predicates |
| Direct kernel getter | 0xfffffe000bd3a480 | Loads the indexed host slot at 0xfffffe000bd3a4fc and stores the selected result through the kernel output pointer at 0xfffffe000bd3a578 |
| MIG setter | 0xfffffe000bdcbdac | Registry record for ID 413 uses a 44 B internal reply and shares the host-private conversion call target |

The original pointer at 0xfffffe000caff030 binds the host-private subsystem at 0xfffffe0007e73228. Its 32 B records for 412 and 413 contain authenticated branch targets. The getter's internal success reply is 52 B, holds one descriptor, and stores its port field at reply +0x24. On getter failure, the stub writes the status at reply +0x28. The mapped user stub handles the 36 B status reply and validates the 40 B complex success reply. Its user output is a task-local Mach name. [Earlier reference ABI](host_special_registration_report.md)

The unnamed converter at 0xfffffe000bd3b240 compares the request destination object with a field at +0x2d0 on the current task, checks port state and type byte 0x19, and validates the converted object's identity against 0xfffffe000cb4c238. On the null-conversion path, the wrapper returns 4 before executing the direct getter. All five observed indices pass the scalar range check. Under normal matching-build MIG processing, a null conversion is consistent with the observed result. The native branch taken remains unobserved.

FairPlayIOKit calls the exact kernel symbol _host_priv_self to obtain 0xfffffe000cb4c238, then calls the exact kernel symbol _host_get_special_port. The slot address is 0xfffffe000cb4c248 + 8 times the index before pointer handling. For an empty ordinary slot, the direct getter invokes the sentinel-preserving callee and writes null with status 0. The file-backed initial words below are eight zero bytes each. Runtime occupancy requires separate evidence. [Prior slot and sentinel analysis](rpc700_namespace_report.md)

    Public host query -> MIG 412 -> host-private conversion -> user wrapper
                                                                   |
                                                                   v
    FairPlayIOKit -> host_priv_self ---------------------> direct kernel getter
                                                                   |
                                                                   v
                                                            host slot table

## Running-build observations

The audit used the reference from mach_host_self and node -1 for all five queries. The same reference returned status 0 and a page size of 16,384 B from host_page_size. The audit then released its host reference successfully. Each output began as 0xffffffff, and each query preserved it.

| Index | Unslid cell | Status | Final output | Association printed by the three inspected jobs |
| --- | --- | ---: | --- | --- |
| 17 | 0xfffffe000cb4c2d0 | 4 | 0xffffffff | com.apple.unfreed, active |
| 31 | 0xfffffe000cb4c340 | 4 | 0xffffffff | com.apple.arcade.fpsd, active |
| 34 | 0xfffffe000cb4c358 | 4 | 0xffffffff | None printed |
| 35 | 0xfffffe000cb4c360 | 4 | 0xffffffff | None printed |
| 36 | 0xfffffe000cb4c368 | 4 | 0xffffffff | None printed |

Both managed-app jobs were idle during the capture. The system daemon listed com.apple.managedappdistributiond.xpc and com.apple.managedappdistributiond.xpc.agent. The GUI agent listed com.apple.managedappdistributionagent.xpc and com.apple.managedappdistributionagent.xpc.legacy. All four endpoints printed active=0 and lacked a host-slot field. A compile-only assertion against the installed host_special_ports.h confirms HOST_MANAGEDAPPDISTD_PORT equals 34. The header SHA-256 is 48f306d2f44ae006e1628b9218b220bd495bf01c56211138d6d73ce1a7a37476. Its service name, live port object and receiver code remain unknown. [Earlier managed-app publication snapshot](rpc700_publication_report.md)

## Assumptions and verification

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The source collection identifies the running kernel. | Unslid registry, conversion and getter addresses. | Check the kernel UUID and rehash the entire collection before comparing instruction windows. |
| The audit task's mapped user stub is the code called by its lookup. | User-side request/reply geometry and emission offset. | Re-read the mapped stub, validate its message constants, and compare the actual send argument registers during an ordinary lookup. |
| The observed call follows normal MIG delivery and the checked kernel record. | Null-conversion explanation for status 4. | Observe the delivered header, converter result and wrapper return branch during an ordinary lookup. |
| Job output is scoped to the inspected launchd domains and capture interval. | Two active FairPlay associations and four inactive managed-app endpoints. | Repeat the same snapshots during ordinary managed-app activity and correlate any newly published association with the receiver. |

The audit independently decodes the immediate of each selected A64 branch and compares it with the disassembler, validates the chained records, and preserves the current instruction windows and timestamped observation. With B collection bytes, F fixups, N symbols and K selected jobs and requests, it uses O(B + F + N + K) time at fixed window sizes and O(B + F + N) space for the static pass. The quality checks cover source identity, exact slots and byte units, outbound Mach ABI, the public host reference control, and the launchd sample's scope. The public getter result cannot measure slot occupancy in this capture, a high-impact limitation for identifying the receiver. [Audit script](triage_evidence/audit_live_host_special_lookup.py) [Compressed receipt](triage_evidence/live_host_special_lookup_audit.json.zst)
