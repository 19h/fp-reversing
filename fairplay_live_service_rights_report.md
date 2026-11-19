# Live FairPlay Mach service names and send rights

All seven Mach services declared by the `fairplayd` and `adid` system jobs were active in `launchctl print` and accessible by name from the audit process's bootstrap namespace. Each lookup delivered a task-local send right. The same two PIDs were present as separate user-client creators under FairPlayIOKit registry service `0x1000002fb`. The capture links both daemons to their launchd and IOKit roles without assigning the bootstrap names to IOKit connection objects. [Live image and registry identities](fairplay_live_slice_identity_report.md)

| System job | Declared name | Port printed by launchctl | Send name in audit task | Declared host slot |
| --- | --- | --- | --- | --- |
| `com.apple.adid` | `com.apple.adid` | `0x95f13` | `0x1c0f` | |
| `com.apple.fairplayd` | `com.apple.fairplayd` | `0xe6e23` | `0x1d07` | |
| `com.apple.fairplayd` | `com.apple.fairplayd.xpc` | `0xe6f93` | `0x1b07` | |
| `com.apple.fairplayd` | `com.apple.fpsd` | `0xe7173` | `0xe03` | |
| `com.apple.fairplayd` | `com.apple.fpsd.sim` | `0xeed9f` | `0xf03` | |
| `com.apple.fairplayd` | `com.apple.unfreed` | `0x2703` | `0x1003` | 17 |
| `com.apple.fairplayd` | `com.apple.arcade.fpsd` | `0x2603` | `0x1a13` | 31 |

The table is a single build `26C5035r` capture. The installed launchd plists and two matching job snapshots supply the name and slot columns. Each initial `bootstrap_look_up` returned success, `mach_port_type` reported `0x10000` (send right), and `mach_port_get_refs` reported one send user reference. Repeating each host-slot service's bootstrap lookup in the same task reused its name and increased its send user-reference count to two. All nine acquired references were released, after which the seven names returned `KERN_INVALID_NAME`. The observed references therefore belong to the audit process and are no longer valid there. [Apple launchd lookup interface](https://github.com/apple-oss-distributions/launchd/blob/main/src/protocol_jobmgr.defs) [Apple XNU Mach port kinds](https://github.com/apple-oss-distributions/xnu/blob/main/doc/mach_ipc/port_types.md)

Ordinary `host_get_special_port` calls using the audit process's host right and `HOST_LOCAL_NODE` returned `KERN_INVALID_ARGUMENT` (4) for slots 17 and 31, with null output. The reason for this build's native query result and the live kernel objects behind those slots remain unknown. The earlier slot-17 KEXT path and slot-31 arcade registration chain are separate static evidence. [Apple XNU host slot definitions](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/host_special_ports.h) [Kernel port resolution](kernel_port_resolution_report.md) [Arcade registration](created_port_report.md)

## Source locations and evidence boundaries

The five non-XPC `fairplayd` names correspond to the original `bootstrap_check_in` call at `0x10044038c` and the CFMachPort wrapper at `0x100001fdc`. The XPC name has its own listener creation at `0x1000935e4` and activation at `0x1000b28c8`. The `adid` name has listener creation at `0x10001a7b4` and activation at `0x10001a980`. These are preferred PCs. A service lookup acquires a send right via bootstrap. It supplies no evidence of user payload reaching the daemon's listener or of the daemons' task-local receive names. [FairPlay check-in](daemon_registration_report.md) [FairPlay XPC listener](daemon_xpc_listener_report.md) [ADID startup listener](adid_startup_report.md)

The older launchctl capture shows different printed numbers for all six FairPlay names and the same two host-slot associations. The historical RAX numbers refer to its guest namespace. For example, `0x1003` was a guest port set in that trace and a send name in this audit task. Daemon request and reply rights, kernel object identities and live selector 26 traffic remain unknown. [Earlier native snapshot](kernel_port_resolution_report.md) [RAX trace](zut_trace_report.md)

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| The two launchd job snapshots and two registry captures span stable processes and endpoints. | Shared PID attribution. | Check each PID and registry ID and compare the job endpoint fields before and after lookup. |
| All comparisons of returned send names occur in one inspection task while the references are held. | Coalescing and distinct simultaneous names. | Repeat the two lookups, query user-reference counts and confirm name retirement after release. |
| Installed plist declarations describe the selected jobs' MachServices. | Service name and slot correspondences. | Compare all seven declarations with the active job endpoint names and host-slot fields. |

The audit takes O(J + E) input work for J job-output bytes and E endpoint lookups, with O(E) simultaneous right bookkeeping and one release per acquired reference. Bootstrap publication visibility has high impact on selecting endpoints for trace correlation. Direct equality with the live host-slot objects remains a high-impact open join. [Audit script](triage_evidence/audit_fairplay_live_service_rights.py) [Compressed observation](triage_evidence/fairplay_live_service_rights_observation.json.zst)
