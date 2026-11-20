# RPC 700 host-slot publication and live receiver candidates

The follow-on dependency scan extends the executable-side search to 801 declared shared-cache images. It resolves the three closest ID 700 table candidates and refreshes the current cache host-special getter and setter reference counts. [RPC 700 dependency scan](live_rpc700_dependency_scan_report.md)

On macOS build `26C5035r`, FairPlayIOKit's alternate constructor route still selects host slot 34 for RPC 700. The installed kernel's slot setter accepts a variable index from Mach request 413. A scan of the current fileset found seven direct transfers to the three setter entries, including four with fixed slots 1, 2, 3 and 10. The installed SDK labels slot 34 `HOST_MANAGEDAPPDISTD_PORT`. Both managed-app jobs were running with all four declared XPC endpoints active, and launchd printed no host-slot association for them. The slot's live object, publisher and RPC 700 receiver remain unknown. [Constructor mode selection](live_fairplay_constructor_mode_report.md) [Current host getter and lookup limits](live_host_special_lookup_report.md)

The boot fileset SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. Its embedded kernel UUID `90195379-954d-3ca3-baac-327341f14211` matches the running kernel, and its FairPlayIOKit UUID is `316464f8-eade-30ca-938e-2f430b1ed5bc`. All source addresses in this report are unslid.

## Current publication path

```text
MIG 413                    setter front -> policy -> slot replacement
request index ------------------^                      |
                                                       v
                              host + 0x10 + 8 * index
                                                       ^
FairPlayIOKit alternate mode -> slot 34 getter --------+
                                  |
                                  +-> RPC 700 receiver unknown
```

| Source site | Target | Slot input |
| --- | --- | --- |
| `0xfffffe000bdcbe50` | Setter front `0xfffffe000bd3a224` | Load W1 from request storage at `0xfffffe000bdcbe10`. This is the variable input in MIG request 413. |
| `0xfffffe000bd3a2a8` | Policy wrapper `0xfffffe000bd3a2c0` | Forward W1 from the setter front. |
| `0xfffffe000bd3a3a0` | Replacement core `0xfffffe000bd3a088` | Forward W1 after policy checks. |
| `0xfffffe000bd3ae88` | Replacement core | 1 |
| `0xfffffe000bd3aeac` | Replacement core | 2 |
| `0xfffffe000bd83250` | Replacement core | 3 |
| `0xfffffe000bdcb284` | Policy wrapper | 10 |

The setter front admits unsigned indices 8 through 36 before the caller and port checks. The replacement core's explicit exclusion is index 26 within that range. Its indexed address calculation at `0xfffffe000bd3a0ec` through `0xfffffe000bd3a104` uses 8 B entries after host +0x10. It authenticates a nonzero old pointer, signs a nonzero replacement, and stores the replacement at `0xfffffe000bd3a144`. The old-send release call is at `0xfffffe000bd3a1c4`. Slot 34's logical cell at `0xfffffe000cb4c358` contains eight zero bytes in the fileset. Its value after startup remains unknown. [Earlier host-special registration and policy contract](host_special_registration_report.md)

The census checks 15,564,800 aligned 4 B words across both file-backed executable fileset segments, including kernel and kext code. It checks immediate `B` and `BL` targets and all 1,037,060 decoded chained fixups. None of the fixups targeted the three exact setter entries. The variable-index route, interior targets, computed transfers and any other writer remain outside the fixed-index result. The four immediate callers cannot account for a slot 34 publication.

## Running jobs and executable-side receiver checks

The capture spans `2026-11-19T06:09:41.637485Z` through `06:09:41.709320Z`. All three jobs were running. Two snapshots agreed on job state, PID and the ten printed endpoints. The active `com.apple.unfreed` and `com.apple.arcade.fpsd` endpoints provide positive controls for launchd's slot field.

| Job | Endpoint | Active | Printed host slot |
| --- | --- | --- | ---: |
| `com.apple.fairplayd` | `com.apple.unfreed` | Yes | 17 |
| `com.apple.fairplayd` | `com.apple.arcade.fpsd` | Yes | 31 |
| `com.apple.managedappdistributiond` | `com.apple.managedappdistributiond.xpc` | Yes | None printed |
| `com.apple.managedappdistributiond` | `com.apple.managedappdistributiond.xpc.agent` | Yes | None printed |
| `com.apple.managedappdistributionagent` | `com.apple.managedappdistributionagent.xpc` | Yes | None printed |
| `com.apple.managedappdistributionagent` | `com.apple.managedappdistributionagent.xpc.legacy` | Yes | None printed |

Live CodeDirectory hashes and slice offsets independently select the installed `arm64e` slice of each job. Process start time, hash and slice offset are stable over the observation. The supplemental architecture query independently agrees for the GUI agent and returns `EPERM` for both system daemons. The following static scan includes both arm64e variants of the two managed-app executables.

| Executable | Slice | UUID | Import rows | RPC 700-shaped headers | Passing headers |
| --- | --- | --- | ---: | ---: | ---: |
| `managedappdistributiond` | `arm64e`, running | `87fa0a7a-a279-3ebc-9448-f44f09938b46` | 2,586 | 22 | 0 |
| `managedappdistributiond` | `arm64e.x1` | `99b71f5a-53b0-3c24-9ece-92824766d81f` | 2,586 | 22 | 0 |
| `managedappdistributionagent` | `arm64e`, running | `1fbd34ea-1b52-3f7f-889a-d77d2d4ae985` | 2,586 | 24 | 0 |
| `managedappdistributionagent` | `arm64e.x1` | `e171f291-0d7a-3e5f-9c37-7c7909079dad` | 2,586 | 24 | 0 |

No import row matches the stated host getter/setter, `mach_` or `mig_` name patterns in the four slices. All four import XPC connection creation, event-handler registration and `xpc_connection_send_message_with_reply_sync`, along with dynamic-loading interfaces. The MIG search tests 8 B-aligned common subsystem headers, chained local dispatch pointers to compiler starts, and descriptor-array extents. The original FairPlay RPC 502 table at `0x1010381c0` passes as a positive control. These checks limit the standard MIG executable-side receiver hypothesis. A loaded library, custom demultiplexer or another process remains possible. [Earlier receiver-candidate inventory](rpc700_namespace_report.md) [Managed-app FairPlay interfaces](managed_fairplay_bridge_report.md)

## Assumption register

| ID | Assumption and dependent result | Falsification evidence |
| --- | --- | --- |
| A1 | The fileset identifies the installed kernel and FairPlayIOKit code under examination. This supports the selected entries and direct-transfer census. | Rehash the fileset and compare its embedded UUIDs with the running kernel and kext. |
| A2 | Immediate branch instructions and original chained fixups delimit the caller census. This supports the seven direct transfers and four fixed indices. | Decode the branch words independently and search for an additional exact transfer in the scanned ranges. Dynamic registrations and other writer forms require their own evidence. |
| A3 | The two launchd snapshots cover the same process lifetimes. This supports the active endpoint counts. | Compare PIDs, process starts and signing identities before and after both queries. |
| A4 | The executable implements a receiver using the common MIG schema or one of the searched direct imports. This bounds the negative executable-side result. | Provide a matching local table, import, or recovered alternate dispatch implementation with a reachable RPC 700 case. |
| A5 | Linking a receiver to the alternate kext request requires live slot and request identity. | Correlate a slot publication and receive right with the RPC 700 send and matching receive. |

**High impact.** The variable-index publisher remains the known route capable of selecting 34. The observed managed-app jobs' active XPC endpoints supply no published slot 34 association. The original public getter's status 4 offers no occupancy measurement.

**Medium impact.** On the inspected build, the running managed-app binaries are different from the older slices analyzed for this receiver. The fresh scan also covers the installed alternate slices. Neither the older analysis nor the current executable scan resolves transitive delivery.

## Reproduction

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_rpc700_publication.py \
  "$KERNEL_COLLECTION" "$DAEMON_IMAGE" --native
```

The script reads fileset and executable bytes, invokes read-only job and process identity queries, and compiles one SDK constant assertion without executing a target. With B input bytes, W aligned executable words, F chained entries and I import rows, extraction uses O(B + W + F + I) time and O(B + F + I) working space. The source receipt records compiler extents, branch windows, four tested slice identities, 92 header matches and the positive control. No RPC 700 was sent. [Audit script](triage_evidence/audit_live_rpc700_publication.py) [Compressed receipt](triage_evidence/live_rpc700_publication_audit.json.zst)
