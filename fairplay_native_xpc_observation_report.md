# Native FairPlay IPC observation

Native unified logs on macOS build `26C5035r` identify `akd` as the client of 141 accepted `com.apple.adid` XPC peers. The logs and the installed binaries agree on the running `akd` and `adid` image UUIDs. The capture supplies a positive control for this named-service connection lifecycle. Delivery of FairPlayIOKit RPC 502 to `fairplayd`, return of RPC 602 to the kext, and a native `fairplayd` request to `adid` remain unknown.

| Edge | Native observation | Corresponding static or historical evidence |
| --- | --- | --- |
| `akd` to `adid` | 141 client activations for `com.apple.adid` and 141 server peer activations naming the `akd` PID. Application requests and replies are unknown. | Named client operations and synchronous send recovered from an earlier `akd` image. [Client contract](akd_adid_client_report.md) |
| `fairplayd` to `adid` | Zero named client events and zero `adid` peer activations naming the observed `fairplayd` PID. Native traffic is unknown. | Current daemon client creation at `0x100e21578`, synchronous send at `0x100e21718`, retry at `0x100e218dc`, and `adid` listener creation at `0x10001a7b4`. [Current client and listener](live_fairplay_adid_ipc_report.md) |
| FairPlayIOKit to `fairplayd` and back | Zero scoped log records tagged with the service, kext or RPC terms. Native delivery and reply are unknown. | The kernel send site at `0xfffffe000bd3da9c` uses the host-special destination. Slot 17 is associated with `com.apple.unfreed`. The RPC 502 daemon stub at `0x1000050c8` builds RPC 602 at `0x100005274` and sends via `_mach_msg` at `0x100035184`. [Service rights](fairplay_live_service_rights_report.md) [Current RPC ABI](live_fairplay_rpc_abi_report.md) |
| Historical RAX `fairplayd` to FairPlayIOKit | Separate guest trace ends its IOKit open with `kIOReturnBadArgument` and a null connection name. Its 22 send/reply pairs include no send with ID 2865, 502 or 700. | Bounded daemon-side observation. [Annotated trace](zut_trace_report.md) |

## Native connection records

The fixed interval was 2026-11-19 04:09:20 through 05:09:20 UTC. The `com.apple.xpc` connection category contains 408 records for `akd`, 306 for `adid`, and zero for `fairplayd`. The selected `akd` PID was 879, `adid` was 910, and `fairplayd` was 3903. The recorded installation UUIDs are `3792B96B-3BC1-34FB-85BB-10ECB1541CE2` for `akd` and `4D24325F-3529-39B1-BBF8-64BBCF406049` for `adid`. Both match installed `arm64e` slices. The older named-client `akd` source has UUID `43016122-1388-34E5-A9AA-208D90ED00F8`, so its function addresses are scoped to that source. [Native observation receipt](triage_evidence/fairplay_native_xpc_observation.json.zst) [Earlier client source identity](akd_adid_client_report.md)

| Recorded operation | Endpoint metadata | `libxpc.dylib` sender PC | Count |
| --- | --- | ---: | ---: |
| Client activation | `akd`, `mach=true listener=false peer=false`, name `com.apple.adid` | `0xb358` | 141 |
| Accepted peer activation | `adid`, `mach=false listener=false peer=true`, name begins `com.apple.adid.peer[879]` | `0xb358` | 141 |
| Peer invalidation | `adid` object matches its activation. The log reports client cancellation or exit. | `0x164c8` | 141 |

These PCs are `senderProgramCounter` values for the logged `libxpc.dylib` image, UUID `94E40B03-44C5-3636-AA1A-C64A5D6B6BBB`. They locate logging sites. Mach send and receive names, dispositions, message IDs, dictionary contents, caller PCs and which invalidation cause applied remain unknown. All 153 captured `adid` peer objects, including 12 naming other PIDs, pair with an invalidation by server object identity and client PID. The receipt omits the process-local object addresses used for that pairing.

| Maximum forward interval (us) | Mutually unique client/peer activation pairs |
| ---: | ---: |
| 100 | 0 |
| 250 | 101 |
| 500 | 127 |
| 1,000 | 125 |
| 5,000 | 79 |
| 20,000 | 67 |

The 1,000 us window retains 125 pairs. Twelve activations on each side have no eligible partner in that window, and four on each side lack a mutually unique assignment. The retained log-time differences range from 115 to 741 us, with a median of 202 us. The corresponding server-object lifetimes range from 639 to 1,651,492 us, with a median of 15,540 us. The timestamp rendering has 1 us resolution. Logger scheduling and timestamp placement impose an unknown error on any estimate of transport latency.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | The logged PID identifies the live `akd` instance throughout the window. This supports server-side client attribution. | Confirm a single boot in the XPC records, match log and process IDs, and verify the matched process start precedes the window and is stable across collection. |
| A2 | A mutually unique forward timestamp candidate is a plausible counterpart. This supports the 125 retained pairings and their timing statistics. | Vary the window over 100 to 20,000 us and reject ambiguous candidates. A shared transaction ID or kernel object observation could confirm or refute each association. |
| A3 | The labels identify the service and connection lifecycle recorded by libxpc. This supports the observed XPC edge. | Require exact client and peer activation labels, match server invalidations by object identity and peer PID, and verify the logged executable UUIDs against installed images. |
| A4 | The query observes retained records at the requested info visibility. This bounds each zero count. | Query all retained `fairplayd` records for the same interval in addition to the terms shown in the receipt. Confirmation of RPC 502/602 delivery requires an independent observation that joins the request and reply. |

## Reproduction and coverage

```sh
python3 triage_evidence/audit_fairplay_native_xpc_observation.py 2026-11-19T04:09:20Z 2026-11-19T05:09:20Z
```

The capture reads existing logs and installed-image metadata. For N log records, C selected client records, P peer records and W window widths, the reducer takes O(N log N + W(C log P + P log C)) time and O(N + C + P) working space. Candidate intervals can also be recomputed from the two timestamp vectors retained in the receipt after the system logs rotate. [Audit](triage_evidence/audit_fairplay_native_xpc_observation.py) [Compressed receipt](triage_evidence/fairplay_native_xpc_observation.json.zst)

High impact attaches to the client attribution and installed-image UUID match, which establish a native comparator for the two unresolved FairPlay edges. The timestamp join has medium impact because it ties activation timing to server object retirement for a subset. The zero log counts have low diagnostic impact. A correlated record of slot-17 delivery, daemon handler selection, and the return to the waiting kernel client would establish the remaining direct RPC join.
