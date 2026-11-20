# FairPlayIOKit open and method diagnostics

Three log sites in the installed FairPlayIOKit driver cover two initializer failures and a provider error returned from selector 26. The selected native log window contains 96 retained events, including 80 attributed to the PID on the live `lskdd` client attachment and 16 to the PID on the `adid` attachment. None names the driver image or matches those three diagnostics. The log query supplies no open request, method call or reply that can be paired with a native client. [Client-class and registry audit](live_fairplay_client_class_report.md) [Earlier native XPC observation](fairplay_native_xpc_observation_report.md)

## Emission sites on the installed build

| Logged branch | Kext `IOLog` call | Return PC passed through the veneer | What a matching record would show |
| --- | --- | --- | --- |
| `initWithTask` reports the entitlement missing | `0xfffffe000a5452e8` | `0xfffffe000a5452ec` | Execution reached that initializer failure. |
| `initWithTask` reports the entitlement invalid | `0xfffffe000a54533c` | `0xfffffe000a545340` | Execution reached the distinct invalid-entitlement failure. |
| `ucSendFPMessage` reports a provider error | `0xfffffe000a545234` | `0xfffffe000a545238` | The provider call at `0xfffffe000a54521c` returned nonzero to the method wrapper. The wrapper passes the status to `IOLog` and returns it to its caller. |

All three call the veneer at `0xfffffe000a6e0264`, which tail-branches through the authenticated import at `0xfffffe0008492e38` to `IOLog`. The kernel moves the original link register into X4 at `0xfffffe000c50a1f8`, strips its authentication at `0xfffffe000c50a1fc`, and forwards it to the logger at `0xfffffe000c50a25c`. Published XNU gives that argument the caller role in `os_log_with_args`. The three return PCs are static attribution candidates. No corresponding native `senderProgramCounter` was available for comparison. [XNU IOKit logging implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOLib.cpp#L1388-L1429)

The successful initializer continues toward owner registration and connection export elsewhere. For selector 26, a zero provider result branches around the diagnostic to the normal result stores at `0xfffffe000a545240` and `0xfffffe000a545248`. These diagnostics therefore have no success counters. Any future match would still need a transaction identifier or contemporaneous transport evidence to pair it with the caller's request and reply. [Open status channels](live_fairplay_iokit_open_report.md) [Selector 26 method mapping](live_kext_selector26_report.md)

## Retained native window

The fixed interval is 2026-11-20 16:57:50 to 16:59:50 UTC, spanning the observed `lskdd` launch. The predicate selects the four named FairPlay client processes, the driver sender image name, and records containing `FairPlayIOKitUserClient`. The read included retained info and debug records. All selected events with a boot UUID agree on one boot. The registry query was taken separately after the covered interval, so the PID join establishes process correspondence with a later attachment. The attachment creation time is unknown.

| Process | Retained events | Events with observed attachment PID | Attached object at registry read |
| --- | ---: | ---: | --- |
| `adid` | 16 | 16 | PID 910, `0x10000130b` |
| `fairplayd` | 0 | 0 | PID 3903, `0x100001702` |
| `lskdd` | 80 | 80 | PID 88947, `0x10026cc8c` |
| `fairplaydeviceidentityd` | 0 | 0 | No matching attachment in this snapshot |

The historical RAX capture separately establishes a Mach-successful open reply `2962` with a null connection and application status `0xe00002c2`. No request `2865` appears among its 22 printed guest sends. Neither the current diagnostic query nor the archived reply identifies the historical failure branch. [Annotated open and retirement](archived_iokit_open_retirement_report.md)

## Assumption register

| Assumption | Dependent claim | Falsification probe |
| --- | --- | --- |
| A1. The pinned boot collection applies to the installed kernel and driver. | Diagnostic text, calls and logger argument provenance. | Rehash the collection, recheck bytes, compare UUIDs and independently decode the veneer and `IOLog` instructions. |
| A2. The chosen predicate includes retained records from the named processes and the selected driver sites. | Counts and zero matches within the returned records. | Repeat the fixed query while the logs are retained, compare its event totals and verify sender image and matching-prefix counts. Log persistence and completeness remain unknown. |
| A3. The attachment PID was stable between the logged interval and the registry read. | PID-level correlation for `adid` and `lskdd`. | Confirm process start time and image identity at both observations. A creation timestamp for the registry entry would be needed for event-level joining. |
| A4. The archived trace retains the printed guest sends and original reply header. | The failed open and zero printed synchronous method sends. | Rehash and reparse the archive and verify the output descriptor and application status independently. |

High impact attaches to identifying exactly which branches can produce each diagnostic. The zero matches have low diagnostic weight because the successful paths shown here bypass the three sites and retention is bounded. For B fileset bytes, T trace bytes and L returned log bytes, audit reduction takes O(B + T + L) time and storage, excluding the operating system's log-store scan. [Auditor](triage_evidence/audit_live_fairplay_iokit_logs.py) [Compressed receipt](triage_evidence/live_fairplay_iokit_logs_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_fairplay_iokit_logs.py \
  "$BOOT_FILESET" "$ANNOTATED_TRACE" --log-window 2026-11-20T16:57:50Z 2026-11-20T16:59:50Z
```
