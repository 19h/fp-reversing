# FairPlay endpoint recovery policy on the running build

The installed launchd image reads the same endpoint flag when it prints `reset` and when it selects a recovery branch after notification 69. A read-only snapshot on build `26C5035r` reported `reset = 0` for all six FairPlay endpoints, including `com.apple.unfreed` at host slot 17 and `com.apple.arcade.fpsd` at host slot 31. If that flag remains clear when the return callback runs, launchd takes the guard assertion and temporary-owner path. The asynchronous destruction branch requires the flag to be set. [Notification 69 registration and return](live_fairplay_receive_right_return_report.md)

```text
MachServices option -> endpoint bit 4 <- launchctl print reads the same bit
                             |
                       notification 69
                             |
             +---------------+---------------+
          bit 4 clear                      bit 4 set
             |                               |
       assert strict guard              queue endpoint reset
       set temporary owner              queue -> destruct captured right
             |                               |
             +-------- shared callback -----+
                      reason 1
```

## Configuration and observed state

The installed FairPlay plist declares six Mach services. Both host-slot entries are dictionaries containing `HostSpecialPort`, and the other four entries have value `true`. None has a `ResetAtClose` option. The plist separately declares `KeepAlive.Crashed = true`. At 11:10:56 UTC on 2026-11-19, launchctl reported one run, running state, and a last-exit field of `(never exited)`. The receipt retains the original plist digest, diagnostic output digest, and selected fields. Raw task-local names are excluded.

| Mach service | Host slot | Active | Managed | Reset | Watching |
| --- | ---: | ---: | ---: | ---: | ---: |
| `com.apple.unfreed` | 17 | 1 | 1 | 0 | 0 |
| `com.apple.arcade.fpsd` | 31 | 1 | 1 | 0 | 0 |
| `com.apple.fairplayd` | | 1 | 1 | 0 | 0 |
| `com.apple.fairplayd.xpc` | | 1 | 1 | 0 | 0 |
| `com.apple.fpsd` | | 1 | 1 | 0 | 0 |
| `com.apple.fpsd.sim` | | 1 | 1 | 0 | 0 |

The selected running PID 1 slice is arm64e, UUID `96360fc3-2fde-3eee-a403-7dfca7b44ac3`. Its Mach-services constructor passes the endpoint into a dictionary callback at `0x100047168`. The callback compares `ResetAtClose` at `0x10005c934` and stores the Boolean in bit 4 of the 16-bit field at endpoint +160 B at `0x10005ca64`. The endpoint printer tests that bit at `0x100047548` and formats `reset = %s` at `0x100047558`. The printer separately reads host slot at +84 B and tests bit 3 of the +160 B field with inverted sense for `managed`. These accesses link the printed values to byte offsets and masks in the inspected image. [Audit receipt](triage_evidence/live_fairplay_endpoint_recovery_audit.json.zst)

## Return callback and right disposition

| Stage | Installed launchd site | Data and control flow |
| --- | --- | --- |
| Capture | `0x100046ed4` through `0x100046ef8` | Check-in constructs a block targeting `0x100047858`, captures the endpoint pointer, and passes the block to notification setup. |
| Invoke and retire notification record | `0x100045e40`, `0x100045e48`, `0x100045e6c` | The event block invokes the captured block, cancels the notification source and unlinks the record. The separate cancel callback tests the record byte at +41 B before deallocating the watched send reference at `0x100045ee8`. |
| Select endpoint recovery | `0x10004786c`, `0x100047870` | The captured block tests endpoint +160 B bit 4. The bit-clear branch obtains the endpoint name, reads the saved 64-bit context from +112 B, asserts the strict guard and marks the receive right temporary owner. |
| Schedule reset when bit 4 is set | `0x1000478d4`, `0x10005ccf0`, `0x10005cd5c`, `0x100047a80` | The selected reset path clears the send-object field at +104 B and queues a block carrying the former object and saved context. The block reads its name and calls `mach_port_destruct` with send-reference delta 0. |
| Update flags and optionally drain | `0x1000478e4`, `0x1000478e8`, `0x10005cf54`, `0x10005cf84` | The shared suffix clears bit 0 and sets bit 6. If the previous bit 8 was set, the drain helper polls the endpoint with send size 0, receive capacity 32 B, timeout 0 and a 20-attempt bound. A successful receive goes through `mach_msg_destroy`. The suffix then clears bit 8 using a fresh flag read. |
| Notify owner and consider rearm | `0x100047924`, `0x10002aa34`, `0x10005ad14`, `0x1000307a0` | The authenticated callback receives the endpoint pointer, reason 1, and the saved owner cookie. The verified ordinary constructor supplies the fixed callback at `0x10002a950`. Its selected deactivation suffix reaches endpoint rearm. |
| Consider pending launch | `0x10005ad18` through `0x10005ad4c`, `0x10005af60`, `0x10005af70` | The selected suffix checks domain +176 B and a pending job reason at +288 B. If eligible, the helper clears that reason and enters the start gate. |

The current bit-8 drain predicate agrees with the archived arm64e and arm64e.x1 instruction bytes. The snapshot identifies bit 4 at print time. It does not expose bit 8 at callback time, identify the effective owner record, or resolve the scheduling order between the mandatory cancel block and a later check-in. The configured crash policy and the selected pending-reason path are independently established. Actual launch policy and the outcome for this job after an exit remain unknown. [Earlier endpoint lifecycle](endpoint_job_lifecycle_report.md) [Original notification capture](triage_evidence/port_destroyed_return_source.json.zst)

## Outgoing Mach interfaces on the bit-clear path

The two public wrappers directly branch to MIG client bodies in the running dyld cache. Both clients emit through the common Mach wrapper. The request prefix is 44 B, composed of a 24 B Mach header, 8 B NDR record, and three 4 B fields for name, flavor and word count. Each attribute word adds 4 B. The SDK compilation separately checks the guard flavor, the temporary-owner flavor, and the 8 B guard structure.

| Operation | Launchd call and arguments | User Mach emission | Kernel stub and operation |
| --- | --- | --- | --- |
| Assert strict guard | `0x10000cf80`, flavor 8, two words containing the saved context | `0x18056ff84`, ID 3242, 52 B | `0xfffffe000bdced70` calls `0xfffffe000bd28e38`. The selected success branch checks the guarded and strict bits and compares the supplied u64 with port +120 B. |
| Mark temporary owner | `0x1000478a8`, flavor 4, zero words | `0x18054b7b8`, ID 3218, 44 B | `0xfffffe000bdd0264` calls `0xfffffe000bd27a50`. The accepted flavor-4 path sets bits 8 and 9 at port +16 B. |

The guard call checks a value already present in the port. The temporary-owner call marks the port for reassignment. The instructions establish those operations and their input contracts. Their actual results for the FairPlay endpoint, the next daemon receive name, and slot 17 object continuity across a restart remain unknown. No restart was induced.

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The captured launchd slice, collection, and cache belong to the audited build. The addresses depend on this identity match. | Reselect PID 1 by CDHash and file offset, verify runtime UUIDs and hash the collection before decoding. |
| A2 | The configured, printed and callback objects refer to the corresponding service endpoint. The prediction from `reset = 0` depends on bit 4 remaining clear through the return. | Verify the constructor capture and all three accesses to the +160 B field. Compare bit 4 at a naturally occurring notification callback. |
| A3 | The fixed owner callback and selected rearm suffix remain reachable for the service at retirement. Its independent guard, domain and pending-reason conditions still apply. | Correlate the owner callback binding, dispatch queue, activation count and pending reason at one natural service exit. |
| A4 | Printed host association and name continuity alone leave host object continuity unknown. | Correlate publication, return, and the next ordinary check-in across the same kernel object lifetime and check for an intervening publication. |

**High impact.** The observed setting selects the preservation path if the endpoint state persists until callback entry. This narrows the native lifecycle observation to guard acceptance, temporary-owner marking, rearm, and subsequent check-in.

**Medium impact.** Optional queue drain and notification-record send-reference retirement can affect what later observation sees. The report locates these operations and leaves their native occurrence open.

## Reproduction and quality gates

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_endpoint_recovery.py \
  "$KERNEL_COLLECTION" "$LAUNCHD_IMAGE" "$FAIRPLAY_JOB_PLIST"
```

The audit reads the installed bytes, queries one launchd job, and compiles six SDK assertions. It verifies 111 decoded instruction anchors across launchd, the two libsystem_kernel client paths, and the kernel. It also checks both archived drain instructions. For B input bytes, F fixups, N symbols, and I retained instruction words, time and working space are O(B + F + N + I). Processing the query is linear in the length of its response.

| Gate | Verified item |
| --- | --- |
| QG1 | Findings use original bytes and observable system fields. |
| QG2 | A1 through A4 give separate falsification probes. |
| QG3 | Evidence covers endpoint configuration, notification dispatch, receive drain, outgoing attribute calls, and the conditional rearm path. |
| QG4 | Flag widths, guard extent, attribute word width, and the 44 B and 52 B request layouts are explicit. |
| QG5 | The archived and current drain tests agree. The print snapshot, callback branch prediction, and native restart remain separately scoped. |
| QG6 | The receipt preserves image identities, original instruction words, authenticated MIG entries, and the selected native diagnostic fields. |
| QG7 | The consequences of temporary-owner marking, optional drain, and right retirement are bounded by the observed state. |

[Audit script](triage_evidence/audit_live_fairplay_endpoint_recovery.py) [Compressed receipt](triage_evidence/live_fairplay_endpoint_recovery_audit.json.zst)
