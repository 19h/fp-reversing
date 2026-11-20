# Current FairPlayIOKit open initializer and status channels

The running kernel's matching boot collection preserves the two status channels relevant to the archived RAX open. Early service or task rejection can return `0xe00002c2` as a routine error. If the inherited provider constructor returns that same value, the open implementation stores it as the application result and returns routine success on the selected branch. The archived 52 B complex reply with a null connection is consistent with the second channel. The historical host build and exact failure gate remain unknown. [Earlier pinned-collection analysis](kernel_iokit_open_report.md) [Archived trace](zut_trace_report.md)

## Captured open and port custody

The supplied file was rehashed and both headers and their descriptors were decoded from the hex bytes. The host names come from the adjacent bridge log lines. Guest and host names are scoped to different IPC namespaces.

| Capture event | Message and width | Port and result fields |
| --- | --- | --- |
| Guest send, line 1726 | Request 2862, 80 B, complex | Service send name `0x1903` with `COPY_SEND`. Reply receive name `0x507` with `MAKE_SEND_ONCE`. Separate task descriptor `0x203` with `COPY_SEND`. Connection type 0, properties address and extent zero. |
| Bridge exchange, lines 1734–1735 | Request 2862, reply 2962 | Host service name `0x1503`, host reply name `0x1603`. Bridge send returned zero. |
| Guest receive, line 1736 | Reply 2962, 52 B, complex | Local reply name `0x507`, remote name zero, null connection descriptor at +28 B and application result `0xe00002c2` at +48 B. |
| Guest trap result, line 1742 | `mach_msg2_trap` | Returns zero. |

The live cache's `IOServiceOpen` export at `0x184ebdb74` calls its extended stub at `0x184ebdba4`. The stub obtains the reply name at `0x184ebdc20`, writes the service send name and local reply name at `0x184ebdc30` and enters Mach transport at `0x184ebdc6c`. The installed cache addresses describe the current system. The trace gives only the historical guest trap PC and message record, so its exact daemon call site remains unknown. [Current Mach transport](live_iokit_mach_transport_report.md)

A standalone native verifier captured 2862/2962 at the same installed call site. Its public open returned `0xe00002c2` and a null connection. The native and archived open messages match outside the defined port-name fields. [Native message capture](live_iokit_mach_headers_report.md)

The next two successful guest deallocations release references to the service and iterator names. Each is adjacent to a host ID 65 receive. The candidate bridge shows how host name retirement could produce this sequence. The notification bodies and receive-map state remain unknown. [Archived IOKit port retirement](archived_iokit_open_retirement_report.md)

## Current kernel routing and open results

| Stage | Current unslid site | Observed original instruction or data flow |
| --- | --- | --- |
| Open dispatch | Routine record `0xfffffe0007e783d8`, stub `0xfffffe000be81ac4` | Subsystem 2800 index 62 has an authenticated stub entry with discriminator `0x3a83`. The selected stub requires the complex bit, two descriptors and 92 B expanded request size. |
| Convert request rights | `0xfffffe000be81b58`, `0xfffffe000be81bb4` | The first helper takes the request's kernel destination object. The second takes the authenticated task descriptor object. Their internal symbol names are unknown. |
| Call open implementation | `0xfffffe000be81bf4` | Calls `0xfffffe000c5bdc84` with resolved service and task and separate result and connection output addresses. |
| Early task rejection | `0xfffffe000c5bdd34`–`0xfffffe000c5bdd54` | The missing-task comparison and mismatch with the thread-derived task take the `0xe00002bc + 6` routine-result path. The stub stores it at expanded reply +40 B at `0xfffffe000be81c2c`. |
| Provider dispatch | `0xfffffe000c5bddbc` | Calls provider vtable +0x7a0 with task in both owning-task and security-ID arguments, connection type in X3, null properties in X4 and address of its initially null client cell in X5. |
| Application result | `0xfffffe000c5bddc8`–`0xfffffe000c5bdde4` | A nonzero provider result is stored through the application status pointer. The client cell is copied separately. The selected branch returns routine zero. |
| Normal reply construction | `0xfffffe000be81c64`–`0xfffffe000be81ca8` | Converts the client output, writes the descriptor and sets complex, size 64 B in the expanded form, one descriptor. Framework expects 52 B after packing. |
| Framework interpretation | `0x184ebdcc4`, `0x184ebdcd0`, `0x184ebdd3c`–`0x184ebdd48`, `0x184ebdbb0` | Short form expects 36 B and reads its routine status at +32 B. The normal complex form reads application result and connection at +48 B and +28 B. The public wrapper selects the application result when the stub returns zero. |

## Inherited constructor and client state

The current provider vtable slots +0x7a0 and +0x7a8 point to the two `IOService::newUserClient` overloads. The older overload returns `0xe00002c7`. In the selected generic path the five-argument `IOUserClient::initWithTask` is called at `0xfffffe000c51b8e8` through slot +0x910. If its low bit is clear, the caller releases the candidate at `0xfffffe000c51b960`, then computes `0xe00002c7 - 5 = 0xe00002c2` at `0xfffffe000c51b964`. The successful publication at `0xfffffe000c51b94c` is reached only beyond additional checks.

The five-argument initializer at `0xfffffe000c5b2194` calls `IOService::init` at `0xfffffe000c5b21c0`. It then calls the four-argument initializer through slot +0x918 and combines both result words with AND at `0xfffffe000c5b21fc`. For canonical Boolean values, both must be true. The current FairPlay override is `0xfffffe000a545264`.

| Access string read by the override | Lookup call |
| --- | --- |
| `com.apple.private.FairPlayIOKitUserClient.access` | `0xfffffe000a5452a4` |
| `com.apple.private.ProvInfoIOKitUserClient.access` | `0xfffffe000a5452b8` |
| `com.apple.private.FairPlayIOKitUserClient.Virtual.access` | `0xfffffe000a5452cc` |

The override compares returned objects to the `kOSBooleanTrue` singleton. Its accepted paths clear client +240 B, then store 1 there if the returned Virtual access object equals that singleton. A later call at `0xfffffe000a54545c` uses the base IOUserClient initializer. If the task is nonnull and the base result nonzero, the override clears client +216 B, stores the task at +224 B, clears a byte at +244 B and returns 1. These stores are separate from the generic constructor's final client publication. The startup adapter consumes the mode before returning from the provider call. The historical bridge process's entitlement objects and intermediate statuses remain unknown. [Open attachment and owner registration](live_iokit_open_owner_report.md)

## Assumptions and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| O1 | The extracted files identify the running build. This qualifies current code locations. | Rehash the boot collection, compare its kernel and kext UUIDs and confirm the running kernel and cache UUIDs. |
| O2 | The original class slots apply to the selected constructor route. This qualifies the initializer chain. | Decode all seven chained-pointer entries and compare class, slot, symbols and authentication metadata. A different runtime provider invalidates the route. |
| O3 | The archive matches the supplied historical capture. This qualifies the observed reply channel. | Require the exact trace digest, verify header fields and both record extents, then check the adjacent bridge and trap results. |
| O4 | The historical implementation uses the same channels as the current one. This qualifies the comparison. | Identify the historical build and RAX producer, or match the corresponding routine and application status stores in contemporaneous evidence. |

High impact for distinguishing construction, framework decoding and transport during cross-layer correlation. Medium impact for the observed per-client state stores because their downstream use is unresolved. The audit works in O(B + T + I) time and space for collection and fixup data B, trace bytes T and selected instructions I, excluding system query overhead.

QG1 covers factual interpretation. QG2 lists premises and probes. QG3 covers the traced open, both status channels and the current inherited initializer. QG4 checks packed versus expanded widths and u32 status arithmetic. QG5 records the unresolved exact gate. QG6 anchors the instructions, fixups and capture bytes. QG7 bounds the impact above. [Audit script](triage_evidence/audit_live_fairplay_iokit_open.py) [Compressed receipt](triage_evidence/live_fairplay_iokit_open_audit.json.zst)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_iokit_open.py \
  "$CURRENT_COLLECTION" "$RAX_TRACE"
```

The installed diagnostic audit identifies the two initializer failure log sites and compares them with the retained native event window. [FairPlay IOKit diagnostic coverage](live_fairplay_iokit_logs_report.md)
