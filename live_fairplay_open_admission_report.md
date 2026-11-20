# Native FairPlayIOKit open denial and entitlement lookup

A public type-zero `IOServiceOpen` call from a standalone verifier reached the FairPlayIOKit initializer's missing-entitlement branch. The driver logged the diagnostic on the verifier's calling thread between two markers around the open. The public call returned `0xe00002c2` and a null connection. All three pre-open Security framework queries on the verifier's own task returned no value and no error. This identifies the native verifier's rejection site. The historical RAX daemon exchange has the same application result, while its specific kernel branch remains unknown. [Native Mach headers](live_iokit_mach_headers_report.md) [Archived open](live_fairplay_iokit_open_report.md)

## From the owning task to AMFI

Installed sites are unslid. The auditor pins kernel UUID `90195379-954d-3ca3-baac-327341f14211` and boot collection SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. The live kext list confirms FairPlayIOKit UUID `316464f8-eade-30ca-938e-2f430b1ed5bc` and AppleMobileFileIntegrity (AMFI) UUID `7f801ed8-bced-3049-a63e-8db71f0ba765`. [Installed open routing](live_fairplay_iokit_open_report.md) [Apple XNU entitlement lookup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L1482-L1511)

| Boundary | Installed data and control flow |
| --- | --- |
| FairPlayIOKit initializer | The initializer holds the owning task in X20, supplies it as X0 at each of the three calls, and preserves the returned objects in X25, X24 and X21. All three calls resolve through the veneer at `0xfffffe000a6e0324` and authenticated slot `0xfffffe0008492e98` to `IOUserClient::copyClientEntitlement`. |
| Kernel IOKit wrapper | `0xfffffe000c5b7930` calls `get_bsdtask_info`. The kernel passes the resulting `proc_t`, the NUL-terminated key and an address for the object pointer to the AMFI function loaded from table +0x1e8 B. The call at `0xfffffe000c5b7950` uses discriminator `0xbcad`. The wrapper selects the object on status zero and returns null otherwise. |
| Provider registration | AMFI's `initializeCoreEntitlementsSupport` passes its `_AMFI` table at `0xfffffe000829ab40` to the registration veneer at call site `0xfffffe0009b510f0`. The kernel register function publishes the pointer to global `0xfffffe0007f8e0c0` at `0xfffffe000c4ee3b4`. The table's authenticated entry `0xfffffe000829ad28` binds the lookup to `OSEntitlementsBridge_copyValueWithProc` at `0xfffffe0009b518c8`. |
| Object lookup | The bridge obtains the process's entitlement object, calls its secure accessor, and forwards the original key and output address. The value bridge calls `OSEntitlements::copyValue` at `0xfffffe0009b51874`. It stores a returned object at `0xfffffe0009b51888`; a null result takes status `0x38`, which the IOKit wrapper maps to a null object. |

| Lookup call | Requested key | Native self-task query |
| --- | --- | --- |
| `0xfffffe000a5452a4` | `com.apple.private.FairPlayIOKitUserClient.access` | No value or error |
| `0xfffffe000a5452b8` | `com.apple.private.ProvInfoIOKitUserClient.access` | No value or error |
| `0xfffffe000a5452cc` | `com.apple.private.FairPlayIOKitUserClient.Virtual.access` | No value or error |

The verifier calls `SecTaskCreateFromSelf` and queries the same three strings immediately before the open. The user-space queries describe the verifier's task. The kernel diagnostic supplies the independent evidence that all three kernel lookups returned null. The missing-entitlement diagnostic alone leaves AMFI's individual lookup statuses unknown. [Apple Security framework entitlement API implementation](https://github.com/apple-oss-distributions/Security/blob/main/sectask/SecTask.c#L331-L349)

## Diagnostic and status attribution

The initializer tests three object pointers at `0xfffffe000a5452d4`, `0xfffffe000a5452d8` and `0xfffffe000a5452dc`. When all are null it calls `IOLog` at `0xfffffe000a5452e8`, then returns false. A present object takes the comparisons with the kernel Boolean singleton and has a separate invalid-entitlement diagnostic. The inherited constructor releases the rejected candidate and subtracts 5 from `0xe00002c7` at `0xfffffe000c51b964`, yielding `0xe00002c2`. The separate Mach capture identifies this application-result channel in complex reply 2962. [Original diagnostics and caller PC](live_fairplay_iokit_logs_report.md) [Native open reply](live_iokit_mach_headers_report.md)

| Stream event in Mach timestamp order | Process attribution | Thread attribution and sender location |
| --- | --- | --- |
| Begin marker immediately before the call | Verifier PID | Issuing thread |
| `[FairPlayIOKitUserClient::initWithTask] Error: entitlement not found` | Kernel, PID 0 | Same thread ID. FairPlayIOKit image UUID and sender offset `0xf8c` B. |
| End marker immediately after the call | Same verifier PID | Same issuing thread |

The driver offset calculation is `0xfffffe000a5452ec - 0xfffffe000a544360 = 0xf8c` B, using the return PC and the driver's `__TEXT_EXEC` base. The distinct invalid-entitlement diagnostic has offset `0xfe0` B. The matching UUID, offset, strict marker interval and thread ID join the kernel event to this verifier call even though the log attributes it to PID 0. The live stream leaves the boot UUID field empty. The audit identifies the booted kernel separately through `kern.uuid`. [XNU IOKit logging implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOLib.cpp#L1388-L1429)

## Assumptions and verification

| Premise and dependent result | Falsification probe |
| --- | --- |
| The loaded kernel and kexts match the selected collection and logger ABI. | Recheck the fileset digest, loaded UUIDs, authenticated imports, registered table entry and original call sites. |
| The log's sender offset is relative to the driver's executable segment and reflects the return address supplied by IOKit. | Recompute the offset from `__TEXT_EXEC`, demand the exact driver UUID and distinguish the two diagnostic offsets and strings. |
| The kernel record falls within the synchronous open on the verifier's thread. | Require both markers, strict Mach timestamp ordering and the same thread ID in all three events. Repeat with a new verifier process. |
| The application's status is comparable to the RAX result. | Decode both reply forms and distinguish the routine and application fields. Historical diagnostic records or an equivalent branch trace are required to assign the RAX failure to a specific site. |

High impact for attributing the native denial and identifying the task-to-AMFI interface. Medium impact for distinguishing the missing and invalid cases when auditing daemon behavior. The final entitlement objects and successful FairPlayIOKit transactions for native `fairplayd` remain unknown. The receipt keeps only the three self-query outcomes and the correlated event records. For fileset size B, fixup and symbol records F, and returned log bytes L, parsing uses O(B + F + L) time and space, excluding system query costs. Run `python3 -B triage_evidence/audit_live_fairplay_open_admission.py "$KC" --observe` with the pinned fileset and SDK. [Auditor](triage_evidence/audit_live_fairplay_open_admission.py) [Compressed receipt](triage_evidence/live_fairplay_open_admission_audit.json.zst)
