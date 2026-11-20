# Current kernel and FairPlay daemon handoff for Arcade

The [process-launch AST audit](live_arcade_ast_report.md) identifies the ordinary `posix_spawn` and shared `execve` writers for bit 11 and follows their event to the kernel handoff. This resolves the static producer left open in the registration audit. Native event and transaction correlation remain unknown.

On macOS build `26C5035r`, the kernel proper still uses host special slot 31 to send one-way request 41471 to `com.apple.arcade.fpsd`. The request carries a send reference to a kernel registration object. The daemon's 51471 client uses that object as its destination and supplies a send reference to an anonymous daemon endpoint. The kernel stores that reference and uses it for subscription RPC 61471. The installed daemon retains all 27 original ranges used to identify the two server stubs, the registration client and the daemon endpoint setup. The native slot contents, port names, triggering event and transaction outcome are unknown. [Earlier registration analysis](created_port_report.md) [Current launchd slot association](live_host_special_publication_report.md)

```text
kernel pending bit 11
    |
    v
host slot 31 -> 41471 (one way) -> fairplayd named Arcade endpoint
                                        |
         kernel registration object <-- 51471 (anonymous send right)
                                    --> 51571 (status)
                    |
                    v
cached anonymous send right -> 61471 (4,096 B OOL) -> fairplayd
                             <- 61571 (status and result)
```

## Current kernel control and endpoint ownership

The running kernel UUID is `90195379-954d-3ca3-baac-327341f14211`. The audited boot fileset contains that kernel and FairPlayIOKit UUID `316464f8-eade-30ca-938e-2f430b1ed5bc`. All kernel addresses below are unslid and belong to the embedded kernel's code. The [FairPlayIOKit constructor report](live_fairplay_constructor_mode_report.md) separately locates its protected slot 17 and slot 34 selection and its RPC 502 and 700 clients. Those kext sites use different message families and endpoint roles.

| Resource or transition | Current location | Evidence |
| --- | --- | --- |
| Pending event to handoff | `0xfffffe000bd29e80` to `0xfffffe000bd29f84` | The event routine merges the word at thread +0x43c B with the word at `[thread +0x1c0] + 0x4c B`. The bit-11 branch clears mask `0x800` atomically in the thread word and calls the handoff at `0xfffffe000bd29958`. |
| Boot registration-object reference | Cell `0xfffffe0007e68540`, allocator call `0xfffffe000c679138`, release-store `0xfffffe000c67913c` | The allocator takes the cell's address as payload and kind word `0x12b`. Its signing path uses the low eight bits of the kind. The 51471 server checks kind `0x2b` and authenticates the payload at object +0x50 B with modifier tag `0x71`. |
| Named Arcade endpoint lookup | `0xfffffe000bd29ad4` | Calls `_host_get_special_port`, using the same kernel host address produced by `_host_priv_self`, selector 31 in W2 and a local output cell. The getter computes the indexed 8 B cell at `0xfffffe000cb4c340`. |
| One-way send and release | `0xfffffe000bd29b5c` and `0xfffffe000bd29b68` | The kernel builds request 41471 with the slot-derived destination and the registration-object descriptor. It drops the temporary named-service send reference after the send call. The wrapper reaches the common Mach send worker at `0xfffffe000bd3d578`. |
| Pending registration and wait | Pending word `0xfffffe000cbdbe10`, cached endpoint cell `0xfffffe000cbdbe18` | With no usable endpoint, the handoff sets the pending word before the lookup. On a successful one-way send it calls `_lck_mtx_sleep_deadline` at `0xfffffe000bd29b90` using the endpoint cell's address. The inspected completion clears the pending word at `0xfffffe000bd29ba0`. |
| Store the daemon endpoint | `0xfffffe000bd29758` through `0xfffffe000bd298e8` | On the admitted pending path the registration implementation releases a previous valid send reference at `0xfffffe000bd29844`, stores the supplied one at `0xfffffe000bd29848` and reaches the wake helper using the same endpoint cell. |
| Subscription call and release | `0xfffffe000bd29cb0`, `0xfffffe000bdda33c`, `0xfffffe000bd29ce0` | The caller passes an acquired anonymous endpoint reference and a 4,096 B out-of-line record. The client emits through the common kernel RPC path, which passes its message to the shared send worker at `0xfffffe000bd3da9c`. The caller releases its temporary endpoint reference after return. |

The four named storage cells contain zero in the fileset bytes. These are initial file values. The daemon launchd snapshot associates slot 31 with `com.apple.arcade.fpsd`. The association does not supply the populated kernel cell's live value or port-object identity. The kernel diagnostic strings “arcade: received register request” and “arcade: subscription validation upcall returned” corroborate the control-flow roles. [Current collection and instruction receipt](triage_evidence/live_arcade_registration_audit.json.zst) [Endpoint metadata and recovery](live_fairplay_endpoint_recovery_report.md)

## Message pairing and emission

The fileset contains a single occurrence of the 51471/51472 subsystem range marker. It resides at +8 B in the subsystem record at `0xfffffe0007e748d8`. The record advertises a 44 B maximum internal reply. A format-8 chained pointer at `0xfffffe000caff0a0` references the subsystem record. The record's authenticated lookup and routine pointers target `0xfffffe000bdda4f4` and `0xfffffe000bdda404`. The lookup compares the message ID with 51471 and uses the same routine target and discriminator as the table entry. The routine calls the registration implementation at `0xfffffe000bdda4a4` and writes its status at `0xfffffe000bdda4a8`. This establishes the routine and reply-buffer producer. The subsequent audit locates the generic send worker’s queue submission for reply 51571 at 0xfffffe000bd0f208. [Status reply submission](live_arcade_registration_reply_report.md) [Subsystem data and chained pointers](triage_evidence/live_arcade_registration_audit.json.zst)

| Direction and ID | Emission and receiver | ABI evidence |
| --- | --- | --- |
| Kernel to named daemon endpoint, 41471 | Kernel `0xfffffe000bd29b5c` to daemon stub `0x1000053c8` | 52 B internal and 40 B user request. One port descriptor carries the registration-object send reference. Its sender disposition is `COPY_SEND`. The header's reply port is null. |
| Daemon to kernel registration object, 51471 | Daemon `0x100004428` to kernel stub `0xfffffe000bdda404` | 40 B user and 52 B internal request. One port descriptor carries the anonymous endpoint send reference. The daemon uses its MIG reply name. |
| Kernel to daemon reply name, 51571 | Kernel status store at `0xfffffe000bdda4a8`, queue send at `0xfffffe000bd0f208`, daemon validation within `0x1000043b4` | 44 B internal and 36 B user status reply. |
| Kernel to anonymous daemon endpoint, 61471 | Kernel `0xfffffe000bdda33c` to daemon stub `0x1000054d8` | 72 B internal and 64 B user request. One out-of-line descriptor covers the 4,096 B record. The client repeats the count and appends a separate 64-bit scalar. It supplies a 56 B internal reply capacity. |
| Daemon to kernel RPC reply endpoint, 61571 | Daemon stub `0x1000054d8`, kernel reply validation in the client at `0xfffffe000bdda298` | 40 B user success or 36 B user status-only reply. The kernel copies the 32-bit decision on the success path at `0xfffffe000bdda3f8`. The daemon stub constructs the reply, with final send through the generic daemon server path. |

The installed `arm64e` daemon slice UUID is `204741e9-b89f-32b4-9321-51f3975c7cac`. The audited 27 ranges cover 11,172 B and match the original pinned thin file byte for byte. The audit also rechecks 22 named daemon instruction anchors. This preserves the evidence for the service-name comparison, creation of the anonymous CF endpoint, the nested 51471 right transfer and the 61471 responder. The previously analyzed local subscription path takes the input into CoreFP's Arcade XPC service. Native execution of either leg remains unknown. [Original daemon-side right transfer](created_port_report.md) [CoreFP subscription boundary](arcade_subscription_report.md) [Observed daemon slice identity](fairplay_live_slice_identity_report.md)

## Assumptions and verification

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The UUID-matched fileset and named arm64e slice identify the current source cohort. | Preferred addresses, pointer records and daemon code equivalence. | Rehash the fileset and slice, compare both UUIDs, and repeat the original-range comparisons. Effective runtime slides remain unobserved. |
| A2. The observed subsystem pointer and matched daemon stub describe the same message family. | 51471 argument, kind and status pairing. | Require range, size, ID, authenticated routine and literal matches independently. A native send/receive trace with matching object identity would test the runtime join. |
| A3. An admitted registration supplies a usable daemon endpoint before the wait ends. | Successful slot-31 to anonymous-endpoint sequence. | Correlate the pending store, named send, nested registration, published reference and subsequent subscription send during the same native event. |
| A4. The source event enters the bit-11 arm. | Static invocation of the kernel handoff. | Compare the merged event words and parent branch under the same native invocation. Native trigger epoch and reachability remain unknown. |
| A5. The archived trace is the complete local capture of the observed run. | Zero visible Arcade exchanges in that run. | Rehash the trace and reparse its 44 printed Mach message headers. The capture covers guest-visible events for the recorded run. |

High impact attaches to the current-build pairing of the three endpoint roles and the relocation from the older kernel evidence. Medium impact attaches to locating the event gate, deadline wait, publication, reference releases and common send worker. The audit checks nine complete compiler-bounded kernel functions with 1,053 decoded instructions, 45 instruction assertions, 14 direct calls and three subsystem fixups. Five earlier function ranges move by `0x47ef4` B and retain all 589 instruction mnemonics. The audit independently checks current operands and records all current instructions. It finds none of the six Arcade request/reply IDs among the 44 archived messages. Source parsing, hashing and comparison use O(B + I + T) time and space for image and retained-evidence bytes B, instruction count I and trace bytes T. The measured layouts, code identities, assumptions and current-versus-archived boundaries were checked without invoking the protocol. [Audit script](triage_evidence/audit_live_arcade_registration.py) [Compressed receipt](triage_evidence/live_arcade_registration_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_arcade_registration.py \
  "$BOOT_FILESET" "$INSTALLED_FAIRPLAYD" "$REFERENCE_FAIRPLAYD" "$ANNOTATED_TRACE"
```
