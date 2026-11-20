# Current IOKit Mach request and reply boundaries

The installed arm64e dyld cache has UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`, also returned by the dyld runtime query in the analysis process. Its IOKit image has UUID `82be1de5-91c4-3152-b63b-81db4c5e7992`, and its libsystem_kernel image has UUID `780a6c1f-be02-34cc-84dd-00e05f61c89b`. That identifies the framework bytes inspected here. The current `fairplayd` task's mapped cache UUID and numeric Mach port names remain unknown. [Live registry observation](daemon_iokit_native_registry_report.md)

The installed `IOConnectCallStructMethod` export is at `0x184ebedb0`. It calls `IOConnectCallMethod` at `0x184ebdd74`. The synchronous method RPC reaches a transport veneer at `0x188088af0` from `0x184ebe090`. The current libsystem_kernel `_mach_msg2_internal` is at `0x18055b918`, and its Mach trap veneer executes `svc #0x80` at `0x180548c1c` with X16 equal to −47. These are preferred unslid addresses in the inspected cache.

At `0x184ebe054` the framework stores header word `0x1513` and the request extent. At `0x184ebe05c` it writes the existing connection name and the reply name into separate header fields. The ordinary method request uses COPY_SEND for the connection destination and MAKE_SEND_ONCE for the reply right. The connection name belongs to the issuing task. The reply returns through the separate receive name used by the call. [Pinned IOKit reply contract](iokit_sync_error_reply_report.md)

## Request emission and rights

All three stubs use the same authenticated transport binding at cache slot `0x1e20f37a0`. The slot is a member of the original v5 slide chain and resolves to the exact libsystem_kernel transport symbol. The first trap call in that transport is at `0x18055b960`; the common trap instruction is at `0x180548c1c`. The open stub also carries the caller-supplied task name as a COPY_SEND port descriptor at request +28 B. The close request uses the connection name from the public call. The method destination is the existing connection supplied through the synchronous method call.

| Request and expected reply IDs | Framework call to transport | Request remote field | Request local field |
| --- | --- | --- | --- |
| 2862 / 2962, open | `0x184ebdc6c` | Service name, COPY_SEND | Separate reply name, MAKE_SEND_ONCE |
| 2865 / 2965, method | `0x184ebe090` | Connection name, COPY_SEND | Separate reply name, MAKE_SEND_ONCE |
| 2816 / 2916, close | `0x184ec1a44` | Connection name, COPY_SEND | Separate reply name, MAKE_SEND_ONCE |

The open and close stubs construct 80 B and 24 B user requests respectively. In the method wrapper, the input length and output capacity take the inline branches at or below 4096 B. At zero scalar input, the method request size is `84 B + align4(input length)`, yielding 100 B for a 16 B descriptor. At `0x184ebe064`–`0x184ebe068`, an eight-byte constant supplies voucher zero and ID 2865. At `0x184ebe06c` X3 receives the two adjacent u32 header names, and at `0x184ebe074` X5 takes the reply name in its upper 32 bits. [Current selector and outer counts](live_kext_selector26_report.md)

The method call obtains its reply name at `0x184ebe04c` through a distinct authenticated slot at `0x1e20f39f8` resolving to `_mig_get_reply_port` at `0x180548f00`. At `0x180548f14`–`0x180548f20` the helper reads the current thread's register-derived storage at +0x10 B and returns the existing nonzero name. When that cell is zero, the helper calls `mach_port_construct` at `0x180548f4c` and stores the returned name at `0x180548f58` on the success path. This gives the allocation-request and name-reuse sites separately from message emission.

## Kernel reply production, queue handoff and userspace receive

The current collection is the one identified by kernel UUID `90195379-954d-3ca3-baac-327341f14211` and decompressed SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. That kernel UUID matches `kern.uuid` during the audit. The current RPC routine record binds message 2865 to stub `0xfffffe000be8152c`. [Current FairPlayIOKit collection](live_kext_selector26_report.md)

| Boundary | Current PC | Data and control |
| --- | --- | --- |
| Common kernel RPC dispatcher | Calls at `0xfffffe000bd0f2fc` and `0xfffffe000bd0f364` | Both call `0xfffffe000bd3c048` with the message and its kernel destination object. |
| Short reply frame | `0xfffffe000bd3c45c` and `0xfffffe000bd3c654` | Seed 44 B. Copy request header +16 B reply object into reply header +8 B. Clear the reply header's other port and voucher. Set ID to request ID +100. |
| Current MIG dispatch | `0xfffffe000bd3c724` | Load stub from the routine record and call with discriminator `0x3a83`. |
| Short result | `0xfffffe000be816e8` | Store the u32 method status at reply header +40 B after the selected method fails. |
| Generic reply continuation | `0xfffffe000bd3c78c`–`0xfffffe000bd3c794` | Load the status and proceed past the no-reply check for ordinary status values other than −305. |
| Common reply queue request | `0xfffffe000bd0f208` | Call queue helper `0xfffffe000bd0fbf0` with reply destination +0x28 B in X0 and the reply message in X1 under the selected conditions. The destination object is read from reply header +8 B. |
| Queue insertion branch | `0xfffffe000bd0fe8c` | Call the ring insertion helper at `0xfffffe000bd0ab5c`. The selected branch writes the reply into the empty or nonempty ring. Native queue state and waiter delivery are unknown. |
| Simple header packing | `0xfffffe000bd0e5ec`–`0xfffffe000bd0e610` | Pack the converted name and header fields at +8 B in the same storage. Kernel message size 44 B becomes 36 B, and RetCode is at user +32 B. |
| Framework status selection | `0x184ebe0dc`–`0x184ebe120` | Match ID 2965, simple-message bit, null received remote name, exact 36 B size and nonzero status. The normal short-result branch selects the body status. |

The copyout path uses the converted local receive name and a null received remote name for the short result. The reply object in the kernel header and the name in the caller's namespace are different representations. The registry ID identifies a user-client registry entry. The current numeric Mach names and right lifetime for that client are unknown. [Pinned queue contract](kernel_queue_send_report.md) [Pinned user copyout](kernel_user_copyout_report.md)

The supplied RAX trace records open request 2862 and a null connection in reply 2962. It has no method request 2865. The current transport map is derived from original installed and boot files; it provides call sites for a future correlation. [Supplied trace](zut_trace_report.md)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| LM1 | The installed cache and boot collection identify the inspected host components. Location claims depend on those images. | Check cache UUID in the process, framework and libsystem_kernel image UUIDs, boot-file hash and runtime kernel UUID. The mapped cache for `fairplayd` still requires a process-specific observation. |
| LM2 | The call uses the ordinary synchronous stub, valid right dispositions and successful kernel object conversion. Construction and request destination claims refer to that path. | Check framework PC, two header names and dispositions, request ID and selected connection object in one passive transaction. |
| LM3 | The kernel method returns an ordinary nonzero status, the reply object and queue satisfy the selected guards, and copyout succeeds. The queue and short-result rows depend on these conditions. | Observe the stub store, reply object transfer, queue handoff or direct receive, user header and returned body status in the same transaction. |
| LM4 | Original cache slide and kernel fixup records identify the logical pointer targets used by the selected branches. | Walk the source chains, recompute pointer targets and compare the selected target with a runtime observation. |

The [audit](triage_evidence/audit_live_iokit_mach_transport.py) checks twenty cache windows, thirteen kernel windows and two original v5 slide bindings. Seven independently compiled arm64e SDK assertions check the two disposition constants, 24 B user header, name offsets, 36 B MIG error layout and u32 RetCode offset. It retains the [compressed source windows](triage_evidence/live_iokit_mach_transport_audit.json.zst), current image UUIDs and per-window SHA-256 hashes. The selected header arithmetic and direct field copies take O(1) local time and storage, excluding right conversion, dispatch and queue work. Audit time scales with read image bytes, fixup words, scoped symbol data and selected windows. No FairPlay method or Mach message was issued by the audit.

```sh
uv run --no-project --python 3.14 --with capstone \
  python triage_evidence/audit_live_iokit_mach_transport.py "$CURRENT_COLLECTION"
```

QG1–QG3 cover factual call sites, conditions, three request emission sites and the 2865/2965 short-reply path. QG4–QG5 cover byte counts, widths and the separate send helper, insertion and receive outcomes. QG6–QG7 cover original image, fixup and instruction provenance and the bounded observations below.

| Impact | Open evidence |
| --- | --- |
| High | Join a passive current `fairplayd` method observation to the registry entry, actual connection and reply names, and a selector 26 result. |
| High | Establish the current provider's successful descriptor and data path below the outer method. |
| Medium | Observe the current queue versus direct handoff choice and the connection and reply right lifetime. |

The open reply decoder audit resolves the name copyout, application versus routine status, and reply-port helper calls. [IOKit open reply validation and copyout](live_iokit_open_reply_copyout_report.md)
