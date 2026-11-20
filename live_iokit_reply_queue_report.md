# Kernel construction and native use of the IOKit MIG reply queue

On installed build `26C5035r`, a miss in the ordinary MIG reply cache reaches the kernel's Mach port constructor. The kernel publishes a receive right in the requesting task and copies its 32-bit name back to libsystem_kernel, which caches it on the issuing thread. A native verifier found that one newly constructed receive queue advanced by two messages during `IOMainPort`, one during FairPlayIOKit matching, and one during iterator advancement. The same queue was empty and carried no outstanding send-once rights at each checkpoint.

## From libsystem_kernel to namespace publication

Addresses are unslid. The kernel evidence is pinned to UUID `90195379-954d-3ca3-baac-327341f14211`, decompressed fileset SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`, and the current libsystem_kernel image in cache `8b1e17c6-72d6-3017-91a4-916022e3612e`. The library passes a 24 B `mach_port_options_t` with flags `0x1000` (`MPO_REPLY_PORT`) and other bytes zero, context zero and the output address. The installed bytes and arm64 SDK declarations agree on the options and port-name widths. [MIG reply cache](live_iokit_mig_reply_port_report.md) [Apple XNU port declarations](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/port.h#L413-L534)

| Boundary | Original site and data flow |
| --- | --- |
| User entry and kernel dispatch | `0x180548f4c` calls the port constructor. Its primary veneer executes `svc #0x80` at `0x180548b14` with selector -24. Kernel row 24 in the 24 B trap table binds `_kernelrpc_mach_port_construct_trap` to `0xfffffe000bd23c98`. |
| Argument import | The handler reads task name u32 at argument +0 B, options address at +8 B, context at +16 B and output address at +24 B. It resolves the task, copies 24 B at `0xfffffe000bd23cdc`, and obtains the task's IPC space from task +0x318 B. The call at `0xfffffe000bd23d24` passes the space, copied options, context and kernel name-output address. |
| Kernel object label | The constructor distinguishes the `0x1000` option at `0xfffffe000bd28088` and `0xfffffe000bd28134`. The branch beginning at `0xfffffe000bd2813c` uses the space's policy to select internal type 10 or 12. Original policy-table name strings identify them as `reply port` and `weak reply port`. Adjacent type 11 is `special reply port`. The installed table supplies these names and values. |
| Port and queue initialization | `0xfffffe000bd28308` extracts `MPO_INSERT_SEND_RIGHT` bit 4, which is zero in the MIG options. The allocator at `0xfffffe000bd14ef4` gets a namespace slot and calls the initializer at `0xfffffe000bd15000`. The initializer sets queue limit 5 at `0xfffffe000bd15110` and stores the name at port +0x34 B. |
| Publish the receive right | With bit 4 clear, the allocator selects type bits `0x20000` and zero send user references. The publisher stores the authenticated object pointer at entry +0 B at `0xfffffe000bd1359c`, then adds the right bits at entry +8 B at `0xfffffe000bd135ac`. The allocator writes the generated name through its kernel output pointer at `0xfffffe000bd15028`. |
| Return to caller | The trap copies out 4 B at `0xfffffe000bd23d38` after successful construction. The MIG helper publishes that name to the thread slot at `0x180548f58`. |

The user wrapper also has an RPC path selected by transport status `0x10000003`. The current client emits ID 3231 at `0x18056f050` and expects 3331. It supplies a 60 B user-form request with one 24 B out-of-line options descriptor. The installed server entry at `0xfffffe000bdcf6fc` validates the expanded 68 B form and calls the same constructor at `0xfffffe000bdcf7d0`. Its 48 B expanded success reply returns the name. These sites establish the fallback ABI from bytes. Native selection of the fallback remains unknown. [Historical service-port constructor](launchd_service_endpoint_report.md) [Apple XNU constructor](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/mach_port.c#L2282-L2454)

## Native queue checkpoints

The verifier retired its existing cached name and obtained a fresh receive right. It called the ordinary IOKit discovery APIs on the issuing thread and used another thread with a separate reply right to query `mach_port_get_attributes` flavor 2 (`MACH_PORT_RECEIVE_STATUS`). A repeated pre-call snapshot controls for measurement effects. The returned status comprises ten 32-bit words. The sequence word is at +4 B and the queue limit at +12 B. The kernel increments the sequence as it delivers a message or removes it for the waiting receiver. [Apple XNU queued receive](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_mqueue.c#L1049-L1069)

| Checkpoint | Sequence | Advance | Current request/reply pairs identified from installed stubs |
| --- | ---: | ---: | --- |
| Fresh reply name | 0 | 0 | None |
| Observer control | 0 | 0 | None |
| First `IOMainPort` | 2 | 2 | 205/305 main-port acquisition and 2877/2977 version negotiation |
| Matching `com_apple_driver_FairPlayIOKit` | 3 | 1 | 2881/2981 |
| `IOIteratorNext` returns a service | 4 | 1 | 2802/2902 |
| Release service, iterator and main send rights | 4 | 0 | None |

Each sample reports queue limit 5, one receive user reference, type `0x20000`, zero queued messages, zero send-once rights and no send rights. The cached name remains the same through all six samples. After retirement the verifier's lookup returned `KERN_INVALID_NAME` (15). The counter supplies counts on the verifier's queue. A separate native capture confirmed the pair IDs and recorded an ordinary open returning a null connection. Production `fairplayd` queue state, the live internal label selected for the verifier and successful native method delivery remain unknown. [Native message capture](live_iokit_mach_headers_report.md) [Registry matching and service identity](live_iokit_matching_report.md)

## Assumption register and verification

| Premise and dependent result | Falsification probe |
| --- | --- |
| Current kernel and cache identities qualify the static constructor and namespace addresses. | Rehash the selected collection, compare the running UUIDs, and recheck trap and MIG records and their authenticated handler targets. |
| The kernel policy table names identify the values received by the generic allocator. No native label is assigned here. | Recheck original string pointers, instructions that write the selected label and the allocator's load of that label. |
| The queue samples concern the issuing thread's receive right and the observer uses a separate one. This qualifies the native deltas. | Check both cached names for inequality, sample twice before discovery and check equality of the issuing name before each sample. |
| The runtime counts match the static discovery transactions. This qualifies the mapping from sequence advances to candidate reply IDs. | Correlate a native message trace with the sampled right at each IOKit emission. An extra receive or different request/reply pair would change the mapping. |

High impact for linking successful native discovery of the FairPlayIOKit service to one kernel reply queue. Medium impact for separating the returned service name, cached MIG receive name and the special reply mechanism. [ADID special reply mechanism](live_adid_xpc_special_reply_kernel_report.md)

Run `python3 -B triage_evidence/audit_live_iokit_reply_queue.py "$KC" --observe` with the pinned decompressed collection and Capstone. Collection parsing uses O(B + F + S) time and storage as an upper bound for collection bytes, fixups and symbols. The checked sites and native sample count are fixed. The receipt retains the exact source windows, handler bindings, type labels and queue samples. [Auditor](triage_evidence/audit_live_iokit_reply_queue.py) [Compressed receipt](triage_evidence/live_iokit_reply_queue_audit.json.zst)
