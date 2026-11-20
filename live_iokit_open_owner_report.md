# FairPlayIOKit open, creator attribution, and owner registration

On build `26C5035r`, the inherited type-zero open route attaches and starts the FairPlay user client before the kernel writes its `IOUserClientCreator` registry label. The label uses the process handling the request. The open implementation then registers the owning task before returning the client object for connection-port export. This ordering bounds what the observed `adid` and `fairplayd` child entries establish. [Open status and initializer](live_fairplay_iokit_open_report.md) [Connection publication](live_fairplay_connection_report.md)

The [connection-to-provider audit](live_iokit_connection_service_report.md) traces the separate getter request. The FairPlay client inherits a null-returning method, so the installed route returns a status-only reply without exporting the attached provider.

## Attach and start

| Operation | Installed call site and binding | Continuation |
| --- | --- | --- |
| Initialize the allocated class | `0xfffffe000c51b8e8`, vtable +0x910, inherited `IOUserClient::initWithTask` | The five-argument initializer invokes the FairPlay four-argument override. Success enters attachment. |
| Attach the client to the provider | `0xfffffe000c51b914`, vtable +0x6a0 resolves to `IOService::attach` | Success reaches the start slot. The failed-attach arm releases the candidate. |
| Start the client | `0xfffffe000c51b940`, vtable +0x5f0 resolves to FairPlay `start` at `0xfffffe000a5454b0` | Success stores the candidate through the constructor output at `0xfffffe000c51b94c`. Failed start calls `IOService::detach` through +0x6a8 at `0xfffffe000c51b9b4` before releasing the candidate. |

The FairPlay start adapter passes its mode from client +240 B and the task from +224 B at `0xfffffe000a545558`. This joins the Virtual entitlement-derived mode to the provider startup call. The adapter forwards the address of the context cell at client +232 B to the provider. It returns true when the selected provider call returns normally. The provider stop report identifies the startup call's binding to `Trped0719ab` and its tail transfer to `_lapsl183ah`. [Pinned XNU constructor](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L7681-L7750) [Provider startup and stop](live_fairplay_provider_stop_report.md)

## Process label and task owner

The open implementation compares the imported task with the current thread's task at `0xfffffe000c5bdd48`. On the accepted route, the helper called at `0xfffffe000c5bdd58` loads the thread's read-only metadata pointer from thread +0x420 B. The installed path loads the process pointer at metadata +24 B, corresponding to `tro_proc` in the pinned source. The PID read at `0xfffffe000c5bde58` then uses process +0x60 B. The original `proc_pid` symbol independently reads PID at +0x60 B on its ordinary process branch. Null and `kernproc` select PID zero in the open path. [Pinned thread metadata layout](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/thread.h#L178-L200)

The helper at `0xfffffe000c50a4d0` formats the `pid %d, ` prefix into a 128 B buffer and calls `proc_name` with the remaining extent. It constructs an `OSString`. Open passes that string in X2 and the literal key `IOUserClientCreator` in X1 at `0xfffffe000c5bdea0`. Original vtable +0x288 resolves this call to `IORegistryEntry::setProperty(const char *, OSObject *)`. The property is generated on the provider-success, nonnull-client path. The generic open logic checks the client metaclass and reserves expansion state before the setter. [Pinned creator assignment](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L4181-L4217) [Pinned process-ID semantics](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L1232-L1249)

The subsequent path reads shared-instance and default-locking state and executes the applicable policy checks. Its first-open block also caches application-suspension interest from a registry property. The selected success path calls `0xfffffe000c5b7b0c` with the client in X0 and the admitted owning task in X1 at `0xfffffe000c5be614`. This is the owner registration routine. It acquires the owner lock, searches the client list for the same task, and allocates a `site.IOUserClientOwner` record on a miss. The original descriptor gives the 48 B allocation size. [Pinned owner registration](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L1594-L1638) [Suspension notification ABI](live_iokit_suspension_report.md)

| Owner record field | Offset | Installed store or linkage site |
| --- | --- | --- |
| Owning task pointer | +0 B | `0xfffffe000c5b7bb0` |
| Task-side queue links | +8 B and +16 B | `0xfffffe000c5b7c18`. Link the record to the head at task +0x650 B at `0xfffffe000c5b7c30`. |
| User-client pointer | +24 B | `0xfffffe000c5b7bb4` |
| Client-side queue links | +32 B and +40 B | `0xfffffe000c5b7bd8`. Link the record to the head at client +0xa0 B at `0xfffffe000c5b7bf0`. |

With N existing owners, the locked duplicate check is O(N), and insertion uses O(1) new storage and pointer writes. The success path proceeds to the final client and application-status output stores at `0xfffffe000c5bdddc` and `0xfffffe000c5bdde0`. The outer MIG stub exports the client in the type-`0x27` connection descriptor in reply 2962. An open failure after creator attribution can instead call the FairPlay close slot at `0xfffffe000c5be690`, release the candidate and reach the final outputs with a null client pointer. The creator label therefore describes a stage before final port publication. [Pinned post-construction checks and cleanup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L4258-L4338) [Connection right publication](live_fairplay_connection_report.md)

## Current registry and executable evidence

Two child entries were stable across the 2026-11-20 03:19 UTC capture. For both processes the live Mach-O offset and 20 B CodeDirectory hash select the same installed arm64e slice, and both checks and the process start time agree on re-read. The signed entitlements show `com.apple.private.FairPlayIOKitUserClient.access = true` on both slices. The ProvInfo and Virtual variants are absent from the two extracted entitlement dictionaries. Both registry entries expose `IOUserClientDefaultLocking = true`. [Earlier executable identity audit](fairplay_live_slice_identity_report.md) [Locking policy and dispatch](live_iokit_method_locking_report.md)

| Registry creator | PID | Client entry ID | Slice UUID |
| --- | ---: | --- | --- |
| `adid` | 910 | `0x10000130b` | `4d24325f-3529-39b1-bbf8-64bbcf406049` |
| `fairplayd` | 3903 | `0x100001702` | `204741e9-b89f-32b4-9321-51f3975c7cac` |

Both are children of the discovered service `0x1000002fb`. The earlier `lskdd` and `fairplaydeviceidentityd` entries belong to their own capture interval. The current evidence attributes the two resident client objects to running signed executables and verifies signature metadata compatible with the private initializer check. The effective entitlement objects at construction time, actual owner-list nodes, task-local connection names and individual Mach messages remain unobserved. The archived RAX open's precise failure point remains unknown. [Registry discovery](live_iokit_matching_report.md) [Earlier additional clients](live_fairplay_additional_clients_report.md) [Archived open](zut_trace_report.md)

## Assumption register and verification

| Premise and dependent result | Falsification probe |
| --- | --- |
| The original boot fileset corresponds to the running kernel and kext. This qualifies the code and bindings. | Check the collection digest, running kernel UUID, loaded driver UUID and current cache UUID. |
| The selected open reaches the inherited constructor and the FairPlay vtable. This qualifies the attach, start, and property-set sequence. | Verify the client class and vtable for the same instance before using the recovered slots. |
| Both registry scans and process attributes describe the same instances. This qualifies the creator attribution and selected signatures. | Compare child IDs, PIDs, start times and both live code-signing attributes across the capture. |
| The final return preserves the same client pointer from construction through owner registration and export. This qualifies the selected static route. | Pair the owner record, final output pointer and reply descriptor on a successful native transaction. |

High impact for distinguishing registry attribution from Mach right ownership, and for linking the admitted task and provider initialization to later connection publication. Medium impact for explaining the locking metadata and two-way owner index. The audit rechecks 50 installed instruction words, six authenticated client slots, the 48 B typed allocation, six literals and the two live registry-to-signature associations. [Auditor](triage_evidence/audit_live_iokit_open_owner.py) [Compressed receipt](triage_evidence/live_iokit_open_owner_audit.json.zst)
