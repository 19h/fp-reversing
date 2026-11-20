# IOKit connection names and registry entry IDs

The registry ID also joins the original connection to the service descriptor received in an IOKit termination notification. Native verification covered two IOSurface controls. [Termination notification registration and delivery](live_iokit_interest_notification_report.md)

On build `26C5035r`, `mach_port_kobject_description` returns the class and 64-bit registry entry ID for an IOKit user-client connection described in an authorized task namespace. A native verifier opened two simultaneous `IOSurfaceRoot` connections in its own task and matched each description to a different child of the provider. This establishes how to join a recorded Mach destination name to an IOKit client object when a valid namespace observation is available. The production `fairplayd` port-to-client join remains unknown. [Mach trap trace names](live_mach_trap_trace_report.md) [FairPlay registry creator attribution](live_iokit_open_owner_report.md)

## Request, type translation and reply

The measured libsystem_kernel export at `0x180567034` branches to its MIG stub at `0x18056f964`. The stub obtains a thread-cached reply right at `0x18056fa08` and calls `_mach_msg2_internal` at `0x18056fa50`. Addresses are unslid. The 36 B request uses the namespace task port as its remote destination with COPY_SEND and the separate local reply name with MAKE_SEND_ONCE. The name being described is a u32 at request +32 B. Request 3239 and expected reply 3339 use the `mach_port` MIG subsystem. The task capability must already support access to the namespace. [Pinned MIG definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/mach_port.defs#L636-L651) [Pinned userspace wrapper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/mach/mach_port.c#L614-L626)

| Stage | Installed site | Observed contract |
| --- | --- | --- |
| Bind request 3239 | Routine slot `0xfffffe0007e74010`, stub `0xfffffe000bdcf054` | Authenticated routine binding. The stub requires a simple 44 B kernel request and passes the namespace task port and lookup name to the query implementation. |
| Resolve the name | Calls at `0xfffffe000bd23008` and `0xfffffe000bd23028` | Resolve the read-capable namespace and look up the name. Require a send or receive right. |
| Publish diagnostic type | Table load `0xfffffe000bd2305c`, store `0xfffffe000bd23088` | Translate kernel type `0x27` to exported IOKit connection type `0x1d`. Translate kernel type `0x28` to exported IOKit object type `0x1e`. |
| Describe the object | Call at `0xfffffe000bd23244`, formatter at `0xfffffe000c5b6388` | Hold the IOKit reference through the description. On the registry-entry branch, use the metaclass name and registry ID with the format `%s(0x%qx)`. The numeric address output is cleared on this build. |
| Assemble and consume reply 3339 | Kernel `0xfffffe000bdcf0dc` through `0xfffffe000bdcf100`, userspace `0x18056fb28` through `0x18056fb64` | The kernel includes the terminating NUL in the length, rounds the string field to 4 B and uses a fixed 64 B kernel prefix. The user stub validates the length and extent against a 56 B prefix and a 512 B string bound. Its type and address fields are at user offsets +36 B and +40 B. |

The formatter obtains the registry ID through the entry's data pointer at object +0x10 B, then reads the u64 ID at +8 B of that record. The independently named `IORegistryEntry::getRegistryEntryID()` at `0xfffffe000c51ae98` uses those same fields. The description therefore exports a registry entry ID even when the separate numeric address field is zero. [Pinned namespace lookup and reference handling](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/mach_debug.c#L501-L603) [Pinned diagnostic type ABI](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach_debug/ipc_info.h#L69-L84) [Pinned IOKit formatter](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L501-L534)

## Native control and FairPlay correlation

The verifier held two type-zero IOSurface connections simultaneously. The two distinct connection names both returned type `0x1d`, address zero and an `IOSurfaceRootUserClient` description with a distinct entry ID. For each ID, traversing the provider's direct children found exactly one matching registry entry. Describing its separate registry-object right returned type `0x1e` with the same class and ID. Each child's parent ID matched the original service, and each `IOUserClientCreator` label matched the verifier PID. The query repeated on each connection before it was closed and returned the same ID. The receipt records the two task-local names and their corresponding child and parent IDs.

A private receive right returned type `0xffffffff` and an empty description. Passing either connection name directly to `IORegistryEntryGetRegistryEntryID` returned `0xe00002c2` with a zero output. The result depends on using the correct right for each operation. For N children, this two-connection verifier performs O(N) work and uses O(1) additional matching state besides the iterator.

For a native `fairplayd` call, the trace's destination name and a description must refer to the same task generation and live right. The associated registry child ID would then identify the client object independently of the creator label. The earlier `lsmp` query obtained no port rows for the daemon. The local verifier used its own task and sent ordinary IOSurface traffic. A paired daemon selector and IOKit result are still unobserved. [Prior daemon namespace query](daemon_iokit_native_registry_report.md) [Installed FairPlay connection types](live_fairplay_connection_report.md)

## Assumption register and verification

| Premise | Dependent finding | Falsification check |
| --- | --- | --- |
| The measured installed cache and kernel fileset correspond to the current host. | Emit sites, MIG layout and formatter. | Compare build, cache and kernel UUIDs, fileset digest, authenticated routine entry and indexed type constants. |
| The connection stays live while its description and registry entry are compared. | Two per-instance joins. | Hold both connections until after child enumeration. Re-query each right and check distinct IDs, unique child matches, parent and creator. |
| A retained production trace and namespace observation refer to the same task generation and right lifetime. | Any eventual FairPlay attribution. | Compare task generation, timestamps and the described right before retirement or reuse. Independently pair the selector and reply outcome. |

High impact for identifying an IOKit client from a task-local Mach name. Medium impact for distinguishing the exported connection type and textual registry ID from the separate address field. Run `python3 -B triage_evidence/audit_live_iokit_port_description.py "$BOOT_FILESET"` on the pinned build with Capstone and the installed Xcode tools. The auditor checks 50 installed instructions and runs two simultaneous native joins. [Auditor](triage_evidence/audit_live_iokit_port_description.py) [Compressed receipt](triage_evidence/live_iokit_port_description_audit.json.zst)
