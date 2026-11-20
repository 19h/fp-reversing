# Direct IOKit traps and the FairPlayIOKit method boundary

The installed FairPlayIOKit user client inherits both direct-trap lookup methods from `IOUserClient`. The leaf returns null for every selector. For an ordinary FairPlay connection that reaches that lookup, the installed Mach trap returns `kIOReturnNotFound` (0xe00002f0) without invoking a provider callback. The synchronous method selector table is a separate virtual dispatch path. The three currently attached daemon slices bind `IOConnectCallStructMethod` and contain zero direct-trap imports.

The audit matches build `26C5035r`, the running kernel UUID `90195379-954d-3ca3-baac-327341f14211`, and the loaded driver UUID `316464f8-eade-30ca-938e-2f430b1ed5bc` to the original boot fileset. The IOKit cache image UUID is `82be1de5-91c4-3152-b63b-81db4c5e7992`. All code locations below are unslid. The earlier kernel dispatch report identified slot 100 in the historical collection. This audit resolves the corresponding installed handler and follows its dispatch on the live driver class. [Historical dispatch table](kernel_dispatch_report.md) [Installed FairPlay selector map](live_kext_selector26_report.md)

## Connection reference and dispatch

| Operation | Installed sites | Observed instruction or binding contract |
| --- | --- | --- |
| Enter from IOKit | `IOConnectTrap0` through `IOConnectTrap6`, entries `0x184ee305c`, `0x184ee3078`, `0x184ee3090`, `0x184ee30a4`, `0x184ee30b4`, `0x184ee30c0`, `0x184ee30c8` | The wrappers leave the connection and selector in X0 and X1, zero the unprovided scalar lanes in X2–X7 and tail-branch to `0x184ed9cd0`. That stub sets X16 to −100 and executes `svc #0x80` at `0x184ed9cd4`. |
| Dispatch the trap | Mach table slot 100, authenticated pointer at `0xfffffe0007f07980` | The table record starts with argument counts 8 and 8 and resolves to `0xfffffe000c5c1dc4`. The first argument supplies the connection reference. The selector is read as u32 at argument-record +8 B. The six optional arguments occupy argument-record +16 B through +63 B. |
| Resolve the existing connection | `0xfffffe000c5c1e7c–0xfffffe000c5c1e88` | On the ordinary IOKit path the lookup takes the reference in the calling task's namespace and requests connection object type `0x27`. A null lookup returns the initialized `kIOReturnBadArgument` (0xe00002c2). The tagged I/O user-server branch has a different lookup type. |
| Look up the external trap | `0xfffffe000c5c1fb0` then `0xfffffe000c5b1ea0` | The handler initializes a local target pointer to zero. After the applicable type and policy handling, virtual slot +0x988 B receives the target output pointer and selector. The inherited implementation calls slot +0x980 B with the selector. Its leaf clears X0 at `0xfffffe000c5b1ec0` and returns. The outer helper leaves the target cell untouched. |
| Return missing-descriptor status | `0xfffffe000c5c1fb8–0xfffffe000c5c1fc4`, cleanup at `0xfffffe000c5c2084` | The handler changes the initialized result by 0x2e in W19, giving 0xe00002f0. The null trap or target causes the branch to cleanup, skipping the scalar callback at `0xfffffe000c5c207c`. The status returns in X0 through the trap. |

The output is a CPU register result. This route uses the existing connection name as an argument and creates no Mach request header, MIG reply port, or new Mach send for this operation. The SDK checks the exact two IOReturn values. Pinned public XNU corroborates the inherited null getter and the conditional target assignment. The installed bytes establish the return status for this build. [XNU trap lookup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L2042-L2047) [XNU target lookup](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOUserClient.cpp#L2096-L2107) [IOReturn definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/IOKit/IOReturn.h#L100-L152)

| FairPlay user-client vtable offset | Original authenticated slot | Resolved implementation |
| --- | --- | --- |
| +0x970 B | `0xfffffe0008481c78` | FairPlay override `getTargetAndMethodForIndex`, `0xfffffe000a544e60`. This is the lookup used by the synchronous method path. |
| +0x980 B | `0xfffffe0008481c88` | Inherited `IOUserClient::getExternalTrapForIndex`, `0xfffffe000c5b1ebc`. |
| +0x988 B | `0xfffffe0008481c90` | Inherited `IOUserClient::getTargetAndTrapForIndex`, `0xfffffe000c5b1e68`. |

In the synchronous path the installed framework packages request 2865 with the connection name as COPY_SEND and a separate reply name as MAKE_SEND_ONCE. It enters transport at `0x184ebe090`, whose ordinary send reaches the Mach2 trap at `0x180548c1c`. The kernel imports the connection and uses the legacy external-method route to the FairPlay +0x970 B slot. The reply returns as 2965 on the separate receive name. [Mach emission, reply and port ownership](live_iokit_mach_transport_report.md) [Kernel policy and virtual method call](live_iokit_method_locking_report.md)

## Live attachment and daemon code

The same FairPlay service entry `0x1000002fb` and three creator entries appeared before and after collecting the running process identities. For each process, the live CodeDirectory hash and Mach-O slice offset identify the inspected ARM64e bytes. The installed call windows retain their selector, authentication modifier and call instruction. The cited caller recoveries supply the table/slot lineage, which the immediate modifier alone cannot establish.

| Creator, PID | User-client registry entry | Structure-method import slot | Selected application call and selector |
| --- | --- | --- | --- |
| `adid`, 910 | `0x10000130b` | `0x1002d8400` | `0x10001f908`, 26. [Installed ADID calls](adid_selector26_installed_report.md) |
| `fairplayd`, 3903 | `0x100001702` | `0x1010a0640` | `0x1002069c4` and `0x100293074`, 26. [FairPlay call and bind recovery](daemon_selector26_return_report.md) |
| `lskdd`, 88947 | `0x10026cc8c` | `0x100e738d0` | `0x100474e38`, 19 under the recovered frame contract. [LSKDD call and bind recovery](live_lskdd_selector19_binding_report.md) |

The import table and chained-fixup views show zero `IOConnectTrap0`–`IOConnectTrap6` or `iokit_user_client_trap` imports across those three slices. A census of all aligned AArch64 SVC encodings in instruction-marked sections covers 30,458,680 B (7,614,670 words) and finds zero SVC instructions. The scope is the three executables' measured slices. Dynamically resolved functions and code in their dependencies remain outside the census. Registry IDs identify the attached objects, while the task-local connection name passed at any selected call remains unknown. [Open-time creator attribution](live_iokit_open_owner_report.md)

The supplied RAX capture has zero named direct-trap records among its 1,748 lines. Its 22 printed guest sends include open request 2862 and omit method request 2865. The raw reply 2962 has a null connection descriptor and application result 0xe00002c2, with successful Mach transport. That result belongs to the archived MIG open. A native admitted method request from any listed daemon and its exact reply have yet to be observed. [Archived open and cleanup](archived_iokit_open_retirement_report.md)

## Assumption register

| Assumption | Dependent result | Falsification check |
| --- | --- | --- |
| A1. The measured cache and boot fileset identify the running build. | Addresses, row-100 binding and FairPlay vtable inheritance. | Match build, runtime cache and kernel UUIDs, loaded driver UUID, fileset hash, symbol entries and authenticated slot targets. |
| A2. The ordinary trap receives a reference to the FairPlay client and reaches its direct-trap lookup. | Null getter and resulting 0xe00002f0. | Check the typed connection lookup, exact class slots, zero target initialization, null-result branch and SDK status constants. The retained attachment does not supply the native invocation. |
| A3. The inspected slices correspond to the live attachment creators. | Current import, call-site and instruction census results. | Match live CodeDirectory hash and slice offset, recheck the process and registry identities, and compare import and fixup views. |
| A4. The archived printout covers the retained RAX interval. | The open exchange and counts for printed methods and named traps. | Rehash the full text and decode raw Mach headers, descriptor and status for the paired open. The printout cannot establish activity outside its capture. |

**High impact.** For the installed FairPlay class, an admitted connection exposes a structure-method path with a separate Mach reply. The direct-trap table leads to the inherited null getter. **Medium impact.** The exact application and framework locations support future native correlation without treating the registry IDs as port names.

Run `python3 -B triage_evidence/audit_live_fairplay_direct_trap.py "$BOOT_FILESET" "$ANNOTATED_TRACE"` with the repository Python dependencies. The fileset is the decompressed Mach-O whose SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. For B input bytes and F reported fixups, the file reads and instruction census take O(B + F) time and O(B + F) space, excluding external tools and system queries. [Auditor](triage_evidence/audit_live_fairplay_direct_trap.py) [Compressed receipt](triage_evidence/live_fairplay_direct_trap_audit.json.zst)
