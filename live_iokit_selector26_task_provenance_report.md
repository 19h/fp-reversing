# Selector 26 connection and task provenance

On the installed build's ordinary FairPlayIOKit route, the task admitted by open request 2862 is written into the new user client. A later inline selector 26 request imports the connection's user client and reads that field when it constructs the embedded virtual-range descriptor. On the ordinary virtual branch, descriptor preparation supplies that task's VM map to the UPL request. Each step below describes an instruction or chained fixup in the matched collection. A native transaction joining these steps remains unobserved. [Open status and trace](live_fairplay_iokit_open_report.md) [Descriptor lifecycle](live_iokit_task_descriptor_lifecycle_report.md)

## Port and object handoffs

| Direction | Message and value | Emission or import point |
| --- | --- | --- |
| User to kernel | Open 2862 uses the service as destination, creates a send-once reply right and carries the designated task as a COPY_SEND descriptor. | Framework transport call `0x184ebdc6c`. The expanded kernel stub loads the task descriptor at `0xfffffe000be81b64` and converts it at `0xfffffe000be81bb4`. |
| Kernel to user | Normal open reply 2962 carries the connection descriptor and a separate application result. | Stub calls the connection exporter at `0xfffffe000be81c64` and writes the kernel port pointer at expanded reply `+0x24` at `0xfffffe000be81c84`. The reply travels on the open's send-once reply right. |
| User to kernel | Method 2865 uses the existing connection as destination and a separate send-once reply right. The inline selector 26 structure carries the 64-bit address and 32-bit extent. | Framework transport call `0x184ebe090`. MIG imports the destination at `0xfffffe000be81644` and invokes the method implementation at `0xfffffe000be816b4`. |
| Kernel to user | Method reply 2965 returns on the reply right for that call. | On the audited short path the method result is stored at `0xfffffe000be816e8`. [Method Mach transport](live_iokit_mach_transport_report.md) |

The open exporter requests kernel object type `0x27` at `0xfffffe000be7e830` and calls its lower conversion at `0xfffffe000be7e834`. The method importer tests that same type at `0xfffffe000be7e2f8`, authenticates the object field from port `+0x50` at `0xfffffe000be7e30c` and calls the object's retain slot at `0xfffffe000be7e334`. These locations identify the connection role on both sides of MIG. The actual namespace names and object identities of a matched native open and method remain unknown.

## Task to user client to VM map

| Transition | Installed location | Provenance |
| --- | --- | --- |
| Open converts the supplied task descriptor | `0xfffffe000be81bb4` | The converter takes the expanded descriptor's port object. Its thread-task fast path compares the object to current task `+0xc0` at `0xfffffe000bd41f44`, then calls the task reference helper at `0xfffffe000bd41fb0`. The stub calls the matching release helper at `0xfffffe000be81c00` after the open implementation returns. |
| Open admits the task | `0xfffffe000c5bdd38`–`0xfffffe000c5bdd4c` | The implementation requires a nonnull task equal to the current thread's task. Later dispatch at `0xfffffe000c5bddbc` passes the admitted pointer in both X1 and X2 to provider slot `+0x7a0`. [Apple XNU open and owning-task contract](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/Kernel/IOUserClient.cpp#L4117-L4187) |
| Generic constructor initializes the client | `0xfffffe000c51b8e8`, `0xfffffe000c5b21f8` | The owning task is held in X24 in the generic route and supplied as X1 at the first call. The base initializer preserves it in X21 and passes it as X1 to the FairPlay override. |
| FairPlay publishes client fields | `0xfffffe000a545470` | The override saves X1 in X20, passes the same value to the base initializer and writes it at user client `+0xe0` when the task is nonnull and base initialization succeeds. Client `+0xd8` initially receives zero. |
| Client starts and is returned | `0xfffffe000c51b914`, `0xfffffe000c51b940`, `0xfffffe000c51b94c` | Constructor checks attach and start before writing the new client through its output pointer. Start writes the provider at client `+0xd8` and reads the same task field at `0xfffffe000a545530` for context construction. |
| Method reads the client-held task | `0xfffffe000a5451e8`–`0xfffffe000a54521c` | The handler loads the buffer address and extent from the inline structure. It separately loads client `+0xe0` into X4, context `+0xe8` into X3 and provider `+0xd8` into X0, then calls provider slot `+0xa20`. |
| Provider constructs a virtual descriptor | `0xfffffe000a546360`, `0xfffffe000c58a010`, `0xfffffe000c586fd0` | Provider moves the saved task from X4 into the factory's X3. The factory sends it as initializer X4. The initializer writes it to descriptor `+0x70`. |
| Prepare selects the map | `0xfffffe000c584f10`–`0xfffffe000c584f40`, `0xfffffe000c585310` | The ordinary branch reads the task from descriptor `+0x70`, loads and authenticates the map pointer from task `+0x28`, and saves it at stack `+0x40`. The nonnull saved map reaches X22 and then X0 of the UPL request at `0xfffffe000c585320`. [Apple XNU task map in virtual wiring](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/iokit/Kernel/IOMemoryDescriptor.cpp#L3979-L3985) |
| Client stops | `0xfffffe000a5455dc` | The stop path clears the provider and task fields together after provider/context and base stop calls. This store establishes the clearing point. Native reference balance remains unknown. |

The generic method implementation also contains optional descriptor paths at `0xfffffe000c5c00f8` and `0xfffffe000c5c015c` that obtain a task from the invocation thread. The ordinary inline method supplies no such out-of-line addresses. For the embedded range the kext consumes the task saved by initialization. The context pointer travels alongside it as a separate argument. The factory, initializer and VM calls above pass kernel pointers and create no additional Mach request.

## Assumptions and scope

| ID | Assumption and dependent conclusion | Falsification check |
| --- | --- | --- |
| T1 | The installed collection identifies the intended build. Instruction addresses, image offsets and slots depend on its SHA-256 and both fileset UUIDs. | Rehash the collection, verify both fileset UUIDs and decode the vtable, import and Mach dispatch entries again after a build change. |
| T2 | The open takes the inherited FairPlay route and later dispatches to selector 26 on that returned connection. Task lineage applies to that route. | Verify the provider and user-client classes, the selector's actual target and the runtime equality of the client object exported and imported. |
| T3 | The request takes the inline method ABI and the descriptor takes the ordinary nonnull task-map branch. The saved task then supplies the VM map. | Verify the optional framework descriptor arguments, the descriptor's memory-reference field and nonnull map in a correlated observation. |
| T4 | The historical RAX session is a separate execution. Its open has a null connection and no following method 2865. | A new capture with a successful open and method would provide the missing native identity and lifetime evidence. [Supplied trace](zut_trace_report.md) |

High impact for mapping the embedded buffer to the address space of the connection's owning task in the selected route. Medium impact for identifying distinct task sources in the generic optional-descriptor path. The next correlation can follow one nominal transaction from the registry-attributed client through open reply, method import and UPL entry. [Native registry observations](daemon_iokit_native_registry_report.md)

## Live registry corroboration

Two read-only registry observations on 2026-11-19 agreed on provider registry ID `0x1000002fb` and four active child clients. At 21:21:47 UTC, the loaded FairPlayIOKit UUID was `316464f8-eade-30ca-938e-2f430b1ed5bc`, matching the audited image. The creator PID and current process basename were checked separately.

| Child registry ID | Creator PID | Registry creator label | Process basename |
| --- | ---: | --- | --- |
| `0x10000130b` | 910 | `adid` | `adid` |
| `0x100001702` | 3903 | `fairplayd` | `fairplayd` |
| `0x1001badf7` | 80938 | `lskdd` | `lskdd` |
| `0x1001bef3c` | 18554 | `fairplaydeviceid` | `fairplaydeviceidentityd` |

The earlier snapshot contains the first two clients. The two additional clients broaden the set of observed service consumers. Their selectors, connection Mach names and VM-map identities are unknown. Registry IDs identify registry entries. [Earlier registry snapshot](daemon_iokit_native_registry_report.md)

## Reproduction

The [auditor](triage_evidence/audit_live_iokit_selector26_task.py) checks the two MIG dispatch records, five constructor and initializer slots, the selector route, 13 direct calls and 40 instruction operands. The [receipt](triage_evidence/live_iokit_selector26_task_audit.json.zst) contains 920 instruction records. The shipped collection supplies the primary binary evidence. Apple's public source corroborates the owning-task test and task-map role on the cited release.

    python3 triage_evidence/audit_live_iokit_selector26_task.py COLLECTION RECEIPT
    ioreg -r -c com_apple_driver_FairPlayIOKit -l -w0

The registry command queries the current host state. This report establishes the selected static chain and the observed registry attachment. It leaves runtime request continuity, actual Mach names, selected methods for the other clients and task reference ownership open.
