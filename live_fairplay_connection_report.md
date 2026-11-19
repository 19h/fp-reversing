# Current FairPlayIOKit connection publication and close

On build `26C5035r`, successful IOKit open exports the client object as a type-`0x27` Mach port. Request 2865 and close request 2816 both import that port type, authenticate the backlink and retain the client used for dispatch. The open request instead targets a type-`0x28` service port. A connection name is published during receive-side right copyout into the caller's IPC space. The native connection name and a matched open, method and close sequence remain unknown. [Current open status channels](live_fairplay_iokit_open_report.md) [Pinned connection lifecycle](iokit_connection_lifecycle_report.md)

```text
type 0x28 service right -> open 2862 -> client object
  -> IOMachPort registry -> type 0x27 port -> reply 2962 send descriptor
  -> receiver IPC copyout -> task-local IOConnect name
       |-> method 2865 -> type 0x27 import -> reply 2965
       +-> close 2816 -> type 0x27 import -> reply 2916 -> deallocate name
```

## Object export and name publication

All addresses are preferred, unslid addresses. The audit matches the decompressed collection hash and kernel and kext UUIDs, then checks the installed cache and libkernel binding. The 52 B user-layout open reply contains a 24 B header, 4 B descriptor count, 12 B send descriptor, 8 B NDR and a 4 B application result. The expanded kernel layout is 64 B. Its additional 12 B consist of 8 B of header expansion and 4 B of descriptor expansion.

| Transition | Unslid instruction sites | Evidence |
| --- | --- | --- |
| Export client object | `0xfffffe000be81c64`, `0xfffffe000be7e830`–`0xfffffe000be7e85c` | The open stub passes the client output to the exporter. It requests type `0x27`, releases the input object reference and returns the port. The null client path returns null. |
| Reuse or allocate registry node | `0xfffffe000c5b083c`, `0xfffffe000c5b08d8`, `0xfffffe000c5b08e8`, `0xfffffe000c5b0844`–`0xfffffe000c5b0868` | The bucket scan compares both the authenticated object pointer and the type byte. On a miss the helper initializes an `IOMachPort` node, associates a new port and publishes the node to the bucket. The vtable store is at `0xfffffe000c5b0a10`. |
| Establish port backlink and send reference | `0xfffffe000be7e930`, `0xfffffe000bd3c9d4`–`0xfffffe000bd3c9d8`, `0xfffffe000bd3cf00`–`0xfffffe000bd3cf14` | The type-`0x27` path uses null auxiliary storage and creation flags `0x27 OR 0x100 = 0x127`. The constructor signs the association at port +80 B. The registry checks type and association before calling the send-reference helper. Its selected active branch increments adjacent counters at port +132 B and +136 B and the reference word at +4 B. |
| Emit open reply descriptor | `0xfffffe000be81b48`, `0xfffffe000be81c78`, `0xfffffe000be81c84` | The stub seeds type 0 and disposition 17 from original metadata, signs the connection port with the descriptor address and discriminator `0x01ab`, and writes it at expanded reply +36 B. Disposition 17 is `MACH_MSG_TYPE_PORT_SEND` in the SDK's receive layout. |
| Resolve caller's name | `0xfffffe000bd0d720`, `0xfffffe000bd0d790`, `0xfffffe000bd11da0`, `0xfffffe000bd11db8`, `0xfffffe000bd11e48` | Port descriptor copyout authenticates the object, supplies its disposition and receiver space, then reads the returned u32 name. In the selected ordinary copyout path the receiver space looks up the object and reserves an entry when lookup fails. The send-right branch publishes the selected name. |
| Pack and return the name | `0xfffffe000bd0e4a8`–`0xfffffe000bd0e4b0`, `0x184ebdd40`, `0x184ebdd48` | The kernel packs the resolved name into the 12 B user descriptor. The framework loads it from reply +28 B and stores it through the open caller's connection output pointer. |

The authentication modifier for the port association is the type byte XOR `0x5a`. The connection importer uses `0x27 XOR 0x5a = 0x7d` at `0xfffffe000be7e308`. The service importer uses `0x28 XOR 0x5a = 0x72` at `0xfffffe000be7e1d4`. The importers test active state and type before authenticating port +80 B. This joins the roles at the object/type boundary. The host-slot receive rights used by FairPlay RPC 502 flow through separate IPC paths. [Host-slot and reply rights](live_fairplay_reply_rights_report.md)

## Later use and release

| Operation | User emission and rights | Kernel import and result |
| --- | --- | --- |
| Method 2865 / 2965 | `0x184ebe090` emits using the connection as `COPY_SEND` and a distinct local reply name as `MAKE_SEND_ONCE`. | `0xfffffe000be81644` imports type `0x27`, `0xfffffe000be816b4` calls the method implementation, and `0xfffffe000be816dc` releases the imported reference under the selected nonnull path. |
| Close 2816 / 2916 | `0x184ec1a44` emits a 24 B request with the same dispositions. The ordinary simple reply is 36 B. | `0xfffffe000be85554` imports through the same converter, `0xfffffe000be8555c` calls the close implementation, and `0xfffffe000be85584` releases its imported reference. |

For a client that takes the selected close branch, the call at `0xfffffe000c5be894` uses vtable +0x920. The original FairPlay binding resolves to `clientClose` at `0xfffffe000a5455ec`. That routine calls `IOService::terminate` through +0x630 with option zero at `0xfffffe000a545620`, then sets W0 to zero regardless of the termination return. The enclosing close implementation also requests its subsequent cleanup before returning zero on this branch.

After the RPC, `IOServiceClose` at `0x184ec199c` requests `mach_port_deallocate` for the original connection name via the cache veneer at call site `0x184ec19c8`. The wrapper preserves the RPC result across deallocation. This is evidence for releasing a task-local user reference after the close call. Object termination, final send-reference retirement and concurrent holders are separate events whose native outcomes remain unknown. [Installed IOKit transport](live_iokit_mach_transport_report.md)

## Assumptions and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| C1 | Collection and cache identity apply to the installed build. This qualifies the sites. | Compare collection hash, kernel and kext UUIDs, loaded cache UUID and IOKit UUID. Check six constants and layout assertions with arm64e SDK compilation. |
| C2 | The object reaches the selected export and ordinary descriptor copyout branches. This qualifies the publication route. | Require a successful open and correlate the object, registry type, descriptor and receiver entry within the same event sequence. |
| C3 | The client takes the selected close route with its original virtual bindings. This qualifies the termination request and cleanup. | Verify both chained vtable entries and correlate the imported object and selected vtable at dispatch. |
| C4 | The native method and close use the name from that same open, with stable object identity. | Observe all three operations with a process-scoped name and object association. Current registry attribution and archived RAX evidence do not satisfy this condition. |

High impact for connecting an ordinary open reply to later request destinations in the same task. Medium impact for distinguishing termination from namespace reference release. The verifier reads a collection of B bytes, F source fixups and I selected instructions in O(B + F + I) time and space, excluding system query costs. Registry lookup depends on the length of one bucket chain. The audit does not issue an IOKit call. The historical RAX open returned a null connection. [Archived open](zut_trace_report.md)

QG1 covers factual scope. QG2 lists premises and probes. QG3 covers export, publication, method import and close. QG4 checks the packed and expanded geometries and dispositions. QG5 bounds the source-selected branches and unresolved lifetime. QG6 checks original pointers, instruction bytes and SDK declarations. QG7 bounds correlation and release-order impact. [Audit script](triage_evidence/audit_live_fairplay_connection.py) [Compressed receipt](triage_evidence/live_fairplay_connection_audit.json.zst)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_connection.py "$CURRENT_COLLECTION"
```
