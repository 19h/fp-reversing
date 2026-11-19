# FairPlayIOKit connection retirement on macOS 26C5035r

The installed kernel registers a no-senders callback for the type-`0x27` IOKit connection exported by the open RPC. The callback rechecks the port's send-right count and make-send generation, then removes the eligible IOMachPort association before dispatching the FairPlay user client's `clientDied`. Explicit close enters `clientClose` directly on its selected branch. Both can reach the same termination request. No native FairPlay retirement was observed. [Connection publication and close](live_fairplay_connection_report.md)

```text
Last kernel send right released
  |
  +-- IOKit connection policy -> kernel callback(port, generation)
  |     -> verify association and generation -> remove association
  |     -> FairPlay clientDied -> IOUserClient::clientDied --+
  |                                                        |
  +-- ordinary notification request -> Mach message 70     |
                                                           v
Explicit close (2816) -> shared-instance / closed gate -> clientClose
   |                                                       |
   +-- framework deallocates its name after the reply      v
                                                   terminate(0)
```

## Registration and dispatch

All addresses are preferred and unslid. The verified boot collection has SHA-256 `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`, kernel UUID `90195379-954d-3ca3-baac-327341f14211` and FairPlayIOKit UUID `316464f8-eade-30ca-938e-2f430b1ed5bc`. The kernel UUID also matches the running host. The executable and chained fixups establish the addresses. Apple XNU release `xnu-12377.121.6` supplies names and structure semantics for comparison. [IOKit registration source](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/device/iokit_rpc.c#L76-L87) [Policy initialization source](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_policy.c#L1767-L1794)

| Transition | Address | Verified behavior |
| --- | --- | --- |
| Startup record | `0xfffffe000cc6d790` | Subsystem 14, rank 0. Its signed function pointer targets `0xfffffe000c679290` and its argument points to the connection descriptor. |
| Connection descriptor | `0xfffffe000cc597e8` | Type `0x27`, name `IKOT_IOKIT_CONNECT`, signed callback at +16 B targeting `0xfffffe000c5b69a0`, corresponding to `iokit_connect_no_senders`. |
| Populate policy | `0xfffffe000c6792c4`, `0xfffffe000c6792fc` | Sets policy bit 5 when the callback is present and copies the callback to row +24 B. Startup default initialization preserves an existing callback. |
| Release a kernel send right | `0xfffffe000bd18258`–`0xfffffe000bd1828c` | Decrements the 32-bit count at port +136 B. An active port reaching zero enters notification preparation. |
| Capture event | `0xfffffe000bd10f40`–`0xfffffe000bd10f64` | For the type-`0x27` policy with bit 5 set, retains the affected port and returns it with the u32 make-send generation from port +132 B and a kernel-object flag at bit 32 of the packed result. |
| Invoke connection callback | `0xfffffe000bd182f8`, `0xfffffe000bd11098`–`0xfffffe000bd110b0` | With the flag set, dispatches through the active port's policy callback with the port in X0 and generation in W1. Authentication uses IA with modifier `0xd507`, matching the descriptor fixup. Releases the notification reference afterward. |
| Emit ordinary notification | `0xfffffe000bd182e4`, `0xfffffe000bd11020`, `0xfffffe000bd11048` | With the flag clear and an active requested destination, supplies that destination at expanded header +8 B and submits a 44 B kernel buffer. The constant at `0xfffffe000700dd18` encodes voucher word zero and message ID 70. |

The policy table starts at `0xfffffe0007e6eb70`. The startup writer and dispatch reader both form a 40 B stride by multiplying the type by five and then shifting left by three. The connection callback slot is `0xfffffe0007e6eb70 + 39 * 40 B + 24 B = 0xfffffe0007e6f1a0`. Its initial image bytes are zero. The startup record and the store into that same slot establish the static binding. The kernel-object path passes the affected connection port internally. The message-70 path sends to the separate, previously requested notification destination. [XNU send-right release](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_port.c#L3009-L3030) [XNU notification preparation and dispatch](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/ipc/ipc_notify.c#L133-L177)

## Registry and user-client lifetime

| Transition | Address | Verified behavior |
| --- | --- | --- |
| Recover IOMachPort | `0xfffffe000c5b69bc` -> `0xfffffe000c5b58a4` | The callback supplies the port, type `0x27` and captured generation. The helper checks active state and type, then authenticates the association at port +80 B. |
| Recheck under lock | `0xfffffe000c5b5938`–`0xfffffe000c5b5990` | Requires a nonnull association, current send-right count zero and current make-send generation equal to the captured u32. The callback exits when the helper returns null. |
| Remove association | `0xfffffe000c5b5a08`–`0xfffffe000c5b5a44`, `0xfffffe000bd3d178` | Clears the hashed flag and unlinks the node when present in a bucket. The disable helper checks the port type and writes an authenticated null to port +80 B. |
| Invoke user-client death handler | `0xfffffe000c5b6a20`, `0xfffffe000c5b6a70`–`0xfffffe000c5b6a98` | Checks the object's ancestry against `IOUserClient::gMetaClass`, takes the client's write lock, calls vtable +`0x928` and unlocks. The returned IOMachPort node is released at `0xfffffe000c5b6ad4`. |
| FairPlay override | `0xfffffe0008481c30` -> `0xfffffe000a545630` | The address-diverse vtable slot with modifier `0xea14` resolves to FairPlay `clientDied`. It stores byte value 1 at client +244 B and uses an authenticated tail branch through the base `clientDied` slot at `0xfffffe0007f627a0`. The semantic name of the byte is unknown. |
| Base-class close gate | `0xfffffe000c5b2038`–`0xfffffe000c5b208c` | Calls virtual `clientClose` when the shared-instance byte at +152 B is set or the closed byte at +153 B changes atomically from zero to one. The failed compare-and-swap branch returns `0xe00002d8` (`kIOReturnNotReady`). |
| Explicit-close join | `0xfffffe000c5be85c`, `0xfffffe000c5be894`, `0xfffffe000a545620` | The explicit RPC checks the same closed byte and calls vtable +`0x920` directly on its selected branch. That binding resolves to FairPlay `clientClose` and requests inherited `IOService::terminate(0)`. |

The affected association is the same port +80 B field authenticated by the method and close imports. Wrapper deallocation releases the caller's name reference after the RPC. The callback rechecks that the port's kernel send-right count is zero and that the make-send generation matches the captured value. Apple's published source also shows a separate internal cleanup path, `IOUserClient::destroyUserReferences`, that disables the prior association and can rebind the connection port to a mappings object. Its use and ordering on a native FairPlay transaction are unknown. [Connection publication and close](live_fairplay_connection_report.md) [XNU registry retirement](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOUserClient.cpp#L263-L306) [XNU internal reference cleanup](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOUserClient.cpp#L352-L391) [XNU connection callback](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOUserClient.cpp#L755-L770) [XNU base death handler](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/iokit/Kernel/IOUserClient.cpp#L1979-L1989)

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| R1 | The identified collection is the installed kernel and matching FairPlay kext. All instruction addresses and fixups depend on that identity. | Recompute the collection SHA-256, read both fileset UUIDs and compare the running kernel UUID. |
| R2 | Ordinary boot runs the recovered subsystem-14 startup record. The populated runtime row follows from that path. | Recover the function and argument fixups independently, match the computed store and read addresses, and check the default initializer's nonnull branch. Direct observation of the live policy row remains unknown. |
| R3 | The callback's port still has a current type-`0x27` IOMachPort association and the client uses the recovered FairPlay vtable. The unlink and FairPlay dispatch depend on these conditions. | Compare the stale-generation, nonzero-send-count and null-association branches against the selected success branch. Check the FairPlay and base-class vtable fixups independently. |
| R4 | Native ordering of successful daemon open, explicit close, final send release and object deallocation is unknown. | Correlate those events from the same ordinary transaction using port-object identity and the make-send generation. No existing trace establishes the sequence. |

High impact for assigning a specific kernel callback and association-removal operation to the connection type. Medium impact for interpreting close logs and avoiding conflation of a task-local deallocation, an emitted notification and a termination request. Low impact for the extra FairPlay byte store until its downstream consumers are identified.

QG1 covers factual scope. QG2 covers premises and probes. QG3 covers registration, callback and emission sites, association removal and close. QG4 verifies u32 fields, byte offsets and the policy-slot calculation. QG5 covers stale and shared-instance paths and unknown native ordering. QG6 uses the original code, chained pointers and released Apple source. QG7 records bounded effects on port and client attribution. For a collection of B bytes, F fixups and I checked instructions, the audit uses O(B + F + I) time and space, excluding host identity queries. It only reads the collection and identity information. [Audit script](triage_evidence/audit_live_fairplay_connection_retirement.py) [Compressed receipt](triage_evidence/live_fairplay_connection_retirement_audit.json.zst)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_connection_retirement.py "$CURRENT_COLLECTION"
```
