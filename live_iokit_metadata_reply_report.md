# Successful inline FairPlayIOKit metadata reply

In the current kernel and IOKit cache, an ordinary successful selector 22 or 23 call produces a 64 B internal reply and a 56 B packed Mach reply with ID 2965. The four-byte metadata word is at packed offset +40 B. IOKit verifies the reply, copies those four bytes to the daemon's output buffer, and stores a 64-bit returned size of 4 B. Five instruction-derived counterexample queries establish the handoff for an arbitrary 32-bit provider word under the ordinary inline-call premises. The native method exchange remains unobserved. [Offline audit](triage_evidence/live_iokit_metadata_reply_audit.json.zst) [Current getter values](live_fairplay_metadata_report.md)

## Packet fields and right use

The recovered daemon calls at `0x100364420` and `0x1004ba9c4` submit selectors 22 and 23 after a successful open on the observed caller's path. Each ordinary request is 84 B with ID 2865, no input bytes or input scalars, and 4 B of output capacity. IOKit writes the connection and reply names at `0x184ebe05c` and emits through `0x184ebe090`. The connection is the request's `COPY_SEND` destination and the local reply field is `MAKE_SEND_ONCE` on a separate receive name. The kernel dispatcher transfers the reply right into the seed reply at `0xfffffe000bd3c474` and writes request ID + 100 at `0xfffffe000bd3c484`. Its ordinary queue handoff starts at `0xfffffe000bd0f208`. The packed receive name belongs to the receiving task and its numeric value remains unknown. [Current Mach transport](live_iokit_mach_transport_report.md) [Observed daemon open path](daemon_iokit_callsite_capture_report.md)

| Reply field | Internal offset | Packed offset | Width and expected value |
| --- | ---: | ---: | --- |
| Header size field | +4 B | +4 B | u32, 64 B internal and 56 B packed |
| Destination right / converted local receive name | +8 B before translation | +12 B | Kernel object then u32 receive name |
| Message ID | +28 B | +20 B | u32, 2965 |
| NDR | +32 B | +24 B | 8 B, `00 00 00 00 01 00 00 00` |
| MIG return code | +40 B | +32 B | u32, 0 |
| Inline result extent | +44 B | +36 B | u32, 4 B |
| Provider metadata | +48 B | +40 B | u32, selector 22 `00 00 0b 4c`, selector 23 `f8 01 00 00` |
| Returned scalar count | +52 B | +44 B | u32, 0 |
| Out-of-line result extent | +56 B | +48 B | u64, 0 |

The packed header is simple and its received remote name is null. No descriptor or scalar output bytes occur in this reply. The 56 B extent excludes the Mach trailer. The ordinary short error form shares ID 2965 and occupies 36 B, with a nonzero return code at packed +32 B. The success body carries no selector echo. To identify a live call, correlate the reply right and receive event with the preceding request's selector and connection. [Short error reply](iokit_sync_error_reply_report.md) [Current framework parser](live_iokit_mach_transport_report.md)

## Direct kernel write and inline count forwarding

Let K be the internal reply header address immediately before packing. The stub's X4 body pointer is K+32 B. At `0xfffffe000be81654`–`0xfffffe000be81664`, the stub caps the requested structure output at 4,096 B and stores the selected 4 B extent at K+44 B. At `0xfffffe000be8168c` and `0xfffffe000be816b0` it passes K+48 B and the address of K+44 B as the first two stack arguments to the synchronous implementation. That implementation seeds `IOExternalMethodArguments.structureOutput` and `structureOutputSize` at argument +88 B and +96 B. It later writes the returned u32 count through the original K+44 B pointer at `0xfffffe000c5c023c`. [Typed argument layout](iokit_structure_arguments_report.md)

The flags-3 adapter receives the output pointer in X4 and a local 64-bit output count in X5. After the exact count checks it moves X4 to X1 at `0xfffffe000c5b49b8` for the no-input member and tail-transfers through the original authenticated member word at `0xfffffe000c5b4a34`. The two UserClient stores at `0xfffffe000a5462a0` and `0xfffffe000a5462f8` consequently write into K+48 B. Their W0 status and the four data bytes travel on different channels. The count remains four when the member returns normally. The legacy caller copies the low 32 bits of the local count back at `0xfffffe000c5b2684` after checking its high half at `0xfffffe000c5b2674`. [Current methods and original records](live_fairplay_metadata_report.md)

The stub saves the method's W0 at `0xfffffe000be816b8` and reloads it at `0xfffffe000be816e0` after releasing its connection-object reference. For status zero, the success block aligns the inline extent to four bytes and copies the scalar segment with byte count zero. It writes the scalar count at `0xfffffe000be8173c`, the out-of-line result extent at `0xfffffe000be81750` and the internal size word at `0xfffffe000be81754`. The internal size is `60 B + round_up(4 B, 4 B) + 8 B * 0 = 64 B`. On the ordinary simple-header packing path, `0xfffffe000bd0e5f4` subtracts 8 B and `0xfffffe000bd0e604` advances the header start by 8 B before rewriting it. The already written body stays at the same storage address, so its offsets relative to the new header decrease by 8 B. [Current queue and copyout sites](live_iokit_mach_transport_report.md)

## Framework validation and daemon publication

The IOKit cache code at `0x184ebe0dc`–`0x184ebe1c4` checks the reply ID, simple-header form, null received remote name, return code, both counts and their relationship to the packed size. With the reported extent of 4 B and a zero scalar count, its size equality is `52 B + round_up(4 B, 4 B) + 8 B * 0 = 56 B`. At `0x184ebe1d4`, the returned extent fits the supplied capacity. The call at `0x184ebe200` reaches `__platform_memmove` through the original authenticated cache slot `0x1e20f1fa0`, with the daemon buffer in X0, packed reply+40 B in X1 and count 4 in X2. After writing its u32 temporary extent at `0x184ebe204`, the successful path checks/scatters the zero scalar and out-of-line counts and returns zero. The enclosing wrapper widens the temporary count and writes the caller's eight-byte `size_t` at `0x184ebde78`. These two results satisfy the daemon's status-zero and exact-size-four guards. [Daemon guard and cache effects](live_fairplay_metadata_report.md)

## Assumptions and verification

| ID | Premise and dependent finding | Falsification probe | Impact |
| --- | --- | --- | --- |
| R1 | Current collected kernel, kext and installed cache frames refer to the named builds. Addresses rely on these identities. | Requery kernel, kext and task cache UUIDs on the host of a native capture, then rehash the original images. | High |
| R2 | The same valid connection selects the current FairPlayIOKit base-provider path, ordinary inline counts and normal retained-object release. This governs the returned values and layouts. | Pair the open's connection descriptor, the selected 2865 request, the actual UserClient and the zero-status return. | High |
| R3 | Argument records and reply buffers meet the declared alias and extent conditions. Helper calls preserve relevant fields and the ordinary memmove copies its declared span. | Observe the provider output pointer, kernel size fields and user copy arguments in one transaction. | High |
| R4 | Ordinary queue delivery and namespace copyout succeed with a simple header and null remote receive name. This qualifies the 56 B packed result. | Pair the internal reply object and destination with the packed header, trailer and receive name in the waiting task. | High |

The auditor checks original collection and cache bytes and the authenticated copy binding. It discharges five nonvacuous bit-vector queries for the stub arguments, value and count forwarding, expanded reply, packed layout and framework copy. The selected instruction and record extraction has O(B + F + I) time and space for image bytes B, fixup/symbol data F and audited instruction bytes I, excluding solver cost. The proof keeps queue scheduling, provider selection, PAC, namespace translation and opaque helper effects as explicit premises. It uses the original sources and the verified metadata receipt. IDA was unnecessary for this increment. [Auditor](triage_evidence/audit_live_iokit_metadata_reply.py) [Instruction and query receipt](triage_evidence/live_iokit_metadata_reply_audit.json.zst)

```sh
python3 triage_evidence/audit_live_iokit_metadata_reply.py "$CURRENT_COLLECTION"
```
