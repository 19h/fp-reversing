# IOKit open reply validation and connection copyout

The installed arm64e IOKit wrapper copies the returned connection name on the accepted complex 2962 reply path. It performs this store even when the reply carries a nonzero provider result. The RAX capture's null connection and `0xe00002c2` result match that reply shape. For the recovered `lskdd` selector 19 route, the caller's output pointer is `0x100e82af8`. [Archived open](live_fairplay_iokit_open_report.md) [Daemon output pointer](live_lskdd_selector19_open_copyout_report.md)

## Reply fields and return channels

At `0x184ebdb84`, public `IOServiceOpen` forwards its X3 output address in X7 and creates a separate local u32 application status. The extended stub retains the output pointer in X19 at `0x184ebdbd8` and the application status pointer in X20. It obtains the reply name through `_mig_get_reply_port` at `0x184ebdc20`. It writes the service and reply names at `0x184ebdc30` and emits request 2862 at `0x184ebdc6c`. The service name carries COPY_SEND and the local field makes a send-once reply right. The task right is a separate request descriptor. [Transport and names](live_iokit_mach_transport_report.md)

| Return path | Framework site and result | Caller connection output |
| --- | --- | --- |
| Accepted complex reply 2962 | `0x184ebdd08` through `0x184ebdd48` checks one descriptor, 52 B, received remote name zero and a port-send descriptor. The stub returns zero. The wrapper returns the u32 application result from reply +48 B. | `0x184ebdd48` writes the u32 name from reply +28 B. This includes a null descriptor name paired with provider failure. |
| Accepted short routine error | `0x184ebdcc4` through `0x184ebdce8` checks 36 B, a nonzero status at +32 B and received remote name zero. The wrapper returns the stub's routine status. | No store. |
| Transport error | `0x184ebdc70` through `0x184ebdcf4` holds the status in W21 for return. | No store. |
| Rejected or notification reply | ID 71 selects `MIG_SERVER_DIED` (−308). Any other unexpected ID selects `MIG_REPLY_MISMATCH` (−301). The other validation failures use `MIG_TYPE_ERROR` (−300). | No store. |

The accepted complex decoder tests type and disposition together at reply +38 B. The halfword is `0x0011`, with disposition 17 and port descriptor type zero. The application status store at `0x184ebdd44` and connection name store at `0x184ebdd48` follow that check. A nonzero caller-visible return alone therefore leaves the output's write history ambiguous. A transport or routine error leaves the previous word intact, while the archived provider-error reply would write zero under this decoder. The archive's equivalent framework build remains unknown.

## Reply-name lifetime

| Condition | Call site | Current behavior |
| --- | --- | --- |
| `MACH_SEND_INVALID_DATA`, `MACH_SEND_INVALID_DEST` or `MACH_SEND_INVALID_HEADER` | `0x184ebdca0` calls `_mig_put_reply_port` through slot `0x1e20f3a08`. | The resolved implementation consists of a return instruction at `0x18054e1d8`. |
| Other nonzero transport result | `0x184ebdcf0` calls `_mig_dealloc_reply_port` through slot `0x1e20f39e0`. | On the ordinary cached-name path it drops the receive reference via `mach_port_mod_refs`, deallocates the supplied name when it differs from the cached name, then clears thread storage +16 B. A zero or sentinel cached name takes the early return. |
| Simple routine error or reply rejected during decoding | `0x184ebdd58` calls `_mach_msg_destroy` through slot `0x1e20f37a8`. | The reply buffer is passed for disposal. |
| Accepted complex reply | `0x184ebdd44` and `0x184ebdd48` | The stub copies both fields and returns through its restore sequence. The cached reply name can be reused by the same issuing thread if it survives to another call. |

Kernel stub `0xfffffe000be81c84` writes the exported connection's port object into expanded reply +36 B. The caller's `0x184ebdd48` receives the packed 32-bit name, a namespace-local representation. A later `lskdd` method uses that connection as the remote name for 2865. The local reply name still comes from the thread's reply-port helper. An actual native 2962-to-2865 pair and numeric names remain unobserved. [Kernel open stub](live_fairplay_iokit_open_report.md) [Method transport](live_iokit_mach_transport_report.md)

## Assumption register

| Premise and dependent result | Falsification probe |
| --- | --- |
| The current cache and library UUIDs identify the inspected implementation. This qualifies the addresses and helper targets. | Recheck cache and image UUIDs, original instructions and v5 slide-chain membership. |
| The ordinary selector 19 fresh-open path passes the recovered output pointer. This qualifies the shared-cell store. | Correlate X3 at the daemon call with X19 at the decoder store and the subsequent connection load. |
| The historical trace's producer and consumer use the same field interpretation. This qualifies its comparison with the current decoder. | Verify the historical image or recover contemporaneous wrapper instructions. |

High impact for copyout and status attribution. Medium impact for reply-name reuse and cleanup. Seven local SDK assertions check layout and constants. The byte-backed audit verifies 31 instruction sites and five authenticated slide-chain bindings. Local field decoding takes O(1) time and storage. Native process image pairing, right lifetime and invocation remain unverified. [Compressed audit receipt](triage_evidence/live_iokit_open_reply_copyout_audit.json.zst)
