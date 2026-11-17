# Selector 26 status in synchronous MIG reply 2965

The pinned synchronous IOKit server preserves both nonzero FairPlay selector 26 results in the simple MIG reply. The retained user-space IOKit code returns the same 32-bit value through `IOConnectCallStructMethod` when Mach receive succeeds and the reply passes its header checks. The supplied fairplayd trace contains no request 2865. [Selector 26 handler results](userclient_populated_cleanup_report.md) · [Historical trace](zut_trace_report.md)

| Selected handler outcome | Handler W0 | Kernel reply RetCode at +40 B | User reply RetCode at +32 B | Public wrapper W0 |
| --- | --- | --- | --- | --- |
| SR1. Command-tag miss | `0xffff5bbc` | `0xffff5bbc` | `0xffff5bbc` | `0xffff5bbc` |
| SR2. Match followed by scalar-type rejection | `0xffff5a87` | `0xffff5a87` | `0xffff5a87` | `0xffff5a87` |

## Server return and reply construction

Kernel PCs omit the common `0xfffffe0000000000` prefix. Request 2865 selects the routine record at `7e6c438` and the stub at `be386b4`. The original pointer at `7e6c440` has IA discriminator `0x3a83`. The record declares 4284 B of reply capacity and zero reply descriptors. The dispatcher at `bcf4830` calls the stub with the kernel request header, request body, end/trailer pointer, reply header and reply body in X0–X4. The header and body pointers refer to the selected kernel representation, where the simple reply body starts 32 B after the header. [Connection lifecycle and routine metadata](iokit_connection_lifecycle_report.md)

| Boundary | Source PC | Result on the selected path |
| --- | --- | --- |
| Legacy structure adapter | `c562fec` -> `c565154`; authenticated tail branch at `c5653b4` | The direct member inherits link `c562ff0`. The 64-bit local output-size cell remains 16 B, so the high-word check at `c562ffc` preserves W0 and writes the u32 size at `c563004`. |
| Synchronous dispatch helper | `c57089c`, `c5708bc`, `c5708dc`, `c5708e0` | Calls the selected legacy virtual method, saves its return in X20, calls the unlock/accounting routine and restores X0 from X20. |
| Synchronous implementation | `c570ba0`, `c570ba4`, `c5709a8` | Saves the helper result in X23, writes back output counts and returns it in X0. Both outer memory descriptor arguments are null on the selected in-band route. |
| MIG status and reference release | `be38840`, `be38864`, `be38868` | Saves W0 at reply body+8 B before the converted connection reference release. The subsequent load recovers the same u32 regardless of the release's volatile X0. |
| Nonzero reply publication | `be3886c`–`be38880` | Writes that u32 at reply header+40 B and copies the kernel NDR record at +32 B. Bypasses the variable success layout and keeps the dispatcher-initialized 44 B extent. |

The dispatcher initializes the 44 B header/body extent at `bcf4764`, extracts the reply disposition from request bits 8–12, and copies the request's internal reply object from header+16 B to reply header+8 B at `bcf4778`. It clears the reply's other port slot and voucher, and adds 100 to the request ID at `bcf4784`. Both status words pass the generic `-305` no-reply comparison at `bcf489c`. That check precedes the later reply-destination and queue contracts. [Common reply send](kernel_reply_send_report.md)

## From kernel reply to the framework return

| Field | Kernel form | User form after simple header packing |
| --- | --- | --- |
| Inline message extent | 44 B = 32 B header + 8 B NDR + 4 B RetCode | 36 B = 24 B header + 8 B NDR + 4 B RetCode |
| ID | 2965 at +28 B | 2965 at +20 B |
| NDR | `0000000001000000` at +32 B | Same at +24 B |
| RetCode | u32 at +40 B | Same u32 at +32 B |

The audited packer at `bcc6630`–`bcc6654` writes the user header 8 B later in the same kernel storage and subtracts 8 B from the inline message size. The NDR and RetCode remain in place. Converted Mach names are supplied by the namespace-copyout stage. The framework requires a null received remote name on the short-result route. The receive name occupies the separate local field. Numeric names and object identities for this exchange remain unknown. [Kernel-to-user copyout](kernel_user_copyout_report.md)

The retained IOKit client calls the transport veneer `0x188088a80` at `0x184e78090`. The veneer resolves to `_mach_msg2_internal` at `0x18055a894`. The ordinary request uses the connection as the COPY_SEND destination and a separate MAKE_SEND_ONCE disposition for its reply name. After transport success, the framework checks reply ID 2965, the simple-message bit, the null remote name and exact 36 B size. At `0x184e78120` it selects the nonzero body word into W19. The cleanup call at `0x184e78154` preserves X19, and `0x184e77f94` returns it in X0. Treating the kernel's 44 B extent as a user reply size instead yields the raw MIG type error `-300` in the model.

The short reply does not enter the in-band structure output copy. The outer wrappers preserve X0. On the selected in-band route, `IOConnectCallMethod` rewrites the public output-size cell from its initialized 16 B local size, which the short result leaves unchanged. The 16 B outer structure and the 14 B extent carried inside it belong to different ABI layers. [Structure arguments and success geometry](iokit_structure_arguments_report.md)

## Evidence and assumptions

The [auditor](triage_evidence/audit_iokit_sync_error_reply.py) checks 50 source ranges totaling 114 instruction words. It compares kernel slices against the original collection and validates the framework slices against the retained function hashes. Six satisfiable premises and six unsatisfiable violation queries cover the selected server return, reply layout, packing, client return and size-representation check. The [compressed receipts](triage_evidence/iokit_sync_error_reply_audit.json.zst) have decoded SHA-256 `fd4934a1afee8f9fb51d7011526f00d5212062450f5fd7c792fbed2ca60d33ca`.

| Assumption | Dependent claims and falsification probe |
| --- | --- |
| SR-A1. Kernel UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84` and retained dyld-cache UUID `2bd06591-e751-3e84-963f-b08dab6af23a` match their captured images. | SR1–SR2. Reread original kernel words and compare the retained framework function hashes and original cache-chain record. The installed cache has a different UUID, so the framework result applies to the retained capture. |
| SR-A2. Admission reached the nominal legacy member and returned normally. Input/output structure extents are 16 B, with zero scalar counts and both outer descriptors absent. | Server return. Recheck the original selector record, in-band argument roles, output-size high word, and nominal call/link. Native class, filter and authentication admission remain premises. |
| SR-A3. The kernel reply has ordinary disjoint backing, the frame canaries agree, and the selected callees return preserving their saved registers and live cells. | Server status and reply. Check the store before release with unconstrained volatile X0, then compare the header, NDR, and status bytes on both sides of packing. |
| SR-A4. The reply reaches the normal Mach receive path and has the expected converted names. | Public return. Check ID, complex bit, null received remote name, size and body-word extraction. The 44 B versus 36 B check distinguishes kernel and user forms. No native delivery or fairplayd correlation is established. |

The fixed-size reply construction and decoding take O(1) time and extra space, apart from transport, namespace operations and the selected device method. The audit processes bounded source spans and byte cells with O(B + I) data work for inspected bytes B and lifted instruction instances I. Solver time is separate.

## Bounded continuation

| Impact | Open evidence |
| --- | --- |
| High | Correlate a native fairplayd call site, selected connection, request and reply rights, method result, and continuation in one transaction. The retained trace records 22 sends and no 2865 request. |
| Medium | Follow the ordinary FairPlay request path to determine whether the daemon preserves, translates or retries these results after the framework returns. |

## Quality gates

- **QG1** passed for factual source and ABI analysis.
- **QG2** passed with SR-A1–SR-A4 and their probes.
- **QG3** passed for the two selected status paths through the nominal public return.
- **QG4** passed with explicit widths, offsets, byte extents and complexity.
- **QG5** passed with the nonzero, success-layout, and kernel/user size cases distinguished.
- **QG6** passed with pinned kernel and framework words, pointer provenance and replayable queries.
- **QG7** passed with ranked remaining transport and daemon joins.
