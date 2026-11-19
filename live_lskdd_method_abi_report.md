# Installed lskdd selector 18 and 19 call boundaries

The follow-up audit resolves selector 19's authenticated import under the recovered frame contract and identifies matching buffer and output-count producers for both selectors. [Selector 19 binding and frame](live_lskdd_selector19_binding_report.md)

The running `lskdd` FairPlayIOKit attachment and the installed arm64e executable are corroborated on build `26C5035r`. The executable has two candidate structure-method call blocks. Their local argument assignments match the current FairPlayIOKit table for selectors 18 and 19, including the full fixed input size. The reaching authenticated call targets, the specific providers behind the loaded connection names and native transactions remain unknown. [Registry and installed-slice identification](live_fairplay_additional_clients_report.md) [Current FairPlayIOKit method table](live_kext_selector26_report.md)

## Daemon block operands

Addresses are preferred and unslid. The audit rechecks the live Mach-O offset of `0x124000` B and 20 B CodeDirectory hash against the recorded arm64e identity and checks the installed slice SHA-256. The original chained fixups contain authenticated code pointers to both block starts. They establish the address-taken entries, while the predecessor dispatch and runtime reachability remain unknown.

| Operand or site | Selector 18 | Selector 19 |
| --- | --- | --- |
| Block entry and original fixup slot | `0x100584b8c`, slot `0x100e44f08` | `0x100474cc4`, slot `0x100e38ff8` |
| Authenticated call | `0x100584cc8` | `0x100474e38` |
| W0 connection name | u32 from `[X10]` at `0x100584c9c`, after X10 loads from SP+0x40 B | u32 from `[X20]` at `0x100474dcc` |
| X2 input pointer | X20 at `0x100584cb8` | Pointer from SP+0x9ae8 B at `0x100474db0` |
| W3 input length | `0xc18` B | `0xc10` B |
| X4 output pointer | X21 at `0x100584cc0` | X19 at `0x100474e30`, after X19 loads from SP+0x89f8 B |
| X5 output-count pointer | SP+0x90 B at `0x100584cb0` | SP+0xaaa0 B at `0x100474e20` and `0x100474e24` |
| Slot used to load X8 | `X28 + 8 * (0x8d41 + u8)` at `0x100584cac` | `X22 + 8 * (0x8caa + u8)` at `0x100474e1c` |

The selector 19 block stores an eight-byte value into input +0 B at `0x100474dc0` and the u32 value 3,072 at input +8 B at `0x100474dc8`. The latter matches the expected length in the previously recovered `GetReEncryptionVault` contract. The initial value in each output-count cell remains unknown. [Earlier FairPlayIOKit structure contracts](foundational_triage_report.md)

All four original arm64e fixups with the call's instruction key, no address diversity and modifier `0x21c3` are listed below. The modifier therefore gives a compatible binding set. A reaching table base and byte-derived index are required to identify the actual slot.

| Slot | Original binding kind | Original target |
| --- | --- | --- |
| `0x100e738d0` | Import | `IOKit/_IOConnectCallStructMethod` |
| `0x100e738d8` | Import | `CoreFoundation/_CFDataGetTypeID` |
| `0x100e739c0` | Import | `libSystem/_vm_allocate` |
| `0x100e739c8` | Rebase | `0x100345e24` |

## Conditional Mach footprints

The installed IOKit export at `0x184ebedb0` forwards the output buffer and size pointer as stack arguments and sets both scalar counts to zero before calling `IOConnectCallMethod`. The synchronous inline path applies when the input size and initial output capacity are at most 4,096 B. This gives exact candidate envelopes if the block reaches this export and selects the corresponding FairPlayIOKit connection.

| Selector | Current driver member | Method table input / output | Request 2865 | Successful reply 2965 with full structure |
| --- | --- | --- | --- | --- |
| 18 | `ProcessEncryptedData` thunk at `0xfffffe000a544f54` | 3,096 B / 3,096 B | 3,180 B | 3,148 B |
| 19 | `GetReEncryptionVault` thunk at `0xfffffe000a545190` | 3,088 B / 3,088 B | 3,172 B | 3,140 B |

Request width is 84 B plus the input size rounded up to a multiple of 4 B, with zero scalar inputs. The selector is at message +32 B, input count at +40 B and input data at +44 B. The method stub obtains the receive name at `0x184ebe04c`, writes connection and reply names at `0x184ebe05c`, and requests transport at `0x184ebe090`. The outgoing destination uses `COPY_SEND`, and the local reply port uses `MAKE_SEND_ONCE`. The packed reply width is 52 B plus the returned inline count rounded up to a multiple of 4 B and 8 B per returned scalar. Both table extents are already multiples of 4 B. Reply structure data starts at +40 B. With sufficient capacity, the framework copies the returned extent and updates the size at `0x184ebe200` and `0x184ebe204`. The ordinary short error reply has the same ID 2965 and is 36 B. The task-local Mach names and returned body values remain unknown. [Installed framework and kernel transport boundaries](live_iokit_mach_transport_report.md)

The supplied RAX trace captures an unsuccessful `fairplayd` open and has no method request 2865. It establishes no `lskdd` selector traffic. IDA MCP listed no loaded `lskdd` database during this audit. The source is the installed daemon, shared cache and earlier kernel-collection method-table receipt. [RAX trace interpretation](zut_trace_report.md)

## Assumption register and checks

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| L1 | The installed slice corresponds to the active registry client. This qualifies the call-block PCs. | Requery the registry child, live slice offset and CodeDirectory hash after file inspection. Require the installed slice SHA-256 and both original authenticated entry fixups. |
| L2 | A candidate block selects the structure-method import. This qualifies the IOKit argument interpretation. | Recover the reaching table base and byte banks and require the resulting slot to be `0x100e738d0`. The other three matching fixups rule out authentication metadata alone as evidence. |
| L3 | The block's connection points to FairPlayIOKit and its output capacity selects the ordinary inline path. This qualifies the request envelope and driver member identity. | Track the issuing task's connection and read the initial output count. Compare the chosen kernel class and selector with the same request. |
| L4 | The method returns the full structure and zero scalars with sufficient buffer capacity. This qualifies the success reply widths. | Compare returned count, scalar count and message extent with the reply constructor and framework copy for the same transaction. |

The calculated width pairs have high impact for correlating ordinary daemon and kernel method events, with the selector and connection required for attribution. The modifier collision has medium impact on interpreting authenticated calls. For N installed bytes, F fixups and I selected words, the audit uses O(N + F + I) time and space, excluding system query costs. The envelope calculations each use O(1) time and space.

QG1 covers factual claims. QG2 records four premises and falsification probes. QG3 covers both selectors, both Mach directions and the reply path. QG4 checks alignment and fixed widths. QG5 keeps the candidate and native observations scoped. QG6 checks source slice identity, fixups, cache, and the current method table. QG7 bounds the correlation and authentication findings. [Audit source](triage_evidence/audit_live_lskdd_method_abi.py) [Compressed receipt](triage_evidence/live_lskdd_method_abi_audit.json.zst)
