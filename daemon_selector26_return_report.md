# fairplayd selector 26 return handling

The two selector 26 call sites in the pinned daemon use the same authenticated IOKit import. Their local return paths differ. At `0x1002069c4`, the recovered phase sends a nonzero API status directly to the result record. At `0x100293074`, the recovered phase first checks the two size fields and can copy the payload before storing the encoded status. The earlier MIG audit supplies the two status words and the short reply's descriptor behavior. [Synchronous MIG 2965 reply](iokit_sync_error_reply_report.md)

| Call PC | Structure input and output | Result field | `0xffff5bbc` | `0xffff5a87` |
| --- | --- | --- | --- | --- |
| `0x1002069c4` | Same record-supplied pointer, selected extent 16 B | u32 at record+24 B, store at `0x10020e6b0` | `0x74c29ded` | `0x74c29cd6` |
| `0x100293074` | Same 16 B stack descriptor, selected inner extent 14 B | u32 at record+8 B, store at `0x1001f48bc` | `0x74c29ded` | `0x74c29cd6` |

The first row injects the two status words at the API boundary. Its input-payload lineage to the selected kext cases is unknown. The second row composes the 16 B public size, unchanged descriptor address and unchanged 14 B inner extent from the modeled short reply. Both encodings are `W0 xor 0x8b3dc651`.

## Connection and Mach transport

Both sites read the connection name from context+4 B and put it in W0. W1 is 26. X5 is a pointer to a u64 output-size cell at SP. Both call instructions use IA discriminator `0x7a6c`. The original left and right lookup banks produce index `0xccea` for all 256 byte inputs at either site. The original format-12 fixup in slot `0x1010a0640` binds `_IOConnectCallStructMethod`, library ordinal 104. The two predecessors separately recover the jump-table base and enter at slots `0x101099820` and `0x101094238`.

The actual Mach send and receive are in the framework. The retained framework calls the transport veneer at `0x184e78090`. Request 2865 uses the connection as COPY_SEND and a separate reply name as MAKE_SEND_ONCE. The matching short reply 2965 carries the converted receive name and a null remote name. The daemon instructions above supply the connection and consume the return. Numeric names, native right identities and a correlated request/reply instance remain unknown. The supplied emulator trace contains 22 sends and no request 2865. [Mach port inventory](mach_ports_report.md) · [Transport and reply fields](iokit_sync_error_reply_report.md) · [Trace coverage](zut_trace_report.md)

## First call

The selected record decode at `0x10043a14c` loads the structure pointer and connection context from record+0 B and +8 B. It decodes the input extent and control word from +16 B and +20 B. For nonnull pointers and decoded control `0xbf1d`, W21 becomes `0x8b3dc651` and `0x10043a23c` selects index `0xbf26` into `0x10020693c`. The decoded extent is used both to initialize the u64 stack capacity at `0x10043a19c` and to fill the input extent in X3. The audit uses 16 B.

For any API status S and inherited phase P in W21, the post-call code computes the encoded status `S xor 0x8b3dc651`. It forms the branch index by taking the u32 sum `P + 0x74c26032` and XORing `0x9fe` into it when the encoded status equals P. In the selected phase P is `0x8b3dc651`, so zero API status is the case that reads the u64 count at `0x1002724a0`. A size mismatch on that edge substitutes `0x74c29fc9`. Each studied nonzero status selects slot `0x10104d308` and writes the result at `0x10020e6b0` without reading the returned count. The epilogue reaches `RETAB` at `0x10020e6c8`.

## Second call

The selected record decode enters `0x100292fc0` with phase `0xb469`. The descriptor's u64 address is written at SP+8 B and the u32 extent at SP+16 B. The final 4 B are zero from the earlier initialization at `0x10043efa8`. The outer structure size is 16 B, and the inner extent in this composition is 14 B.

| Order | Source PC | Selected effect |
| --- | --- | --- |
| 1 | `0x100293078`–`0x1002930a8` | Loads the full u64 outer size. A value of 16 B selects index `0xa5bd`. Any other value reaches the shared shape marker `0x74c29fc9`. |
| 2 | `0x1001dc090`–`0x1001dc0bc` | Loads the u32 returned extent and tests equality with the submitted extent. Equality selects `0x4c27`. Inequality reaches the same shape marker. |
| 3 | `0x1002f9c48`–`0x1002f9cdc` | Encodes the API status in W8. The 14 B extent yields a six-byte remainder and selects the copy continuation at `0x1002ffc08`. |
| 4 | `0x1003e5114` / `0x1003e511c`, then `0x1002bfadc`–`0x1002bfb74` | Copies byte offsets 13 through 8 in the remainder loop, then offsets 7 through 0 in the final eight-byte group. |
| 5 | `0x1001f48bc`, `0x1001f48d8` | Stores W8 to record+8 B and reaches `RETAB`. |

The short reply leaves the descriptor and public size cell at their submitted values. With the descriptor address still equal to the daemon destination, all 14 loads and stores address the same corresponding bytes. The model therefore preserves every possible 14 B buffer contents **at API return**, including any inner payload state already written by the provider during the call. The size mismatch controls exercise a u64 count whose low 32 bits are still 16, and an inner extent of 13 B with the outer count still 16 B. Both store the shape marker with zero daemon payload-byte stores. [Provider write-back order](interface_abi_report.md#userclient-to-core-abi-and-statusdata-ordering)

## Evidence and assumptions

The [auditor](triage_evidence/audit_daemon_selector26_return.py) reads the pinned daemon directly. Its [compressed receipts](triage_evidence/daemon_selector26_return_audit.json.zst) retain source bytes, format-12 fixups, authenticated branch destinations, store order and twelve replayable bit-vector queries. The shape partitions quantify over the complete u64 size and u32 extent domains for this selected phase and submitted extent. The second path's 14 B copy and result store use arbitrary payload bytes and an arbitrary u32 API status. Time is O(N) and auxiliary space O(1) for the daemon copy, where N is the inner extent in bytes. The audit uses O(I + N) data work and space for I lifted instruction visits, before solver costs.

| Assumption | Dependent result and falsification probe |
| --- | --- |
| D1. The image SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. | Both rows. Re-read the source words and decode the bound import and rebased jump entries from original format-12 words. |
| D2. The first record decodes to control `0xbf1d` and a 16 B extent, with both pointers nonnull and the surviving pool base from `0x10043a08c`. | First row. Lift the predecessor, check W21, resolve `0xbf26`, and use both zero-status sizes as controls. The local status-to-index equation remains parameterized over the phase. |
| D3. The second record decodes to phase `0xb469`, nonnull pointers and an inner extent of 14 B, with normal storage and preserved live registers across the API. | Second row. Check the stack descriptor writes, then test the two guards independently using symbolic sizes and concrete mismatch controls. |
| D4. The framework has the retained short-reply behavior, with successful Mach delivery and ordinary return. | Composition of the second row. Recheck the upstream 36 B reply decode, lack of framework structure copy, and 16 B size-cell write-back. Change either size field and replay the mismatch path. |
| D5. The abstract record, frame and payload have valid backing, with the descriptor address equal to the daemon destination on the short path. | Byte-for-byte identity and publication order. Replay recorded byte loads and stores with independent symbolic bytes. PAC execution, native frame contents and the caller's subsequent status handling are unknown. |

| Impact | Open join |
| --- | --- |
| High | Correlate a native 2865/2965 exchange to the daemon PC, connection and reply rights, and selected result record. |
| Medium | Follow the two records' consumers to identify status translation or retry behavior and determine whether the first call's structure reaches the selected kext payload cases. |

QG1–QG7 pass for this increment. The report supplies factual ABI findings, stated premises with falsification probes, both call and return paths, exact widths and complexity, separate zero and mismatch cases, pinned-image provenance, and impact-ranked gaps.
