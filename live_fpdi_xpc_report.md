# fairplaydeviceidentityd XPC receive and reply interfaces

The installed `fairplaydeviceidentityd` listener hands each peer to a second event handler on the captured queue. That handler forwards dictionaries and logged non-disconnection XPC errors to a protected worker, where the worker reads an audit token from the event. Disjoint blocks in the same dispatch table resolve to the dictionary `data` reader, associated reply creation, `data` and `status` writers, and a send on the captured peer. The worker's entry ABI and these local call contracts are established from original bytes. The opcode inside the data payload and a continuous request-to-IOKit-to-reply route remain unknown. [Running process and attachment](live_fairplay_additional_clients_report.md)

## Peer and event handling

The earlier live snapshot identified the launchd job `com.apple.fairplaydeviceidentityd`, active named endpoint, and a FairPlayIOKit user client attributed to the same running process. The code below is scoped to the matching installed arm64e image, UUID `0a404c50-4901-312f-9e36-04565d30f305`, SHA-256 `f73ababfd9265e1bdacde11467d5a3701cec634c49ce3a65f5769cf5ccd843f0`. All PCs are preferred virtual addresses.

| Phase | Site | Observed code contract |
| --- | --- | --- |
| Named listener | `0x1000022e4`, `0x100002348`, `0x100002350` | Create with the service name and flag 1, install invoke PC `0x1000025a8`, activate |
| Peer queue | `0x1000025c8` | `xpc_connection_set_target_queue(peer, listener_block[0x20])` |
| Peer event handler | `0x10000261c`, `0x100002624` | Install invoke PC `0x100002638`, capturing peer at block+0x20, then resume peer |
| Dictionary event | Branch at `0x100002680`, tail at `0x1000026f0` | `worker(block[0x20], event)` at `0x1001f4de4` |
| Error event, invalid connection | Branch at `0x10000269c`, tail at `0x100002728` | Log the disconnect and cancel the captured peer |
| Error event, other error object | `0x1000026b0` through `0x1000026d0` | Log the description and fall through to the same worker tail |
| Other event type | `0x10000268c`, `0x100002728` | Log the unexpected type and cancel the captured peer |

The type checks read the imported error and dictionary objects, and the invalid-connection branch compares the event pointer with the imported constant. The peer handle comes from X1 at the listener-block invocation and is stored in the second block at +0x20. That handle is used for both cancellation and worker argument X0. The worker saves the peer at SP+0x80 and event at SP+0xc0. No receive or send right name for that peer is exposed in these source windows.

## Worker token and first resource requests

The worker loads a pool base of `0x1005e7c40` and computes the function table base `0x1005c0a80`. The table-root selector uses the bank pair `0x1005b1940` and `0x1005bbf30` with XOR key `0xb8` and addend `0x16d`. All 256 possible indexed bytes produce the same slot `0x1005e8898`. Its rebase value `0x1227a5aab` is adjusted by subtracting `0x221e502b` to obtain the function table base. The worker later saves this base at SP+0x1d8 through X7.

| Site | Resolved target or route | Argument, result or field |
| --- | --- | --- |
| `0x1001f5108` | Local byte fill at `0x10020bc88` | X0=SP+0x2f8, W1=0, X2=32 B. Clears the span from SP+0x2f8 through SP+0x317 |
| `0x1001f51bc` | Local helper at `0x1001fb0ac` | X0=FP-0x98. Higher-level role unknown |
| `0x1001f5228` | `xpc_dictionary_get_audit_token` | X0=event, X1=SP+0x2f8. Reads audit metadata before the following size-taking calls |
| `0x1001f5288` | Shared arena allocation wrapper at `0x10020b5f0` ([audit](live_fpdi_allocation_report.md)) | X0=128 B. The result check selects `0x100096130` if null or `0x100015bf4` if nonnull |
| `0x10001b120` | Same size-taking helper | Reached through the first nonnull route. X0=112 B. The result selects `0x1000968d0` if null or `0x100071970` if nonnull |
| `0x1000719b4`, `0x1000719c0`, `0x1000719c8` | Nonnull result initializer | Writes at result offsets +0, +4, +0x48, +0x4c and +0x50 |

For the 32 B fill and starting address A, the leading byte count is `p = (-A) & 7`. After p leading stores, the helper writes `floor((32-p)/8)` 8 B words and `(32-p) mod 8` trailing bytes. Thus the sum of the three store intervals is 32 B for each of eight possible alignments. The source writes zero in this call. The consumer and policy meaning of the token fields, and the lower backing mechanism and lifetime of the helper results, remain unknown.

## Dictionary fields and send site

| Operation | Original call PC | Proven local arguments |
| --- | --- | --- |
| Get request data | `0x100096d1c` | X0=event from SP+0xc0, X1=`data`, X2=SP+0x3f8 for returned length. X0 is checked for null |
| Create associated reply | `0x100098828` | X0=event from SP+0xc0. The returned object is stored at SP+0x478 and tested for null |
| Set reply data | `0x10002b884` | X0=object from SP+0x478, X1=`data`, X2=buffer from SP+0x468, X3=zero-extended u32 extent |
| Set reply status | `0x100064054` | X0=X21, X1=`status`, X2=sign-extended u32 operand |
| Send | `0x1000640b0` | `xpc_connection_send_message` with X0=peer from SP+0x80 and X1=X21, the object from the immediately preceding status write |

The two `data` calls load their key through the same SP+0x30 slot and signed adjustment, yielding the NUL-terminated literal at `0x1005795a6`. The `status` call independently selects the literal at `0x1005a8528`. These strings establish the dictionary fields, with the output data buffer's producer and the status namespace still unknown. An original authenticated slot at table index `0x24e3` leads to the status-and-send block. The dispatch after the data write could use that slot if W20 equals `0x24e3`; the reaching W20 definition remains unknown. The status write and send occur in one original straight-line block. Their recovered destination is the peer XPC connection, while the libxpc Mach emission PC, message ID and rights for this daemon-specific reply remain unknown.

The independently located candidate selector-26 call at `0x1000159c4` has its own table-register and connection provenance gap. The XPC worker establishes the candidate table base for its own uses. A join from the request's `data` value through the driver call, output buffer and send requires a recovered continuation or a matching native trace. [Candidate driver call](live_fairplay_additional_clients_report.md)

## Assumptions and reproducibility

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| DX1 | Installed identity matches the running slice identified in the earlier capture. This governs preferred addresses and image-level association. | Compare live Mach-O offset and CodeDirectory hash with the installed slice and rehash its file bytes. |
| DX2 | The intact protected frame carries the saved pool/table roots and peer/event arguments to the inspected blocks. This governs conditional local binding and dataflow. | Check the original call, table fixups, frame stores and every reaching definition on a continuous route. |
| DX3 | API semantics follow the exact authenticated imports and their argument widths. This governs the dictionary contract. | Compare the imported symbol and raw fixup, then observe one ordinary request and its associated reply. |
| DX4 | The selected initial helper results satisfy the specified null or nonnull case. This governs only the tested route identities. | Check both outcomes and the selected table slots, and identify the backing helper before assigning lifetime. |

Run `python3 triage_evidence/audit_live_fpdi_xpc.py "$INSTALLED_FPDI"` with the installed universal daemon. The audit takes O(B + F + I + 256S) time and O(B + F + I + 256S) space for input bytes B, decoded fixups F, retained instructions I and bank selectors S. Exact import and route checks, source windows, NUL-terminated fields and independently decoded arm64e fixups are retained. High impact attaches to the peer-scoped receive/send boundary and the recovered schema fields. Medium impact attaches to the token staging and the early resource branches. QG1–QG3 cover factual scope, explicit premises, and the local IPC contracts. QG4–QG5 cover byte widths, route cases and unknown joins. QG6–QG7 cover original-byte provenance and bounded impact. [Audit](triage_evidence/audit_live_fpdi_xpc.py) [Compressed receipt](triage_evidence/live_fpdi_xpc_audit.json.zst)

The follow-up record-adapter audit resolves the table base and structure-method import for the selected selector 26 branch. The XPC worker's connection to that adapter still depends on the upstream calling record. [Selector 26 adapter](live_fpdi_selector26_route_report.md)
