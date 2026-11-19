# fairplayd consumption of selector 26 reply fields

The descriptor helper reads the returned extent and address before copying the pointed-to bytes. The final four bytes of the outer reply are copied by the IOKit framework but have no reader in the audited daemon helper interval. This joins the current framework's nominal success format to separately verified field loads in the pinned daemon. A matching native exchange remains unknown. [Current inline reply](live_iokit_selector26_inline_reply_report.md) [Daemon return paths](daemon_selector26_return_report.md)

## Read order and data flow

The descriptor helper at call PC `0x100293074` supplies SP+8 B as both the input and output structure and SP as the u64 size cell. Stack offsets below are relative to SP in that helper before its epilogue. Packed offsets apply to the accepted 68 B Mach reply with a 16 B structure and zero scalar results.

| Field | Caller stack offset | Packed reply offset | Width | First post-call daemon reader |
| --- | --- | --- | --- | --- |
| Outer count | +0 B | +36 B | u32 on wire, u64 in size cell | `0x100293078` |
| Inner extent | +16 B | +48 B | u32 | `0x1001dc090` after outer count matches 16 B |
| Inner address | +8 B | +40 B | u64 | `0x1002ffc0c` after inner extent matches the submitted extent in the 14 B replay |
| Final inline word | +20 B | +52 B | 4 B | No load of these four bytes through `0x1001f48d8` in the audited paths |

After the address load, the 14 B replay reads the pointed-to data once in descending order from offset 13 B at `0x1003e5114` to offset 0 B at `0x1002bfb54`. The submitted and returned addresses are equal in this replay, so each byte store addresses its corresponding source byte. The helper stores the encoded API status at `0x1001f48bc` and returns at `0x1001f48d8`. The result record receives the status word. The 16 B descriptor is local to the helper frame.

With an outer size of `0x100000010` B, the helper reads only the outer count among these fields. With an outer size of 16 B and inner extent of 13 B for a submitted 14 B extent, it reads the count and extent and skips the address and payload. In the direct helper at call PC `0x1002069c4`, zero API status reaches the full-width size-cell read at `0x1002724a0`. The tested nonzero API status skips that read. The direct structure lives in the caller-supplied buffer, so the descriptor field map above applies to the descriptor helper. [Direct and descriptor result records](daemon_selector26_pidpath_returns_report.md)

## Evidence boundaries

| Assumption | Dependent fact | Falsification probe |
| --- | --- | --- |
| The daemon matches the pinned SHA-256 in the audit and enters the previously recovered descriptor phase. | Exact load sites and authenticated continuations. | Re-read the source spans and confirm the selector and stack arguments at the ordinary API call. |
| The modeled matching return preserves the submitted address and reports the submitted 14 B extent. | The descending read and the same-address stores. | Compare submitted and returned address and extent in one correlated ordinary call. |
| The current IOKit framework receives a normal success reply with a 16 B structure and zero scalars. | Packed offsets and framework publication into the daemon frame. | Check the received count, declared message length and copy length together. |
| The audited interval ends at the local epilogue. | No trailing-word load in the helper and local descriptor lifetime. | Verify range overlap for each memory read from the return boundary to the epilogue. |

The helper performs O(N) work and uses O(1) auxiliary storage for an N-byte copy on the audited branch. The audit verifies two direct profiles and three descriptor profiles against original source words and their replayed load addresses. The 14 B profile establishes local field consumption. Transport of that exact inner extent and native byte values remain unknown.

The final word has low impact on the selected helper's computation. A matched native call has high impact on whether the framework, provider and daemon use these same fields in one exchange. [Audit script](triage_evidence/audit_daemon_selector26_reply_fields.py) [Compressed receipt](triage_evidence/daemon_selector26_reply_fields_audit.json.zst)
