# Installed selector 26 exhausted-input schema request

When the first record consumes the declared input, the installed FairPlayIOKit parser retains its container H at C+0x418 and requests key `0xfa834112` from that container. All 24 replays reached the nonnull-container lookup branch with the new callback and output alias saved. The same key occurs at byte 118 in archived ADID Avp selector 100 packets, four levels deep. The packet and innermost container have different cursor boundaries from the selected first-record exhaustion path. Native transport or a matching transaction remains unknown. [Audit script](triage_evidence/audit_live_fairplay_early_schema.py) [Audit receipt](triage_evidence/live_fairplay_early_schema_audit.json.zst)

```text
first record consumed -> status SUCCESS and C+0x418 = H
  -> fixed action -> schema helper(H, key, &S[0xbc4])
     -> shared lookup(H, key, &C[0x710])
        -> nonnull H branch -> stop before head inspection
```

## Exhaustion and fixed action

F is the frame base, C the auxiliary region, S the workspace, H the 16 B container and J its first 32 B node. At exhausted-input entry `0xfffffe000a6a1cbc`, the cursor equals the input extent and both H links already contain J. The continuation stores `0x31ae0066` at S+0xc94 at `0xfffffe000a6a1cdc`. It loads H from C+0xb0 and stores it through the C+0x170 alias at `0xfffffe000a6a1d00`. F+0x908 and C+0x170 both carry C+0x418. Its original zero becomes H. The replay checks these aliases against their original prefix stores. [Installed first-record publication](live_fairplay_early_publication_report.md)

The original producer at `0xfffffe000a676af0` constructs `0x1830b7ce` and stores it at S+0x1e0. The selected action depends on that internal producer. The first comparison literal in the historical report has been corrected to `0x89f25623`, matching both original and installed instruction bytes. [Historical exhaustion report](userclient_early_schema_report.md) [Earlier all-action comparison proof](userclient_message_parser_report.md)

| Installed branch PC | Predicate on the action word | Taken target | Selected outcome |
| --- | --- | --- | --- |
| `0xfffffe000a6a1d44` | Equal to `0x89f25623` | `0xfffffe000a6a241c` | Fallthrough |
| `0xfffffe000a6a1d54` | Equal to `0xfbb3f478` | `0xfffffe000a6a22d4` | Fallthrough |
| `0xfffffe000a6a1d64` | Unequal to `0x1830b7ce` | `0xfffffe000a6774a0` | Fallthrough into status gate |

The gate transfers at `0xfffffe000a6a1db4` with modifier `0x64d8`. The all-status32 source proof selects request block `0xfffffe000a677870` for W23=`0x31ae0066` and failure target `0xfffffe000a682dac` for every other u32. The replays exercise the success path. Failure effects remain outside this branch check.

## Two lookup handoffs

The request passes the same H through both handoffs. The encoded key `0xcb2d4174` XOR the u32 success token `0x31ae0066` yields raw key `0xfa834112`. The private return indices select chained table slots for these caller epochs.

| Channel | Exhausted parser to schema helper | Schema helper to shared lookup |
| --- | --- | --- |
| Transfer PC and modifier | `0xfffffe000a6778b4`, `0x2d2b` | `0xfffffe000a6954bc`, `0x0ee9` |
| Target | `0xfffffe000a695408` | `0xfffffe000a6a3c44` |
| X22 and W9 | H, encoded key | H, encoded key |
| Result alias | X11=S+0xbc4 | X10=C+0x710 |
| W8 return index | `0xf6` | `0x7f` |
| Saved return | C+0x4d0 = `0xfffffe000a6778b8` | C+0xc8 = `0xfffffe000a6a2dc4` |
| Saved output address | C+0x5f0 = S+0xbc4 | C+0x758 = C+0x710 |

The helper clears C+0x710 and F+0xaa8 and writes the success token to S+0xb64. The shared entry saves the encoded key at S+0 and selects the nonnull target `0xfffffe000a6a3d70` with modifier `0x7250`. This overwrites the shared return and result-alias cells from first publication. The previous lookup used index `0x6c`, callback `0xfffffe000a6a3cf4`, and result C+0x50. C+0x50 remains zero. The suffix stops before inspecting the populated head, and schema lookup delivery and type/length handling remain open on this build. [Earlier publication caller](live_fairplay_early_publication_report.md) [Historical schema lookup evaluation](userclient_schema_search_report.md)

## ADID byte correspondence and extent boundary

A bounded parser walks the frozen source-built 320 B Avp method-100 packets. The twelve fixture rows share one SHA-256 and byte string. The matching raw key is absent from the outer level. The path below lists record headers in absolute packet byte offsets. [ADID packet provenance](adid_avp_packet_report.md)

| Key | Type | Header offset | Body interval |
| --- | --- | ---: | --- |
| `0xfd2821c7` | `0x50db` | 32 B | [42, 298) B |
| `0x351bdea7` | `0x50db` | 84 B | [94, 270) B |
| `0xfd2821c7` | `0x50db` | 108 B | [118, 246) B |
| `0xfa834112` | `0x9777` | 118 B | [128, 132) B, BE u32 zero |

A first-record parse of the whole packet would reach cursor 18 B with declared extent 320 B under the verified framing. In the 128 B innermost container, the matching field is the first 14 B record. That view still has a 114 B suffix. The selected installed exhaustion path requires cursor equal to declared extent. The matching key supports a candidate schema relationship, with the subview or transport adapter that could connect Avp method 100 to this primary selector 26 input still unknown. The observed source emission is an IOKit method call over the Avp connection. The primary provider enters `_PRnut72j9` with its own staging address and u32 extent. [ADID call ABI](adid_iokit_caller_report.md) [Installed primary provider entry](live_fairplay_core_entry_report.md)

## Evidence and assumptions

The audit pins the installed `26C5035r` collection and verifies the whole `_PRnut72j9` hash. It compares 139 action and schema words and 19 inherited lookup-entry words, checks 39 authenticated chained slots and resolves three direct comparison branches. All selected words match under the code translation. The audit reproduces all 13 archived solver results, with a 115 s limit per query. Across 24 cases it reproduces the prior publication replay, checks nine additional prefix cells per case, and carries the resulting modeled state directly into the new suffix. The new suffixes execute 3,504 installed instruction visits in total. Each checks eight private loads, ten stores totaling 68 B and seven logical authenticated transfers. Each preserves H's links, the cursor and Z's serialized record interval. The writer between the original prefix and the publication suffix remains a conditional source composition. [Installed image and replay identity](live_fairplay_early_publication_report.md) [Source proof provenance](userclient_early_schema_report.md)

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| E1 | Archived words and translated installed fixups represent the selected function and caller. The exact handoff map depends on that identity. | Rehash the pinned image and function, compare the spans and resolve each callback slot. |
| E2 | The fixed action, output aliases, published links and input cursor retain the checked epochs. The request inherits H and the parser result storage under this premise. | Replay the original producers, compare the nine prefix cells and verify both H links and cursor before and after the suffix. |
| E3 | H is nonnull, input is exhausted and W23 holds raw success. This selects the observed helper path. | Check cursor against declared extent and test other u32 statuses against the source gate proof. |
| E4 | Source-built packets describe the archived method-100 boundary. The file-level raw key correspondence depends on these exact bytes. | Parse each declared subrange and compare its header, extent, and packet digest. To establish transport, correlate native connection identity and the exact staging subview. |

High impact applies to the confirmed parser-to-lookup handoff and the unresolved staging subview. Medium impact applies to the distinct callback epochs and the corrected comparison literal. Low impact applies to interpreting the zero scalar without its consumer. Native lookup, Mach endpoint changes and matched daemon identity remain unknown or outside the observed suffix. The selected path has O(1) work and additional storage through shared lookup entry. The bounded packet walk takes O(B) time for B input bytes with a fixed four-level depth and O(1) extra space excluding the audit rows. [Mach ports and emission sites](mach_ports_report.md)

QG1 covers factual scope. QG2 records premises and probes. QG3 covers exhaustion, container retention, action, two handoffs and packet correspondence. QG4 checks u32/u64 widths and exact byte ranges. QG5 separates the synthetic packet, projected writer state and installed suffix. QG6 ties the claims to file bytes, fixups, replay and solver results. QG7 identifies the remaining staging, lookup and native joins.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_early_schema.py "$CURRENT_COLLECTION"
```
