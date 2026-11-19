# Installed selector 26 first TLV decode and node request

In the installed FairPlayIOKit core, the first parser reads a 10 B big-endian header directly from the provider's staging buffer. It reads the length field first and checks whether the complete body fits before reading the tag or type. Accepted scalar and span records populate different value fields in the same request for a 32 B `site.FPTTLVNode`. A zero-tag span uses the early parser success path and bypasses that node allocation. [Installed selector 26 core entry](live_fairplay_core_entry_report.md)

```text
staging pointer + cursor
  -> length bytes
  -> body fits?
       |-- no  -> early parser failure
       `-- yes -> tag and type
                 |-- scalar -> decode 4 B or 8 B
                 `-- span   -> retain pointer and length
                      |-- zero tag -> early parser success
                      `-- otherwise
                 -> pack selected record -> 32 B allocation request
```

## Build and evidence

The installed collection SHA-256 is `0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126`. Kernel and FairPlayIOKit UUIDs are `90195379-954d-3ca3-baac-327341f14211` and `316464f8-eade-30ca-938e-2f430b1ed5bc`. The compiler-bounded core has a separate identity hash. In 873 selected continuation words, six changed operands construct the installed data-pool base. The audit checks all seven selected branch fixups, both node-selector bank rules over 256 inputs each, and replays ten historical SMT queries. [Historical header analysis](userclient_early_header_report.md) [Installed audit receipt](triage_evidence/live_fairplay_early_header_audit.json.zst)

The replay starts at the installed compiler entry and uses 66 cases from the archived matrix. It selects the cases with a u32 provider extent, omitting six archived high-word profiles. Cases vary the header, two private stack placements, and three controller fixtures. Three declared register-only allocator returns per case supply the workspace, auxiliary region and early container. The source writes none of the declared input bytes. The audit checks 117,348 instruction visits, 1,440 logical edges, and the ordered offsets of 636 source input-byte reads. It matches private access addresses and widths to the archived traces and independently checks selected field and terminal register values. Native allocation and hardware pointer authentication remain unknown.

## Read order and field domains

Let I be the entry staging pointer, N the u32 extent, and c the current cursor. In these cases c begins at zero. The existing 10 B header-fit gate precedes the first length read. The four installed length loads at `0xfffffe000a6a1f5c`, `0xfffffe000a6a1f68`, `0xfffffe000a6a1f70`, and `0xfffffe000a6a1f80` read consecutive bytes at I+c+6 through I+c+9.

| Offset from I+c | Field | Early decoded representation |
| --- | --- | --- |
| +0 to +3 B | Big-endian u32 tag D | `D XOR 0x31ae0066` |
| +4 to +5 B | Big-endian u16 type V | `V XOR 0xa2e3`, consumed as u16 |
| +6 to +9 B | Big-endian u32 length L | Temporary `L XOR 0x652d5642`, then retained `L XOR 0x31ae0066` |
| +10 B onward | Body of L bytes | Scalar value or span address, according to V |

The extent calculation starts at `0xfffffe000a6a1fc4`. It forms `c + 10 + L` and selects the tag/type decode at `0xfffffe000a6a2024` when the result is at most N. The selected failure target is `0xfffffe000a6a2d8c`. The first tag and type loads are at `0xfffffe000a6a2084` and `0xfffffe000a6a2150`. The overlength profiles read four length bytes and leave cursor zero. The short-header profiles reach retirement without a source input read. For c<N and N a u32, the candidate sum fits u64. [Entry header-fit gate](live_fairplay_core_entry_report.md)

| Raw V | Early internal type | Selected body use | Later staged internal type for the same raw V |
| --- | --- | --- | --- |
| `0x9777` | `0x3594` | L=4, decode big-endian u32 | `0xa129` |
| `0x8485` | `0x2666` | L=8, decode big-endian u64 | `0xb2db` |
| `0x50db` | `0xf238` | Retain I+c+10 and L | `0x6685` |

The u32 and u64 publications at `0xfffffe000a6a22c4` and `0xfffffe000a6a2cd0` encode their values with XOR constants `0x31ae0066` and `0x8f98c6acce5848ca`. The normal span address and cursor stores are at `0xfffffe000a6a2aa4` and `0xfffffe000a6a2aa8`. The scalar cursor store is at `0xfffffe000a6a2cf0`. Each accepted case advances the cursor to the end of the record. Span cases read the header and retain the body address without reading body bytes.

The earlier staged-parser evidence derives its type as `V XOR 0x365e` after recovering the staged field bytes. If both phases see the same raw V, the early and late type values differ by XOR `0x94bd`. The runtime relationship between the input buffers remains unknown. [Historical staged metadata decoder](userclient_record_metadata_report.md)

## Allocation and retirement boundaries

Let S be the workspace, C the auxiliary region, and H the early 16 B container. The selected producer at `0xfffffe000a6a2644`–`0xfffffe000a6a2664` packs the arguments below before the node request.

| Destination | Width | Value |
| --- | --- | --- |
| C+0x260 | 8 B | Callback `0xfffffe000a6a2d30` |
| C+0x20 | 8 B | H |
| S+0x1d0 | 4 B | Encoded tag |
| S+0x1b2 | 2 B | Encoded type |
| S+0x94 | 4 B | Encoded length |
| S+0x110 | 4 B | Encoded u32 value, or the zero-value encoding when unused |
| S+0xad0 | 8 B | Encoded u64 value, or the zero-value encoding when unused |
| C+0x168 | 8 B | Span address, or zero when unused |

The following count gate at `0xfffffe000a6a26a4` checks whether L+10 is representable as u32. The pending call at `0xfffffe000a6a27f4` reaches `_IOMallocTypeImpl` through slot `0xfffffe0008491258` with IA modifier `0xd0c8`. X0 is the descriptor at `0xfffffe0008491f40`, named `site.FPTTLVNode`, with signature `1121`, flags `0x64`, and extent 32 B. The descriptor pool slot at `0xfffffe0008488ca8` holds descriptor-plus-8 B. The replay verifies the descriptor, complete selected metadata stores, cursor and call arguments before stopping.

| Outcome | Cases | Terminal effect in the modeled prefix |
| --- | --- | --- |
| Accepted record reaches node allocation | 24 | Pending typed request at `0xfffffe000a6a27f4`. No node return fixture is supplied. |
| Zero-tag span | 12 | Cursor 10 B, early status `0x31ae0066`, H retained at C+0x418. A 16 B extent case leaves six suffix bytes unread. |
| Rejected header, length, or type | 30 | Cursor zero, early status `0xce515bb8`, H retained at C+0x3d0. |

Both retirement paths stop at `0xfffffe000a6a1754` before the typed release call. In the selected scope, the scalar decode handles at most 8 B and the span path publishes a pointer and length. These operations use O(1) source work and additional state per record, excluding allocators and later phases. No new Mach transfer or message emission occurs in the replayed prefix. Native request admission, pointer ownership, completion of the parser, and the matched daemon transaction remain unknown. [Mach endpoints and emission sites](mach_ports_report.md)

## Assumptions and coverage

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| H1 | Collection, archived cases, and selector evidence match their pinned identities. Current field and target claims depend on them. | Rehash the fileset and archives and compare selected original instruction words and chained fixups. |
| H2 | Entry staging, frame and allocator fixtures remain valid for the replay. Source continuity and pointer publication depend on them. | Check all visited edge and memory-event sequences, and verify the input byte offsets and typed request arguments directly. |
| H3 | Header and body checks run in the recorded source phase. Field widths and cursor math depend on c<N and a u32 N. | Recheck the length-first order and the separate short and overlength outcomes, then rerun the phase-constrained source proofs. |
| H4 | Early and staged field relations assume equal raw type bytes. Cross-epoch inference depends on that equality. | Trace an admitted request's original bytes through the actual staging copy and later decoder. |
| H5 | The fixture stops before node allocation or retirement. Native ownership and caller correlation need separate events. | Observe the allocator or release return, the actual list update, and a matching provider request identity before joining those lifetimes. |

High impact applies to the installed wire-to-record mapping and length-first gate. Medium impact applies to the field-domain mapping to the later staged decoder. Low impact applies to inferring business meaning from numeric tags or type names alone.

QG1 covers factual scope. QG2 records dependency and stress tests. QG3 covers raw fields, ordering, supported types, metadata and stops. QG4 checks units and size arithmetic. QG5 records null boundaries, suffix handling and runtime limits. QG6 uses original collection bytes, archived provenance and replayed formulas. QG7 bounds the later ownership and transaction claims.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 triage_evidence/audit_live_fairplay_early_header.py "$CURRENT_COLLECTION"
```
