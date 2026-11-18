# fairplayd selector 26 aggregate fields after the method return

After a modeled successful selector 26 return and a successful 16 B allocation, `fairplayd` interprets the first 14 B of the aggregate. Bytes 6–9 form a big-endian u32 that contributes to the first length check. A conditional replay identifies three more field-dependent dispatches and maps four groups of aggregate bytes to the caller stack before `_malloc(32)` at `0x100948dd0`. [Earlier aggregate lifetime](daemon_selector26_pidpath_ownership_report.md)

## Length check and dispatch

The audit reads the original `fairplayd.arm64e` image pinned to SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. At the unsigned comparison `0x100908f8c`, the left operand is `record_offset + 10 + u64(be32(aggregate[6:10]))`. The direct and descriptor profiles supply offset 0 and the full aggregate extent of 272 B or 288 B as the right operand. The proof covers all values of the four bytes in both extents. The load at `0x100908fa0` uses the alternate slot when the computed end exceeds the extent. The 10 B prefix matches the field widths of a separately recovered header writer. Whether the two paths move the same record at runtime is unknown. [Upstream header writer](daemon_selector26_header_report.md) [IOKit return premises](daemon_selector26_pidpath_returns_report.md)

| Jump-table load | Slot and destination on the replayed path | Other slot and destination under the preceding path conditions |
| --- | --- | --- |
| `0x100908fa0` | `0x101064260` to `0x100a37d98` | `0x101064280` to `0x10068fe78` |
| `0x10098a6e4` | `0x10105db30` to `0x100646968` | `0x10105db18` to `0x1007480cc` |
| `0x1006469a8` | `0x10106d110` to `0x10064ccc0` | `0x101064280` to `0x10068fe78` |
| `0x10064cd20` | `0x10109d6e0` to `0x1009f75b0` | `0x10105d868` to `0x10068fe78` |

The solver establishes two possible slot addresses at each load, conditioned on the earlier selected slots. The audit continues through the original fixture's destinations. The table's alternate destinations identify branch targets only. Their eventual results and allocation lifetimes are unknown.

## Stack record fields

Offsets in this table count from the aggregate base and use inclusive ranges. `be32` assembles the bytes in big-endian order. The two exact XOR equations hold under the selected path predicates. For the other two payload-derived fields, the symbolic expressions identify their source bytes. [Replay audit](triage_evidence/audit_daemon_selector26_pidpath_fields.py)

| Input offsets | Store PC | Stack field | Verified relation |
| --- | --- | --- | --- |
| 0–3 B | `0x1009b83b0` | SP+0x9e8 B, u32 | `be32(aggregate[0:4]) xor 0x8b3dc651` |
| 4–5 B | `0x1009b83b4` | SP+0x9ee B, u16 | Expression uses only bytes 4 and 5 |
| 6–9 B | `0x1009b83b8` | SP+0x9f0 B, u32 | Expression uses only bytes 6 through 9 |
| 10–13 B | `0x1009b83bc` | SP+0x9f4 B, u32 | `be32(aggregate[10:14]) xor 0x8b3dc651` |
| None of the 14 modeled bytes | `0x1009b83c0` and `0x1009b83c4` | SP+0x9f8 B and SP+0xa00 B, u64 each | Both expressions are independent of the modeled bytes |

## Assumptions and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| F1 | The previous replay reconstructs the caller frame and retains the original aggregate pointer. The length comparison and stack offsets depend on that frame. | Compare the aggregate base, record offset, extent and stack register at each reported PC on the pinned build. |
| F2 | The modeled API return and allocator continue through the ordinary success path. The stack formulas after the first dispatch are conditional on the fixture's four slot selections. | Check whether an ordinary matching request takes the same slots and produces the same stack writes. |
| F3 | Chained fixups resolve logical branch targets. The replay checks slot words and follows those targets with modeled pointer authentication. | Re-read the original words and compare the resolved destinations with a native execution trace. |

Four replays cover both caller forms at both extents. The audit verifies 30 original chained fixup words. The local span consumes a fixed number of bytes and takes O(1) time and auxiliary storage. Replay evidence scales as O(J) for J instruction and access records, excluding solver work. [Replay audit](triage_evidence/audit_daemon_selector26_pidpath_fields.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_pidpath_fields.py
```

| Impact | Open evidence |
| --- | --- |
| High | Match these daemon reads to bytes supplied by a native selector 26 provider reply. |
| High | Follow the next allocation and determine which fields reach caller-visible state. |
| Medium | Recover the alternate dispatch paths and the protocol meaning of the field at offsets 4–5 B. |
