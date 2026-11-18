# fairplayd selector 26 aggregate buffer construction

The successful modeled return from `_malloc` at `0x1006b09e0` feeds a buffer built from the retained child list. The writer reads each child in descending address order and applies a bytewise XOR while preserving that child's offset within its destination segment. It then writes a trailing region and reaches a helper call. The replay follows two helper returns to the next allocation. The eventual aggregate consumer and native daemon–kext transfer remain unknown. [Allocation-size observations](daemon_selector26_postrelease_report.md)

## Buffer layout and provenance

PCs are unslid in the pinned `fairplayd.arm64e` image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Ranges below are half-open byte offsets from the returned pointer.

| Part | Mismatch path | Modeled equality path |
| --- | --- | --- |
| First retained child | [0, 14) | [0, 14) |
| Second retained child | [14, 28) | [14, 40) |
| Third retained child | [28, 54) | [40, 82) |
| Fourth retained child | [54, 96) | Absent |
| First trailing writes | [96, 106) | [82, 92) |
| Final descending writes | [106, 112) | [92, 96) |
| Allocation extent | 112 B | 96 B |

The list-head load at `0x1009d675c` starts the construction walk. The walk reads each owner's 4 B extent at +0x10 B and its 8 B child pointer at +0x18 B at `0x10063eb74` and `0x10087695c`. After output for that child, `0x10093b8f0` rereads its extent and `0x1006c078c` loads the next owner at +0 B.

The payload loop loads one byte at `0x10070b900`, XORs it with bytes derived from the loop state, then stores one byte at `0x10070bc30`. For a child of size N and destination base B, the body visits offsets i from N − 1 through 0 and writes to B + i. The destination segment bases follow the cumulative sizes of the preceding children. Replacing each child byte with a distinct symbolic input makes every destination byte in the payload reduce to its matching input XOR a concrete byte under the retained state. This establishes byte correspondence for arbitrary child-byte values at that replay point.

The trailing writes begin with four stores at `0x100a0b1cc`, `0x100a0b41c`, `0x100a0b5d8`, and `0x100a0b7f8`. Stores at `0x1006d36d4` and `0x1006d36d8` add two bytes, then the four-byte writer supplies the next four. The loop at `0x10090b374` writes the remaining six or four bytes in descending order. The replay records exactly one store for each byte of the allocation. The semantic role of the trailing bytes remains unknown.

## Handoff after construction

| Call PC | Callee | Argument checked in X0 |
| --- | --- | --- |
| `0x100a3826c` | `0x100444dfc` via slot `0x1010a01b0` | X29 − 0xa0 B |
| `0x10064b5bc` | `0x100444dfc` via slot `0x1010a01b0` | Same stack record |
| `0x100948dd0` | `libSystem/_malloc` | 32 B |

The original caller code between these calls does not read or write the aggregate. The two helper returns model separate opaque 8 B results at stack-record+8 B, following the earlier helper ABI audit. Consequently, memory accesses inside those helper calls remain unknown for this continuation. [Earlier helper consumers](daemon_selector26_helper_consumers_report.md)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The retained owner topology and extents carry forward from the successful allocator replay. The new buffer is disjoint. The layout applies to the two modeled histories. | Compare the allocation identities, owner links and effective store addresses in an ordinary trace of the pinned image. |
| A2 | Child-byte symbols vary independently with other inputs and the call state preserved. The replay checks a per-byte XOR relation at that state. | Vary the retained loop state, repeat the byte correspondence checks and compare the resulting XOR terms. |
| A3 | The helper model supplies only its opaque stack-record output and clobbers caller-saved state. The aggregate access check covers original caller instructions. | Inspect the helper's actual reads and writes with the observed stack-record argument and track any alias of the aggregate. |

The audit checks both modeled comparison histories with class fixtures `0x98` and `0x99`. All four cases passed. The mismatch and equality spans traverse 154 and 134 authenticated edges, respectively. They reference 27 distinct chained fixup words checked against the original image. The journal and offset checks take O(E + J + B) time and space for E authenticated edges, J memory events and a B-byte output, excluding the symbolic evaluator and fixup parser. [Reproducible audit](triage_evidence/audit_daemon_selector26_aggregate.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_aggregate.py
```

| Impact | Open evidence |
| --- | --- |
| High | Find the first aggregate consumer and establish whether it reaches a native IOKit or Mach call. |
| Medium | Determine the semantic role of the trailing bytes and the sizing rule beyond these two histories. |
| Medium | Resolve whether either helper can see the aggregate through an indirect reference. |
