# fairplayd selector 26 cleanup and subsequent allocation

After the original 14 B child is passed to `_free`, the modeled continuation clears its pointer field and passes the original 32 B owner to `_free`. It then clears two stack ranges and requests a new 16 B allocation. A modeled null return walks and releases the remaining linked owners before returning to the outer adapter's rejection entry. A modeled nonnull return proceeds to a separate allocation whose observed size differs with the retained list. [First release boundary](daemon_selector26_linked_child_retirement_report.md)

## Common continuation

PCs are unslid in the pinned `fairplayd.arm64e` image with SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

| PC | Operation |
| --- | --- |
| `0x100643c68` | Zeroes the 8 B child pointer at original owner+0x18 B |
| `0x10094caf4` | Passes the original 32 B owner to `_free` |
| `0x100640a84` | Calls the byte-fill routine at `0x10046faf8` with SP+0xae0 B, byte 0 and length 16 B |
| `0x100640adc` | Calls the same routine with SP+0xaf0 B, byte 0 and length 32 B |
| `0x100a05060` | Calls `_malloc(16)` |

Isolated execution of the original byte-fill routine independently checks both aligned calls. It fills every destination byte with zero and leaves X0 at the end of each range. The continuation replay models those effects and abstracts the allocator calls. [Byte-fill instruction provenance](daemon_frame_entry_report.md)

## Modeled null return

The cleanup traversal loads each node's successor and child pointer at `0x10063f7e4` and `0x10063f7e8`. It calls `_free` for the child at `0x100942a64`, clears the child field at `0x100942a6c`, and frees the owner at `0x100a35f0c`. The order below excludes the original pair, which the common prefix releases.

| Earlier comparison | Child extents in release order |
| --- | --- |
| Mismatch | 14 B, 14 B, 26 B, 42 B |
| Modeled equality | 14 B, 26 B, 42 B |

Both paths then pass the two 16 B list containers to `_free` at `0x100945d50`, followed by the 128 B allocation at `0x100902cbc` and the earlier 120 B and 8 B allocations at `0x100a86f0c` and `0x100a2fe70`. The core writes `0x74c29d85` to its private status field at `0x1009e5714`. The modeled stack guard matches at `0x1009e572c`. The return at `0x1009e5750` reaches the adapter, which writes a zero output at `0x100902aec`, restores the outer stack, then returns to `0x10028a8b4`. This audit reaches the outer rejection entry at `0x1002c99a0`. Its continuation after that entry remains open for these cases. [Earlier allocation ownership](daemon_selector26_late_ownership_report.md)

## Modeled nonnull return

The first 16 B allocation is filled bytewise, followed by another `_malloc(16)` at `0x100723080`. The first buffer's bytes 6 through 9 and then 0 through 5 are read before it is passed to `_free` at `0x1006fd704`. The path allocates another 32 B owner and 14 B child, visits the retained list, then requests another allocation at `0x1006b09e0`. The list walk reads the 4 B extent at owner+0x10 B and the successor at owner+0 B at `0x10063f484` and `0x10074b150`, respectively.

| Earlier comparison | Traversed extents | Sum | Allocation argument |
| --- | --- | --- | --- |
| Mismatch | 14 + 14 + 26 + 42 B | 96 B | 112 B |
| Modeled equality | 14 + 26 + 42 B | 82 B | 96 B |

Both arguments fit strict upward rounding to the next 16 B multiple, `16 × (floor(sum / 16) + 1)`. Ordinary ceiling alignment would give 96 B for the mismatch fixture. The two observations establish the call arguments and consistency with strict rounding. The general arithmetic dependence and the allocated buffer's eventual consumer remain unknown.

## Assumption register and validation

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The original allocator returns and comparison histories are inherited from the prior audit. The new 16 B result is either zero or a disjoint modeled pointer. Release ordering and nonnull reachability apply to these cases. | Compare the allocator results and the identities supplied to each recorded call in an ordinary trace of the pinned build. |
| A2 | The byte-fill return summaries use two aligned original-code controls. Stack offsets and arguments are verified at the caller. | Run the original fill with both observed lengths and check the write extent and X0. |
| A3 | The retained guard values agree and the saved return PCs are modeled without hardware authentication. The error result and adapter handoff follow from this frame. | Check the stack guard operands, restored X30 and output store through both return sites. |
| A4 | The two traversal histories supply different extent sequences. The relation between their sums and allocation arguments is observational. | Isolate the arithmetic feeding W0 and compare results across other list extents, including exact multiples of 16 B. |

The audit checks both class fixtures for each combination of comparison outcome and allocator result. All eight cases passed. The audited spans use 120 distinct chained fixup words, checked against the original image. Its journal checks walk the bounded call and memory sequences in linear time and space, excluding the inherited symbolic evaluation and original fixup parsing. [Reproducible audit](triage_evidence/audit_daemon_selector26_postrelease.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_postrelease.py
```

| Impact | Open evidence |
| --- | --- |
| High | Trace the nonnull allocation to its eventual consumer and determine whether its contents reach IOKit or Mach. |
| High | Match a successful native daemon request with the FairPlayIOKit method and reply. |
| Medium | Follow the specific outer rejection continuation and identify any object release or fallback. |
