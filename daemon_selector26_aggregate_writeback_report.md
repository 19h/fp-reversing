# fairplayd selector 26 aggregate writeback and return

The private callee at `0x100457e28` rewrites the caller's aggregate in place in 16 B blocks, then writes a 4 B result to the caller's stack record. The caller reads that field and dispatches to `0x100640d30` in all eight replay cases. This establishes a private daemon contract for the audited paths. The rewritten bytes' later use and a successful native FairPlayIOKit transfer remain unknown. [Aggregate pointer handoff](daemon_selector26_aggregate_handoff_report.md)

## In-place block processing

PCs are unslid in the pinned `fairplayd.arm64e` image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Each pass through the block at `0x1004a55b0` loads 16 bytes before the first write to that block. It uses the same load order for every block in both modeled comparison histories. The tail of the routine processes the initialized trailing bytes as part of the final block. [Read order and byte-table use](daemon_selector26_aggregate_reads_report.md) [Payload and trailing bytes](daemon_selector26_aggregate_report.md)

| Earlier comparison | Aggregate size | Payload | Trailing bytes | Block passes |
| --- | ---: | ---: | ---: | ---: |
| Mismatch | 112 B | 96 B | 16 B | 7 |
| Modeled equality | 96 B | 82 B | 14 B | 6 |

All recorded aggregate stores are 1 B wide. The order runs down the left pair of columns, then down the right pair. Offsets are relative to the start of the current block.

| Store PC | Block offset (B) | Store PC | Block offset (B) |
| --- | ---: | --- | ---: |
| `0x1004a74a4` | 0 | `0x1004a76d8` | 8 |
| `0x1004a7518` | 6 | `0x1004a76fc` | 10 |
| `0x1004a758c` | 11 | `0x1004a7720` | 4 |
| `0x1004a75b0` | 2 | `0x1004a7758` | 1 |
| `0x1004a7638` | 5 | `0x1004a777c` | 12 |
| `0x1004a765c` | 3 | `0x1004a77b4` | 13 |
| `0x1004a7690` | 15 | `0x1004a77d8` | 14 |
| `0x1004a76c4` | 9 | `0x1004a7998` | 7 |

The branch at `0x1004a7a2c` routes nonfinal passes through `0x100609fec`. That block updates scratch words and branches back to the block reader at `0x1004a55b0`. The final pass instead routes through `0x1004a51dc`, which reloads the caller record pointer from callee SP+0 B. Before the result store, all observed writes stay within the callee frame or the aggregate allocation. The processing span contains no calls. Changing the synthetic child-byte pattern changes the final aggregate in each class and comparison history.

## Private result and caller dispatch

| PC | Observed effect |
| --- | --- |
| `0x10031615c` | Writes `0x8b3dc651` to caller record+0x1c B in each replay |
| `0x100316174` | The saved and current stack guard match in the modeled state |
| `0x100316194` | The logical `RETAB` restores control to `0x10072c308` with the caller's SP and FP |
| `0x10072c30c` | Loads the same word from caller FP−0x84 B |
| `0x10072c318` | Compares the loaded word with `0x8b3dc651` |
| `0x10072c334` | Branches through chained slot `0x101082b80` to `0x100640d30` |

The result's equality with the caller's comparison word is observed across the tested states. Its wider status-code domain and the other caller continuation remain unknown.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The pinned-image replay inherits the earlier comparison histories, successful disjoint allocations and original-image global bytes. The read and write extents apply to the two resulting aggregate sizes. | Trace the actual block bases and terminal branch using both allocation sizes on the pinned build. |
| A2 | Both preceding opaque helper results are set to zero. The child expressions are evaluated with two synthetic inputs immediately after the first 16 B read. Read order, overwrite extent and result apply to those states. | Use the helper's observed outputs and child bytes and compare the final buffer and private result. |
| A3 | The entry replay executes the original stack-guard store. The epilogue compares the guard and restores the saved stack and link, with pointer authentication modeled as logical control flow. | Capture the original saved and live guard values and the return target during ordinary execution. |

The audit checks the ordered journals against block size, verifies the private result load from the original record, and checks the five distinct continuation-slot words against the pinned image. Journal checks use O(J) time and space for J memory events, excluding underlying instruction interpretation, expression simplification and fixup parsing. [Reproducible audit](triage_evidence/audit_daemon_selector26_aggregate_writeback.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_aggregate_writeback.py
```

| Impact | Open evidence |
| --- | --- |
| High | Follow `0x100640d30` to the next consumer or release of the rewritten aggregate. |
| High | Correlate a successful native daemon request and reply with the FairPlayIOKit dispatch. |
| Medium | Test the return field under other genuine helper results and determine when the alternate continuation is selected. |
