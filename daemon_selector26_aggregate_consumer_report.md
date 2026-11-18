# fairplayd selector 26 rewritten aggregate consumer

The continuation at `0x100640d30` reads every rewritten aggregate byte and writes an XOR-transformed copy into a separate allocation starting at offset 10 B. It releases that destination before passing the original aggregate pointer to `_free` at `0x1009b5494`. The audited span contains only allocation and release calls. A successful native exchange with FairPlayIOKit remains open. [Aggregate writeback and caller dispatch](daemon_selector26_aggregate_writeback_report.md)

## Byte mapping and allocation sequence

PCs are unslid in the pinned `fairplayd.arm64e` image with SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The loop at `0x10064618c` decrements the index before loading one byte at `0x100646190`. The XOR at `0x10064630c` combines that byte with the low 8 bits of the shifted word in X13. The store at `0x100646310` writes one byte to `destination + 10 + index`, with the destination base in X8. The audit replaces each source byte with an independent 8-bit symbol, reduces the stored byte XOR that symbol to a concrete mask, and reinstates the concrete result before continuing. Every audited source and destination index is visited once in descending order, including bytes in the aggregate's initialized trailing region. [Original aggregate layout](daemon_selector26_aggregate_report.md) [Replay audit](triage_evidence/audit_daemon_selector26_aggregate_consumer.py)

| Order | Call PC | Operation | Mismatch | Modeled equality |
| ---: | --- | --- | ---: | ---: |
| 1 | `0x100948dd0` | `_malloc` | 32 B | 32 B |
| 2 | `0x100a2fc00` | `_malloc` | 42 B | 42 B |
| 3 | `0x100948dd0` | `_malloc` | 32 B | 32 B |
| 4 | `0x100a2fc00` | `_malloc` for the transformed copy | 122 B | 106 B |
| 5 | `0x100a05060` | `_malloc` | 224 B | 208 B |

For mismatch, the 112 B source maps to destination offsets 10 through 121 B. For modeled equality, the 96 B source maps to offsets 10 through 105 B. Each range ends at the last byte of its allocation. The original aggregate retains the bytes present on entry to `0x100640d30` through the final call. Ten `_free` calls follow the five allocations. The 42 B buffer and the transformed copy each reach `_free` at `0x100942a64`, in that order. The last call passes the original aggregate pointer at `0x1009b5494`. The fifth allocation has no release in the audited span. Its later ownership and disposition are unknown.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The replay inherits the mismatch and modeled equality histories with successful, distinct allocator returns. The allocation and release sequence applies to those histories. | Capture allocation results, the two child releases and the original aggregate release during a normal request on the pinned build. |
| A2 | Both preceding helper outputs are zero, with synthetic child patterns selected by seeds 0 and 17 for class fixtures `0x98` and `0x99`, respectively. The byte correspondence and masks apply to those frame states. | Repeat the byte mapping with observed helper outputs and source bytes, checking both the destination base and the store span. |
| A3 | Chained operands are resolved from the pinned image and pointer authentication is modeled as logical control flow. | Compare the resolved call targets with runtime branch targets on the matching image. |

The audit verifies 78 distinct chained-slot words against the original image and checks the ordered memory journals. Journal checks take O(J) time and retain O(J) space for J recorded memory events, excluding instruction replay and fixup parsing.

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_aggregate_consumer.py
```

| Impact | Open evidence |
| --- | --- |
| High | Follow the 224 B or 208 B allocation from `0x100a05060` through the original aggregate release to its first subsequent consumer or release. |
| High | Correlate a normal native daemon request and reply with the FairPlayIOKit dispatch. |
| Medium | Determine the roles of the ten bytes preceding the transformed payload and whether they vary with the helper outputs. |
