# fairplayd selector 26 first aggregate reads

The callee at `0x100457e28` reads the first 16 B of the selector 26 aggregate in a fixed order across the audited cases. Each byte then indexes one of four 256 B windows in the daemon's `__TEXT,__const` section. The first aggregate read is at `0x1004a5da0` and accesses offset 2 B. This consumption occurs inside `fairplayd`. A subsequent native daemon–kext transfer remains unknown. [Aggregate pointer handoff](daemon_selector26_aggregate_handoff_report.md)

## From caller scratch to the aggregate

PCs are unslid in `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The caller originally clears its 16 B scratch region at SP+0xae0 B. Before invoking the callee it writes scratch bytes 0–7 at `0x10098b9b4` and bytes 8–15 at `0x10082aff8`, one byte at a time. Each half depends on a distinct opaque 64-bit result from `0x100444dfc` in the inherited replay. The callee reaches the checkpoint at `0x1003cc84c` with X8 pointing to this scratch region. The preceding load at `0x1003cc7b8` reads scratch byte 6. The span starting at `0x1003cc84c` uses the other 15 scratch bytes before the next authenticated branch. [Scratch initialization](daemon_selector26_postrelease_report.md)

At `0x1003ccd3c`, chained slot `0x10105a1c0` selects the next block at `0x1004a55b0`. The block reloads the aggregate pointer from the callee's SP+0x38 B into X9 at `0x1004a55e4`. It then forms addresses from that base and reads one byte at each site below. The table gives encounter order.

| Aggregate load PC | Offset (B) | Table load PC | Window base |
| --- | ---: | --- | --- |
| `0x1004a5da0` | 2 | `0x1004a5db0` | `0x100e78660` |
| `0x1004a5de0` | 8 | `0x1004a5dec` | `0x100e635d0` |
| `0x1004a5dfc` | 1 | `0x1004a5e18` | `0x100fa9ae0` |
| `0x1004a5e64` | 9 | `0x1004a5e84` | `0x100fa9ae0` |
| `0x1004a5ec4` | 5 | `0x1004a5ef0` | `0x100fa9ae0` |
| `0x1004a5f04` | 10 | `0x1004a5f14` | `0x100e78660` |
| `0x1004a5f54` | 13 | `0x1004a5f74` | `0x100fa9ae0` |
| `0x1004a5f80` | 12 | `0x1004a5f94` | `0x100e635d0` |
| `0x1004a5fd4` | 6 | `0x1004a5fe4` | `0x100e78660` |
| `0x1004a601c` | 14 | `0x1004a602c` | `0x100e78660` |
| `0x1004a6064` | 3 | `0x1004a6070` | `0x100e6a1d0` |
| `0x1004a60a4` | 4 | `0x1004a60b4` | `0x100e635d0` |
| `0x1004a60e4` | 0 | `0x1004a60f0` | `0x100e635d0` |
| `0x1004a615c` | 11 | `0x1004a6168` | `0x100e6a1d0` |
| `0x1004a61a4` | 7 | `0x1004a61b4` | `0x100e6a1d0` |
| `0x1004a61fc` | 15 | `0x1004a620c` | `0x100e6a1d0` |

The first table index equals the byte read at aggregate+2 B XOR `0x16`. Each table address stays within its 256 B window for arbitrary values of the symbolic aggregate bytes in the replay. The audit reads the window bytes from the pinned image and ends at `0x1004a6210`. It records no aggregate writes or calls between the first lookup and that boundary. [Reproducible audit](triage_evidence/audit_daemon_selector26_aggregate_reads.py)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The inherited replay uses successful disjoint allocation returns, original-image global bytes and logical pointer authentication. The recovered pointer flow and branch apply to those states. | Trace the original branch target and the reload from callee SP+0x38 B during ordinary execution of the pinned build. |
| A2 | The added replay substitutes two fixture pairs for the opaque helper results at the lookup checkpoint. The observed order of aggregate reads applies to those pairs and the retained states. | Record both real helper outputs and compare scratch bytes, branch target and aggregate read order. |
| A3 | Child-derived aggregate bytes stay symbolic. The table proofs use the selected bank bases and the image's `__const` bytes. | Compare the first source byte and following lookup address across different child contents, using the same scratch and global state. |

The audit crosses class fixtures `0x98` and `0x99`, the earlier mismatch and modeled equality paths, and two synthetic pairs for the helper outputs. The all-zero pair yields an initial lookup at `0x100e786ed`. The pair `0x0102030405060708`, `0x1112131415161718` yields `0x100e786ef`. All eight cases agree on the subsequent aggregate loads and window bases. The added branch uses a chained fixup checked directly against the pinned image.

The table lift selects from 256 original bytes using the eight index bits. For T table sites and window size W, it builds O(TW) selection terms in O(TW) time and space. These bounds exclude the inherited replay, solver queries and fixup parsing.

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_aggregate_reads.py
```

| Impact | Open evidence |
| --- | --- |
| High | Follow the first block's derived state into the next aggregate block or the callee's output fields. |
| High | Correlate a successful native `fairplayd` request and reply with the corresponding FairPlayIOKit dispatch. |
| Medium | Resolve how `0x100444dfc` produces the two outputs that supply the scratch region. |
