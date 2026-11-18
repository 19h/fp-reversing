# fairplayd selector 26 aggregate pointer handoff

Both modeled selector 26 paths pass the aggregate's address to the internal routine at `0x100457e28` through a caller-owned stack record. The callee loads both copies of the pointer, preserves one in its own frame, and uses it in a null test. The audited prefix reaches a byte lookup whose address depends on the retained computation state. Aggregate payload consumption and a native daemon–kext transfer remain unknown. [Aggregate construction](daemon_selector26_aggregate_report.md)

## Caller and callee contract

PCs are unslid in the pinned `fairplayd.arm64e` image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. After the two modeled returns from `0x100444dfc`, the caller requests a 32 B owner at `0x100948dd0` and a 26 B child at `0x100a2fc00`. With successful returns, it reaches `0x10072c304` in 53 authenticated edges from the child allocation. Chained slot `0x1010a0208` identifies the callee. X0 points to the caller's FP−0xa0 B stack record.

| Record offset | Width read | Callee load PC | Proven content or role |
| --- | ---: | --- | --- |
| +0x08 B | 4 B | `0x100457f7c` | Scalar input |
| +0x18 B | 4 B | `0x100457f80` | Scalar input |
| +0x20 B | 8 B | `0x1005142f8` | Caller SP+0xae0 B |
| +0x0c B | 4 B | `0x10046778c` | Scalar input |
| +0x28 B | 8 B | `0x10046779c` | Aggregate pointer written at `0x10072c2a8` |
| +0x00 B | 8 B | `0x1003ce340` | Aggregate pointer written at `0x10072c278` |

The caller also supplies its SP+0xaf0 B at record+0x10 B. The audited callee prefix does not load that field. At `0x1003ce360` the callee saves the aggregate pointer in its SP+0x38 B field. The preceding `CMP` and following `CCMP` at `0x1003ce35c` and `0x1003ce364` select a continuation based on the existing SP+0x40 B pointer and the aggregate pointer.

## Boundary at the next lookup

Five authenticated branches carry the callee from entry to the audited checkpoint. The span ends before `LDRB W10,[X10]` at `0x1003cc84c`. Z3 admits the effective address `0x100e786ed` and also admits another value while the preceding shared-helper result remains opaque. The following instruction at `0x1003cc850` uses X8 equal to caller SP+0xae0 B at the checkpoint. Its address is therefore in the caller's 16 B stack region. The completed instructions in the audited callee prefix perform no load from the 96 B or 112 B aggregate itself. [Stack region initialization](daemon_selector26_postrelease_report.md)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The inherited replay keeps both shared-helper results opaque and models successful, disjoint allocator returns. The new call and pointer publication apply to those states. | Compare the two pointer stores and X0 with ordinary execution of the pinned image. |
| A2 | The callee uses the retained global state and a logical return address in place of hardware PAC. Its recorded argument reads and dispatch apply to this entry state. | Compare original chained slots and their targets, then record the data accesses in the first five callee branches. |
| A3 | The earlier helper result remains unconstrained within the replay. The lookup address checks establish variation within that model. | Trace the actual helper result into the lookup and compare the possible effective addresses with the observed one. |

The audit compares ordered edges and field accesses in both modeled comparison histories for classes `0x98` and `0x99`. All four cases passed with the same 60 authenticated edges and 43 distinct chained fixup words, checked against the original image. The journal checks take O(E + J) time and space for E edges and J memory events, excluding inherited symbolic execution, solver queries and fixup parsing. [Reproducible audit](triage_evidence/audit_daemon_selector26_aggregate_handoff.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_aggregate_handoff.py
```

| Impact | Open evidence |
| --- | --- |
| High | Follow the saved aggregate pointer to its first byte read and correlate any subsequent IOKit or Mach call. |
| High | Establish a successful native selector exchange and correlate the caller and driver paths. |
| Medium | Resolve the shared-helper output feeding the lookup and trace the callee status field back to the caller. |
