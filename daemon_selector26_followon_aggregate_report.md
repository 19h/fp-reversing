# fairplayd selector 26 follow-on aggregate

The 224 B or 208 B allocation from `0x100a05060` survives the original aggregate release. The selector 26 continuation reads every byte of the surviving buffer at `0x100646190` and writes a second XOR-transformed copy at `0x100646310`. After constructing the copy, it calls the private daemon routine at `0x10043fe84` with a pointer to a caller stack record. [Previous aggregate consumer](daemon_selector26_aggregate_consumer_report.md)

## Cleanup, byte mapping, and private call

All PCs are unslid in the original `fairplayd.arm64e` image with SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The replay starts on return from the original aggregate's `_free` at `0x1009b5494`. The mismatch path makes 11 more `_free` calls and the modeled equality path makes nine. Both then reach the five `_malloc` calls below. At `0x100a2fc08`, the caller stores the final destination pointer into the preceding 32 B object's pointer field at offset 24 B. The field retains that pointer at the private call.

| Call PC | Allocation | Mismatch | Modeled equality |
| --- | --- | ---: | ---: |
| `0x1006470e4` | First allocation after cleanup | 16 B | 16 B |
| `0x100948dd0` | First of two 32 B allocations | 32 B | 32 B |
| `0x100a2fc00` | Allocation after the first 32 B request | 14 B | 14 B |
| `0x100948dd0` | Second of two 32 B allocations | 32 B | 32 B |
| `0x100a2fc00` | Destination allocation | 234 B | 218 B |

The copy reads the source in descending index order. The destination offset is `10 + index` B, so the indexed region ends at byte 233 for mismatch and byte 217 for modeled equality. The audit supplies each load with an independent 8-bit symbol and checks that XORing the written value with that symbol yields a concrete mask. It restores the concrete transformed byte before continuing and checks that only the transfer loop writes the mapped destination range. The source is fully initialized at the start of this span and receives no subsequent stores through the private call. [Replay audit](triage_evidence/audit_daemon_selector26_followon_aggregate.py)

| PC or slot | Evidence at the call boundary |
| --- | --- |
| `0x10064be1c` | Writes `0x80f63fa2` at record offset 0 B as a 4 B word |
| `0x10064be24` | Writes the caller SP+`0xbaf` B address at record offset 8 B |
| `0x10064be7c` | Sets X0 to caller FP minus `0xa0` B |
| `0x10064be84` | Calls through chained slot `0x1010a0fb8`, which resolves to `0x10043fe84` |
| `0x10043fe88` | Reserves a 96 B callee frame |
| `0x10043fe9c` | Stores the caller's frame anchor and logical return address |
| `0x10043fea4` | Retains the stack record pointer in X19 |

The retained RAX capture has 1,748 lines and SHA-256 `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`. Lines 1726 and 1736 show the open request/reply IDs 2862/2962. The reply bytes at lines 1738–1740 encode a null connection name and `0xe00002c2`. The capture ends at line 1748 without a selector 26 method send. The static continuation therefore has no matching runtime observation in that capture. [Trace provenance and raw message decode](zut_trace_report.md)

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The replay inherits the modeled comparison histories, successful distinct allocations, and logical returns from `_free`. The postrelease call sequence depends on that state. | Compare the allocator results and call sequence for a normal request on the pinned image. |
| A2 | The upstream fixture uses zero outputs for both shared helpers, with synthetic child patterns for classes `0x98` and `0x99`. The source-to-destination mapping is verified in those frame states. | Substitute observed helper outputs and child bytes, then compare the copy span and call arguments. |
| A3 | The prologue models `PACIBSP` with a logical return address. The stack record and saved link checks depend on that model. | Capture X0, SP, FP and the authenticated return target on the matching build. |

All four cases reach the same private callee. The mismatch cases traverse 406 authenticated edges and the modeled equality cases traverse 385. The audit checks 81 distinct chained-slot words against the pinned image. The journal checks take O(J) time and space for J recorded events, excluding instruction replay and fixup parsing.

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_followon_aggregate.py
```

| Impact | Open evidence |
| --- | --- |
| High | Trace the private routine's use of the stack record to locate the eventual consumer of the transformed allocation. |
| High | Match a successful native method request and reply to the pinned daemon and kext dispatches. |
| Medium | Verify the lifetime and release points for both allocations beyond callee entry. |
