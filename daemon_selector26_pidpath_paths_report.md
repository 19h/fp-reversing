# fairplayd selector 26 process-path continuations

The positive self-process path branch builds a new aggregate and reaches `IOConnectCallStructMethod` with selector 26. The replay recovers both the direct structure and stack descriptor calls from the state carried through the earlier query. The nonpositive branch releases the intermediate allocations and reaches the outer rejection entry. [Self-process path query](daemon_selector26_self_pidpath_report.md)

## Positive path and IOKit arguments

All PCs and slots are unslid in the pinned `fairplayd.arm64e` image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. From `0x1009c0424`, the caller invokes `_strnlen` at `0x1009c0494` with the same output pointer passed to the process query and a 4,096 B limit. A synthetic 18 B path plus terminator yields a 32 B object and a 29 B child allocation. The transfer reads 19 bytes in descending order at `0x100646190`, including the NUL, and writes each byte XOR its mask at child offset `10 + index` B at `0x100646310`. The object's pointer at offset 24 B references the child. The assembly pass also reads the entire earlier transformed child at `0x10091667c` in descending order. [Earlier transformed allocation](daemon_selector26_followon_aggregate_report.md)

The final allocation at `0x100a05060` is 288 B in the mismatch history and 272 B in the modeled equality history for this path. Both ABI selections take that allocation from the same caller frame into an established selector 26 helper. The call target `IOKit/_IOConnectCallStructMethod` comes from chained slot `0x1010a0640`.

| Replay class | Private call and helper | IOKit call PC | Public structure input and output | Aggregate pointer in caller record |
| --- | --- | --- | --- | --- |
| `0x98` | `0x100943d3c` to `0x10043a018` | `0x1002069c4` | Same aggregate pointer in X2 and X4, full aggregate extent in X3 | Offset 0 B |
| `0x99` | `0x100915e7c` to `0x10043ee28` | `0x100293074` | Same 16 B descriptor at callee SP+8 B in X2 and X4, 16 in X3 | Offset 24 B |

Both calls use W0 from connection context offset 4 B and W1=26. X5 points to the callee's 8 B output-size cell at SP, initialized to the respective public size. In the descriptor form the first 8 B of the public structure hold the aggregate pointer and the next 4 B hold the full aggregate extent. The replay's `0x417` connection name comes from the modeled open, and the audit stops at the IOKit import. The separately recovered framework send uses request 2865, a `COPY_SEND` connection right and a distinct `MAKE_SEND_ONCE` reply right. Its transport veneer call is `0x184e78090` in the retained framework image. No native port names or request/reply transaction were observed in this increment. [Caller record ABIs](daemon_selector26_callers_report.md) [Mach transport and dispositions](iokit_sync_error_reply_report.md)

## Nonpositive path

Results 0 and −1 enter `0x10065f430`, store the private marker `0x74c29dee`, and follow eight `_free` calls. `0x100942a64` releases the previously transformed child and `0x100a35f0c` releases its 32 B owner. `0x10070f118` releases the 224 B or 208 B source aggregate. The path journal contains no reads of the process-path buffer or the transformed child's bytes. At `0x1009e5714` the core writes `0x74c29dee` to its caller-visible status field at `R+8 B`, with `R` the core argument record. The logical epilogue returns to `0x100902ae0`; its adapter publishes a zero output and returns to `0x10028a8b4`. The replay reaches the outer rejection entry at `0x1002c99a0`.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Prior synthetic child patterns, controller state and distinct successful allocations are retained. The two ABI selections and aggregate lengths apply to the corresponding replay states. | Compare caller PC, connection, buffer, length and register arguments during an ordinary successful daemon request on the pinned build. |
| A2 | The modeled process query supplies either a NUL-terminated 18 B string or a nonpositive result with no write. `_strnlen` is modeled as returning the length of that string. | Compare the path result, stored bytes and `_strnlen` return from a runtime request. |
| A3 | Allocator/free returns follow the modeled call ABI. Authenticated calls and returns use logical chained targets and saved links. | Compare stack guards, resolved calls and release order with measurements on the matching image. |

The audit replays two return classes in each of four retained upstream states and verifies 98 chained fixup words against the pinned image. Journal checks take O(J) time and space for J recorded events, excluding instruction interpretation and fixup parsing. The audit verifies the transfer into the path child and the later IOKit arguments. The byte-level composition of the final aggregate is still open. [Replay audit](triage_evidence/audit_daemon_selector26_pidpath_paths.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_pidpath_paths.py
```

| Impact | Open evidence |
| --- | --- |
| High | Match the modeled daemon import to a native 2865 request, FairPlayIOKit dispatch and 2965 reply using the actual connection and reply rights. |
| High | Trace the result and buffer ownership after the additional selector 26 call and verify the corresponding provider behavior. |
| Medium | Isolate the inherited selector inputs that distinguish the direct and descriptor routes, and test other observed process-path lengths. |
