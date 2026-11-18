# fairplayd selector 26 linked children and first release call

Both modeled selector 26 paths allocate, populate and link a 42 B child before a further 14 B allocation. They then reach `_free` at `0x100643c5c` with X0 holding the original 14 B child pointer. The audit stops at the call boundary. The effects of the free, any later cleanup, and the native daemon–kext exchange remain unknown. [Prior owner links](daemon_selector26_second_child_writes_report.md)

## Allocation and release sequence

The table starts at the first allocator call after the second child is initialized. Addresses are unslid program counters from the pinned `fairplayd.arm64e` image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

| Reachability in the replay | Owner allocation, 32 B | Child allocation | Next call |
| --- | --- | --- | --- |
| Mismatch | `0x100a17948` | `_malloc(26)` at `0x100a5dcec` | `_malloc(32)` at `0x100a21528` |
| Both paths | `0x100a21528` | `_malloc(42)` at `0x1006443cc` | `_malloc(32)` at `0x100948dd0` |
| Both paths | `0x100948dd0` | `_malloc(14)` at `0x100a2fc00` | `_free(original_child)` at `0x100643c5c` |

Each modeled owner retains its child extent as a 4 B field at +0x10 B and its child pointer as an 8 B field at +0x18 B at the end of its audited span. Every byte of each newly allocated child is assigned once. For the 26 B and 42 B payloads, the first ten writes advance from offset 0 through 9. The remaining writes descend from offset 25 or 41 through offset 10. Their loop stores occur at `0x100646ccc` and `0x10064d9f8`, respectively. The last 14 B allocation uses ascending writes throughout.

| 8 B store | Mismatch-only 26 B child owner | Shared 42 B child owner |
| --- | --- | --- |
| Previous owner+0 receives the new owner | `0x10063f69c` | `0x1006436f0` |
| New owner+8 receives the previous owner | `0x10063f6a4` | `0x1006436f8` |
| List tail receives the new owner | `0x10063f6a8` | `0x1006436fc` |

The final call uses the chained import slot `0x10109ff30` for `libSystem/_free`. Its argument equals the pointer recorded at +0x18 B of the original owner before these spans. The compared spans leave the original child's 14 B unmodified before the call. The audit reaches only allocator imports in these spans.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The replay uses disjoint successful allocator returns and the inherited comparison histories. The equality history sets the modeled frame reference to the decoded word. Reachability and call counts apply to these inputs. | Match the comparison operands and successive allocation identities in an ordinary trace of the pinned build. |
| A2 | The retained frame and memory journal model the private record fields and payload writes. Store width, order and pointer identity follow from that model. | Compare effective addresses and transfer widths for the stores at the recorded instruction sites. |
| A3 | The final authenticated call is identified by the original image's chained import and the modeled X0 value. Completion of the release remains unknown. | Reconstruct the return edge and follow the original owner fields and remaining allocations through the subsequent calls. |

The audit checks both class fixtures, `0x98` and `0x99`, for both comparison outcomes. The new spans traverse 175 authenticated edges in the mismatch history and 114 in the equality history. They reference 74 distinct chained fixup words, independently checked against the pinned image. The audit compares full ordered edge sequences across class fixtures for each outcome. Its journal and edge checks take O(E + J) time and space for E edges and J memory events, excluding the inherited symbolic replay and the chained-fixup parser. [Reproducible audit](triage_evidence/audit_daemon_selector26_linked_child_retirement.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_linked_child_retirement.py
```

| Impact | Open evidence |
| --- | --- |
| High | Establish whether and where live child contents cross the daemon–kext boundary in a successful native request. |
| Medium | Follow the first release return and identify the disposition of each owner and remaining child. |
| Medium | Establish the native input values and semantic roles of the reversed byte sequences. |
