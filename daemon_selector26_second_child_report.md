# fairplayd selector 26 second child allocation and reload

After the selector 26 readback comparison, both successful allocation sequences build a new 32 B owner and enter the same private record consumer. The mismatch path gives the new owner a 14 B child. The modeled equality path gives it a 26 B child. Both publish the child at owner+0x18 B and reload it into X17 at `0x100651b20`. The paths retain different frame slots for the new owner and different table entries for the next dispatch. [Readback continuations](daemon_selector26_readback_continuations_report.md)

## Allocation return and publication

Addresses are unslid in the pinned arm64e image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The replay models both allocator results as successful, nonoverlapping allocations. The same two class fixtures are used on each continuation.

| Operation | Mismatch | Modeled equality |
| --- | --- | --- |
| Owner `_malloc(32)` call | `0x100948dd0` | `0x100a17948` |
| Save returned owner | `0x100948dd8`, SP+0x2d0 B | `0x100a17950`, SP+0x5b8 B |
| Branch on nonzero allocator return | `0x100948e14` via `0x10105c310` to `0x100a2fa8c` | `0x100a1797c` via `0x1010756c8` to `0x100a5dc7c` |
| Zero owner bytes 0 to 15 | `0x100a2fab8` | `0x100a5dc90` |
| Store 4 B extent at owner+0x10 B | `0x100a2fbb8`, 14 B | `0x100a5dc98`, 26 B |
| Child `_malloc` call | `0x100a2fc00`, 14 B | `0x100a5dcec`, 26 B |
| Save child at X20+0x18 B | `0x100a2fc08` | `0x100a5dcf4` |
| Branch after child return | `0x100a2fc30` via `0x10107ec68` to `0x1009d0ac0` | `0x100a5dd28` via `0x101093dc8` to `0x10063d924` |

Both child calls use original import slot `0x10109ff58` for `_malloc`. X20 holds the new owner at the child call and after its modeled return. The two final branch sites `0x1009d0af8` and `0x10063d958` use slot `0x101048cd0` to enter `0x100943260` with X16 holding the new child field's address. The original owner's child field keeps its original pointer throughout both audited continuations.

## Common record consumer and deferred dispatch

At `0x1009432c4` and `0x1009432fc`, the consumer loads SP+0x2d0 B and SP+0x5b8 B. The following stores record each loaded value plus 24 B at SP+0x250 B (`0x1009432cc`) and SP+0x228 B (`0x100943304`). The two continuations enter with W22 set to `0xb22f`; the dispatch at `0x1009434b0` uses slot `0x101055670` to reach `0x100651b1c`. [Earlier record consumer](daemon_selector26_record_consumer_report.md)

| Consumer state | Mismatch | Modeled equality |
| --- | --- | --- |
| SP+0x250 B after consumer | New owner's child field address | Original owner's child field address |
| SP+0x228 B after consumer | Unresolved owner input plus 24 B | New owner's child field address |
| W26 at consumer entry | `0x12d7` | `0x1325` |
| Deferred table word loaded into X24 at `0x100651b1c` | Slot `0x1010435a8` | Slot `0x101043818` |
| X17 loaded from X16 at `0x100651b20` | New 14 B child pointer | New 26 B child pointer |

In both cases, the X17 reload uses the exact field written by the child allocator return. The span from owner allocation return through that reload contains no reads or writes of either child buffer's payload. The deferred table word is loaded before the child pointer, and the audit ends before the branch that uses that word. The checked calls are private allocator calls within the daemon path. Native IOKit and Mach interactions remain unknown for this continuation.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The two class fixtures retain the preceding offline frame and heap histories. Equality is modeled by constraining the reference to the decoded word. | Compare an ordinary invocation's frame producers, readback operands, and branch destination against the modeled inputs and target. |
| A2 | Both calls return distinct live allocations. Owner field stores and pointer reloads apply to this successful-return case. | Compare both returned addresses, the owner extent and pointer stores, and the reload effective address in one captured ordinary invocation. |
| A3 | The mismatch retains an unresolved SP+0x5b8 B input. Its staged address is a symbolic 64-bit addition, with the allocation reload independently using X16. | Recover the reaching write to SP+0x5b8 B and compare the resulting SP+0x228 B value and X16 load address. |

The offline audit verifies all four class-and-outcome cases and nine distinct chained fixups. It checks the exact owner writes, both frame-derived addresses, both deferred table slots, and the absence of accesses overlapping either payload. It rules out a counterexample to the SP+0x228 B relation. Byte-overlap checks scan O(E) journal entries for the two child bounds. [Reproducible audit](triage_evidence/audit_daemon_selector26_second_child.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_second_child.py
```

| Impact | Open evidence |
| --- | --- |
| High | Follow the two deferred table entries through payload initialization and any transfer or retirement. |
| High | Match a successful native daemon request to the corresponding FairPlayIOKit selector and reply. |
| Medium | Establish the reaching SP+0x5b8 B owner on the mismatch path and the outcomes of allocator failure. |
