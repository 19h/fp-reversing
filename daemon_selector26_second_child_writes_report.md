# fairplayd selector 26 second child initialization and owner links

Both continuations fill the entire second child after the shared reload at `0x100651b20`. The mismatch path writes 14 B in ascending order. The modeled equality path writes its first 10 B in ascending order and its last 16 B in descending order. Both then reread the original 14 B child and connect the two owner records before another allocation. [Second child allocation and reload](daemon_selector26_second_child_report.md)

## Write order and dispatch

Addresses use the pinned arm64e image and are unslid. After loading the pending target from the table into X24, the common writer emits four one-byte stores at `0x100651d1c`, `0x100651ec0`, `0x1006520bc`, and `0x100652170`. Its authenticated branch at `0x100652184` consumes the pending target. Both paths also use the two-byte writer at `0x100657668` and `0x1006577e8` before returning to the four-byte writer for offsets 6 through 9.

| Stage | Mismatch | Modeled equality |
| --- | --- | --- |
| First four-byte writer exit | Slot `0x1010435a8` to `0x1006d4db0` | Slot `0x101043818` to `0x1009de2d4` |
| After offsets 0 to 9 | Third four-byte writer visit writes offsets 10 to 13 | Slot `0x101043868` enters `0x10094dd2c`, preparing the reverse byte loop |
| Last write | Offset 13 at `0x100652170` | Offset 10 at `0x100646ccc` |
| Next `_malloc(32)` | `0x100a17948` | `0x100a21528` |
| Authenticated edges from reload through next call | 38 | 44 |

The reverse loop reloads the new child pointer at `0x10094dd34`. It reads one source byte per iteration at `0x100646c90`, from offsets 15 through 0 relative to the base saved at SP+0x420 B. It XORs that byte with a byte computed from local arithmetic and writes the result at `0x100646ccc`. Destination offsets run from 25 down to 10. The branch at `0x100646ce8` takes 15 backedges via slot `0x10104ad98` to `0x100646c14`, then exits via slot `0x10109dc30` to `0x1006455c8`. The replay checks the order and source and destination addresses. The native source bytes and their interpretation remain unknown.

## Original child reread and owner links

Both paths reload the original child pointer at `0x10063dd8c`, read only offsets 0 through 3 of that child and revisit the comparison at `0x1009d12e4`. Both take the mismatch branch on this later visit. The initialized second child is bypassed by the reread. No further payload access occurs before the next allocation call.

| 8 B link store | Mismatch PC | Modeled equality PC |
| --- | --- | --- |
| Original owner+0 points to new owner | `0x1006527b8` | `0x10063f69c` |
| New owner+8 points to original owner | `0x1006527c0` | `0x10063f6a4` |

Both owners still hold their respective child pointers at +0x18 B when the audited spans end. The audit stops at the next allocator call. A subsequent transfer or release and the native daemon–kext exchange remain unknown.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Both class fixtures preserve the prior successful allocator and helper-return models. The equality entry varies the modeled frame reference. | Compare the actual allocator returns, comparison results and writer targets in an ordinary trace of the pinned build. |
| A2 | The reverse loop uses the inherited SP+0x420 B source base and a disjoint child allocation. The replay claims byte addresses and order. | Capture the source base and each effective load and store address, then compare their offsets and progression. |
| A3 | Both paths preserve the original and new owner identities through the later comparison and link writes. The audit stops before the next return. | Match the two stores and child fields to allocation identities, then follow ownership through the next return. |

The audit verifies four class-and-outcome cases and 49 distinct chained fixups. It confirms each new payload byte is initialized once, checks the original child's four reads and unchanged contents, and verifies the two link stores and both child fields. Journal verification takes O(E) time for E memory events and compares the ordered events across the two class fixtures. [Reproducible audit](triage_evidence/audit_daemon_selector26_second_child_writes.py)

```sh
uv run --no-project --python 3.14 --with z3-solver --with capstone --with unicorn \
  python triage_evidence/audit_daemon_selector26_second_child_writes.py
```

| Impact | Open evidence |
| --- | --- |
| High | Identify the eventual consumer of the linked owner records and establish whether either child contributes to an external message. |
| High | Match an ordinary successful native request with the FairPlayIOKit selector invocation and reply. |
| Medium | Identify the source bytes used in the reverse writer and verify both next allocator returns. |
