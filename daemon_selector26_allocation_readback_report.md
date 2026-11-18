# fairplayd selector 26 allocation readback

The first payload consumer on both extended selector 26 class paths reads bytes 0 through 3 of the initialized 14 B allocation. It transforms those bytes into W14 and compares that word with a separate 4 B frame value. The readback uses the same instruction block as the previously identified conditional producer path. The two entry states select different continuations after the readback. [Allocation completion](daemon_selector26_allocation_completion_report.md) · [Conditional stack producer inputs](daemon_selector26_stack_input_origins_report.md)

## Same-frame transfer

At `0x10063dd8c` the original code reloads the allocation pointer into X14, then sets X19 to `0x661a590b302baf96` before entering `0x100646334`. That block reads 30 unavailable 8 B fields and four unavailable 2 B fields in both modeled histories. They supply values staged in registers and frame cells. Leaving all 34 unavailable inputs symbolic keeps the branch at `0x1006468fc` resolved through slot `0x10105fca8` to `0x1009736fc`, with X14 and X19 intact. SP is the same across the two fragments.

At `0x100973710`, X19 plus `0x99e5a6f4cfd4506a` wraps to zero in 64 bits. The next instruction forms the first read address directly from X14. All addresses are unslid in the pinned image.

| Read PC | Offset in the allocation | Access width |
| --- | --- | --- |
| `0x100973934` | 0 B | 1 B |
| `0x100973998` | 1 B | 1 B |
| `0x100973cf4` | 2 B | 1 B |
| `0x100973ea0` | 3 B | 1 B |

The word produced at `0x100973ec8` depends on all four bytes at the retained entry state. The audit checks independent influence for each byte by holding the other three equal while varying that byte. No additional symbolic inputs occur in the resulting word at this entry state. The audited readback has no accesses to allocation offsets 4 through 13.

## Comparison dispatch

The branch at `0x100973ed0` uses the entry W16 index `0x734` to reach `0x1009d12bc` through slot `0x10103d890` (IA diversity `0x8cfa`). At `0x1009d12e4`, the original code compares W14 with the 32-bit value loaded from SP+0xa14 B at `0x1009d12e0`. At phase `0xb22f`, the next index is `0x7307 XOR (0x18 × mismatch)`. Branch `0x1009d131c` has IA diversity `0x95ed`.

| Comparison outcome | Table index | Original slot | Target |
| --- | --- | --- | --- |
| Equal | `0x7307` | `0x101073728` | `0x10065467c` |
| Different | `0x731f` | `0x1010737e8` | `0x100641ec4` |

The earlier conditional producer entered the decoder with W16 = `0x74f`, directing its result to the SP+0x874 B store through slot `0x10103d968`. Here the verified input is owned by the modeled 14 B allocation and the resulting word feeds the private comparison. Native outcomes and any IOKit handoff remain unknown.

## Candidate writes for the missing frame inputs

A scan of aligned instructions in `__TEXT,__text` finds the following direct unsigned-immediate `STR Xn, [SP,#offset]` instructions. The cluster is a candidate based on its matching offsets. The scan also finds many competing stores. The cluster's path and frame identity relative to this consumer remain unknown.

| Missing frame field | Matching instructions in section | Candidate in one instruction region |
| --- | --- | --- |
| SP+0x938 B | 23 | `0x1006f5b34`, X30 |
| SP+0x958 B | 33 | `0x1006f5b2c`, X22 |
| SP+0x978 B | 65 | `0x1006f5b4c`, X16 |
| SP+0x998 B | 79 | `0x1006f5b08`, X6 |
| SP+0x9b8 B | 183 | `0x1006f5d6c`, X15 |

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Both class profiles preserve their modeled allocation identity, frame, X14 and X19 through the readback. | Compare the publication, reload and all four effective addresses in one ordinary invocation. |
| A2 | The 34 unavailable fields are independent symbolic values in the offline block. The local continuation has fixed phase `0xb22f` and a known table base. | Recover actual frame producers and compare the branch, reference word and four load results in the same invocation. |
| A3 | The store count is specific to one instruction encoding and its exact SP-relative field offsets. | Search independently for register-relative aliases and paired stores, then test frame continuity and order. |

The audit regenerates both class paths, verifies four original chained fixups, checks the four load addresses, and verifies both outcomes of the decoded-word predicate over symbolic byte inputs. The scan takes O(N) time for N instruction words and stores O(H) matching rows. Instructions and bytes come from the same pinned image used by the prior audits. [Offline audit](triage_evidence/audit_daemon_selector26_allocation_readback.py)

| Impact | Open evidence |
| --- | --- |
| High | Trace both result paths through the remaining allocation consumers and eventual release or handoff. |
| High | Correlate an ordinary successful daemon request with its kext method invocation. |
| Medium | Establish which frame producers reach the 34 unavailable fields. |
