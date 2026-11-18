# fairplayd selector 26 allocation completion

Both modeled fairplayd class paths initialize all 14 B of the private allocation. After writing offsets 0–9, the original code runs two signed-halfword comparisons and a word equality test, then reenters the four-byte writer at offset 10. Later code reloads the pointer into X14 at `0x10063dd8c` and retains it up to the next unresolved stack load at `0x10064633c`. The payload has no modeled reads through that point. PCs are unslid in the pinned arm64e image. [First ten byte writes](daemon_selector26_allocation_prefix_report.md)

## Conditions and final four bytes

Both modeled paths have the same values in the second record. `0x1009b83b4` writes the halfword at SP+0x9ee B. The record consumer sign extends it into SP+0x1f8 B at `0x1009432d8`. `0x1009b83b8` writes the word at SP+0x9f0 B, which the consumer copies to SP+0x188 B at `0x100943314`. These are the two sources tested before the final writer visit. [Record layout and transfers](daemon_selector26_record_consumer_report.md)

| Branch PC | Reaching test or transfer | Original slot | Replayed target |
| --- | --- | --- | --- |
| `0x10070c498` | Signed halfword `0x86b4` (−31,052) is less than `0x9546` (−27,322). | `0x1010894f0` | `0x10092e844` |
| `0x10092e880` | W13 equals the signed immediate `-0x794c` (−31,052). | `0x10105d198` | `0x100902b04` |
| `0x100902b48` | SP+0x188 B equals `0x8b3dc655`. | `0x101075830` | `0x10068fb70` |
| `0x10068fbdc` | Restages the allocation pointer field in X16 and loads W28 from SP+0x178 B. | `0x10104f740` | `0x100a18e10` |
| `0x100a18e20` | Dispatches through the phase-derived index `0x36f0`. | `0x101055670` | `0x100651b1c` |
| `0x100652184` | Exits after the third four-byte writer visit. | `0x1010436c8` | `0x1009a9d1c` |

The first test computes `(0xbd × signed_less_than) XOR 0x9e7d`. At phase `0xb22f`, all halfword values below the threshold use index `0x9ec0`. Equality and larger values use index `0x9e7d`, whose original slot `0x1010892d8` resolves to `0x1008781e8`. The alternate target is verified statically. Both extended class paths take the less-than edge.

Before the third visit, `0x10068fbc4` through `0x10068fbd0` set X11 to `0x71134a47fbd9f0c1`, which is ten greater than on the first visit. SP+0x178 B supplies SP+0x9f4 B XOR `0x01263f51` as this visit's W28. The same writer at `0x100651b20` reloads the pointer from the 32 B object's +0x18 B field. Each of the following stores writes 1 B.

| Store PC | Offset in the allocation, B |
| --- | --- |
| `0x100651d1c` | 10 |
| `0x100651ec0` | 11 |
| `0x1006520bc` | 12 |
| `0x100652170` | 13 |

## Pointer handoff and next missing input

At `0x100a2d88c` the continuation loads the 32 B object's pointer through X8. On the second visit to that fragment, the nonnull branch reaches `0x10063dd88`, where X11 still holds the object pointer. `LDR X14, [X11,#0x18]` at `0x10063dd8c` reads the same field that received the 14 B allocation's pointer at `0x100a2fc08`. The branch at `0x10063ddb8` reaches `0x100646334` via original slot `0x10104c798`, with X14 holding the allocation pointer.

The first unresolved input in that block is `LDR X15, [SP,#0x938]` at `0x10064633c`. The modeled memory maps have no bytes or overlapping stores for that 8 B field. The verified post-allocation continuation makes no calls and reads no bytes from the 14 B payload before this load. The meaning of the payload and its relationship to any IOKit request remain unknown.

## Assumption register and verification

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | Both modeled class paths retain the allocation and phase history. The final four stores depend on these states. | Verify the three comparison operands, the allocator return, the pointer field and the four address offsets within the same ordinary invocation. |
| A2 | The comparison proof fixes the two phase-derived index terms and ranges over all 16-bit values of the signed input. Only the retained branch is followed through the rest of the audit. | Recompute the index with independent instruction lifting and recover the alternate path from slot `0x1010892d8`. |
| A3 | The original continuation carries the modeled object pointer into the field reload. The missing-input result covers the resulting histories up to the stated stack load. | Compare the last write to SP+0x938 B and the X14 allocation identity at `0x10064633c` using an ordinary same-frame capture. |

The audit verifies the two retained class paths, one full-domain 16-bit equivalence, all fourteen store addresses and widths per profile, 43 matching branch events, 37 original fixup words including the alternate target, the post-write pointer transfer, and absence of payload reads before the next load. Branch bookkeeping for I instruction visits and L recorded loads takes O(I × L) time and O(I + L) space, excluding prior replay setup and bit-vector solving. [Offline audit](triage_evidence/audit_daemon_selector26_allocation_completion.py)

| Impact | Open evidence |
| --- | --- |
| High | Establish the reaching definition of SP+0x938 B, then track X14 to the payload's first consumer or release. |
| High | Correlate a successful fairplayd method exchange with its kext invocation. |
| Medium | Resolve the alternate signed-comparison path and its allocation ownership. |
