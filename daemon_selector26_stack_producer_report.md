# fairplayd selector 26 stack producer

Two predecessor blocks in the pinned arm64e image can enter the candidate stack producer's dispatcher with phase `0xb22f`. That dispatcher selects between a status-and-pointer path and a path that writes the halfword later read at `0x10094326c`. Both retained all-nonnull profiles reach the halfword load via `0x1009d0af8` and contain neither the dispatcher nor the writer. The retained profiles therefore still end with the value unknown. PCs and chained-fixup slots below are unslid. [Retained replay](daemon_selector26_helper_consumers_report.md)

## Conditional control flow

Both predecessors use X21 as the table base and move it to X30. The required base for these joins is `0x101039ef0`. The signed table index for the shared edge is `0x2435`, giving slot `0x10104c098` and IA diversity `0x6e5c`.

| Predecessor | Admission premise | Live state at `0x10069a06c` |
| --- | --- | --- |
| `0x10065f160`, branch `0x10065f194` | W8 = `0x2435` | W8 = `0xb22f`, the incoming index plus `0x8dfa`. The block also stages an 8 B value at SP+0x750 B. |
| `0x100974074`, branch `0x100974098` | u32 at SP+0x26c B = `0xb22f` | W8 = `0xb22f`, with the dispatch index computed by subtracting `0x8dfa`. The block stages W14 at SP+0x79c B. |

The comparison at `0x10069a08c` tests u32 at SP+0x86c B against `0x8b3dc651`. The conditional comparison at `0x10069a0a0` requires that match and tests u16 at SP+0x872 B against the low 16 bits of W8 minus `0x9aed`, which is `0x1742` in this phase. At `0x10069a0c0`, the signed index is `(W8 + 0x1617) XOR (12 × mismatch)` with 32-bit arithmetic. The mismatch bit is zero only when both comparisons match.

| Condition at the dispatcher | Original slot and target | Immediate effect |
| --- | --- | --- |
| Both match | `0x10109e120` → `0x100962ce8` | Publishes `0x8b3dc651` at SP+0x70c B. The next block at `0x1006449d8` forwards the 8 B value from SP+0x438 B through the pointer at SP+0x2d8 B before dispatching to `0x10063ee68`. |
| Either differs | `0x10109e140` → `0x1009dcfcc` | Stages the private record documented below. A nonzero SP+0x438 B selects `0x100645600` via `0x1010761a0`. A zero selects `0x100967f08` via `0x101076218`. This second continuation writes `0x74c29d88` to SP+0x70c B and stages SP+0x438 B at SP+0x510 B before dispatching to `0x100981e0c`. |

## Private record fields

| Source in the same frame | Store | Destination | Retained consumer |
| --- | --- | --- | --- |
| SP+0x438 B | `0x1009dd000` | SP+0x7f0 B, 8 B | Also selects the writer's next block. |
| SP+0x86c B | `0x1009dd004` | SP+0x910 B, 4 B | Unknown at this cut. |
| SP+0x872 B | `0x1009dd008` | SP+0x916 B, 2 B | `0x10094326c`, sign extends the halfword to 32 bits. |
| SP+0x874 B | `0x1009dd00c` | SP+0x918 B, 4 B | `0x100943278`. |
| SP+0x79c B | `0x1009dd014` | SP+0x91c B, 4 B | `0x1009432a0`. |
| SP+0x618 B | `0x1009dd01c` | SP+0x920 B, 8 B | Unknown at this cut. |
| SP+0x750 B | `0x1009dd024` | SP+0x770 B, 8 B | Unknown at this cut. |

## Assumption register

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The predecessor entry states supply the table base and index or phase above. Both local joins to `0x10069a06c` depend on those inputs. | Trace the last write to the index or SP+0x26c B at each predecessor's incoming edge. Check the X21 table identity in the same frame. |
| A2 | The stack frame remains live across the analyzed private branches, with SP+0x2d8 B pointing to writable storage for the status-and-pointer arm. | Track SP and the destination's last definition through each branch. Recheck field aliases before any downstream use. |
| A3 | The two all-nonnull profiles represent the modeled class paths. Their edge histories bound the conclusion about the missing reaching store. | Compare an independent ordinary invocation that records the same predecessor and consumer PCs, stack ownership and the last writer to the consumed bytes. |

The offline audit checks both predecessor joins, all eight equality and pointer-nullness combinations, and both retained class profiles. The solver rules out a counterexample to the decoded dispatcher index for all 48 input bits at fixed phase `0xb22f`. Nine original format-12 fixup words match the recorded targets and diversities. Replay comparison is O(E) time and O(E) space for E recorded edges, with fixed-size instruction fragments and a separate bounded bit-vector solver query. QG1–QG7 cover factual scope, explicit premises, original-image provenance, exact register widths and byte offsets, branch coverage and the remaining joins. Native reachability and authenticated execution remain unknown. [Offline audit](triage_evidence/audit_daemon_selector26_stack_producer.py)

| Impact | Open evidence |
| --- | --- |
| High | Establish frame and phase continuity from the retained constructor path to either predecessor and from the writer to the signed load. |
| High | Correlate a successful daemon exchange with the corresponding kext invocation. The verified branches are private to the daemon. |
| Medium | Resolve the reaching definitions of SP+0x86c B, SP+0x872 B and SP+0x874 B in the candidate predecessor histories. |
