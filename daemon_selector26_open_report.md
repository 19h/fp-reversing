# fairplayd IOKit connection handoff to the selector 26 constructor

In the pinned arm64e image, the service-matching fragment entered with W24=`0x5dee` can reach the selector 26 constructor caller after successful IOKit matching, a nonzero iterator result and successful type-0 open. The open call writes the connection name through `context+4 B`. The constructor caller passes the same context pointer in its argument record. This is a conditional static connection handoff. [Prior constructor and selector split](daemon_selector26_constructor_join_report.md)

## Calls, values and branch destinations

F denotes the caller SP, C denotes X20, and R denotes FP−0x78 B. All PCs are unslid in the original Mach-O, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The frame remains fixed across these fragments. The selected table entries use original format-12 chained fixups. [Audit generator](triage_evidence/audit_daemon_selector26_open.py) [Compressed evidence](triage_evidence/daemon_selector26_open_audit.json.zst)

| Call PC | Binding and input/output contract | W0 = 0 | W0 != 0 |
| --- | --- | --- | --- |
| `0x1002b7b94` | `0x1010a0d88`, IA `0xa027`, `IOServiceGetMatchingServices`. W0 reads main port from F+0x7c B, X1 holds the matching dictionary, X2 points to the iterator output at F+0x78 B. | Slot `0x101095b90` to `0x10018453c`. | Slot `0x101068e60` to `0x1000bd85c`. |
| `0x10018458c` | `0x1010a0e38`, IA `0xd62a`, `IOIteratorNext`. W0 reads the iterator name from F+0x78 B and returns the service name. | Slot `0x101068e60` to `0x1000bd85c`. | Slot `0x101068ee0` to `0x100176964`. |
| `0x100176a0c` | `0x1010a0b48`, IA `0xe82b`, `IOServiceOpen`. W0 retains the iterator's service result, W1 holds the task name, W2=0, X3=C+4 B. The block saves the service name at F+0xc B before calling. | Slot `0x101056900` to `0x1001f50b0`. | Slot `0x1010568f8` to `0x1002c99a0`. |

The task lookup selects `0x1010a39c8` at `0x1001769b4`. Its original unauthenticated chained binding references `_mach_task_self_` with addend `0x7bf13863`. The instructions at `0x1001769c0`–`0x1001769c8` cancel that addend. The next instruction reads the 32-bit name from the resolved data symbol. The open block changes W24 from `0x5dee` to `0x3941`, which the successful branch carries into the constructor caller. [Compressed evidence](triage_evidence/daemon_selector26_open_audit.json.zst)

At `0x1001f50c0`, the caller reads the inherited control word at F+0x4c B. Both successful fixtures preserve that word across matching, iteration and open. The source store at `0x1001f5108` copies C to R+0x10 B, and the call at `0x1001f5178` passes R to `0x1004110fc`. The phase field decodes to `0x8934` in these fixtures. The existing selector 26 helper audit independently reads a connection name at C+4 B before the IOKit call. The frame origin of F+0x4c B is unknown. [Constructor phase and caller record](daemon_selector26_record_origin_report.md) [Selector 26 helper calls](daemon_selector26_return_report.md)

## RAX observation and transport boundary

The annotated trace records the iterator reply 2902 carrying guest service send right `0x1903`, then open request 2862 to that name with reply name `0x507`. The task descriptor carries guest name `0x203` with disposition `COPY_SEND`. Reply 2962 returns `0xe00002c2` and a null connection name. The two messages use the recorded `mach_msg2_trap` wrapper at `0x180547c20`. The 22 observed sends contain no 2865 method request. Exact association between those trace messages and the unslid daemon call PCs above is unknown. [Trace mapping](zut_trace_report.md) [Framework and kernel open path](kernel_iokit_open_report.md)

The native service instance, connection port, and successful selector 26 request/reply identity remain unknown. The retained static framework evidence associates the two selector 26 call sites with MIG 2865/2965. [Selector 26 return report](daemon_selector26_return_report.md)

## Assumption register and checks

| ID | Premise and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The pinned file and original chained pointer words identify the call and branch destinations. Logical dispatch depends on the recorded IA diversity and current mapping. | Rehash the image and decode the 11 original fixups and separate task import. Hardware authentication and actual load addresses are unknown. |
| A2 | Entry phase is `0x5dee`. Iterator bank bases are `0x100e99a00` and `0x100f4e390`, inherited at F+0x28 B and F+0x30 B. Constructor bank bases are `0x100fc4230` and `0x101031fa0`, inherited at F+0x40 B and F+0x38 B. | Check all 256 inputs per bank rule. Resolve the reaching writes to the inherited slots before asserting whole-function reachability. The matching and open pair comes from the source rebases in the matching block. |
| A3 | The API calls return normally, obey the ABI and provide the declared opaque outputs. The matching output at F+0x78 B, C+4 B, R and F+0x4c B are disjoint. | Clear the volatile registers at each modeled return and test matching failure, iterator exhaustion, rejected open and two successful continuations. Compare with a correlated passive runtime capture. |
| A4 | The previous constructor and method audits apply under their own entry and allocation premises. | Compare the argument record and context across the caller and constructor boundary. Resolve the starting dictionary and actual control word and correlate the reply independently. |

The generator checks 1,280 bank inputs across five rules, five frame profiles and three symbolic branch equations over all 32-bit return values. It retains the raw instruction spans and tests the service, task, type, output pointer and constructor arguments. For I instruction visits and B byte-indexed bank inputs, source evaluation uses O(I+B) time and O(I) retained trace space plus the fixed-size banks. Solver resources are separate. QG1–QG7 cover factual scope, the four premises, the selected route and alternate branch outcomes, exact widths and offsets, trace provenance and the remaining interface boundaries.

| Impact | Open evidence |
| --- | --- |
| High | Identify the reaching writes for F+0x4c B and the inherited bank pointers. Establish the ordinary matching dictionary and call-site lineage. |
| High | Correlate a successful native open with its connection right and a selector 26 transaction. |

The [class-matching entry report](daemon_selector26_match_entry_report.md) identifies two reaching writes to F+0x4c B and sources the iterator's F+0x28/+0x30 B bank pair. The two paths match different service classes before the shared open fragment.
