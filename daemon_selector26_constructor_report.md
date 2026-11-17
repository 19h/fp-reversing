# fairplayd selector 26 caller constructor

The caller at `0x1001f5178` enters a local constructor through `0x1004110fc`. For decoded phase `0x8934`, a nonnull context and three successful allocations, the pinned executable allocates a 16 B object, a 32 B node, and a 14 B buffer in that order. At the last audited branch, X22 holds the node and the node holds the buffer pointer. The connection between the node and the selector 26 call record remains unknown. [Caller record origins](daemon_selector26_record_origin_report.md) [Selector 26 call sites](daemon_selector26_return_report.md)

| Address | Instruction-level effect |
| --- | --- |
| `0x10005bf20` | Calls `malloc(16)`. On the selected continuation, `0x100015c5c` zeros the 16 B object and `0x100015c60` saves its pointer at FP−0xb8 B. |
| `0x10004ea30` | With W8 initially `0x8934`, branches through slot `0x101050040` with IA modifier `0x5530` to `0x10008c8e8`. W8 reaches that target as `0x9ea4`, and W23 as `0x8b3dc655`. |
| `0x10008c8e8`–`0x10008c990` | Copies the incoming SP+0xe0 B word back to that cell and saves the 16 B object pointer at SP+0x40 B. At `0x10008c974`, decoded W10 is 4. `CMN W10, #10` leaves carry clear and selects `0x10001bc34`. |
| `0x10001bc9c` | Calls `malloc(32)`. The nonnull branch at `0x10001bcd4` reaches `0x100015a3c` through slot `0x101091b68`. |
| `0x100015a48`, `0x100015aa8` | Zeros node offsets 0 and 8 B as two 64-bit stores. Computes 14 from the selected W23 and stores it as a 32-bit extent at node+16 B. The extent agrees with the decoded 4 B plus 10 B overhead. |
| `0x100015af4`, `0x100015b00` | Calls `malloc(14)` with the same extent in X0, then writes the returned pointer at node+24 B. The route reaches `0x10005c5f4` through slot `0x101059310` with IA modifier `0x7aa4`. Buffer contents remain unspecified at that boundary. |

The allocator calls share import slot `0x10109ff58` with IA modifier `0x6aa4`. The bank producers at `0x10005bed4` and `0x10005bef4` supply the first pair, which yields index `0xcbb5 + 0x58 = 0xcc0d`. The producers at `0x10005bf84` and `0x10005bf98` supply the second pair, which yields `0xcbca + 0x43 = 0xcc0d`. Both equalities hold for all 256 byte indices into each pair. The lift also confirms that, at `0x10005c5f4`, the caller record pointer and phase are still in SP+0x90 B and SP+0x124 B. FP−0xc0 B remains zero, and FP−0xb8 B and SP+0x40 B still hold the first allocation. No instruction in this interval reads or writes the new buffer's contents. [Audit script](triage_evidence/audit_daemon_selector26_constructor.py) [Compressed evidence](triage_evidence/daemon_selector26_constructor_audit.json.zst)

The supplied RAX trace contains 22 sends and ends with Mach request 2862. Reply 2962 reports `0xe00002c2` and a null connection port. There is no send with ID 2865 in the capture. The constructor evidence is static and conditional on the stated phase and successful allocations. The native exchange and the downstream use of the buffer remain unknown. [Trace and port attribution](zut_trace_report.md)

## Assumption register

| Assumption | Dependent conclusion and falsification probe |
| --- | --- |
| A1. The pinned Mach-O and its chained fixups represent the audited build. | Branch targets and allocator identity. Re-read the instruction bytes and original slot words, and verify the import and both complete 256-entry bank compositions. |
| A2. The caller supplies a valid aligned record with decoded phase `0x8934` and a nonnull context. | Selected route and 14 B extent. Recover the phase from the caller and check the reaching definitions of W8 and W23 against the recorded instruction slices. |
| A3. Each allocator returns a disjoint aligned writable region and preserves the callee-saved registers. | Field and pointer writes. Invalidate volatile registers and flags at each allocator return, and verify the next use has a post-call definition. |
| A4. The SP+0xe0 B input is an arbitrary 64-bit word. | Its source is unknown. The audit passes it symbolically, checks unconditional branch resolution within this interval, and proves preservation. Follow its downstream uses before assigning semantics. |

The audit checks three global-word profiles, 512 bank inputs and the corresponding original fixups. The execution model uses O(I) time and space for the lifted I instructions with fixed-size register and memory operations, excluding solver cost. Bank enumeration takes O(B) time for B byte indices. The runtime costs of the allocator and later continuations are outside the audited interval.

| Impact | Open question |
| --- | --- |
| High | Which instruction first writes the buffer, and does the same pointer or a derived record reach a selector 26 argument? |
| Medium | Where is the 32 B node attached to an owner, and how does that owner relate to the first 16 B allocation? |

QG1–QG7 cover the documented static interval, corroborating trace boundary and explicit assumptions.
