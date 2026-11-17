# fairplayd selector 26 failure cleanup

After saving the encoded selector 26 error at SP+0xe8 B, the pinned daemon enters a cleanup dispatcher at `0x100008f88`. Its first two branches test pointers. The error word at SP+0xe8 B does not select either branch. [Caller status gate](daemon_selector26_callers_report.md)

## Pointer tests and cleanup interfaces

Let P be the u64 value at FP−0xc0 B. The first dispatcher loads P at `0x100008f98`. It also loads the code pointer for `0x1000242f8` into X2 from original slot `0x10103f778`. The nonnull branch saves that continuation and the address of the P cell at SP+0x128 B and +0x130 B before loading Q from P+0 B.

| Selected condition | Original branch destination | Effect |
| --- | --- | --- |
| P is null | Index `0x90c5`, slot `0x101082518`, IA `0x8e7b`, entry `0x100026478` | Sets X0 to zero and tail-branches through X2 at `0x100026484`, using IA `0xf2d5`. |
| P is nonnull, Q is null | Index `0x90ac` to `0x1000c2020`, then index `0x37c5` to `0x100025c4c` | Requests `free(P)` at `0x100025c98` under the bank premise below. On return it clears the P cell at `0x100025ca4` and selects the same tail fragment through slot `0x10104f570`, IA `0x0f65`. |
| P and Q are nonnull | Index `0x90ac`, then index `0x37e9` to `0x100127c48` | Reads Q+0 B into X26 and Q+24 B into X0. The second field selects the next retirement step. |

For the last row, a nonnull Q+24 B value enters `0x1000d2950`. With the selected bank pair, `0x1000d299c` requests `free` on that value, and `0x1000d29a4` clears the field after normal return. Both the null and nonnull Q+24 B paths then enter `0x10000c238`, which conditionally resolves a separate `free(Q)` at `0x10000c2a0`. X26 has already captured the Q+0 B value before that call. The exit selects its next fragment from a predicate on X26 and forwards X26 in X23 at `0x10000c2c0`. The later retirement sequence and the complete object type remain unknown.

Both paths into `0x100026478` supply X0=0 to `0x1000242f8`. That fragment computes an index from W28, W16 and W1. W28 is inherited on the null-P path and reloaded from SP+0x124 B on the selected free-and-clear path. The continuation cannot be assigned a unique destination from the retained entry facts alone.

## Source evidence and assumptions

The pointers select local code and heap retirement. The analyzed blocks do not reload the saved status at SP+0xe8 B. The later error consumer and any external publication remain unknown. The only named external interface here is the allocator import. The original format-12 slot `0x10109ff30` binds `libSystem/_free` with IA `0x46a2`. [Mach transport of the earlier status](iokit_sync_error_reply_report.md)

| Call PC | Conditional bank bases, left and right | Key and additive | Index |
| --- | --- | --- | --- |
| `0x100025c98` | `0x100e99a00`, `0x100f4e390` | `0x9c`, `0xcbda` | `0xcc08` |
| `0x1000d299c` | `0x100fc4230`, `0x101031fa0` | `0xe4`, `0xcbab` | `0xcc08` |
| `0x10000c2a0` | `0x100e99a00`, `0x100f4e390` | `0x78`, `0xcb67` | `0xcc08` |

The source audit records six modeled paths covering the null P path, the null Q path and the four combinations of null and nonnull values at Q+0 B and Q+24 B. It checks the selected branch slots, call arguments, ordered pointer clears and preservation of the saved status on those paths. It also checks each byte-bank rule over all 256 inputs. Each dispatcher and call setup uses O(1) time and space, excluding the imported allocator and subsequent retirement iterations. [Audit script](triage_evidence/audit_daemon_selector26_cleanup.py) [Compressed evidence](triage_evidence/daemon_selector26_cleanup_audit.json.zst)

| Assumption | Dependent claim and falsification probe |
| --- | --- |
| F1. The pinned binary and original fixup catalog match the earlier selector 26 audit. | All address claims. Re-read each original range and decode the original fixup words for the branch and import slots. |
| F2. The caller supplies the recovered error phase, live table base and valid frame. | Pointer-based route selection. Evaluate both P values and, when P is nonnull, both Q values against original branch slots. |
| F3. The frame-relative bank cells supply the listed source pairs. | Import identity at each selected call. Capture the reaching values at FP−0xe8/0xf0 B or FP−0xf8/0x100 B and re-evaluate the byte-bank rule. |
| F4. The imported calls return normally and preserve live frame state. | Ordered pointer clears and continuation after each call. Compare the call argument, the first following write and the preserved pointer from the original slices. Native allocator and PAC behavior remain unknown. |

| Impact | Open join |
| --- | --- |
| High | Correlate the frame and its cleanup path to a matched native selector 26 exchange. |
| Medium | Identify the later load of SP+0xe8 B and the reaching definitions for the continuation state at `0x1000242f8`. |

QG1–QG7 cover the stated cleanup interval, alternate pointer cases, source provenance, conditional ABI claims and the remaining interface joins.
