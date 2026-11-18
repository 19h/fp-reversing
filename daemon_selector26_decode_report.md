# fairplayd constructor readback decode and allocator loop

The four bytes read from the first constructed buffer feed a local jump-table decision. The recovered transform is a big-endian 32-bit load expressed as four byte loads and register arithmetic, followed by an XOR mask that varies with the buffer address in the audited layouts. The selected route appends the second node and returns to the 32 B node allocator. The connection to the selector 26 argument records remains unknown. [Byte readback and insertion](daemon_selector26_readback_report.md) [Selector 26 call sites](daemon_selector26_return_report.md)

| Original PC | Source-derived effect |
| --- | --- |
| `0x10015f354`, `0x10015f360`, `0x10015f370`, `0x10015f37c` | Read offsets 0–3 of the first buffer as four unsigned bytes. |
| `0x100012ab8` through `0x1000132d0` | In each audited frame, normalize those bytes to `BE32(buffer[0:4]) XOR mask` in W8. Three proofs cover every 32-bit input independently for each frame. |
| `0x1000132d4`, `0x1000132d8`, `0x1000132e4` | Read the last W2 save at SP+0xb4 B, XOR it into the normalized word and compare the result to `0x05fe9959`. Both visits to `0x10001bc3c` write this 4 B cell. The second visit supplies `0x8c74d4f5` in all three constructor profiles. |
| `0x1000132e8` through `0x1000132fc` | Select index `0x8aea` on equality and `0x8b02` on inequality. All three original constructor buffers normalize to `0xfa88cee0` and select `0x8b02`. |
| `0x100013330` | On the observed inequality edge, use slot `0x10107f700` with IA modifier `0x051e` to reach `0x1000de840`. The downstream path links the second node into the same owner at `0x100013a68` through `0x100013a74`. |
| `0x10001bc9c` | The post-insertion continuation calls the original `_malloc` import with X0 = 32. This is a third visit to the node allocation call on the selected path. |

The model accounts for all 32 output bits. Let the four bytes appear at increasing addresses as `b0` through `b3`. Then `BE32 = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3`. In the three retained layouts, the decoder's XOR masks differ, while its outputs for the corresponding locally generated buffers are identical. Crossing the three global-word pairs and three heap layouts preserves the mask for each layout. In five single-allocation relocation controls, moving the first buffer changes the mask and moving the owner, either node or the second buffer preserves it. These controls establish address dependence for the tested placements. A general address-to-mask equation remains unknown. [Audit](triage_evidence/audit_daemon_selector26_decode.py) [Compressed receipt](triage_evidence/daemon_selector26_decode_audit.json.zst)

The audited instructions consume the four bytes locally and reach a pending allocator call. The retained RAX trace ends at failed IOKit open 2862 with a null connection and contains no selector 26 request. The native call lineage, Mach names and rights at the selector boundary remain unknown. The connected IDA instance listed a different binary, so the additional checks use the pinned original Mach-O bytes and original format-12 fixups. [Trace and port attribution](zut_trace_report.md)

## Assumption register

| Assumption | Dependent result and falsification probe |
| --- | --- |
| A1. Original daemon SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` identifies the audited image. | The instruction, comparison and target evidence. Re-read original bytes and decode the chained words and imports. |
| A2. The selected phase is `0x8934`, the context is nonnull and the five initial allocations are valid and disjoint. | The observed normalized word and allocator loop. Rebuild all three parent frames, check both stack stores and follow actual table loads through the next pending call. |
| A3. SP+0xf8 B is supplied as an arbitrary 64-bit live-in. | Branch continuity through the consumer. Repeat the proof with the word symbolic and require every followed destination to resolve. Its source remains unknown. |
| A4. The arithmetic proof substitutes only the four bytes at the local buffer input. | Full 32-bit transform and comparison equations for the retained frames. Check the negations with Z3 and require unsatisfiability. The original-byte replay separately checks the branch and pending allocator call. |

For a fixed number of profiles, the replay builds the instruction and access journals in O(I) time and space for I visits, excluding solver and fixup decoding costs. The decoded scalar has width 32 bits. There are six unsatisfiability checks spanning three profiles. The relocation controls add fourteen bounded input profiles.

| Impact | Open evidence |
| --- | --- |
| High | Find the exit from the constructor loop and trace the exiting buffer or object to a caller argument or local retirement. |
| High | Correlate a live selector 26 call to a successful device open and identify both Mach rights in the exchange. |
| Medium | Derive the general address-to-mask equation and establish the SP+0xf8 B producer. |

QG1–QG7 cover the reported static interval, exact widths, explicit premises, solver checks and source-backed transport boundary.
