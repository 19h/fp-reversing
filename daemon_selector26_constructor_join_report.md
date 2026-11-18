# fairplayd constructor handoff and selector 26 dispatch byte

The recovered `0x8934` constructor links five 14 B nodes and enters the list serializer in the same frame. The serializer allocates 96 B for the 70 B payload, 10 B trailer and 16 B zero padding. The caller-owned record supplies the dispatch byte. For the audited caller at `0x1001f5178`, the descriptor form is selected exactly when the low byte of the caller's SP+0x4c B word is zero. [Constructor readback](daemon_selector26_decode_report.md) [List serialization](daemon_selector26_list_transfer_report.md)

The source is the original arm64e Mach-O, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. PCs are unslid. The evidence records the original instruction spans and chained fixups, the continuation after each added node, and both adjusted-byte outcomes across the three original constructor fixture profiles. [Audit generator](triage_evidence/audit_daemon_selector26_constructor_join.py) [Compressed evidence](triage_evidence/daemon_selector26_constructor_join_audit.json.zst)

## Constructor continuation and frame

The replay starts from the prior second-node readback with the SP+0xf8 B word symbolic. Each of the three remaining node allocations requests 32 B for the node and 14 B for its bytes. After each fill, the replay follows the existing next links, decodes the first four bytes of each visited buffer and uses the null-next path to link the new node and update the tail. It checks the source instructions and branch targets for each visit. [Node links and readback](daemon_selector26_readback_report.md)

| Nodes linked | Prior load and save | Reloaded slot at `0x1001e2e0c` | Continuation |
| --- | --- | --- | --- |
| 2 | `0x10002bfd8`, `0x10002bfdc` | `0x101041970`, IA `0x7cb2` | `0x1000fe5bc` starts another iteration. |
| 3 | Same load and SP+0xc8 B save | `0x101041a60`, IA `0x7cb2` | `0x100098968` starts another iteration through `0x1001343c0`. |
| 4 | Same load and SP+0xc8 B save | `0x101041a40`, IA `0x7cb2` | `0x10008797c` starts another iteration through `0x10007fa24`. |
| 5 | Same load and SP+0xc8 B save | `0x101041960`, IA `0x7cb2` | `0x1000c6b94` enters the list count path. W28=`0x8934` and W16=`0x8b3dc651`. |

The serializer reads the owner pointer saved at FP−0xb8 B and follows the five constructed nodes. The independently recovered 14 B extent and source pointer at node+0x10 B and node+0x18 B stay live into the two traversals. The generated profiles verify all 96 allocation bytes before handoff. The replay also resolves the previously assumed allocator bank pair from the constructor's original FP−0xe8 B and FP−0xf0 B slots. [Constructor frame saves](daemon_selector26_record_origin_report.md) [List extent proof](daemon_selector26_list_extent_report.md)

## Caller byte and argument record

Let R be the caller's aligned record pointer, equal to its FP−0x78 B. Let U be the u32 at the caller's SP+0x4c B. The caller stores a byte at R+0 B at `0x1001f511c`, then calls `0x1004110fc` with R in X0 at `0x1001f5178`. The callee computes the address-dependent bias in X16 at `0x10041128c`. At `0x10005be70` it saves R at its SP+0x90 B and at `0x10005be74` saves the bias at its SP+0x38 B. The constructor profiles verify preservation to the list-count entry. The serializer reloads R into X6 at `0x100085a48`, then the split at `0x1000c62f0` reads R+0 B and subtracts the saved bias before the byte comparison. [Prior caller record recovery](daemon_selector26_record_origin_report.md) [Caller split](daemon_selector26_callers_report.md)

For incoming W24=`0x3941` and 16 B-aligned R, the record address cancels in the low byte. The original instruction lift proves the adjusted value for all u32 U and all aligned R:

```text
adjusted = u8(2*U + (U XOR 0xef) + 0x3e)
adjusted == 0x2d iff u8(U) == 0
```

Only the low eight bits of U enter this comparison. The adjusted value selects the helper through the existing split and the same serialized buffer and 96 B encoded extent reach its record.

| U fixture | Raw R+0 B at R=`0x8000` | Bias low byte | Adjusted byte | Original call and target |
| --- | --- | --- | --- | --- |
| 16 | `0x09` | `0xac` | `0x5d` | Direct structure, `0x1000f2204` to `0x10043a018`. |
| 0 | `0xd9` | `0xac` | `0x2d` | Descriptor, `0x100111754` to `0x10043ee28`. |

The U fixtures exercise the selector partition. The reaching definition and environmental meaning of the caller's SP+0x4c B word are unknown. The call record address is the constructor FP−0x80 B in both forms. The recovered context save and the normal allocator return supply the context and buffer fields respectively. The RAX trace ends at failed IOKit open. The connection from these two daemon call sites to the framework's Mach message transport remains source-derived. [IOKit sites and Mach transport](daemon_selector26_return_report.md) [RAX trace](zut_trace_report.md)

## Assumption register

| Assumption | Dependent result and falsification probe |
| --- | --- |
| A1. Source bytes and original format-12 fixups match the pinned image. | Logical branch targets and store/load provenance. Re-read the bytes, decode the original chained words and check the saved pointer's producer and reload. |
| A2. The constructor receives the selected nonnull context and phase, and each allocator returns writable, disjoint storage. | Five-node shape, 70 B list extent and 96 B serialization. Recheck the three established global/heap fixture pairs and the source-derived continuations at each appended node. |
| A3. The original caller enters with W24=`0x3941` and aligned R. The caller-owned byte remains live in the callee. | Address cancellation and selector partition. Prove both bit-vector formulas over all aligned R and u32 U, then compare the chosen branch and decoded record fields in both finite U profiles. |
| A4. The inherited SP+0xf8 B word is an available frame value. | Constructor readback. Keep the whole word symbolic and require concrete recovered branch targets. Its original producer remains unknown. |

The selected constructor visits 0, 1, 2, 3 and 4 existing nodes in successive insertions, with a fixed 14 B fill per node. An append that scans k existing nodes takes O(k+14) time and O(1) auxiliary state excluding allocated nodes and buffers. The proved list work and padding then use O(5+70+16) instruction-block visits up to constant factors. The evidence retains O(I) visits and accesses for I source instruction visits, excluding solver and fixup decoding costs.

| Impact | Open evidence |
| --- | --- |
| High | Identify reaching writes to caller SP+0x4c B and callee SP+0xf8 B to connect the conditional profile to earlier daemon inputs. |
| High | Correlate the source-backed constructor and serialized allocation with a successful 2865/2965 transaction and concrete Mach port rights. |
| Medium | Compare the constructor's encoded node bytes to the serializer's source-address mask. |

QG1–QG7 cover factual scope, source assumptions, complete selected frame joins, exact widths and bounds, the two dispatch outcomes, original provenance and unresolved external interfaces.
