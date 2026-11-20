# Discovery status in the daemon caller

The daemon caller at `0x10046fc5c` invokes the discovery adapter at `0x1003f57bc` and reads its 32-bit status at `0x1003f57d4`. The explored continuations publish the same word at byte offset `0x28` of the caller's incoming record and return. Five offline profiles execute the actual adapter and caller instructions around a modeled discovery return. The earlier audit independently established the discovery routine's write at byte offset `0x10` in the child record. [Discovery output](daemon_class_marker_output_report.md) [Audit](triage_evidence/audit_daemon_class_marker_caller.py) [Receipt](triage_evidence/daemon_class_marker_caller_audit.json.zst)

## Call and return

P denotes the parent record passed in X0. Q denotes the child record at parent FP−0xa0 B. The reached parent phase is `0x7b68`. The successful modeled allocation path carries W19=`0xb72d` into the child builder. The source writes the child phase at Q+0x34 B as the address-dependent key plus W19−`0x427`. The child decodes this as `0xb306`.

| Site | Operation |
| --- | --- |
| `0x10046ff30` | Save P at parent SP+0x260 B. |
| `0x1003a8464` | Call `malloc` through slot `0x10109ff58`, IA `0x6aa4`. The return value becomes Q+0x18 B. |
| `0x1003f57bc` | Call the adapter `0x10061748c` through slot `0x1010a1260`, IA `0x8409`. X0 is Q and X1 points to the parent stack cursor cell. The ordered banks at `0x100e99a00` and `0x100f4e390` collapse all 256 input-byte choices to index `0xce6e` for this site. |
| `0x1006176d0` | Pass the same Q in X0 to `0x100559b7c`. X1 now points to the adapter's local cursor. |
| `0x1003f57d4` | Read W23 from parent FP−0x90 B, the same address as Q+0x10 B. Before this load the parent adds the adapter's cursor delta to SP. |
| `0x1004ccb5c` | Store W23 to P+0x28 B. The guard-checked epilogue returns at `0x1004ccb94`. |

The adapter computes its cursor delta from the value in the local cursor cell supplied in X1 to the outer routine. The source initializes the cell at `0x10061761c` and reads it at `0x1006176d4`. This corrects the description of the cursor input in the preceding output report.

Two other call sites share the adapter's authentication modifier `0x8409`. Original bank indices select `0x10047d47c` at `0x10047ef48` and `0x100912ad8` at `0x100914350`. They establish why the modifier alone cannot identify the call. The reaching banks at the remaining candidate `0x1005535c0` are outside the verified path.

## Copy and release

The tail dispatch at `0x1003f5950` has an exact predicate over the reaching 32-bit control in W26. The status in W23 survives both checked arms. The replays use synthetic payload bytes and test positive extents of 1 B and 16 B as well as the no-copy path.

| Reaching W26 | First target | Observed continuation |
| --- | --- | --- |
| `0x540148f9` | `0x1003836a0` | Request `free` of the modeled allocation at `0x1003836f0` and publish status. |
| Any other word under the fixed phase | `0x1004cbed4` | Enter byte-copy loop at `0x1004d0340`. In the positive-extent profiles it copies the requested bytes in descending offset order, XORs each with `0x98`, and writes to the buffer designated by P+0x18 B. It then joins the same free and status publication. |

## Assumptions and verification

| Assumption | Dependent result | Falsification probe |
| --- | --- | --- |
| A1. The pinned arm64e image supplies the instruction and fixup evidence. | Sites, indexed targets and register effects. | Verify 31 original chained words and three ordered bank selections over all 256 inputs per pair. Hardware authentication remains unknown. |
| A2. The helper at `0x100412ebc` returns with Q+4 B unequal to `0x14`, `malloc` supplies the declared pointer, and `free` returns ordinarily. | The selected parent phase, its successful allocation route and final return. | Check actual call arguments and edge targets. Observe zero, one and 16 byte copy extents in the model. Native helper and allocator effects remain unknown. |
| A3. The modeled outer return supplies the discovery status and advances the adapter's local cursor by the source-observed `0xe0`. | Same-record status handoff, ordinary stack restoration and copy data flow. | Vary the three previously observed statuses, check exact W23 and P+0x28 B values, require a single 4 B status store, and check unchanged destination suffix bytes. A continuous native join remains unknown. |

The audit retains 64 logical transfers across five profiles and discharges three bit-vector queries for the local status load, local store and branch predicate. Replay time is linear in instruction visits and the byte-copy loop uses O(n) time for n copied bytes. The receipt uses O(t+n) space for t recorded transfers and byte offsets. Run `python3 -B triage_evidence/audit_daemon_class_marker_caller.py` in the existing Unicorn, Capstone and Z3 environment. IDA's bridge was unavailable during the caller lookup.

| Remaining evidence | Impact | Discriminator |
| --- | --- | --- |
| Consumer above `0x10046fc5c` | High | Recover callers and trace the same P+0x28 B value into a further record or reply. |
| Native cross-layer attribution | High | Join the exact parent, child and IOKit call in one observation. The prior archived open supplies transport evidence independently of these replays. |
| Extent and content provenance | Medium | Resolve reachable parent input and the outer routine's writes to the allocation that feeds the copy. |
