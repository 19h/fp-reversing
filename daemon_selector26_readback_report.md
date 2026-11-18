# fairplayd first buffer read and second node insertion

The normal constructor route reads offsets 0–3 of its first 14 B buffer. It then links the second node after the first and updates the 16 B object's tail pointer. These effects follow from the pinned daemon instructions with the unresolved SP+0xf8 B word modeled symbolically. The join to either selector 26 argument remains unknown. [Constructor handoff](daemon_selector26_node_report.md) [Selector 26 call sites](daemon_selector26_return_report.md)

| Original PC | Observed effect |
| --- | --- |
| `0x100054958`, `0x100054964` | Reads 8 B at SP+0xf8 B and adds `0xc84937ac` modulo 2^64 into X20. No audited reaching store overlaps the eight bytes before the load. |
| `0x1000549b4` | Branches via slot `0x101051a58` with IA modifier `0xc0b6` to `0x10015f344`. X0 still holds the first buffer pointer. |
| `0x10015f354`, `0x10015f360`, `0x10015f370`, `0x10015f37c` | Four unsigned byte reads at offsets 0, 1, 2 and 3 into W14, W8, W30 and W16, respectively. No read from the second buffer occurs in this block. |
| `0x100013a68` | Writes the second node pointer to first node+0 B. |
| `0x100013a6c`, `0x100013a70` | Reads object+8 B, still the first node, then stores that pointer at second node+8 B. |
| `0x100013a74` | Writes the second node pointer to object+8 B. Object+0 B still holds the first node. |

```text
owner +0  --> first node  -- +0 --> second node
owner +8  -----------------------> second node
              first node  <-- +8 -- second node
```

The audit follows nine logical authenticated edges from the unresolved load through insertion and stops at `0x1000e72c4`. The first node's +8 B and second node's +0 B fields are zero there. Both original buffer pointers remain in their node+24 B fields. This supports a two-ended doubly linked list interpretation for this sequence. Removal, later traversal and external publication remain unknown. No additional port transfer or Mach send appears in the interval. [Audit](triage_evidence/audit_daemon_selector26_readback.py) [Compressed receipt](triage_evidence/daemon_selector26_readback_audit.json.zst)

The retained trace ends with a failed IOKit open and a null connection port. Native reachability, native pointer authentication and the pointer identity at a live selector 26 call remain unknown. [Trace and port attribution](zut_trace_report.md)

## Assumption register

| Assumption | Dependent result and falsification probe |
| --- | --- |
| A1. The pinned original image and format-12 fixups match the prior handoff audit. | Instructions and destinations. Re-read the source spans and decode the original target and discriminator words. |
| A2. The decoded phase is `0x8934`, the context is nonnull and the five allocations are writable, aligned and disjoint. | The selected read and insertion paths. Rebuild the parent frame under its three distinct allocation layouts and check the resulting access journals. |
| A3. The 8 B stack word at SP+0xf8 B is present as an arbitrary u64. | Continuation branch and pointer effects for the audited path. Require the branch targets, data access addresses and published pointers to resolve with that value symbolic. The replay leaves the producer unknown. |

The audit uses O(I) time and space for I instruction visits in a fixed set of three profiles, excluding symbolic simplification and fixup decoding. The initial read transfers four individually addressed bytes.

| Impact | Open evidence |
| --- | --- |
| High | Follow the four loaded bytes to their downstream use and distinguish local interpretation from transport serialization. |
| High | Resolve the original stack-word producer and correlate the node or buffer with a live selector 26 request. |
| Medium | Check later insertions and retirements to establish the lifetime of the head and tail references. |

QG1–QG7 cover the conditional source interval, exact widths, fixture premises, source provenance and the remaining transport boundary.
