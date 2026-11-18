# fairplayd list serialization and selector 26 argument records

On the recovered `0x8934` path, `fairplayd` serializes the counted list into one allocation. It transforms each source byte with an address-dependent XOR, preserves node order and byte offsets within each node, then appends a 10 B header followed by zero padding. Both checked selector 26 argument forms receive the allocation base and encode its full extent. [List count and allocation](daemon_selector26_list_extent_report.md) [Caller record codecs](daemon_selector26_callers_report.md)

The source is the original arm64e Mach-O, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. PCs are unslid virtual addresses. The receipt includes 36 source spans, 24 independently decoded format-12 fixups, four bit-vector proofs and twelve static profiles. It retains the symbolic XOR expression and the exact write order for each profile. [Audit generator](triage_evidence/audit_daemon_selector26_list_transfer.py) [Compressed evidence](triage_evidence/daemon_selector26_list_transfer_audit.json.zst)

## Node transfer and traversal

Let B be the fresh allocation base, C the cumulative extent of preceding nodes in bytes, n the current node's u32 extent in bytes, and S the pointer at node+0x18 B. For n>0 B the original setup supplies X12=S, X13=n−1, X14=B+C+n−1 and X15=`(S+n−1)<<3`, with the pointer arithmetic modulo `2^64`. The 32-bit cumulative count is carried as `W8 = u32(0x500c0e89 + C)`. The source equations recover C even when that encoding wraps.

| Original PC | Source-derived operation |
| --- | --- |
| `0x100084058`, `0x1000e66bc` | Selects the zero-length skip at `0x100034ec8` or sets up the positive-length loop at `0x100090998`, via slot `0x10104dea8`, IA `0x17c9`. |
| `0x100090b6c`, `0x100090ba8` | For index i, reads the byte at S+i and writes it XOR the source-derived mask to B+C+i. The store post-decrements X14 by 1 B. |
| `0x100090bb8`, `0x100090bbc`, `0x100090bc4` | Decrements X13 by 1 and X15 by 8. With pre-decrement i>0, repeats via `0x10104dea8`. With i=0, branches to `0x100107b48` via `0x10104dfb8`. Both use IA `0x17c9`. |
| `0x100107b4c`, `0x100107b5c` | Reloads n and joins the advance block at `0x100034ec8` via `0x101077718`, IA `0x48f7`. The zero-length route joins with n=0 and skips byte accesses for that node. |
| `0x100034eec`, `0x100034ef0`, `0x100034f1c` | Advances the encoded count by n and loads node+0 B. A next node reenters `0x100083e80` via `0x101046b78`. A null next pointer enters `0x10008a358` via `0x101078110`. Both use IA `0x9dfb`. |
| `0x10008a3a8` | Reconstructs the cumulative offset and reaches the shared header writer via `0x101046b08`, IA `0x9dfb`. |

The byte proof holds for arbitrary input bytes. It obtains the mask by substituting zero for the byte read and proves that the original output equals the supplied byte XOR that mask at the same source base and index. The byte loop visits a node's offsets in descending order. Source offset i maps to destination offset C+i, so bytes remain in their original positions within the node's span. The relationship between this transform and the earlier constructor's byte encoding remains unknown. [Constructor fills](daemon_selector26_node_report.md)

## Layout and argument handoff

For a stable finite list, the transfer pass advances C by the same n values collected by the count pass. Induction gives adjacent output spans `[C,C+n)` and final `C=T`. The extent guard gives `T <= 0xffffffe5` B, padding `P=16-((T+10)&15)` B and allocation size `N=T+10+P` B. A separate proof checks all ten trailer byte values and addresses over that admitted range. It also establishes X8=B+T+10 before the existing P-iteration zero loop. [Size and padding proof](daemon_selector26_padding_report.md)

| Allocation-relative interval (B) | Value |
| --- | --- |
| `[0,T)` | Node bytes after the XOR transform, in list order |
| `[T,T+4)` | Big-endian u32 zero |
| `[T+4,T+6)` | Big-endian u16 `0x50db` |
| `[T+6,T+10)` | Big-endian u32 padding count P |
| `[T+10,N)` | P zero bytes |

The recovered writes partition the entire allocation under these premises. In each finite profile the audit checked that every byte of the allocation was written exactly once before reaching either helper. An empty list takes the previously recovered header-first route and writes the same layout with T=0 B. A nonempty list containing only zero-length nodes reaches the header through the advance block and also uses T=0 B.

| Dispatch byte at zero bias | Local call | Argument fields |
| --- | --- | --- |
| `0x2c` | `0x1000f2204` to `0x10043a018` | B at record+0 B, encoded u32 N at record+16 B |
| `0x2d` | `0x100111754` to `0x10043ee28` | B at record+24 B, encoded u32 N at record+0 B |

The latter offsets are the internal caller record layout. The prior helper audit maps the calls to the downstream `_IOConnectCallStructMethod` arguments and the framework's Mach transport. This report checks the serializer through the helper handoff under the recovered frame premises. The retained RAX trace ends at the failed IOKit open, so no native selector 26 message or associated port identities were observed. [IOKit arguments and transport](daemon_selector26_return_report.md) [Trace coverage](zut_trace_report.md)

## Assumption register

| Assumption | Dependent result and falsification probe |
| --- | --- |
| A1. The original supported instructions and chained fixups match the pinned Mach-O. | The source transformations and logical authenticated routes. Rebuild the bit-vector proof from the original bytes and independently decode the consumed slots. |
| A2. The selected `0x8934` frame reaches the count and transfer blocks with the recorded table and bank roots. | Composition from count through allocation and serialization. Replay both caller records with empty, zero-length, single-node and mixed lists. The earlier constructor's reaching branch remains unknown. |
| A3. The list is stable, finite and acyclic, the source spans are readable, and the fresh nonnull allocator result is valid and disjoint. | Equality of the two traversal extents and the proof of full write coverage. Check the exact read and write offsets, recurrence and cursor across adjacent nodes. Native ownership and synchronization remain unknown. |
| A4. SP+0x90 B supplies the earlier caller audit's dispatch pointer and compatible frame state. | Selection of both local argument records. Replay `0x2c` and `0x2d` with zero bias and decode both records against the actual allocation extent. The dispatch byte's producer remains unknown. |

With m nodes and T payload bytes, the two traversals, trailer and padding take O(m+T+P) time and O(1) auxiliary state excluding the N B result. The checks include empty head, a nonempty zero-byte payload, full 16 B padding when T=6 B, two 14 B nodes, and a zero-length node between two positive-length nodes. The two 14 B nodes yield a 28 B payload, 10 B header and 10 B zero tail in a 48 B allocation.

| Impact | Open evidence |
| --- | --- |
| High | Trace the normal constructor continuation into `0x1000c6b94` and recover the dispatch-byte producer in that frame. |
| High | Correlate the helper's selected record and serialized allocation with a successful native 2865/2965 exchange. |
| Medium | Compare the producer-side encoding with the verified XOR mask and determine the relationship to the separate list flattener. |

QG1–QG7 cover the source premises, exact data widths, complete conditional allocation layout, both record mappings, boundary cases, original provenance and open interface evidence.
