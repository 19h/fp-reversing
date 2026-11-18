# fairplayd allocation and padding upstream of selector 26

On the recovered normal path, the buffer passed into either selector 26 argument record comes from `_malloc` at `0x10008f4e0`. The caller records encode the allocation extent. The ten-byte header's last field encodes the number of zero bytes written immediately after the header. This establishes the common producer for the two lengths that the earlier header audit modeled independently. [Header writer](daemon_selector26_header_report.md) [Caller records](daemon_selector26_callers_report.md)

The source is the original arm64e Mach-O with SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are unslid virtual addresses. The audit checks source instruction bytes, original chained-fixup words and the arithmetic implied by the selected entry state. [Audit generator](triage_evidence/audit_daemon_selector26_padding.py) [Compressed evidence](triage_evidence/daemon_selector26_padding_audit.json.zst)

## Extent and allocation

Let `T` be the incoming unsigned 32-bit byte count in W8 at `0x1000ee4e8). The original source yields the following under incoming W10=`0x6246`.

```text
P = 16 - ((T + 10) & 15)      padding in bytes, 1 <= P <= 16
N = u64(T) + P + 10          allocation extent in bytes
admit iff u64(T) + P < 0xfffffff6
      iff T <= 0xffffffe5
```

The low four bits used to derive `P` are unaffected by wrap in the 32-bit addition. The guard at `0x1000ee58c` compares widened unsigned operands. On the admitted route `N` is divisible by 16 B and lies between 16 B and `0xfffffff0` B inclusive. It fits exactly in W0 and is zero-extended into X0. The already aligned case receives 16 B of padding.

| T (B) | P (B) | N (B) | Guard |
| --- | --- | --- | --- |
| 0 | 6 | 16 | Admit |
| 5 | 1 | 16 | Admit |
| 6 | 16 | 32 | Admit |
| `0xffffffe5` | 1 | `0xfffffff0` | Admit |
| `0xffffffe6` | 16 | `0x100000000` | Reject |

The last two rows are arithmetic boundary checks. The audit does not allocate storage at either boundary.

| Original PC | Slot and IA modifier | Source-derived effect |
| --- | --- | --- |
| `0x1000ee5b0` | `0x101088c78`, `0x6ff9` | The admitted branch enters `0x10008f46c` with W21=`0x4d28`, X22=`P` and W19=`u32(0x37c30c43 - P)`. The other slot, `0x10106b120`, targets `0x100013334`. |
| `0x10008f4c4`, `0x10008f4d8`, `0x10008f4e0` | `0x10109ff58`, `0x6aa4` | Produces `N` in W0, saves the 8 B X0 at SP+0x130 B and calls the libSystem `_malloc` import. |
| `0x10008f50c` | `0x101060830`, `0xf6ab` | A nonnull return selects `0x1000859ec`. The original X0 becomes the pointer in X7 at `0x1000859f8`. |
| `0x1000fe3d8` | `0x10106d040`, `0xa57c` | After the header stores, positive X22 selects the loop at `0x100011f88`. |
| `0x100011ff8` | `0x10106d040` or `0x10106d138`, `0xa57c` | Repeats at `0x100011f88` while the incremented index is below `P`. Otherwise enters the caller split at `0x1000c62f0`. |

The allocator lookup reads the left bank from FP−0xe8 B and the right bank from FP−0xf0 B. For each of the two checked ordered pairs, all 256 lookup inputs give byte index contribution `0x8c` with key `0xd7`, producing table index `0xcc0d`. The pairs are `(0x100e99a00, 0x100f4e390)` and `(0x100fc4230, 0x101031fa0)`. The reaching definitions of those frame slots at this allocation are unknown. [Earlier frame saves](daemon_selector26_record_origin_report.md)

## Buffer writes and caller handoff

Let B be the modeled fresh nonnull allocation result. The header writer advances X8 to B+10 B and initializes the padding index to zero. The store at `0x100011fa0` writes one zero byte to `[X8,X12]` per iteration. The audited write footprint through either caller dispatch is:

| Allocation-relative interval (B) | Observed effect |
| --- | --- |
| `[0,4)` | Big-endian u32 zero |
| `[4,6)` | Big-endian u16 `0x50db` |
| `[6,10)` | Big-endian u32 `P` |
| `[10,10+P)` | `P` zero bytes |
| `[10+P,N)` | Outside the recovered write footprint. Any additional producer is unknown. |

The common dispatch loads its control byte through the pointer from SP+0x90 B. With the established caller frame and zero bias, the `0x2c` fixture reaches the direct structure helper via `0x1000f2204` and puts B at record+0 B. The `0x2d` fixture reaches the descriptor helper via `0x100111754` and puts B at record+24 B. Both encode `N` from SP+0x130 B. The minimum allocation of 16 B is reachable in both fixtures. The 14 B descriptor example in the independent caller audit established a local record codec and falls outside the admitted sizes of this producer. [Caller record codecs](daemon_selector26_callers_report.md) [IOKit sites and return channels](daemon_selector26_return_report.md)

The earlier node constructor reaches its own 14 B allocations at a different call site. The independently audited list flattener uses the same padding equation and places its header after the copied list bytes. This route places the header at the allocation base. The lineage of `T` and any link to either earlier component remain unknown. The retained RAX trace reaches IOKit open 2862/2962 and records status `0xe00002c2` with a null connection. Native selector 26 message 2865, its payload and its connection and reply rights remain unobserved. [Node constructor](daemon_selector26_node_report.md) [List flattener](daemon_list_output_report.md) [Trace coverage](zut_trace_report.md)

## Assumption register

| Assumption | Dependent result and falsification probe |
| --- | --- |
| A1. The original image and its format-12 chained fixups match the pin. | All unslid PCs and logical authenticated targets. Recompute the source spans and decode the consumed slot words from the Mach-O. |
| A2. The size block enters with W10=`0x6246`, arbitrary u32 W8 and the expected table pointer. | Exact padding and admitted interval. Solve the negated source equations over all u32 values and check the two guard slots against the original image. The reaching phase and count producers remain unknown. |
| A3. The two bank slots contain a checked pair, and the allocator returns aligned, fresh, nonaliasing writable storage. | Import identity and the continuation with B in X0. Enumerate all 256 bank inputs per pair, then replay ordinary ABI return with caller-clobbered registers invalidated. This is a modeled allocator result. |
| A4. [X20] contains a zero u64, SP+0x90 B holds the dispatch pointer and the caller frame matches the prior record audit. | Header and both record routes. Check the expected authenticated edges, all 16 padding counts, control-byte loads and both pointer and size codecs. The actual producers of [X20] and SP+0x90 B on this route remain unknown. |

The size calculation and caller handoff use O(1) time and auxiliary state. The prefix writer uses O(P) time and O(1) auxiliary state, with exactly `10 + P` byte stores. The evidence generator records O(I) instruction visits and accesses, excluding solver and fixup-decoding costs. Five negated bit-vector properties are unsatisfiable. Thirty-two finite profiles cover all `T mod 16` residues once per caller form and verify the complete local write sequence.

| Impact | Open evidence |
| --- | --- |
| High | Resolve the authenticated predecessor and reaching definitions of W8, W10 and SP+0x90 B at this allocation route. |
| High | Correlate local argument records to a successful selector 26 transaction and identify its connection and reply rights. |
| Medium | Relate this positive-padding route to the separate list and node constructors through original pointer and count producers. |

QG1–QG7 cover the factual scope, conditional inputs, allocation and caller joins, exact widths and bounds, arithmetic boundary cases, original source provenance and open interface evidence.
