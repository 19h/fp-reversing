# Small retirement dispatch, zone geometry and heap-class guards

The complete original small-retirement routine checks the zone interval, indexes a u32 zone-flag table, selects the heap/accounting source, and checks the heap class before calling `bzero(base, element_extent)`. Its data-heap route requires exact class equality. Its ordinary typed-heap route also admits zone class 1. The selected 14 B and 32 B contexts preserve these distinct predicates. Native initialized class values, allocation identity, ownership, actual clearing and deallocation remain unknown. [KD1-KD7]

This extends the [metadata query and caller](kernel_retirement_query_report.md), [allocator boundaries](kernel_allocator_boundary_report.md), and [selected 48 B MixedData retirement](mixed_data_retirement_report.md). The latter already supplies selected displacement/clear contracts; this increment establishes the complete 73-word dispatch and the linked normal 14/32 B paths. It establishes no additional Mach endpoint, right transfer or emission site.

## Primary evidence and claims

Original kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The normalized predecessor kext SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Compiler boundaries identify the routine as `0xfffffe000bcfed8c..0xfffffe000bcfeeb0` exclusive, 292 B / 73 four-byte instructions, SHA-256 `623d907bbadae6222b2b3f2ee324feb2e5b8459b6424ffdaff3c2a7519a9c229`. Its bytes exactly match both the preceding query capture and the older MixedData capture. No exact original symbol names this routine or its two error targets; original nlist records identify the clear target as `_bzero` and `___bzero`. No new IDA observation was needed.

| Claim | Established conditional source result | Dependencies |
| --- | --- | --- |
| KD1 | The raw zone guard is exactly the half-open 132,480 B interval starting at the zone base | KD-A1-A3 |
| KD2 | For the query's 10-bit zone index, admission is exactly index < 690 and the reciprocal expression yields a u32 table offset of 4 * index | KD-A1-A4 |
| KD3 | Normal and tagged heap/accounting selection preserves the zone flag, base, request and element extent needed downstream | KD-A1-A4 |
| KD4 | Special heaps require class equality; the ordinary branch also accepts zone class 1. Rejection calls retain the original operands | KD-A1-A4 |
| KD5 | Linked admitted normal 14/32 B contexts request the recovered base and element extent at the original bzero call | KD-A1-A5 |
| KD6 | Under the declared post-clear ABI/memory/authentication envelope, the tail selects accounting, restores its frame/nonvolatile GPRs, and forwards zone/base/element extent | KD-A1-A6 |
| KD7 | Twenty source obligations cover all 73 instructions, five predecessor formulas recheck, and an altered class comparison produces a counterexample | KD-A1-A7 |

Evidence: [extractor](triage_evidence/recover_kernel_retirement_dispatch.py), [instruction audit](triage_evidence/audit_kernel_retirement_dispatch.py), [delivery verifier](triage_evidence/verify_kernel_retirement_dispatch_delivery.py), [checks](triage_evidence/kernel_retirement_dispatch_checks.json.zst), [proofs](triage_evidence/kernel_retirement_dispatch_audit.json.zst). Decoded checks SHA-256: `5845261a55f5222e41d7a405a1666d3775a2d4285909947f4dffb77b2e823c62`. Decoded audit SHA-256: `b3a0c655276c8cce73a29e33fe7843e65f3c3ac5b5a90fd8819559b50ea10d40`.

## Inputs and exact zone interval

| Entry register | Source role |
| --- | --- |
| X0 | Original heap descriptor, or tagged view pointer with low bit 1 |
| X1 | Recovered element base P |
| X2 | Original request N; selected normal contexts use 14 or 32 B |
| X3 | Zone record pointer Z |
| X4 | Element extent E; the preceding query/caller supplies a zero-extended u16 |

The routine allocates a 48 B frame. X19 carries Z, X20 carries P and X21 carries E. Let B=`0xfffffe000caeb480`, and let subtraction and logical shifts below use u64 bit-vector semantics. The gate at `0xfffffe000bcfedb8` rejects when `((Z-B) >> 7) >= 0x40b`. Equivalently:

```text
admit = B <=_u Z <_u B + 132480
132480 B = 0x40b * 128 B = 690 * 192 B
```

This guard alone admits addresses between record starts; it contains no independent modulo-192 alignment check. The earlier query supplies `Z=B+192*i`, where i is a 10-bit index. Under that correspondence the admitted indices are exactly 0 through 689. The threshold does not establish the number of initialized zones.

| Query index i | Byte displacement 192*i | Guard result |
| --- | --- | --- |
| 0 | 0 B | Admit |
| 689 | 132,288 B | Admit |
| 690 | 132,480 B | Reject |
| 1023 | 196,416 B | Reject |

On rejection, `0xfffffe000bcfeea8` moves the original Z into X0; `0xfffffe000bcfeeac` calls `0xfffffe000c6336f8`. This report establishes that call boundary. Callee fatality, return and native effects remain unknown.

## Flag indexing, heap selection and accounting

After admission, the instructions compute:

```text
t = (((Z-B) * 0x01555556) >> 30) AND 0x3fffffffc
F = load_u32_le(0xfffffe0007e6a7a0 + t)
```

For every admitted query-derived index i, t=4*i. The u32 load is at `0xfffffe000bcfede0`; its class bits are `C=(F >> 8) AND 7`. This proof applies to query-derived record starts. The raw range gate's acceptance of an arbitrary unaligned address does not supply that correspondence. Runtime flag contents are symbolic inputs; retained original data snapshots do not establish initialized values. [KD-A3-A4]

If X0 bit 0 is zero, the routine uses X0 as the heap and loads its accounting pointer from heap+0. If bit 0 is one, it clears that bit to obtain view V, reads u32 flags at V+0x48, and selects:

| View flag condition, in source precedence | Selected heap H |
| --- | --- |
| Bit 3 set | `0xfffffe0007f8bfb0`, data heap |
| Bit 3 clear and bit 15 set | `0xfffffe0007e6a780`, variable heap |
| Bits 3 and 15 clear | `0xfffffe0007f36938`, typed heap |

For a tagged view, X22 first receives u64[V+8]. A nonzero value supplies accounting directly. Zero falls through to the heap+0 load at `0xfffffe000bcfee20`. Thus a view-accounting value of zero selects another source rather than ending the selection. This local contract extends the earlier selected MixedData flags; all u32 view flags are admitted by the proof's declared memory domain. The heap names reflect predecessor source correspondence; these addresses have no exact original nlist symbols in this capture.

## Heap-class policy and error operands

The routine reads the heap's u8 class K at H+0x10. Original instructions implement the following policies for every u32 zone flag and every u8 heap class:

| Selected heap | Admission condition |
| --- | --- |
| Data heap `0xfffffe0007f8bfb0` | C == K |
| Second special heap `0xfffffe0007f411b8` | C == K |
| Other heaps, including typed `0xfffffe0007f36938` | C == 1 OR C == K |

The first special comparison branches at `0xfffffe000bcfee30`; the second at `0xfffffe000bcfee40`. The ordinary branch uses CMP/CCMP/B.EQ at `0xfffffe000bcfee44..0xfffffe000bcfee4c`. Strict equality uses CMP/B.NE at `0xfffffe000bcfee5c..0xfffffe000bcfee60`. For example, C=1 and K=0 passes the ordinary predicate but fails either strict predicate. C is only three bits; K remains the complete eight-bit loaded value.

Class rejection calls `0xfffffe000c62d430` at `0xfffffe000bcfee58` with X0=selected heap, X1=P, X2=N and X3=Z. Its runtime effects and nonreturn behavior are unestablished. The error call's syntactic fall-through is not treated as an admitted clear path; the clear proofs take the original successful branches.

## Clear boundary and zone tail

```text
query/caller outputs
        |
        v
zone interval -> flag table -> heap/accounting -> heap-class gate
        |                                        |
        +-> geometry error call                  +-> class error call
                                                 |
                                           admitted branch
                                                 v
                                       bzero(P, E) request
                                                 |
                                  conditional ordinary return
                                                 v
                                accounting fallback, frame restore
                                                 |
                                                 v
                                      zone tail(Z, S, P, E)
```

For the selected normal contexts, the predecessor supplies heap=data and N=14 B, or heap=typed and N=32 B. Linked proofs include the real prologue, zone gate, reciprocal load, heap accounting, the appropriate class gate, and the clear call at `0xfffffe000bcfee78` targeting `0xfffffe000c6480c0`. Its arguments are X0=P and X1=E. The requested size N does not replace E. No concrete initialized E or native successful clearing is inferred. [KD-A4-A5]

For post-clear continuation the audit uses a fresh byte array for external memory. It preserves only the saved 48 B frame and the selected zone+8 accounting field; other bytes may change arbitrarily. Every volatile GPR may change, while the ordinary ABI preserves X19-X22 and SP. PACIBSP/AUTIBSP are explicit conditional identity envelopes: no native signing or authentication is proved. This allows the selected native effects to remain assumptions rather than an implicit no-op clear model. [KD-A5-A6]

| Accounting after ordinary clear return | Tail X1 |
| --- | --- |
| Previously selected X22 nonzero | That same pointer |
| Previously selected X22 zero | u64[Z+8], loaded at `0xfffffe000bcfee80` |

The tail at `0xfffffe000bcfeea4` targets `0xfffffe000bd74fcc` with X0=Z, X1=selected accounting S, X2=P and X3=E. The 48 B frame and X19-X22/X29/X30 are restored under the envelope. Whether S is nonzero or a valid native accounting object remains unknown. This increment stops at the zone-tail boundary; older selected-cache evidence is conditional on its separate cache premises.

## Proof scope and reproducibility

The extractor captures 14 contiguous spans covering all 73 instructions, including both error calls and both authentication instructions. Twenty nonvacuous source counterexample queries are UNSAT. They include universal interval/index checks, all flag/class selection domains, the two linked normal clear requests, and four post-clear accounting/restore cases. There are 449 proof instruction instances and 429 linked-edge obligations. A block cut is explicit; linked paths verify the expected successor at every subsequent instruction. All loads/stores use one little-endian byte array, including frame and data aliases within the declared domains. Arithmetic is exact fixed-width arithmetic without numerical error.

Five predecessor formulas recheck: the 14/32 B query-caller argument proofs and three earlier scalar/large clear coverage formulas. Those clear formulas do not execute the external bzero target in this increment. Changing the ordinary source comparison's immediate from 1 to 2 yields a SAT counterexample for C=1,K=0; the recorded diagnostic replays independently. Solver search has a 30 s per-query timeout. Query construction and output use O(I+Q) time/space for I instruction instances and Q expression-DAG nodes; SMT search complexity is separate. No target execution or database mutation occurs.

The delivery verifier reconstructs the extraction and audit, compares canonical formula ASTs, re-solves frozen obligations, checks receipt digests and original inputs, and verifies exact publication custody and decoded archive path hygiene. The global manifest records the full goal as active.

## Assumption register

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| KD-A1: pinned source | The recorded collection, compiler boundaries and dependencies supply these bytes. All claims depend on this source identity. | Recapture the 292 B routine and compare both predecessor captures, boundaries and symbol records. |
| KD-A2: architectural model | Fixed-width register operations, byte-array loads/stores, flags and linked branches implement the captured instructions. KD1-KD7 depend on the model. | Replay independent formula ASTs and the altered-immediate counterexample; compare decoding and semantics with another instruction engine. |
| KD-A3: address domain | Declared stack, flag table, heap/view and selected zone regions are valid, nonwrapping and disjoint for their specified accesses. KD2-KD6 are conditional on those domains. | Recover actual mapped regions and aliases; an overlapping frame/metadata write invalidates the corresponding domain. The raw geometry theorem does not assume native Z validity. |
| KD-A4: coherent input epoch | The query-derived Z, flag word, heap/view fields and accounting loads refer to the stated epoch. KD2-KD6 do not prove that epoch occurs. | Compare original query outputs, live zone ID/flags and heap class/accounting for one matched allocation and retirement. Check alternate writers or changed fields. |
| KD-A5: clear boundary | Predecessor 14/32 B inputs select these heap contexts; an admitted call receives P/E. Ordinary clear return is assumed only for KD6. | Compare call registers and completion; error, trap or nonreturn invalidates the continuation. Validate the actual allocation extent and its separation from metadata/frame. |
| KD-A6: ABI/memory/PAC | For KD6, the clear preserves nonvolatile GPRs/SP, the saved frame and zone+8; authentication succeeds under the modeled identity envelope. | Recover callee ABI and memory writes and independently verify native PAC state, saved-frame integrity and zone accounting stability. |
| KD-A7: bounded interpretation | The source proofs and prior formulas establish these dispatch/ABI contracts, without establishing native ownership, clear, free, locking or daemon transaction identity. KD7 and all broader interpretations use this boundary. | Correlate initialized metadata, allocation identity, concrete clearing, zone release/cache behavior and daemon/kext request/response epochs. |

## Bounded continuation

| Impact | Next evidence | Unresolved consequence |
| --- | --- | --- |
| High | Recover the zone-tail's independent zone reclassification and cache/full-cache branches for these normal heaps | Whether the same element is actually retired, and how accounting/reuse proceeds |
| High | Match daemon request/response buffers to a concrete userclient node and one allocation/retirement epoch | Daemon/kext transaction identity remains unestablished |
| Medium | Recover producers of the u32 zone-class flags and u8 heap classes | Equality predicates are known; initialized values and cross-heap lineage remain unknown |
| Medium | Inspect the two error callees and their call-graph terminal behavior | Fatality/nonreturn cannot be inferred from their calling sites alone |
| Low | Extend the reciprocal/address proof to arbitrary raw addresses admitted between records | The current indexed-load correspondence is restricted to query-derived record starts |

## Scoped quality gates

- **QG1**: Factual source, control-flow and ABI claims only.
- **QG2**: KD-A1-KD-A7 identify dependencies and falsification probes.
- **QG3**: Complete 73-word dispatch, four external transfers, all heap-class branches, accounting routes and linked normal contexts are covered; the overall interface goal remains active.
- **QG4**: 73 * 4 B = 292 B; frame 48 B; zone stride 192 B; 690 * 192 B = 132,480 B; flag stride 4 B; u8/u32/u64 domains and complexity are explicit.
- **QG5**: Guard threshold versus initialized count, requested versus element extent, raw versus query-derived Z, strict versus ordinary classes, and clear request versus native completion remain distinct. Both error transfers stop at their callee boundaries.
- **QG6**: Primary collection bytes, compiler bounds, two exact predecessor matches, original clear symbols, 20 new proofs, five prior rechecks and the altered-source counterexample are retained and replayed.
- **QG7**: Ranked continuation covers native identity, deeper retirement, class producers, error behavior and the unaligned-address scope boundary.

The [two retirement diagnostic callees](kernel_retirement_diagnostics_report.md) now have complete source coverage: geometry rejection produces the zone-array _panic request; class rejection selects typed/regular/heap formats and exact variadic operands. The typed route stores a diagnostic byte and zone pointer before its _panic call. Source call boundaries and missing local return instructions remain separate from native panic execution/termination; initialization, synchronization and allocation ownership remain unknown.

The [complete zone-retirement tail](kernel_zone_retirement_report.md) now establishes reclassification/displacement gates, per-thread and CPU accounting, authenticated-cache boundaries, current/spare magazine publication, both-full helper custody, and nesting/pending/deeper-release continuations. Its source proofs do not establish native authentication, helper effects, actual reclamation or a matching daemon transaction; no new Mach endpoint is established.
