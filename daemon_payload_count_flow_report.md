# fairplayd: context count/data interface and payload copy bounds

The retained payload consumer reads a u32 count at context+0x1c and advances that pointer to data at context+0x20. The count is 6 in both retained contexts. Original count reconstruction, saved memory, register saves/restores and loop conditions now connect that count to the earlier four-byte direct read and the later two-byte scratch-prefix copy. These count/data offsets match the previously recovered six-byte network-record publication. This establishes a static layout correspondence; a native constructor-to-consumer object epoch and daemon-kext transaction identity remain unknown. [CF1-CF6; CF-A1-CF-A6]

The earlier payload report established the eight pre-mixer bytes as six context bytes followed by two preserved scratch-encoder bytes. This increment explains why the copy replaces exactly the first two scratch bytes: the direct reader has advanced the logical position from 0 to 4, leaving `6 B - 4 B = 2 B`. The final two scratch bytes retain their earlier encoded values. Application names for the final two bytes remain unknown. [CF2-CF4]

| Evidence | Primary provenance and scope |
| --- | --- |
| CF1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original count-read/state, carry-reconstruction, cursor/gate, pointer-publication, save/restore and copy instructions. |
| CF2 | [Payload scalar mixers](daemon_payload_scalar_mixers_report.md), [retained record extension](daemon_record_extension_report.md), and pinned checks/replay/audit receipts. Their private-model admissions, fixture contents and declared allocation/free returns remain dependencies. |
| CF3 | [Extractor](triage_evidence/recover_daemon_payload_count_flow.py), [checks](triage_evidence/daemon_payload_count_flow_checks.json.zst): selected original chunks from intervals 1/3, saved-cell continuity through interval 2, exact count/data addresses and loop inputs for classes 2/3. |
| CF4 | [Independent auditor](triage_evidence/audit_daemon_payload_count_flow.py), [audit](triage_evidence/daemon_payload_count_flow_audit.json.zst): original-byte/frame/effect replay with explicit writeback handling, independent forward byte folds and sixteen source/composition obligations. |
| CF5 | [Publication verifier](triage_evidence/verify_daemon_payload_count_flow_publication.py): fresh extraction/audit equality, source proof reconstruction and re-solving, exact manifest delta, original-input custody and path hygiene. |
| CF6 | [Context state publication](daemon_context_state_publish_report.md), whose checks/audit are pinned by CF3-CF4, maps a network-record count to C+0x1c and six bytes to C+0x20..C+0x25. [Network identity](daemon_network_identity_report.md) separately qualifies the IOKit/cache producer. Native field validity and object-epoch continuity are not inferred from matching offsets. |

Decoded checks SHA-256: `ae049dbc07c56b85bd8e5929b91cfc90078b54c739208d9a9a3396bdc0fb3a3b`. Decoded audit SHA-256: `8ce40257cf18caf157ce8803cbbd9085c150889079eed458e2fdf9ac22d5820b`. Parent/dependency hashes and decoded interval hashes appear in CF3-CF4. Existing source/reference evidence sufficed; additional IDA data was unnecessary for these contracts. [CF1-CF5]

## Count/data interface and source continuity

Addresses below belong to the retained private model. J is its 552 B context at `0x6500115b20`. B denotes bytes; source ranges are half-open. The earlier producer and current consumer are separate evidence epochs. [CF2-CF4,CF6; CF-A2,CF-A6]

| Field | Earlier producer source | Current consumer source | Current retained value |
| --- | --- | --- | --- |
| C/J+0x1c | `0x100597974..0x10059797c`, network-record count publication | `0x10083e784`, `ldr w13,[x12],#4` | u32 6 from `0x6500115b3c` |
| C/J+0x20..+0x25 | `0x10059ccd4`, `0x10059ccd8`, six-byte reverse-index copy | Shared reader loads at `0x100a8d8a4`, `0x100a8d8b8`, `0x100a8d8cc`, `0x100a8d8e4`; tail read at `0x100a396a4` | Six zero-valued retained context bytes |

The post-incrementing count read leaves X12=`0x6500115b40`, exactly J+0x20. The source saves this advanced pointer in its state, reloads that same state field at `0x100c3ca28`, and stores it at caller SP+0x1e0 at `0x100c3ca2c`. Subsequent direct-reader and tail-copy pointer loads consume this saved value. The count's original pointer is inherited in these consumer intervals. [The pointer-origin report](daemon_count_pointer_origin_report.md) separately identifies its constructor-side source store at `0x100710630` and immediate snapshot-copy use. [The lineage report](daemon_count_pointer_lineage_report.md) establishes conditional preservation of these eight pointer bytes through the selected intervening models. Whole-machine initializer continuity and native object continuity remain unknown. [CF3-CF4; CF-A2]

```text
retained J+0x1c: u32 count 6
       |
       +-> post-increment X12 by 4 B -> J+0x20 data pointer
       |
       +-> encoded state -> unsigned reconstruction -> biased u64 count
                                                   |
                                                   +-> saved cell
                                                       -> helper saves/restores
                                                       -> word/tail gates

J+[32,36): 4 B -> direct BE32 reader -> first affine payload word
J+[36,38): 2 B -> scratch+[0,2)
scratch+[2,4): 2 B remain encoded -> scratch BE32 reader -> second affine word
```

## Unsigned count reconstruction

Let N be the u32 count and q the low32 address/state key. The original preparation consists of `0x10083e788..0x10083e7a0` and `0x10083e834..0x10083e84c`, with the intervening source preserved in the retained replay. The resulting state word is `low = u32(N + 0x0d38177c - q)`. In the actual retained frames, preparation q is `0xb56d8b14`, and the reconstruction's q64 is `0x8ac9c0d6b56d8b14`; their low32 values match. General composition uses this explicit key equality. [CF3-CF4; CF-A3]

Under the checked reconstruction phase W8=`0x250`, original `0x100bab334..0x100bab384` computes the following. Additions marked u32 wrap; the u64 reconstruction and constant bias are exact for every u32 N. [CF4]

```text
C32 = 0x0d38177c
s32 = u32(low + low32(q64))
carry64 = (s32 < C32 unsigned) ? 0x100000000 : 0
extended64 = zero_extend(s32) OR carry64
           = zero_extend(N) + C32

encoded_count64 = extended64 + 0x4a2cb691b94eaf9a
                = zero_extend(N) + 0x4a2cb691c686c716
```

The carry term preserves unsigned addition beyond 32 bits; treating this as a signed extension or dropping the carry would change the all-u32 contract. The publication add at `0x100bab4d0` defines X1, and `0x100bab6ec` stores it at SP+0xc8. For N=6, `s32=0x0d381782` and `encoded_count64=0x4a2cb691c686c71c`. No native length validity or admission for every possible N is implied by the arithmetic theorem. [CF3-CF4; CF-A3-CF-A4]

Two register values used by that final add are preserved through 84 frames each per context; X1 then remains preserved through 135 frames until its spill. Instruction-definition scans and exact frame comparisons give `2 * (84 + 84 + 135) = 606` preservation checks across the two contexts. [CF3-CF4]

## Saved cells and actual copy bounds

| Saved cell | Retained address | Established value before the relevant read | Consumer |
| --- | --- | --- | --- |
| Encoded count, SP+0xc8 | `0x680005fc08` | `0x4a2cb691c686c71c` | `0x100c22ae0` copies it to SP+0x2d0; `0x100c27a98` also reloads it |
| Count loop copy, SP+0x2d0 | `0x680005fe10` | Same encoded u64 count | `0x100c1db60` reloads X23 |
| Advanced data pointer, SP+0x1e0 | `0x680005fd20` | `0x6500115b40` | Direct-reader setup and `0x100a8c78c` tail-copy setup |

The first and third cells have eight checked boundary links, totaling 64 byte links, across two cells, two contexts and the two intervening boundaries. Independent forward folds check all source writes and compare incoming fixture bytes. Neither declared API effect invalidates these cells, and there is no overlapping write before the relevant query cut. This scope concerns those reads; later end-of-interval state is not substituted for an earlier read epoch. Other in-interval count copies, inner/outer register spills and restores have exact per-read predecessor checks. [CF3-CF4; CF-A5]

Let i denote the decoded u32 logical byte index, with encoded cursor `u32(i+0x4a384b6e)`. Original `0x100c1db44..0x100c1db64` advances that cursor by 4 and reloads the saved encoded count. Original word-gate arithmetic at `0x100bdafc4..0x100bdaffc` computes `unsigned64(i) < u64(unsigned64(N)-4)`. For `N>=4`, this is exactly `unsigned64(i)+4 < unsigned64(N)`. The N>=4 premise is separately checked as nonvacuous. The modular equation remains exact below that domain, but admission/behavior of low-count caller paths is unknown here. [CF4; CF-A4]

| Gate | N | i | Tested condition | Retained result |
| --- | --- | --- | --- | --- |
| First word gate | 6 | 0 | `0+4 < 6` | Direct four-byte reader path |
| Next word gate | 6 | 4 | `4+4 < 6` | Scratch/tail preparation path |
| Tail entry | 6 | 4 | `6 > 4` | Enter prefix copy |
| First tail step | 6 | 4 | `6 > u32(4+1)` | Copy index 4, continue |
| Second tail step | 6 | 5 | `6 > u32(5+1)` | Copy index 5, exit |

Original tail entry `0x100a8c730..0x100a8c758` compares N and i after canceling the saved count bias. The loop copies one byte from data+i to scratch+(i-4). Its original increment/dispatch arithmetic at `0x100a396b0..0x100a396cc` continues when `N > u32(i+1)`, using selector `0x66ad`; otherwise it uses `0x6659`. The general equation retains u32 index wrap. The actual indices 4/5 do not wrap. [CF3-CF4; CF-A4]

| Tail selector | Logical table slot | Original fixup target | Role |
| --- | --- | --- | --- |
| `0x66ad` | `0x10106d458` | `0x100a39694` | Next byte-copy iteration |
| `0x6659` | `0x10106d1b8` | `0x100bd8394` | Scratch-reader setup |

Both dispatches use logical authentication modifier `0xa96e`. These are internal code-dispatch slots, not Mach ports. Complete retained replay establishes the two original copy stores and their actual targets. CF2 supplies the following scratch reader, affine scalar mixers, original overwrite timeline and final digest-body joins. [CF2-CF4]

## Assumptions and validation

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CF-A1: Pinned original image and dependencies are the intended specimen | Every source mapping and proof | Rehash image, receipt and code dependencies; compare each retained instruction word. |
| CF-A2: Retained path admissions, fixtures, owner identities and declared API effects apply | Count 6, pointer identity and concrete source order | Match parent interval hashes and complete selected frames/effects; retain inherited pointer/fixture origins and API assumptions. Require native observations before promoting modeled identities. |
| CF-A3: Reconstruction phase W8=0x250 and preparation/reconstruction low32 keys agree | General encoded-count composition | Check both actual key values, saved-field predecessor bytes and all-u32 stage/carry proofs. A different phase/key relationship requires another contract. |
| CF-A4: u32/u64 wrap and comparison domains are retained | Word and tail gate interpretations | Prove modular source equations and the N>=4 integer interpretation separately. Keep `u32(i+1)` at the tail step; do not infer caller admission or a length validation result from a local equation. |
| CF-A5: Saved bytes are evaluated at the actual query cut | Cross-boundary count/data continuity | Fold every overlapping write independently, check declared invalidations and compare incoming values; a conflicting pre-read write or API invalidation falsifies the link. |
| CF-A6: Constructor/consumer correspondence is a source-layout result | Network-record field interpretation | Match the count/data offsets and source roles; establish pointer identity, constructor writes and native lifetime in the same observed transaction before claiming a native epoch join. |

Independent replay checks 666 original A64 visits, 22,464 GP/SP values, 702 NZCV frames, 110 reads, 58 writes and eighteen logical authenticated edges in 36 chunks. Ten writeback instructions include the post-incrementing count load and inner/outer pair saves/restores. The audit checks 364 in-interval predecessor bytes and separates 332 incoming/image bytes. These read-custody counts and the 64 boundary byte links are overlapping evidence populations, not additive totals. [CF3-CF4]

Sixteen nonvacuous UNSAT obligations cover the count load/pointer advance, encoded state, unsigned reconstruction, final count bias, word-cursor advance, modular word gate, tail entry/step, both tail dispatches, advanced pointer publication, four stack writeback cases and the domain-qualified word-gate interpretation. The proof composition is explicit; no single monolithic whole-caller theorem or native continuation is claimed. Original inputs remain unchanged. [CF3-CF5]

For P decoded parent bytes, C selected chunks, E event/fixture bytes, Q read-byte queries and V selected visits, extraction/audit take O(P+CE+Q log(E+Q)+32V) time and O(parent receipts+largest interval+selected frames) space. Proof-DAG construction/storage and solver search are additional; each query has a 30 s timeout. Count decoding and each loop step take O(1) time/space. The two retained copy steps process exactly 2 B; the full record-message/digest complexity is inherited from CF2. [CF3-CF5]

## Bounded continuation and quality gates

| Impact | Continuation or pattern | Discriminating evidence |
| --- | --- | --- |
| High | Join the original count/data pointer and context producer epoch | Trace the inherited pointer cell and constructor writes through actual object lifetime; source-layout correspondence alone does not establish that epoch. |
| High | Recover admission and terminal-word handling for other counts | Trace the earlier count-dependent branches with original state; distinguish the proved modular gate from caller admission and retain index-wrap domains. |
| High | Join the structured payload to its transport/kext transaction | Match buffer, selector/message, port/right ownership and transaction context. Current internal dispatch slots supply no Mach identity. |
| Medium | Explain the preserved scratch-encoder suffix and cache/W19 producers | Join original generator state and byte-reader consumers in the same epoch; the partial copy retains two prior encoded bytes in this path. |
| Low | Consolidate source labels for count/state/pointer roles | Retain actual instruction ranges, phase/key assumptions and unknown native identities. |

**QG1** passes: factual source/interface analysis. **QG2** passes: CF-A1-CF-A6 record dependencies and falsification probes. **QG3** passes for count/data origins, saved-byte continuity and copy bounds; the full interface goal remains active. **QG4** passes: byte extents, u32/u64 arithmetic, wrap/comparison domains, exact counts and complexity are stated. **QG5** passes: local unsigned arithmetic, actual count 6, N>=4 interpretation, read epochs and native admission are distinguished. **QG6** passes after primary-byte comparison, independent writeback replay, fresh proofs, original-input custody and publication verification. **QG7** passes: continuation includes constructor epoch, count admission, state/cache producers and transport identity. No new target interval, root byte, API-return premise, native API/IPC event, Mach port/right/disposition, message emission site, hardware PAC event or IDB mutation is introduced.
