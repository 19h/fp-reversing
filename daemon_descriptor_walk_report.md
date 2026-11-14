# Bounded encoded-node traversal and conditional descriptor entry

The recovered phase of the source consumer at `0x100a5eac4..0x100a5eb2c` performs a bounded pointer walk with XOR accumulation. Its decoded u64 becomes X14 and, on the continuation edge, supplies the next node's address. The earlier configuration name `counter64` identifies a decoded input word; this consumer establishes an address role for that word. Its complete native type, ownership and validity remain unknown. [DW1-DW5; DW-A1-DW-A5]

In the recovered phase, the cursor starts at 1 and the limit is 19. Each readable-node step increments the cursor, decodes the next address, and exits when that address is zero or the incremented cursor exceeds 19. The maximum is 19 node visits, including the initial node, and 18 back edges, provided the reads and source phase complete. No actual linked-node chain is instantiated or executed in this increment. [DW1, DW3-DW5; DW-A3-DW-A5]

```text
152 inherited success states
  + separate SP+2b0 / 8 B root premise -> 1010b7cc0
  -> four original prefixes, 383 instructions each
  -> STOP before undefined [outer SP+9e0] / 4 B
     all 16 descriptor bytes remain undefined

abstract source contract for a readable node at b:
  word / u32 at b; encoded q / u64 at b+8
  next = u64(q-b)
  acc ^= u32(word-low32(q))
  cursor = u32(cursor+1)
       |
       +-- next == 0 OR cursor > 19 -> 100bd9408
       |
       +-- otherwise -> 100a5eac4, then read next through X14

The last two edges are source proofs, not modeled execution past the stop.
```

| Evidence | Primary artifact and scope |
| --- | --- |
| DW1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original consumer words and authenticated table slots are retained. |
| DW2 | [Constructor-buffer checks](triage_evidence/daemon_constructor_buffer_checks.json.zst), [descriptor report](daemon_constructor_descriptor_report.md) and [caller report](daemon_feedback_callers_report.md) qualify the 152 inherited states, source-compatible root producer and encoded local-node pointer. |
| DW3 | [Extractor](triage_evidence/recover_daemon_descriptor_walk.py) and [checks](triage_evidence/daemon_descriptor_walk_checks.json.zst): one additional root premise, four original prefixes and all 152 member-specific terminal exports. |
| DW4 | [Independent replayer/auditor](triage_evidence/replay_daemon_descriptor_walk.py) and [receipt](triage_evidence/daemon_descriptor_walk_replay.json.zst): full GP/Q/NZCV/byte/pointer replay, all-parent admission, fault controls and six source obligations. |
| DW5 | [Publication verifier](triage_evidence/verify_daemon_descriptor_walk_publication.py): fresh replay/admission/proof reconstruction, original-word checks, exact manifest delta, input preservation and decoded path hygiene. |

## Conditional prefix and current phase

The separate entry supplies `0x1010b7cc0` at outer SP+0x2b0, matching the previously verified original initializer producer. The actual initializer/current-caller epoch is not joined. This is 8 B of additional model definition per parent: inherited 96 B plus 8 B gives 104 B of conditional root fields. No descriptor byte or payload byte is supplied. [DW2-DW5; DW-A1-DW-A2]

Four classes, sizes 68/68/8/8, cover all 152 success exports through exact incoming byte/register demands and owner/configuration equality. Each prefix has 383 visits, 70 reads, 32 writes, four logical authenticated edges and two internal calls. Execution stops at `0x100a5eac8` before the undefined 4 B read at `0x6800060ae0=outer_SP+0x9e0`. No descriptor input, next-node address or outgoing consumer edge is executed. S/64 B, U/48 B, F/57 B and J/552 B retain their inherited bytes and unknown-byte masks. [DW3-DW5; DW-A2-DW-A4]

| Consumer phase input | Value at every representative stop |
| --- | --- |
| Node address X14 | `0x6800060ae0` |
| Cursor W8 | 1 |
| X0 and W16 limit | 19 |
| Accumulator W10 | `0x6773dea5` |
| Key X1 | `0xd839aac13e909dd4` |
| X2 | `u64(2*X1)=0xb07355827d213ba8` |
| X3 | `u64(-X1)=0x27c6553ec16f622c` |
| Dispatch W4 / W13 / X20 | `0x31` / `0x77dd` / `0x101039ef0` |

These phase values arise from the original prefix. Pointer origins start at actual original authenticated-fixup reads; all sixteen authenticated edges across four prefixes have exact origin chains. No inherited pointer tag or equal-number origin guess is needed for these prefixes. Native PAC and concurrency remain unknown. [DW3-DW5; DW-A3-DW-A4]

## Node format and canonical step

| Node field | Source read | Decoded role |
| --- | --- | --- |
| b+0 / u32 | `0x100a5eac8` | Combined with low32(q); contributes `u32(word-low32(q))` to the XOR accumulator |
| b+4..b+7 / 4 B | No read in this body | Unused by this body; complete node layout remains unknown |
| b+8 / u64 | `0x100a5eacc` | Address-biased encoding q; next address=`u64(q-b)` |

The body reads 12 B through two loads inside a 16 B address span. Null next is encoded by q=b, rather than requiring a zero raw qword. The earlier aligned initializer equation q=`u64(b+decoded_input_word)` therefore gives this decoded input word the next-address role when consumed by this phase. The initializer writes the same two widths and leaves the same four intervening bytes without a retained writer. This is source-format agreement; native epoch continuity remains unknown. [DW1-DW5; DW-A1-DW-A5]

After subtraction at `0x100a5eaec`, the arithmetic at `0x100a5eaf0..0x100a5eafc` preserves next. For all u64 a and next, `(next XOR a)-a+((2*a) AND (2*next))=next` modulo 2^64. The observed X1/X2/X3 satisfy a/2a/-a. Thus X14 carries the decoded next address across the dispatch and becomes the base of the next node read on the back edge. The loop also preserves the key triple, limit and dispatch registers and performs no source stores. [DW1, DW4-DW5; DW-A3-DW-A4]

## Predicate, outgoing edges and bound

For incremented u32 cursor v, the source forms A=`u64(X0-zero_extend64(v))` and B=`u32(W16-v)`. The sign of `u64(-(A XOR zero_extend64(B))) OR A` detects `A != zero_extend64(B)`. CCMP/CSET combines that sign with the null-next condition. With X0=zero_extend64(W16)=N, the mixed-width inequality is exactly unsigned(v)>N. The complete source contract is therefore:

```text
v    = u32(cursor+1)
next = u64(q-b)
acc' = acc XOR u32(word-low32(q))
exit = (next == 0) OR unsigned(v) > N
```

| Condition in this phase | Table index / original slot | Original target / logical IA |
| --- | --- | --- |
| Nonzero next and v<=19 | `0x77dd` / `0x101075dd8` | `0x100a5eac4` / `0x0957`, IA, address diversity 0 |
| Zero next or v>19 | `0x77ec` / `0x101075e50` | `0x100bd9408` / `0x0957`, IA, address diversity 0 |

`LDR X5,[X20,W15,SXTW #3]` at `0x100a5eb20` loads the selected original authenticated slot; source `0x100a5eb2c` is `BRAA X5,X17`. W15 is reset to 1 before the branch. Independent pointer-format-12 checks establish target/diversity compatibility for both slots. No hardware authentication executes. [DW1, DW4-DW5]

Starting cursor=1, visit j produces cursor=1+j. Visits j=1..18 produce 2..19 and may follow a nonzero next address; visit j=19 produces 20 and forces the exit. There is no u32 wrap in this range. Earlier null-next values shorten the walk. A cycle is subject to the same visit cap; this body does not establish an identity-based cycle detector or any native success/error interpretation of the exit. [DW1, DW4-DW5; DW-A3-DW-A5]

For the separately recovered initializer node, the decoded word contribution is `0xb5caf0c6`; the first compatible step would change accumulator `0x6773dea5` to `0xd2b92e63`. Other nodes' contributions remain symbolic. An XOR accumulator is established; conventional checksum, authentication or validation identity remains unknown. The model does not execute even that first descriptor read. [DW2, DW4-DW5; DW-A2-DW-A5]

## Verification, terminology and remaining interfaces

Full independent replay checks 49,152 GP/SP values, 49,152 Q values, 1,536 NZCV frames, 1,480 read bytes, 1,008 write bytes and sixteen logical authenticated edges over 1,532 original visits. All 152 parent admissions check 38,000 incoming byte demands and 1,368 incoming register demands. Missing/changed roots, changed SP and changed owners are rejected; unused Q0 changes survive the declared projection. Each terminal export preserves its own unused input state. [DW3-DW5]

Six nonvacuous source obligations cover cursor increment, node delta/affine mix, signed-OR inequality, CCMP/CSET, the mixed-width unsigned bound and both original dispatches. Their composition yields the canonical step above. The composition is a mathematical source contract, separate from prefix execution: abstract word/q inputs are not installed into the actual terminal states. All queries first check satisfiable premises and have a 30 s timeout. [DW4-DW5]

The earlier `counter64` configuration label remains in frozen artifacts for reproducibility. At this consumer, the value q-b is used as the next memory-read base. The report therefore uses **decoded input word** for producer algebra and **next address** for this consumer's established role. Agreement with separate initializer profiles qualifies a candidate source interface; it does not establish a live pointer, a native list allocation or the current initializer epoch. [DW2-DW5; DW-A2-DW-A5]

Time is O(visits*frame state + parents*demands + query DAG), excluding solver search complexity and publication input I/O. Storage is O(receipts + parent maps + largest interval + query DAG). Cursor/node-visit counts are dimensionless integers; addresses, offsets, field widths and stack/object extents are bytes. Arithmetic wraps at u32/u64 widths. Addresses are original-image/model virtual addresses; no native ASLR mapping is inferred. Receipts use `zstd --ultra -22 -q -T1` with decoded round-trip checks. No target API, allocation/free, filesystem operation, IPC, hardware PAC or IDB mutation executes. Retained evidence suffices; IDA is not accessed. [DW1-DW5]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| DW-A1: Exact pinned image, fixups and inherited receipts apply | Prefix, node operations and logical edges | Check all source words, source/parent/dependency hashes, original read bytes and independently decoded pointer fields. |
| DW-A2: The additional 8 B root is an explicitly separate premise | All post-frontier model results | Verify initializer compatibility and exact root demand; reject changed/missing bytes; retain the unjoined epoch and all 16 undefined descriptor bytes. |
| DW-A3: Admitted prefix phase and compatible readable-node steps apply | Canonical traversal and 19-visit bound | Check all 152 dependencies and phase values; prove full-width step equations; verify limit/key/dispatch preservation and no stores; preserve original per-parent unknowns. |
| DW-A4: Sequential source semantics and logical authentication apply | Replay, accumulator and target/modifier results | Check complete frames, byte effects and exact authenticated-pointer origins; native PAC, mutation ordering and scheduling remain unknown. |
| DW-A5: Pointer-use evidence establishes a local role, not complete native identity | Terminology and cross-layer interpretation | Require actual node provenance, readable extents, lifetime, epoch and transport joins before assigning native types or daemon-kext identities. |

| Impact | Bounded next evidence | Present limit |
| --- | --- | --- |
| High | Trace the initializer input word to an actual chain head | The consumer uses it as an address; native type, ownership and current epoch remain unknown. |
| High | Recover the exit block's use of accumulator/cursor/next | Exit target is source-resolved; full helper result and validation semantics remain unknown. |
| High | Establish actual node layouts, lifetimes and mutation ordering | This body reads two fields in a 16 B span; it neither allocates nodes nor writes their contents. |
| High | Join descriptor/U/S/F identities to actual Mach/IOKit buffers | No new Mach-port name, transferred right, external emission or native daemon-kext transaction pairing is established. |
| Medium | Inventory other phases and limits of this consumer | The 19-visit result is qualified by this recovered phase; a global limit for all callers remains unknown. |

**QG1**: factual source/ABI analysis. **QG2**: DW-A1-DW-A5 state dependencies and falsification probes. **QG3**: this traversal/prefix increment is covered; the full interface goal remains active. **QG4**: widths, byte units, dimensionless counts, exact bounds and complexity are explicit. **QG5**: configuration labels, pointer use, abstract proof inputs and concrete unknowns are separated. **QG6**: complete fresh replay, admissions, source proofs, fixups and publication checks qualify primary evidence. **QG7**: impact-labeled adjacent work and unknown interfaces are explicit.
