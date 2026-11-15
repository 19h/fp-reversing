# fairplayd: serialized state, middle-block transform and twenty-byte splice

Current retained-message result: [the record-digest report](daemon_record_digest_report.md) establishes the exact 67-byte SHA-1 message and its downstream format in both retained contexts. Earlier message-unknown statements below describe this report's original evidence stage; native admission and the inherited body's upstream semantic identity remain unknown.

Current result: [the complete state-format composition](daemon_state_splice_report.md) resolves the middle AES transform and its serializer/formatter contract for the retained contexts. Earlier transform-unknown statements below describe this report's original evidence stage; upstream message and native transaction identity remain open.

The twenty-byte input at the record-extension frontier has an exact retained source lineage: a five-word serializer produces S[20], a descriptor-driven table transform consumes S[2:18] and produces T[16], and a formatter writes `S[0:2] || T[0:16] || S[18:20]`. The formatter's twenty stores survive unchanged to the missing-bank frontier. Both retained normal execution classes agree. The transform algorithm, source message, native caller epoch and daemon-kext transaction identity remain unknown. [RI1-RI6; RI-A1-RI-A6]

The serializer's mask is algebraically identical to big-endian serialization of words decoded with XOR `0xf4f92df7`, followed by byte XOR `0x98`. This matches the representation recovered for the earlier SHA-1 family. This increment establishes representation compatibility; it does not establish that these five words are a SHA-1 digest of a particular message. The middle transform also changes the observed sixteen bytes, so the record input is not a direct copy of S. [RI1-RI5; RI-A4-RI-A5]

| Evidence | Primary provenance and scope |
| --- | --- |
| RI1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; all selected instruction words and local source spans are checked against this image. |
| RI2 | [Record extension](daemon_record_extension_report.md) and [record banks](daemon_record_banks_report.md); pinned complete parent receipts and 608 conditional frontier exports. The prior full admission corpus is not rerun. |
| RI3 | [Extractor](triage_evidence/recover_daemon_record_input_origin.py), [checks](triage_evidence/daemon_record_input_origin_checks.json.zst): two retained classes, selected source frames, ordered effects, byte writers and buffer mappings. |
| RI4 | [Auditor](triage_evidence/audit_daemon_record_input_origin.py), [audit](triage_evidence/daemon_record_input_origin_audit.json.zst): independent scalar replay, predecessor searches for byte epochs, six nonvacuous UNSAT obligations, snapshots and alias/classification controls. |
| RI5 | [Publication verifier](triage_evidence/verify_daemon_record_input_origin_publication.py): fresh extraction/audit, canonical SMT comparison, exact owned delta, original-input preservation and decoded path hygiene. |
| RI6 | [Encoded SHA-1 core](daemon_sha1_core_report.md), [earlier serializer](daemon_digest_output_report.md), [ABI](interface_abi_report.md) and [ports](mach_ports_report.md). Earlier component classifications and transport evidence keep their original scopes. |

Decoded receipt SHA-256 values: `450d52130015a8ae1e0f033db234be880051d9071b9f478cc93e9778bce7a12e` (RI3), `3fc418ed9272a785fbea01bef58a11a625b4c748dbab9d2fd3b04f8d4fb84363` (RI4).

## Source frames and data mapping

Addresses/pointers use u64 arithmetic, scalar words use u32 arithmetic, and byte stores reduce modulo 2^8. B denotes bytes. Source addresses are unslid; retained private addresses are model coordinates. Let F be the formatter frame, K the later constructor frame, S the serialized buffer and T the transformed buffer. In both retained classes:

| Coordinate | Retained value | Role |
| --- | --- | --- |
| F | `0x680005fb60` | Serializer/formatter SP |
| K | `0x6800060100` = F+0x5a0 | Later record-extension SP |
| S | F+0x1cc = `0x680005fd2c` | Twenty serialized bytes |
| T | F+0x1bc = `0x680005fd1c` | Sixteen transform output bytes |
| Output pointer cell | F+0x90 = `0x680005fbf0` | Written by `0x100a5e2d8`; read by `0x100aaa370` |
| Output | K+0xc4b0 = `0x680006c5b0` | Twenty-byte later masked-copy input |
| Serializer state window | F+0x414 through F+0x427 | Five four-byte words |

F and K are distinct source frames. Equal numeric frame offsets at other call depths do not identify the same cells. Each retained read is joined to its latest preceding overlapping byte store. The output pointer's eight bytes all come from `0x100a5e2d8` at visit 281964, rather than an older reuse of that stack cell. [RI3-RI5; RI-A1-RI-A3]

```text
five encoded u32 words
         |
         v
 serializer -> S[20]
                  +-- S[0:2] ---------------------------------+
                  +-- S[2:18] -> descriptor/table transform ---+--> formatter
                  +-- S[18:20] -------------------------------+       |
                                                                    v
                                                          K+0xc4b0, 20 B
                                                                    |
                                                                    v
                                                    retained missing-bank frontier
```

## Five-word serializer and state-word lifetime

At `0x100be044c`, the source forms a local base F+0x3cc. The load at `0x100be0454` reads the selected four-byte word with a further +0x48 displacement. The retained five iterations read F+0x414+4*j for j=0..4. Four stores per word execute in byte order 0, 2, 1, 3. Their address/value mapping is big-endian. [RI1,RI3-RI5; RI-A1-RI-A4]

For arbitrary u32 W and counter c, with the source's incoming W12=`0xd3286d1e`, define `b=u32(c+0xd3286d1e)`. Store byte k goes to `destination + zero_extend64(u32(b+k))` and equals:

```text
serialized_byte[k] = byte_BE_k(W) XOR [6c,61,b5,6f][k], k=0..3
                   = byte_BE_k(W XOR f4f92df7) XOR 98
```

The universal source proof includes modular address wrap. A contiguous four-byte or twenty-byte memory contract additionally requires the admitted nonwrapping addresses and nonaliasing needed by that use. The retained cases use consecutive S addresses and five iterations; no arbitrary-length serializer termination claim is made. [RI4-RI5; RI-A2-RI-A4]

| j | Word address | Encoded u32 W | Actual latest writer | Read visit |
| --- | --- | --- | --- | --- |
| 0 | `0x680005ff74` | `0x547087f7` | `0x100a14bd4`, visit 345225 | 345582 |
| 1 | `0x680005ff78` | `0xe159766a` | `0x100a14bd8`, visit 345226 | 345731 |
| 2 | `0x680005ff7c` | `0x72e940ea` | `0x100a14f04`, visit 345429 | 345880 |
| 3 | `0x680005ff80` | `0xa6874009` | `0x100a14f08`, visit 345430 | 346029 |
| 4 | `0x680005ff84` | `0x90a0709e` | `0x100abc50c`, visit 345018 | 346178 |

These definitions precede the serializer reads. Subsequently, `0x100a66654` overwrites the same twenty state-window bytes at visits 346297..346810, before the helper call at visit 348818. The retained overwrite is not a zero fill. A later state-window snapshot therefore does not recover the serialized words. Upstream initialization/compression/message lineage for these writers remains unknown in this increment. [RI3-RI5; RI-A1-RI-A4]

## Descriptor and call interfaces

The first call passes a record R=F+0x430. The wrapper creates descriptor D at its own SP+0x10, where wrapperSP=F-0x50. The inner helper reserves another 0x160 B; its working SP is F-0x1b0. All listed field roles come from actual selected loads/stores. They are private source interfaces, without an established public type. [RI1,RI3-RI5; RI-A1-RI-A3,RI-A5]

| Record/descriptor field | Retained value | Source custody |
| --- | --- | --- |
| R+0x00 | T | Load `0x100427c90`; store into D+0x10 at `0x100427ce4` |
| R+0x10 | S+2 | Load `0x100427c8c`; store into D+0 at `0x100427ce0` |
| R+0x18 | `0x8f94d014`, 4 B | Encoded control read `0x100427c84` |
| D+0x0c | `0x63fb8bc9`, 4 B | Produced by wrapper at `0x100427cdc`; consumed at `0x1004115b0` |
| D+0x08 | `0x8b3dc651`, 4 B | Helper suffix store `0x1000d4918` |
| R+0x08 | `0x8b3dc651`, 4 B | Wrapper loads D+8 at `0x100427da8` and stores R+8 at `0x100427dac` |

The wrapper's control encoding depends on pointer-derived arithmetic. The two encoded control values are retained for this placement; they are not promoted to placement-independent operation selectors. The result transfer theorem holds for arbitrary four-byte result values. The checked helper suffix writes the familiar encoded zero, while its complete error/result domain remains unknown. [RI1,RI3-RI5; RI-A2-RI-A5]

| Transfer | Call/return PC | Target | Logical modifier | Call SP |
| --- | --- | --- | --- | --- |
| Outer -> wrapper | `0x100c1ce88` | `0x100427b0c` | `0x5278` | F |
| Wrapper -> inner helper | `0x100427da4` | `0x100411480` | `0x5431` | F-0x50 |
| Inner helper -> wrapper | `0x1000d4950` | `0x100427da8` | RETAB, inherited logical return | F-0x50 |
| Wrapper -> outer | `0x100427dd4` | `0x100c1ce8c` | RETAB, inherited logical return | F |

The helper reads sixteen one-byte inputs at `0x10004e954`, in descending order S+17 through S+2, at visits 349166..350216. Its output loop stores sixteen bytes at `0x100085bfc`, in descending order T+15 through T, at visits 352903..353938. The retained helper/formatter slice is replayed continuously, including its table reads, intermediate writes, calls and logical returns. Table-driven data flow alone does not identify a cipher, mode, key, digest or white-box construction. Hardware pointer authentication is not executed. [RI3-RI5; RI-A1-RI-A5]

## Formatter and retained values

Original formatter `0x100aaa324..0x100aaa3e4` loads twenty source bytes, loads the saved output pointer, and writes twenty bytes at `0x100aaa374..0x100aaa3d4`. Its stores execute from output offset 19 down to 0. The universal proof assigns every source byte an independent eight-bit value and checks each load address, destination address and stored byte. [RI1,RI3-RI5; RI-A1-RI-A3]

| Output offsets | Formatter-frame source | Producer |
| --- | --- | --- |
| 0..1 | F+0x1cc..0x1cd = S+0..1 | Serializer stores `0x100be048c` / `0x100be04d8` |
| 2..17 | F+0x1bc..0x1cb = T+0..15 | Helper stores `0x100085bfc` |
| 18..19 | F+0x1de..0x1df = S+18..19 | Serializer stores `0x100be04c0` / `0x100be04e0` |

| Stage | Retained hexadecimal bytes |
| --- | --- |
| S, 20 B | `381132988d38c3051e88f585cae6f566fcc1c5f1` |
| S[2:18], 16 B | `32988d38c3051e88f585cae6f566fcc1` |
| T, 16 B | `6de813d1f4098eee3d71c6c4d26e80cd` |
| Spliced record input, 20 B | `38116de813d1f4098eee3d71c6c4d26e80cdc5f1` |

The formatter sets W8=`0x8b3dc651`, W21=`W22 XOR 0x221b`, and logical modifier X17=`0xc6fe`. At retained W22=`0x7aa5`, its table load is `0x101077418`, and its branch selects `0x100a653cc`. The proof checks these register equations independently of the byte values. This is an internal continuation, with no port transfer. [RI1,RI3-RI5; RI-A1-RI-A3,RI-A6]

There are exactly twenty parent writes overlapping the final twenty-byte input window, all from this formatter. Independent all-store snapshots match at formatter completion and at the final retained stop. All 608 previously exported normal frontier values match the same input vector; their prior admission proof remains a pinned dependency. The missing bank fields are still undefined there. The later record-bank XOR result remains a conditional prediction, without a new post-frontier execution. [RI2-RI5; RI-A1-RI-A3,RI-A6]

## Verification, assumptions and continuation

The two-class extraction retains 24 chunks and 10,808 source instruction visits. Independent replay checks 346,624 GP/SP values, 10,832 NZCV frames, 2,156 ordered reads, 332 writes, 82 logical edges, four logical PAC prologues and four conditional branches. Per-byte predecessor searches independently check 3,960 writer/read links; 5,110 incoming-or-image read bytes remain separately qualified by the pinned parent model. Three twenty-byte snapshots per class add 120 checked bytes. SIMD registers are unchanged in the extracted chunks; selected source instructions have no SIMD-register accesses. [RI3-RI5; RI-A1-RI-A3]

Six source obligations return UNSAT with satisfiable premise checks: serializer bytes/addresses, encoding equivalence, all twenty formatter byte stores, formatter read/register/dispatch values, four-byte wrapper result transfer and the helper's encoded-zero store. Two observed classification controls reject an identity middle transform and a whole-S copy. Source-executed finite controls also compare disjoint storage with overlapping formatter output: aliasing T into the output changes two late-read header bytes. Thus the general snapshot splice requires the nonalias premise; actual retained source/destination windows satisfy it. [RI4-RI5; RI-A2-RI-A5]

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| RI-A1: Pinned source image and retained parent receipt identity | All numeric source, frame and byte mappings | Rehash source/dependencies, recapture instruction bytes, regenerate extraction and replay; a changed image/receipt invalidates these coordinates. |
| RI-A2: Parent allocator/owner and ABI models apply to retained normal classes | Conditional helper/formatter reachability and frontier composition | Inspect the pinned prior admissions; recover authentic caller inputs and outcomes. These two classes do not exhaust arbitrary native calls or register-clobber values. |
| RI-A3: Actual read values and nonalias/preservation premises | Snapshot splice and current-frontier input lineage | Independent byte-predecessor search, all-store snapshots and disjoint/overlap source controls. Universal load-value equations alone do not prove alias-safe copying. |
| RI-A4: State encoding compatibility is distinguished from digest/message identity | Serializer interpretation | Six local source obligations qualify encoding; establish upstream initialization, message assembly, padding and compression before asserting a particular digest. |
| RI-A5: T denotes the observed table transform, with algorithm unknown | Middle replacement and private descriptor roles | Replay the full selected helper slice; recover its stages, table semantics, state and independent input vectors before assigning cipher/mode/key semantics. |
| RI-A6: Private model lineage is distinguished from native transport | No new Mach endpoint, right, emission site or daemon-kext pairing | Join the caller and consumer to authentic port/right and IOKit records. No native API, IPC, new target interval, new root byte or IDB mutation occurs here. |

Reproduction uses the established Python/Z3 environment: run `recover_daemon_record_input_origin.py`, then `audit_daemon_record_input_origin.py`; after publication refresh, run `verify_daemon_record_input_origin_publication.py`. Nontrivial JSON is stored with `zstd --ultra -22 -q -T1`, preserving decoded hashes. Extraction takes O(parent bytes + visits + effect bytes + selected frames) time/space. Independent replay adds O(32*selected visits) checks; predecessor searches add O(read bytes*log(writes per address)); source proof construction uses O(expression DAG) space. Solver search is additional, with a 30 s limit per query. [RI3-RI5]

| Impact | Bounded next investigation | Evidence needed |
| --- | --- | --- |
| High | Establish the five serialized words' message/compression lineage | Follow the actual `0x100a14bd4`, `0x100a14bd8`, `0x100a14f04`, `0x100a14f08` and `0x100abc50c` producers upstream, retaining frame epochs and input-byte provenance. |
| High | Classify the middle-sixteen-byte transform | Recover descriptor control decoding, input staging, intermediate table stages and output encoding, with independent vectors. |
| High | Continue the current bank/caller join | Establish reaching definitions for K+0x390/+0x398/+0x3a0 without importing setup values across an unproved frame epoch. |
| Medium | Establish native publication/consumer/transport correspondence | Connect the constructed object and retained `itgr` context to its actual caller/consumer and a matched daemon-kext transaction. |

**QG1**: Factual technical scope. **QG2**: RI-A1 through RI-A6 register assumptions and falsification probes. **QG3**: Serialization, middle transform inputs/outputs, descriptor and call interfaces, formatter, byte custody and transport boundary are covered for this increment; the full goal remains active. **QG4**: Byte units, integer widths, endian order, modular wrap and complexity are explicit. **QG5**: State-word reuse, actual versus predicted stores, nonalias versus overlap, encoding versus algorithm and private versus native interfaces are distinguished. **QG6**: Pinned original bytes, parent receipts, fresh independent replay, predecessor searches, snapshots and universal obligations provide primary provenance. **QG7**: Impact-labelled continuation is bounded above. All gates pass for this increment; the stated native/algorithm/message unknowns remain outside its established conclusions.

## Block-staging follow-up

The [block-staging increment](daemon_block_staging_report.md) resolves the pointer-dependent control formulas and the exact condition for wrapper/callee roundtrip. It maps both inner sixteen-byte buffers, recovers the input/output XOR masks, and records the core word-table footprint. The complete algorithm and upstream serialized-message lineage remain unknown.

## Core-lookup follow-up

The [core-lookup increment](daemon_core_lookup_report.md) extracts an executable, context-specialized sixteen-byte transform with 192 data lookups. Universal source queries establish fixed read/write cells, lookup extents and the outgoing logical branch; changed-input source-model runs match the standalone graph evaluator. The primitive identity and native daemon-kext transaction mapping remain unknown.

## Complete state-format follow-up

[The state-format report](daemon_state_splice_report.md) composes the five encoded words, serializer, recovered AES wrapper and twenty-byte formatter. Decode each word with XOR 0xf4f92df7, serialize big-endian, encrypt decoded bytes 2..17 under the recovered AES-128 key, preserve both two-byte edges, then XOR all 20 bytes with 0x98. Four source queries, fresh epoch/custody checks and 196 complete format controls qualify this conditional 160-bit permutation. Upstream message identity, native admission, the later undefined bank fields and daemon-kext pairing remain open.

## Retained record-message digest follow-up

[The record-digest report](daemon_record_digest_report.md) identifies the retained five words as SHA-1 of an exact 67-byte message: an 11-byte image prefix, a decoded 48-byte window at owner offset 77, and an eight-byte image suffix. The body uses the established record mask indexed by the original owner offset. Fresh source replay checks both compression blocks, every schedule word and round-entry state, byte epochs and downstream AES composition in both contexts. Native admission, the inherited body's upstream semantic origin, later missing bank fields and daemon-kext pairing remain open.
