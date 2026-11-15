# fairplayd: five-word state to the AES middle-block record format

The five-word serializer, established AES wrapper and twenty-byte formatter compose into one conditional 160-bit permutation. Decode each source word with XOR `0xf4f92df7`, serialize the five decoded words big-endian, encrypt bytes 2 through 17 with the recovered AES-128 key, preserve the two bytes at each end, then XOR every output byte with `0x98`. Four universal source/composition queries establish the word, byte, address and continuation equations. The state/message origin, native caller epoch and daemon-kext transaction identity remain unknown. [SS1-SS6; SS-A1-SS-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| SS1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`: serializer, state writers, formatter and continuation instructions. |
| SS2 | [Serialized-input lineage](daemon_record_input_origin_report.md), [complete block cipher](daemon_core_cipher_report.md), [record extension](daemon_record_extension_report.md), [record banks](daemon_record_banks_report.md), and their pinned receipts. Prior complete caller/core admissions and post-formatter preservation remain dependencies; their full original traces are not rerun here. |
| SS3 | [Extractor](triage_evidence/recover_daemon_state_splice.py), [checks](triage_evidence/daemon_state_splice_checks.json.zst), [compact format model](triage_evidence/daemon_state_splice_kernel.py): exact encoded/decoded words, read epochs, state reuse, source slices and the complete twenty-byte format. |
| SS4 | [Auditor](triage_evidence/audit_daemon_state_splice.py), [audit](triage_evidence/daemon_state_splice_audit.json.zst): fresh scalar replay, four universal obligations, byte-custody checks, source-executed format controls, host AES roundtrips and alias controls. |
| SS5 | [Publication verifier](triage_evidence/verify_daemon_state_splice_publication.py): fresh extraction/audit, canonical query comparison/re-solving, exact manifest delta, original-input preservation and decoded path hygiene. |
| SS6 | [FIPS 197-upd1](https://doi.org/10.6028/NIST.FIPS.197-upd1) defines the AES primitive already identified in SS2. The [encoded SHA-1 component](daemon_sha1_core_report.md) supplies representation context; representation compatibility does not identify this state's message. |

Decoded checks SHA-256: `850a325d4f00433f9dc33bafb04344c95e2887b09e048f9c90aaa1adf900b066`. Decoded audit SHA-256: `96bcc09acbe63d071a6363a9cf6e666b6826710febeba1ac68dde8cb4d736161`. Parent source/cipher/lineage receipt hashes are sealed in SS3. [SS3-SS5]

## Exact state and format contract

Let W[0..4] be the five encoded u32 values at their serializer read epochs. Let Q[j]=W[j] XOR `0xf4f92df7`, and let P be their twenty-byte big-endian concatenation. K=`db55ebcef63f382c0cc860693c6fe140`. Then:

```text
P = BE32(Q[0]) || BE32(Q[1]) || BE32(Q[2]) || BE32(Q[3]) || BE32(Q[4])
O = (P[0:2] || AES128_encrypt_K(P[2:18]) || P[18:20]) XOR 98 repeated20
```

The source serializer first writes S=P XOR `98` repeated20. The recovered wrapper receives S[2:18] and computes `AES128_K(S[2:18] XOR 98 repeated16) XOR 98 repeated16`. Its input XOR therefore cancels the serializer's byte encoding. The formatter's twenty source stores implement the stated splice. [SS1-SS4; SS-A1-SS-A4]

```text
five encoded u32 words -- XOR f4f92df7 -- BE20 --> P[20]
                                                 |
                +-- bytes 0..1 ------------------+
                +-- bytes 2..17 -- AES-128(K) ----+--> concatenate --> XOR98 --> O
                +-- bytes 18..19 ----------------+
```

| Output window before byte XOR | Exact decoded-state source | Extent |
| --- | --- | --- |
| Prefix | BE16(Q[0] >> 16) | 2 B |
| AES plaintext | BE16(Q[0] AND `ffff`) || BE32(Q[1]) || BE32(Q[2]) || BE32(Q[3]) || BE16(Q[4] >> 16) | 16 B |
| Suffix | BE16(Q[4] AND `ffff`) | 2 B |

The AES boundary crosses the first and last word halves. It does not coincide with an integer number of the five source words. The conditional 160-bit map is bijective: undo the byte XOR, decrypt the middle block, preserve the four edge bytes, parse five big-endian words and undo the word XOR. This establishes a component-format inverse under the same premises, without native decoder/caller admission or a protocol-mode claim. [SS2-SS4; SS-A1-SS-A5]

The universal composition treats the fixed-key encryption as an uninterpreted 128-bit function while lifting the actual serializer/formatter instructions. It proves XOR cancellation, ordering and source/destination equations for arbitrary five-u32 inputs; SS2 separately establishes that function as the recovered AES-128 block primitive. This avoids replacing the source formatter with a handwritten splice as the proof premise. [SS3-SS5]

## Word epochs and retained bytes

| j | Encoded W[j] | Decoded Q[j] | Latest writer PC | Writer visit | Serializer read visit |
| --- | --- | --- | --- | --- | --- |
| 0 | `547087f7` | `a089aa00` | `0x100a14bd4` | 345225 | 345582 |
| 1 | `e159766a` | `15a05b9d` | `0x100a14bd8` | 345226 | 345731 |
| 2 | `72e940ea` | `86106d1d` | `0x100a14f04` | 345429 | 345880 |
| 3 | `a6874009` | `527e6dfe` | `0x100a14f08` | 345430 | 346029 |
| 4 | `90a0709e` | `64595d69` | `0x100abc50c` | 345018 | 346178 |

These are actual retained last-writer/read links, not values recovered from the later state-window snapshot. Source `0x100a66654` subsequently overwrites all twenty state-window bytes after the fifth serializer read and before the helper call. The new audit checks all 40 word-origin bytes and 40 reuse events across the two contexts. It replays the selected writer stores and serializer slices; upstream arithmetic, compression and message formation remain unestablished here. [SS2-SS4; SS-A1-SS-A3,SS-A5]

| Stage | Retained hexadecimal bytes |
| --- | --- |
| Decoded P, 20 B | `a089aa0015a05b9d86106d1d527e6dfe64595d69` |
| AES plaintext, 16 B | `aa0015a05b9d86106d1d527e6dfe6459` |
| AES ciphertext before output byte XOR, 16 B | `f5708b496c911676a5e95e5c4af61855` |
| Serialized S, 20 B | `381132988d38c3051e88f585cae6f566fcc1c5f1` |
| Formatter O, 20 B | `38116de813d1f4098eee3d71c6c4d26e80cdc5f1` |

All 608 retained frontier exports contain this same O. Their three later bank fields remain undefined, and the later bank-XOR output remains a conditional prediction. No new execution crosses that frontier. [SS2-SS4; SS-A2-SS-A3,SS-A6]

## Source interfaces, control and ownership boundary

| Touch point | Established role |
| --- | --- |
| F=`0x680005fb60`; F+`0x414` through F+`0x427` | Five encoded state words at their read epochs |
| `0x100be0454` | Selected word load; four original stores serialize its bytes in execution order 0,2,1,3 |
| F+`0x1cc`=`0x680005fd2c` | Twenty-byte S buffer |
| F+`0x1bc`=`0x680005fd1c` | Sixteen-byte transformed T buffer |
| `0x100c1ce88` -> `0x100427b0c` | Retained outer-to-wrapper call; original modifier `0x5278` |
| `0x100427da4` -> `0x100411480` | Retained wrapper-to-descriptor call; original modifier `0x5431` |
| `0x100a5e2d8` -> `0x100aaa370` | Latest writer -> reader of the saved eight-byte output pointer at F+`0x90` |
| `0x100aaa324` through `0x100aaa3e0` | Twenty-byte formatter and outgoing logical branch |
| O=`0x680006c5b0`=Kframe+`0xc4b0` | Later record-extension input; Kframe=`0x6800060100` |

The formatter stores output offsets 19 down to 0. Its source loads use the fixed two/sixteen/two mapping, and the saved pointer's sixteen byte-origin links across both contexts resolve to the current `0x100a5e2d8` store. A stale reuse of that pointer cell is not substituted. [SS1-SS4]

For arbitrary u32 phase p, the source dispatch read has address `table + 8*sign_extend64(p)`. It returns the symbolic target, sets W8=`0x8b3dc651`, W21=`p XOR 0x221b` and X17=`0xc6fe`. In the retained case p=`0x7aa5`, the read is `0x101077418` and the outgoing target is `0x100a653cc`. These are internal source control equations. No Mach endpoint, right, port emission, IOKit selector or new native transaction correspondence is established. Hardware pointer authentication remains unexecuted. [SS1-SS4; SS-A1-SS-A2,SS-A6]

The snapshot splice requires source/destination preservation and nonaliasing. The retained buffers are disjoint; the fresh original-source alias controls reproduce the earlier failure when output overlaps T and changes two later header reads. The universal load-value proof is not a general alias-safe-copy theorem. [SS2-SS4; SS-A2-SS-A3]

## Validation, assumptions and continuation

Fresh replay checks 468 source visits in 24 slices, 15744 GP/SP values, 492 NZCV frames, 54 reads, 92 writes and two logical edges. Byte-custody checks cover 40 source word bytes, 40 later state-byte stores and sixteen saved-pointer byte origins. The four solver obligations are nonvacuous UNSAT queries using QF_UFBV, with 30 s limits. [SS3-SS5]

The 196 complete format controls execute the original five serializer slices and formatter with the independently established AES wrapper. They check 980 serialized source words and 3920 formatter output bytes. Independently assembled host OpenSSL results agree, and all 196 middle blocks decrypt back to their original plaintexts. The 160 single-bit controls comprise 32 edge bits, each changing exactly its corresponding output edge bit while preserving the encrypted middle, and 128 middle bits, each preserving both edges while changing the encrypted middle. These finite controls supplement the universal composition; they do not generalize native reachability. [SS3-SS5]

The word XOR/endian representation agrees with the separately recovered SHA-1 family. Establishing that these particular words are a digest of a particular message still requires their initialization, message assembly, padding, compression and caller lineage. This report supplies the exact downstream state-format function and its source epochs. [SS2-SS4,SS6; SS-A4-SS-A6]

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| SS-A1: Pinned original source, parent lift and source-slice semantics apply | Word/byte/address/control identities | Rehash dependencies, replay selected frames and re-solve all source obligations; compare the parent ISA lift with another implementation. |
| SS-A2: Retained contexts, placements and fixed AES contract apply | Conditional 160-bit format and its inverse | Recover authentic controller/caller epochs, the five-iteration path and valid storage beyond the retained cases; all-word coverage does not exhaust native environments. |
| SS-A3: Read epochs, saved-pointer custody and buffer preservation/nonaliasing apply | Snapshot composition and frontier input | Check latest-writer byte links and state reuse ordering; rerun disjoint/overlap source controls and obtain native object-lifetime evidence. |
| SS-A4: Pinned AES theorem discharges the fixed-key cipher cut | Universal format simplification and bijection | Inspect its full finite terminal/decoder certificates, source queries and independent block results; this increment freshly proves surrounding source composition rather than rerunning the entire AES instruction corpus. |
| SS-A5: Five-word encoding is distinguished from message/digest identity | Decoded state interpretation | Follow the five actual producer PCs upstream through initialization, input assembly, padding and compression before assigning a particular digest/message. |
| SS-A6: Retained component/format evidence is distinguished from native transport | Missing-bank boundary and no new daemon-kext join | Establish reaching definitions for Kframe+`0x390`/`0x398`/`0x3a0`, authentic callers and matched native port/right/IOKit histories. Do not import setup values across an unproved frame epoch. |

Reproduction in the established Python/Z3/OpenSSL environment runs `recover_daemon_state_splice.py`, then `audit_daemon_state_splice.py`; after manifest refresh run `verify_daemon_state_splice_publication.py`. The compact format uses O(20 + one AES block) work/storage; source replay adds O(32*visits) checks, vector source execution is linear in the selected slices and proof DAG construction is linear in expression nodes. Solver search is additional. Nontrivial JSON uses `zstd --ultra -22 -q -T1` with decoded hashes and roundtrip checks. No new target interval, memory root, native target/API/IPC, hardware PAC or IDB operation occurs. [SS3-SS5]

| Impact | Bounded next investigation | Required evidence |
| --- | --- | --- |
| High | Establish upstream state/message identity | Actual reaching definitions for the five producer PCs, initialization, message bytes, padding and compression/caller epochs. |
| High | Continue the record input into its consumer | Authentic missing bank-field definitions and successful post-frontier source/native custody. |
| High | Join private format with daemon-kext traffic | Actual object consumers and matched Mach-right/IOKit transaction history. |
| Medium | Use the exact partial-block layout as a comparison fingerprint | Independently establish related helper equations; matching constants or state size alone does not prove an interface join. |

**QG1**: Factual technical scope. **QG2**: SS-A1 through SS-A6 record assumptions and falsification probes. **QG3**: Complete state/format composition, word epochs, source and destination interfaces, continuation and frontier limits are covered; the full goal remains active. **QG4**: u32/u64 arithmetic, big-endian word order, 20/16/2 B windows, 160/128/32-bit boundaries, counts and complexity are explicit. **QG5**: Word read versus overwritten state epochs, fixed component versus native environment, arbitrary cipher cut versus pinned AES identity, snapshot versus aliased stores and retained versus post-frontier values are distinguished. **QG6**: Original instructions/effects, pinned full cipher/lineage evidence, fresh replay, source obligations and host roundtrips provide provenance. **QG7**: Impact-labelled continuation is bounded above. All gates pass for this increment; upstream message identity, native caller admission and daemon-kext pairing remain unknown.
