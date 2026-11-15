# fairplayd: retained record-message SHA-1 and the downstream AES format

The five words consumed by the [state formatter](daemon_state_splice_report.md) are the SHA-1 digest of an exact 67-byte message in both retained contexts. The source initializes the standard five-word IV, consumes two correctly padded blocks, expands two 80-word schedules and performs two groups of 80 rounds before the established serializer/AES splice. The message is an 11-byte image prefix, a decoded 48-byte owner window and an eight-byte image suffix. This establishes the retained message-to-record computation. Native caller admission, general compression equivalence and daemon-kext transaction identity remain unknown. [RD1-RD6; RD-A1-RD-A6]

| Evidence | Primary provenance and extent |
| --- | --- |
| RD1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; actual initialization, copy/codec, decoder, schedule, rounds and state-store instructions. |
| RD2 | [Record extension](daemon_record_extension_report.md), [state format](daemon_state_splice_report.md) and their pinned checks/replay receipts. Original whole-path conditional admissions, API returns, preceding owner creation and inherited bytes remain dependencies. |
| RD3 | [Extractor](triage_evidence/recover_daemon_record_digest.py), [checks](triage_evidence/daemon_record_digest_checks.json.zst): two contexts, original source slices, exact input/storage epochs, schedules, round maps, message/body representations and final digest. |
| RD4 | [Auditor](triage_evidence/audit_daemon_record_digest.py), [audit](triage_evidence/daemon_record_digest_audit.json.zst): fresh complete selected scalar replay, independent predecessor searches, source lemmas, standard compression model, hashlib/OpenSSL and downstream AES composition. |
| RD5 | [Publication verifier](triage_evidence/verify_daemon_record_digest_publication.py): fresh extraction/audit, canonical query comparison and re-solving, exact manifest delta, original-input preservation and path hygiene. |
| RD6 | [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4), sections 5.1.1, 5.3.1 and 6.1.2, supplies the padding/IV/compression reference. The separate [SHA-1 core](daemon_sha1_core_report.md) uses different source entries; [record spans](daemon_record_spans_report.md) already establishes the same 16-byte record codec mask. Their general/native caller joins are not imported here. |

Decoded checks SHA-256: `34ac5df9c9e8652805299b78578beec6487bdf4b6cf734a8cbc4a9a3b06239f4`. Decoded audit SHA-256: `a431060e47f25bd562afe90e795d4c8d762ad767787eec3dc3bf99a1eb060244`. Parent pins and script/dependency hashes are retained in RD3-RD4. [RD3-RD5]

## Exact retained message and storage conversion

Let R denote the retained 224-byte owner at `0x66000d0000`. Let H be the following sixteen mask bytes, indexed by the original owner offset modulo 16:

```text
H = d98c9317498b221182b3198570dd904f
B[j] = R[77+j] XOR H[(77+j) AND 15],  0 <= j < 48
M = ASCII("w4H4fsHDF23") || B || ASCII("KyrG0zzZ")
D = SHA1(M)
O = (D[0:2] || AES128_K(D[2:18]) || D[18:20]) XOR 98 repeated20
K = db55ebcef63f382c0cc860693c6fe140
```

The owner bounds hold: `77 B + 48 B = 125 B <= 224 B`. Its 48 input bytes occur in the interval's inherited defined-byte fixtures, with provenance `byte_equivalent_preceding_source_state`; none has a writer in this interval before its codec read. This is an inherited source-state premise, not a new byte definition or native acquisition. The input window's upstream semantic identity remains unknown. [RD2-RD4; RD-A2-RD-A3]

| Message offsets / B, half-open | Length | Actual origin / operation | Retained decoded value |
| --- | --- | --- | --- |
| [0,11) | 11 B | Image `0x100f3c930` through `0x100f3c93a`; copied encoded bytes, decoded with XOR `0x98` | ASCII `w4H4fsHDF23` |
| [11,59) | 48 B | Owner R+[77,125), decoded with H using owner-relative offsets | Hexadecimal value below |
| [59,67) | 8 B | Image `0x100fd59e0` through `0x100fd59e7`; copied encoded bytes, decoded with XOR `0x98` | ASCII `KyrG0zzZ` |

```text
R[77:125], stored:
ec4de4a92fdbbbd180b42ccfa7c697e9d12130a1a07a4115944d71b4bfdf33c19fd154c3208e4bae8ba127b3da08c044

B, decoded:
31ddab70a348ac980b963d4d14df12990cb17f782ce9565c1f6f60360cc6b6b142411b1aac1d5ce70083363169114534

M, 67 B:
773448346673484446323331ddab70a348ac980b963d4d14df12990cb17f782ce9565c1f6f60360cc6b6b142411b1aac1d5ce700833631691145344b797247307a7a5a

D, 20 B:
a089aa0015a05b9d86106d1d527e6dfe64595d69

O, 20 B:
38116de813d1f4098eee3d71c6c4d26e80cdc5f1
```

The binary body begins with byte `0x31`; that byte is not part of the eleven-byte ASCII prefix. The suffix crosses the compression-block boundary: its first five bytes end the first block and its last three bytes begin the second. The source buffers hold the message bytes XOR `0x98`; hashing those stored bytes directly produces a different digest. [RD3-RD4]

```text
inherited owner R[77:125] -- record-mask decode --> B[48]
image prefix[11] -------------------+               |
                                   +--> M[67] <----+
image suffix[8] -------------------+       |
                                          v
                            standard IV / two SHA-1 blocks
                                          |
                                          v
                         D[20] -> partial-block AES -> O[20]
                                          |
                               retained record-input frontier
```

## Source byte codec and read epochs

The body-copy block reads one owner byte and three fixed-bank bytes. With nibble n, original source bias b, and effective bank slices A/B/C, its stored byte is the low eight bits of `input XOR A[n] XOR B[n] XOR C[n] XOR (n OR (n<<5)) XOR b`. The retained bias is `0x6e`. XOR `0x98` converts that stored byte to the logical message byte, producing H. The auditor proves the local byte equation and all five load addresses plus the destination address for arbitrary input bytes, nibble input, bias, pointers and u32 output index. All sixteen fixed-bank rows and all 48 actual codec visits are checked per context. [RD1,RD3-RD4; RD-A1-RD-A3]

| Effective fixed-bank start | Sixteen original bytes |
| --- | --- |
| `0x100e36310` | `8ba768f096f2cc94d5669070942ce0b3` |
| `0x100f2f6b3` | `aa97fe407f16f747f6bf1d615968f234` |
| `0x100ed2441` | `0e6bb132d23c29d35fb52809c7c2bad1` |

The effective B/C starts include the source's +3/+1 displacements. The nibble sequence is 13,14,15,0 through 12, repeated three times. Thus the common mask is indexed by owner byte 77 onwards, rather than restarting at mask index zero for this 48-byte message segment. Matching the already established record-reader mask supports a shared representation; actual source reads establish this particular owner's use. It does not identify an external wire schema. [RD3-RD4,RD6]

| Source touch point | Established retained role |
| --- | --- |
| `0x1004904bc`; `0x10031cf48` / `0x10031cf5c` | Initialize five state words to the encoded standard SHA-1 IV |
| `0x100b55af8` -> `0x100b55b04` | Direct image-byte copy for the prefix and the final three suffix bytes |
| `0x100a7bb64` through `0x100a7bba4` | Owner-byte and three-bank codec for the 48-byte body |
| `0x100b6dbd8` -> `0x100b6dbe4` | Copy the first five suffix bytes into the end of the first 64-byte buffer |
| `0x100c19030` | Write the second block's 52 encoded zero bytes |
| `0x100aac294` / `0x100aac2a8` / `0x100aac2b8` / `0x100aac2d0` | Read the four encoded bytes of each initial schedule word |
| `0x100aac488`; `0x100a8b73c` | Store the first sixteen and expanded sixty-four schedule words |
| `0x100abc50c`; `0x100a14bd4` / `0x100a14bd8` / `0x100a14f04` / `0x100a14f08` | Feed forward the five working words into the context state |

All 128 compression-input byte reads have actual preceding source writers in each context. The independent predecessor search checks those 256 byte links, 5,908 byte links for the complete core reads and 768 links for selected copy/codec reads. Core reads also include 5,312 incoming/image bytes and copy/codec reads include 422 incoming/image bytes; these are explicitly separate from current-interval writers. The 96 owner-body input bytes across both contexts are checked against their inherited fixtures, and all 326 original image bytes read by the message/codec slices match the original file. [RD3-RD4; RD-A1-RD-A3]

The earlier state-format report already establishes the actual last-word-write to serializer-read links and the subsequent overwrite of that state window. The current result joins those particular final words to their two-block source computation. It does not substitute a later state-window snapshot. [RD2-RD4]

## Padding, compression and register interfaces

For 67 B, the bit length is `67 B * 8 bit/B = 536 bit`. The required zero-bit count is `k=(448-(536+1)) mod 512=423 bit`; therefore `536+1+423+64=1024 bit=128 B`. In byte form, the exact source input is `M || 80 || zero[52] || BE64(536)`. The second decoded block begins `7a7a5a80` and ends `0000000000000218`. This matches the standard padding construction. [RD3-RD4,RD6]

F=`0x680005fb60`; the 100-byte context C=F+`0x3cc`=`0x680005ff2c`. Encoded block bytes occupy C+[0,64); the five encoded state words occupy C+`0x48` through C+`0x5b`. The source stores digest extent 20 at C+`0x5c`. These are the retained local placements, not a native caller-wide type. [RD1-RD4; RD-A2]

| Compression block | Original visit interval, half-open | Initial decoded five-word state | Final decoded five-word state |
| --- | --- | --- | --- |
| 0 | [307536,325851) | `67452301 efcdab89 98badcfe 10325476 c3d2e1f0` | `3e4a14b8 dbbe734b 83c7c846 2ad4a544 8b0d89d1` |
| 1 | [327124,345439) | `3e4a14b8 dbbe734b 83c7c846 2ad4a544 8b0d89d1` | `a089aa00 15a05b9d 86106d1d 527e6dfe 64595d69` |

Both retained classes have these same visits and values. Each core interval contains 18,315 source visits. The fresh comparison checks every schedule word and every round-entry state, plus the final working state before feed-forward. All 1,024 expanded-schedule input reads and 320 round input reads use the required source addresses and values. Every such byte has a writer in the same compression interval before its read; no future state is used to fill the schedule. [RD3-RD4]

| Rounds | Original loop entry | A | B | C | D | E |
| --- | --- | --- | --- | --- | --- | --- |
| 0..19 | `0x100a0c1ac` | W22 | W10 | W4 | W12 | W15 |
| 20..39 | `0x100aa8330` | W22 | W0 | W4 | W12 | W19 |
| 40..59 | `0x100bd9094` | W22 | W15 | W4 | W12 | W24 |
| 60..79 | `0x100a1a054` | W22 | W19 | W4 | W12 | W0 |
| Before feed-forward | `0x100abc2f8` | W22 | W10 | W4 | W12 | W0 |

Working/context words use XOR `0xf4f92df7`; schedule words use XOR `0x8b3dc651`. The finite comparisons use the actual low 32-bit values and inspect full GP/SP/NZCV frames during source replay. The new loop entries differ from the earlier generic SHA-1 source copy; none of that copy's universal round contracts is treated as a proof for these new instructions. [RD3-RD4,RD6; RD-A4]

## Verification and evidence boundaries

Fresh independent scalar replay checks 76,000 source visits in 262 slices, 2,440,384 GP/SP values, 76,262 NZCV frames, 2,846 reads, 612 writes and 668 logical authenticated edges. Four complete compression blocks cover 320 schedule words, 320 round-entry states and twenty final working words across two contexts. Their two complete message digests agree with both hashlib and host OpenSSL. Host AES composition then reproduces both retained O values. Four comparison controls per context change segment order, omit the prefix, omit the suffix or hash the wrong byte encoding; all produce distinct digests. These are model/reference controls, not additional native input admissions. [RD3-RD5]

Six nonvacuous QF_BV obligations establish two IV/extent contracts, two direct-copy contracts, the body codec equation/addresses and the expanded schedule value for arbitrary four u32 inputs under its recorded cutpoint constants. They do not constitute universal proofs of the four new round loops, message-assembly control flow or caller acceptance. Full source replay and complete per-round comparisons establish the retained cases. Original prior admissions/allocator transitions and unsliced upstream work remain pinned dependencies. Logical edge checks do not execute hardware pointer authentication. [RD2-RD5; RD-A1-RD-A6]

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| RD-A1: Pinned source/lift/parent bytes apply | Instruction identities, replay and local equations | Rehash all pins, rebuild the extraction, compare each parent slice, replay all frames and re-solve the original queries; compare the ISA lift with another implementation. |
| RD-A2: Retained API/owner/caller and defined-byte premises apply | The two complete message-to-record computations | Verify owner extent 224 B and inherited body bytes; recover authentic native allocation, caller and object-lifetime histories before generalizing reachability. |
| RD-A3: Original read epochs, image banks and nonaliasing/preservation apply | Body decode, padded blocks and downstream splice | Independently search actual writer histories, rehash/read all bank rows, compare inherited fixtures and preserve the state-format alias limitations. |
| RD-A4: Finite retained compression is distinguished from universal algorithm equivalence | Classification of these source loops and exact digest | Check all schedule/round/final states and two host implementations; prove generic new-round and handover invariants before asserting an arbitrary-input source theorem. |
| RD-A5: Common record mask is distinguished from semantic/wire identity | Representation join at owner+[77,125) | Trace the inherited 48-byte window to its preceding producers and external consumers; a common mask alone does not establish a transaction or native schema. |
| RD-A6: Native transport and the later missing-bank frontier remain separate | No new Mach-right/IOKit transaction claim | Establish Kframe+`0x390`/`0x398`/`0x3a0` reaching definitions, native caller/controller epochs and matching daemon/kext right/message/buffer histories. |

The compact retained computation uses O(67 + two SHA-1 blocks + one AES block) work and O(128 + hash/AES workspace) storage. Extraction and byte-custody scanning are linear in parent bytes/visits/effects plus selected frames. Independent predecessor searches add O(read bytes * log(write history)); replay adds O(32*selected visits). Proof DAG construction is linear in expression nodes; solver search is additional, with 30 s limits. Reproduction runs the extractor, auditor, manifest refresh and publication verifier in that order. Nontrivial JSON uses `zstd --ultra -22 -q -T1` with decoded hashes and exact roundtrips. [RD3-RD5]

| Impact | Bounded next investigation | Required evidence |
| --- | --- | --- |
| High | Identify the 48-byte owner's upstream semantic content | Actual prior writer/copy lineage into R+[77,125), including allocation and record epochs. |
| High | Continue O through the later record consumer | Authentic missing-bank reaching definitions and post-frontier byte/control custody. |
| High | Join this private computation with daemon-kext traffic | Actual native object consumers and matched Mach/IOKit request/reply buffers and rights. |
| Medium | Generalize this SHA-1 source copy | Universal four-phase round, counter/owner and helper-handover invariants. |
| Medium | Compare the prefix/body/suffix construction at other source sites | Independent source/data-flow joins; literal strings and masks alone are insufficient. |

**QG1**: factual technical scope. **QG2**: RD-A1 through RD-A6 give premises and falsification probes. **QG3**: retained message identity, body codec, initialization/padding/compression, epochs, register/memory interfaces and downstream AES composition are covered; the full goal remains active. **QG4**: byte/bit extents, modular widths, endianness, exact counts and complexity are explicit. **QG5**: stored/decoded bytes, mask indexing, new/old source copies, inherited/current writers, finite/universal results and source/native execution remain distinct. **QG6**: original source, pinned admissions, fresh parent extraction, independent replay/custody, local proofs, standard algorithm reference and two host digest implementations support the claims. **QG7**: impact-labelled continuation is bounded above. All gates pass for this increment; native admission, body semantic origin and daemon-kext pairing remain unknown.
