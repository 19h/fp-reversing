# fairplayd: digest-body writer lineage across record growth

All 48 bytes in the retained digest-body window now have concrete source writers in both conditional contexts. The final window contains eight four-byte word emissions, twelve surviving stores from the address/cache/text-dependent byte encoder and two two-byte emissions. Their chains include 316 intervening byte copies and 640 inherited-boundary checks across the two contexts. The incoming scalar producers and application-level field names remain unknown. This is a source/model lineage result; native daemon-kext pairing remains unknown. [DB1-DB6; DB-A1-DB-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| DB1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; actual copy, word, table-byte and two-byte source instructions. |
| DB2 | [Record extension](daemon_record_extension_report.md) and [retained digest](daemon_record_digest_report.md), with their checks/replay/audit receipts pinned in DB3. The complete conditional parent paths, declared API returns and source-state admissions remain dependencies. |
| DB3 | [Extractor](triage_evidence/recover_daemon_digest_body_origins.py), [checks](triage_evidence/daemon_digest_body_origins_checks.json.zst): source slices, per-byte epoch chains, fixture boundaries, actual owner growth and codec inputs. |
| DB4 | [Auditor](triage_evidence/audit_daemon_digest_body_origins.py), [audit](triage_evidence/daemon_digest_body_origins_audit.json.zst): independent forward last-writer fold, complete selected scalar replay, original bank reads and eight nonvacuous source equations. |
| DB5 | [Publication verifier](triage_evidence/verify_daemon_digest_body_origins_publication.py): fresh extraction/audit, query comparison/re-solving, original-input custody, exact manifest delta and path hygiene. |
| DB6 | [Post-seed byte codec](daemon_postseed_output_report.md) documents the same `0x100a0ca74` encoder and its separate earlier caller. The present slices establish its use within this digest window; identity of the two native caller epochs is unknown. |

Decoded checks SHA-256: `625ffd36a7cca083c4e20b295639adbdd190d858e2b83a7c4ff81f30e66f1758`. Decoded audit SHA-256: `dc216f1beb7244d7269b4d2bf682ef5d80dc1d2a4e844ecd20ab14fc735fa239`. Parent pins, dependency hashes and decoded interval hashes are recorded in DB3-DB4. No additional IDA data was required for this increment. [DB2-DB5]

## Owner and epoch sequence

All ranges are half-open and measured in bytes. Owner addresses identify private conditional-model allocations, not native allocations. The selected consumer reads final owner `R=0x66000d0000` at offsets `[77,125)`, within its 224 B extent. Each incoming-boundary link checks defined fixture bytes and rejects passage through a fresh-allocation or invalidated span. Each copy follows the exact preceding one-byte source read, rather than interpreting equality as an ownership join. [DB2-DB4; DB-A2-DB-A3]

```text
interval 1: owner 0x6600090000 / 97 B
               |
               | 14 surviving bytes copied in interval 2
               v
interval 2: owner 0x66000a0000 / 125 B, 4 latest producer bytes
interval 3: same owner, 30 latest producer bytes
               |
               | 48 bytes copied in interval 4
               v
            owner 0x66000b0000 / 145 B
               |
               | 48 bytes copied in interval 6
               v
            owner 0x66000c0000 / 185 B
               |
               | 48 bytes copied in interval 8
               v
            owner 0x66000d0000 / 224 B
interval 9:    R+[77,125) -> digest-body codec -> 67 B message
```

Per context, `14 + 48 + 48 + 48 = 158` copy-byte links. The final producer partition is `14 + 4 + 30 = 48` bytes across intervals 1, 2 and 3. Nine intervals per context suffice; no demanded byte reaches interval 0. Earlier writes at some selected addresses differ from the retained value, so selecting the latest writer matters. No selected query in this corpus has a later in-interval write after its queried epoch; the audit records that count as zero. Earlier conflicting writes are the retained negative control. [DB3-DB4]

## Exact source mappings

The following mappings hold in both retained classes 2 and 3. Their agreement is agreement of two conditional source/model contexts, not two independent native observations. `P4` denotes stores `0x100c70e28`, `0x100c70e80`, `0x100c70ed0`, `0x100c70f18`; `PB` denotes `0x100a0ca74`; `P2` denotes `0x100b755ac`, `0x100b755f8`. [DB3-DB4; DB-A2]

| Body range / B | Owner offsets / B | Latest interval | Producer | Stored hexadecimal bytes |
| --- | --- | --- | --- | --- |
| [0,4) | [77,81) | 2 | P4 | `ec4de4a9` |
| [4,8) | [81,85) | 1 | P4 | `2fdbbbd1` |
| [8,12) | [85,89) | 1 | P4 | `80b42ccf` |
| [12,14) | [89,91) | 1 | PB | `a7c6` |
| [14,16) | [91,93) | 3 | P2 | `97e9` |
| [16,20) | [93,97) | 1 | PB | `d12130a1` |
| [20,24) | [97,101) | 3 | P4 | `a07a4115` |
| [24,28) | [101,105) | 3 | P4 | `944d71b4` |
| [28,32) | [105,109) | 3 | P4 | `bfdf33c1` |
| [32,34) | [109,111) | 3 | PB | `9fd1` |
| [34,36) | [111,113) | 3 | P2 | `54c3` |
| [36,40) | [113,117) | 3 | PB | `208e4bae` |
| [40,44) | [117,121) | 3 | P4 | `8ba127b3` |
| [44,48) | [121,125) | 3 | P4 | `da08c044` |

Copy reads/stores occur at `0x100b5c9b4`/`0x100b5c9b8`, preceded by the original index decrement at `0x100b5c9b0`. The source equation establishes `dst[i] = src[i]` with arbitrary u64 modular addresses/index and an arbitrary byte. Concrete extents and owner validity remain separate parent premises. [DB2-DB4]

## Four-byte and two-byte codecs

Let `H=d98c9317498b221182b3198570dd904f`, indexed by owner offset modulo 16. The four-byte writer consumes u32 W11 and emits a big-endian word through three fixed image banks per byte. Normalizing its stored bytes with H gives:

```text
decoded4 = BE32(W11 XOR 0xe4b5bf34)
decoded2 = BE16(low16(V) XOR 0x534c)
```

Here V is W8 after the preceding two-byte arithmetic, at `0x100b755a0`. The second equation does not identify V's upstream semantic value. Four arbitrary-word/source-byte equations and two arbitrary-word two-byte tail equations establish the final arithmetic. Exhaustive fixed-bank identities cover all 16 nibble values; original loads and all GP/SP/NZCV frames bind these equations to each retained writer. Neither equation asserts an application field type. [DB3-DB4; DB-A4-DB-A5]

| Owner offset / B | Interval | W11 input | Normalized four-byte output | Store source visits |
| --- | --- | --- | --- | --- |
| 77 | 2 | `0xd5681444` | `31ddab70` | 47868, 47890, 47910, 47928 |
| 81 | 1 | `0x47fd13ac` | `a348ac98` | 15083, 15105, 15125, 15143 |
| 85 | 1 | `0xef238279` | `0b963d4d` | 29684, 29706, 29726, 29744 |
| 97 | 3 | `0xc85ce968` | `2ce9565c` | 14632, 14654, 14674, 14692 |
| 101 | 3 | `0xfbdadf02` | `1f6f6036` | 15145, 15167, 15187, 15205 |
| 105 | 3 | `0xe8730985` | `0cc6b6b1` | 29746, 29768, 29788, 29806 |
| 117 | 3 | `0xe4368905` | `00833631` | 86182, 86204, 86224, 86242 |
| 121 | 3 | `0x8da4fa00` | `69114534` | 100516, 100538, 100558, 100576 |

| Owner offset / B | Interval | V after arithmetic | Normalized two-byte output | Store source visits |
| --- | --- | --- | --- | --- |
| 91 | 3 | `0xfffe41d5` | `1299` | 85657, 85676 |
| 111 | 3 | `0xfffe4856` | `1b1a` | 57615, 57634 |

The first byte's effective banks start at `0x100e36310`, `0x100f2f6b3`, `0x100ed2441`. The remaining word bytes and the two-byte writer use effective banks at `0x100f21190`, `0x100fa38b4`, `0x100ffc9e1`. Exact 16 B image slices and their row identities are retained in DB3. No key material or external parameter was substituted for an unknown source value. [DB1,DB3-DB4]

## Twelve surviving address/cache/text-encoded bytes

For phase W10=`0xbc66`, the selected encoder slices reproduce the previously established transform. All operations marked u32 wrap modulo `2^32`; `a` is the full u64 destination address and `shift` is a bit count. [DB1,DB3-DB4,DB6]

```text
cached_word = 0xa0018891
text_base   = 0x100822058
mask64      = 0xfff0c01200007fff
r           = u32(cached_word + low32(a))
ta          = byte[text_base + (u32(r + 0x0ba3ccc8) AND mask64)]
tb          = byte[text_base + (u32(r + 0x0ba3ccca) AND mask64)]
stored8     = low8((W9 >> (shift AND 31)) XOR u32(31*low32(a)) XOR ta XOR tb XOR 0xd7)
```

| Owner offsets / B, ascending | Interval | W9 input | Selected shift bits, same order | Stored bytes |
| --- | --- | --- | --- | --- |
| 89,90 | 1 | `0xfde68442` | 16,8 | `a7c6` |
| 93,94,95,96 | 1 | `0x7d9d589e` | 24,16,8,0 | `d12130a1` |
| 109,110 | 3 | `0xdf24b242` | 8,0 | `9fd1` |
| 113,114,115,116 | 3 | `0x501c308c` | 24,16,8,0 | `208e4bae` |

These are surviving last writes, not a census of every attempt made by the encoder or a claim that each surviving group is a complete field. In particular, offsets 89,90 do not select W9's low sixteen bits. The receipt preserves all twelve source-text read addresses and actual bytes. The cached-word read is at `0x6500115e34`; initialization/ownership of that cache and upstream production of W9 remain dependencies. Absolute destination arithmetic enters the local equation; whole-path relocation invariance is unknown. [DB3-DB4,DB6; DB-A4-DB-A5]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| DB-A1: The pinned source image and original instruction bytes are the intended specimen | All source mappings and equations | Rehash the image; compare every selected instruction and fixed bank byte against the source image. |
| DB-A2: Parent admitted source paths, declared malloc/free returns and fixture epochs apply | Concrete owner addresses, extents, interval order and retained lineage | Match parent/decoded interval hashes; retain exact API premises; reject an inherited byte inside a fresh or invalidated span. Native return and allocation observations would test the model premise. |
| DB-A3: Copy classification requires an actual preceding read of the emitted byte | The cross-owner lineage | Check read/store PCs, one-byte widths, read-before-write order and equal values; independently fold all preceding writes before each exact cut. |
| DB-A4: The fixed image bank bindings and phase `0xbc66` apply at the selected slices | Word/two-byte normalization and address-dependent byte equation | Replay every source frame/load/store, check all nibble rows and original bank/text addresses; reject a changed H phase; arbitrary-word source equations separately test the arithmetic. |
| DB-A5: Incoming scalar/cache values are source/model inputs whose deeper meaning is unknown | Limits on naming and environmental interpretation | Recover upstream W11/W9/V and cache producers, with their own epochs; do not promote a stored word to a protocol field from width or placement alone. |
| DB-A6: The selected final owner bytes feed the already pinned digest consumer | Digest-body join and cross-layer scope | Match all 48 consumer reads and value-preserving chains; require a separate call/owner/transport join before assigning a Mach or IOKit meaning. |

## Validation, complexity and scope

The independent audit checks 360 original source chunks, 3,744 instruction visits, 131,328 GP/SP values, 4,104 NZCV frames, 856 reads and 412 writes. The 412 writes comprise 96 selected producer stores and 316 copy stores. It separately checks 384 last-writer read bytes and 2,212 incoming/image read bytes of the selected slices; these latter reads are not claimed to have newly recovered producers. Sixteen word groups, four two-byte groups and twenty-four complete byte-codec cases pass. Eight source queries are UNSAT after satisfiable empty-premise checks. [DB3-DB5]

Extraction uses per-address histories plus predecessor searches. The independent audit instead sorts queries and folds writes forward before each queried epoch. Let P be parent byte volume, Q byte-query count, C selected-chunk count, E parent event/fixture-byte count and V selected instruction count. A conservative bound for each implementation is `O(P+(Q+C)E+(E+Q)log(E+Q)+32V)` time and `O(largest interval+receipts+32V)` space. This includes repeated fixture/event scans, source-slice construction, copy-read validation and earlier/later-write controls. Proof DAG construction/storage and solver search are additional; each query has a 30 s timeout. [DB3-DB5]

No new target interval, root byte, native API execution, Mach right/disposition, message emission site, hardware PAC authentication or IDB mutation is introduced. The result closes the local inherited-byte gap for the digest body. Upstream scalar semantics, native caller admission, the later missing record-bank frontier and daemon-kext transaction identity remain unknown. [DB2-DB5]

| Impact | Bounded continuation | Discriminating evidence |
| --- | --- | --- |
| High | Recover producers of the eight W11 words and two V values | Follow source definitions into caller arithmetic and original bank reads; `0x100b9e534` and `0x1009dad14` are retained predecessor candidates for selected word emissions, not established semantic entries. |
| High | Recover the four W9 words and cache lifecycle in these exact epochs | Trace their last definitions and address/cache inputs; equality with another caller's encoder does not identify its stream or native state. |
| High | Join the constructed owner to native daemon transport and a kext request | Require concrete buffer def-use, selector/message fields, port/right ownership and matching transaction identity. Current writer lineage supplies none of those missing joins. |
| Medium | Recover superseded writes and complete encoder attempts | Compare all epochs at offsets 77, 89-92 and 109-112; test zero-byte retries and later field replacements without treating a surviving fragment as a whole field. |
| Medium | Test whole-path relocation and alternate admitted inputs | Vary destination/cache context coherently; local absolute-address arithmetic alone does not establish the final message's relocation behavior. |
| Low | Add navigation labels for the three writer classes and generic copy | Preserve exact source PCs, parent cuts and unknown whole-function boundaries. |

**QG1** passes: factual technical analysis. **QG2** passes: DB-A1-DB-A6 specify dependencies and falsification probes. **QG3** passes for this digest-body origin increment; the full interface investigation remains incomplete. **QG4** passes: byte extents, bit counts, u32/u64 arithmetic, BE32/BE16 order and complexity are explicit. **QG5** passes: retained and superseded writes, declared API effects, scalar inputs and native observations remain distinct; the later-write control count is explicitly zero. **QG6** passes after pinned primary bytes, fresh independent replay/source equations and publication verification. **QG7** passes: continuation is bounded by scalar/cache origins, writer epochs, relocation and transport identity.
