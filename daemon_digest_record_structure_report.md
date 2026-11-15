# fairplayd: retained digest-body structure and read-before-overwrite epochs

Payload-source continuation: [The scalar-mixer report](daemon_payload_scalar_mixers_report.md) now establishes the two previously opaque mixers as the same bijective affine u32 transform and recovers their separate BE32 input provenance. Scratch prefix replacement explains the second input. The original structure receipt and its limited semantic claims remain preserved; native schema and a combined-value interpretation remain unknown.

The retained 48 B digest body has a recoverable local span layout: a 48 B span starts at owner offset 77, with a 28 B span starting 20 B later at offset 97. Both end at offset 125. Packed fields at offsets 85 and 105 each decode to the count-like value 1. Two adjacent words are additive transforms of indexed private-bank entries 3 and 4; twelve surviving byte stores receive four exactly identified tempered words. The final 8 B pass through two other word mixers whose application meaning remains unknown. This establishes conditional local structure, not a native wire schema or daemon-kext transaction. [DS1-DS6; DS-A1-DS-A6]

The earlier writer-lineage report also needed a counter-scope correction. Its zero later-write counter applied only to queries already having an in-interval predecessor writer. The present audit includes incoming-fixture queries: 316 such reads have later source overwrites, and all 316 overwrite bytes differ from the consumed byte. The recovered digest body is unchanged. [DS2-DS5]

| Evidence | Primary provenance and scope |
| --- | --- |
| DS1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; actual scalar/count, indexed-bank, tempering, word-mixer and overwrite instructions. |
| DS2 | [Digest-body writer lineage](daemon_digest_body_origins_report.md), [record extension](daemon_record_extension_report.md) and their pinned checks/audit/replay receipts. The admitted parent paths, defined fixtures and declared API returns remain dependencies. |
| DS3 | [Extractor](triage_evidence/recover_daemon_digest_record_structure.py), [checks](triage_evidence/daemon_digest_record_structure_checks.json.zst): original producer-to-store slices, scalar/count custody, exact field values, tempered-word consumers and first post-read overwrite events. |
| DS4 | [Auditor](triage_evidence/audit_daemon_digest_record_structure.py), [audit](triage_evidence/daemon_digest_record_structure_audit.json.zst): independent replay/inverse decodes, future-writer scans, two new source equations and fresh reconstruction of fifty prior source proofs plus one ring normalization. |
| DS5 | [Publication verifier](triage_evidence/verify_daemon_digest_record_structure_publication.py): fresh extraction/audit, canonical proof comparison/re-solving, exact owned-file/manifest delta, original-input preservation and path hygiene. |
| DS6 | [Packed-word contract](daemon_packed_words_report.md), [append-field contract](daemon_append_fields_report.md), [local span layout](daemon_record_spans_report.md) and [byte encoder](daemon_postseed_output_report.md). Their general contracts have separate domains; this increment checks the actual inputs and epochs before applying them. |

Decoded checks SHA-256: `8b4b05e9d76bdbb22ae73de9c2b37b66888f98f92268483547c53169de2acb9e`. Decoded audit SHA-256: `862051c07acb2f45558aff786793b531b028a04b63883933500769e32565692b`. Parent/dependency hashes and every decoded parent-interval hash appear in DS3-DS4. Reference data sufficed; no additional IDA data was required. [DS2-DS5]

## Local layout and distinct count meanings

Offsets are owner-relative, ranges are half-open and B denotes bytes. Final owner R is the 224 B private conditional-model allocation at `0x66000d0000`. These addresses are not native allocator observations. The existing owner-offset codec has mask `H=d98c9317498b221182b3198570dd904f`. [DS2-DS4; DS-A2]

```text
R+[77,125): 48 B span
|-- R+[77,97): 20 B prefix
|   |-- +77: packed scalar 48, packing bit count 6
|   |-- +81: indexed bank word, index 3
|   |-- +85: packed count-like scalar 1, packing bit count 1
|   `-- +89..96: surviving byte and two-byte emissions
`-- R+[97,125): 28 B span
    |-- R+[97,117): 20 B prefix
    |   |-- +97: packed scalar 28, packing bit count 5
    |   |-- +101: indexed bank word, index 4
    |   |-- +105: packed count-like scalar 1, packing bit count 1
    |   `-- +109..116: surviving byte and two-byte emissions
    `-- R+[117,125): 8 B payload, two other word mixers
```

The exact arithmetic is `77 B + 48 B = 125 B`, `97 B + 28 B = 125 B`, `77 B + 20 B = 97 B` and `97 B + 20 B + 8 B = 125 B <= 224 B`. These establish nested ranges. Interpreting their first 20 B as record prefixes uses the previously established constructor layout and is explicitly conditional; field names, record types and native schema remain unknown. In particular, the two four-byte payload emissions do not establish a native u64 value. [DS2-DS4,DS6; DS-A3]

Let A be the packed producer's entry W8, K its scalar cell at FP-0xd0, n its count cell at FP-0xcc and V the word after removing H from the emitted bytes. All arithmetic is u32. [DS3-DS4,DS6]

```text
D = K XOR 0x8b3dc651
auxiliary = A XOR 0x6703cce9
n = max(1, bit_length(D))
V = u32(((u32(auxiliary << (n AND 31)) AND 0x07ffffff)
         OR u32(n << 27)) + D)
producer_W11 = V XOR 0xc156f94e
caller_W11   = V XOR 0xe4b5bf34
```

For `1 <= n <= 27` and `D < 2^n`, the inverse is `n=V>>27`, `D=V AND (2^n-1)` and retained auxiliary bits `(V AND 0x07ffffff)>>n`. All eight retained applications satisfy this domain. The count n measures scalar bit width; it is distinct from the record's count-like scalar D. Auxiliary bits do not change D within this domain. Their upstream semantic meaning is unknown. [DS3-DS4,DS6; DS-A4]

| Owner offset / B | Interval | Entry A | Decoded D | Packing count n / bits | Retained auxiliary bits / value | V after H normalization |
| --- | --- | --- | --- | --- | --- | --- |
| 77 | 2 | `0x84a4ba44` | 48 | 6 | 21 / `0x776ad` | `31ddab70` |
| 85 | 1 | `0x3ec8d24f` | 1 | 1 | 26 / `0x1cb1ea6` | `0b963d4d` |
| 97 | 3 | `0xcba4865b` | 28 | 5 | 22 / `0x274ab2` | `2ce9565c` |
| 105 | 3 | `0xa16097b1` | 1 | 1 | 26 / `0x2635b58` | `0cc6b6b1` |

Each row occurs in both retained classes 2 and 3. The actual K/n reads have eight source-writer byte links per row. Source `0x100a30dfc` spills K, `0x100add45c` spills n, `0x100c29260` reloads n and `0x100c2943c` reloads K. Twenty-six count-loop iterations across the two contexts check every current scalar/counter and logical branch. The complete producer/caller/store paths are replayed; the shared fifty-proof/ring decomposition is freshly reconstructed rather than treating a few observed values as a universal proof. [DS3-DS4]

## Indexed fields and generated-byte inputs

The source loads U+0x20 at `0x1009dab6c`, then the selected u32 at `0x1009dab70`. The following mixer and word writer give `normalized32 = u32(raw_element + 0xb69f7313)`. The new all-u32 source equation also checks the owner-pointer load at U+8. All sixteen bank-element bytes across the two contexts are inherited inputs in these intervals; their producers and application names remain unknown. [DS3-DS4; DS-A5]

| Owner offset / B | Interval | Bank base | Index | Element address | Raw element | Normalized word |
| --- | --- | --- | --- | --- | --- | --- |
| 81 | 1 | `0x650011519c` | 3 | `0x65001151a8` | `0xeca93985` | `a348ac98` |
| 101 | 3 | `0x650011519c` | 4 | `0x65001151ac` | `0x68cfed23` | `1f6f6036` |

For the byte-emitter inputs, original `0x100a7ccc0..0x100a7ccf0` implements the following exact tempering equation. Logical right shifts and u32 truncation apply. Its variable third shift is 15 under the checked phase `low5(W10)=6`. A new arbitrary-u32 source proof establishes the equation under that phase. [DS1,DS3-DS4]

```text
y = raw_W19 XOR (raw_W19 >> 11)
y = y XOR ((y << 7) AND 0x9d2c5680)
y = y XOR ((y << 15) AND 0xefc60000)
W9 = y XOR (y >> 18)
```

| Interval | Raw W19 | Tempered W9 | Owner offsets receiving surviving byte stores / B |
| --- | --- | --- | --- |
| 1 | `0x3140c7a3` | `0xfde68442` | 89,90 |
| 1 | `0xc6699e4a` | `0x7d9d589e` | 93,94,95,96 |
| 3 | `0x0de13d2c` | `0xdf24b242` | 109,110 |
| 3 | `0x5e53ea76` | `0x501c308c` | 113,114,115,116 |

W9 remains unchanged, with no intervening X9/W9 definition, through every selected byte-encoder entry. Across both contexts, 3,736 preserved-frame checks connect eight tempered words to twenty-four consumers. DS2 supplies their subsequent address/cache/text encoding and final byte lineage. This does not establish statistical randomness, native entropy provenance or equivalence of separate caller epochs. The producer of each incoming raw W19 remains outside this increment. [DS2-DS4,DS6; DS-A5]

| Payload owner range / B | Source mixer, end exclusive | Entry W8 | Normalized output | Interpretation |
| --- | --- | --- | --- | --- |
| [117,121) | `0x100a630cc..0x100a63288` | `0x6703cce9` | `00833631` | Actual source path established; application value unknown |
| [121,125) | `0x100a86930..0x100a86b00` | `0x6703af14` | `69114534` | Actual source path established; application value unknown |

Both complete mixer/caller/store paths pass original-byte/frame/effect replay in each context. Their normalization uses the existing word codec. No compact general semantic equation for these two mixers is asserted here. [DS3-DS4]

## Counter correction and actual read epochs

DS2's frozen audit field `end_of_interval_writer_changes=0` counts later writes only when the queried byte already has an in-interval predecessor writer. Its incoming-fixture branch did not update that counter. The earlier report stated its scope too broadly; that prose is corrected in this publication. The frozen receipt is preserved, and its restricted counter retains its original meaning. DS3-DS4 independently examine all 1,052 lineage queries, including the incoming-fixture cases. [DS2-DS5]

There are 316 first post-read overwrites across both contexts, all on incoming-fixture queries, all changing the consumed byte. Per context, the counts are 14 in interval 2 and 48 each in intervals 4, 6 and 8: `14+48+48+48=158`, hence `2*158=316`. Each first overwrite is retained with its exact source instruction/frame and independently replayed. [DS3-DS4]

```text
class 2, interval 8, owner 0x66000c0000 + 77 B

entry fixture 0xec
      |
      v
visit 1068:  0x100b5c9b4 reads 0xec -> copied to the new owner
      |
      v
visit 52788: 0x100ab03bc writes 0x1c to the old owner byte

The consumer's value is 0xec; the interval's later value is 0x1c.
```

This is a concrete falsifier for replacing the consumer's read epoch with end-of-interval memory. It does not invalidate the earlier per-read last-writer chains: those chains already retained the incoming fixture at the correct cut. It also does not establish an intended erasure guarantee or native lifetime behavior. [DS2-DS4; DS-A2,DS-A6]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| DS-A1: The pinned image and original instructions are the intended specimen | Every source mapping and proof | Rehash the image; compare all selected original bytes and shared proof dependency hashes. |
| DS-A2: Parent admissions, owner/fixture epochs and declared API returns apply | Concrete field addresses, copy/read epochs and overwrites | Match decoded parent hashes and source frames/effects; retain API/owner assumptions; require native allocation/call observations before promoting them to native facts. |
| DS-A3: The established 20 B prefix layout applies to these local spans | Parent/child record interpretation | Check decoded spans, exact starts/endpoints, +8 count-like fields and complete producer-to-store slices; a different source reader/layout or native schema would falsify the interpretation. Geometric containment remains a separate exact result. |
| DS-A4: Packed-word canonical inverse is applied within its proved domain | Decoded scalars 48/1/28/1 and auxiliary fields | Verify all scalar/count source writers, complete count loops and actual A/K/n inputs; freshly reconstruct fifty source proofs and the ring normalization; retain `1<=n<=27`, `D<2^n` and u32 wrap. |
| DS-A5: Bank elements, auxiliary A, incoming W19 and cache values have only the stated provenance | Limits on tag, randomness and payload naming | Preserve inherited element reads and actual register inputs; trace their producers before assigning external names, entropy origins or a complete payload type. |
| DS-A6: Each queried read must retain its own epoch, including entry-fixture reads | Correct digest bytes and corrected counter scope | Independently scan all queries for first later writes; the 316 changed bytes and explicit 0xec/0x1c event pair reject a final-memory substitution. |

## Validation and bounded continuation

The independent audit checks 390 original source chunks, 6,322 instruction visits, 214,784 GP/SP values, 6,712 NZCV frames, 434 reads, 396 writes and 50 logical authenticated edges. It separately checks 288 last-writer read bytes and 1,648 incoming/image read bytes of the selected slices. The scalar/count custody checks cover another 64 byte links; bank-element checks retain sixteen incoming bytes. Source replay supplies finite path/effect evidence; the generic packed-word result uses the explicitly pinned decomposed source/ring proof. Hardware authentication is not executed. [DS3-DS5]

New source obligations cover arbitrary-u32 tempering under `low5(W10)=6` and the indexed-word additive mixer with its pointer-load interface. Fifty prior packed-word/count/inverse obligations and one exact ring normalization are freshly reconstructed and compared to their pinned originals. New/shared proofs remain separately counted. All proof premises are checked for satisfiability before the bad-result query is UNSAT. [DS4-DS5]

For P parent bytes, Q byte queries, C selected chunks, E parent events/fixture bytes and V selected instruction visits, a conservative extraction/audit bound is `O(P+(Q+C)E+(E+Q)log(E+Q)+32V)` time and `O(parent receipts+largest interval+selected frames)` space. This includes repeated event scans and source-slice/custody checks. Proof DAG storage/construction and solver search are additional; each source query has a 30 s timeout. Target byte widths, bit counts and endpoint arithmetic are exact. [DS3-DS5]

No new target interval, root byte, API-return premise, native API/IPC execution, Mach port/right/disposition, message emission site, hardware PAC event or IDB mutation is introduced. Native schema, original caller admission, full payload meaning, cache/bank initialization and daemon-kext pairing remain unknown. The full investigation remains active. [DS2-DS5]

| Impact | Bounded continuation | Discriminating evidence |
| --- | --- | --- |
| High | Recover the two final payload mixers' compact scalar contracts | Follow their actual A inputs and arithmetic; test whether the 8 B represents one logical value before assigning a width/type. |
| High | Recover the U+0x20 bank's producer and index-selection semantics | Join entries 3/4 to exact source definitions and independent consumers; widths and additive encoding alone do not identify record types. |
| High | Trace incoming raw W19, auxiliary A and cache initialization in these epochs | Preserve their def-use paths and address/context dependencies; tempering alone does not prove external entropy or native randomness. |
| High | Join the locally structured owner to transport and a kext transaction | Require buffer/selector/message, port/right ownership and matching transaction evidence; the current nested layout does not establish those joins. |
| Medium | Expand epoch controls to other fixture-backed reads | Measure overwritten incoming reads explicitly; counter names and zero totals require a verified population definition. |
| Low | Add source-navigation labels for packed span/count and bank fields | Keep local interpretation, actual source PCs and unknown native schema explicit. |

**QG1** passes: factual source analysis. **QG2** passes: DS-A1-DS-A6 record dependencies and falsification probes. **QG3** passes for this retained structure/epoch increment; the full interface investigation remains incomplete. **QG4** passes: u32/u64 domains, bit counts, byte extents, exact endpoints and complexity are explicit. **QG5** passes: bit width and count-like values, geometric nesting and schema, incoming reads and later writes, new and shared proofs are distinct; the prior counter scope is corrected. **QG6** passes after pinned primary bytes, independent replay, fresh source/ring checks and publication verification. **QG7** passes: continuation covers opaque payloads, bank/cache origins, epoch populations and native transport joins.
