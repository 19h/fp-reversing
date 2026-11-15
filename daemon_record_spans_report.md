# fairplayd: local record spans, scalar payload and selected resize context

Subsequent span evidence: [the digest-record structure report](daemon_digest_record_structure_report.md) applies the same packed-scalar contract to spans 48 B at offset 77 and 28 B at offset 97, both ending at 125, with count-like scalar 1 at offsets 85/105. This supports a conditional 20 B prefix/child interpretation while preserving unknown native schema and final 8 B payload semantics. Its complete incoming-read epoch scan also documents the old-owner overwrites excluded from the earlier restricted counter.

The first constructor append calculates **4*4+20=36**, adds that span to the old header scalar 20, and supplies 56 as the requested header to the resize interface. The resulting 57 B buffer contains a 36-byte span beginning at offset 21, including four encoded scalar words with values **0, 1, 0, 1** beginning at offset 41. The arithmetic, serialized span, payload placement and allocation increase agree. [RS1-RS5; RS-A1-RS-A5]

The later 77 B buffer retains that span and contains another 20-byte span at offset 57. Its next resize reads the scalar **20 at offset 57**, rather than the enclosing scalar **76 at offset 1**, and requests 97 B using target scalar 40. This resolves the selected record context for that request. The previous extent-minus-one relationship applies to the enclosing offset-1 field; it is not a general interpretation of every span field. [RS2-RS5; RS-A3-RS-A6]

The field at record-start+14 is 1 for the enclosing F record and 2 for the enclosing H record, while the appended records contain zero. With the prior proved 0->1 and 1->2 updates, this supports a local child-count interpretation and a nested record layout. Exact offsets, values and span endpoints are established; a complete native structure type, native acceptance rule and daemon-kext buffer identity remain unknown. [RS2-RS5; RS-A4-RS-A6]

| Evidence | Primary source and scope |
| --- | --- |
| RS1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; exact selected original instruction words are retained in RS4. |
| RS2 | [Constructor extent/header checks](triage_evidence/daemon_constructor_extent_checks.json.zst), decoded SHA-256 `6bbd9bba929ade62267d9dbe0a39bc0ec4944e98077df56e87ee4805a4122209`; [audit](triage_evidence/daemon_constructor_extent_audit.json.zst), `2b6cb82792deb42dee210fad77363caddf499c9f44d9991ac4163868771f303d`; [report](daemon_constructor_extent_report.md). These qualify the earlier producer/writer, generic extent/header coupling and constructor journals. |
| RS3 | [Growth checks](triage_evidence/daemon_descriptor_growth_checks.json.zst), decoded SHA-256 `b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2`; [replay](triage_evidence/daemon_descriptor_growth_replay.json.zst), `bee4ab3224710559fefdd8bca070110e48c03ab52d01c92b617988b9b3d5bd67`. [Scalar serialization](daemon_scalar_serialization_report.md), [constructor halfword](daemon_constructor_halves_report.md), [halfword update](daemon_halfword_update_report.md) and [packed-halfword](daemon_packed_halves_report.md) receipts qualify the codecs and earlier count-field updates. Their hashes are pinned in RS4. Full prior admission/allocation corpora are not rerun. |
| RS4 | [Extractor](triage_evidence/recover_daemon_record_spans.py) and [checks](triage_evidence/daemon_record_spans_checks.json.zst): selected source/custody, 48 new constructor field occurrences, two later resize classes, and 456 freshly checked exports. |
| RS5 | [Independent auditor](triage_evidence/audit_daemon_record_spans.py) and [receipt](triage_evidence/daemon_record_spans_audit.json.zst): 23 nonvacuous UNSAT obligations, two SAT interpretation controls and independent selected source replay. |
| RS6 | [Publication verifier](triage_evidence/verify_daemon_record_spans_publication.py): fresh extraction/audit and canonical query checks, exact manifest delta, original-input preservation and decoded path hygiene. |

## First append: count, payload width and requested span

All equations operate modulo 2^32, with zero-extension to u64 for allocator counts. Let c denote the decoded constructor count, b the scaled value, s the new span, p the old header scalar, a the requested header scalar, and C the old decoded allocation extent. The source contracts compose as follows: [RS1-RS2, RS4-RS5; RS-A2]

```
b = u32(c << 2)
s = u32(b + 20)
a = u32(p + s)
N = u32(C + a - p) = u32(C + s)

retained instance:
c=4; b=16; s=36; p=20; a=56; C=21; N=57
```

In this retained instance, the four payload fields each occupy 4 B, so `4*4 B=16 B`. Their first byte is at record-start+20, establishing a 20 B prefix for this record. The source's numeric scaling and constant addition match those actual byte widths. The generic arithmetic contracts preserve wrap; arbitrary c values are not thereby admitted native records or proven payload-loop bounds. [RS4-RS5; RS-A2, RS-A5]

| Source interval, end exclusive | Established interface |
| --- | --- |
| `0x100501614..0x100501618` | Original store of encoded count `0x8b3dc655`, consumed at SP+0x537c by `0x1006c306c`. |
| `0x1006ce4a8..0x1006ce4c8` | W11=`0x4183`, W8=`c XOR 0x8b3dc651`; output W8=`u32(c<<2) XOR 0x8b3dc651`, W10=`0xca23`. |
| `0x10077cff0..0x10077d1ac` | W10=`0xca23`, W8=`b XOR 0x8b3dc651`; output W13=`u32(b+20) XOR 0x8b3dc651`. |
| `0x10077d1ac..0x10077d1b4` | Store W13 to SP+0x48cc. A separate universal proof checks the address, width and value for arbitrary u64 SP and u32 input. |
| `0x1008d8314..0x1008d83ec` | W10=`0x493`, W13 encoded s, encoded p at SP+0x64a8; output W12=`u32(p+s)`. Its unrelated status spill is retained in replay. |
| `0x100765f24..0x100765f28` | Store a at SP+0x312c for the previously proved resize interface. |

Every byte of the count read has `0x100501614` as its last source writer. Every byte of the old-header read has `0x100855534` as its last writer. The encoded span 36 remains in W13 until the sum, and the resulting 56 remains in W12 until its operand store. All four prefix classes pass these checks. [RS4-RS5]

The encoded 36 stored at SP+0x48cc survives the declared malloc and free transitions. The later source load at `0x1008ca578` consumes exactly those bytes. Neither preceding continuation writes that cell, and neither declared API event invalidates it. Thus the appended span's value is joined to its source calculation across both transitions. The actual scalar/count reads of each packed-word producer have current-interval source writers. [RS2, RS4-RS5; RS-A3-RS-A4]

## Stored spans and scalar payload

The earlier producer/writer contracts from RS2 apply to six new field occurrences in each of eight successful constructor classes. Selected replay includes each complete producer, its single caller XOR and its writer. The caller changes W12 by XOR `0x259ef046`; no other intervening W12 change occurs. Each produced scalar, count, packed value, mixed writer input and four stored bytes agree. [RS2, RS4-RS5; RS-A4]

| F offset / B | Stored bytes | Packed V | Count | Decoded scalar | Local role |
| --- | --- | --- | --- | --- | --- |
| 21 | `be78bca6` | `0x355aad24` | 6 | 36 | New record's span field |
| 29 | `d548dc1e` | `0x08d893c7` | 1 | 1 | Additional header scalar; native meaning unknown |
| 41 | `bf1be39e` | `0x0c0266ee` | 1 | 0 | First payload scalar |
| 45 | `d56dc2be` | `0x08fd8d67` | 1 | 1 | Second payload scalar |
| 49 | `8568ed1d` | `0x09fbfa54` | 1 | 0 | Third payload scalar |
| 53 | `86b43775` | `0x0d9626f7` | 1 | 1 | Fourth payload scalar |

The 16 payload bytes are four encoded scalar fields, rather than an inferred sequence of raw native-endian integers. Their decoded values are exactly 0/1/0/1 in these admitted states. A source tag word `0x76657273` participates in the retained constructor branch, but the word alone does not establish a native version schema, wire tag or transport encoding. Other header fields remain opaque or have separately qualified codecs. [RS1-RS4; RS-A4-RS-A5]

| Buffer / record start / B | Span scalar | Numeric end offset | Scalar at start+14 | Evidence status |
| --- | --- | --- | --- | --- |
| T / 1 | 20 | 21 | 0 | Prior constructor/serialization and halfword receipts |
| F / 1 | 56 | 57 | 1 | Freshly checked in 152 exports |
| F / 21 | 36 | 57 | 0 | Freshly checked in 152 exports |
| H / 1 | 76 | 77 | 2 | Freshly checked in 304 exports |
| H / 21 | 36 | 57 | 0 | Freshly checked in 304 exports |
| H / 57 | 20 | 77 | 0 | Freshly checked in 304 exports |

These endpoints and count-like values support the following local span layout. Intervals are half-open byte offsets. Parent/child labels are an interpretation supported by the contiguous spans and one increment per append; they do not establish a complete native type. [RS2-RS5; RS-A5]

```
F/57 B
  byte[0]
  enclosing span [1,57), scalar56, count-like field1
    prefix [1,21): 20 B
    appended span [21,57), scalar36, count-like field0
      prefix [21,41): 20 B
      scalar payload [41,57): 4 fields * 4 B

H/77 B
  byte[0]
  enclosing span [1,77), scalar76, count-like field2
    prefix [1,21): 20 B
    prior appended span [21,57), scalar36, count-like field0
    new appended span [57,77), scalar20, count-like field0
```

The first appended span still ends at 57 after the buffer grows to 77 B. Its scalar 36 therefore cannot be treated as the current allocation extent minus its field offset in every later state. The enclosing span and the most recently appended span both happen to end at the current extent in H. This separates local span length from the global allocation count. [RS3-RS5; RS-A5]

## Later resize selects the offset-57 record

The last selected reader at `0x100a44574` resolves U+8 to H and reads H+57..60=`9e6fd1e4`. The four reads have the actual earlier stores `0x100c70e28/0x100c70e80/0x100c70ed0/0x100c70f18` as their last writers. The reader's encoded offset W8=`0x4225556d` decodes to 57; SP is `0x680005fb50`. It loads the same D/E/K banks through local SP+0x278/0x270/0x280. [RS1, RS3-RS5]

Sixteen universal source queries cover all offset residues with symbolic upper 28 offset bits, u64 buffer base and four independent input bytes. They prove the four actual byte addresses and W10=`V XOR 0x8b3dc651`, using the common mask `d98c9317498b221182b3198570dd904f`. Coherent input bytes disjoint from fixed bank/pointer cells are explicit premises. As in the earlier reader, offsets wrap at u32 before zero-extension and u64 base addition. [RS5; RS-A2]

For these bytes, V=`0x2d765494`, count five and scalar 20. The original decoder extraction at `0x100a2ec30..0x100a2ecf0` has a universal contract for all u32 V, including the count-zero shift case:

```
n = V >> 27
D = V                         if n == 0
    V AND ((1 << n) - 1)       otherwise
```

The following original re-encoding block `0x100a2ecf0..0x100a2edc4` is fully replayed for both retained classes and yields W27=`0x8b3dc645`, encoded 20. A universal reduction of that final block remains unknown; it is not included among the 23 successful obligations. The concrete encoded value stays unchanged until the resize arithmetic. No monolithic universal contract for the whole later decoder is claimed. [RS4-RS5; RS-A6]

Original `0x100d95aac` stores target operand 40 at local SP+0x3dc. All four bytes read at `0x100c055e8` trace to that exact store. The phase word `0x0ec513e8` at SP+0x19c also has a current source writer, `0x100baba94`. Under that phase, `0x100c055ec..0x100c0564c` proves for arbitrary u32 raw extent r, decoded selected header p and operand a:

```
entry: W27=p XOR 0x8b3dc651, W22=r, W21=a
exit:  W8=u32(r+a-p)

retained: C=77; selected p=20; a=40
          decoded request = 77+40-20 = 97 B
```

The raw request becomes `0x10ecc472`. The pinned allocator-count contract decodes it to 97 B; the retained boundary at `0x100d640ac` has X0=`0x61` and remains pending before the authenticated malloc call. No return, 97 B owner, rewritten span 40 or appended bytes beyond H/77 B are supplied or observed. The complete generic calculation of operand 40 before its source store remains unknown. [RS3-RS5; RS-A3, RS-A6]

| SAT interpretation control | Substituted selected scalar p | Decoded request for C=77, a=40 | Limit |
| --- | --- | --- | --- |
| Offset-57 record selected | 20 | 97 B | Matches the actual source reads and pending count. |
| Enclosing scalar substituted | 76 | 41 B | Demonstrates why replacing the selected local scalar by the enclosing scalar changes the result. This substitution is not an admitted target execution. |

The actual source addresses and custody establish which scalar was selected. The controls only check the arithmetic distinction; they add no target state or native admission premise. The native lifetime and complete caller/initializer epoch remain unknown. [RS4-RS5; RS-A3-RS-A6]

## Verification, assumption register and continuation

Independent replay checks 20,112 original instructions across 184 slices, 649,472 GP/SP values, 20,296 NZCV frames, 1,136 read events and 274 write events. Selected Q registers remain unchanged, and decoded instructions are checked for absence of vector-register access. The 23 nonvacuous UNSAT obligations comprise count scaling/phase, 20-unit overhead, span spill, old-header-plus-span addition, later generic extent update, composed allocation increase, later scalar extraction and sixteen later byte-reader residues. Two SAT controls distinguish the selected record from the enclosing record. [RS4-RS5]

Fresh export checks cover 152 F and 304 H states: 1,976 word fields totaling 7,904 B and 1,216 halfword fields totaling 2,432 B, hence 3,192 fields and 10,336 B across 456 exports. Each state is checked against its matching F/57 B or H/77 B owner. Prior admissions, full API/owner transitions and original authentication corpora remain pinned; they are not rerun by this increment. The earlier count loop's general input contract remains unproved here, while each selected count and packed scalar is checked against its actual inputs. [RS2-RS5; RS-A3-RS-A4, RS-A6]

Time is O(parent receipt bytes + selected visits*32 + custody scans + decoded export bytes + proof DAG), excluding solver search; storage is O(parent receipts + largest decoded state + selected evidence + proof DAG). Solver queries have a 30 s bound. Arithmetic widths are u32/u64; offsets, field widths and allocation extents use B. The exact source scaling and this instance's payload width are separated from a universal native count/type claim. Archives use `zstd --ultra -22 -q -T1` with decoded round-trip checks. [RS4-RS6]

No new Mach name, right disposition, send/receive site or native daemon-kext transaction is established. No new target interval, guest input, conditional root/owner definition or API-return premise is introduced. No native target API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation executes. IDA MCP's supervisor was unavailable at this check; the retained original source and journals suffice for these results. The undefined NULL-route S+0x30, four-byte node gap, native caller/initializer epoch and pending malloc97 result remain unresolved. [RS2-RS6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RS-A1: Original image and pinned receipts apply | Exact source and selected values | Verify original SHA, dependency/parent pins, each visited word and exact fresh extraction/replay. |
| RS-A2: Stated arithmetic phases and coherent input cells apply | Universal span/reader/resize contracts | Prove fixed phases and addresses, cover all sixteen reader residues with symbolic base/upper offset bits/bytes, preserve wrap and exclude fixed-cell aliasing. |
| RS-A3: Existing conditional admission, API and owner premises apply | Cross-API span custody and 456 exports | Check source last writers, absence of intervening stores/invalidation and every matching owner/field; retain the prior full replay/admission pins and pending return boundary. |
| RS-A4: Packed-scalar/halfword formats apply in their proved canonical domains | Decoded payload values and count-like fields | Compare actual scalar/count reads, complete producer replay, caller XOR and stored bytes; check each exported field with its proper width and offset-dependent mask. |
| RS-A5: Span and count evidence supports a local layout, with native schema still unknown | Enclosing/appended record and child-count interpretation | Check all endpoints and count-like fields; retain the interior span ending at 57 after growth; require independent native consumers and complete transactions before assigning a conventional structure type. |
| RS-A6: Unproved general interfaces remain separate from selected concrete behavior | Later re-encoding, operand 40, input admission and transport | Replay the final decoder concretely, retain the universal-reencoding unknown, trace the exact operand store/read, and require its full generic producer/caller epoch and actual transport-buffer join. |

| Impact | Bounded next evidence | Present limit |
| --- | --- | --- |
| High | Trace default-coordinate writers and other helper return classes after the [caller-contract recovery](daemon_resize_callers_report.md) | The target-40 producer and explicit/default selector are now established locally; native caller-wide semantics remain unknown. |
| High | Join the enclosing/appended span layout to daemon-kext payload consumers | Local bytes, endpoints and count updates are established; native schema and transaction identity remain unknown. |
| High | Establish native initializer/caller and lifetime continuity for the current records | All present owners and API returns are conditional model premises. |
| Medium | Reduce the later decoder's final re-encoding network with explicit component proofs | Complete concrete replay and universal scalar extraction pass; the final universal re-encoding remains unproved. |
| Medium | Trace the source tag and remaining prefix fields through their separate mixers | A source tag and four scalar payloads are known; a native version schema or wire-tag interpretation is not established. |

**QG1**: factual technical analysis. **QG2**: RS-A1-RS-A6 enumerate assumptions, dependencies and falsification probes. **QG3**: local span arithmetic, payload values, layout and selected resize context are covered; the full interface goal remains active. **QG4**: widths, byte units, modular equations, counts and complexity are explicit. **QG5**: numeric endpoints, provisional hierarchy, prior admissions, concrete re-encoding and universal unknowns are separated. **QG6**: original bytes, pinned parent journals, fresh extraction, independent selected replay, source queries and publication checks establish provenance. **QG7**: bounded continuation opportunities have impact labels and explicit evidence limits.

## Private resize caller and coordinate follow-up

The [private resize-caller follow-up](daemon_resize_callers_report.md) establishes the later target40 as old-span20 plus new-span20, traces the biased contribution to caller record+0x2c, and proves explicit/default record-coordinate selection. The successful helper result selects offset57 while U+0x18 supplies default offset1; global error semantics remain unknown. Ten consumed caller fields span through offset0x3b, with exact byte custody and a distinct pre-call word lifetime. Sixteen nonvacuous obligations, three SAT controls, 1,450 independent instruction replays and 2,128 state-word checks across 304 exports qualify this increment. No new native transport, port emission or daemon-kext identity is established; the full goal remains active.

The [child-payload follow-up](daemon_child_payload_report.md) joins the private raw bytes 98 99 98 99 to the four packed scalar payload fields 0/1/0/1 at buffer offsets 41/45/49/53. Thirty-two fresh custody links across eight retained successful classes establish the byte decoder, encoded-scalar spill, actual producer read and destination-position read. The nested operation also requires a base compatible with mask4: set selects non-NULL U+0, clear requires non-NULL U+8. Thirteen universal obligations and 1,096 independently replayed instructions qualify this increment. The alternative execution, native caller/root/cache epochs, J+0x68 publication and daemon-kext transaction identity remain unknown. No new port emission is established; the full goal remains active.

The [child-loop/output follow-up](daemon_child_loop_report.md) establishes the counted envelope around payload fields at offsets 41,45,49,53 B and the separate optional coordinate result. Raw coordinate 0x76d8ea95 decodes to 21 B under the existing codec and is copied as encoded bytes, while W27 carries the restored raw status. The loop bound is conditional on stable decoded u32 count and normal body return; arbitrary memory/body admission remains unknown.

## Retained record-message digest follow-up

[The record-digest report](daemon_record_digest_report.md) identifies the retained five words as SHA-1 of an exact 67-byte message: an 11-byte image prefix, a decoded 48-byte window at owner offset 77, and an eight-byte image suffix. The body uses the established record mask indexed by the original owner offset. Fresh source replay checks both compression blocks, every schedule word and round-entry state, byte epochs and downstream AES composition in both contexts. Native admission, the inherited body's upstream semantic origin, later missing bank fields and daemon-kext pairing remain open.
