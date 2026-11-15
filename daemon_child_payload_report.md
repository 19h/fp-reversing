# fairplayd: nested storage consistency and byte-to-scalar payload lineage

The private token previously recovered as raw bytes `98 99 98 99` is the source of the first appended record's four scalar payload fields. Original reader `0x1008f0c3c` consumes one token byte per element; the following XOR produces the encoded scalar `(raw XOR 0x98) XOR 0x8b3dc651`. Exact source custody joins those results to the packed-word producer and destination offsets 41,45,49,53. The decoded payload is therefore 0,1,0,1 with an established local input-to-output lineage across eight retained successful branch classes. [CP1-CP6; CP-A1-CP-A6]

The nested operation at `0x1005015e8` also applies a storage consistency gate before the previously documented record-selection call. For non-NULL U, its validation-wrapper condition is `(mask4 set AND U+0 non-NULL) OR (mask4 clear AND U+8 non-NULL)`. Both earlier published storage modes satisfy their corresponding condition. The alternative branch remains a source contract without an execution witness. Native schema, caller/cache/root epoch and daemon-kext buffer identity remain unknown. [CP1-CP6; CP-A2-CP-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| CP1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; CP4 retains 131 instruction words in ten spans and twelve original authenticated pointer words. |
| CP2 | [Child-operation prelude](daemon_child_operation_report.md): immediate token writer, saved U/destination pair, tag/count inputs and outer result contract. Exact checks/audit are pinned in CP4. |
| CP3 | [Constructor-buffer paths](daemon_constructor_buffer_report.md), [record-span payload fields](daemon_record_spans_report.md) and [record selector](daemon_record_selection_report.md). Their conditional admission, API/owner and field-codec contracts remain pinned; complete prior admissions are not rerun here. |
| CP4 | [Extractor](triage_evidence/recover_daemon_child_payload.py), [checks](triage_evidence/daemon_child_payload_checks.json.zst): selected source/fixups, 32 new payload custody chains, sixteen inherited token-survival intervals and 120 replay slices. |
| CP5 | [Auditor](triage_evidence/audit_daemon_child_payload.py), [receipt](triage_evidence/daemon_child_payload_audit.json.zst): thirteen nonvacuous UNSAT obligations, eight mode controls and independent GP/SP/Q/NZCV, memory-event and logical-edge replay. No proof cuts. |
| CP6 | [Publication verifier](triage_evidence/verify_daemon_child_payload_publication.py): fresh extraction/audit, canonical SMT comparison, exact manifest delta, preserved original inputs and decoded path hygiene. |

## Nested mode gate and saved inputs

U64 pointer/address arithmetic wraps modulo 2^64; u32 scalar arithmetic wraps modulo 2^32. B denotes bytes. SP denotes the outer private-frame base, not a measured native stack placement. Original instructions retain the following fields before the nested operation branches. The generic source equation permits arbitrary tag, first word, count, U and root under its fixed dispatch phase. [CP1, CP4-CP5; CP-A1-CP-A4]

| Saved field | Width | Incoming role / retained value | Original writer |
| --- | --- | --- | --- |
| SP+0x8ca0 | 8 B | Continuation `0x100751f0c` | `0x1005015fc` |
| SP+0x6588 | 8 B | U | `0x100501600` |
| SP+0x6fc4 | 4 B | Raw tag `0x76657273` | `0x100501608` |
| SP+0x741c | 4 B | First word `0x8b3dc650`, encoded 1 | `0x10050160c` |
| SP+0x537c | 4 B | Count `0x8b3dc655`, encoded 4 | `0x100501614` |
| SP+0x2ac8 | 8 B | Encoded descriptor/root loaded from SP+0x260 | `0x100501618` |

These are distinct from the outer prelude's saved fields. In particular, SP+0x5378 contains four token bytes and SP+0x537c contains the separate encoded count. Native root continuity remains unknown; CP3 supplies an additional conditional root premise before reaching the retained successful paths. This increment adds no root definition. The ASCII spelling `vers` of the tag does not establish a conventional version schema or wire format. [CP2-CP5; CP-A2-CP-A6]

```text
U == NULL -> saved nested return
U != NULL:
  U+0 != NULL and mask4 set -------> validation wrapper 0x10057f4ec
  otherwise:
    U+8 == NULL -------------------> saved nested return
    U+8 != NULL and mask4 clear ---> validation wrapper 0x10057f4ec
    U+8 != NULL and mask4 set -----> saved nested return
```

| Storage condition | Source blocks | Established decision |
| --- | --- | --- |
| U+0 availability | `0x10086588c` | Non-NULL selects the primary mask test; NULL selects the secondary-base check |
| Primary mask4 | `0x1005a72c8` | Set reaches validation directly; clear falls through to the secondary-base check |
| U+8 availability | `0x10057530c` | NULL returns; non-NULL selects the clear-mode test |
| Secondary mask4 | `0x10080fba8` | Clear reaches validation; set returns |

Thus storage availability alone is insufficient. With only U+0 present and mask4 clear, or only U+8 present and mask4 set, the nested operation returns before validation. With both bases present, mask4 selects the matching representation. Eight scalar controls enumerate every combination of base availability and mask4; no new request or runtime state is constructed. [CP4-CP5; CP-A2-CP-A5]

Both successful routes rebuild W21=`0x8af4` before `0x10057f4ec`. The earlier clear validation call `0x10057f5ec -> 0x10045f984`, IA diversity `0x0290`, is established in CP3; it selects/defaults a record coordinate and checks span/count bounds under the earlier source contracts. This increment does not execute that helper on an alternative object. Rejection bridge `0x1008f2a1c` loads SP+0x8ca0 and branches with IA diversity `0xd08c`, preserving W27. [CP1, CP3-CP5; CP-A2-CP-A5]

## Private-byte input and packed-scalar output

The later payload setup copies the saved token pointer from SP+0x4450 to SP+0x7520 at `0x1007579e0`. It separately decodes the count from SP+0x2690 by XOR `0x8b3dc651`, zero-extends it to u64 and stores it at SP+0x7df8. The retained count is 4. The two fields do not constitute a recovered public structure type. [CP2-CP5; CP-A2-CP-A4]

At the recovered phase W8=`0x97a`, original block `0x1008f0c14..0x1008f0c68` has the following universal contract for arbitrary byte b, pointer P, u64 index i and u32 start position p:

```text
read address = u64(P+i)
W23 = zero_extend32(b XOR 0x98) XOR 0x8b3dc651
[SP+0x6428] / u32 = u32(p + 4*low32(i))
```

The input address uses the entire u64 index. Destination position arithmetic uses its low32 bits and wraps in u32. The generic theorem does not imply index bounds, input readability or room for every destination word. In the retained eight successful classes, the actual four indices are exactly 0,1,2,3, p=41 B and the input pointer is SP+0x5378. [CP4-CP5; CP-A2-CP-A5]

Combining CP2's token writer with the new decoder gives an additional compact codec relation. If the writer input is P32, its four raw bytes are BE(P32 XOR `0xec2d0e54`); decoding each with XOR `0x98` gives BE(P32 XOR `0x74b596cc`). For P32=`0x74b496cd`, the decoded four-byte sequence is `00 01 00 01`. This algebraic composition is proved for every P32; the subsequent complete payload loop and packed-word writer remain qualified by their separate prior contracts. [CP2, CP4-CP5; CP-A1-CP-A5]

```text
immediate writer input 0x74b496cd
  -> raw private bytes 98 99 98 99 at SP+0x5378
  -> pointer SP+0x4450 -> SP+0x7520
  -> LDRB at 0x1008f0c3c, index 0..3
  -> encoded scalar in W23
  -> spill at 0x1008f3940, SP+0xab28
  -> actual producer read 0x100618880
  -> existing packed-word producer/writer
  -> F+41, F+45, F+49, F+53

same iteration:
  p+4*i -> SP+0x6428 -> read 0x100584edc -> destination offset
```

| Index | Raw token byte | Encoded scalar W23 | Decoded scalar | Destination offset / B | Actual stored bytes |
| --- | --- | --- | --- | --- | --- |
| 0 | `0x98` | `0x8b3dc651` | 0 | 41 | `bf1be39e` |
| 1 | `0x99` | `0x8b3dc650` | 1 | 45 | `d56dc2be` |
| 2 | `0x98` | `0x8b3dc651` | 0 | 49 | `8568ed1d` |
| 3 | `0x99` | `0x8b3dc650` | 1 | 53 | `86b43775` |

Each field occupies 4 B under CP3's packed-scalar codec; its raw bytes include auxiliary packed bits and the position-dependent storage mask. The 4 B input therefore supplies four values represented by 16 B of packed output. This is scalar conversion and serialization, not an unmodified byte copy. A higher-level version-number interpretation remains a candidate. [CP2-CP5; CP-A2-CP-A6]

For every one of the 32 input/output links, fresh custody establishes the pointer-load writer at `0x1007579e0`, unchanged W23 until the scalar spill, that spill as the last writer consumed by `0x100618880`, and the original position store `0x1008f0c34` as the last writer consumed by `0x100584edc`. Matching the scalar's numeric value alone is not used as pointer or byte provenance. The existing packed-field receipt supplies the producer/writer contract and actual final bytes. [CP3-CP6; CP-A2-CP-A4]

The token bytes and saved pointer survive all four constructor prefixes and sixteen retained successful continuation intervals without an overlapping source store. Neither of the two declared API-return invalidation sets per successful branch overlaps those fields. Their inherited values agree with the earlier prelude. These are checks within the pinned conditional model and its declared allocation/free transitions, not proof of a continuous native initializer/caller epoch. No new return value, owner or guest byte is supplied. [CP2-CP6; CP-A2-CP-A4]

## Original dispatch mappings

| Index32 | Target | IA modifier |
| --- | --- | --- |
| `0x1362` | `0x100751f0c` | `0xd08c` |
| `0x3efa` | `0x10086588c` | `0xa298` |
| `0x3eda` | `0x1008f2a1c` | `0xa298` |
| `0x2ed8` | `0x1005a72c8` | `0x82cf` |
| `0x2eb9` | `0x10057530c` | `0x82cf` |
| `0x717c` | `0x10057f4ec` | `0xd21b` |
| `0x718f` | `0x10057530c` | `0xd21b` |
| `0x8d0e` | `0x10080fba8` | `0x4ae9` |
| `0x8d0f` | `0x1008f2a1c` | `0x4ae9` |
| `0x7492` | `0x10057f4ec` | `0x7dc1` |
| `0x7429` | `0x1008f2a1c` | `0x7dc1` |
| `0x1f62` | `0x1008f3914` | `0x4d13` |

The original format-12 words match their target, IA diversity and address-diversity-0 fields. Selected logical transfers are independently checked against the next retained PC and modifier. Native hardware authentication and concurrent pointer mutation remain unknown. [CP1, CP4-CP6; CP-A1,CP-A4]

## Verification, assumptions and bounded continuation

Independent replay covers 120 selected slices and 1,096 original instruction visits: 38,912 GP/SP values, 38,912 Q values, 1,216 NZCV frames, 256 reads, 104 writes and 48 logical authenticated edges. Thirteen nonvacuous UNSAT obligations cover nested saved fields and gate predicates, pointer/count forwarding, all-u8 decoding, index/position arithmetic, spill/read addresses and writer/reader composition. Eight scalar controls cover storage modes. Complete earlier admissions and field-codec corpora remain pinned; the new work adds 32 explicit lineage links rather than reclassifying them as native executions. [CP4-CP6]

Extraction costs O(parent receipt bytes + retained visits/events + custody scans) time and space; selected replay costs O(visits*32 + byte events). Source proofs add their expression-DAG size and solver search; each query has a 30 s timeout. No generic loop-termination or native performance bound is claimed. Checks, audit and manifest use zstd archives with decoded round-trip checks. Existing original source and retained traces suffice; IDA is not accessed. [CP1-CP6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CP-A1: Exact pinned image, fixups and receipts apply | Opcodes, constants, dispatch and inherited codecs | Rehash source and parents, compare selected instruction words and original format-12 fields, regenerate source/proof receipts. |
| CP-A2: Fixed source phases and prior conditional admissions apply | Four prefix and eight success classes, 32 lineage links | Replay complete selected GP/SP/Q/NZCV and byte events; check each class/interval identity and retain the earlier root/API/owner premises. |
| CP-A3: Coherent separated memory and inherited byte definitions apply | Token survival, pointer forwarding and output custody | Check every overlap and API invalidation; verify each current last writer and preserved register interval. Native epoch continuity remains unknown. |
| CP-A4: Sequential memory and logical authentication apply | Saved continuation, byte reads and source ordering | Compare next PCs/modifiers and actual load/store order; require separate native scheduling/PAC/lifetime evidence. |
| CP-A5: Generic local equations do not establish complete arbitrary-input execution | All-u8 decoder, u64 indices, modular destination and mode controls | Preserve wrap, observed indices and fixed phases; do not infer arbitrary loop bounds, readable ranges, allocator feasibility or native alternative admission. |
| CP-A6: Local payload and tag do not establish a public format or external exposure | `vers` interpretation, operation identity and daemon-kext conclusions | Require independent native consumers, caller/context publication and matching Mach/IOKit buffer bytes/transaction identity. |

| Impact | Bounded next evidence | Present limitation / falsification target |
| --- | --- | --- |
| High | Close the alternate mode's full validation and payload-writing contracts | Its mode gates are proved; no alternative execution or native cache/root epoch is observed. |
| High | Follow the saved nested result through the outer equality successor and parent/context publication | The earlier outer raw-status gate is exact; J+0x68 publication remains unknown. |
| High | Pair the resulting tagged scalar record with daemon Mach/IOKit payloads | This increment establishes no new port, right transfer, external emission or matched daemon-kext transaction. |
| Medium | Prove the generic element-count loop and complete arbitrary-input conversion | Four observed indices and generic per-byte decoding do not alone establish complete loop bounds or arbitrary array admission. |
| Medium | Establish the tag's semantic schema using independent consumers | Input-to-output conversion is exact; a conventional version-vector name remains unknown. |

**QG1**: factual source/data-flow analysis. **QG2**: CP-A1-CP-A6 identify assumptions and probes. **QG3**: the nested-mode and payload-lineage increment is covered; the full interface goal remains active. **QG4**: widths, byte units, wrap, counts and complexity are explicit. **QG5**: distinct raw bytes, encoded scalars, packed output, source modes and native boundaries. **QG6**: delivery requires fresh source/replay/proof/publication verification against pinned primary artifacts. **QG7**: impact-labeled adjacent opportunities and unresolved interfaces are explicit.

The [subsequent loop/output/status report](daemon_child_loop_report.md) closes the counted control envelope: exact `vers` initializes zero, the gate compares a u64 count to a zero-extended u32 index, and the back edge reloads/increments the saved index. A stable decoded u32 count plus normal body return gives exactly C iterations. The eight retained four-element cases then emit an optional encoded coordinate and restore the nested raw status through the outer equality successor. Complete arbitrary-body admission/termination and native transaction identity remain unknown.
