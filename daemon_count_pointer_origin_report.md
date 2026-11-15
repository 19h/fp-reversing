# fairplayd: count-pointer initialization and container snapshot

Storage follow-up: [The network-storage report](daemon_context_network_storage_report.md) identifies original zeroing of J+[32,52), six overwritten data bytes and a 14 B tail preserved in checked raw-success controls. This supplies initialization/write-coverage evidence for the snapshot tail; its application meaning and a native constructor/publication/snapshot epoch join remain unknown.

Current lineage extension: [The lineage report](daemon_count_pointer_lineage_report.md) establishes conditional preservation of the eight count-pointer bytes through 149 stages for each normal payload representative, while retaining 116 B of explicit entry roots per lineage. It separately identifies the earlier SP+0x7f38 producer at 0x1005d0f78. Whole-machine initializer continuity, the earlier base-pointer boundary chain and native lifetime remain unknown.

Original `0x10071062c..0x100710634` initializes the previously inherited count-pointer cell: `X9 = context + 0x1c; [outer_SP+0x71c0] = X9`. The retained constructor reloads that cell and passes it as the source of a 24 B copy into a newly allocated 64 B container at offset 24. This establishes a constructor-side pointer producer and its immediate use. Whole-machine initializer/caller continuity and native daemon-kext transaction identity remain unknown. [CP1-CP5; CP-A1-CP-A5]

| Evidence | Primary provenance and scope |
| --- | --- |
| CP1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original load, pointer arithmetic, store, reload and byte-copy instructions. |
| CP2 | [State-container construction](daemon_state_container_construction_report.md) and pinned checks/audit: 76 constructor contexts, 12 declared free-return paths per context, and declared fresh 64 B allocation success. Existing fixture/API premises remain dependencies. |
| CP3 | [Extractor](triage_evidence/recover_daemon_count_pointer_origin.py), [checks](triage_evidence/daemon_count_pointer_origin_checks.json.zst): all 912 pointer paths, 76 snapshot transfers and four representative source/frame sets. |
| CP4 | [Independent auditor](triage_evidence/audit_daemon_count_pointer_origin.py), [audit](triage_evidence/daemon_count_pointer_origin_audit.json.zst): register-definition scans, fixture and source-event checks, selected full scalar replay, explicit byte post-increment semantics and eleven universal source obligations. |
| CP5 | [Publication verifier](triage_evidence/verify_daemon_count_pointer_origin_publication.py): fresh extraction/audit comparison, reconstructed/re-solved source queries, manifest delta, immutable input custody and path checks. |
| CP6 | [Count/data consumer](daemon_payload_count_flow_report.md), whose checks are pinned by CP3: later `0x10083e780` loads the same numerical cell/value in classes 2/3; `0x10083e784` reads the count and advances to data. This is a layout/value correspondence across separately retained epochs. |

Decoded checks SHA-256: `e5b618f3d9d245d5d0a3919fae60d4be635905e32b34686b82dcec5d1be9dcb6`. Decoded audit SHA-256: `b82f4d46a1ab485a7aa2359680e4b2e008f51a0137972f56ad97f52335be112c`. CP3-CP4 record parent/dependency and decoded interval hashes. The associated source and receipts sufficed; no additional IDA data was required. [CP1-CP5]

Addresses below are private-model addresses. J=`0x6500115b20` is the retained 552 B context; outer SP=`0x6800060100`; S=`0x6600040000` is the declared fresh 64 B owner. B denotes bytes. Ranges are half-open. [CP2-CP4; CP-A2]

| Operation | Original PC | Retained source/destination | Established role |
| --- | --- | --- | --- |
| Reload context base | `0x1008337c4` | `[SP+0x7f38]`, address `0x6800068038`, to X21 | Incoming saved pointer J |
| Form count pointer | `0x10071062c` | `X9 = X21+0x1c` | J+28=`0x6500115b3c` |
| Publish count pointer | `0x100710630` | 8 B store at SP+0x71c0=`0x68000672c0` | Pointer cell initialized before pending malloc(64) at `0x100710758` |
| Reload snapshot source | `0x100595f5c` | Same pointer cell to X20 | Constructor-side use after declared malloc success |
| Invoke internal copy | `0x100595f84` | X0=J+28, X1=S+24, X2=24 | Logical target `0x10046f89c`, modifier `0x34a1` |
| Copy byte pairs | `0x10046f9e4..0x10046fa24` | J+[28,52) to S+[24,48) | Eight post-incrementing read/store pairs, repeated three times |
| Later payload pointer read | `0x10083e780` | Same numerical cell/value | Conditional pointer-byte lineage established in the later lineage report; whole-machine join unknown |

The context-base load occurs at visit 29, address formation at visit 111 and pointer store at visit 112 in every retained free-return path. X21 equals J in all 83 frames numbered 30..112. The 81 intervening instructions at visits 30..110 neither define X21/W21 nor issue a call. The pointer store is the only write overlapping its 8 B cell in each interval. This identifies a source producer rather than deriving provenance from an end-state value alone. The earlier producer of `[SP+0x7f38]` was outside this increment; the subsequent lineage report identifies its local source copy at `0x1005d0f78`. [CP3-CP4; CP-A3]

Each successful allocation interval inherits the pointer bytes from its first free-return parent. Its allocation premise does not invalidate those 8 B, and no source write overlaps the cell. There are 76 checked links, or `76 * 8 B = 608 B` of boundary comparisons. The existing parent models only the first free-return path's allocation continuation; the other 11 paths per context are not treated as independently continued allocations. [CP2-CP4; CP-A2]

```text
saved context-base cell -> X21=J
                            |
                            + 28 B -> saved count-pointer cell
                                         |
                       declared malloc(64) success
                                         |
                                         v
J+[28,52) -- internal copy, 24 B --> S+[24,48)

separate later epoch: same cell/value -> u32 count -> J+32 data
                       complete intervening epoch chain unknown
```

| Snapshot source | Snapshot destination | Width | Current interpretation |
| --- | --- | --- | --- |
| J+[28,32) | S+[24,28) | 4 B | Count field; retained little-endian u32 6 |
| J+[32,38) | S+[28,34) | 6 B | Same offsets as the six-byte network-data publication and payload input |
| J+[38,52) | S+[34,48) | 14 B | Additional copied context bytes; application role unknown |

All 24 source bytes are unchanged incoming fixtures before their individual reads. The retained snapshot is `06 00 00 00` followed by 20 zero bytes. The copy length is the immediate 24 at the call; it is not derived from the retained count 6. Consequently the snapshot spans more than the known count-plus-six-byte field. Matching offsets and zero values establish neither the remaining field types nor a native object lifetime. [CP3-CP4,CP6; CP-A2,CP-A4]

The source obligations quantify arbitrary 64-bit pointers and an arbitrary 8-bit transferred value: the saved-base load uses SP+0x7f38; the pointer producer stores context+28 at SP+0x71c0; the reload uses the latter cell; each of eight distinct original byte pairs transfers exactly one byte and advances both pointers by 1 B. Addition follows AArch64 modulo-2^64 semantics. These local theorems do not establish memory accessibility for arbitrary pointers. [CP4; CP-A1]

| Validation | Checked result |
| --- | --- |
| Constructor/free-return coverage | 76 contexts, 912 paths, 912 pointer stores / 7,296 stored bytes |
| X21 preservation | 75,696 concrete frame checks; 73,872 instruction-definition/call exclusions |
| Snapshot transfers | 76 copies / 1,824 bytes; 3,648 original byte-instruction checks |
| Representative full scalar replay | Contexts 0/19/38/57; 108 chunks / 208 visits; 10,112 GP/SP values, 316 NZCV frames, 104 reads, 100 writes |
| Selected post-increment replay | 192 original byte load/store instructions |
| Universal source queries | 11 nonvacuous obligations, each UNSAT for contract violation |
| New target intervals/root bytes/API return premises | 0 / 0 / 0 |

CP3 extraction is O(P+V+E+32C) time and O(parent receipts+largest interval+selected chunks) space; CP4 adds proof-DAG construction and solver search capped at 30 s/query. P is decoded parent size, V examined visits, E examined event/fixture bytes and C selected frames. No native API, Mach operation, hardware authentication or IDB edit occurred. [CP3-CP5]

| Assumption register | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CP-A1: Pinned image bytes decode as AArch64 instructions | All source contracts | Rehash the image; compare every selected opcode and reconstruct all eleven obligations. |
| CP-A2: Retained fixtures, allocation and free-return premises apply only to their declared epochs | Pointer values, snapshots and boundary links | Change a fixture or invalidate the cell; require fresh extraction/audit failure. Native allocator/object observations would test extension beyond this model. |
| CP-A3: Equal X21 frames are accompanied by no intervening register definition/call | Pointer producer attribution | Scan all intervening original instructions and reject a W21/X21 write, call or mismatching frame. |
| CP-A4: Copy events retain individual read/write epochs and post-increment semantics | 24 B snapshot map | Check all 3,648 byte instructions and pairwise source/destination increments; replay arbitrary byte values independently of retained zeros. |
| CP-A5: Later cell/value correspondence does not prove complete lifetime continuity | Constructor/consumer comparison only | Audit every intervening parent boundary and overwrite before asserting a full retained chain; native pointer/owner epochs are a separate probe. |

| Bounded continuation | Impact | Specific unresolved evidence |
| --- | --- | --- |
| Establish initializer-to-current-caller control continuity | High | Caller/control lifetime across the inherited 116 B of separate entry premises; the later lineage report closes the conditional pointer-byte route |
| Trace the earlier saved context-base cell and network-field admission | High | Local saved-base writers established by follow-ups; full earlier base route, count validity and constructor object epoch |
| Identify the remaining 14 snapshot bytes | Medium | Explicit zero initialization and retained write exclusion established by the storage follow-up; independent application consumers/types remain unknown |
| Join private owners to observed transport | High | Same native transaction's buffer, selector, Mach right and emission/receive evidence |

**QG1** passes: descriptive source and evidence claims require no normative premise. **QG2** passes: CP-A1..CP-A5 give dependent scope and falsification probes. **QG3** passes for this increment: pointer producer, local control/data flow, allocation interface and later correspondence are reported; no new Mach port/right or emission site is established. **QG4** passes: byte widths, offsets, modular pointer arithmetic and reproduction counts are explicit. **QG5** passes: branch coverage is separated from continued allocation coverage; retained and native epoch gaps remain explicit unknowns. **QG6** passes: original-image bytes, pinned parent receipts and fresh source obligations supply provenance. **QG7** passes: impact-ranked continuation is bounded above. The full investigation remains active. [CP1-CP6]
