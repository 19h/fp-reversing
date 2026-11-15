# fairplayd: conditional count-pointer lineage and saved context base

The original count-pointer store at `0x100710630` now has a checked byte lineage to the later pointer read at `0x10083e780` for both retained normal payload representatives. Each lineage crosses 149 stages, including nine derived exports and explicit API/initializer premises. The eight pointer bytes remain unchanged after their original store. This establishes conditional byte provenance through the retained models. Whole-machine initializer/caller continuity and native object/transport identity remain unknown. [PL1-PL5; PL-A1-PL-A5]

An earlier source producer is also identified: `0x1005d0f74` loads the context pointer from outer SP+0x9b8, and `0x1005d0f78` copies it to SP+0x7f38 in all 16 retained pathname-family cases. The count-pointer producer later reloads the latter cell. The full intervening chain between these earlier base-pointer and later count-pointer stages is outside this increment. [PL2-PL4; PL-A4]

| Evidence | Primary provenance and scope |
| --- | --- |
| PL1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original load/store instructions and source journals. |
| PL2 | [Count-pointer origin](daemon_count_pointer_origin_report.md), [payload count/data flow](daemon_payload_count_flow_report.md), [pathname family](daemon_state_path_family_report.md), and the 32 pinned parent checks/audit/replay artifacts listed in PL3. Their API, root, owner and class-admission premises remain dependencies. |
| PL3 | [Extractor](triage_evidence/recover_daemon_count_pointer_lineage.py), [checks](triage_evidence/daemon_count_pointer_lineage_checks.json.zst): exact parent selectors, 16 earlier base publications, both complete selected pointer routes, byte values, API/root spans and source chunks. |
| PL4 | [Independent auditor](triage_evidence/audit_daemon_count_pointer_lineage.py), [audit](triage_evidence/daemon_count_pointer_lineage_audit.json.zst): separately assembled stage order, coverage/membership checks, byte histories, PC/API transitions, source replay and two source/composition obligations. |
| PL5 | [Publication verifier](triage_evidence/verify_daemon_count_pointer_lineage_publication.py): fresh receipt comparison, reconstructed/re-solved source queries, exact manifest delta, original-input custody and path hygiene. |

Decoded checks SHA-256: `dc0f782dbed641ce994be21437845794091bd2220ee2615a8cd793c1a681f1f7`. Decoded audit SHA-256: `cd50e869fd7e5526dbe544fd31d9bc74fd1f3cf9ac83cd3359d1624496395d85`. PL3-PL4 retain all dependency and decoded interval hashes. Existing original-image bytes and retained receipts sufficed; no additional IDA data was required. [PL1-PL5]

All numerical addresses below belong to the retained private model. Outer SP=`0x6800060100`; context J=`0x6500115b20`. B denotes bytes. Source ranges are half-open. [PL2-PL4; PL-A2]

| Pointer stage | Original source | Source/destination | Retained value |
| --- | --- | --- | --- |
| Earlier base publication | `0x1005d0f74..0x1005d0f7c` | SP+0x9b8=`0x6800060ab8` to SP+0x7f38=`0x6800068038` | J, 8 B |
| Base reload | `0x1008337c4` | SP+0x7f38 to X21 | J |
| Count-pointer publication | `0x10071062c..0x100710634` | X21+28 to SP+0x71c0=`0x68000672c0` | J+0x1c=`0x6500115b3c`, 8 B |
| Later pointer consumer | `0x10083e780` | SP+0x71c0 to X12 | Same eight bytes |
| Following count/data use, established previously | `0x10083e784` | u32 count read, then pointer increment by 4 B | Count 6; advanced pointer J+32 |

The earlier base publication occurs at pathname-family interval 27, visits 177/178, in all 16 cases. Its source pointer is an unchanged incoming fixture in that interval. A binary-wide direct SP-offset store-pattern scan located three candidate stores to SP+0x7f38: `0x1005d0f78`, `0x10077fe50` and `0x10080c458`. Only the first is attributed to these retained cases; this pattern scan does not cover every possible indirect alias or establish a global unique writer. The attributed source bytes and concrete frames are independently replayed for every family case. [PL1-PL4; PL-A1,PL-A4]

| Lineage selection | Normal payload class 2 | Normal payload class 3 |
| --- | --- | --- |
| Filtered growth-parent index | 0 | 272 |
| Growth coverage index / class | 304 / 2 | 576 / 3 |
| Descriptor cohort | 0 | 68 |
| Polynomial / walk class | 0 / 0 | 2 / 2 |
| Constructor parent | 0 | 17 |
| Constructor-buffer success branch / prefix | 1 / 0 | 5 / 1 |
| Gate / table-consumer / mixing-handoff / emitter class | 0 / 0 / 0 / 0 | 1 / 1 / 1 / 1 |

The two representatives are different parent selections. Payload class 3 is not merely a second API-clobber pattern of class 2's parent. PL4 verifies the coverage links and constructor success membership against the frozen parent artifacts. [PL3-PL4; PL-A3]

```text
original count-pointer store
 -> malloc(64) success -> malloc(21) success -> malloc(48) success
 -> emitter completion -> shared table mixing -> selected handoff
 -> table consumer -> conditional gate roots -> conditional buffer root
 -> constructor-buffer success -> conditional walk root
 -> conditional terminal-node fields -> growth success
 -> record extension -> original pointer read

Eight pointer bytes preserved throughout both conditional lineages.
Initializer/root/API premises remain explicit at their actual boundaries.
```

There are 140 interval stages and nine derived exports per lineage. Their adjacent PC values match exactly, with +4 B only for the 18 declared API returns across both lineages. The first interval contains the original pointer store; every subsequent interval has no overlapping write before the relevant cut. Every export's defined pointer bytes match its predecessor and successor. The last cut is immediately after visit 86098's pointer read, before the following count read. [PL3-PL4]

The entry premises add 88 B at the gate, 8 B at the buffer prefix, 8 B at the descriptor walk and 12 B of terminal-node fields: `88 B + 8 B + 8 B + 12 B = 116 B` per lineage. These are inherited conditional premises, not new bytes supplied by this increment. All their spans and the declared API memory spans are disjoint from the 8 B pointer cell. This proves a conditional component lineage while retaining the explicit initializer/caller gaps. It does not make the separately supplied entry state a continuous native execution. [PL2-PL4; PL-A2,PL-A5]

| Validation | Checked scope/result |
| --- | --- |
| Earlier saved-base publication | 16 cases; 128 incoming source bytes checked |
| Pointer lineage | 298 stages; 296 PC/cell links; 2,368 boundary byte comparisons |
| Declared transitions | 18 API links, 18 derived exports, 78 disjoint premise spans |
| Existing journals inspected | 2,519,528 recorded visits and 70,268 write events, counted separately per lineage; shared journals contribute to both totals |
| New selected scalar replay | 18 chunks / 34 visits; 1,664 GP/SP values, 52 NZCV frames, 18 reads, 16 writes |
| Universal source obligations | 2 nonvacuous UNSAT results: saved-base cell copy and composed saved-base reload/count-pointer publication |
| New target intervals/root bytes/API return premises | 0 / 0 / 0 |

PL4 inspects recorded journals and their pinned prior audits; it does not freshly replay all 2,519,528 visits. Fresh scalar replay covers the 34 selected original instructions. The source composition joins separated blocks under the earlier X21-preservation and equal-SP-endpoint checks; it is not a theorem about every possible intervening path. [PL2-PL5; PL-A3]

Extraction takes O(image bytes+parent bytes+recorded visits+effect bytes+selected frames) time and O(image bytes+parent receipts+largest interval+compact lineage) space. The audit adds per-byte predecessor queries with O(log(writes)) lookup, scalar frame checking and proof-DAG construction; solver search is capped at 30 s/query. The eight queried cell bytes are a fixed-width component. No native API, Mach operation, hardware authentication or IDB edit occurred. [PL3-PL5]

| Assumption register | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PL-A1: The pinned image and recorded source bytes identify the same AArch64 instructions | Source semantics and all model joins | Rehash the image and parents; reconstruct/re-solve both obligations and replay selected opcodes/frames. |
| PL-A2: Declared API effects, fixtures, owner extents and separate entry premises apply only to their stated models | Conditional pointer lineage | Introduce an overlapping invalidation or mismatching incoming byte and require audit failure; native API memory effects require separate observation. |
| PL-A3: Coverage links select the actual representative parent, and no original interval/export is skipped | Both 149-stage routes and composed producer contract | Independently assemble selector order, verify parent/class membership, check every PC transition and byte predecessor; reject a missing repeated mixing batch even if endpoint PCs match. |
| PL-A4: The earlier saved-base publication is a local source producer, without an audited full chain to the later base reload | Earlier SP+0x7f38 attribution only | Trace SP+0x9b8's writer and every intervening state-file parent boundary before asserting that larger base-pointer chain. |
| PL-A5: Byte preservation across conditional roots does not prove whole-machine initializer continuity or native object ownership | Scope of all cross-stage interpretations | Inspect the initializer/caller control and lifetime joins separately; equal cell bytes and disjoint roots alone do not prove them. |

| Bounded continuation | Impact | Unresolved evidence |
| --- | --- | --- |
| Trace the saved context-base input at SP+0x9b8 | High | Its original writer and caller/context lifetime |
| Complete the earlier base-pointer boundary chain | Medium | Pathname-family to selected SIDB/SIDN constructor parents, including modeled file-control forks |
| Establish field validity and remaining snapshot roles | Medium | Network-count admission and producers/consumers of the 14 copied bytes beyond count+six-byte data |
| Join retained private owners to transport | High | Same native transaction's buffer/selector/Mach right and emission/receive evidence |

**QG1** passes: descriptive evidence requires no normative premise. **QG2** passes: PL-A1..PL-A5 specify dependencies and falsification probes. **QG3** passes for this increment: earlier base publication, selected count-pointer lineage, explicit external/entry premises and unresolved transport scope are covered; no new Mach port/right or message-emission site is established. **QG4** passes: widths, byte counts, source offsets, PC increments and verification complexity are explicit. **QG5** passes: conditional byte lineage, whole-machine continuity and native lifetime remain separate claims; earlier base-chain gaps are explicit. **QG6** passes: original source bytes, 32 pinned primary artifacts, source replay and reconstructed obligations provide provenance. **QG7** passes: impact-ranked continuation is bounded above. The full investigation remains active. [PL1-PL5]
