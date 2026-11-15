# fairplayd: saved context-base lineage through SIDB/SIDN controls

The retained eight-byte context-base alias now has a checked route from its original SP+0x7f38 store through the SIDB/SIDN state-file branches to the later base reload and count-pointer publication. All 76 retained constructor contexts are covered. They originate from pathname-family case 0, one admission/open selection, two later ABI patterns and two synthetic file-prefix words. This closes the previously unresolved conditional earlier-base route; native object lifetime, whole-machine initializer continuity and daemon-kext transaction identity remain unknown. [SB1-SB6; SB-A1-SB-A5]

The graph contains 481 distinct intervals and 2,304 route-stage occurrences, with 2,228 adjacent PC/byte links. Eight routes have 29 stages, 60 have 30 and eight have 34. Shared prefixes are checked once as distinct intervals and referenced by every dependent route. The current audit inspects 74,288 recorded visits and 4,834 write events; fresh scalar replay covers 230 selected original instructions. [SB3-SB5]

| Evidence | Primary provenance and scope |
| --- | --- |
| SB1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original stack stores, reloads and count-pointer instructions. |
| SB2 | [Pathname family](daemon_state_path_family_report.md), [admission](daemon_state_file_admission_report.md), [metadata](daemon_state_file_metadata_report.md), [file input](daemon_state_file_input_report.md), [word routing](daemon_state_word_routing_report.md), [path removal](daemon_state_path_removal_report.md), and [container construction](daemon_state_container_construction_report.md). Their checks/audits retain conditional source intervals, declared API effects and scalar-output premises. |
| SB3 | [Extractor](triage_evidence/recover_daemon_saved_base_statefile_lineage.py), [checks](triage_evidence/daemon_saved_base_statefile_lineage_checks.json.zst): exact ancestry, distinct stages, source events, premise spans, route order and selected scalar chunks. Twenty parent receipts are pinned. |
| SB4 | [Independent auditor](triage_evidence/audit_daemon_saved_base_statefile_lineage.py), [audit](triage_evidence/daemon_saved_base_statefile_lineage_audit.json.zst): independent finite-parent derivation, ordered incoming byte queries, invalidation exclusions, every route link, X21 preservation and two source-composition controls. |
| SB5 | [Publication verifier](triage_evidence/verify_daemon_saved_base_statefile_lineage_publication.py): fresh extraction/audit comparison, reconstructed and re-solved queries, exact manifest delta, input custody and path hygiene. |
| SB6 | [Network-storage report](daemon_context_network_storage_report.md), [pointer origin](daemon_count_pointer_origin_report.md), [later pointer lineage](daemon_count_pointer_lineage_report.md). Their source-event anchors join the new graph to the earlier X22 save and both normal payload pointer consumers. Their native/initializer and 116 B per-lineage entry premises remain dependencies. |

Decoded checks SHA-256: 3e11e65054d84710e24465f20e9004075c0e924f53a7d9458a8cd293087f2347. Decoded audit SHA-256: b6d4842ecf171d6892730d174c23dd2617a45b71eac053847a5146e5a5d8313b. SB3-SB4 retain source/dependency/parent and decoded interval hashes. Existing original bytes and frozen receipts sufficed; no new IDA data was required. [SB1-SB5]

All addresses below are retained private-model addresses. J=`0x6500115b20` is the 552 B context. Outer SP=`0x6800060100`. B denotes bytes. Source pointer additions use AArch64 modulo-2^64 arithmetic. [SB2-SB4; SB-A2]

| Operation | Original PC | Component location/value |
| --- | --- | --- |
| Earlier X22 save, established by SB6 | `0x1004cf268` | SP+0x9b8=`0x6800060ab8` receives J, 8 B |
| Saved-base copy, new graph entry | `0x1005d0f74/0x1005d0f78` | Reload saved J; store SP+0x7f38=`0x6800068038`, 8 B |
| Constructor base reload, all 76 graph exits | `0x1008337c4` | X21 receives J from the same absolute alias cell |
| Count address and publication | `0x10071062c/0x100710630` | X9=J+28; store SP+0x71c0=`0x68000672c0`, 8 B |
| Later normal consumers, established by SB6 | `0x10083e780` | Count-pointer cell read in payload classes 2/3 |

The first new stage begins at pathname-family interval 27, visit 177, before the original saved-base load/store. Its store is the same event, decoded interval and case as the earlier storage report's family-case-0 endpoint. That event-level overlap joins the two local routes without introducing an additional pointer fixture. The next family interval reaches the pending SIDB lstat request. [SB3-SB4,SB6; SB-A3]

```text
earlier original X22 save -> saved-base copy
                               |
                               v
                     family case 0 / admission 0 / open 0
                               |
                  SIDB metadata and exact-count read
                               |
              +----------------+----------------+
              |                                 |
       metadata ABI 0                    metadata ABI 1
       prefix 0 / 0x7000c                prefix 0 / 0x7000c
              |                                 |
              +------ four removal parents -----+
                               |
                     19 SIDN-query routes each
                               |
                 76 constructor base reloads
                               |
                      count-pointer store
                               |
              prior conditional later pointer lineages
```

| Removal context | Word-routing parent | Synthetic raw BE32 prefix | Input/metadata context | Constructor parents |
| --- | --- | --- | --- | --- |
| 0 | 0 | 0 | 0 | 0..18 |
| 1 | 2 | 0x7000c | 0 | 19..37 |
| 2 | 21 | 0 | 1 | 38..56 |
| 3 | 23 | 0x7000c | 1 | 57..75 |

All four select timestamp case 0, seconds=0 and nanoseconds=0. The metadata contexts use ABI patterns 0/1; their input continuations use 1/0, word continuations 0/1, removal continuations 1/0 and constructor continuations 0/1. These are declared clobber controls, not native observations. Constructor parent 17 shares the first row's earlier SIDB path with parent 0; it differs in the later removal route. They are the actual parents of the previously reported normal payload representatives. [SB2-SB4,SB6; SB-A3]

The shared admission selects lstat status 0, mode `0x81a4`, open case 0 without a separate once-callback invocation, and synchronization status 0. The following metadata continuation declares descriptor 7, fstat status 0 and size 4,096 B. The nonnull allocation declares the same logical 4,096 B extent; read return is exactly 4,096. The read invalidates the payload, and the later four-byte prefix remains an explicit synthetic definition. Neither native file contents nor a native successful read are recovered. Both prefix controls are outside the source interval `[0x60003,0x7000c)`. [SB2-SB4; SB-A2-SB-A3]

Each removal parent has 19 SIDN-query origins: two link-mode controls, twelve errno controls, three failed-unlink controls and two synchronization sequences. The independent ordering derives these origins from query indices and checks them against parent metadata. Each SIDN continuation selects lstat status 0, link mode `0xa000`, and the first retained buffer-free return before the base reload/count-pointer store. Other SIDN cleanup paths and constructor allocation results remain separate prior coverage; this increment does not claim a full Cartesian product of all file/admission controls. [SB2-SB4; SB-A3]

| Transition class | Supplied/opaque component | Relation to the saved alias |
| --- | --- | --- |
| Imported API returns | Declared register clobbers, errno/stat/lock/once output invalidations, buffer allocation/retirement premises | All declared memory spans checked disjoint from the alias's 8 B |
| Scalar-output boundaries | Mode u16, size u64, timestamps u64, errno u32 and synthetic four-byte file prefix | Explicit output spans checked disjoint; resume at the same pending source PC |
| Original source intervals | Recorded instructions and source writes | Initial alias store is the only overlapping write before each selected exit |
| Source register interval | X21 from the base reload to count address formation | 83 frames retain J; 81 intervening instructions neither define X21/W21 nor call |

The alias cell is absolute outer-frame storage even while source routines use inner SP values. Every route compares its eight incoming bytes to its predecessor, rather than assuming that equal stack-offset names imply the same cell. API returns advance the source PC by 4 B and identify the preceding call site; supplied-output continuations resume at the same source PC. Zero-visit output/API intervals remain explicit stages. Existing parent instruction/state audits are pinned dependencies; the new audit does not freshly replay every retained visit or all GP/Q/API state joins. [SB2-SB4; SB-A2-SB-A4]

The composed source proof uses an arbitrary byte-addressed initial memory, arbitrary 64-bit context pointer and arbitrary outer SP. It executes six original instructions in four blocks: the earlier X22 save, the saved-base load/store pair, the constructor base reload, and the count-pointer ADD/STR pair. Loads read the byte memory produced by preceding stores. With equal SP endpoints and intervening alias-byte/X21 preservation supplied by the interval audits, the final stored value is context+28 at SP+0x71c0. This is a component composition, not an assertion that those blocks execute consecutively. Arbitrary pointer memory accessibility is not proved. [SB1,SB3-SB4,SB6; SB-A1-SB-A4]

The second nonvacuous source control inserts a one-bit overwrite of the alias's least significant byte before the constructor reload. The original equality then becomes impossible for every context/SP value. It tests the composition's dependence on write exclusion; it is not a recovered target write or a claim of external write access. [SB4; SB-A4]

| Validation | Checked scope/result |
| --- | --- |
| Finite ancestry | 76 constructor contexts; four word parents; one pathname-family source |
| Distinct intervals / route occurrences | 481 / 2,304; twelve distinct zero-visit stages retained |
| All route links | 2,228; 1,696 API returns and 532 supplied-output resumptions |
| Boundary byte comparisons | 17,824 B across all route links; 3,840 distinct incoming fixture-byte queries |
| Declared effects | 333 distinct API-transition stages, 147 scalar-output stages; 731 disjoint premise spans |
| Original source joins | One earlier alias anchor and 76 exact prior constructor read/store anchors |
| Existing journals inspected | 74,288 distinct recorded visits / 4,834 write events |
| Base/count register checks | 76 reloads/stores; 6,308 X21 frames; 6,156 definition/call exclusions |
| Fresh selected scalar replay | 153 chunks / 230 visits; 12,256 GP/SP values, 383 NZCV frames, 77 reads, 77 writes |
| Source obligations | Two nonvacuous UNSAT results: unchanged-memory composition and overlapping-byte negative control |
| New target intervals/root bytes/API return premises | 0 / 0 / 0 |

The new graph joins to the prior later pointer lineage through constructor parents 0 and 17 and their exact first-free interval/read/store events. It closes the conditional saved-base route that those reports left open. Their separate initializer/control roots, including 116 B per later representative, do not disappear. No native filesystem/API/Mach operation, hardware authentication or IDB edit occurred. [SB2-SB6; SB-A5]

Extraction takes O(parent bytes+unique recorded visits+effect bytes+chain links) time and O(parent receipts+largest interval+compact stages/chains) space. The independent audit adds O(32C+proof DAG) frame/proof construction for C selected frames; its eight-byte fixture queries use ordered overlays. Shared stages are materialized once, while all route links are checked separately. Solver search is capped at 30 s/query. [SB3-SB5]

| Assumption register | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SB-A1: Pinned original bytes and twenty parent receipts identify the same source/model epochs | All source semantics and joins | Rehash image/parents, replay selected original opcodes and reconstruct both obligations. |
| SB-A2: Declared API effects, owners and scalar outputs apply only to their recorded intervals | Conditional base-pointer byte continuity | Remove a definition or introduce a mismatching/overlapping memory effect and require audit rejection; native effects need independent observation. |
| SB-A3: The finite ancestry/order selects all 76 retained constructor parents, without extending their admission coverage | Coverage and earlier/later event joins | Independently derive four prefix parents, every query origin, exact source PCs and interval hashes; reject a skipped zero-visit or repeated stage. |
| SB-A4: Alias bytes, endpoint SP and intervening X21 are preserved at the stated cuts | Six-instruction source composition | Check every original write and declared span, all byte/PC links and X21 definitions; the one-bit overwrite control must break the equality. |
| SB-A5: A component lineage through separately declared API/output/entry premises does not establish whole-machine/native object continuity | Scope of context lifetime and daemon-kext interpretation | Observe caller/initializer ownership, actual file outputs and the same native buffer/selector/right transaction before asserting a native join. |

| Bounded continuation | Impact | Unresolved evidence |
| --- | --- | --- |
| Join retained private data to native transport | High | Same transaction's daemon buffer, selector, Mach right and emission/receive sites |
| Recover caller/context lifetime admission | High | Restored X22's original owner and initializer/control joins; earlier local and state-file base routes are now checked |
| Establish native external-input semantics | Medium | Actual filesystem/property/cache values and native effects versus the declared scalar/API controls |
| Resolve remaining context/payload fields | Medium | Application type of the 14 B tail, count admission beyond six, later cache/bank producers |

**QG1** passes: descriptive technical claims require no normative premise. **QG2** passes: SB-A1..SB-A5 specify dependent scope and falsification probes. **QG3** passes for this increment: original routine roles, file/API control interfaces and conditional base/count flow are covered; no new Mach port/right or emission site is established. **QG4** passes: widths, modular additions, byte extents, provenance counts and complexity are explicit. **QG5** passes: finite branch coverage, conditional component lineage and whole-machine/native lifetime remain distinct. **QG6** passes: original bytes, twenty pinned primary receipts, exact event anchors, independent replay and reconstructed obligations provide provenance. **QG7** passes: continuation is bounded and impact-ranked above. The full investigation remains active. [SB1-SB6]
