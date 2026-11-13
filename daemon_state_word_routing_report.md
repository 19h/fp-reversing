# SIDB first-word range routing and repeated pathname query

The first four SIDB bytes participate in two unsigned range comparisons. Under the retained incoming phase, let `w=BE32(buffer[0:4])`. The source copies `w XOR 0x8b3dc651` into two private u32 cells, then distinguishes `w<0x60003`, `0x60003<=w<0x7000c`, and `w>=0x7000c`. The middle interval reaches a pending malloc(64); the other two paths converge on a three-adapter chain that requests `___error`, clears the borrowed four-byte errno cell, and requests `lstat` on the same inline SIDB pathname. The interval's format meaning and the eventual meaning of the allocation remain unknown. [WR1-WR5; WR-A1-WR-A7]

```text
explicit synthetic four-byte prefix; remaining 4092 B unknown
     |
     +-> d = BE32(prefix) XOR 6703cce9
     +-> two private u32 stores = d XOR ec3e0ab8
     |                         = BE32(prefix) XOR 8b3dc651
     |
     +-> lower unsigned comparison
          +-- w < 60003 ----------------------------+
          +-- w >= 60003 -> upper comparison        |
                              +-- w >= 7000c --------+
                              +-- w < 7000c          |
                                   |                 |
                            record-word leaf         |
                            -> malloc(64) pending    |
                                                     v
                             same SIDB object -> adapters
                                   -> ___error() request
                                   + declared borrowed pointer return
                                   -> u32 errno = 0
                                   -> lstat(object+32, SP+40) pending
```

These are conditional original-source continuations with synthetic prefixes. They do not identify actual file contents, report a native file access, or establish a daemon-kext transaction. The second `lstat` request is a new call site after the selected buffer-read path, distinct from the earlier pre-open pathname query. No lookup identity, revalidation policy or successful filesystem outcome is inferred. [WR1-WR5; WR-A2-WR-A7]

| Evidence | Primary artifact and scope |
| --- | --- |
| WR1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original opcodes, logical fixups and states in the [extractor](triage_evidence/recover_daemon_state_word_routing.py). |
| WR2 | [File-input report](daemon_state_file_input_report.md) and [parent checks](triage_evidence/daemon_state_file_input_checks.json.zst): 256 contexts, three timestamp controls each, ending before the first undefined buffer-byte read. |
| WR3 | [Current checks](triage_evidence/daemon_state_word_routing_checks.json.zst): 2316 synthetic-prefix cases, 1543 borrowed-errno continuations and 3859 source intervals. |
| WR4 | [Auditor](triage_evidence/audit_daemon_state_word_routing.py) and [audit](triage_evidence/daemon_state_word_routing_audit.json.zst): independent original-instruction replay, exact state/owner joins and twelve nonvacuous equations. |
| WR5 | [Publication verifier](triage_evidence/verify_daemon_state_word_routing_publication.py): exact coverage, rebuilt equations, original-byte checks, decoded-payload path hygiene, preserved inputs and publication delta. |

## Private word representations

The incoming boundary is `0x1005b94fc`, before `LDRB W10,[X28,W10,UXTW]`, with X28=A=`0x6600030000`, W10=0 and an initially undefined 4096 B owner. Only bytes A..A+3 receive explicit control values. The same original four loads read offsets 0,1,2,3 in every retained prefix continuation. No later file byte is supplied or read in this increment. [WR1-WR4; WR-A2,WR-A3,WR-A5]

The preceding expression `d=w XOR 0x6703cce9` is rebuilt from original source, then `EOR W28,W19,W0` at `0x1005b95b8` uses the recorded W0=`0xec3e0ab8`. Thus `0x6703cce9 XOR 0xec3e0ab8=0x8b3dc651`, and both stores represent `w XOR 0x8b3dc651`. This cancellation does not prove that the file is encrypted or that either stored word is a status. [WR1-WR4; WR-A1-WR-A3]

| Original site | Destination in retained model | Exact u32 representation |
| --- | --- | --- |
| 0x1005b95bc | 0x6800069094 = incoming SP+0x8f94 | w XOR 0x8b3dc651 |
| 0x10059ab14 | 0x6800067144 = incoming SP+0x7044 | Same representation |

The surrounding private frame and scalar phase constants are premises. The word's later storage consumer, field type, persistence and native exposure remain unknown. In particular, the numerical XOR constant also appearing in other raw records does not assign all such fields one semantic type. [WR1-WR4; WR-A2,WR-A3,WR-A7]

## Exact unsigned range dispatch

The lower fragment `0x1005fa9e0..0x1005faa8c` reduces its compared value to `u32(w-0x60003)` and compares it unsigned against `u32(-0x60003)=0xfff9fffd`. The `lo` result is true exactly when `w>=0x60003`. The upper fragment `0x10054e94c..0x10054e9f8` similarly compares `u32(w-0x7000c)` against `u32(-0x7000c)=0xfff8fff4`; its `lo` result is true exactly when `w>=0x7000c`. All additions/subtractions wrap modulo 2^32. These are original-source equations, not signed comparisons or host-integer approximations. [WR1,WR3-WR5; WR-A1-WR-A3]

| Source range | Original dispatch index | Logical next target | IA modifier |
| --- | --- | --- | --- |
| w < 0x60003 | Lower 0x3c5d | 0x1006655b0 | 0x8aec |
| w >= 0x60003 | Lower 0x450b | 0x10054e94c | 0x8aec |
| Lower passed; w < 0x7000c | Upper 0x9039 | 0x100531de0 | 0xd28d |
| Lower passed; w >= 0x7000c | Upper 0x9045 | 0x1006655b0 | 0xd28d |

The original table is at `0x101039ef0`. The four slots are respectively `0x1010581d8`, `0x10105c748`, `0x1010820b8`, and `0x101082118`. Original authenticated-fixup words and logical targets are retained separately in WR3. The two gates cover all 2^32 input words under their recorded phases; finite controls exercise the whole retained paths. The middle interval includes `0x7000c-0x60003=0x10009=65545` distinct words. An inclusive upper endpoint is therefore `0x7000b`. [WR1,WR3-WR5; WR-A1-WR-A3]

The middle route calls `0x100531ea0 -> 0x100436378`, IA `0x58a3`. The four-instruction leaf writes raw u32 `0x8b3dc650` through X0, here the reused private caller-record address `0x6800070db8`, and returns. It then reaches imported malloc at `0x10058bf4c`, IA `0x6aa4`, X0=64 B. No allocator return, wrapper payload or final routine result is supplied. The allocation's role and whether the range denotes supported versions, a migration band or another condition remain unknown. [WR1,WR3-WR5; WR-A2,WR-A3,WR-A7]

The endpoint decomposition `w=(upper16<<16)|lower16` gives `(6,3)` at the lower bound, `(7,11)` at the last middle word and `(7,12)` at the first upper word. This is a numerical observation, not an established major/minor format. The source compares complete u32 words: the interval also contains every `(6,k)` for k=3..65535 and `(7,k)` for k=0..11, totaling `65533+12=65545` words. A packed-format-revision interpretation is a candidate for producer/consumer validation; no field-splitting or native format evidence is supplied here. [WR1,WR3-WR5; WR-A3,WR-A7]

## Out-of-range adapter chain and new lstat site

The two outer ranges share the original `0x1006655b0` continuation. It reads a code pointer from incoming SP+`0x8658` at `0x1006655b4`, then branches at `0x1006655bc`, IA `0xaec3`, to `0x1007c5fc8`. The private pointer value matches original fixup slot `0x101040f50`, whose target/diversity corroborate this logical edge. The private copy's original producer is not established in this increment. Independent replay verifies the private value and matches the original fixup metadata; this is not a hardware PAC execution. [WR1-WR5; WR-A1,WR-A2,WR-A6]

The initial X9 branch has stronger direct predecessor provenance: the parent interval reads `0x10103f8c0 -> 0x10059ab00` at `0x1005b94f4`; the only following parent instruction, `0x1005b94f8`, leaves X9 intact. The current prefix also leaves X9 intact until `0x1005b95e4`, IA `0xe0d4`. The auditor verifies that complete boundary join separately from the private-cell metadata witness. [WR1-WR5; WR-A1,WR-A2,WR-A6]

| Call site -> entry | IA | First argument in retained model |
| --- | --- | --- |
| 0x10089fb34 -> 0x10041a980 | 0xb69a | Reused request at 0x6800070db8 |
| 0x10041ac34 -> 0x1004946d8 | 0xf248 | Private record at 0x68000600c8 |
| 0x100494920 -> 0x100493f38 | 0x4e06 | Same private record address |
| 0x1004cd11c -> imported ___error | 0x6e96 | No source arguments assigned a semantic role |

The original outer caller records the SIDB object B=`0x6600006000`; the chain preserves its identity into the filesystem-request setup. After a declared ordinary ABI return of the existing borrowed errno cell E=`0x6600020000`, original `0x1004cd120` stores four zero bytes through X0. It does not read an initial errno value. Original `0x1004cd124` stores B at private SP+16, and `0x1004cd128` advances the working object pointer by 32 B to its inline pathname. No new owner is created, retired or resized. [WR1-WR5; WR-A2-WR-A5]

| Pending site | Interface / IA | Source argument |
| --- | --- | --- |
| 0x1004cd194 | lstat / 0xf401 | X0=B+32=0x6600006020 |
| Same | Output-address argument | X1=SP+40=0x680005ff38; call SP=0x680005ff10 |

The pathname is the source-constructed `/var/db/fpsd/SC Info/SC Info.sidb`, including its terminal NUL in the carried 34 B path extent. This target ABI path contains no analyst-machine path. All SIDB object bytes, including the supplied timestamps, and all other non-errno/non-buffer owners remain unchanged. The inherited J+`0x34` generated 32 B also remain unchanged. Full private/image state changes are retained and independently replayed; this preservation claim concerns the specified owners and generated field. [WR1-WR5; WR-A2-WR-A5]

The prior query at `0x10063c368` preceded open/fstat/read. This new query is source-reachable after the selected exact-read/timestamp/close path and a synthetic out-of-range prefix. The two requests consume the same stored pathname but have different private output addresses and adapter chains. Neither native file identity nor a relationship between the opened descriptor and the newly looked-up object is established. The new lstat output remains completely unexecuted; stale stack definitions are not observations of its return bytes. [WR1-WR5; WR-A2,WR-A4,WR-A7]

No new Mach port/right, emission site, IOKit selector, kext call or native daemon-kext transaction is established. This increment adds a file-input-to-filesystem-control dependency; actual external modification of the file and a native temporal join remain unknown. [WR1-WR5; WR-A4,WR-A7]

## Routine-entry and code-fragment metadata

The original Mach-O advertises starts at all three called adapter entries and at the record-writing leaf. None of the ten exact queried sites has an original symbol-table name. The publication verifier decodes all 1005 `LC_FUNCTION_STARTS` entries, checks the 1864 B table at file offset 17603576 B, and retains these results in the manifest. Table SHA-256 is `ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54`. [WR1,WR5; WR-A1,WR-A6,WR-A7]

| Queried site | Preceding advertised start | Next advertised start |
| --- | --- | --- |
| 0x10041a980 | 0x10041a980 | 0x10041ac7c |
| 0x1004946d8 | 0x1004946d8 | 0x100494948 |
| 0x100493f38 | 0x100493f38 | 0x1004946d8 |
| 0x100436378 | 0x100436378 | 0x100436388 |
| 0x1005b94fc | 0x100559b7c | 0x10061748c |
| 0x1005fa9e0 | 0x100559b7c | 0x10061748c |
| 0x10054e94c | 0x10054127c | 0x10055975c |
| 0x10058bf4c | 0x100559b7c | 0x10061748c |
| 0x1004cd11c | 0x1004bd65c | 0x1004d4268 |
| 0x1004cd194 | 0x1004bd65c | 0x1004d4268 |

The original calls establish the adapter chain; the start table independently supports its entry addresses. It does not establish complete chunks, shared-thunk ownership or semantic routine names. A read-only IDA inventory and input-SHA-256 check on 2026-11-13 found no matching image among the six listed databases, so no unrelated database knowledge was used. The backing image supplies all positive evidence in this increment. Metadata parsing is O(image bytes + start entries + symbol entries) time and O(start entries) additional space. [WR1,WR5; WR-A1,WR-A6,WR-A7]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| WR-A1: The pinned image, logical fixups and decoders apply. | All source addresses, opcode effects and logical branches. | Rehash source/dependencies, compare every opcode and raw fixup word, replay GP/Q/NZCV/SP and byte effects. Hardware PAC validity remains unknown. |
| WR-A2: All 768 parent first-byte cuts have their recorded incoming phase. | Coverage, B/A identities, private fields and prefix/gate seeds. | Exact parent-state joins, source X9 predecessor proof, gate-register constants, owner masks and unchanged generated field. Other caller epochs require separate joins. |
| WR-A3: Synthetic prefixes are controls; source words use exact 32-bit arithmetic. | Two private stores, thresholds and route partition. | Supply only four previously unknown bytes, rebuild all-bit equations, test endpoints/adjacent/high-bit values and preserve the other 4092 unknown bytes. Do not label control bytes recovered file content. |
| WR-A4: Borrowed writable errno storage and ordinary ABI return semantics apply. | errno zero store and pending lstat request. | Exact four-byte existing owner, both clobber patterns across the matrix, callee-saved registers/vector lanes, pointer-width return and original write/arguments. Native TLS or API success is not inferred. |
| WR-A5: Declared owner extents/masks and pathname provenance apply. | Same inline path, unchanged owners and file-byte opacity. | Compare every owner and defined gap, require zero payload writes and only four prefix reads, preserve all generated bytes. Native allocation size/lifetime and historical structure layout remain unknown. |
| WR-A6: Parent private dispatch values are conditional state premises. | Out-of-range continuation via SP+0x8658. | Check the actual private load and original target/modifier metadata separately. Recover the private-copy producer before claiming a complete origin chain. Direct X9 predecessor provenance is independently verified. |
| WR-A7: Range membership, raw records and API requests have no additional assigned native semantics. | Bounds on format, allocation, filesystem and cross-layer conclusions. | Trace later record/allocation/content consumers and obtain matching native outcomes/epochs before assigning format versions, acceptance, replacement, identity, transport or daemon-kext pairing. Those facts remain unknown. |

## Coverage, reproduction and receipts

Every one of 256 parent contexts has three timestamp continuations. All `256 x 3=768` first-byte cuts receive words 0, `0x60003`, and `0x7000c`. Thus `768 x 3=2304` base prefix cases are retained. One representative cut adds twelve distinct controls, producing 2316 prefix cases. Of those, 773 take the middle route and 1543 reach the errno-accessor request. One opposite parent ABI pattern continues each accessor, giving `2316+1543=3859` intervals. The pattern is linked to the parent, not crossed again with both alternatives; both patterns occur across the complete matrix. [WR2-WR5; WR-A2-WR-A4]

| Retained source quantity | Exact count |
| --- | --- |
| Source intervals / visits | 3859 / 1374568 |
| Source reads / writes | 256989 / 74070 |
| Logical edges / source calls | 20844 / 5402 |
| Four-byte prefix controls / supplied bytes | 2316 / 9264 |
| Nonvacuous source equations | 12 |

| Extra control word | Relation / retained outcome |
| --- | --- |
| 1, 0x60002 | Below interval; errno -> lstat |
| 0x60004, 0x68000, 0x70000, 0x7000a, 0x7000b | Within interval; malloc(64) pending |
| 0x7000d, 0x7fffffff, 0x80000000, 0xffffffff, 0x6703cce9 | Above interval; errno -> lstat |

Twelve nonvacuous source equations rebuild the four-byte codec, both private stores, both modular comparison expressions, both dispatch indices, their range composition, borrowed-errno/path setup, lstat arguments, the 64 B allocator argument/IA and the record-writing leaf. There are twelve equations because the combined errno-clear/path setup is one obligation. All use a 30 s/query solver bound. The clear/path equation uses fixed disjoint errno/stack locations while quantifying object-pointer bits; it does not assume that independently named symbolic memory cells correctly model arbitrary aliasing. [WR1,WR3-WR5; WR-A1-WR-A6]

Algorithmically, the recovered word stores/range classification use O(1) time and O(1) auxiliary space per four-byte word. Evidence generation/replay uses O(parent bytes + source visits x retained register/effect state + owner joins + query DAG + owned artifact bytes) time/storage, with the stated solver bound. All counts are exact validation quantities, not native traffic, timings or allocation footprints. [WR1-WR5]

```text
python triage_evidence/recover_daemon_state_word_routing.py
python triage_evidence/audit_daemon_state_word_routing.py
zstd --ultra -22 -q -T1 triage_evidence/daemon_state_word_routing_checks.json
zstd --ultra -22 -q -T1 triage_evidence/daemon_state_word_routing_audit.json
python triage_evidence/validate_rpc502_sidecar_delivery.py
zstd --ultra -22 -q -T1 triage_evidence/interface_manifest.json
python triage_evidence/verify_daemon_state_word_routing_publication.py
```

Use Python with Unicorn, Capstone and Z3 and include `triage_evidence` on the module search path. Verify each archive round trip before removing plaintext duplicates. The source resolver uses the original backing image; no target API or IDB mutation executes. All new files, decoded interval payloads and the actual commit message undergo the analyst-path scrub. [WR1-WR5]

| Independent replay | Exact count |
| --- | --- |
| inherited_X9_fixup_origins_checked | 2316 |
| register_values_checked | 44109664 |
| NZCV_values_checked | 1378427 |
| vector_register_values_checked | 44109664 |
| read_bytes_checked | 1339004 |
| source_visits | 1374568 |
| write_bytes_checked | 549332 |
| original_authenticated_edges_checked | 20071 |
| private_dispatch_values_matched_to_original_fixups | 1543 |

The model joins check 2316 prefix insertions, 4632 private word stores, 2316 lower-gate partitions, 1546 upper-gate partitions, 1543 borrowed errno returns/lstat requests and preservation across all 3859 intervals. The 15791028 unsupplied-byte checks are repeated validation quantities, not native memory footprints. [WR3-WR5]

| Logical artifact | SHA-256 |
| --- | --- |
| Current checks | `8b8018a75831eeb9c205087dabc5be372a7d30b6a756c6fb344529108ad55565` |
| Independent audit | `9fa9599b2f510aab80d74a73dd55ab409af362790e51606a025a4d1456838e96` |
| Extractor | `515dabcf72f6030609fe0a7e42a0bedb56e0771388b4385def1efdcae4454b1b` |
| Auditor | `c909286ee25f8290c5ef12fc90fb87e4d6d0f8ea85e838bf3c0dab35c763a32d` |

These are decoded-artifact hashes; archive hashes differ. The manifest retains source/audit counts, dispatch metadata and advertised-start brackets; the publication verifier recomputes them and checks the exact publication delta and all three original inputs. [WR1-WR5]

## Bounded continuation opportunities

| Impact | Follow-up | Evidence required / architectural boundary |
| --- | --- | --- |
| High | Recover the new lstat return and demanded metadata fields. | Invalidate output before supplying only demanded fields; establish which file-control operation follows each source partition. |
| High | Identify the middle-route 64 B allocation and its consumer. | Original return/payload stores and later record interpretation; raw 0x8b3dc650 does not assign success/failure meaning. |
| High | Establish the first word's format role. | Subsequent field readers, producers and comparisons, plus matching file provenance; numeric resemblance to a version is insufficient. |
| High | Trace resulting file-derived state into daemon/kext producers. | Source data dependencies and matching native transport/transaction/epoch identities; none is inferred from the heap buffer. |
| Medium | Establish the producer of the private SP+0x8658 code pointer. | Original writer/fixup/copy chain and retained-state joins; current metadata match establishes the logical value and modifier only. |
| Medium | Join opened descriptor identity to the repeated pathname lookup. | Native file identity and temporal evidence; identical path bytes do not prove identical objects. |
| Medium | Follow the two stored word representations. | Original consumers of private SP+0x8f94/+0x7044 and exact field use; avoid assigning status types solely from XOR constants. |

## Quality gates

- **QG1**: Pass. Factual original-source, data-flow and interface analysis.
- **QG2**: Pass. WR-A1-WR-A7 state assumptions, dependent results and falsification probes.
- **QG3**: Pass for the declared first-word/routing increment. Every inherited first-byte cut has all three route controls; full interface investigation remains active and incomplete.
- **QG4**: Pass. Byte extents, u32/u64 arithmetic, half-open/inclusive endpoints, exact counts and complexity are explicit.
- **QG5**: Pass. Synthetic/native content, two private word representations, unsigned wraparound, distinct lstat sites, pending allocation/output and incomplete private-pointer provenance remain distinct.
- **QG6**: Pass after independent replay, twelve rebuilt equations, source/fixup/dependency checks and exact publication verification. Native observations are not claimed.
- **QG7**: Pass. The impact-labeled continuation table bounds file-control, allocation, format, provenance, temporal identity and cross-layer follow-ups.

The [SIDB removal and SIDN handoff continuation](daemon_state_path_removal_report.md) resumes four pending lstat states spanning both outer word routes and prior ABI patterns. It proves local return/mode/errno/unlink predicates, retains conditional removal and synchronization requests, distinguishes writes to already-zero fields from ownership retirement, and follows raw status propagation into a new pending SIDN query at the shared lstat call site. The remaining1539 parents and native outcomes remain outside that full-path matrix.
