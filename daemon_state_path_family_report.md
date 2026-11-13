# Daemon state-path family, caller gate and first filesystem request

The selected caller constructs ten pathname objects, publishes them into ten context fields, checks nine fields for nonnull values and then passes the SIDB object's inline pathname to the imported `lstat` binding. The larger rbSyncResp object contains a20 B decoded filename payload with two trailing NUL bytes; its context field is omitted from the retained nine-field gate. Separate single-field-zero controls reach an imported rwlock-destruction request for every checked field. These are original-file-backed conditional source results. Native allocation, initialization, destruction, filesystem effects, caller epoch linkage and daemon-kext delivery remain unknown. The full interface investigation remains active. [PF1-PF6; PF-A1-PF-A8]

```text
successful SIDB parent -> nine more path constructors -> ten context fields
                                                        |
                        nine nonnull checks -------------+
                          | all pass            | a checked field is zero
                          v                     v
                     SIDB consumer       object+0 -> raw lock pointer
                          |                     |
                          v                     v
                     ___error()          pthread_rwlock_destroy(lock)
                          |               [pending; no return supplied]
                    source stores u32 zero
                          |
                          v
           lstat(SIDB_object+32, private_SP+24)
           [pending; no filesystem output supplied]
```

| Evidence | Primary artifact and scope |
| --- | --- |
| PF1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_state_path_family.py) retains source bytes, filename constants, canonical logical fixups, GP/Q/NZCV/SP states and source byte events. |
| PF2 | [SIDB report](daemon_state_path_objects_report.md), [checks](triage_evidence/daemon_state_path_objects_checks.json.zst) and [audit](triage_evidence/daemon_state_path_objects_audit.json.zst): eight successful conditional SIDB states and prior constructor-failure contracts. |
| PF3 | [Current checks](triage_evidence/daemon_state_path_family_checks.json.zst): sixteen complete family continuations and twenty separate single-field-zero controls,484 intervals. |
| PF4 | [Independent auditor](triage_evidence/audit_daemon_state_path_family.py) and [audit](triage_evidence/daemon_state_path_family_audit.json.zst): original-instruction replay, complete byte-mask comparisons, exact API/state joins and23 nonvacuous source equations. |
| PF5 | [Rwlock lifecycle report](daemon_rwlock_lifecycle_report.md): initializer/status contracts and earlier creator provenance; its all-u32 predicates are rebuilt through the prior auditor. |
| PF6 | [Publication verifier](triage_evidence/verify_daemon_state_path_family_publication.py): source/dependency hashes, exact case coverage, rebuilt equations, decoded packed-payload hygiene, preserved inputs and exact manifest delta. |

## Ordered field and filename mapping

J=`0x6500115b20` is the inherited conditional context. All paths have the source-decoded directory `/var/db/fpsd/SC Info/`. The first object is inherited from PF2; the other nine are constructed here by the common entry `0x100410c4c`. Every listed caller call uses IA modifier `0x704f`; return is call+4. Each successful source publication uses `0x10003a3e0`. The table records construction order, which differs from context-offset order and gate order. [PF1-PF4; PF-A1-PF-A3]

| Order | Context field | Basename as C string | Encoded filename source | Filename payload | malloc request | Caller call |
| --- | --- | --- | --- | --- | --- | --- |
| 1, inherited | J+0x118 | SC Info.sidb | 0x10102fa20 | 12 B | 74 B | 0x1004cef30 |
| 2 | J+0x120 | SC Info.sidn | 0x1010130e0 | 12 B | 74 B | 0x1004cf038 |
| 3 | J+0x110 | SC Info.sidd | 0x10100a2f0 | 12 B | 74 B | 0x1004cf148 |
| 4 | J+0x108 | SC Info.sidv | 0x100fc22f0 | 12 B | 74 B | 0x1004cf260 |
| 5 | J+0x128 | SC Info.sidr | 0x100fec610 | 12 B | 74 B | 0x1004cf36c |
| 6 | J+0x130 | SC Info.sidl | 0x100f70f65 | 12 B | 74 B | 0x1004cf474 |
| 7 | J+0x138 | SC Info.rbSyncResp | 0x101029830 | 20 B | 82 B | 0x1004cf578 |
| 8 | J+0x140 | SC Info.sidt | 0x100eef330 | 12 B | 74 B | 0x1004cf684 |
| 9 | J+0x148 | SC Info.sids | 0x101004660 | 12 B | 74 B | 0x1004cf778 |
| 10 | J+0x150 | SC Info.sido | 0x100fea4f0 | 12 B | 74 B | 0x1004cf888 |

For each new ordinal o, the declared object owner is `0x6600006000+(o-1)*0x2000`; its separate200 B lock owner begins at object+`0x1000`. These addresses are model premises, not recovered native heap addresses. Each object malloc binds at `0x10018ed34`, the lock malloc at `0x10019385c`, and `pthread_rwlock_init(L,NULL)` at `0x100130fcc`. Both malloc sites use IA`0x6aa4`; initialization uses IA`0xa027`. Nonnull object/lock returns start with no defined bytes. Source defines the lock's first8 B before initialization; the return premise then invalidates all200 B as opaque library state. The following retained source does not access lock bytes. [PF1-PF5; PF-A2-PF-A3]

Within this family, the ten requested object extents sum to9*74+82=748 B, and the ten lock requests sum to10*200=2000 B. Thus2748 B of requested spans have this family role, excluding allocator overhead and all other inherited owners. Nine objects are new here:8*74+82=674 B plus9*200=1800 B, totaling2474 B per complete continuation. Native allocation sizes and whole-process footprint remain unknown. [PF1-PF4; PF-A2-PF-A3]

All nine new initializer returns are explicitly zero; constructor status stored at request+8 is consequently `0x8b3dc651`, rather than zero. Previous PF2 failure scenarios are separate evidence. The present full-family cases do not exhaust the Cartesian product of ten constructor failures, and the zero-field controls do not equate a failed allocation with a zero destination: PF2 shows that failed construction preserves the previous field bytes. [PF2-PF5; PF-A2-PF-A4]

## Complete written extent and the larger filename

The common layout has a raw lock pointer at object+0, zero u64 values at+8/+16, byte1 at+24, an undefined3 B gap at+25..27, zero u32 at+28 and pathname bytes at+32. The directory loop decodes20 bytes with XOR`0x98`, then writes `/`. Filename groups use the original four-byte transform `(e2 XOR 0x52,e0 XOR 0x3e,e3 XOR 0x99,e1 XOR 0x22)`. Source-image filename bytes and every corresponding read are checked. The common helper separately appends its terminal NUL. [PF1-PF5; PF-A3-PF-A5]

| Property | Twelve-byte filename payload | Twenty-byte rbSyncResp payload |
| --- | --- | --- |
| Decoded filename bytes | Twelve visible bytes | Eighteen visible bytes, then `00 00` |
| Complete source-written path | 20+1+12+1=34 B | 20+1+20+1=42 B |
| C-string length before first NUL | 33 B | 39 B |
| Extent through first NUL | 34 B | 40 B |
| Explicit constructor terminal | object+65 | object+73 |
| Defined header plus full path | 29+34=63 B | 29+42=71 B |
| Undefined header gap plus tail | 3+8=11 B | 3+8=11 B |
| Complete requested owner | 63+11=74 B | 71+11=82 B |

For rbSyncResp the three consecutive path NULs occupy object+71,+72,+73. The last is the constructor's explicit terminal store at `0x10003a3d8`; the preceding two come from the decoded20 B payload. Bytes+74..81 remain undefined. The allocation relation N=32+20+1+F+1+8=F+62 is verified for F=12 and20 here; an arbitrary-length size theorem is not claimed. Each object's complete definition mask is compared after construction and again at the final `lstat` boundary. [PF1-PF4; PF-A3-PF-A5]

Five source-local arbitrary-data quad proofs now cover offsets0,4,8,12,16 under the retained decoding phase. Two are new; the other three are rebuilt from PF2. Decoded payload length and C-string length must remain distinct when recovering future consumers. No SIDB/SIDN/SIDD/SIDV/SIDR/SIDL/SIDT/SIDS/SIDO file-format semantics or rbSyncResp content format is established merely from these names. [PF1-PF6; PF-A5]

## Caller admission and requested cleanup

After the tenth constructor returns, the caller reaches `0x1004cf894`. The source reads and checks the following fields in this order. Nine nonvacuous equations establish, for every64-bit pointer value under the recorded surrounding phase, that each original gate's dispatch index equals its NULL index for zero and its distinct nonnull index otherwise. They do not establish validity or ownership of an arbitrary nonnull pointer. [PF1-PF4; PF-A4-PF-A6]

| Gate order | Field | Object | Original field read |
| --- | --- | --- | --- |
| 1 | J+0x118 | SIDB | 0x1004cf894 |
| 2 | J+0x110 | SIDD | 0x1005a8ad8 |
| 3 | J+0x108 | SIDV | 0x10059fe2c |
| 4 | J+0x120 | SIDN | 0x1005d3370 |
| 5 | J+0x128 | SIDR | 0x1007f5294 |
| 6 | J+0x130 | SIDL | 0x1007fc548 |
| 7 | J+0x140 | SIDT | 0x1005eb634 |
| 8 | J+0x148 | SIDS | 0x1005c57b4 |
| 9 | J+0x150 | SIDO | 0x10060f1c0 |

The complete retained gate-to-errno source reads no J+`0x138` field. Setting only that field to zero preserves the route to `___error`. Setting any one of the nine checked fields to zero instead reaches `0x10031ca0c`, imported `pthread_rwlock_destroy`, IA`0xfe1e`. The twenty controls cross ten individual zero fields with both new ABI patterns in the first successful parent only. They are counterfactual local-state controls with exact eight-byte substitutions, not native failure observations or a proof about all combinations of missing fields. [PF1,PF3-PF4; PF-A4-PF-A6]

For the zero-SIDB control, the first requested destruction uses the SIDN object's lock. For the other eight checked-field controls, it uses the SIDB object's lock. The cleanup adapter `0x1004271ac` loads an object pointer at `0x1004272f0`; source `0x1004272f8` reads the raw lock pointer from object+0. It calls `0x100427448 -> 0x10044aba8`, IA`0xa419`, before the imported destruction request. No destruction return, object free, complete cleanup order or native resource lifetime is supplied or inferred. The omitted rbSyncResp gate does not establish that object's optionality in later operations. [PF1,PF3-PF5; PF-A3-PF-A4,PF-A6]

## SIDB consumer record, errno and lstat ABI

After the nonnull checks the caller reloads SIDB at `0x1006d9aac` and SIDN at `0x10083947c`, saving both in its frame. The first retained filesystem request consumes SIDB. The SIDN reload alone does not establish a second file operation. The consumer chain is source-paired as follows. [PF1-PF4; PF-A6-PF-A8]

| Source boundary | Interface and established role |
| --- | --- |
| 0x10083955c -> 0x10042f208, IA0x6aa4 | Caller adapter receiving the reused request record |
| 0x10042f3b4 | Writes raw SIDB object pointer into private record+0 |
| 0x10042f3c8 | Writes a u32 control value into private record+12; no final native record type assigned |
| 0x10042f4b8 -> 0x100618fdc, IA0xe200 | Passes private record as X0 and a separate private adjustment cell as X1 |
| 0x100619234 -> 0x1006176f8, IA0x11d8 | Passes the same record as X0 and an inner adjustment cell as X1 |
| 0x100617884 / 0x10061788c | Reads record+12 control / record+0 SIDB pointer |
| 0x10063c2f8, IA0x6e96 | Imported `___error` request; no source arguments assigned a semantic role |
| 0x10063c2fc | Writes four zero bytes through the declared return pointer |
| 0x10063c300 | Computes X0=SIDB object+32 |
| 0x10063c360 | Computes X1=SP+24 |
| 0x10063c368, IA0xf401 | Pending imported `lstat` request |

In these continuations the private record is `0x68000600c8`, and the pending `lstat` call has SP=`0x680005fec0`, X0=`0x6600006020`, X1=`0x680005fed8`. X0 points to the already source-constructed `/var/db/fpsd/SC Info/SC Info.sidb` including NUL. X1 is a private stack address intended for the imported interface's output; its required extent, native stat layout and returned bytes remain unknown in this increment. No result is supplied for `lstat`. [PF1-PF4; PF-A6-PF-A8]

The `___error` return is an explicit borrowed four-byte cell at `0x6600020000`, initially undefined. It is not modeled as a malloc allocation or as a native thread-local-storage observation. The original store defines zero immediately, without reading an initial value. A source equation covers both that u32 zero store and the following object+32 argument calculation for arbitrary64-bit pointer values. Normal GP/Q/flag clobbers remain explicit ABI premises; the source paths are crossed with two patterns. [PF1,PF3-PF4; PF-A3,PF-A7-PF-A8]

No Mach port/right, message emission, IOKit selector, generated-stream transport or daemon-kext pairing is added by these intervals. The inherited32 B generated field at J+`0x34` is preserved without source access. The filesystem API binding and pathname are now source-paired, while actual file existence, metadata, permissions, content, environment state and external control remain unknown. [PF1-PF6; PF-A1-PF-A8]

## Assumption register and falsification probes

| Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- |
| PF-A1: Pinned original image and logical fixups apply | Addresses, opcodes, constants and imported bindings | Recheck source SHA, each source instruction and every used fixup/modifier; no hardware PAC result inferred. |
| PF-A2: Eight successful SIDB states are conditional entries | Sixteen complete family continuations | Exact parent GP/Q/NZCV/SP, owners and known bytes; retain separate constructor/caller epoch premise and earlier failures. |
| PF-A3: Explicit disjoint malloc owners, init-zero returns and opaque lock effects apply | New object layout, publication and lock state | Start every owner undefined; compare every byte/mask; invalidate all200 lock bytes; compare both ABI patterns and no later lock-byte access. Native ownership unknown. |
| PF-A4: Zero controls substitute only one context u64 | Gate/cleanup branch evidence | Compare all other bytes/registers/owners; cross both patterns and ten fields; do not identify source zero controls with allocation failures. |
| PF-A5: Retained directory/filename phase and payload lengths apply | Ten names,34/42 B written extents and embedded NULs | Pin original constants and all filename reads, recheck all five arbitrary-data quad equations and exact complete definition masks. Arbitrary lengths remain unproved. |
| PF-A6: Retained source prefix bounds admission and consumption | Nine required nonnull fields, omitted rbSyncResp check, first cleanup and SIDB consumer | Verify ordered field reads, distinct all-pointer gate indices, all calls and pointer def-use; stop at first imported boundary. Later optionality/lifetime unknown. |
| PF-A7: Borrowed four-byte errno storage is writable | Original errno zero store and next lstat argument | No initial errno value; exact borrowed owner, source u32 store and arbitrary-pointer equation; native TLS and lstat output remain unknown. |
| PF-A8: Imported operations and native epochs require separate evidence | Filesystem/environment/IPC limits | No target API or syscall executes; retain pending lstat/destruction boundaries and unknown native output extents. Independently join native events before claiming daemon-kext transport. |

## Reproduction, checks and bounded continuation

Checks logical SHA-256: `b264e1892232c182f44e15fe3ff00f5a64804ed2d53dd17bae29d26fe94ddc82`. Audit logical SHA-256: `cdbb348eeee38b883aba51fcbac4285d70a2dfb36cf771a21a806f21bde40f32`. Reproduction uses the pinned source resolver and Python dependencies already used by PF2; run the current extractor, auditor and publication verifier in that order. Large receipt JSON files and the manifest are stored as Zstandard archives with `--ultra -22 -q -T1`. [PF1-PF6]

The16 family cases cross all eight successful PF2 parents with both new ABI patterns. Each has29 intervals:27 API-return intervals for nine constructors, one caller gate interval and one borrowed-errno return interval. The20 controls add one interval each:16*29+20=484. There are282104 source visits,39942 reads,14374 writes,11260 logical edges and364 internal calls. Independent replay checks9042816 scalar register values,9042816 vector register values,282588 flag states,207996 read B,70542 write B and10970 authenticated logical edges. It checks448 API-return joins,16 ordinary joins and20 single-field-zero state joins. The144 new object publications cover9200 defined bytes and1584 undefined-gap bytes. Eighteen controls reach a pending lock-destruction request; the two rbSyncResp controls reach errno. All512 carried generated-stream bytes are preserved across the sixteen complete cases. [PF3-PF4,PF6]

Twenty-three nonvacuous equations include eleven rebuilt PF2 constructor equations, two additional filename groups, nine original null-dispatch equations and one errno/path-argument equation. Every source instruction and full scalar/vector/flag state is checked by the independent replay; source-equation solver limit is30 s/query. Arithmetic uses exact u8/u32/u64 wrapping. For K path objects, construction is O(sum(D+F)) source work with O(1) in-place auxiliary storage per object, excluding the explicitly requested owners. Retained comparison uses O(sum(N)) object-byte storage; overall receipt/replay complexity is O(V*(register state+effects)+query DAG) time and O(receipts+largest interval+sum(N)) storage. Counts are exact conditional-path counts, not native timing measurements. [PF1-PF6]

| Impact | Further evidence | Architectural consequence and boundary |
| --- | --- | --- |
| High | Recover lstat return partitions and exact output-field reads | Determine which metadata controls file initialization, open or replacement; no output bytes are invented here |
| High | Follow SIDN and the remaining pathname objects into file APIs | Establish file-pair relationships and sequencing from actual operations rather than suffix names |
| High | Join native caller/constructor and filesystem events | Determine environment-specific state and actual daemon-kext data transport |
| High | Continue the pending rwlock destruction request and later object cleanup | Establish complete lifetime and cleanup order; current prefix establishes only the first request |
| Medium | Recover rbSyncResp consumers beyond the omitted gate | Determine whether embedded NULs and the larger complete written extent affect later operations; optionality remains bounded to this gate |
| Medium | Recover control word at private record+12 and adjustment adapters | Assign operation/status roles from source dispatch and output def-use |
| Medium | Trace pathname-input writers and publication synchronization | Establish native external control and concurrent visibility |

**QG1** passes: factual source/ABI analysis. **QG2** passes: PF-A1-PF-A8 register dependencies and probes. **QG3** passes for this family/gate/first-filesystem-request increment; the full interface goal remains active. **QG4** passes: exact widths, byte counts, modular arithmetic and complexity. **QG5** passes: construction/gate order, decoded/C-string extents, zero-control/failure behavior, borrowed/allocated storage and pending/native API effects remain distinct. **QG6** passes after independent replay,23 nonvacuous equations, source/provenance checks and exact publication verification. **QG7** passes: bounded expansion covers metadata consumers, file relationships, native epoch joins, destruction, rbSyncResp extent, operation controls and visibility.

The [subsequent file-admission report](daemon_state_file_admission_report.md) resolves the former pending lstat return through exact output invalidation, mode/errno gates and caller status stores. Its selected non-link/zero-field route reaches paired SIDB read-lock/unlock requests, updates object+28 and requests open(SIDB_path,0x110,stack_zero). No open result or native filesystem effect is supplied.
