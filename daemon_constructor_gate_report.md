# Conditional constructor gate, arena transfer and 48-byte object initialization

An explicitly separate initializer-compatible entry now connects the mixed-table constructor to the shared gate at `0x1010b5de0`, the readiness byte at `0x1010c5798`, an existing arena, and initialization of U/48 B. The original inherited frontier remains undefined: eleven pointer fields, totaling 88 B, are supplied as additional entry premises because twelve retained initializer profiles agree on their values. This agreement does not establish a continuous initializer-to-current-caller path or a native epoch. [CG1-CG6; CG-A1-CG-A8]

Under those premises, four complete classes cover all 76 inherited states through exact register, byte and owner admission. They execute 386004 original instruction visits, 48 internal calls and no imported call. U acquires 40 defined bytes and retains eight undefined bytes; its pointer is stored into S+0 after initialization. J/552 B remains unchanged. No new Mach or IOKit emission, J+0x68 publication, native ownership or daemon-kext transaction pairing is established. [CG1-CG6; CG-A1-CG-A8]

```text
76 inherited states at 10057ac04, SP+5b0 undefined
  + separate entry premise: eleven source-compatible pointers / 88 B
  -> four classes, sizes 34/4/34/4; exact dependency admission
  -> gate CASAL at 1006b7730: 00005d96 -> 000a94ef
  -> readiness load at 10082552c: byte == 1
  -> address-derived arena fill and six arena/header stores
  -> plain gate release at 100775768: 000a94ef -> 00005d96
  -> arena pointer -> U+32; three internal generator chains
  -> modify fourteen bytes of T/21 B
  -> U fields; then store U into S+0 at 1008258d8
  -> cursor 480 -> 460; inherited saved continuation verified
  -> STOP 1005f149c before undefined SP+260 / 8 B

Initializer/caller epoch join and native transport remain unknown.
```

| Evidence | Primary artifact and scope |
| --- | --- |
| CG1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_constructor_gate.py) retains source words, fixups, journals, premises and terminal exports. |
| CG2 | [Table-consumer parent](daemon_table_consumer_report.md), its [checks](triage_evidence/daemon_table_consumer_checks.json.zst), and twelve separately retained initializer profiles in [bank-origin checks](triage_evidence/daemon_return_bank_origins_checks.json.zst). |
| CG3 | [Current checks](triage_evidence/daemon_constructor_gate_checks.json.zst): four full source executions, explicit root provenance, 76 conditional terminal exports and the pending undefined load. |
| CG4 | [Independent replayer](triage_evidence/replay_daemon_constructor_gate.py) and [receipt](triage_evidence/daemon_constructor_gate_replay.json.zst): every GP/SP/Q/NZCV frame, byte event, logical edge and exact saved-pointer chain. |
| CG5 | [Auditor](triage_evidence/audit_daemon_constructor_gate.py) and [receipt](triage_evidence/daemon_constructor_gate_audit.json.zst): all-parent admissions/fault controls, gate/fill/object contracts, eight nonvacuous source proofs and complete direct opcode census for twelve stack offsets. |
| CG6 | [Publication verifier](triage_evidence/verify_daemon_constructor_gate_publication.py): pinned full replay; fresh admissions, contracts, source proofs, pointer provenance, exact manifest delta, original-input preservation and decoded path hygiene. |

## Explicit additional entry premises

Outer SP is `0x6800060100` in the retained caller. Each listed 8 B field is undefined in the inherited entry and is added only in the separate conditional entry. Every one of the twelve initializer profiles contains exactly one overlapping 8 B store to its own frame-relative field, with no later overlapping store in that profile. The current image pointer values agree across four frame placements and three request variants. Other controller, request, initialization and lifetime contexts remain outside this admission. [CG1-CG6; CG-A1-CG-A4]

| Outer-SP offset / 8 B | Supplied pointer | Initializer writer | Established current role |
| --- | --- | --- | --- |
| +0x5b0 | `0x1010b5de0` | `0x1004c2b98` | Shared u32 gate root |
| +0x578 | `0x1010c5798` | `0x1004c287c` | Readiness-byte root |
| +0x5b8 | `0x1010b5ef0` | `0x1004c2c70` | Arena descriptor root D |
| +0x860 | `0x1010b5f20` | `0x1004c362c` | Existing arena sentinel D+48 |
| +0x420 | `0x100f21190` | `0x1004c2d8c` | Image byte-table root |
| +0x418 | `0x100fa38b0` | `0x1004c2fc0` | Image byte-table root |
| +0x428 | `0x100ffc9e0` | `0x1004c2c8c` | Image byte-table root |
| +0x3e8 | `0x100e36310` | `0x1004c26e8` | Image byte-table root |
| +0x3e0 | `0x100f2f6b0` | `0x1004c2f34` | Image byte-table root |
| +0x3d8 | `0x100ed2440` | `0x1004c35f4` | Image byte-table root |
| +0x438 | `0x100fa7ba0` | `0x1004c312c` | Image byte-table root |

These are new root definitions, not new payload bytes, API returns or owner extents. The 88 B delta is checked separately for every parent: `76*88=6688 B`. All subsequent terminal exports preserve that conditional origin. The earlier reports' unconditional undefined boundary is unchanged. [CG1-CG6; CG-A1-CG-A5]

The complete 14849960 B original text is scanned as 3712490 aligned 32-bit words, SHA-256 `94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e`. The census enumerates direct unsigned-immediate `STR Xn,[SP,#offset]` candidates for these eleven offsets and +0x260. All 144 initializer writer words are checked against the original image. Same-offset stores in other frames do not establish an alias or epoch join; indexed, paired and aliased-base stores remain outside this exact opcode census. [CG1-CG6; CG-A1-CG-A4]

## Shared gate and readiness interface

`0x10057ac04` loads the gate pointer into X19. Emission `0x10057ac0c` transfers to `0x1008c7994` with logical IA modifier `0xa55f`; its actual parent load from slot `0x101048b28` is verified through the interval boundary. Stores at `0x1008c79a0`/`0x1008c79a4` save continuation `0x1008b37e4` at SP+0x5198 and raw word `0x3997fcea5bd1f9a4` at SP+0x6ee0. The latter's broader semantic role remains unknown. [CG1-CG6; CG-A1-CG-A6]

At `0x1006b772c`, W13 becomes `0x5d96`; `CASAL W13,W10,[X19]` at `0x1006b7730` uses desired W10=`0xa94ef`. Its value-level contract is `returned_old=old` and `gate_after=(old==0x5d96 ? 0xa94ef : old)`. The subsequent original compare uses W11=`0x5d96`. The proof covers every u32 gate word, including all other values; the retained full path begins with the already source-defined available word. A failed CAS value equation does not imply a physical memory write. Native acquire/release visibility, scheduling, fairness and concurrent mutation remain unobserved. [CG1-CG6; CG-A1-CG-A4,CG-A6]

| Predicate and index | Original slot | Target | Logical IA modifier / emission |
| --- | --- | --- | --- |
| gate old == `0x5d96`; `0xb322` | `0x101093800` | `0x100825508` | `0xe155` / `0x1006b774c` |
| gate old != `0x5d96`; `0x9b84` | `0x101087b10` | `0x1006b772c` | `0xe155` / `0x1006b774c` |
| readiness byte == 1; `0xafb5` | `0x101091c98` | `0x10076d73c` | `0x48e8` / `0x10082555c` |
| readiness byte != 1; `0x99f` | `0x10103ebe8` | `0x100775760` | `0x48e8` / `0x10082555c` |

The nonmatching gate route returns to the original CAS block. Under unchanged gate memory it repeats that local block; no timing or native progress claim follows. Readiness is an exact-one test, not a bit-zero test. The retained byte is 1; the universal source query covers all 256 byte values. The non-one target begins the shared plain-release path. That release's `STR W8,[X19]` at `0x100775768` restores `0x5d96`; the retained warm path also reaches it after the arena work. It then reloads the saved continuation and emits at `0x100775774`, IA `0x9717`, to `0x1008b37e4`. [CG1-CG6; CG-A1-CG-A6]

These addresses are the same gate/readiness/descriptor roots recovered in the [readiness/arena report](daemon_readiness_arena_report.md) and [second-mix report](daemon_second_mix_report.md). This establishes architectural reuse of the source cells on the separate compatible entry. It does not establish a native mutex implementation, a complete critical-section inventory or cross-process synchronization. [CG1-CG6; CG-A1-CG-A4,CG-A8]

## Arena transfer and address-derived fill

Store `0x10054b73c` first fills four private bytes at SP+0x651c..+0x651f, then 292 arena bytes at `0x6500115138..0x650011525b`, each descending. The emitted first four bytes in descending order are `42 8e f0 3c`; subsequent bytes vary. For the current counter pointer a and W2=b, the byte is `u8((low32(a) XOR b)*(low32(a)+17))`. Each iteration decrements remaining before storing at `base+remaining-1`, increments a, and stores the remaining count at SP+0x3668. Both the finite byte ledger and a source equation check this transfer. This is address-derived filling; a zero-fill interpretation is contradicted by its actual bytes. [CG1-CG6; CG-A1-CG-A7]

| Original writer | Address / bytes | Retained value and data-flow role |
| --- | --- | --- |
| `0x1007cf774` | `0x6500100008` / 8 B | Raw `0x5e878c613b82756e`; prior arena-node metadata update |
| `0x1007cf790` | `0x6500115184` / 8 B | Raw `0x5e878c613b82756e`; current node header |
| `0x1007cf790` | `0x650011518c` / 8 B | Raw `0x5e878c613b812312`; next header word |
| `0x1007cf7cc` | `0x6500115194` / 8 B | Raw `0x5c42ed99bf0a7e70`; third header word |
| `0x1007cf7e0` | `0x650011525c` / 8 B | Raw `0x5e878c613b8123ea`; marker word |
| `0x1007cf7f0` | D+40=`0x1010b5f18` / 8 B | Raw `0x1aa4071f0801844f`; shared descriptor update |

All six stores occur after acquisition and before the plain gate release. The node address is `0x6500115184`; original `ADD X27,X10,#0x18` at `0x1007cf7f4` produces `0x650011519c`. That pointer reaches U+32 through store `0x100604a40`. These are precise local node/header/payload offsets. A complete allocation-size, free-list, ownership or native-lifetime contract is not established by these stores alone. [CG1-CG6; CG-A1-CG-A4,CG-A6-CG-A8]

## U layout, T updates and publication into S

Model objects retain the earlier owner extents: S=`0x6600040000`/64 B, T=`0x6600050000`/21 B, U=`0x6600060000`/48 B and J=`0x6500115b20`/552 B. Their native placement and lifetime remain unknown. U begins with all 48 bytes undefined. The following seven byte-journal stores define 40 B; paired source instructions account for two separate events each. [CG1-CG6; CG-A1-CG-A5,CG-A8]

| U offset / width | Final value | Original writer and established role |
| --- | --- | --- |
| +0x00 / u64 | 0 | `0x100825890`, first STP element; raw zero field |
| +0x08 / pointer64 | T | `0x100825890`, second STP element; pointer to the 21 B object |
| +0x10 / u32 | `0x10ecc426` | `0x1008258ac`; duplicates +0x14 |
| +0x14 / u32 | `0x10ecc426` | `0x1008258a8`, first STP element |
| +0x18 / u32 | `0x76d8ea81` | `0x1008258a8`, second STP element; word loaded from SP+0x3608 |
| +0x1c / 4 B | unknown | No definition supplied or written |
| +0x20 / pointer64 | `0x650011519c` | `0x100604a40`; arena node+24 pointer |
| +0x28 / u32 | `0xd299e642` | `0x1008258d0`; flag-selected raw word |
| +0x2c / 4 B | unknown | No definition supplied or written |

For incoming u32 phase p and the SP+0x3608 word a, original instructions prove `U[0x10]=U[0x14]=u32(a+(p XOR0x9a13b551))` and `U[0x18]=a`. At the actual field-transfer phase p=`0x6cf4`. The flag at SP+0x662f selects `0xd299e642` when nonzero, `0xd299e646` when zero. The field's higher-level status/size nomenclature remains unknown. [CG1-CG6; CG-A1-CG-A7]

After all seven U events, `0x1008258d8` stores U into S+0. S retains its 53-defined/11-undefined-byte split; all other defined S bytes retain their values. J's entire 552 B is unchanged, with no write overlapping it. Thus the new publication is into S, not into J+0x68. Its native owner visibility remains unknown. [CG1-CG6; CG-A1-CG-A5,CG-A8]

There are three invocations each of original internal entries `0x100add594`, `0x100acd9c4`, `0x10041a5e0` and `0x100427514`: twelve internal calls per class. They extend the previously recovered generator/adapter/comparison chain without supplying any new imported return. Fourteen T byte stores change offsets 1..12,15,16; final T is `06a2b5113d35bd9145be84e9f3294b55898a446d91`, fully defined. Neither the internal generator path nor this object pointer store establishes an external protocol message. [CG1-CG6; CG-A1-CG-A8]

## Continuation provenance and unresolved field

The original cursor at SP+0x16d0 moves from `0x480` to `0x460` through `0x10068ae70..0x10068ae7c`, a 32 B rewind proved for every u64 input. Reload `0x10068ae7c` consumes continuation `0x1007812e8` from SP+0x8ca8 and emission `0x10068ae84` uses IA `0x5ae9`. Its earlier origin is load `0x10083c8b0` from slot `0x10103ea90`, then store `0x10083c8b8`. The audit checks all 76 original constructor origin pairs, 678 intervening retained intervals and allocator invalidation spans, then the current save/load chains; no overlapping destruction is admitted. This is inherited conditional source provenance, not an original initializer epoch join. [CG1-CG6; CG-A1-CG-A6]

The stop is `0x1005f149c`, before `LDR X13,[SP,#0x260]`, address `0x6800060360`, extent 8 B, definedness mask `0000000000000000`. Physical `ca` backing bytes do not define it. Initializer writer `0x10061a5e8` has four distinct profile values: `0x44b9fdee0c489c26`, `0x44b9fdee0c489d26`, `0x44b9fdee0c489e26`, `0x44b9fdee0c489f26`. Their frame-placement dependence contradicts a single invariant-pointer substitution. An address-dependent source decoder and a complete live-frame join remain open. [CG1-CG6; CG-A1-CG-A4,CG-A8]

## Verification and limits

Each class executes 96501 visits, 16788 reads, 3082 writes, 4596 logical edges and twelve internal calls; `4*96501=386004`. Full independent replay checks 12352256 GP/SP and the same number of Q values, `32*(386004+4)` each; 386008 NZCV frames; 396564 read B and 53960 write B. It checks 18336 authenticated pointer chains, 18340 original fixup reads, 36 exact saved-pointer stores and 32 exact reloads. Original return edges account for the other 48 logical edges. Hardware PAC does not execute. [CG3-CG6; CG-A1-CG-A6]

Exact 76-parent admission checks 4283 byte demands and six whole registers per parent: SP,X20,X26,X29,X8,X9. Totals are 325508 byte demands, 456 register demands, 873836 terminal B, 2432 preserved Q values and 608 undefined frontier B. Forty-four changed root-byte and forty-four missing root-byte controls, eight changed-register controls and four owner controls are rejected. Eight unused Q0/X18 and four unused-byte controls preserve their supplied differences; 152 inherited unread-byte differences remain. [CG3-CG6; CG-A2-CG-A6]

Eight nonvacuous UNSAT source queries establish CAS return/replacement, gate dispatch, exact-one readiness dispatch, release value, duplicated U fields, U flag/S publication, cursor rewind and descending address-derived fill. Arithmetic is u8/u32/u64 modulo 2^width, with explicit signed extraction/widening and source-defined flags. All addresses, offsets and extents are in bytes. Extraction/audit complexity is O(receipts+visits+parents*demands+initializer journals+text words+query DAG) time/storage; full replay is O(visits*(register state+byte effects)+joins) time and O(receipts+largest interval+byte map) storage. Solver timeout is 30 s per query; no native performance is measured. [CG1-CG6]

Logical SHA-256: checks `9c4ad519628142f228742dd3a011a6b10f94aa106783bd6ba30caffad70af6ff`; replay `fc62eda40f7eeb4750c193183740342c223f684247ade9713b7fcd5decb047dc`; audit `d95e9e56e1fef1cd3f2fcf610670abcaa98e03159995d478d166e572d97d5b34`. Large JSON receipts and the manifest are compressed with `zstd --ultra -22 -q -T1`, with decoded round-trip checks. Written raw/structured/packed/hexadecimal content is checked for analyst-local paths. Three original inputs remain unchanged. Existing evidence suffices for this increment; no IDB access or mutation is needed. [CG1-CG6]

## Assumption register and bounded next evidence

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CG-A1: Pinned original source/fixups apply | Instructions, pointers, targets and equations | Check each visited opcode, initializer writer word, original fixup word/IA modifier and text SHA. |
| CG-A2: The 76 inherited states are conditional entries | Four-class coverage and terminal state | Check required bytes/registers, PC, configuration, owner extents and each parent export; other allocator/SIDB frontiers remain outside scope. |
| CG-A3: Eleven initializer-compatible fields are additional premises | All continuation results | Require all twelve writer profiles, reject changed/missing live root bytes, preserve the original undefined frontier and keep the current initializer epoch join false. |
| CG-A4: Sequential execution and inherited image/allocator/input premises apply | Gate transition, arena metadata, T and U bytes | Replay all frames/events and preserve owners; native concurrent changes, native allocation success and lifetime remain unknown. |
| CG-A5: Exact whole-register/byte admission permits class reuse | 76 conditional exports | Verify 4283 byte/six-register demands per parent, reject changed owners/registers, preserve unused Q/GP/bytes and undefined U/frontier fields. |
| CG-A6: Exact pointer provenance and logical authentication apply | Original dispatch, saved continuations and returns | Follow actual fixup reads through only exact 64-bit loads/MOVs/stores, invalidate overlapping byte tags, check all earlier origin/custody journals; do not infer hardware PAC. |
| CG-A7: Source phases, address widths and selected byte tables apply | Fill equation and U field formulas | Prove original fragments for all declared bit patterns, compare every finite address/value, distinguish raw fields from higher-level status/length names. |
| CG-A8: Local source publication does not establish native/external exposure | S/U/T ownership and cross-layer conclusions | Require continuous caller/lifetime and transport-buffer joins; J and IPC boundaries remain explicitly unchanged or unknown. |

| Impact | Bounded next evidence | Result sought and present limit |
| --- | --- | --- |
| High | Recover SP+0x260's source address-dependent decoder | Establish its caller-frame value without projecting one initializer placement onto another. |
| High | Trace S/U/T consumers after that field | Establish raw field interpretations, object lifecycle and any complete J publication; eight U bytes remain undefined. |
| High | Join actual payload/object identities to Mach/IOKit requests | Establish transport buffers, port directions and emission sites; this increment has no imported call or IPC emission. |
| High | Establish a continuous initializer-to-current-frame path | Replace the eleven additional root premises with source custody for the actual caller epoch. |
| Medium | Inventory other users of this same gate and descriptor | Establish source critical-section boundaries, release paths and concurrency-sensitive state; no native synchronization classification follows yet. |
| Medium | Reduce the earlier block kernel and present byte-table transforms | Establish compact algorithms and conventional identities beyond full finite replay. |
| Medium | Broaden remaining allocator/failure/SIDB states | Establish coverage beyond this 76-state constructor-success subset. |

**QG1** passes: factual source/interface analysis. **QG2** passes: CG-A1-CG-A8 record dependencies and falsification probes. **QG3** passes for this separate conditional gate/arena/object increment; the full interface goal remains active. **QG4** passes: exact widths, byte extents, counts, modular equations and complexity are explicit. **QG5** passes: added root premises, nonconstant +0x260, address-derived fill, U definedness and S/J publication sites remain distinct. **QG6** passes after full independent replay, fresh admission/contracts/equations/census, origin/custody checks and publication verification. **QG7** passes: impact-labeled next evidence and native/transport limits are explicit.
