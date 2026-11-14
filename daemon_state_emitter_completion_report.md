# Constructor emitter completion, heap population and table-copy interface

The constructor's private 21-byte emitter request now completes. Original instructions produce `9ed9bba4d80a2a283821340f11b1d36bcf12dcf509` at private scratch `0x680006c5d0`. The actual caller copies all 21 bytes, descending, into T/21 B while applying XOR `0x98`; T becomes `0641233c4092b2b0a0b9ac9789294bf3578a446d91`. This establishes the scratch-to-heap data path previously left open. It does not establish a file-format field, external delivery or native transaction. [EC1-EC6; EC-A1-EC-A9]

All 76 inherited success states are covered by four independently replayed representative executions plus explicit read-before-write admission and member-specific terminal exports. The four classes have 34, 4, 34 and 4 members. Coverage does not mean 76 full instruction replays. The next interface is an original 256-byte image-to-private copy, completed before the frontier at `0x1006d7fa8`. U/48 B remains wholly undefined; S/64 B retains 53 defined and 11 undefined bytes. No current write publishes non-NULL S at J+0x68. [EC2-EC6; EC-A2-EC-A6,EC-A9]

```text
76 inherited states at full-state twist entry
  -> 4 machine/controller classes + exact byte-dependency admission
     -> 6 full in-place 624-word twists per execution
     -> select indices9..14 / temper / 21 nonzero byte stores
     -> private21 output complete / raw status 8b3dc651
     -> adapter adjustment0 / caller SP restored
     -> descending21 byte copy, each XOR98 -> T/21 fully defined
     -> private cursor480 -> 680, reserving512 B
     -> first256 scratch undefined; second256 receives image table
     -> original copy returns -> 1006d7fa8, before next instruction

U/48 undefined; private slot carries U+32
S/64 mask unchanged; J+68 publication not observed
Mach/IOKit emission and native epoch pairing unknown
```

No new imported return value or input byte is supplied. No native target API, IPC, filesystem, allocation/free, hardware pointer authentication or IDB mutation executes. Prior conditional allocator/ABI and synthetic-input premises remain inherited. [EC1-EC6; EC-A1-EC-A4,EC-A9]

| Evidence | Primary artifact and verified scope |
| --- | --- |
| EC1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_state_emitter_completion.py) retains original opcodes, fixups, journals and terminal definitions. |
| EC2 | [Parent allocation cascade](daemon_state_allocation_cascade_report.md), [checks](triage_evidence/daemon_state_allocation_cascade_checks.json.zst) and [audit](triage_evidence/daemon_state_allocation_cascade_audit.json.zst): all 76 successful T/21 B and U/48 B continuations at the full-state twist entry. |
| EC3 | [Current checks](triage_evidence/daemon_state_emitter_completion_checks.json.zst): four complete source journals, 320 intervals, 76 admitted parent indices and 76 derived terminal states. |
| EC4 | [Independent auditor](triage_evidence/audit_daemon_state_emitter_completion.py) and [audit](triage_evidence/daemon_state_emitter_completion_audit.json.zst): GP/Q/NZCV/byte replay, compact generator/copy contracts, incoming dependencies, fault controls and eleven source equations. |
| EC5 | [Generated-stream](daemon_generated_stream_report.md) and [postseed-output](daemon_postseed_output_report.md) evidence: source-pinned twist, comparison, byte codec, adapter and XOR-copy equations. Their equations are rebuilt for this increment; their caller-specific output bytes are not substituted. |
| EC6 | [Publication verifier](triage_evidence/verify_daemon_state_emitter_completion_publication.py): pinned replay receipts, original bytes/fixups, joins, fresh all-parent admission/effects, rebuilt equations, sixteen function-start brackets, exact manifest delta, input preservation and decoded path hygiene. |

## Exact emission, return and copy sites

Addresses are preferred-image or retained model addresses. S=`0x6600040000`/64 B, T=`0x6600050000`/21 B, U=`0x6600060000`/48 B, J=`0x6500115b20`; outer SP=`0x6800060100`. Native allocation placements and lifetimes remain unknown. [EC1-EC4,EC6; EC-A1-EC-A4]

| Site or interface | Source-established action | Extent / target |
| --- | --- | --- |
| 0x100a6cd1c | Inherited pending full-state twist entry | Original first instruction begins this increment |
| 0x100a5e93c / 0x100b312a4 / 0x100a2f634 | In-place generator-state updates | 227 + 396 + 1 u32 words per full twist at G=0x1010c784c |
| 0x100a0ca74 | Address-dependent nonzero output candidate store | One byte at output+remaining-1; remaining decrements only for nonzero stored byte |
| 0x100a6d390 | Completion status store | u32 0x8b3dc651 at request0x6800070db8 |
| 0x100a6d3c8 | Logical emitter return | 0x100add7d8 |
| 0x100add7d8 / 0x100add7e4 | Read temporary low32 / write adapter adjustment | 0x2ef8f9c5 at0x6800060070; u64 zero at0x680006bda0 |
| 0x100add7f8 | Logical adapter return | 0x10093ca84 |
| 0x10093ca84..0x10093ca90 | Caller adjustment reload and SP addition | SP+delta modulo2^64; actual delta0 preserves0x6800060100 |
| 0x100576f10 / 0x100576f28 | Actual private-output read / transformed heap store | 21 descending byte pairs; T[i]=output[i] XOR0x98 |
| 0x1006d7ef0 | Private cursor reservation | u64 0x480 ->0x680 at0x68000617d0, reserving512 B |
| 0x1004e020c | Carry a heap-relative pointer in private storage | U+32=0x6600060020 at0x6800062d40; no write into U |
| 0x1006d7fa4 | Original internal copy call / IA0x34a1 | Target0x10046f89c; X0=source0x100e406a0, X1=destination0x680006c6f0, X2=256 B |
| 0x1006d7fa8 | Final frontier | Copy returned; stopped before next instruction |

The adapter computes `delta64 = zero_extend64(low16(input32-expected32)) << 4`. Here input32 and expectedW21 both equal seed low32 `0x2ef8f9c5`, so delta=0 B. This result follows from the actual temporary read and expected register, separately from the private completion status. The caller's frame adjustment is independently proved for arbitrary 64-bit SP and adjustment values. A zero adjustment and raw status do not establish a public API return or aggregate constructor success. [EC1,EC3-EC6; EC-A1-EC-A4,EC-A8-EC-A9]

## Generator schedule and byte transformation

The state is 624 u32 words, 2496 B. Each full twist traverses i=0..623 in place. With the source-visible current array M, `y=(M[i]&0x80000000)|(M[(i+1)%624]&0x7fffffff)` and `M[i]=u32(M[(i+397)%624] XOR (y>>1) XOR (0x9908b0df if M[(i+1)%624]&1 else 0))`. Later indices can read words already updated in that traversal. Each selected raw word is tempered by XOR-right11, XOR-left7 masked0x9d2c5680, XOR-left15 masked0xefc60000, then XOR-right18, with u32 truncation. These source equations do not imply a conventional library extraction schedule. [EC1,EC3-EC6; EC-A1-EC-A3,EC-A7]

Each retained execution performs six complete twists: `6*624=3744` word updates. Index and generation counter start at9; the six selections use indices9..14 and both finish at15. The 21 byte attempts use shifts `(0,8,16,24)` five times followed by0. All stored bytes are nonzero, so exactly21 attempts complete the request without a zero retry on these paths. Each selection is preceded by a new full twist. Arbitrary-state termination and behavior of unseen zero candidates remain unknown beyond the source-local retry equation. [EC1,EC3-EC6; EC-A1-EC-A3,EC-A7]

The byte codec is address dependent. For byte destination a, let c be the source-selected cached u32, r=u32(c+low32(a)), m the decoded image mask and t the decoded text base. The original text reads use `ta=byte[t+(u32(r+0x0ba3ccc8)&m)]`, `tb=byte[t+(u32(r+0x0ba3ccca)&m)]`. The candidate is `u8((tempered>>(shift&31)) XOR u32(31*low32(a)) XOR ta XOR tb)`; the stored byte is candidate XOR0xd7. The auditor checks actual cache/text address producers, bytes, shifts, remaining counts and descending output addresses. No new randomness or entropy API executes in this increment. [EC1,EC3-EC6; EC-A1-EC-A4,EC-A7]

| Region after completion | Size | Established bytes or definedness |
| --- | --- | --- |
| Private output0x680006c5d0 | 21 B | 9ed9bba4d80a2a283821340f11b1d36bcf12dcf509 |
| T=0x6600050000 | 21 B | 0641233c4092b2b0a0b9ac9789294bf3578a446d91 |
| S=0x6600040000 | 64 B | 53 defined,11 undefined; mask and values unchanged |
| U=0x6600060000 | 48 B | Entirely undefined; no payload read or write |
| First new private scratch0x680006c5f0 | 256 B | Entirely undefined at current frontier |
| Second new private scratch0x680006c6f0 | 256 B | Exact image table from0x100e406a0 |
| J+0x34 | 32 B | Earlier generated bytes unchanged |
| J+0x68 | 8 B | No current source write publishes non-NULL S |

The 256-byte literal contains every byte value exactly once; SHA-256 `3217b5ed48b0ac4623abdd9e60de4889964d34591f450151fa180e5d7c69b266`. The original copy performs32 u64 loads and32 u64 stores in104 source visits including call/return. A permutation table alone does not establish an algorithm identity. The next mixing loop and consumers of its result remain unrecovered. Likewise T[0]=0x06 does not establish equivalence to an earlier context header whose numerical value is6. [EC1,EC3-EC6; EC-A1-EC-A3,EC-A7-EC-A9]

## Four-class coverage and control provenance

The class key includes all31 GP registers, all32 Q registers, SP, NZCV, pending PC, owners, configuration and two live controller words. Grouping only by machine/owner state was insufficient: the byte-dependency check rejected eight states because those controller words differed. The final four-class partition preserves those values explicitly. Values below are decoded little-endian u32, not raw byte strings. [EC1-EC4,EC6; EC-A1-EC-A3,EC-A5]

| Representative parent index | Members | Inherited ABI pattern | u32 at0x1010c4f48 | u32 at0x1010c4670 |
| --- | --- | --- | --- | --- |
| 0 | 34 | 1 | 0x8fd18fb9 | 0x46b9aad9 |
| 17 | 4 | 1 | 0xf6240d9f | 0x86808883 |
| 38 | 34 | 0 | 0x8fd18fb9 | 0x46b9aad9 |
| 55 | 4 | 0 | 0xf6240d9f | 0x86808883 |

Each representative receives complete independent instruction replay. Ordered reads identify every byte required before its first write; later reads must match preceding source effects. Each of76 parents must match exact machine-entry state and all required bytes, retaining incoming-defined versus immutable-image provenance. The decoded source fixups are included. Source writes must be disjoint from visited opcode bytes. Under the sequential deterministic model, equal admitted inputs therefore support the same source trace/effects. Every parent's final definitions are its own original definitions overlaid with those effects; unread incoming differences are preserved. This is finite conditional coverage, not arbitrary native schedule, hardware PAC or allocator equivalence. [EC1-EC4,EC6; EC-A1-EC-A6,EC-A9]

Coverage checks321228 ordered read B and66040 ordered write B across the four journals; admits76 parents against267436 byte requirements; verifies797532 derived terminal B; and preserves152 unread byte differences. These are accumulated checks, not distinct memory footprints. Four changed-live-byte controls and20 changed-machine-state controls are rejected; four changed-unused-byte controls are admitted with the changed byte preserved. The machine controls cover GP, Q, SP, NZCV and owner differences. [EC3,EC4,EC6; EC-A2-EC-A6]

The caller's indirect continuation is source-traced: load0x1007cf718 reads slot0x101043300 ->0x1004e01e0; store0x1007cf720 saves it at0x6800068fb8; reload0x10059cd50 feeds branch0x1005068ac with IA0x7295. Replay checks origin, save/reload, register and byte non-overwrite. The copy target has a separate cross-interval origin: load0x1006d7f48 reads slot0x10109fc88 ->0x10046f89c into X11, which remains unchanged through the pending copy call at0x1006d7fa4. Four explicit origin checks join that producer to the next interval. Logical targets/modifiers do not observe hardware authentication. [EC1,EC3,EC4,EC6; EC-A1-EC-A3]

The original1005-entry LC_FUNCTION_STARTS table has1864 B at file offset17603576, SHA-256 `ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54`. Sixteen sites are bracketed; copy target0x10046f89c is an advertised start, while the other inspected sites are interior fragments. No exact-site original symbol is present. Complete noncontiguous function chunks, original semantic names and all callers remain unknown. Retained original-image evidence sufficed; IDA was not queried. [EC1,EC3,EC4,EC6; EC-A1,EC-A9]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| EC-A1: Pinned image and decoded source fixups apply | Instructions, equations, targets and metadata | Verify image/opcode/slot/modifier bytes, original start brackets and saved continuation/copy origins; native PAC remains unknown. |
| EC-A2: All76 frozen inherited success states are conditional entries | Current complete finite paths and coverage | Verify exact parent indices, GP/Q/NZCV/SP/owner/configuration joins; do not expand the earlier836 other pending allocations or full1543-state frontier by these counts. |
| EC-A3: Sequential deterministic source model applies | Four representative traces and member effects | Independently replay every instruction/register/read/write, require all demanded bytes and no opcode overwrite; concurrent native mutation remains outside the model. |
| EC-A4: Inherited imported-return, allocator and synthetic-input premises apply | T/U owner identities, generator entry and seed context | Check parent receipt hashes/joins and no new imported return or input byte; historical native ABI, file contents and allocator placements remain unknown. |
| EC-A5: Class partition and read-before-write admission are exact | All76 coverage from four executions | Include both live controller words; verify every ordered read/effect, changed-live-byte/GP/Q/SP/NZCV/owner rejection and unused-byte preservation. |
| EC-A6: Undefined bytes and unread differences remain unknown/preserved | S53/11, undefined U/48 and first private256 B | Check masks, all reads/writes and each member-specific terminal map; never fill an absent byte from allocator backing storage. |
| EC-A7: Current source phases and generation state apply | Six full twists,21 nonzero stores, exact output and heap bytes | Recompute all3744 updates per representative, every624-word boundary, tempering, address-dependent codec and21 actual XOR-copy pairs; arbitrary-state output/termination remains unknown. |
| EC-A8: Private status, adapter delta and actual consumer interfaces are distinct | Completion/return, frame restoration and table copy | Check exact status/delta addresses, return targets, arbitrary-bit SP equation, original copy source/destination/length and boundary registers; final public status remains unknown. |
| EC-A9: Local stores do not establish publication, algorithm identity or transport | Payload-role, lifetime and daemon-kext conclusions | Require downstream consumers, object identity, actual emission and native epochs; do not name an algorithm from a permutation table or equate numeric byte values with fields. |

## Reproduction, quality gates and bounded continuation

Checks logical SHA-256: `7339ebf095b22c8c390b536023d1639fbd2d36295124208a1784f1737f0bd2f1`. Audit logical SHA-256: `f94527805283b8d0c99a5fd964e914e043ba57869bd551c4864c02ceb03931ba`. Checks, audit and manifest use `zstd --ultra -22 -q -T1`; round-trip decoded hashes are checked. Raw, structured and decoded hexadecimal payloads are checked for analyst-local paths. Inherited target-defined ABI paths retain their evidence meaning. [EC3,EC4,EC6]

Per representative:78 emitter intervals/79076 source visits,496 caller-setup visits and104 original-copy visits. Thus `4*80=320 intervals` and `4*(79076+496+104)=318704 source visits`. The four journals contain63740 reads,16080 writes,15496 logical edges and48 internal calls. Every representative finishes at0x1006d7fa8 with outer SP0x6800060100, X19=U+32, X20=second private table0x680006c6f0, X21=first private scratch0x680006c5f0 and X22=J+0x1c. Retired A/4096 B remains undefined and absent from the owner list. No final mixing, U initialization or container publication is claimed. [EC1-EC4,EC6; EC-A1-EC-A9]

Independent replay covers all320 intervals and verifies10208768 scalar plus10208768 vector register values: `(318704+320)*32` of each. Compact contracts check14976 twist updates,199680 full-state boundary words,24 selected/tempered words,84 emitted bytes,84 actual heap-copy byte pairs and1024 table-copy B. Eleven nonvacuous UNSAT queries cover original first/second/last twist equations and table addresses, tempering, byte codec/retry transfer, shift exhaustion, comparison record, byte-copy transform, status store, adapter delta and caller SP restoration. Solver limit30 s/query. The publication verifier freshly rebuilds the equations and coverage; it verifies the pinned complete replay receipt rather than repeating that entire replay. [EC1,EC3-EC6]

Arithmetic is exact u8/u16/u32/u64 modulo2^width, with unsigned comparisons and explicit zero extension; lengths/addresses/offsets are bytes. Extraction time/storage is O(parent bytes+representative visits+effects+source). Independent replay is O(V*(register state+effects)+P*D+joins+query DAG) time, O(receipts+largest interval+requirements+parent state) storage, where V is retained visits, P=76 and D is required input bytes per class. No native timing or memory cost is measured. [EC1-EC6]

| Impact | Next evidence | Architectural purpose and current boundary |
| --- | --- | --- |
| High | Continue0x1006d7fa8 through actual mixing and U consumers | Establish table transformation, read-before-write status of first scratch, U layout and payload role; current U remains undefined. |
| High | Trace T and S stores through J+0x68 publication and consumers | Establish object layout, aggregate status and ownership/data paths; current heap bytes alone do not establish those roles. |
| High | Join actual object/generated bytes to Mach/IOKit buffers and native epochs | Establish daemon-kext transaction pairing, ports and emission sites; this increment introduces no such emission. |
| High | Find S+0x30 producer/lifetime on failure routes | Resolve the parent's undefined8 B demand without invented values. |
| Medium | Broaden earlier836 pending64 B allocator states and caller phases | Test whether the observed allocation/generation/copy chain generalizes; present76 parents are the full current success subset. |
| Medium | Determine generator-state serialization and native scheduling | Evaluate whether globally mutated words can be joined across actual callers; current execution is sequential and conditional. |

**QG1** passes: factual source/ABI analysis. **QG2** passes: EC-A1-EC-A9 record dependencies and falsification probes. **QG3** passes for the emitter/heap-copy/table-interface increment; the full interface goal remains active. **QG4** passes: exact byte extents, widths, counts, equations and complexity. **QG5** passes: four-class coverage versus four full replays, raw status versus adapter adjustment, private copy versus external delivery, and table contents versus algorithm identity remain explicit. **QG6** passes after source-pinned replay, admission/fault controls, eleven rebuilt equations, function metadata, preserved-input and publication checks. **QG7** passes: impact-labeled continuation and unknowns are bounded above.
