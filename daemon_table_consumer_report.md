# Mixed-table consumer: record decoder, byte passes, block feedback and caller status

The pending call at `0x1004d5df0` now completes through advertised entry `0x1004172f4`, with logical IA modifier `0xf248`. On the inherited caller path, this is an in-place 256 B transformation: a descending byte pass, sixteen 16 B block transfers with carried state, and a second descending byte pass. The record decoder establishes destination/source roles, an extent of 256 B, normalized control `0x616f`, and a separate encoded-image source for 16 B of private initialization state. Conventional algorithm identity remains unknown. [TC1-TC6; TC-A1-TC-A9]

Four complete machine/controller classes, sizes 34/4/34/4, cover all 76 inherited states through exact incoming-byte admission and parent-specific terminal exports. The retained execution has 228728 original instruction visits, eight intervals and four executed internal calls. All four classes produce the same final 256 B, SHA-256 `1e27862cdae21623b3d793365576f53012bae4b6134aca92d5e08bac32167992`. These are conditional source executions; native daemon-kext transaction pairing remains unknown. [TC1-TC6; TC-A1-TC-A6,TC-A9]

```text
76 frozen constructor states
  -> 4 machine/controller classes; exact byte/register/owner admission
  -> call 1004d5df0 -> 1004172f4 / logical IA f248
       decode record: destination = source = first private table; extent 256
       descending pre-XOR pass, i = 255..0
       image16 -> private16 initialization state
       16 successive blocks, each reads/writes 16 B
         original 2054-instruction kernel
         24-instruction feedback transfer between successive blocks
       descending post-XOR pass, i = 255..0
       record status store; stack guard comparison; original RETAB
  -> return 1004d5df4; caller reads record status = 8b3dc651
  -> copy status; private cursor 680 -> 580; take success slot
  -> STOP 10057ac04 before reading undefined SP+5b0 / 8 B

S/T/U payloads and context unchanged; no new Mach/IOKit emission
```

| Evidence | Primary artifact and scope |
| --- | --- |
| TC1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_table_consumer.py) retains all source words, fixups, journals and member-specific exports. |
| TC2 | [Table-mixing parent report](daemon_state_table_mixing_report.md) and [checks](triage_evidence/daemon_state_table_mixing_checks.json.zst): all 76 incoming states before the call, including mixed table bytes and the actual target load at `0x1004d5de0`. |
| TC3 | [Current checks](triage_evidence/daemon_table_consumer_checks.json.zst): four full classes, eight intervals, source regions/fixups, register projection and 76 terminal exports. |
| TC4 | [Independent replayer](triage_evidence/replay_daemon_table_consumer.py) and [receipt](triage_evidence/daemon_table_consumer_replay.json.zst): every GP/SP/Q/NZCV frame, ordered byte event, logical edge and cross-interval call-target origin. |
| TC5 | [Auditor](triage_evidence/audit_daemon_table_consumer.py) and [audit receipt](triage_evidence/daemon_table_consumer_audit.json.zst): all-parent admission/fault controls, byte-pass equations, block footprints, state decoding, status/cursor contracts, nine nonvacuous source queries and original-text/initializer census. |
| TC6 | [Publication verifier](triage_evidence/verify_daemon_table_consumer_publication.py): pinned full replay; fresh coverage, contracts, equations, census, fourteen function-start brackets, exact manifest delta, input preservation and decoded path hygiene. |

## Recovered private record ABI

The retained model placements are outer SP=`0x6800060100`, record R=SP+`0x10cb8`=`0x6800070db8`, first table A=`0x680006c5f0`/256 B and second table B=`0x680006c6f0`/256 B. These addresses do not establish native placement or lifetime. Entry `0x1004172f4` subtracts `0x1f0` from SP, saves X19-X30, sets FP=outer SP-`0x10`, and saves the record pointer at callee SP+`0x10`. No new API return, input byte or owner extent is supplied. No native target API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation executes. [TC1-TC6; TC-A1-TC-A4]

| Record field | Raw current value | Established consumer role and source site |
| --- | --- | --- |
| +0x00 / u32 | `0x8b3dc651` after call | Status output written at `0x10002fce4`, then read by caller at `0x1004d5df4`. Its equal pre-call value does not prove execution; the source write ledger does. |
| +0x04 / u32 | `0xbe39842c` | Address-coded control; adding the decoder key yields `0x616f` at `0x100417478`. Further phase arithmetic remains in original source. |
| +0x08 / u32 | `0x39af9964` | Encoded extent: key addition followed by `+0x84898a59` gives u32 256 at `0x100417438`; stored as 64-bit count at callee SP by `0x10041745c`. |
| +0x0c / u32 | `0x68` | Residual prior definition; no current read establishes a parameter role. |
| +0x10 / u64 | A | Destination pointer loaded by `0x100417420`; descending prepass stores use it at `0x100012040`. |
| +0x18 / u64 | A | Source pointer loaded by `0x100417420`; descending prepass loads use it at `0x100012004`. |
| +0x20 / u64 | `0x100fe69d4` | Encoded-image initializer source, reloaded sixteen times at `0x1000ac768`; its bytes are read at `0x1000ac770` and decoded to private 16 B. A cryptographic key/IV designation remains unknown. |

For record address r, the callee key is `K=u32((low32(r) XOR0x8515cfbd)*0xc7f6dca7)`, from original `0x1004173ec..0x100417420`. The producer from TC2 has a different-looking OR/add/XOR expression. Their round trip proves destination=source, extent=256 and control=`0x616f` for every pointer and **even outer SP**, under the current source phases. Every retained SP is `0x6800060100`, satisfying this premise. [TC1-TC6; TC-A1-TC-A5,TC-A8]

The address premise is material: an algebra-only control with SP=`0x6800060101` gives decoded extent 1880246194 and control `0x7012a821`. No odd-SP target execution is performed. The universal proof is explicitly conditioned on even SP; it does not assert producer/consumer compatibility at arbitrary address parity. Pointer aliasing itself remains exact. Incoming X1=`0x14` is not the count consumed by this decoder. [TC1,TC3-TC6; TC-A1,TC-A5,TC-A8]

The complete original-text census finds one authenticated fixup targeting the entry: slot `0x1010a09e0`, target `0x1004172f4`, IA diversity `0xf248`, address diversity 0. The parent's load at `0x1004d5de0` is checked through the pending-call boundary without an intervening X8 write. No direct immediate B/BL targets the entry in the scanned text. This is a direct-opcode/fixup census, not proof that no other indirect caller exists. [TC1-TC6; TC-A1-TC-A3,TC-A9]

## Byte passes and initialization state

Let `j=i&15`. For the retained table selections, the prepass computes `A[i]=source[i] XOR pre[j]` for i=255..0. Its load/store sites are `0x100012004`/`0x100012040`; every intermediate lookup and address is checked. The mask is `37b85dbd06176e5946953aa7a1f9c8f6`. The source equation is:

`pre[j]=image[0x100e5d890+j] XOR image[0x100e4c173+j] XOR image[0x100ffe717+j] XOR u8(0x57*j) XOR0xe8`.

The independent query covers every input/table byte and count 1..256, including descending source/destination addresses. It abstracts the three actual table bytes as independent u8 inputs; the finite audit separately checks all selected image addresses/bytes. Each original iteration is 24 instructions, totaling 6144 visits per class. Aliased source/destination therefore performs this pass in place. Behavior for other overlap arrangements is unknown. [TC1,TC3-TC6; TC-A1-TC-A5,TC-A7-TC-A9]

The routine separately reads the sixteen bytes at `0x100fe69d4..0x100fe69e3`, descending, and writes private state at outer SP-`0x80`..SP-`0x71`, via `0x1000ac840`. For image byte b at index j, its source-defined transform is:

`private[j]=u8((b XOR0x6a)+((b<<1)&0xd4)+0x39) XOR image[0x100f6b3c0+j] XOR image[0x100f6f7d0+j] XOR image[0x100ecd420+j] XOR u8(0x7b*j) XOR0x0b`.

All four classes produce `d165d5ddc61f5740517e83448c2fda81`. The query retains original fragments `0x1000ac768..0x1000ac78c` and `0x1000ac828..0x1000ac844`, with the selected lookup bytes treated as explicit parameters. The full replay and finite read ledger additionally validate the intervening opaque table selection. This state is stack-local on the recovered path; its standard cryptographic interpretation remains unknown. [TC1,TC3-TC6; TC-A1-TC-A5,TC-A7-TC-A9]

After the block kernel, the second pass computes `A[i]=A[i] XOR post[j]`, again i=255..0, at store `0x1000f71d8`. Its mask is `71da45d49d7fb9a620c697e8de8b02bb`:

`post[j]=image[0x100fed074+j] XOR image[0x100e9a435+j] XOR image[0x100e3d370+j] XOR u8(0x5f*j) XOR0x56`.

The decrement is independently proved from `0x1000f7100..0x1000f7110`, with count 1..256. The byte equation uses `0x1000f7198..0x1000f719c` and `0x1000f71b4..0x1000f71dc`, given the selected table pointers. It does not claim a universal simplification of the intervening global-dependent dispatch. Every selected table address and ordered read/write is checked across the complete finite path. Each original iteration is 62 instructions, totaling 15872 visits per class. [TC1,TC3-TC6; TC-A1-TC-A5,TC-A7-TC-A9]

## Sixteen-byte block kernel and carried state

Each block executes exactly the contiguous original span `0x1000591ac..0x10005b1c4`: 2054 instructions, including its final authenticated branch. There are sixteen executions, totaling `16*2054=32864` source visits per class. Fifteen intervening transfers execute `0x1000bcd5c..0x1000bcdbc`, 24 instructions each. This is a source-defined block kernel with exact finite replay, not a recovered standard cipher implementation. [TC1,TC3-TC6; TC-A1-TC-A5,TC-A7-TC-A9]

| Block-local operation | Original order of offsets within the current 16 B block |
| --- | --- |
| Input reads | `9,7,8,10,5,12,0,1,2,14,6,11,15,4,3,13` |
| Output writes | `7,15,0,10,12,8,9,11,13,4,1,3,6,5,2,14` |

Block k covers A+16*k..A+16*k+15, k=0..15. Every input read precedes every output write within that block. The input byte values match the prepass array, and the exact output bytes are retained per block in TC5. Register/private-word state carries between blocks, so this footprint does not establish independent-block operation. The common source includes arithmetic, shifts, bit-field operations and image lookups; algorithm identity and a compact semantic reduction of that central kernel remain incomplete. [TC1,TC3-TC6; TC-A1-TC-A5,TC-A7-TC-A9]

The original inter-block transfer has the following exact assignments. Right-hand sides refer to its incoming values; arithmetic is u32, and the store uses callee SP. A source query proves these equations for all six incoming u32 words. [TC1,TC3-TC6; TC-A1-TC-A3,TC-A7-TC-A8]

| Output | Equation from `0x1000bcd5c..0x1000bcdac` |
| --- | --- |
| W7 | incoming W1 |
| W15 | incoming W10 XOR `0x29fd2e49` |
| W19 | u32(incoming W1+`0xa21b06bd`) XOR incoming W8 |
| u32 at callee SP+0x98 | incoming W0 XOR `0xf4b8b043` |
| W2 | incoming W2 XOR `0xb41558cc` |
| W5 | incoming W21 XOR `0x22b89c83` |

These source-level state transfers remain explicit. They do not establish CBC, another named mode, or that the private 16 B is a standard key or IV. The full central source and every intermediate GP/SP/Q/NZCV frame are retained for subsequent semantic reduction. [TC1,TC3-TC6; TC-A1-TC-A9]

## Completion status, cursor rollback and next undefined field

The epilogue `0x10002fcbc..0x10002fce8` writes `0x8b3dc651` when its private completion word equals `0x21fb086f`; otherwise it writes `0x74c29d89`. This source equation is proved for every completion u32 word. The complete retained path has the success word and executes the actual status store. It then compares the saved stack-guard value, takes no guard-failure branch, restores X19-X30 and SP, and executes original RETAB at `0x10002fd1c` to `0x1004d5df4`. All 32 Q values remain unchanged. Hardware authentication and native stack-guard validity are not established. [TC1,TC3-TC6; TC-A1-TC-A6,TC-A8-TC-A9]

The caller consumes status through the record, not as the returned X0 value: X0 is `0xa6` at return. Caller load `0x1004d5df4` reads `0x8b3dc651`; store `0x1004d5df8` copies it to outer SP+`0x2d70`. Instructions through `0x1004d5e0c` rewind the private cursor at SP+`0x16d0` from `0x680` to `0x580`. The universal caller equation is `cursor_after=u64(cursor_before-256)` and index `0x5ade` for success, `0x5205` otherwise, under the recovered phase values. [TC1,TC3-TC6; TC-A1-TC-A6,TC-A8-TC-A9]

The original target load is at `0x1004d5e30`, success slot `0x1010675e0`; emission at `0x1004d5e38` uses IA `0xc80c` and reaches `0x10057abdc`. This is an internal control-flow transfer. At `0x10057ac04`, execution stops before `ldr x19,[sp,#0x5b0]`: address `0x68000606b0`, extent 8 B, every byte undefined. Physical backing patterns are not data definitions. No load of this field, later target transfer, new callback, non-NULL publication or transport delivery is claimed. [TC1,TC3-TC6; TC-A1-TC-A6,TC-A9]

The second private table remains unchanged. S=`0x6600040000`/64 B retains 53 defined and 11 undefined bytes; T=`0x6600050000`/21 B remains populated as before; U=`0x6600060000`/48 B remains wholly undefined. No current read/write touches these payloads or the retained 552 B context at J=`0x6500115b20`. X19's U+32 value is restored by the callee and remains until the stopped load would overwrite it. The private cursor rewind does not itself establish a native free or invalidation of table bytes. No new Mach name, right, message, IOKit request or emission site occurs in these intervals. [TC1-TC6; TC-A1-TC-A6,TC-A9]

## Shared image state and architectural touch points

The prologue loads u64 G1 at `0x1010b6890` and u64 G2 at the source-selected cell `0x1010c4670`, then writes both cells through original stores `0x1004173e0` and `0x1004173e8`. These are the only image-memory writes in each complete call interval. For outer SP s, let `d=u64(G1-(s-0x88)+G2)` and C=`0x73d046208eaed1a6`. Original source proves `G1_after=u64(d*0x0a5cd4cf+C)` and `G2_after=u64((d XOR C)*0x0a5cd4cf)` for every SP/G1/G2 bit pattern, given that selected cell. The finite full replay additionally establishes the actual cell selection and all later reads. [TC1,TC3-TC6; TC-A1-TC-A5,TC-A7-TC-A9]

| Representatives | Cell | Before u64 | After u64 |
| --- | --- | --- | --- |
| 0,38 | `0x1010b6890` | `0xf08490a95d93d60f` | `0x138bf662231c6c36` |
| 0,38 | `0x1010c4670` | `0x48d931d446b9aad9` | `0x10b27792af56640a` |
| 17,55 | `0x1010b6890` | `0xf08490a95d93d60f` | `0xc593d03db19270ac` |
| 17,55 | `0x1010c4670` | `0x2f505d6d86808883` | `0x6d313fc62e6be904` |

The two controller families produce equal table bytes but different shared-global states; complete exports preserve this distinction. These updates depend on inherited image state and stack placement. Native serialization, synchronization and inter-caller epochs are unknown. The record itself also uses address-dependent field coding, so its raw encoded fields remain tied to the producing record address. [TC1,TC3-TC6; TC-A1-TC-A9]

## Producer candidates and architectural boundaries

The entire original text, address `0x100001058`, extent 14849960 B, SHA-256 `94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e`, is scanned as 3712490 aligned instruction words. Sixteen encodings directly store u64 to `[SP,#0x5b0]`. Among these, initializer `0x1004c2b98` is independently present in all twelve retained upstream profiles: each writes `0x1010b5de0` to its own frame+`0x5b0`, with no later overlapping write in that retained profile. All candidate PCs and original words are retained in TC5. [TC1,TC5-TC6; TC-A1,TC-A3-TC-A4,TC-A9]

That initializer and the current constructor are distinct conditional paths with different frame placements. No continuous initializer-to-current-constructor control/lifetime join is established. The value `0x1010b5de0` therefore remains a source-established candidate for a separate compatible-entry premise; it is not injected into the current state. The census covers direct STR encodings only: alias-base writes, partial stores, stack rebasing and indirect callers require further analysis. [TC1,TC5-TC6; TC-A1,TC-A3-TC-A4,TC-A9]

The original LC_FUNCTION_STARTS table has 1005 entries, 1864 B at file offset 17603576, SHA-256 `ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54`. Fourteen current/candidate sites are bracketed. Only `0x1004172f4` among these sites is an advertised start, next advertised start `0x10041762c`. The low-address transformation fragments fall inside other advertised brackets. No exact-site original symbol is present. These brackets do not establish semantic ownership of noncontiguous chunks, complete callers or original routine names. Retained original-image evidence was sufficient; IDA was not queried for this increment. [TC1,TC3-TC6; TC-A1,TC-A9]

## Admission, falsification and reproduction

Each class requires 6037 incoming/read-only bytes and 15 whole registers. For all 76 parents this is `6037*76=458812` byte-requirement checks and `15*76=1140` register checks. Original deterministic effects define 756 distinct effect bytes per class. Every member retains its own unused bytes and register values; terminal comparisons check 829300 accumulated defined bytes, 2432 Q values and 608 still-undefined frontier bytes. Counts are accumulated checks, not native memory usage. [TC3-TC6; TC-A2-TC-A6]

Fault controls reject four changed demanded bytes, eight changed required registers and four changed owners. Eight unused Q0/X18 controls and four unused-byte controls are admitted and preserved. The projection has no vector access; independent semantic hooks exclude audit-only frame inspections. Ordered admission checks all later reads/effects, original immutable/fixup bytes, pending PCs, owner extents and configurations; writes do not overlap visited opcodes. [TC3-TC6; TC-A1-TC-A6]

Full independent replay checks 7319552 GP/SP values, 7319552 Q values, 228736 NZCV frames, 159816 read B and 16704 write B. Each register total is `(228728+8)*32`. It verifies 2280 authenticated logical edges and four inherited target-load origins; the remaining four logical edges are original returns. No frames are sampled. Unsupported CNEG was implemented as exact conditional negation before the successful full replay; existing evidence modules remain unchanged. [TC3-TC6; TC-A1-TC-A6]

Per class the complete call interval, including the caller's BLRAA, has 57154 visits/10968 reads/1259 writes/570 logical edges/one internal call; the caller tail adds 28 visits/five reads/two writes/one logical edge. Thus `4*(57154+28)=228728` visits across eight intervals. Three complete passes over A produce `3*256=768` byte writes per class, with 256 prepass writes, 256 central writes and 256 postpass writes. The sixteen block kernels and fifteen feedback transfers retain exact source order. Across four classes, finite contracts check 64 blocks, 60 feedback transfers, 64 input/output initializer bytes and 6144 mask-table reads. [TC3-TC6; TC-A1-TC-A8]

| Query | Scope of nonvacuous UNSAT result |
| --- | --- |
| 1 | Original producer/consumer extent, control and alias round trip for every even SP and pointer bit pattern |
| 2 | Original prepass byte equation and descending addresses for every input/table byte and count 1..256 |
| 3 | Original private-state decoder fragments for every initializer/table byte and index 0..15 |
| 4 | Original postpass decrement and low-nibble index for count 1..256 |
| 5 | Original postpass byte equation for every input/table byte and index 0..255, given selected table pointers |
| 6 | Original record-status store for every completion u32 word |
| 7 | Original caller status copy, u64 cursor rewind and success/failure slot partition |
| 8 | Original inter-block feedback assignments for all six incoming u32 words |
| 9 | Original paired shared-global updates for every SP/u64 state, given the source-selected second cell |

Logical SHA-256 values: checks `5137ecaa23c9984c362309dced8482323b1aca63357dcac61d3de3090a695f14`; replay `6318ee73698283ebfc4cf0534516402c471f75ae07b339feecfacdc4b433dd4c`; audit `05e23d2ba79cb44cde6226bc8dcf93fc280110810a3fdae1bed49edab9f05f8a`. Receipts and manifest use `zstd --ultra -22 -q -T1`, with exact decoded round-trip checks. Raw, structured, packed and decoded hexadecimal payloads are checked for analyst-local paths; all three original inputs remain unchanged. [TC3-TC6]

Arithmetic uses u8/u32/u64 modulo 2^width, explicit widening, source-defined flags, unsigned pointer comparisons and masked shift counts. Addresses, offsets and extents are bytes. Extraction is O(parent bytes+visits+effects+source) time/storage. Replay is O(V*(register state+byte effects)+joins) time and O(receipts+largest interval+byte map) storage. Contract/admission/publication work is O(receipts+V+P*D+text words+owned bytes+query DAG) time/storage, P=76 and D=6037 byte demands plus 15 registers. Source queries have a 30 s solver limit each. Native performance and native memory cost are unmeasured. [TC1-TC6]

## Assumption register and bounded continuation

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| TC-A1: Pinned original image, fixups and source phases apply | Decoder, addresses, branch targets and equations | Check every visited opcode, slot/modifier and function-start table; logical authentication remains distinct from native PAC. |
| TC-A2: The 76 inherited states are conditional entries | Complete finite call/return and exports | Admit every required register/byte, pending PC, configuration and owner; other 836 pending allocator states and the full 1543-state SIDB frontier are not expanded. |
| TC-A3: Sequential deterministic execution applies | Ordered byte effects, shared class coverage and termination | Replay every frame/event, preserve read-before-write requirements and reject opcode overlap; native concurrent mutation is unknown. |
| TC-A4: Earlier allocator, guard, image-global and input premises remain inherited | Placement, private state and context preservation | Check parent/dependency pins and absence of new input/API-return definitions; native owner lifetime and caller epochs remain unknown. |
| TC-A5: Whole-register/byte class admission applies | Four source executions cover 76 parents | Independently track semantic dependencies, verify 6037 demands and 15 registers, reject changed live bytes/SP/X0/owners, preserve unused Q0/X18/bytes and compare every terminal map. |
| TC-A6: Original frame save/restore and class identity apply | Return state and caller continuation | Check original return edge, saved/restored GP/SP, all Q values, ordered journals and source guard comparison; no fabricated ABI return/clobber is supplied. |
| TC-A7: Actual selected image tables and current phases apply | XOR masks, initializer bytes and block footprint | Check every selected read address/byte, all 64 block instances and source equations; arbitrary controller/input-context admission and standard algorithm identity remain unknown. |
| TC-A8: Address parity, exact widths and source fragments apply | Encoded extent/control, byte equations and feedback | Require even outer SP for the producer/consumer round trip; retain an odd-SP algebraic counterexample; distinguish selected-pointer equations from full finite dispatch verification. |
| TC-A9: Local effects do not establish native/public behavior | Ownership, algorithm naming, publication, port and epoch boundaries | Require actual downstream consumers, continuous initializer/control/lifetime joins and concrete transport-buffer identity; the current undefined field remains unsupplied. |

| Impact | Next evidence | Purpose and current limit |
| --- | --- | --- |
| High | Join initializer store `0x1004c2b98` to the current frame or analyze an explicitly separate compatible entry | Resolve SP+0x5b0 with source provenance; twelve matching initializer profiles do not establish the current epoch. |
| High | Reduce the 2054-instruction block kernel and its carried words | Establish compact semantic structure and test conventional algorithm identity; full finite replay alone does not name the algorithm. |
| High | Trace transformed table consumers, U+32 and non-NULL context publication | Establish the 48 B object's layout, generated 21 B payload role and ownership; these payloads remain unchanged here. |
| High | Join actual generated data/object identities to Mach/IOKit buffers and native epochs | Establish daemon-kext transport and concrete emission sites; this increment executes no IPC. |
| Medium | Cover non-aliased/overlapping source and destination arrangements | Establish behavior beyond the recovered aliased caller; the original pointer-order branch is visible but those paths are not admitted here. |
| Medium | Recover additional indirect callers and noncontiguous chunk ownership in IDA if retained evidence is insufficient | Strengthen routine boundaries and architectural reuse; function-start brackets and one fixup do not enumerate semantic callers. |
| Medium | Broaden the remaining allocator/frontier states and original failure paths | Determine scope beyond this 76-state success subset; earlier S+0x30 failure-field provenance remains unresolved. |

**QG1** passes: factual source/interface analysis. **QG2** passes: TC-A1-TC-A9 record dependencies and falsification probes. **QG3** passes for the complete conditional call/return and caller-field increment; the full interface goal remains active. **QG4** passes: exact widths, equations, source counts, byte extents and complexity are retained. **QG5** passes: even-SP qualification, aliased-path scope, original status writes, cursor movement, block feedback and pending undefined load are distinguished. **QG6** passes after pinned full replay, fresh admission/contracts/equations/census, original metadata, input preservation and publication verification. **QG7** passes: impact-labeled continuation and native/public evidence boundaries are explicit.

Follow-up: The [conditional constructor-gate report](daemon_constructor_gate_report.md) adds an explicitly separate compatible entry with eleven source-proven pointer premises (88 B), without joining the initializer to the current caller epoch. Four fully replayed classes cover all 76 inherited states: shared-gate acquisition/release, exact-one readiness, arena metadata, fourteen T byte updates, U/48 B initialization with 40 defined/eight unknown bytes, and the actual U pointer store into S+0. J/552 B remains unchanged; no new Mach/IOKit emission is established. Execution stops before undefined SP+0x260; the full interface goal remains active.
