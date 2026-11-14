# Constructor table initialization, complete mixing and next-call handoff

The constructor's previously unresolved table loop now completes. It expands six context bytes from J+0x20 into256 private bytes, then performs2569 updates selected by the current byte's low two bits. A structured four-case model matches all16903 ordered array events and all retained table snapshots. The next pending internal call is at0x1004d5df0, target0x1004172f4, IA0xf248. Its private record contains two raw pointers to the same mixed table. Their callee-defined meanings remain unknown. [TM1-TM6; TM-A1-TM-A9]

All76 inherited states are covered through one complete shared loop execution, explicit incoming-register/byte admission, and four separately replayed controller/ABI handoffs. This is46 original-source intervals/613006 instruction visits, not76 full loop replays. T/21 B remains unchanged, U/48 B remains wholly undefined, and S/64 B retains53 defined/11 undefined bytes. No current write publishes non-NULL S at J+0x68 or emits a Mach/IOKit message. Native scheduling, object lifetimes and daemon-kext pairing remain unknown. [TM1-TM6; TM-A1-TM-A9]

```text
76 frozen states after original256 B table copy
  -> shared register/byte dependency admission
  -> read J+1c =6; cyclic reads J+20..J+25 (all zero here)
  -> initialize first private256 B to98
  -> i=0..2568: four-way update of first[i&ff]
       case0: neighbor-dependent polynomial / image permutation
       case1: neighbor-dependent polynomial
       case2: two overwrites -> case3 -> final overwrite
       case3: neighbor rotation / overwrite -> final overwrite
  -> shared loop exit1004d5cb0
  -> four controller/ABI handoffs, admitted against all76 states
  -> record: two pointers alias mixed256 B
  -> pending1004d5df0 ->1004172f4 / IA f248; STOP before call

T21 preserved; U48 undefined; S64 mask53/11 preserved
Publication, external delivery and native transaction pairing unknown
```

No new imported return, allocation, input byte, native target API/IPC/filesystem operation, allocation/free, hardware PAC or IDB mutation is supplied or executed. Original guest instructions run with inherited conditional premises. The64-iteration batch stops occur before original instructions and alter no target state. [TM1-TM6; TM-A1-TM-A6,TM-A9]

| Evidence | Primary artifact and scope |
| --- | --- |
| TM1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_state_table_mixing.py) retains source words/fixups, full journals and parent-specific exports. |
| TM2 | [Parent emitter report](daemon_state_emitter_completion_report.md), [checks](triage_evidence/daemon_state_emitter_completion_checks.json.zst) and [audit](triage_evidence/daemon_state_emitter_completion_audit.json.zst): all76 states at0x1006d7fa8, T/21 B populated and original image table copied to private storage. |
| TM3 | [Current checks](triage_evidence/daemon_state_table_mixing_checks.json.zst):42 shared intervals, four handoff intervals, original code regions/fixups, conservative register projection and76 terminal exports. |
| TM4 | [Independent replayer](triage_evidence/replay_daemon_state_table_mixing.py) and [replay receipt](triage_evidence/daemon_state_table_mixing_replay.json.zst): every GP/SP/Q/NZCV frame, byte event and authenticated logical target; separate semantic read/write projection. |
| TM5 | [Auditor and structured model](triage_evidence/audit_daemon_state_table_mixing.py), [audit receipt](triage_evidence/daemon_state_table_mixing_audit.json.zst): all-parent byte/owner/register admission, fault controls, structured iteration simulation and six nonvacuous original-source equations. |
| TM6 | [Publication verifier](triage_evidence/verify_daemon_state_table_mixing_publication.py): source/receipt/dependency pins, joins, fresh coverage/equations, fourteen function-start brackets, exact manifest delta, preservation and decoded path hygiene. |

## Input expansion and exact data channels

J=`0x6500115b20`, S=`0x6600040000`/64 B, T=`0x6600050000`/21 B and U=`0x6600060000`/48 B are retained model placements. Outer SP remains0x6800060100. The first private table is0x680006c5f0; the second is0x680006c6f0. These addresses do not establish native allocation placements or lifetime. [TM1-TM5; TM-A1-TM-A4]

| Source site | Read or effect | Established current value |
| --- | --- | --- |
| 0x1006d7fa8 | u32 load at J+0x1c | 6, used as the expansion divisor/length |
| 0x10059d518 | Cyclic input-byte load | J+0x20+(i modulo6), i=0..255; all six input bytes are zero |
| 0x10059d5a8 | Expansion output byte store | First private table+i; all256 stored bytes are0x98 |
| 0x10059d5c8 | Expansion branch / IA0x0cac | 255 returns to0x10059d4f0; final transfer to0x1007cb6cc |
| 0x1007cb6f0 | Length-derived byte-pointer formation | J+0x20+(3 modulo6)=J+0x23 |
| 0x10058c40c | Per-iteration bound input | Byte at J+0x23; zero on all retained paths |
| 0x10058c400 | Common final byte store | First private table+(counter&255) |
| 0x10058c470 | Loop backedge or exit / IA0x8650 | Back to0x1004f69cc or exit0x1004d5cb0 |

The initialization counter spans0x61748454..0x61748554; source pointer arithmetic converts it to offsets0..255. Its quotient/remainder and address-dependent rotate/encode arithmetic are retained as original instructions. Under these frozen six zero bytes, the full source execution produces256 bytes0x98 before any read of that new table. Since `256=42*6+4`, context offsets0..3 are read43 times each and offsets4..5 are read42 times each. This is a recovered cyclic context-input expansion, with no established cryptographic key designation. [TM1,TM3-TM6; TM-A1-TM-A3,TM-A7]

The generated T/21 B is not an input to this increment: no S/T/U payload read or write occurs in any retained interval. The six-byte source is at J+0x20, separately from the earlier generated32 B at J+0x34. T's leading0x06 and the context length6 are numerical equalities at different addresses; they do not establish one format field. [TM1-TM6; TM-A2-TM-A4,TM-A7-TM-A9]

The second table remains the exact256-byte image permutation from0x100e406a0, SHA-256 `3217b5ed48b0ac4623abdd9e60de4889964d34591f450151fa180e5d7c69b266`. It is read by two update routes and is never written here. The final first table contains158 distinct byte values, so it is not itself a permutation of all256 byte values. Its full256 B are retained in TM5; SHA-256 `fa98e6c0f62c1c2d55b1db20164a9ddb9b43303ef8703115f19142b4208ae91f`. No standard algorithm identity is established by these properties. [TM1,TM3-TM6; TM-A1-TM-A3,TM-A7-TM-A9]

## Four-way transfer and termination

Let A be the mutable first table, B the fixed second table, n the u32 iteration counter and `tag=A[n&255]&3`, evaluated before any current-iteration write. Original opaque dispatch reduces to tag bit1 for the first branch and bit0 for the second, under the recovered source phases. Each of the four256-byte-domain partitions has64 values. Six source queries cover this dispatch, the bound, counter/store and next-record fields; the complete finite execution and structured model additionally check the observed source paths. [TM1,TM3-TM6; TM-A1-TM-A3,TM-A7-TM-A8]

| Raw-byte tag | Original route and IA emission | Array dependencies and ordered effects | Actual iterations |
| --- | --- | --- | --- |
| 0 | 0x100866d98 ->0x10076276c; branch0x100866dec / IA0x212e | Reads A[(5*n+8)&255], applies the original polynomial/signed-widening/reduction sequence and B lookup, then writes A[n&255] | 820 |
| 1 | 0x100866d98 ->0x10047c518; branch0x100866dec / IA0x212e | Reads A[(n+3)&255], A[(n+5)&255], A[(n+9)&255], applies original polynomial/signed-widening/reduction, then writes A[n&255] | 528 |
| 2 | 0x100779dac ->0x10080c604; branch0x100779de0 / IA0x7c4f; then0x10051979c | Reads B[current_byte XOR0x98] and A[(n+11)&255]; writes A[n&255] twice, then executes tag3's neighbor transfer and common final write | 609 |
| 3 | 0x100779dac ->0x10051979c; branch0x100779de0 / IA0x7c4f | Reads A[(n+1)&255]&7 for rotation; writes A[n&255], then reads A[(n+17)&255], A[(2*n)&255], A[(n*n+17)&255] and performs the common final write | 612 |

Every intermediate write is to the same current index; these are overwrites, not swaps. Neighbor reads observe preceding writes in source order. In particular, the twice-indexed read can alias the current byte when n modulo256 is zero. The structured model retains each intervening write/read and the exact source ALU operations; it does not replace the loop with simultaneous array updates. The reduction fragments contain0x257/599 and0xf6eb/63211; equivalence to conventional signed remainder over all u32 input patterns remains unproved, and no such substitution occurs. [TM1,TM3-TM6; TM-A1-TM-A3,TM-A7-TM-A8]

For the selected context byte b, the original bound arithmetic is `N=256*(10+(b modulo7))+9`, covering every u8 b under the current phases. Thus `2569<=N<=4105`. Here b=0, so N=2569; the counter starts0, advances exactly1, and exits when the post-store counter is no longer below N. The bound byte is read unchanged once per iteration. Arithmetic cannot wrap the u32 counter on this path. Actual table writes are `820+528+4*609+2*612=5008 B`; adding initialization gives5264 one-byte writes before exit. These are accumulated source writes, not a5264 B allocation. [TM1,TM3-TM6; TM-A1-TM-A3,TM-A7-TM-A8]

## Next private record and architectural boundary

The loop exits at0x1004d5cb0. The following80 instructions construct a new record at R=outer SP+0x10cb8=0x6800070db8, then stop before0x1004d5df0 executes. This address was previously the emitter request/status cell; equal storage does not establish equal record semantics across epochs. Four handoffs have identical first40 defined bytes and the same pending target/modifier, while retaining their distinct machine/controller state. [TM1-TM6; TM-A1-TM-A6,TM-A8-TM-A9]

| R-relative extent | Width | Current raw value | Writer / evidence |
| --- | --- | --- | --- |
| +0x00 | u32 | 0x8b3dc651 | Inherited emitter completion; no new write here |
| +0x04 | u32 | 0xbe39842c | 0x1004d5d24; address-coded field |
| +0x08 | u32 | 0x39af9964 | 0x1004d5d28; address-coded field |
| +0x0c | u32 | 0x68 | Residual prior definition; not a newly established parameter |
| +0x10 | u64 | 0x680006c5f0 | 0x1004d5d14; raw first-table pointer |
| +0x18 | u64 | 0x680006c5f0 | 0x1004d5d10; same raw pointer |
| +0x20 | u64 | 0x100fe69d4 | 0x1004d5d98; source-selected/encoded image value; callee-defined role unknown |

Let r be the record address and `k=u32((((low32(r) OR0x1a6e4f73)+(NOT low32(r) OR0xe591b08c)) XOR0x9f7b80cf)*0xc7f6dca7)`. Original source proves the two pointer stores for arbitrary pointer/SP bits and fields `R+4=u32(0x5205-k+0xf6a)`, `R+8=u32(0x7b7676a7-k)`. This establishes producers and coding equations, without assigning input/output/count meanings before the callee decoder is recovered. X0=R, X8=0x1004172f4 and X17=0xf248 at the pending call. Residual X1=0x14 is not established as a length argument. [TM1,TM3-TM6; TM-A1-TM-A3,TM-A8-TM-A9]

The handoff reads u32 controllers at0x1010b8dc8 and0x1010c4670. The first is zero on every retained path; the second is0x46b9aad9 or0x86808883. Consequently the shared loop ends before those reads, and separate handoff classes preserve their dependencies. Representatives0,17,38,55 have34,4,34,4 members respectively. Neither the common final table nor matching record bytes justifies replacing their full machine states with one representative. [TM1,TM3-TM6; TM-A2-TM-A6]

No new source call is executed: the retained call count is zero because the frontier precedes the instruction. No callee return, result status, table transformation after this frontier, U initialization or J+0x68 publication is claimed. A record with aliased raw pointers does not by itself establish an in-place operation. [TM1-TM6; TM-A1-TM-A9]

## Dependency coverage and independent checks

The shared conservative projection requires SP and X2/X20/X21/X22/X23/X24/X26/X27: nine whole-register values. Independent semantic read/write hooks require the same set except X2, whose inclusion is conservative. No Q register is read or written. X18/X19/X20/X21/X29, SP and all32 Q registers pass through the shared region; the handoff subsequently changes X20/X21. Each export preserves unwritten values from its own parent. Model X19 remains U+32 without any U payload access. [TM3-TM6; TM-A2-TM-A6]

All76 shared admissions verify355 byte requirements each:26980 accumulated checks and684 register requirements. The four handoff classes add6384 byte-requirement checks. Their fresh terminal byte maps contain816988 accumulated defined bytes, with2432 parent-specific Q register values preserved. The shared transfer preserves720 incoming byte differences outside its dependencies. These are coverage counts, not native memory usage. [TM3-TM6; TM-A2-TM-A6]

Fault controls reject a changed demanded byte, two changed required registers and a changed owner. They admit and preserve changed unused Q0/X18 values and an unused private byte. Changed dead X0/NZCV inputs are admitted and overwritten by verified source effects. Admission also checks pending PC, configuration, owner extents, every read-before-write byte and all ordered later reads/effects. Original writes are disjoint from visited opcode bytes. Sequential deterministic execution and definedness remain explicit assumptions. [TM3-TM6; TM-A1-TM-A6]

Replay independently checks19617664 scalar and19617664 vector register values,613052 NZCV states,234476 read B,5392 write B and13712 original authenticated logical edges. Each scalar/vector total is `(613006+46)*32`. Numeric register projections are recomputed from the independent model after each semantic write and checked at every retained frame; unchanged values are cached. Semantic dependency hooks exclude these audit-only frame inspections. No source frames are sampled or skipped. [TM3-TM6; TM-A1-TM-A6]

The structured model uses four source-defined point programs, selected by tag, with its own mutable byte array and fixed image table. It initializes that array independently to0x98 from the source-established zero-input expansion. It matches2569 iterations,16903 ordered array events,2569 bound-byte reads and10496 B of complete batch-boundary snapshots. Exact widening, shifts, overflow and intermediate stores are retained. The six universal equations do not claim arbitrary context admission, arbitrary loop termination under changing memory, or a recognized cryptographic algorithm. [TM1,TM3-TM6; TM-A1-TM-A3,TM-A7-TM-A9]

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| TM-A1: Pinned image and decoded fixups apply | Original instructions, dispatch targets and routine boundaries | Verify image/opcode/slot/modifier bytes and original function-start brackets; logical authentication remains distinct from native PAC. |
| TM-A2: All76 inherited frozen states are conditional entries | Complete finite paths and exports | Check every parent index, required entry register/byte, configuration, pending PC and owner extent; other836 allocator frontiers and the complete1543-state SIDB frontier are not expanded by these counts. |
| TM-A3: Sequential deterministic execution applies | Shared loop trace, effects and termination | Replay every source frame/effect, preserve ordered read-before-write dependencies and reject opcode overwrite; concurrent native mutation is unknown. |
| TM-A4: Prior allocator/import/input premises remain inherited | S/T/U placement, context contents and generator outputs | Check parent receipt/source pins and absence of newly supplied return/input values; native allocator address, file contents, ABI epoch and lifetime remain unknown. |
| TM-A5: Conservative and semantic register/byte projections apply | One shared execution covers76 incoming states | Independently track semantic reads/writes, verify355 byte demands, preserve unused GP/Q values, reject changed demanded bytes/registers/owners and check overwritten dead inputs. |
| TM-A6: Handoff controller reads are separate dependencies | Four post-loop handoff classes and final records | Stop shared effects at the loop exit, replay all four handoffs and admit every member against exact class machine state and required bytes. |
| TM-A7: Current six-byte context input and source phases apply | Initialization0x98, four routes and bound2569 | Verify original length6, all256 cyclic reads, per-iteration bound byte, exact dispatch equations and structured point transfers; arbitrary input-context admission remains unknown. |
| TM-A8: Source order, widths and private field coding apply | In-place updates, aliases, record and pending call | Check every intermediate overwrite/read, exact signed widening/shift/reduction instructions and original pointer/field equations; do not infer callee field meanings from raw equality. |
| TM-A9: Local computation does not establish native/public behavior | Publication, algorithm identity, ownership and IPC conclusions | Require actual callee consumers, output/status propagation, emission sites, object identity and native epochs; U payload and daemon-kext pairing remain unknown. |

## Reproduction, provenance and bounded continuation

Logical SHA-256 values: checks `48880e37460e2a7bf8862ebb59b739357791656bcb426a4b2ecc4643a94edbe7`; replay `db6afc8b68eeead78fcc0f7399ad0d8382b4bf4b964c74d52d686eea278ec0f8`; audit `15c8b51ba1a781a2ee03efa37e24e14737faed37851c614a037a30aebf0dac91`. All three receipts and the manifest use `zstd --ultra -22 -q -T1` with decoded round-trip checks. Raw, structured, packed-export and decoded hexadecimal payloads are checked for analyst-local paths. Original inputs remain unchanged. [TM3-TM6]

The journals comprise one14119-visit expansion/prefix,41 loop batches totaling598567 visits, and four80-visit handoffs: `14119+598567+4*80=613006 visits`, `1+41+4=46 intervals`. Forty full64-iteration batches plus one9-iteration batch give `40*64+9=2569 iterations`. Recorded totals are42212 reads,5284 writes and13712 logical edges, with zero executed calls. Full independent replay is pinned once; publication checks freshly rebuild source equations and coverage rather than repeat the entire replay or structured simulation. [TM3-TM6]

The source's1005-entry LC_FUNCTION_STARTS table occupies1864 B at file offset17603576, SHA-256 `ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54`. Fourteen sites are bracketed. Target0x1004172f4 is an advertised start; the other inspected sites are interior fragments. No exact-site original symbol is present. Complete noncontiguous chunks, all callers and original semantic names remain unknown. Original-image evidence was sufficient; IDA was not queried for this increment. [TM1,TM3-TM6; TM-A1,TM-A9]

Arithmetic uses exact u8/u16/u32/u64 modulo2^width, explicit sign/zero extension, signed comparisons/shifts where specified and unsigned counter admission. Addresses, offsets and extents are bytes. Six nonvacuous UNSAT queries cover the bound, original counter/current-byte store, root dispatch, two subdispatches and arbitrary-SP/pointer handoff fields; solver limit30 s/query. Extraction time/storage is O(parent bytes+retained visits+effects+source). Replay is O(V*(register state+byte effects)+joins) time, O(receipts+largest interval+byte map) storage. Structured simulation is O(256+N*K) time and O(256+receipts+source-expression DAG) storage, with N=2569 and K the bounded point-program size. Dependency/publication work is O(receipts+V+P*D+owned bytes+query DAG), P=76. No native timing or memory cost is measured. [TM1-TM6]

| Impact | Next evidence | Purpose and present boundary |
| --- | --- | --- |
| High | Decode original0x1004172f4 record consumer and continue its actual return | Establish pointer roles, extent, output/status and table processing; call remains pending. |
| High | Trace U+32 and T/S consumers through actual container publication | Establish48 B object layout,21 B payload role, ownership and J+0x68 publication; current heap payloads are unchanged/undefined as recorded. |
| High | Join generated bytes/object identities to Mach/IOKit buffers and native epochs | Establish actual daemon-kext transport, ports and emission sites; no new IPC evidence is asserted here. |
| High | Resolve S+0x30 producer/lifetime on inherited failure paths | Supply source-established field provenance rather than invented heap contents. |
| Medium | Recover nonzero six-byte context producers and source phase variants | Test input dependence, initialization transforms and bound sensitivity beyond the frozen zero-input paths. |
| Medium | Simplify the four point programs and prove any conventional reduction identities | Improve semantic naming while retaining exact source operations until equivalence is established. |
| Medium | Broaden other836 pending64 B allocations and native synchronization evidence | Determine scope beyond this76-state subset and assess globally mutable state across actual caller epochs. |

**QG1** passes: factual source/ABI analysis. **QG2** passes: TM-A1-TM-A9 give dependencies and falsification probes. **QG3** passes for the complete table-loop/handoff increment; the full interface goal remains active. **QG4** passes: exact widths, counts, extents, equations and complexity. **QG5** passes: ordered overwrites, four handoff classes, inherited status versus new record fields, and pending versus executed call remain explicit. **QG6** passes after source-pinned full replay, structured simulation, fresh dependency/equation checks, metadata, input preservation and publication verification. **QG7** passes: impact-labeled continuation and unresolved native/public boundaries are bounded above.

Follow-up: The [table-consumer report](daemon_table_consumer_report.md) completes the original call to `0x1004172f4`: decoded destination/source roles, 256 B extent, two byte masks, sixteen block transfers with feedback, record status and caller cursor rollback. Four full classes admit all 76 inherited states. Execution stops before an undefined 8 B load at SP+0x5b0; twelve separate initializer profiles identify a producer candidate without establishing the current epoch. No new Mach/IOKit emission or context publication is established.
