# Scratch-pointer producer, admission class and cursor restoration

The original daemon contains a source-local producer for the pointer cell S+`0x4a20` left unknown in the [cache-codec continuation](daemon_return_cache_codec_report.md). The producer reserves 128 B from a frame-relative cursor and publishes several views, including a pointer 64 B into that region. Its admitted predecessor, complete status dispatch and ordinary cursor restoration are recovered. This establishes a conditional component contract; a continuous path from this component to the retained IOKit caller remains unknown. [SP1-SP7]

```text
0x10066f180: (phase32 AND 0x6f95d3ef) == 0x1366
  -> table[0x1d4b] -> 0x10070e738
     save table[0x1366] as continuation
     R = S + 0xc070 + cursor64
     S+0x4a20 = R+0x40; cursor64 += 0x80
  -> table[0x6298] -> signed status split
     status == 0x8b3dc650 OR status == 0x8b3dc653
       true  -> table[0x1f87] -> STOP before helper 0x1007b2fdc
       false -> table[0x1f74] -> cursor64 -= 0x80
                -> STOP before saved continuation 0x1007920a8

Separate consumer slices, with no producer/consumer control join:
  S+0x4a20 -> X20
  S+0x4a20 -> S+0x8ad0 -> prior unknown pointer/count gate
  S+0x4a20 -> S+0xa990
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SP-A1 | The pinned original daemon and parent receipts identify the analyzed source and contexts. All source-address claims depend on them. | Rehash source and dependencies; compare opcodes and independently decode original authenticated pointer words. Matching native build/task/provider identity remains unknown. |
| SP-A2 | S is a stable SP throughout this admitted component. Its four input cells and scalar register context are explicit readable fixtures. Finite executions depend on these premises. | Replay two SP placements, two admitted phases, eleven statuses, three cursors and two unspecified-backing patterns; fail on any read of undefined private bytes. No native caller admission is inferred. |
| SP-A3 | Fixed SP-relative stores and copies describe source-local fields, with modular u64 address arithmetic. Pointer-view equations depend on this address model. | Prove the equations for all u64 S/cursors and independently check wrapping controls. Valid native frame bounds, alignment, readability and object ownership require separate evidence. |
| SP-A4 | Logical authenticated edges use original normalized targets and original IA diversities. Local control-flow claims depend on these exact slots. | Decode format-12 words separately, compare live software registers at every edge and reject diversity-only target inference. Hardware authentication is not executed. |
| SP-A5 | The direct-access census has its stated syntactic scope. The unique-writer statement depends on that scope. | Decode every aligned word with base-field bits 9: 5 equal to 31, inspect explicit SP operands and overlapping fixed-width accesses, including scalar/vector and pair forms. Computed aliases, register indexing, other sections and differing SP epochs remain excluded. |
| SP-A6 | Source-local production and the preceding caller's eight unknown byte origins remain separate. Cross-context statements depend on retaining that boundary. | Check all twelve prior initializer write ledgers and eight caller frontiers; require uninterrupted control flow, SP-epoch equality and an intervening-overlap audit before replacing unknown bytes. |
| SP-A7 | Only the owned increment is published. Preservation and verification claims depend on the exact delta. | Check receipts, original inputs, logical manifest hashes, archive round trips and raw/typed/decoded-payload path hygiene; preserve parent evidence unchanged. |

## Admission and reservation contract

At `0x10066f180`, let M=`phase32 AND 0x6f95d3ef`. The original instructions compute `outgoing32 = u32((M XOR 0x134e) * 0x277)` and `index32 = u32(outgoing32 - 0x546b) XOR M`. The complete source proof establishes `index32 == 0x1d4b` if and only if M=`0x1366`. This admits 1, 024 phase bit patterns: ten bits are unconstrained. Every admitted phase produces outgoing W11=`0x6298` and saved-continuation index W12=`0x1366`. [SP2-SP4]

The predecessor loads X26 from S+`0xda0`, loads the u32 status from S+`0x70c4`, sets X1=S+`0x6000`, X13=S+`0x4684` and X14=S+`0x2520`, then branches through the writer's exact table slot with IA diversity `0x4768`. Other incoming registers are retained as explicit context. These equations do not establish where the phase or status originated. [SP2-SP4]

Let U be the incoming u64 cursor at S+`0x16d0` and R=`u64(S+0xc070+U)`. The writer at `0x10070e738` first saves the continuation loaded through incoming W12, then emits the following fields. All arithmetic wraps modulo 2^64 unless a u32 width is specified. [SP2-SP4]

| Cell | Original writer | Value |
| --- | --- | --- |
| S+`0x5f40` | `0x10070e744` | `0x1007920a8`, from table index `0x1366` |
| S+`0x7a8c` | `0x10070e748` | Incoming status32 |
| S+`0x5288` | `0x10070e74c` | Incoming X26, loaded by the predecessor |
| S+`0x1e78` | `0x10070e750` | Incoming X9 |
| S+`0x276c` | `0x10070e754` | Incoming W10 |
| S+`0x4780` | `0x10070e758` | S+`0x2520` |
| S+`0x3680` | `0x10070e75c` | S+`0x4684` |
| S+`0x7dc8` | `0x10070e770` | R |
| S+`0x2c58` | `0x10070e778` | R+`0x30` |
| S+`0x4a20` | `0x10070e780` | R+`0x40` |
| S+`0x7928` | `0x10070e788` | R+`0x5f` |
| S+`0x16d0` | `0x10070e790` | U+`0x80` |
| S+`0xf0c`, S+`0x20bc` | `0x10070e7a0`, `...7a4` | u32 `0x8b3dc651` |
| S+`0x5c48` | `0x10070e7e0` | u64 `0xe87f552eb3388cb6` |
| S+`0x211f` | `0x10070e7f8` | One-byte predicate `status32 == 0x8b3dc650` |

The body additionally clears u64 fields S+`0x7820`, `0x12a0`, `0x8950`, `0x73c0` and u32 fields S+`0x78b8`, `0x630c`, `0x2154`. These are 23 stores in total. It does not store through the newly formed R views. Therefore the view equations and 128 B cursor increment do not establish initialized payload bytes, an allocator-owned object or external exposure. Bounds on U are unknown. [SP2-SP4]

## Status dispatch and cursor restoration

After the writer, W10=`0x770f`. At `0x10083039c`, the source computes W9=W21=`0x1f74`, tests `s32(status32) < s32(0x8b3dc653)`, and selects index `0x7712` when true or `0x770f` when false. The lower branch tests equality with `0x8b3dc650`; the upper branch tests equality with `0x8b3dc653`. Both equality selectors reduce to XOR `0xf3` against `0x1f74`. Thus only those two bit patterns select `0x1f87`. All other u32 statuses select `0x1f74`. The stored one-byte predicate at S+`0x211f` distinguishes only the first special value. [SP2-SP4]

| Role | Index | Original slot | Decoded target | IA diversity |
| --- | --- | --- | --- | --- |
| Pointer writer | `0x1d4b` | `0x101048948` | `0x10070e738` | `0x4768` |
| Writer continuation | `0x1366` | `0x101043a20` | `0x1007920a8` | `0xd08c` |
| Status dispatcher | `0x6298` | `0x10106b3b0` | `0x10083039c` | `0xbbef` |
| Lower signed branch | `0x7712` | `0x101075780` | `0x1007505ac` | `0xef72` |
| Upper signed branch | `0x770f` | `0x101075768` | `0x100827e5c` | `0xef72` |
| Restore cursor | `0x1f74` | `0x101049a90` | `0x10095f530` | `0xf30e` |
| Special helper | `0x1f87` | `0x101049b28` | `0x1007b2fdc` | `0xf30e` |
| Clock success successor | `0x3c16` | `0x101057fa0` | `0x1007019b0` | `0xf30e` |
| Retained IOKit entry | `0xebf` | `0x1010414e8` | `0x10084c9b8` | `0xe8b8` |

`0x10095f530..0x10095f544` reads the cursor, subtracts `0x80`, stores it and loads the saved continuation from S+`0x5f40`. The source proof establishes `(U+128)-128 == U` for every u64 U. It branches with diversity `0xd08c` to `0x1007920a8`. The stored view pointers remain in their cells; cursor restoration does not clear them. This is neither an allocation/free observation nor proof of subsequent valid or invalid dereferencing. [SP2-SP4]

The direct saved continuation is not the retained IOKit entry: target addresses and diversities differ. Modifier-only matching would also be ambiguous: the image census finds nineteen literal MOVZ-X17 sites for `0x4768` and six authenticated rebase candidates, versus four sites and nine candidates for `0xd08c`. These inventories do not prove any other edge. [SP2-SP5]

## Conditional clock-call ABI

Let F denote the separate initializer SP. The twelve prior initializer paths each write F+`0x870` with `0x100e99700` at `0x1004c26f4`, and F+`0x868` with `0x100f4e190` at `0x1004c2658`, with no later overlapping writes before their existing boundaries. Those paths remain separate from this component. Conditional on the same two bank roots at the component, every selector byte x satisfies:

```text
x XOR right256[left256[x] XOR 0x56] == 0x14
index = 0xcbf2 + 0x14 = 0xcc06
slot  = 0x10109ff20 -> libSystem/_gettimeofday
```

The initializer field ledgers and all 256 original bank bytes on each side are retained. Original format-12 import decoding confirms `_gettimeofday`, zero import addend, key IA, diversity `0x9298`, address diversity zero. [SP2-SP4]

For arbitrary u32 controller values C0/C1 loaded through S+`0x9c8` and S+`0x9c0`, the helper computes `mix32 = u32(((C0+C1) XOR 0xa6) * 0x0a5cd4cf)`. It reads left[low8(mix32)] and right[left-byte XOR `0x56`], then forms `0xcbf2 + low8(mix32 XOR right-byte)`. The source proof covers both bank addresses, u32 wrapping and the full candidate-index bounds `0xcbf2..0xccf1`; the exhaustive bank identity then fixes the target independently of C0/C1. [SP2-SP4]

At call site `0x1007b3058`, X0 retains the writer's R+`0x30`, X1 is zero and X17 is `0x9298`. No clock API executes. A separate, unexecuted return-consumer slice proves that W0=0 selects index `0x3c16`, target `0x1007019b0`; any nonzero u32 W0 selects index `0x1f74`, the cursor-restoration body. Native output values, errno effects, timing, success and admission are unknown. [SP2-SP4]

Fresh compile-only current arm64e Darwin SDK assertions verify a 16 B, 8 B-aligned `timeval`, signed 64-bit `tv_sec` at offset 0 and signed 32-bit `tv_usec` at offset 8, plus the `int gettimeofday(struct timeval *, void *)` type. Seconds have unit s; microseconds have unit 10^-6 s. Under that ABI, the R+`0x30` buffer occupies `[R+0x30, R+0x40)` and the S+`0x4a20` view begins at its end. This relates adjacent views; it does not establish actual API writes, padding contents or the original build's SDK identity. [SP4]

## Direct accesses and retained unknown frontier

The original executable text contains 14, 849, 960 B, or 3, 712, 490 aligned four-byte words. The census decodes 355, 213 words whose base-register field is 31, then inspects explicit fixed-immediate SP memory operands and accessed widths for overlap with `[S+0x4a20, S+0x4a28)`. It finds the following four accesses and no unclassified nearby widths. [SP2-SP5]

| Source PC | Access | Established local effect |
| --- | --- | --- |
| `0x10070e780` | Store 8 B | Publish R+`0x40` to S+`0x4a20` |
| `0x1007fb820` | Load 8 B | Copy S+`0x4a20` to X20 |
| `0x10085ead8` | Load 8 B | Following two instructions copy the value to S+`0x8ad0` |
| `0x1009acd88` | Load 8 B | Following two instructions copy the value to S+`0xa990` |

The latter two three-instruction copy slices are proved for every u64 pointer. This is a syntactic direct-access result. Register-indexed SP accesses, computed aliases, other executable regions and SP-epoch equivalence remain outside its scope. The u32 unsigned-immediate STR form cannot encode byte offset `0x4a20`: its maximum is `4095*4 = 16, 380 B`, below 18, 976 B. Treating overflowing offset bits as an instruction pattern would produce false matches. [SP2-SP5]

All twelve prior initializer paths have zero writes overlapping F+`0x4a20` before their retained boundaries. All eight prior caller paths still stop at `0x10080e294` with the original eight byte origins from their separate S+`0x4a20`. The new component does not replace these origins or modify the parent receipts. There is no established producer-to-caller control join, equality of SP epochs, intervening preservation, native ownership or external-input control. [SP2-SP4, SP6]

The executed component has no call instruction, Mach port operation or message-emission site. The separately classified helper prefix contains the clock call above; it establishes no new Mach port, port right or daemon-kext transaction. [SP2-SP4]

## Provenance and verification

| ID | Primary evidence and role |
| --- | --- |
| SP1 | Original thin daemon `fairplayd.arm64e`, SHA256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are preferred virtual addresses. |
| SP2 | [Extractor](triage_evidence/recover_daemon_scratch_pointer_origin.py) and [checks](triage_evidence/daemon_scratch_pointer_origin_checks.json.zst): original bytes, census, nine source obligations, bank identity, initializer ledgers and 132 finite component traces. |
| SP3 | Original authenticated words for the nine listed rebase slots and the clock import; independent format-12 decoding checks targets, import name/addend, IA key and diversities. No hardware authentication is claimed. |
| SP4 | [Independent auditor](triage_evidence/audit_daemon_scratch_pointer_origin.py) and [audit](triage_evidence/daemon_scratch_pointer_origin_audit.json.zst): 264 component replays, 16 clock-prefix controls, 6 return-selector controls, all 256 bank inputs and fresh compile-only SDK checks with relative-header hashes. |
| SP5 | Whole-text SHA256 `94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e`; exact aligned scan, original opcodes and explicit census exclusions in SP2. |
| SP6 | Pinned [bank-origin](daemon_return_bank_origins_report.md) and [cache-codec](daemon_return_cache_codec_report.md) evidence, unchanged. Static source production, conditional component execution and native observations retain separate scopes. |
| SP7 | [Publication verifier](triage_evidence/verify_daemon_scratch_pointer_origin_publication.py): owned delta, receipt/source pins, manifest/input preservation and raw/typed/decoded-payload path hygiene. No new live IDA readback is claimed. |

The 132 component cases span two placements, two admitted phases, eleven status values and three u64 cursors, including modular wrap. They retain 15, 144 source visits, 1, 800 reads, 3, 144 writes and 636 logical edges. Independent replay under two unspecified-backing patterns checks 30, 288 source visits: 29, 016 A64 instructions and 1, 272 logical authenticated edges. It checks 969, 216 register values, 30, 288 NZCV values, 27, 744 read bytes, 41, 064 write bytes and 6, 288 write effects. The 264 replay boundaries divide into216 saved continuations and 48 helper entries. [SP2-SP4]

Sixteen clock-prefix controls add 496 A64 instructions without executing the call; six separate return-selector controls add 48 instructions without an API model or output effects. Nine nonvacuous original-source obligations are UNSAT. Current SDK compile checks pass. These are offline software observations. [SP2-SP4]

Reservation, dispatch, bank selection and restoration have O(1) fixed-width work per invocation. Extraction and auditing use O(N+C*(I+E)+Q) time/space in text words N, case visits I, recorded effects E and fixed query count Q; solver complexity is separate, with a 30 s limit per query. Large JSON is archived with zstd level 22 and verified by exact decompression. [SP2-SP4, SP7]

## Bounded continuation

| Impact | Open question | Evidence needed |
| --- | --- | --- |
| High | Producer-to-IOKit caller join | Uninterrupted source control flow, matching SP epoch and every intervening overlapping write; keep the eight existing origins unknown until that join exists. |
| High | Clock-success path and scratch consumers | Resolve the source-selected successors of `0x1007019b0`, subsequent environment/API contracts and first reads of the time buffer and R+`0x40` view. No clock output premise is introduced here. |
| High | Native daemon-kext transaction identity | Matching-build task/connection/provider, selector, buffers and ordered return observations. A frame-relative pointer and clock dependency alone do not establish transport. |
| Medium | Wider producer classes | Classify the other `0x4768` candidates and computed/partial stores, with SP-epoch tracking; diversity equality is insufficient. |
| Medium | Cursor bounds and ownership | Establish cursor origin, valid arena extent, alignment and consumers after restoration; retained pointer cells alone do not prove an object lifetime. |
| Low | Repeated scratch-view patterns | Compare exact offsets, access widths and control epochs with prior digest/output scratch records before asserting shared structure types. |

## Scoped quality gates

**QG1** passes for factual analysis. **QG2** passes with SP-A1..SP-A7. **QG3** passes for this increment's source routines, local control/data flow, environmental call ABI and emission accounting; the full goal remains active.

**QG4** passes with u32/u64 wrapping, exact byte extents, signed comparisons and time-field units. **QG5** passes within the stated scope: direct stores do not establish a reaching definition across separate paths; reserved views do not establish initialized payloads; the clock call and its return consumer are classified without executing the API. **QG6** passes for original bytes/fixups, nine source obligations, independent CPU/effect replay and current SDK declarations. **QG7** passes with the impact-ranked continuation table. No native API, Mach/IOKit transaction, allocation, free or PAC executes. [SP1-SP7]
