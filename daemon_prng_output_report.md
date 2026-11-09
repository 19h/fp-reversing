# PRNG word consumer, buffer, global counters, and comparison-record ABI

The source's first generated words are consumed by **in-place u32 XOR updates to an arena buffer selected through global pointer cell `0x1010C8278`**. The caller's loop bound is 512 bytes, or 128 words. This increment validates the first two updates, complete 624-word twist passes, tempering, global index/counter writes, and the nonzero-counter path that bypasses fresh entropy initialization.

It also recovers the complete leaf `0x100444D6C`: a 40-byte accessed private record selects u64 equality or unsigned greater-than. Its counter caller compares the generation count with 5119. Under the recovered caller phase, the local counter rule is `C<=5119 ? C+1 : 0`. Combining it with the earlier zero-counter seed guard yields a conditional 5121-output seed epoch; concurrent/other native writers remain unknown.

No new Mach/IOKit emission is established. The masked buffer's later consumers and its relation to driver messages remain unknown. The full interface investigation remains active.

## Provenance and assumption register

Primary daemon: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are preferred virtual addresses. [Contracts](triage_evidence/daemon_prng_output_contracts.json) contain 15 source spans, 15 original fixups, an exhaustive 256-input bank, four context summaries and 285 live-IDB row matches. The IDB views cover 231 of 377 path-pool instruction rows; all pool bytes and executed opcode bytes are checked against the original image. Earlier [seed-material](daemon_seed_material_report.md), [entropy/time](daemon_entropy_return_report.md), and [context-transfer](daemon_context_transfer_report.md) artifacts remain frozen.

| ID | Assumption or boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| PG1 | The pinned image is the intended specimen | PCs, globals and routines | Rehash original bytes/fixups and compare explicit live-IDB target |
| PG2 | The sealed incoming states and startup premises apply | Full continuation | Replay original prefixes before new instructions; native startup/global state remains unknown |
| PG3 | Final RAM/register snapshots preserve sealed source effects | Symbolic restoration | Check new reads/registers against independently replayed complete prefixes; retain original SSA and byte origins |
| PG4 | Frame/arena owners are valid, mapped and disjoint | Memory interfaces | Verify addresses and widths; 90,000-byte owner contains the 512-byte selected buffer |
| PG5 | Two table cells at F+0x6D8/+0x6DC retain their initialized values | Input-dependent reads | Reconstruct bounded addresses under SSA definitions; verify actual A64 addresses and bytes |
| PG6 | Selected A64/bit-vector semantics are adequate | Recurrences and codecs | 24 paired source proofs, complete-state A64 comparison, register-shift/ASR semantics and fail-closed operations |
| PG7 | API summaries and their declared outputs/clobbers apply | Prefix state | Preserve SP/X18-X29/D8-D15 low halves; no new API summary is added in the continuation |
| PG8 | Caller key producer receives X0=R and normalized R is 4-byte aligned | Record key agreement | Source prekey proof, 221-instruction liveness certificate and an outside-domain alignment probe |
| PG9 | The counter caller has its recovered phase and matching key | Counter route/reset | Prove all-u32 C under that phase; examine alternative callers/phases separately |
| PG10 | Table fixups supply abstract decoded targets | Dispatch identity | Verify original auth-rebase words/diversity and all 256 bank inputs; native PAC remains unknown |
| PG11 | Four F/H representations delimit full-path coverage | Addresses and stream behavior | Compare both placements and zero/reference API tuples; arbitrary native ASLR/configuration is not proved |
| PG12 | No other writer interleaves with the counter/index update | Conditional epoch interpretation | Census writers/callers and reader synchronization; native concurrency/lifecycle remains unknown |
| PG13 | Static loop/branch contracts are distinct from executed coverage | 128-word bound and reset branch | First two updates execute; remaining 126 updates and reset-at-5120 are source-local contracts, not complete native observations |
| PG14 | Prior artifacts remain frozen except six aggregate reporting/publisher paths | Preservation | Check 3,015 prior artifacts, exactly six changes and the three original inputs |

Whole-path results depend on PG1-PG11. The epoch interpretation additionally depends on PG12; coverage limits in PG13 apply throughout. No result establishes unconditional native reachability or a native C++ class ABI.

## Data flow and publication order

```text
prior allocation / byte initialization
                 |
0x1002FB820 -> global data pointer 0x1010C8278 -> arena buffer D
                 |
seed/mixed state -> full twist -> select state[index]
                                      |
                        global index publication
                                      |
                       counter compare / publication
                                      |
                 temper -> XOR existing buffer word
                                      |
                       advance byte offset by 4
```

| Interface | Source site | Observed contract |
| --- | --- | --- |
| Buffer pointer publication | `0x1002FB820` | Store u64 D into `0x1010C8278`, then test D for NULL at `0x1002FB824` |
| Buffer pointer use | `0x100350604` | Load D through `0x1010C8278` |
| Byte offset | F+`0x48C` | 0 then 4 in the two updates; unsigned loop bound 512 |
| Existing word | `0x100350610` | Read u32 at D+offset |
| Masked word publication | `0x100350624` | Write u32 `existing XOR tempered_word` at the same address |
| Global state index | `0x1010C67DC`, writer `0x10029A130` | Selected cases publish 1 then 2 |
| Global generation counter | `0x1010C8258`, writer `0x1003505B8` | Selected cases publish 1 then 2 |
| Local extraction index | F+`0x60C` | Reset to 0 at `0x100406D90` before first extraction; advanced at `0x10029A124` |

The data pointer is published during the earlier context-transfer phase, before these mask updates. Each update publishes the global index, then the generation counter, then the masked word. Synchronization and native reader ownership are unresolved; these stores alone do not establish a ready/publication protocol.

[The byte-provenance audit](triage_evidence/daemon_prng_output_provenance.json) reconstructs overlapping and partial writes. The existing first/second buffer words were initialized bytewise at `0x1004C8398`; their physical backing bytes are not promoted into source definitions. F+`0x358` holds D at pointer publication, but later holds a different arena-interior pointer used by seed mixing. It is a reused scratch slot, not a permanent object-member identity. F+`0x1E0` is finally written with the address `0x1010C8278` at `0x1002C5934`; the current consumer dereferences that cell.

## Complete twist and temper operations

The private table initialized earlier at `0x1002DC0C0` contains encoded words `0x94FDEAB5` and `0x0DF55A6A`. XOR with `0x94FDEAB5` yields 0 or `0x9908B0DF`. A read address is always `F+0x6D8 + 4*(next_word&1)`.

| Phase | Table read | State destinations per pass | Far-word source |
| --- | --- | --- | --- |
| First | `0x10035C6F8` | 0..226, 227 words | old state[i+397] |
| Second | `0x100474058` | 227..622, 396 words | updated state[i-227] |
| Last | `0x1003B092C` | 623, one word | updated state[396], with updated state[0] as next |

For each destination, the source-local rule is:

```text
y = (current & 0x80000000) | (next & 0x7FFFFFFF)
updated = far XOR (y >> 1) XOR ((next & 1) ? 0x9908B0DF : 0)
```

Each pass writes 624 u32 words, `624*4=2,496 bytes`. All arithmetic and shifts operate on u32 values; address arithmetic is u64. The source clears next's bit 0 before the right shift, which gives the same shifted result. The last phase's carried W8=`0x8A9B8560` is an explicit source-contract premise verified in all retained contexts.

The selected executions perform a full twist before **each** of the two extractions. They then select state[0] and state[1], respectively. The second operation follows the original nonzero-counter branch at `0x10031CC98` and adds no entropy/time call. This observed scheduling is retained explicitly; equivalence to a conventional MT19937 output stream is not asserted.

For selected raw word r, the source at `0x1003505BC..0x1003505F4` computes:

```text
t = r XOR (r >> 11)
t = t XOR ((t << 7) & 0x9D2C5680)
t = t XOR ((t << 15) & 0xEFC60000)
word = t XOR (t >> 18)
```

The source expresses the last step using `0x05A98E10`, a right shift by 2 and a register-controlled shift by 16. Both recovered counter paths establish the same effective shift. The constants cancel to the rule above. The following source XORs this word into the existing arena word, rather than returning it through an established standalone C-function result ABI.

For context 0 with the declared reference inputs:

| Byte offset | Existing u32 | Tempered u32 | Stored u32 |
| --- | --- | --- | --- |
| 0 | `0xA2EED01C` | `0x46830B11` | `0xE46DDB0D` |
| 4 | `0xD62A2478` | `0x72BDE74A` | `0xA497C332` |

These are little-endian u32 memory updates. No native entropy or clock sample is claimed.

## Complete 40-byte accessed comparison record

Analysis label: `compare_select_eq_or_unsigned_gt_record40`; no IDB symbol is changed. The complete 36-instruction leaf is `0x100444D6C..0x100444DF8`. It has no calls or stack frame, preserves X0=R, and writes only the u32 at R+0. Define:

```text
K = u64((R XOR 0x823819558515CFBD) * 0xC7F6DCA7)
k = low32(K)
```

| Offset | Width | Decoded role |
| --- | --- | --- |
| +`0x00` | u32 | Output |
| +`0x04` | u32 | mask = raw+k |
| +`0x08` | u32 | false_choice = raw-k |
| +`0x0C` | u32 | mode = raw XOR k; bit 0 only |
| +`0x10` | u64 | A = raw+K |
| +`0x18` | 4 bytes | Unread by this complete leaf |
| +`0x1C` | u32 | true_choice = raw XOR k |
| +`0x20` | u64 | B = raw XOR K |

```text
choose = (mode&1) ? unsigned64(A)>unsigned64(B) : A==B
output = mask XOR (choose ? true_choice : false_choice)
```

The accessed range ends at R+`0x27`: 40 bytes. Broader object size and a native/wire structure declaration are not inferred. The frame reuses R=F+`0xAF8`, which other callers use with different record layouts.

The helper prekey identity holds for every u64 R; the caller normalization requires 4-byte alignment. Source `0x10032C9FC..0x10032CA50` produces the prekey, X12 remains unchanged through 221 intervening instructions, and `0x10032CDD0..0x10032CDD4` multiplies/stores the key at F+`0x1A0`. The coefficient inverse is `0xEBBDCC7D8FD10B17`. A source-derived two-byte-aligned counterexample is retained outside the caller proof domain.

The caller at `0x10029A1E0` selects original slot `0x10109FFE0` -> `0x100444D6C`, IA diversity `0xA499`, address diversity 0. All 256 byte-bank inputs select that slot. Under its recovered phase, it decodes A=zero-extended u32 C from `0x1010C8258`, B=5119, mode=1. The complete leaf supports equality as well; this caller uses unsigned greater-than.

## Counter, buffer loop, and bounds

| C domain | Result index / slot | Target | Published next C |
| --- | --- | --- | --- |
| 0..5119 | `0x17A4` / `0x101045C10` | `0x100478558` | C+1 |
| 5120..`0xFFFFFFFF` | `0x17A0` / `0x101045BF0` | `0x1002B3D7C` | 0 |

Both slots use IA diversity `0xF647`. Both paths establish the inputs needed for the standard final tempering shift. The counter's reset branch is proved statically for all u32 C; the whole-prefix numerical replays exercise C=0 and C=1.

The earlier zero/nonzero seed guard tests the same cell. With no intervening writer and the recovered phase maintained, the recurrence is `0 -> 1 -> ... -> 5120 -> 0`: **5121 output operations per cycle**. Reset occurs after producing the operation entered with C=5120; the next invocation sees zero and selects fresh initialization. This is a conditional source composition, not an observed native epoch or a complete writer census.

Source `0x100350628` advances the byte offset by 4. The guard at `0x100409418` compares the updated offset unsigned with 512:

| Guard | Index / original slot | Decoded target |
| --- | --- | --- |
| updated offset <512 | `0x3170` / `0x101052A70` | `0x1002DC094`, next word |
| updated offset >=512 | `0x3195` / `0x101052B98` | `0x100315438`, exit continuation |

Both use IA diversity `0x7A6B`. Starting at offset 0 and advancing by 4 gives 128 word positions, 0..508, covering 512 bytes. The four selected data pointers have `D+512<=H+90000`. The remaining 126 updates and exit continuation are not executed in this increment. Under the local rules, a pass entered with C=0 stays below the reset threshold through 128 updates; that inference depends on the same phase and no other counter writer.

The 32-byte material/time reservation is released by `0x1003505FC..0x100350600` before each word update. The second word reuses the frame area and takes the nonzero seed guard. The stopping PC is `0x100350628` after the second data write, before its next offset increment executes.

## Verification and scope

[Four symbolic profiles](triage_evidence/daemon_prng_output_profiles.json) each contain 26,666 new source visits, two full twist passes, 1,248 exact finite reads and 21,432 total ordered SSA definitions including sealed prefixes. Each symbolic address is expanded through its source definitions until a two-address range is proved. [Independent checks](triage_evidence/daemon_prng_output_checks.json) rederive all **4,992 finite-read certificates**, candidate values and selected-read expressions. Original unknown private bytes retain their origins; no new unknown input is introduced.

[Eight full-prefix A64 replays](triage_evidence/daemon_prng_output_replays.json) match **2,633,576 source visits**, including **213,328 new-continuation visits**. They verify all recorded register/NZCV/memory effects, actual input-dependent read addresses, both complete 624-word states, the two tempered values and the two XOR updates. Both encoded table choices occur. The four F/H representations each use zero/reference declared API tuples and corresponding caller-clobber/backing patterns. No new API summary is added beyond the four sealed entropy/time summaries.

[Twenty-four source proof pairs](triage_evidence/daemon_prng_output_proofs.json) cover 247 lifted instruction visits, plus a 221-instruction key-liveness certificate, seven nonempty premise witnesses and an outside-alignment probe. The checker independently reruns two full-prefix cases. These are software observation counts, not durations.

The compact twist uses O(N) time and O(N) state for N=624; tempering and one word update use O(1) additional time/state. The static 512-byte pass uses 128 word updates; the observed full-twist scheduling would require O(128*N) state-update work if maintained throughout that pass. Scripts scale with journal bytes, source visits, byte effects and serialized SSA expressions. Local range queries are limited to 2 s; source SMT queries to 30 s. [Preservation](triage_evidence/daemon_prng_output_preservation.json) and [scoped gates](triage_evidence/daemon_prng_output_quality_gates.json) retain hashes and counts.

All target operations are offline source analysis or A64 emulation. No native API, actual Mach/IOKit operation, native PAC, or IDB mutation is performed. The global pointer, index, generation counter and internal table selectors have established process-local roles. Their later relationship to Mach descriptors, user-client arguments and driver payloads remains unresolved.

## Bounded continuation opportunities

| Impact | Investigation | Discriminating evidence |
| --- | --- | --- |
| High | Follow the masked buffer and `0x100315438` exit | Reader/alias census and data dependencies into established Mach/IOKit arguments |
| High | Complete the remaining 126 updates and later modes | Exact loop summary or additional full-source execution; retain register/memory boundary contracts |
| High | Census all writers/owners of counter, index and buffer pointer | Native lifecycle, synchronization, reset and replacement paths |
| Medium | Establish the allocator's 512-byte object contract and NULL path | Allocation-size/header/free provenance and post-publication failure behavior |
| Medium | Expand generator/reseed-state coverage | Counter endpoints, alternate control words, representations and seed-epoch transitions |
| Low | Catalog other comparison-record layouts | Complete source leaves, codecs, caller phases and source-bound proofs |

## Scoped quality gates

| Gate | Result |
| --- | --- |
| QG1 | Pass: factual technical analysis |
| QG2 | Pass: PG1-PG14 with dependencies and falsification probes |
| QG3 | Pass for this increment: twist/temper, first two buffer updates, complete record40, counters, provenance and loop guard; full objective active |
| QG4 | Pass: u32/u64 arithmetic, little-endian bytes, 512-byte/128-word bounds, 5121-operation conditional period and complexity explicit |
| QG5 | Pass: static versus executed coverage, selected scheduling versus stream identity, temporal frame reuse, initial bytes versus generated masks, and native writer assumptions distinguished |
| QG6 | Pass: pinned source/fixups, live-IDB rows, source proofs, finite-read certificates, byte provenance and independent A64 effects |
| QG7 | Pass: bounded impact-labeled continuation table |

Full-goal completion is false.
