# Mode1 post-extension word consumer, frame updates and continuation

Current extension: [Internal phase latch and C0/LOCAL handoff](daemon_mode_one_phase_handoff_report.md) establishes sixteen repack stores,32 bijective word encodings in a296 B workspace,a distinct re-entry mixer with F460=86,and conditional request-field/raw-error suffixes. All880 captured nonbranch sites translate;122 UNSAT and nine SAT results pass. Later set-bit-visit reachability,successful publication,budget history and native daemon-kext pairing remain unknown.

The word-extension exit at `0x100c5917c` reaches a source-proved 64-round consumer at `0x100d53ba4`. Two u32 read sites consume logical grid streams 135..198 and 67..130, covering 128 distinct words / 512 B. Two further u32 sites read 128 distinct words / 512 B from a scattered 192-slot image bank at `0x100f4aaf0`. A following block performs 20 private-frame stores and sets phase `0x2ac4`; the selected signed comparison `52 < 86` then reaches `0x100cec684`. The entire private word view and scratch domain remain unwritten. These are static source/control/address contracts; complete byte-access bounds, natural round-value equations, algorithm identity, caller publication and native daemon/kext pairing remain unknown. [WR1-WR8]

Evidence: [source, pointer records and image banks](triage_evidence/daemon_mode_one_word_rounds_source.json), [38 queries, source SSA and coverage ledgers](triage_evidence/daemon_mode_one_word_rounds_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_word_rounds.py), [validator](triage_evidence/validate_daemon_mode_one_word_rounds.py), [frame/SSA helper](triage_evidence/daemon_word_round_tools.py), [preservation](triage_evidence/daemon_mode_one_word_rounds_delivery.json), [quality gates](triage_evidence/daemon_mode_one_word_rounds_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_word_rounds_publication.py). Context: [lookup families](daemon_mode_one_lookup_roles_report.md), [word-grid producer](daemon_mode_one_word_schedule_report.md), [bank/frame-root producers](daemon_mode_one_inverse_tables_report.md), [initial frame encodings](daemon_mode_one_state_materialization_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original image | `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Captured source | Six ranges, 13404 instructions / 53616 B |
| Translation | All 13400 captured nonbranch sites; 2024 predecessor nonbranch sites freshly replayed |
| Prior source recapture | 17 ranges / 18884 B |
| Pointer/control provenance | Seven pointer records, seven edge bindings, two independently decoded ADRP targets |
| Image data | Two 256 B byte banks and one 768 B word bank; 256 selector cases |
| SMT | 34 UNSAT and four SAT; includes 15 UNSAT and one SAT predecessor replays |
| Local proofs | 19 UNSAT and three SAT controls/domains; one certified selector cut |
| Source alteration controls | Five source/data/pointer/target/native-claim alterations rejected |
| Execution | No target execution, emulation, IPC/API request, new IDA access, IDB edit or hardware PAC check |

## Source blocks and control chain

| Block | Source interval, end exclusive | Instructions | Local function |
| --- | --- | ---: | --- |
| Setup | `0x100c5917c..0x100c6270c` | 9572 | Reset round counter, prepare private arithmetic state and control cells |
| Round | `0x100d53ba4..0x100d56e90` | 3259 | Read two grid words and two image words, update private state, increment round counter |
| State update | `0x100b2ab1c..0x100b2b398` | 543 | Twenty u32 frame stores and phase/control handoff |
| Gate | `0x100cad378..0x100cad3e0` | 26 | Signed threshold comparison and selected continuation |
| Root publications | Two retained source fragments | 4 | Publish saved bank pointers and CELL0 pointer |

The setup writes F+0x750=0, retains F+0x598=0x9033, writes F+0x5a0=0xab26 and sets the u64 F+0x588 value to 7. These results are proved for arbitrary modeled incoming data and byte returns; they do not require choosing concrete table-return values. The setup also changes F+0x6d8 to the preexisting u32 at F+0x540. Its earlier saved-byte/phase interpretation no longer applies after this handoff. [WR2-WR4]

| Source | Table index / condition | Target | IA diversity |
| --- | --- | --- | --- |
| Word-extension predecessor | 0xb8d9 | `0x100c5917c` | 0x4a5b |
| Setup | 0x9033 | `0x100d53ba4` | 0xf68f |
| Round, IX=0..62 | 0x9033 | `0x100d53ba4` | 0xf68f |
| Round, IX=63 | 0x9043 | `0x100b2ab1c` | 0xf68f |
| State update | 0xab26 | `0x100cad378` | 0xe7b9 |
| Gate, signed F460 < 86 | 0x2aca | `0x100cec684` | 0xb560 |
| Gate, signed F460 >= 86 | 0x2ac4 | `0x100dc9674` | 0xb560 |

The round reads its u32 counter from F+0x750 and writes IX+1. Its source dispatch expression is exactly the two-way selection above for IX<64. Starting from the setup's zero, the selected path therefore executes IX=0..63: 63 repeat edges and one exit edge. The retained source pointer records establish authenticated rebase targets and diversity fields; hardware authentication is not tested. [WR1-WR3]

## The two private-grid streams

The inherited producer view is `W=F+0x8b0`, with physical word slot `(47*j) mod273` for logical label j. The consumer addresses are:

| Read site | Address, for 0<=IX<64 |
| --- | --- |
| `0x100d5455c` | `W +4*((47*(IX+135)) mod273)` |
| `0x100d545a8` | `W +4*((47*(IX+67)) mod273)` |

Both complete source expressions, including their short quotient/mask calculations and UXTH-scaled address operands, are universally checked against these formulas. The first uses the numerator offset 0x18c9=47*135; the second uses 0xc4d=47*67. Their logical labels are among the predecessor's 256 established populated words. [WR2-WR4]

The 64-entry coverage ledger verifies that these two sites read 128 distinct slots, with no repetition within or between their streams. Their total classified grid footprint is `2*64*4 B=512 B`. The other 128 populated grid words lie outside this pair's footprint. The remaining byte-read addresses and the native identity/aliasing of CELL0 are not fully established here, so this is not a proof that no other read can touch those bytes. [WR4-WR6]

## Global-word reads and a fixed image-word bank

The round reads a u32 through the pointer saved at F+0x580 at `0x100d5442c`, and another u32 directly from `0x1010c4670` at `0x100d54434`. The first pointer is retained as CELL0 in this increment; its native identity is not inferred from the later literal global read. The two observed word values A and B remain independent arbitrary u32 inputs in the proofs. No equality, fixed initial value or synchronization of their writers is assumed for the selector theorem. [WR3,WR5-WR6]

Let `V=u8(((B-A) XOR0xa6)*0x0a5cd4cf)`. Source bindings prove the two byte reads:

| Site | Address / returned byte |
| --- | --- |
| `0x100d54458` | `0x100e99a00 + V`, returning L |
| `0x100d54468` | `0x100f4e390 +(L XOR0xd7)`, returning R |

For every V in 0..255, the original pinned banks satisfy `V XOR right[left[V] XOR0xd7] =0x8c`. A universal bit-vector query checks the finite bank functions. A separate source query binds both addresses and the actual low-byte selector to this same expression. Under the immutable-bank and valid-read premises, the cut at `0x100d54854` therefore sets its masked selector to 0x8c. It does not replace an entire unmasked data register with that byte. [WR3-WR5]

The source then reads pool slot `0x1010a4080`, whose unauthenticated rebase target is `0x13063d4ee`. Adding the exact u64 source bias `0xffffffffd090d602` yields `0x100f4aaf0`. The slot expression, original rebase record and biased root are all checked. Thus arbitrary changes to the two modeled global word values can change the selected intermediate byte-bank addresses, but cannot change this resolved word-bank pointer under the recorded bank premises. Native bank mutation or invalid mappings are outside the theorem. [WR3,WR6]

| Image-word read | Address, for 0<=IX<64 |
| --- | --- |
| `0x100d5487c` | `0x100f4aaf0 +4*((53*(IX XOR0x74)) mod192)` |
| `0x100d54884` | `0x100f4aaf0 +4*((53*(IX XOR0x0d)) mod192)` |

The XOR argument ranges are 64..127 and 0..63, respectively. Since gcd(53,192)=1, their scatter produces 128 distinct word slots. The ledger checks every round and both source formulas; the classified footprint is 512 B within the 768 B bank. The other 64 slots lie outside these two read sites' footprint. All 192 original u32 values are retained as source data without assigning an algorithm name to the bank. [WR4-WR6]

## Frame-state update and next gate

At `0x100b2ab1c`, the selected path performs exactly 20 literal u32 frame stores. Their values and addresses are retained in the complete source SSA/store ledger. Two directly recovered relations illustrate the state handoff:

```
new F540 = old F540 + old F6d8                  (u32)
new F510 = current F710 + current F728          (u32)
```

Here "current" refers to values after earlier stores in this same block; it is not an unverified claim about the block's initial operands. These relations and the following control facts are source-certified together. Natural round-state equations beyond them remain unknown. [WR2,WR4-WR5]

The state-update block reads the established F+0x5a0=0xab26 and writes F+0x730=`0xab26 XOR0x81e2=0x2ac4`. Its branch selects table index 0xab26 and reaches `0x100cad378`. F+0x750 changes epoch: it now receives low32 of the incoming W5 value at `0x100b2ab24`. The previous interpretation as a round counter has expired. The proof does not infer a public field type or external owner for these stores. [WR2,WR4,WR7]

With F+0x730=0x2ac4, the gate computes:

```
(0x2ac4 XOR0x2ac3)*0x749 -0x32a9
 = 7*1865 -12969
 = 13055 -12969
 = 86
```

Its comparison is signed u32 interpretation, not unsigned. The generic source proof selects 0x2aca when `s32(F460)<86`, otherwise 0x2ac4. The earlier materializer's F+0x460=0x34=52 is freshly replayed, and retained absorption/gather/extension store ledgers plus the new source stores preserve this cell. The selected comparison is therefore `52<86`, reaching `0x100cec684`. The alternative `0x100dc9674` remains the generic other branch, not the selected continuation. The next target's behavior is not proved in this increment. [WR2,WR4-WR5,WR8]

## Preservation, byte accesses and architectural scope

| Block | Frame stores | Distinct bytes written | Inclusive frame-offset envelope |
| --- | ---: | ---: | --- |
| Setup | 140 | 360 B | 0x468..0x753 |
| One round | 89 | 228 B | 0x590..0x753 |
| State update | 20 | 80 B | 0x50c..0x753 |
| Gate | 0 | 0 B | Empty |

These are envelopes, not claims that every enclosed byte is written. Every actual store is a literal frame store; all corresponding load/store addresses are source-certified. There are no stores into the 1092 B word view starting at F+0x8b0, including its 1024 populated bytes, or into the 963 B scratch domain starting at F+0xd00. Saved roots F+0x570/+0x578/+0x580/+0x738/+0x740/+0x758, selector F+0x598 and selected F+0x460 remain untouched. [WR2,WR4,WR6]

The new helper forwards little-endian frame bytes explicitly, including partial-width overlaps, rather than assuming that every reload has the width of its most recent store. Separate word-store/reload laws, a partial-width overwrite identity and the EXTR32 shift-28 identity check the added frontend operations. Both source ADRP instructions are independently decoded from their instruction words to verify their page targets. All 13400 captured nonbranch sites translate; unsupported instructions cause rejection. [WR1,WR4]

The setup has 484 byte-load sites, including the direct saved map byte at F+0xe5e; the round has 140. The selected path therefore contains `484+64*140=9444` byte-read operations. Two per-round byte reads are the fully bound original selector-bank reads above. This increment does not establish complete address bounds, table-family membership or value equations for the other byte accesses. Their values remain arbitrary component inputs where they are unnecessary for the word-address and control proofs. Valid reads remain a premise of the static path. [WR5-WR6]

There are no calls, traps, Mach send/receive operations, port creation/right transfers or external callbacks in the four selected blocks. No new incoming/outgoing Mach-port identity or message-emission location is established. The new architectural touch points are the private-grid consumer, saved frame epochs, two global-word read sites and the fixed image-word bank. The caller-visible output/serialization path and native daemon/kext association remain unresolved. [WR6-WR8]

## Assumption register and controls

One new SAT query establishes a nonempty round domain. Two further SAT controls distinguish a wrong grid base of 134 from 135 and signed from unsigned threshold comparison. The fourth SAT result is the replayed predecessor domain check. These are mathematical controls, not observed native inputs or runs. All accepted queries reject unknown, timeout, diagnostics and unexpected results.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| WR1 | Pinned image and original bytes identify the analyzed variant | Rehash image, recapture 53616 B and 17 prior ranges, check seven pointer records and both ADRP encodings; reject five source alterations |
| WR2 | Selected predecessor, frame roots and F460 epoch apply | Regenerate and compare the word-grid predecessor source/translation/semantics; replay root publications and compact F460 proof; check intervening stores |
| WR3 | Original bank bytes and relocation records remain applicable | Recheck all 256 selector cases, source bank addresses, slot 0x1010a4080 and its bias; falsify by a different bank epoch or rebase model |
| WR4 | Fixed-width ISA translation and byte-coherent frame forwarding preserve source semantics | Translate every captured nonbranch site; check endian/partial-width/EXTR identities and original global/grid/ROM/control/frame addresses |
| WR5 | The selector cut uses the actual source operands and immutable-bank relation | Match both read sites/byte symbols and the masked source selector; retain the universal bank lemma and explicit source-binding certificate |
| WR6 | Valid nonwrapping frame, mapped reads and source memory premises hold | Establish native owner/mapping/lifetime and CELL0 identity; complete the other byte-read bounds and alias analysis before claiming a full read footprint |
| WR7 | Private frame stores do not alone establish caller-visible publication | Follow actual copy/return/serialization consumers; preserve the F750 counter-to-data epoch transition |
| WR8 | Complete natural-value equations, algorithm and cross-layer pairing remain unknown | Follow 0x100cec684, compose the new state-update SSA and connect resulting buffers to concrete interface contracts |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence needed |
| --- | --- | --- |
| High | Follow `0x100cec684` toward output or outer control | Source-bound next selectors, state/buffer owners and any copy/return/publication chain |
| High | Complete the 624 byte-access sites' bounds and algebra | Actual roots, typed value premises and checked table-family/address certificates for the new bodies |
| High | Recover complete natural round/state-update equations | Compose actual grid/ROM/table values through source store SSA; instruction motifs alone do not identify an algorithm |
| Medium | Identify native CELL0 and mutable global writers | Original producer/caller provenance and mapping/lifetime evidence; do not assume equality with the literal global |

For N source instructions, M forwarded frame-byte operations and L total expanded/intermediate string processing across source expressions, bank functions, proof queries and records, frontend construction is O(N+M+L) time and storage. Source widths are fixed and each scalar frame access touches at most 8 B. Solver complexity is separate; each query has a 15000 ms solver limit and a 20 s process limit. Slot labels/counts are dimensionless and extents are bytes.

QG1: The report states source, arithmetic, control, memory and provenance facts.

QG2: WR1-WR8 register dependent results and falsification probes.

QG3: The selected setup, 64-round word-address/control contract, global/bank touch points, 20-store update, signed gate and architectural/Mach scope are covered; the overall investigation remains active.

QG4: 34 UNSAT, four SAT, full captured-source coverage, 128+128 distinct classified word reads, byte/store counts and gate arithmetic are reproducible.

QG5: Classified word footprints are distinguished from unresolved byte/global aliasing, frame counter epochs and unknown natural-value equations/native behavior.

QG6: Fresh source/data/fixup capture, predecessor comparison/replays, full source SSA, binding ledgers and five alteration controls establish scoped provenance.

QG7: Four impact-ranked followups retain the actual output/interface objective and unresolved data/control/value boundaries.
