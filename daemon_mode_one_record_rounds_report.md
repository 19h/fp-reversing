# Selected-record 64-round consumer, scratch refresh and suffix re-entry

The word-extension exit enters `0x100af5f50`, then the 64-round consumer at `0x100d8bb28`. The consumer reads 128 initialized private-grid words and 128 distinct image-bank words. All 623 scratch-byte read sites in the setup/body are bounded to the 961-byte domain. The exit updates sixteen saved state words and replaces both 64-byte scratch planes. Its original control circuit reduces to unsigned `COUNT > u32(BIAS+0xac6de8b8)`. After the established first prefix, this is `COUNT > 64`: COUNT=64 enters `0x100c74750`; larger values enter a register adapter and return to the plane initializer. Decoded round arithmetic, whole algorithm, native traversal/output and daemon/kext pairing remain unknown. [CR1-CR8]

Evidence: [source, image banks and fixups](triage_evidence/daemon_mode_one_record_rounds_source.json.zst), [queries, source SSA and complete ledgers](triage_evidence/daemon_mode_one_record_rounds_checks.json.zst), [extractor](triage_evidence/recover_daemon_mode_one_record_rounds.py), [validator](triage_evidence/validate_daemon_mode_one_record_rounds.py), [preservation](triage_evidence/daemon_mode_one_record_rounds_delivery.json), [quality gates](triage_evidence/daemon_mode_one_record_rounds_quality_gates.json), [sealer](triage_evidence/seal_daemon_mode_one_record_rounds.py), [publication audit](triage_evidence/verify_daemon_mode_one_record_rounds_publication.py). Context: [incoming word extension](daemon_mode_one_record_word_extension_report.md), [first 64-byte absorption](daemon_mode_one_record_long_prefix_report.md), [initializer first-entry contract](daemon_mode_one_record_long_planes_report.md), [saved image-root producers](daemon_mode_one_phase_handoff_report.md), [retained codebooks](daemon_mode_one_record_codecs_report.md).

| Evidence | Verified scope |
| --- | --- |
| Image | `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Current source | Four complete ranges, 16451 instructions / 65804 B; 16447 nonbranch sites translated |
| Incoming recapture | 61 ranges / 97224 B, including the image-root producers and twelve record-path stages |
| Instruction checks | 294 bitfield decodes, two ADRP decodes, five corrected CMP register-write reports; no SP write |
| Pointer provenance | Eight original records; six branch bindings including the repeated round entry |
| Source proof | 93 UNSAT / 2 SAT; seven selected predecessor queries replayed |
| Selected traversal | 8944+64*3334+4073=226393 nonbranch instances; optional re-entry adapter adds 96 |
| Integrity | Eight deliberately altered source, address, counter, image, lineage and native-claim records rejected |

F denotes the private frame, T=F+0xd10, WORD=F+0x8b0, COUNT=u32[F+0x728] and BIAS=u32[F+0x18]. All offsets/extents are bytes; arithmetic is modular u32/u64. Coherent readable nonwrapping mappings, stable saved/image roots and no outside writes remain premises. These are source models and solver results, with no target execution, emulation, API/IPC requests, IDA access, IDB mutation or hardware PAC test. [CR1-CR4]

## Setup and incoming state

The setup has 8944 nonbranch instructions, 598 loads and 107 private-frame stores. Its operand-based first-read census requires W1, X23, X24, W22, W14, W27, W15, W20, X22 and W25. The actual word-extension source proves the high halves of incoming X22/X23/X24 are zero. The setup then supplies zero-extended X7/X13/X20/X28 to the round entry. Width constraints are established at their actual boundaries. [CR2-CR3]

The setup consumes sixteen saved u32 words at F-relative offsets:

```text
444 448 44c 458 460 464 468 46c
470 474 478 47c 480 484 488 48c
```

It also reads the retained byte at F+0xeed and uses the saved scratch, word-grid and authenticated-table roots. The source models retain arbitrary values for the saved data words and scratch-byte returns. Their decoded state representations and native producers are not inferred from their offsets. [CR2-CR4]

A fresh query over the earlier gather exit proves F+0x598=0x5588. The intervening extension preserves it. The setup clears only low32 bits of F+0x738, sets F+0x558=0x3c0d and F+0x590=0x487a61a9, and copies u32[F+0x48c] into F+0x6c0. It selects table slot0x5588 -> `0x100d8bb28`, IA diversity0x8d97. This slot is loaded before the final frame/register effects complete. [CR2-CR3,CR7]

## Environment-dependent reads and constant image family

Each round reads two independent u32 values:

| Source PC | Read |
| --- | --- |
| `0x100d8c1c4` | Through CELL0=u64[F+0x580] |
| `0x100d8c1cc` | At image address `0x1010c4670` |

Let their values be C and G. The source constructs

```text
z = u8(((G-C) XOR0xa6)*0x0a5cd4cf)
family = z XOR Right[Left[z] XOR0x4e]
```

The saved roots established by the workspace producer are Left=`0x100fc4130` at F+0x588 and Right=`0x101031ea0` at F+0x568. A fresh producer-query replay, original-byte recapture and twelve-stage literal/normalized store census preserve those roots. Historical computed-store domains retain their pinned prior source certificates; this is not a replay of every historical solver query. CELL0 remains an independently named pointer with unknown native owner/identity. [CR1-CR4]

All 256 original byte cases give family=0xff. The proof binds the actual controller and byte-bank read addresses to that rule. It then replaces only the low eight bits of W10 at `0x100d8c204`; its upper 24 bits remain unchanged. The retained cut record names both its source-binding certificate and finite-bank lemma. Equality or constancy of C and G is unnecessary. [CR3-CR4]

The selected pointer is read at `0x100d8c25c` from pool slot `0x1010a4568`. Its original rebase target `0x12eb216df` plus u64 bias `0xffffffffd241f721` gives `0x100f40e00`. The retained bank contains 192 u32 slots / 768 B. Values are preserved as original bytes; no round-constant decoding is claimed. [CR1,CR3-CR4]

## Exact 64-round read and control interface

For IX=0..63, source certificates prove:

| Read PC | Exact address |
| --- | --- |
| `0x100d8c2b0` | `WORD+4*((227*(IX+143)) mod280)` |
| `0x100d8c5c8` | `WORD+4*((227*(IX+211)) mod280)` |
| `0x100d8c270` | `0x100f40e00+4*((179*((IX XOR0x2f)+76)) mod192)` |
| `0x100d8c4e0` | `0x100f40e00+4*((179*(IX XOR8)) mod192)` |

The full 64-case ledger checks every grid label against the incoming 256 initialized words. Each pair of read streams has 128 distinct slots across the traversal: 512 B from the grid and 512 B from the image bank. The other 128 populated grid words and 64 image slots are outside these four read sites. Those coverage counts do not decode the values or identify a complete hash. [CR3-CR5]

The round loads IX from low32 F+0x738 and ultimately stores IX+1 there. IX=63 selects0xc9e9 -> `0x100ca55b0`; all earlier IX select0x5588 -> the round entry. Both records use IA diversity0x8d97. A separate finite-index theorem establishes 63 repeats, 64 bodies and final low32 F+0x738=64. F+0x730 receives the incoming u32[F+0x6d8], not the round index. [CR3,CR5,CR7]

## Complete scratch-byte containment

There are 485 scratch-byte read sites in setup and 138 in the body, hence 485+64*138=9317 operations on the selected traversal. One setup read is the literal T+477. Of the remaining 622 sites, 615 have source-certified reciprocal remainder shapes and seven have direct unsigned64 offset-bound certificates. [CR3-CR4]

| u64 multiplier / shift | Numerator domain | Sites |
| --- | --- | --- |
| `0x443215 / 32` | 0..4033828 | 352 |
| `0x8864298f / 41` | Full u32 | 262 |
| `0x8864299 / 37` | 0..4033828 | 1 |

Original-source range queries prove the bounded numerators. Integer theorems prove each quotient equals floor(N/961), including product/subtraction width closure and remainder0..960. A separate bit-vector theorem proves subsequent low16 extraction preserves those remainders. Candidate DAG aliases propose shapes; the accepted equalities use the original source SSA. [CR3-CR4]

Aggregate 138-site, 46-site, one eight-site and one individual round shape query returned unknown at15000 ms and are excluded. Accepted setup groups of at most46 and round groups of at most8 provide coverage. At `0x100d8e92c`, two separate universal source overapproximations prove the computed remainder and its saved/reloaded address. One source numerator or remainder definition is replaced by an unconstrained u32 for each corresponding proof; no concrete value or assumed equality is introduced. The actual numerator bound is proved separately. Together these identities complete all623 bounds. Unsplit free-numerator and tactic attempts are also excluded. Early exploratory queries with an undeclared CELL0 emitted diagnostics and were rejected; accepted queries declare it explicitly. Solver diagnostics, timeout/unknown, nonzero exit and unexpected results fail validation. [CR3,CR8]

Containment does not establish which initialized codebook family each read selects, its returned value or the decoded arithmetic. None of these bounds assumes a lookup-value codomain. [CR4,CR6]

## State update and scratch refresh

The 4073-instruction update has 50 saved-frame loads plus one branch-pointer load. It makes 163 private-frame store effects: 35 u32 stores and 128 byte stores. There are no byte reads, record-buffer reads or external calls in this block. All sixteen saved state-word destinations listed above are written; complete expressions and store epochs remain in the source model. For example, the original source proves:

```text
u32[F+0x478] = old_u32[F+0x478] + incoming_u32[F+0x610]
u32[F+0x48c] = old_u32[F+0x48c] + incoming_u32[F+0x6c0] + 0xb966c739
```

These are raw modular state equations, not a recovered standard compression function. F+0x6c0's incoming state is consumed before the cell is repurposed to a control boolean. F+0x738 is also repurposed to a data expression; its final value cannot be interpreted as the earlier round count. [CR3,CR6-CR7]

The 128 byte destinations are exactly:

```text
T+((866*(896+i)) mod961), 0<=i<64
T+((866*(827+i)) mod961), 0<=i<64
```

Each is written once. They replace the two old planes, preserve all 800 C/D/E/H/I arithmetic/codebook cells and introduce no new record reads. A topological declared-leaf census excludes COUNT and BIAS from every byte value; their presence in the branch circuit therefore does not imply a data dependency in these stores. Remaining dependency membership is an upper bound, not proof of influence. The compact byte functions and their correspondence to the updated saved state remain unknown. [CR3-CR4,CR6]

The complete 1120-byte grid view, including its 1024 populated bytes, survives setup, all rounds and update. COUNT, PBUF, saved roots, F+0x18/F+0x2cc progress biases, the 296-byte workspace and F+0x1210 budget also survive. Preserving the budget locally does not prove complete accounting. [CR4,CR7]

## Exact suffix predicate and re-entry ABI

The update implements this unsigned source predicate for all u32 COUNT and BIAS:

```text
more = COUNT > u32(BIAS+0xac6de8b8)
```

Its original carry-sensitive circuit remains valid across modular wraparound. The validator proves equality to this expression over the entire u32 domain, rather than extrapolating from one frame valuation. At `0x100ca61b8`, low32 F+0x720 becomes 1 iff more. The final pointer load at `0x100ca954c` selects:

| Predicate | Selector | Original target |
| --- | --- | --- |
| False | 0x3c0d | `0x100c74750` |
| True | 0x3c10 | `0x100db56f0` |

Both records use IA diversity0xbcfd. The earlier prefix source proves BIAS=0x53921788. The gather/extension scalar-store census and new complete store census preserve it. Since u32(0x53921788+0xac6de8b8)=64, the selected predicate is COUNT>64. The established incoming COUNT>=64 path therefore reaches the false edge exactly at COUNT=64 and the true edge for COUNT>=65. A SAT negative control refutes replacing the strict comparison with COUNT>=64. [CR2-CR3,CR5,CR7]

The 96-instruction adapter at `0x100db56f0` makes three loads and no stores. The update supplies F+0x6b0=0x6317 and restores W24=0x23. The adapter preserves W24 and supplies:

| Register | Value |
| --- | --- |
| W19 | 0x4923 |
| W23 / W22 / W21 / W27 | 0xc8 / 0x5c / 0x74 / 0x16 |
| W8 | 0x7f3081c2 |

It selects0x6317 -> `0x100c88438`, IA diversity0xbfe1. This matches the initializer's previously established constant register ABI; the two four-word data banks remain arbitrary in that earlier contract. However, BIAS now differs by64 from the initializer's first-entry epoch. Its downstream count test and subsequent record-address progression require fresh parameterized proofs. No second-block read or complete multi-block traversal is claimed here. The 6895-instruction alternative block at `0x100c74750` also remains outside the new translated source. [CR3,CR6-CR8]

## Architectural and external-control context

COUNT controls the post-round route, while the body repetition is fixed at64. The two runtime controller-word values enter a byte selector whose image family is source-proved constant. Saved image pointers, original byte banks, the private grid, scratch and scalar frame state are distinct architectural interfaces. The source uses authenticated continuation records at the listed emissions, but successful native authentication and arrival remain premises. [CR1-CR5,CR7]

All four captured ranges have one terminal BRAA and no other call, branch or trap. They perform no Mach send/receive, port allocation or right transfer, and establish no new incoming/outgoing Mach-port contract. New stores are private frame effects, not established caller-output or interprocess publication. The broad daemon/kext interaction remains an open investigation. [CR1,CR4,CR7-CR8]

## Assumption register and bounded continuation

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| CR1 | Pinned image, fixups and bank bytes identify the source variant | Recapture65804 current/97224 prior bytes, eight pointer records and1280 bank bytes; reject eight altered records |
| CR2 | Incoming roots, scalar epochs and widths compose | Replay seven selected predecessor queries; prove F598=5588 and incoming X22/X23/X24 high halves; check twelve-stage root and post-prefix scalar preservation |
| CR3 | ISA lowering, SSA and proof composition are accurate | Translate16447 sites; independently decode294 bitfields/two ADRPs; check original read/store addresses, justified low-byte cut, finite bank cases and all623 scratch bounds |
| CR4 | Coherent nonwrapping mappings, stable image roots and no outside writes | Check initialized grid coverage, all store footprints, retained800 cells and protected roots; native owners/extents remain unknown |
| CR5 | The64-body counter induction and raw suffix predicate compose | Prove IX+1, final IX63 branch, full64-case read chronology and all-u32 carry-sensitive predicate; refute the wrong COUNT64 boundary |
| CR6 | Raw state/lookup representations are interpreted within proved scope | Retain arbitrary byte returns and word values, all163 update stores and dependency census; do not infer decoded recurrence, initialized lookup membership or whole hash identity |
| CR7 | Frame epochs, source arrivals and PAC prerequisites permit traversal | Distinguish low32 reset, IX counter, later data and boolean roles; verify six slot/modifier bindings; native PAC/exceptions/arrival remain unknown |
| CR8 | Re-entry/final-route semantics, output and cross-layer pairing remain incomplete | Reprove initializer with advanced BIAS, follow0x100c74750, establish actual record/output consumers and corresponding external interface |

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| High | Re-entry at0x100c88438 | Parameterized BIAS/count test, actual second-block or short-suffix addresses and accumulated progress |
| High | Alternative0x100c74750 | Complete source/control and resulting serialization or next interface |
| High | Decoded round/state recurrence | Initialized lookup-family/value contracts and representation maps, including image words and128-byte refresh |
| High | Daemon/kext connection | Actual native owners, caller-visible output and matched external ABI |
| Medium | Controller-cell lifecycle | CELL0 pointer producer/owner, global writer widths and synchronization context |

The selected body count is64; it does not grow with COUNT. Extraction and source translation are linear in captured instructions. The finite chronology uses O(64) cases and bounded slot sets. Query size is linear in retained SSA plus the selected terms; SMT runtime is solver-dependent, limited to15000 ms per query and20 s per process. No value recurrence is unrolled through64 bodies. Source replay, assertions, preservation and publication checks all concern this increment, not completion of the broader goal.

QG1: The claims concern factual source, ABI, memory/control, mathematical equality and evidence provenance.

QG2: CR1-CR8 identify assumptions, dependent results and falsification probes.

QG3: Full setup/round/update/adapter source, both word-read families, all scratch containment and suffix selection are covered for this increment; the broader goal remains active.

QG4: Widths, byte extents, all64 cases, accepted solver results, finite image cases and source operation counts are reproducible.

QG5: Register ABI and changed frame epoch are distinct; bounds and initialized table semantics are distinct; u32 phases are separated from pointers/full-u64 stores; private updates are separated from output.

QG6: Original bytes/fixups, fresh prior-source recapture, original-source solver equalities and complete retained ledgers support the stated scope; no new native or IDA observation is claimed.

QG7: The bounded continuation prioritizes advanced-BIAS re-entry, the alternative block, decoded state, lifecycle and actual cross-layer publication.

Follow-up: [Position-aware re-entry and bounded absorption cycle](daemon_mode_one_record_reentry_report.md) proves the changed frame epoch,shifted short/full record addresses,the24/15 seed-word split,and conditional cycle coverage while retaining the modular-boundary counterexample.
