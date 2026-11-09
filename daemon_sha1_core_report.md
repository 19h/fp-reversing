# Selector-2 encoded SHA-1 compression core

Selector2 reaches a complete SHA-1 block-compression implementation. The recovered source decodes 16 big-endian input words, expands an 80-word schedule, executes four groups of 20 rounds and accumulates five working words into the context state. Its 320-byte scratch reservation is now identified as the 80-u32 schedule in the checked path. Schedule words use XOR0x8B3DC651; context and working-state words use XOR0xF4F92DF7. This establishes the nature of the core beyond its earlier IV/selector signature. Native caller continuity, completion of the retained identity path, external digest formatting, 36-byte cache publication and driver IPC linkage remain unknown. The full daemon/kext/deeper-interface investigation remains active.

This extends the [compression-frame ABI report](daemon_compression_frame_report.md). The new executions are isolated source compositions under declared frame/context premises. They do not resume the retained unknown-frame frontiers by supplying purported native values.

## Evidence and proof scope

| Evidence | Verified extent |
| --- | --- |
| Original daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Original source | 13 contiguous spans; 1,467 unique instructions; 16 original authenticated fixups |
| Current IDB | `fairplayd`, target `6b117c693e3b`; ten read-only windows / 5,376 bytes, raw identical |
| Local source proofs | 44 solver obligations, with original/normalized artifacts; 1,302 lifted instructions |
| Supporting algebra | 26 independently proved source-register substitutions: 16 round lemmas and ten feed-forward operand lemmas |
| Complete core cases | 48 persisted and freshly recomputed compositions; 783,984 source visits |
| Execution accounting | 7,968 modeled BRAA visits; 776,016 instructions executed by the isolated A64 engine |
| Ordered effects | 28,224 reads / 5,040 writes checked independently |
| Semantic comparisons | 3,840 schedule words; 3,840 round-entry states; 3,840 round-exit states; 48 complete context results |
| External model checks | 16 padded-message SHA-1 comparisons and 16 standard-IV raw-block model-tail comparisons against host hashlib |

[Source contracts and helper ABIs](triage_evidence/daemon_sha1_core_contracts.json), [proof artifacts](triage_evidence/daemon_sha1_core_proofs.json), [rewrite plan](triage_evidence/daemon_sha1_core_rewrite_plan.json), [complete source traces](triage_evidence/daemon_sha1_core_profiles.json), [independent reference model](triage_evidence/daemon_sha1_core_model.py), [independent checks](triage_evidence/daemon_sha1_core_checks.json), and [current IDB bytes](triage_evidence/daemon_sha1_core_ida_bytes.json) provide provenance. [Preservation](triage_evidence/daemon_sha1_core_preservation.json) and [delivery gates](triage_evidence/daemon_sha1_core_quality_gates.json) seal the increment.

The source lift records an equivalence obligation for every proposed register substitution. The proof chain is accepted only after those lemmas and their dependent obligations are discharged. It then establishes the decoder, schedule, round and state-accumulation identities under the recorded helper-entry premises. The independent verifier reconstructs those expressions, matches both serialized forms and re-solves the normalized obligations. The earlier monolithic round query timed out; an overgeneralized sum-abstraction query was rejected after SAT. Neither is accepted evidence; the [solver audit](triage_evidence/daemon_sha1_core_solver_audit.json) records these exploratory outcomes separately. The final proof uses certified substitutions and semantics-preserving normalization.

These are universal local word identities plus finite complete source executions. A universal whole-program/native reachability, arbitrary aliasing or caller-state preservation proof is not established. Each helper's counter domain and calibrated register constants are explicit premises. Their occurrence and stability are independently checked throughout the 48 complete traces. No fairplayd process, target framework call, Mach/IOKit operation, hardware PAC or IDB mutation executes. Host hashlib supplies independent algorithm checks.

All addresses, offsets and encoding/control constants below have explicit `0x` prefixes. Counts/extents are decimal bytes unless stated. F denotes the relevant outer SP; C is context, B is schedule scratch, and T=`0x101039EF0`. Arithmetic on words wraps modulo 2^32; pointer/cursor arithmetic wraps modulo 2^64, subject to valid-owner/nonaliasing premises.

## Source roles and exact algorithm correspondence

The decoded recurrence agrees with [FIPS180-4, sections4.1.1, 4.2.1 and6.1.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf), DOI `10.6028/NIST.FIPS.180-4`. The equations below are independently recovered from the daemon's source instructions and checked against that reference.

| Source entry / write site | Recovered role |
| --- | --- |
| `0x100A361B0` | Selector2 setup; loads the fifth encoded state word from C+0x58 and prepares input-word decoding |
| `0x100968C04`; store `0x100968DB8` | Decode four encoded bytes as one big-endian word and store 16 encoded schedule words |
| `0x100BA8BA4`; store `0x100BA8C10` | Expand schedule words16 through79 |
| `0x100A0DD8C` | Rounds0 through19: choose function; constant0x5A827999 |
| `0x100D30E74` | Rounds20 through39: parity; constant0x6ED9EBA1 |
| `0x100ACC478` | Rounds40 through59: majority; constant0x8F1BBCDC |
| `0x100D30C74` | Rounds60 through79: parity; constant0xCA62C1D6 |
| `0x100908450`; context store `0x100908658` | Preserve final C/D working words in frame temporaries and accumulate final E into context word4 |
| `0x100BDF3BC`; paired stores `0x100BDF7BC`, `0x100BDFAEC` | Accumulate final A/B/C/D into context words0 through3 |
| `0x100BDFAF0` | Reaches the previously recovered return epilogue; execution stops before it in these cases |

Let encoded byte d be decoded as d XOR0x98, and let ROL denote 32-bit rotation. The source establishes:

```text
W[t] = BE32(decoded input[4*t:4*t+4])                     0 <= t < 16
W[t] = ROL1(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16])   16 <= t < 80
stored_schedule[t] = W[t] XOR 0x8B3DC651

T0 = ROL5(A) + f(B,C,D) + E + K[t] + W[t]               mod 2^32
(A,B,C,D,E) <- (T0,A,ROL30(B),C,D)

decoded_state[j] <- initial_state[j] + working80[j]       mod 2^32
stored_context_word[j] = decoded_state[j] XOR 0xF4F92DF7
```

The input buffer is 64 bytes. The schedule is 80*4=320 bytes, written at B+4*t in increasing t order. All 80 words are written before their required reads in every complete case; undefined private-byte reads are rejected. Input-word and expanded-word contracts prove the actual source addresses and encoding over all byte/word values under their index domains. Schedule expansion reads exactly the t-3/t-8/t-14/t-16 words. Round contracts prove the working-word transformations for arbitrary u32 inputs under the recorded phase and counter premises.

The shared other-selector target `0x100BDF3BC` is therefore also a state-accumulation block on the verified selector2 path. Its appearance in the other-value selector partition does not establish an error-handler role. Its behavior from those other entry states remains a separate question.

## Register and memory ABI

The complete cases begin at the shared frame setup ABEE44. Exactly seven incoming registers, including SP, are declared defined: SP=F, X4=X12=C, X30=T, W8=W15=0x471C and W20 equal to continuation index0x0E or0x58. No unrelated incoming GPR or initial condition flags are declared defined. Both the trace engine and independent audit reject source reads of undefined registers.

The source requires the previously recovered saved-frame cells. These are explicit isolated fixtures, not recovered native caller values: F+0x31DC (encoded count), F+0x2F50 (saved input value), F+0x2E50 (context/root value), F+0x2C8C (raw count), F+0x3490 (raw input value), F+0x3620 (cursor), and F+0x273C (saved mode). The context is 100 bytes with the earlier buffer/state/size/selector layout. No input bytes are defined through the separately saved input pointer; the core reads its encoded block from C.

At B76438, the source saves `load64(T+8*signed32(W20))` at F+0x2DE0, reserves B=F+0x39F0+Q through cursor Q+320, and transfers the dispatch root from X30 to X2 before X30 is used as a state register. Selector2 subsequently loads C through F+0x2A70. The phase-specific working-state register maps are:

| Phase / rounds | A | B | C | D | E |
| --- | --- | --- | --- | --- | --- |
| 0 / 0..19 | W11 | W19 | W0 | W30 | W15 |
| 1 / 20..39 | W11 | W13 | W0 | W20 | W5 |
| 2 / 40..59 | W11 | W13 (also W1) | W0 | W26 | W19 |
| 3 / 60..79 | W11 | W13 | W0 | W5 | W4 |

Each listed word carries the decoded working word XOR0xF4F92DF7. The recorded helper-entry ABI includes the zero-extended word representations needed by source instructions that read X-register aliases. The finite audit checks full register values, not only their low halves. The local proofs establish word transitions under those entry encodings; complete universal loop/handover/caller invariants are not asserted.

The source uses different encoded counter registers in the four round groups, while X16 addresses the schedule and X2 retains T. Original dispatch-cell identities, pointer diversity and actual data/control reads are retained in each journal. BRAA is modeled from original logical targets and checked metadata; native authentication is not executed.

## State writes, caller geometry and publication boundary

In each complete core case, the only writes inside C are five u32 state updates at C+0x48/+0x4C/+0x50/+0x54/+0x58. The 64-byte encoded input buffer, eight counter bytes and size/selector fields remain byte-identical. The last two context stores are paired instructions: their journals contain two 4-byte effects each. There is no separate canonical 20-byte digest-buffer write in this checked core.

For the padded `abc` fixture with the standard IV, decoding the resulting state and serializing its words big-endian gives:

```text
a9993e364706816aba3e25717850c26c9cd0d89d
```

This equals host hashlib's SHA-1 result. The cases also cover empty/short/non-ASCII messages, 55-byte one-block padding boundaries, varied raw 64-byte blocks and eight arbitrary five-word initial states. There are 16 padded-message, 16 standard-IV raw-block and 16 custom-state cases across the two continuation/frame placements. For standard-IV raw blocks, the reference model's subsequent padding block is checked against hashlib; the daemon execution still processes only the declared first block.

Combining the new source scratch formula with the retained layout in the preceding reports gives this conditional geometry, assuming the same F and preserved cursor:

| Retained branch | Context | Reserved output before compression | Derived schedule scratch |
| --- | --- | --- | --- |
| Short finalization, Q=0x310 | F+0x3C70, 100 bytes | F+0x3CE0, 32 bytes | F+0x3D00, 320 bytes; end F+0x3E40 |
| Long update, Q=0x2F0 | F+0x3C70, 100 bytes | No such reservation yet | F+0x3CE0, 320 bytes; end F+0x3E20 |

The short output ends exactly where the derived scratch begins; neither overlaps the 100-byte context, whose end is F+0x3CD4. This arithmetic does not resume a retained frontier or establish native bounds/preservation. The separate heap cache of 36 bytes remains a different owner. A completed identity digest, its final byte/text representation and a write/copy into that cache remain unknown.

```text
declared C: encoded block[64] + counters + encoded state[5] + size/selector
                     |
              decode16 BE words
                     v
          schedule[80], XOR0x8B3DC651
                     |
              4 groups * 20 rounds
                     v
          add five working words to initial state
                     |
          C+0x48..0x58, XOR0xF4F92DF7
                     v
          stop before saved-return epilogue BDFAF0

native retained caller -> core: frame inputs still unjoined
core state -> external digest -> cache[36] -> driver IPC: unknown joins
```

## Assumption register and bounded continuation

| ID | Premise / dependent claims | Stress or falsification probe |
| --- | --- | --- |
| SC1 | Original thin image/fixups/current IDB identity / all addresses | Rehash image; compare 13 spans and ten current byte windows |
| SC2 | Accessed frame-control, context, schedule and static-table cells do not overlap / local word proofs | Defined-byte ledgers and alternate placements; arbitrary aliasing/native owner bounds remain outside scope |
| SC3 | Shared-entry mode/register/frame declarations / complete isolated core traces | Only seven incoming registers defined; reject undefined GPR/flag/byte reads and mutable/unknown image reads |
| SC4 | Original read-only logical dispatch targets / modeled branch identity | Independently decode 16 fixups and check each of7,968 BRAA edges; require separate native preservation/authentication evidence |
| SC5 | Recorded helper constants, encoded counters and zero-extended state words / universal local identities | Reclassify helper inputs in all48 complete traces; native caller and universal cross-helper invariants remain open |
| SC6 | Proposed algebraic substitutions are accepted only after proof / compositional source equivalence | Rebuild26 source-register lemmas and all dependent obligations; reject SAT/unknown proposals |
| SC7 | Independent reference implements the stated algorithm / semantic comparisons | Compare all80 schedule/round steps and32 hashlib oracle cases; retain arbitrary-state comparisons separately |
| SC8 | Context state update is distinct from digest-buffer formatting / output interpretation | Check exact five state writes and unchanged remaining context bytes; follow actual finalizer output stores |
| SC9 | Same frame and cursor persist / derived retained scratch geometry | Recompute Q+320 and owner intervals; trace intervening effects and native arena bounds |
| SC10 | Selector2 scope / core classification | Prove fixed selector dispatch as before; analyze selector1 and other-entry roles separately |
| SC11 | Host-side source execution is isolated / execution boundary | No fairplayd/framework/Mach/IOKit/hardware-PAC execution or IDB writes; original inputs preserved |
| SC12 | Cache/transport joins remain unproved / architectural scope | Require actual producer, publication, emission and matching driver-consumer evidence |

| Impact | Additional opportunity / unresolved pattern | Required next evidence |
| --- | --- | --- |
| High | The selector2 core is identified; final byte representation is still open | Follow the short continuation and actual finalizer state-to-output stores |
| High | Retained identity frontiers require ambient frame provenance | Recover real producers or establish their irrelevance on a continuous path; do not assign native values from these fixtures |
| High | Core state and cache[36] are different storage contracts | Recover explicit copying/encoding/publication into the cache and its downstream consumers |
| High | Digest-to-driver relationship remains unknown | Join resulting bytes to an existing Mach/IOKit emission and matching kernel/kext input |
| Medium | Selector1 may implement another compression family | Recover its endian handling, schedule, rounds and output contract independently |
| Medium | BDF3BC is shared state accumulation | Classify other selector-entry states without assigning an error role from routing alone |
| Medium | The schedule mask also occurs in other field codecs | Establish actual data flow; a repeated numeric mask alone does not identify a wire contract |
| Low | Universal whole-core interpretation still needs stronger invariants | Prove register/counter/owner preservation and helper handovers beyond the finite complete corpus |

Reproduction uses the pinned Python/Z3 environment from the preceding reports. Run `probe_daemon_sha1_core.py`, `recover_daemon_sha1_core.py`, `prove_daemon_sha1_core.py`, then `validate_daemon_sha1_core.py`. The source probe records explicit fixtures, original instructions, register/byte-definedness, ordered effects, authenticated-target metadata and round snapshots. The validator reconstructs proofs, reruns all48 complete cases and compares independent semantic/byte ledgers. For a block, the compact model uses O(80) time/space including retained history. Source tooling uses O(total visits/effects + source + solver resources) time; memory includes compressed artifacts, one decoded/fresh journal, one private mapping and solver expressions. Solver queries have a 30-second limit; no polynomial SMT complexity bound is claimed.

QG1: factual technical scope. QG2: SC1-SC12 and falsification probes. QG3: selector2 core increment covered; full objective remains incomplete. QG4: explicit byte/word widths, masks, endianness, modulo arithmetic, modeled dispatch counts and geometry. QG5: local universal proofs, finite complete cores, state writes, native caller continuity and cache/IPC publication remain distinct. QG6: original source/fixups, live IDB, certified proof chain, fresh complete traces, standard reference and host algorithm oracles support scoped claims. QG7: impact-ranked additional evidence table provided.
