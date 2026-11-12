# CoreFP1201 consumer handoff after Montgomery precomputation

Original caller 0x9819c4 passes the completed precomputation pair, imported input, modulus and optional auxiliary descriptor through cursor wrapper 0x1142c08 to implementation 0x1142154. The implementation stages a second 48 B record and reaches 0x114245c -> 0x74fd0c. That call remains unexecuted. Twelve independently audited private checkpoints establish this handoff; the complete consumer's arithmetic function, request1201 return and native daemon/kext linkage remain unknown. The full investigation remains active.

## Primary source and retained evidence

Addresses use reference CoreFP arm64e preferred base 0, SHA-256 `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; universal SHA-256 `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`. Fresh read-only IDA current/original bytes equal independently parsed reference bytes:

| Bounded role | Compiler-bounded interval | Size | SHA-256 |
| --- | --- | --- | --- |
| Consumer cursor wrapper | 0x1142c08..0x1142e30 | 552 B | `c498a0d116dfeb0a72309f6bd91a76dee428d83e70173e7e1c3666d60dca604c` |
| Consumer implementation | 0x1142154..0x1142c08 | 2740 B | `6ae430a6038ad6cea268ce3fc2a933c6b8151380119467ec4c8415d70dfe2e7b` |

The 3292 B increment brings selected code to 34332 B. Independent reference parsing checks all selected bytes, the retained 85464 B parent, 3072 B lookup banks, 79512 original fixup words and 1602 compiler starts. IDA's initial implementation end is 0x1142614; indirect continuations extend through the compiler-bounded interval. Its wrapper end matches the compiler boundary. A knowledge-store query for both entries returned no matching facts or notes. No IDB edits or native target/API execution occur.

Artifacts: [producer](triage_evidence/recover_fpsd1201_consumer.py), [continuation checks](triage_evidence/fpsd1201_consumer_checks.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_consumer.py), [audit receipt](triage_evidence/fpsd1201_consumer_audit.json.zst), [IDA readback](triage_evidence/fpsd1201_consumer_ida_readback.json.zst), [publication verifier](triage_evidence/verify_fpsd1201_consumer_publication.py). The [precomputation report](fpsd1201_reduction_report.md) establishes the preceding complete child/wrapper returns and distinguishes odd, even and bounded-zero inputs.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CF1 | Pinned bytes and compiler starts identify this snapshot. All address/source claims depend on identity. | Fresh current/original IDA hashes equal independent reference extraction. Native image selection remains unknown. |
| CF2 | Published checkpoints retain their audited CPU/RAM and provenance. Continuation results depend on these private states. | Pin the prior full-replay receipt and checks hashes; compare all restored register, SIMD, flag and RAM values, plus the reaching original pointer load. Prefix instructions are not rerun here. |
| CF3 | State 0x8a6e selects this incoming record contract. | Independently simplify the pointer mask and check every retained record. Other states remain outside the contract. |
| CF4 | Existing diagnostic modulus, input and auxiliary controls preserve their stated timing. | Resume all twelve positive cases without new operand controls. Explicit null-auxiliary cases contain source-initialized 65537; the other auxiliary descriptors retain unbacked diagnostic bytes. Native field production remains unknown. |
| CF5 | Original decoded pointer rows, sequential globals and declared PAC/guard models define private execution. | Independently check new journals, CPU frames, original pointer metadata and final RAM. Native authentication, initialization and concurrent epochs remain unknown. |
| CF6 | Local frame arithmetic describes the wrapper/child cursor channel. | Check all twelve seed-dependent frame geometries and observed child increments. The wrapper emission and complete return remain unexecuted. |
| CF7 | The first outgoing record and unretained call define the current boundary. | Stop before 0x114245c and verify its reaching definitions. Later arithmetic, output writes and limb consumption remain unknown. |
| CF8 | A Montgomery-product interpretation of the next dependency is a hypothesis. | Recover 0x74fd0c and its implementation, then compare complete original results against independent arithmetic. Current pointer roles alone do not establish that function. |

## Incoming record and optional operand [CF1-CF5]

For incoming record C and p=low32(C), all 32-bit operations wrap modulo 2^32:

```text
H = ((p XOR 0x1766cddd) * 0xb7a7bfff) mod 2^32
state = MEM32[C+0x10] XOR H = 0x8a6e
```

The implementation computes this state at 0x1142294..0x11422d0. Its original OR/AND/subtract expression equals the stated XOR expression for every 32-bit pointer value; no alignment premise is required for this simplification.

| Incoming C offset | Width | Recovered association | Evidence boundary |
| --- | --- | --- | --- |
| +0x00 | 64 bits | Prepared pair Q | Loaded at 0x11422d4; Q+8 loaded at 0x1142304 |
| +0x08 | 64 bits | Candidate result descriptor | Retained pointer; original load at 0x1142618 lies beyond the executed boundary |
| +0x10 | 32 bits | Encoded entry state | Loaded at 0x11422cc; remaining four bytes are not assigned a role |
| +0x18 | 64 bits | Auxiliary descriptor | Loaded at 0x11422d8 and saved locally; its limbs are not consumed in this continuation |
| +0x20 | 64 bits | Imported input descriptor | Loaded by the same LDP and passed to the next record |
| +0x28 | 64 bits | Context modulus descriptor | Loaded at 0x11422e4 and passed to the next record |

The predecessor's source-staged record chooses the auxiliary source. Eight retained cases preserve the nonnull context auxiliary at context+0x3a0, whose descriptor bytes remain diagnostic 0xa5. Four explicit null-auxiliary controls instead select the local scalar descriptor initialized to 65537. Both sources reach the same new call boundary. The local fallback is source-produced within the retained prefix; its native selection and the nonnull context field's actual contents remain unknown.

The descriptor grammar remains signed count s32(MEM32[D+4]-0x4b0cf050), payload pointer D+8, and little-order 32-bit limbs decoded by XOR 0x1ac70ef2. Imported input retains 32 limbs, representing the earlier 128 B diagnostic input. Reading a descriptor pointer or retaining a checkpoint view does not establish that the target read its payload. This continuation reads neither the imported input's 128 B limb extent nor the fallback auxiliary's single limb.

## First outgoing record [CF1-CF5,CF7,CF8]

At 0x114245c, X0 points to 48 B record A at child X29-0x90. X1 points to a separate local cursor cell. These are private process addresses; they are not Mach names.

| Outgoing A offset | Width | Reaching value | Original definition |
| --- | --- | --- | --- |
| +0x00 | 64 bits | Q's second descriptor | Q+8 load 0x1142304; store 0x1142358 |
| +0x08 | 32 bits | Encoded control, observed decoded state 0xd7f4 | Store 0x1142348 |
| +0x10 | 64 bits | Modulus descriptor | STP at 0x1142350 |
| +0x18 | 64 bits | Pair Q | Same STP |
| +0x20 | 64 bits | Local scratch descriptor | STP at 0x1142354 |
| +0x28 | 64 bits | Imported input descriptor | Same STP |

For the retained outgoing addresses, MEM32[A+8] XOR (((low32(A) XOR 0x7043a3fa)*0x4ecee2ad) mod 2^32) equals 0xd7f4. This is an observed selected-state association; the receiving routine's full admission grammar remains unknown. The scratch descriptor has raw word +0 equal to 0x82, encoded count 0x4b0cf050 and payload pointer child SP+0x2b8. Its decoded count is zero. Native capacity, ownership and later normalization are not assigned from word +0.

For the nine odd-modulus checkpoints, Q's second descriptor was independently established as R^2 mod n with R=2^32. The three even controls retain the predecessor's literal arithmetic outcomes; no inverse interpretation is added. Passing R^2, Q, n and an input into a common helper makes a Montgomery-domain conversion a bounded candidate [CF8]. Complete multiplication and exponentiation semantics remain unknown.

```text
audited precomputation checkpoint at 0x9819c4
    Q + modulus + imported input + auxiliary + candidate result
                         |
                         v
               wrapper 0x1142c08
                         |
                         v
            implementation 0x1142154
                         |
                         v
       A = {Q.second, control, n, Q, scratch, input}
                         |
                         v
       0x114245c -> 0x74fd0c [call not executed]
```

## Calls, cursor channel and environment [CF1,CF2,CF5-CF7]

| Call site | Original pointer slot | Target | IA modifier | Execution in this increment |
| --- | --- | --- | --- | --- |
| 0x9819c4 | 0x1d056a0 | 0x1142c08 | 0x4032 | Executed with the retained reaching pointer-load association |
| 0x1142e08 | 0x1d04098 | 0x1142154 | 0x33f2 | Executed |
| 0x114245c | 0x1d03d18 | 0x74fd0c | 0xca9b | Stopped before execution |

All selected authenticated rows use key IA and address diversity 0. PAC instructions are explicit private models, not native authentication observations. The guard pointer and mutable-global epoch are restored from the declared audited checkpoint. The implementation reads the declared guard at entry; its epilogue check has not executed.

For wrapper seed s, arithmetic wraps modulo 2^64 unless an explicit extraction is shown:

```text
mix = (s*0x2ec5 + 1) mod 2^64
padding = 16*((mix >> 60)+1) B                 # 16..256 B
child entry SP = wrapper entry SP - 64 B - padding
child cursor entry = s - 240                  # raw unit unknown
child writes (child cursor entry + 240) at 0x1142288
```

All twelve observed increments restore the wrapper's raw incoming seed. The wrapper's later emission site is STR X8,[X19] at 0x1142e18. Its unexecuted formula is 16*((u32(child_cursor_after)-u32(s)) mod 2^16) B. If the final child cursor equals s, that formula emits 0 B; a complete consumer return and actual emission are not established here. The caller's later SP adjustment is likewise beyond the current boundary. Raw cursor units remain unknown.

The root status remains 0xa5a5a5a5, outer output seed is preserved, and candidate P+0x880..P+0x8ff remains untouched. None of the newly executed instructions invokes a Mach API or emits a Mach right. The [Mach-port report](mach_ports_report.md) retains the established send/receive and right-emission evidence. Actual IPC exposure, native endpoint/right ownership, daemon/kext pairing and deeper transport remain unknown.

## Independent verification and bounded continuation

The producer resumes twelve positive checkpoints from the published precomputation checks, preserving their exact CPU/RAM and adding no operand controls. Zero has no completed precomputation checkpoint and is excluded with its earlier 64-iteration boundary preserved. The prior full-replay receipt is pinned by SHA-256 `40264eef84f86e6fdf9de0a480b6e46b88ffcc3f9168db976600e6bc818ca2e0`; prefix instructions are not rerun in this increment.

An independent auditor constructs a fresh private CPU, loads original bytes and decoded original pointer rows, restores each pinned checkpoint and checks all 3888 new visits, 828 reads, 516 writes, 48 PAC models, 144 full CPU frames and 72 consumer checkpoints. Restored checkpoint RAM and final RAM each cover 1818624 B across the twelve profiles. Each profile checks its reaching original pointer load, seed-dependent child frame, early cursor restoration and outgoing record. Five retained UNSAT queries, five independently reconstructed obligations and 17 selected original instructions pass. Full consumer equivalence and native execution remain unproved.

| Impact | Bounded continuation / context | Probe and current boundary |
| --- | --- | --- |
| High | Recover the first receiving arithmetic helper. | Inspect 0x74fd0c, recover its record grammar and dependencies, and compare complete original results against independent arithmetic. Current call remains unexecuted. |
| High | Recover full consumer control flow and auxiliary use. | Follow the later count/bit/loop paths and actual descriptor writes. An exponentiation interpretation remains unproved. |
| High | Establish source-produced context and real IPC continuity. | Trace modulus/auxiliary writers and match endpoint, session, payload, status and ownership across transport evidence. Diagnostic backing does not establish native admission. |
| Medium | Resolve complete cursor lifetime and output channel. | Reach the consumer epilogue and wrapper emission at 0x1142e18 without supplied results. Current seed restoration occurs early, before further arithmetic. |
| Medium | Distinguish representation capacity from raw metadata. | Recover scratch descriptor word +0 consumers and bounds; 0x82 alone does not establish an allocation contract. |
| Low | Extend mathematical coverage after a complete contract is recovered. | Vary canonical widths, aliases, zero/even admission and environmental epochs only with declared backing and independent oracles. |

Quality gates: **QG1** no normative content is required. **QG2** CF1-CF8 state assumptions, dependencies and falsification probes. **QG3** bounded routine roles, incoming/outgoing records, data/control flow, original dispatch sites, environmental controls, cursor channels and port consequences are covered. **QG4** B denotes bytes; limbs are 32 bits; modular widths, raw cursor units, extent checks and complexity are explicit. **QG5** checkpoint provenance, unbacked auxiliary, tested zero/even scope, unexecuted calls/returns and arithmetic hypotheses are distinguished. **QG6** primary binary bytes, fresh IDA readback, independent reference parsing, prior replay receipt and fresh continuation replay support claims. **QG7** impact-ranked expansion remains bounded. The full investigation remains active.

## CoreFP1201 complete product continuation

The [complete product continuation](fpsd1201_product_report.md) resolves the previously unexecuted 0x74fd0c dependency and implementation 0x74eb08 under tested canonical inputs. It retains six width-mismatched odd counterexamples, verifies complete product/wrapper returns, and advances the outer consumer to unexecuted 0x11425bc -> 0x59f4e8. Full outer consumer and native request1201 processing remain open.
