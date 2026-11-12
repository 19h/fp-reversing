# CoreFP1201 complete Montgomery product and auxiliary-consumer boundary

Original implementation 0x74eb08 and cursor wrapper 0x74fd0c perform Montgomery multiplication on the tested canonical odd-modulus inputs. Eighty-one complete implementation calls agree with a separate big-integer modular oracle, including widths from one through 64 limbs (32..2048 bits) and distinct or aliased outputs. All 96 profiles complete both implementation and wrapper returns. Six retained width-mismatched odd-modulus controls falsify an unrestricted modular interpretation and remain explicit counterexamples. The continued outer consumer stops before 0x11425bc -> 0x59f4e8. Complete request1201 processing and native daemon/kext linkage remain unknown; the full investigation remains active.

## Primary source and artifacts

Addresses use reference CoreFP arm64e preferred base 0, SHA-256 `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; universal SHA-256 `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`. Fresh read-only IDA current/original bytes equal independent reference extraction:

| Recovered bounded role | Compiler-bounded interval | Size | SHA-256 |
| --- | --- | --- | --- |
| Product cursor wrapper | 0x74fd0c..0x74ff38 | 556 B | `6b163c894400902eb94c1d004abc16867bffa53164326bb39f1f8fd522f09005` |
| Montgomery-product implementation | 0x74eb08..0x74fd0c | 4612 B | `736e0190a0a23d3ef98abb1a64c5801ce7034883cf8b9f59d07597e52a95b9af` |

The 5168 B increment brings selected code to 39500 B. Independent parsing also checks the retained 85464 B parent, 3072 B lookup banks, 79512 original fixup words and 1602 compiler starts. IDA's initial implementation end is 0x74ed40, before indirect continuations; its wrapper end matches the compiler boundary. A knowledge-store query for 0x74fd0c returned no matching facts or notes. No IDB edits or native target/API execution occur.

Artifacts: [producer](triage_evidence/recover_fpsd1201_product.py), [checks and private states](triage_evidence/fpsd1201_product_checks.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_product.py), [audit receipt](triage_evidence/fpsd1201_product_audit.json.zst), [IDA readback](triage_evidence/fpsd1201_product_ida_readback.json.zst), [publication verifier](triage_evidence/verify_fpsd1201_product_publication.py). The [preceding consumer report](fpsd1201_consumer_report.md) establishes the incoming record, prepared-pair handoff and original call checkpoint.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PF1 | Pinned bytes and compiler starts identify this snapshot. All source/address claims depend on identity. | Fresh IDA current/original hashes agree with independent reference parsing. Native image selection remains unknown. |
| PF2 | Prior checkpoints and isolated fixture origins preserve their recorded provenance. | Pin the prior replay receipt; independently reconstruct checkpoint CPU/RAM, reaching pointer loads and every new operand control. Prefix instructions are not rerun here. |
| PF3 | The tested canonical mathematical interpretation uses positive odd n, canonical counts, 0 <= a,b < n and R=2^(32*k). | Eighty-one complete calls match the independent oracle across selected widths and output aliases. This is finite whole-call evidence, not a universal equivalence proof. |
| PF4 | Retained wide-input and even controls have separate interpretations. | Six odd counterexamples and six even profiles remain classified independently. No modular inverse is assigned to even n; no native admission conclusion follows. |
| PF5 | Declared global/guard backing, sequential epochs and explicit PAC models define private execution. | Check all new journals, CPU frames, original pointer rows and final RAM. Native initialization, authentication and concurrency remain unknown. |
| PF6 | Count predicates are interpreted at their actual 32-bit widths. | Independently prove the raw-count polynomial identity; distinguish bounded canonical counts from modular zero divisors and signed-count edge cases. |
| PF7 | Descriptor snapshots include neighboring bytes beyond the active operand extent. | Operand immutability checks use descriptor/count-defined limbs. Full journals and RAM remain byte-exact; a comparison result may change unrelated bytes inside a larger snapshot. |
| PF8 | The next auxiliary call defines the outer-consumer boundary. | Twenty-four nested profiles stop before 0x11425bc -> 0x59f4e8. Complete outer arithmetic, candidate result export, IPC exposure and native ownership remain unknown. |

## Product record and mathematical role [PF1-PF6]

Both wrapper and implementation receive X0 pointing to a 48 B record A and X1 pointing to a separate cursor cell. For p=low32(A), the selected state is:

```text
H = ((p XOR 0x7043a3fa) * 0x4ecee2ad) mod 2^32
MEM32[A+0x08] XOR H = 0xd7f4
```

The implementation's OR/AND/complement expression at 0x74ec48..0x74ec60 equals this mask for all 32-bit pointer values.

| A offset | Width | Role | Original load |
| --- | --- | --- | --- |
| +0x00 | 64 bits | First input descriptor a | 0x74ec6c |
| +0x08 | 32 bits | Encoded entry state | 0x74ec64 |
| +0x10 | 64 bits | Modulus descriptor n | 0x74ec70 |
| +0x18 | 64 bits | Prepared pair Q; Q+0x10 supplies coefficient c | 0x74eebc and 0x74ef48 |
| +0x20 | 64 bits | Output descriptor | 0x74eca8 |
| +0x28 | 64 bits | Second input descriptor b | Same LDP |

Descriptors retain signed count s32(MEM32[D+4]-0x4b0cf050), payload pointer D+8, and little-order 32-bit magnitude limbs decoded by XOR 0x1ac70ef2. For the tested positive odd modulus of k limbs, c=-n^-1 modulo 2^32 and the independently checked result is:

```text
R = 2^(32*k)
output = (a*b*R^-1) mod n
```

The implementation combines ordinary products with low-word Montgomery correction. Source 0x74f074 forms a limb product/add; 0x74f07c multiplies its low word by c; 0x74f094 accumulates the corresponding modulus term. A later reduction path uses 0x74f38c and 0x74f3a4. Original shift, comparison, subtraction and copy routines perform subsequent representation/reduction work and output delivery. Exact loop equivalence outside the tested contract remains unproved.

In the nested caller, a is Q's second descriptor. For the nine odd checkpoints, the earlier precomputation established a=R^2 mod n, so the product becomes b*R mod n when the tested canonical input condition holds. This establishes a local Montgomery-domain conversion for the canonicalized controls. It does not establish a complete exponentiation or authorization result.

## Case classes, aliases and counterexamples [PF2-PF4,PF7]

| Profile class | Count | Input provenance | Independent interpretation |
| --- | --- | --- | --- |
| Retained checkpoints | 12 | Exact prior input, modulus and prepared pair; no new operand controls | Nine odd comparisons include three agreements and six counterexamples; three even outcomes remain diagnostic |
| Canonicalized checkpoints | 12 | Replace only b's encoded count and low limb with b=min(0x12345678,n-1) at the audited checkpoint | Nine odd Montgomery results and three literal even REDC controls |
| Isolated products | 72 | Independently reconstructed private record, descriptors, coefficient and backing | Seventy-two odd Montgomery results; distinct, first-input and second-input output aliases |

The isolated one-word cases use n in {3,7,0xffffffff,0x80000001} with zero, near-modulus and interior operands. Wider cases use n=2^(32*k)-159 for k in {2,4,8,16,32,64}, with operand pairs (n-1,n-2) and (1,n-1), each under all three output aliases. These tests cover carries, reductions, asymmetric operand counts and in-place output. They do not establish arbitrary partial-overlap behavior or every modulus at each width. Output descriptor word +0 and its payload pointer are preserved on the retained complete returns; native capacity/ownership meaning remains unknown.

The retained second input has 32 limbs representing the earlier 128 B diagnostic input, while every retained modulus has one limb. Its value lies outside 0 <= b < n. Three accidental agreements do not establish a general modular interpretation:

| Odd n | Retained result | Unrestricted a*b*R^-1 mod n | Classification |
| --- | --- | --- | --- |
| 0x1 | 0x0 | 0x0 | Agreement |
| 0x3 | 0x0 | 0x0 | Agreement |
| 0x5 | 0x0 | 0x0 | Agreement |
| 0x7 | 0x4 | 0x3 | Counterexample |
| 0x11 | 0xa | 0x6 | Counterexample |
| 0x10001 | 0x3d29 | 0x0 | Counterexample |
| 0xffffffff | 0xd1cfb0cb | 0xb4b4b4b4 | Counterexample |
| 0x80000001 | 0x1f2bc6c0 | 0x34b4b4b9 | Counterexample |
| 0x7fffffff | 0xb8c13ce | 0x4b4b4b4c | Counterexample |

The exact unrestricted behavior for arbitrary mismatched widths remains unknown. The table establishes a falsification boundary, not a native defect: source-produced context widths and native input admission remain unestablished. The canonicalized controls retain the same modulus/pair and recover all nine expected odd results after an explicit input change. Their values are diagnostic controls, not source-produced replacements or supplied arithmetic outputs.

Even n in {2,0x80000000,0xfffffffe} remains separate. Retained outputs are respectively 0, 0 and 0x8358065d. The three canonicalized even controls match the literal one-word recurrence below, without an inverse interpretation; the last result is 0x125ba4a9:

```text
T = a*b
m = ((T mod 2^32)*c) mod 2^32
t = floor((T + m*n)/2^32)
output = t-n if t >= n else t
```

## Count grammar and environmental context [PF1,PF5-PF7]

Let Araw and Braw be the two encoded 32-bit count words. The original entry predicate at 0x74ecbc..0x74ecdc satisfies the universal identity, modulo 2^32:

```text
Braw*0x57f4924c + (Araw+0x5cfe7d64)*(Braw+0xb4f30fb0)
  = (Araw-0x4b0cf050)*(Braw-0x4b0cf050) + 0xe524f7c0
```

Its equality test against 0xe524f7c0 therefore checks a modular count product of zero. For nonnegative canonical counts at most 130, this is equivalent to at least one count being zero. It is not equivalent for arbitrary 32-bit counts: decoded counts 65536 and 65536 have zero product modulo 2^32. That is an algebraic counterexample, not an executed malformed descriptor or native admission result. A later selected-width comparison uses CMP W3,#0x83 at 0x74ede4. The complete native admission/capacity contract, signed minimum-count behavior and arbitrary malformed representations remain unknown.

Implementation-local descriptors contain raw metadata word 0x82 and stack payload pointers. The finite tests establish their numerical use and complete outputs; they do not assign allocator ownership to that metadata. Guard and mutable-global state come from the prior audited checkpoints or the declared constructor-entry fixture. All complete implementation calls execute the guard comparison and epilogue. Passing that declared private guard check does not establish native initialization or authenticity.

The 1024 B payload snapshots are evidence windows, not allocation-size declarations. In particular, a local comparison result can lie inside the window of a neighboring small descriptor. The independent audit compares operand stability only over the descriptor and count-defined limbs; it also checks every source read/write and complete final RAM separately. No ownership or mutation claim is derived solely from bytes appearing in a snapshot window.

## Original calls, returns and cursor emissions [PF1,PF2,PF5,PF8]

| Call site(s) | Original pointer slot | Target | IA modifier | Role |
| --- | --- | --- | --- | --- |
| 0x114245c | 0x1d03d18 | 0x74fd0c | 0xca9b | Product wrapper |
| 0x74ff10 | 0x1d04d38 | 0x74eb08 | 0x9ad6 | Product implementation |
| 0x74f614, 0x74f79c, 0x1142544 | 0x1d039b8 | 0x649430 | 0x8dc5 | Raw descriptor/limb copy |
| 0x74f6c4, 0x74f9b8, 0x74fabc, 0x74fcc8 | 0x1d03da8 | 0x33abec | 0x3d56 | Comparison |
| 0x74f8d8 | 0x1d03860 | 0x5a600c | 0xdd63 | Signed shift |
| 0x74fbd8 | 0x1d03920 | 0x5e8158 | 0x6144 | Signed in-place subtraction |
| 0x11425bc | 0x1d037a8 | 0x59f4e8 | 0x7c9f | Next unexecuted auxiliary dependency |

All selected authenticated rows use key IA and address diversity 0. Arguments are private process addresses, not Mach names. For incoming product-wrapper cursor seed s:

```text
mix = (s*0x2ea5 + 1) mod 2^64
padding = 16*((mix >> 60)+1) B                 # 16..256 B
product child entry SP = wrapper entry SP - 64 B - padding
child cursor entry = s - 112                  # raw unit unknown
child adds 112 at 0x74ec34
wrapper emits 16*((u32(child_cursor_after)-u32(s)) mod 2^16) B
```

All 96 early increments and complete child returns restore the raw seed. Implementation RETAB 0x74f7e0 executes, wrapper STR 0x74ff20 emits 0 B, and wrapper RETAB 0x74ff34 executes. The nested caller consumes the zero adjustment at 0x114246c. This is a stack-accounting channel, separate from the arithmetic output descriptor and root status.

After the product returns, the caller invokes original copy 0x1142544 and constructs the next record with the auxiliary descriptor at +0x08. Twenty-four nested profiles stop before 0x11425bc -> 0x59f4e8. The original caller later reads a word at record+0x04 at 0x11425c0, but the next routine's complete result grammar and function remain unknown. Nonnull auxiliary descriptors still contain unbacked diagnostic bytes; explicit null-auxiliary controls retain the source-initialized scalar 65537.

The nested root status remains 0xa5a5a5a5, outer output seed is preserved, and candidate P+0x880..P+0x8ff remains untouched. None of the newly executed paths invokes a Mach API or emits a Mach right. The [Mach-port report](mach_ports_report.md) retains established transport/right-emission evidence. Complete outer consumer return, native endpoint identity, daemon/kext pairing and deeper ownership remain unestablished.

## Independent validation and bounded continuation

The auditor constructs a fresh private CPU and independently reconstructs all new controls and isolated fixture bytes. It checks 1684168 visits, 255310 reads, 79914 writes, 59842 PAC models, 63570 full CPU frames, 3320 product-family checkpoints and 216 caller checkpoints. Restored, initial and final RAM are checked separately at 14548992 B each across 96 profiles. The 24 nested runs pin the preceding receipt SHA-256 `fb318e7c9c39e3943b58ca281ca7975d9a545e83cc1029c4f636f2645e1a7e71`; their prefix instructions are not rerun. The 72 isolated runs reconstruct the earlier declared constructor-entry fixture before applying their own explicit record/operand controls.

Independent helper oracles check 180 copies, 787 comparisons, 282 shifts and 219 subtractions. All 96 complete product children and wrappers, frame geometries, early cursor restorations and zero stack adjustments pass. Six retained UNSAT queries and six independently reconstructed obligations cover the pointer mask, count polynomial and cursor/padding identities; 22 selected original instructions are checked exactly. Solver normalization of the count polynomial is independently reconstructed before its UNSAT obligation is accepted. Complete arbitrary-input algorithm equivalence remains unproved.

| Impact | Bounded continuation / context | Probe and current boundary |
| --- | --- | --- |
| High | Recover auxiliary consumer 0x59f4e8 and complete the outer arithmetic sequence. | Establish its input/result grammar, actual auxiliary use and subsequent control flow; current call remains unexecuted. |
| High | Establish source-produced modulus/input width and admission invariants. | Trace context producers and normalization. Six retained counterexamples require preserving arithmetic preconditions when interpreting native roles. |
| High | Connect arithmetic output to real transport and ownership. | Follow candidate result export, complete request1201 return, endpoint/session identity and daemon/kext/deeper consumers. Current local returns supply no native IPC join. |
| Medium | Explain the exact mismatched-width recurrence. | Derive loop widths and intermediate normalization from original code; current full replay preserves outcomes without assigning a general mathematical contract. |
| Medium | Recover native descriptor capacity and malformed-count admission. | Trace metadata consumers and validation before interpreting modular zero divisors or the selected 0x83 comparison as native exposure. |
| Low | Extend finite arithmetic and alias coverage. | Test additional moduli, wider accepted counts and partial overlaps after establishing their backing and receiving contract. Current complete results cover selected widths and whole-descriptor aliases. |

Quality gates: **QG1** no normative content is required. **QG2** PF1-PF8 state assumptions, dependencies and falsification probes. **QG3** bounded routine roles, incoming record, output/alias behavior, original dispatch rows, data/control flow, environmental controls, stack emission locations and port consequences are covered. **QG4** B denotes bytes; limbs are 32 bits; modular widths, active extents, raw cursor units and complexity are explicit. **QG5** canonical, width-mismatched, even, zero-count and native-evidence limits are separated; neighboring snapshot bytes are not treated as operand ownership. **QG6** original bytes, fresh IDA, independent reference parsing, pinned predecessor receipts, complete replay and separate integer oracles support claims. **QG7** impact-ranked expansion remains bounded. The full investigation remains active.

## Subsequent auxiliary and consumer continuation

The [auxiliary/exponentiation report](fpsd1201_auxiliary_report.md) resolves 0x59f4e8 as magnitude bit length and 0x57af24 as magnitude bit selection. It completes 16 private consumer children/wrappers, with 14 odd-modulus exponentiation-oracle matches and two separate even controls. Eight unbacked auxiliary descriptors stop before a payload read. This advances the complete backed/canonical cases to unexecuted 0x981bc8 -> 0x32f628. The retained product counterexamples and native context/transport limits above remain applicable.
