# Original boot-option parsing and topology/thread composition

Original boot-option scanning and conversion now execute before original serialized-tree readers, CPU enumeration, the post-enumeration helper and bootstrap-thread construction. The selected composition uses no declared tree-reader or boot-option output returns. Actual boot-input provenance, startup caller continuity, callback authentication, lower receiver effects and a matched daemon/kext/kernel transaction remain unknown. [BO1-BO7]

```text
private NUL-terminated option buffer at bootargs+0x6c
  original option scanner
    original bounded name comparison and strlen
    original numeric decoder -> original delimiter callback
    original width-dependent output stores
  original serialized-tree readers and topology publication
  original enumeration return -> configuration helper -> thread copy/setter
  explicit later CPU-initializer call frame
    declared cache/context returns and logical system effects
```

Thirteen private components include nine topology cases and four dedicated API groups containing 29 calls. Eight cases reach the original 1472 B thread-template copy; the zero-limit case stops before the null boot-record load. Original tree initialization precedes every component, with an explicit complete-RAM caller frame into main or each dedicated API. This is conditional composition, not native startup. [BO3-BO6]

| Claim | Established result | Dependencies |
| --- | --- | --- |
| BO1 | Pinned source closure, data and exact aliases | BO-A1 |
| BO2 | Scanner/converter/flag/delimiter register ABIs and output ownership | BO-A1-BO-A3 |
| BO3 | Selected grammar, name matching, duplicates, numeric widths and string/presence behavior | BO-A1-BO-A3 |
| BO4 | Source callback construction and logical authenticated call boundary | BO-A1, BO-A4 |
| BO5 | Original option inputs compose with tree/topology/main/thread setup | BO-A1-BO-A5 |
| BO6 | Local proofs, independent grammar/call/byte checks, register-aware replay and controls | BO-A1-BO-A6 |
| BO7 | Mach/daemon limits and impact-ranked continuation | BO-A1-BO-A7 |

Primary provenance is collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, original compiler starts, exact nlist, chained fixups and source/data bytes. The normalized kext remains SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Reference data sufficed; no IDB was read or modified. [BO1]

Artifacts: [capture producer](triage_evidence/recover_kernel_boot_option_execution.py), [private executor](triage_evidence/probe_kernel_boot_option_execution.py), [independent grammar/contracts and replay](triage_evidence/replay_kernel_boot_option_execution.py), [source audit](triage_evidence/audit_kernel_boot_option_execution.py), [delivery verifier](triage_evidence/verify_kernel_boot_option_execution_delivery.py), [capture](triage_evidence/kernel_boot_option_execution_checks.json.zst), [audit](triage_evidence/kernel_boot_option_execution_audit.json.zst). Decoded capture: 555652 B, SHA-256 `5e446c087eb354dbfcab980fa75ed1637c126e6a0d01a04725d1007a7991e23d`. Decoded audit: 52528053 B, SHA-256 `7e7f47cc6f2624baceb1f5f1b1208a04f361b27d3095cb07b1a9d8759d947257`. [BO6]

## Original routines and register contracts

Twenty-four captured routines contain 3681 words / 14724 B; twenty intervals exactly match the [serialized-tree capture](kernel_secure_dt_execution_report.md). Four additions provide `_strlen`, the flag writer, numeric decoder and delimiter callback. The capture includes 29 strings, 19 logical data blocks, three original pointer fixups and three retained opaque words. A 32 B original `_strlen` literal block at `0xfffffe000bc9daa0` and the original string `1` at `0xfffffe00070eb5dc` are captured. [BO1]

Intervals are half-open. Original names remain unknown for the role-described routines. [BO1]

| Original interval | Words | Exact name / role | Executed unique PCs |
| --- | ---: | --- | ---: |
| 0xfffffe000c5e48a4..0xfffffe000c5e4ca8 | 257 | Boot-option scanner; name unknown | 204 |
| 0xfffffe000c5e4d20..0xfffffe000c5e4f50 | 140 | Numeric decoder; name unknown | 139 |
| 0xfffffe000c5e4f50..0xfffffe000c5e4f88 | 14 | Delimiter callback; name unknown | 14 |
| 0xfffffe000c5e4ca8..0xfffffe000c5e4d20 | 30 | Width-dependent flag writer; name unknown | 30 |
| 0xfffffe000bc9db70..0xfffffe000bc9dbe0 | 28 | _strlen | 25 |
| 0xfffffe000bc9dbf0..0xfffffe000bc9dd7c | 99 | _strncmp; previous capture | 65 |

The three remaining `_strlen` interval words decode as UDF padding and are unexecuted. The separate three opaque words retained from earlier captures are also unexecuted. The uppercase hexadecimal conversion instruction at `0xfffffe000c5e4e4c` is captured but unexecuted in these fixtures. PC coverage does not prove exhaustive path coverage. [BO1,BO6]

| Routine | Incoming contract | Return / output contract in selected calls |
| --- | --- | --- |
| Scanner | X0 option buffer; X1 requested name; X2 output; W3 width; W4 interpretation mode | X0=1 when selected matching option found, else 0; miss preserves output |
| Numeric decoder | X0 token delimiter/value pointer; X1 u64 output; X2 callback; W3=0 from scanner | W0=0 stores full u64 result; W0=1 preserves output; opposite success polarity from scanner |
| Delimiter callback | W0 character | W0=1 exactly for NUL/TAB/SPACE in the checked contract, otherwise 0 |
| Flag writer | X0 output; W1 width | Writes numeric one with selected width; X0 remains the pointer; no status-return type inferred |
| strlen | X0 NUL-terminated requested name | X0 byte length |

Actual topology callers pass buffer `bootargs+0x6c`, widths 4 B for `cpus`, 8 B for `cpumask`, zero for `enable_skstb`/`enable_skstsct`, 4 B for `cluster_power`, and 4 B for `siq_realtime_thread_mode`. W4 is zero. The original buffer producer, native capacity, source of its contents and any daemon influence remain unknown. The private integration buffers are bounded to at most 256 B including NUL. [BO2,BO5]

## Selected scanner and numeric semantics

The scanner separates option names using NUL, TAB, SPACE and `=`. It compares the selected name bytes with original `_strncmp` and also requires equality with original `_strlen(requested_name)`. It scans ordinary matching options through the remaining buffer; the last selected numeric duplicate supplies the final value in the tested cases. Width zero is presence-only and does not write the caller output. [BO2,BO3]

| Input / call | Established result |
| --- | --- |
| `cpus=2 cpumask=0x4` | u32 CPU limit 2; u64 mask 4 |
| `cpus=02 cpumask=0b100` | Same limit/mask through octal/binary decoding |
| `cpus=3 cpus=2 cpumask=1 cpumask=0x4` | Last selected values: 2 and 4 |
| `cpus_extra=0 cpus=1 cpumask_extra=0` | Exact requested names select only cpus=1 |
| Dedicated `n=7`, request `n_extra` | Absent; output preserved despite a matching prefix |
| Bare `enable_skstb`, width 0 | Present; no caller-output write |
| Dedicated `n`, width 0 | Present; output preserved |
| Dedicated `n=auto`, width 16, W4=0 | Converter rejects numeric form; scanner writes NUL-terminated `auto` |
| Dedicated `n=17`, width 16, W4=1 | Writes text `17` rather than a binary integer |
| Dedicated `n= 7`, width 4 | Present; fallback string is empty at the leading separator |
| Dedicated `n =7`, width 4 | Selected call returns absent and preserves output |

Dedicated flag calls with `-n` exercise the original one/two/three/four/eight-byte writer. The flag branch returns after its selected match. Bare options in forced-text mode use the captured original string `1`. Special underscore-name paths, unusual signed widths and broader string-mode behavior remain outside the executed fixture domain. No general buffer-capacity guarantee is inferred. [BO3,BO-A3]

Numeric decoding tests decimal, leading-zero octal, lowercase `0x` hexadecimal and lowercase `0b` binary prefixes; lowercase hex digits; a leading minus sign; and case-insensitive K/M/G suffixes. Accumulation is modular u64. Suffixes shift the signed-u32 scale by 10/20/30 before sign extension and modular u64 multiplication. These are numeric multipliers; no physical unit is implied. [BO3,BO6]

| Dedicated value | Raw u64 result |
| --- | --- |
| `17`, `021`, `0x11`, `0b10001` | 17 |
| `-17` | 0xffffffffffffffef |
| `2K` | 2048 |
| `3m` | 3145728 |
| `1G` | 1073741824 |

| Requested numeric width | Observed store |
| --- | --- |
| 0 | No caller-output store; presence status |
| 1 B | Low 8 bits |
| 2 B | Low 16 bits |
| 3 B | Low 24 bits; adjacent fourth byte preserved by the original 32-bit read/modify/write |
| 4 B | Low 32 bits |
| 8 B | Full 64 bits |

The three-byte numeric case `0x12345678` writes `78 56 34` while retaining a fourth byte initialized to `a5`. The three-byte flag path similarly writes `01 00 00` and preserves that byte. Captured source also contains a default 32-bit numeric-store path; extents beyond the listed numeric cases remain unestablished here. Implicit/forced text output is checked separately. [BO2,BO3,BO6]

## Callback boundary and cross-layer composition

Original scanner PCs `0xfffffe000c5e49d0..0xfffffe000c5e49dc` construct the delimiter callback address and discriminator `0xba5`. Source PACIA signs that pointer before it is passed to the numeric decoder. The decoder uses original BLRAA instructions with the callback pointer in X19 and discriminator in X17. The private executor and independent replay require the target to equal `0xfffffe000c5e4f50` and X17 to equal `0xba5` at every selected authenticated call. [BO4,BO6]

All 129 callback calls execute the original delimiter body. PACIA and BLRAA authentication are logical envelopes: the model retains the raw callback address, records the source instruction, updates LR/PC for the call and does not compute or validate native authentication bits. Native authentication, fault behavior and actual return/PAC semantics remain unknown. [BO4,BO-A4]

Original option parsing now produces the limit/mask/power/mode bytes consumed by original enumeration and the post-enumeration helper. The independent grammar derives an option map only for record-formula validation; that map is never injected into executor memory or used as an execution-time API result. Original tree initialization, lookup/property/iterator/scan routines, numeric decoding and caller stores all execute before original topology return and thread setup in the eight composed cases. [BO5,BO6]

The bare power-flag case clears the original cluster-power word before `cluster_power=7` overwrites it, and `siq_realtime_thread_mode=3` reaches the admitted original system-register gate. The sixteen-CPU case parses `cpus=0x10`, publishes ordinal 15 and consumes it in original bootstrap-thread construction. The zero-CPU case parses zero and stops before the original null boot-record load. [BO5]

Explicit call frames remain at initializer-to-main, initializer/dedicated-API boundaries and main-to-later-CPU-initializer. Their 46 epoch records preserve complete RAM and declare SP/LR/argument changes. They do not establish the real bootloader/kernel caller chain or intervening registration callbacks. The 42 remaining declared returns are lower selector0e/cache/context helpers; no tree or boot-option output return is modeled. Hardware/system effects, lower receiver state and native boot inputs remain unknown. [BO4,BO5]

## Verification and assumptions

Twenty-six new nonvacuous original-source queries are UNSAT over 72 distinct PCs/instruction instances and 46 linked-edge obligations. Four unchanged thread-binding/setter/block-offset/bootstrap-address contracts are re-solved. New obligations cover input/width gates, delimiter masks, exact-name length, callback construction, converter ABI, numeric and flag width stores, three-byte preservation, opposite success polarity, modular accumulation, signed scaling and presence-only status. They are local source obligations, not a universal proof of the scanner. [BO6]

Thirteen components pass 9194 independent semantic checks. The independent implementation reads actual entry memory, derives scanner/converter results and output preservation, and applies source/model journals in event order. Every selected option API entry is paired with an original return using both PC and restored SP. Dedicated parser returns are recorded separately from original tree-call returns. [BO6]

| Original API family | Calls / matched returns |
| --- | ---: |
| Option scanner | 82 |
| strlen | 43 |
| Numeric decoder | 34 |
| Delimiter callback | 129 |
| Flag writer | 5 |
| Option API total | 293 |
| Original tree APIs | 2526 |
| Dedicated option scanner calls | 29, included in scanner total |

Fresh replay imports no executor. It checks 162451 source visits / 1760 unique PCs, 30759 reads, 13880 writes, 42 declared non-environmental helper returns, 2344 logical effects, all 46 epochs and 4468736 final mapped bytes. Initial SIMD Q0-Q31 are explicitly zeroed; all final SIMD registers are captured and compared, totaling 416 vector-register checks. Final SP and NZCV are also compared. Original NEON `_strlen` and selected `_strncmp` paths execute. [BO6]

Independent formulas separately compare 9416704 dedicated-API nonstack bytes, 3117056 topology bytes, 2781184 post-helper checkpoint bytes and 2781184 thread/caller bytes, cumulatively across cases/checkpoints. These counts overlap and are not disjoint physical memory. Private stack bytes are checked by fresh replay. Independent checks also cover thirteen initializer publications, eight boot-record returns, eight post-helper returns and eight complete 1472 B copies. [BO5,BO6]

Four NOP controls are rejected: u32 numeric output store `0xfffffe000c5e4b38`, digit accumulation `0xfffffe000c5e4e5c`, flag store `0xfffffe000c5e4cf8` and exact-name length branch `0xfffffe000c5e498c`. They are excluded from positive totals. The largest positive case uses 68807 visits under the 100000-visit limit. Scanner coverage is 204/257 PCs; numeric decoder 139/140; flag writer 30/30; delimiter callback 14/14; strlen 25/28 including no UDF execution. Complete path coverage and native behavior are not inferred. [BO6]

Extraction costs O(K+F+I+D+N) time/space in collection bytes K, fixups F, source I, data D and symbols N. Proof construction costs O(I+Q) in source/formula DAG Q; SMT search is separate with a 30 s/query limit and no polynomial claim. Execution/replay costs O(V+J+M+T) time/space in source visits V, journals J, mapped bytes M and fixture bytes T; sorted phase materialization adds O(J log J) time. Independent per-call grammar checks additionally cost the option/tree/string bytes examined across calls. Widths are exact little-endian u8/u16/u24/u32/u64 with stated modular arithmetic; no statistical uncertainty estimate applies. Archives use `zstd --ultra -22 -q -T1`, decoded roundtrip verification and decoded/nested path hygiene. [BO6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BO-A1: Pinned images, compiler starts, fixups, literals and exact aliases identify this build | BO1-BO7 | Rehash all 24 intervals and twenty prior matches, 29 strings, 19 data blocks and three fixups; preserve opaque/UDF words; no cross-build equivalence |
| BO-A2: Private ASCII/NUL option buffers and serialized trees instantiate the stated input domain | BO2-BO7 | Separate grammar and tree decoder, 29 dedicated calls, radix/sign/suffix cases, matching/misses/duplicates, full output guards and original reader execution; authentic boot contents/capacities unknown |
| BO-A3: Width/mode/name cases establish only the selected scanner semantics | BO2-BO7 | Widths 0/1/2/3/4/8/16/32 are admitted by the harness; exercised numeric/flag widths and 16 B text cases are enumerated above; special underscore names, unusual signed widths and untested string modes excluded |
| BO-A4: PACIA/BLRAA/PAC/system envelopes support only logical source composition | BO4-BO7 | Original target/discriminator checked at all 129 callback calls, independent source journals, 416 final vector checks and SP/NZCV comparisons; native authentication/hardware/fault semantics unknown |
| BO-A5: Explicit complete-RAM call frames and lower helper contracts do not establish startup continuity | BO5-BO7 | All 46 epochs, thirteen initializer returns, eight original enumeration/helper returns and copies; actual caller chain, later main callbacks, CPU-data+0xa38 and later thread+0x1b8 producers remain open |
| BO-A6: Independent grammar/call/record/byte checks, local lifting and replay support this increment | BO6,BO7 | 26 nonvacuous proofs, four prior rechecks, 9194 checks and four altered-source rejections; finite PC/path coverage and shared decoder/emulator limitations retained |
| BO-A7: Boot-option contracts do not establish daemon control or a Mach transfer | BO7 | Correlate actual daemon/user-client/provider payloads, rights, statuses and kernel epochs; no such new transaction/right observed |

No new incoming/outgoing Mach port, right or message-emission location is established. The [Mach inventory](mach_ports_report.md) remains the endpoint reference. Option strings are boot-environment inputs in this conditional composition; direct fairplayd influence over them remains unknown. Selector0e is a lower wrapper selector, not a Mach port name. [BO7]

| Impact | Next discriminating work | Evidence it could establish |
| --- | --- | --- |
| High | Trace actual bootargs/tree initializer callers and copied-header handoff | Native provenance, lifetime and extents of command-line/tree inputs; replacement of the first explicit call cut |
| High | Execute remaining main callbacks and original cache/context helpers | Intervening mutation/order and replacement of the later CPU-caller cut |
| High | Recover CPU-data+0xa38 and later thread+0x1b8 writers | Lifetime of TPIDR_EL0 low48 payload and later lower-block selection |
| High | Resolve selector0e pre/post helpers and receiver alongside other lower selectors | Cross-facility ownership, argument propagation and returned state |
| High | Pair real daemon/user-client/provider traffic with kernel/lower traffic | Matched payload/right/status/epoch evidence beyond boot prerequisites |
| Medium | Correlate other parser callers with their actual width/mode domains | Establish which additional scanner branches form reachable architectural interfaces |

**QG1** Pass: factual technical analysis. **QG2** Pass: BO-A1-BO-A7 register dependencies and falsification probes. **QG3** Pass for this increment: original parser/helper roles, buffer/register ABI, output/status/control flow, topology/thread composition and Mach boundaries covered; full goal remains active. **QG4** Pass: widths, byte extents, modular arithmetic, complexity and reproducible artifacts stated. **QG5** Pass: scanner versus converter success polarity, presence versus stores, three-byte preservation, finite coverage, exact names versus roles and explicit epochs/authentication envelopes distinguished. **QG6** Pass: pinned primary bytes/metadata, rebuilt source obligations, independent grammar/call/tree/record/byte checks, register-aware replay and controls; native limits explicit. **QG7** Pass: bounded impact-ranked continuation above. `full_goal_complete=false`. [BO1-BO7]

## Boot-environment publication follow-up

The previously open bootargs-global producer is now recovered: main passes its original 1152 B copy to 0xfffffe000c5e6620, and PC 0xfffffe000c5e6690 writes global 0xfffffe0007f8b6e8. Local later main parser-call ABIs consume that pointer plus 0x6c. This new prefix and the existing parser/topology cases retain their separate call-frame boundaries. See the [boot-environment publication report](kernel_boot_environment_publication_report.md) for source PCs, assumptions, scoped validation and remaining boundaries.

## Original platform-return follow-up

A new original main/platform experiment reaches this report enumeration call site without the earlier generic-initializer-to-main epoch. It executes real clock/cache/identity/diagnostic helpers, the timer calculation and four preceding parser calls. The state histories are not yet claimed joined through enumeration/thread setup. See the [platform environment execution report](kernel_platform_environment_execution_report.md) for source intervals, contracts, assumptions and remaining boundaries.


## Initialized-data and continuous thread-handoff follow-up

The [bootstrap state-composition report](kernel_bootstrap_state_composition_report.md) preserves the prior zero-page fixture and establishes its pre-store null-destination boundary. A separately declared original initialized topology page permits continuous main/platform/timer/enumeration/post-helper/thread-copy/setter execution, without a call-frame epoch or later state repair. The paired input/register comparison, original pointer fixups, post-helper default 2, selected CPU ordinal, logical register custody and remaining selector0e/native/Mach boundaries are explicit.
