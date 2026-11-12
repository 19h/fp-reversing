# Daemon remainder preparation and nested record helper

Subsequent processing evidence: the [nested-helper report](daemon_nested_helper_processing_report.md) follows the loaded target to block processing, record+0x1c status production, return and caller continuation. It proves the selected first-loop count projection and independently checks 16 declared-state/operand cases. Native admission, cryptographic identification and transport pairing remain unresolved.

An explicitly declared interior object word now composes the remainder-selected branch with the previously conditional frame-word producer. With decoded word0, source writes root-frame F+0x4ec=12, reaches0x1003fd1d8, writes F+0x560=12 at0x100530748, and takes the equality continuation0x100537880. It then constructs a nested record and calls internal helper0x1004234c4 at0x10049d42c. Four relocated prefix/extended variants execute the helper's entry through its initial dispatch-target load. Four decoded-word1 controls still stop before arithmetic on the unspecified F+0x560 word.

The nested helper has its own address-key family, `u32((low32(record) XOR 0xb521e742)*0x74cae98d)`. Its caller and decoder agree for all u64 record addresses under the stated memory domain. In the composed variants, the record carries two workspace pointers, equal range words, tag0x2530 and a first decoded control word0x7a725e73 that normalizes to integer16. The helper loads target0x1000bba74 through original slot0x10104ca70; execution stops before the final modifier setup and branch. Its full algorithm and native caller admission remain unknown.

The original four partial ingress fixtures are unchanged. The new states declare a different object word at an interior boundary; they do not establish that an admitted request reaches this state. No native IPC/IOKit execution or daemon/kext pairing is added. The full investigation remains active.

Primary evidence: [producer](triage_evidence/recover_daemon_remainder_preparation.py), [source, proofs and journals](triage_evidence/daemon_remainder_preparation_checks.json.zst), [independent auditor](triage_evidence/audit_daemon_remainder_preparation.py), [A64 replays and ABI joins](triage_evidence/daemon_remainder_preparation_audit.json.zst), [publication verifier](triage_evidence/verify_daemon_remainder_preparation_publication.py). Parent evidence: [admission gate and object lineage](daemon_frame_admission_report.md), [conditional frame-word definition](daemon_frame_word_report.md), [source ingress](daemon_versioned_ingress_report.md), [Mach index](mach_ports_report.md). Original daemon SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

Preferred image base is0x100000000. F is the root's post-prologue SP, I=F+0x8d8 the nested record, G=F-0x2f0 the helper's post-prologue SP, and A the retained private32 B allocation. Machine fields are little-endian. B denotes bytes; u32/u64 arithmetic wraps at its stated width. Control-word units and public protocol meanings remain unknown.

| Assumption | Dependent results | Stress test / falsification probe |
|---|---|---|
| RP1 | Image, twenty receipts and twenty-one source dependencies identify this increment. | Rehash all pins, source regions, executed opcodes and used original fixups. |
| RP2 | The callback prefix and parent ingress prefix are restored rather than freshly executed. | Check original opcodes/read consistency during symbolic restoration; independently restore CPU/RAM and compare every initial register/flag. Retain exact restoration boundaries. |
| RP3 | At0x1004c75a0, A+0x10 is explicitly declared as raw0x8b3dc651 or0x8b3dc650, decoding to0 or1. Its prior source value is0x8b3dc64d. | Retain the old/new word and allocation identity; independently verify the prior value before overlay. A composed native producer is required for admission. |
| RP4 | Parent allocation and frame ownership persist through these interior variants. | Preserve allocator-model effects during restoration; check no new allocation/free and no access outside the retained allocation lifetime. |
| RP5 | Unspecified bytes remain copy-only; source-dependent arithmetic/control is rejected. | Use two physical backing realizations, preserve byte origins and stop all word1 variants before0x10063736c. A backing value is not a definition. |
| RP6 | PAC and return signing use logical transfers; resolved slots use original image fixups. | Independently check targets, modifiers, call return token, prologue effects and all four0x9298 collision slots. No hardware authentication is asserted. |
| RP7 | Symbolic records, frames and table cells are disjoint, without wrapping/aliasing. | Seven fresh source obligations are UNSAT; concrete variants use two placements. Arbitrary record addresses in key theorems do not imply valid pointees. |
| RP8 | Equal range words and tag0x2530 select the helper's initial index0x2570. | Replay complete helper entry; prove the range/control predicate and table-index projection; stop before executing the loaded target. |
| RP9 | Workspace pointers and control normalization identify source-local roles, without a public algorithm/type assignment. | Follow later consumers and return/result stores before naming an algorithm, length or transport field. |

```text
restored parent context at0x1004c75a0
  declare decoded object word [RP3]
       |
       +-- 1 --> reader route --> unspecified F+0x560
       |                          STOP before ADD0x10063736c
       |
       +-- 0 --> remainder writer0x10052249c: [F+0x4ec]=12
                 preparation0x10046a104 and original source continuations
                 0x1003fd1d8 -> 0x100530720: [F+0x560]=12
                 equality route0x100537880
                 record caller0x10049d308
                 0x10049d42c -> helper0x1004234c4
                       |
                       +-- key and field decode
                       +-- equal range / tag0x2530
                       +-- index0x2570 -> target0x1000bba74
                       `-- STOP0x10042379c before modifier/BRAA/target entry
```

For each parent epoch and variant, the producer restores the sealed callback epoch and the parent journal up to the first0x1004c75a0 entry. It retains the modeled malloc effects and original field writers, then declares only the new u32 object word. Prefix/extended classes remain2/5. All newly executed effects form a continuous source journal. Restoration, old allocator models and native startup are excluded from new execution totals [RP2-RP4].

The zero-word variants have one overlapping write to F+0x560:0x100530748 stores12. F+0x4ec and F+0x3c4 also hold12. The source comparison is equality, so the path takes0x100537880. The new journal contains the previously separate0x1003fd1d8 ->0x100530720 edge and the later nested helper call in the same root frame. This closes that conditional composition; it does not supply a missing writer to the original partial paths.

| I-relative offset | Width | Caller-produced representation | Helper-entry use |
|---|---|---|---|
| +0 | 8 B | Pointer F+0x610 | Not read by the inspected entry. |
| +8 | 8 B | Range word F+0x6c8 | Compared unsigned with +0x10. |
| +0x10 | 8 B | Same range word F+0x6c8 | Equality holds in all four composed variants. |
| +0x18 | 4 B | First control word XOR K(I) | XOR K(I) gives0x7a725e73; saved at G+0x1c. |
| +0x20 | 8 B | Pointer F+0x600 | Not read by the inspected entry. |
| +0x28 | 4 B | u32(K(I)+tag) | Subtract K(I) gives tag0x2530. |

The caller writes40 B across these fields, with a4 B hole at+0x1c. Its highest field access ends at+0x2c. It does not establish a fully initialized contiguous48 B object. The inspected helper reads only the range words and the two u32 controls, and saves I at G+0x20. Its pointer validity, eventual use of +0/+0x20 and result locations require further source work [RP7-RP9].

The caller's key projection at0x10049d378..0x10049d3b0 and the decoder at0x1004235bc..0x1004235ec both equal K(I) for every u64 I. The caller encodes tag as `u32(phase-0x2d1a)`; the composed phase is0x524a, giving0x2530. The helper normalizes its first decoded control as `u32(control+0x858da19d)` and stores its zero-extended value at G+0. For0x7a725e73 this is16. No byte-length or public operation interpretation is assigned.

Let T be the decoded tag, L/M the range words, and `p=(L>M) XOR lowbit(T XOR 0x49c5)`. The helper's dispatch index is `T OR (u32(((T-0xb80) XOR 0x19f0)*p))`. Equal L/M and T=0x2530 give p=1 and index0x2570. The source materializes the table through a256-input bank cancellation: roots0x101031da0/0x100e99900, XOR0x86, constant0x58, pool index0x91a, slot0x1010a6230 and original rebase0x1303ecd02. Adding the source's u64 bias0xffffffffd0c4d1ee yields table0x101039ef0.

The internal call uses original slot0x1010a00a0 and IA modifier0x9298. Caller X0=I and X1=0. The inspected helper prefix does not dereference incoming X1 before replacing it. Its fixed reservation is96 B of saved GPRs plus656 B locals, totaling752 B/0x2f0; helper FP is caller SP-16. It performs original state/table preparation, key/field decoding and dispatch-target materialization. These observations support the label internal record decoder and range-conditioned dispatcher; the complete routine's algorithm remains unknown.

| Original slot | Target sharing IA0x9298 | Established distinction |
|---|---|---|
| 0x10109ff20 | libSystem/_gettimeofday | Imported API; not called in this increment. |
| 0x1010a0048 | 0x100419638 | Distinct internal target. |
| 0x1010a00a0 | 0x1004234c4 | Actual source-selected helper here. |
| 0x1010a00c8 | 0x100425be0 | Distinct internal target. |

All four collision pointers are checked against original pointer words/import metadata. Modifier equality alone does not identify a function. The helper's later pending branch uses slot0x10104ca70/target0x1000bba74 and original IA0x202d; the journal stops before loading that final modifier. No entry into0x1000bba74 is claimed [RP6,RP8].

Validation covers eight cases across two epochs: four zero-word cases execute2685 visits each and four one-word cases116 visits each, totaling11204. There are464 read events,312 write events and6752 per-case source-pool entries; the pool sum includes pending decoded boundaries and is not an executed union. Four contiguous source regions retain356 instructions/1424 B. Seven fresh negated source obligations are UNSAT.

Sixteen independent A64 replays check22408 visits,21296 register effects,312 NZCV effects,6024 read B,3312 written B and624 write effects. No unspecified byte is written in these new journals; word1 cases retain the unknown load and stop before arithmetic. All boundary GPRs/SP, initial registers/flags, logical call/PAC edges and allocation-lifetime checks pass. Prefix restoration is validated separately and excluded from those visit totals. No new external API model is used.

There is no new Mach port, right/descriptor producer or message-emission location. No journal visits IOKit0x100478a04. Complete buffer identity, native admitted object state, endpoint/connection provenance and daemon/kext pairing remain unknown. No matching live-IDB readback or annotation is asserted.

| Bounded continuation | Impact | Falsifiable completion criterion |
|---|---|---|
| Follow helper target0x1000bba74. | High | Establish its later pointer accesses, operation/control use, writes, return status and connection to the surrounding root. |
| Establish a source producer for the declared object word. | High | Compose an admitted upstream path yielding the required state; an interior declaration is insufficient. |
| Recover the full helper algorithm and result contract. | High | Link entry decoding to complete data processing and caller result consumption, with independent source/CPU checks. |
| Establish remaining reader-route definitions. | High | Find a dominating writer/input contract for F+0x560 and other consumed fields on the original partial path. |
| Connect the prepared workspace to transport. | High | Match complete buffer/connection lifetimes and actual method/message events across compatible daemon/kext identities. |

Quality gates for this bounded increment:

- **QG1**: Factual technical analysis requires no normative premise.
- **QG2**: RP1-RP9 identify assumptions, dependent results and falsification probes.
- **QG3**: Composed preparation, frame definition, nested record/key ABI, decoder/dispatch, environmental context and IPC limits are covered; the larger goal remains active.
- **QG4**: Numeric controls, byte extents, frame geometry, restored prefixes, source/replay visits and effect counts retain distinct units and scopes.
- **QG5**: Declared interior variants, original partial paths, key families, pointer/value roles and same-modifier targets are not conflated.
- **QG6**: Original bytes/fixups/imports, hashes, source queries, bank cancellation and independent A64 CPU/RAM effects support the stated claims; native admission/PAC and live-IDB evidence remain unknown.
- **QG7**: The continuation table bounds and ranks helper processing, admitted state production, result ABI, remaining definitions and native transport.
