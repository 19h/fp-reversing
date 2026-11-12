# Daemon nested-helper block processing and result contract

The selected path through internal helper `0x1004234c4` now runs to its return and the caller's status-dependent continuation. It processes a 16 B block at root-frame `F+0x6c8`, reads two additional 16 B operands through record pointers `+0` and `+0x20`, writes status `0x8b3dc651` at record `+0x1c`, and returns to `0x10049d430`. The caller reads that field and selects `0x100383700`. The cryptographic algorithm and native admission remain unknown.

The formerly ambiguous normalized control is a byte count for the first processing loop on this selected path. An all-u32 source proof connects its entry normalization to the loop counter. The retained value is 16. This does not establish other tag paths, arbitrary pointer validity or a public transport length.

Primary evidence: [generator](triage_evidence/recover_daemon_nested_helper_processing.py), [source, proofs and journals](triage_evidence/daemon_nested_helper_processing_checks.json.zst), [independent auditor](triage_evidence/audit_daemon_nested_helper_processing.py), [replays and data-flow joins](triage_evidence/daemon_nested_helper_processing_audit.json.zst), [publication verifier](triage_evidence/verify_daemon_nested_helper_processing_publication.py). The [preparation report](daemon_remainder_preparation_report.md) establishes the nested record's creation and entry decoding. Original daemon SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

F is the root's post-prologue SP; G=F-0x2f0 is the helper's post-prologue SP; I=F+0x8d8 is the record. B denotes bytes. Machine fields are little-endian; u32/u64 arithmetic wraps at its stated width. Preferred image base is `0x100000000`.

| Assumption | Dependent results | Stress test / falsification probe |
|---|---|---|
| NP1 | Original bytes, 22 pinned receipts and 23 dependencies identify this increment. | Rehash inputs, opcodes, source regions and original fixup words. |
| NP2 | Callback, ingress and preparation prefixes are restored, without new execution credit. | Check source read consistency during restoration; independently restore RAM/registers/flags and compare the complete initial state. |
| NP3 | The parent's declared decoded object word remains zero; three extra profiles explicitly change one operand bit at the interior boundary. | Retain original/new operand bytes and verify each before overlay. No admitted upstream producer is inferred. |
| NP4 | Private owners remain live; unassigned bytes remain copy-only. | Use two physical backing patterns, allocation-lifetime checks and strict rejection of unknown-dependent computation. |
| NP5 | PAC uses logical source transfers, without hardware authentication. | Check original target slots, modifiers, return token and fixed-frame restoration independently. |
| NP6 | Symbolic record/frame cells are disjoint and accesses do not wrap. | Seven fresh UNSAT obligations; two concrete frame placements. Address algebra does not prove pointee validity. |
| NP7 | Chosen tag `0x2530` and count 16 identify the inspected processing path. | Verify every source transfer and stop before the selected caller continuation. Other tags/counts require new paths. |
| NP8 | Operand relations are finite observations; the complete cryptographic algorithm is unknown. | Recover source-equivalent transformations or independently identify the primitive before assigning a cryptographic name. |

```text
restored helper entry dispatch [NP2,NP3]
  -> target 0x1000bba74
  -> first byte loop: block -> preprocessed block
  -> record +0: 16 B -> helper-local operand
  -> record +0x20: 16 B -> table-driven processing
  -> core writes 16 block bytes
  -> final byte loop rewrites those 16 bytes
  -> record +0x1c = 0x8b3dc651
  -> RETAB 0x10015fa38 -> caller 0x10049d430
  -> caller reads +0x1c -> index 0x554a
  -> STOP at 0x100383700 before its first instruction
```

| Record field / region | Established role on this path | Access / emission locations |
|---|---|---|
| I+0, 8 B | Pointer to read-only 16 B operand at F+0x610. | Pointer read `0x10015d3cc`; byte reads `0x10015d3dc`. |
| I+8 / I+0x10, 8 B each | Parent entry supplies equal range words pointing to F+0x6c8. | Entry decoding belongs to the preceding increment. |
| I+0x18, 4 B | XOR-decoded control; `N=u32(control+0x858da19d)` becomes first-loop byte count. | Normalization `0x100423610`; projection `0x1000896e4`. |
| I+0x1c, 4 B | Out-of-band result field, previously unwritten by the caller. | Write `0x10015fa00`; caller read `0x10049d430`. |
| I+0x20, 8 B | Pointer to read-only 16 B operand at F+0x600. | Pointer read `0x10002b9ac`; 16 permuted byte reads in the processing journal. |
| I+0x28, 4 B | Decoded tag `0x2530`. | Entry decoder in the preceding increment. |
| F+0x6c8 .. +0x6d7 | In-place 16 B block, rewritten in three stages. | First writes `0x1000bc2b4`; 16 distinct core stores; final writes `0x10002c0d0`. |
| G+0x270 .. +0x27f | Decoded local copy of the pointer-0 operand. | Writes `0x10015d40c`; 16 permuted reads in the processing journal. |

The first and final byte loops traverse addresses in descending order, from offset 15 to 0 in all cases. The middle stage writes every block byte once through 16 distinct store PCs retained in each ABI join. Both workspace inputs remain read-only. Outside the helper frame, new writes comprise 48 one-byte block writes and one 4 B result write. The result fills the caller's 4 B hole, so the accessed record prefix through `I+0x2c` is now defined; no initialized 48 B structure is inferred.

For the count proof, entry arithmetic produces `N - (0x4dabca80 AND (N<<1)) + 0x0098256826d5e540`. The selected target preserves its low 32 bits, and `0x1000896e4` XORs the zero-extended value with `0x26d5e540`. The result is `ZeroExt32(N)` for all u32 N. The first loop decrements this counter before each one-byte access and selects its exit at zero. This projection is conditional on entering that selected path [NP6,NP7].

| Result / continuation condition | Status or index | Original slot / target | Evidence boundary |
|---|---|---|---|
| Internal u32 guard equals `0x0c67c7c7`. | Store `0x8b3dc651` at I+0x1c. | Result writer `0x10015fa00`. | Executed in every case; selection proved for all guard words. |
| Internal guard differs. | Store `0x74c29d89` at I+0x1c. | Same writer. | Source-proved alternative; not executed here. |
| Caller phase `0x524a`, before status decision. | Index `0x524a`. | `0x101063140` -> `0x10062369c`, IA `0x4df7`. | Executed. |
| Caller reads status `0x8b3dc651`, phase `0x553e`. | Index `0x554a`. | `0x101064940` -> `0x100383700`, IA `0x1d9f`. | Transfer executed; target's first instruction not executed. |
| Any other caller status, same phase. | Index `0x553e`. | `0x1010648e0` -> `0x1003c3ee0`. | Source-proved selector and original fixup; target not executed here. |

The helper's epilogue checks the restored stack-guard value, restores its 752 B fixed reservation and saved registers, then executes logical `RETAB` at `0x10015fa38`. Eleven callee-saved GPRs X19-X29, SP and the return token match entry. X0 happens to contain `0xffffffffc886deca` in these cases; the caller's inspected result decision uses I+0x1c. A general X0 return type is unknown.

Four operand profiles are evaluated for each of two source variants and two frame placements: baseline, block byte 0 XOR 1, pointer-0 byte 0 XOR 1, and pointer-0x20 byte 0 XOR 1. These additional interior declarations preserve all other input bytes. They do not establish a native producer [NP3].

| Changed operand | First-pass block distance | Local pointer-0 distance |
|---|---|---|
| Block bit 0 | 1 bit | 0 bits |
| Pointer-0 bit 0 | 0 bits | 1 bit |
| Pointer-0x20 bit 0 | 0 bits | 0 bits |

| Epoch / source variant | Block-bit core/output distance | Pointer-0-bit core/output distance | Pointer-0x20-bit core/output distance |
|---|---|---|---|
| 0 / prefix | 61 / 61 bits | 61 / 61 bits | 72 / 72 bits |
| 0 / extended | 59 / 59 bits | 59 / 59 bits | 63 / 63 bits |
| 1 / prefix | 61 / 61 bits | 61 / 61 bits | 72 / 72 bits |
| 1 / extended | 63 / 63 bits | 63 / 63 bits | 61 / 61 bits |

The block-bit and pointer-0-bit profiles produce identical final blocks within each of the four contexts. This is a finite input relation, not a proof of XOR composition or an algorithm assignment. The measured distances describe these vectors only. Epoch-0/prefix baseline input block is `dce69bdfb5e379a899a30bd7696a668f`; final block is `5817645ddc55fe54031c44a84e9b4d0f`. Other contexts have distinct encoded workspace values and sometimes distinct outputs; equivalence across contexts is not assumed. Complete intermediate vectors and operand inputs remain in the joins.

Validation retains 11 source regions, 203 instructions / 812 B, and seven fresh UNSAT obligations. Sixteen source cases execute 112,000 instruction visits, 20,384 read events and 2,880 write events. The 58,496 per-case source-pool entries include pending boundaries and are not an executed union. Each case executes 7,000 visits and reaches the same declared caller cut.

Thirty-two independent A64 replays check 224,000 visits, 216,032 register effects, 2,016 NZCV effects, 161,248 read B, 21,760 written B and 5,760 write effects. No unspecified bytes are copied in the new journals. Original `EXTR` and unscaled byte-load effects execute in the independent CPU model; no native API model is added. Prefix restoration remains separate from these execution totals.

No new Mach port, right/descriptor producer or message emission is established. There are no external API calls or IOKit call-site visits in this continuation. Live matching-IDB readback, native caller admission, full transport-buffer identity and daemon/kext pairing remain unknown. The full investigation remains active.

| Bounded continuation | Impact | Falsifiable completion criterion |
|---|---|---|
| Identify the table-driven primitive and operand meanings. | High | Recover source-equivalent processing and independently verify the algorithm across its actual contract. |
| Establish the block/pointer-0 relation beyond finite vectors. | High | Prove its combining transformation from source; matched outputs alone are insufficient. |
| Follow caller target `0x100383700`. | High | Identify downstream object writes, lengths, result consumers and any actual transport call. |
| Establish native admission for the declared state. | High | Compose a source producer for the interior object word and recover its external input provenance. |
| Generalize tag/count and error paths. | Medium | Recover alternate dispatches, field accesses and status production without assuming this path's ABI applies. |

Quality gates for this increment:

- **QG1**: The report contains factual technical analysis without a normative premise.
- **QG2**: NP1-NP8 identify assumptions, dependent results and falsification probes.
- **QG3**: Processing path, count projection, record result, caller continuation, operand roles and IPC limits are covered; full goal completion is not asserted.
- **QG4**: Byte extents, bit distances, frame geometry, source/replay counts and restoration scopes are distinct and reproducible.
- **QG5**: Concrete variants, all-u32 proofs, cold alternatives, cryptographic identification and native exposure remain distinct.
- **QG6**: Original bytes/fixups, hashes, solver queries and independent A64 effects support the claims. No native PAC/API or matching live-IDB evidence is asserted.
- **QG7**: The continuation table bounds and ranks primitive recovery, operand combination, downstream consumption, admission and alternate paths.
