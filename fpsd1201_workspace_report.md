# CoreFP1201 context producer, pre-helper gate and shared fdpc prefix

The original parent constructs an SP-relative context C, writes prefix `00 66 64 70 63 00 00 00 01`, saves C and two offsets, and advances its selected workspace cursor by 1872 B. A later original gate reloads C and the separate P+0x900 destination before staging the arithmetic/export record. These are independently replayed fragments separated by an explicit unexecuted parent gap. Two receipt-pinned daemon representatives have the same nine-byte prefix. Full field meanings, native context continuity and matched daemon/kext exchange remain unknown.

## Primary evidence and assumption register

The [producer](triage_evidence/recover_fpsd1201_workspace.py), [journals](triage_evidence/fpsd1201_workspace_checks.json), [independent auditor](triage_evidence/audit_fpsd1201_workspace.py), [replay receipt](triage_evidence/fpsd1201_workspace_audit.json) and [publication verifier](triage_evidence/verify_fpsd1201_workspace_publication.py) retain the bounded evidence. Logical JSON links resolve to compressed `.json.zst` artifacts. The existing complete parent capture is sufficient; no new IDA access or IDB edit is required.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| WS1 | The pinned original CoreFP bytes identify these fragments and pointer rows. All source-address claims depend on this image. | Independently parse the universal/slice image; compare the complete 85464 B parent and all 79512 raw fixup words. |
| WS2 | Original authenticated IA rows are represented through explicit private PAC models. Selected edges depend on them. | Check every reaching load, target/diversity, complete pre-branch CPU frame and raw pointer word. Native PAC acceptance remains unknown. |
| WS3 | Owner P, cursor backing and selected operation/control states are declared private inputs. Numeric SP derivation does not prove native allocation/capacity. | Exercise five cursors, two constructor states and all recorded accesses; retain a satisfiable u64 wrap countermodel. Trace actual incoming owner/cursor production separately. |
| WS4 | Constructor and pre-helper gate are distinct fragments with an unexecuted gap. Their conditional cell join assumes preservation through that gap. | Restore exact constructor CPU/RAM, log every gap control, and preserve the prefix/pointer cells. Recover actual intervening path, SP epochs, aliases and callees before claiming native continuity. |
| WS5 | The pre-helper gate uses declared W23=0xc1f7, a declared saved status and separately backed cursor-seed pointer. Gate conclusions depend on those controls. | Check exact equality/non-equality cases, independently prove the full u32 status partition and verify complete source-staged records. Actual saved-status/seed origin remains unknown. |
| WS6 | The daemon witnesses are extracted from sealed, independently replayed predecessor journals; that prefix is not freshly executed here. Cross-image equality depends on that receipt. | Pin both checks/audit hashes and generator/auditor identities, decode both complete witnesses independently, and check all encoded-limb knownness masks. |
| WS7 | A common literal prefix and compatible local arithmetic do not identify a native transaction, right or receiving endpoint. | Establish remaining byte producers, exact wire epochs, endpoint/right history and daemon/kext consumers independently. |

Universal CoreFP SHA-256 is `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`; arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Parent `[0x8e81c8,0x8fcfa0)` is 85464 B, SHA-256 `4e0ebb4383ce0f3d074358e851dd1bdfff67e77d675e0cfa9e73b4a03ff9a94e`. The [earlier caller profiles](triage_evidence/corefp_client_flow_profiles.json) use explicit decoded operation precondition `0xc1f7`; that is private source evidence, not native admission.

## Source-produced context and pointer geometry [WS1-WS3]

Before the selected constructor, source `0x8ea164..0x8ea178` loads the saved operation/control word at SP+0x4ac, derives W12=word-0x8094, and loads X16 from SP+0x5c8. Let S denote this fragment's SP, t=X16 its incoming cursor and P its incoming X20. The selected `0xc1f7` state gives W12=`0x4163`, then W14=`0xc516`. All address/cursor arithmetic below is modulo 2^64; W12/W14 arithmetic is modulo 2^32.

```text
C = S + 0x9a0 + t
saved next pointer  = C + 0x80
saved later pointer = C + 0x6f0
new cursor = t - 0xbdc6 + zero_extend(W14)
           = t + 0x750 = t + 1872 B   [selected state only]
```

| Original site | Source-produced value | Destination / role |
| --- | --- | --- |
| `0x8ea1b4/0x8ea1b8` | P+0x880 | SP+0x1b8, candidate request1201/export pointer |
| `0x8ea1bc/0x8ea1c0` | P+0x900 | SP+0x1a8, later XOR destination |
| `0x8ea1dc/0x8ea1e0` | S+0x9a0+t | X13=C; no allocator or SP assignment executes |
| `0x8ea1e4/0x8ea1e8` | C+128 B | SP+0x1d0 |
| `0x8ea1ec..0x8ea1f8` | Little-endian u64 `0x0000006370646600` | C[0..7] = `00 66 64 70 63 00 00 00` |
| `0x8ea1fc/0x8ea200` | Byte 1 | C[8] |
| `0x8ea208` | C | SP+0x1f0 |
| `0x8ea20c/0x8ea210` | C+1776 B | SP+0x840 |
| `0x8ea220` | t+1872 B in selected state | SP+0x5c8 |
| `0x8ea228/0x8ea234` | C+9 | SP+0x7b8 / SP+0x838 |

This fragment defines exactly nine bytes of C's first 128-byte range. The remaining 119 bytes retain diagnostic `0xa5` backing in every new case; they are not established native input. Saving C+128 and C+1776 does not initialize either referent or prove a 1776/1872-byte allocation. The 96 B difference between 1872 and 1776 is arithmetic geometry only; no ownership or semantic role is assigned to it.

Five cursor controls, 0, 16, 32, 256 and 4096, execute the selected constructor. Five additional contrast cases use W12 derived from word `0xfd60`, selecting a different original row and cursor increment 17081 B. Their native admission is unknown. They prevent generalizing 1872 B beyond the selected state.

| Declared saved word | W12 | W14 | Cursor increment | Original row / target at `0x8ea24c` |
| --- | --- | --- | --- | --- |
| `0xc1f7` | `0x4163` | `0xc516` | 1872 B | `0x1ca2458 -> 0x8ea48c`, IA diversity `0x372d` |
| `0xfd60`, contrast only | `0x7ccc` | `0x1007f` | 17081 B | `0x1cbffa0 -> 0x8ed4c0`, IA diversity `0x372d` |

The cursor identity is modular. An explicit solver countermodel shows that t+1872 can wrap below t when no range bound is supplied. The finite fixtures use valid declared backing; no universal no-wrap, alignment or capacity guarantee follows.

## Pre-helper gate and source-staged record [WS1,WS2,WS4,WS5]

The second fragment restores exact constructor CPU/RAM, then explicitly sets W23=`0xc1f7`, writes the saved status at SP+0x864, and backs the separate cursor-seed pointer/data at SP+0x398. It starts at `0x8f33dc`. No instruction in the intervening parent gap is executed. The first original branch uses index `0xc1f7-0xbdb4=0x443`, row `0x1c83b58`, IA diversity `0xec73`, to reach `0x8f33f4`.

Source `0x8f33f8` derives W22=`0xc1f7 XOR 0xba27 = 0x7bd0`; W21 becomes `0x5ba0`. The saved word read at `0x8f33e4` is compared at `0x8f3410` against `0x5ba0 XOR 0xba1da27b = 0xba1df9db`. A universal u32 proof gives:

| Saved status | Branch index | Original row / target at `0x8f3444` |
| --- | --- | --- |
| Exactly `0xba1df9db` | `0x85e3` | `0x1cc4858 -> 0x8f3448`, IA diversity `0x4cd4` |
| Every other u32 value | `0x7bd0` | `0x1cbf7c0 -> 0x8f3664`, IA diversity `0x4cd4`; stop |

Before that branch, `0x8f3430` reloads X25 from SP+0x1a8 and `0x8f343c` reloads X12 from SP+0x1f0. In the declared gap-preserving composition these are the source-produced P+0x900 and C. The five matching-status cases execute the original constructor through `0x8f34f4` and stop at `0x8f34f8`, before helper-call preparation. They derive W20=`0x55e1`, W22=`0x7bd0`, W23=`0x3de80` and stage the [earlier recovered record](fpsd1201_record_report.md) with C+0x290, C+0x3a0, C, candidate P+0x880 and the count pointer SP+0x5c4. The latter cell is set to 128; the separate seed is copied to SP+0x978.

All 80 record bytes, including untouched diagnostic padding/status, are checked independently. The C+0x290/C+0x3a0 descriptors are not initialized by these fragments and no helper or arithmetic is executed. Twenty nonmatching cases stop at the alternate continuation without staging the record. They use saved status 0, `0x45e2a205`, `0xba1df9da` and `0xffffffff` for each cursor.

## Distinct status cells and slot reuse [WS1,WS4,WS5]

| Cell | Original role / access | Current boundary |
| --- | --- | --- |
| SP+0x864 | Saved pre-helper word, loaded `0x8f33e4`, compared `0x8f3410`; direct named store `0x8f2860` writes W9 | Actual reaching producer/value and intervening path remain unknown. |
| FP-0x88 | Root helper marker, compared `0x8f3594/0x8f3598` after the helper | The [handoff report](fpsd1201_handoff_report.md) covers this later, separate gate. |
| Nested export record+0x18 | Exporter-local status, emitted `0x32f930` | The [export report](fpsd1201_export_report.md) establishes its local nonpropagation under two short-length controls. |

The complete-parent census has two direct 64-bit stores beginning at SP+0x1f0. The first, `0x8ea208`, stores C. The second, `0x8f4cf0`, stores X9 immediately after `AND X9,X8,#0xff`; it is a value in 0..255 used as a byte-table selector at `0x8f4cf4..0x8f4d10`. It is not a second recovered context-pointer producer. This corrects the earlier caller report's field-role wording. If it executes in the same epoch, it still overwrites the cell; its selector role does not prove that C survives to the later reload. Aliased stores, callees and actual ordering remain unresolved.

## Shared client/daemon prefix [WS6,WS7]

The [daemon certificate report](fpsd1200_certificate_report.md) retains two later nonnull profiles with a source-built 128-byte representative under the supplied CoreFP leaf modulus. This increment independently extracts each complete representative from the original encoded limbs at Montgomery call 73, entry `0x10094593c`, checkpoint visit 9196383. The previous arithmetic receipt validates the source-knownness and full exponent sequence; those daemon instructions are not rerun here.

Daemon checks SHA-256 is `33c9de98eda8d6ef4f3ff2fed8190f6cd3aa3567ca43e35d82d0ab63fb7d866d`; its audit SHA-256 is `87faaa02a47c02f6312291945eba4838c5f35101fb96e1fb2e85fdaf56017b7d`. The selected daemon image SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Both decoded 128-byte witnesses, complete call/checkpoint records and decoded-payload hashes are retained.

```text
CoreFP constructor C[0:9]     00 66 64 70 63 00 00 00 01
daemon representative[0:9]    00 66 64 70 63 00 00 00 01
                                 ASCII fdpc

client remaining 119 bytes:   not defined by selected fragments
daemon remaining 119 bytes:   sealed original journal witness
native transaction pairing:  unknown
```

The equality is exactly nine source-defined bytes, not a full representative equality, wire transcript, standard-padding identification or protocol-version interpretation. The client context later supplies C-derived descriptor/input roles; the daemon's separately recovered exponentiation exports reply[68,196). Connecting those complete byte producers and consumers remains necessary before assigning a shared message meaning.

## Validation and bounded continuation

Fresh replay passes 35 profiles: ten constructors, 25 pre-helper gates and five complete record stagings. It checks 1345 original visits, 170 reads, 225 writes, 60 PAC models, 155 complete CPU frames, 90 prefix-store bytes and 400 record bytes. Initial/final RAM each total 5304320 B; restored constructor RAM totals 3788800 B. Six retained plus six independent UNSAT obligations cover cursor/offset geometry, saved-status partition, candidate/XOR disjointness and selector bounds; one SAT countermodel preserves the wrap boundary. Source checks compare 85464 B, 79512 raw words and 20 exact instructions. Two sealed daemon witnesses independently yield 256 representative bytes and the same nine-byte prefix. No native operation or intervening parent gap executes.

| Impact | Bounded continuation | Falsification / remaining boundary |
| --- | --- | --- |
| High | Recover all remaining C[9:128] byte producers and C+0x290/C+0x3a0 descriptors. | Nine literal bytes do not establish a complete admitted arithmetic input, key role or message meaning. |
| High | Resolve actual constructor -> pre-helper -> post-helper path and frame epochs. | Discharge each explicit gap control; prove whether SP+0x1f0 is preserved or repurposed on that path. |
| High | Compare complete client/daemon representatives and real wire/endpoint history. | Shared prefix alone does not pair calls, rights, native transactions or kext consumption. |
| Medium | Recover the saved pre-helper status and cursor-seed producers. | Direct stores and equality predicates do not establish their native values or prior callee success. |
| Medium | Bound native cursor capacity, alignment and no-wrap. | Selected increment and saved offsets are exact; the explicit wrap countermodel remains feasible without additional premises. |
| Low | Classify the alternate selected-state continuation. | The 0xfd60 controls stop at 0x8ed4c0 and do not establish native admission or its full function. |

Quality gates: **QG1** factual technical analysis requires no normative content. **QG2** WS1-WS7 list dependencies and falsification probes. **QG3** the increment covers context/pointer producers, prefix stores, selected cursor geometry, pre-helper control flow, record staging, slot reuse and cross-image comparison. **QG4** B denotes bytes; u32/u64 arithmetic, modular wrap, offset extents and producer/auditor complexity are explicit. **QG5** constructor/gap/native state, three status cells, pointer/index reuse, selected/contrast states and nine/full128-byte evidence remain separate. **QG6** original file bytes, raw pointer words, existing IDA capture, independent replay, complete state checks and pinned daemon receipts support claims. **QG7** impact-ranked continuation is bounded. The full investigation remains active.
