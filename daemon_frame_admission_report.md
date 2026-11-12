# Daemon frame admission: object-word lineage and unsigned gate

Subsequent composed-source evidence: the [remainder-preparation report](daemon_remainder_preparation_report.md) follows a declared decoded-word0 interior variant through this remainder writer, frame+0x560=12, the equality continuation and nested helper0x1004234c4. The helper record/key and initial target are checked by source proofs and independent A64 replay. The declared word is not established by an admitted upstream producer; original partial fixtures and native pairing remain unresolved.

The immediate predecessor of the unresolved reader tests `n < (w XOR 0x8b3dc651)` using unsigned u32 ordering. If true it enters `0x1004712f4`, then the reader; otherwise it enters `0x10052249c`, which defines frame+0x4ec as `u32(m - (w XOR 0x8b3dc651))`. This recovers a source admission predicate and one upstream producer for the prior frame-word investigation. It does not establish native entry admission or a complete producer-to-reader path.

In all four retained partial ingress cases, n=0, w=0x8b3dc64d and m=12. The decoded comparison value is28, so the reader route is selected. The word comes from a private allocated object's offset+0x10: it is initialized to0x8b3dc651, updated through frame+0x3ac to0x8b3dc64d, then loaded by the gate setup. Prefix and extended classes are respectively2 and5; both satisfy the setup's unsigned class>1 test. Neither partial case defines frame+0x4ec or+0x560, and all four remain stopped before arithmetic at0x10063736c. Native field meanings and daemon/kext pairing remain unknown. The full investigation is active.

Primary evidence: [producer](triage_evidence/recover_daemon_frame_admission.py), [source, queries and controls](triage_evidence/daemon_frame_admission_checks.json.zst), [independent auditor](triage_evidence/audit_daemon_frame_admission.py), [A64 audit](triage_evidence/daemon_frame_admission_audit.json.zst), [publication verifier](triage_evidence/verify_daemon_frame_admission_publication.py). Parent evidence: [conditional frame-word definition](daemon_frame_word_report.md), [source ingress](daemon_versioned_ingress_report.md), [root lifecycle](daemon_versioned_root_report.md), [Mach index](mach_ports_report.md). Original image SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.

Addresses use preferred base0x100000000. F is the post-prologue root SP; A is the private modeled32 B allocation. B denotes bytes. Values n,w,m,d are u32 numbers; their public schema, units and length/offset interpretation are unknown. U32 arithmetic wraps modulo2^32.

| Assumption | Dependent results | Stress test / falsification probe |
|---|---|---|
| FA1 | Original image, eighteen receipts and twenty source dependencies identify this analysis. | Rehash all pins, source regions and original fixups; reproduce source queries and control audits. |
| FA2 | Four actual lineages come from pinned private ingress journals, not a native capture. | Recheck191598 original opcodes, object/frame events and source branches. Parent independent CPU replays are retained, not repeated. |
| FA3 | Gate setup starts with the observed phase context, X10=0xadf4fdbf, X9=A and X23=original table root. Controls vary the class and object word. | Check two relocated owners, classes0,1,2,5,0xffffffff and all source effects. Earlier admission requires a composed upstream path. |
| FA4 | Symbolic cells and table cells are disjoint, without wrapping/aliasing. | Retain source queries and two concrete layouts. Aliasing records require another domain. |
| FA5 | PAC transfers use original resolved slots and logical branches. Unspecified RAM has two backing patterns. | Independently check instructions, targets, modifiers, registers, flags and memory events; stop before the unspecified word load. No hardware PAC or native object ownership is established. |
| FA6 | The word-update proof fixes initial object word0x8b3dc651, source count tag0x73113b31 and phase0x4a2. | Reproduce the original update/commit circuit and retained source reads. A universal decrement-by-four rule for other words/tags is not established. |
| FA7 | The unsigned gate formula is universal over u32 n,w at phase0x7de7. Setup always supplies n=0 in these controls. | Eleven fresh source obligations are UNSAT; standalone A64 controls cover equality, high bits and both sides of the overflow threshold. |
| FA8 | The other source copy to frame displacement+0x4ec is conditional evidence only. | Prove its original load/store behavior; establish frame ownership, phase and upstream value before composing it with this root. |

```text
retained object lineage [FA2,FA6]
  0x10031cb80: [A+0x10] = 0x8b3dc651
  0x100461a50: read that word
  0x100461c10: [F+0x3ac] = 0x8b3dc64d
  0x1004c5798: [A+0x10] = [F+0x3ac]
                         |
gate setup 0x1004c75a0 [FA3]
  n=0; m=(class>1 ? 12 : 0)
  [F+0x4ff]=(class>1); w=[A+0x10]
                         |
unsigned gate 0x10063ac7c [FA7]
  [F+0x55c]=n; [F+0x3c4]=m; d=w XOR 0x8b3dc651
                         |
           +-------------+-------------+
           |                           |
         n < d                       n >= d
           |                           |
  0x1004712f4                  0x10052249c
  [F+0x508]=[F+0x380]          [F+0x4ec]=u32(m-d)
           |                           |
  0x10063735c                  0x10046a104
  STOP before load F+0x560     STOP before preparation entry
```

| Source edge | Index | Original slot | Destination | IA modifier |
|---|---|---|---|---|
| 0x1004c7618, observed phase | 0x4a42 | 0x10105f100 | 0x10063ac7c | 0x3512 |
| 0x10063ad54, n<d | 0x7e31 | 0x101079078 | 0x1004712f4 | 0x8897 |
| 0x10063ad54, n>=d | 0x7de7 | 0x101078e28 | 0x10052249c | 0x8897 |
| 0x1005225b4, gate's phase | 0x7a21 | 0x101076ff8 | 0x10046a104 | 0xd50d |
| 0x100471358, reader route | 0x4a7f | 0x10105f2e8 | 0x10063735c | 0xa50a |

At setup,0x1004c75cc selects12 or0 from the unsigned class>1 predicate;0x1004c75d4 stores its Boolean at F+0x4ff. Instructions0x1004c75d8..0x1004c75e4 retain the A+0x10 address at F+0x430 and its u32 contents at F+0x558. These are local field contracts, without assigning a public capability, length or status name.

The comparison circuit first forms `(w XOR C)-C`, with C=0x8b3dc651. Adding0x5f6aff32 gives `u32(d+K)`, K=0xd42d38e1. It computes carry_n=`n>0x2bd2c71e` and carry_d=`u32(d+K)<K`. If their values differ, it selects carry_d; otherwise it compares `u32(n+K)<u32(d+K)`. This exactly implements unsigned n<d. The threshold is `~K` at32 bits. The independent controls exercise both sides and equality, rather than treating encoded comparisons as signed ordering.

The remainder writer stores u32(m-d) at0x100522594, reloads A from F+0x380 and selects the preparation edge through the original table. This source formula does not establish m>=d or exclude modular underflow in other entry domains. Full setup controls reach this writer only for d=0, because their n=0; they therefore produce remainder m. If that value reaches the previous conditional writer without an intervening update to it or the limit, its comparison is equality and selects0x100537880. This last statement is a source-contract composition premise, not a newly executed edge from0x10046a104 to the previous writer.

Instructions0x100524030..0x10052403c provide another local copy: u64[A] goes to F+0x3a0 and u32[F+0x348] goes to F+0x4ec. A fresh query proves those effects. Ownership of that frame and its connection to the current root remain unknown [FA8]. It is not substituted for the source writer selected by this gate.

The actual word lineage has exactly two overlapping writes to A+0x10 before the reader boundary: initialization0x10031cb80 and commit0x1004c5798. The latter copies the value previously stored at F+0x3ac by0x100461c10. The gate setup reads that committed value. For the retained initial word/tag/phase, fresh source queries prove raw0x8b3dc64d and decoded28. The raw numeric change is minus4 in this domain; other initial words/tags are not covered by that reduction [FA6].

Validation includes68 source-local controls/6560 source visits:40 full setup controls and28 isolated comparison controls. Full controls use two epochs, five classes and decoded words0,1,28,0xffffffff. Isolated controls additionally vary n across equality, adjacent values, high-bit values and the threshold0x2bd2c71e. Forty controls select the reader branch, including ten isolated controls that stop at its predecessor's entry. The others select the remainder branch. None reads or writes F+0x560.

The independent A64 engine replays all68 controls with backing bytes0 and0xa5:136 replays,13120 visits,419840 register values,13120 NZCV values,3648 read B,2768 written B and296 logical PAC transfers. Eight retained source regions contain319 instructions/1276 B; source-region counts are not an executed union. Word-update/commit provenance uses fresh source queries plus retained parent CPU evidence; those regions are not newly CPU-replayed by these gate controls. The four actual partial paths contribute191598 opcode rechecks and separate lineage audits. Eleven fresh negated source obligations are UNSAT. Producer/auditor complexity is O(parent visits+patterns*control effects) time/space, with30 s per solver query.

There is no new incoming/outgoing Mach port, right/descriptor producer or message-emission location. Controls contain no call instruction or external API model, and do not execute IOKit0x100478a04 or a kext routine. No matching live-IDB observation, native caller admission, full buffer identity or daemon/kext pairing is asserted.

| Bounded continuation | Impact | Falsifiable completion criterion |
|---|---|---|
| Establish native input/object-word meaning. | High | Compose native admission, allocation initialization and the word/tag producers; private initial values alone are insufficient. |
| Follow the remainder-selected preparation. | High | Compose0x10046a104 to subsequent field updates and any real entry to0x1003fd1d8/0x100530720, retaining phase and frame identity. |
| Establish the missing definition on the reader route. | High | Find a dominating write or justified input/lifetime contract for F+0x560 and the remaining reader inputs. |
| Resolve the alternate +0x4ec copy. | Medium | Establish its frame, F+0x348 producer and admitted incoming edge. |
| Correlate with native transport. | High | Match complete buffers, connection/right provenance and actual method/message events across compatible source identities. |

Quality gates for this bounded increment:

- **QG1**: Factual technical analysis requires no normative premise.
- **QG2**: FA1-FA8 state assumptions, dependent results and falsification probes.
- **QG3**: Object/frame lineage, comparison, field producers, control edges, environmental premises and IPC limits are covered; the larger goal remains active.
- **QG4**: Modular u32 values, unknown field units, byte extents, source visits, independent replays and retained-parent checks are distinguished.
- **QG5**: Classes2/5, conditional writers, observed updates, arbitrary u32 comparisons and unknown native semantics retain distinct scopes.
- **QG6**: Original bytes/fixups, pinned hashes, fresh source queries, independent A64 effects and retained parent CPU evidence support their stated domains.
- **QG7**: The continuation table bounds and ranks native admission, preparation, missing definitions, alternate copying and transport correlation.
