# Helper output recovered from a later register snapshot

The selected helper output is determined through bit35 by the raw X5 register recorded at the third node-allocation import entry. Across the twelve retained successful profiles, X5=0x968f340323885d42 and the inferred low36 helper result is **0x151633a82**. This extends the earlier wire-derived low32 value0x51633a82 by four bits. The full64-bit result remains unknown: this increment leaves bits36..63 unresolved. [HR1-HR5]

The recorded `args` array contains raw X0..X7 snapshots; it is not a declaration that every register is a semantic argument to every import. For this `_malloc` entry, X0=32 B is the requested size and X5 is an incidental live residue. The historical generator captures those registers before applying the import model and reads allocation size only from X0. No target probe was imported or run for this investigation. [HR3,HR4]

Evidence: [original-source ranges, register-access ledger and frozen snapshots](triage_evidence/daemon_helper_result_residue_source.json), [bit-vector certificate and counterexamples](triage_evidence/daemon_helper_result_residue_checks.json), [extractor](triage_evidence/recover_daemon_helper_result_residue.py), [validator](triage_evidence/validate_daemon_helper_result_residue.py), [preservation](triage_evidence/daemon_helper_result_residue_delivery.json), [scoped quality gates](triage_evidence/daemon_helper_result_residue_quality_gates.json). Prior interfaces: [population/helper ABI](daemon_scalar_field_population_report.md), [constructor entry](daemon_constructor_inputs_report.md), [wire codec](daemon_payload_codec_report.md), [record-to-XPC lineage](daemon_record_stream_report.md).

Addresses/constants are hexadecimal; sizes use B. Arithmetic is u64 modular unless a narrower bit slice is explicit. R denotes the post0x100449e38 X5 value; T denotes X17 immediately before0x100449fa8; GEN denotes the helper's stored u64 output. These are analytical names. Thin-image SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` at `/Users/___/Downloads/zut/fairplayd.arm64e`.

## Source liveness and the snapshot boundary

Eight original ranges contain510 instructions/2040 B. Seven intervals, totaling509 instructions after the last X5 definition, contain no W5/X5 write, verified through Capstone's explicit/implicit register-access metadata with W/X aliases normalized. The last definition is EOR X5,X5,X7,LSL#1 at0x100449e38. The complete helper bytes and35 prior source ranges/26356 B are rechecked against the pinned image. Forty-four original pointer records are also recaptured. [HR1,HR2]

| Interval | Source control and effect relevant to X5 |
| --- | --- |
| 0x100449e3c..0x10044a3e0 | Helper remainder; no X5 definition; only terminal RETAB |
| 0x1006f0b28..0x1006f0b60 | Post-call low32 output consumer, then BRAA to adapter |
| 0x100752360..0x1007523ac | Selected nonnull collection adapter, then BRAA to u32 root |
| 0x100828290..0x1008282d0 | U32 root, then BRAA to constructor entry |
| 0x100700d80..0x100700df0 | Constructor frame staging, then BRAA to extent guard |
| 0x10083c564..0x10083c604 | Selected valid extent guard, then BRAA to node allocation |
| 0x1006958b0..0x10069592c | Allocation preparation; only call is final BLRAA at0x100695928 |

The retained event sequence contains the helper call, PACIBSP, RETAB, five selected BRAA edges and the allocation call. There is no intervening source call in these intervals. Normal completion, compatible saved frame/table/phase state and the observed selected branches are premises. This establishes preservation through the import-entry snapshot; it makes no assertion about X5 after `_malloc` returns. AArch64 X5 is not generally call-preserved. [HR2-HR4]

## Exact output relation and the recovered four bits

The helper's last X11 definition is at0x100449fa8:

```text
X11 = R XOR ((T << 36) mod2^64)
```

No later W11/X11 definition precedes output formation. At0x10044a3a4..0x10044a3b4, MOV/MOVK form0xc0eaaa2272eb67c0 and XOR it with X11. The existing argument/output ABI places that full64-bit value at ARG+8 via0x10044a3bc. Six scalar instructions are translated into a straight-line bit-vector expression; the later pointer/store contract is reused from the prior source certificate. [HR2,HR5]

```text
GEN = R XOR ((T << 36) mod2^64) XOR0xc0eaaa2272eb67c0

low36(GEN) = low36(R XOR0xc0eaaa2272eb67c0)
          = 0x151633a82                    [retained R]

low32(GEN) = 0x51633a82
bits35..32 = 0x1
```

The shifted term is zero in bits0..35. It is not zero throughout64 bits: GEN bits36..63 also depend on low28(T). The corresponding abstract expression is bijective in those28 T bits for fixed R. Two explicit cut assignments, T=0 and T=1, preserve low36 and change bit36. This refutes recovery of all64 output bits from R and the final XOR constant alone. These are algebraic counterexamples; the complete helper's reaching constraints on T have not been solved, so arbitrary cut assignments are not claimed to be reachable. [HR5]

Six UNSAT queries establish the source expression, low36 projection, low32 wire composition and the exact contribution/equivalence of the unresolved28-bit slice. Two SAT counterexamples reject the full64 simplification and show the bit36 limitation of this cut. Separate altered-source controls for shift35 and a changed output constant are rejected with SAT counterexamples. Solver limits are15000 ms per query; no solver-unknown result is accepted.

## Independent consistency with the retained wire field

The prior population/constructor/serializer contracts compose to:

```text
wire payload = BE32(low32(GEN) XOR0x55919137)
             = BE32(0x04f2abb5)
             = 04 f2 ab b5
```

All twelve retained profiles have this exact payload under identifier0xf6964e3e, tag0x9777 and extent4 B. This independently recorded wire field agrees with the live-residue inference; neither source of frozen data is a native observation. The new low36 result is inferred from a later register snapshot, not a direct helper output-cell capture. Equal results across these finite path/count/opaque variations do not establish exclusive input dependence, entropy properties, time independence or an algorithm identity. [HR3-HR6]

The stage itself emits no Mach message. Its previously established allocation-to-XPC lineage remains scoped to the private recorded model. No new native peer, port right, kernel selector or daemon-kext transaction is identified by the extra four result bits. [HR6]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| HR1 | Ranges, disassembly and pointer records belong to the pinned thin build. All address claims depend on this identity. | Rehash original image and dependencies; recapture bytes and Capstone metadata; reject mixed-build ranges/fixups. |
| HR2 | The selected normal-return path and compatible frame/table/phase state apply. Snapshot-to-helper register identity depends on these conditions. | Verify all seven intervals for W5/X5 writes and intervening calls; compare every selected retained edge, including PAC/return events. Do not extend preservation beyond the allocation call. |
| HR3 | Frozen profiles and their producer preserve pre-model X0..X7 entry snapshots. Observed R and inferred constants are corpus-bound. | Rehash profiles/producer; inspect capture order and match third allocation by call site and ordinal; do not rerun a probe or relabel model observations as native. |
| HR4 | Helper/argument/frame/state accesses complete normally with stable saved slots and required owner separation. Source output-memory lineage depends on prior ABI premises. | Reuse source-pinned helper store/caller load contracts; recover aliases and native owner/state epochs before generalizing. Register liveness alone is not a memory noninterference proof. |
| HR5 | T is an opaque cut intermediate. The six-instruction scalar lift, not the whole helper algorithm, is the proved expression. | Retain source sites and widths; refute omitted shift/wrong constant; recover T's reaching definitions before determining bits36..63. SAT cut assignments do not prove real reachability. |
| HR6 | Prior caller/constructor/wire-codec and private XPC lineage premises apply. Field consistency depends on these contracts. | Check exact field identity/width/endian bytes and source ownership. Native endpoints, complete found-value behavior and daemon-kext pairing remain unknown. |

Static extraction/liveness checking costs O(source bytes+instructions+frozen events), with linear retained evidence storage. The six-instruction lift has O(1) fixed-size expression work; SMT cost is separate and bounded per query. No target-code execution is part of these algorithms.

## Bounded continuation opportunities

| Impact | Next target | Question resolved |
| --- | --- | --- |
| High | Recover reaching constraints on T at0x100449fa8 and the mutable-state producers. | Whether full64 output can be reconstructed and how state evolves. |
| High | Complete the found-record reader and remaining builder-to-serializer joins. | Full field grammar, acceptance behavior and consumer contract. |
| High | Establish same-build native owners/endpoints for selector26/RPC502/700. | Actual daemon-kext/deeper transaction pairing. |
| Medium | Audit raw-register arrays at other historical import snapshots. | Separate semantic parameters from incidental preserved residues; recover additional data-flow evidence without new execution. |
| Low | Check other consumers' result widths for this helper. | Which callers retain the extra high bits. |

## Scoped quality gates

- QG1: Technical source/register/interface facts require no normative conclusion.
- QG2: HR1-HR6 record dependencies and falsification probes.
- QG3: Source liveness, snapshot semantics, exact scalar output relation, low36 recovery and wire consistency are covered. The broad interface goal remains incomplete.
- QG4: u64 modular shifts/XOR,36/32/28-bit slices, BE32 and byte extents are explicit and reproducible.
- QG5: The shifted intermediate prevents the proposed full64 inference; two SAT counterexamples retain this boundary. Only six scalar instructions are value-lifted;510 captured instructions receive source/liveness inspection.
- QG6: Original bytes/fixups, pinned historical producer/profile data and solver queries supply provenance. No target/native execution, new emulation, native API/IPC, IDA access or IDB/memory mutation occurred.
- QG7: Continuations are bounded and impact-labeled; native pairing and full goal completion remain unknown.
