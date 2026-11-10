# Two private-view imports, nonzero copy counts and an initial even32-byte case

The continuation at `0x100daefe8` initializes two byte-copy loops. The first scatters source bytes XOR0xf9; the second scatters unchanged source bytes into the other plane. Both have the same exact nonzero u32 count. Earlier initializer/even-adapter source establishes view bases F+0x1150 and F+0x1100 and, with the initial progression word, a32-byte count for each loop. That specialization then flips C(32) and selects a suffix-word XOR mask0x00000300. Native arrival at this later context, complete decoded padding, view ownership/extent, whole algorithm, output and daemon/kext pairing remain unknown. [VI1-VI8]

Evidence: [original source and authenticated edges](triage_evidence/daemon_mode_one_even_view_import_source.json.zst), [proofs and copy/control ledgers](triage_evidence/daemon_mode_one_even_view_import_checks.json.zst), [extractor](triage_evidence/recover_daemon_mode_one_even_view_import.py), [validator](triage_evidence/validate_daemon_mode_one_even_view_import.py), [preservation](triage_evidence/daemon_mode_one_even_view_import_delivery.json), [quality gates](triage_evidence/daemon_mode_one_even_view_import_quality_gates.json), [sealer](triage_evidence/seal_daemon_mode_one_even_view_import.py), [publication audit](triage_evidence/verify_daemon_mode_one_even_view_import_publication.py). Context: [incoming parity/reentry gate](daemon_mode_one_secondary_reentry_report.md), [initial parity adapters](daemon_mode_one_parity_state_adapters_report.md), [initializer and slot epochs](daemon_mode_one_workspace_state_install_report.md), [word XOR and plane coordinates](daemon_mode_one_word_xor_plane_refresh_report.md), [interface ABI](interface_abi_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original image | fairplayd.arm64e, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Current source | Five ranges;148 instructions /592 B;143 nonbranch source sites translated |
| Prior recapture | Nineteen ranges /46,920 B |
| Accepted results | 35 UNSAT /two abstract SAT;ten predecessor propositions replayed |
| Original control | Seven source/slot/modifier bindings; six unique authenticated records |
| Encoding checks | Two UMULL and one UDIV; eight corrected comparison GPR-write reports; zero SP writes |
| Initial even specialization | 32 iterations per loop;64 source bytes read;64 copied bytes plus one marker byte |
| Integrity | Seven altered source, target, modifier, ISA, lineage and native claims rejected |

F is the private frame. Offsets/extents are bytes; scalar arithmetic is modular u32/u64. All numerical equalities are exact. Computed source bytes are independent u8 component inputs; literal frame forwarding is byte-exact. Valid coherent nonwrapping mappings, stable roots and absence of outside writes remain premises. UNSAT results cover the coherent-memory subset; SAT witnesses can omit native correlations. No target execution/emulation, target API/IPC request, new IDA access, IDB change or hardware pointer-authentication check occurred. [VI1-VI4,VI8]

## Incoming nonzero partition and concrete source-byte offset

Retain P=PSTATE, AWORD=u32[F4ac] and BWORD=u32[F4a4]. A fresh query against the preceding even-gate source proves:

```text
R = u32(BWORD-P-AWORD+0x29ee6c20)
R=0: slot0xc94e ->0x100c2ab70       // previously proved C(0) toggle
R!=0:slot0xc96f ->0x100daefe8

W8=u32(BWORD-P-AWORD)
W9=u32(0x6c054010+R)
W13=0xa05a; W12=0x1e31
W19=P; W7=0x883fddf1; W20=0xd6; W23=0xb3
X21=F+0x8b0
X0=the value supplied at refresh entry, preserved through refresh
```

The refresh temporarily saves X0 in X26 at0x100c62fec and restores X0 at0x100c65034. X26 is subsequently reused; its final value is a separate epoch. This closes a previously unproved caller binding for the second byte reader. [VI2-VI4]

Both copy loops read at byte offset:

```text
I = u32(P+0xb59d0a84) = u32(P-0x4a62f57c)
source_offset(j) = u32(I+j)
```

Thus the progression word has an exact encoded byte-index role in these readers. The previously proved advance P+64 advances this source index by64 modulo2^32. Native message-position meaning and nonwrapping traversal bounds remain separate questions. [VI2-VI5]

The31-instruction entry at `0x100daefe8..0x100daf064` selects slot0xa05a ->0x100d87098, modifier0x62ce. It initializes the first logical index to0 and resolves its source base:

```text
V0 = u64[F360]+0xf00f12f95e107577     mod2^64
X0 = V1, the preserved second source base
```

No source byte is read in this preparation block. [VI1-VI4]

## Two exact-count loops and their destination coordinates

The first loop is `0x100d87098..0x100d87104`,27 instructions. For logical j in0..R-1 and R!=0:

```text
source at0x100d870b4: V0+zext64(u32(I+j))
N0=u32(799*j)
destination at0x100d870c0: F+0x8b0+(N0 mod962)
stored byte = source byte XOR0xf9
```

Its source counter is W3=u32(0x44009da2+j); W10=u32(799*j). Both are advanced for the next iteration. The original wrapping comparison is universally equivalent to `u32(j+1) <unsigned R` within j<R. R!=0 and j<R imply j+1 does not wrap, so the component performs exactly R iterations under valid complete execution. The current byte is copied before the stop test; the incoming gate excludes a zero-count entry. [VI3-VI5]

| First-loop branch | Slot / target | Modifier |
| --- | --- | --- |
| j+1<R |0xa05a ->0x100d87098|0x62ce|
| j+1=R |0x9fd3 ->0x100cba534|0x62ce|

The30-instruction bridge at `0x100cba534..0x100cba5ac` initializes the second counter and preserves the same R. It selects slot0x6f65 ->0x100b8e918, modifier0x885e. [VI1-VI4]

The second loop is `0x100b8e918..0x100b8e98c`,29 instructions:

```text
source at0x100b8e938: V1+zext64(u32(I+j))
N1=u32(799*j+473807)                 // 473807=799*593
actual UDIV denominator=962
destination at0x100b8e94c: F+0x8b0+(N1 mod962)
stored byte = source byte
```

Its counter is W11=u32(0x05513566+j), and its rotated comparison reduces to the same j+1<R test. X2 is temporarily used for the divisor and restored from X19 to zero-extended P each iteration. [VI3-VI5]

| Second-loop branch | Slot / target | Modifier |
| --- | --- | --- |
| j+1<R |0xb94e ->0x100b8e918|0xb9e1|
| j+1=R |0x966a ->0x100c2ab70|0xb9e1|

The first loop's reciprocal and the marker use the original half-u32/UMULL/shift expression. Source queries prove their exact numerator/remainder shapes, and the predecessor's integer certificate establishes equality to division by962, remainder0..961 and operand widths. The second loop has an actual UDIV; a fresh integer theorem proves its remainder bounds and nonoverflowing product. These proofs bound all generic destination bytes to the962-byte domain. [VI3-VI4]

They do not establish plane-only writes for arbitrary R. The numerators wrap as u32 before remainder reduction. The familiar coordinate C(j)=F+8b0+((799*j)mod962) agrees directly with those formulas where the relevant product does not wrap; this is checked for all32 initial-even iterations. No generic R<=64 or native source extent is proved. [VI3-VI5,VI8]

## Saved-view producer and initial even32-byte specialization

A fresh source proof establishes that the initializer's u64 F300 store at0x100b5c038 satisfies:

```text
u64[F300]+0xf00f12f95e107577 = F+0x1150   mod2^64
```

The even adapter copies F300 to F360 at0x100be1308. Its restored X0 is the saved F+0x1100 view, which common setup saves at F380. Fresh queries against the complete earlier even-context source prove:

```text
u64[F360]+bias = F+0x1150
u64[F380] = F+0x1100
u32[F4a8] = u32[F4ac]
u32(u32[F4a4]-u32[F4ac]+0xdf8b76a4) = 32
u32(u32[F4a4]+0x8cca81ed) = 96
```

At P=0x4a62f57c these identities give I=0 and R=32. They hold for all remaining component inputs in that source model, rather than only the all-zero valuation that proposed them. [VI1-VI4,VI6]

The initial setup's recorded flag is zero. The equations establish saved-field/root values and the arithmetic specialization; native arrival at this later nonzero-copy continuation under those same values is not established. Later progression values require the general R contract and cannot automatically inherit32. The source bases also require continuity of the even-adapter frame epoch. [VI2,VI6,VI8]

For this explicit specialization, the complete copy ledger proves:

| Operation | Source interval | Destination labels | Value |
| --- | --- | --- | --- |
| First32-byte copy |[F+1150,F+1170)|C(0..31)|source XOR0xf9|
| Second32-byte copy |[F+1100,F+1120)|C(593..624)|source unchanged|
| Following marker |existing byte at C(32)|C(32)=F+adc|old byte XOR0x80|

The64 source locations are distinct and disjoint from the65 written bytes. All65 destinations belong to the two established planes; the800 arithmetic/codec cells, completed secondary grid, saved roots and296-byte workspace remain unwritten. The read intervals establish this component's accesses, not a native allocation extent or owner. [VI3-VI6]

## Marker composition, paired data flow and suffix-mask component

For the general post-copy marker, original source proves:

```text
Nmarker=u32(799*R)
read and write address = F+8b0+(Nmarker mod962)
byte = old byte XOR0x80
```

The marker restores W24 from F6f8 and X28 from the saved X14, then returns to the known comparison at0x100c55454 through slot0x1e31, modifier0xe346. W2=P, W10=u32(P+AWORD) and W8=0x4d20 provide the comparison's source ABI. [VI2-VI4]

Combined full-source numerator/address queries reached `unknown` at45,000 ms and are excluded. Accepted proofs retain the unmodified source and compose these exact certificates:

1. Original numerator equals u32(799*R).
2. Both original addresses use the exact source numerator's reciprocal remainder.
3. At R=32 the original numerator is25568.
4. Independent constant evaluation gives quotient26 and remainder556.

Congruence yields F+0x8b0+556=F+0xadc=C(32). No source value is cut or replaced. Only the two byte accesses are normalized in the coherent R=32 model, after the address proof; that model verifies the original addresses through the same exact shape and proves the XOR value and restored continuation ABI. [VI3-VI4]

For the32 copied indices, define the analyst projection Q[j]=plane0[j] XOR plane1[j] XOR0xf9. The proved byte stores and independent u8 algebra give:

```text
Q[j] = u8[F+0x1150+j] XOR u8[F+0x1100+j], 0<=j<32
```

This is an exact data-flow relation, not an established native decoder. A universal constant-XOR-F9 proposal for every refreshed pair is false in the broad component model. Its SAT witness can omit actual entry correlations, so it does not disprove a stronger representation relation for a fully constrained native context. The remaining plane bytes are not proved to decode to zero. [VI3-VI4,VI7]

The initial even-context source also proves the subsequent comparison selects the known four-cell word-XOR arm at P=P0. Its encoded suffix input plus bias is96; the replayed original word contract therefore supplies mask96*8=768=0x00000300. In coordinate order C(60)..C(63), the XOR-mask bytes are00,00,03,00. The original store order is C(63),C(62),C(61),C(60), with low-to-high mask bytes. This is a proved XOR action, not an unconditional write of a decoded bit-length field. No complete standard-padding or whole-hash identity is assigned. [VI2-VI4,VI6-VI8]

## Effects and architectural boundary

| Body | Nonbranch sites | Loads | Stores | Read bytes | Store-effect bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Entry |30|3|0|24|0|
| One first-copy iteration |26|3|1|17|1|
| Bridge |29|2|0|16|0|
| One second-copy iteration |28|3|1|17|1|
| Marker |30|6|1|29|1|

The32-byte specialization performs203 loads reading1157 B and65 byte stores writing65 distinct bytes. This table excludes the later four-cell word XOR and prior producer/refresh bodies. Counts are source effects rather than measured native events. Generic valid execution performs R iterations in each loop; source-index arithmetic and the native extent needed for that execution remain explicit premises. [VI3-VI5]

There is no direct API call, Mach send/receive, port allocation or right transfer in the five captured ranges. Their control transfers are the seven recorded private BRAA bindings. No new port-emission site is established. The concrete architectural interfaces are now the two byte-read PCs, the decoded private-view bases, source-index/count encodings, two scatter planes, restored register pair, marker update and next word/seed interface. Native view contents, ownership, caller-visible output, serialization and matched daemon/kext transport remain unresolved. [VI1-VI4,VI8]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| VI1 | Pinned image and records identify this variant; all source claims | Rehash the image, recapture592 current and46,920 prior bytes, verify six pointer records/seven bindings and reject seven alterations |
| VI2 | Gate, saved-view epochs and caller controls compose; entry and downstream interfaces | Replay ten predecessor propositions with recorded original query hashes; freshly prove the complete incoming gate ABI, X0 preservation, source bases and marker return controls |
| VI3 | Memory models and congruence preserve original semantics; copy values, bounds and specialized writes | Retain both original remainder shapes, integer width/range certificates, all32 coordinate rows,65-byte disjointness and two justified marker normalizations; require coherent nonwrapping mappings/no outside writes |
| VI4 | ISA widths/flags and strict solver handling are accurate; all accepted equalities | Translate143 current sites, check two UMULL/one UDIV encodings, correct eight comparison-role reports and reject malformed, unknown, timed-out or unexpected results |
| VI5 | R!=0 and logical j<R are loop invariants; exact iteration count | Prove both counter transitions, rotated stop tests, strict j+1 progress, unique last iteration and equal counts; retain u32 source/numerator wrap for the general case |
| VI6 | Initial even-context saved values survive with P=P0;32-byte specialization and suffix mask | Universally prove both roots, remaining count32, equal base position, biased suffix input96 and word-gate equality; recorded initial flag0 does not establish native arrival at this later path |
| VI7 | Independent component bytes/words overapproximate native correlations; projection and negative-control interpretation | Prove the copied-pair relation by exact u8 algebra; retain broad pair-F9 counterexample without treating it as a native padding counterexample or assigning zero tail bytes |
| VI8 | Native owner/extent, arrival, decoded padding, whole algorithm/output and daemon/kext pairing remain unknown | Follow actual producers of both views and the9,241-instruction continuation; match progress/flag epochs and result ownership to an external serialization/transport contract |

## Bounded continuation

- High impact: recover the producers and paired representation of the32-byte view contents, especially the separate9,241-instruction continuation at0x100d183e8. The exact internal readers are now located. [VI2,VI6-VI8]
- High impact: establish the actual control path that combines the initial even saved fields with entry into this later reader. Initial flag0 and a later flag/progression epoch must be reconciled before claiming native32-byte execution. [VI2,VI5-VI6]
- High impact: prove the correlated post-refresh tail representation before interpreting the marker and0x300 XOR mask as complete padding. Broad pair-XOR refutation does not settle the actual correlated case. [VI6-VI7]
- High impact: follow completed state/output to concrete ownership, serialization and matched daemon/kext transport. These private copies establish no new message or port. [VI8]
- Medium impact: derive any tighter generic R/source-extent bounds from actual producer and progression constraints. The initial32-byte case does not constrain every later entry. [VI3,VI5-VI6]

## Scoped quality gates

QG1: Source, mathematical and interface claims require no normative premise.
QG2: VI1-VI8 identify dependent claims and falsification probes.
QG3: This increment covers both byte readers, generic nonzero count/control contracts, private-view ancestry, the initial32-byte specialization, marker and suffix-mask components. The full interface objective remains active.
QG4: Byte units, u8/u32/u64 widths, exact modular arithmetic, source effects and distinct storage are explicit. Extraction/audit costs O(image/source/dependency bytes); the finite ledger costs O(32) time/space. Under their stated execution premises, the two copy loops cost O(R) source steps and use a962-byte destination domain. SMT worst-case cost is exponential in Boolean variables, with45,000 ms solver and50 s process limits.
QG5: Zero-count bypass, generic versus initial-even counts, source-index/numerator wrap, saved-view epochs, failed combined queries and unproved padding are separated. Historical propositions retain their source assertions while timeout budgets are raised from15 to45 seconds where needed; original query hashes are recorded.
QG6: Original executable/fixup bytes, fresh source equations, exact accepted queries and preserved predecessor models provide provenance. No new live IDA or native observation is claimed.
QG7: High/medium impact continuation opportunities identify the remaining control, representation, ownership and transport gaps.

The serializer producer now proves the actual flag1/parity0 handoff, exact view bytes and the next initial even count 32, closing the prior static phase/progression-entry gap. The matched-state view/LOCAL XOR relation is proved separately; actual tail/padding, ownership and native execution remain unknown. [Result words, views and publication](daemon_mode_one_result_publication_report.md).
