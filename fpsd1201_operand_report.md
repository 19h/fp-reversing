# CoreFP1201 operand preparation and negative inverse coefficient

The selected prefix of child 0x14f8d28 computes a plain 32-bit coefficient from the first decoded context limb. For every odd limb n, the recovered recurrence yields coefficient = -n^-1 modulo 2^32. It writes this value into a descriptor-pair record, then initializes a separate temporary to scalar 1 through original routine 0x181b00. The completed 128-byte import remains in a third, distinct descriptor. This prefix prepares arithmetic operands; complete child semantics, protected-operation completion and native daemon/kext lineage remain unknown.

The unchanged diagnostic context stops before a dereference of its unbacked payload pointer. Explicitly backed controls proceed to call 0x14f9408 -> 0x5a600c, captured before execution. The broader investigation remains active.

## Source and evidence

Addresses use reference CoreFP arm64e preferred base 0, SHA-256 `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; universal SHA-256 `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`. Fresh read-only IDA bytes equal IDA original bytes and the matching reference file:

| Routine | Compiler-bounded interval | Size | SHA-256 |
| --- | --- | --- | --- |
| Cursor wrapper | 0x14fac64..0x14fae60 | 508 B | `29b4fcbd317b4dc019411c97cc76b7b744409dddac46871af3a3998cb9d7da69` |
| Arithmetic child | 0x14f8d28..0x14fac64 | 7996 B | `c9061adae45d6ed11fe2300ca6b6b745ab02d1af00927544a8f7b5e47797fef1` |

IDA's initial child function ends at 0x14f8ff4, covering only 716 B. The retained compiler starts establish the full 7996 B interval, including indirect continuations. Semantic claims here cover the selected prefix through 0x14f9408, not every later block or call in that interval.

The matching reference file corroborates 13852 B of selected code, the earlier 85464 B parent, 3072 B of banks, all 79512 retained fixup words and all 1602 compiler starts. Five bank compositions are checked over all 256 inputs each; 15 selected state/table/callee bindings are retained. A knowledge-store lookup returned no matching stored analysis for these routines. No native operation or IDB mutation occurs.

Artifacts: [producer](triage_evidence/recover_fpsd1201_operand.py), [checks and complete private states](triage_evidence/fpsd1201_operand_checks.json.zst), [independent auditor](triage_evidence/audit_fpsd1201_operand.py), [audit receipt](triage_evidence/fpsd1201_operand_audit.json.zst), [IDA readback](triage_evidence/fpsd1201_operand_ida_readback.json.zst), [publication verifier](triage_evidence/verify_fpsd1201_operand_publication.py). The [importer report](fpsd1201_import_report.md) establishes the preceding byte import; the [record report](fpsd1201_record_report.md) establishes the outer helper and selected 65537 initializer.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| OP1 | The pinned image and compiler starts describe this snapshot. All addresses and semantics depend on identity. | Fresh IDA/current/original bytes and the independent reference-file parse agree. A mismatch invalidates correspondence; native image selection remains unknown. |
| OP2 | Decoded record state 0xb9d0 selects this prefix. Recurrence and binding claims depend on it. | Original source staging and independent record decoding agree across all profiles. Other record controls and later child continuations remain outside the recovered contract. |
| OP3 | The unchanged context retains the predecessor's diagnostic backing. Its stopped read depends on that fixture. | Eight cases stop before reading address 0xa5a5a5a5a5a5a5a5. This establishes an unresolved context prerequisite, not a native crash or native pointer value. |
| OP4 | Backed descriptor, limb and second-cursor controls are explicit private inputs applied at wrapper entry. Continued prefixes depend on them. | All before/after control bytes are retained and reconstructed independently. Four cursor seeds, 24 odd operands and four even controls are covered. Native context production, ownership and bounds remain unknown. |
| OP5 | Original decoded pointers and modeled PAC determine private control flow. Continuation depends on this model. | All selected associations, original words, CPU frames and bank compositions are checked. Hardware PAC, concurrent globals and native loader execution are not inferred. |
| OP6 | The limb codec and selected loop constants remain as recovered at entry. Universal arithmetic meaning depends on these premises and odd n. | Distinct textual/structured instruction lifters prove the source equations; 31 induction obligations close the recurrence. Independent modular-inverse oracles check odd finite cases; even controls establish that their coefficients are not inverses. |
| OP7 | Imported data, the two arithmetic temporaries and caller outputs remain separate until source consumers join them. Data-flow conclusions depend on these identities. | Exact descriptor/payload addresses, stores and unchanged fields are checked. The initializer changes a separate temporary; candidate P+0x880 remains untouched. |
| OP8 | Stopping before 0x5a600c bounds evidence. Status, cursor and architectural conclusions depend on this boundary. | The next call is not executed; neither wrapper returns in these prefixes. Retained seed/status bytes are not completed outputs. Complete arithmetic, external status mapping and native IPC lineage remain unknown. |

## Record, context prerequisite and descriptor identities [OP1-OP5,OP7]

Let R be the record passed at 0x98189c and p=low32(R). Its selected word codec is:

```text
M = ((p XOR 0x5f8c1ee6) * 0x2a03d31f) mod 2^32
MEM32[R] XOR M = 0xb9d0
```

| Prefix record offset | Width | Role |
| --- | --- | --- |
| +0x00 | 32 bits | Encoded state |
| +0x08 | 64 bits | Pointer to descriptor-pair record Q |
| +0x10 | 64 bits | Context descriptor C+0x290 |

These are the 24 B consumed by the recovered entry prefix. Retained 32 B snapshots include neighboring reused bytes; no additional ABI role is assigned to them here. Pair Q holds two descriptor pointers at +0x00/+0x08 and receives the plain coefficient at +0x10, width 32 bits, store 0x14f9254.

The child reads context count word C+0x294 at 0x14f8ea4, loads payload pointer C+0x298 at 0x14f8ed8, and reads its first word at 0x14f8edc. The unchanged fixture's pointer is unbacked; execution stops before that last instruction. Backed zero-count and even controls also reach this first-word read. No zero-count or oddness rejection occurs before that read in this selected prefix. Actual caller preconditions and later rejection policy remain unknown. The diagnostic controls are applied at wrapper entry after the preceding import; earlier metadata reads retain the predecessor's count word 0x4b0cf052. These controls do not establish a whole-call context epoch.

Let S be the outer child's SP at call 0x98189c. Original staging keeps three descriptor identities distinct:

| Role | Descriptor | Initial word +0 | Count word | Payload pointer | Effect in this increment |
| --- | --- | --- | --- | --- | --- |
| Completed import | S+0x90 | 64 | 0x4b0cf070, count 32 | S+0x2d0 | Preserved; preceding import wrote 128 B |
| Pair first temporary | S+0xa0 | 130 | 0x4b0cf050, count 0 | S+0x3d0 | Initialized to scalar 1; count becomes 1 |
| Pair second temporary | S+0x80 | 130 | 0x4b0cf050, count 0 | S+0x5d8 | Preserved |

Q is S+0x68. Initializer completion preserves the first temporary's word +0 = 130 and payload pointer. Word +0 is not assigned a capacity or ownership meaning from these observations alone. The two temporary payload pointers differ by 520 B; that address difference does not prove a native allocation extent.

## Cursor wrapper and selected bindings [OP1-OP5,OP8]

| Role | Original slot | Effective target |
| --- | --- | --- |
| Outer call to wrapper | 0x1d05948 | 0x14fac64, IA modifier 0x0b1e |
| Wrapper state A | 0x1d101c8 | 0x1d33698 after -4 bias |
| Shared state B | 0x1d120a8 | 0x1d37f68 |
| Wrapper cursor metadata | 0x1d11650 | 0x1d332a0 after -4 bias |
| Child state A | 0x1d07638 | 0x1d43800 after -4 bias |
| Common table base | 0x1d108e8 | 0x1c81940 after -4 bias |
| Wrapper's child | 0x1d04c30 | 0x14f8d28, IA modifier 0x3a12 |

The wrapper reads seed s from its caller's X1 cell, stores s-0x90 in a separate scratch cell at 0x14fadbc, then passes the scratch address as child X1. The child adds 0x90 at 0x14f8e48 and stores it at 0x14f8e4c, before the context dereference. Subtraction/addition cancel for every u64 seed, including wraparound.

The wrapper's unexecuted return suffix would write `((low32(scratch)-low32(s)) AND 0xffff)<<4` to the caller's cell. That conditional source formula is distinct from an observed completed return. Both the second caller cell and the original outer helper output retain their seeds in these stopped prefixes; a zero seed is not evidence of a computed zero adjustment.

## Source recurrence and coefficient [OP1,OP2,OP5,OP6]

The first context word decodes as `n = encoded_limb XOR 0x1ac70ef2`. Under the selected record state, source entry initializes candidate v=1 and bit index i=1. The loop's source equations reduce to:

```text
q = n
v = 1
for i = 1 .. 31:
    b = (q >> 1) AND 1
    q = ((q >> 1) + b*n) mod 2^32
    v = (v + b*2^i) mod 2^32
coefficient = (-v) mod 2^32
MEM32[Q+0x10] = coefficient
```

The encoded working word remains `q XOR 0x1ac70ef2`. The source shift path, bit test, encoded addition, candidate-bit update and loop increment/state are proved from original straight-line instructions. The encoded-add identity is split into four byte obligations. Unsupported lifter instructions reject; the producer parses operand text while the auditor uses structured Capstone operands. Thirty-one further obligations establish the arithmetic invariant, with u64 cursor cancellation checked separately: 40 new retained and 40 independent queries pass.

For odd n, let P_i=n*v_i modulo 2^32 after iteration i. The induction starts at P_0=n, whose low bit is 1. Before iteration i, q's relevant low bits equal `P_(i-1) >> (i-1)`. Thus b is bit i of P_(i-1). Adding `b*n*2^i` clears that bit because n is odd, while preserving all lower bits. The updated q maintains the shifted-product relation. After i=31, P_31 equals the integer 1 modulo 2^32; therefore `n*coefficient = -1 mod 2^32`.

Even n has no multiplicative inverse in the u32 ring. Four even controls still reach coefficient publication and scalar-one initialization; this prefix does not establish an oddness-rejection policy or successful later arithmetic for them.

| Selected transition | Original slot | Target | Modifier |
| --- | --- | --- | --- |
| Loop entry/re-entry | 0x1cde7c0 | 0x14f9030 | IA0xa437 |
| Conditional add | 0x1cc9318 | 0x14f9064 | IA0x6ff2 |
| Skip/converge | 0x1cc9338 | 0x14f8ff4 | IA0x6ff2 |
| Loop complete | 0x1cde440 | 0x14f9208 | IA0xa437 |

The source counter increments by 1, tests against 32 at 0x14f900c and completes 31 semantic iterations. Private instruction counts vary with the add path. This establishes the selected inverse-coefficient prefix; a complete modular multiplication, exponentiation or RSA implementation is not established.

## Scalar-one initialization and next helper [OP1,OP4-OP8]

Call 0x14f932c selects original initializer 0x181b00 through slot 0x1d039d8, IA modifier 0x58b1. Its decoded scalar word is 0x0c9600c5; adding 0xf369ff3c modulo 2^32 gives 1. This differs from the earlier auxiliary-NULL initializer word 0x0c9700c5, which gives 65537. Both values have one limb; a count of one does not identify the scalar.

All 28 backed controls execute the scalar-one initializer through its original return. The first temporary then contains descriptor word +0 = 130, encoded count 0x4b0cf051 and limb 0x1ac70ef3, equal to `1 XOR 0x1ac70ef2`. The second temporary and completed import descriptor remain unchanged.

```text
context descriptor -> first encoded limb -> inverse recurrence
                                           -> Q+0x10 coefficient
pair Q+0x00 -> first temporary -> original initializer -> scalar 1
pair Q+0x08 -> second temporary                         [preserved]
completed import descriptor                            [preserved]
  -> stop before 0x14f9408 -> 0x5a600c
```

The next call uses slot 0x1d03860, IA modifier 0xdd63. Its CPU frame and 24 argument-record bytes are retained before execution. Its record grammar, effects and return remain unknown. No source read/write touches candidate P+0x880..P+0x8ff. No new incoming or outgoing Mach right is emitted by the recovered prefix; the request1200/request1201 port and native daemon/kext joins remain open.

## Validation and continuation

The independent audit passes 36 profiles: eight unchanged-context boundaries and 28 backed prefixes, including 24 odd operands and four even controls. It checks 306543 original instruction visits, 32696 reads, 6162 writes, 13607 PAC models, 15001 complete CPU frames, 1088 operand checkpoints, 72 second-cursor checkpoints and 5455872 B of final RAM. All 868 source recurrence steps agree with the compact oracle; all 24 odd results also agree with a separate modular-inverse oracle. All 28 scalar-one initializations complete. The preceding import is checked afresh for 4608 bytes and 1152 limb values; 18 earlier selected 65537 initializations remain distinct.

```text
$PYTHON triage_evidence/recover_fpsd1201_operand.py
$PYTHON triage_evidence/audit_fpsd1201_operand.py
$PYTHON triage_evidence/verify_fpsd1201_operand_publication.py
```

The u32 recurrence has 31 bounded iterations and constant word storage. Generalized to w-bit words, it takes O(w) word operations and O(1) words; bit-operation cost depends on the word arithmetic implementation. The retained replay costs O(I+C(B+F+V+PJ+R)) time and O(I+B+F+C(V+J+P+R)) space for image bytes I, selected code B, fixups F, profiles C, visits V, PAC sites P, journal entries J and retained RAM R. Exhaustive bank checks add 1280 finite inputs. Solver cost is separate, with 60 s limits per new query; these are not native timing measurements.

| Impact | Next discriminating evidence |
| --- | --- |
| High | Recover 0x5a600c's record and descriptor transformation, then follow the remaining arithmetic-child calls to complete the preparation contract. |
| High | Recover the actual C+0x290 descriptor and its payload producer, normalized count, bounds and ownership. The unbacked diagnostic boundary identifies the missing data dependency. |
| High | Join the separate imported value, arithmetic temporaries, candidate P+0x880 and actual request1201 destination across all parent SP epochs. |
| High | Match native endpoint/right identity and daemon/kext/deeper transactions after the source buffer and status lineage is established. |
| Medium | Determine where oddness and zero-count preconditions are supplied or rejected; the observed prefix alone does not establish those policies. |
| Medium | Recover synchronization and lifetime rules for the shared mutable state cells, including the wrapper/child's common state B. |

**QG1** passes: factual technical analysis. **QG2** passes: OP1-OP8 state assumptions, dependencies and probes. **QG3** passes for the operand-preparation increment; the full goal remains incomplete. **QG4** passes: u32/u64 modular widths, scalar/count distinction, byte extents and induction agree. **QG5** passes: unbacked versus backed inputs, even controls, distinct descriptors, incomplete IDA bounds and stopped returns are explicit. **QG6** passes: primary binary bytes, matching file, original fixups, distinct source lifters, independent replay and scoped proofs support the claims. **QG7** passes: impact-ranked continuation covers arithmetic, context production, ownership and native interface joins.
