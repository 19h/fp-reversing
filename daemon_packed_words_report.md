# fairplayd: packed scalar words and bit-count producer

The longer word producer at `0x100c29254..0x100c29804` now has a compact, composed source proof. It combines shifted auxiliary bits, a five-bit count field and a decoded unsigned scalar, then applies an XOR representation. Its upstream count loop computes `max(1, bit_length(scalar))`, including count 1 for zero. The three retained fields decode to scalars **76, 20 and 1**. Complete native field names, upstream scalar admission and daemon-kext buffer identity remain unknown. [PW1-PW5; PW-A1-PW-A5]

This resolves the general word-producer reduction left open by the [append-field report](daemon_append_fields_report.md). The separate two-byte producer remains open. No target interval, guest input, owner or API-return premise is added. The 304-member non-NULL scope and six earlier complete producer replays remain pinned prior evidence; they are not rerun or counted as new checks. [PW2-PW4]

| Evidence | Primary source and scope |
| --- | --- |
| PW1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; instruction bytes, original dispatch slots and format-12 authentication fields. |
| PW2 | [Append checks](triage_evidence/daemon_append_fields_checks.json.zst), decoded SHA-256 `bac22d45750863b7d3bce0993bc891b70a60f43548907c1135a64f89c50e91f7`, and [audit](triage_evidence/daemon_append_fields_audit.json.zst), `a79919e954824d1e1716e3298b455d6f8f03966cfc5ef6242c80d97dad903049`; [growth checks](triage_evidence/daemon_descriptor_growth_checks.json.zst), `b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2`, retain complete source frames and effects. |
| PW3 | [Extractor](triage_evidence/recover_daemon_packed_words.py) and [checks](triage_evidence/daemon_packed_words_checks.json.zst): source fragments, count-loop phase, six packed fields, 26 loop iterations, raw/count stores and original dispatch metadata. |
| PW4 | [Independent auditor](triage_evidence/audit_daemon_packed_words.py) and [receipt](triage_evidence/daemon_packed_words_audit.json.zst): 50 source obligations, one exact ring normalization, complete selected count-source replay, field decodes and three format controls. |
| PW5 | [Publication verifier](triage_evidence/verify_daemon_packed_words_publication.py): fresh extraction/audit, source-query and normalization checks, exact manifest delta, preserved inputs and decoded path hygiene. |

## Complete word-producer equation

Let A be entry W8, n the u32 word loaded from FP-0xcc, and K the u32 word loaded from FP-0xd0. All operations below wrap at 32 bits. AArch64 variable shifts mask their shift count to five bits. [PW1, PW3-PW4]

```
R = A XOR 0x6703cce9
D = K XOR 0x8b3dc651
B = (u32(R << (n & 31)) & 0x07ffffff) OR u32(n << 27)
V = u32(B + D)
producer_W11 = V XOR 0xc156f94e
caller_W11   = V XOR 0xe4b5bf34
```

The caller equation includes its separately proven XOR `0x25e3467a`. The producer formula covers every 32-bit A, n and K under the stated readable input-cell interface. It does not require the scalar to fit a particular format. The word writer's six banks, encoded offset and output/read-cell disjointness premise remain those established in the append-field report. No native memory-validity or input-admission claim follows from these arithmetic contracts. [PW2-PW4; PW-A2-PW-A4]

| Source fragment, end exclusive | Proven transform |
| --- | --- |
| `0x100c29254..0x100c29268` | Load n and compute `u32((A XOR 0x6703cce9) << (n&31))` |
| `0x100c29268..0x100c292c8` | Produce `low27(shifted XOR 0x0095a602)` through the modular product/combiner/inverse chain |
| `0x100c292c8..0x100c29340` | For a 27-bit t, produce `(t OR u32(n<<27)) XOR 0x53ca1e3d` |
| `0x100c29340..0x100c2943c` | Produce `(input XOR 0x535fb83f) + 0x95097265` |
| `0x100c2943c..0x100c29520` | Add `(K XOR 0x8b3dc651) + 0x759f5b7b` |
| `0x100c29520..0x100c29804` | Produce `(input - 0x0aa8cde0) XOR 0xc156f94e` |

The two additive biases cancel because `u32(0x95097265+0x759f5b7b)=0x0aa8cde0`. Count register W9 survives the product/combiner/inverse fragments until the count-packing fragment; each fragment's live inputs are explicitly seeded, and its original words are retained. [PW1, PW3-PW4]

The first chain is proved through four source obligations and an exact normalization over Z/(2^27). Its combiner gives `low27(a+b+0x28b29012)` for arbitrary u32 a and b. The original product coefficients and inverse satisfy:

```
((u*0x4990dd09 + t*0xb66f22f7 + 0x28b29012) * 0x0103c139)
    = u - t + 0x0095a602                     (modulo 2^27)
t = low27((u << 1) AND 0x012b4c04)
low27(u - t + 0x0095a602) = low27(u XOR 0x0095a602)
```

The coefficient normalization has exact zero difference at width 27; the source combiner, projection and XOR identities have separate nonvacuous UNSAT obligations. Their composition establishes the first chain. The report does not claim a monolithic nonlinear SMT proof of the entire original producer. [PW4; PW-A2]

A source identity used to decompose the final stage at `0x100c29718..0x100c2972c` explains an apparent quotient/remainder construction. For arbitrary u32 quotient q and word w, it computes `q*(46*256) + u32((w-46*q)<<8) = u32(w<<8)`. The preceding four instructions write only X10 and access no memory. The proof therefore allows an arbitrary quotient, replaces the cancellation result by `u32(w<<8)`, and resumes the remaining original source with only W8/W9/W10/W11 seeded. The dead W12/W13 scratch values are not assumed. This explicitly justified symbolic cut removes the quotient expression without changing target execution; no interpretation of the preceding magic-multiply quotient is needed. [PW1, PW4]

## Count loop and dispatch interfaces

The loop at `0x100cc81e0` has a fixed recovered register phase, including scalar XOR key `0x8b3dc651`, shift count 1 and dispatch base `0x101039ef0`. One original iteration increments the u32 counter, prepares the encoded next scalar and selects a target using the **current** decoded scalar. The phase registers survive the iteration. [PW1, PW3-PW4]

```
count = 0
current = decoded_scalar
do:
    count += 1
    next = current >> 1
    done = current < 2                    # unsigned
    current = next
while not done
```

This is O(max(1, bit_length(D))) time and O(1) state, with at most 32 iterations for a u32 D. Thirty-two nonvacuous width partitions cover every u32 scalar: width 1 includes both 0 and 1; widths 2..32 partition the remaining values by their highest set bit. Within each partition, all earlier iterations continue and the last exits. Together with the proven step, initialization and dispatch contracts, this establishes `count=max(1, bit_length(D))`. [PW4; PW-A3]

| Scalar predicate | Original table index / slot | Target | Logical authentication |
| --- | --- | --- | --- |
| D >= 2 | 0x7550 / `0x101074970` | `0x100cc81e0`, continue | IA diversity 0x73a4, address diversity 0 |
| D < 2 | 0x926d / `0x101083258` | `0x100add458`, exit/store | Same |

Both slots are independently decoded original authenticated rebases. Source `BRAA X13,X17` at `0x100cc822c` uses X17=`0x73a4`. All 26 retained logical branch targets match the selected original slot and source register. Hardware authentication and native relocated pointer values remain unknown. [PW1, PW3-PW4; PW-A1-PW-A5]

| Source producer/consumer | Exact contract |
| --- | --- |
| `0x100a30df0` | Initialize W10 count to zero |
| `0x100a30dfc` | Store raw scalar K at FP-0xd0, four bytes |
| `0x100add45c` | Store completed count at FP-0xcc, four bytes |
| `0x100c29260` | Reload the count for the word producer |
| `0x100c2943c` | Reload raw scalar K for the same producer |

The retained FP is `0x68000600a0`, giving scalar cell `0x680005ffd0` and adjacent count cell `0x680005ffd4`. The archive joins their last source writers to the producer's reads; neither cell is newly supplied. [PW2-PW4]

## Recoverable field format and retained values

When `1 <= n <= 27` and `D < 2^n`, the scalar does not carry into the auxiliary/count fields. The packed value V then has this layout: [PW4; PW-A4]

```
bit 31                 27 26                  n n-1             0
    +--------------------+---------------------+----------------+
    | count n: 5 bits    | low(27-n) bits of R | scalar: n bits |
    +--------------------+---------------------+----------------+
                         27-bit payload
```

The inverse is `n=V>>27`, `D=V&((1<<n)-1)` and `auxiliary=(V&0x07ffffff)>>n`. The latter recovers only the low 27-n bits of R. For the source-produced count `max(1,bit_length(D))`, this format interpretation is guaranteed for `D <= 0x07ffffff`. The unconditional u32 producer equation still applies outside that domain, but these separate field interpretations need not. [PW4; PW-A4]

Both inherited growth classes have the following values; each row appears twice in the evidence, once per class. [PW2-PW4]

| H offset / B | Scalar D, decimal | Count n | Retained auxiliary bits / value | Packed V | Producer W11 | Caller/writer W11 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 76 | 7 | 20 / 0x70c14 | 0x3b860a4c | 0xfad0f302 | 0xdf33b578 |
| 57 | 20 | 5 | 22 / 0x2bb2a4 | 0x2d765494 | 0xec20adda | 0xc9c3eba0 |
| 65 | 1 | 1 | 26 / 0x1d6fd64 | 0x0badfac9 | 0xcafb0387 | 0xef1845fd |

For example, the H+57 field has count 5, scalar 20 and auxiliary value `0x2bb2a4`. Its packed value is `(5<<27) OR (0x2bb2a4<<5) OR 20 = 0x2d765494`. The caller XOR gives `0xc9c3eba0`; the already proven byte mask `57ac3a44` produces stored bytes `9e6fd1e4`. All quantities are exact bit patterns. [PW2-PW4]

Scalar 76 numerically matches one less than the modeled buffer extent measured in bytes, and scalar 20 numerically matches the append width in bytes. Native units and length-field meaning remain unknown. The auxiliary source word is transformed entry W8; its complete earlier producer and a native randomness property are not established here. [PW2-PW4; PW-A5]

```
raw scalar spill -> unsigned bit-count loop -> count spill
          |                                      |
          +------------------+-------------------+
                             v
entry W8 -> shifted auxiliary/count packing -> scalar addition
                             |
                             v
              producer XOR -> caller XOR -> byte masks -> H field
```

The three controls distinguish the exact source equation from stronger interpretations. They operate on source arithmetic or proof variables; no target input or native call is supplied. [PW4]

| Control | Verified outcome | Interpretation limit |
| --- | --- | --- |
| D=0 | Source count is 1; proposed count 0 is rejected | The loop has a minimum width, rather than the usual zero bit length |
| D=0x08000000, source count 28, R=0 | V=0xe8000000; V>>27 is 29 | Above the 27-bit scalar domain, addition can alter the count field; native admission of this input is unknown |
| D=1, count 1, R=0 or 0x80000000 | Both produce V=0x08000001 | The full auxiliary word is not recoverable |

These controls establish representation limits, not a native defect or externally reachable behavior. The byte writer remains invertible for its single mixed u32 input under its bank/disjointness premises; the larger producer maps several inputs into a packed word and discards auxiliary bits. [PW2-PW4; PW-A4-PW-A5]

## Verification and assumption register

Fresh selected replay checks 518 original count-related instructions across 44 spans, 17,984 GP/SP values, 562 NZCV frames, 26 reads and 12 writes. It separately checks 26 logical loop branches and six field decodes. The six original word-producer replays and 304-member admissions remain prior pinned checks. Fifty new nonvacuous obligations are UNSAT, one modulo-2^27 coefficient normalization has exact zero difference, and three interpretation controls are SAT with explicit witnesses. [PW2-PW5]

The 50 obligations comprise 17 source/composition identities, 32 complete u32 width partitions and one format/inverse identity. Time is O(parent receipt bytes + selected visits*32 + proof DAG), with source-loop O(max(1,bit_length(D))) time and O(1) state; solver search complexity is separate and each query has a 30 s bound. Storage is O(parent receipts + selected evidence + proof DAG). Word arithmetic is u32, pointer arithmetic is u64, bit counts are dimensionless and storage extents use B. Archives use `zstd --ultra -22 -q -T1` with decoded round-trip validation. [PW3-PW5]

No new Mach name, right disposition, incoming/outgoing emission or native daemon-kext transaction is established. The pending malloc97 and NULL-route undefined S+0x30 frontiers remain unchanged. No native target API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation executes. The original image and retained references suffice; IDA is not accessed. [PW2-PW5; PW-A5]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PW-A1: Pinned image, source dependencies and parent receipts apply | Original transforms, concrete instances and dispatch targets | Verify hashes, every selected original word, original format-12 slots and exact parent extraction. |
| PW-A2: Stated instruction widths and composed fragment interfaces apply | Universal word-producer reduction | Prove each source fragment, count preservation, modulo-2^27 projection and zero ring difference; compose identities explicitly rather than claim an unsupported monolithic result. |
| PW-A3: Recovered count-loop phase applies | Complete u32 bit-width contract and current spill/read join | Prove phase preservation and both dispatches; cover all 32 width partitions, including zero; replay all 26 current iterations and source stores. |
| PW-A4: Scalar fits the stated domain and prior byte-writer premises apply | Separate count/scalar/auxiliary inverse | Prove the inverse under count/scalar bounds; check all six actual fields; retain bank/output disjointness and reject the out-of-domain count interpretation. |
| PW-A5: Local representation does not establish native admission or complete identity | Native field names, units, auxiliary nature, ownership and transport | Require actual earlier value producers, caller bounds, complete native epochs and matching daemon-kext buffers/messages; preserve the existing allocation and missing-field frontiers. |

| Impact | Bounded continuation | Current evidence limit |
| --- | --- | --- |
| High | Recover earlier scalar producers and any admission bound before the count loop | Exact scalar spills and width semantics; native acceptance domain remains unknown |
| High | Join the auxiliary entry word to its complete earlier byte/source producer | Current W8 values and retained bits are established; full provenance and randomness remain unknown |
| High | Reduce the separate two-byte producer and compare its count/payload organization | Its exact byte inputs and writer contract are pinned; general compact reduction remains open |
| High | Match these scalar/auxiliary fields to actual daemon-kext buffer consumers | No new native transaction or port emission is established |
| Medium | Use the proved quotient cancellation when reducing nearby arithmetic obfuscation | One exact source fragment is proved; other occurrences require their own evidence |

**QG1**: factual technical analysis. **QG2**: PW-A1-PW-A5 state assumptions, dependent results and falsification probes. **QG3**: the packed-word/count increment is covered; the full interface goal remains active. **QG4**: widths, arithmetic, source counts, units and complexity are explicit. **QG5**: universal producer arithmetic, bounded field interpretation, prior replay and unknown native semantics are separated. **QG6**: original words/fixups, fresh selected replay, composed proofs, exact normalization and publication checks establish provenance. **QG7**: bounded adjacent interfaces and impact labels are explicit.

Follow-up: The [packed-halfword report](daemon_packed_halves_report.md) resolves the separate two-byte producer into a composed scalar/count/auxiliary equation. Its four-bit count and twelve-bit payload encode retained scalars 0 and 2, with count 1 for zero. Thirty-two source obligations, four format controls and fresh replay of 1,066 instructions check the reduction, scalar preparation, six count iterations and twelve saved-register joins. The earlier scalar-cell writer, native admission and daemon-kext pairing remain unknown; the full goal remains active.

The [scalar serialization follow-up](daemon_scalar_serialization_report.md) proves the common periodic mask for recovered word/halfword fields, traces the gate word q to T+1..4 and checks header-scalar/extent agreement across 532 model snapshots. The word decoder includes its count-zero shift case; native field types and daemon-kext identity remain unknown.
