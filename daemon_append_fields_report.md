# fairplayd: append-field codecs and value provenance

The four-byte writer at `0x100c70dd8` emits a big-endian input word combined with six original-image byte banks and the decoded offset modulo 16. The two-byte writer at `0x100b75548` emits the low 16 bits of a complemented input sum through related banks. The word appended at H+61 comes from entry 2 of the array referenced by U+0x20; its Boolean mixer reduces to an addition and XOR. These are source-block contracts within the inherited conditional execution. Complete native structure names, caller epoch and daemon-kext transport identity remain unknown. [AF1-AF5; AF-A1-AF-A4]

No new guest inputs, owner, API-return premise or target interval is introduced. This increment reuses the two non-NULL growth classes, representing 304 previously admitted parent/ABI combinations. Their complete interval replay and admissions remain pinned prior evidence; this increment independently replays 30 selected spans, rather than rerunning those admissions. [AF2-AF4]

| Evidence | Primary source and scope |
| --- | --- |
| AF1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; exact instruction words and bank bytes. |
| AF2 | [Growth report](daemon_descriptor_growth_report.md), [checks](triage_evidence/daemon_descriptor_growth_checks.json.zst), SHA-256 `b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2`, and [independent replay](triage_evidence/daemon_descriptor_growth_replay.json.zst), SHA-256 `bee4ab3224710559fefdd8bca070110e48c03ab52d01c92b617988b9b3d5bd67`; digests refer to decoded JSON. |
| AF3 | [Extractor](triage_evidence/recover_daemon_append_fields.py) and [checks](triage_evidence/daemon_append_fields_checks.json.zst): source spans, fixed banks, occurrence values, producer-to-writer joins and per-byte last-writer custody. |
| AF4 | [Independent auditor](triage_evidence/audit_daemon_append_fields.py) and [receipt](triage_evidence/daemon_append_fields_audit.json.zst): selected complete GP/SP and NZCV replay, exact reads/writes, 35 universal source obligations and three counterexample controls. |
| AF5 | [Publication verifier](triage_evidence/verify_daemon_append_fields_publication.py): fresh extraction/audit/proof checks, exact manifest delta, preserved original inputs and decoded path hygiene. |

## Source interfaces and arithmetic widths

All additions, subtractions and shifts below use AArch64 u32 arithmetic unless stated otherwise. `u8` truncates to eight bits; `BEj(x)` selects byte j of a four-byte big-endian word. A and B in the half-word input equation are input values, distinct from the bank names in the following table. Byte extents use B; offsets and event counts are dimensionless. [AF1, AF3-AF4]

| Source block, end exclusive | Input contract | Recovered role |
| --- | --- | --- |
| `0x100c70dd8..0x100c70f1c` | X9=base; W10=encoded offset; W11=mixed word; six bank pointers in the current SP frame | Four byte stores at decoded offsets o through o+3 |
| `0x100b75548..0x100b755fc` | X22=base; W21=encoded offset; W8=A; W10=B; three bank pointers | Two byte stores from `N=u32(-2-A-B)` |
| `0x1009dabb0..0x1009dad18` | W11=raw array word; X5=U with U+8=H | `W11=u32(raw+0xb69f7313) XOR 0xe4b5bf34`; X9=H |
| `0x100b9e52c..0x100b9e538` | W11=producer result | XOR W11 with `0x25e3467a` |
| `0x100aec72c..0x100aec738` | Same | Same XOR contract at the other caller |

The block boundaries identify bounded data transforms, not complete functions. Dispatch loads and authenticated branches surrounding these blocks remain in the pinned growth journals. [AF1-AF4; AF-A4]

| Bank | SP offset / B | Original-image address | Required byte extent / B |
| --- | --- | --- | --- |
| A | 0x148 | `0x100ed2440` | 17 |
| B | 0x150 | `0x100e36310` | 16 |
| C | 0x140 | `0x100f2f6b0` | 19 |
| D | 0x278 | `0x100f21190` | 16 |
| E | 0x270 | `0x100fa38b0` | 20 |
| K | 0x280 | `0x100ffc9e0` | 17 |

The retained writer instances have SP=`0x680005fb70`. Every consumed stack pointer equals its listed bank address, and every consumed bank byte matches the original image. The archive retains the complete required bank extents. The universal queries explicitly exclude output overlap with the consumed pointer cells and bank extents; all retained H stores satisfy that premise. The fixed-cell symbolic lift relies on this separation. Native stack contents and relocated addresses remain unknown. [AF1, AF3-AF4; AF-A2]

## Four-byte and two-byte codec equations

For the four-byte writer, `o=u32(W10+0xae20ac2a)` and `kj=u32(o+j)&15`. Define these byte masks:

```
m0 = u8(B[k0] XOR C[k0+3] XOR A[k0+1] XOR (33*k0) XOR 0x12)
m1 = u8(D[k1] XOR E[k1+4] XOR K[k1+1] XOR (31*k1) XOR 0x7e)
m2 = u8(D[k2] XOR E[k2+4] XOR K[k2+1] XOR (31*k2) XOR 0x74)
m3 = u8(D[k3] XOR E[k3+4] XOR K[k3+1] XOR (31*k3) XOR 0xff)
output[j] = BEj(W11) XOR mj
address[j] = u64(base + zero_extend64(u32(o+j)))
```

Sixteen exhaustive low-offset partitions retain 28 symbolic high offset bits, an arbitrary 32-bit word and an arbitrary 64-bit base whose output bytes are disjoint from the consumed bank/pointer cells. Each source obligation proves all four byte values, widths, addresses and inverse reconstruction. The offset addition wraps at 32 bits before widening; addresses need not be contiguous across that wrap. These are arithmetic/store-expression contracts, not allocation-bounds proofs. [AF1, AF4; AF-A2-AF-A3]

For the two-byte writer, `o=u32(W21+0x8927158e)` and `N=u32(-2-W8-W10)`. With `kj=u32(o+j)&15`:

```
h0 = u8(D[k0] XOR E[k0+4] XOR K[k0+1] XOR (31*k0) XOR 0x98)
h1 = u8(D[k1] XOR E[k1+4] XOR K[k1+1] XOR (31*k1) XOR 0x87)
output[0] = u8(N >> 8) XOR h0
output[1] = u8(N) XOR h1
address[j] = u64(base + zero_extend64(u32(o+j)))
```

Another sixteen partitions prove both stores and inverse reconstruction of low16(N), for all two u32 inputs and offsets, and all bases whose output bytes are disjoint from the consumed bank/pointer cells, under these bank bindings. The high 16 bits of N and the separate summands cannot be recovered from the two output bytes alone. The masks depend on field position as well as offset residue; the two writer kinds are not interchangeable. [AF1, AF4]

## Retained fields and value producers

Both growth classes have the following values. For four-byte fields, V=`W11 XOR 0xe4b5bf34` is a recovered intermediate representation; this definition alone assigns no native field name. The mask column acts on the mixed input shown, not on V. [AF3-AF4; AF-A4]

| H offset / B | Mixed input, big-endian hex | XOR mask, hex | Stored bytes, hex | V for four-byte field |
| --- | --- | --- | --- | --- |
| 1 / 4 B | df33b578 | 6826a87d | b7151d05 | 3b860a4c |
| 57 / 4 B | c9c3eba0 | 57ac3a44 | 9e6fd1e4 | 2d765494 |
| 61 / 4 B | 7d0dcee1 | 3925f0ed | 44283e0c | 99b871d5 |
| 65 / 4 B | ef1845fd | 6826a87d | 873eed80 | 0badfac9 |
| 71 / 2 B | 45ca | 42ce | 0704 | Not applicable |
| 15 / 2 B | 7c26 | 1c95 | 60b3 | Not applicable |

At `0x1009dab6c`, X5=U=`0x6600060000` and U+0x20 supplies array pointer `0x650011519c`. At `0x1009dab70`, index X11=2 selects `0x65001151a4`, containing little-endian raw word `0xe318fec2`. The word has no writer in this interval; its earlier source/entry provenance remains required. The universal mixer gives:

```
u32(0xe318fec2 + 0xb69f7313) = 0x99b871d5
0x99b871d5 XOR 0xe4b5bf34  = 0x7d0dcee1
BE32(0x7d0dcee1) XOR 3925f0ed = 44283e0c at H+61
```

The Boolean network therefore preserves a bijective u32 value representation in this field; neither the array element's native meaning nor its producer is established here. [AF1, AF3-AF4; AF-A3-AF-A4]

Three other four-byte occurrences use the longer producer `0x100c29254..0x100c29804`, followed by one of the two proven caller XOR blocks. Its W8 entry value is last defined at `0x100a8d918`; its count cell is last written at `0x100add45c`, and its second stack word at `0x100a30dfc`. Every consumed byte has a current-interval last writer. [AF3-AF4]

| H offset | Producer entry W8 | Count at `0x680005ffd4` | Word at `0x680005ffd0` | Producer output W11 | Caller XOR result |
| --- | --- | --- | --- | --- | --- |
| 1 | 0254c0fd | 7 | 8b3dc61d | fad0f302 | df33b578 |
| 57 | e9a87e4d | 5 | 8b3dc645 | ec20adda | c9c3eba0 |
| 65 | b6d5318d | 1 | 8b3dc650 | cafb0387 | ef1845fd |

The longer source contains a variable shift, a 27-bit mask and count-dependent operations. All its retained instructions and values replay, but a universal compact reduction of the complete producer is **unknown**. The three counts and second words differ; substituting one occurrence's inputs into the others does not describe their source executions. A length, nonce or random-field interpretation remains unestablished. [AF1, AF3-AF4; AF-A4]

The two-byte producer at `0x100b75220..0x100b75548` consumes bytes at `0x680005ff0a` and `0x680005ff0b`. Their last writers are actual earlier `0x100a0ca74` encoded-stream stores. The source combines the bytes, applies its phase-dependent arithmetic and enters the two-byte writer without an intervening source gap. [AF3-AF4]

| Destination | Consumed bytes at increasing addresses | W23 | W24 | Writer N / consumed low16 |
| --- | --- | --- | --- | --- |
| H+71 | c3 43 | 0x0df8 | 1 | 0xfffe45ca / 0x45ca |
| H+15 | 2f da | 0x0dfa | 2 | 0xfffe7c26 / 0x7c26 |

Both have W25=`0x7a6302fa`. The source also consumes a saved pointer and an eight-byte zero cursor written at `0x100add7e4`; these distinct control reads remain in the receipt. The two input bytes are demonstrated encoded-stream outputs. A universal compact reduction of this longer producer and its native field meaning remain unknown. The existing stream-byte codec is described in the [generated-stream report](daemon_generated_stream_report.md). [AF2-AF4]

```
U+0x20 -> word array[2] -> add/XOR mixer -> four-byte writer -> H+61
stack word/count pair -> longer producer -> caller XOR -> writer -> H+1/57/65
encoded-stream byte stores -> two-byte producer -> two-byte writer -> H+71/15
```

The remaining tail offsets 69..70 and 73..76 still come directly from encoded-stream byte stores. This increment neither supplies a 97 B allocator return nor advances the growth frontier. The NULL route's undefined S+0x30 boundary is preserved. No new incoming/outgoing Mach port, right transfer, emission site or native daemon-kext transaction is established. [AF2-AF5; AF-A4]

## Verification and assumption register

Fresh extraction and independent selected replay check 4,018 original instructions across 30 spans, 129,536 GP/SP values, 4,048 NZCV frames, 210 read events and 40 byte-store events. All 12 writer occurrences reproduce their values and addresses; six producer-to-writer joins pass. Thirty-five nonvacuous source obligations are UNSAT: sixteen four-byte partitions, sixteen two-byte partitions, the array mixer and the two caller XORs. Incorrect little-endian extraction and signed offset widening have SAT counterexamples. A third concrete byte-memory control places the output over bank D: later reads consume earlier stores and the fixed-bank formula differs, demonstrating why output/read-cell disjointness is required: base `0x100f21191`, offset 0 and input 0 yield `3d000fdb`, whereas the fixed-bank formula gives `3d392c23`. Complete inherited branch admissions are pinned, not counted as fresh checks. [AF2-AF5]

Time is O(parent receipt bytes + selected visits*32 + selected reads*prior writes + proof DAG); storage is O(parent receipts + selected evidence + proof DAG), excluding solver search. Each solver has a 30 s bound. Zstandard archives use `--ultra -22 -q -T1` with decoded round-trip validation. The existing image and receipts suffice; IDA is not accessed. No native target API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation executes. [AF3-AF5]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| AF-A1: Pinned image and parent receipts apply | Source spans, retained states and prior 304-member scope | Verify original/source/dependency hashes and exact visited instruction bytes; reconstruct this increment from the pinned parents. |
| AF-A2: Recovered bank bindings, disjoint output/read cells and arithmetic semantics apply | Universal four-/two-byte store contracts | Check all actual bank-pointer/byte reads and output disjointness; constrain every symbolic output away from consumed pointer/bank spans; exhaust all 16 offset residues while retaining high bits and base symbolically; reject signed widening and wrong endianness. |
| AF-A3: Inherited conditional phases and defined inputs apply | Array element, producer custody and concrete field values | Compare every selected GP/SP and NZCV frame, ordered reads/writes, last writers and caller joins; preserve missing earlier array-word provenance. |
| AF-A4: Local data transforms do not establish complete native identities | Field names, ownership, caller lifetime and transport interpretation | Require full producer reductions, actual initializers and native caller/buffer/IPC joins; retain pending allocation and undefined-field boundaries. |

| Impact | Bounded continuation | Current evidence limit |
| --- | --- | --- |
| High | Reduce the longer 27-bit/count producer to a compact universal formula | Three exact input/output families and complete selected replay; general reduction unknown. |
| High | Reduce the two-byte producer and establish the word-array element's earlier producer | Exact encoded-stream byte custody and indexed read; complete semantic values unknown. |
| High | Join U/H identities and these scalar representations to actual daemon-kext IPC buffers | No native transport identity or message emission added. |
| Medium | Identify other callers sharing these writer banks and distinguish their offset phases | This report covers the retained non-NULL growth instances and the stated universal block contracts. |

**QG1**: factual technical analysis. **QG2**: AF-A1-AF-A4 state dependencies and falsification probes. **QG3**: the field-codec increment is covered; the full interface goal remains active. **QG4**: byte extents, arithmetic widths, modular offsets, counts and complexity are explicit. **QG5**: proven writer/mixer contracts, concrete longer-producer replay and unknown general/native semantics are separated. **QG6**: original bytes, pinned primary receipts, fresh extraction/replay, proof queries and publication checks establish provenance. **QG7**: bounded adjacent interfaces and impact labels are explicit.
