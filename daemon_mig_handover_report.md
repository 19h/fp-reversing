# Post-copy handovers, private record layouts and caller consumers

The source path from protected-core operation AD952088 now reaches private entry `0x1004D4268` with a128-byte caller record. The overwritten former phase at F+0x9D0 is consumed into that record's +0x58 scalar; the earlier tag survives separately in W27. Operation A70E6EB4 reaches a different private entry, `0x10046EF4C`, with a40-byte record at the same stack address. These are distinct protocols and frame epochs, not one globally typed object. [MH1-MH10]

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [original copy/caller spans and cached-word decode](triage_evidence/daemon_mig_handover_source.json), [symbolic continuations](triage_evidence/daemon_mig_handover_symbolic.json), [fourteen source proof pairs and field ledgers](triage_evidence/daemon_mig_handover_proofs.json), [fresh CPU and readback checks](triage_evidence/daemon_mig_handover_checks.json), [preservation](triage_evidence/daemon_mig_handover_delivery.json), and [scoped gates](triage_evidence/daemon_mig_handover_quality_gates.json). The [preceding head report](daemon_operation_heads_report.md) supplies the source-established setup and incoming argument epoch. No fresh IDA query is required by this increment's evidence.

## Source-continuous position and copy contract

The new private CPU cases start at protected-core entry0x10061A2D0 and follow the retained setup, operation dispatcher, argument head and original copy helper. They stop before a non-copy callee or outer authenticated return. They do not join a native MIG transaction to those paths. The six constructor relationships for requests1000/1200,1001/1201 and1002/1202 remain governed by the preceding report's alignment and admission premises. [MH1,MH2]

Let B be the borrowed record base, F the protected-core frame and R=F+0x10CB8. In the retained private context, B=0x6800001000,F=0x680004F230,entry SP E=0x6800060000 and R=0x680005FEE8. Offsets below are hexadecimal bytes unless explicitly decimal.

```text
AD952088
  B+8 --copy32--> F+BC0
  F+9D0 := input_u32(B+0)       [preceding head]
  phase-bearing value -> record R+58
  build128-byte record at R
  cache cell1010B8D10 -> word at F+BA68
  BLRAA466A08 -> private entry4D4268       [stop before call]
  separate caller consumer after a return:
    SP := F + returned_word(F+BA68)
    W6 := u32(R+48)

A70E6EB4
  B+18 --copy32--> F+5D68
  test B+0, B+38, B+40 for NULL
    any NULL -> raw result74C29D88 -> restore SP -> stop before RETAB
    all non-NULL:
      F+5D68 -> F+C080 -> F+C0A0       [two further copy32 calls]
      build distinct40-byte record at R
      BLRAA4C4648 -> private entry46EF4C [stop before call]
      separate caller gate after a return:
        true iff byte_flag==0 OR u8(R+8)==5B
```

The three A70E6EB4 pointer predicates use the full u64 fields at B+0,B+0x38 and B+0x40. B+8 is also loaded earlier but is not part of this three-pointer gate. The first32-byte copy precedes the gate; even its any-NULL branch requires that input span. Neither pointer classification establishes readable pointees for a later callee. [MH3,MH6]

| Operation/class | Original copy call PC | Source | Destination in retained context |
| --- | --- | --- | --- |
| AD952088 | `0x100466834` | B+8 | F+0xBC0 |
| A70E6EB4,both classes | `0x100592F64` | B+0x18 | F+0x5D68 |
| A70E6EB4,all non-NULL | `0x1004C4360` | F+0x5D68 | F+0xC080 |
| A70E6EB4,all non-NULL | `0x1004C45B4` | F+0xC080 | F+0xC0A0 |

Each call selects original slot0x10109FC88 -> helper0x10046F89C, IA diversity34A1/address diversity0. Its original function is604 bytes. The checked paths copy exactly32 bytes, preserve SP and X19-X29, and propagate the same symbolic input bytes through all three A70E6EB4 destinations. The proof covers these aligned, nonoverlapping32-byte paths, not every size/alignment supported by the complete helper. It does not assign an imported `memcpy` identity. The cursor-dependent scratch placements are the retained context's values, not native fixed addresses. [MH2-MH4]

## AD952088: 128-byte record and two phase lineages

The original source writes104 bytes across15 fields before call0x100466A08. Twenty-four bytes remain unproduced in the logical record, including the u32 at R+0x48 subsequently read by the caller. The highest-address field ends at R+128=F+0x10D38, immediately before the saved guard. The source writes no guard byte. This is a bounded caller record, not a recovered complete C type or native allocation contract. [MH4-MH6]

Define `K128(R)=u32((low32(R) XOR 0x7A9247F6)*0x31B6B333)`. The source's14-instruction pre-multiplication expression has that XOR normal form for every u64 SP, without an alignment restriction. Its original MUL at0x100466894 supplies the constant multiplier. A second, universally quantified computed-key lemma proves the field equations below; the two lemmas compose. Original CPU builder cases execute the actual MUL and stores. [MH4]

Let I0=u32(B+0),I4=u32(B+4),I56=u32(B+0x38),Q48=u64(B+0x30),Q64=u64(B+0x40),A=the incoming W27 phase and H=the incoming W20 phase. Arithmetic in u32 fields is modulo2^32; u64 additions are modulo2^64.

| R offset | Width | Source-produced value |
| --- | ---: | --- |
| +0x00 | 8 | F+0xBC0, pointer to the copied32-byte input |
| +0x08 | 4 | K128 + I4 + 0x72D85FD7 |
| +0x10 | 8 | B + 0x3CAA1EF2F6106D5E |
| +0x18 | 4 | (I56 XOR0x8B3DC651) - K128 |
| +0x20 | 8 | Q48 |
| +0x28 | 8 | B + 0x3F9273076EE1A810 |
| +0x30 | 4 | H - K128 - 0x179 |
| +0x38 | 8 | Q64 |
| +0x40 | 8 | B + 0x4FB6A6DFC639C7CB |
| +0x48 | 4 | Unproduced before call; caller later reads a u32 here |
| +0x50 | 8 | B + 0x4A83435B1F0A2D7F |
| +0x58 | 4 | I0*0x121D0B99 + K128 + (A XOR0x0ADE8461) |
| +0x60 | 8 | B + 0x0C1825A49380C80D |
| +0x68 | 8 | B + 0x247F7CF79B589F68 |
| +0x70 | 8 | B + 0x3481CF9DE847370C |
| +0x78 | 8 | B + 0x78E117D710DB84C2 |

The large B-derived words are opaque additive representations. The new caller does not dereference them; they are not assigned ordinary pointer ownership or structure-field identities. Padding and the result slot remain separate from initialized fields. [MH5,MH6]

The concrete phase consumer is `0x10046692C`, which reloads u32(F+0x9D0), followed by MADD at0x100466930 and the R+0x58 store at0x100466938. In this retained epoch A=0x6CF4 and H=0x575D. Thus the former tag field carries I0, while W27 independently preserves the original tag component. The coefficient0x121D0B99 is odd and has inverse0xADC518A9 modulo2^32. The scalar transform is therefore bijective over the local u32 domain with the other terms fixed. This proves information flow into a child-record field, not arbitrary native control of an operation, code target or receiving-port namespace. The callee's interpretation of R+0x58 is unknown. [MH4,MH7]

The same K128 XOR/multiplier normal form occurs in the retained [RSA-path report](rpc502_rsa_report.md), with different record fields and codec directions. Shared address-key algebra does not establish shared function identity, an RSA operation, or a native control-flow join. [MH7,MH10]

## AD952088: next call and post-return word

| Location | Source-established interface |
| --- | --- |
| Pool slot0x1010A3BE8 | Exhaustive256-input bank cancellation selects a decoded address0x1010B8D10, after bias-0xEA9DCF |
| `0x1004669A8` | Load an unknown u64 from that runtime cell |
| `0x1004669B0` | Store its value at F+0xBA68 |
| `0x100466A08` | BLRAA through slot0x1010A12D0 ->0x1004D4268; IA/BDFE,address diversity0 |
| Call registers | X0=R; X1=F+0xBA68 |
| `0x100466A0C..A1C` | After a separate assumed return: SP=F+delta_out, W6=u32(R+0x48) |

The initial cached value is unknown and remains eight symbolic bytes. The post-return value delta_out and result32 are independent inputs to the caller-consumer theorem. No equality between the cached input and returned word is assumed. The theorem covers all u64 delta_out and u32 results as modular arithmetic; valid native stack placement after an actual return is a separate premise. The new continuous paths stop before0x100466A08, so callee effects, actual returned values and success remain unestablished. [MH5,MH8]

## A70E6EB4: distinct 40-byte record and two-byte caller gate

For all three tested u64 fields nonzero, source reaches private entry0x10046EF4C through original slot0x1010A0248 at call0x1004C4648, IA/BA8C/address diversity0. At the same R base, four source writes define28 of the first40 bytes. Twelve bytes remain unproduced, including R+8..15. Source does not initialize the entire40-byte span. [MH3-MH6]

| R offset | Width | Value before call |
| --- | ---: | --- |
| +0x00 | 8 | F+0xBFC0, a frame-workspace address; complete pointee extent/schema unknown |
| +0x08 | 1 read after call | Unproduced before call; first caller read is LDRB at0x1004C464C |
| +0x10 | 8 | F+0x2CFF, address of a source-initialized zero byte |
| +0x18 | 4 | u32(phase21-K40(R)-0xA5D) |
| +0x20 | 8 | F+0xC0A0, the final32-byte copy destination in this context |

`K40(R)=u32((low32(R) XOR0xC6D66014)*0x6B86592F)`. For retained phase21=0x960F, the stored word is0x60F8BF6E and `stored+K40=0x8BB2`. This is a caller-side algebraic form; the callee's control decoding and operation meaning are not established. The final source X1 happens to be F+0xC0C0 after the copy helper's pointer advance. Its interpretation by this callee is not assigned. [MH4,MH8]

The separate caller component reads both R+8/u8 and F+0x2CFF/u8 before deriving `take=(flag8==0 OR result8==0x5B)`. For every pair of byte values and arbitrary phase32, its table index is `phase32 XOR (take ?0x12:0)`. The source-initialized zero flag does not remove the earlier unconditional R+8 read or establish that the callee leaves the flag unchanged. [MH4,MH8]

| take for retained phase0x960F | Index | Original slot | Target at branch0x1004C467C |
| --- | --- | --- | --- |
| False | 0x960F | 0x101084F68 | 0x1004B3E6C |
| True | 0x961D | 0x101084FD8 | 0x1004B4F2C |

Both slots have IA diversity6DEB/address diversity0. No native returned flag, result byte or selected branch is observed. The any-NULL operation class instead follows its original result epilogue: raw u32(P+24)=0x74C29D88, SP restored to E, then stop before RETAB0x100528E20. Under the retained XOR0x8B3DC651 wrapper codec that word is0xFFFF5BD9; its symbolic error name is unknown. [MH3,MH8]

## Validation and assumptions

Fourteen source obligations produce28 original/simplified UNSAT files. They cover the generic key input, universal-key128-byte fields,40-byte builder, affine inverse, two caller consumers, both handover targets, NULL result/SP, runtime-word argument, actual40-byte live fields, every copied byte, copy-preserved registers/SP and the two pointer classes' coverage/disjointness. Native validity and the complete callee behavior are not included in those formulas. [MH1-MH9]

Fresh replay checks24 continuous entry-to-frontier cases over46,832 source visits,9,624 reads,6,512 writes,224 logical control edges and24 boundaries. Eight byte/export/private-memory variants per class include each NULL position and all-nonzero counterparts. The three symbolic products contain five copy-call instances; the24 executions perform40 such calls. Isolated original-source checks add eight128-byte builders,eight40-byte builders,24 returned-word/status consumers and28 two-byte gates:68 cases and1,088 instructions. Unwritten record gaps and the adjacent guard retain nonzero physical fill in those isolated cases; they are not promoted to logically defined native data. [MH5,MH9]

The proof harness initially failed to apply its formal key cut; that was corrected to an explicit post-MUL symbolic seed. Independent replay also rejected a byte-store journal entry carrying a32-bit expression; store values are now serialized at their actual byte width. All dependent products were regenerated and the final source, proof, journal and CPU checks pass. These corrections concern the analysis harness, not target defects. [MH4,MH9]

With the preceding reports' pinned Python/Z3 environment, run `capture_daemon_mig_handover.py`, `daemon_mig_handover_symbolic.py`, `prove_daemon_mig_handover.py` and `validate_daemon_mig_handover.py` under `triage_evidence/`. The validator rebuilds products, solves both SMT forms, and repeats all CPU cases. Time is O(source/artifact bytes + cases*source visits + BV/solver resources); space is O(one CPU map/journal + expression DAGs). Widths, byte endpoints, source addresses and counts are exact.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| MH1 | Pinned original image/fixups/helper identify the analyzed source | Rehash source; regenerate all spans, bank selection and original slot words; replay exact opcodes |
| MH2 | Retained setup/controller/cursor state defines this frame epoch | Fresh continuous entry-to-frontier cases; vary upstream setup separately before generalizing native invariance |
| MH3 | Three specific full-u64 inputs define the A70E6EB4 NULL partition | Prove coverage/disjointness; rotate each NULL field and all-nonzero inputs; do not infer a check of B+8 |
| MH4 | Source key/field/caller equations compose at explicit formal boundaries | Regenerate14 obligations and28 files; actual-MUL/store CPU cases check the key cut; u32/u64/byte types remain distinct |
| MH5 | Private frame/borrowed spans are valid for the modeled reads/writes | Strict stop on unknown frame cells/addresses; preserve24/12 record gaps and guard; native owners/extents remain unknown |
| MH6 | The32-byte copy paths have the recorded alignment/nonoverlap | Check all symbolic byte identities, source reads/writes and X19-X29/SP preservation; other helper sizes/alignment paths remain outside the theorem |
| MH7 | I0 is a local u32 input, distinct from native namespace/admission constraints | Source writer-to-consumer-to-R+58 chain and invertible arithmetic; recover its actual MIG field provenance and callee use before external-control claims |
| MH8 | Caller consumers receive explicit hypothetical returned values | All-u64/u32 and all-byte-pair formulas plus isolated CPU cases; native callees are not executed and no input/output word equality is imposed |
| MH9 | Z3/Unicorn validate bounded source models, with logical PAC | Independent journal-width/opcode/effect/boundary checks; hardware PAC, native frameworks and delivery remain untested |
| MH10 | Matching offsets/codecs require distinct owner/control epochs | Keep40/128-byte layouts, earlier RSA codec and auxiliary caller contexts separate until a source-continuous join is proved |

## Bounded continuation and quality gates

| Impact | Next target | Information resolved |
| --- | --- | --- |
| High | Enter0x1004D4268 with its actual128-byte record and runtime word | First reads of the phase-bearing scalar, status producer, stack-word update and downstream core contract |
| High | Enter0x10046EF4C with its40-byte record | Producer of R+8, use of the byte-flag pointer and the caller gate's actual result meanings |
| High | Recover the nested auxiliary constructor's upstream phase4F79 and frame roots | Missing auxiliary-to-A70E6EB4 entry/control join |
| Medium | Map AD952088 I0 back through MIG1000/1200 wrapper construction | Whether its source is received service identity, another transported scalar or local state |
| Medium | Recover initialization/writers of cell0x1010B8D10 | Native incoming stack-word values and environment invariants |
| Low | Extend copy-helper coverage beyond the retained32-byte aligned paths | Complete generic copy semantics and special edge cases |

QG1: Factual source, data-flow and ABI analysis requires no normative content.

QG2: MH1-MH10 specify dependencies and falsification probes.

QG3: Two handovers, NULL result, copy composition, record epochs and caller consumers are covered for this increment; the full goal remains active and incomplete.

QG4: Byte/u32/u64 widths, modular domains, field extents, definedness and complexity are explicit and reproducible.

QG5: Old/new phase lineages,40/128-byte layouts, cached/returned words, copied/unproduced bytes and local/native control are distinguished.

QG6: Original bytes/fixups, certified source equations, rebuilt SMT, strict journals and fresh CPU cases provide traceable provenance.

QG7: Impact-labeled continuations address callee outputs, external provenance, environmental initialization and remaining cross-layer joins. No new Mach-message emission, right transfer or IOKit selector is established.
