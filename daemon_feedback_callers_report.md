# Authenticated feedback callers and private-record codec

The original call at `0x1008a2784` resolves to wrapper `0x100b211f4`, and its nested call at `0x100b21438` resolves to helper `0x100b003c8`. Their logical IA modifiers are `0xd07f` and `0xe672`. All 152 retained success exports have the same required caller fields and record bytes. Source proofs establish both argument interfaces and an address-derived record codec. Hardware authentication and a continuous initializer/current-caller epoch remain unknown. [FC1-FC4; FC-A1-FC-A4]

```text
152 retained success states, outer SP = 6800060100
  R = outer SP+10cb8; Q = outer SP+bdc8
  root+descriptor bytes remain undefined; no new definitions supplied
        |
  1008a2784: X0=R, X1=Q, IA=d07f
        v
  100b211f4 wrapper
  X19 saves Q; X0 remains R
  dynamic local cell L receives old-d0 (prior source contract)
        |
  100b21438: X0=R, X1=L, IA=e672
        v
  100b003c8 helper source phases
  key = (R XOR 4de3a292f9d49974)*da51a827
  mode = u32(R[4]+low32(key)) = 7a6302fa in retained states
  decoded pointer from R[30] = outer SP+9e0
        |
  descriptor contents and actual current execution remain UNKNOWN
```

| Evidence | Primary artifact and scope |
| --- | --- |
| FC1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_feedback_callers.py) retains original caller/wrapper/helper words, six 256 B tables and five original fixups. |
| FC2 | Frozen [constructor-buffer checks](triage_evidence/daemon_constructor_buffer_checks.json.zst) provide 152 success exports; the [feedback-root report](daemon_feedback_roots_report.md) and [descriptor report](daemon_constructor_descriptor_report.md) qualify inherited root, stack and feedback contracts. |
| FC3 | [Caller checks](triage_evidence/daemon_feedback_callers_checks.json.zst): all-parent field/record checks, three full-u32 selector partitions, seven source obligations and explicit proof-lemma composition. |
| FC4 | [Publication verifier](triage_evidence/verify_daemon_feedback_callers_publication.py): fresh source/fixup/partition/record reconstruction, retained-query comparison, exact manifest delta, input preservation and decoded path checks. |

## Call targets and argument contracts

| Original call / target | Original authenticated slot | Logical IA | Arguments at the source call |
| --- | --- | --- | --- |
| `0x1008a2784 -> 0x100b211f4` | `0x1010a0158`; bytes `f4 11 b2 00 7f d0 08 80` | `0xd07f`, IA, address diversity 0 | X0=`outer_SP+0x10cb8` (R); X1=`outer_SP+0xbdc8` (Q) |
| `0x100b21438 -> 0x100b003c8` | `0x1010a04a8`; bytes `c8 03 b0 00 72 e6 08 80` | `0xe672`, IA, address diversity 0 | X0 retains R; X1=X20, the wrapper's dynamic local-cell pointer |

Both source instructions are `BLRAA X8,X17`. Independent pointer-format-12 decoding checks target, key, diversity and address-diversity fields. This establishes logical target/modifier compatibility with the original fixups, not successful hardware PAC. The wrapper prologue saves incoming X1 in X19. A complete source register-write census confirms that X0 is preserved from the prologue through the nested call setup. The dynamic local cell and its seed/restoration equations retain their previous conditional source scope. [FC1-FC4; FC-A1-FC-A4]

The caller selector uses tables `0x101031da0` / `0x100e99900`, inner XOR `0x0a`, and collapses to low byte `0xea`. Adding `0xcb63` to that byte and indexing table base `0x101039ef0` reaches the first authenticated slot. The wrapper's first nested selector uses tables `0x100e99a00` / `0x100f4e390`, inner XOR `0x54`, and produces W16=`0xccb7`. Its second selector uses `0x100fc4130` / `0x101031ea0`, XOR `0xbb`, to reach base slot `0x1010a6230`. The decoded base, scaled W16 and signed bias `0xffffffffd0c4d1ee` reach `0x1010a04a8`. [FC1-FC4]

| Outer-SP field / u64 | Value in every success export |
| --- | --- |
| +0x9c8 | `0x1010b8dc8` |
| +0x9c0 | `0x1010c4670` |
| +0x5f0 | `0x101031da0` |
| +0x5e0 | `0x100e99900` |
| +0x9d8 | `0x101039ef0` |

These are `5*8 B=40 B` of already defined field evidence per export, not new premises. The selector lift begins after the controller arithmetic and permits every u32 result, so target recovery does not depend on sampled controller contents. Three selectors each cover 256 low bytes with 24 symbolic upper bits: `256*2^24=2^32` inputs per domain. [FC1-FC4; FC-A2-FC-A3]

## Record writers and descriptor codec

Let r=`u64(outer_SP+0x10cb8)`, key=`u64((r XOR 0x4de3a292f9d49974)*0xda51a827)`, k=low32(key), and p be the caller's W23 phase word. The caller's different-looking u32 key construction equals k for every u64 outer SP; the nested helper computes the full key for every u64 record address. No stack-alignment premise is required for these two equalities. [FC1-FC4; FC-A1-FC-A4]

| R offset / width | Original caller writer | Source value |
| --- | --- | --- |
| +0x00 / u32 | `0x1008a26dc` | `u32(k+0x8b3dc650)` |
| +0x04 / u32 | `0x1008a26e0` | `u32(p-k+0x7a628cad)` |
| +0x08 / pointer64 | `0x1008a26f0` | `outer_SP+0x1d14` |
| +0x10 / u64 | `0x1008a26ec` | Source X9; U=`0x6600060000` in every retained export |
| +0x1c / u32 | `0x1008a26ac` | `u32(0x54620be7-k)` |
| +0x20 / u64 | `0x1008a269c` | 0 |
| +0x28 / u16 | `0x1008a26b8` | `u16(k+0x548b)` |
| +0x2c / u32 | `0x1008a26c8` | `u32(0x0d38177c-k)` |
| +0x30 / u64 | `0x1008a2698` | `(outer_SP+0x9e0) XOR 0xe34daea63ad53f9b` |
| +0x38 / u32 | `0x1008a2700` | `u32(k+0xbcabc95e)` |

These ten stores assign 54 B. Four bytes R+0x18..+0x1b and two bytes R+0x2a..+0x2b are defined by inherited state and preserved by this writer phase; their semantic roles remain unknown. The retained record therefore has 60 defined bytes and four undefined bytes at R+0x3c..+0x3f. This describes the selected 64 B observation window, not a proven complete record extent. [FC1-FC4; FC-A2-FC-A3]

The nested decoder at `0x100b00578..0x100b005a8` establishes:

```text
mode = u32(raw_R4 + low32(key)) = u32(p + 7a628cad)
D = raw_R30 XOR e34daea63ad54846
             XOR zero_extend64(mode XOR 7a637527)
```

All 152 exports have p=`0x764d`, r=`0x6800070db8`, key=`0x8ac9c0d6b56d8b14`, mode=`0x7a6302fa`, and D=`0x6800060ae0=outer_SP+0x9e0`. The constants' XOR is `0x77dd`, equal to `mode XOR 0x7a637527`, so the pointer masks cancel. Mode is a locally decoded word; conventional operation identity remains unknown. D is extracted before the next local-record encoding step, not asserted to remain in X12 indefinitely. [FC1-FC4; FC-A2-FC-A4]

The final proof composes the independently proven full-key equation at `0x100b00578`. It replaces an equal X15 expression in the symbolic proof DAG before lifting the consumer. The receipt records the producer lemma, consumer, boundary PC and rewritten register. Directly flattened composition reached the 30 s solver limit; the lemma composition discharges the same conclusion. This changes neither guest bytes nor a guest state. [FC1-FC4; FC-A4]

## Verification and present scope

Fresh reconstruction checks 152 parent-specific records, all five field values, W23, descriptor-pointer decoding and the inherited undefined boundaries. The three selectors retain 12,032 instruction instances and 3,584 read instances. Seven obligations have satisfiable premises and UNSAT negated conclusions: three selectors, caller-key equality, full nested key, ten record writers, and the composed mode/pointer equation. Selectors use exhaustive low-byte partitions with symbolic upper bits; normalization reduces their constant targets before the solver query. [FC1-FC4]

Time/storage is O(parent bytes + 256*selector words + query DAG), excluding solver search complexity and publication input I/O. The six unique tables occupy `6*256 B=1536 B`. Arithmetic wraps at the declared u16/u32/u64 widths; addresses, field widths, offsets and stack extents are bytes. Original inputs are preserved and new/changed raw and decoded files receive path checks. No target API, allocation, free, filesystem operation, IPC, hardware PAC or IDB mutation executes. Retained evidence suffices; IDA is not accessed. [FC1-FC4]

The current execution frontier remains before undefined SP+0x2b0/8 B, and all 16 B at SP+0x9e0 remain undefined. A source-level call/record contract does not execute through that boundary or join the initializer epoch. No Mach-port name, transferred right, external emission or native daemon-kext transaction pairing is established here. [FC1-FC4; FC-A2-FC-A5]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FC-A1: Pinned original image, tables, fixups and scalar semantics apply | Targets, logical IA, codecs and writers | Check image/parent/dependency hashes, original source words, all table reads and independent pointer-format-12 fields. |
| FC-A2: The 152 exports retain their published conditional scope | Caller fields, actual record values and unknown bytes | Check every success member, record byte mask, phase word and undefined root/descriptor spans; do not substitute values. |
| FC-A3: Complete u32 partitions and compatible source phases apply | Input-independent targets and argument shape | Check 256 distinct low bytes per selector with 24 symbolic upper bits; reject symbolic/unlisted reads; verify X0 preservation and exact record-store widths. |
| FC-A4: Proven key equality qualifies symbolic composition | Full key, mode and pointer conclusions | Independently discharge both key equations; record and reproduce the exact lemma rewrite; preserve solver timeout failures as observation limits. |
| FC-A5: Logical calls and local pointer values do not establish native custody | External control and cross-layer interpretation | Require continuous epoch/lifetime and actual Mach/IOKit buffer joins; retain native PAC, concurrency, record extent and operation identity as unknown. |

| Impact | Bounded next evidence | Present limit |
| --- | --- | --- |
| High | Establish initializer-to-current-caller custody | Producer/root and call ABI are source-paired; actual current epoch remains unknown. |
| High | Recover the descriptor consumer beyond D | Pointer arithmetic is known; descriptor bytes and counter-dependent downstream semantics remain unresolved. |
| High | Establish U's role through the nested helper | All retained R+0x10 values name U; complete operation and native object lifetime remain unknown. |
| High | Join the private record and U/S/F objects to transport buffers | No new Mach/IOKit emission or daemon-kext transaction identity is established. |
| Medium | Recover inherited six record bytes and complete extent | This writer assigns 54 B inside a 64 B observation window; six bytes are inherited and four remain undefined. |

**QG1**: factual source/ABI analysis. **QG2**: FC-A1-FC-A5 enumerate dependencies and falsification probes. **QG3**: this caller/record increment is covered; the full interface goal remains active. **QG4**: modular widths, byte units, coverage counts and complexity are explicit. **QG5**: proof composition, inherited bytes, unknown extent and native epoch are separated. **QG6**: fresh source/table/fixup/parent/solver and publication verification qualify primary evidence. **QG7**: impact-labeled adjacent work and remaining interfaces are explicit.
