# Digest serialization and the SP+0x3050 continuation root

The post-compression path writes encoded digest bytes through the pointer saved at SP+0x2FE0. Selector low byte1 uses little-endian word serialization; low byte2 uses big-endian serialization. Both XOR each serialized byte with0x98. Under the checked size declarations, those paths write16 and20 bytes respectively. Zero-size paths and other selector-byte routes converge without serializer output writes. The context remains unchanged. Every complete serializer case then stops before the unresolved u64 read at SP+0x3050. Native identity completion, cache publication and driver IPC linkage remain unknown. The full daemon/kext/deeper-interface investigation remains active.

This extends the [encoded SHA-1 core report](daemon_sha1_core_report.md). Six fresh core/serializer value compositions match the three distinct prepared messages represented by288 retained short cases. They use separate declared component contexts and do not resume those retained unknown-frame frontiers or establish a continuous native call.

## Evidence and execution boundaries

| Evidence | Verified extent |
| --- | --- |
| Original daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| New source | 15 spans / 448 instructions; 383 instructions observed in serializer/decision traces |
| Current IDB | `fairplayd`, target `6b117c693e3b`; 15 read-only ranges / 1,792 bytes, raw identical |
| Original target metadata | 15 authenticated fixups and actual branch-cell provenance |
| Source proofs | 22 rebuilt obligations / 44 original-normalized SMT artifacts; 403 lifted instructions |
| Serializer cases | 64 complete isolated cases across state patterns, two placements, selector1/size16, selector2/size20 and both zero-size paths |
| Selector cases | All256 low-byte values with upper bits0 and0xFFFFFF00; 512 decisions, stopped before serialization/common continuation |
| Conditional compositions | Three retained prepared messages at two placements; six fresh core and serializer pairs |
| Aggregate source visits | 141,948; includes2,990 modeled BRAA visits and138,958 executed A64 instructions |
| Formatter effect audit | 43,950 source visits; 4,448 ordered reads / 1,278 writes, including the six component serializers |
| Core components | 97,998 source visits; 3,528 reads / 630 writes, freshly replayed against the frozen core contract and reference result |
| Retained input audit | 288 unchanged short frontiers; 401,568 retained source visits / 74,400 effects inspected; three distinct prepared messages |
| Shift-access correction | Three instruction-access records and36 isolated architectural instruction checks |

[Source contracts, roots and selector decisions](triage_evidence/daemon_digest_output_contracts.json), [proofs](triage_evidence/daemon_digest_output_proofs.json), [complete traces and value compositions](triage_evidence/daemon_digest_output_profiles.json), [retained input audit/reference](triage_evidence/daemon_digest_output_inputs.py), [shift-access helper](triage_evidence/daemon_digest_output_access.py), [independent checks](triage_evidence/daemon_digest_output_checks.json), and [current IDB bytes](triage_evidence/daemon_digest_output_ida_bytes.json) contain the evidence. [Preservation](triage_evidence/daemon_digest_output_preservation.json) and [scoped gates](triage_evidence/daemon_digest_output_quality_gates.json) seal the increment.

The 64 serializers,512 decisions and six paired compositions are582 logical cases; the paired cases execute two isolated components each. No fairplayd process, target framework call, Mach/IOKit operation, hardware PAC or IDB mutation executes. The three retained messages originate in the earlier declared CF/UTF-8 models, not live hardware-property queries.

Addresses, offsets and encoding/control constants below use explicit `0x` prefixes. Counts/extents are decimal bytes unless stated. F denotes the applicable outer SP, C the context, O the output owner and T=`0x101039EF0`. u32/u64 arithmetic wraps modulo2^32/2^64. Accessed frame-control/context/output/table cells require valid-owner and nonoverlap premises.

## Serialization and routing contract

At `0x1009DE090`, saved mode F+0x273C=0x471C selects original slot `0x10108E210`, target `0x100B30120`, IA diversity0xAFFD. The source loads C from F+0x2F40 and the selector word from C+0x60. B30120 saves C at F+0x2A70. Subsequent signed-byte and low-byte comparisons reduce to the following dispatch:

| Selector word low byte | Source route | Checked output declaration |
| --- | --- | --- |
| 1 | `0x10095B7DC` -> size gate `0x100C0A3C4` -> first LE writer `0x100B57120` -> LE loop `0x100B30004` | 16 bytes, or zero-size skip |
| 2 | `0x100A4739C` -> size gate `0x100AE05DC` -> first BE writer `0x100BE71BC` -> BE loop `0x1008B6060` | 20 bytes, or zero-size skip |
| Other254 byte values | `0x100BB1574` | No serializer writes before that continuation |

The local source proofs cover every u32 selector word and show that these decisions depend only on its low byte. The512 finite cases independently check both zero and set upper bits. The first partition uses signed low-byte comparison with2; the subsequent branches test exactly1 or2. This is an internal context selector, not an established Mach ID or IOKit selector. The meaning/status of other selector entries after the common continuation remains unknown.

For a plaintext state word H[j], the context stores `H[j] XOR0xF4F92DF7`. The serializer reads these encoded u32 words at C+0x48+4*j and writes through O=load64(F+0x2FE0):

| Path | Exact value contract |
| --- | --- |
| Selector1, size16 | `O[0:16] = LE32(H[0]) || ... || LE32(H[3])`, then XOR each byte with0x98 |
| Selector2, size20 | `O[0:20] = BE32(H[0]) || ... || BE32(H[4])`, then XOR each byte with0x98 |
| Size0 in either route | No output bytes are defined by the serializer before the common continuation |

These are encoded binary bytes, not hexadecimal text or unencoded canonical digest bytes. Selector1's compression algorithm is not identified by its serializer alone. Other nonzero output-size declarations and their native admission are outside this report.

The first-word routines write four bytes at O+0..3. The loops use a byte counter advancing by4, read C+0x48+4*j and write O+4*j..4*j+3. The BE loop's actual store order is byte1,byte2,byte3,byte0; the resulting address/value mapping is the same big-endian contract. Proofs establish each byte, each address, the next control cell, the counter update and every live input needed for the next loop iteration. Under the declared sizes, the domains are j=1..3 for LE and j=1..4 for BE. All four domains, including the first-word singleton domains, are checked nonempty.

Only SP and X30=T are declared incoming registers at 9DE090. The required saved mode, context and output cells are explicit fixtures. Context bytes0..71, including the message buffer and counter words, are left undefined in these formatter inputs. Only the five state words, size and selector are defined. Source read-definedness checks reject any reliance on the undefined bytes. The formatter writes no context bytes and defines only the requested16/20 output bytes; the remaining declared32-byte output reservation stays undefined by this path.

## Conditional link to retained prepared inputs

The retained short-path inputs are reconstructed from their original ordered effects and strlen model records. Their encoded64-byte blocks decode exactly to the padded modeled UTF-8 messages; their initial five state words match the previously recovered SHA-1 IV. The original stop remains ABEE7C before reading F+0x2E50.

For each of the three distinct prepared messages, the new pipeline executes the frozen source compression component, extracts its actual five updated state words plus size/selector fields, and passes those values to the new source serializer in a separate declared context. Both placements agree with independent SHA-1/reference expectations. The resulting outputs are value-matched to all288 retained preparations. This is an explicit component value boundary, not one continuous emulator/native frame or an observed cache write.

For example, the independently checked declared `abc` state serializes in the BE path as:

```text
canonical state bytes: a9993e364706816aba3e25717850c26c9cd0d89d
source output bytes:  3101a6aedf9e19f222a6bde9e0c85af404484005
relation:             each byte XOR 0x98
```

Under the preceding retained-frame layout, O=F+0x3CE0 is a32-byte reservation. The selector2 writer would fill its first20 bytes, ending at F+0x3CF4;12 reserved bytes precede the derived scratch start F+0x3D00. This geometry is compatible with the earlier100-byte context and320-byte scratch layout. Same-frame continuity, native bounds and preservation remain prerequisites. O is not equated with the separate36-byte heap-cache owner.

## Common continuation and unresolved frame root

All complete serializer and zero-size cases execute the prefix at `0x100BB1574`, then stop before `0x100BB15D0` reads u64 R=load64(F+0x3050). The new traces neither define that cell nor borrow its RAM-fill marker. The following source prefix, analyzed separately under explicit saved-field premises, establishes:

| Destination, u64 | Exact source value |
| --- | --- |
| F+0x2A68 | R+0x32C |
| F+0x2A60 | load64(F+0x33C8) |
| F+0x2A28 | load64(F+0x3108) |
| F+0x2A58 | load64(F+0x2DA8) |
| F+0x2A20 | load64(F+0x34B8) |
| F+0x2A50 | load64(F+0x2C28) |
| F+0x2A48 / F+0x2A40 | R+0x11C / R+0x20F |
| F+0x2A30 / F+0x2A38 | R / R+0xE4 |

This prefix copies values and produces numeric aliases without dereferencing R. It also needs five additional saved u64 cells beyond F+0x3050. Their native producers and preservation are unknown. The earlier compression frame uses F+0x2A68/+0x2A60 as u32 count-related cells; this continuation writes u64 values there. These are phase-specific stack roles, not globally typed fields.

A bounded original-text census finds the following exact scalar unsigned-immediate SP+0x3050 accesses. No scalar32 accesses at that exact offset were found.

| Access | Sites |
| --- | --- |
| STR64 | `0x1007CFA88`, `0x100ACE980`, `0x100BDB268` |
| LDR64 | `0x100503B44`, `0x1005AFF0C`, `0x10077B24C`, `0x1008D6608`, `0x100BB15D0` |

The three source-local producer contracts are:

| Producer | Proven local effects |
| --- | --- |
| 7CFA64 prefix | U=load64(F+0x16D0); R=F+0xC070+U -> F+0x3050. Stores R+0x480/+0x490/+0x560/+0x610 into other saved cells and produces R+0x6B0 in X22. U's native role and owner bounds are unknown. |
| ACE964 prefix | X13 -> F+0x3050; W23 -> F+0x3160; byte F+0x2AA7 records exactly `W23==0x8B3DC651` |
| BDB258 prefix | X20 -> F+0x3050; W10 -> F+0x3160; byte F+0x2AA7=0 |

No continuous same-frame native path from these writers to the serializer's frontier is established. The stack-derived producer and its larger numeric aliases prevent treating this offset uniformly as the earlier872-byte heap object. Produced aliases do not themselves prove an allocation extent or a valid dereference. Paired, computed, alias, overlapping-offset and changed-frame-base accesses remain outside the census.

## Instruction-access reporting correction

Capstone5.0.7 reports conservative destination reads for these shift aliases. The new trace harness corrects only LSL/LSR destination entries that are not also explicit inputs:

| Original instruction | Reported reads | Architectural operand reads used by this harness |
| --- | --- | --- |
| BE71E4: `LSR W14,W9,#24` | W14,W9 | W9 |
| BE7218: `LSL W15,W14,#1` | W15,W14 | W14 |
| 8B6078: `LSR W8,W16,W8` | W16,W8 | W16,W8; W8 is the shift input |

The raw instructions, reported/corrected sets and writes are retained in the contract. Thirty-six isolated executions check varied source values, destination fills and shift counts, including architectural modulo32 shift amounts. No old destination value is invented to pass the trace. The symbolic byte proofs independently use instruction operands, and the frozen earlier artifacts are unchanged.

```text
saved context C / selector / size
              |
       low byte1          low byte2
       LE word bytes      BE word bytes
              +----- XOR0x98 -----+
                                 v
                         O = saved F+0x2FE0
                         16 / 20 defined bytes
                                 |
                         common prefix BB1574
                                 |
                         stop before F+0x3050 read

retained prepared block -> isolated source core -> state value -> isolated serializer
  component composition is checked; native frame/cache/IPC joins remain unknown
```

## Assumption register and bounded continuation

| ID | Premise / dependent results | Stress or falsification probe |
| --- | --- | --- |
| DO1 | Original image/fixups/current IDB identity / all source addresses | Rehash source and compare15 ranges; independently decode15 fixups |
| DO2 | Accessed frame-control/context/output/table cells are valid and do not overlap / source proofs | Defined-byte ledgers and two placements; native allocation/lifetime bounds remain open |
| DO3 | Saved mode0x471C and T root / routing | Source-lift the entry and low-byte predicates; do not assign these constants a transport role |
| DO4 | Declared selector/size pairs1/16,2/20 or zero / complete serializer contracts | All-u32 word/address proofs and bounded loop/handover proofs; other sizes/native admission remain unknown |
| DO5 | Context state uses XOR0xF4F92DF7 / output decoding | Compare actual source state reads and all byte equations; use independent endian reference |
| DO6 | LSL/LSR access correction follows explicit operands / minimal GPR traces | Preserve true same-register/variable-shift inputs;36 original-instruction executions and exact read-set records |
| DO7 | Retained CF/UTF-8 fixtures and prepared blocks are conditional models /288 input matches | Verify parent payloads, ordered effects, actual modeled byte lengths and unchanged original frontiers |
| DO8 | Core-to-serializer transfer is a value composition / six pipeline outputs | Rerun both source components; match actual core state values and independent hashes; do not infer native continuity |
| DO9 | Same F/cursor and saved output survive / retained geometry | Recompute20/32-byte intervals and scratch relation; prove native preservation/bounds separately |
| DO10 | SP+0x3050 writer/census roles are source-local / root interpretation | Trace actual predecessors and frame bases; do not infer heap-object identity or extent from offsets |
| DO11 | Five further saved fields are available / continuation-copy interpretation | Recover F+0x33C8/+0x3108/+0x2DA8/+0x34B8/+0x2C28 producers; do not fill them to continue |
| DO12 | Encoded output is not yet cache publication or IPC / architectural scope | Require actual copy/publication, emission and matching consumer evidence |

| Impact | Additional opportunity / unresolved pattern | Required next evidence |
| --- | --- | --- |
| High | The remaining frontier is an outer root/saved-field interface | Join actual SP+0x3050 producers and five saved fields with same-frame continuity |
| High | Encoded20-byte output is now identified | Follow O's actual consumer and any copy/transform into the separate cache |
| High | Native cache-to-driver linkage remains open | Join resulting bytes to known Mach/IOKit emission and matching driver input |
| Medium | Selector1 has an LE16 serializer | Recover its compression algorithm independently rather than naming it from endian/size alone |
| Medium | Saved cells change width/role across phases | Establish per-path layouts and intervening overwrite/preservation constraints |
| Low | Shift-alias metadata can create false undefined-input stops | Keep the exact operand correction and source-instruction checks local and reproducible |

Reproduction uses the pinned Python/Z3 environment from the preceding reports. Run `probe_daemon_digest_output.py`, `recover_daemon_digest_output.py`, `prove_daemon_digest_output.py`, then `validate_daemon_digest_output.py`. The verifier reconstructs proofs, checks nonempty domains, source/fixup/IDB/access records, ordered serializer ledgers, helper ABIs, selector decisions, fresh component replays and retained value matches. Time is O(source bytes + retained visits/effects + new visits/effects + solver resources); space includes compressed artifacts, one decoded/fresh component journal, one private mapping and solver expressions. Solver queries have a30-second limit; no polynomial SMT bound is claimed.

QG1: factual technical scope. QG2: DO1-DO12 with probes and dependent results. QG3: serialization/root-interface increment covered; full objective remains incomplete. QG4: explicit endianness, bytes/words, modulo widths, source versus modeled-branch counts and geometry. QG5: universal local identities, component value composition, unchanged retained stops, phase-specific roots and native publication remain distinct. QG6: original source, current IDB, rebuilt proofs, fresh traces, independent references and exact access-reporting checks support scoped claims. QG7: impact-ranked continuation table provided.
