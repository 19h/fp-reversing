# Terminal result words, paired private views and LOCAL publication

Under the retained request/root contracts, the flag1 source path writes exactly 32 bytes to LOCAL, then stores raw result code 0x8b3dc651 at REQUEST+0. The flag0 path instead writes two 32-byte private views, sets flag1/parity0, and reaches the even32-byte import interface. Eight exact big-endian output-word identities and 32 matched-input byte identities recover the serializers' compact representations. Native execution, buffer ownership/extent/alias policy, whole algorithm and matched daemon/kext transport remain unknown. [RP1-RP8]

Evidence: [original source, fixups and guard import](triage_evidence/daemon_mode_one_result_publication_source.json.zst), [proofs, word identities and store ledgers](triage_evidence/daemon_mode_one_result_publication_checks.json.zst), [extractor](triage_evidence/recover_daemon_mode_one_result_publication.py), [validator](triage_evidence/validate_daemon_mode_one_result_publication.py), [preservation](triage_evidence/daemon_mode_one_result_publication_delivery.json), [quality gates](triage_evidence/daemon_mode_one_result_publication_quality_gates.json), [sealer](triage_evidence/seal_daemon_mode_one_result_publication.py), [publication audit](triage_evidence/verify_daemon_mode_one_result_publication_publication.py). Context: [private-view import](daemon_mode_one_even_view_import_report.md), [state commit and reentry](daemon_mode_one_secondary_reentry_report.md), [LOCAL/request root](daemon_mode_one_record_checkpoint_report.md), [parity adapters](daemon_mode_one_parity_state_adapters_report.md), [interface ABI](interface_abi_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original image | fairplayd.arm64e, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Current source | Eight ranges; 10,711 instructions /42,844 B; 10,704 nonbranch source sites translated |
| Prior recapture | Twenty-six ranges /110,464 B |
| Accepted results | 37 UNSAT /three abstract SAT;13 predecessor propositions replayed |
| Original control | Eight source/slot/modifier bindings and eight authenticated records |
| Guard provenance | One additional unauthenticated import record, independently decoded from original bytes/import table |
| ISA checks | 538 UMULL, 14 UDIV, 264 bitfields, 11 register-LSR, two EON and one immediate TST: 830 checks |
| State materialization | 149 literal private u32 stores;14 source-proved nonzero UDIV denominators 962 |
| Serializer geometry | 64 private-view bytes; 32 LOCAL bytes;one request-result u32 store |
| Value recovery | Eight exact big-endian word identities; 32 matched-input view/LOCAL identities |
| Integrity | Eight altered source, target, ISA, guard, lineage and native claims rejected |

F denotes the private frame; offsets/extents are bytes. Scalar arithmetic is modular u32/u64 and byte values are u8. FLAG0/FLAG1 refer to FLAG's low bit, except where the serializer writes literal u32 value 1. Stable coherent nonwrapping mappings and no outside mutation remain premises. LOCAL32 is assumed disjoint from the private frame for stable field reads during serialization. REQUEST/LOCAL ownership, writable extents and their mutual alias policy remain unknown. These source contracts do not establish execution on a native request. No target execution/emulation, target API/IPC request, new IDA access, IDB change or hardware PAC/RETAB test occurred. [RP1-RP4,RP8]

## Complete terminal materialization and two serializer targets

The 9,241-instruction body at `0x100d183e8..0x100d2144c` is now fully translated through its final dispatch. It is reached directly from the preceding update when FLAG bit0=1, or through the flag0 upper-bound gate. That update proves incoming W2=FLAG AND 1 and F738=0xb55a. The gate preserves W2. These caller contracts are replayed. [RP1-RP3]

The body saves W2 at F6d0 and preserves FLAG and F738. Original-source queries prove:

```text
u32[F434] = 0x6012
u32[F6d8] = 0x40d0
u32[F6d0] = FLAG AND1
u32[F738] = 0xb55a

FLAG bit0=0:slot 0xb55a ->0x100c86898
FLAG bit0=1:slot 0xb578 ->0x100bf6f60
IA diversity 0x0ead
```

The closing source shifts F6d0 by 1, inserts FLAG bit0 at bit 5, and XORs that word with F738. The caller binding restricts the added bit pattern to 0 or 0x22. An unrestricted F6d0 interpretation would lose this exact two-target interface. [RP2-RP4]

There are 718 loads and 149 u32 stores: 165 frame reads, 552 computed byte lookups and one dispatch read. One of the frame reads is the literal byte at F+a36; the complete byte-read census is 553. The 14 UDIV denominators are universally 962 under the caller contract. Computed byte-address bounds, lookup values and post-mutation table validity are not newly proved. Complete decoded arithmetic and an algorithm identity remain unknown. [RP3-RP4,RP8]

The EON at 0x100d19750 complements its operand after the 32-bit LSL4, then XORs it with the other register. The local lowering handles this shifted form, and the original encoding is independently checked. The immediate TST at 0x100d1f3d4 tests mask 0x40000 without a GPR write; its logical-immediate encoding and source EQ/NE role are explicit. These corrections concern the source model, not an observed target run. [RP1,RP4]

## Flag0 serializer: two views and an explicit phase change

The 625-instruction serializer at `0x100c86898..0x100c8725c` writes every byte in each half-open interval exactly once:

```text
view A: [F+0x1100,F+0x1120)
view B: [F+0x1150,F+0x1170)
```

Its 61 SP-alias byte stores have retained original-address records. Three further stores use saved roots or computed indices. Fresh original-source proofs establish:

| Store PC | Exact destination |
| --- | --- |
|0x100c86a68|F+0x115c|
|0x100c86ac8|F+0x1100|
|0x100c86ba4|F+0x1109|

The saved roots are F368=F+1150 and F370=F+1100. Only after proving these three original addresses does the coherent model normalize them to literal frame bytes. All 64 byte values and their chronological store PCs remain in the ledger. The two views are private representations of the serialized state; no native allocation owner is inferred from their addresses. [RP2-RP4,RP6]

Seven additional u32 stores update scalar fields. The control handoff is universally:

```text
u32[F4f8] = 1
u32[F4b4] = 0
u32[F708] = 0xc83d
W11 = 0                         // reloaded from F4b4
slot 0x40d0 ->0x100b6fe00
IA diversity 0x465a
```

F748 is a data epoch here. A zero valuation produced 0, but the corresponding constant proposal has a retained abstract SAT counterexample. No zero premise is imposed on the word subsequently reloaded by the dispatcher. [RP3-RP5,RP7]

## Flag1 serializer: LOCAL bytes and request result

The 311-instruction block at `0x100bf6f60..0x100bf743c` performs 32 byte stores. Their exact destinations are LOCAL+0 through LOCAL+31, each written once. The chronological offsets are:

```text
0,4,12,8,16,1,20,24,9,28,5,17,13,21,25,29,
2,6,10, 14,18,22,26,30,3, 11,7,15,19,23,27,31
```

The saved encoded pointer is `u64[F350]=LOCAL+0x2c238c16ca76f3a8`; the serializer's pointer biases cancel this encoding modulo 2^64. The retained request checkpoint establishes `LOCAL=u64[REQUEST+0x18]`. The odd adapter restores the encoded root from F358. Pointer arithmetic alone establishes neither ownership nor writable extent. All 11 register-LSR encodings are independently checked. [RP2-RP4,RP6]

Define D0 through D7 as the eight big-endian u32 words occupying consecutive four-byte groups in LOCAL. The original store bytes universally equal these compact identities, evaluated at serializer entry:

| Word | Exact u32 expression |
| --- | --- |
| D0 | F6f8 XOR F710 XOR 0x11413f3d |
| D1 | F6e8 XOR F720 XOR 0x1490b20e |
| D2 | F718 XOR F730 XOR 0x2dc184b7 |
| D3 | F6cc XOR F6e0 XOR 0xbda713ff |
| D4 | F6f0 XOR F728 XOR 0xc4ba655f |
| D5 | F6c0 XOR F6c8 XOR 0xc7211506 |
| D6 | incoming W23 XOR incoming W27 XOR 0x9af50c1f |
| D7 | incoming W3 XOR incoming W30 XOR 0x4136483d |

Here Fxxx in the table denotes the u32 field value, and incoming W registers denote their low 32 bits. One original-source certificate compares all eight packed words against these expressions. Eight words and a 32-byte output do not identify the complete algorithm. [RP3-RP4,RP7-RP8]

After the stores, outgoing W9 is `0x8b3dc651`. Slot 0x6012 selects `0x100d7cc50`, IA diversity 0x8041. The two-instruction prefix loads REQUEST from F388 and stores W9 as a u32 at REQUEST+0. This is a raw result code; its consumer-defined meaning remains unknown. [RP2-RP4,RP8]

The independently hashed 17-instruction return region spans `0x100d7cc50..0x100d7cc94`. Following the result store, it loads the saved canary, dereferences `___stack_chk_guard`, compares, and conditionally branches to 0x100d7cc94. The restore path reaches RETAB at 0x100d7cc90. Only the two-instruction result prefix is included in the symbolic publication theorem. Canary equality, hardware authentication and native return are unproved. The original guard slot 0x1010b1e18 contains raw 0x40080000000000e5: an unauthenticated bind of import ordinal 229, independently checked against the original import table. It is distinct from the eight authenticated dispatch records. [RP1-RP4,RP8]

## Matched-state representation and the next even import

For the same serializer input fields and registers, every byte index j in [0,32) satisfies:

```text
viewB[j] XOR viewA[j] = LOCAL_serializer_byte[j] XOR 0x2f
```

The source proof checks all 32 identities without sampling. The actual flag0 and flag1 phases use different state values. This identity therefore compares the encoders on matched input state; it does not equate a first-pass view with the final second-pass output. Combining the identity with the retained view-copy contracts gives, for bytes actually copied:

```text
plane0 = viewB XOR 0xf9
plane1 = viewA
plane0 XOR plane1 XOR 0xd6 = matched LOCAL_serializer_byte
```

The constant follows from 0x2f XOR 0xf9 = 0xd6. Actual refresh-tail values, decoded padding and the whole recurrence remain unproved. [RP2-RP4,RP7-RP8]

The actual composed flag0 handoff closes the prior flag/progression-entry gap. Views select the parity dispatcher at 0x100b6fe00 with parity 0; its slot 0xc83d reaches the even adapter at 0x100be0eac. That adapter restores X0=F+0x1100, copies the encoded F+0x1150 root from F300 to F360, and preserves encoded LOCAL at F350. Setup at 0x100d74e68 receives the serializer's literal flag1 and selects slot 0x9654, reaching the skip block at 0x100dc4288. The original-source composition establishes:

```text
u32(F4a4-F4ac+0xdf8b76a4) = 32
u32(F4a4+0x8cca81ed) = 96
F4a8 = F4ac
F380 = F+0x1100
u64(F360+0xf00f12f95e107577) = F+0x1150
F350 remains encoded LOCAL
```

The skip reaches slot 0x34d0 / 0x100c62f48 with W19=0x4a62f57c, W13=0x4923, W27=0x2dd9b66a, W7=0xb4, W20=0xd6, X0=F+0x1100, X21=F+0x8b0 and X6=TABLE. FLAG=1 and parity=0. The generic even/setup theorem permits arbitrary incoming W20 reloaded from F748: the count 32 and encoded suffix component 96 do not depend on treating that field as zero. This is a static bridge to the previously proved initial even import, under the retained root and mapping contracts. It is not evidence of native arrival. [RP2-RP5,RP8]

## Effects, external control and evidence boundary

The source models retain every translated nonbranch site and memory effect. Read and store byte counts below sum instruction widths; they are not counts of distinct addresses.

| Model | Nonbranch sites | Loads | Stores | Read bytes | Store-effect bytes | Literal/normalized frame stores |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| materialize | 9240 | 718 | 149 | 1225 | 596 | 149 |
| views | 624 | 36 | 71 | 160 | 92 | 71 |
| LOCAL | 310 | 16 | 32 | 76 | 32 | 0 |
| dispatch | 18 | 4 | 1 | 24 | 4 | 1 |
| even | 293 | 22 | 12 | 108 | 52 | 12 |
| setup | 199 | 5 | 15 | 28 | 64 | 15 |
| skip | 18 | 4 | 1 | 24 | 4 | 1 |
| status prefix | 2 | 1 | 1 | 8 | 4 | 0 |

The translated ranges contain no SP writes. LOCAL writes precede the request-result write. Stable private field reads require LOCAL's 32-byte destination to be disjoint from the private frame. REQUEST/LOCAL overlap is not resolved; the final request store could alter overlapping output bytes. The proofs do not establish native mappings, caller allocation sizes or external mutability. Computed byte reads are abstract u8 values where current address/value validity has not been proved. Abstract SAT results witness model valuations, not native executions or vulnerabilities. [RP3-RP4,RP6-RP8]

There are no direct Mach sends, receives, right transfers, port allocations or target API calls in these captured source ranges. Consequently this increment identifies zero port-emission sites and no new incoming/outgoing port. The source shows private representation changes and writes through a retained request-derived pointer. Whether a consumer copies these bytes into a daemon reply or an IOKit argument remains unknown. The earlier interface reports retain the broader port and architectural inventories. [RP1-RP2,RP8]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| RP1 | Pinned image and source encodings match the analyzed build; all source claims depend on this. | Rehash image, recapture bytes, independently decode the 830 recorded ISA cases; reject any mismatch. |
| RP2 | Retained caller/root/dispatch contracts compose at the stated boundaries. | Replay 13 predecessor propositions, compare original slots/modifiers/import records, and recapture all 26 predecessor ranges. |
| RP3 | Coherent nonwrapping mappings, stable relevant memory and stated disjointness hold for execution. | Examine caller extents and ownership; an unmapped access, wraparound, outside write or LOCAL/private-frame overlap invalidates native applicability. |
| RP4 | The recorded instruction lowerings model the used ARM semantics and memory widths. | Independently check shifted EON, immediate TST, bitfields, UDIV and register shifts; mutate source/ISA evidence and require rejection. |
| RP5 | Control claims use the proven caller FLAG relation and actual serializer handoff. | Allow arbitrary reloaded W20; retain the SAT refutation of F748=0; changing FLAG or F6d0 outside the caller contract invalidates the two-target inference. |
| RP6 | LOCAL denotes the request-derived root; stable publication additionally requires writable extent and appropriate alias policy. | Trace REQUEST+0x18 ownership/extent and REQUEST/LOCAL overlap in callers; arithmetic cancellation alone cannot supply those facts. |
| RP7 | Word/view identities compare the stated entry values and matched state. | Compare all eight packed words and 32 bytes universally; using different phase states falsifies the proposed cross-phase equality, which is not claimed. |
| RP8 | Conclusions are bounded static contracts, with no native, algorithm-identity or transport inference. | Establish actual caller/consumer and normal return before promoting claims; reject altered native/lineage assertions in the validation harness. |

## Bounded continuation

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High | Caller and consumers of REQUEST+0, REQUEST+0x18 and LOCAL's 32 bytes | Result-code interpretation, external exposure and any concrete daemon/IOKit transport linkage. |
| High | Full eight-word recurrence plus current lookup-byte address/value validity | Algorithm identity and whether all 552 computed byte reads remain within established tables after state mutation. |
| High | Actual even refresh-tail representation using the matched-state decoder constant 0xd6 | Decoded tail and padding, before promoting the initial import proof to whole-operation claims. |
| Medium | Caller allocations, alias contracts and canary/return path | Writable extents, stable final output and conditions for normal return. |

## Scoped quality gates

- QG1: Descriptive source and interface analysis; no normative conclusion is required.
- QG2: RP1-RP8 enumerate assumptions, dependent results and falsification probes.
- QG3: This increment covers source/function, dispatch, data/control flow, result publication, external-control boundaries and the absence of direct port emissions in the captured ranges; whole-goal questions remain explicit.
- QG4: Byte extents, effect counts and modular u8/u32/u64 identities are reproducible from original-source ledgers and SMT queries; no physical-unit calculation is involved. Extraction/audit cost is O(B) time in input bytes and O(I) retained instruction/effect records. Each finite serializer ledger is O(32); bit-vector solving has exponential worst-case Boolean complexity and uses a 45,000 ms solver timeout with a 50 s process limit.
- QG5: The sampled F748 constant is explicitly refuted; matched-state encoder equivalence is separated from different-state phase execution, and alias/canary limitations remain explicit.
- QG6: Pinned original bytes, fixups/imports, 830 ISA checks, 37 UNSAT results, three abstract SAT results, 13 predecessor replays and eight rejected alterations provide scoped provenance. Preservation and publication audits separately verify artifacts and links.
- QG7: The impact-ranked continuation identifies unresolved recurrence, ownership, return and cross-layer consumer questions without treating them as established findings.

The result consumer now uses LOCAL32 as a verification candidate against an address-decoded first-key span, then rejoins the known option parser or retries another inline object source. This closes the local consumer question under normal-return/zero-delta premises; external serialization and native execution remain unknown. [Caller output verification and retry](daemon_mode_one_output_verification_report.md).
