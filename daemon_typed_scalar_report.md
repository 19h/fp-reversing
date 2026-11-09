# Constructor type partition and eight-byte scalar writer

The selected constructor type tree admits exactly internal discriminator `0x86b4` with a 4 B payload, `0x9546` with an 8 B payload, or `0x4118` with a variable payload extent. The separate earlier allocation guard still applies. This partition is proved over all 65,536 u16 discriminator values and all u32 encoded extents under the recorded phase/frame premises. It describes the checks after allocation and header writing, not validation before every memory access. [TS1-TS4]

The previously unresolved u64 path reaches `0x1005a2c2c`. It writes eight encoded bytes at record-buffer offsets 10-17 whose clear representation is BE64(B XOR `0x2c220a381b62f9ab`), where B is the full u64 saved from constructor-entry X12 at frame+`0xa668`. The existing reader removes that XOR and therefore recovers B. The writer returns through the original common constructor finish continuation. The 12 retained private profiles exercise u32/span routes only; no u64 construction, native call completion or daemon-kext transport is observed. [TS1-TS8]

Evidence: [source, constants, liveness, fixups and frozen occurrences](triage_evidence/daemon_typed_scalar_source.json), [90-query certificate](triage_evidence/daemon_typed_scalar_checks.json), [extractor](triage_evidence/recover_daemon_typed_scalar.py), [validator](triage_evidence/validate_daemon_typed_scalar.py), [preservation](triage_evidence/daemon_typed_scalar_delivery.json), [scoped gates](triage_evidence/daemon_typed_scalar_quality_gates.json). Adjacent contracts: [constructor input/allocation join](daemon_constructor_inputs_report.md), [header/u32 codec](daemon_header_codec_report.md), [lookup/replacement/retirement](daemon_constructor_lookup_report.md), [reader](daemon_xpc_records_report.md). Reference files sufficed; no new IDA access or mutation, target execution, emulation, native API or IPC request occurred.

| Evidence | Exact scope |
| --- | --- |
| Original thin image | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Fresh capture | 15 fragments, 1519 instructions, 6076 B; 14 original pointer records |
| Constant and liveness provenance | Ten four-instruction literal groups; 17 liveness intervals; source key-preservation checks across prior header helpers and selected type path |
| Prior recapture | 28 ranges, 7048 B |
| Static certificate | 90 UNSAT queries; 1815 translated instruction instances, 1780 SSA definitions |
| Codec components | Eight seed, 56 round and eight byte-selection lemmas; literal-origin and whole-writer cut composition queries |
| Frozen occurrences | 12 profiles; 36 u32 routes, 24 span routes, zero u64 routes or failure-frontier entries in this corpus |
| Altered controls | Ten source/constant/liveness/fixup/event/count/native-label alterations rejected |

Addresses are original unslid VAs. Hexadecimal offsets/constants have `0x` prefixes; extents use B. u16/u32/u64 denote exact bit widths, with modular integer operations. K denotes the shared-core frame. These are flattened private control interfaces, not public C prototypes. The compatible core phase is `0x6cf4`; the actual native producer of that phase remains unknown.

```text
entry fields -> allocation guard -> allocations -> 10 B header
                                                      |
                                                      v
                                       sign-extended u16 type tree
                                         /           |          \
                                     u32,4 B      u64,8 B       span
                                        |             |          |
                                     word writer   u64 writer  byte loop
                                        \             |          /
                                         +------------+---------+
                                                      |
                                                 common finish
                                                      |
                                          lookup / append / replace
```

## Complete selected type/extent partition [TS1-TS4]

Entry `0x100700d80` saves T/u16 at K+`0xa65e`, encoded extent E/u32 at K+`0xa660`, V/u32 at K+`0xa664`, B/u64 at K+`0xa668`, and span source S/u64 at K+`0xa670`. The saved type is loaded with LDRSH at `0x1008ecb94` and stored as sign-extended u32 at K+`0x978`. The prior extent relay supplies the same E at K+`0x988`.

Let `P=E XOR 0x8b3dc651`. The earlier selected allocation guard requires `P<=0xfffffff5`, so the mathematical requested allocation N=P+10 B fits u32. Under that guard and successful normal allocations/header construction, the type tree has this exact acceptance table:

| Internal T | Wire tag T XOR 0x11c3 | Accepted P | Source of scalar/span operand | Selected destination |
| --- | --- | --- | --- | --- |
| `0x86b4` | `0x9777` | Exactly 4 B | V from K+0xa664, relayed to K+0x8f8 | `0x100534f24`, u32 word-writer caller |
| `0x9546` | `0x8485` | Exactly 8 B | B from K+0xa668, full 64-bit load | `0x1004cdd70`, u64 writer caller |
| `0x4118` | `0x50db` | 0..4294967285 B under the earlier guard | S from K+0xa670 | `0x1004c1dd4`, established span count gate |
| Every other u16 T | Remaining wire tags | No accepted extent | No successful type branch established | Common failure frontier |

The u32 gate tests E=`0x8b3dc655`, while the u64 gate tests E=`0x8b3dc659`. These are exactly P=4 and P=8, not independent length codecs. The u64 gate directly reloads K+`0xa660`; the u32 gate reloads the earlier relay K+`0x988`. Their common entry-field provenance is established in the prior constructor report and recaptured here.

| Site | Exact source predicate / role | Original table index(es) |
| --- | --- | --- |
| `0x1004f4bc4` | s16(T) < s16(0x9546) | True 0x6f57; false 0x6f0f |
| `0x100609b18` | Exact T=0x86b4 | Match 0xc0cd; other 0x53c3 |
| `0x1005e72c4` | s16(T) < s16(0x4118) | True 0x24e6; false 0x24aa |
| `0x100546360` | Exact T=0x9546 | Match 0x53aa; other 0x53c3 |
| `0x10058ac54` | Exact low16 T=0x4118 | Match 0x64ae; other 0x53c3 |
| `0x1005c96d4` | Exact E=0x8b3dc655 | Match 0xc864; other 0x53c3 |
| `0x10079d560` | Exact E=0x8b3dc659 | Match 0xcb61; other 0xa1c8 |

The signed thresholds are structural: sign extension changes the ordering of `0x86b4` and `0x9546` relative to `0x4118`. An unsigned translation of these comparisons would produce a different tree. The proof composes the actual translated table-address expressions, not a classification inferred from three sample tags. Source checks cover all 2^48 combinations of T/u16 and E/u32 symbolically. They do not prove that every admitted combination is reachable from an external request.

Invalid-tag gates supply raw W6=`0x74c29d88`; the wrong-scalar-extent gates supply W6=`0x74c29d8f`. Those instructions also execute on their successful branches, so the raw assignments alone do not mean failure. The selected cleanup branches carry them to `0x1008c3528`: invalid tags use intermediate `0x100544fd0`; the u64 size failure reaches cleanup through index `0xa1c8`. Cleanup's first instruction snapshots X6 into X25. Their public error meanings and subsequent full cleanup/return behavior remain unknown.

## U64 caller and saved-value join [TS1-TS5]

At `0x1004cdd70`, the compatible input W14=`0x6cf4` produces the following exact private call interface:

| Operand | Value / source |
| --- | --- |
| X1 | `K+0xa668`, address of the entry's full u64 B |
| X14 | `K+0x38a0`, address of the newly allocated node-pointer cell |
| X16 | `0x56b0cedea8e1a866`, scalar pre-XOR constant |
| W0 | `0x134c`, continuation selector |
| Writer dispatch | Index 0x7d2d -> `0x1005a2c2c`, IA modifier 0x14ad, address diversity zero |

The writer loads NODE=[X14] at `0x1005a2c2c`, BUF=[NODE+0x18] at `0x1005a2c30`, and B=[X1] at `0x1005a2c54`. At `0x1005a2c58`, X16 becomes B XOR `0x56b0cedea8e1a866`. It resolves table[0x134c] into X0 at `0x1005a2c60`; that original fixup targets common finish `0x1005ae7a0` with IA modifier `0xd08c`.

Source liveness checks establish that X14=BUF survives to the final store, X16's scalar value survives until the phase reload, and X0's resolved continuation survives to the exit. Four separately defined high-byte slices also survive their respective mask calculations. The literal key X20 left by the final header-word helper survives that helper's tail and the selected type/call path. These facts close specific register joins; they do not establish native heap/frame validity or authenticated control transfer.

## Eight-byte codec [TS1-TS6]

For j=0..7 and A=BUF+10+j, the exact source contract is:

```text
wire = B XOR 0x2c220a381b62f9ab
BUF[10+j] = BE64_byte(wire,j) XOR m(A)
```

The common mask m(A), also used by the established payload producer/serializer and word decoder, has this canonical u64 form:

```text
s = ROR64(A & ~7,8) + 0x622c5d3364e5d59f
x = s XOR 0xa7bebfcf1750d389
y = s XOR 0xb6dc5654307e7f72
for q in [0x324a764c67af2e0e, 0xe70987b7a1f527b0,
          0x9032dc5079388982, 0x144db9b1af6b5721,
          0xeb8e58819a88bf30, 0x7faaf81a732f68b4,
          0x4f99108510ad96e0]:
    x = (ROR64(x,8) + y) XOR q
    y = ROR64(y,61) XOR x
m(A) = (x >> (8 * (A & 7))) & 0xff
```

All additions/rotations/XORs in the state are u64. The last y update is unused. Each byte has an independent exact source seed, seven arbitrary-state round lemmas and a selection/store lemma. The seed proofs hold for every u64 A; no guessed user-space address range or fixed alignment of BUF is used to normalize the masked seed expressions.

| Payload offset / B | Store PC | Byte XOR applied after the initial X16 pre-XOR |
| --- | --- | --- |
| 10 | `0x1005a2e4c` | 0x7a |
| 11 | `0x1005a2f2c` | 0x92 |
| 12 | `0x1005a3098` | 0xc4 |
| 13 | `0x1005a3228` | 0xe6 |
| 14 | `0x1005a3390` | 0xb3 |
| 15 | `0x1005a34b4` | 0x83 in the emitted low byte |
| 16 | `0x1005a35c8` | 0x51 |
| 17 | `0x1005a37c0` | 0xa9, plus the mask-word delta described below |

The final byte's seventh-round word differs from the canonical word by uniform XOR `0x6464646464646464`. Its selected mask byte therefore differs by 0x64. Combining this with the final 0xa9 byte XOR gives 0xcd. The complete source correction is consequently `0x7a92c4e6b38351cd`; XOR with the incoming pre-XOR constant gives `0x2c220a381b62f9ab`. Treating the final byte's intermediate word as canonical without its delta would yield an incorrect low byte.

A separate whole-writer query translates all instructions before the final BRAA and substitutes eight final mask-word cuts justified by the seed/round lemmas. It proves all eight exact store addresses/bytes and outgoing phase/continuation together for arbitrary B/u64, BUF/u64 and independent canonical word states. It is a compositional source certificate, not target execution or a native byte-memory/lifetime proof. The arbitrary canonical words are instantiated by m(A) only through the preceding source lemmas.

The existing serializer removes m(A) from each node byte. It therefore emits BE64(B XOR `0x2c220a381b62f9ab`); the reader's scalar XOR recovers B exactly. The 8 B scalar route has a conditional requested record extent of 18 B under the prior allocator/header agreement. All scalar values, including values with nonzero high 32 bits, are in the symbolic proof domain; this is not a low32-only result.

At `0x1005a37c4`, the writer reloads core frame+`0x9d0`, sets X22 to that value and transfers via X0 at `0x1005a37d0`. Under the recorded core epoch, X16/X22=`0x6cf4`, matching the common finish's input contract. The existing finish then performs lookup and append/replacement. Native continuation acceptance and successful final constructor return remain conditional on the adjacent contracts and owner/call premises.

## Frozen occurrences and complexity [TS7-TS8]

The selected original-build corpus contains 12 successful private send profiles. In each, the discriminator tree is entered five times: three u32 routes and two span routes. Across the corpus there are 36 u32 and 24 span routes, zero u64 writer entries and zero entries to the captured failure frontier. These are counts in this corpus only, not a census of all callers or builds. Authenticated transfers were bypassed by the historical private model. No new profile, malformed fixture or native request was executed.

The scalar writer uses a fixed eight-byte, seven-round calculation: O(1) time and O(1) scalar space independent of B. A span retains O(P) copying time under its separate contract. First-match lookup later takes O(k) time for k examined candidates, under finite stable acyclic-list premises. Source extraction is O(image/fixup bytes + frozen profile bytes); translation is O(selected instruction instances). Bit-vector solving has separate solver complexity and a 15000 ms per-query timeout.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| TS1 | Pinned thin build, original bytes/fixups and recorded pointer roots; all source roles | Rehash/recapture image, literals and fixups; changed build or target invalidates address-specific transfer |
| TS2 | Compatible core epoch0x6cf4, phase relay values and continuation state; selected type tree/caller/return joins | Establish actual incoming producers and compare frame epoch; another phase is not covered |
| TS3 | Stable saved frame fields and valid nonaliasing frame/node/buffer owners; field and store effects | Establish concrete roots, extents and aliases; source equations alone do not validate native addresses |
| TS4 | Earlier allocation guard and normal allocation/header path; combined admissible extent and 18 B u64 record | Retain P<=0xfffffff5 and actual allocator lineage; type admission alone does not prove allocation success |
| TS5 | Literal-key origins and certified register liveness across helpers/selected path; compact codec composition | Recapture write sets and carried values; a clobber invalidates the affected component stitch |
| TS6 | Final-word cuts are instantiated by their seed/round lemmas at the exact byte addresses; whole-writer composition | Recheck all eight cuts, last-byte XOR64 delta, store PCs and BE64 extraction; independent byte/slice/address checks expose a wrong stitch |
| TS7 | Frozen private event ledgers accurately retain the named corpus; occurrence counts only | Recount target sites and profile identity; injected target/count/native-label alterations are rejected |
| TS8 | Shared representation is not proof of native routing, ownership, PAC or daemon-kext pairing | Requires independent native caller/receiver and matching selector/message/right evidence; no such observation is added here |

## Bounded continuation

| Impact | Remaining interface question |
| --- | --- |
| High | Native phase, saved-field and allocator/owner provenance for the selected typed constructor and scalar writer |
| High | Original upstream u64 caller roots and application-specific field meanings; this route alone does not identify them |
| High | FairPlayIOKit selector26/RPC502/700 native caller/receiver pairing and concrete Mach rights; no new port emission is established |
| Medium | Cleanup after0x1008c3528: preserve distinct invalid-tag/extent markers while recovering release and return contracts |
| Medium | Relate every external parser/adaptor's admitted records to constructor inputs; matching wire formats alone does not prove a complete caller join |
| Low | Distinguish unsigned wire tags from signed internal type-order comparisons in future annotations |

## Scoped quality gates

QG1: No normative conclusion is required; the increment concerns source contracts and evidence bounds.

QG2: TS1-TS8 enumerate premises, dependent results and falsification probes.

QG3: Selected full-u16 discriminator partition, scalar extent gates, u64 operand/codec/return, failure-entry marker preservation and finite occurrence counts are covered. Broad IPC/native interface completion remains unproved.

QG4: Exact widths, BE64/BE32 order, B extents, modular arithmetic, rotations, universal domains and complexity are explicit and reproducible.

QG5: Signed ordering, post-header admission, gate markers on successful branches, scalar high halves, last-byte delta, source cuts and absent u64 observations are reconciled. Full cleanup and native joins remain explicitly unknown.

QG6: Original-source recapture, fresh fixups, literal origins, liveness, frozen event recount, 90 UNSAT queries and ten altered controls provide scoped primary provenance. Memory supplies build/evidence-boundary guidance only.

QG7: Bounded high/medium/low continuations retain native owner, upstream caller and daemon-kext endpoint obligations. No target/native effects or full-goal completion are claimed.
