# fairplayd: counted record-span walk and cursor/endpoint separation

Helper `0x10045f984` conditionally returns a selected record coordinate after a bounded, counted span walk. For the recovered clear-storage representation, the span and count readers now have general source contracts. The initial span must be at least 20 B. A zero count returns the selected coordinate without walking trailing spans. A nonzero count starts a cursor 20 B after the record start, reads successive span words, requires positive nonwrapping advances within the enclosing endpoint, and returns the selected coordinate only when the final cursor equals that endpoint. This supports a nested-record framing interpretation, not complete recursive validation of every nested header. Native schema and daemon-kext transaction identity remain unknown. [WAL1-WAL6; WAL-A1-WAL-A6]

This increment corrects the preceding storage report's terminology: SP+0x6c holds the encoded cursor `o+20`, whereas W25 holds the enclosing endpoint `o+p`. They coincided in every retained helper case because p=20 B. The preceding arithmetic proof remains valid for its independent input variable; calling that variable the general record endpoint was incorrect. The new producer and join proofs establish the distinction for arbitrary offsets and spans. The earlier report and its cross-references are corrected in this publication; frozen proof receipts remain unchanged. [WAL2, WAL4-WAL5]

| Evidence | Primary provenance and scope |
| --- | --- |
| WAL1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; WAL4 retains 604 instruction words, 53 immutable bank bytes and 19 original authenticated dispatch words. |
| WAL2 | [Record-selection](daemon_record_selection_report.md) and [record-storage](daemon_record_storage_report.md) reports and frozen receipts. Storage checks decoded SHA-256 `08dd5c2d5d3c14efd4ec744f35267c1d9f879d2a93c3d4ea8ca68f3c22e31337`, audit `1be9029f3b67f0d543db412982617378cae7064ff4a9ade39f503b4da5f0eac4`; exact upstream pins are in WAL4. These establish earlier availability/coordinate/span gates and the alternative halfword mask. |
| WAL3 | [Scalar-serialization report](daemon_scalar_serialization_report.md) and source-derived periodic mask; its generator and the exact D/E/K image bytes are pinned in WAL4. General contracts for the current helper's distinct reader instances are freshly proved here. |
| WAL4 | [Extractor](triage_evidence/recover_daemon_record_walk.py), [checks](triage_evidence/daemon_record_walk_checks.json.zst): six retained classes, 54 saved cells/288 B with last-writer custody, source, banks and dispatches. |
| WAL5 | [Auditor](triage_evidence/audit_daemon_record_walk.py), [receipt](triage_evidence/daemon_record_walk_audit.json.zst): 58 nonvacuous UNSAT obligations, ten scalar controls and 1,980 independently replayed instruction visits. No new execution or proof cut. |
| WAL6 | [Publication verifier](triage_evidence/verify_daemon_record_walk_publication.py): fresh extraction/audit, canonical SMT comparison, report checks, exact manifest delta, original-input preservation and decoded path hygiene. |

## Coordinates, decoder contracts and lifetime

U denotes the retained 48 B model object. Pointers and address arithmetic are u64 modulo 2^64; scalar arithmetic is u32 modulo 2^32 unless explicitly narrowed. B is the byte unit. Encoded coordinates use bias `0x89271580`: decoded offset equals `u32(encoded+bias)`. Encoded zero is `0x76d8ea80`. These are private source representations, not native protocol field names. [WAL2, WAL4-WAL5]

| Source, end exclusive | Interface or recovered contract |
| --- | --- |
| `0x10049f880..0x10049f888` | Store `u32(o+20-bias)` at helper SP+0x6c, from W23=`u32(o-bias)` |
| `0x100333948..0x1003339b8` | Initial span p>=20 selects index `0xc94c`; smaller p selects encoded-zero return |
| `0x1003209ac..0x1003209f0` | W15=`u32(o+p+0xabc03b53)` becomes W25=`u32(o+p)`; transformed halfword becomes encoded count in W26 |
| `0x1003209f4` | Reload SP+0x6c into W15: this is the cursor, distinct from W25 |
| `0x100405d98..0x100405f9c` | Clear-storage four-byte reader returns decoded scalar XOR `0x8b3dc651` in W16 |
| `0x1003cbb0c..0x1003cbd2c` | Clear-storage two-byte reader returns low16(W1)=`u16((decoded_count XOR 0x7390)+14)` |

The clear-storage readers use U+8 and the common 16 B periodic mask M retained in WAL4. For raw bytes b[j], their recovered equations are:

```
word at offset o:
    P32 = BE32(b[j] XOR M[(o+j) & 15], j=0..3)
    n   = P32 >> 27
    q   = P32 if n==0 else P32 & (2^n-1)
    W16 = q XOR 0x8b3dc651

halfword at record offset o+14:
    P16 = BE16(b[j] XOR M[(o+14+j) & 15], j=0..1)
    n   = P16 >> 12
    h   = P16 & (2^n-1)                 # n==0 gives zero
    low16(W1) = u16((h XOR 0x7390)+14)
```

Sixteen residue proofs per reader quantify all high offset bits and all raw input bits, including u32 offset wrap, while checking the actual load addresses. The word contract preserves the cursor and ten caller/loop/dispatch registers, including X0, X25, X26, X27 and X21. The zero-width cases differ: word width zero retains P32, whereas halfword width zero decodes zero. The decoded clear-storage bounds are q<=2^31-1 and h<=2^15-1. Arbitrary serialized inputs are covered; compatibility with every producer or native admission is not inferred. [WAL4-WAL5; WAL-A2-WAL-A3]

The word reader has a caller-selected continuation. Initial use supplies X27=`0x100333948`, which applies the minimum-span gate. The counted-walk use supplies X27=`0x1003fb284`, which applies positive advancement. Both pass through `0x1003ec410`: it sets IA modifier `0x352e` and branches through X27. Clear/alternative word readers are selected by flag mask 4 at U+0x28; the alternative target is `0x100357e2c`. Its general word decoder contract remains unknown. The shared control equations below apply to its abstract returned scalar q=`W16 XOR 0x8b3dc651`, but the complete byte-to-walk contract is established here for the clear-storage route. [WAL1-WAL5; WAL-A2-WAL-A4]

## Counted walk

After the earlier availability, explicit/default coordinate selection and first-bound gate, the following pseudocode expresses the recovered clear-storage behavior. Source comparisons are unsigned and modular where written; subsequent inequalities use ordinary integers only after the nonwrapping checks. The clear-storage flag and bank/phase premises must hold at every reader invocation. [WAL2, WAL4-WAL5]

```
p = read_clear_word(o)
if p < 20: return encoded_zero
E = u32(o+p)
if E <= o or E > capacity: return encoded_zero
h = read_clear_half(o+14)
if h == 0: return selected_encoded_coordinate
c = u32(o+20)
while h != 0:
    if c > 0xffffffeb: return encoded_zero
    if u32(c+20) > E: return encoded_zero
    q = read_clear_word(c)
    next = u32(c+q)
    if next <= c: return encoded_zero
    if next > E: return encoded_zero
    c = next
    h = u16(h-1)
return selected_encoded_coordinate if c == E else encoded_zero
```

```
record start o
   +-- fixed 20 B prefix --+ cursor c=o+20
                          |
                          +-> header room -> span q -> positive advance
                                               |
                          +<-- count remains --+-> next cursor <= E
                          |
                          +-> count exhausted -> c==E -> selected coordinate

enclosing endpoint E=o+p remains separate from the moving cursor
```

| Gate / source | Predicate | Accepted target | Rejected target |
| --- | --- | --- | --- |
| Cursor guard `0x1004bad90` | c+20<2^32 | `0x10063b9bc` | Encoded-zero return |
| Header room `0x10063b9bc` | u32(c+20)<=E | `0x100333920` | Encoded-zero return |
| Reader prepare/config `0x100333920`, `0x1005320f8` | U+0x28 mask4 clear / set | `0x100405d98` / `0x100357e2c` | No rejection at this selector |
| Positive advance `0x1003fb284` | u32(c+q)>c | `0x10031424c` | Encoded-zero return |
| Endpoint bound `0x10031424c` | u32(c+q)<=E | `0x1003f0f58` | Encoded-zero return |
| Count step `0x1003f0f58` | count before decrement equals 1 | `0x1004a86e8` | Otherwise repeat at `0x1004bad90` |
| Finish `0x1004a86e8` | c==E | `0x10048d3d0` | Encoded-zero return |

The count decrement is proved for arbitrary upper bits in W26: only its encoded low16 count controls the branch. For nonzero count, the decoded variant strictly decreases. The clear-storage bound permits at most 32,767 iterations; the abstract u16 control bound is 65,535. This is a source termination argument under readable cells and the stated phase/representation premises, not a timing or native scheduling measurement. Each iteration has fixed-size reader/control work: O(h) time and O(1) auxiliary space. [WAL5; WAL-A2-WAL-A4]

At a successful child step, q>0, q<=E-c, and the cursor strictly increases without wrap. The initial minimum-span and inherited parent bounds imply that the initial cursor and count field lie within the admitted parent span. They do not prove that the earlier initial word read was readable before those checks executed. Initial read validity, object consistency and alias separation remain explicit premises. [WAL2, WAL5; WAL-A2-WAL-A3]

The source does not require every child span q>=20. It requires 20 B of remaining enclosing space before each word read and a positive advance. It also does not inspect a child's count field or recurse into that child's contents. With nonzero h and successful exact consumption, the last q is at least 20 B because its preceding header-room gate and final equality imply that bound. Earlier q values may be smaller. A zero initial count bypasses the final cursor/endpoint equality check. [WAL5; WAL-A5]

## Controls, dispatch evidence and retained scope

The following controls evaluate only the recovered scalar predicates, at relative record offset zero. They contain no target byte stream, new guest input or execution witness. [WAL5]

| Enclosing span / B | Count | Successive spans / B | Scalar-model result |
| --- | --- | --- | --- |
| 20 | 0 | Empty | Selected coordinate |
| 24 | 0 | Empty | Selected coordinate; trailing extent is not checked by this branch |
| 40 | 1 | 20 | Selected coordinate |
| 44 | 2 | 1, 23 | Selected coordinate; first positive span is below 20 B |
| 19 | 0 | Empty | Initial minimum rejection |
| 20 | 1 | 20 | Header-room rejection |
| 40 | 2 | 1, 19 | Header-room rejection before the second read, despite the span sum |
| 40 | 1 | 0 | Positive-advance rejection |
| 40 | 1 | 21 | Enclosing-endpoint rejection |
| 44 | 1 | 20 | Final-equality rejection |

| Index | Target | IA modifier | Role |
| --- | --- | --- | --- |
| `0x1bc3` | `0x1004aa840` | `0xcb9a` | Initial/cursor rejection |
| `0xc94c` | `0x100470afc` | `0xcb9a` | Initial span minimum accepted |
| `0x1bec` | `0x10063b9bc` | `0xcb9a` | Cursor arithmetic accepted |
| `0xc68b` | `0x100333920` | `0x2712` | Header room accepted |
| `0xc6dd` | `0x1004aa840` | `0x2712` | Header room rejected |
| `0x25e0` | `0x1005320f8` | `0x8216` | Child reader preparation |
| `0xbff7` | `0x100405d98` | `0x43b0` | Clear-storage word reader |
| `0xc00f` | `0x100357e2c` | `0x43b0` | Alternative word reader |
| `0xc4` | `0x1003fb284` | `0x352e` | Child continuation loaded into X27 |
| `0x602d` | `0x1003ec410` | `0x143b` | Word return bridge |
| `0xa743` | `0x1004aa840` | `0xf01d` | Positive advance rejected |
| `0xb243` | `0x10031424c` | `0xf01d` | Positive advance accepted |
| `0xca3b` | `0x1003f0f58` | `0x62c0` | Child endpoint accepted |
| `0xca8a` | `0x1004aa840` | `0x62c0` | Child endpoint rejected |
| `0x3a47` | `0x1004a86e8` | `0xd137` | Last counted iteration completed |
| `0x3a61` | `0x1004bad90` | `0xd137` | Repeat counted walk |
| `0xac30` | `0x10048d3d0` | `0xfb0f` | Exact final consumption |
| `0x6993` | `0x1004aa840` | `0xfb0f` | Final equality rejected |
| `0x83da` | `0x10048d3d0` | `0xd137` | Initial zero-count return |

Original format-12 words, target indices and IA modifiers are checked against the original image and fixup decoder. Hardware authentication acceptance is unmeasured. The selected-coordinate reload and caller result store are inherited from WAL2; six newly proved rejection profiles explicitly rebuild encoded zero before dispatch. [WAL1-WAL2, WAL4-WAL5]

| Retained helper group | Cases | o / B | p / B | Initial c / B | E / B | Decoded count |
| --- | --- | --- | --- | --- | --- | --- |
| Constructor-prefix | 4 | 1 | 20 | 21 | 21 | 0 |
| Later growth | 2 | 57 | 20 | 77 | 77 | 0 |

All retained cases therefore take the initial zero-count route; none observes the nonzero walk. The 54 saved-cell checks cover cursor, reader banks and phase cells: SP+0x74=`0xca3b`, +0x98=`0x5c01a05e`, +0xa0=`0xa743`, +0x9c=`0x93f3cc4d`, +0xa4=`0x1bc3`. Independent replay checks 65,856 GP/SP values, 2,058 NZCV frames, 270 reads and 66 writes across 78 slices. Individual last-writer and larger selected slices can overlap; 1,980 counts replay visits, not unique instructions or native executions. Full upstream admission corpora are pinned rather than rerun. [WAL4-WAL5]

## Assumption register and bounded continuation

| Assumption / dependent results | Premise | Stress test or falsification probe |
| --- | --- | --- |
| WAL-A1: binary-specific addresses and mappings | Pinned image and exact instruction/fixup words | Reject source, bank, parent-pin or dispatch-word mismatch; do not transfer mappings to another build. |
| WAL-A2: source phases and reader composition | Fixed phase cells, readable separated cells, clear flag at every clear-reader invocation | Six actual phases and last writers checked; arbitrary raw-byte and high-offset proofs cover all 16 residues. Verify representation stability and initial-read admission before asserting native behavior. |
| WAL-A3: address/format interpretation | u32/u64 modular widths, fixed D/E/K banks, no overlap of payload reads with protected cells | Actual source load addresses proved, including wrap. Word width-zero and half width-zero differ; both are proved. Parent bounds after a read do not establish prior readability. |
| WAL-A4: counted-loop result and termination | Source control phases and readable words throughout the walk; cursor/end/count/continuation preserved at clear-reader calls | Arbitrary upper count bits and the decreasing nonzero u16 variant are proved. Alternative word decoder and mixed-representation handovers remain outside the complete byte-to-walk contract. |
| WAL-A5: semantic scope | Span walking and framing, without native schema or recursive validation claims | Short positive child and zero-count extra-extent controls falsify stronger validation interpretations. Retained count-zero cases are not nonzero execution evidence. |
| WAL-A6: external interface pairing | Private static coordinate and field behavior only | Recover a producer/caller epoch and matched daemon-kext bytes before assigning protocol field names or exchange identity. Native ownership, synchronization and transaction pairing remain unknown. |

| Impact | Next discriminating work | What it would establish |
| --- | --- | --- |
| High | Recover alternative word reader `0x100357e2c` and its phase-preservation interfaces | Complete alternative byte-to-span-walk contract and representation comparison |
| High | Trace U+0/U+8 and flag writers through matching caller epochs | Native representation admission, readable bounds and format stability |
| Medium | Join counted spans to producers and a matched kext-side transaction | Whether the framing corresponds to shared daemon-kext records, including child/count field identities |
| Medium | Track ownership and synchronization of global cache/table and U | Lifetime and concurrency premises that static arithmetic cannot establish |
| Low | Classify producer restrictions on short child spans and zero-count trailing extent | Distinguish broader reader domain from actual producer schema |

## Quality gates and reproduction

**QG1** passes: factual source and ABI analysis. **QG2** passes: WAL-A1-WAL-A6 identify premises, dependent claims and falsification probes. **QG3** passes for this increment: current clear readers, cursor/endpoint producers, initial minimum, full counted-loop gates, decrement, final selection and encoded-zero rejections are covered; the full investigation remains active. **QG4** passes: B extents, signed/modular widths, decoder count widths and algorithm complexity are explicit. **QG5** passes: cursor/endpoint terminology is corrected; actual zero-count traces, static nonzero contracts, field interpretation, alternative format and native gaps are distinguished. **QG6** passes: exact original image words/banks/fixups, pinned upstream receipts and fresh solver/replay evidence support the claims. **QG7** passes: impact-labeled bounded follow-up is listed.

Run the extractor, auditor and publication verifier with the repository evidence directory on the Python module path and existing Capstone/Z3 dependencies available. Extraction/replay costs O(parent receipt bytes + selected journal bytes + source words + replay visits*32); symbolic work costs O(source DAG plus solver resources), with 30 s/query limits. All 58 delivered obligations are nonvacuous UNSAT; no proof cuts, rewritten instructions, new target intervals, guest bytes, owner definitions or API-return premises are used. No native target API, IPC, filesystem operation, allocation/free, hardware PAC or IDB mutation occurs. Original primary inputs remain byte-identical. This increment establishes no new port emission or native daemon-kext exchange.
