# fairplayd: record-coordinate selection, span gates and default-field lifetime

Helper `0x10045f984` selects a supplied or default record coordinate, checks storage availability, and applies span bounds before returning the selected coordinate on the retained successful path. Four mapped gate rejections write the encoded zero-coordinate value `0x76d8ea80`. The source therefore provides more specific local evidence than the earlier generic status label. A complete function name, all return classes, native schema and daemon-kext transaction identity remain unknown. [SEL1-SEL5; SEL-A1-SEL-A6]

Under the recorded phases, the recovered arithmetic gates are:

```
o = selected byte offset; d = default byte offset
p = decoded span; C = decoded extent

first gate:    u32(o+d) < C
span gates:   u32(o+p) > o  AND  u32(o+p) <= C
```

The span gates jointly imply `o<C`, `p!=0` and `p<=C-o`, with no addition wrap. The first gate remains a separate modular comparison; it does not itself establish arbitrary multi-byte read bounds. Native input admission, all decoder domains and the complete caller epoch are not established by these equations. [SEL4-SEL5; SEL-A2-SEL-A5]

| Evidence | Primary source and scope |
| --- | --- |
| SEL1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; exact selected instruction words and original dispatch words are retained in SEL4. |
| SEL2 | [Resize-caller report](daemon_resize_callers_report.md), [checks](triage_evidence/daemon_resize_callers_checks.json.zst), decoded SHA-256 `421f899bf25a3ac563aa923545423c65aa6c2cb19ffa5ccc45aa928bb2049ac1`, and [audit](triage_evidence/daemon_resize_callers_audit.json.zst), `727dcee019edfe6bf0f49e8f3f89e138839f7b23eca502cbdf859a452d0faa3e`: coordinate representation and caller custody. |
| SEL3 | [Constructor-gate](daemon_constructor_gate_report.md), [constructor-buffer](daemon_constructor_buffer_report.md) and [descriptor-growth](daemon_descriptor_growth_report.md) journals, admissions and replay receipts. Their exact checks/replay/audit hashes are pinned in SEL4. Full prior admission corpora are not rerun. |
| SEL4 | [Extractor](triage_evidence/recover_daemon_record_selection.py), [checks](triage_evidence/daemon_record_selection_checks.json.zst): six helper cases, four initializer cases, 58-journal write census, original fixups, whole-text exact-store census and 608 exported snapshots. |
| SEL5 | [Independent auditor](triage_evidence/audit_daemon_record_selection.py), [receipt](triage_evidence/daemon_record_selection_audit.json.zst): selected original instruction replay, 16 nonvacuous UNSAT obligations and four SAT controls. |
| SEL6 | [Publication verifier](triage_evidence/verify_daemon_record_selection_publication.py): fresh extraction/audit, canonical queries, manifest delta, original-input preservation and decoded path hygiene. |

## Storage availability and coordinate selection

U=`0x6600060000` is the retained 48 B model object. Offsets and buffer extents below use B; pointers and SP are u64, scalar arithmetic is u32 unless explicitly narrowed. The six helper cases comprise four constructor-prefix classes and two later growth classes, covering 76 earlier and 304 later conditional invocations through pinned admission. These are representative model cases, not 380 native executions. [SEL2-SEL4; SEL-A3]

| Source interval, end exclusive | Fixed phase | Proven dispatch predicate | Targets |
| --- | --- | --- | --- |
| `0x1005275c4..0x100527608` | W15=`0x6968` | U+0 is zero / nonzero | Zero: `0x100534460`; nonzero: `0x1004983ec` |
| `0x100534460..0x100534490` | W2=`0x8ee5` | U+8 is zero / nonzero | Zero: `0x1004aa840`; nonzero: `0x1004983ec` |
| `0x1004983ec..0x100498420` | W1=`0x6993`; arbitrary input/bias/default data | Supplied encoded coordinate denotes zero / nonzero | Zero selects U+0x18; nonzero retains supplied coordinate |

Thus a nonzero U+0 bypasses the U+8 null check. The retained cases use U+0=0 and a nonzero U+8 pointing to T or H. The alternate U+0 representation is a source-supported interface opportunity; a complete storage type or consistency rule is unknown. The U+8-null route sets W2=`0x76d8ea80` at `0x100534494..0x10053449c` before its direct return-store dispatch. [SEL4-SEL5; SEL-A2-SEL-A5]

For encoded input q, the helper substitutes the default when q=`0x76d8ea80`; the byte coordinate is `u32(q+0x89271580)`. Default U+0x18=`0x76d8ea81` denotes offset 1. In the later case the supplied coordinate `0x76d8eab9` denotes offset 57 and overrides that default. SEL2 establishes the complete caller/result custody for the latter case. [SEL2, SEL4-SEL5]

The first gate extends through `0x10049847c`. Its unsigned comparisons and conditional select reduce to `u32(o+d)<C` for arbitrary u32 supplied/default coordinates and extent, with the stated phase and distinct fixed input cells. The true index `0x6fc3` dispatches to `0x10049f6a8`; false index `0x6993` dispatches directly to `0x1004aa840`. W2 remains the encoded zero coordinate on the false path. The retained pairs are `o=1,d=1,C=21` and `o=57,d=1,C=77`. [SEL4-SEL5; SEL-A2]

## Span arithmetic and dispatch

The successful first-gate block saves the selected coordinate at helper SP+0x68. Original `0x10049f6a8..0x10049f6e8` prepares `u32(o+0x36fe01a4)` at helper SP+0x7c and `u32(o+0x79396704)` at helper SP+0x78. Their address, width and value contracts hold for arbitrary u64 SP and u32 o. The subsequent span gate consumes exactly these saved bytes; its phase cell at SP+0x70 is `0x1bc3`. [SEL4-SEL5]

| Source interval, end exclusive | Input interface | Proven result | Dispatch / result |
| --- | --- | --- | --- |
| `0x100470afc..0x100470bc8` | W16=`p XOR 0x8b3dc651`; saved coordinate operands; phase `0x1bc3` | `u32(o+p)>o`; W15=`u32(o+p+0xabc03b53)` | True index `0x1ffb` -> `0x1003f8a58`; false `0x1bc3` -> return store |
| `0x1003f8a58..0x1003f8acc` | W1=`0xa71d`; that W15 value; U+0x14=`u32(C-0xef133bef)` | `u32(o+p)<=C` | True index `0xa71d` -> `0x10048e9f4`; false `0xa743` -> return store |
| `0x10048e9f4..0x10048ea28` | W6=`0x6ce1`; flag word U+0x28 | Flag mask `0x4` clear / set | Clear `0x6ce1` -> `0x1003cbb0c`; set `0x6ce6` -> `0x100495c3c` |
| `0x1003209ac..0x1003209f0` | W6=`0x3a61`; transformed word W1 | Low16(W1)=`0x739e` / different | Equal `0x83da` -> `0x10048d3d0`; different `0x3a61` -> `0x1004bad90` |

Both span rejection routes explicitly rebuild W2=`0x76d8ea80`: `0x100470bcc..0x100470bd4` and `0x1003f8ad0..0x1003f8ad8`. The common store `0x1004aa840` writes W2 to the caller record at X0. Generic result-store and selected-coordinate reload contracts are separately proved. Logical targets and IA modifiers are checked against the exact format-12 words and original import/rebase decoding; hardware PAC acceptance is not measured. [SEL4-SEL5; SEL-A2-SEL-A3]

```
storage available
  -> select explicit/default coordinate
  -> u32(o+d) < C ?
       false -> encoded-zero result store
       true  -> read/decode span p
                -> u32(o+p) > o ?
                     false -> encoded-zero result store
                     true  -> u32(o+p) <= C ?
                                  false -> encoded-zero result store
                                  true  -> flag-selected processing
                                           + mask4 clear -> transformed halfword check
                                           |                equal -> reload selected coordinate -> result store
                                           |                different -> further processing, result unknown
                                           + mask4 set -> alternate processing, result unknown
```

The last two alternate branches are not proved rejection or acceptance paths. In particular, target `0x1004bad90` contains further arithmetic and another dispatch. The set-mask4 branch at `0x100495c3c` reads U+0 and additional state. Their source existence extends the interface map, but neither a complete traversal algorithm nor their final result is established here. [SEL1, SEL4; SEL-A5]

## Actual buffer reads and the decoder boundary

Each retained helper case reads six buffer bytes: four at o..o+3 and two at o+14..o+15. The first group is read at `0x100405d9c/0x100405dfc/0x100405e4c/0x100405e98`; the second at `0x1003cbb20/0x1003cbb5c`. Selected replay covers the complete straight-line word reader and halfword reader/decoder. The original full parent replays qualify the intervening word decoder. A new universal word- or half-decoder contract is not claimed. [SEL3-SEL5; SEL-A4]

| Buffer / extent | o | Span bytes | Decoded p | End o+p | Two-byte field offset | Field bytes | Decoded scalar in this case |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T / 21 B | 1 | `a2b5113d` | 20 B | 21 B | 15 | `5589` | 0 |
| H / 77 B | 57 | `9e6fd1e4` | 20 B | 77 B | 71 | `0704` | 0 |

Both spans end exactly at their extent and pass the nonwrapping/end predicates. The masked halfword codec from the pinned serialization work decodes both two-byte fields to zero. Both actual helper decoders produce W1=`0x739e`, and the equality route reloads and returns the saved selected coordinate. This supports a zero-field interpretation for these cases; a general equivalence between that transformed equality and a native child-count or other semantic field remains unknown. [SEL2-SEL5; SEL-A4-SEL-A5]

The earlier span report associates record-start+14 with a count-like field. The new helper reads match that location, but two zero-valued cases do not prove a universal field type or complete traversal policy. Four SAT controls check exact-end acceptance, a zero span failing the positive gate and an end beyond the extent failing the end gate. They are arithmetic interpretation controls, not new admitted target requests. [SEL4-SEL5]

## Default-coordinate initialization and lifetime

`0x100825894` reads outer SP+0x3608=`0x6800063708`. The second STP element at `0x1008258a8` copies that word to U+0x18. A generic source obligation proves that exact four-byte copy for arbitrary data and arithmetic phase. In each of four initializer classes the value is `0x76d8ea81`; every source-read byte is inherited, with no current-interval writer. The earlier constructor interval's producer and allocation/header role are established in the alternative-header follow-up; its native epoch remains unknown. [SEL3-SEL5; SEL-A3, SEL-A6]

The write census scans 58 retained journals totaling 2,044,454 source visits. It finds 44 overlapping write events: four initializer stores and 40 one-byte cleanup writes. The latter occur in ten retained cleanup classes, descend through U+0x1b..U+0x18 and leave raw bytes `88b47aa6` before the declared free(U). These bytes belong to the cleanup fill; no post-cleanup coordinate interpretation is assigned. No overlapping mutation occurs on the retained successful continuation paths. The census is bounded to these journals, not every possible source path or native concurrent writer. [SEL3-SEL4; SEL-A3]

Fresh snapshot checks cover 76 initializer, 76 constructor-prefix, 152 successful constructor and 304 successful growth exports, totaling 608 phase snapshots. Each checks the live U/48 B owner, coordinate word, U+8 pointer and U+0x14 extent. There are 1,824 word comparisons, one u64 and two u32 values per snapshot, totaling 9,728 B. These snapshots reuse underlying conditional parents and are not 608 independent native objects. [SEL3-SEL4]

The whole-text census scans 14,849,960 B as 3,712,490 aligned words, text SHA-256 `94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e`. It finds one exact direct unsigned-immediate `STR Wn,[SP,#0x3608]`: `0x10070a320`, source W22. Indexed, paired, aliased-base and other-width stores are outside this exact opcode census. The candidate does not establish that its SP equals the current outer SP or that it supplied this inherited word. [SEL1, SEL4; SEL-A6]

## Verification and evidence limits

Independent replay checks 2,848 instruction occurrences in 118 slices, 94,912 GP/SP values, 2,966 NZCV frames, 316 read events and 66 write events. Overlapping selections count as occurrences. Sixteen nonvacuous UNSAT obligations and four SAT controls pass; thirteen original dispatch routes and their original fixup words are checked. The retained helper phases are asserted explicitly. [SEL4-SEL6]

Extraction is O(parent receipt bytes + journal visits + custody scans + text words + exported bytes) time and O(parent receipts + selected evidence + largest journal) space. Replay adds O(selected visits*32) work; proof DAG construction/storage is linear in lifted operations, excluding solver search. Queries have a 30 s limit. Arithmetic uses exact u32/u64 wrap, explicit unsigned comparisons and low16 narrowing; offsets/extents use B. Archives use `zstd --ultra -22 -q -T1` with decoded round-trip checks. [SEL4-SEL6]

No target interval, guest input, owner/root definition or API-return premise is added. No native API/IPC, target filesystem, allocation/free, hardware PAC or IDB mutation executes. The managed IDA instance inventory contained no matching fairplayd image; no unrelated database is used. No new Mach port, right disposition, emission site or native daemon-kext buffer pairing is established. Native caller/initializer epochs, the pending malloc97 result, the NULL-route S+0x30 read and the earlier node gap remain unknown. [SEL2-SEL6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SEL-A1: Pinned image, receipts and source fixups apply | Original instructions, concrete values and dispatch targets | Verify original/dependency/parent hashes, every selected word, fresh extraction and independent original fixup decoding. |
| SEL-A2: Stated phases and distinct input cells apply | Universal gate, pointer, coordinate and save contracts | Assert each retained phase, leave data arbitrary, check nonvacuity, preserve wrap and unsigned comparison, and map both gate outcomes. |
| SEL-A3: Prior conditional admissions, owners and API premises apply | Six helper cases, write continuity and 608 snapshots | Check live U ownership, field values, exact source writers and all overlapping retained writes; retain parent full replay/admission hashes and pending boundaries. |
| SEL-A4: Concrete decoded fields are separate from a general decoder contract | Span20 and zero-valued two-byte fields | Compare actual bytes with the pinned offset-dependent codec, replay selected reader/decoder instructions, assert actual transformed outputs and leave general decoder contracts false. |
| SEL-A5: Recovered gates do not define the entire routine or native schema | Function-role and alternate-path interpretations | Preserve the alternative U+0 representation, mask4 branch, mismatch continuation and their unknown final results; require other paths before assigning a complete type, traversal policy or error taxonomy. |
| SEL-A6: A same-offset source store is not a current-frame epoch proof | Earlier default-word provenance and native cross-layer scope | Enumerate the exact opcode census and excluded forms; require source-ordered frame/lifetime continuity and a matched native transaction before joining the candidate or local records to IPC. |

| Impact | Bounded continuation | Present limit |
| --- | --- | --- |
| High | Recover both U+0/U+8 storage representations and mask4-selected processing | Availability gates and alternate target are known; complete representation and access policy remain unknown. |
| High | Recover the transformed-halfword mismatch continuation and its return classes | Exact comparator and target are known; a general traversal/selection algorithm is not established. |
| High | Establish the native caller epoch and matched daemon-kext buffer transaction | Current dataflow is conditional local source evidence. |
| Medium | Join the SP+0x3608 candidate store to the inherited default word | Exact candidate and current copy are known; frame identity/lifetime continuity remain unknown. |
| Medium | Prove compact general contracts for the helper's word and halfword decoders | Selected concrete readers/decoders pass; their whole-domain reductions remain unknown. |

**QG1**: factual technical analysis. **QG2**: SEL-A1-SEL-A6 list assumptions, dependencies and falsification probes. **QG3**: storage/coordinate gates, span checks, default lifetime, actual reads and return boundaries are covered; the larger interface goal remains active. **QG4**: arithmetic widths, byte units, counts, equations and complexity are explicit. **QG5**: exact-end acceptance, wrap, alternate paths, inherited word and native unknowns remain distinct. **QG6**: original source/fixups, pinned journals, fresh extraction, independent replay, solver receipts and publication verification establish provenance. **QG7**: bounded extensions have impact labels and explicit limits.


## Alternate record-storage reader

The [record-storage follow-up](daemon_record_storage_report.md) recovers the flag-mask-4 path through U+0: two byte loads, two indexed cached u64 loads, a common eight-round masking transform and a decoded big-endian u16 zero test. It rejoins the saved-coordinate selection gate; the immediate nonzero continuation requires cursor32+20<2^32 before further processing. Shared global mask/table cells establish an architectural connection to the cached consumer, while different keys and index arithmetic preclude codec identity. Twenty-nine nonvacuous obligations, four interpretation checks, 138 independent replay visits, 24 saved-cell custody checks and seven original dispatch words qualify the increment. The alternative path is absent from retained journals. Native representation admission and daemon-kext pairing remain unknown; the counted continuation is resolved by the walk follow-up; no new port emission or native exchange is observed, and the full goal remains active.


## Counted record-span walk

The [counted-walk follow-up](daemon_record_walk_report.md) distinguishes cursor o+20 from enclosing endpoint o+p, establishes the initial 20 B minimum and proves the full clear-storage counted-span walk through exact final consumption. General word/halfword reader contracts now cover every offset residue and input bit. The source decrements a 16-bit count and rejects nonpositive, wrapping or out-of-parent advances; it does not recursively validate every nested header. Zero count can accept extra enclosing extent, and earlier positive child spans can be below 20 B. Fifty-eight nonvacuous obligations, ten scalar controls, 1,980 independent replay visits, 54 saved-cell custody checks and 19 original dispatch mappings qualify the increment. Retained cases all have count zero. The alternative word contract is established in the [subsequent reader follow-up](daemon_alternate_word_report.md); native representation admission and daemon-kext pairing remain unknown; no new port emission or native exchange is observed, and the full goal remains active.

## Alternative word reader and saved context

The [alternative-reader report](daemon_alternate_word_report.md) establishes the U+0 four-byte reader at `0x100357e2c`: four address-dependent cached-word masks, full-width big-endian u32 assembly and the common continuation interface. Its final-byte whitening cancels in assembly. It restores caller X0 from SP+0xa8 and rebuilds the phases needed by the span gates. Forty-five source proofs, four interpretation controls and 330 independent setup/custody replay visits qualify this source contract. Retained calls select the clear route; native alternative admission, cache publication epoch and daemon-kext transaction pairing remain unknown. No new port emission is established.

## Alternative header publication and immediate caller

The [alternative-header follow-up](daemon_alternative_header_report.md) establishes the three masked header-word writes, U initialization, parent-pointer store and saved return after the alternative fill. Its generic decoded words are 20, u32(X+0xeceb3944) and 1; the remaining eight record bytes retain the fill result under the same cache epoch. The earlier clear caller's source literal X=0x867a282a maps to ASCII `sean`, without proving native alternative use of that literal. U+0x20 is zero, U+0x28 has mask4 set, and published capacity/default match the allocation/header coordinate. Thirty-six source queries, 60 checked normalizer applications, 456 independent producer/store replay visits and a 1,524-instruction source composition qualify the result. Separate caller contracts reload the child/result pair and identify 0x100762e48 as the next boundary. Native caller/cache epochs, J+0x68 publication and daemon-kext pairing remain unknown; no new port emission is established and the full goal remains active.
