# fairplayd: storage-selector production, admission gates and byte custody

The representation flag used by the recovered record readers now has a source-derived producer on the retained conditional constructor path. A pointer, a pointed u32 and a separate tag determine whether the selector byte at outer SP+0x662f is written. The retained inputs are P=J+0x1c, pointed word 6 and tag `0x4e40e176`; they produce byte 1. That byte remains defined and unchanged through the intervening allocation, emitter and table-processing stages. The later initializer maps nonzero to U+0x28=`0xd299e642`, whose mask 4 is clear. This explains clear-reader selection in the retained cases without assuming a direct public request flag. The earlier native initializer/caller epoch, alternative constructor completion and daemon-kext transaction pairing remain unknown. [FLG1-FLG6; FLG-A1-FLG-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| FLG1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. FLG4 retains 135 source instruction words, eight original authenticated dispatch words and nine candidate-site contexts. |
| FLG2 | [State-container construction](daemon_state_container_construction_report.md), [allocation cascade](daemon_state_allocation_cascade_report.md), [emitter completion](daemon_state_emitter_completion_report.md), [table mixing](daemon_state_table_mixing_report.md), [table consumer](daemon_table_consumer_report.md) and [conditional initializer](daemon_constructor_gate_report.md). Frozen checks/audits and exact hashes are pinned in FLG4. These supply existing source/ABI admissions, not native observations. |
| FLG3 | [Record-selection](daemon_record_selection_report.md), [counted-walk](daemon_record_walk_report.md), [alternative halfword](daemon_record_storage_report.md) and [alternative word](daemon_alternate_word_report.md) contracts. Their pinned receipts define the reader interfaces and the successful object exports projected here. |
| FLG4 | [Extractor](triage_evidence/recover_daemon_storage_flag.py), [checks](triage_evidence/daemon_storage_flag_checks.json.zst): 76 constructor cases, input custody, selector persistence, 456 phase snapshots, 608 object views and bounded original-text census. |
| FLG5 | [Auditor](triage_evidence/audit_daemon_storage_flag.py), [receipt](triage_evidence/daemon_storage_flag_audit.json.zst): 16 nonvacuous UNSAT source obligations, eight scalar controls and 4,916 independently replayed instruction visits. Zero proof cuts. |
| FLG6 | [Publication verifier](triage_evidence/verify_daemon_storage_flag_publication.py): fresh extraction/audit, canonical SMT comparison, report assertions, exact manifest delta, original-input preservation and decoded path hygiene. |

## Private inputs and source decision

Widths are u8/u32/u64, with arithmetic modulo 2^width. Pointers are u64; byte extents use B. Outer SP is `0x6800060100` in the retained model. Source equations quantify arbitrary u64 frame/pointer values and u32 input words under readable, separated input cells. The model addresses establish source roles, not native placement or ownership. [FLG1-FLG5; FLG-A1-FLG-A3]

| Cell or value | Source transfer | Established role |
| --- | --- | --- |
| Outer SP+0x9c20 / u64 | `0x10083c8c4` stores incoming X20; `0x10098aad4` reloads it | Saved input pointer P |
| Outer SP+0x9c2c / u32 | `0x10083c8c8` stores incoming W8; `0x1008a3bf8` or `0x100753c90` reloads it | Independent tag T |
| P[0..3] / u32 | `0x1008a3bf0`, only on the non-NULL pointer route | Pointed word H |
| Outer SP+0x662f / u8 | `0x10068f7c0` stores comparison result, or `0x10091020c` stores zero | Saved selector byte b |
| U+0x28 / u32 | `0x1008258d0` | Reader flag word derived later from b |

Tag constants T1=`0x4e40e175` and T2=`0x4e40e176` are private source comparison values. Their native enum names, public API meanings and complete producer restrictions are unknown. Under the checked source phases, the decision is:

```
P = load64(outer_SP+0x9c20)
T = load32(outer_SP+0x9c2c)
if P == 0:
    if T != T1: goto saved_return        # selector writer bypassed
    b = 0
else:
    H = load32(P)
    if H == 0 and T != T1: goto saved_return
    b = u8(T == T2)
store8(outer_SP+0x662f,b)
next_constructor = 0x100934280 if b != 0 else 0x1008c0750

# Later, if execution reaches the U initializer with the saved byte intact:
U[0x28] = 0xd299e642 if b != 0 else 0xd299e646
```

The non-NULL test uses `CCMP W10,W12,#4,EQ`. When H is nonzero, the conditional compare is skipped and the immediate NZCV value sets Z=1. It therefore permits the selector comparison for every T in that case. Treating this as an unconditional tag equality would give the wrong partition. With H=0, only T1 proceeds; T2 does not reach its selector writer on that route. These conclusions quantify all H32 and T32 values. [FLG4-FLG5; FLG-A2-FLG-A3]

| P | H | T | Reaches selector writer | b | U mask4 if later published |
| --- | --- | --- | --- | --- | --- |
| NULL | Not read | T1 | Yes | 0 | Set |
| NULL | Not read | Other, including T2 | No | No new write | Unknown from this route |
| Non-NULL | 0 | T1 | Yes | 0 | Set |
| Non-NULL | 0 | Other, including T2 | No | No new write | Unknown from this route |
| Non-NULL | Nonzero | T2 | Yes | 1 | Clear |
| Non-NULL | Nonzero | Other, including T1 | Yes | 0 | Set |

`saved_return` is `0x10068ae70`: its already recovered source rewinds a private cursor by 32 B, reloads the saved continuation and branches through it. The current partition does not assign a public error code, overwrite an older selector byte or prove an eventual external return value. The subsequent alternative-fill report establishes the allocation and initial byte fill following `0x1008c0750`; later header writes and constructor completion remain unknown. Consequently, the null-pointer/T1 source route does not prove that a later alternative reader dereferences a NULL U+0. [FLG2-FLG5; FLG-A3-FLG-A6]

| Source gate | Index | Target | IA modifier |
| --- | --- | --- | --- |
| P non-NULL | `0x66c1` | `0x1008a3be0` | `0x4f69` |
| P NULL | `0x66d6` | `0x100753c74` | `0x4f69` |
| Non-NULL gate proceeds | `0x245b` | `0x10068f774` | `0x724e` |
| Non-NULL gate bypasses writer | `0x246d` | `0x10068ae70` | `0x724e` |
| NULL and T1 | `0xae32` | `0x100910200` | `0x6d79` |
| NULL and other tag | `0x76bf` | `0x10068ae70` | `0x6d79` |
| b=0 | `0x9a64` | `0x1008c0750` | `0x2175` |
| b=1 | `0x9a68` | `0x100934280` | `0x2175` |

The original format-12 pointer words and logical IA modifiers are checked against image bytes and the original fixup decoder. Their hardware authentication acceptance is unmeasured. [FLG1, FLG4-FLG5]

## Retained selector custody and object views

Every one of the 76 selected non-NULL S/64 B constructor returns has exactly one overlapping write to the selector byte: `0x10068f7c0 -> 01`. Current-interval last writers establish both saved P and T. The pointed H bytes are inherited context bytes, with no current-interval writer: P=J+0x1c=`0x6500115b3c`, H=6 and T=T2. FLG2 independently established copying J+0x1c[24] to S+0x18; the present read therefore adds a selector role for that same pointed context word. A version, policy, authorization or wire-field identity for 6 is unknown. [FLG2, FLG4-FLG5; FLG-A2-FLG-A4]

```
76 conditional S constructors
   P=J+0x1c, H=6, T=T2
      -> source comparison -> SP+0x662f = 1
      -> existing allocator-return premises and original emitter
      -> original table initialization/mixing/consumer
      -> separate source-compatible initializer-root premises
      -> source reload of saved byte 1
      -> U+0x28 = d299e642 -> mask4 clear
      -> clear word/halfword readers through U+8
```

| Checked projection | Coverage | Result |
| --- | --- | --- |
| Selector-producing constructors | 76 | Saved P and T have current-interval last-writer custody; H is inherited; b=1 |
| Later source intervals | 606 / 1,620,162 visits | Defined selector byte is 1 at entry and exit; zero overlapping writes |
| Selected allocation-return invalidations | 152 | No invalidation overlaps the selector byte |
| Conditional initializer root-premise sets | 76 | All added root fields are disjoint from the selector byte |
| Phase snapshots | 456 = 6*76 | Selector remains 1 at every checked phase |
| Successful U object views | 608 | U+0=0; U+0x28=`0xd299e642`; U+8 follows the established backing-buffer transition |

The six snapshot phases are container construction, allocation cascade, emitter completion, table mixing, table consumer and conditional initializer. The source persistence census traverses the selected successful allocation path and retained shared source intervals. It does not count every parent as a separate original execution. Existing complete register/byte/owner admissions are hash-pinned; this increment freshly checks the selector projection and its non-overwrite/non-invalidation conditions. It does not rerun every earlier admission or close the native epoch gap. In particular, the later initializer still depends on its earlier explicitly separate root premises. [FLG2, FLG4-FLG5; FLG-A4]

| U export phase | Views | U+0 | U+8 | U+0x28 |
| --- | --- | --- | --- | --- |
| Initializer | 76 | 0 | T=`0x6600050000` | `0xd299e642` |
| Constructor prefix | 76 | 0 | T=`0x6600050000` | `0xd299e642` |
| Successful first growth | 152 | 0 | F=`0x6600070000` | `0xd299e642` |
| Successful later growth | 304 | 0 | H-buffer=`0x6600080000` | `0xd299e642` |

Here H-buffer is a backing-buffer label, distinct from pointed scalar H. The 608 views check 1,824 field values and 12,160 B. They reuse conditional parent exports and are not 608 independent native objects. The U base publication source copies two distinct saved u64 cells to U+0 and U+8; the flag publication source maps every possible saved u8, not only 0 and 1. Fresh reader-selector proof establishes mask4 set -> word reader `0x100357e2c`, mask4 clear -> `0x100405d98`, while rebuilding W6=`0x602d` and preserving the decoded offset and selected child continuation. Halfword selection is inherited from FLG3. [FLG3-FLG5; FLG-A2-FLG-A4]

## Bounded source census and independent checks

The original 14,849,960 B text is scanned as 3,712,490 aligned instruction words, SHA-256 `94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e`. Exactly six unsigned-immediate STRB and three LDRB instructions have displacement `0x62f` when all base registers are included. Candidate words and 36 B contexts ending at each site are retained. This is an exact opcode-family census, not an inventory of all writes to any runtime stack address. Other widths, addressing forms, alias bases, computed pointers and frame epochs remain outside it. [FLG1, FLG4; FLG-A1,FLG-A5]

| Store candidate | Base visible at the site | Established scope |
| --- | --- | --- |
| `0x1003c4128` | SP | SP+0x62f in that frame; not the same offset as the selector |
| `0x100684a04` | X25 | Effective object/frame relation unknown |
| `0x10068f7c0` | X11, immediately rebuilt as SP+0x6000 | Conditional Boolean selector producer |
| `0x10089dce8` | X13, immediately rebuilt as SP+0x2000 | SP+0x262f in that frame |
| `0x10091020c` | X10, immediately rebuilt as SP+0x6000 | Zero selector producer on the NULL/T1 source route |
| `0x100aa2694` | X20 | Effective object/frame relation unknown |

The three read candidates are `0x1003c4110` at SP+0x62f, `0x100809170` through SP+0x2000 plus 0x62f, and the initializer read `0x1008258b4` through SP+0x6000 plus 0x62f. Identical low displacements alone establish neither shared storage nor an epoch join. The retained constructor-to-initializer selector projection uses the original journals and checked parent indices, not this displacement census as an alias proof. [FLG4-FLG5; FLG-A4-FLG-A5]

Independent replay checks 167,296 GP/SP values, 167,296 unchanged Q-register values, 5,228 NZCV frames, 700 reads and 240 writes across 312 selected slices. The 4,916 visits are replay visits, not new target intervals or unique instruction addresses. Replay explicitly selects the correct constructor or initializer parent journal, checks each source word, compares every intermediate frame and consumes every selected read/write event. Sixteen source obligations establish the input stores, pointer/tag partitions, preserved phases, canonical Boolean write, zero write, U base/flag publication and word-reader selector. No proof cuts or target rewrites are used. Eight scalar truth-table controls exercise the listed partitions without constructing a target byte stream. [FLG4-FLG5; FLG-A2-FLG-A4]

This increment establishes no new Mach send/receive, port allocation, right transfer, IOKit call or port-emission site. The pointed context value and tag have a private selector role; their relationship to an externally supplied request, on-disk schema or kext buffer remains unknown. [FLG1-FLG5; FLG-A6]

## Assumption register and bounded continuation

| Assumption / dependent results | Premise | Stress test or falsification probe |
| --- | --- | --- |
| FLG-A1: build-specific mappings | Pinned image, original source/fixup words and exact upstream receipts | Reject source spans, text SHA, candidate contexts, route words or receipt-hash mismatches; do not transfer mappings to another build. |
| FLG-A2: source phases and readable inputs | Recorded phase words, readable separated pointer/tag/object/frame cells | Universal u32/u64 source proofs cover pointer nullness, every tag/header and all saved-byte values. Independent replay checks actual phases; readability before each source load remains a premise. |
| FLG-A3: gate semantics | Conditional compare, canonical Boolean and distinct T1/T2 predicates | Scalar controls include NULL/T2 and zero-header/T2 bypasses, nonzero-header/other-tag admission and the actual nonzero-header/T2 case. Require a completed subsequent source route before inferring later storage contents. |
| FLG-A4: conditional byte custody | Existing source/ABI admissions, selected parent indices, non-overlapping invalidations and separate later root premises | Check the selector at every retained interval entry/exit and all phase exports; reject any write/invalidation/root overlap. This projection does not establish the earlier native initializer/caller epoch or rerun all prior admissions. |
| FLG-A5: census limits and aliasing | Exact aligned unsigned-immediate byte load/store encoding with displacement 0x62f | Retain all base registers and nearby source bytes; distinguish SP+0x62f, +0x262f and +0x662f. Other forms, aliases and native concurrent writers remain unknown. |
| FLG-A6: external interpretation | Private source selector and retained object fields only | Recover native caller epoch, complete alternative base initialization and matched daemon-kext request/response bytes before assigning public policy, enum or wire-field identities. |

| Impact | Next discriminating work | Information gained |
| --- | --- | --- |
| High | Join the recovered alternative header/publication contract to native caller and cache epochs | Which alternative buffer, literal and caller premises hold natively |
| High | Trace producers of saved P/T and the pointed context word to matching caller epochs | Native selector admission and producer restrictions beyond the retained P/H/T values |
| High | Establish mask/table initialization and publication lifetime at the alternative-reader epoch | Which cached-word validity and table-bound premises are met |
| Medium | Join these object/selector contracts with paired daemon-kext buffer evidence | Whether this internal storage representation participates in the external exchange |
| Low | Resolve X25/X20 candidate bases and other byte-write forms | Broader writer inventory without conflating stack offsets across frames |

## Quality gates and reproduction

**QG1** passes: factual source, data-flow and ABI analysis. **QG2** passes: FLG-A1-FLG-A6 identify premises, dependent results and falsification probes. **QG3** passes for this increment: selector inputs, gate partitions, producer, later flag/base publication, retained byte custody and object exports are covered; the full investigation remains active. **QG4** passes: B extents, u8/u32/u64 widths, phase values and census bounds are explicit. **QG5** passes: CCMP fallback flags, T1/T2 asymmetry, bypass-without-write, conditional parent reuse and native/alternative gaps are distinguished. **QG6** passes: original image words/fixups, frozen parent admissions, fresh solver obligations and intermediate-frame replay provide primary provenance. **QG7** passes: impact-labeled bounded extensions are listed.

Run the extractor, auditor and publication verifier with the evidence directory on the Python module path and existing Capstone/Z3 dependencies available. Extraction costs O(parent receipt bytes + retained visits + exports + text words) time and O(parent receipts + selected evidence) space. Independent selected replay costs O(visits*32); symbolic work costs O(source DAG plus solver resources), with 30 s/query limits. The target selector and fixed-size gate work are O(1) time/space; no native timing measurement is inferred. All 16 source obligations are nonvacuous UNSAT, and all eight scalar controls match. There are zero new target intervals, guest input bytes, owner/root definitions, API-return premises, proof cuts or instruction rewrites. Original image and retained receipts suffice; no IDB data or mutation is used. No native target operation, allocation/free or hardware PAC test occurs. Original primary inputs remain byte-identical.

## Alternative allocation and address-masked zero fill

The [alternative-fill follow-up](daemon_alternative_fill_report.md) resolves the b=0 allocation prefix: it requests N B, saves its result in the future U+0 cell and selects a cached-word byte initializer after the shared 48 B object allocation. Each byte is the same address-dependent mask used by the alternative readers, giving zero intermediate decoded bytes if the cache epoch is unchanged. The word reader still applies its final scalar XOR. Twenty-one source obligations, three checked normalizer cuts, ten scalar controls, 512 bank rows and 152 independent zero-store replay visits qualify the result. All 76 retained snapshots remain clear-route cases. The subsequent header follow-up establishes alternative header/publication source contracts; native caller/cache epoch and daemon-kext pairing remain unknown; no new port emission is established and the full goal remains active.

## Alternative header publication and immediate caller

The [alternative-header follow-up](daemon_alternative_header_report.md) establishes the three masked header-word writes, U initialization, parent-pointer store and saved return after the alternative fill. Its generic decoded words are 20, u32(X+0xeceb3944) and 1; the remaining eight record bytes retain the fill result under the same cache epoch. The earlier clear caller's source literal X=0x867a282a maps to ASCII `sean`, without proving native alternative use of that literal. U+0x20 is zero, U+0x28 has mask4 set, and published capacity/default match the allocation/header coordinate. Thirty-six source queries, 60 checked normalizer applications, 456 independent producer/store replay visits and a 1,524-instruction source composition qualify the result. Separate caller contracts reload the child/result pair and identify 0x100762e48 as the next boundary. Native caller/cache epochs, J+0x68 publication and daemon-kext pairing remain unknown; no new port emission is established and the full goal remains active.

The [child-operation follow-up](daemon_child_operation_report.md) resolves the earlier 0x100762e48 prelude: it writes raw token bytes 98 99 98 99, reloads the saved U/result pair, prepares raw tag 0x76657273 and advances a private cursor by 32 B. Base availability and low-two-bit guards precede the existing validation boundary; both clear flag 0xd299e642 and alternative flag 0xd299e646 pass those guards under their separate source premises. The saved outer result gate at 0x10072c448 accepts exactly raw W27=0x8b3dc651. Eighteen universal source obligations and 876 independent replay visits across four retained clear classes qualify the result. The alternative execution, native root/cache/caller epochs, J+0x68 publication and daemon-kext transaction identity remain unknown. No new port emission is established; the full goal remains active.

The [child-payload follow-up](daemon_child_payload_report.md) joins the private raw bytes 98 99 98 99 to the four packed scalar payload fields 0/1/0/1 at buffer offsets 41/45/49/53. Thirty-two fresh custody links across eight retained successful classes establish the byte decoder, encoded-scalar spill, actual producer read and destination-position read. The nested operation also requires a base compatible with mask4: set selects non-NULL U+0, clear requires non-NULL U+8. Thirteen universal obligations and 1,096 independently replayed instructions qualify this increment. The alternative execution, native caller/root/cache epochs, J+0x68 publication and daemon-kext transaction identity remain unknown. No new port emission is established; the full goal remains active.
