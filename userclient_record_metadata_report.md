# Staged record metadata, bounds and cursor production

Subsequent original-entry evidence: The [early header report](userclient_early_header_report.md) continues through declared input bytes in 72 private cases, with 48 exact predecessor prefixes, ten fresh source proofs and two rejected source mutations. It establishes the early BE header and scalar/span domains, conditional wire-field correspondence to staged decoding, zero-tag span success with an unread suffix, and the earlier 32 B FPTTLVNode request. Input custody and allocator returns are fixtures; node allocation/free bodies and matched native daemon/kext identity remain unknown. Earlier boundaries below retain their historical scopes.

Subsequent original-entry evidence: The [earlier FPTTLV entry report](userclient_fpttlv_entry_report.md) continues through the first 16 B allocation return in 84 private cases, preserving 72 predecessor prefixes exactly. Source zeroing, a ten-byte early header-fit gate, the first selected original-input byte at I+6, distinct empty/short cleanup cells and typed-retirement/staging-request frontiers are independently checked. Six source proofs and two rejected store-removal controls pass. No input-content read, native allocation/free or new Mach emission executes. Earlier boundaries below describe their historical increments; later staged objects and matched daemon/kext transactions remain separate open joins.

The selected nonempty parser reads a protected ten-byte header from the staged input at the current cursor. Its header gate requires ten remaining bytes. After decoding the payload length L, it stores candidate cursor `cursor+10+L` and accepts the body extent exactly when that candidate does not exceed the decoded outer extent N. For transformed type0x6685, the source publishes the body pointer and commits the candidate cursor into the metadata return consumed by node construction.

This resolves the selected metadata/body/cursor producer left open by the [node constructor](userclient_record_nodes_report.md), [writer](userclient_record_writer_report.md) and [publication](userclient_record_publication_report.md). It also connects the special encoded tag/type pair to staged bytes: decoded tag0 with transformed type0x6685 selects the existing parser-success continuation before node construction. That selection permits an unconsumed outer suffix. Its business meaning remains unknown. Complete other-type/failure behavior, native storage/locking and successful daemon-kext correlation remain open; the full objective remains active.

## Primary evidence and validation

| Artifact | SHA-256 of decoded content | Coverage |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Selected instructions and data |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original instructions and chained table pointers |
| [Checks](triage_evidence/userclient_record_metadata_checks.json.zst) | `b3829fa50d766e7b7776f8d2d16f5102fd2994dacffe5382597b2eae1447caff` | 18 spans, 408 selected instructions, 15 terminal transfers, 25 literal accesses |
| [Audit](triage_evidence/userclient_record_metadata_audit.json.zst) | `2e7536a9fe17c40b37708ebf50d1531aa2e5a019cf8857a1b4e92103bf05b9b9` | 26 nonvacuous UNSAT obligations, five predecessor rechecks, 5,759 proof instruction instances |

The [extractor](triage_evidence/recover_userclient_record_metadata.py) compares every selected word against both images and checks the complete 50,634-instruction `_PRnut72j9` container hash. Original branch pointers are checked separately from normalized pointers. The [audit](triage_evidence/audit_userclient_record_metadata.py) reconstructs the selected source with arbitrary header bytes, outer length32 and cursor64. Seven alternate MOVK sites have separate pointer-bit proofs; the composed decoder/body path assumes the corresponding normal pointer branches. The [delivery verifier](triage_evidence/verify_userclient_record_metadata_delivery.py) reconstructs receipts and checks publication custody.

Five frozen predecessor formulas are re-solved: container initialization, the arbitrary parser-cursor gate, metadata return, valid metadata-outcome dispatch and tail-append cursor preservation. This is formula reuse, not a fresh complete constructor/writer/publication replay. Four equality controls reject altered instruction bytes, a table target, header width and an unsupported native-input claim. These controls test custody sensitivity. No target code executes, no native PAC authentication is tested and no IDB is changed.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| RM1 | Staged-pointer cell alias and selected entry phase | RM-A1-RM-A3 |
| RM2 | Exact ten-byte header extent gate under nonempty-cursor invariant | RM-A1-RM-A4 |
| RM3 | Staged-byte tag/type/length provenance and widths | RM-A1-RM-A5 |
| RM4 | Exact candidate cursor and body-extent predicate | RM-A1-RM-A4 |
| RM5 | Selected type0x6685 body pointer and metadata return | RM-A1-RM-A5 |
| RM6 | Short-header/body rejection retains parser cursor | RM-A1-RM-A4, RM-A6 |
| RM7 | Strict progress, bounded payload range and zero-length case | RM-A1-RM-A5 |
| RM8 | Decoded zero-tag success selection and possible unconsumed suffix | RM-A1-RM-A5, RM-A7 |
| RM9 | Literal-access inventory, cost and cross-layer limits | RM-A1-RM-A8 |

## Entry, storage and header representation

C is the scratch base, S the source-state base and F the selected SP epoch. B is the retained staged-buffer base, N its decoded unsigned32 extent and c the current unsigned64 cursor. `SUCCESS=0x31ae0066`. The selected entry premise is `c < zero_extend32(N)`. This invariant follows at the local nonempty branch; native allocation identity, frame retention and all incoming dispatcher paths are separate premises.

At `0xfffffe000a635efc` the source forms C+0x3d8 and at `0xfffffe000a635f00` saves that address in F+0x890. The nonempty input phase at `0xfffffe000a6421e0`..`0xfffffe000a642244` exclusive loads B from C+0x618 and retains it at C+0x3d8. Its nonnull gate selects `0xfffffe000a642248`. It loads X20=K1 and preserves the parser initializer's X26=K0, where K0=`0x02e859d27e491464` and K1=`0x4dae26df20976138`.

The [staging report](userclient_container_staging_report.md) establishes the selected protected copy and parser-entry ABI. This increment's symbolic bytes describe the ten decoded bytes at B+c; it does not identify an external request or infer literal plaintext storage. For address a:

```text
mask8(a) = low8((((ROR64(a & ~7, 8) + K0) XOR K1)
                >> ((a & 7) * 8)))
decoded_byte(a) = stored_byte(a) XOR mask8(a)
```

| Decoded header offsets | Width | Selected channel |
| --- | --- | --- |
| 0..3 | BE u32 | D=decoded tag; T=D XOR SUCCESS |
| 4..5 | BE u16 | U=BE16 XOR0x365e |
| 6..9 | BE u32 | L=payload length; E=L XOR SUCCESS |

T and E are encoded internal channels; U is the transformed type consumed by dispatch. These arithmetic roles do not identify tag business semantics. The type decoder's W8 may contain irrelevant high bits; its low16 are stored with STRH and later reloaded with LDRH. No proof treats the immediate helper result as a zero-extended u16.

## Header gate and shared decoder callbacks

The source at `0xfffffe000a64224c`..`0xfffffe000a64232c` exclusive saves c at F+0xbd8 and constructs S+0xaa0 for the later body check. Under `c < N`, its obfuscated CMN64 predicate is exactly `c+10 <= zero_extend32(N)`. Because c<N<=2^32-1, c+10 cannot overflow u64. Passing selects `0xfffffe000a642330`; failing selects `0xfffffe000a6423c0` with W10=0 and raw W23=0xce515bb8. The following outcome gate selects `0xfffffe000a662440`; its cleanup/final return remains unknown.

The passing preparation selects shared word entry `0xfffffe000a637138` through the bridge. It normalizes the decoder offset to c and loads B through the retained cell alias. Four tag bytes produce T, then the tag callback requests the two-byte type helper at B+c+4. Its STRH return retains U and requests the length word at B+c+6. The ten exact byte addresses lie inside [B,B+N) under the header invariant and disjoint, nonwrapping staged-storage premises.

| Phase | Private callback index | Target | Result / retained field |
| --- | --- | --- | --- |
| Tag word | 0x17a | `0xfffffe000a638db8` | T -> S+0xa18 at `0xfffffe000a638dc4` |
| Type helper | 0x1c | `0xfffffe000a639dc0` | low16(U) -> S+0x2a0 at `0xfffffe000a639dd4` |
| Length word | 0x1a9 | `0xfffffe000a6390b4` | W22=E before extent check |

The shared word decoder's callback load at `0xfffffe000a63713c` has both tag and length phases. The original bytes do not support treating that PC as a single fixed continuation.

## Candidate cursor and body bounds

At `0xfffffe000a6390b8`..`0xfffffe000a639160` exclusive the source computes:

```text
body_offset64 = c + 10
candidate64   = body_offset64 + zero_extend32(L)
body_fits     = candidate64 <= zero_extend32(N)
```

The extent predicate is proved under the preceding nonempty/header invariants. Candidate arithmetic has no u64 overflow in that scope: c<N<=2^32-1 and L<=2^32-1. Candidate may exceed N on rejection. The source stores E at S+0xa64 (`0xfffffe000a63911c`) and candidate at S+0xcf8 (`0xfffffe000a639120`) before selecting the bounds outcome. Thus the presence of candidate metadata does not itself mean the record was accepted.

| Body extent result | Selected target | F+0xa80 / outcome |
| --- | --- | --- |
| candidate<=N | `0xfffffe000a639164` | F+0xa80 still c; proceed to type dispatch |
| candidate>N | `0xfffffe000a6423c0`, then `0xfffffe000a662440` | F+0xa80 remains c; W10=0, W23=0xce515bb8 |

The rejection proof reaches the failure frontier without committing candidate to the parser cursor. It does not establish rollback of all scratch metadata or complete native cleanup.

## Type0x6685 payload and metadata return

The first type gate at `0xfffffe000a639168` compares U with0xa129; the selected path follows its unequal branch to `0xfffffe000a63a784`, where U==0x6685 selects `0xfffffe000a63dc9c`. Other type handlers remain outside this increment.

The selected body publication computes P=B+c+10, checks the normal top-bit pointer branch and stores P at C+0x280 (`0xfffffe000a63dcc0`). The alternate MOVK replaces high16 with0xc8a2; its bit transform is proved separately, without a native storage-equivalence claim. The normal branch selects metadata return `0xfffffe000a63dcd0`.

| Producer channel | Width | Metadata-return destination |
| --- | --- | --- |
| S+0xcf8=c+10+L | u64 | F+0xa80 at `0xfffffe000a63dce0` |
| S+0xa18=T | u32 | S+0xaec |
| S+0x2a0=U | u16 | S+0xa08 |
| S+0xa64=E | u32 | S+0x9e8 |
| Selected return | u32 | W10=1 and W23=SUCCESS |

The composed outcome gate selects `0xfffffe000a6423f4`. The [constructor](userclient_record_nodes_report.md) subsequently retains P into C+0x348 and the writer uses that body source. On the selected accepted path, [P,P+L) lies within [B,B+N); P+L=B+candidate. If L==0, P is the empty payload's start, possibly the one-past end of B, and no payload byte is implied readable there. Cursor advancement is exactly ten bytes in that case. Otherwise advancement is ten plus L. All accepted selected cases strictly increase c and keep the committed cursor<=N.

```text
staged B + c
    |
    +-- protected tag[4], type[2], length[4]
    |           |
    |       header fits? -- no --> failure frontier; cursor unchanged
    |           |
    +-- body P=B+c+10, candidate=c+10+L
                |
            body fits? -- no --> failure frontier; candidate retained
                |
           selected U=0x6685
                |
        metadata return commits candidate
                |
        D==0? -- yes --> parser-success continuation
                |
                no --> ordinary node construction -> writer -> publication
```

## Decoded zero tag and early success selection

After metadata return, the already recovered reserved-pair gate compares T with SUCCESS and U with0x6685. The current byte provenance gives `T=BE32(header[0..3]) XOR SUCCESS`, so that selected pair is exactly D=0/U=0x6685. It selects `0xfffffe000a6421b0`, the previously recovered parser-success continuation, before ordinary node construction. A selected nonzero D enters `0xfffffe000a642454`.

The zero-tag success selection is nonvacuous even with candidate<N. Therefore this branch does not require complete outer-envelope consumption. It is a local control-flow fact; naming the pair as a business terminator, requiring L=0, asserting that trailing bytes are processed, or inferring an external protocol guarantee would exceed the evidence. The selected type handler has already published P and committed the candidate before this gate.

## Literal access inventory and architectural limits

The complete pinned `_PRnut72j9` instruction container contains 25 literal-base accesses to the nine selected cells. This inventory checks textual base/displacement syntax, not alias-equivalent addresses or every possible runtime frame epoch. The four source-state metadata cells each have one direct store; their later reads bind them to the metadata return. C+0x280 additionally has an earlier store at `0xfffffe000a64200c` and a constructor read at `0xfffffe000a642490`. F+0xa80 additionally has the original initialization store at `0xfffffe000a642078` and the cursor-gate load at `0xfffffe000a64214c`. These distinctions prevent treating every reference to the same displacement as the selected producer.

| Cell | Selected direct producer | Role |
| --- | --- | --- |
| S+0xa18 | `0xfffffe000a638dc4` | Tag T |
| S+0x2a0 | `0xfffffe000a639dd4` | Type U, STRH |
| S+0xa64 | `0xfffffe000a63911c` | Encoded payload length E |
| S+0xcf8 | `0xfffffe000a639120` | Candidate cursor |
| C+0x280 | `0xfffffe000a63dcc0` | Selected staged body pointer |
| F+0xa80 | `0xfffffe000a63dce0` | Committed metadata-return cursor |

The selected source now connects staged bytes to constructor metadata, payload source and cursor advancement. Construction/writer/publication remain supported by their own conditional reports. Complete end-to-end nonempty parsing requires their storage, phase, type, failure and ordinary-call premises to compose across actual incoming paths. No new Mach right, incoming/outgoing port, message emission site or successful daemon-provider transaction is established here. The existing [Mach ports](mach_ports_report.md), [interface ABI](interface_abi_report.md) and [investigation status](interface_investigation_status.md) retain those interfaces and unresolved correlations.

The selected fixed-size decode, bounds checks and metadata publication take O(1) work and O(1) auxiliary state, excluding downstream payload copy, list search, allocation and cleanup. If repeated accepted continuing iterations satisfy these premises, each consumes at least10 B; that local progress lemma is not a proof of termination for every type/failure/dispatcher path. Extraction takes O(B+I) time/space, with B the pinned container/image bytes and I decoded instructions; the literal inventory scans the entire pinned container. Proof construction takes O(instruction instances+query DAG); SMT search is separate with30 s/query limits. All extents/offsets are bytes, header words are BE, status/tag/length channels are u32, type storage is u16, and pointers/cursor are u64.

## Original private table mapping

| Private index | Original slot | Target |
| --- | --- | --- |
| 0x1c | `0xfffffe0008473000` | `0xfffffe000a639dc0` |
| 0x17a | `0xfffffe0008473af0` | `0xfffffe000a638db8` |
| 0x1a9 | `0xfffffe0008473c68` | `0xfffffe000a6390b4` |
| 0x22e | `0xfffffe0008474090` | `0xfffffe000a637128` |
| 0x22f | `0xfffffe0008474098` | `0xfffffe000a656ef0` |
| 0x252 | `0xfffffe00084741b0` | `0xfffffe000a63930c` |
| 0x449 | `0xfffffe0008475168` | `0xfffffe000a6421b0` |
| 0x46d | `0xfffffe0008475288` | `0xfffffe000a642454` |
| 0x4a9 | `0xfffffe0008475468` | `0xfffffe000a662440` |
| 0x514 | `0xfffffe00084757c0` | `0xfffffe000a63dcd0` |
| 0x54d | `0xfffffe0008475988` | `0xfffffe000a6423c0` |
| 0x560 | `0xfffffe0008475a20` | `0xfffffe000a6423c0` |
| 0x593 | `0xfffffe0008475bb8` | `0xfffffe000a642248` |
| 0x63c | `0xfffffe0008476100` | `0xfffffe000a642330` |
| 0x87f | `0xfffffe0008477318` | `0xfffffe000a6421dc` |
| 0x88c | `0xfffffe0008477380` | `0xfffffe000a6423f4` |
| 0x893 | `0xfffffe00084773b8` | `0xfffffe000a642180` |
| 0xe07 | `0xfffffe0008479f58` | `0xfffffe000a637138` |
| 0xe40 | `0xfffffe000847a120` | `0xfffffe000a639164` |
| 0xe7d | `0xfffffe000847a308` | `0xfffffe000a6423c0` |

These are private dispatcher selectors, not Mach message IDs or external IOUserClient selectors. Original pointer metadata establishes table destinations; native authentication remains outside the model.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RM-A1: Pinned images, original table pointers and predecessor receipts | RM1-RM9 | Fresh dual-image/full-container custody, reconstructed queries, original pointer checks and four altered-evidence controls |
| RM-A2: Selected C/S/F phase, dispatcher constants and retained pointer aliases | RM1-RM9 | Captured alias/input source, predecessor initializer/cursor formulas; trace every incoming epoch and alias/call that can modify these roots |
| RM-A3: AArch64 W/X, unsigned comparisons, loads/stores and BE byte assembly match the source model | RM1-RM9 | Arbitrary decoded bytes, explicit u16 truncation/reload, u32 zero extension and seven alternate pointer-bit proofs |
| RM-A4: Nonempty gate gives c<N; header decoding additionally requires c+10<=N | RM2-RM9 | Exact gates, short-header/body rejection, strict progress and zero-length checks; do not extend simplified predicates to arbitrary invalid incoming epochs |
| RM-A5: Valid separate nonwrapping staged storage, matching protection keys and normal pointer branches | RM3, RM5, RM7, RM8 | Ten exact byte addresses, half-open payload extent and original key/cell source; verify native allocation identity, pointer authentication and branch behavior separately |
| RM-A6: Common failure frontier effects remain unknown | RM6, RM9 limits | Selected rejection leaves F+0xa80 unchanged; recover `0xfffffe000a662440`, rollback, cleanup and final status before claiming a complete failure contract |
| RM-A7: Zero-tag branch is parser-success selection, with business meaning unassigned | RM8, RM9 limits | Composed zero/nonzero tag proofs and nonvacuous candidate<N case; establish caller semantics and remaining-input policy from successful correlated evidence |
| RM-A8: Other types, complete parser composition, ownership/locking and daemon correlation remain unknown | RM9 limits | Trace U=0xa129/0xb2db handlers, shared failure cleanup, native epochs and a successful correlated daemon/provider exchange |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Failure frontier `0xfffffe000a662440` and new-node cleanup `0xfffffe000a6622bc` | Establish rollback, ownership and final status for rejected/partially constructed records |
| High | Actual selected-input caller and successful daemon/provider exchange | Bind staged bytes and recovered channels to external control and cross-layer IPC |
| High | Native storage/key/frame/locking epochs across parser, writer and publication | Validate composition premises rather than infer runtime identity from source cuts |
| Medium | U=0xa129/0xb2db and remaining type dispatch | Complete metadata/body semantics beyond selected type0x6685 |
| Medium | Decoded zero-tag selected success with candidate<N | Determine caller-visible remaining-input policy and business semantics |
| Medium | Whole finite-list traversal and duplicate-tag behavior | Complete the selected record's downstream lookup/publication invariant |

## Quality gates

- **QG1**: Factual source, interface and control-flow claims require no normative conclusion.
- **QG2**: RM-A1-RM-A8 enumerate dependencies and falsification probes.
- **QG3**: Selected staged bytes, decoder callbacks, header/body gates, rejection frontier, body pointer, cursor commit and zero-tag branch are covered; the full objective remains active.
- **QG4**: BE fields, u16 truncation, u32 zero extension, u64 cursor arithmetic, byte extents and scoped costs are explicit.
- **QG5**: Candidate versus committed cursor, protected storage versus decoded bytes, selected success versus full consumption, pointer bits versus native identity and local progress versus global termination are distinct.
- **QG6**: Dual-image words, original pointers, 26 nonvacuous formulas, five predecessor rechecks, 25 literal accesses and four custody controls support bounded claims.
- **QG7**: Ranked continuation retains failure cleanup, cross-layer input provenance, native epochs, other types and zero-tag/suffix semantics.

## Parser cleanup increment

The [cleanup follow-up](userclient_parser_cleanup_report.md) establishes this increment. It follows selected parser failure to retained-container/list retirement requests, null output and raw-status resume. Native callee effects and all incoming state compositions remain open.

## Parser caller and command dispatch increment

The actual parser caller now has a conditional command-field lookup, protected scalar reader and exact two-value switch. The first command links to the existing hash-input reader; second-body semantics, native storage/ownership and cross-layer correlation remain open. See the [command-dispatch report](userclient_command_dispatch_report.md) for the source contracts, status frontiers and assumption register.

## Caller cleanup and copy-back increment

Caller cleanup callback0x1a, distinct staged/auxiliary buffers, finite protected copy-back and outer allocation/retirement/status contracts are now established conditionally. Native identity, aliases, callee effects and cross-layer transaction correlation remain open. See the [caller-return report](userclient_caller_return_report.md) for original requests, proofs, scope and assumption probes.


The [serializer emission contract](userclient_serializer_emission_report.md) now closes conditional finite stable-list emission: decoded node-byte concatenation, terminal tag0/type50db/big-endian padding length, exact zero payload, and output pointer/extent publication with flag1/raw SUCCESS. The terminal shape normalizes to the recovered parser type0x6685. Original metadata-node construction, native list/storage validity and daemon transaction pairing remain unknown; no additional Mach endpoint is established.


The [query writer contract](userclient_query_writer_report.md) now establishes the three conditional14 B records: exact big-endian tags, raw type97 77 (parser-normalized0xa129), length4 and big-endian scalars0x4c0b0000/0x1f8/0x99ab. Each writer reaches the shared list lookup with W8 callback index0x6c (separate W0 control0x19) and retained pending-node/constructor-return state. This resolves the earlier query-byte frontier; actual query list publication/order, resulting serializer extent and native daemon pairing remain unknown. No additional Mach endpoint is established.


## Staged fallback allocation outcomes

The [fallback-parser report](userclient_fallback_parser_report.md) composes the actual protected buffer through staged-allocation outcomes. NULL restores all 14 source-observed input bytes before a new buffer-release request; non-NULL initializes the new container and decodes its first BE32 tag from protected offsets 0..3. Ordinary-return, surviving-buffer and writable-input premises remain explicit; complete parsing, native effects and authenticated outer return remain unknown.

## Subsequent actual fallback metadata composition

The [actual fallback-metadata report](userclient_fallback_metadata_report.md) now composes these conditional header roles with the actual non-NULL protected fallback predecessor. It certifies the complete live-state interface for both modes, keeps the newly decoded length distinct from earlier abstract fields, and follows selected zero-tag success through the real output-cell publication and saved caller. Other handlers, node construction, native continuity and outer return remain unknown.
