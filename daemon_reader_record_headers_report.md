# N19 cursor admission, record allocation and header reconstruction

The N19 source path now binds its opaque preparation inputs to concrete roles: N0 is the current byte cursor and N24 is the decoded total input extent on this path. Before the first header read, it requires a non-NULL buffer and at least10 B remaining. The admitted u32 extent bounds the cursor and makes its encoded read key simplify to cursor+WORD_BASE. That identity is false over unrestricted u64 cursors.

The ordinary-record path allocates a32 B node and an extent+10 B record buffer, then enters shared header writers. Its identifier, tag and extent arguments preserve the decoded input header fields before destination-address masking. Complete payload reconstruction, list insertion, the actual loop back edge, cleanup and native daemon-kext pairing remain unproved. The broader investigation remains active.

No target code was executed or emulated, no FairPlay request was sent and no IDB was modified. Original-file references suffice; no additional IDA query was needed. The workspace currently resolves to `/Users/___/dev/fp-reversing`; `/Users/___/dev/dylex/extracted` remains a symlink to it.

## Primary evidence and finite coverage

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Source virtual addresses are unslid. Offsets, selectors and constants below are hexadecimal unless marked as decimal counts or byte units.

- [Source blocks, banks, fixups and prior-source recaptures](triage_evidence/daemon_reader_record_headers_source.json), [recovery script](triage_evidence/recover_daemon_reader_record_headers.py).
- [Static validator and complete SMT queries](triage_evidence/validate_daemon_reader_record_headers.py), [proof results](triage_evidence/daemon_reader_record_headers_checks.json).
- [Preservation seal](triage_evidence/daemon_reader_record_headers_delivery.json), [scoped quality gates](triage_evidence/daemon_reader_record_headers_quality_gates.json), [independent publication audit](triage_evidence/verify_daemon_reader_record_headers_publication.py).
- Prior [container/caller origins](daemon_reader_container_origins_report.md), [normalized extent gates](daemon_reader_extent_families_report.md), [reader codecs](daemon_existing_scalar_reader_report.md), [common header writers](daemon_header_codec_report.md), [cache footprint](daemon_reader_context_footprint_report.md).

Fifteen complete branch-terminated source ranges contain1110 instructions /4440 B, including two allocation-call boundaries. Every instruction other than BRAA/BLRAA is translated:1093 distinct PCs,1126 translated instances and1037 SSA definitions. The extra33 instances examine the first-word caller outside its admitted cursor domain. Four prior source ranges are separately byte-recaptured and excluded from these new translation counts.

Twenty-four original pointer records support21 branch-slot/modifier matches and allocator/return records. Two exact bank pairs cover512 byte-input cases. None of these source ranges writes SP. Allocation calls are not run: each proof stops before BLRAA and resumes with a symbolic result, preserved SP/X19-X29 and fresh other register state. [The preceding allocation report](daemon_reader_container_origins_report.md) records the primary ABI reference and native-evidence limits.

## Input extent, buffer and10 B header admission

The loop component at0x1004ddaec receives cursor C in X8, raw input extent in W19 and private control W12=0xb350. It decodes S=zero_extend64(raw_extent XOR0x8b3dc651), computes S-C modulo2^64 and selects the nonempty route exactly when S>C. The previous entry proof establishes C=0 for the first iteration. Production of later loop-entry states remains unresolved.

On the nonempty route,0x10052b478 loads BUF from frame+0x5cf8, saves it at+0x4120 and selects the rejection entry0x10085e850 if BUF=0. A non-NULL value enters0x1004dbcf8. That block stores S at frame+0xa608 and C at+0xa610, then requires remaining=S-C>9 B. These are the previously opaque N24 and N0 cells. Their local source producer is now joined to this selected input path; arbitrary native epoch/alias equivalence is not inferred.

| Stage | Condition / value | Selected source frontier |
|---|---|---|
| Remaining-input component | S>C | Slot0xb358 ->0x10052b478 |
| Remaining-input component | S<=C | Slot0xb350 ->0x1005588b4 |
| Buffer gate | BUF!=0 | Slot0x6ff5 ->0x1004dbcf8 |
| Buffer gate | BUF=0 | Slot0x701f ->0x10085e850 |
| Header admission | S-C>=10 B, under C<S | Slot0x1ba2 ->0x1004f8144 |
| Header admission | S-C<10 B | Slot0x185d ->0x10085e850 |

For admitted C<S and S a zero-extended u32, C is also below2^32. The ten logical header offsets C through C+9 are within S and cannot wrap64 bits. This does not establish a physical nonwrapping BUF allocation or its lifetime.

## First-word key and read-cache provenance

Caller0x1004f8144 supplies BUF, return selector0xaf and encoded key C+0x661a590b302baf96 to preparation0x1006f6bf0 through slot0x2520. It supplies decoder selector0x8c3f. The key identity is proved in the admitted u32 cursor range. A SAT counterexample rejects extending it to arbitrary u64 cursors; no native input or fault fixture is constructed.

The complete preparation source is translated with unrelated context loads named as arbitrary values. It preserves the supplied BUF/key/return selector and derives:

| Prepared frame cell | Value on this path |
|---|---|
| 0x830 | C+WORD_BASE+6 modulo2^64 |
| 0x810 | C+WORD_BASE+10 modulo2^64 |
| 0x828 | C+10 modulo2^64 |
| 0x820 | S |

WORD_BASE is0x661a590b302baf96. Together with the established generic word-reader contract, the first word uses logical offsets C..C+3 and the length word uses C+6..C+9. The N19 tag caller's actual seed0x79b09650c3f6825c and cursor/buffer cells are separately checked through the full204-instruction tag body: its two byte reads occur at BUF+C+4 and BUF+C+5 in the admitted range, with return selector0x1fa.

These checks establish address/argument joins. Applying decoded field semantics also requires the prior reader's canonical key/register preconditions. The source preparation has eager reads of other frame cells; this increment does not erase those reads or establish their native initialization/validity.

## Offset geometry and ordinary-record size guard

Let P be the decoded u32 payload extent and E=C+10+zero_extend64(P). Under C<S, S-C>=10 B and S<=2^32-1:

```text
C <= 2^32 - 11
E <= (2^32 - 11) + 10 + (2^32 - 1)
  = 2^33 - 2 B
  = 8589934590 B < 2^64 B
```

Thus this logical offset addition cannot wrap64 bits. If the earlier source-proved N19 fit gate admits E<=S, then E>C and P<=S-C-10<=0xfffffff5. This supplies the missing no-wrap premise for this selected N19 cursor/extent domain. Physical BUF+offset validity and complete native admission remain separate. The strict-progress relation is conditional on using E as the next cursor; the actual back-edge assignment is not proved here.

Ordinary-record block0x1005bea60 independently accepts exactly P<=0xfffffff5 over every u32 P value. It selects slot0x8753 ->0x1005f3b24 on fit and0x701f ->0x10085e850 otherwise. The inherited registers become W27=0x7b3b and W24=0x6cf4. This guard ensures that N=P+10 fits a u32 record extent. Under the admitted fit relation above, the bound is already implied by the input extent.

## Node and record-buffer construction

The node-allocation stage0x1005f3b24 resolves its original byte-bank dispatch to the authenticated `libSystem/_malloc` binding and supplies X0=32 B. The normal-result pointer is staged at frame+0x5440. Its successful route enters0x1004d617c. The next allocation requests N=P+10 B through the same import, using a different bank/key pair.

The node bank uses key0xf3/additive0xcbca; the record bank uses key0xa3/additive0xcb9b. All256 inputs of each exact original bank pair select index0xcc0d, slot0x10109ff58, IA diversity0x6aa4. Controller u32 values are arbitrary in the source queries; native bank contents and authenticated import behavior remain premises.

Under normal returns and valid non-NULL NODE/REC objects, the source establishes:

| Node offset | Width / B | Value |
|---|---:|---|
| 0 | 8 | 0 |
| 8 | 8 | 0 |
| 0x10 | 4 | N=P+10, plain u32 |
| 0x18 | 8 | REC, record-buffer pointer |

These stores write28 B within a32 B envelope; offsets0x14..0x17 are not written by these stores. A separate64-bit expression is staged at frame+0xa630 and retained in the SSA ledger without assigning it a semantic field name. The node's two zero cells are structurally consistent with the earlier record-node layout; list insertion, ownership and a complete type remain unproved.

Allocation-result continuation records are included as control-flow frontiers. This increment does not follow their cleanup dereferences, prove native allocation-failure behavior or execute a failure fixture. Successful object contracts explicitly require valid non-NULL allocations and frame/heap separation.

## N19 joins into the shared header writers

After a successful record-buffer result,0x1005bfca8 supplies the buffer-pointer cell NODE+0x18, W21=0x6cf4, W24=0x27b and W22=HRAW XOR0x01263f51 to shared setup0x1008ecb78. HRAW is the saved preceding-word representation from the reader. The entire setup is translated and byte-identical to the prior common-writer source.

Its critical N19 cache values are:

| Frame cell | Meaning in this writer epoch |
|---|---|
| 0x9a0 /u64 | NODE+0x18, buffer-pointer cell |
| 0x970 /u32 | sign_extend32(reader_tag16) |
| 0x950 /u32 | sign_extend32(reader_tag16) XOR0xffffcbf9 |
| 0x980 /u32 | P XOR0x8b3dc651 |
| 0x938 /u32 | Payload-router selector0xadb6 |

The setup also supplies the common word-writer constants, offset base0x71134a47fbd9f0b7 and preserved return selector0x27b. Scratch offsets such as0x9a0/0x980 have different roles in other reader/writer epochs. The source does not support one global field type for each SP offset across all paths.

| Header field | Shared writer position | N19 argument before common writer | Result before destination mask |
|---|---|---|---|
| Preceding word | REC+0..3 | HRAW XOR0x01263f51 | HRAW XOR0x8b3dc651 |
| Tag | REC+4..5 | reader_tag XOR0xcbf9 | reader_tag XOR0x4799 |
| Declared extent | REC+6..9 | (P XOR0x8b3dc651) XOR0x01263f51 | P |

The tag uses N19's cache at0x950 and the generic tag writer's XOR0x8c60. The earlier constructor path used a different cache/XOR pair; sharing the writer does not imply identical caller encodings. Here cbf9 XOR8c60=4799, matching the reader's tag representation. The identifier/extent composition uses01263f51 XOR8a1bf900=8b3dc651.

The first word returns through slot0x27b ->0x1007b1fbc. Its tag caller supplies the sign-extended tag and its high byte, buffer-pointer cell and tag-return selector0xa48. That selector returns to0x1005ffd64, which stages word offset6 and length-return selector0x29b through the common word caller0x100615004. The extent return0x100517a0c uses cached selector0xadb6 ->0x1004a0f64, the next payload-routing frontier.

The helper input literals W21=0x30b3 and W7=0x01263f51 are established by the shared setup and preserved by the intervening helpers according to the pinned source liveness checks. They are explicit entry values in the component model. The N19-specific joins replace the older caller-specific contracts;66 generic codec lemmas are replayed against recaptured source.

Actual stored bytes include destination-address-dependent masks. The proved claim is preservation of decoded header field values before that mask, not equality of encrypted bytes at different addresses or native transport compatibility.

```text
cursor/extent + nonnull buffer + remaining>=10
  -> ten header byte positions and decoder keys
  -> decoded field caches + fitting end
  -> exact record-size guard
  ->32 B node + (P+10) B record buffer
  -> shared word/tag/word header writers
  -> payload router at1004a0f64 (remaining work)
```

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent result | Stress test / falsification probe |
|---|---|---|---|
| RH1 | The pinned original daemon is the intended build. | All addresses, bytes and original fixups. | Rehash the image and all recaptured ranges; another build invalidates address reuse. |
| RH2 | Loop-entry registers have the specified component values; later back-edge production is not established. | Cursor/extent admission and progress interpretation. | Trace the actual cursor assignment/return selector after insertion. The first-entry zero cursor is supported by the preceding allocation report. |
| RH3 | Selected frame/cache values and borrowed buffer cells are valid and consistent in this epoch. | Decoder key/cache and field joins. | Resolve intervening aliases, eager context loads and physical BUF extent/lifetime. Offset bounds alone do not prove native address validity. |
| RH4 | Native banks match the original file and allocation calls return normally with SP/X19-X29 preserved. | Allocation target/arguments and post-call state. | Verify actual call identity/effects before promoting the static model to native evidence. Other registers are freshly symbolic. |
| RH5 | Successful NODE/REC pointers are valid for requested extents and separate from the frame. | Node initialization and record-buffer staging. | Establish actual allocation/owner/lifetime facts and cleanup independently. Failure frontiers are not a cleanup proof. |
| RH6 | Established reader register/key preconditions apply to the raw field representations. | Decoded input-field interpretation. | Recheck canonical reader keys/call epochs; new footprint proofs alone do not establish a complete cipher/value transform. |
| RH7 | Exact shared-writer source, critical caller arguments and helper liveness compose as recorded. | Header-field preservation before destination masking. | Recheck W21/W7, return selectors and cache epochs; distinct writer callers have different tag encodings. |
| RH8 | Original authentication metadata describes intended continuations. | Conditional branch/call/return maps. | Re-decode target/key/diversity; hardware PAC, endpoint identity, transport direction and daemon-kext pairing remain unproved. |

## Verification and bounded continuation

Twenty-two new UNSAT queries cover admission/cursor producers, read-key/cache joins, tag read footprint,10 B offset bounds, no-wrap/progress geometry, the ordinary extent guard, two256-case bank identities and node/buffer/header caller contracts. Sixty-six prior generic codec queries are replayed successfully; six older caller-specific contracts are excluded and replaced by the new N19 joins. One SAT query rejects extending the encoded read-key identity to unrestricted u64 cursors. Six changed-ledger controls reject altered admission/bank data, missing preparation, invented full-parser completion, changed node-store operands and an omitted prior reference. They check evidence integrity, not native behavior.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_reader_record_headers.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_reader_record_headers.py
```

Extraction/translation costs O(I+R+512) time/space for captured instructions I and pointer records R. Query construction repeats finite source projections. QF_BV worst-case solver time is not claimed polynomial. Per-query timeout is15 s and subprocess limit20 s; unknown/timeouts are rejected. Publication checking costs O(total artifact bytes+links), with O(manifest+largest JSON) memory. Byte units,32/64/128-bit arithmetic and modular versus physical-owner bounds are explicit.

- High: recover payload routing/reconstruction and node insertion, then prove the actual cursor back edge and complete two-word container role.
- High: connect the selected private caller and buffer/extent cells to outer operation/transport inputs. Shared codec use does not establish native daemon-kext exchange.
- Medium: recover the staged raw64 expression at+0xa630, inactive-cache consumers and successful record ownership/cleanup.
- Medium: complete frame-epoch/alias proofs for eager shared preparers before assigning global SP-offset field types.
- Low: retain source-local labels until complete compiler-function/container semantics are proved; no IDB renames are made.

No new Mach endpoint or successful daemon-kext exchange is established. The full cross-layer goal remains active.

Publication environment note: the historical MacOSX27.0 SDK `mach/port.h` citation in `kernel_root_port_construct_report.md` is no longer installed. Its retained source hash is `959cc098bb307ccc44a2193a9ff7b8ec8bbcedc335933512cdbe13d3c9088185`; the installed MacOSX27.2 header hashes to `d4b2e42d1fd594f8cc9af492b4490d064bf913829e136b3774110f775c0711e5`. The manifest and independent audit record this single unavailable external primary reference, with no equivalence claim or substitution. All owned report/evidence links must still resolve. This increment's daemon proofs do not depend on that SDK header.

## Scoped quality gates

QG1: Pass. Technical source observations and falsification probes require no normative conclusion.

QG2: Pass for RH1-RH8. Assumptions, dependencies and tests are explicit.

QG3: Pass for the stated admission/allocation/header increment. Payload completion, insertion, back-edge and native interface closure remain active work.

QG4: Pass. Byte widths, exact node layout, u32 record-size bound, u64/128-bit geometry and reproducible limits/complexity are explicit.

QG5: Pass for bounded claims. Domain-restricted key identity, logical offsets versus native pointers, per-epoch scratch roles and masked bytes versus field values remain distinct.

QG6: Pass. Exact source hashes/recaptures, complete non-control-instruction coverage, original fixups, exhaustive banks and new/replayed solver queries support the claims. Memory guidance supplies no semantic premise.

QG7: Pass for the finite high/medium/low continuation list. No full-goal completion is claimed.


## Subsequent payload and append evidence

The [payload reconstruction and append report](daemon_reader_record_payloads_report.md) resolves the earlier payload-router frontier into exact u32/u64/span gates,scalar caller encodings and span address-aware recoding. It also establishes the actual append cursor back edge through1009a1808. Its source/SMT contracts supersede the earlier open append-back-edge item for the selected absent-result append path. Full lookup,replacement completion/retirement,the raw64 reader transform,native owners and cross-layer exchange remain unproved.
