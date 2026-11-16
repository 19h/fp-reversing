# Query scalar records: protected bytes and publication request

The three second-command constructor requests conditionally produce exact 14 B records. After removing the address-dependent storage mask, their fields are a big-endian tag, type bytes `97 77`, big-endian payload length4, and a big-endian scalar. The scalar values are `0x4c0b0000`, `0x1f8` and `0x99ab`. The raw type normalizes to `0xa129` under the recovered parser rule. Each completed writer requests the shared list lookup using the original tag control and W8 callback index0x6c (separate W0 control0x19). The linked publication increment establishes conditional insertion/replacement and saved return; actual native list contents/order and daemon transaction identity remain unknown.

## Evidence and claim register

Primary evidence is the original kernel collection and normalized kext. The [extractor](triage_evidence/recover_userclient_query_writer.py), [instruction audit](triage_evidence/audit_userclient_query_writer.py), [delivery verifier](triage_evidence/verify_userclient_query_writer_delivery.py), [checks](triage_evidence/userclient_query_writer_checks.json.zst) and [formulas](triage_evidence/userclient_query_writer_audit.json.zst) retain the source words and bounded obligations. This increment composes the [query requests and allocation ABI](userclient_query_records_report.md), specializes the [shared record writer](userclient_record_writer_report.md), and uses the established [parser normalization](userclient_record_metadata_report.md). The existing [parser-node publication](userclient_record_publication_report.md) describes a different callback channel; its list effects are not assumed for these requests.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| QW1 | All three original request paths supply the query node, exact tag/scalar controls and alternate writer phase | QW-A1-QW-A4 |
| QW2 | Four protected stores decode to the big-endian tag control XOR SUCCESS | QW-A1-QW-A5 |
| QW3 | The selected alternate type writer emits decoded bytes97 77; parser normalization gives0xa129 | QW-A1-QW-A6 |
| QW4 | The next four stores encode payload length4 and select the query scalar gate | QW-A1-QW-A5 |
| QW5 | With typecontrol0x3594, the gate admits exactly extentcontrol=SUCCESS-4; other u32 extent controls select retirement | QW-A1-QW-A4 |
| QW6 | Four final stores encode the scalar control XOR SUCCESS; the complete node has14 B, retained buffer/callback custody and the publication continuation | QW-A1-QW-A5 |
| QW7 | The next block clears C+0x50 and requests shared lookup with H, original tag and W8 index0x6c; lookup entry retains that callback and output/tag state; actual list effects remain open | QW-A1-QW-A7 |

Normalized-image SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original-collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. The containing `_PRnut72j9` range is `0xfffffe000a635208`..`0xfffffe000a666930` exclusive,50,634 words, SHA-256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297`; the original C export identifies it at line199131. Eight new spans contain264 words. Four captured MOVK alternatives are excluded under nominal-pointer guards, leaving260 newly modeled locations, in addition to436 distinct predecessor locations. Eight terminal transfers and eleven original chained branch pointers are recaptured separately.

Decoded checks SHA-256: `1a183d8958078e52c40c5cdd817d317134781888c9a0159aa732520ffac7b1bb`. Decoded audit SHA-256: `93fdbacd3030e57c85cb8a13a31592f5529568892a65caa66f88c2562ff44db2`. There are29 new nonvacuous UNSAT obligations, six re-solved predecessor formulas,15,474 source instruction instances in those new obligations,1,280 exhaustive bank-composition cases, and24 record profiles covering all eight buffer-base residues modulo8 for each request. The profiles check336 byte stores separately from the proof-instance count. One source-literal mutation produces a SAT counterexample. No target execution or new IDA observation is used; the supplied image/reference evidence is sufficient for this boundary.

## Exact recovered records

F is the selected frame SP, C the4096 B context, S the16384 B workspace, H the selected container, J the32 B node and B its14 B data buffer. `SUCCESS=0x31ae0066`, `TOKEN=0x886a1ca3`, `PHASE=0x7795e642`. Scalars and controls are u32; type controls are u16; pointers are u64.

| Request | Original tag control | Decoded tag | Decoded scalar | Saved callback |
| --- | --- | --- | --- | --- |
| First | 0x33b7bc52 | 0x0219bc34 | 0x4c0b0000 | `0xfffffe000a656f8c` |
| Second | 0xb0ac8a39 | 0x81028a5f | 0x000001f8 | `0xfffffe000a657018` |
| Third | 0xa024e3ab | 0x918ae3cd | 0x000099ab | `0xfffffe000a65f358` |

| Request | Complete decoded14 B record |
| --- | --- |
| First | `02 19 bc 34 97 77 00 00 00 04 4c 0b 00 00` |
| Second | `81 02 8a 5f 97 77 00 00 00 04 00 00 01 f8` |
| Third | `91 8a e3 cd 97 77 00 00 00 04 00 00 99 ab` |

These are decoded node bytes. Native protected storage differs with its address. Meaning of0x99ab remains unknown. The first two scalar values agree with the earlier helper values, but the constructor uses its literal request controls rather than consuming those helper result words. No additional semantic name is inferred from a tag value.

For address a, define the byte mask using u64 arithmetic:

```text
K0 = 0x02e859d27e491464
K1 = 0x4dae26df20976138
mask(a) = low8(((ROR64(a AND ~7,8) + K0) XOR K1)
               >> (8 * (a AND 7)))
stored[B+j] = decoded_record[j] XOR mask(B+j), 0 <= j < 14
```

| Offset (B) | Extent (B) | Decoded value |
| --- | --- | --- |
| 0 | 4 | BE32(tagcontrol XOR SUCCESS) |
| 4 | 2 | 97 77 |
| 6 | 4 | BE32(4) |
| 10 | 4 | BE32(scalarcontrol XOR SUCCESS) |

The source word writer first transforms its input by bytewise XOR equivalent to0x2502309f. The constructor supplies tagcontrol XOR0x14ac30f9; their composition is tagcontrol XOR0x31ae0066. The length channel supplies `(SUCCESS-4) XOR0x14ac30f9`, which composes to4. The scalar channel similarly yields scalarcontrol XOR SUCCESS. All three word passes are explicitly followed through original instructions, rather than assuming that a common writer preserves the same offset or continuation.

## Selected source/control path

```text
original request -> constructor packet -> node/data allocation return cuts
 -> query writer entry: X16=&J.buffer, W24=0x13c, W25=TOKEN
 -> shared setup: query node C+0x58, query type S+0x1b2
 -> word writer: tag at offsets0..3 -> alternate type writer
 -> type at offsets4..5 -> word writer: length at offsets6..9
 -> typecontrol/extentcontrol gate -> scalar bridge
 -> word writer: scalar at offsets10..13
 -> query publication request -> shared lookup entry
 -> retain callback6c/tag/output -> nonnull-H search frontier
```

| Block/source | Established effect |
| --- | --- |
| `0xfffffe000a661884`..`0xfffffe000a6618e8` | Derives W24=0x13c, W23=tagcontrol XOR0x14ac30f9, selected node-buffer cell and original writer target |
| `0xfffffe000a654b38` | Loads query J from C+0x58 |
| `0xfffffe000a654b40`, `0xfffffe000a654b48` | Loads query extentcontrol from S+0x94 and scalarcontrol from S+0x110 |
| `0xfffffe000a654b68` | Loads query typecontrol0x3594 from S+0x1b2 |
| `0xfffffe000a654c68` | Word writer selects its saved continuation from the current W24 |
| `0xfffffe000a654ccc`, `0xfffffe000a654d18`, `0xfffffe000a654d74`, `0xfffffe000a654db0` | Four byte stores, reused for tag, length and scalar |
| `0xfffffe000a655014`, `0xfffffe000a655038` | Alternate query type stores at B+4 and B+5 |
| `0xfffffe000a654dd0`..`0xfffffe000a654e30` | Selected typecontrol0x3594 and exact extentcontrol equality gate |
| `0xfffffe000a654e38`..`0xfffffe000a654e6c` | Restores the query node-buffer cell and scalar control; affine offset causes the next word pass to write at B+10 |
| `0xfffffe000a655cb8`..`0xfffffe000a655d34` | Prepares query publication request with W8=0x6c and W0=0x19 |
| `0xfffffe000a662ab8`..`0xfffffe000a662afc` | Retains W8-selected callback, requested tag and output address, then selects nonnull-H search |

Shared setup reads independent words for four other node channels, C+0x768/C+0x458/C+0x140/C+0x6b8, and other workspace type/length controls. The model leaves those words arbitrary. This selected route forms their buffer-field addresses but does not dereference their node pointers. It only dereferences the admitted query J and B. Equal-looking parser/query metadata registers therefore do not establish the same active node channel.

The selected type writer derives low8(-0x5e XOR0x35)=0x97 and low8(0x3594 XOR0xffffffe3)=0x77. The existing parser transformation gives `BE16(97 77) XOR0x365e = 0xa129`. This is a format correspondence. Complete parser acceptance or the meaning of every type0xa129 consumer is not established here.

| Private index | Original target | Selected use |
| --- | --- | --- |
| 0x439 | `0xfffffe000a654c64` | Common four-byte writer |
| 0x13c | `0xfffffe000a654fc8` | Query type writer after tag |
| 0x2c9 | `0xfffffe000a654c44` | Restore key and select next word pass |
| 0x165 | `0xfffffe000a654dcc` | Query type/extent gate after length |
| 0xc44 | `0xfffffe000a654e34` | Admitted scalar bridge |
| 0x871 | `0xfffffe000a664074` | Extent mismatch retirement frontier |
| 0x129 | `0xfffffe000a655cb4` | Query publication request after scalar |
| 0x49a | `0xfffffe000a662ab4` | Shared list lookup entry |
| 0x6c | `0xfffffe000a662b64` | Query lookup callback retained at C+0xc8 |
| 0x630 | `0xfffffe000a662be0` | Nonnull-container search |
| 0x63e | `0xfffffe000a662b00` | Captured null-container branch, outside the admitted H premise |

The arbitrary-u32 gate proof assumes the selected typecontrol0x3594, retains the direct type-branch guard and establishes the exact success/mismatch frontier. Other type controls and subsequent retirement effects are outside that theorem.

## Outgoing publication request and architectural limit

| Channel | Exact state at outgoing transfer |
| --- | --- |
| H | X22=u64[C+0x20], the original selected container |
| Tag | W9=u32[S+0x1d0], the original tag control |
| Lookup callback index | W8=0x6c; entry retains table[0x6c]=`0xfffffe000a662b64` at C+0xc8 |
| Separate private control | W0=0x19; its downstream meaning is unknown |
| Roots and phase | X2=C, X4=S, X7=private table, W1=PHASE, W3=TOKEN, W30=SUCCESS |
| Transfer | X11=`0xfffffe000a662ab4`, BRAA at `0xfffffe000a655d34` |
| Caller candidate-result cell | C+0x50 cleared at `0xfffffe000a655ccc`; identity with the lookup output address remains unproved |
| Pending node | C+0x58=J, with J.next=J.previous=0, J.extent=14 and J.buffer=B |
| Constructor return | C+0x260=`0xfffffe000a664230`, retained |
| Request callback | C+0x5a8 retains the request-specific callback in the first table |
| Lookup output address | X10 loaded from F+0x348 and retained at C+0x758 by `0xfffffe000a662ad0`; its producer remains unknown here |
| Retained lookup tag | Original tag control stored at S+0 by `0xfffffe000a662acc` |
| Admitted nonnull-H search | Lookup entry selects `0xfffffe000a662be0`; actual node search is beyond this increment |

The shared lookup target also appears in the parser-node publication work. Its incoming W8 callback index and caller node/result state differ here. The source explicitly consumes W8 for callback selection; W0=0x19 is a separate control. Matching target addresses do not prove identical publication semantics. The writer establishes one pending record per admitted construction; it does not establish all three records simultaneously survive, are appended in request order, replace matching input records, or contribute exactly42 B to the serializer's node sum L.

The [serializer emission contract](userclient_serializer_emission_report.md) establishes how a finite stable node list is transcoded into auxiliary bytes and padded. Applying it to these exact records requires the intervening lookup/publication/return path and resulting list state. No Mach port is allocated, transmitted or identified by these internal writer blocks; private table indices and record tags are not Mach message identifiers or user-client selectors.

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| QW-A1: Only the pinned original and normalized images are covered | QW1-QW7 | Complete containing-range hash, every selected word, original branch pointers and fresh predecessor extraction; recapture for another build |
| QW-A2: The modeled AArch64 integer, byte-store, rotate and register-shift semantics apply | QW1-QW7 | Exact byte/address obligations over symbolic bases,24 residue profiles and altered high-type MOV literal SAT control |
| QW-A3: F/C/S/H/J/B are valid, nonwrapping and pairwise separate over the declared storage extents | QW1-QW7 | Address obligations and interval constraints; native allocator identity/capacity remains unknown |
| QW-A4: Original request phase, accepted nonnull helper/allocation return cuts and ordinary call preservation hold | QW1, QW5-QW7 | Reconstruct each request through allocation cuts, freshly recapture predecessor source, check1,280 bank cases and re-solve request/entry obligations |
| QW-A5: Nominal-pointer guards hold at each reused word-store site | QW2-QW4, QW6-QW7 | Four explicit retag sites,12 guards across three word passes per record and nonvacuous premises; native alternate-pointer behavior is unknown |
| QW-A6: The previously proved parser normalization is applicable as a field rule | QW3 | Re-solve its source formula and retain the explicit raw-type XOR correspondence; complete parser acceptance is a separate probe |
| QW-A7: Lookup result, F+0x348 producer, publication ordering/retirement and native daemon pairing remain unknown | QW7 limit | Recover index0x6c callback, C+0x50/C+0x58 data flow and saved constructor return; correlate a complete native request/response |

## Bounded continuation and cost

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | Shared lookup index0x6c callback and query publication path | Establish insertion/replacement, result cell, pending-node custody and return to C+0x260/C+0x5a8 |
| High | H before/after all three constructions | Determine surviving records, list order and actual L;42 B from three records is presently only a candidate subtotal |
| High | Native synchronization, node/data ownership and stable list across size/emission passes | Discharge environmental premises connecting writer, serializer and caller |
| High | Observed daemon endpoint/selector/transfer/request/response | Establish one native cross-layer transaction using these bytes |
| Medium | Original F+0x348 producer and other query type paths | Complete lookup-private ABI and bound alternate constructor behavior |
| Medium | Consumers of normalized type0xa129 and scalar0x99ab | Determine semantics without treating numerical resemblance as identity |
| Low | Other callers of the shared word/type writers | Identify candidate shared-format interfaces requiring independent channel/phase verification |

The selected writer performs14 byte stores per record:4 tag+2 type+4 length+4 scalar, bounded O(1) local time/state per record, excluding allocation and lookup/publication. Three admitted constructions perform42 such stores, which does not determine the final list size. Extraction is O(B+I) time/space for consumed image bytes B and instructions I. Formula construction is O(instruction instances+query DAG); SMT search is separate with30 s/query limits. Bank validation is O(256R) for R=5. Profile checking is O(3*8*14) decoded byte comparisons. These are static instruction-model results, not measured native timings.

## Quality gates

- **QG1**: Claims are factual source/data/control/ABI analysis.
- **QG2**: QW-A1-QW-A7 identify dependencies and falsification probes.
- **QG3**: All three writer entries, exact tag/type/length/scalar bytes, gate outcomes, node custody and outgoing publication request and lookup-entry retention are covered conditionally; full interface work remains active.
- **QG4**: u16/u32/u64 widths, big-endian fields,14 B records,32 B nodes, mask operations, source/profile accounting and complexity are explicit.
- **QG5**: Private versus decoded tags/types, helper results versus literal controls, shared writer versus selected channel, pending node versus surviving list, and static versus native evidence remain distinct.
- **QG6**: Dual-image capture, eleven original pointers,29 nonvacuous formulas, six prior rechecks, fresh predecessor extraction,1,280 bank cases,24 profiles and the mutation counterexample support the bounded claims.
- **QG7**: Ranked continuation preserves lookup/publication, resulting list state, ownership/synchronization, native pairing, unresolved private ABI and semantic context.


The [query publication contract](userclient_query_publication_report.md) now establishes conditional first-match replacement or miss append, exact list links, original old-data/typed retirement requests and raw-success return through the saved constructor/request callbacks. The output-slot producer identifies &C+0x50 under a stable frame-slot premise. Separate finite-list lemmas show that three successful distinct-tag14 B constructions retain42 B of records and, for accepted sizing/copy, imply M=N>=64 B. Actual native list contents/order, allocation/free effects, synchronization, full failure cleanup and daemon transaction pairing remain unknown; no additional Mach endpoint is established.
