# User-client parser caller and scalar command dispatch

Subsequent schema-search evidence: The [schema search report](userclient_schema_search_report.md) joins the actual early serializer stores to protected tag decoding, exact matching-node/sole-node-miss results, the caller-specific callback and buffer/extent preparation for another header read. Twenty-two source proofs, four prior rechecks, 900 evaluated fields, 122 controller-premise checks and three mutations pass. A synthetic source composition reproduces the fourteen-byte ADID field and finds it by key; retained states and derived substitutions remain distinct. Subsequent field decoding/meaning, packet-layer identity, native transport and new Mach emissions remain unknown. Earlier boundaries below retain their historical scopes.

Subsequent exhausted-input evidence: The [early schema-key report](userclient_early_schema_report.md) follows successful first-record exhaustion through C+0x418 container publication, source-fixed action selection and the caller-specific shared lookup request for raw key `0xfa834112`. Thirteen source proofs, four prior rechecks, 30 partial-state evaluations, 270 additional prefix-cell reconstructions, 390 resulting fields and three mutation controls pass. Independent parsing locates the same key in twelve identical retained ADID packet fixtures. Kernel field decoding/meaning, Avp selector 100 to primary selector 26 transport, native transaction identity and new Mach emission remain unknown. Earlier boundaries below retain their historical scopes.

The parser's actual caller searches its returned container for encoded tag `0x45e5918e`, reads a protected ten-byte record header, requires transformed type `0xa129` and a four-byte payload, then selects between two command values. The unmasked big-endian scalar values are `0x88594abe` and `0x73eba01e`. The first enters the previously recovered hash-input reader; the second enters a distinct body whose query/record request phase is now partially recovered in [the query-record report](userclient_query_records_report.md); complete command behavior remains unknown. Other scalar values set raw status `0xce515bb7` and enter common cleanup. These are conditional static contracts for the pinned image, not evidence of a successful native daemon transaction.

## Evidence and claim register

Primary evidence is the original kernel collection and normalized FairPlayIOKit image. The [extractor](triage_evidence/recover_userclient_command_dispatch.py), [independent source audit](triage_evidence/audit_userclient_command_dispatch.py) and [delivery verifier](triage_evidence/verify_userclient_command_dispatch_delivery.py) preserve the selected instructions, original table pointers, callback bank and reproducible SMT queries in [checks](triage_evidence/userclient_command_dispatch_checks.json.zst) and [audit](triage_evidence/userclient_command_dispatch_audit.json.zst).

| Claim | Established result | Dependencies |
| --- | --- | --- |
| CD1 | The parser caller splits exactly on W23=`0x31ae0066`; the selected failure path tests that same success constant again | CD-A1-CD-A3 |
| CD2 | Successful status selects either an explicit null-container frontier or a caller-specific lookup of tag `0x45e5918e`, output C+0x1f8 and continuation `0xfffffe000a656cfc` | CD-A1-CD-A4 |
| CD3 | Shared search matches the protected encoded tag, follows next pointers on mismatch and returns the matched node or an empty-list miss | CD-A1-CD-A5 |
| CD4 | The caller reads node.buffer and node.extent, checks a ten-byte header, then checks `10+L <= extent` with widened arithmetic | CD-A1-CD-A6 |
| CD5 | Type `0xa129` requires L=4, decodes bytes10..13 as a big-endian scalar, saves its encoded value and commits cursor14 | CD-A1-CD-A6 |
| CD6 | The exact two-value switch selects first-command entry, second-command entry or unsupported-value cleanup | CD-A1-CD-A6 |
| CD7 | The first command retains H at C+0x4b0 and reaches the existing hash-input reader conditionally; the second initially retains H at C+0x3a8 | CD-A1-CD-A7 |
| CD8 | Null container, search miss, selected parse rejection, other types and unsupported scalar values have distinct source status/cleanup edges | CD-A1-CD-A7 |
| CD9 | 685 selected instruction locations, 44 nonvacuous new UNSAT queries, four predecessor rechecks, 256 bank cases and four altered-evidence equality controls support these bounded results | CD-A1-CD-A8 |

Pinned normalized source SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Both images agree on every selected instruction word. The enclosing function `0xfffffe000a635208`..`0xfffffe000a666930` exclusive has 50,634 instruction words and byte SHA-256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297`.

Decoded checks SHA-256: `7e2e2dbd07769720d56219865aeb60ee9ed62695dd63bd5d79551ad3f228925e`. Decoded audit SHA-256: `7a552ddbb31ca2c1fd3f1c3bade719bdc30ad1b6218358d46240459a1a89323c`. The audit covers 37 spans, 30 separately frozen authenticated branch instructions, six alternate retag transforms and 16,215 proof instruction instances. Static pointer metadata and branch modifiers do not establish native pointer authentication.

## Caller phase and retained cells

C denotes the selected context X2, S the selected state X4 and F the selected SP. H is the parser output, N a selected list node, B its protected buffer and E its u32 extent. `TOKEN=0x886a1ca3`, `PHASE=0x7795e642`, `SUCCESS=0x31ae0066`. W-register arithmetic wraps modulo2^32; pointer/offset arithmetic uses64 bits.

| Cell / channel | Role | Original producer or use |
| --- | --- | --- |
| F+0x988 -> C+0x600 | Parser output cell address; its value is H | `0xfffffe000a635e74` / `0xfffffe000a635e78` |
| F+0x5a8 -> C+0x1f8 | This caller's lookup-result cell address; its value becomes N | `0xfffffe000a635c3c` / `0xfffffe000a635c40` |
| F+0x8e8 -> C+0x770 | Selected node-buffer cell address | `0xfffffe000a635c64` / `0xfffffe000a635c68` |
| C+0xc8 | Shared-search callback; this caller saves `0xfffffe000a656cfc` | `0xfffffe000a662ac8` |
| C+0x758 | Shared-search result-address channel; this caller saves &C+0x1f8 | `0xfffffe000a662ad0` |
| S+0x0 | Requested encoded tag | Shared-search entry |
| S+0xcf0 | Encoded scalar, initially SUCCESS, later V XOR SUCCESS | `0xfffffe000a656c6c`, `0xfffffe000a63acdc` |
| F+0xa78 / F+0xba8 | Reader cursor / retained record start, initialized0 | `0xfffffe000a656c70`, `0xfffffe000a656df8` |
| S+0xd88 | Transformed u16 type | `0xfffffe000a6370c0` |
| S+0x1c0 | Candidate cursor `10+L`, saved before body rejection | `0xfffffe000a6374a4` |
| S+0xde4 | Raw status saved by common caller cleanup | `0xfffffe000a656f24` |

The [staging report](userclient_container_staging_report.md) establishes the parser output/callback ABI. The [cleanup report](userclient_parser_cleanup_report.md) establishes selected failure publication of null H and saved W23 before return to `0xfffffe000a656c08`. This increment starts with that caller phase; full original-entry and native frame identity remain unknown.

At `0xfffffe000a656c1c`, W23 is compared with SUCCESS. Success selects private index0x71c and `0xfffffe000a656c44`; non-success selects0x68 and `0xfffffe000a65f358`. The subsequent comparison at `0xfffffe000a65f38c` computes the same SUCCESS constant. Under the preceding non-success premise, its index0xb11 edge to `0xfffffe000a65f3b4` cannot be selected; index0x840 reaches `0xfffffe000a656f00`. This is a conditional unreachable edge, not evidence of a second distinguished error value or a claim about all callers of that block.

## Lookup request, traversal and byte representation

The nonnull-H path clears C+0x1f8, initializes S+0xcf0 to SUCCESS and F+0xa78 to0. At `0xfffffe000a656ca4` it requests tag `0x45e5918e` in W9, H in X22, &C+0x1f8 in X10 and private return index0x6b in W8. The branch at `0xfffffe000a656cf8` enters shared search `0xfffffe000a662ab4`. Its saved callback is this caller's `0xfffffe000a656cfc`, distinct from the publication and copying-reader callers.

The [publication report](userclient_record_publication_report.md) covers the shared search with arbitrary requested and stored tags. Here the original instructions are composed again with the command caller's actual request and continuation. Empty H.head returns miss `0xce515bda`, null result and the caller callback; the caller's status gate selects common cleanup. Each nonempty iteration reads N.buffer, decodes its first four protected bytes and compares the encoded result with REQUEST. Mismatch follows N.next and repeats the empty/decode gate. Match publishes N at C+0x1f8, returns SUCCESS and enters `0xfffffe000a656d48`.

The callback's bank uses FL=`0xfffffe000792fcc0`, FR=`0xfffffe00079391f0`, key0x87, composition constant0xdf, additive-0x93 and pool bias-4. All256 byte inputs are checked. It produces original descriptor `0xfffffe000847bce0` and phase multiplier `0x4d08a3fb`; no retirement call occurs in this search callback. Native type-site equivalence or deallocation does not follow from retaining that descriptor.

The nominal protected-byte path uses K0=`0x02e859d27e491464`, K1=`0x4dae26df20976138` and:

```text
mask8(a) = low8((((ROR64(a & ~7, 8) + K0) XOR K1)
                >> ((a & 7) * 8)))
plain[j] = stored[B+j] XOR mask8(B+j)
D = BE32(plain[0:4]); T = D XOR SUCCESS
U = BE16(plain[4:6]) XOR 0x365e
L = BE32(plain[6:10])
V = BE32(plain[10:14])
```

T=`0x45e5918e` therefore corresponds to unmasked header word D=`0x744b91e8`. The raw stored bytes depend on B. These numbers specify the recovered protected-node representation; native external request bytes and the full daemon producer are not established. Six alternate pointer-retag instructions are separately checked only as bit transforms; the composed decoder uses explicit nominal pointer-branch guards.

## Scalar reader and complete command-value switch

The caller retains B at C+0x770, loads E from N+0x10 as u32 and branches on B. The all-buffer64 nullable gate is independently proved at a successful-search return cut with valid N. Composed search proofs additionally require accessible nonnull B for their earlier four tag-byte reads; a zero B is not inferred to be a valid incoming matched-search state.

For the composed nominal path, header admission at `0xfffffe000a656e1c` is exactly E>=10. The protected decoder reads type at offset4 and length at offset6. Body admission is exactly `10+ZE64(L)<=ZE64(E)`. The candidate is saved at S+0x1c0 before rejection. Because E is u32, accepted offsets do not wrap, and accepted scalar access offsets0..13 lie within the retained node extent.

At `0xfffffe000a637524`, U!=0xa129 branches to the other-type dispatcher. For U=0xa129, encoded length is compared with SUCCESS-4, which equals SUCCESS XOR4. L=4 selects payload decoding at `0xfffffe000a637568`; other L selects cleanup with retained raw status `0xce515bb8`. Four protected bytes at offsets10..13 produce V XOR SUCCESS. The store at `0xfffffe000a63acdc` publishes that value to S+0xcf0. The final type gate commits cursor14 and enters command dispatch `0xfffffe000a63ad3c`. E may exceed14; this path does not require the node extent to equal14.

| Decoded V | Compared encoded V XOR SUCCESS | Decision location | Selected edge |
| --- | --- | --- | --- |
| `0x88594abe` | `0xb9f74ad8` | `0xfffffe000a63ad50` B.EQ | `0xfffffe000a63dd14` |
| `0x73eba01e` | `0x4245a078` | `0xfffffe000a63ad60` B.NE not taken | Fallthrough `0xfffffe000a63ad64` |
| All other u32 values | Neither comparison value | `0xfffffe000a63ad60` B.NE taken | `0xfffffe000a63ddd0` |

```text
parser SUCCESS, H nonnull
  -> lookup T=45e5918e -> matched node N
  -> B nonnull, E>=10, 10+L<=E
  -> U=a129, L=4 -> protected BE32 scalar V
       +-- V=88594abe -> first command -> prior hash-input reader, if Q!=0
       +-- V=73eba01e -> second command entry, body still open
       +-- otherwise -> status ce515bb7 -> caller cleanup
```

## Command entries and status frontiers

The first command loads Q from F+0x738, retains H at C+0x4b0, clears C+0x128 and initializes S+0xaa8 to encoded zero. Q!=0 selects private index0x8c4 and `0xfffffe000a63dd80`; Q=0 selects0x8ed and common cleanup with raw status `0xce515bbf`. The [input-reader report](userclient_input_reader_report.md) independently establishes that next reader's requested tag `0x2685a3ce`, copied payload output, encoded-length output and hash-gate continuation. The command-field tag, command scalar and subsequent hash-input tag are distinct channels. No semantic command name is assigned from these values alone.

The second command begins at `0xfffffe000a63ad64`. Its selected initial instructions set W21=PHASE, W23=0x9dc and copy H from C+0x600 to C+0x3a8. W23=0x9dc is recorded as an entry-phase value. The later [query-record increment](userclient_query_records_report.md) establishes conditional helper calls, construction packets and continuations; native success/error meaning and complete command effects remain unknown.

| Condition / phase | Raw status at established frontier | Frontier / consequence |
| --- | --- | --- |
| Parser non-success with already published null H | Original W23 | Same-success retest fails; cleanup saves W23 at S+0xde4 and selects `0xfffffe000a665e90` |
| Parser SUCCESS with null H | `0xce515bbf` | Explicit null-container block saves status and selects `0xfffffe000a665e90` |
| Empty command search | `0xce515bda` | Caller rejects non-success and selects `0xfffffe000a656f00` |
| Null B at isolated successful-search return cut | `0xce515bbf` | Nullable node-buffer gate selects common cleanup |
| Short header, oversized body, or U=a129 with L!=4 | `0xce515bb8` | Selected bounds/type path selects common cleanup |
| U=6685 or U=b2db after accepted bounds | `0xce515ae1` | Other-type dispatcher joins final U=a129 test, fails it and selects cleanup |
| Other U excluding a129/6685/b2db after accepted bounds | Retained `0xce515bb8` | Direct branch from `0xfffffe000a63a634` to cleanup |
| Accepted scalar before command switch | `0xce515ae1` | Final scalar gate selects command dispatch despite this W23 value |
| Unsupported command scalar | `0xce515bb7` | `0xfffffe000a63ddd0` assigns status, then branches to cleanup |

Common cleanup at `0xfffffe000a656f00` saves W23 to S+0xde4, sets callback index W24=0x1a and selects `0xfffffe000a656f4c` for nonnull H or `0xfffffe000a665e90` for null H. This increment stops at those frontiers. The previous parser destructor report uses callback0x50; applying its output/status publication wholesale to this different caller would require a new composition. Staged-buffer retirement and final caller return remain open.

## Original private table mapping

| Private index | Original slot | Target |
| --- | --- | --- |
| 0x3f | `0xfffffe0008473118` | `0xfffffe000a6370ac` |
| 0x68 | `0xfffffe0008473260` | `0xfffffe000a65f358` |
| 0x6b | `0xfffffe0008473278` | `0xfffffe000a656cfc` |
| 0x181 | `0xfffffe0008473b28` | `0xfffffe000a63d624` |
| 0x1b7 | `0xfffffe0008473cd8` | `0xfffffe000a63acd0` |
| 0x1c5 | `0xfffffe0008473d48` | `0xfffffe000a6382a0` |
| 0x1d0 | `0xfffffe0008473da0` | `0xfffffe000a63747c` |
| 0x22e | `0xfffffe0008474090` | `0xfffffe000a637128` |
| 0x22f | `0xfffffe0008474098` | `0xfffffe000a656ef0` |
| 0x252 | `0xfffffe00084741b0` | `0xfffffe000a63930c` |
| 0x300 | `0xfffffe0008474720` | `0xfffffe000a656ca0` |
| 0x316 | `0xfffffe00084747d0` | `0xfffffe000a665e50` |
| 0x48e | `0xfffffe0008475390` | `0xfffffe000a63acf0` |
| 0x49a | `0xfffffe00084753f0` | `0xfffffe000a662ab4` |
| 0x49c | `0xfffffe0008475400` | `0xfffffe000a665e90` |
| 0x4a7 | `0xfffffe0008475458` | `0xfffffe000a656f4c` |
| 0x50c | `0xfffffe0008475780` | `0xfffffe000a662c60` |
| 0x50d | `0xfffffe0008475788` | `0xfffffe000a662c44` |
| 0x52d | `0xfffffe0008475888` | `0xfffffe000a662c00` |
| 0x630 | `0xfffffe00084760a0` | `0xfffffe000a662be0` |
| 0x63e | `0xfffffe0008476110` | `0xfffffe000a662b00` |
| 0x69d | `0xfffffe0008476408` | `0xfffffe000a637514` |
| 0x6ba | `0xfffffe00084764f0` | `0xfffffe000a656f00` |
| 0x6cc | `0xfffffe0008476580` | `0xfffffe000a637568` |
| 0x71c | `0xfffffe0008476800` | `0xfffffe000a656c44` |
| 0x840 | `0xfffffe0008477120` | `0xfffffe000a656f00` |
| 0x874 | `0xfffffe00084772c0` | `0xfffffe000a656d9c` |
| 0x8c4 | `0xfffffe0008477540` | `0xfffffe000a63dd80` |
| 0x8ed | `0xfffffe0008477688` | `0xfffffe000a656f00` |
| 0x95d | `0xfffffe0008477a08` | `0xfffffe000a656d48` |
| 0xb11 | `0xfffffe00084787a8` | `0xfffffe000a65f3b4` |
| 0xb47 | `0xfffffe0008478958` | `0xfffffe000a63ad3c` |
| 0xe07 | `0xfffffe0008479f58` | `0xfffffe000a637138` |
| 0xe44 | `0xfffffe000847a140` | `0xfffffe000a656e48` |
| 0xe91 | `0xfffffe000847a3a8` | `0xfffffe000a63d680` |
| 0xeb6 | `0xfffffe000847a4d0` | `0xfffffe000a662c44` |

These indices are internal dispatch/callback indices. No new Mach message ID, port right, message emission site or IOUserClient selector follows from this table. External contracts remain in [Mach ports](mach_ports_report.md), [interface ABI](interface_abi_report.md) and [investigation status](interface_investigation_status.md).

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CD-A1: Pinned original/normalized images, original pointers and predecessor receipts | CD1-CD9 | Fresh dual-image/full-container custody, generator/dependency hashes, frozen-query reconstruction and four altered-evidence equality controls |
| CD-A2: Selected C/S/F roots, phase tokens and retained bank/key epochs | CD1-CD8 | Three original cell roots, exact request/callback stores and query all incoming state/call/alias writers separately |
| CD-A3: AArch64 W/X widths, unsigned comparisons and modeled arithmetic/memory semantics | CD1-CD9 | Arbitrary statuses/pointers/extents, widened bounds, all256 bank inputs and separate retag transforms |
| CD-A4: Parser status/H supplied at the established caller cut; whole original-entry identity is not proved | CD2, CD8 | Null/non-null H cases, parser output/callback predecessor recheck, recover all native entry and frame epochs |
| CD-A5: Valid H/N fields, accessible first four protected tag bytes and a finite stable next chain | CD3-CD8 | Empty/match/mismatch/successor cases; establish native storage lifetime/locking and every intervening writer before extending to native traversal |
| CD-A6: Stable node bytes across search/header reread, accessible selected buffer, distinct valid frame/context/state/node storage and nominal pointer branch guards | CD4-CD8 | Arbitrary14 symbolic bytes, exact header/body/type gates, extent>14 case, all read offsets and independent nullable result cut; test native aliases, mutation epochs and alternate pointer execution separately |
| CD-A7: Entry stores and cleanup branch requests do not establish subsequent body, retirement or business semantics | CD7-CD8 | Exact first-reader predecessor proofs, second-entry stores, distinct callback0x1a/0x50 and recovery of each next source frontier |
| CD-A8: Native authentication, external byte identity, successful cross-layer transaction and complete interfaces remain unknown | CD9 limits | Correlate one successful daemon/provider exchange with exact images, message/selector, bytes, object epochs and returned status |

## Bounded continuation and cost

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Second command body from `0xfffffe000a63ad64` | Recover its actual facilities, data consumers and deeper ABI requests |
| High | Common cleanup callback0x1a and staged-buffer retirement | Bind saved caller status to exact object/buffer retirement requests and final return |
| High | Native daemon producer of command tag/scalar and successful provider transaction | Connect these conditional record contracts to actual external control and daemon/kext interaction |
| High | Node storage aliases, mutation epochs and synchronization | Validate tag/header reread consistency and traversal premises |
| Medium | Repeated success check after parser failure | Establish all incoming phase states before attributing broader obfuscation or dead-code behavior |
| Medium | Cursor14 with E>14 | Determine the producer's record-extent convention and remaining-byte policy |

For k visited finite nodes, conditional lookup takes O(k) source work and O(1) auxiliary state. This caller's header/scalar/switch work is O(1), excluding subsequent command bodies and cleanup. Extraction takes O(B+I+256R) time/space for pinned input bytes B, selected instructions I and bank rules R. Proof construction takes O(instruction instances+query DAG) time/space; SMT search is separate with30 s/query limits. Header/scalar/extents use bytes; type is u16, tag/scalar/status/extent are u32 and pointers/cursors are u64. No native target, allocator, Mach endpoint or IDB is executed or modified.

## Quality gates

- **QG1**: Source/control/data/ABI claims require no normative conclusion.
- **QG2**: CD-A1-CD-A8 enumerate assumptions and falsification probes.
- **QG3**: The selected caller, shared lookup, header/scalar gates, complete scalar-value switch, command entries and bounded rejection/cleanup frontiers are covered; the full objective remains active.
- **QG4**: Byte widths, BE decoding, u32/u64 arithmetic, cursor14 and conditional complexity are explicit.
- **QG5**: Command field/tag/value channels, raw status versus phase meaning, nominal storage versus null-result cut, emitted cleanup requests versus native retirement and caller-specific callbacks are distinct.
- **QG6**: Dual-image words, original table/bank records, 44 nonvacuous source formulas, four predecessor rechecks, 256 bank cases and four custody equality controls support bounded claims.
- **QG7**: Ranked continuation retains second-body recovery, caller cleanup, native producer/transaction identity, aliasing and remaining-byte semantics.

## Caller cleanup and copy-back increment

The caller cleanup callback0x1a now composes with container/list destruction, optional auxiliary retirement, protected copy-back, outer retirement and a guarded decoded status result. Second-command body semantics remain open. See the [caller-return report](userclient_caller_return_report.md) for original requests, proofs, scope and assumption probes.


## Selector26 transfer boundary

The unsupported-command raw value0xce515bb7 decodes arithmetically to0xffff5bd1 under the selected guarded cleanup theorem. The surrounding adapter preserves that normal return while requesting copy-out before the handler status gate; no native command reachability or successful transfer is inferred. [Evidence and exact boundaries](userclient_transfer_boundary_report.md).


## Second-command query records

The second command now has source-proved version/capability helper calls,three conditional scalar-record request packets and exact callback status gates. Its first selected constructor requests a32 B typed node and14 B data buffer before entering a protected writer. Complete command/writer/publication semantics remain open. [Evidence and exact boundaries](userclient_query_records_report.md).


The [auxiliary copy contract](userclient_auxiliary_copy_report.md) now establishes the conditional publication stores, exact extent/success callback gate, saved-mode split and reverse byte-transcode step between auxiliary and staging masks. Original argument producers establish counter=N and mode=N XOR0x7c233caf, supporting conditional N-byte composition; complete serializer reachability and native transaction pairing remain unknown. This increment establishes no additional Mach port endpoint.
