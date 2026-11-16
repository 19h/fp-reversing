# Auxiliary serializer bytes and publication

Under a finite stable-list and valid-storage contract, the auxiliary producer concatenates each node's decoded bytes in list order, then appends a terminal record: four zero tag bytes, type bytes 50 db, big-endian payload length P, and P zero bytes. The complete output has M=L+10+P bytes, where L is the node-byte sum and P is the previously proved 1-16 B padding count. The producer writes the buffer under the auxiliary address mask, publishes its pointer and M XOR SUCCESS, sets flag1/raw SUCCESS and selects the saved callback. Its terminal header matches the recovered parser's normalized zero-tag/type 0x6685 shape. The linked query-writer increment establishes three scalar-node byte strings; their list publication and native transaction pairing remain unknown.

## Evidence and claim register

The [extractor](triage_evidence/recover_userclient_serializer_emission.py), [instruction audit](triage_evidence/audit_userclient_serializer_emission.py), [delivery verifier](triage_evidence/verify_userclient_serializer_emission_delivery.py), [checks](triage_evidence/userclient_serializer_emission_checks.json.zst) and [proofs](triage_evidence/userclient_serializer_emission_audit.json.zst) retain source bytes, formulas and exact boundaries. Primary sources are the original kernel collection and normalized kext. Predecessors cover [size/allocation](userclient_serializer_extent_report.md), [auxiliary-to-staging transcode](userclient_auxiliary_copy_report.md), [parser metadata and terminal predicate](userclient_record_metadata_report.md), [query requests](userclient_query_records_report.md), and [final caller copy/retirement](userclient_caller_return_report.md).

| Claim | Established result | Dependencies |
| --- | --- | --- |
| EM1 | Copy setup supplies cursor0, source/destination keys and encoded M; node extent0 bypasses bytes and advances the link | EM-A1-EM-A4 |
| EM2 | Each nonzero node copies exactly E decoded bytes from its source to the auxiliary prefix, using reverse byte order within that node and preserving the next iteration's phase | EM-A1-EM-A5 |
| EM3 | The ten emitted header bytes decode exactly to tag0, type bytes 50 db and big-endian P | EM-A1-EM-A5 |
| EM4 | The normalized terminal type is0x6685; the complete terminal record occupies exactly 10+P B and fills the suffix through M | EM-A1-EM-A6 |
| EM5 | The zero loop initializes counter P, writes exactly P protected zero bytes and selects publication after its final byte | EM-A1-EM-A5 |
| EM6 | Publication stores the actual auxiliary pointer and encoded M, sets flag1/raw SUCCESS and selects the saved callback; finite stable-list composition closes the selected serializer path | EM-A1-EM-A6 |
| EM7 | 495 captured words, 482 modeled locations, 17 nonvacuous source queries, six prior rechecks and 16 terminal profiles support the bounded contract | EM-A1-EM-A7 |

Normalized image SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Original collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. All 495 selected words, 11 separately captured terminal transfers and 12 original chained branch pointers are checked against both sources. Thirteen captured MOVK retag alternatives are excluded under explicit nominal-pointer branch guards, leaving 482 modeled instruction locations. None of these checks establishes native PAC authentication.

Decoded checks SHA-256: `28ba2f73f67bc6bc54c154fd29bf9b0f798291751a16f506c19d5d7b1767ee07`. Decoded audit SHA-256: `67ff9460d93b3250764bff70fd509c59b818d287df5c2997ede1cd57a835eae9`. The 17 new source proofs record 3,574 instruction instances. Six predecessor formulas are re-solved. Sixteen terminal-only instruction-model profiles exercise all padding counts, all eight auxiliary-base residues modulo8, 136 zero-byte steps and 8,000 additional source instruction instances. The finite-profile instances are excluded from 3,574. A changed terminal-type literal produces a SAT counterexample.

The containing routine is `_PRnut72j9`, `0xfffffe000a635208`..`0xfffffe000a666930` exclusive, 50,634 words, complete containing-range SHA-256 `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297`. The retained original C export names it at line 199131. This report recovers selected internal serializer blocks; complete semantics of that obfuscated routine remain unresolved. No target execution, IDB mutation or new live IDA observation supplies this increment.

## Exact output and its control/data path

F denotes the selected frame SP, C the context, S the workspace, H the container, J_i a node, B_i its byte source and A the auxiliary destination. Node extent E_i is u32[J_i+0x10], source B_i is u64[J_i+0x18], and next is u64[J_i+0]. L=sum(E_i), P=16-((L+10) AND 15), M=L+10+P. `SUCCESS=0x31ae0066`, `TOKEN=0x886a1ca3`, `PAD_BASE=0x1aad43d4`.

For a storage address a, the byte mask is:

```text
mask(a,k0,k1) = byte((ROR64(a AND 0xfffffffffffffff8,8) +k0) XOR k1,
                     a AND7)
```

Here byte(x,r) extracts bits 8r..8r+7. The rotate, addition and XOR operate at u64 width.

| Storage | k0 | k1 |
| --- | --- | --- |
| Node source/staging family | 0x02e859d27e491464 | 0x4dae26df20976138 |
| Auxiliary destination | 0xc318995a4ba7c5cd | 0x72cef43cdf673afd |

Define node plain byte D_i[j]=u8[B_i+j] XOR mask(B_i+j,source keys), and output plain byte O[q]=u8[A+q] XOR mask(A+q,auxiliary keys). The conditional output contract is:

```text
O[0:M] = D_0[0:E_0] || ... || D_(k-1)[0:E_(k-1)]
         || 00 00 00 00 || 50 db || BE32(P) || zero_bytes(P)
```

The source-byte definition is mathematical storage decoding. Complete agreement with the unresolved original metadata writer is not inferred from matching key constants.

| Output offset (B) | Decoded content | Exact extent |
| --- | --- | --- |
| 0..L exclusive | Concatenated node bytes in next-link order | L B |
| L+0 through L+3 | Tag bytes 00 00 00 00 | 4 B |
| L+4 through L+5 | Type bytes 50 db | 2 B |
| L+6 through L+9 | Big-endian u32 P | 4 B |
| L+10..M exclusive | Zero payload | P B |

```text
H -> size pass -> accepted L,P,M -> allocation A
  -> node list in next-link order
     -> each node: E-1 down to0, source mask -> auxiliary mask
  -> tag0 / type50db / BE32(P)
  -> P-1 down to0: protected zero bytes
  -> publish A and encoded M -> flag1/raw SUCCESS -> saved callback
```

The selected emission spans contain internal control transfers and no modeled external call. Size computation and allocation are established in the predecessor. This report closes emission-to-publication under the stated list, storage and pointer premises, while leaving their native validity explicit.

## Node loop and terminal record source locations

| Source location | Established effect |
| --- | --- |
| `0xfffffe000a6600d0` | Loads node extent E from J+0x10 |
| `0xfffffe000a66018c` | E=0 -> index0x2c2/advance; E!=0 -> index0x27d/copy setup |
| `0xfffffe000a66019c` | Loads node source B from J+0x18 |
| `0xfffffe000a6601e4` | Derives initial counter E; the preceding affine cursor reduces to the current prefix offset |
| `0xfffffe000a66022c` | Reads B[T-1] in an admitted positive-counter step |
| `0xfffffe000a660280` | Writes the same decoded byte at A+prefix+(T-1), under the auxiliary mask |
| `0xfffffe000a660290` | Remaining counter0 -> index0x61d/bridge; nonzero -> index0x61f/same byte step |
| `0xfffffe000a6602b8` | Reloads node extent; stable-list premise equates it with the value used by the byte loop |
| `0xfffffe000a66007c` | Adds the stable extent to the prefix cursor |
| `0xfffffe000a660080` | Loads the next pointer from J+0 |
| `0xfffffe000a6600a0` | Next null -> index0x2a7/terminal record; nonnull -> index0x35a/node gate |

The node-byte source uses temporary key1=`0x77941ce51aad5b02` and a final XOR 0x3a per byte. Their combined key is `0x77941ce51aad5b02 XOR 0x3a3a3a3a3a3a3a3a = 0x4dae26df20976138`. The arbitrary-byte theorem proves:

```text
written_byte XOR mask(A+prefix+j,auxiliary keys)
  = source_stored_byte XOR mask(B+j,source keys)
```

The node body temporarily uses X2/X3 as byte/pointer temporaries. Its bridge restores W3=TOKEN; the terminal block later restores X2=C from F+0xa28. Source preservation proofs retain the buffer bases, loop phase, key registers, padding control and encoded output extent across each admitted node iteration. The apparent context-register clobber is therefore part of the recovered internal register protocol.

| Decoded terminal field | Protected byte-store PCs |
| --- | --- |
| Four zero tag bytes | `0xfffffe000a65fa48`, `0xfffffe000a65fa7c`, `0xfffffe000a65fab0`, `0xfffffe000a65fae4` |
| Type bytes 50 db | `0xfffffe000a65fb5c`, `0xfffffe000a65fb98` |
| Big-endian length P | `0xfffffe000a65fc84`, `0xfffffe000a65fcc4`, `0xfffffe000a65fd04`, `0xfffffe000a65fd44` |
| Zero payload byte | `0xfffffe000a65fe4c`, repeated P times |

The header consumes W22=PAD_BASE+P for its length and independently reads S+0xb40=PAD_BASE+P for the fill counter. The proofs establish both reductions for every P in 1..16. A stable equality of those private channels is part of the state contract. The actual sizing producer supplies this equality. The header's P=0 bypass target is captured, but P=0 is outside the producer's proved domain.

## Finite composition, publication and parser touch point

For a finite stable list with valid disjoint source/destination storage:

1. The predecessor size pass supplies L, P and M after checked accumulation and allocation.
2. Induction on a node's positive counter T proves exactly E writes at indices E-1 through0; extent0 skips the byte loop.
3. The restored next-node phase advances the prefix by the same E and follows the stable next link. Induction over k nodes yields the concatenated prefix of length L.
4. The header writes [L,L+10). A second counter induction gives exactly P zero writes in [L+10,M), without overlap with the header or node prefix.
5. The final zero step selects publication. The source stores the exact A and encoded M and selects the saved callback with flag1/raw SUCCESS.

| Publication channel | Exact source/effect |
| --- | --- |
| Internal allocation cell | Header reloads C+0x198 into X10=A at `0xfffffe000a65fd94` |
| Auxiliary pointer output | `0xfffffe000a65fe74` writes X10 through C+0x548=&C+0x3c0 |
| Encoded extent output | `0xfffffe000a65fe78` writes W28=M XOR SUCCESS through X21=&S+0xbe4 |
| Success controls | `0xfffffe000a65fe84` sets W8=1; following instructions set W23=SUCCESS |
| Saved return | Index0x614 -> `0xfffffe000a65fe98`; restores X28=X27 |
| Callback | Saved C+0x468 -> X24=`0xfffffe000a65fea8` |

The zero-fill loop uses X0 as an affine-address constant while X10 retains A. The published pointer is the reloaded allocation, not that temporary constant.

An independent raw-source lemma first proves all ten pointer-formation and store addresses. Declared rewrites use those exact identities in the byte theorem; the finite profiles use the raw instruction model without these rewrites. Another named dependency substitutes the proved decoded bytes into parser normalization `BE16(type bytes) XOR 0x365e`, giving 0x6685 with zero tag and declared length P. The delivery verifier requires every referenced lemma to precede its use and re-solves the frozen formulas. This factoring preserves the source obligations while avoiding duplicate pointer/masking expansion under the 30 s/query limit.

The predecessor parser source proof recognizes decoded zero tag and normalized type 0x6685 as its selected terminal-success shape before ordinary node construction. The appended record has exactly that shape and a bounded payload ending at M. This does not prove that arbitrary preceding node records are accepted by a complete parser invocation. The type bytes and table indices are private format/control facts; no Mach message identifier, user-client selector or new port endpoint is inferred.

With M equal to the caller's original low32 length, the prior consumer transcodes the auxiliary bytes into staging while preserving their decoded values. The prior final-copy contract then removes the staging mask. Native end-to-end response bytes still require the stated allocation/list/private-state/pointer premises and an observed matching transaction.

## Assumption register and falsification probes

| Assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- |
| EM-A1: Results apply only to the pinned original/normalized images | EM1-EM7 | Compare complete containing-function hash, every selected word and 12 original branch pointers; another build requires recapture |
| EM-A2: Modeled AArch64 u32/u64 operations, byte accesses, rotate and register shifts | EM1-EM7 | Arbitrary extent/cursor/counter/source byte proofs, all 8 address residues in finite profiles, and altered terminal-type literal SAT control |
| EM-A3: Selected F/C/S/table roots and valid separate private storage, destination A[M] and admitted node/source ranges | EM1-EM7 | Exact read/write addresses, nonwrapping/disjoint bounds, publication-cell aliases and root preservation; native capacity/ownership is not inferred |
| EM-A4: A finite stable next-link list, stable extents/source bytes, checked sum L and consistent padding controls from the size pass | EM1-EM7 | Extent0/nonzero splits, repeated extent reload, exact prefix advance and predecessor size/allocation rechecks; inspect locking/ownership before claiming native stability or termination |
| EM-A5: Nominal-pointer guards hold at every admitted byte/header/fill step | EM2-EM7 | Thirteen explicit source guards and excluded retag alternatives, arbitrary address/counter bounds and finite profiles; recover native retag behavior independently |
| EM-A6: Predecessor source contracts remain applicable at their declared phase cuts | EM4, EM6, EM7 | Re-solve six size/allocation/copy/parser proofs, require the source-byte lemma before parser normalization, and preserve exact output aliases/encoded M |
| EM-A7: Original metadata construction, complete core semantics, native environment and observed daemon pairing remain unknown | EM7 limits | Recover the protected writer/list publication, then correlate actual endpoint/selector/transfer/request/response evidence |

## Bounded continuation and cost

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | Protected metadata writer `0xfffffe000a654ad4` and subsequent node-list publication | Establish actual tag/type/scalar bytes for the three query requests, rather than treating source nodes as arbitrary bytes |
| High | H/list state before and after the query sequence | Determine record order, replaced/retained records and the value of L for this command |
| High | Native list/data/private-state ownership and synchronization | Discharge snapshot assumptions spanning sizing, node emission and extent reloads |
| High | Observed daemon/provider request, selector, endpoint and transfer counts | Validate one complete native cross-layer transaction |
| Medium | Native allocation capacity, PAC, pointer retags and lifetime | Establish the environmental premises behind the conditional source contract |
| Medium | Parser context for preceding emitted records and meaning of0x99ab | Connect terminal recognition to complete record semantics without assuming whole-stream acceptance |
| Low | Other consumers of the exact terminal shape and mask pairs | Locate candidate shared-format touch points requiring independent source verification |

For k finite stable nodes with total L bytes, the selected emission performs L node-byte stores,10 header stores and P zero stores. Local work is O(k+L+P), auxiliary output storage is M=L+10+P B, and additional loop state is O(1), excluding earlier allocation and later cleanup. The 13 MOVK alternatives are outside the nominal-pointer execution domain. The prior size pass is O(k); the prior caller transcode is O(N) when admitted N=M. Extraction uses O(B+I) time/space for consumed image bytes B and instructions I. Proof construction uses O(instruction instances+query DAG); SMT search is separate with 30 s/query limits. Finite profile cost is O(16*I+136 byte steps). Extents/cursors are u32, promoted counters/addresses are u64, and each proof states the nonwrapping range needed for address arithmetic.

## Quality gates

- **QG1**: Claims are factual source/data/control/ABI analysis.
- **QG2**: EM-A1-EM-A7 identify dependencies and falsification probes.
- **QG3**: Node bytes, zero extents, loop state, terminal fields, zero payload, output publication and parser-shape touch point are covered conditionally; original metadata construction and full interface work remain active.
- **QG4**: u32/u64 widths, byte ranges, big-endian length, masks, counters,495/482/13 instruction accounting,3,574 proof instances and 8,000 separate profile instances are explicit.
- **QG5**: Source-defined plain bytes versus writer meaning, successful padding domain versus P=0 bypass, temporary registers versus output roots, parser shape versus complete acceptance, and conditional path versus native execution remain distinct.
- **QG6**: Dual-image capture, 12 original pointers,17 nonvacuous source formulas, six prior rechecks, 16 terminal profiles, 136 zero steps, all 8 base residues, dependency-checked normalization and the mutation SAT control support the bounded contract.
- **QG7**: Ranked continuation preserves writer/list semantics, snapshot context, native transaction pairing, environment, preceding-record acceptance and bounded shared-format candidates.


The [query writer contract](userclient_query_writer_report.md) now establishes the three conditional14 B records: exact big-endian tags, raw type97 77 (parser-normalized0xa129), length4 and big-endian scalars0x4c0b0000/0x1f8/0x99ab. Each writer reaches the shared list lookup with W8 callback index0x6c (separate W0 control0x19) and retained pending-node/constructor-return state. This resolves the earlier query-byte frontier; actual query list publication/order, resulting serializer extent and native daemon pairing remain unknown. No additional Mach endpoint is established.
