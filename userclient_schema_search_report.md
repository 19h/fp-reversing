# Schema lookup: actual protected-tag round trip and reader handoff

Subsequent schema-scalar evidence: The [schema scalar report](userclient_schema_scalar_report.md) follows actual protected header/body bytes through exact bounds/type/length gates, raw u32 publication, cursor commitment and saved caller status selection. Fifteen source proofs, four prior rechecks, 390 derived field evaluations, 62 controller-premise checks and three mutations pass. The synthetic fourteen-byte ADID field decodes to zero and SUCCESS; u64/span representations commit the cursor but return a distinct type error. Native transport, packet-layer identity, application meaning and new Mach emissions remain unknown. Earlier boundaries below retain their historical scopes.

The schema caller searches the original first early node using the protected bytes actually produced by the early serializer. It finds that node exactly when its raw tag is `0xfa834112`; every other raw tag follows the source-zero next link and returns raw miss to the original caller. A match publishes the node at C+0x710, retains its buffer at C+0x560 and prepares another header read over that same buffer. A synthetic source composition reproduces the ADID field's exact 14-byte record and finds it under this key.

This extends [the schema request](userclient_early_schema_report.md) beyond a common-key observation. The constructive record is a modeled compatibility witness, not a native packet submission. The identity of the corresponding container layer in a full ADID packet, later field decoding/meaning and Avp selector 100 to primary selector 26 transport remain unknown. The stopped continuous guest is unchanged.

## Custody and claims

| Evidence | Identity / coverage |
| --- | --- |
| Original kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Full `_PRnut72j9` container | `[0xfffffe000a635208, 0xfffffe000a666930)`, 202536 bytes / 50634 words |
| Container SHA-256 | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` |
| Decoded checks SHA-256 | `4b6aa07b08d68275cb9ed0f47a744026cfe90c409606929ede81da6bb16968c0` |
| Decoded audit SHA-256 | `d3ecfc8a02cb3fa53a635b826b33cd58a1d005ad0a2d7cb0ca2d3ea8684cf2e9` |
| Original selected source | 11 spans, 268 words, 51 original table pointers; all 268 words covered, including four separate alternate-retag transforms |
| New source obligations | 22 nonvacuous UNSAT queries; 14547 lifted instruction instances |
| Prior rechecks | Four complete schema-request formulas re-solved UNSAT |
| Original prefix custody | One additional eight-byte alias cell in each of 30 retained prefixes: 30 cells / 240 bytes |
| Expression evaluation | 30 retained projections and 30 explicitly derived key substitutions; 900 field values |
| Additional checks | 122 UNSAT controller-premise queries; three rejected source mutations; exact 14-byte constructive record |

The [generator](triage_evidence/recover_userclient_schema_search.py) rehashes the full original function, compares selected words with both pinned images, verifies original pointer slots and reconstructs the alias from overlapping original source stores. The [auditor](triage_evidence/audit_userclient_schema_search.py) executes the captured instructions symbolically and loads the actual protected bytes from its preceding serializer stores. It supplies no replacement decoded-tag bytes. The [delivery verifier](triage_evidence/verify_userclient_schema_search_delivery.py) reconstructs the receipts and checks exact publication custody. Frozen receipts: [checks](triage_evidence/userclient_schema_search_checks.json.zst), [audit](triage_evidence/userclient_schema_search_audit.json.zst). Hashes refer to decoded JSON. Reference data sufficed; no IDB was required or modified.

| Claim | Established result |
| --- | --- |
| SS1 | Original source defines F+0x898 as the address C+0x560; all 30 original prefixes independently retain that value. |
| SS2 | Shared lookup selects the first published node J and decodes its four actual protected tag bytes to `D XOR 0x31ae0066`. |
| SS3 | Every raw tag32 selects exact key match or successor processing; this source-built sole-node list returns J/SUCCESS or zero/MISS. |
| SS4 | The schema callback selects node fields exactly for raw SUCCESS; all other status32 values select the saved caller return. |
| SS5 | Found-node buffer/extent channels, nullable-buffer routing and the bounded-cursor ten-byte header-fit predicate are established independently. |
| SS6 | Four matching scalar/span compositions preserve the record and request the next original header reader; four nonmatching compositions return raw miss to the saved caller. |
| SS7 | Controller reads and abstract certified-bank bytes are independent across the two lookup callbacks; 900 evaluated fields and 122 premise checks pass without filling missing setup cells. |
| SS8 | The exact ADID field can be represented by the modeled early u32 constructor and found by this search. Native admission, complete field decoding, container-layer identity and transport pairing are unknown. |

## Protected tag and exact lookup result

F is the retained frame base, C the context, S the workspace, H the 16-byte container, J its first 32-byte node and Z the record buffer. D, U and L are raw tag32, type16 and length32. The inherited first-record/exhaustion premises give H.head=H.tail=J, J.next=J.previous=0, J.extent32=L+10, J.buffer=Z and cursor=declared low32 input size=L+10. Valid scalar/span domains and separated storage remain explicit assumptions. `SUCCESS=0x31ae0066`; `MISS=0xce515bda`.

| Original site | Data/control result |
| --- | --- |
| `0xfffffe000a662c14` / `0xfffffe000a662c18` | Read H.head=J; retain it at C+0x2b0. |
| `0xfffffe000a662c7c` | Read J.buffer=Z for tag decoding. |
| `0xfffffe000a637158`, `0xfffffe000a637190`, `0xfffffe000a6371d4`, `0xfffffe000a637214` | Read the existing protected bytes at Z+0, Z+1, Z+2 and Z+3. |
| `0xfffffe000a637244` | Produce W22=`D XOR SUCCESS` from the protected BE32 bytes. |
| `0xfffffe000a63d64c` / `0xfffffe000a63d650` | Load requested encoded key `0xcb2d4174` from S+0 and compare it with W22. |
| `0xfffffe000a662c4c` | Publish the selected node or zero through the saved schema output address C+0x710. |

The decoder retains the same address-dependent protection constants as the writer: K0=`0x02e859d27e491464` and K1=`0x4dae26df20976138`. Its four normal pointer branches are explicit guards. Alternate MOVK paths have separate source-level bit-transform proofs; they are not executed as normal pointers and do not establish native pointer authentication.

```text
actual serializer stores -> protected Z[0:4]
                                 |
                          original decoder
                                 |
                          encoded raw D
                                 |
       +-------------------------+-------------------------+
       | D = fa834112                                      | D != fa834112
       v                                                   v
C+0x710 = J; SUCCESS                                J.next = 0 -> empty gate
       |                                            C+0x710 = 0; MISS
       +--------------------+------------------------------+
                            |
                 callback 0xfffffe000a661c34
                 +----------+-----------+
                 | SUCCESS              | all other statuses
                 v                      v
             node fields       saved caller 0xfffffe000a636728
```

The tag-match BRAA at `0xfffffe000a63d67c`, modifier `0xde40`, selects `0xfffffe000a662c44` for a match and `0xfffffe000a63d680` otherwise. A mismatch requests the shared node gate again. J.next is source-defined zero, so this particular list terminates after one comparison. General multi-node traversal, duplicate policy, list mutation and native lifetime remain outside this composition.

Both results pass through the shared callback bank and return to `0xfffffe000a661c34`, modifier `0x8d28`. The certified 256-input bank relation is inherited and rebuilt. This auditor gives each controller read and each abstract left-bank byte a distinct symbol: four controller reads and two bank bytes across the two lookup calls. The source result therefore does not depend on equality of controller values between calls.

## Schema callback, buffer alias and extent

The source producer at `0xfffffe000a636104` is `ADD X8,X2,#0x560`; `0xfffffe000a636108` stores that address at F+0x898. The actual X2=C producer value and all overlapping stores are checked in every retained prefix. This identifies a buffer output channel, separately from the lookup's node output C+0x710 and the caller's still-zero scalar result S+0xbc4.

| Condition / handoff | Exact target / modifier | Established effect |
| --- | --- | --- |
| Callback status32=SUCCESS | `0xfffffe000a661c88` / `0x3751` | Read node through C+0x710. |
| Callback status32!=SUCCESS | `0xfffffe000a661e40` / `0x3751` | Select saved caller return; no node dereference follows in the proof. |
| Found node buffer64=0 | `0xfffffe000a661e40` / `0xd784` | Publish zero through C+0x560; raw status becomes `0xce515bbf`. |
| Found node buffer64!=0 | `0xfffffe000a661cec` / `0xd784` | Publish the buffer and retain zero-extended node extent32 in X11. |
| Header does not fit, with bounded cursor | `0xfffffe000a661e40` / `0x3751` | Select saved caller return with raw status `0xce515bb8`. |
| Header fits | `0xfffffe000a661da0` / `0x3751` | Prepare another protected-header read. |
| Saved caller return, `0xfffffe000a661e4c` | `0xfffffe000a636728` / `0x415f` | Preserve the selected raw status. |

The nullable-buffer obligation is an independent cut over every buffer64 and extent32. Its stated register/node-cell premises come from the matching composition, but it does not assert that a NULL buffer is natively reachable after successful allocation. The complete composed paths retain their earlier non-NULL Z premise.

For arbitrary node extent32 M and cursor64 c satisfying `0<=c<=zero_extend32(M)`, original source proves:

```text
S+0x260 = zero_extend32(M) + 0x7834dd25aad3a2b1
F+0xbd0 = c
header fits exactly when c + 10 <= zero_extend32(M)
```

The addition is u64. Given M<=2^32-1 and c<=M, c+10 cannot wrap u64. The bounded-cursor premise is essential; no result is claimed for arbitrary cursor values outside the node extent. In the composed found path, M=L+10 and c=0, so the ten-byte header always fits. S+0x260 is an encoded extent channel; assigning it a public semantic type or business meaning requires later consumers.

## Next reader request and preserved state

The terminal BRAA at `0xfffffe000a661e3c` requests `0xfffffe000a656ef0`, modifier `0x5e04`. This is the original protected-word bridge; the proof stops at this request. It has not executed the subsequent header callback or decoded a scalar result.

| Channel | Exact value / interpretation |
| --- | --- |
| X8 | Original Z buffer |
| X10 | `0x59ea252df044bd94` |
| X1 | `0xa615dad20fbb426c` |
| Effective first-word offset | X10+X1=0 modulo 2^64 |
| W11 | `0xe07`, bridge index selecting the word decoder |
| W9 | `0x1a2`, decoder return index selecting `0xfffffe000a638e68` |
| X26 / X20 | K0 / K1, original protection constants |
| Saved buffer output | C+0x560=Z, through F+0x898 |
| Saved caller result / return | C+0x5f0=S+0xbc4; C+0x4d0=`0xfffffe000a636728` |
| Scalar result | S+0xbc4 remains source-defined zero |
| Pending raw status | `0xce515bb8`, set before the next reader request; it is not a completed-operation result here |

All new search and callback stores are proved disjoint from the full L+10-byte Z extent. H's head/tail, J's links/extent/buffer and the committed cursor are preserved. For nonzero spans, complete payload construction retains the preceding finite reverse-copy induction; one modeled final copy step is not presented as an entire copy.

## Constructive ADID field compatibility

The prior [ADID packet evidence](adid_avp_packet_report.md) pins arm64e slice SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. All twelve retained 320-byte source-built packet fixtures have the same bytes; they are not twelve independent native captures. Their nested field at packet offset 118 has this exact raw record:

```text
fa834112 9777 00000004 00000000
 tag32  type16 length32 scalar32       [all fields big-endian]
```

The new constructive certificate selects an existing u32 storage placement and substitutes raw D=`0xfa834112`, U=`0x9777`, L=4, V=0 and declared size N=14 into the universal original-source composition. All storage/branch/table premises are checked again. The actual fourteen serializer-store bytes equal the fourteen ADID field bytes protected at that placement's Z addresses. The source lookup returns the same modeled J and reaches the next header-read request.

This witness establishes representation compatibility and actual key-search success under the stated model. It does not submit the full 320-byte packet, identify H with any particular nested ADID container, validate the field's type/length in the next helper, read the scalar as a business value, establish native allocation/PAC/ownership, or correlate Avp selector 100 with primary selector 26. The ADID field is independently parsed frozen evidence; its use in this kext composition is an explicit synthetic substitution.

## Evaluation and negative controls

Thirty evaluations preserve the retained predecessor inputs. Their original tags all differ from the requested key, so all return raw MISS to `0xfffffe000a636728`; 14 resulting fields per case are checked. Thirty additional evaluations explicitly substitute the requested tag while retaining the other model parameters; 16 resulting fields per case are checked on the found path. These derived evaluations are not claimed to be retained guest prefixes. Together they check 900 values. The separate ADID witness substitutes both tag and scalar, checks fourteen protected bytes and reaches the same request boundary.

All storage, pointer-branch and table-membership premises are checked for each binding. There are 122 additional UNSAT checks for the still-unbound controller expressions across the 60 evaluations and the constructive witness. The eight unrelated setup cells remain symbolic; zero concrete values are assigned to missing cells. Continuous private execution remains stopped before the original undefined load at `0xfffffe000a654ae4`.

| Copied-source mutation | Oracle violation / stop boundary |
| --- | --- |
| NOP first protected-tag byte load at `0xfffffe000a637158` | Decoded tag violates the actual serializer-to-reader round trip; stop before following the wrong comparison. |
| NOP selected-result store at `0xfffffe000a662c4c` | A found result is not published at C+0x710; stop before loading that unpublished node. |
| Change output-alias ADD immediate at `0xfffffe000a636104` from `0x560` to `0x568` | The buffer store reaches the wrong context cell; stop before the extent check. |

All three controls have satisfiable storage/branch/table premises and a satisfiable contract violation. Only copied symbolic source is changed. The controls stop before following an invalid node or changed comparison and execute no native fault behavior.

This source-built sole-node search takes O(1) work and auxiliary storage. No general traversal cost or native latency follows. Preceding scalar construction remains O(1); nonzero-span construction retains O(L) copy work. The next header read is requested but not executed here. Evidence construction and expression evaluation are linear in selected instruction/query DAGs, original prefix-store reconstruction and checked bytes; finite-bank certification has 256 inputs. SMT search is separate: 60 seconds per new query and 120 seconds per retained-formula recheck. Retained formulas are parsed into fresh solver contexts.

## Assumption register

| Assumption | Dependencies and falsification probe |
| --- | --- |
| SS-A1: Pinned images, tables and dependency closure | SS1-SS8. Rehash the complete function, dual-image words, original pointer slots, bank arrays and dependency artifacts; rebuild both receipts. |
| SS-A2: Retained source epochs and alias producers | SS1-SS7. Reconstruct the eight-byte F+0x898 cell in all 30 original prefixes and check X2 at the actual ADD producer. Intervening writes or a different caller epoch invalidate the join. |
| SS-A3: Valid separated storage and inherited scalar/span domains | SS2-SS7. Check nonzero nonwrapping H/F/C/S/J/Z extents, F alignment, image separation, L+10 capacity and a readable separated span source when needed. Native admission/ownership remain unknown. |
| SS-A4: Original first-record/exhausted-input state | SS2-SS7. Require source-produced H links, J.next=0 and cursor=low32 declared size=L+10; varying earlier list contents or selecting a remaining suffix requires new analysis. |
| SS-A5: Fixed-width lift, normal pointer guards and certified bank relation | SS2-SS7. Check four actual protected-tag load addresses, all source target/modifier values, all 256 bank cases, independent controller symbols, 22 source formulas, four prior formulas and three source mutations. Native PAC/BTI remain unproved. |
| SS-A6: Independent nullable-buffer and bounded-cursor cuts | SS4-SS6. Bind each cut's register/node-cell premises explicitly; require c<=zero_extend32(M) for the header predicate. Establish native failure reachability separately; do not substitute nullable-cut storage for the composed allocated buffer. |
| SS-A7: Synthetic compatibility scope and unexecuted reader frontier | SS7-SS8. Keep original projections, derived key substitutions and the ADID witness distinct. Follow `0xfffffe000a638e68`, subsequent type/length/scalar consumers, full-packet container ancestry and actual transport before asserting common semantics or a paired transaction. |

## Bounded continuation

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | Requested decoder and callback `0xfffffe000a638e68` | Recover actual schema type/length requirements, scalar publication and final helper status. |
| High | H ancestry versus the ADID packet's four-level containment path | Establish or falsify compatible container-layer identity rather than only record representation. |
| High | Avp selector 100 and primary selector 26 provider/caller lineage | Determine whether a real transport join exists; selectors remain distinct. |
| Medium | Multiple records, duplicate tags, mutation and retirement paths | Extend beyond the source-built sole-node list and recover complete early list policy. |
| Medium | Native allocation/lifetime, pointer authentication and locking | Test the model's storage/epoch premises and external reachability. This increment establishes no new Mach endpoint or emission site. |

## Quality gates

- **QG1**: Factual source, codec, state and ABI claims require no normative conclusion.
- **QG2**: SS-A1-SS-A7 list dependent results and falsification probes.
- **QG3**: Actual protected-tag round trip, found/miss results, callback, buffer/extent ABI, next request and constructive ADID compatibility are covered; the broader investigation remains active.
- **QG4**: u32/u64 arithmetic, ten-byte headers, 14-byte record, exact extents/offsets, proof/evaluation counts and scoped costs are reproducible.
- **QG5**: Original and derived states, node/buffer/scalar channels, pending/final status, nullable-cut/composed buffers and representation/native-transport evidence remain distinct.
- **QG6**: Original words/pointers/arrays, source-store custody, 22 fresh obligations, four rechecks, 122 premise checks, three mutations and the exact fourteen-byte witness support the bounded claims.
- **QG7**: Continuation covers type/length/scalar semantics, container ancestry, native transport, multi-record policy and lifecycle evidence with explicit impact labels.
