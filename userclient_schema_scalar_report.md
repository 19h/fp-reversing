# Protected schema field: exact u32 output, cursor commitment and caller status

The schema helper reads the actual protected ten-byte header from the first published early record. For raw type `0x9777` and length 4, it reads the four actual protected body bytes, removes the internal encoding and writes the original u32 through C+0x5f0 to S+0xbc4. It commits cursor 14, returns raw SUCCESS and selects the saved caller's success continuation. The exact ADID field `fa83411297770000000400000000` reproduces this result with output zero in a synthetic source composition.

This extends [the schema search](userclient_schema_search_report.md) through field decoding and caller status selection. Native execution, application meaning of the resulting zero, the corresponding full ADID container layer and matched daemon/kext transport remain unknown. The original continuous guest still stops before its undefined private load; these are conditional original-instruction compositions.

## Custody and claims

| Evidence | Identity / coverage |
| --- | --- |
| Original kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Full `_PRnut72j9` container | `[0xfffffe000a635208, 0xfffffe000a666930)`, 202536 bytes / 50634 words |
| Container SHA-256 | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` |
| Decoded checks SHA-256 | `d83365fed0e9cddd837d509254651e6f45c7b718b60f166ea730cbcc0ce50440` |
| Decoded audit SHA-256 | `27e7a4cc7dcea11fdcb4e89d72d11f34dca9da4e0615fccea176f4c4ca2e84e3` |
| Original selected source | 14 spans, 267 words, 63 original table pointers; all 267 words covered |
| Source obligations | 15 nonvacuous UNSAT queries, including two universal codec identities and two separate alternate-retag transforms; 7694 lifted instruction instances |
| Retained proof rechecks | Four preceding found-node/header-request formulas re-solved UNSAT |
| Derived evaluations | 30 explicit key substitutions, 390 checked fields, 62 additional controller-premise UNSAT checks |
| Independent controls | Three rejected copied-source mutations; exact 14-byte ADID-compatible field decoded to zero |

The [generator](triage_evidence/recover_userclient_schema_scalar.py) rebuilds the preceding source receipt and compares the new instruction words against both pinned images, verifies original table pointers and retains the original prefix/dependency custody. The [auditor](triage_evidence/audit_userclient_schema_scalar.py) executes those instructions against the protected bytes actually stored by the preceding serializer. The [delivery verifier](triage_evidence/verify_userclient_schema_scalar_delivery.py) reconstructs both receipts and checks exact publication custody. Frozen receipts: [checks](triage_evidence/userclient_schema_scalar_checks.json.zst), [audit](triage_evidence/userclient_schema_scalar_audit.json.zst). Hashes refer to decoded JSON. Existing reference data sufficed; no IDB was required or modified.

| Claim | Established result |
| --- | --- |
| SC1 | Actual protected header bytes at Z+0 through Z+9 yield the selected record's tag32, transformed type16 and transformed length32. |
| SC2 | The body-fit predicate is exact for arbitrary length32/extent32 and a cursor64 bounded by that extent, under the stated source register/cell premises. |
| SC3 | The raw u32 type selects its body reader exactly for length 4; every other length selects the short-body error return. |
| SC4 | The actual u32 body bytes at Z+10 through Z+13 produce the original raw value at the caller's output address, with raw SUCCESS. |
| SC5 | The recovered u64/span types commit the candidate cursor and return a distinct type error without publishing a scalar; unsupported types and body rejection select the other error before commitment. |
| SC6 | Every raw status32 selects the caller's success continuation exactly for SUCCESS and the error continuation otherwise. |
| SC7 | All four source-built domains preserve the record/container while reaching the exact caller continuation; 30 derived projections and three mutations qualify the contracts. |
| SC8 | The exact ADID field is representable, searchable and decodable to zero in this synthetic source composition. Its native origin, transport pairing, container-layer identity and business meaning remain unknown. |

## Data and control interfaces

F is the retained frame base, C the context, S the workspace, H the 16-byte container, J the first 32-byte node and Z the protected record buffer. D, U, L and V are raw tag32, type16, length32 and u32 value. This composition retains D=`0xfa834112`, H.head=H.tail=J, J.next=J.previous=0, J.extent32=L+10, J.buffer=Z, C+0x560=Z, C+0x5f0=S+0xbc4 and saved return C+0x4d0=`0xfffffe000a636728` from their preceding producers.

| Original site | Exact channel / effect |
| --- | --- |
| `0xfffffe000a638e68` | Tag decoder callback, selected by original return index `0x1a2`; requests the type reader. |
| `0xfffffe000a639348`, `0xfffffe000a639380` | Read actual protected type bytes at Z+4 and Z+5. |
| `0xfffffe000a63a2d4` | Store low16 transformed type `U XOR 0x365e` at S+0xc70. |
| `0xfffffe000a637158`, `0xfffffe000a637190`, `0xfffffe000a6371d4`, `0xfffffe000a637214` | Shared word decoder reads tag offsets 0..3, length offsets 6..9 and u32 body offsets 10..13 on their respective calls. |
| `0xfffffe000a638bac` | Store candidate cursor `c+10+zero_extend32(L)` at S+0xad8, before deciding whether it fits. |
| `0xfffffe000a638c08` through `0xfffffe000a638c44` | Read transformed type and select the exact u32 type/length route. |
| `0xfffffe000a63ac24` | Save decoded body word `V XOR 0x31ae0066` at S+0xb64. |
| `0xfffffe000a63ac58` | Commit the candidate cursor from S+0xad8 to F+0xaa8. |
| `0xfffffe000a63acb8` | Store raw V through C+0x5f0, whose original value is S+0xbc4. |
| `0xfffffe000a63acc0` / `0xfffffe000a63acc4` | Publish raw SUCCESS=`0x31ae0066` after the output store. |
| `0xfffffe000a661e44` / `0xfffffe000a661e4c` | Load C+0x4d0 and return to `0xfffffe000a636728`, BRAA modifier `0x415f`. |
| `0xfffffe000a636760` / `0xfffffe000a636778` | Select the caller continuation by raw status, BRAA modifier `0x0d4c`. |

The effective type offset is the source cursor plus 4; length offset is cursor plus 6; body offset is cursor plus 10. In the composed first-node reader c=0. The word decoder produces `raw32 XOR SUCCESS`; the type decoder's low16 result is `raw16 XOR 0x365e`. These are internal encodings. Neither is interpreted as a Mach return code or public IOKit status.

The body-fit cut takes arbitrary extent32 M, length32 L and cursor64 c with `0<=c<=zero_extend32(M)`, plus the preceding source register constants W3=`0x886a1ca3`, W19=`0x7795e642`, W30=SUCCESS and S+0x260=`zero_extend32(M)+0x7834dd25aad3a2b1`. It proves:

```text
candidate = c + 10 + zero_extend32(L)
fits      = candidate <= zero_extend32(M)       [unsigned u64]
```

The candidate is at most `2*(2^32-1)+10 = 8589934600` bytes under this cut, so it cannot wrap u64. The cut does not assert memory validity or native reachability for arbitrary rejected headers. All subsequent loads in the complete compositions retain the original separated-storage premises. In those compositions M=L+10 and c=0, so the complete body fits.

| Input condition after header read | Selected source path | Committed cursor / output / raw status |
| --- | --- | --- |
| Body does not fit | `0xfffffe000a63abf4` | No cursor commitment or scalar store; `0xce515bb8`. |
| U=`0x9777`, L!=4 | `0xfffffe000a63abf4` | No cursor commitment or scalar store; `0xce515bb8`. |
| U=`0x9777`, L=4 | `0xfffffe000a638c50` -> `0xfffffe000a63ac18` -> `0xfffffe000a63ac94` | Cursor=c+14; output=V; SUCCESS. |
| U=`0x8485` or `0x50db`, body fits | `0xfffffe000a63ac3c` | Cursor=c+10+L; no scalar store; `0xce515ae1`. |
| Other raw U | `0xfffffe000a63abf4` | No cursor commitment or scalar store; `0xce515bb8`. |
| Saved caller status=SUCCESS | `0xfffffe000a63677c` | Caller success continuation selected. |
| Any other saved caller status32 | `0xfffffe000a641c1c` | Caller error continuation selected. |

The two non-u32 accepted header types are span and u64 representations established by the preceding serializer. This helper does not read their bodies as u32. Its common path first commits the candidate cursor, then checks the transformed type again, returning `0xce515ae1` for these types. The original caller output remains its source-defined zero in the complete modeled u64/span cases. This differs from the earlier short/type rejection, which has already stored a candidate at S+0xad8 but has not committed it at F+0xaa8.

```text
published J -> actual protected header -> candidate / bounds / type / length
                                            |
                +---------------------------+----------------------+
                | u32, length 4             | u64/span             | rejected
                v                           v                      v
       actual protected body          commit candidate       no commitment
       encoded V -> saved word        output unchanged       output unchanged
       commit candidate               type error             short/type error
       raw V -> saved output                |                      |
       SUCCESS                              |                      |
                +---------------------------+----------------------+
                                            v
                              saved caller status test
                                /                  \
                      SUCCESS /                    \ other status32
                             v                      v
                       a63677c                  a641c1c
```

All new composed reader/caller stores are disjoint from the entire L+10-byte protected Z extent. Container links, node links, extent and buffer remain unchanged. The proof ends at caller continuation selection; the downstream interpretation of S+0xbc4 is not established here. There are no new Mach port creations, right transfers or message emissions in the interpreted source spans; existing endpoint results retain their separate evidence scopes.

## Codec normalization, evaluations and controls

The auditor uses two universally proved u32 identities to keep expressions compact. For every u32 b, modulo 2^32:

```text
b + 0x31ae0066 - ((b << 1) & 0x635c00cc) = b XOR 0x31ae0066
b - (((b & 0x365f) XOR (b & 1)) << 1) + 0x365e = b XOR 0x365e
```

Before each replacement it checks the actual lifted instruction expression against that exact arithmetic shape and checks the word decoder's source constants. The operand b remains the aggregate from the actual byte loads; no decoded tag, type, length or scalar is supplied as replacement input. Every use is recorded. Universal identity proofs and source-shape assertions are distinct evidence. The two alternate type-pointer MOVK words have separate bit-transform proofs; the normal read path retains explicit branch guards and does not establish native PAC/BTI.

Thirty evaluations explicitly replace the tag of an existing predecessor placement by `0xfa834112`. They cover six u32, twelve u64, six zero-span and six nonzero-span inputs, checking thirteen fields per case, or 390 values. These are derived projections, not newly executed retained guest prefixes. All storage, branch and original-table premises are checked again; 62 residual controller-premise checks across these cases and the ADID witness pass. Four controller reads and two certified-bank bytes remain independent per composition. The eight unrelated setup cells remain symbolic; no missing cell is assigned a concrete value.

The ADID witness additionally substitutes U=`0x9777`, L=4, V=0 and N=14 into an existing u32 placement. Its actual fourteen serializer bytes equal the exact raw field protected at that Z address. This same node is found, its header/body read, output zero published, cursor 14 committed and SUCCESS routed to `0xfffffe000a63677c`. The twelve frozen 320-byte ADID fixtures have identical bytes and remain source-built fixtures rather than independent native captures. The evidence does not identify H with one particular nested ADID layer or submit the complete packet to the kext.

| Copied-source mutation | Checked violation / boundary |
| --- | --- |
| Change transformed-type literal at `0xfffffe000a638c0c` from `0xa129` to `0xa128` | A valid u32 selects the wrong direct branch; stop before following that branch. |
| NOP cursor store at `0xfffffe000a63ac58` | Successful decoding reaches the saved caller without committing cursor 14. |
| NOP scalar store at `0xfffffe000a63acb8` | A nonzero raw V is not published at the output channel. |

Every mutation retains satisfiable storage/branch/table premises and yields a satisfiable contract violation. Only copied symbolic source is modified. The continuous private guest remains stopped before `0xfffffe000a654ae4`; no native target or fault path executes.

This selected single-node scalar read uses O(1) work and auxiliary storage. The preceding nonzero-span constructor retains its finite O(L) copy proof; its final copy step is not interpreted as the whole copy. Evidence construction is linear in selected instruction/query DAGs, dependency bytes and evaluated fields; finite bank verification has 256 inputs. SMT search is separate: 60 seconds per new query, 120 seconds per retained formula recheck, with fresh solver contexts for those rechecks. No native latency is inferred.

## Assumption register

| Assumption | Dependent results / stress test or falsification probe |
| --- | --- |
| SC-A1: Pinned images, tables and dependency closure | SC1-SC8. Rehash the full function, dual-image words, pointer slots, bank arrays and frozen predecessors; rebuild both receipts. |
| SC-A2: Selected original source epochs and saved aliases | SC1-SC8. Rebuild the earlier C+0x560 buffer, C+0x5f0 output, C+0x4d0 return and F+0x898 alias producers; intervening writes invalidate the join. |
| SC-A3: Valid separated storage and original scalar/span domains | SC1, SC4-SC8. Check nonzero nonwrapping F/C/S/H/J/Z extents, capacity L+10, F alignment, image separation and separated readable span input when needed. Native admission/lifetime remain unknown. |
| SC-A4: First published sole node, selected key and exhausted input | SC1, SC4, SC5, SC7, SC8. Retain H.head=H.tail=J, J.next=0, D=fa834112 and outer low32 size=L+10. A different list, duplicate, cursor or packet nesting requires another composition. |
| SC-A5: Fixed-width lift, exact source constants, normal pointer guards and codec identities | SC1-SC8. Check actual byte-load addresses, every rewrite's source shape, both universal identities, all source target/modifier values, 256 bank inputs, 15 source formulas and three mutations. Changing W30 breaks the stated bounds/status interpretation and is outside those cuts. |
| SC-A6: Bounded cursor and source encoded extent for universal body-fit cut | SC2. Require 0<=c<=zero_extend32(M) and S+0x260=M+bias, with W3/W19/W30 as stated. Probe arbitrary length32 and both fit outcomes; no result is assigned to unbounded cursor64. |
| SC-A7: Synthetic cross-image correspondence and independent controllers | SC7, SC8. Check every derived binding and all fourteen protected bytes; retain per-read controller/bank symbols. A matching native transaction, layer identity or application meaning needs independent evidence. |

## Bounded continuation

| Impact | Interface / falsification target |
| --- | --- |
| High | Follow `0xfffffe000a63677c` to the consumer of S+0xbc4 and establish the resulting state/action selection. A different read epoch or overwritten value falsifies a direct join. |
| High | Establish the native daemon/Avp-to-primary26 transaction and identify the ADID container layer corresponding to H. Record-level compatibility alone does not identify transport. |
| Medium | Compare the cursor-committing non-u32 type-error path with caller cleanup/retry consumers; the source establishes ordering, while native reachability and lifecycle remain unknown. |
| Medium | Extend beyond the source-built sole node to duplicate/multiple-node traversal and lifetime synchronization, retaining actual pointer provenance. |
| Low | Reuse the certified codec identities for other protected-header callers after checking their original instruction shapes and byte-address premises. |

## Quality gates

- **QG1**: Pass. Factual source contracts and evidence limits; no normative judgment required.
- **QG2**: Pass. SC-A1 through SC-A7 identify dependencies and falsification probes.
- **QG3**: Pass for this increment. Protected header, bounds/type/length gates, u32 output, cursor/status/error ordering and saved caller covered; full interface goal remains active.
- **QG4**: Pass. BE16/BE32 fields, u16/u32/u64 arithmetic, byte capacities, nonwrapping bound, explicit counts and complexity are reproducible.
- **QG5**: Pass. Retained versus derived states, candidate versus committed cursor, two error classes, normal versus alternate pointers and native versus source-built execution remain distinct.
- **QG6**: Pass. Pinned original bytes/tables, dependency custody, solver formulas, actual serializer/load bytes and frozen ADID field provide primary provenance; no external semantic reference is invented.
- **QG7**: Pass. The bounded continuation table records impact and specific unresolved joins.
