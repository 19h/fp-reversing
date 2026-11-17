# First early record publication and parser return

The early serialization path conditionally publishes its first record into the source-zeroed 16-byte container: head and tail both become the new node, whose next and previous links remain zero. It then requests the retained callback `0xfffffe000a661ba0`, which selects the early parser cursor gate on raw success. The cursor is unchanged by publication. All 30 retained fixtures have cursor equal to the low32 input size and select exhausted input; a universal source obligation separately covers a remaining suffix.

This extends [early payload serialization](userclient_early_payload_report.md). Four compositions cover u32, u64, zero-length span and nonzero span. The result assumes the explicit storage/epoch/normal-pointer premises below. It does not continue the stopped private guest, initialize its eight unrelated setup cells, execute native PAC or establish native allocation/ownership/locking. Nonempty early lookup/replacement, exhausted-input handling beyond the selected edge and a complete daemon/kext transaction remain unknown.

## Evidence and custody

| Evidence | Identity / coverage |
| --- | --- |
| Original kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Full `_PRnut72j9` container | `[0xfffffe000a635208, 0xfffffe000a666930)`, 202536 bytes / 50634 words |
| Container SHA-256 | `d54edd3241fee05c2f0ed690b0fb1234742c0eb33722e3633f9f0ce80c7da297` |
| Decoded checks SHA-256 | `f0d3a605400d34ce4e79a92a09ec583f33e3bd726fc058578d3c7fa74bbb3c26` |
| Decoded audit SHA-256 | `e4f5500b71e6b6b45d91b649d0b5fb71029f3f3eddc0cbee0c9fa7d9ae318743` |
| Source capture | 15 spans, 186 words, 30 original table-pointer records; all 186 new words covered |
| New source obligations | 18 nonvacuous UNSAT queries, 9305 lifted instruction instances |
| Prior rechecks | Four scalar/span payload obligations re-solved UNSAT |
| Prefix custody / evaluation | 480 reconstructed cells across 30 states; 270 post-publication field values |
| Additional case checks | 30 UNSAT controller-premise queries with controller values unbound |

The [generator](triage_evidence/recover_userclient_early_publication.py) rehashes the complete original function, compares selected words with both images, verifies original pointers and checks the complete 256-input bank relation. It reconstructs every retained cell from all overlapping source stores. The [auditor](triage_evidence/audit_userclient_early_publication.py) composes original instructions through the first publication, preserves the earlier scalar/span premises and adds independent field/control oracles. The [delivery verifier](triage_evidence/verify_userclient_early_publication_delivery.py) reconstructs the receipts and checks publication custody. Receipts are [checks](triage_evidence/userclient_early_publication_checks.json.zst) and [audit](triage_evidence/userclient_early_publication_audit.json.zst); hashes refer to decoded JSON. No IDB was required or modified.

## Claim register

| Claim | Established result |
| --- | --- |
| EU1 | Source produces the early output alias and empty container; 16 retained cells per predecessor have overlapping-store custody. |
| EU2 | All four payload compositions emit the same caller-specific early lookup request ABI. |
| EU3 | Shared lookup saves the early callback/output, reads the empty head, publishes a zero old-result and returns raw miss. |
| EU4 | A certified 256-input bank reduction preserves the caller return and selects descriptor metadata independently of two arbitrary controller values. |
| EU5 | Raw miss selects the empty append, writes both H words to J and preserves the node's links, extent and buffer. |
| EU6 | The saved callback receives raw success and selects exact success/error continuations; success returns to the early cursor gate. |
| EU7 | Publication preserves cursor and serialized buffer; all 30 fixture projections select exhausted input without binding unrelated setup cells or controllers. |
| EU8 | Three source mutations are rejected; native publication, later early records and complete external operation remain outside the claims. |

## Early and later lookup interfaces

`F`, `C`, `S`, `J` and `Z` retain the early payload report's frame/context/workspace/node/buffer meanings. `H` is the earlier 16-byte FPTTLV result. `D` and `L` are raw tag32 and length32; `N` is the low32 declared input size. The first record's source-produced cursor is `c=zero_extend32(L)+10`. `SUCCESS=0x31ae0066`, `MISS=0xce515bda` and the control token is `0x886a1ca3`.

| Channel | Early path, this proof | Later path, prior evidence |
| --- | --- | --- |
| Common lookup entry | `0xfffffe000a662ab4` | `0xfffffe000a662ab4` |
| Container root | C+0x20 | C+0x780 |
| New-node root | C+0x58 | C+0x6b8 |
| Lookup output | C+0x50, via F+0x348 | C+0x628, via F+0x350 |
| Encoded requested tag | S+0x1d0 | S+0x128 |
| Private return index | `0x6c` | `0x7b` |
| Lookup-return target | `0xfffffe000a662b64` | `0xfffffe000a66248c` |

Later-channel claims retain the scope of the [record publication report](userclient_record_publication_report.md). Sharing the lookup entry does not identify the two containers or make their saved output/return channels interchangeable. Private table indices are neither Mach message identifiers nor user-client selectors.

At `0xfffffe000a655cb4`, the early request clears C+0x50, loads H from C+0x20 and encoded D from S+0x1d0, loads the output alias from F+0x348, and requests lookup entry through table index `0x49a`. The terminal BRAA is at `0xfffffe000a655d34`, modifier `0x0ee9`.

| Request field | Exact value |
| --- | --- |
| X2 / X4 / X7 | C / S / private table base |
| X22 | H |
| W9 | `D XOR SUCCESS` |
| X10 | C+0x50 |
| W8 | `0x6c`, caller return index |
| W3 / W30 | Control token / SUCCESS |
| X20 | Byte-mask key1 `0x4dae26df20976138` |
| X21 | Lookup bank root `0xfffffe000792fcc0` |
| X28 | Retained root `0xfffffe0007949dd0` |

The output alias has an original two-instruction producer at `0xfffffe000a635e64`: `ADD X8,X2,#0x50; STR X8,[SP,#0x348]`. Its X2=C premise is checked at the actual producer visit in every retained prefix. Source STP at `0xfffffe000a6366c8` zeroes H's two words. The new proof includes both producer sequences; source custody distinguishes these stores from allocator-zeroing assumptions.

## Empty lookup and certified callback bank

Shared lookup stores its caller return at C+0xc8, the output alias at C+0x758 and the requested encoded tag at S+0. H is non-NULL under the storage premise. Its head is zero, so lookup stores zero at C+0x2b0, publishes zero through the saved output alias and supplies raw MISS. It does not inspect a node header or payload on this first-record path.

The callback block at `0xfffffe000a662b00` reads two controller words and reduces them through two captured 256-byte tables. For all byte indices i:

```text
i XOR right[left[i] XOR 0x87] = 0xdf
index = 0xdf - 0x93 = 0x4c
slot  = 0xfffffe0008472160
selected original pointer target - 4 = 0xfffffe000847bce0
```

The left/right table bases are `0xfffffe000792fcc0` and `0xfffffe00079391f0`. The selected descriptor address is metadata returned in X22; no retirement function executes on this path. The controller pair can be arbitrary u32 values. The auditor implements the captured UXTB operand explicitly and uses the full-array certificate for the paired lookup reduction. It does not assign fixed controller values to force the result.

The callback transfer at `0xfffffe000a662b60` returns to the saved early target `0xfffffe000a662b64`, modifier `0x8d28`, with raw MISS and C+0x50 still zero. Thirty additional case-premise SMT checks establish the unresolved controller-dependent address identities universally after binding each known predecessor projection; they are separate from the 18 source obligations.

## First-node publication and parser callback

The early status branches test raw SUCCESS and MISS. The actual empty-container result is MISS, so the selected path loads H's tail and J from C+0x58. With tail zero, table index `0xd6a` selects `0xfffffe000a662bc4`.

```text
serialized first record
        |
lookup(H, encoded D, &C+0x50, early return)
        |
empty H -> MISS, old result = 0
        |
STP J,J,[H] -> H.head = J; H.tail = J
        |
saved callback C+0x260 = 0xfffffe000a661ba0
        |
SUCCESS -> early cursor gate
        +--- c < N --> 0xfffffe000a660c28, next-header availability
        +--- c = N --> 0xfffffe000a660b2c, exhausted input
```

The head/tail store is at `0xfffffe000a662bc8`. J.next and J.previous remain zero; J+0x10 remains u32 L+10; J+0x18 remains Z; C+0x58 remains J; C+0x50 remains zero. These exact fields are proved, rather than inferred from descriptor names.

| Handoff | Selected target | Modifier |
| --- | --- | --- |
| Empty append return, `0xfffffe000a662bdc` | `0xfffffe000a664218` | `0x7250` |
| Saved callback, `0xfffffe000a66422c` | `0xfffffe000a661ba0` | `0xf596` |
| Successful parser callback, `0xfffffe000a661bf8` | `0xfffffe000a660af4` | `0xc9dc` |
| Cursor gate, `0xfffffe000a660b28` | Next-header or exhausted-input target | `0x2f10` |

The saved callback is loaded from C+0x260 at `0xfffffe000a664224`. A separate all-status32 source obligation proves that the handler selects `0xfffffe000a660af4` exactly for SUCCESS and `0xfffffe000a661bfc` for every other status, under its stated control-register premises. This does not execute the error continuation or establish its full cleanup effects.

Publication performs eight source store instances, totaling 60 bytes: C+0x50 clearing, lookup's return/tag/output/head/result state, and H's two list links. Every publication store is proved disjoint from Z's L+10-byte extent. The record bytes therefore retain the preceding serialization contract. Nonzero span composition uses the previously proved complete reverse-copy induction and the final source step; it does not pretend that one modeled final step writes the whole payload.

## Evaluation and negative controls

All 30 stopped predecessor states have H's two words and J's two links source-defined zero. Sixteen cells per state, including frame roots, callbacks, tag, cursor, size and links, are reconstructed from all overlapping source stores. The four resulting source compositions cover u32, u64, zero spans and nonzero spans. Partial-state evaluation checks nine resulting fields per case, totaling 270 values, and all storage/branch/table premises. Each fixture has c=N and selects `0xfffffe000a660b2c`.

The universal cursor proof permits c<N and selects next-header availability without reading another header. No raw-status, callback or pointer from a different caller epoch is substituted. The eight unrelated setup cells and both controller values remain unbound. The continuous private guest still stops at its earlier undefined load; these are symbolic compositions and predecessor-bound expression evaluations.

| Copied-source mutation | Oracle rejection |
| --- | --- |
| NOP head/tail STP at `0xfffffe000a662bc8` | H does not acquire the new node as both head and tail. |
| NOP new-node load at `0xfffffe000a662ba8` | Published links violate the exact J identity contract. |
| NOP saved-callback load at `0xfffffe000a664224` | Selected callback target violates the retained handler ABI. |

All three mutated paths have satisfiable storage/branch/lookup premises and a satisfiable contract violation. Controls stop at the mutated callback handoff before following its target. Only copied symbolic source changes; original images and IDBs remain unchanged. These controls establish source-oracle sensitivity, not native fault behavior.

First-record lookup and append take O(1) selected work because the container is empty. Publication adds O(1) storage and leaves the L+10-byte record intact. Combined scalar paths remain O(1); a nonzero span retains O(L) preceding copy work. Evidence construction is linear in captured source, query DAGs and prefix-store reconstruction, plus the 256-input certificate; solver search is separate with 30-second query limits. No native latency or allocator cost is inferred.

## Assumption register

| Assumption | Dependencies and falsification probe |
| --- | --- |
| EU-A1: Pinned images, pointer interpretation and dependency closure | EU1-EU8. Rehash full container, dual-image words, original slots, tables and all dependencies; rebuild both receipts. |
| EU-A2: Retained source epochs and first-record state | EU1-EU7. Reconstruct all 480 cells from overlapping stores and check the output-alias producer register. A prior record, changed alias or intervening native write invalidates empty-first-record applicability. |
| EU-A3: Separate valid H/F/C/S/J/Z extents and span input where needed | EU2-EU7. Require nonzero nonwrapping extents, F alignment 16 bytes, image separation, `L<=0xfffffff5` and Z extent L+10; add a separated readable P extent for nonzero spans. Native admission remains unknown. |
| EU-A4: First cursor and declared size | EU5-EU7. Require `c=zero_extend32(L)+10<=zero_extend32(N)`; exclude the earlier zero-tag span bypass when claiming this node path. Fixture equality c=N is checked, not generalized to every caller. |
| EU-A5: Normal pointer guards and logical authenticated transfers | EU2-EU8. Check satisfiable branch premises, original pointer membership and exact modifiers; establish native PAC/BTI/retag behavior independently. |
| EU-A6: Stable bank arrays and independent fixed-width lift | EU3-EU7. Exhaust all 256 bank indices; leave controllers arbitrary; check 18 source obligations, 30 case-premise queries, four prior payload formulas and three mutations. |
| EU-A7: First publication scope | EU7-EU8. Follow nonempty early lookup/replacement, exhausted-input handling and native ownership before asserting a complete parser, lasting external publication or matched daemon transaction. |

## Bounded continuation

| Impact | Next evidence | Contribution |
| --- | --- | --- |
| High | Exhausted-input target `0xfffffe000a660b2c` | Recover container publication/cleanup and the next outer phase without equating a selected edge with completion. |
| High | Next-header and nonempty early lookup/replacement paths | Extend beyond first record; establish duplicate policy and early list retirement ABI. |
| High | Original selector/caller and matched daemon-provider request | Connect admitted input capacity, record identity and native transaction provenance. |
| Medium | Native allocation, lifetime, pointer authentication and synchronization | Determine whether the symbolic storage/epoch premises hold in a live operation. |
| Medium | S+0x20 marker producer and other setup-cell consumers | Recover remaining external state/control transitions; this increment establishes no new Mach endpoint or emission site. |

## Quality gates

- **QG1**: Factual source, memory and ABI claims require no normative conclusion.
- **QG2**: EU-A1-EU-A7 identify dependencies and falsification probes.
- **QG3**: First publication, shared lookup ABI, bank reduction, callbacks, cursor selection, custody and interface limits are covered; full investigation remains active.
- **QG4**: u32/u64 widths, 16/32-byte objects, exact stores/bytes, fixed control values, counts and scoped costs are reproducible.
- **QG5**: Early/later roots, first/later records, symbolic composition/continuous guest execution, serialized bytes/list links and conditional/native publication remain distinct.
- **QG6**: Original words/pointers/arrays, overlapping-store custody, 18 source proofs, four prior rechecks, 30 controller-premise queries and three controls support the bounded claims.
- **QG7**: Continuation is impact-ranked and preserves native, multi-record, cleanup, marker and matched IPC questions.
