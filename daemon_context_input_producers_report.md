# Context-input producer candidates and shared tag-return interfaces

The original daemon text contains one locally SP-affine full-width store candidate for each of the25 opaque inputs of preparation0x1006f6bf0. Six candidates are tag-return stages using a shared two-byte decoder and then the same four-byte decoder. This establishes local address/width effects and a conditional internal ABI. Which store initializes a cell in an actual native frame epoch remains unknown. No candidate store PC occurs in the retained path intervals; this does not exclude aliased initialization.

This increment preserves all original inputs and IDBs. It uses original-file disassembly, existing frozen path evidence, read-only IDA knowledge, static SSA and bit-vector queries. It executes no target code and sends no FairPlay request. The broader interface investigation remains active.

## Primary provenance and evidence

The primary source is `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Its original `__text` begins at0x100001058, spans14849960 B and hashes to `94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e`. Addresses below are unslid source virtual addresses; all offsets and selectors below are hexadecimal. Pointer metadata is decoded from original chained fixups and independently checked against the retained dyld_info evidence. File hashes and dependency hashes are included in the source ledger.

- [Source census, exact windows, stage blocks, fixups and IDA knowledge snapshot](triage_evidence/daemon_context_input_producers_source.json).
- [Executable source recovery](triage_evidence/recover_daemon_context_input_producers.py) and [static validator with complete SMT queries](triage_evidence/validate_daemon_context_input_producers.py).
- [Checks and solver results](triage_evidence/daemon_context_input_producers_checks.json), [preservation seal](triage_evidence/daemon_context_input_producers_delivery.json), [scoped quality gates](triage_evidence/daemon_context_input_producers_quality_gates.json).
- Prior [complete preparation footprint](daemon_reader_context_footprint_report.md), [conditional stack epoch](daemon_reader_stack_epoch_report.md) and [existing scalar reader](daemon_existing_scalar_reader_report.md).

The whole-text candidate census covers3712490 aligned instruction words, with zero skipdata entries,48569 original table-target resets and46294 unresolved recognized store instructions. Recognized stores are STR/STRB/STRH/STUR/STURB/STURH/STP. The scan tracks local SP/MOV/ADD/SUB affine chains, clearing aliases at known original entries, control transfers and conservative clobbers. Memory-derived/nonaffine aliases, unsupported stores, opaque callees and epoch equivalence remain outside this census. Therefore neither the single candidate per field nor the unresolved-store count proves exhaustive writers.

The25 contiguous candidate windows contain90 instruction instances. Twenty nearest original table-target stage blocks contain504 instances. A stage boundary here is a source dispatch target, not an independently established complete compiler function. Separate full-body liveness checks cover204 tag-helper and484 word-helper instructions. Fourteen original pointer records match their source targets, IA keys and diversity fields. Hardware PAC was not exercised.

## Candidate writes

Each row proves that execution of its captured local window stores the stated width at local SP+offset and preserves SP. N labels retain the preparation footprint's opaque input names; they are not semantic names. This table does not establish same-frame temporal ordering, the stored value's upstream provenance, or native reachability.

| Input | SP offset | Width / B | Source store PC |
|---|---:|---:|---|
| N0 | 0xa610 | 8 | 0x1004dbd20 |
| N1 | 0x9ea8 | 8 | 0x1006173ac |
| N2 | 0x9ea0 | 8 | 0x1006173a4 |
| N3 | 0x9e98 | 8 | 0x1004d5680 |
| N4 | 0x9e88 | 8 | 0x1005ec6bc |
| N5 | 0x9e78 | 8 | 0x1007f6950 |
| N6 | 0xae40 | 8 | 0x10089870c |
| N7 | 0xae30 | 8 | 0x100664b48 |
| N8 | 0xae20 | 8 | 0x1008caef8 |
| N9 | 0xae10 | 8 | 0x10085235c |
| N10 | 0xada0 | 8 | 0x100709824 |
| N11 | 0x9eb8 | 8 | 0x1004d5b6c |
| N12 | 0x9e58 | 8 | 0x100466a58 |
| N13 | 0x9e38 | 8 | 0x100538d04 |
| N14 | 0x9e90 | 8 | 0x1004d5678 |
| N15 | 0x9e80 | 8 | 0x1005ec6b0 |
| N16 | 0x9e70 | 8 | 0x1007f6948 |
| N17 | 0xad90 | 8 | 0x10075b86c |
| N18 | 0x959e | 2 | 0x1004e2ef0 |
| N19 | 0x958a | 2 | 0x10054981c |
| N20 | 0x8f7e | 2 | 0x10058acb0 |
| N21 | 0x8f6e | 2 | 0x100579728 |
| N22 | 0x8f56 | 2 | 0x1004f91dc |
| N23 | 0x8f46 | 2 | 0x1005775f0 |
| N24 | 0xa608 | 8 | 0x1004dbd1c |

There are19 full8 B stores and six full2 B stores. The25 exact addresses and widths are independently checked from contiguous source windows, rather than accepted from the candidate scanner. Same numeric SP offset in another stage does not establish the same native allocation. The prior stack-epoch result identifies F on its checked path; it does not place these additional candidate stores in that epoch.

## Six-stage tag-to-word ABI

The tag decoder at0x1005122cc loads its continuation from TABLE[sign_extend64(W16)] using8 B entries. X4 carries that pointer without later X4/W4 definitions to BRAA X4,X17 at0x1005125f8, with IA diversity0x271f. Six original entries identify the stages below. For selected phase0x6cf4, each stage:

1. Saves low16(W24) in its persistent2 B tag cell.
2. Saves raw W24 in a distinct4 B working cache cell.
3. Supplies X1=&frame[buffer_pointer_cell], X4=loaded next-word key, X6=incoming X28 and W16=next-word return selector; X22 reloads phase0x6cf4.
4. Uses dispatch index0x3a31 to branch to0x100530d34 with IA diversity0x073a.

The shared caller dereferences X1 to obtain the actual buffer pointer and preserves X4, X6 and W16. It uses dispatch index0x8c3f to enter0x100800004 with IA diversity0xd6ff. That word decoder loads X22=TABLE[sign_extend64(W16)], carries it without later X22/W22 definitions, and ends in BRAA X22,X17 at0x100800790 with IA diversity0x232d.

| Input | Tag-return stage | Incoming selector | Persistent tag | Working tag | Buffer-pointer cell | Key cell | Word-return selector | Next source frontier |
|---|---|---:|---:|---:|---:|---:|---:|---|
| N18 | 0x1004e2ee8 | 0x212 | 0x959e | 0x980 | 0x3710 | 0x8f8 | 0xef | 0x10052b3e8 |
| N19 | 0x10054980c | 0x1fa | 0x958a | 0x9b8 | 0x4120 | 0x830 | 0xf2 | 0x1005f4734 |
| N20 | 0x10058aca0 | 0x20b | 0x8f7e | 0x9a0 | 0x7f68 | 0x8e8 | 0xc9 | 0x100549e08 |
| N21 | 0x100579720 | 0x20c | 0x8f6e | 0x990 | 0x2220 | 0x8d0 | 0xae | 0x1005937a4 |
| N22 | 0x1004f91cc | 0x211 | 0x8f56 | 0x998 | 0xcc0 | 0x8a8 | 0xa6 | 0x100527de0 |
| N23 | 0x1005775e8 | 0x1f5 | 0x8f46 | 0x988 | 0x4720 | 0x880 | 0xdd | 0x1005450dc |

```text
TABLE[incoming selector], IA271f
    -> stage: save tag16 + raw tag32; set pointer-cell/key/selector/X6
    -> TABLE[3a31], IA073a -> 100530d34: X1 = *X1
    -> TABLE[8c3f], IAd6ff -> 100800004: read next word
    -> TABLE[word-return selector], IA232d -> next source frontier
```

For N18, the prior scalar-reader analysis establishes the next word as a length and follows its type/extent gate. Equivalent complete accessor semantics for the remaining five stages are unknown. Shared shape and matching source fixups establish the common local ABI, not identical policy, types or native routes.

Preparation reads each persistent tag as u16 and zero-extends it into its working u32 cache. A return stage writes raw W24 to that cache. These effects are distinct: an abstract source input W24=0xabcd9777 writes0x9777 persistently and0xabcd9777 to the working cell; preparation from that persistent cell would produce0x00009777. A SAT witness demonstrates the distinction, without asserting this raw input occurs in a native decoder. Frame epoch and write ordering determine which effect a consumer sees.

All addresses and pointer arithmetic use64-bit modular semantics. W registers and working tags use32 bits; persistent tags use16 bits. The decoded data's byte order is covered by the prior reader proof; little-endian source instruction decoding does not establish a wire format. Offset arithmetic is exact within these finite-width source models; numerical measurement uncertainty does not apply. Valid memory, object lifetime and successful authenticated transfer remain premises.

## Read-only IDA knowledge

The reference ledgers did not identify producers for the25 fields, so two knowledge queries used the fairplayd database with short identifier6b117c693e3b. The local request returned seven unverified facts, including four global fallback facts; the targeted field query returned zero. None supplies these producer mappings, and none is used as a semantic premise. The snapshot records the exact responses. No current IDB input-byte/hash attestation was obtained, and no IDB was changed. Earlier ARM64/H2 or other-architecture addresses are not transferred into this analysis.

## Assumption register and falsification probes

| ID | Assumption or evidence boundary | Dependent result | Stress test / falsification probe |
|---|---|---|---|
| CP1 | The pinned original daemon is the intended source build. | All addresses and contracts. | Rehash the complete image and recaptured windows; another build invalidates address reuse. |
| CP2 | A local window begins with its recorded SP and executes its captured instructions. | Exact candidate address and full-width effect. | Re-execute the static SSA translation with changed offsets/widths; no claim about reaching the window. |
| CP3 | Equal offsets do not establish equal active frame epochs. | Candidate interpretation only. | Connect each writer to a preparation invocation with a source-bounded SP/control-flow join before promoting it to a reaching definition. |
| CP4 | Phase0x6cf4 and required loaded table/key/buffer cells are valid. | Six tag-to-word staging contracts. | Solve other phase values and trace cell writers; a differing branch target refutes unconditional routing. |
| CP5 | Original pointer records describe intended authenticated destinations. | Conditional continuation map. | Re-decode each original fixup and compare target/key/diversity; native PAC success remains separate. |
| CP6 | The census recognizes only its specified local alias/store subset. | One candidate per field within that subset. | Extend to memory-derived aliases, unsupported stores and opaque callees; any additional writer refutes an exhaustive interpretation. |
| CP7 | Retained intervals are a finite historical scope. | Zero candidate-PC occurrences in those intervals. | Compare every candidate PC with their instruction intervals; absence does not exclude another route or alias. |
| CP8 | IDA knowledge is unverified and unused for semantics. | Provenance isolation and source-only conclusions. | Check returned verification/scope fields and source derivation; any semantic dependency on a recalled claim violates this boundary. |

## Verification and reproduction

Thirty-four UNSAT queries cover25 producer-window address/SP effects, six staging contracts, generic signed continuation indexing for both helpers and the shared word caller. One SAT witness checks raw32 versus saved16 semantics. The translated projection contains201 instruction instances and149 SSA definitions. Six changed-ledger controls reject a wrong offset, missing producer, wrong width, false reaching-definition promotion, invented retained-path occurrence and use of unverified knowledge. These are evidence-integrity controls, not six native behavioral tests. Whole-stage disassembly and helper liveness checks exceed the selected SSA projection.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_context_input_producers.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_context_input_producers.py
```

The census takes O(T+H) time for T decoded text words and H candidate overlaps with a fixed25-field target set; keeping that set variable gives O(T*N+H). Storage is O(text bytes+entry resets+H+captured evidence). Each finite SSA query is QF_BV; no polynomial solver-time bound is claimed. Per-query timeout is15 s, subprocess limit20 s, and unknown/timeouts are rejected. Publication verification is O(total artifact bytes+links), with O(manifest+largest JSON) memory. The independent publication audit rehashes the sealed inventory and validates JSON, links and owned-path preservation.

## Bounded continuation

- High: connect candidate stores to actual preparation/read epochs with explicit SP and intervening-write joins. This resolves whether persistent fields are earlier semantic state, reused workspace or values from another route; it is currently unknown.
- High: follow the five new word-return frontiers and their buffer/key producers to recover complete accessor/control contracts. Matching decoder interfaces provide precise entry points without assigning unsupported types.
- Medium: model supported nonaffine aliases and memory-derived frame pointers to widen the producer census. Unresolved stores remain potential aliases; their count is not an exposure estimate.
- Medium: preserve the raw32/low16 distinction in any lifted cache model. Premature zero extension can alter later comparisons even when persistent bytes agree.
- Low: retain the IDA scope/verification metadata when correlating knowledge; local queries can include global fallback facts and another build's addresses.

No new Mach port emission or daemon-kext pairing is established. The previously retained trace's failed user-client open still prevents treating it as a successful selector26/RPC502/700 exchange. Native endpoint, authorization, mapping, PAC and object-lifetime facts remain unknown; this increment does not close them.

## Scoped quality gates

QG1: Pass. The increment contains technical observations, explicit premises and falsification probes; no normative conclusion is required.

QG2: Pass for CP1-CP8. Assumptions and dependent claims are bounded above.

QG3: Pass for this producer/interface increment. It covers all25 targeted context inputs and six local tag-to-word contracts. The broader interface goal remains active.

QG4: Pass. Byte extents,16/32/64-bit effects, modular arithmetic, selectors, source byte order and algorithmic bounds are explicit and reproducible.

QG5: Pass for the bounded claims. Candidate versus reaching definition, raw32 versus saved16, local versus global knowledge, source versus retained occurrence and native versus modeled transfer remain distinct; unknown native state is not represented as a contradiction resolved by this increment.

QG6: Pass. Original-file identities, contiguous source windows, independently decoded fixups, fresh census recapture and complete solver queries support the local claims. Recalled knowledge is not semantic evidence.

QG7: Pass for the finite continuation list above. Additional high/medium/low opportunities are specified without claiming that broader work is complete.


## Reader extent-family refinement

[Five reader extent gates and signed tag prefixes](daemon_reader_extent_families_report.md): all five compare modular64(length-word offset + 4 B + decoded u32 extent) with their saved limit. Four use encoded cursor coordinates; five fixed bridges lead to signed-low16 tag partitions at0xd0ee. First rejection effects differ across families. Nineteen blocks/406 instructions plus386 preparation instructions,31 pointer records/32 slot matches,772 distinct translated PCs,23 UNSAT queries,one SAT coordinate counterexample and six changed-ledger controls pass. Same-frame cache initialization,no-wrap admission,complete accessor semantics and native daemon-kext pairing remain unknown. No new Mach port emission is established.
