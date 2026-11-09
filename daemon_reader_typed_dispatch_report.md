# Five reader families: exact tag dispatch and payload caller interfaces

All five source-bounded tag forests recognize exactly reader tags0xc31c,0xd0ee and0x1742. Under the established XOR0x4799 transform these correspond respectively to wire tags0x8485,0x9777 and0x50db. Recognition is distinct from payload validity and successful output. The u32 routes require exactly4 B and stage five different word-return selectors. N19 additionally requires exactly8 B on its recognized64 route and stages a payload pointer on its span route. The other four families stage an encoded end on recognized alternate-type routes, with different following status behavior.

These findings extend the earlier extent gates through exact tag routing, exact scalar extents and local payload/alternate interfaces. Complete value publication, native frame/cache initialization, buffer ownership, admission, authenticated transfer and daemon-kext pairing remain unknown. The broader investigation remains active. No target code was executed or emulated, no FairPlay request was sent and no IDB was modified. Existing original-file evidence sufficed; no additional IDA query was used.

## Primary provenance and coverage

The primary source is `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. All source virtual addresses below are unslid. Offsets, selectors, tags and constants are hexadecimal unless explicitly given as decimal counts or byte units.

- [Source blocks, transitions and exact authenticated fixups](triage_evidence/daemon_reader_typed_dispatch_source.json), [recovery script](triage_evidence/recover_daemon_reader_typed_dispatch.py).
- [Complete source-linked SMT queries and translation validator](triage_evidence/validate_daemon_reader_typed_dispatch.py), [checks](triage_evidence/daemon_reader_typed_dispatch_checks.json).
- [Preservation seal](triage_evidence/daemon_reader_typed_dispatch_delivery.json), [scoped quality gates](triage_evidence/daemon_reader_typed_dispatch_quality_gates.json), [independent publication auditor](triage_evidence/verify_daemon_reader_typed_dispatch_publication.py).
- Prior [normalized extent gates and first tag partitions](daemon_reader_extent_families_report.md), [tag-return caller interfaces](daemon_context_input_producers_report.md), [preparation/cache mapping](daemon_reader_context_footprint_report.md), [established word codec and N18 u32 reader](daemon_existing_scalar_reader_report.md).

Fifty-four source blocks contain1000 instructions /4000 B. Preparation contributes386 instructions /1544 B, yielding1386 captured instruction instances /5544 B. Every nonbranch instruction in this set is translated:1331 distinct instruction PCs,1412 translated instances and1276 SSA definitions. The additional81 translation instances compose the four alternate blocks and two following rejection blocks from both their recognized64 and span incoming states. All54 blocks have one terminal BRAA, no earlier control transfer and no SP write. They are dispatch continuations, not independently established complete compiler functions.

Fifty original pointer records support63 checked branch-slot/modifier matches and five u32 decoder-return destinations. Original chained fixups are decoded and independently checked against retained dyld_info evidence. Matching target/key/diversity metadata is conditional static evidence; hardware PAC success and native destination identity remain unknown.

## Exact tag forest

Let t=low16(raw_working_tag) and s=sign_extend32(t). The first split at signed0xd0ee was established previously. This increment checks the following source continuations using exact inherited registers:

```text
s < signed(0xd0ee):
    t == 0xc31c -> recognized64 route
    otherwise   -> rejection entry
otherwise:
    s < signed(0x1742):
        t == 0xd0ee -> u32 extent gate
        otherwise   -> rejection entry
    otherwise:
        t == 0x1742 -> recognized-span route
        otherwise   -> rejection entry
```

A separate bit-vector query proves that these signed regions recognize exactly the three tags for every one of65536 low16 patterns and arbitrary upper16 bits of the raw u32 working tag. The per-block source queries prove the actual branch selections, rather than inferring them from this schematic tree. They compose the preparation, extent gate, fixed bridge, first tag prefix and each later block. The phase premise is low32(frame+0x9d0)=0x6cf4; its upper32 bits are arbitrary. The working tag represents the newer tag-return store, replacing preparation's older zero-extended persistent tag value.

| Family | Lower exact-tag block | Upper signed split | Exact u32 block | Exact span block | Unknown-tag rejection entry |
|---|---|---|---|---|---|
| N19 | 0x1006116d0 | 0x100576488 | 0x100580d28 | 0x1004d3e9c | 0x10085e850 |
| N20 | 0x100586c34 | 0x100577268 | 0x1005cf940 | 0x1007f5554 | 0x1004ac0f8 |
| N21 | 0x100547cd0 | 0x1005a6244 | 0x1006192ac | 0x10055379c | 0x1005d0cb0 |
| N22 | 0x10058f08c | 0x1005eed28 | 0x100603ea0 | 0x10051958c | 0x1004ac0f8 |
| N23 | 0x100541708 | 0x10054b89c | 0x1005ef664 | 0x1005cccdc | 0x100555418 |

Tag recognition alone does not validate the full extent or payload. In particular, the checked recognized64 alternate routes of N20/N21/N22/N23 do not impose an exact8 B extent before staging their alternate effects. The earlier normalized extent gate still governs entry into the forest. Whether earlier native admission establishes stronger invariants is unknown.

## Exact scalar extents and u32 payload ABI

The prior source codec supplies W1=decoded_word XOR0x8ec35f08 and W4=decoded_word XOR0x8b3dc651. Define P=W1 XOR0x8ec35f08, a u32 extent. All five u32 routes require P=4 B; a different value enters that family's recorded rejection path. N19's recognized64 route requires P=8 B. These are universal bit-vector checks over all u32 P values, not sampled successful fixtures.

| Family / route | Exact extent gate | Required extent / B | Matching slot -> next block | Mismatch slot -> rejection |
|---|---|---:|---|---|
| N19 / u32 | 0x1005446bc | 4 | 0x1827 -> 0x10057c0e4 | 0x185d -> 0x10085e850 |
| N19 / u64 | 0x100499044 | 8 | 0x851d -> 0x1004a4de8 | 0x185d -> 0x10085e850 |
| N20 / u32 | 0x1004cd6c8 | 4 | 0x62c1 -> 0x10053a8dc | 0x2c8b -> 0x1004ac0f8 |
| N21 / u32 | 0x1005337c0 | 4 | 0xc69a -> 0x1004d7368 | 0x2b6e -> 0x1005d0cb0 |
| N22 / u32 | 0x10057a194 | 4 | 0xabb3 -> 0x1007f7638 | 0x1e39 -> 0x1004ac0f8 |
| N23 / u32 | 0x10055a4bc | 4 | 0x323e -> 0x1007fac14 | 0x2a94 -> 0x100555418 |

For each u32 match, the payload caller supplies X1=&frame[buffer_pointer_cell], X4=prepared payload key, X6=incoming X28, X22=0x6cf4 and W16=its return selector. The payload key equals the length-word key+4 modulo2^64, placing the word read4 B after that length word under the prior codec contract. The caller also writes canonical u32 reader tag0xd0ee into its working tag cache.

All five callers use slot0x3a31, IA diversity0x073a, to enter shared0x100530d34. The prior checked common caller dereferences the pointer cell and enters word decoder0x100800004 through slot0x8c3f. Its return table uses W16 and IA diversity0x232d. The five return destinations below are original-file fixup facts; their payload staging/publication semantics are not recovered by this increment.

| Family | Payload caller | Buffer-pointer cell | Payload key cell | Working tag cell | W16 return selector | Word-return frontier |
|---|---|---|---|---|---|---|
| N19 | 0x10057c0e4 | 0x4120 | 0x810 | 0x9b8 | 0xda | 0x100532b34 |
| N20 | 0x10053a8dc | 0x7f68 | 0x808 | 0x9a0 | 0xd0 | 0x1005705f4 |
| N21 | 0x1004d7368 | 0x2220 | 0x800 | 0x990 | 0xc3 | 0x10052c2bc |
| N22 | 0x1007f7638 | 0xcc0 | 0x7f8 | 0x998 | 0xea | 0x100509164 |
| N23 | 0x1007fac14 | 0x4720 | 0x7f0 | 0x988 | 0xe2 | 0x10047c454 |

The pointer-cell interface is distinct from a direct buffer pointer. The caller's X6 relation proves carried-register flow; applying the canonical decoder also requires its prior register/key preconditions. Actual buffer ownership, native validity of the four-byte read and delivery of a final value are not established here.

## N19 recognized64 and span routes

After exact tag0xc31c and exact P=8 B, caller0x1004a4de8 selects slot0xbe63, IA diversity0xa7d2, entering0x100588cb0. It supplies X0=N0 (the raw original cursor), X10=&frame[0x4120], X3=incoming X20 and W8=0x8c4. This is an entry ABI. The helper's complete algorithm and return protocol remain unknown; the8 B extent predicate does not independently prove that helper's full semantics.

For exact tag0x1742, block0x1004ac118 loads the buffer pointer cell at frame+0x4120 and raw cursor N0 from prepared frame+0x7e8, then stores (BUF+N0+10) mod2^64 as8 B at frame+0x63a0. Slot0x746b with IA diversity0x23bc selects0x1004730ec. The local block stages a payload-start pointer without an allocation or copy in that checked block. Complete span length/output publication, ownership and native pointer validity are unknown. No exact scalar-size requirement is imposed by this local span stage beyond the earlier extent-gate contract.

## Recognized alternate-tag effects

For N20/N21/N22/N23, both recognized64 tag0xc31c and span tag0x1742 enter a shared per-family alternate block. Exact incoming register states from both paths are proved. Each stores (C+10+zero_extend64(P)) mod2^64, where C is the family's encoded cursor input from the prior extent report. This is an encoded end value; interpreting the destination as a complete live iterator or ownership state would require later consumers.

| Family | Alternate block | Encoded-end destination | Local marker | Next slot -> frontier |
|---|---|---|---|---|
| N20 | 0x1005aabf8 | 0x6f18 | W6=0x74c29cd6 | 0x27b6 -> 0x1005f1648 |
| N21 | 0x1005a9908 | 0x4828 | X6 preserved until next block | 0x3631 -> 0x1005d0cb0 |
| N22 | 0x100617120 | 0x8d98 | W6=0x74c29cd6 | 0x33fb -> 0x1005f1648 |
| N23 | 0x1005c6110 | 0x3d58 | X6 preserved until next block | 0x36bf -> 0x100555418 |

N21 and N23 then enter their previously identified rejection blocks. The new proofs compose those blocks after both alternate-tag incoming states. Following the encoded-end store, N21 clears u64 frame+0x8318 and stages u32+0x26c4=0x8b3dc651 and u64+0x6f18=0x510df273a0723664. N23 clears u64+0x1bf0 and stages u32+0x1744=0x8b3dc651 and u64+0x8d98=0x799f55970eba2bcd. Both set W6=0x74c29d88 after their context-head dereference. The checked stores do not overwrite the earlier encoded-end destinations+0x4828 /+0x3d58.

Thus a recognized alternate tag can stage an end before the following local rejection effects, whereas an unknown tag enters the rejection block directly. This is a source-local ordering distinction. Complete cleanup, external status encoding and successful native outcomes remain unknown. N20/N22's0x74c29cd6 marker is kept distinct from0x74c29d88 and the earlier0x74c29d8f markers.

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent result | Stress test / falsification probe |
|---|---|---|---|
| TD1 | The pinned original daemon is the intended build. | Addresses, bytes and fixups. | Rehash the whole source and recaptured ranges; do not transfer these addresses to H2 or another build. |
| TD2 | Source-composed preparation/cache values apply at the relevant frame epoch, without intervening clobbers. | Cursor/key/limit and caller interpretation. | Join actual producers/preparation/reader entries with SP and alias-write history; current candidate writers do not prove this join. |
| TD3 | The newer raw32 tag-return value occupies the working cache. | Exact tag forest. | Trace its write/read epoch; every source query permits arbitrary upper16 tag bits. |
| TD4 | Low32 phase=0x6cf4; upper32 is unrestricted. | Fixed routing and inherited registers. | Re-solve another phase; no unconditional all-phase routing is claimed. |
| TD5 | Prior codec register/key preconditions and W1/W4/tag transforms apply. | Wire-tag names and logical payload-word placement. | Recheck pinned source codec proofs and carried-register inputs; a shared destination alone does not establish those preconditions. |
| TD6 | Original fixups describe intended authenticated targets; native memory and PAC validity are additional premises. | Conditional branch/return map. | Independently decode target/key/diversity and resolve owners; no hardware PAC or native endpoint proof is supplied here. |
| TD7 | The earlier modular extent contract supplies admission; nonwrapping arithmetic is a separate unproved native premise. | Reachable-body interpretation and pointer validity. | Recover earlier admission/limit producers; retain modulo64 source semantics until the no-wrap premise is established. |
| TD8 | Alternate/rejection borrowed reads complete and no unmodeled concurrent write intervenes. | Local stores, status markers and ordering. | Resolve context-head owners and later consumers/cleanup; do not infer an external result from a local marker. |

## Verification and reproduction

Forty-six UNSAT queries cover20 exact/signed tag branch contracts, six exact extent gates, five u32 caller ABIs, the N19 recognized64 entry, its span pointer, eight alternate-path effects, four following rejection effects and one exhaustive tag-partition identity. One SAT counterexample rejects a single common payload path for all recognized tags: the source-composed N20 recognized64 case selects its alternate route. This is an abstract source-state counterexample; no target input, native fixture or target execution is constructed.

Six changed-ledger controls reject a swapped extent destination, wrong key cell, wrong word-return selector, reversed tag branch, invented complete-accessor claim and missing span block. They are evidence-integrity controls. The source and solver ledgers contain exact queries, inputs, ranges and hashes. All prior artifacts outside the explicitly owned report/index update set remain preserved by the publication seal.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_reader_typed_dispatch.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_reader_typed_dispatch.py
```

Source extraction and SSA storage cost O(I+R) time/space for captured instructions I and pointer records R. Query construction costs O(sum of composed certificate lengths). QF_BV worst-case solver time is not claimed polynomial. Each query has15 s timeout and20 s subprocess limit; unknown/timeouts are rejected. Publication verification costs O(total artifact bytes+links), with O(manifest+largest JSON) memory. Extents are bytes; W/u32, low16 tags, X/u64 addresses and modulo2^64 arithmetic are explicit. The inherited source codec handles data byte order; little-endian instruction decoding is not a wire-format inference.

## Bounded continuation

- High: follow all five u32 return frontiers through payload staging, saved-tag checks, output publication and complete returns. This remains necessary for complete accessor semantics.
- High: recover0x100588cb0 and0x1004730ec through N19's recognized64/span result paths; entry width and staged pointer alone do not establish full result types or ownership.
- High: connect buffer/cursor/limit/cache producers to native frame epochs and outer operation selectors. These joins remain necessary for daemon-kext attribution.
- Medium: connect alternate-marker and end-store effects through their consumers and external result representation, preserving the recognized-versus-unknown ordering distinction.
- Medium: resolve no-wrap/native admission preconditions from preceding source gates without replacing encoded cursor coordinates by raw offsets.
- Low: use source-local labels such as exact_tag_router[N19] or stage_u32_word_call[N20] until complete compiler-function/accessor semantics justify stronger names. No IDB rename is made.

No new Mach endpoint or emission is established by this increment. Native selector26/RPC502/700 pairing and a successful daemon-kext exchange remain unknown.

## Scoped quality gates

QG1: Pass. The increment contains technical source observations and falsification probes; no normative conclusion is required.

QG2: Pass for TD1-TD8. Assumptions and dependent interpretations are explicit.

QG3: Pass for these five exact-tag forests and stated local ABIs. Complete accessor publication and the broader cross-layer goal remain active.

QG4: Pass. Exact byte widths, signed tag regions, modular arithmetic, source byte-order boundaries and reproducible complexity/time limits are explicit.

QG5: Pass for the bounded claims. Recognition versus validity/output, pointer cells versus pointers, staged encoded ends versus logical offsets and differing local markers remain distinct. Native unknowns are not presented as resolved.

QG6: Pass. Primary source identities, recaptured disassembly, independently checked fixups, all nonbranch instruction coverage and complete solver queries support the local contracts. Memory guidance supplies no semantic premise.

QG7: Pass for the finite high/medium/low continuation list. The full investigation is not marked complete.


## Reader value-consumer refinement

[Reader value consumers and conditional output](daemon_reader_value_consumers_report.md): N20/N21 converge on value cell7390,N22/N23 on78f0;context byte+68 selects comparison with+70 or+74. N19 joins variants,writes22 B within a24 B field envelope and separately stages a span pointer;its zero-word/span arm publishes CTX through borrowed OUT with raw success. Full885-instruction helper reads exactly eight payload bytes and stages raw X9;the complete transform is unknown. Sixteen blocks/1200 instructions plus118 span-context/386 preparation instructions,25 fixups/26 slot matches,1681 translated PCs,22 UNSAT queries,one SAT inactive-store counterexample and six changed-ledger controls pass. Native owners/cache/control attribution,ordinary publication and daemon-kext pairing remain unknown.
