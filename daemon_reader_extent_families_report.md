# Five reader families: normalized extent gates and signed tag prefixes

Five additional word-return families reduce to the same conditional source contract: decode a u32 extent P, compute a modular u64 end at length_word_offset + 4 B + P, compare it with a saved limit, and on fit enter a signed-low16 tag partition at0xd0ee. Four families use encoded cursor coordinates. Their source saved-end values are not interchangeable with logical byte offsets. First rejection effects also differ between families.

This establishes the extent gate, fixed fit bridge, first tag partition and first rejection block. Complete accessor types, payload publication, ownership, native admission and daemon-kext pairing remain unknown. The broader investigation remains active. No target code was executed or emulated, no FairPlay request was sent and no IDB was modified. Existing original-file references suffice for this increment; no additional IDA query was needed.

## Provenance and finite coverage

The primary source is `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses below are unslid source virtual addresses. All offsets, selectors and constants below are hexadecimal unless a decimal count or unit is explicit.

- [Original source blocks, exact fixups and dependency hashes](triage_evidence/daemon_reader_extent_families_source.json).
- [Recovery script](triage_evidence/recover_daemon_reader_extent_families.py), [static validator and complete SMT queries](triage_evidence/validate_daemon_reader_extent_families.py), [proof results](triage_evidence/daemon_reader_extent_families_checks.json).
- [Preservation seal](triage_evidence/daemon_reader_extent_families_delivery.json), [scoped gates](triage_evidence/daemon_reader_extent_families_quality_gates.json), [independent publication audit](triage_evidence/verify_daemon_reader_extent_families_publication.py).
- Prior [producer/tag-return interfaces](daemon_context_input_producers_report.md), [preparation/cache relations](daemon_reader_context_footprint_report.md), [word codec and established N18 u32 reader](daemon_existing_scalar_reader_report.md).

Nineteen complete branch-terminated source blocks contain406 instructions /1624 B. Preparation contributes386 instructions /1544 B, for792 captured instruction instances /3168 B. The static translations cover every nonbranch instruction in that set:772 distinct instruction PCs,779 translated instances and689 SSA definitions. The extra seven instances arise from translating the shared N20/N22 rejection block twice with different incoming states. Thirty-one original authenticated pointer records support32 branch-slot/modifier matches. All19 additional blocks have one terminal BRAA, no earlier control transfer and no SP write. Source bytes and fixup records are freshly recaptured and checked; hardware authentication and native memory validity are separate unknowns.

## Common extent contract

Let C be the family's original u64 cursor input, L its u64 limit input, K its prepared word-key value, and W=0x661a590b302baf96 the prior source-proved word-key base. The word reader uses O=(K-W) mod2^64 as a byte offset relative to its supplied buffer. Its returned W1 representation gives P=W1 XOR0x8ec35f08, a u32 value. Its parallel W4 representation is P XOR0x8b3dc651. These codec relations are supported by the pinned prior source proofs, not a new native read.

The gate computes:

```text
O        = (C + key_bias - W) mod 2^64       # byte offset, not a pointer
P        = W1 XOR 0x8ec35f08                 # u32 extent
E        = (O + 4 + zero_extend64(P)) mod 2^64
fit      = unsigned64(E) <= unsigned64(L)
savedEnd = (C + 10 + zero_extend64(P)) mod 2^64
```

The additions of4 and10 represent byte displacements; all compared values are byte offsets/extents in the selected source coordinate system. Runtime buffer ownership and backing extent are not established by the equations. The source uses64-bit additions rather than wrapping the sum at32 bits. P ranges from0 through4294967295 B; P+4 ranges from4 through4294967299 B before any u64 wrap.

| Family | Gate PC | C input | L input | key_bias | O-C mod2^64 | Saved-end frame cell |
|---|---|---|---|---|---|---|
| N19 | 0x1005f4734 | N0 | N24 | 0x661a590b302baf9c | 0x0000000000000006 | 0x9590 |
| N20 | 0x100549e08 | N1 | N2 | 0x150c66978fb97938 | 0xaef20d8c5f8dc9a2 | 0x8f80 |
| N21 | 0x1005937a4 | N3 | N14 | 0xe56372fd4e50e7b | 0xa83bde24a4b95ee5 | 0x8f70 |
| N22 | 0x100527de0 | N4 | N15 | 0xec7b0374217183cf | 0x8660aa68f145d439 | 0x8f58 |
| N23 | 0x1005450dc | N5 | N16 | 0x42f093c391145ff4 | 0xdcd63ab860e8b05e | 0x8f48 |

The source-preparation composition proves each K=C+key_bias relation directly, using arbitrary abstract context inputs. It then proves all five full gate equations. It does not establish that preparation and a candidate producer execute in the same native frame epoch, or that intervening aliases preserve their cells. Those remain explicit composition premises.

N19 directly compares savedEnd with L because O=C+6. It additionally stores the returned encoded W4 extent as4 B at frame+0x958c and savedEnd as8 B at frame+0x9590. In the other four families, savedEnd retains the original cursor encoding while the comparison implements the translated logical end. A SAT counterexample rejects replacing N20's logical E with its savedEnd; it is an abstract bit-vector counterexample, with no native request or target fixture.

## The four wrapped comparison networks

The N20/N21/N22/N23 gates compare translated end coordinates with translated limits using several flags and a conditional select. Their common arithmetic pattern has a compact identity. For arbitrary u64 z, bias b and limit l:

```text
lo  = z < b
hi  = l > ~b
gt  = z > (l + b mod 2^64)
bad = (hi XOR lo) ? lo : gt
bad == ((z - b mod 2^64) > l)
```

An independent universal UNSAT query proves this identity for all u64 inputs. Separate source-composed gate queries prove that each actual instruction network selects its fit/reject slot according to the common E<=L predicate, including its phase-dependent multiplications and inversions. The generic identity alone is not used as a substitute for checking the source networks.

For N20, b=0x99a8b155; N21 b=0x24f8bf7e; N22 b=0x355fb187; N23 b=0xfee3fc5b. The source thresholds loaded by MOV/MOVK are the64-bit complements ~b. The original coordinate bias and these comparison biases are different quantities; both are retained in the source and queries.

Modulo64 fit does not by itself imply that O+4+P fits without wrapping. A separate universal query proves equivalence to a widened128-bit sum only under the explicit premise O+4+P<=2^64-1. The widened sum cannot overflow128 bits because its maximum is less than2^65. Whether prior native paths establish the no-wrap premise is unknown. This is a source arithmetic boundary, not a confirmed native defect or an established externally reachable condition.

## Fit bridges and first tag split

All five fit branches enter fixed bridges and then signed tag partitions. The queries compose exact outgoing registers from gate to bridge to tag prefix; they do not substitute core-phase values for inherited registers that already changed meaning. Only low32(frame+0x9d0)=0x6cf4 is required; its upper32 bits are arbitrary in every source proof.

The working tag is the raw u32 value saved by the prior tag-return stage. The type query replaces preparation's older zero-extended saved tag with this raw value. Despite arbitrary upper16 bits, the split depends only on sign_extend32(low16(tag)). The boundary is0xffffd0ee, or -12050 as a signed32 value. Equality follows the nonlower branch. This is the first partition only; it does not establish that either branch accepts that type.

| Family | Fit slot -> bridge | Bridge slot -> tag prefix | Tag < signed0xd0ee: slot -> frontier | Otherwise: slot -> frontier |
|---|---|---|---|---|
| N19 | 0x8661 -> 0x100574bf4 | 0xb6a4 -> 0x1005fbaa0 | 0x8055 -> 0x1006116d0 | 0x806f -> 0x100576488 |
| N20 | 0x7aae -> 0x1005f96fc | 0x35a1 -> 0x10053063c | 0x5ad8 -> 0x100586c34 | 0x5ad5 -> 0x100577268 |
| N21 | 0x8907 -> 0x1005ef6ac | 0xae84 -> 0x10060542c | 0xabb5 -> 0x100547cd0 | 0xabc6 -> 0x1005a6244 |
| N22 | 0x2c41 -> 0x10054c07c | 0xa598 -> 0x1005ad68c | 0x6c67 -> 0x10058f08c | 0x6c8f -> 0x1005eed28 |
| N23 | 0x3695 -> 0x1005aaa28 | 0x9fb9 -> 0x100552738 | 0xa170 -> 0x100541708 | 0xa15a -> 0x10054b89c |

```text
prepared key/limit cells + returned decoded word
    -> normalized extent gate
       | fit -> fixed bridge -> signed low16 tag partition -> two source frontiers
       | reject -> family-specific first rejection block -> recorded next frontier(s)
```

Native caller/endpoint identity, buffer-pointer production, subsequent exact-tag predicates, complete accepted-type sets and publication remain unresolved for these five families. The previously established N18 u32 reader provides a structural comparison, not semantic equivalence for its siblings.

## First rejection effects

These effects apply after entering the recorded rejection block and completing its required reads. They are not final return values or a proved cleanup contract.

| Family | Reject slot -> first block | Local effect | Next slot(s) |
|---|---|---|---|
| N19 | 0x86a0 -> 0x10085e850 | Store u32 status0x74c29d8f at+0x2b1c; copy u64[+0x6368] to+0x4ed8; X19=&frame[0x4ed8]. | 0x3ad1 -> 0x1006e3d4c |
| N20 | 0x7a75 -> 0x1004ac0f8 | Set W6=0x74c29d8f; no frame store in this block. | 0x30e4 -> 0x1005f1648 |
| N21 | 0x88f4 -> 0x1005d0cb0 | Read u64[u64[frame+0x21b0]]; clear u64+0x8318; stage u32+0x26c4=0x8b3dc651 and u64+0x6f18=0x510df273a0723664; W6=0x74c29d88. | 0xc944 -> 0x1005f1648; 0xc935 -> 0x1005aadb8 |
| N22 | 0x2c8b -> 0x1004ac0f8 | Set W6=0x74c29d8f; no frame store in this block. | 0x30e4 -> 0x1005f1648 |
| N23 | 0x36bf -> 0x100555418 | Read u64[u64[frame+0x19f0]]; clear u64+0x1bf0; stage u32+0x1744=0x8b3dc651 and u64+0x8d98=0x799f55970eba2bcd; W6=0x74c29d88. | 0x33fb -> 0x1005f1648; 0x33ce -> 0x1005f4fc8 |

For N21 and N23, the listed next slots are respectively for a NULL versus non-NULL loaded context head. The dereference itself occurs before selecting the next slot; valid memory is a premise. N20 and N22 share the same first rejection block and next selector, reached with correctly composed phase-bearing registers. The raw marker distinction0x74c29d88 versus0x74c29d8f remains explicit; a common external error meaning has not been inferred.

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent result | Stress test / falsification probe |
|---|---|---|---|
| EF1 | The pinned original daemon is the intended build. | All addresses and contracts. | Rehash the original file and every source range; another build invalidates reused addresses. |
| EF2 | Gate-entry key/limit caches equal the source preparation values, with the same relevant frame epoch and no intervening clobber. | Normalized cursor/limit interpretation. | Join each producer/preparation/gate with explicit SP and intervening alias writes; current candidates alone do not establish this join. |
| EF3 | The prior word codec's W1/W4 relations apply to this returned word and prepared key. | Decoded u32 P and logical word offset O. | Recapture its source and pinned proof dependencies; buffer validity and actual native routing remain separate. |
| EF4 | Low32 of the phase load is0x6cf4. Upper32 is arbitrary and proved irrelevant to these effects. | Slot selection and composed bridges. | Re-solve another low32 phase; current contracts are not unconditional across phases. |
| EF5 | The working tag is the raw u32 tag-return value, not its older preparation copy. | Signed-low16 prefix contract. | Trace the exact tag-cache write/read epoch; source queries cover all raw32 tags and reject dependence on their upper16 bits. |
| EF6 | Ordinary nonwrapping end arithmetic requires a separate no-wrap premise. | Widened interpretation only. | Prove the premise from earlier gates; without it, retain the modular64 source predicate. |
| EF7 | Original chained fixups describe intended targets; valid native memory and successful authenticated transfer are additional premises. | Conditional branch maps. | Independently decode target/key/diversity; no hardware PAC, endpoint or daemon-kext identity is proved here. |
| EF8 | First rejection blocks complete their borrowed/context reads. | Their local stores, markers and next slots. | Resolve pointer owners/lifetimes and later return/cleanup routes; do not infer an external status from a raw local marker. |

## Verification and reproduction

Twenty-three UNSAT queries comprise one five-key preparation binding, five normalized extent/store contracts, five fixed bridges, five signed tag prefixes, five first-rejection effects, one generic translated-comparison identity and one no-wrap/widened equivalence. One SAT counterexample rejects the encoded-cursor shortcut. Six changed-ledger controls reject an incorrect key bias, swapped fit/reject index, wrong saved-end store width, wrong tag cell, invented initialization claim and missing rejection block. They test evidence integrity, not native behavior.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_reader_extent_families.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_reader_extent_families.py
```

Source extraction and translation cost O(I+R) time and space for I captured instructions and R retained pointer records. Query construction repeats the preparation projection across composed certificates; its total size is O(sum of certificate instruction instances). QF_BV solver worst-case time is not claimed polynomial. Query timeout is15 s and subprocess limit20 s; unknown or timeout is rejected. Publication checking costs O(total artifact bytes+links), with O(manifest+largest JSON) memory. All numerical source widths and byte displacements are exact within these conditional finite-width models.

## Bounded continuation

- High: follow the ten tag frontiers to exact type predicates, per-type extent checks, payload decoders and output publishers. The shared first split supplies an exact comparison point without proving complete equivalence.
- High: establish the producers and frame epochs of the five buffer/cursor/limit families. This connects mathematical compositions to actual caller state and remains required for stronger native interpretations.
- Medium: connect the differing rejection markers through return and cleanup to the external result representation. Source-local W6 values do not establish a shared external error code.
- Medium: derive or refute the no-wrap premise from preceding source admission gates and saved-limit producers. Preserve encoded coordinates while doing so.
- Low: use stable labels such as extent_gate[N20] in reports until complete accessor semantics support stronger names; no IDB rename is made by this increment.

No Mach port is newly created, transferred or emitted in these checked blocks. This increment refines daemon-internal serialization/control interfaces. Native selector26/RPC502/700 daemon-kext pairing and successful FairPlay exchange remain unknown.

## Scoped quality gates

QG1: Pass. Technical source observations and falsification probes require no normative conclusion.

QG2: Pass for EF1-EF8. Assumptions, dependent claims and tests are explicit.

QG3: Pass for this five-family extent/type-prefix increment. Complete accessor semantics and the full cross-layer objective remain active.

QG4: Pass. Byte units,32/64/128-bit widths, modular arithmetic, signed tag ordering, complexity and reproduction are specified.

QG5: Pass for the bounded claims. Encoded versus logical coordinates, modulo versus widened bounds, raw versus saved tags and differing local failure markers remain distinct. Unknown native preconditions are not represented as resolved.

QG6: Pass. Primary source hashes, contiguous disassembly, original independently checked fixups, full nonbranch translation coverage and complete solver queries support the local claims. Memory guidance supplies no semantic premise.

QG7: Pass for the finite high/medium/low continuation list. No broader completion is claimed.


## Typed reader dispatch refinement

[Exact tag forests and payload caller interfaces](daemon_reader_typed_dispatch_report.md): all five recognize precisely reader tagsc31c/d0ee/1742 (wire8485/9777/50db). Five u32 routes require4 B and stage distinct word-return selectors; N19 also requires8 B on its recognized64 route and stages a span payload pointer. Four alternate routes store an encoded end; N20/N22 stage74c29cd6,while N21/N23 then reach74c29d88 rejection effects. Fifty-four blocks/1000 instructions plus386 preparation instructions,50 pointer records/63 slot matches,1331 translated PCs,46 UNSAT queries,one SAT path counterexample and six changed-ledger controls pass. Complete accessor output,native cache/owner/admission/PAC and daemon-kext pairing remain unknown.
