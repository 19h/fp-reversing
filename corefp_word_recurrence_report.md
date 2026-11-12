# CoreFP common word recurrence and paired scan-entry state

All four post-product word bodies implement the same two-stage u64 recurrence. Under the shared word stream, hash seed, index and metadata interfaces below, their different head/tail splits preserve a common final hash seed and the incoming accumulator-bank XOR. This derives the paired scan-entry condition previously recorded as an unexplained observation. Native control production, arbitrary-length address traversal and buffer ownership remain unknown.

The [word-codec report](corefp_word_codec_report.md) supplies the preceding product contract: the first pass hashes raw words while storing their XOR encoding; the second pass recovers the identical raw-word product. This increment reduces the arithmetic after those products. Together they establish a conditional mathematical join across the earlier arithmetic passes; they do not establish arbitrary native admission or the complete transform algorithm.

The subsequent [word-input report](corefp_word_inputs_report.md) derives original producers for the common initial hash, recurrence parameters, fold metadata and coherent header indexes. A master entry W22=`0xf82c` composes the retained fixed controls through separate stack epochs. Upstream master/base production, native backing and admitted selector/target sets remain unknown; these conditional producer results refine WR3-WR5 without establishing universal native traversal.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_word_recurrence.py), [checks](triage_evidence/corefp_word_recurrence_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_word_recurrence.py), [audit](triage_evidence/corefp_word_recurrence_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_word_recurrence_publication.py) retain four source bodies, sixteen normalization cuts, 32 complete component frames/journals, six paired stream joins and 37 new obligations. Sixteen parent receipts and nineteen source dependencies are SHA-256 pinned. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. The three original supplied inputs are unchanged. Addresses are preferred-base-zero offsets; B denotes bytes.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| WR1 | The pinned image, receipts and dependencies identify the analyzed source. All source results depend on these bindings. | Compare every body/cut instruction, dependency hash and preserved input. |
| WR2 | Existing private caller/context/backing/PAC/sequential-CASAL fixtures apply. Retained whole-caller continuity depends on these interfaces. | Freshly reconstruct six initial CPU/RAM states and replay all 488136 visits/journals. Native ownership, authentication, concurrency and input admission remain unknown. |
| WR3 | Each body receives its declared metadata and two coherent biased indexes. The arbitrary-scalar recurrence depends on those interfaces. | Prove all sixteen cut-entry bindings and four complete body projections; check all 32 retained inputs and run original-byte metadata falsifiers. Universal production of metadata, indexes and branch targets remains separate. |
| WR4 | The paired word streams use the same ordered raw words, initial h and recurrence parameters; the preceding codec/epoch contract applies. Seed/bank equality depends on this common-stream premise. | Join all products to the sixteen raw-word epochs, verify every state/index transition and compare both complete stream oracles. Arbitrary native aliases, lengths and intervening mutation remain unknown. |
| WR5 | Only separately proved source identities may replace algebraic cuts. Composed body proofs depend on these exact substitutions. | Recheck every retained query, compare a separate full-frame integer interpreter and execute unchanged original bodies for 229888 finite cases. |
| WR6 | Each stream ends in a tail body, with at least one head and tail step; the final v carrier reaches its named initializer entry. The initializer-seed join depends on this lifetime/control premise. | Prove both tail carriers and compare all six joined initializer frames. Lengths below two complete u64 words and incomplete-word tails are outside this theorem. |

## Common recurrence [WR1,WR3,WR5]

Let all arithmetic below wrap at the stated width before reuse. Define u64 F with logical shifts:

```text
F(x):
    x = u64(x + (x >> 32))
    x = u64(x - (x >> 16))
    return u64(x + (x >> 8))

u = u64(raw_word * abdf5fe3f3ef5db9)
t = F(u64((h XOR u) + index))
v = F(u64((u64(t + a) XOR u) + index))

A = A XOR low32(t)     XOR low32(v)
B = B XOR low32(t + b) XOR low32(v + b)
C = C XOR low32(t + a) XOR low32(v + a)
h = u64(v + a)
```

The multiplier is hexadecimal; shift counts are decimal. A/B/C are u32 accumulator words. The recurrence parameters a and b are independent u64/u32 inputs to the source theorem. Every retained caller has a=`98c9b5333f174cc8`, b=`9f8ba664` and initial h=`5f3bad8804febfc3`, in hexadecimal. The body theorem accepts arbitrary u64 `q=h XOR u`, product u and index, arbitrary a/b and arbitrary accumulator words. Hash state does not depend on the accumulator bank within this recurrence; admitted control flow remains a separate interface.

| Body | Source interval | Instructions / B | q / product inputs | Bank input/output | Final h |
| --- | --- | --- | --- | --- | --- |
| First head | `[0x1b4934,0x1b4d50)` | 263 / 1052 | X19 / X28 | W6/W5/W1 | X19 |
| First tail | `[0x1b4f1c,0x1b51bc)` | 168 / 672 | X3 / X2 | W6/W5/W1 | X19 |
| Second head | `[0x1b57d0,0x1b5c20)` | 276 / 1104 | X12 / X3 | W15/W6/W14 | X12 |
| Second tail | `[0x1b5e1c,0x1b63dc)` | 368 / 1472 | X12 / X20 | W15/W6/W14 | X12 |

These are 1075 source instructions/4300 B, contained in the existing 59120 B caller/allocator/retirement inventory. The sixteen normalization cuts overlap these bodies and are not additional disjoint source coverage. Across six callers the selected bodies execute 8226 visits, eighteen reads/120 B, no writes and no PAC models. The second tail performs three reads: u32 at FP-`0xc8`, u64 at FP-`0x98`, then one u64 control-table value. Arbitrary typed read values are permitted by its hash/bank projection; source address/dispatch admission is not thereby proved. Surrounding BRAA operations retain their frozen whole-caller premises.

The first-tail X7 and second-tail X1 hold v, before the a bias. Their final h registers contain v+a. These carriers reach the first and second scan-initializer seed inputs respectively in all six retained callers. The full component frames also include counter/predicate side effects; only the stated data projection is unified by the source theorem.

## Normalization cuts and coherent indexes [WR3,WR5]

Eight obfuscated transforms simplify to `x + bias`. Eight high-word folds simplify to `(x+c) + ((x+c)>>32)`, wrapping the addition x+c before shifting. The following source SUB/ADD instructions supply the remaining two steps of F. Bitwise carry networks in the source are therefore arithmetic folds; no function name or algorithm family is inferred from their appearance.

| Body | First MBA bias | First fold bias | Second MBA bias | Second index delta | Second fold bias |
| --- | --- | --- | --- | --- | --- |
| First head | `4fc84954f2f0a315` | `ea1994a3111eca82` | `28f482aaf618e308` | `8ed880be33eec4f3` | `d6aee21e48c104c1` |
| First tail | `244e5ace68e5835c` | `9a786ae3dad6aace` | `53d4a500057eb2b8` | `74791a59a058dc36` | `eee6c51fe30eeb7d` |
| Second head | `bef2bc538f768e65` | `ea8707f943881e74` | `fb850901ecc42272` | `2997a9c8be84ff1e` | `868010333d95b2cc` |
| Second tail | `f0802bad09d38a3a` | `ba7f7c4151ad93ea` | `716024ac4b0a68b8` | `e0b734e758f5b6da` | `ab18f078f733789f` |

All literals are hexadecimal u64. First-stage index delta is zero. If `offset_j=MBA_bias_j+fold_bias_j+delta_j` modulo 2^64, the typed index contract is:

| Body | First biased index + offset | Second biased index + offset |
| --- | --- | --- |
| First head | `X26 + 39e1ddf8040f6d97` | `X20 + 8e7be58772c8acbc` |
| First tail | `X21 + bec6c5b243bc2e2a` | `X7 + b734847988e67a6b` |
| Second head | `X2 + a979c44cd2feacd9` | `X16 + ab9cc2fde8ded45c` |
| Second tail | `X2 + aaffa7ee5b811e24` | `X1 + fd304a0c9b339831` |

Both expressions in a row must equal the same arbitrary u64 index. In all retained streams they equal the ascending word index 0..N-1. The source theorem substitutes those typed register values; it does not prove the preceding encoded-counter, length or address-generation machinery.

The checks archive lists every cut's source extent, exact instructions, output register, bias and incoming metadata. For example, the first-head second fold requires X0/X7/X11/X13/X14/X16; the second-tail folds require X24 and X27 at their respective cuts. Sixteen separate entry-binding proofs establish that the composed body actually supplies each cut's required metadata. Capstone reports the `LSL` destination as an input in its register-access result; the cut-input census uses that instruction's explicit source operands. An independent scalar interpreter and original-byte runs check the resulting complete frames.

The 37 new obligations comprise sixteen source-cut identities, sixteen cut-entry binding checks, four complete recurrence projections and one bank-XOR composition identity. Ten entry-binding checks are vacuous because those cuts have no external metadata; six impose metadata equations. The algebraic substitutions preserve original source side effects on other registers; finite component runs execute every original instruction without substitutions.

## Paired stream and scan-entry join [WR2-WR6]

For a common raw-word stream, initial h, a and b, the recurrence produces the same t/v/h sequence independently of the incoming bank. Each step XORs the same three u32 update words into each bank. Induction therefore preserves any componentwise bank XOR. In particular, the [earlier field encoding](corefp_scan_entry_report.md) supplies `eb3e515b` to each paired word, so this difference survives all admitted word steps. Different head/tail split positions do not alter the recurrence when their typed interfaces hold.

| Retained extent | N words | First head/tail steps | Second head/tail steps | Derived common initializer seed |
| --- | --- | --- | --- | --- |
| 16 B, four profiles | 2 | 1 / 1 | 1 / 1 | `7651b2bf6eff9a8a` |
| 32 B, two profiles | 4 | 1 / 3 | 3 / 1 | `65e683634cf8c95c` |

The independent stream oracle starts from each original encoded/decoded field bank and the retained initial h. It joins every product to the earlier raw-word epoch, verifies both index registers, checks every q=`previous_h XOR product`, reproduces every full body output projection and reaches the exact frozen initializer-entry CPU/stack frames. It retains all t/v/h/bank steps. The final banks are the same twelve word vectors already reported in the scan-entry table; every paired final word still XORs to `eb3e515b`.

This replaces an unexplained retained equal-seed/bank observation with a source-derived conditional mechanism. The common-stream, metadata, index and lifetime contracts remain premises. The full arithmetic-pass flag remains false because universal address generation, branch-target selection, native backing and admission are not reduced here. Initial h equality outside the retained streams is likewise an explicit common-stream premise.

```text
common raw words + h0 + a/b + indexes
                  |
         common two-stage F recurrence
                  |
       equal t/v/h, common bank XOR updates
                  |
     preserved bank XOR + equal final v carriers
                  |
       paired scan-entry banks / u64 seeds
                  |
       common initializer and preparation scans
                  |
          downstream phase parameters
```

## Validation and continuation

The auditor does not import the new producer. It reconstructs six initial CPU frames and 3313664 B of initial RAM; checks 488136 original visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM; and checks original workspace/preparation oracles. A separate integer source interpreter compares all 32 full component CPU/stack frames and their read journals, including NZCV and control side effects.

Each original-byte component domain executes 2048 q-byte cases, 2048 product-byte cases, 3072 bank-byte cases and sixteen index controls: 7184 cases per domain, 229888 overall. The index controls include zero, small/boundary values, 2^31, 2^32-1, 2^32 and 2^64-1. These are component cuts; varied biased-index inputs need not describe an admitted native caller. Original source and stack bytes are preserved. Finite source visits are `7184*(263*6+168*10+276*10+368*6)=59095584`. Ordered complete ending-frame digests are retained.

Metadata falsifiers alter one bit in X11, X16, X10 or X24 for first-head, first-tail, second-head or second-tail domains respectively. The audit retains every attempted q value and exact actual/candidate state and requires a rejected common-recurrence candidate in each of 32 domains. The 38 attempted off-premise cases execute 10434 source visits, separately from the finite corpus. These demonstrate dependence on metadata; they do not establish a native failure or security property.

All 37 new and 1155 frozen obligations are independently UNSAT, totaling 1192 with a 30 s/query limit. Replay time/space is conservatively `O(C*(Bsrc+V*J+P*Fpage+R))` for C profiles, source bytes Bsrc, visits V, journal/state cost J, touched pages P, page/frame payload Fpage and other retained bytes R. Finite components take `O(7184*Kc)` time for Kc retained component visits with bounded private maps; SMT costs are separate. The compact stream recurrence takes O(N) time and O(1) working space for N words, excluding retained output evidence.

No new incoming/outgoing Mach port, right, descriptor, message emission or daemon/kext pairing is established. No native target/API/IPC or IDA operation occurs; original file evidence suffices. The full investigation remains active.

| Impact | Remaining investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Complete upstream master/base production and normal traversal after the conditional word-input joins. | Establish admitted lengths/splits, same-epoch backing and selector/target confinement. |
| High | Compose the full raw preparation and word path with downstream consumers. | Establish same-epoch backing, permitted lengths/splits and exact producer-to-consumer continuity. |
| High | Establish native selector/context/holder ownership and admission. | Require original initialization and coherent native entry/backing evidence. |
| Medium | Characterize partial words, zero/one-word inputs and non-retained split controls. | Establish source-specific behavior without extrapolating the nonempty head/tail theorem. |
| Low | Join local recurrence to daemon/kext transport. | Require actual serializers, consumers and endpoint/right epoch joins. |

- **QG1**: No normative premise is required.
- **QG2**: WR1-WR6 identify dependencies and falsification probes.
- **QG3**: Word recurrence, bank/hash flow, index/metadata contracts, typed control reads, carrier lifetimes and cross-level limits are covered.
- **QG4**: U32/u64 widths, wrapping before shifts, extents, exact finite counts and complexity are explicit.
- **QG5**: Mathematical stream equality is conditional on admission/metadata/index/lifetime interfaces; native behavior, partial words and short streams remain unknown.
- **QG6**: Original bytes, pinned receipts, retained queries, cut-binding proofs, fresh replay, independent scalar frames, unchanged-byte components and stream oracles provide reproducible provenance.
- **QG7**: Impact-ranked continuation retains original producers, raw inputs, native owners, length/split edges and transport.
