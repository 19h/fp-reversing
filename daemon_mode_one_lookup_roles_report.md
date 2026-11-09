# Mode1 word-extension lookup families and encoded value contracts

All 69 byte-read sites in the selected word-extension loop at `0x100bdc3b0` resolve to five established arithmetic/conversion tables: 16 B, 8 U, 23 C, 14 D and 8 Q. Their addresses lie in an 800-cell union within the 963 B private scratch domain. Across the source-proved 48 iterations, these sites account for 3312 reads: 1152 conversion reads and 2160 arithmetic reads. The classification is conditional on the established entry/frame and preserved producer-table contracts. The compact word recurrence, complete algorithm identity, caller publication and native daemon/kext interaction remain unknown. [LR1-LR8]

Evidence: [source and producer recapture](triage_evidence/daemon_mode_one_lookup_roles_source.json), [753 queries and source-linked role/range ledgers](triage_evidence/daemon_mode_one_lookup_roles_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_lookup_roles.py), [validator](triage_evidence/validate_daemon_mode_one_lookup_roles.py), [typed algebra helper](triage_evidence/daemon_word_lookup_role_models.py), [preservation](triage_evidence/daemon_mode_one_lookup_roles_delivery.json), [quality gates](triage_evidence/daemon_mode_one_lookup_roles_quality_gates.json), [independent publication audit](triage_evidence/verify_daemon_mode_one_lookup_roles_publication.py). Predecessors: [all 69 scratch bounds](daemon_mode_one_lookup_bounds_report.md), [word-grid extension](daemon_mode_one_word_schedule_report.md), [digit-map/XOR producers](daemon_mode_one_digit_maps_report.md), [sum/carry producers](daemon_mode_one_carry_table_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original image | `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Word-loop source | Three recaptured ranges, 2026 instructions / 8104 B; all 2024 nonbranch sites covered by fresh predecessor translation replay |
| Producer lineage | Fresh digit-map source/translation and finite algebra comparison; original 944 B operation data recaptured |
| Replayed queries | 272 bounds queries: 268 UNSAT, 4 SAT; 39 producer queries: 36 UNSAT, 3 SAT |
| New local queries | 439 UNSAT and 3 SAT; total 743 UNSAT and 10 SAT |
| Range derivation | 528 records, including 378 independently checked nontrivial transfers |
| Role derivation | 46 interval classifications and 23 universal unary-function certificates |
| Additional source algebra | Ten bound source-expression events; 6347 canonicalizer rewrite applications retained |
| Source controls | Four source/data/target/native-claim alterations rejected |
| Execution | No target execution, emulation, IPC/API request, new IDA access, IDB mutation or hardware PAC check |

## Table coordinates and value domains

Let `T=F+0xd00` and `P(j)=T+((757*j) mod963)`. Logical intervals below describe coordinates before this physical scatter. They are not contiguous physical byte ranges. Let `R` be the unknown permutation of the sixteen natural digit labels established by the producer algebra, `E(j)=0xd4 XOR j`, and `H(j)=0xd4 XOR (j<<4)`. [LR2-LR4]

| Family | Logical interval | Established producer contract | Sites | Reads in 48 iterations |
| --- | --- | --- | ---: | ---: |
| B | 17..32, indexed as 17+j | `B[j]=E(R(j))` | 16 | 768 |
| U | 0..15 | `U[t]=E(R_inverse(t))` | 8 | 384 |
| C | 706..961 | `C[R(a)+16*R(b)]=E(R((a+b) mod16))` | 23 | 1104 |
| D | 182..437 | `D[R(a)+16*R(b)]=H(R(floor((a+b)/16)))` | 14 | 672 |
| Q | 440..695 | `Q[R(a)+16*R(b)]=E(R(a XOR b))` | 8 | 384 |

The actual producer offset arrays are compared to every interval's `757*j mod963` coordinates. The five regions contain `16+16+256+256+256=800` distinct physical cells. They exclude all 128 plane cells, whose logical intervals are 40..103 and 112..175, and the other 35 scratch cells. This proves a read-footprint subset; it does not establish that every cell in that union is reached. [LR3,LR6]

For B/U/C/Q returns, E lies in `0xd0..0xdf`, with known-zero mask `0x20` and known-one mask `0xd0`. D returns use H: the conservative interval is `0x04..0xf4`, with known-zero mask `0x0b` and known-one mask `0x04`; its low nibble is always 4. Separate universal encoding queries verify both domains for arbitrary digits 0..15. The D interval is an overapproximation: under the producer contract its natural carry input is only 0 or 1, subsequently mapped through unknown R. The proof does not treat a D return as an E byte. [LR3-LR5]

These contracts identify the operation performed by each selected table read. They do not yet identify the natural operands at every site or compose the complete word-output equations. Concrete R values, concrete native read values and a complete cryptographic primitive remain unknown.

## Source-order premise chain

The validator reconstructs the original typed source SSA and checks its 69 site/index/numerator bindings against the freshly replayed bounds ledger. It then visits reads B0 through B68 in source order. After proving a read belongs to one table family, it assigns that family's E or H codomain to that read's byte symbol. A later address proof may use this result. Every used byte-symbol dependency must have an index strictly smaller than the current read; otherwise validation fails. No future returned-byte assumption is admitted. [LR1-LR5]

The phase symbol named SIZE in the inherited source model is the saved map-B[0] byte shifted left by four. It is not the original request length or the word-loop counter. The source seed at `0x100d76e78` reads `P(17)`, and its established store sets F+0x6d8 to that byte shifted left four. A universal query therefore bounds the current phase to `0xd00..0xdf0`, with its low four bits zero. The parent loop preserves this phase cell. [LR2,LR4]

Unsigned intervals and known-bit masks propose local facts. For each of the 378 nontrivial transfers needed by the classification, a separate query declares fresh immediate operands, asserts only their already certified facts and asks whether the output claim can fail. All return UNSAT. The 528-record ledger also retains constants/full-width leaves and producer-codomain/phase premises. Retained table-preservation lineage is checked separately and explicitly remains a premise rather than a newly replayed full history proof. [LR2-LR5]

For 23 sites, interval propagation alone is too coarse. Their normalized logical coordinate has three XOR/add terms over a common u32 input. A bounded mathematical enumeration proposes a region; a universal bit-vector query under the independently derived input interval/masks then proves that the complete expression stays in that region. Enumeration is not an accepted substitute for that query. The other 46 sites follow from checked interval propagation. [LR4-LR5]

## Algebra behind the remaining hidden roles

Each original physical remainder is already proved to be `N mod963`. New logical normalization recognizes `N=757*G+C mod2^32` and constructs `J=G+C*0x91c1195d mod2^32`. The constant is the multiplicative inverse of 757 modulo 2^32. A universal ring query proves `N=757*J mod2^32`; the proved logical domains put J within 0..962, and a separate integer query excludes product wrap. Consequently the source address is exactly P(J). The canonicalizer's symbolic identities and closed constant folds are checked again for the expanded graph. [LR4-LR5]

Ten source-bound events resolve opaque stride/mask expressions: two OR-stride constants, six complementary masked-XOR sums, one byte-conditioned stride and one physical-offset cancellation. The helper retains their source nodes, transformed nodes, operands, local certificates and the source-to-transformed dependency ledger. Associative/commutative ADD/XOR laws, zero identities and XOR pair cancellation are separately checked at every used source width.

At `0x100bdd994`, the remaining coefficient is a function of a single byte V. After the unconditional mask identities, it is:

```
K(V) = 0x267b63c1
       - (((V+0xb6) AND0x36) XOR((0xffffff49-V) AND0xc2618436))
       + 0x9be6236a                         (all operations u32)
```

A universal query under `0<=V<=255` proves `K(V)=757`; a separate checked range record establishes that source V bound. The numerator becomes `757*(V+182)`, identifying this access as D. This argument does not rely on one observed byte value.

At `0x100bddbd8`, an earlier physical remainder R from `0x100bdd994` obscures another coordinate. Its already replayed bound gives `0<=R<=962`. The source pair reduces by the checked identity:

```
(R OR0x2c1) + (G - (R AND0x13e)) = G+0x2c1   (u32, R<=962)
```

The masks are disjoint and their union is 0x3ff. After this cancellation, the logical expression has the same variable component as the D access at `0x100bdd9a0`, offset by 524: `182..437 +524 =706..961`. The accepted certificate for the later site is its own universal unary-function proof; the shifted relation also explains its C classification. [LR4-LR5]

## Complete site census

The machine-readable ledger records the original index/remainder/numerator, simplified numerator, logical node/domain, role certificate, range record, prior-read premises and return codomain for each site.

| Family | Original LDRB sites |
| --- | --- |
| B | `0x100bdccf4`, `0x100bdcd00`, `0x100bdcd0c`, `0x100bdcd2c`, `0x100bdcd6c`, `0x100bdcd9c`, `0x100bdcdc8`, `0x100bdcdec`, `0x100bdce48`, `0x100bdce6c`, `0x100bdceec`, `0x100bdcf4c`, `0x100bdcf78`, `0x100bdcf88`, `0x100bdd000`, `0x100bdd02c` |
| U | `0x100bddf8c`, `0x100bddf94`, `0x100bddfa0`, `0x100bde038`, `0x100bde044`, `0x100bde0c0`, `0x100bde0c8`, `0x100bde148` |
| C | `0x100bdd0ec`, `0x100bdd25c`, `0x100bdd270`, `0x100bdd310`, `0x100bdd3d4`, `0x100bdd3e8`, `0x100bdd470`, `0x100bdd4f4`, `0x100bdd57c`, `0x100bdd590`, `0x100bdd6d4`, `0x100bdd6e8`, `0x100bdd71c`, `0x100bdd7a8`, `0x100bdd894`, `0x100bdd8a8`, `0x100bdda40`, `0x100bdda44`, `0x100bddbd8`, `0x100bddbe4`, `0x100bddbe8`, `0x100bddd98`, `0x100bdde04` |
| D | `0x100bdd18c`, `0x100bdd1a0`, `0x100bdd2e8`, `0x100bdd314`, `0x100bdd474`, `0x100bdd4b4`, `0x100bdd60c`, `0x100bdd648`, `0x100bdd788`, `0x100bdd7ac`, `0x100bdd994`, `0x100bdd9a0`, `0x100bddb10`, `0x100bddb28` |
| Q | `0x100bddd60`, `0x100bddd64`, `0x100bdddec`, `0x100bdddf0`, `0x100bdde08`, `0x100bdde0c`, `0x100bdde94`, `0x100bdded0` |

## Data-flow, control-flow and interface consequences

The selected loop's byte side is now a closed table-family footprint: `24*48=1152` forward/inverse conversions and `(23+14+8)*48=2160` sum/carry/XOR-table reads. The total is `(16+8+23+14+8)*48=3312`. All word-grid and literal frame stores remain below T under the parent theorem, so the loop leaves all 963 scratch bytes unwritten. The retained materialization, absorption and gather evidence preserves the 800 producer cells on the selected path to this loop. Native memory coherence, aliasing and outside writers remain separate premises. [LR2-LR3,LR6-LR7]

The parent control theorem remains 48 bodies with four output stores per body, completing four 64-word streams in a private 273-slot view. The exit selector remains 0xb8d9 with target `0x100c5917c`. This increment identifies the byte operators inside that producer; it does not establish an external buffer owner, return ABI or caller-visible serialization. [LR2,LR7-LR8]

There are no new calls, traps, Mach send/receive operations, port creations, right transfers or external callbacks in these source bodies. Incoming/outgoing Mach-port identities and message-emission locations gain no new evidence from this increment. The daemon/kext pairing and deeper architectural handoff remain unresolved at the native boundary. [LR7-LR8]

## Assumption register and controls

Two new SAT counterexample controls distinguish an incorrect B upper bound of 31 and the incorrect treatment of arbitrary H returns as E bytes. A third SAT query checks that the E/H abstract domains are nonempty. Together with the seven replayed SAT results, these are mathematical controls/domains, not observed native behavior. All accepted queries reject unknown, timeout, solver diagnostics and unexpected results.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| LR1 | Pinned image, source and SSA establish the local code model | Rehash original image, recapture all word-loop and producer bytes, replay and compare source translations; four alterations must fail |
| LR2 | Selected entry, phase epoch, private frame and producer-preservation chronology hold | Compare retained materialization/absorption/gather contracts; freshly replay the parent source proof; falsify by finding a selected-path overlapping write or different entry binding |
| LR3 | Producer B/U/C/D/Q compositions and offset arrays are the applicable table epoch | Fresh producer source/translation/finite comparison and 39 replayed queries; compare all five offset arrays and retained 800-cell preservation |
| LR4 | Typed parsing, canonicalization and arithmetic substitutions preserve expressions | Replay 6347 rewrite records, width-specific ADD/XOR laws, ten bound source events, ring inverse/no-wrap and phase/codomain certificates |
| LR5 | Every range/role premise is justified before use | Check 378 transfer queries and 23 unary queries; reject any future-byte dependency; distinguish D/H from other E returns |
| LR6 | Family bounds are conservative and do not imply endpoint/cell attainment | Recompute all 69 bindings, role/read totals and disjoint 800/128/35 partition; preserve unresolved concrete values and operand equations |
| LR7 | Nonwrapping mapped frame, valid lifetimes, coherence and noninterfering external writers | Obtain independent ownership/mapping/lifetime and outside-writer evidence; static offsets do not prove native access validity |
| LR8 | Whole recurrence, algorithm, publication and cross-layer pairing are unknown | Compose actual natural operands through output SSA; follow exit consumers and serialization provenance without inferring a native exchange |

## Bounded continuation and quality gates

| Impact | Next investigation | Evidence required |
| --- | --- | --- |
| High | Compose the four complete word-output equations | Recover natural digit operands for the 45 arithmetic reads and substitute the proved table contracts into actual store SSA |
| High | Follow `0x100c5917c` and the completed grid | Actual consumer read/copy/return chain, extents and owner bindings |
| High | Connect private output to daemon/kext ABI buffers | Source-linked serialization and matching interface contracts; native pairing remains a separate evidentiary requirement |
| Medium | Reduce the H codomain to its two actual carry labels | Preserve shared unknown-R consistency and prove which encoded carry feeds each downstream operation |

For S=69 sites, V typed nodes, E operand edges, C<=65537 finite candidate inputs per unary expression and L total expanded expression/query processing, a conservative frontend bound is O(S*V*(V+E)+L+S*C) time and O(S*(V+E)+L+S*C) storage. This accounts for repeated dependency-cone walks and domain updates rather than assuming every walk is memoized. SMT complexity is solver-dependent; each accepted query has a 15000 ms solver limit and 20 s process limit. Extents are bytes, labels/counts are dimensionless and all source arithmetic widths are explicit.

QG1: Factual source, table algebra, dependency and footprint statements require no normative premise.

QG2: LR1-LR8 identify dependent results and falsification probes.

QG3: All 69 lookup roles, encoded value domains, source-order premises, source sites and architectural/Mach scope are covered; the overall interface investigation remains active.

QG4: 743 UNSAT, 10 SAT, 378 checked transfers, 23 universal unary certificates, ten source algebra events and all read/region counts are reproducible.

QG5: Producer preservation retained from prior evidence is distinguished from fresh proof replays; conservative codomains and unknown concrete values/whole recurrence remain explicit.

QG6: Fresh source capture, predecessor comparison, proof replay, source-linked role/range ledgers and four rejected source alterations establish provenance for this increment.

QG7: Four impact-ranked followups retain unresolved output equations, publication and cross-layer interfaces.
