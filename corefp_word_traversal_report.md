# CoreFP word-loop predicates, splits and authenticated dispatch rows

Subsequent selector evidence: the [word-selector report](corefp_word_selectors_report.md) derives both complete four-read selector projections, the same decoded buffer base and the u64 divisor cache. Under the stated source, backing, control and epoch premises, Euclidean certificates establish 0 <= r1,r2 < N for nonzero 29-bit N; constant-word controls demonstrate different splits. This refines the external remainder premises below while retaining native admission, backing and hardware PAC limits.

Original source reduces the four word-loop decisions to unsigned cyclic interval membership. Under the selected operation and typed count/remainder, backing, table and normal-flow interfaces below, each word pass visits indexes `0..N-1` in order. Its head length is `H=max(1,r)` for selector remainder r; the tail contains `N-H` words. Both segments are nonempty for `2 <= N <= 0x1fffffff` and `0 <= r < N`. The retained head lengths are not universal constants.

This extends the [input-lineage report](corefp_input_lineage_report.md), [word-input report](corefp_word_inputs_report.md) and [common-recurrence report](corefp_word_recurrence_report.md). It supplies conditional control and target-row evidence for their common word stream. Native admission, allocation extent, hardware pointer authentication, concurrency and daemon/kext pairing remain unknown. The full transform algorithm remains unknown.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_word_traversal.py), [checks](triage_evidence/corefp_word_traversal_checks.json.zst), [independent auditor](triage_evidence/audit_corefp_word_traversal.py), [audit](triage_evidence/corefp_word_traversal_audit.json.zst) and [publication verifier](triage_evidence/verify_corefp_word_traversal_publication.py) retain nineteen primary source regions, ten preservation contracts, five additional division/remainder-context instructions, twelve logical target rows, 130 complete primary frames/journals and six caller joins. Twenty-two parent receipts and twenty-five source dependencies are SHA-256 pinned. CoreFP arm64e SHA-256 is `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses are preferred-base-zero offsets; B denotes bytes. All unlabeled arithmetic literals below are hexadecimal; u32/u64 denote modular widths.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| WT1 | Pinned original image, receipts and dependencies identify the analyzed source. All source claims depend on these bindings. | Compare exact primary/context/census instructions, fixup rows, dependency hashes and three preserved original inputs. |
| WT2 | Existing private caller/context/backing/PAC/sequential-CASAL fixtures apply. Retained whole-caller joins depend on these interfaces. | Independently reconstruct six initial CPU/RAM states and replay 488136 visits with all journals. Native ownership, authentication, concurrency and entry admission remain unknown. |
| WT3 | Count and selector interfaces carry `2 <= N <= 0x1fffffff` and `0 <= r1,r2 < N`; entry indexes and metadata obey the preceding word-input contract. Conditional nonempty ordered traversal depends on these domains. | Prove source count decoding and 29-bit bound encodings; retain exact UDIV/MSUB context; check both remainders in each caller. Execute two outside-domain arithmetic falsifiers. Whole selector generation and arbitrary native input admission remain separate. |
| WT4 | Execution remains on the stated normal-flow corridors with the selected operation-derived branch keys and no intervening mutation of preserved inputs. Predicate composition depends on this premise. | Check ten writer-free censuses, arbitrary cyclic predicates, counter successors, 32 header/dispatch joins and deliberately altered wrap flags. Unexpected native targets/exceptions do not inherit preservation. |
| WT5 | The table cache, backing reads and decoded target rows retain the declared values through their consumers. Target-set/loop-edge claims depend on these interfaces. | Bind original cache load/subtract/store, 32 same-epoch cache reads and twelve logical rows; independently compare 24 initial edges and 32 decisions. Hardware PAC acceptance and universal cache-row selection remain unknown. |
| WT6 | Declared word buffers are backed and the preceding codec/recurrence contracts apply without external mutation. Common-stream and paired-state composition depends on this premise. | Join source buffer/index controls to prior lineage and retained raw-word epochs; separately require native allocation extent, alias and ownership evidence. No new native backing fact follows from pointer arithmetic. |

## Count and selector interfaces [WT1,WT3]

The six-instruction source region `[0x1b45dc,0x1b45f4)` reads u32(SP+`0x3ec`), shifts it right by three, stores that encoded value at SP+`0x458`, and constructs W1:

```text
E = load_u32(SP+3ec) >> 3
store_u32(SP+458, E)
N = E XOR 08b1c7cb
```

N is always at most `0x1fffffff`. If the encoded length is `u32(n XOR 458e3e59)`, the source theorem gives `N=n>>3`. This interface counts complete 8 B words; treatment of partial bytes and lengths below two words is outside the nonempty split theorem.

| Selector | Original context | Typed output |
| --- | --- | --- |
| First | `0x1b46b4 UDIV X11,X10,X1`; `0x1b46b8 STUR X1,[FP-0xd0]`; `0x1b46bc MSUB W10,W11,W1,W10` | r1 in W10; u64 N cached at SP+`0x450` |
| Second | `0x1b559c UDIV X10,X8,X15`; `0x1b55a0 MSUB W14,W10,W15,W8` | r2 in W14 |

For the architectural unsigned quotient with nonzero divisor N, Euclidean division gives `0 <= r < N`. A separate universal query proves that the u32 MSUB projects the low 32 bits of the corresponding u64 subtraction. The complete dividend/table selector computation is not symbolically reduced in this increment. The typed divisor/quotient/remainder relationship remains explicit; retained full caller replay checks its actual N and r values. This distinction prevents treating the isolated projection identity as proof of the entire selector chain.

| Bound producer | Source interval | Proved output / domain |
| --- | --- | --- |
| First head | `[0x1b46c0,0x1b4738)` | W10=`u32(7390ff4b+r1)` for `r1 <= 0x1fffffff` |
| First tail | `[0x1b4d74,0x1b4de4)` | W9=`u32(722872e2+N)`, W10=`722872e2`, W11=`8568`, given incoming key `8569` and encoded SP+`0x458` |
| Second head encode | `[0x1b55a4,0x1b55f0)` | Encoded W17 from r2; preserved to the decoder |
| Second head decode | `[0x1b5620,0x1b567c)` | W7=`u32(3076d59e+r2)`, W11=`3076d59e` for `r2 <= 0x1fffffff` |
| Second tail | `[0x1b5c64,0x1b5cdc)` | W11=`u32(1b64d3f9+N)`, u32(SP+`0x450`)=`1b64d3f9`, given u64(SP+`0x410`)=`7c09` and encoded count |

The head bounds are not identities over arbitrary u32 remainders. Independent original-byte runs confirm both retained SAT witnesses:

| Bound | Outside-domain r | Actual upper | Rejected unrestricted candidate |
| --- | --- | --- | --- |
| First | `d5974002` | `c9283f4d` | `49283f4d` |
| Second | `5341d782` | `03b8ad20` | `83b8ad20` |

Both r values exceed the source count domain. These are arithmetic counterexamples with no dispatch or native fault execution.

## Four cyclic decisions and ordered traversal [WT3-WT6]

Define `inside(x,L,U) = (u32(x-L) <u u32(U-L))`. This handles wrapped and empty u32 intervals. The original header computes W17=`U <u L`; the dispatch combines two comparisons using this flag. Every dispatch increments its encoded counter by one. If decoded index `i=u32(counter-bias)`, all four configurations satisfy `u32(bias+step)=L+1`. For `i,bound <= 0x1fffffff`, the proved predicate reduces to `i+1 <u bound`.

| Body | Header / dispatch interval | Counter / bias | L / step | Table index |
| --- | --- | --- | --- | --- |
| First head | `[0x1b48a0,0x1b48a8)` / `[0x1b4d24,0x1b4d70)` | W9 / `37a981c3` | `7390ff4b` / `3be77d89` | `(NOT inside)*6c XOR f82c` |
| First tail | `[0x1b4e9c,0x1b4ea4)` / `[0x1b5190,0x1b51d0)` | W20 / `37a981c3` | `722872e2` / `3a7ef120` | `inside XOR 8568` |
| Second head | `[0x1b56d8,0x1b56e0)` / `[0x1b5be8,0x1b5c3c)` | W1 / `20390963` | `3076d59e` / `103dcc3c` | `inside*bd XOR d373` |
| Second tail | `[0x1b5d20,0x1b5d2c)` / `[0x1b636c,0x1b63e0)` | W16 / `20390963` | `1b64d3f9` / `fb2bca97` | `inside*e4 XOR b970` |

The head upper bound uses r; the tail upper bound uses N. Heads execute before testing their successor, so r=0 still produces one head word. For either pass:

```text
r in [0,N)             H=max(1,r)       1 <= H < N
    |
    v
head: i=0 ... H-1  --> tail: i=H ... N-1 --> scan initializer
       H words               N-H words
```

The successor predicate and fixed continue/exit rows give a bounded induction: the head exits at H and the tail exits at N; every index is used once by each pass. This is conditional on WT3-WT6, including the previously established index producers, actual row values, normal-flow preservation and backing. It does not establish that every native record reaches these loops or that other operations share the rows.

| Retained caller | N | r1 / r2 | H1 / H2 |
| --- | --- | --- | --- |
| separate_ramp16 | 2 | 1 / 1 | 1 / 1 |
| separate_zero16 | 2 | 1 / 1 | 1 / 1 |
| separate_flip16 | 2 | 1 / 1 | 1 / 1 |
| separate_ramp32 | 4 | 1 / 3 | 1 / 3 |
| separate_zero32 | 4 | 1 / 3 | 1 / 3 |
| separate_clobber | 2 | 1 / 1 | 1 / 1 |

The exact r values in this table are receipt-bound. The formulas do not assert that first heads always have one word or second tails always have one word. Different admissible remainders can select different splits while retaining the ordered common stream.

## Table cache, authenticated rows and stack epochs [WT4,WT5]

The five-instruction region `[0x1af8b0,0x1af8c4)` selects an image pointer row, loads it, subtracts four and stores the result at FP-`0x98` = SP+`0x488`. In each retained caller the origin row is `0x1d108e8`, whose decoded nonauthenticated target is `0x1c81944`; subtraction produces table T=`0x1c81940`. Each decision loads u64(SP+`0x488`), then u64(T+8*index). These are decoded chained-fixup/source contracts, not recovered live process addresses.

| Logical role | Index | Target | IA diversity / branch modifier |
| --- | --- | --- | --- |
| First initial | `c644` | `1b48a0` | `774e` |
| First continue | `f82c` | `1b48a0` | `2883` |
| First exit | `f840` | `1b4d74` | `2883` |
| First tail initial | `8569` | `1b4e9c` | `5e63` |
| First tail continue | `8569` | `1b4e9c` | `5e63` |
| First tail exit | `8568` | `1b51d4` | `5e63` |
| Second initial | `6eb3` | `1b56d8` | `b144` |
| Second continue | `d3ce` | `1b56d8` | `e8d0` |
| Second exit | `d373` | `1b5c40` | `e8d0` |
| Second tail initial | `7c09` | `1b5d20` | `6ff1` |
| Second tail continue | `b994` | `1b5d20` | `f3d5` |
| Second tail exit | `b970` | `1b63e4` | `f3d5` |

The twelve roles occupy eleven distinct physical rows, all format 12, authenticated, nonbinding, chain-membership verified, key IA and address-diversity zero. Initial branch PCs are `0x1b489c`, `0x1b4e98`, `0x1b56d4`, `0x1b5d1c`; loop branch PCs are `0x1b4d70`, `0x1b51d0`, `0x1b5c3c`, `0x1b63e0`. The auditor checks all 24 retained initial edges and 32 loop decisions against decoded rows and actual next visits. It checks 32 exact cache-store/read epochs with no intervening overlapping write. Universal selection of the cache-origin row remains a premise outside the retained callers.

SP+`0x450` changes role: first it caches u64 N; later the second-tail bound writes only its lower four bytes as L. SP+`0x458` first carries encoded N; the second-tail dispatch later reads its separately produced u32 branch key `b970`. Typed reads and their epochs must be distinguished; equal offsets do not imply equal logical fields.

The preservation census explicitly treats AArch64 CMP/TST/CCMP as NZCV-only writers. Capstone's register-access annotation can list a comparison operand as a GPR write; accepting that annotation would falsely reject a preserved counter. Both producer and auditor apply the same architectural correction, and the separate integer interpreter checks all complete register/NZCV results against original-byte execution. No preservation of NZCV across the body is assumed: the retained wrap flag is W17.

## Validation and remaining scope

Nineteen primary regions contain 245 instructions/980 B; 130 executions produce 1634 visits, 106 reads/728 B and 18 writes/96 B with no regional PAC model. Ten censuses contain 1411 unique instructions/5644 B. Their union with the primary regions is 1619 instructions/6476 B. Adding the five separate UDIV/MSUB-context instructions gives 1624 instructions/6496 B. Overlapping views are counted by union, not addition.

The independent auditor imports no new producer. It reconstructs six initial CPU frames and 3313664 B of RAM and checks 488136 source visits, 63394 reads, 40562 writes, 21086 PAC models, 30 API/sequential-CASAL models, 182 state points and 3313664 B of final RAM, together with the existing workspace/preparation oracles. A separate integer interpreter compares all 130 complete primary CPU/stack frames and read/write journals, including u32 zero extension and NZCV.

Original-byte private component runs contribute 92160 cyclic-branch cases/2039808 visits and 30720 bound/count cases/835584 visits: 122880 cases/2875392 visits total. Branch domains vary all four bytes of counter/lower/upper scalars (second-tail lower is fixed); bound/count domains vary the appropriate full-u32 or restricted 29-bit input. Each byte-domain case XORs its shifted byte with a fixed diagnostic word. These finite samples supplement universal proofs; they are not exhaustive scalar enumeration. Components stop before BRAA, supply only private table cells and preserve source bytes and declared unaffected stack bytes.

Thirty-two altered-wrap-flag controls and two outside-domain bound controls contribute 34 negative cases/800 visits. Both table alternatives remain privately backed; the controls compare scalar target selections without executing the selected branch. The 38 new and 1263 frozen obligations are independently UNSAT, totaling 1301; two separate outside-domain queries are SAT with original-byte-confirmed witnesses. The inherited word-body set includes ten previously documented vacuous entry-binding checks; the aggregate UNSAT count must not be interpreted as 1301 independent nonvacuous semantic discoveries. Queries have a 30 s limit.

Replay complexity is conservatively `O(C*(Bsrc+V*J+P*Fpage+R))` time/space for C profiles, source bytes Bsrc, visits V, journal/state cost J, touched pages P, frame/page payload Fpage and other retained bytes R. Component time is `O(K*L)` for K cases and source length L, with bounded private maps; solver complexity is separate. Reduced predicates and split arithmetic use constant space/time per word, and a complete conditional pass takes `O(N)` word steps.

No native target/API/IPC or IDA operation occurs; original files suffice. No new incoming/outgoing Mach port, right, descriptor or message-emission site is established. The local continue/exit edges refine control flow inside CoreFP; they do not establish daemon/kext transport or ownership.

| Impact | Remaining investigation | Completion / falsification condition |
| --- | --- | --- |
| High | Recover complete source selector/dividend production and divisor lifetimes. | Compose original loads/UDIV/MSUB with bound generation for admitted inputs, including exceptional count domains. |
| High | Prove cache-origin selection and target/backing preservation beyond retained callers. | Recover upstream table-base/index producers and same-epoch native image/owner constraints. |
| High | Join native entry-record admission and allocation extent to the two word passes. | Establish original producer, operation domain, complete length/backing and alias lifetimes. |
| Medium | Extend short and partial-word behavior. | Resolve N=0/1 and residual bytes without applying the nonempty split theorem. |
| Medium | Compose paired codec/recurrence traversal with subsequent scans and output. | Preserve raw-word epochs, tail carriers and exact scan initializer lifetimes. |
| Low | Join local control contracts to daemon/kext IPC. | Require actual serializers, endpoint identities, consumers and matched right/message epochs. |

- **QG1**: No normative premise is required.
- **QG2**: WT1-WT6 identify assumptions, dependent results and falsification probes.
- **QG3**: Count/remainder interfaces, domain bounds, four predicates, counter progression, target rows, stack lifetimes and cross-layer limits are covered.
- **QG4**: U32/u64 widths, unsigned comparisons, modular arithmetic, 8 B words, half-open source intervals, union coverage, counts and complexity are explicit.
- **QG5**: Remainder premises differ from full selector proof; do-while heads differ from constant splits; arithmetic falsifiers differ from native faults; decoded rows differ from hardware PAC acceptance.
- **QG6**: Exact original bytes/fixups, pinned receipts, independent full replay/scalar frames, original-byte finite controls and epoch joins provide reproducible provenance.
- **QG7**: Impact-ranked continuation retains selector production, cache selection, admission/backing, short domains, downstream composition and transport pairing.
