# Mode1 scratch initialization and state-dependent 16-byte permutation

Follow-up: [Inverse tables and encoded cyclic16 operation](daemon_mode_one_inverse_tables_report.md) establishes an inverse/reset pair,equal seeded shuffles and a256-entry table that encodes addition modulo16 under relabeling. All998 captured nonbranch sites are modeled;172 new plus45 replayed UNSAT,two algebraic bank certificates,15 selector equalities and finite group checks pass. The local budget/spills are preserved through the writer;next consumer0x100c18e20,whole return and native daemon-kext exchange remain unknown.

Publication provenance: [username-path scrub](username_path_scrub_report.md) separates archived metadata transformations from fresh post-redaction source certificates. The no-IDB-mutation statement below concerns live research databases;historical metadata redaction is documented separately.

The selected mode1 protected-core path builds a permutation of the sixteen byte values `0xd0` through `0xdf`. Routine `0x100d4fde0` initializes sixteen distinct cells in a 963 B frame region. Routine `0x100ca047c` performs fifteen forward, state-dependent transpositions among those cells. Every swap selects a position at or after its fixed position. This establishes the structure of an in-place forward Fisher-Yates permutation; uniformity, randomness, coverage of all permutations and the surrounding cryptographic algorithm remain unknown. [SC1-SC10]

The earlier [paired source-pass result](daemon_mode_one_source_passes_report.md) supplies the first bank in W0-W3. Initialization preserves all four words, including an obfuscated identity update of W3. The permutation consumes and subsequently changes the first bank. Its writes preserve the second-bank spills and the separate budget cell. The next original continuation is `0x100dd165c`; its semantics and the complete return path remain unknown. These routines contain no call, trap or Mach emission. [SC2-SC9]

Evidence: [source bytes, pointers and register roles](triage_evidence/daemon_mode_one_scatter_source.json), [source/solver/finite certificates](triage_evidence/daemon_mode_one_scatter_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_scatter.py), [validator](triage_evidence/validate_daemon_mode_one_scatter.py), [preservation](triage_evidence/daemon_mode_one_scatter_delivery.json), [quality gates](triage_evidence/daemon_mode_one_scatter_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_scatter_publication.py). Parent frame and request: [mode1 adapter](daemon_mode_one_adapter_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original artifact | `fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Source | Three ranges,451 instructions,1804 B;includes the previously recovered33-instruction handoff |
| New bodies |31-instruction initialization loop and387-instruction permutation block |
| Source translation |448 nonbranch sites,527 instruction instances,517 SSA definitions |
| Pointers |Three original authenticated-rebase records,four branch/modifier matches |
| Recapture |Six prior ranges,1676 B matched again to original bytes |
| SMT |66 UNSAT queries and one separate SAT nonempty abstract-domain check |
| Composition |14 bounded-selector abstractions,15 address certificates,145 finite address cases |
| Permutation |15 source-linked swaps,135 finite transposition cases and a universal coherent-memory array theorem |
| Integrity |Six altered source/metadata/native-claim controls rejected |
| Execution |No target execution,CPU emulation,API/IPC request,IDA query or IDB mutation |

Virtual addresses are unslid. Instruction/frame constants are hexadecimal unless explicitly decimal. F is the protected-core SP,called K by the certificates;F is the preceding adapter report's J. Scratch base T=F+0xd00. Integer byte positions use decimal j. State arithmetic is modulo2^32;address arithmetic is u64. A valid,nonwrapping private frame and coherent memory remain premises. Machine-specific paths are omitted;artifact identities use names and content hashes. [SC1,SC3-SC5]

## Initialization and control [SC2-SC6]

| Block | Original selector / IA diversity | Selected successor |
| --- | --- | --- |
| Handoff `0x100d5e37c` | `3d26` / `5ccd` |Initialization `0x100d4fde0` |
| Initialization repeat | `3d26` / `5ccd` |Same block |
| Initialization completion | `c7ec` / `5ccd` |Permutation `0x100ca047c` |
| Permutation exit | `8a66` / `4930` |`0x100dd165c` |

The handoff establishes X11=T,X8=TABLE,W13=0x8a66 and the initialization constants. W4 starts at15. The compare tests W4 before decrementing it,so rounds j=0..15 each write one byte;round15 selects completion. W5 starts at84784 and increases by757 each round. Its selected address is:

```
A(j) = (84784 + 757*j) mod 963
byte[T + A(j)] = 0xd4 XOR j                  # j=0..15
```

All16 numerators are at most96139. The instruction sequence `UMULL; LSR40; MSUB` computes the exact remainder modulo963;its multiplier is0x440dd2cf. The initialization's arithmetic on W3 is an identity for every u32 x:

```
((x + 0x2a813e61) & 0x557ec19e)
 - ((0x557ec19e - x) & 0xaa813e61) == x       # modulo2^32
```

| j | A(j), decimal | Frame offset | Initial byte |
| --- | --- | --- | --- |
|0|40|d28|d4|
|1|797|101d|d5|
|2|591|f4f|d6|
|3|385|e81|d7|
|4|179|db3|d0|
|5|936|10a8|d1|
|6|730|fda|d2|
|7|524|f0c|d3|
|8|318|e3e|dc|
|9|112|d70|dd|
|10|869|1065|de|
|11|663|f97|df|
|12|457|ec9|d8|
|13|251|dfb|d9|
|14|45|d2d|da|
|15|802|1022|db|

The function A has distinct values on this16-position domain. The963 B region is an address domain,not an assertion that963 bytes are initialized or that a963-element table exists. Only the sixteen named cells are read or written by the recovered permutation. [SC4-SC6]

## Fifteen source-linked transpositions [SC4-SC8]

For i=0..14,the block reads the old byte at T+A(i) and an old byte at T+A(k),then writes the two bytes exchanged. The selected k satisfies i<=k<=15. Both reads precede both writes. All30 byte stores and30 byte loads are included in the ledger;no additional memory writes occur in the387-instruction block.

| i | Fixed offset | Selected-position derivation | Read fixed / selected PCs | Write fixed / selected PCs |
| --- | --- | --- | --- | --- |
|0|d28|W1 &15|ca047c / ca04c8|ca04cc / ca04d0|
|1|101d|1+(W0 mod15)|ca04f0 / ca04f8|ca0500 / ca0504|
|2|f4f|2+(W2 mod14)|ca0528 / ca05b0|ca05b4 / ca05b8|
|3|e81|3+(W3 mod13)|ca05dc / ca05d8|ca05e0 / ca05f8|
|4|db3|4+(live W14 mod12)|ca0654 / ca06ac|ca06bc / ca06c0|
|5|10a8|5+(live W19 mod11)|ca0700 / ca06e0|ca0708 / ca070c|
|6|fda|6+(live W21 mod10)|ca0728 / ca0748|ca074c / ca0750|
|7|f0c|7+(live W7 mod9)|ca07a8 / ca078c|ca07e4 / ca0808|
|8|e3e|8+(live W7 &7)|ca0824 / ca0838|ca083c / ca0840|
|9|d70|9+(live W2 mod7)|ca0850 / ca0858|ca085c / ca0860|
|10|1065|10+(live W10 mod6)|ca08b0 / ca0880|ca08b8 / ca08d8|
|11|f97|11+(live W15 mod5)|ca08dc / ca08fc|ca0900 / ca0904|
|12|ec9|12+(live W12 &3)|ca092c / ca0924|ca094c / ca0980|
|13|dfb|13+(live W16 mod3)|ca0998 / ca0994|ca099c / ca09a0|
|14|d2d|14 if live W10 bit0=0,otherwise15|ca09a4 / ca09b8|ca09bc / ca09c0|

PCs in this table have common prefix0x100. W0-W3 in the first four rows refer to the incoming first state bank. Later `live` values are source-register values at the respective operation,not the incoming words. Their exact upstream SSA expressions are retained in the evidence. The modulo14 selector uses an initial unsigned right shift by1;the modulo7 selector uses a corrected reciprocal sequence. No label assigns these changing words to a known cipher schedule.

At row2,a masked expression involving an earlier address reduces to the constant offset2. At row4,an obfuscated divisor reduces to963,so its UDIV-based read and reciprocal-based write select the same cell. At row13,a byte-dependent masked expression reduces to13 for every byte. The finite address certificates and source swap query include these expressions rather than assuming their intended constants. [SC5-SC7]

The local interpretation is:

```
for j in 0..15:
    scratch[A(j)] = 0xd4 XOR j
for i in 0..14:
    k = source_selected_position(i)          # proved i <= k <= 15
    old_i = scratch[A(i)]
    old_k = scratch[A(k)]
    scratch[A(i)] = old_k
    scratch[A(k)] = old_i
```

The explicit old-byte reads are material: self-swaps require coherent reads of the same cell. A universal array-store theorem proves the two-write operation exchanges the old bytes and preserves every other address,including when the addresses are equal. The135 finite position cases establish that every admitted transposition preserves a16-label permutation. Induction from initialization therefore proves that the final named cells still contain each byte in0xd0..0xdf exactly once. It does not prove that every abstract selector tuple is reachable or that the output is uniformly distributed. [SC4-SC8]

## Proof boundaries, memory and private ABI [SC3-SC10]

The fourteen bounded selectors deliberately overapproximate their computed source values. Each remainder abstraction is justified by an independently translated original instruction slice,an exact integer division theorem and a remainder-range theorem. The full stream proves required live constants;address certificates prove the live numerator equals84784+757*(i+selector). All allowed small selector values are then checked against the actual reciprocal/shift. This avoids treating correlated state-dependent choices as independently reachable native states.

The multiplier0x440dd2cf with shift40 is exact for all u32 numerators. The shorter multiplier0x440dd3 with shift32 is proved only over0..100000;the selected address numerators84784..96139 lie within that domain. Extending the short reciprocal to every u32 would be unsupported. All UMULL products are exact unsigned32-by32 products in64 bits. Integer remainder lemmas justify the source modular arithmetic and its bounded results. No timeout/unknown solver result is counted as evidence.

There are46 dynamic byte writes:16 initialization writes and30 swap writes. All target the same sixteen cells. The final operation preserves all other947 bytes in the963 B scratch address domain under the frame/ownership premises. No assertion is made about their initial contents. The four second-bank u32 spills at F+720,F+728,F+730,F+748 and the8 B budget cell at F+1210 are disjoint from every possible byte write. The handoff's earlier bank stores precede this preservation interval. SP is unchanged throughout both new bodies;the first bank is preserved through initialization but used and changed by the permutation.

The continuation receives the same scratch base in X11 and the modified scratch bytes;the source reloads TABLE from F+740 and selects index8a66 with IA diversity4930. Other exit-register arithmetic is retained as SSA,but its downstream contract is unknown. The indirect branches are private control transfers. These451 instructions establish no new incoming/outgoing Mach port,right,name,message layout or emission site. Native source ownership,PAC,admission,whole-operation budget history and daemon-kext pairing remain unknown. [SC3-SC10]

For this selected path,initialization takes16 rounds and the permutation takes15 swaps;both use O(1) working storage and fixed time in the recovered control model. A generalized n-position version would use O(n) operations,but the source admits only the recovered16-position theorem here. Static source extraction is O(B+I),where B is bytes read and I is decoded instructions. Finite address verification takes O(145) cases and the position induction checks O(135*16) label operations;SMT complexity is solver-dependent and is bounded operationally by a15000 ms per-query timeout. These are analysis bounds,not measured native timing.

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| SC1 |Pinned original artifact and unslid addresses |Rehash artifact;recapture all451 instructions and three fixup records;reject byte/metadata disagreement |
| SC2 |Selected mode1 nonnull LEN32 parent path and original phase |Recheck parent entry predicates;different phase/source admission does not inherit this contract |
| SC3 |F denotes the same valid nonwrapping protected frame |Check stack allocation/probe and owner lifetime;frame relocation or invalid access falsifies physical-memory composition |
| SC4 |Ordinary coherent private memory during initialization/swaps |Check writer/concurrency lineage;intervening external writes invalidate the permutation induction |
| SC5 |SSA instruction widths and operand roles match original encodings |Recapture;check all448 modeled sites;two CMP/TST alias roles are corrected after raw Rd31/S-bit checks |
| SC6 |Integer/BV division bridge and bounded numerator domains |Replay exact quotient/shape queries;test short-reciprocal extension separately rather than extrapolating beyond100000 |
| SC7 |Fresh selectors are sound overapproximations of live source remainders |Inspect each source slice,live constants and range lemma;do not infer independent reachability or uniformity |
| SC8 |Two-read/two-write source blocks are composed in source order |Check all15 ledger entries,alias case,array theorem and complete store census;extra stores would invalidate induction |
| SC9 |No hidden effect is assigned to unexecuted branches/PAC |Original pointer metadata establishes targets;native authentication,exceptions and scheduling remain unknown |
| SC10 |Algorithm identity,downstream output and whole return remain unknown |Follow target0x100dd165c and later consumers;do not identify a cipher from a16-byte permutation alone |

## Bounded continuation opportunities

| Impact | Follow-up | Discriminating evidence |
| --- | --- | --- |
|High|Follow0x100dd165c and all consumers of the sixteen initialized cells|Distinguish a nibble substitution/permutation representation,intermediate schedule or later output;these meanings remain candidates |
|High|Recover use of second-bank spills and the complete budget/return path|Determine whether duplicate state banks are compared,combined or consumed independently;current region preserves them |
|Medium|Recover compact recurrence for later selector-producing state updates|Replace conservative independent selector abstractions with actual correlated state-to-permutation semantics;this is not required for the proved permutation invariant |
|Medium|Join scratch/result effects to request LOCAL and caller-visible result|Establish a private ABI role before assigning an external operation or daemon-kext exchange |
|Low|Classify comparison-role discrepancies beyond these two aliases|Current correction is bounded to original CMP/TST-to-zero encodings;no general Capstone defect claim is made |

## Quality gates

QG1: The report requires no normative judgment.

QG2: SC1-SC10 list assumptions,dependent results and falsification probes.

QG3: This increment covers initialization,all15 swaps,bounded selection,permutation invariance,memory preservation,control successors and absence of new Mach emissions. The full cross-layer objective remains active.

QG4: B,u32/u64 widths,modular versus integer arithmetic,963 B address domain,16 distinct cells and finite-analysis complexity are explicit.

QG5: Coherent self-swaps,changing register epochs,the restricted reciprocal,selector correlation and the second-bank preservation interval are distinguished. Later output and native effects remain unknown.

QG6: Three original ranges/451 instructions,448 modeled sites,three pointers/four edge matches,six prior recaptures,66 UNSAT queries,145 address cases,135 transpositions,a coherent-memory theorem and six integrity controls ground the claims. The one SAT result is only a domain check.

QG7: Impact-ranked follow-ups concern actual scratch consumers,duplicate-bank use,complete return and external ABI linkage. Structural Fisher-Yates classification does not establish a named FairPlay cryptographic primitive.
