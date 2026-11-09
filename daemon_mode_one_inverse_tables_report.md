# Mode1 inverse tables and an encoded cyclic-group operation

Follow-up: [Encoded nibble-sum and carry tables](daemon_mode_one_carry_table_report.md) establishes that0x100c18e20 builds a second256-entry table,paired with the prior table to encode base16 sum and carry under one relabeling. All124 new nonbranch sites are translated;19 UNSAT certificates and256 paired identities pass. The544 meaningful scratch bytes are disjoint. Next routine0x100c9589c,caller output and native daemon-kext exchange remain unknown.

The selected mode1 protected-core path constructs an encoded Cayley table for the cyclic group of order16. Its logical operation is addition modulo16 under a source-derived relabeling. The result follows from source-linked inverse construction,two equivalent seeded shuffles,a fixed-data operation,and a256-entry table writer. It identifies these local routines without assigning a standard FairPlay cipher or a native protocol result. [IT1-IT10]

This replaces the partial checkpoint. All998 distinct nonbranch instruction sites in the captured ranges are translated. Validation passes172 new plus45 replayed UNSAT queries,two separate SAT domain checks,two refreshed algebraic bank certificates,15 selector equalities,30 source swap certificates,256 fixed-operation isomorphism pairs and4096 associativity triples. Full source inputs,code,data and fixup hashes are retained. [IT1-IT8]

Evidence: [source and data](triage_evidence/daemon_mode_one_inverse_tables_source.json), [proofs and semantic composition](triage_evidence/daemon_mode_one_inverse_tables_checks.json), [extractor](triage_evidence/recover_daemon_mode_one_inverse_tables.py), [validator](triage_evidence/validate_daemon_mode_one_inverse_tables.py), [paired shuffle and table models](triage_evidence/daemon_mode_one_shuffle_models.py), [preservation](triage_evidence/daemon_mode_one_inverse_tables_delivery.json), [quality gates](triage_evidence/daemon_mode_one_inverse_tables_quality_gates.json), [publication audit](triage_evidence/verify_daemon_mode_one_inverse_tables_publication.py). Parent evidence: [first permutation](daemon_mode_one_scatter_report.md), [equal source-word banks](daemon_mode_one_source_passes_report.md), [request and stack epochs](daemon_mode_one_adapter_report.md).

| Evidence | Verified scope |
| --- | --- |
| Artifact |fairplayd.arm64e,SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e |
| Source |10 ranges,1052 summed instructions/4208 B;1003 distinct sites,including an overlapping seed/first-shuffle capture |
| Translation |All998 distinct nonbranch sites;1209 modeled instances,1200 SSA definitions |
| Metadata/data |Nine pointers,nine branch/modifier matches;three data ranges/1456 B;256 bank inputs |
| Recapture |Nine prior ranges,3480 B;semantic fields of the two source passes independently matched to fresh original-byte extraction |
| Arithmetic |172 new and45 replayed UNSAT queries;two SAT domain checks are not native witnesses |
| Algebra |Two prior bank certificates refreshed;fixed operation classified by a16-label cycle,256 isomorphism pairs and4096 associativity triples |
| Integrity |Six altered-source/data/native-claim controls rejected |
| Execution |No target execution,CPU emulation,FairPlay request or live-IDB mutation;no IDA fact is used |

Addresses are unslid. Unprefixed frame offsets,selectors and modifiers are hexadecimal;iteration counts and array indices are decimal. F is protected-core SP,K in the certificates. T=F+0xd00. Word operations use u32 unless explicitly64-bit;bytes are unsigned. Extents use B. Names below are analytical,not recovered public Apple types. Machine-specific username paths are omitted. The earlier one-time history scrub is not repeated. [IT1-IT4]

## Compact local semantics

Let E(j)=0xd4 XOR j for0<=j<16. Apos(j)=(84784+757*j) mod963;Bpos(j)=(12869+757*j) mod963;Cpos(t)=(534442+757*t) mod963. The initial permutation occupies bytes T+Apos(j). The complete recovered flow is:

```
first shuffle:   A[j] = E(pi(j))
inverse:         B[pi(j)] = E(j)
reset:           A[j] = E(j)
second shuffle:  A[j] = E(pi(j))
for t = 0..255:
    x = t & 15; y = t >> 4
    u = pi_inverse(x); v = pi_inverse(y)
    C[t] = E(pi(Fixed(u,v)))
```

Here A[j],B[j],C[t] denote bytes at their respective physical scatter positions,not contiguous arrays. The repeated pi is proved from source selector comparisons and matching transpositions under equal four-word seeds. The prior two32-byte source passes establish that seed equality under their stable-source/frame premises. The permutation need not be uniform,and coverage of every possible permutation is not claimed. [IT2-IT7]

The fixed operation satisfies Fixed(L(a),L(b))=L((a+b) mod16),where the source-data label cycle is:

`L = [9, 3, a, f, 0, e, 7, 6, 1, 4, 8, d, b, 5, 2, c]`

This cycle starts at identity label9 and advances by generator label3. Every label occurs once. The identity and generator of the generated decoded operation are pi(9) and pi(3). Defining R=pi composed with L gives decoded_C(R(a),R(b))=R((a+b) mod16),so the generated operation is a relabeling of addition modulo16. This is an algebraic composition argument over the source-certified relations;it is not enumeration of16! permutations or evidence of native execution.

## Routine roles and control

| Source entry | Established role | Selected continuation |
| --- | --- | --- |
|0x100ca047c|First15-transposition shuffle;included again for direct comparison|8a66/IA4930 |
|0x100dd165c|Sixteen-round inverse of the first scattered permutation|8a66 repeat;8a68/IA4930 exits |
|0x100c97370|Sixteen-round reinitialization A[j]=E(j),preserving B|6d9c repeat;6dcb/IAd68d exits |
|0x100dbfc3c|Second15-transposition shuffle,using second-bank spills|8d87/IA06d7 |
|0x100c07254|256-round encoded binary-operation table builder|8d87 repeat;c7f3/IA06d7 exits |
|0x100c18e20|Next consumer|Unknown in this increment |

The inverse reads each A position once. Its selected byte E(k) produces Bpos(k),and the stored value is E(j). Bijectivity of the preceding permutation makes all sixteen destination writes distinct. B is disjoint from A,so inverse construction does not corrupt its input. The following reset restores the same initial E ordering in A while preserving B.

Both shuffles implement15 forward transpositions with stage i selecting a position in i..15. Both reads precede both writes,including self swaps. The second source uses different registers,UDIV for one remainder,additional masked arithmetic and byte-dependent expressions. Those expressions are retained in SSA. The15 source dividend/bit-selector comparisons establish equality without assuming equality of the current selectors;only prior selector equalities enter the induction. Word-division shapes and exact reciprocal/range lemmas justify the remainder abstractions. Coherent-memory transposition induction then gives the same pi for equal seeds. [IT3-IT7]

## Fixed data,environmental inputs and byte-table ABI

The original unauthenticated rebases at0x1010a2fb8 and0x1010a4000,combined with their source biases,select256 B banks at0x100e99a00 and0x100f4e390. For every byte z,their source codec z XOR Right[Left[z] XOR0x6d] equals0xd0. Thus two word-cell reads can change the intermediate codec value but cannot change the selected operation-table family under the immutable-bank premises.

The resulting pool slot is0x1010a8c28. Its original rebase plus source bias0xffffffff8e873ed9 selects0x100f715a0. That944 B image region has many byte values;only the256 source-selected positions define the decoded operation. For natural byte argument q=u+16*v,the position is (342023+527*(q XOR0x34)) mod944. These selected bytes are all in0x70..0x7f. The original decoder is:

```
decode(y) = y XOR (y >> 1) XOR (0xe8 OR (y >> 5)) XOR 0xac
```

Its selected outputs are nibbles. The source combines two inverse-table bytes into q XOR0x34,selects and decodes the fixed byte,looks up the second permutation at Apos(decode(y)),and stores that byte at Cpos(t). Source-proved live-register cuts replace only the constant bank result and the decoded nibble after their equalities are established. They are not assumptions of the desired final group result. [IT4-IT8]

| Frame cell / register | Local contract |
| --- | --- |
|F+720,F+748,F+728,F+730|u32 second-bank words,read in word1/word0/word2/word3 order by the second shuffle |
|F+580|u64 word-cell pointer saved from X2;the table loop reads its u32 pointee |
|F+438|u64 word-cell pointer saved from X24;the table loop reads its u32 pointee |
|F+578,F+570|Saved left/right byte-bank roots |
|F+738|Saved scratch base T |
|F+740|Saved private branch-table base |
|X21 in the writer|Scratch base T |
|X23 after the operation load|Fixed image-data base0x100f715a0 |
|F+1210|Separate8 B budget cell;not written by the new byte-table path |

The four source-root publication fragments and both bank rebases are included. Complete native ownership and global-cell writer synchronization are not established. The two u32 cell values are arbitrary in the table proof,so the constant family selection does not depend on their equality,particular initial values or a sampled counter state. Valid dereferences and immutable image banks remain required.

A,B and C contain16,16 and256 distinct byte positions respectively. All288 positions are pairwise disjoint within the963 B scratch address domain. The new path performs318 byte writes:16 inverse,16 reset,30 shuffle and256 result writes. It preserves the second-bank spills,word-pointer cells,saved branch/scratch roots and budget cell through0x100c07394. Earlier root-publication writes precede that preservation interval. No claim extends this invariant through the next consumer or whole return.

These captured ranges contain private authenticated branches and no call,trap or Mach emission. They establish no new incoming/outgoing port,name,right or message ABI. The result is a local stack table;its linkage to caller-visible output and a successful daemon/kext exchange remains unknown. Fixed branch selectors such as8d87 are not identified as Mach names.

For the selected path,the loops have fixed16/16/256 iteration counts and the two shuffles have15 swaps each. Working storage is fixed:the963 B address domain includes288 meaningful table cells in this proof. Source extraction and artifact hashing are linear in bytes read;the fixed algebra checks use256 pairs and4096 triples. SMT runtime is solver-dependent,with a15000 ms per-query limit;unknown/time-out results are not accepted as certificates.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| IT1 |Pinned artifact,unslid code/data and original fixups |Rehash and recapture all ranges and pointers;reject disagreement |
| IT2 |Selected mode1 nonnull LEN32 path |Recheck the parent admission and phases;other paths do not inherit this contract |
| IT3 |Same valid nonwrapping writable private frame,disjoint from immutable image data |Check stack/image mappings and owner lifetime;native validity is not established |
| IT4 |Stable32 source bytes across the paired mixers |Replayed queries and algebra certificates establish equal banks under this premise;intervening source writes invalidate it |
| IT5 |Ordinary coherent memory and no outside writes to A/B/C during construction |Check writer/concurrency lineage;self swaps require coherent reads |
| IT6 |Original byte banks,rebases and saved roots remain stable |Recheck512 bank bytes,944 fixed bytes,nine pointer records and source root publications |
| IT7 |SSA widths,comparison roles and live-register abstractions match the source |All998 nonbranch sites are covered;division shapes,range lemmas and source selector induction reject substitutions |
| IT8 |Source composition is lifted through proved bijections |Review inverse write uniqueness,the15 paired choices,finite Fixed/L identity and the R=pi composed with L derivation |
| IT9 |Private branch authentication and native cell access are not executed |Original targets/modifiers are static metadata;hardware PAC,exceptions and native mappings remain unknown |
| IT10 |Caller-visible output,complete budget/return and daemon/kext pairing remain unknown |Trace0x100c18e20 and later consumers;the local Cayley table alone does not identify a full cipher or external operation |

## Bounded continuation opportunities

| Impact | Follow-up | Discriminating evidence |
| --- | --- | --- |
|High|Trace0x100c18e20 and all C-table consumers|Determine which encoded arithmetic operations use the generated table and how they affect caller-visible data |
|High|Recover the complete budget and return path|Join local table construction to request result,LOCAL and the caller's adjusted continuation |
|Medium|Trace word-cell pointer producers and state updates|Connect F580/F438 to concrete persistent state and synchronization;their values do not alter this table-family selection |
|Medium|Classify later encoded operations jointly|Distinguish a larger arithmetic construction or cryptographic primitive from this isolated cyclic operation |
|Low|Refresh live IDA knowledge when the bridge is reachable|The checkpoint attempt found no authenticated worker;no stored IDA fact supplies a semantic premise here |

## Quality gates

QG1: No normative judgment is required.

QG2: IT1-IT10 list assumptions,dependent results and falsification probes.

QG3: Inverse,reset,both shuffles,fixed operation,full table writer,frame inputs and control successors are covered. The broader daemon/kext objective remains active.

QG4: u32/u64 arithmetic,byte domains,summed/distinct source extents,loop counts and finite/solver complexity are explicit.

QG5: Encoded bytes differ from logical labels;the944 B region differs from its256 selected positions;the seed-dependent pi is not a uniformity claim;native and whole-return limits remain explicit.

QG6: Original-byte/fixup recapture,all998 modeled sites,172 new plus45 replayed UNSAT queries,two prior bank certificates,15 selector equalities,30 swap certificates and finite algebra establish the local result. The two SAT checks are abstract domain checks. Old nested metadata hashes retain their prior epoch;semantic fields are separately refreshed.

QG7: Scope expansion is bounded by actual consumers,return/budget history,word-cell lineage and larger operation identification. No standard-cipher identity,native success,new Mach emission or full-goal completion is claimed.
