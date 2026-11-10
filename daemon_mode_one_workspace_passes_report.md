# Dual workspace passes and seeded 16-cell byte permutation

The LOCAL-present successor performs two read-only passes over the complete296-byte workspace. Each pass reads74 consecutive u32 words exactly once and uses a separately seeded four-word scalar recurrence. Their exit initializes16 byte values and performs15 swaps over distinct frame coordinates. Original-source bounds and coherent-array laws establish that the resulting values remain a permutation of0..15. The stage stores F+0xc80 into the former scratch-root slot,rebases X26/X20 to F+0x8b0 and continues to `0x100a4f144`. The decoded scalar algorithm,exact decoded permutation function,native output and daemon/kext pairing remain unknown. [WP1-WP8]

Evidence: [source and pointer records](triage_evidence/daemon_mode_one_workspace_passes_source.json.zst), [174 accepted proofs and ledgers](triage_evidence/daemon_mode_one_workspace_passes_checks.json.zst), [extractor](triage_evidence/recover_daemon_mode_one_workspace_passes.py), [validator](triage_evidence/validate_daemon_mode_one_workspace_passes.py), [preservation](triage_evidence/daemon_mode_one_workspace_passes_delivery.json), [quality gates](triage_evidence/daemon_mode_one_workspace_passes_quality_gates.json), [sealer](triage_evidence/seal_daemon_mode_one_workspace_passes.py), [publication audit](triage_evidence/verify_daemon_mode_one_workspace_passes_publication.py). Context: [checkpoint and LOCAL gate](daemon_mode_one_record_checkpoint_report.md), [word-grid root](daemon_mode_one_record_word_gather_report.md), [absorption cycle](daemon_mode_one_record_reentry_report.md), [private wrapper](daemon_mode_one_adapter_report.md), [foundational triage](foundational_triage_report.md).

| Evidence | Verified scope |
| --- | --- |
| Image | `fairplayd.arm64e`,SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Current source |Three complete BRAA-terminated fragments,731 instructions /2924 B;728 nonbranch sites translated |
| Incoming source |142 nonbranch sites from the previously captured LOCAL-present continuation |
| Prior recapture |Ten ranges /34804 B |
| Control provenance |Five original authenticated records /five source slot-modifier bindings |
| ISA checks |13 UMULL,one UDIV,one immediate TST and three corrected comparison GPR-write reports;no SP write |
| Accepted checks |174 UNSAT,including three refreshed predecessor queries;zero SAT/unknown results counted as proofs |
| Scalar passes |Two four-word recurrences;74 workspace reads per pass,148 reads /592 B total |
| Swap bounds |12 integer division theorems,11 actual BV remainder-shape proofs,three mask bounds and14 explicit bounded overapproximations |
| Byte stage |16 seed stores,15 swaps,29 byte reads /46 byte stores;133 exhaustive selected-address cases plus the final two-choice bound |
| Coherent memory |Two generic array laws and256 finite index transpositions |
| Integrity |Eight source/counter/swap/target/TST/UMULL/lineage/native-claim alterations rejected |

F is the private frame,W(j)=u32[F+0x768+4*j],0<=j<74. Offsets and extents are bytes;scalar arithmetic is modular u32/u64 unless an integer theorem is explicitly identified. Mappings must be coherent and nonwrapping,saved roots stable and frame objects disjoint from externally rooted objects. No target execution,emulation,API/IPC request,IDA access,IDB mutation or hardware PAC test occurred. The three entries are private continuations;compiler-function boundaries and public API identities are not established. [WP1-WP4]

## Two bounded workspace passes

The incoming gate at `0x100c57884` supplies W10=0x56d3,X13=0x39eba85c,X26=F+0xc80 and the first scalar seed. A fresh source proof checks these values,including the control word absent from the earlier report's abbreviated outgoing table. The prior original-wrapper sufficiency contract and word-view-root contract are refreshed. Native arrival and the saved request/cookie premises remain separate. [WP2-WP3]

| Component | First pass | Second pass |
| --- | --- | --- |
| Entry |`0x100d3ce60` |`0x100ab7b74` |
| Current index |X13=0x39eba85c+j |W11=j |
| Word read |`0x100d3ce90` |`0x100ab7b80` |
| Actual address |F+0x768+4*j |F+0x768+4*j |
| Recurrence state |W5,W6,W14,W16 |W8,W9,W12,W21 |
| Four initial words |a9502f98,a20cd51f,79705c69,71b2bb0c |a9502f98,a20cd51f,5bfaf402,5e281186 |
| Next index |j+1 |j+1 |
| Repeat |j<73,slot0x56d3 |j<73,slot0x406e |
| Exit after j=73 |slot0x7e25 -> second pass |slot0x404a -> byte stage |
| IA modifier |0xe138 |0x0c65 |

Each component is proved for unrestricted incoming four-word state and WORD,under0<=j<74. The first pass forms its read address through a64-bit biased coordinate;the source bias cancels to4*j. Its comparison is between incremented X13 and0x39eba8a6. The second pass's obfuscated increment simplifies to exactly one independently of WORD and the scalar state;its repeat predicate is unsigned next<74. [WP3,WP5]

The source components define two encoded recurrences:

```text
S = (a9502f98,a20cd51f,79705c69,71b2bb0c)
for j in 0..73:
    S = first_source_step(S,W(j),j)

T = (a9502f98,a20cd51f,5bfaf402,5e281186)
for j in 0..73:
    T = second_source_step(T,W(j),j)
```

The retained source models and four outgoing expressions specify each step exactly. Declared dependency upper bounds contain only the four incoming state words,WORD and j. Membership in a dependency set does not prove actual influence. A decoded compact algorithm or cryptographic identity is not assigned. The second seed is reset from source constants;it is not the four outgoing first-pass state words. [WP3,WP6]

Five first-pass output registers,W5,W6,W7,W16,W19,survive the second pass unchanged. Their exact relationship to a decoded four-word first-pass state is not yet established. The second pass overwrites the first pass's W14 state register. Consequently,the surviving five-register interface must be interpreted using its actual source expressions rather than assuming the earlier four-register layout remains intact. [WP3,WP6-WP7]

Both loops make no stores. The finite byte-interval ledger proves that each reads offsets0..295 exactly once through its74 word-read sites. Together they make148 workspace reads /592 B;this count excludes repeated TABLE and continuation-pointer reads. The unchanged workspace therefore supplies the same word sequence to both scalar passes under the stability premise. [WP3-WP5]

The first pass leaves fixed constants W0=0x404a,W1=0x9c46cba1,W2=0x0d92891d,W3=0x5385c82f,W4=0xa0c828c7,W20=0x06a7eeda and X15=F+0x768. The second preserves those constants and exits with W13=0x8721,W22=1,X26=F+0xc80. These values bind the byte-stage entry. [WP2-WP3,WP7]

## New byte domain and frame epochs

At `0x100b0c100`,the byte stage stores X26=F+0xc80 into u64[F+0x750]. At `0x100b0c108`,it reloads X26=u64[F+0x758]=F+0x8b0. F+0x750 formerly held T=F+0xd10;its old root interpretation ends at this store. The stored F+0xc80 pointer has no proved object extent or consumer in this increment. [WP2-WP4,WP7]

The16 identity stores initialize the distinct physical coordinates

```text
P(j) = F+0x8b0 + ((799*j) mod962), 0<=j<16
byte[P(j)] = j
```

Only these16 cells are initialized by this stage. The arithmetic modulus962 does not establish that a complete962-byte array is initialized. Their physical offsets from the new root are:

```text
0,799,636,473,310,147,946,783,620,457,294,131,930,767,604,441
```

The first store is zero at the loaded root;the following15 literal stores reach the other coordinates. The source checks both each address and its byte value. These cells lie in the former1120-byte word-grid view. That view's earlier word interpretation is partially overwritten;u64[F+0x758] itself remains the same root. The296-byte workspace ends at F+0x88f and is disjoint from every seeded cell. [WP3-WP4,WP7]

The complete334-instruction block makes one u64 root store and46 byte stores. Byte effects cover exactly the16 seeded cells;the root store covers another eight bytes. Total write effects are54 B over24 distinct frame bytes. There are29 byte reads plus three u64 reads,53 B of load effects. None of these source accesses dereferences LOCAL or consumes the saved LOCAL+bias word at F+0x358. The saved frame views at F+0x368/F+0x370,the request root,the old domain at F+0xd10 and the budget remain untouched. This local access census does not establish that upstream workspace contents are independent of all external context. [WP3-WP4,WP6-WP7]

## Fifteen source swaps and coherent-memory composition

After initialization,the source swaps cell i with a selected cell in i..15,for i=0..14. The first selection covers all16 possible logical cells under an exhaustive16-case address proof. The following ranges shrink to the final choice14 or15. For swap12,the source maps a two-bit value r to14 XOR r,which enumerates12..15 in a different order. This affects selection encoding while retaining the required suffix domain. [WP3,WP5]

Each pair stores the selected cell's prior byte to P(i) and the fixed cell's prior byte to the selected address. All reads precede both stores. The first swap uses the already proved zero seed as its fixed-cell prior value;the other14 swaps read both prior values. Literal and computed forms of the fixed address are checked,including the concealed read at `0x100b0c510`. [WP3-WP5]

The byte frontend deliberately models every byte load as an independent component input. It does not forward literal-frame reads from an incomplete map that ignores aliasing computed stores. Source value-flow proofs establish the swap interface;two separate array laws compose that interface with coherent16-cell memory:

```text
swap(A,i,j)[n] = A[index_transposition(i,j,n)]
swap(swap(A,i,j),i,j) = A
```

Both laws include i=j. The256 finite index transpositions enumerate every pair on the16-cell identity index set and preserve its distinct values. Induction over the15 source swaps therefore preserves the initialized permutation of0..15 for every admitted choice. These are generic array/index proofs,not native observations or an enumeration of all decoded workspace states. [WP3-WP6]

Uniformity,randomness,unpredictability and a decoded closed-form permutation function are not proved. The stage contains no call to an entropy source. Its scalar inputs derive from the earlier encoded workspace passes;the exact source expressions are retained. [WP1,WP6-WP8]

## Division facts and exhaustive bounds

A broad direct selected-address membership query timed out and is excluded. The accepted proof decomposes the actual source into11 remainder computations and three small-mask bounds. Each original expression,source numerator,quotient shape,replacement symbol and range is recorded. The replacements are independent bounded overapproximations:they preserve the address/permutation property while allowing more choices than the exact value recurrence. They do not constitute a decoded value-equivalence proof. [WP3,WP5-WP6]

For divisors3,5,6,7,9,10,11,12,13,14,15 and347,integer queries prove the recorded reciprocal quotient formula equals floor(N/d) for every0<=N<=2^32-1. The divide-by7 theorem includes its correction and nonwrapping intermediate bounds;divide-by14 includes the initial floor(N/2). The source's unsigned UMULL32x32 product fits u64,logical shifts correspond to unsigned floors,and modular u32 remainder subtraction equals N-d*floor(N/d). Eleven fresh BV shape queries bind the byte stage's actual expressions to these forms. The347 theorem is auxiliary;no347 overapproximation is inserted into either scalar recurrence. [WP3,WP5]

The instruction-width and immediate-TST semantics are documented in the primary [Arm armasm Reference Guide6.01,ARM DUI0802B,sections5.144,5.149,5.150 and5.154](https://documentation-service.arm.com/static/5f3fa899428f7a6b3328fd44). UMULL multiplies two32-bit unsigned operands into a64-bit destination;TST sets flags without retaining the AND result.

The three mask queries establish ranges0..15,0..7 and0..3. The resulting small domains permit133 exhaustive residue/address cases,followed by a separate two-choice final-address proof. Case coverage is complete for the stated bounded components;the proof does not sample native inputs. All accepted queries terminate with UNSAT. Solver timeouts and exploratory hypotheses are excluded from the174 accepted results. [WP3,WP5]

## Outgoing interface and external touch points

The terminal authenticated slot0x8721 selects `0x100a4f144`,IA modifier0xaf8b. The outgoing ABI is:

| Register/root | Source-proved value |
| --- | --- |
| X0 |799 |
| X1 |962 |
| X2 |545 |
| X3 |0x441fef |
| X4 |16 |
| X5 |0x2527 |
| X13 |0x8721 |
| X15 |0 |
| X16 |0x73acf |
| X20,X26 |F+0x8b0 |
| X30 |0x422b |
| u64[F+0x750] |F+0xc80 |
| u64[F+0x758] |F+0x8b0 |

These numeric words are private control/coordinate constants;they are not established Mach rights or decoded algorithm keys. The next continuation is recorded as the frontier,without claiming its complete memory or output semantics. [WP1-WP3,WP7-WP8]

All three complete fragments have one terminal BRAA and no internal branch,call or trap. They establish no new Mach send/receive,port allocation,right transfer or message-emission site. Actual LOCAL ownership,destination extents,external serialization and a matched daemon/kext ABI remain unresolved. [WP1,WP4,WP8]

## Assumption register and bounded continuation

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| WP1 |Pinned image/source/pointer metadata identify these continuations |Recapture2924 current/34804 prior bytes;five authenticated records/bindings and raw opcode checks;reject eight alterations |
| WP2 |Incoming gate,frame epoch and word root compose |Freshly translate142 entry sites;refresh three predecessor queries;check actual seed/control constants and saved-root access census |
| WP3 |ISA widths,SSA,component interfaces and byte effects are accurate |Translate728 sites;verify UMULL/UDIV/TST fields,two pass contracts,all seed/swap effects and array laws;byte reads remain explicit independent inputs |
| WP4 |Mappings are coherent/nonwrapping,roots stable,objects disjoint and no outside mutation occurs |Check16 distinct coordinates,read-before-write order,the sole root store and preserved regions;native owners/extents remain unknown |
| WP5 |Finite domains and integer/BV correspondence cover actual source expressions |Prove12 full-u32 reciprocal facts,11 BV shapes,three mask bounds,14 bounded cuts,133 cases and the final two-choice address;integer product/shift bounds are explicit |
| WP6 |Scalar/permutation semantics stay within proved scope |Retain four-word recurrences,dependency upper bounds and all source-cut expressions;do not infer influence,decoded identity,uniformity or exact decoded permutation function |
| WP7 |Register/root epochs remain distinct |Check separate scalar seeds,first-output write census,F750 replacement,F758 partial-grid reuse and complete outgoing ABI |
| WP8 |Next continuation,LOCAL/output consumers and cross-layer exposure remain incomplete |Analyze0x100a4f144;trace actual LOCAL+bias use,derived-view extents,serialization and matched external interfaces |

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| High |`0x100a4f144` and successors |Consumers of the seeded permutation,new F750 root and outgoing coordinate constants |
| High |LOCAL/output ownership and daemon/kext pairing |Actual use of F358/F368/F370,result consumers,extents,serialization and matched ABI |
| Medium |Decoded scalar recurrences |Independent compact four-word models and equivalence against the retained raw source |
| Medium |Exact permutation selection function |Compose both scalar passes with the exact remainder functions;the current overapproximations prove the invariant only |
| Medium |Later word-grid consumers |Prove their epochs respect the16 overwritten byte cells in the former word view |

For this fixed workspace,both passes and the15 swaps take bounded work and space:O(74+74+15)=O(1) per invocation. With a generalized n-word workspace and m-cell suffix-swap construction,the source structure uses O(n+m) work and O(m) byte state plus fixed scalar state. Source translation is linear in captured instructions/effects;finite proof construction is linear in enumerated cases. SMT runtime is solver-dependent,limited to15000 ms per query and20 s per process.

QG1:Claims concern factual source,private ABI,control/data flow,arithmetic and provenance.

QG2:WP1-WP8 identify premises,dependent results and falsification probes.

QG3:The increment covers both workspace loops,scalar-state boundaries,byte initialization/swaps,source bounds,alias-safe composition,root epochs,outgoing ABI and publication artifacts;the broader objective remains active.

QG4:74*4=296 B per pass;148*4=592 B workspace reads;16+15*2=46 byte stores;46+8=54 B write effects over16+8=24 distinct bytes. Modular widths and integer domains are explicit.

QG5:Separate state seeds,overwritten W14,F750 and partial word-grid epochs are distinguished;bounded cuts preserve the invariant without asserting decoded value equivalence.

QG6:Claims trace to the pinned image,original authenticated records,fresh source comparison,174 accepted proofs,finite ledgers and preserved predecessor evidence. Immediate TST semantics use the primary Arm reference recorded by the extractor;no native behavior is inferred.

QG7:Impact-ranked next steps cover the next continuation,LOCAL/output/cross-layer exposure,decoded scalar functions,exact selection function and later grid consumers. No unrelated target probing is included.


## Inverse map and encoded modulo16 addition follow-up

The former frontier constructs inverse(P),reinitializes the original forward cells as Q using retained second-pass state,and generates a256-entry nibble table implementing separately encoded addition modulo16. The selected ROM law has identity symbol12 and eight order16 generators. Generated-table associativity is not inferred from the ROM group law. See the [source-pinned encoded-addition report](daemon_mode_one_encoded_addition_report.md) for685 UNSAT/one abstract SAT,ROM/loader provenance and scoped assumptions.
