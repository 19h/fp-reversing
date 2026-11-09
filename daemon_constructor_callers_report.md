# Descriptor-array application, typed constructor callers and status returns

The source at `0x1008cadf0` applies selected records from a borrowed 40 B descriptor array to a collection. It saves the array/count/qualifier/collection-pointer-cell interface, examines records in increasing index order, filters by a 32-bit word at+0x24, dispatches three private kind codes, calls the shared constructor, and returns its raw status on the first normally returned non-success. Reaching the end produces raw success `0x8b3dc651`. These are conditional private source contracts, not a recovered public C/MIG signature. [CA1-CA8]

The u64-specific root at `0x1006b74e8` and additional generic root at `0x10097b9b0` are now identified by source-to-slot proofs. The u64 root reads a full 64-bit descriptor operand and fixes an8 B payload; the generic root reloads scalar/span values from separate frame cells and preserves incoming identifier/type/extent operands. Neither root occurs in the 12 retained successful private profiles.

The array's span guard is exactly `pointer!=0`. A provisional interpretation excluding0x845e was disproved by a symbolic counterexample: the final constant cancels that control phase. The corrected universal source query proves that a NULL span pointer selects record skip, independently of its extent; the subsequent nonnull pointer transform is the identity. This is a source admission/omission distinction, not evidence of a native failure or application meaning. [CA3-CA5]

Evidence: [original source, pointer/branch checks, census and frozen episodes](triage_evidence/daemon_constructor_callers_source.json), [29-query certificate and rejected interpretation](triage_evidence/daemon_constructor_callers_checks.json), [extractor](triage_evidence/recover_daemon_constructor_callers.py), [validator](triage_evidence/validate_daemon_constructor_callers.py), [preservation](triage_evidence/daemon_constructor_callers_delivery.json), [scoped gates](triage_evidence/daemon_constructor_callers_quality_gates.json). Adjacent contracts: [constructor input/allocation](daemon_constructor_inputs_report.md), [type/u64 writer](daemon_typed_scalar_report.md), [lookup/replacement](daemon_constructor_lookup_report.md), [candidate cleanup](daemon_constructor_failure_report.md), [bank origins](daemon_constructor_bank_origins_report.md). Reference files sufficed; no additional IDA access/mutation, target execution, new emulation, native API or IPC request occurred.

| Evidence | Exact scope |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Source capture | 32 fragments, 559 instructions, 2236 B |
| Accepted translation coverage | All 527 nonterminal instructions covered exactly once; 501 SSA definitions; 32 terminal BRAAs checked through source operands/pointer metadata |
| Static certificate | 29 UNSAT source/algebra queries; ten altered controls and one rejected semantic interpretation |
| Original pointers | 48 records independently decoded against original chained words and fresh fixup catalog |
| Branch compatibility | 32 selected source cases;50 slot/modifier matches; hardware authentication is not tested |
| Bounded census | Eight literal modifier/branch candidates; eight original pointer targets share modifier 0x2c67 |
| Frozen evidence | 12 successful private profiles;24 array episodes,48 record filters,24 selected constructor calls;36 other constructor calls |
| Unobserved roots | Zero u64-root and zero generic-root occurrences in this corpus |
| Prior recapture | 43 ranges,10720 B |

Addresses/offsets/constants are hexadecimal; extents use B. K denotes the shared frame; BASE the borrowed descriptor array; N/u32 its count; C the collection pointer; and CELL the address from which C is loaded. Integer operations wrap at their stated u32/u64 width unless the loop invariant proves absence of wrap. Physical owners, compatible phases, original table contents and normal call completion are separate premises.

```text
borrowed40 B descriptors + qualifier + collection-pointer cell
                              |
                              v
                  array entry / unsigned count gate
                              |
                              v
              record+0x24 equals qualifier?
                     /                  \
                   no                    yes
                   |                      |
                   |               private kind32
                   |            /        |        \
                   |          u32       u64       span
                   |            |        |      ptr==0 --> skip
                   |            +--------+--------+
                   |                     |
                   |              shared constructor
                   |                     |
                   |             exact success marker?
                   |              /             \
                   +----------> advance          no
                                  |               |
                           count not exhausted    |
                              /          \        |
                            next         complete-+
                                           |
                                 saved continuation / X6
```

## Array entry and borrowed descriptor view [CA1-CA4]

At `0x1008cadf0`, the compatible incoming W8 phase is0x6cf4. The exact inputs and saves are:

| Input | Source action / destination | Width |
| --- | --- | --- |
| X14=CELL | Loads C=[CELL], stores C at K+0x3fa0 | 8 B |
| X13 selector | Resolves original table entry, saves continuation at K+0x6d40 | 8 B pointer |
| W15 qualifier | Stores K+0x1cbc | 4 B |
| X11=BASE | Stores K+0x4af8 | 8 B |
| W9=N | Stores K+0x2c6c | 4 B |
| Initial index | W10=0; loop stores index at K+0x2bf4 | 4 B |

The CELL read occurs before the BASE guard, so CELL must be readable even if BASE is NULL. NULL BASE selects direct continuation relay with raw W6=0x74c29d88. Nonnull BASE enters the count gate; count zero completes without reading a descriptor and produces 0x8b3dc651. C itself may be NULL until a selected descriptor requires a constructor; the typed adapters then take their invalid-collection path. No public error names are assigned to these markers.

The filter at 0x100864934 zero-extends the u32 index and addresses BASE+40*index. Its word at descriptor+0x24 is compared exactly with the saved qualifier. Equality selects kind processing; inequality selects advancement without constructing that record. The descriptor pointer is independently recomputed at 0x1009c4088. Under valid readable ownership, the consumer view is:

| Descriptor offset | Width | Captured consumer meaning |
| --- | --- | --- |
| +0x00 | 8 B | Full u64 operand B for the u64 kind |
| +0x08 | 4 B | U32 operand V for the u32 kind |
| +0x0c | 4 B | Not read by the captured typed descriptor paths; meaning unknown |
| +0x10 | 8 B | Span source pointer S |
| +0x18 | 4 B | Constructor identifier operand HE |
| +0x1c | 4 B | Private kind code |
| +0x20 | 4 B | Encoded constructor extent E, consulted for span |
| +0x24 | 4 B | Exact qualifier word |
| Stride | 40 B | Selected array record extent |

This is an analytical consumer view, not a canonical Apple declaration. Only the qualifier is needed for a skipped record. A matched record needs its kind; scalar paths then read their value/identifier fields. The span path reads its pointer before its identifier/extent, so a NULL span pointer skips without consuming those later fields. No zero-filled unused/padding fields are assumed.

This 40 B view differs from both the earlier 32 B local reader argument and the 10 B external record header. They must not be merged solely because each eventually supplies constructor operands. [The reader report](daemon_xpc_records_report.md) records its different offsets/widths and evidence boundary.

## Kind membership and exact constructor operands [CA2-CA5]

The signed 32 decision tree admits exactly three private kind values across all 2^32 input patterns, after qualifier selection. Its adjacent threshold ranges supply the u64 leaf; exact equality gates supply u32/span leaves. Unknown matched kinds select completion with raw marker 0x74c29d8f.

| Private kind | Typed root | Constructor T/internal 16 | External wire tag | Payload extent / source |
| --- | --- | --- | --- | --- |
| 0x372c9ea2 | 0x100828290 | 0x86b4 | 0x9777 | Fixed4 B; V=[descriptor+8] |
| 0x372c9ea1 | 0x1006b74e8 | 0x9546 | 0x8485 | Fixed8 B; B=[descriptor+0] |
| 0x372c9ea0 | 0x10069d718 | 0x4118 | 0x50db | P=E XOR 0x8b3dc651; E=[descriptor+0x20], S=[descriptor+0x10] |

HE=[descriptor+0x18] in all three cases. Source T is an internal 16-bit discriminator; the external tag is T XOR 0x11c3 under the existing header codec. Scalar descriptor extent+0x20 is not used by these typed roots: they supply exact encoded 4/8 B extents themselves. This does not assert application-specific meanings for HE, V, B or the kind/qualifier values.

The u32 parameter stage0x1009d452c reads HE/V and collection C from K+0x3fa0. Adapter0x100752360 saves the outer continuation at K+0x3598, checks C, then reaches root 0x100828290. The span parameter stage0x1009312bc reads HE/S/E and C; its pointer arithmetic proves X20=S for every u64 input. Adapter0x100894dac saves its outer continuation at K+0x2a78 and checks C before root 0x10069d718.

The u64 collection gate0x100941ef4 supplies C and preserves the descriptor pointer. Root0x1006b74e8, under incoming W9=0x556c, reads full B/u64 at+0 and HE/u32 at+0x18, sets internal T=0x9546, E=0x8b3dc659, unused scalar 32 default0x8b3dc651 and span0, produces phase 0x6cf4 and selects common entry0x100700d80. Thus high 32 bits of B are preserved; this is not a low 32-only mapping.

All typed roots select original index 0x5eb2 ->0x100700d80 with IA modifier 0x2c67. Their constructor-return selectors are distinct: u32=0x222 ->0x100781e0c; span=0x1ee ->0x1006d8264; u64=0x22e ->0x100712d84, each IA 0x151e. The u32/span outer continuation cells are separate from constructor cell K+0x6ed0. Saved-frame continuity remains a premise across the shared constructor.

## Null-span omission and conditional read footprint [CA3-CA5]

At0x1009123b4, let S be the u64 word loaded from descriptor+0x10. The source arithmetic is:

```text
a    = 0xf9763f7e3ff5ff73
mask = 0xf2ec7efc7febfee6 = 2*a mod 2^64
b    = 0xf9763f7e3ff57b15 = a-0x845e mod 2^64
left = (S XOR a) + ((S << 1) AND mask) = S+a mod 2^64
right= b+0x845e = a mod 2^64
left != right  <=>  S != 0
```

The phase 0x845e is not a pointer sentinel. The rejected alternative `S!=0x845e` has a SAT counterexample in the checks ledger and is not accepted behavior. The valid source predicate is proved for every u64 S.

For S=0, the selected target is common advancement0x10084dce0: the descriptor is omitted without a constructor call. For S!=0, parameter setup0x1009312bc computes exactly X20=S, reads HE/E and calls the span constructor through its adapter. The pointer transform there uses the identity `(S XOR c)+2*(S AND c)-c=S mod 2^64`; no pointer encryption is assigned to this field.

This differs from the lower constructor's zero-payload rule. With a nonnull S and E=0x8b3dc651, the decoded payload P is zero and a zero-length span record can be constructed under the adjacent contracts. With S=0, this array layer omits the descriptor before reading E. The application meaning of omission versus an empty span remains unknown. A nonnull pointer alone does not establish readable P-byte ownership.

One branch-target load overwrites X12 before entering the span-kind stage. The callee initializes W12 before consuming it; the source query leaves unrelated incoming registers arbitrary and proves that no restoration of an old W12 phase is needed. This register epoch is not generalized to every indirect branch.

## Loop, status and continuation contract [CA1-CA6]

Under valid inputs and normal child-call completion, the analytical behavior is:

```text
C = *CELL                       # CELL must be readable
save continuation / C / BASE / N / qualifier
if BASE == 0:
    return raw 0x74c29d88 through saved continuation
index = 0
while index < N:                 # unsigned u32 comparison
    r = BASE + 40*index
    if r.qualifier == qualifier:
        if r.kind == 0x372c9ea2:
            status = construct_u32(C, r.HE, r.V)
        elif r.kind == 0x372c9ea1:
            status = construct_u64(C, r.HE, r.B)
        elif r.kind == 0x372c9ea0:
            if r.S != 0:
                status = construct_span(C, r.HE, r.E, r.S)
            else:
                advance
        else:
            return raw 0x74c29d8f through saved continuation
        if status.low 32 != 0x8b3dc651:
            return status through saved continuation
    advance:
    index = index+1
return raw 0x8b3dc651 through saved continuation
```

This pseudocode is a source interpretation, not runnable target code or a public declaration. Construction can itself require normal allocator returns, valid owners, compatible phases and frame continuity; the earlier cleanup report does not establish graceful handling of every invalid/null owner.

| Return/status stage | Source predicate | Successful continuation | Other status continuation |
| --- | --- | --- | --- |
| U32 outer 0x10072d2cc | W6==0x8b3dc651 | Index0x2c4e ->0x10084dce0 | Index0x2c7c ->0x100757d2c |
| Span outer 0x100882c94 | W6==0x8b3dc651 | Index0x2c4e ->0x10084dce0 | Index0x2c7c ->0x100757d2c |
| U64 constructor0x100712d84 | W6==0x8b3dc651 | Index0x7c6a ->0x10084dce0 | Index0x556c ->0x100757d2c |

Common advancement loads INDEX from K+0x2bf4 and N from K+0x2c6c, computes the modular u32 INDEX+1, and selects 0x10082e028. That count stage stores the current index, assigns raw success, and follows index 0x5524 ->0x100864934 exactly when N>index unsigned; otherwise it selects completion. The original 64-bit carry expression is proved equivalent to this unsigned comparison for all u32 indices/counts.

With initial index 0 and the source gate index<N, every visited index satisfies index<=N-1. Therefore index+1 does not wrap and is at most N. At most N descriptors are examined unless an earlier returned error completes the loop. These are symbolic bounds; no giant-count input or target fixture is executed. Physical BASE+40*N readable extent remains a separate owner premise.

Completion0x100757d2c reloads the saved outer continuation from K+0x6d40 and uses index 0x2f82 ->0x100692834. The relay branches through X13 with IA 0x7d32 and preserves full X6. This completion block is used for both normal end and errors; it is not a failure-only routine. NULL BASE uses the same final relay directly with the entry's raw invalid marker.

The array layer performs no whole-collection rollback in these captured fragments. Subject to the constructor ownership contracts, earlier successfully appended/replaced records remain committed when a later construction normally returns an error. Outer continuation cleanup and actual native lifetime effects remain unknown. The public meaning of the raw X6/W6 markers is not assigned.

## Additional generic caller [CA2-CA6]

Root0x10097b9b0 is a fourth source-proved route to the common constructor, separate from the three typed roots above. Under phase 0x6cf4 it preserves incoming HE, low 16 T and E while loading:

| Operand | Frame source | Width |
| --- | --- | --- |
| C | K+0x2ff8 | 8 B |
| V | K+0x1a74 | 4 B |
| B | K+0x7768 | 8 B |
| S | K+0x31f0 | 8 B |
| Constructor return | Index0x228 ->0x10084d5d0 | Pointer, IA 0x151e |

Its exact-success branch selects index 0x8784 ->0x1006d54e8, whose full workflow is outside this increment. Other statuses select index 0x1a25 ->0x1008f045c. That error frontier stores low 32 W6 at K+0x850c, copies C from K+0x2ff8 to K+0x1548, supplies X19=&[K+0x1548] and phase W24=0x6cf4, then selects original helper index 0x3ad1 ->0x1006e3d4c with IA 0x1310. The next helper's full effects and any public response remain unproved. No retained profile observes this generic root.

## Two observed array callers and profile accounting [CA6-CA8]

| Caller | Source arguments / continuation |
| --- | --- |
| 0x100703a30 | CELL=object+8; BASE and N are incoming operands; qualifier 2; continuation index 0x99 ->0x1009a9e00 |
| 0x1008f05f0 | CELL address loaded from K+0x3950; BASE from K+0x3430; N/u32 from K+0x8dd0; qualifier 1; continuation index 0x8b ->0x10088f390 |

The first caller's returned success selects 0x1008f05f0; its other-status frontier is0x10090a400. The second caller's returned success selects 0x1008d8b64; its other-status frontier is also0x10090a400. Their full downstream effects remain unproved here. Equality/aliasing of the two caller arrays or collection-pointer cells is not inferred from these interfaces.

Each of the 12 retained profiles contains two array episodes. The first examines two records and invokes two constructors; the second examines two records and invokes none. The latter records take qualifier-skip branches. Both episodes reach their recorded outer continuations. The same profile has three additional constructor calls outside these array episodes.

| Frozen call class | Through array | Outside array episodes | Total |
| --- | ---: | ---: | ---: |
| U32 typed root | 12 | 24 | 36 |
| Span typed root | 12 | 12 | 24 |
| U64 typed root | 0 | 0 | 0 |
| Generic root | 0 | 0 | 0 |
| Constructor entries | 24 | 36 | 60 |

The complete recorded corpus supplies 24 array episodes, 48 qualifier tests, 24 selected records/constructor calls and 24 qualifier skips. Its positive occurrences are historical private-model evidence with PAC authentication bypassed, not native invocation or peer identity. The u64/generic proofs are source-only. No new generator, CPU emulation, malformed input, allocator-failure fixture or native transaction was run.

## Bounded caller census and pointer authentication metadata [CA1, CA7]

The original aligned `__text` census finds eight literal `MOV X17,#0x2c67` instructions immediately followed by BRAA/BLRAA. Their modifier instruction addresses are:

| Modifier instruction | Following branch | Classification in this increment |
| --- | --- | --- |
| 0x10021f398 | 0x10021f39c | Body/phase not classified |
| 0x1005a9430 | 0x1005a9434 | Body/phase not classified |
| 0x1005be3c8 | 0x1005be3cc | Body/phase not classified |
| 0x10069d748 | 0x10069d74c | Span constructor root |
| 0x1006b752c | 0x1006b7530 | U64 constructor root |
| 0x1008282c8 | 0x1008282cc | U32 constructor root |
| 0x10097b9d8 | 0x10097b9dc | Additional generic constructor root |
| 0x100c41bf0 | 0x100c41bf4 | Body/phase not classified |

Eight original pointers share modifier `0x2c67`, targeting `0x10028b128`, `0x100700d80`, `0x1005211c4`, `0x10095aea4`, `0x1005ab918`, `0x100117038`, `0x100649f6c` and `0x1005408bc`. Modifier equality therefore does not identify a constructor target. The four classified roots also have source-proved table-slot selections. Computed modifiers, other branch forms, unexamined phases and caller completeness remain outside this literal census.

The certificate decodes 48 original chained-pointer records independently and checks 50 selected slot/modifier matches across 32 terminal branches. Matching original IA key/diversity/address-diversity metadata establishes static compatibility only. Neither hardware PAC acceptance nor the physical runtime table contents are established. The two relay return examples are the observed array callers, not the complete set of possible return destinations.

## Algorithmic bounds and owner conditions [CA3-CA5]

For N descriptors, the local walker performs O(N) control work and uses O(1) scalar bookkeeping space, excluding the child constructor and output collection. Let M <= N be the number of selected, non-omitted records reaching a constructor, K0 the initial number of collection nodes, and Pi the decoded payload extent of selected record i in B. Under the previously recovered linear lookup, normal-return and finite-list premises, cumulative lookup work is O(M*K0 + M^2); payload processing adds O(sum(Pi)). Exact allocator complexity is unknown. Additional output storage is bounded by successfully committed nodes and their buffers; existing-node replacement can retire old storage. These are source-level bounds, not measurements.

A sufficient borrowed-array condition is a readable 40*N B region, with arithmetic and address validity checked separately; this is stronger than the actual conditional read footprint. The walker always needs each visited qualifier, then a selected kind, and only then its type-specific fields. A NULL span skips identifier/extent reads. CELL itself requires an 8 B read even when BASE is NULL. A nonnull span can decode to zero payload extent and still enter the constructor. Borrowed array/span lifetime, collection/frame separation, physical mapping, initialization and normal child completion are premises. No target fault, malformed-input behavior or pointer-validity guarantee follows from the bit-vector identities.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Static stress test or falsification probe |
| --- | --- | --- |
| CA1 | Addresses and original pointers belong to thin image SHA-256 4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e. All source claims depend on this identity. | Rehash the original image; recapture fragment bytes and chained records; reject any mismatch or cross-build address substitution. |
| CA2 | The specified entry phases, original table selections and saved continuations are compatible. Private ABI composition depends on these premises. | Compare every selected slot with its original fixup and terminal modifier; trace a producer to each required phase/continuation without assuming register preservation across unknown bodies. |
| CA3 | CELL, the conditionally read descriptor fields, borrowed span bytes and collection/frame owners are valid for the relevant lifetimes and do not alias destructively. Memory effects depend on these premises. | Recover upstream allocations, stores and last uses; prove the actual read footprint lies within each owner and excludes destructive frame/list aliasing. No native owner proof is supplied here. |
| CA4 | The child constructor returns normally and satisfies the previously recovered list/commit contracts. Iteration after a child and partial-commit claims depend on this premise. | Join exact saved continuation/status and owner state across each child exit; inspect outer cleanup for rollback or collection retirement. Unknown exits cannot be treated as normal returns. |
| CA5 | W operations are u32, X operations are u64, kind partitions use the captured signed comparisons, and the count gate uses unsigned ordering. Algebra and loop bounds depend on these widths. | Run the universal bit-vector mismatch queries, including NULL-span cancellation, exact kind membership and nonwrapping in-range increment. Reject mutated constants, widths, offsets or predicates. |
| CA6 | Frozen private profiles retain the recorded event order and source identity. Occurrence counts depend on that corpus only. | Rehash profiles; partition each entry-to-relay episode; distinguish 24 array constructor calls from 36 calls elsewhere. Zero occurrences do not establish unreachability. |
| CA7 | The literal modifier census is bounded by its exact instruction pattern. No result assumes all callers have that pattern. | Inspect the four unclassified candidates, computed modifier forms and other branch mechanisms separately; retain the eight-target collision counterexample to modifier-only classification. |
| CA8 | Public error names, native peer identity, native successful IPC and FairPlayIOKit selector26/RPC502/700 pairing remain unknown. No recovered private status is assigned such meaning. | Require same-build producer/consumer and native endpoint provenance before linking these private routines to an external peer or public ABI. The retained failed IOServiceOpen trace does not supply that link. |

## Bounded continuation opportunities

| Impact | Further static investigation | Question resolved |
| --- | --- | --- |
| High | Trace descriptor/CELL/count producers into both array callers and the generic root. | Concrete object ownership, descriptor initialization, qualifier meaning and source of each encoded value. |
| High | Analyze outer continuations 0x10090a400 and 0x1008d8b64, and generic error successor 0x1006e3d4c. | Whether earlier commits survive, are rolled back, or are retired by a broader owner; full status propagation. |
| High | Establish same-frame reaching definitions from setup to constructor roots and authenticate original pool/table provenance. | Native phase/owner/table assumptions presently missing from the private source composition. |
| High | Correlate same-build native endpoint evidence for selector26/RPC502/700 with the kernel-side interface reports. | Actual daemon-to-kext transaction pairing and concrete Mach rights; this increment establishes neither. |
| Medium | Classify the four remaining literal modifier candidates and other branch forms. | Additional constructor callers or unrelated targets; bounded census completeness. |
| Medium | Compare descriptor production with the existing 32 B reader argument and 10 B wire header contracts. | Explicit field conversion and ownership transfer; equal-looking fields alone do not establish ABI identity. |
| Low | Add a field-oriented index of the 40 B view and conditional read sites. | Faster navigation without changing established semantics or claiming a public struct definition. |

## Scoped quality gates

- QG1: This increment reports technical source contracts; no normative conclusion is required.
- QG2: CA1-CA8 enumerate dependencies and falsification probes. Unknown native owners, phases and endpoint provenance remain explicit.
- QG3: The increment covers descriptor entry/layout, qualifier and kind control, typed/generic constructor operands, local status/continuation interfaces, loop progress, bounded caller census and frozen occurrence separation. The broader investigation remains active.
- QG4: Widths are u16/u32/u64 as specified, offsets and addresses are hexadecimal, extents are B, descriptor stride is 40 B, and modular arithmetic is distinguished from the nonwrapping loop invariant. Algorithms and their conditional time/space bounds are stated.
- QG5: All 527 nonterminal source instructions are translated exactly once. The corrected NULL-span predicate supersedes the rejected 0x845e-sentinel interpretation. Completion is shared by end/success and errors; array and non-array calls are counted separately.
- QG6: Original image bytes, independent original fixup decoding, fresh fixup catalog, 29 UNSAT source/algebra queries, ten rejected alterations and one SAT semantic-rejection query provide scoped provenance. The SAT query refutes an interpretation; it is not a target behavior proof.
- QG7: Continuation opportunities are bounded and impact-labeled above. No new target execution, emulation, native API/IPC operation or IDB mutation was performed; native pairing and full-goal completion remain unknown.
