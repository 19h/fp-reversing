# Reader preparation: exact memory footprint and compact affine cache semantics

Under the selected cursor-zero u32-reader entry, the386-instruction preparation0x1006f6bf0 has a compact recovered effect:50 fixed frame stores reduce to four constants,two SIZE-derived affine values and44 affine values derived individually from25 prior context inputs. Every relation is universally checked against the original instruction translation. This recovers the complete cache-value map for that entry; semantic names for the remaining context inputs and the native working-frame owner remain unknown. [CF1-CF7]

The stage reads28 frame-relative cells/188 B and one original dispatch-table cell/8 B, and writes50 nonoverlapping frame cells/376 B. No frame read overlaps a frame write within the preparation. Six critical cache values and24 terminal registers are independent of the25 other input loads. The wider cache is not independent: all25 abstract input values are recoverable from chosen cache cells. Independence of one projection must not be generalized to all memory effects or later consumers. [CF2-CF5]

Evidence: [source,read/write ledgers,affine candidates and metadata boundaries](triage_evidence/daemon_reader_context_footprint_source.json), [56-query certificate and explicit negative control](triage_evidence/daemon_reader_context_footprint_checks.json), [extractor](triage_evidence/recover_daemon_reader_context_footprint.py), [validator](triage_evidence/validate_daemon_reader_context_footprint.py), [preservation](triage_evidence/daemon_reader_context_footprint_delivery.json), [scoped gates](triage_evidence/daemon_reader_context_footprint_quality_gates.json). Prior contracts: [existing-record reader](daemon_existing_scalar_reader_report.md), [entry and selected population](daemon_scalar_field_population_report.md), [word-reader mask](daemon_constructor_lookup_report.md), [adapter and shared-core boundary](daemon_xpc_core_bridge_report.md).

Addresses/constants are hexadecimal; extents use B. K is the preparation's working SP, C=0x797188010b5fa78c its selected encoded cursor zero, SIZE the prior node extent zero-extended from u32, TABLE the source dispatch root, and FN the selected stored pointer. Input labels N0..N24 are analytical cut names, not original parameters. All additions/subtractions are modular at the target cell's u32/u64 width. A physically loaded u64 SIZE field is supplied by the earlier zero-extension store; this does not generalize to unrelated callers.

| Evidence | Verified scope |
| --- | --- |
| Original thin | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| New captured source | Preparation386 instructions plus six-instruction metadata-entry prefix;392 instructions/1568 B |
| Preparation translation |385 distinct nonbranch instructions,335 SSA definitions per run;770 instruction instances for two copies |
| Decoder-input census |484 original instructions/1936 B recaptured;22 GPRs read before definition |
| Footprints |28 frame loads/188 B,one8 B table load;44 u64 stores plus six u32 stores/376 B |
| Universal certificate |56 UNSAT queries:50 affine cells,25-input inverse composition,read/store addresses,frame-byte disjointness,selected projection and prefix delta |
| Negative evidence | One SAT witness rejects whole-cache independence;five altered ledgers rejected |
| Retained execution | Zero found-reader entries, inherited from the pinned prior corpus; no new target/model run |

## All preparation inputs and fixed read addresses

Twenty-two frame loads read8 B each; six read2 B each. The first three shared frame inputs are the cursor, SIZE and TABLE root. The other25 frame inputs remain opaque prior values. The dispatch slot is TABLE+0x461f8=0x1010800e8 in the source image; its original IA0xd6ff fixup targets0x100800004. The branch retains FN as a pointer rather than claiming that native authentication succeeded.

The address theorem covers every load for arbitrary nuisance values and arbitrary initial unrelated GPRs under the selected phase. No loaded context value is then used as an additional dereference base in this preparation; all load addresses reduce to K+fixed_offset or the selected TABLE slot. This does not prove those native addresses mapped/readable. [CF1-CF4]

| Source site | Owner / offset | Width | Role |
| --- | --- | --- | --- |
|0x1006f6bfc |K+0xa640 |8 B |cursor_zero |
|0x1006f6c38 |K+0xa638 |8 B |node_extent_u32 |
|0x1006f6c98 |K+0xa610 |8 B |N0 |
|0x1006f6cbc |K+0x9ea8 |8 B |N1 |
|0x1006f6cf0 |K+0x9ea0 |8 B |N2 |
|0x1006f6d50 |K+0x9e98 |8 B |N3 |
|0x1006f6dc4 |K+0x9e88 |8 B |N4 |
|0x1006f6e20 |K+0x9e78 |8 B |N5 |
|0x1006f6e7c |K+0xae40 |8 B |N6 |
|0x1006f6e98 |K+0xae30 |8 B |N7 |
|0x1006f6eb4 |K+0xae20 |8 B |N8 |
|0x1006f6ed0 |K+0xae10 |8 B |N9 |
|0x1006f6eec |K+0xada0 |8 B |N10 |
|0x1006f6f20 |K+0x9eb8 |8 B |N11 |
|0x1006f6f54 |K+0x9e58 |8 B |N12 |
|0x1006f6f70 |K+0x9e38 |8 B |N13 |
|0x1006f6fac |K+0x9e90 |8 B |N14 |
|0x1006f6ffc |K+0x9e80 |8 B |N15 |
|0x1006f704c |K+0x9e70 |8 B |N16 |
|0x1006f7064 |K+0xad90 |8 B |N17 |
|0x1006f7088 |K+0x9d8 |8 B |dispatch_table_root |
|0x1006f708c |TABLE+0x461f8 |8 B |selected_dispatch_pointer |
|0x1006f7094 |K+0x959e |2 B |N18 |
|0x1006f709c |K+0x958a |2 B |N19 |
|0x1006f70a4 |K+0x8f7e |2 B |N20 |
|0x1006f70ac |K+0x8f6e |2 B |N21 |
|0x1006f70b4 |K+0x8f56 |2 B |N22 |
|0x1006f70bc |K+0x8f46 |2 B |N23 |
|0x1006f70d0 |K+0xa608 |8 B |N24 |

## Recovered cache equations

The table below is the compact semantics of every preparation store for this selected entry. F=K+offset. Each nonconstant relation has coefficient+1; the constant is added modulo the cell width. A16-bit input is zero-extended for its32-bit cache store. SIZE is zero-extended to64 bits. The source artifact retains every original expression, candidate-proposal query and source site; the validator proves each row for all raw abstract inputs. Two scalar SMT assignments proposed the candidates and are explicitly not the universal proof. [CF2-CF5]

| Frame offset | Width | Exact value |
| --- | --- | --- |
|+0x978 |8 B |0x797188010b5fa796 |
|+0x970 |8 B |0xd68943be |
|+0x958 |8 B |zero_extend64(SIZE) |
|+0x950 |8 B |zero_extend64(SIZE) +0xd68943b4 |
|+0x818 |8 B |0x661a590b302bafa0 |
|+0x810 |8 B |N0 +0x661a590b302bafa0 |
|+0x948 |8 B |N1 +0xa |
|+0x940 |8 B |N1 +0xaef20d8cf9367afb |
|+0x938 |8 B |N2 |
|+0x930 |8 B |N2 +0x99a8b155 |
|+0x808 |8 B |N1 +0x150c66978fb9793c |
|+0x928 |8 B |N3 +0xa83bde24c9b21e67 |
|+0x800 |8 B |N3 +0xe56372fd4e50e7f |
|+0x7f8 |8 B |N4 +0xec7b0374217183d3 |
|+0x7f0 |8 B |N5 +0x42f093c391145ff8 |
|+0x920 |8 B |N6 +0xeb1989bac796c815 |
|+0x918 |8 B |N7 +0x5f45041c0d1bf7fd |
|+0x910 |8 B |N8 +0x193322aa87c952c9 |
|+0x908 |8 B |N9 +0xe6a362d759bc4dd6 |
|+0x900 |8 B |N10 +0x17c88b3b499ba4e0 |
|+0x8f8 |8 B |0x661a590b302baf9c |
|+0x8f0 |8 B |N11 +0xdc2cf8995f41fe0 |
|+0x8e8 |8 B |N1 +0x150c66978fb97938 |
|+0x8e0 |8 B |N12 +0x3f842a0b43709657 |
|+0x8d8 |8 B |N13 +0x63059617dc96a679 |
|+0x8d0 |8 B |N3 +0xe56372fd4e50e7b |
|+0x8c8 |8 B |N3 +0xa |
|+0x8c0 |8 B |N14 |
|+0x8b8 |8 B |N14 +0x24f8bf7e |
|+0x8b0 |8 B |N4 +0x8660aa6926a585c4 |
|+0x8a8 |8 B |N4 +0xec7b0374217183cf |
|+0x8a0 |8 B |N4 +0xa |
|+0x898 |8 B |N15 |
|+0x890 |8 B |N15 +0x355fb187 |
|+0x888 |8 B |N5 +0xdcd63ab95fccacbd |
|+0x880 |8 B |N5 +0x42f093c391145ff4 |
|+0x850 |8 B |N5 +0xa |
|+0x848 |8 B |N16 |
|+0x840 |8 B |N16 +0xfee3fc5b |
|+0x838 |8 B |N17 +0x661a590b302baf9c |
|+0x830 |8 B |N0 +0x661a590b302baf9c |
|+0x980 |4 B |zero_extend32(N18) |
|+0x9b8 |4 B |zero_extend32(N19) |
|+0x9a0 |4 B |zero_extend32(N20) |
|+0x990 |4 B |zero_extend32(N21) |
|+0x998 |4 B |zero_extend32(N22) |
|+0x988 |4 B |zero_extend32(N23) |
|+0x7e8 |8 B |N0 |
|+0x828 |8 B |N0 +0xa |
|+0x820 |8 B |N24 |

The six critical fields are+978,+970,+958,+950,+818 and+8f8. These carry the previously proved cursor/extent terms and encoded length/payload offsets. The other44 stores each depend on one prior context input. Their algebra is now established; their broader application/field meanings remain unknown. Assigning all fields one immutable structure type would discard their distinct caller and read/write epochs.

A chosen cell for each N input recovers it by modular subtraction of its listed bias; for the six16-bit inputs the low16 result is retained. Thus the cache preserves19*64+6*16=1312 abstract input bits. This is a reversible data-flow statement, not an entropy, native reachability, observability or exposure claim. Actual producers can constrain these values jointly.

For example N0=[K+a610]/u64 gives cache+810=N0+0x661a590b302bafa0. Two abstract assignments differing only in N0=0 versus1 produce different+810 values. The SAT negative control therefore refutes whole-cache independence even though the selected critical values are unchanged. No target fixture or native call was executed for this witness.

## Projected interface and exact limits of independence

The word decoder's complete source register-use census identifies22 GPR values read before definition: X0,X1,X2,X4,X5,X6,X7,X8,X9,X11,X12,X14,X15,X16,X19,X20,X21,X23,X25,X26,X27 and X30. The preparation projection additionally checks its selected branch target X22 and modifier X17, totaling24 registers. These are internal block-interface values; the census is not a claim of22 C/API formal arguments. LR/X30 can be a data register in this continuation convention. [CF3-CF5]

Two separately translated preparations receive independent values for all25 nuisance loads, with the same selected cursor,SIZE,BUF,TABLE,FN and caller phase/selector. The proof compares all50 store addresses,the six critical store values and24 terminal registers. No compared value changes. Each copy translates all385 nonbranch source instructions once; the second copy is an intentional self-composition, not another native execution.

The remaining44 cache values and unselected terminal registers are excluded from that independence theorem. They have real source effects. The [existing-reader certificate](daemon_existing_scalar_reader_report.md) supplies the selected subsequent uses and saved-tag overwrite epochs; the present projection does not establish independence of arbitrary later consumers, aliasing owners, changed cursors, changed phases or a complete native call.

## Footprint bounds, disjointness and initialization obligations

The exact frame read footprint totals188 B, spread over28 nonoverlapping cells. Its bounding interval is K+[0x9d8,0xae48). The50 frame stores total376 B and lie in K+[0x7e8,0x9bc). Source-derived widths and offsets give:

```text
write envelope: [0x07e8,0x09bc)     376 actual written B
read envelope:  [0x09d8,0xae48)     188 actual read B
```

These envelopes are disjoint. An explicit byte-address theorem checks that adding the same u64 K cannot make a read byte coincide with a write byte over these bounded offsets. Native access validity still requires mapped owners and nonwrapping accesses; TABLE/frame separation is a separate premise.

Consequently none of the28 frame loads is initialized by an earlier store within this preparation. Their reaching values come from prior epochs. The selected cursor/SIZE stores have the earlier entry source contracts. TABLE remains a shared named root whose native reaching definition is a premise; the25 opaque producer/lifetime origins remain unknown. A bounding extent0xae48=44616 B is not proof of an allocated44616 B frame and does not mean every intervening byte is read. Native zero-initialization of any entire envelope is not inferred. [CF2-CF4]

## Why compiler containment does not establish the working frame

The original LC_FUNCTION_STARTS metadata places0x1006f6bf0 within the container beginning0x10065ffd8 and ending before0x100873194, an extent2175420 B. The captured six-instruction entry prefix reserves48 B via the pre-indexed register-pair store, then16 B via SUB SP:

```text
entry SP = S
SP after prefix = S -48 B -16 B = S -64 B
FP after prefix = S -16 B
```

The prefix-delta theorem proves only those source effects. It does not join that entry SP to K at the internal preparation. Later calls, stack-delta handling and internal branch entries remain separate obligations, as already bounded by the [adapter report](daemon_xpc_core_bridge_report.md). Neither the small prefix reservation nor the large metadata container proves a native frame size, stack overrun or a valid native access. The active control-flow/stack epoch must be established directly. [CF4,CF6]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| CF1 | Pinned original bytes/fixup/compiler-start metadata and decoder census refer to this thin build. | Rehash/recapture386+6 instructions and the484-instruction word decoder; check original selected pointer record and metadata membership. Reject cross-build labels. |
| CF2 | Selected cursor0,phase8c3f,SIZE/u32 zero-extension and stable input cells apply. Cache equations depend on this entry. | Source-linked universal proof of every store and address; recover other cursor/phase entries separately. Candidate zero/one assignments alone are insufficient. |
| CF3 | Frame,TABLE,BUF/output owners and source bytes have the required lifetime and separation. | Recover mapped owners and reaching stores; distinguish sparse footprint,bounding envelope and initialized bytes. Native access/PAC success remains unproved. |
| CF4 | Named loads represent normally completed source reads; prior producer constraints remain unknown. | Check all29 addresses,widths and frame read/write disjointness. Preserve25 independent abstract cuts without claiming native feasibility of every assignment. |
| CF5 | Independence applies only to the enumerated projection; the remaining cache values remain observable effects. | Two-run proof compares six fields/24 GPRs/all store addresses; retain SAT whole-cache counterexample and25-value inverse proof. Do not infer whole-call noninterference or entropy. |
| CF6 | Compiler metadata containment and entry-prefix SP arithmetic do not identify K's native owner. | Follow actual incoming continuations,calls and stack deltas; retain2175420 B container versus64 B prefix reservation as distinct facts. No native safety/fault conclusion follows. |
| CF7 | Earlier reader/native-pairing evidence boundaries remain in force. | Retain zero found-reader observations and require same-build native endpoint/owner/PAC evidence for stronger claims. Full goal completion remains unknown. |

Source extraction,dependency traversal and interval construction take O(bytes+instructions+dependency edges). The two-copy SSA translation is linear in385 instructions per copy. Candidate fitting uses two fixed-size SMT evaluations; universal solver work is additional,with15000 ms per certificate query. The dependency ledger is a syntactic overapproximation; universal affine/projection/inverse lemmas establish the stated semantic relations. No CPU/guest/API/IPC target runs in this workflow.

## Bounded continuation opportunities

| Impact | Next source target | Question resolved |
| --- | --- | --- |
| High | Prior writes and owner epochs for25 context inputs,plus TABLE/frame/BUF roots. | Actual native input admissibility and lifetime constraints. |
| High | Active working-SP production across adapter/core entries and stack-delta returns. | Concrete memory owner for the sparse footprint; compiler labels alone do not supply it. |
| High | Remaining builder/serializer consumers and same-build selector26/RPC502/700 endpoints. | Complete field-to-IPC representation and actual daemon-kext/deeper pairing. |
| Medium | Other consumers of the44 affine cache fields. | Their compact decoder-offset roles and whether prior values affect later control/data. |
| Low | Equivalent preparation entries with nonzero cursor/other phases. | Generality limits of the selected cache map. |

## Scoped quality gates

- QG1: Technical source/data-flow/interface facts require no normative conclusion.
- QG2: CF1-CF7 list dependencies and falsification probes.
- QG3: Full selected cache map,footprints,decoder-input projection and compiler-frame distinction are covered; native owners,producer epochs and broad interface completion remain unproved.
- QG4: u16/u32/u64 widths,modular affine relations,188/8/376 B footprints,44616 B bound,64 B prefix and1312 abstract bits are explicit and reproducible.
- QG5:56 accepted UNSAT queries,one SAT negative control and five altered-ledger controls retain projection/full-cache and metadata/active-frame distinctions. All385 preparation instructions are translated once per copy.
- QG6: Original bytes/fixups/metadata,full source translation,explicit candidate proposals and universal certificates provide primary provenance. No target/native execution,new emulation,native API/IPC,IDA access,IDB mutation or memory-store update occurred.
- QG7: Continuations remain bounded and impact-labeled; native pairing and full goal completion are unknown.


## Subsequent conditional working-SP join

The [later stack-epoch audit](daemon_reader_stack_epoch_report.md) establishes conditional K=F=core_entrySP-0x10dd0 for the selected subscription path through keyed-reader entry and builder finish,with a source-only SP-preserving found-reader extension. The sparse preparation footprint fits the68944 B source local area. This refines source frame placement without proving native mapping,initialization,normal callee/PAC returns or endpoint pairing;the compiler-container caution remains applicable.


## Context-input producer refinement

[Context-input producer candidates and six tag-to-word interfaces](daemon_context_input_producers_report.md): one locally SP-affine full-width store candidate for each of25 opaque preparation inputs; six stages share pointer-cell/key/selector staging into the common word reader. Thirty-four UNSAT queries, one SAT width-distinction witness and six changed-ledger controls pass. Same-active-frame reaching definitions, exhaustive aliases and native initialization remain unknown. Read-only IDA knowledge returned no matching producer facts and was not used semantically. No new Mach port emission or successful daemon-kext pairing is established.
