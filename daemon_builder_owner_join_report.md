# Builder object, descriptor/child joins and cleanup pointer correction

The selected source path constructs a 128 B builder with separately allocated 16 B collection containers at builder+0 and builder+8. It applies descriptors with qualifier2 through the +8 cell and qualifier1 through the +0 cell. Its caller writes two complete 40 B descriptors, both with qualifier2: a fixed u32 record and a span whose pointer is the original string pointer and whose decoded extent is low32(LEN+1). These are conditional private source contracts, not public Apple types or a native owner observation. [BO1-BO5]

One earlier prose composition was incorrect. At0x10097a0c4, X8 initially holds the heap builder H, but the block saves H at K+0x6520 and changes X8 to &K[0x6520]. The following cleanup therefore reads H through this frame-local cell. It drains the builder's +8 and +0 child cells, frees H, and clears the local cell. The old prose instead forwarded H itself as the cell address. The [retirement report](daemon_collection_retirement_report.md) is corrected; its historical source/check JSON remains unchanged. [BO6]

The new certificate asserts the actual register outputs across the join and supplies a frame byte-memory store/load proof. Two SAT interpretation-rejection queries refute the old preservation/clear interpretation. They produce no target input, fault or execution. Twenty-eight positive source/memory queries are UNSAT; two aggregate heap queries returned unknown at15000 ms and remain explicitly excluded, with their full text retained. Six compositional memory components support the accepted graph instead. [BO3,BO6]

Evidence: [source, original pointers/banks, census, frozen owners and erratum](triage_evidence/daemon_builder_owner_join_source.json), [accepted/excluded queries and alteration checks](triage_evidence/daemon_builder_owner_join_checks.json), [extractor](triage_evidence/recover_daemon_builder_owner_join.py), [validator](triage_evidence/validate_daemon_builder_owner_join.py), [preservation](triage_evidence/daemon_builder_owner_join_delivery.json), [scoped gates](triage_evidence/daemon_builder_owner_join_quality_gates.json). Adjacent contracts: [40 B consumer](daemon_constructor_callers_report.md), [collection retirement](daemon_collection_retirement_report.md), [constructor codec](daemon_constructor_inputs_report.md), [bank initializer origins](daemon_constructor_bank_origins_report.md). No new IDA access/mutation, CPU/target emulation, native API or IPC operation occurred.

| Evidence | Exact scope |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Source fragments | 17 fragments, 573 instructions, 2292 B |
| SSA coverage | All551 nonbranch/noncall instructions translated exactly once;501 definitions; shared formulas reused by join queries |
| Accepted certificate | 28 UNSAT queries, including six compositional memory components |
| Rejected interpretations | Two SAT source-expression counterexamples; ten altered ledgers rejected |
| Excluded queries | Two historical15000 ms aggregate byte-array queries returned unknown; neither contributes a behavior proof |
| Original metadata | 29 independently decoded pointer records;17 terminal branches/26 selected slot-modifier matches |
| Call selectors | Five sites;1280 exhaustive original byte-bank cases; original malloc/free/strnlen bindings |
| Bounded store census | Three literal STR-X/SP+3950 candidates;156 B of additional windows outside the17-fragment SSA coverage |
| Frozen evidence | 12 builder allocations,24 child allocations;16 child1 bank-root field instances from eight older setup profiles |
| Prior recapture | 63 ranges/4308 B |
| Native/error scope | No native graph observations and zero outer-cleanup entries in the retained successful corpus |

Addresses, offsets, selectors and constants are hexadecimal; extents use B. K is the shared frame, H the heap builder value, C0/C1 the child container pointers, BASE the descriptor array, STR its span pointer, LEN the bounded-length call result, OUT the separate caller result-cell address, and CONT a saved code pointer. u32/u64 arithmetic is modular unless a bound is proved. SCELL=&K[0x6520] is a frame address and is distinct in role from H. Names are analytical roles, not recovered public declarations.

## Selected caller and builder allocation [BO1-BO5]

At0x1007ccfd4, the selected masked phase is `(W13 AND0xe2e57ffb)==0xc7b`. The source derives W21=0xc7b, W22=0x6f21, count W24=2 and BASE=X10+X12. It initializes its local output at K+0x3ff8 to zero. An original bank selector reaches `_strnlen` with X0=STR and W1=0x400. The post-call source explicitly establishes X12=K+0x8000, supplies OUT=&K[0x3ff8], sets X19=0, loads the root allocator's right-bank pointer from K+0x5e0 and selects the builder entry at0x100766c18. Preserving X20..X26 across the import remains a normal-call premise; no caller-saved X12 preservation is assumed.

| Builder entry input/effect | Source contract |
| --- | --- |
| W21=0xc7b | Select CONT from original table; save/u64 at K+0x86d8 |
| X8=OUT | Save/u64 at K+0x7700 |
| X23=BASE | Save/u64 at K+0x3430 |
| W24=2; X12=K+0x8000 | Save count/u32 at K+0x8dd0 |
| Root call0x100766ca8 | Select original `_malloc`; request128 B |
| Normal result X0=H | Save/u64 at K+0x3950 before the null guard |
| H!=0 | Index0x6f21 ->0x100710f38; intervening optional preparation is outside this increment |
| H==0 | Index0x6f33 ->0x100755bc0 with raw marker0x74c29d85; selected caller's output was already zeroed |

This is a selected source-phase contract. The caller's descriptor-address arithmetic and physical 80 B storage, complete optional preparation, native allocator result and same-frame reaching definitions require separate premises. No allocation-failure fixture was run.

## Two complete producer descriptors [BO2-BO5]

Post-call source0x1007cd09c..0x1007cd32c writes80 B with eleven logical store effects. LEN and STR remain arbitrary u64 variables in the source query. The exact fields are:

| Field in each40 B descriptor | Descriptor0 / BASE+0 | Descriptor1 / BASE+0x28 |
| --- | --- | --- |
| +0x00 / u64 inactive scalar | 0x2c220a381b62f9ab | 0x2c220a381b62f9ab |
| +0x08 / u32 value | 0xa7c636e9 | 0x8b3dc651, inactive for span |
| +0x0c / u32 | Zero in this producer | Zero in this producer |
| +0x10 / u64 span pointer | Zero, inactive for u32 | STR, exact identity for all64-bit inputs |
| +0x18 / u32 identifier HE | 0xf5b8e304 | 0x94dc5979 |
| +0x1c / u32 private kind | 0x372c9ea2, u32 leaf | 0x372c9ea0, span leaf |
| +0x20 / u32 encoded extent E | 0x8b3dc655; typed scalar root independently fixes4 B | `(low32(LEN)+1) XOR0x8b3dc651` |
| +0x24 / u32 qualifier | 2 | 2 |

The scalar value, identifiers and kinds have no assigned application-specific meaning here. The existing codecs map the scalar/span internal tags to wire tags0x9777/0x50db; inactive fields are not thereby interpreted as canonical padding. This particular producer initializes them, whereas other consumers need not read them.

The span constructor decodes `P=E XOR0x8b3dc651=low32(LEN+1)`. For the bounded-length result0<=LEN<=1024, P=LEN+1 without u32 wrap and lies in1..1025 B. This is the requested extent. A terminator at STR+LEN and readability of the full P-byte span remain premises, especially at the bound; neither pointer validity nor native copy behavior follows from the arithmetic. No boundary/fault input was executed.

## Child creation and descriptor destination [BO2-BO5]

At0x100863000 the source reloads H from K+0x3950 into X19 and requests16 B for C1. On its normal nonnull return,0x10072cf4c zeros C1.head and C1.tail (two8 B words), stores C1 at H+8, then requests16 B for C0. On the second normal nonnull return,0x100857c94 zeros C0.head/tail and stores C0 at H+0. The two 16 B allocations are collection containers; they are distinct from32 B record nodes and the128 B builder. Remaining builder bytes+0x10..+0x7f are outside this field recovery and are not presumed initialized or classified.

```text
H : requested128 B builder
 |
 +-- [H+0] = C0 : requested16 B container
 |                 initially head=0, tail=0
 |                 CELL=H, qualifier1
 |
 +-- [H+8] = C1 : requested16 B container
                   initially head=0, tail=0
                   CELL=H+8, qualifier2
```

| Consumer | Exact source arguments | Selected producer consequence |
| --- | --- | --- |
| 0x100703a30 ->array helper | CELL=H+8, qualifier2, BASE/count incoming from saved producer | Both descriptors match; span admission additionally requires STR!=0 under the earlier array contract |
| 0x1008f05f0 ->array helper | CELL=H, qualifier1, BASE=[K+3430], count=[K+8dd0] | Neither of these two descriptors matches |
| Array entry0x1008cadf0 | Reads child pointer=[CELL], saves it at K+0x3fa0 | Reads C1 or C0 according to supplied child-cell address, not H as the container |

The source CCMP gate in0x100857c94 calls the first application only when BASE!=0 and count!=0. Its NZCV fallback is0x4 when BASE==0. The certificate models this exact compare and fallback. A zero/null array takes a different continuation; it is not labeled a failed native constructor.

The source/byte-memory composition establishes the local destination relation under disjoint live owners and stable frame fields. The intervening preparation and arbitrary aliases/concurrency remain outside the proof. It does not establish a native builder instance or a complete public struct.

## Cleanup pointer epoch and explicit correction [BO3,BO6]

The source chain is:

```text
finish: X8 = H loaded from K+0x3950
                 |
                 v
cleanup_save:
    [K+0x6520] = H
    X8 = K+0x6520 = SCELL
    [K+0x4a68] = SCELL
                 |
                 v
cleanup_cell:
    [K+0x5120] = SCELL
                 |
                 v
cleanup_object:
    H = *SCELL
    [K+0x77b8] = H
                 |
                 v
    drain CELL=H+8  -> C1
    drain CELL=H+0  -> C0
    free(H)
    *SCELL = 0
                 |
                 v
prior nil-output/status continuation
```

| Exact site | Source effect / corrected meaning |
| --- | --- |
| 0x10097a0d8 | Stores incoming heap H at K+0x6520 |
| 0x10097a0dc /0x10097a0e0 | Computes X8=K+0x6520 |
| 0x10097a0e4 | Stores this address at K+0x4a68 |
| 0x1007322e0 | Saves the forwarded cell address at K+0x5120 |
| 0x1007778fc | Loads H through the cell address; it does not read H's first child as the outer object |
| 0x10083dd78 | Supplies CELL=H+8 to the first drain |
| 0x1004c61ec | Reloads H from K+0x77b8 before the second drain |
| 0x100580868 /0x100580884 | Loads saved H and supplies it to selected `_free` |
| 0x100580888 /0x100543ba0 | Reloads SCELL from K+0x5120 and stores zero at SCELL after normal builder release |

The prior local certificate tested each block with independent input variables. It did not assert that the next block's X8 input was the previous block's actual X8 output. Its local equations remain true, but they did not support the old prose composition. The new join passes SSA outputs into subsequent inputs and proves the changed X8 value explicitly. A separate frame byte-array query verifies that storing the cell addresses at K+0x4a68/+0x5120 and the marker at+0x36c4 leaves the saved H at+0x6520 intact.

The corrected final clear is at the frame-local SCELL, after the two drain calls have cleared H's child fields and H has been released. The earlier report's association of this clear with the incoming heap address was incorrect. The machine-readable erratum records the historical report hash and exact source sites; original source/check JSON is preserved. Status-width, shared-finish and separate frozen temporary-drain results from that report remain scoped as documented.

## Compositional memory proof and excluded queries [BO3-BO6]

| Accepted component | What it establishes |
| --- | --- |
| Frame byte-array join | Actual saved H and two copies of SCELL survive the exact frame-store sequence |
| LE64 store/load identity | Eight little-endian byte stores reload as the original full64 word |
| Eight-byte noninterference | Each byte outside those eight addresses is unchanged |
|128/16 B owner-prefix separation | Arbitrary offsets0..15 in nonwrapping disjoint owners cannot alias |
|16/16 B owner-prefix separation | Same separation for the two child containers |
| Six-word publication join | Source write order yields C1/C0 at H+8/H+0 and four zero head/tail words in distinct cells |

The byte identities and separation lemmas justify treating the six source accesses as independent8 B cells for the final array-of-words composition. This is a compositional certificate under explicit owner premises. It is not a native byte-memory execution, complete frame/heap alias proof, or proof of constructor lifetime after subsequent mutations.

The first aggregate heap byte-array query returned unknown at15000 ms. A second version adding explicit redundant byte disequalities also returned unknown. Both are retained with query text and historical generator hash, marked accepted=false. Neither is treated as UNSAT, SAT, failure behavior or native evidence. The accepted component proofs do not depend on either unknown result.

The two rejected interpretations are source-only SAT checks: X8 need not remain H after cleanup_save, and the final cell-clear address need not equal H. They refute universal preservation/address claims without invoking a target or producing a fault fixture.

## Original call selectors and conditional roots [BO1-BO5]

| Role / call site | Original bank pair | Key / addend | Collapsed index | Original binding / IA |
| --- | --- | --- | --- | --- |
| Bounded length /0x1007cd098 | A |0xf3 /0xcc4d |0xcc90 | `_strnlen` /0x0682 |
| Builder allocation /0x100766ca8 | C |0x9a /0xcb28 |0xcc0d | `_malloc` /0x6aa4 |
| C1 allocation /0x100863070 | D |0x6d /0xcb3d |0xcc0d | `_malloc` /0x6aa4 |
| C0 allocation /0x10072cfc0 | A |0xf3 /0xcbca |0xcc0d | `_malloc` /0x6aa4 |
| Builder release /0x100580884 | B |0xbb /0xcb4d |0xcc08 | `_free` /0x46a2 |

A=(0x100fc4230,0x101031fa0); B=(0x100fc4130,0x101031ea0); C=(0x101031da0,0x100e99900); D=(0x100e99a00,0x100f4e390). All1280 byte-input cases are checked against original array bytes. Source queries verify the selected byte addresses/index, arguments and relevant frame-root loads. Original chained records and a fresh fixup catalog identify the imports; matching IA metadata is not hardware authentication.

D's pointers are read from K+0x600/+0x5f8. Eight retained setup profiles supply sixteen field instances, written at0x1004c2838/0x1004c343c with original instruction bytes checked. These are frozen setup observations. They do not establish the same native frame or absence of later writes before this builder. The other bank-root premises remain as stated in the earlier initializer report.

## Bounded saved-pointer writer census [BO1,BO2]

The original aligned-text scan for literal unsigned-immediate `STR Xn,[SP,#0x3950]` finds:

| Store | Source-local role | Remaining limit |
| --- | --- | --- |
| 0x100766cac | Saves the normal128 B allocation result X0 | Native allocator and frame epoch are separate |
| 0x10078cd14 | Clears the saved pointer on the established nil-result leaf | Does not classify other frame uses |
| 0x100ace664 | Copies a value loaded from frame+0x2dd0 | Different workflow/frame epoch is unjoined |

The census checks the entire original `__text` for this exact aligned encoding and retains52 B per window. Computed-address stores, paired stores, other widths/forms, aliases and frame equivalence are excluded. Three literal candidates do not establish global single-assignment or native reaching definitions.

## Frozen evidence and evidence boundary [BO7]

Every retained successful profile records one requested128 B builder allocation at return0x100766cac and two requested16 B child allocations at returns0x100863074/0x10072cfc4. All three allocation records remain live at the profile's stopping boundary. The original source implies the +8/+0 publication relation using those recorded results and the normal-call/frame premises. The source-implied child map is not relabeled as a recorded heap-cell snapshot.

The profiles enter both descriptor applications once and the array helper twice. The earlier episode ledger records two selected constructor calls for qualifier2 and none for qualifier1, consistent with the fully recovered two-descriptor producer. Subsequent builder consumers and additional constructors are separate from this producer/destination statement. Zero profiles enter the new outer cleanup path; its owner-matched disposal remains source-derived.

The length import is recorded as `_strnlen` with limit1024 and a result within0..1024 in these profiles. Requested extents, source-compatible pointer identities and live-allocation metadata do not prove native readable buffers, actual allocator behavior, hardware PAC, a successful UserClient open or a daemon-kext peer. No frozen generator or target was rerun.

## Complexity and access scope [BO3-BO5]

The recovered producer writes exactly80 B in fixed work and uses O(1) scalar auxiliary storage. The bounded-length call is external; under its conventional bounded-scan contract its input work is O(min(length,1024)), but the source certificate establishes call binding/arguments and arithmetic, not that native implementation or input ownership. Builder/container initialization adds three allocation requests for128+16+16=160 B, excluding record nodes/buffers, opaque preparation and allocator metadata. Allocator internal complexity is unknown.

For the two-descriptor producer, the first application examines at most two records and can construct two; the second examines at most two and selects none. The shared generic walker and constructor may have other counts/callers, with their previously documented conditional O(N) and list-search bounds. Cleanup of n0/n1 child nodes remains O(n0+n1) source control work and O(1) scalar storage under finite acyclic exclusive ownership. No upper bound on native time or total heap use is inferred from this fixed producer.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Static stress test or falsification probe |
| --- | --- | --- |
| BO1 | Code, pointer records and banks belong to the pinned thin image. All source identities depend on this build. | Rehash image and recapture bytes/fixups/catalog; reject cross-build substitutions. |
| BO2 | The selected masked phase, saved table/continuation epoch and same shared frame are compatible; unmodeled preparation does not overwrite relevant saved fields. Producer-to-consumer joins depend on these conditions. | Trace all reaching stores, including computed/pair aliases and alternative0x100ace664, and establish actual frame identity. A bounded literal census is insufficient. |
| BO3 | BASE has80 writable/readable B; builder/child/frame owners are live, disjoint and nonwrapping for the specified accesses, and published words remain stable between modeled stores. Byte/cell composition depends on these premises. | Recover allocations, aliases and lifetime endpoints; check full conditional byte footprints. Three requested sizes alone do not establish native owners. |
| BO4 | Original bank roots are present and each import returns normally with required callee-saved registers/SP preserved. Post-call joins depend on this condition. | Verify source arguments/root loads/bank relations, original binding and local register definitions. Do not assume caller-saved X8/X12 preservation. |
| BO5 | LEN is the returned bounded length; actual span has the requested LEN+1 readable bytes. Source extent/codec arithmetic is unconditional; readable/terminated-span interpretation is conditional. | Check all-u64 LEN/STR source identities and the bounded no-wrap range; recover terminator/owner provenance separately. No boundary/fault fixture is supplied. |
| BO6 | Cleanup receives the source-produced SCELL address and saved H/continuations remain stable under the owner premises. Corrected disposal depends on this composition. | Pass actual SSA outputs into each following block; verify the frame store/load join and reject heap-preservation/heap-clear interpretations. Local block proofs alone do not certify inter-block prose. |
| BO7 | Frozen allocation/liveness/episode records retain their recorded source identity and model scope. Occurrence claims are corpus-bound. | Rehash profiles, match allocator returns/extents/live owners and distinguish source-implied child maps from heap snapshots/native graphs. |
| BO8 | Complete optional preparation, all early-failure initialization, public prototypes/status meanings, native credentials/ports/PAC and selector26/RPC502/700 endpoint pairing remain unknown. | Require same-build owner and public/IPC consumer joins plus native provenance before assigning those meanings. The retained open failure supplies no successful transaction. |

## Bounded continuation opportunities

| Impact | Next static target | Question resolved |
| --- | --- | --- |
| High | Trace all builder fields+0x10..+0x7f and opaque preparation, including original temporary-buffer release. | Complete128 B field grammar and lifetime/initialization coverage beyond the two child pointers. |
| High | Follow builder success consumers, C1 field population and both collection serialization joins. | How the two-collection object becomes external request/reply data and which identifiers carry which application meanings. |
| High | Establish native same-frame/root/owner and endpoint provenance for selector26/RPC502/700. | Actual cross-facility transaction pairing and remaining source-to-runtime assumptions. |
| Medium | Recover alternative saved-pointer producer0x100ace664 and all computed/pair writes. | Distinct frame epochs and complete reaching definitions for saved builder state. |
| Medium | Examine source initialization on early allocation-return branches without executing failure fixtures. | Which owner invariants are established before each cleanup entry. |
| Low | Enforce register-output composition checks at future private-ABI joins. | Prevent repetition of the X8 preservation error when local equations individually pass. |

## Scoped quality gates

- QG1: This increment reports technical source, ABI, proof-scope and historical correction facts; no normative conclusion is required.
- QG2: BO1-BO8 enumerate dependencies and falsification probes.
- QG3: Selected builder/descriptor production, child creation/destinations, corrected cleanup ownership, original call selectors and frozen-scope limits are covered. The broader interface investigation remains active.
- QG4: u32/u64 modular domains, little-endian byte composition, B extents,128+16+16=160 B requested owner total,80 B descriptor stores and conditional complexity/length bounds are explicit.
- QG5: All551 nonbranch/noncall instructions of the17 fragments are covered exactly once in the translation ledger; five calls/17 terminal branches are checked separately. Actual source register epochs replace the incorrect prose assumption. Two SAT interpretation rejections and two excluded unknown queries are distinguished from28 accepted UNSAT queries.
- QG6: Original bytes/pointers/banks/catalog, frozen allocation/setup records, accepted source/memory components, ten rejected alterations and the explicit historical report hash provide scoped provenance. No new target/native execution is claimed.
- QG7: Continuations are bounded and impact-labeled. Unclassified builder fields, opaque/early-failure paths, native ownership and daemon-kext/public ABI identity remain unknown. Scoped gates do not imply full-goal completion.
