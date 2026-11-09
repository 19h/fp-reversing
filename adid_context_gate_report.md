# CoreADI adid: reversible state view, context-gate timing and pointer consistency

The subsequent [state-producer report](adid_state_producer_report.md) recovers the preceding state-word producer and word permutation. Under its inspected scalar/alignment prefix,the permutation rotates eight words right once. The complete local codec combines that rotation with the vector phase below,and its inverse constructs fresh representations checked by original code. The gate fields and native object grammar remain separate requirements.

The inspected vector loop has a compact reversible per-byte model for its 64-byte state window. Its output supplies the context view consumed by two recovered guards. Initial edits to a tag are overwritten before those guards; edits at the original load change control flow but leave other fields inconsistent. The baseline tag equality selects an error path, rather than demonstrating a valid context. Complete valid-context construction and feasible request paths to the IOKit callers remain unknown.

All twelve cases start at the original XPC callback and use the retained private peer state. They apply no analyst-selected instruction-PC jumps. Seven complete with the previously observed four-byte payload error; five deliberately inconsistent field cases stop at private read boundaries. None demonstrates a native fault, accepted provider state or successful protected operation.

## Identity, assumptions and evidence

Provider addresses are preferred virtual addresses in the selected arm64e `/System/Library/PrivateFrameworks/CoreADI.framework/adid` slice: base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. The [context/error report](adid_context_report.md) establishes the earlier status production; the [protected-dispatch report](adid_driver_dispatch_report.md) establishes the source frame and separately controlled IOKit caller fragments.

| Assumption | Dependent results | Stress test / falsification boundary |
| --- | --- | --- |
| G1: pinned provider bytes/fixups describe the inspected image | Addresses, constants, branch cells and vector sequence | Fresh instruction/compiler-range/window readbacks and independent dyld_info agree. Native image/runtime integrity remains unknown. |
| G2: frozen private peer/API/PAC/vector models describe the stated experiments | Full-callback source paths, fields and replies | Baseline source visits match the complete frozen context case; five fresh executions reproduce source/event/block results. Same declared models, not native behavior or independent-emulator equivalence. |
| G3: initial and late field changes describe their exact observation epochs | Mutation timing and gate alternatives | Every patch retains before/after bytes and position; original stores account for intervening changes. No valid native constructor, permission or feasibility is inferred from a patch. |
| G4: captured vectors and original literal lanes describe the selected loop | Compact byte model | Independent Python arithmetic and TBL gather match all 48 observed chunks; four local proofs include byte reduction/inverse. Other state transforms, key producers and full protected algorithms remain unknown. |
| G5: the captured state word W20=`0xd5b` applies to the local guard reductions | Tag/pointer branch-index partitions | Original operands agree in the retained cases; original chained slots match destinations. Different local state words or predecessors require a different proof. |
| G6: additive field decodes describe only the inspected pointer arithmetic | Two sentinel forms and read-address calculations | Full64-bit round-trip/offset proofs and exact private boundary addresses agree. Complete field/object types, allocation extents and valid pointed data remain unknown. |
| G7: complete block snapshots around observed writes/API boundaries describe their net effects | Continuous mutation provenance and overwrite source | 1623 source write effects reconstruct all 64 watched bytes; 913 API boundaries have zero net block changes. This is guest/model instrumentation, not native memory monitoring. |
| G8: a 64-byte transform span is an observed state window | Raw layout and state-view interpretation | Four original 16-byte iterations cover it. This does not establish a complete native object type, persistent-file grammar, message size or port representation. |
| G9: completion/private stops delimit control and error claims | Seven replies and five inconsistent-state stops | Exact stores/branches, no-reply boundaries and error bytes are retained. Native error policy, exceptional cleanup, concurrency, lifetimes and successful request semantics remain unknown. |

Artifacts: [profiles and complete mutation events](triage_evidence/adid_context_gate_profiles.json), [static contracts/proofs](triage_evidence/adid_context_gate_contracts.json), [producer](triage_evidence/probe_adid_context_gates.py), [recoverer](triage_evidence/recover_adid_context_gates.py), [fresh checks](triage_evidence/adid_context_gate_checks.json), [validator](triage_evidence/validate_adid_context_gates_delivery.py) and [quality gates](triage_evidence/adid_context_gate_quality_gates.json). Original inputs, earlier source/proof/profile artifacts and IDBs remain preserved.

## Compact source-state transformation [G1,G2,G4,G8]

The original vector sequence at `0x1001997d8..0x100199894` processes four 16-byte chunks in place. The watched span is `0x1002dcb68..0x1002dcba8`, with offsets 0, 16, 32 and 48 bytes. Original load `0x100199800`, table instruction `0x10019986c` and store `0x100199870` are retained with their registers and memory observations.

Let x[i] be an input byte, k the state word replicated into Q4, and i the byte position 0..63. All byte arithmetic below is modulo 256:

```text
s(i,k) = ((i*i - k*k) XOR k) mod 256
y[i]   = ((155*x[i]) mod 256) XOR s(i,k)
x[i]   = (147*(y[i] XOR s(i,k))) mod 256
```

The 32-bit source products `(i+k)*(i-k)` reduce to `i*i-k*k` for the selected low byte. The full-domain reduction covers arbitrary u32 i/k and u8 x. The output depends only on their low bytes. The inverse proof uses `155*147 = 22785 = 89*256+1`, so multiplication by 147 inverts multiplication by 155 modulo 256. This is the mathematical inverse of the inspected loop; no separate native inverse routine is asserted.

The original literal vectors contain positions `[12,13,14,15]`, `[8,9,10,11]`, `[4,5,6,7]` and `[0,1,2,3]`. Each iteration advances them by 16. The TBL selector is the fixed byte sequence `[0,4,8,...,60]`, gathering the low bytes of the computed u32 lanes. The validator separately checks that gather against the captured 64-byte register table and checks the compact arithmetic against the captured output bytes.

One readable form is:

```text
for i = 0..63:
    term = ((i*i - k*k) XOR k) AND 255
    data[i] = ((155*data[i]) AND 255) XOR term
```

The local operation is O(64) time and O(1) auxiliary storage; for an analogous N-byte span, O(N) time. The evidence establishes this local reversible state representation, not the complete program algorithm or a cryptographic primitive for FairPlay content.

## Mutation epochs and source provenance [G1-G3,G7,G8]

```text
private peer checkpoint
        |
optional explicit early tag edit
        |
original callback/persistence/context stores
        |
original 64-byte vector transform
        |
observed context view before field loads
        |
optional explicit late field edit
        |
original pointer24 / tag guards
        +--> error production -> data reply ffff501f
        |
        +--> inconsistent pointed-state continuation -> private read boundary
```

The producer records all observed guest writes overlapping the full 64-byte span. Each event contains the original instruction address, before/after block snapshots and individual observed write addresses, widths and low-u64 values. The checker independently applies those writes to reconstruct the after image. Before images form a continuous ledger through the final memory snapshot, including explicit analyst patches.

The 16-byte Q-register store at `0x100199870` is observed as eight-byte memory-hook portions. Grouping by the original instruction and checking complete snapshots avoids treating a partial hook value as an entire vector. Four stores supply the guard-view state. Earlier and later original stores also mutate this region, so a single raw physical snapshot is not a stable field interpretation for every program epoch.

An initial hypothesis that modeled API copies restored the tag was not supported: there are zero net changes to this block across the 913 instrumented API boundaries in these twelve cases. Original source stores explain the recorded overwrite. This conclusion is limited to the inspected block and declared API models.

All four early tag edits, including zero and `0xffffffff`, reach the original tag load with `0x16e4e4d3` and preserve the complete baseline source path and error payload. Thus editing the initial physical word did not test an alternative value at that later guard. Other intermediate state differences are retained rather than assumed absent.

## Guard-view fields and exact branch partitions [G1,G2,G5,G6,G8]

At the baseline field loads, the first 40 bytes have this observed structure. Widths describe accessed fields, not a complete native declaration.

| Offset / width, bytes | Baseline observed value | Established use / boundary |
| --- | --- | --- |
| 0 / 4 | `0x16e4e4d3` | Compared by the tag guard; equality selects the local error path |
| 4 / 4 | `0x04166fd7` | Opaque |
| 8 / 8 | `0x58ce03d8d8c95487` | Compared and used in later pointer arithmetic; complete pointed type unknown |
| 16 / 4 | `0x256ff1e8` | Opaque in this increment |
| 20 / 4 | 0 | Opaque |
| 24 / 8 | `0x6fac17cb61e34e69` | Pointer24 comparison and later decoded read |
| 32 / 8 | `0x089503966af1b068` | Opaque; not assigned a native pointer/object type |

Bytes +40..+63 are retained in every complete snapshot. Their participation in the vector span does not establish field meanings. Similarity to previously recovered count/pointer codecs is not treated as a type proof. None of these values is identified as a Mach port name or right.

The local table base is `0x1002c40c0`. With W20=`0xd5b`, the full-domain branch proof gives:

| Original guard / branch | Predicate | Selected table index | Original target |
| --- | --- | --- | --- |
| Load `0x10019e498`, compare `0x10019e4ac`, branch `0x10019e4f8` | field+24 equals `0x6fac17cb61e34e69` | `0x8b4` | `0x10019e6a4` |
| Same pointer24 guard | Field differs | `0x8e8` | `0x10019e4fc` |
| Load `0x10019bdcc`, compare `0x10019bde0`, branch `0x10019be14` | tag equals `0x16e4e4d3` | `0x23f8` | `0x10019c098` |
| Same tag guard | Tag differs | `0x23da` | `0x10019be18` |

Each selected slot is read back as an original authenticated chained pointer. The first baseline target produces earlier raw status `0x0058748a`; the tag-equality target stores final raw `0x005874ae` at `0x10019c0b4`. The [prior status/serialization report](adid_context_report.md) traces the latter through the four-byte payload `ffff501f`, signed -45025. The two statuses are distinct.

The equality branch is an error condition under this local prefix. The constant's semantic role outside this branch remains unknown; it is not promoted to a valid-context tag. The physical original-image bytes happen to contain the same tag value, while the running private state has intervening transformations and stores.

## Additive pointer fields and inconsistent-state controls [G3,G5,G6,G9]

The inspected source arithmetic has these local decodes:

```text
field8  = P + 0x58ce03d8d8c95487 mod 2^64
P       = field8 + 0xa731fc272736ab79 mod 2^64

field24 = Q + 0x6fac17cb61e34e69 mod 2^64
Q       = field24 + 0x9053e8349e1cb197 mod 2^64
read at 0x10019e604 uses Q+8
```

The pointer proof establishes the round trips and +8 address relation. It does not establish the full native record type or valid P/Q ownership. The baseline constants correspond arithmetically to zero P/Q in these local decodes. A literal field value zero is different from the encoded-zero value.

| Explicit experiment | Observed result |
| --- | --- |
| Baseline, or any of four early tag edits | Completes original callback, emits `ffff501f` |
| Late tag equals baseline value | Same completed error reply |
| Late tag 0, `0x16e4e4d2` or `0xffffffff`, other fields retained | Takes the tag-inequality continuation; private read at `0x10019c1c4`, address `0x18`; no observed reply |
| Late field24 equals baseline encoded-zero value | Same completed error reply |
| Late field24 is `0x6fac17cb61e34e68` | Decoded Q is -1 modulo 2^64; Q+8 is 7; private read at `0x10019e604`, address `0x7` |
| Late field24 is literal zero | Private read at `0x10019e604`, address `0x9053e8349e1cb19f` |

These late mutations deliberately make isolated fields inconsistent with the retained object state. Their private read stops are diagnostic boundaries, not native OOM/fault/reachability claims or evidence of a valid accepted context. The fields' real writers and consistency relationships remain necessary evidence before extending these paths to actual IOKit requests.

## Verification and bounded continuation

The [fresh validator](triage_evidence/validate_adid_context_gates_delivery.py) passes 21271 assertions across 12 private cases, 15545 unique original instruction records in 13 compiler ranges and 526393 retained original visits. It reconstructs 1623 complete source write effects, observes 913 API boundaries with zero net block changes, checks 48 vector chunks / 768 bytes against independent arithmetic and gather oracles, and freshly solves four full-domain local proof obligations. Five complete source/event/block replays reproduce 219735 hook steps. Seven cases complete with the error payload; five stop at explicit inconsistent-state read boundaries.

The baseline matches the earlier full callback's ordered original source stream. All entry paths start at the original callback; there are no analyst-selected instruction-PC jumps. Byte-model and pointer/branch proofs cover their declared local domains and prefixes. No native target, loader, IOKit, Mach, target-file/environment or synchronization API was executed, and no original input or IDB was modified.

The validator takes O(B+F+R+V) time/space over source/artifact bytes B, fixups F, retained records R and source visits V. The watched-block ledger has fixed 64-byte snapshots per mutation event, and each execution has an explicit source-hook cap.

| Impact | Remaining interface | Concrete next evidence |
| --- | --- | --- |
| High | Valid context construction | Recover the producers and invariants of the tag and both pointer fields, their allocation/list/record grammar and the accepted persistent-data path without isolated field patches |
| High | Feasible request-to-IOKit flow | Map public selectors and context prerequisites to the three upstream callers, then recover skipped metadata gates and subsequent reply/control effects |
| High | Real provider responses and deeper operation selection | Locate Avp implementation/actual image and port pairing, authentic selector26/100 responses and raw record consumers through PRnut72j9/host slots/RPC families |
| Medium | State-transform lifecycle | Recover the state-word producer, other representation transitions, reentry/concurrency and the semantics of all 64 observed bytes; compare any native inverse implementation independently |
| Medium | Complete consistency/error/ownership contract | Account for pointed data, all tag/status/count consumers, retries, exception paths, buffers, port rights and final object retirement |
| Low | Additional experiment instrumentation | Extend mutation provenance to other state windows as demanded by their consumers, preserving source-store/model-API/analyst changes as distinct evidence |

QG1-QG7 pass for this bounded increment: descriptive findings; G1-G9 dependencies/probes; concrete data/control/ABI progress; exact modular arithmetic, widths and mutation reconstruction; explicit timing, representation and inconsistent-state boundaries; primary source/fixup and independent-oracle provenance; and impact-labeled continuation. Valid native contexts, complete request feasibility, successful algorithms and full architectural coverage remain unknown. The full goal remains active and incomplete.
