# Legacy record wrappers, internal bridges and stack displacement

Two unresolved `0x9d3a` modifier sites in the [RW lifecycle census](rw_lifecycle_report.md) resolve to internal record bridges. They do not call `IORWLockFree`. This reclassifies two of the eight previously unresolved candidates, leaving six unresolved. The separate FairPlay cached RW-pointer producer remains **unknown**.

The analysis establishes the two named outer wrappers' record construction, source status forwarding, the second bridge's stack-displacement contract and exact original stack-probe bindings. [Contracts](triage_evidence/legacy_stack_contracts.json), [retained profiles](triage_evidence/legacy_stack_profiles.json), [distinct fresh replays](triage_evidence/legacy_stack_replays.json), [independent checks](triage_evidence/legacy_stack_checks.json) and [five local proofs](triage_evidence/legacy_stack_proofs.json) retain the evidence. The broad interface objective remains active and incomplete.

```text
_zzLw2eOVu9pOHqpiNw1K4ki(X0, W1, X2)
  -> 32-byte partial stack record P
  -> unnamed bridge A52FD18       [outer call modifier 9D3A]
  -> another 32-byte record Q
  -> inner operation A55E8B0      [MODELED; target not executed]
  -> Q+10 status -> P+10 status -> adjusted W0 return

_Vt05NUgPD3Xy28y1R3R(eight register inputs)
  -> 64-byte partial stack record P + displacement cell C
  -> unnamed bridge A570CF4       [outer call modifier 9D3A]
       -> original __chkstk_darwin / __chkstk_darwin_probe
       -> inner operation A561344(P, local_state_cell)
                                      [MODELED; target not executed]
       -> source writes byte displacement D into C
  -> original SP = SP + D
       D = 0: source status read and normal return
       D != 0: STOP before relocated output read
```

All execution is in a private guest with original instruction bytes and abstracted PAC. No native target, Mach/IOKit, synchronization, heap, provider, crypto, credential or target-file operation executes. The two inner operations supply explicit modeled writes/clobbers, not native behavior. The original stack probe executes only against mapped private guest storage.

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LS1 | Pinned original KC and normalized image define this build | Addresses, symbols, banks and source bytes | Verify complete hashes, compiler envelopes and original chained-pointer membership; compare actual runtime identity separately |
| LS2 | Abstracted PAC and private mapped memory describe conditional instruction semantics | All replay results | Reject source escapes/unmodeled calls and compare every visited instruction; hardware PAC, runtime mappings and native reachability remain separate |
| LS3 | Six mutable-global fixtures describe local source operands without concurrent modification | Dispatch and bridge compositions | Check original/zero/declared-noise fixtures, exhaustive byte-bank identities and ordered global epochs; establish real serialization independently |
| LS4 | Inner operations perform exactly the declared output/state writes, return and preserve callee-saved registers | Status forwarding, displacement and completed modeled compositions | Clobber X0-X17/NZCV as declared; recover actual inner-operation ABI, field production and lifetime before asserting native results |
| LS5 | Opaque register inputs are width/byte-flow probes, not valid pointed objects | Record layouts and carrier forwarding | Keep pointed data unaccessed; resolve actual types, caller constraints and native input provenance separately |
| LS6 | Original stack-probe loads into WZR establish guest-page touches only | Probe execution and private local-cell allocation | Check exact probe instructions and mapped addresses; no native guard-page, fault or stack-capacity conclusion follows |
| LS7 | Zero derived displacement leaves the original frame available | Complete second-wrapper returns | Verify source-produced D=0 and all read/write epochs; nonzero cases stop before relocated data/frame reads |
| LS8 | Address-relative record equations describe fixed-width local operations | Compact records, width loss and arithmetic proofs | Vary aligned stack placement and full-width canaries; preserve holes, output provenance and intermediate versus final operand distinctions |
| LS9 | The earlier modifier census is bounded to its literal construction grammar | Two exclusions and six remaining candidates | Recheck the exact sites/slots; expand other modifier constructions independently; equal modifiers do not establish callee identity |

LS1-LS9 qualify the corresponding results. Retained/fresh agreement shares the private engine; independent byte reconstruction and compact equations test separate properties, not the engine's complete correctness.

## Primary source and exact interfaces

| Source | Verified coverage / identity |
| --- | --- |
| Original KC | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized FairPlayIOKit | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Source extraction | Eight compiler envelopes; six execute, two inner targets remain unexecuted |
| Dispatch/data provenance | Eighteen exhaustive byte-bank rules, ten original pointer bindings, six original mutable-global spans and original stack-guard bytes |
| Identity and delivery | [Fresh source identity](triage_evidence/legacy_stack_source_identity.json), [preservation](triage_evidence/legacy_stack_preservation.json) and [quality gates](triage_evidence/legacy_stack_quality_gates.json) |

| Entry / call site | Exact target / name | Established role |
| --- | --- | --- |
| `0xfffffe000a50c2b0` | `_zzLw2eOVu9pOHqpiNw1K4ki` | Three-register wrapper constructing the first record |
| Call `0xfffffe000a50c4cc` | `0xfffffe000a52fd18`, exact name unknown | Internal record bridge; original slot `0xfffffe00084714e8` |
| Call `0xfffffe000a5302ac` | `0xfffffe000a55e8b0`, exact name unknown | Inner operation, modeled; slot `0xfffffe00084714c8` |
| `0xfffffe000a50e618` | `_Vt05NUgPD3Xy28y1R3R` | Eight-register wrapper constructing the second record |
| Call `0xfffffe000a50e860` | `0xfffffe000a570cf4`, exact name unknown | Internal record/stack bridge; slot `0xfffffe00084713c0` |
| Call `0xfffffe000a570ee4` | `0xfffffe000a561344`, exact name unknown | Inner operation, modeled; slot `0xfffffe0008471610` |
| Import slot `0xfffffe000847c610` | `___chkstk_darwin`, `0xfffffe000a5a1cc4` | Original two-instruction veneer |
| Veneer branch target | `___chkstk_darwin_probe`, `0xfffffe000a5a1ccc` | Exact original stack-page probe |
| Import slot `0xfffffe000847c5f8` | `___stack_chk_guard`, `0xfffffe000cacb000` | Source guard read/save/check |

Names above are exact-address nlist matches. Each table-base rule resolves to `0xfffffe000846c420` through original pool slot `0xfffffe0008471b38` with bias -8. Target identities use the corresponding checked original slot. The eighteen rules cover 4608 byte inputs, retaining both original 256-byte banks per rule. They establish local index identities, not all predecessor states or hardware authentication.

## First wrapper: 32-byte record and status forwarding

Let B be the wrapper's body SP after reserving 64 bytes and P=B+8. Arithmetic is unsigned at the indicated width. The source's expanded address expression and the bridge's different expanded expression both reduce to:

```text
K64(P) = ((P XOR 0x2bf25469f26d6f2a) * 0xeac8f755) mod 2^64
```

| Record offset | Width, bytes | Source value |
| --- | ---: | --- |
| `+0x00` | 8 | Input X0, forwarded without a pointed-data read |
| `+0x08` | 4 | `low32(K64 + 0xc83b1be7)` |
| `+0x0c` | 2 | `low16(K64 + W1*0x7e23 + 0x64ca)` |
| `+0x10` | 4 | Output field; uninitialized by outer construction |
| `+0x18` | 8 | `K64 XOR (X2*0x0af36ba5d7ced8c7 + 0x23aeddd02b5fde50 mod 2^64)` |

Only 22 of the 32 bytes are source-initialized before the call; gaps remain unknown and are not promoted to fields. Input W1 contributes only its low16 bits to the emitted halfword. Twelve paired retained/fresh traces differ in input W1 by `0x10000` and are otherwise identical. This is a local representation property; actual admissible W1 values and their semantic names remain unknown.

The bridge constructs another 32-byte record Q=P-`0x50`, initializes 24 bytes, puts a pointer to Q-8 at Q+0 and forwards the original outer X0 to Q+`0x18`. At `0xfffffe000a52fea4`, the original intermediate X1 equals `input_X2 + 0x442b0f63903f796e mod 2^64`. The affine composition is therefore an offset transform at this observation, not an identity decoder. No final pointer/type interpretation is assigned to that intermediate.

The inner operation at `0xfffffe000a55e8b0` is not executed. Its model writes a declared status32 to Q+`0x10` and clobbers caller-saved registers. Original source copies Q+`0x10` to P+`0x10` at `0xfffffe000a5302b4`; the outer source returns `status32 + 0xa1a9e7b7 mod 2^32`. The native meaning of that adjusted return remains unknown. Incidental modeled X0 does not provide the returned status.

## Second wrapper: 64-byte record and stack contract

Here B=entry_SP-`0x90`, P=B+`0x18`, and C=B+8 is a separate 8-byte displacement cell. Define p=low32(P), with every operation below reduced modulo `2^32`:

```text
t = ((p OR 0x976412f0) XOR 0xfffffffe)
    - (0x689bed0f OR NOT32(p))
K32(P) = (t XOR 0xd83db235) * 0x4ca11177
```

| Record offset | Width, bytes | Source value |
| --- | ---: | --- |
| `+0x00` | 4 | `K32 + W7` |
| `+0x04` | 4 | `K32 XOR 0x6e3` |
| `+0x08` | 4 | `W4 - K32` |
| `+0x10` | 8 | X3 |
| `+0x18` | 4 | `K32 XOR W6` |
| `+0x20` | 8 | X5 |
| `+0x28` | 8 | X2 |
| `+0x30` | 8 | X0 |
| `+0x38` | 4 | Output; uninitialized by outer construction |
| `+0x3c` | 4 | `W1 - K32` |

The initialized union is 52 bytes within a minimum 64-byte extent. The widths of X0/X2/X3/X5 are preserved; W1/W4/W6/W7 enter u32 arithmetic. These field operations do not establish final business types or an accepted request language.

Before the outer call, source loads S64 from `0xfffffe000ccc2e88` and stores it into C. The bridge reads S64 from C. It requests a private stack probe with:

```text
A_bytes = ((((S64 * 0x2ec5 + 1) mod 2^64) >> 56) AND 0xf0) + 16
```

A is a multiple of 16 in `[16,256]` bytes. Original `___chkstk_darwin` and `___chkstk_darwin_probe` execute; these fixtures take the short path, performing one byte load into WZR at the local-cell address. The 4096-byte probe loop is retained statically but not exercised by these sizes. The guest's mapped-page touch is distinct from native stack/guard validation.

The local cell initially contains `S64-0x40 mod 2^64`. The modeled inner operation receives the original P in X0 and that local cell in X1. It writes status32 at P+`0x38` and a declared new low32 state R32 into the local cell. Original source reads the low32 state, computes the difference from low32(S64), and writes this u64 byte displacement to C at `0xfffffe000a570ef4`:

```text
D_bytes = 16 * ((R32 - low32(S64)) mod 2^16)
```

D is a multiple of 16 in `[0,1048560]` bytes. The outer source reads C at `0xfffffe000a50e868` and updates SP at `0xfffffe000a50e870`. Its next instruction would read W0 from the updated SP+`0x50`, equivalently original P+`0x38`+D. The model writes only the original record's output field; it does not relocate a frame.

Seventy-two cases derive D=0, consume the modeled output through original source and return status32 with the entry SP restored. Seventy-two derive nonzero D and stop before `0xfffffe000a50e874`, before any relocated output or saved-frame read. Native frame relocation, stack capacity, inner-operation constraints and eventual return are **unknown**. This establishes an actual source mechanism for intra-caller SP movement; association with particular unresolved saved-slot lineages remains unproved.

## Fresh verification, preservation and bounded continuation

| Check | Coverage |
| --- | ---: |
| Fresh cases / original source visits | 192 / 67968 |
| Instruction bytes rechecked | 271872 |
| First-family cases / second-family cases | 48 / 144 |
| Outer source-initialized record bytes summed over cases | 8544 |
| Inner first-family record bytes summed over cases | 1152 |
| Original stack-probe reads | 144 |
| First-family status bytes forwarded by original source | 192 |
| Paired W1-period traces | 12 |
| Unsatisfiable local refutations | 5 |

Cases vary original, zero and declared-noise global fixtures; two aligned stack placements; zero, all-ones and distinct register canaries; two modeled status values; and second-family state deltas 0, 1, `0xffff` and `0x10000`. First-family cases add a W1-period partner. Original mutable-global spans contain nonzero values; zero fixtures are explicitly synthetic.

The verifier freshly recreates all cases, compares complete retained/fresh profiles, independently computes both outer records, replays every source/model write epoch, checks all recorded read bytes and distinguishes source/model provenance. Unknown record holes remain unknown. It verifies target slots, source/model ordering, the source-produced displacement read and stopped boundaries. The five local queries cover shared key64 expressions, W1 halfword periodicity, u32 record roundtrips, stack-displacement projection/bounds and the first bridge's 64-bit affine intermediate. The pinned generator retains each original SMT query and its normalized counterpart. Fresh verification simplifies and solves the original query again and separately solves the normalized file. These are arithmetic identities, not native input/lifetime proofs.

Complexity is `O(B+C*(V+E)+256R)` time/retained space for source bytes B, cases C, visits V, events E and bank rules R, plus solver-dependent proof cost. Each run is limited to 30000 visits. Byte quantities and unsigned fixed widths are explicit; there is no SI conversion.

Set `ANALYSIS_PYTHON`, `Z3_PYTHON_SITE` and `Z3_LIBRARY_DIR` to the local analysis interpreter, Z3 Python package directory and Z3 shared-library directory before running:

```sh
PYTHONPATH="triage_evidence:${Z3_PYTHON_SITE}" \
Z3_LIBRARY_PATH="${Z3_LIBRARY_DIR}" \
"${ANALYSIS_PYTHON}" -P triage_evidence/validate_legacy_stack.py
```

| Impact | Remaining interface question | Discriminating evidence |
| --- | --- | --- |
| High | Does the resolved RW allocator populate cached cell `0xfffffe000ccceab8`? | Establish X20 reaching definitions at allocator-return/free fragments and their original dispatcher states |
| High | Which saved-slot definitions survive real stack-displacement calls? | Resolve actual caller-to-bridge bindings, source-produced state and frame epochs; do not reuse a body-SP translation across an unproved displacement |
| Medium | What do the two inner record operations consume/produce? | Follow their verified entry records and output/state consumers, retaining operation/type and native-reachability unknowns |
| Medium | Which of the six remaining literal modifier candidates are teardown operations? | Exact source bank/slot/argument provenance for each site |
| Low | What is the semantic domain of the first wrapper's narrowed W1? | Establish actual caller definitions and field interpretation; trace periodicity alone is insufficient |

QG1 passes for factual technical analysis. QG2 is LS1-LS9 with dependencies and falsification probes. QG3 passes for this increment's two reclassifications, wrapper/bridge records, original probe and source stack/status effects; the broader objective remains incomplete. QG4 covers fixed widths, byte epochs, bounds, counts and complexity. QG5 separates modifier/target, intermediate/final operand, model/source output, zero/nonzero displacement and private/native effects. QG6 uses primary bytes, exact symbols/chains, exhaustive banks, fresh replay and five local proofs. QG7 is the impact-labeled continuation table. Original inputs, IDBs, external `dump.md` and published predecessor evidence remain preserved.


The [named-wrapper reader lineage](lskd_reader_lineage_report.md) now binds phase `0x6e3`, the four reader-call banks and context byte `+0x174` on a matched source template. It recovers the complete flag-record decoder and the conditional clock-entry gate. Earlier unresolved-root statements describe the earlier bounded increment; the intervening context transform, full route preservation, native epoch and daemon request lineage remain open.


The [context re-encoding and record-return analysis](lskd_context_return_report.md) now closes the selected default/rejection representation path, decodes original W1 values 1,2,4,5 and state144 updates, and maps private statuses to exact stored u32 results through a cached RW release. Actual operation meanings, matched lock ownership, whole-operation cursor preservation and daemon request lineage remain open. Earlier restoration/selector-unknown statements describe the earlier bounded increment.
