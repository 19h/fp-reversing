# RW allocation/free contracts and bounded kext lifecycle candidates

The original `IORWLockAlloc` and `IORWLockFree` wrappers share an IOKit group-pointer cell and delegate to `lck_rw_alloc_init` / `lck_rw_free`. The allocation site is named `site.lck_rw_old_t`, with a metadata size word of 16 bytes. Original initialization writes 16 bytes; a composed free-validation prefix accepts those private initialized representations and updates their header before group accounting.

The investigation also resolves one kext allocation call and one free/clear fragment, while excluding a same-modifier internal helper. Their association with cached fallback cell `0xfffffe000ccceab8` remains **unknown**. Neither the shared store's X20 destination nor the cleanup fragment's X20 cell has a complete reaching definition. This extends [the sample-lock report](sample_lock_report.md) without asserting cached-cell publication, native ownership or lifecycle completion. The broad objective remains active and incomplete.

[Contracts](triage_evidence/rw_lifecycle_contracts.json), [retained prefixes](triage_evidence/rw_lifecycle_profiles.json), [distinct fresh replays](triage_evidence/rw_lifecycle_replays.json), [independent checks](triage_evidence/rw_lifecycle_checks.json), [four local proofs](triage_evidence/rw_lifecycle_proofs.json) and [SDK checks](triage_evidence/rw_lifecycle_sdk_checks.json) retain the evidence.

```text
kext allocator wrapper -> IORWLockAlloc
  -> load group pointer; attributes = NULL
  -> lck_rw_alloc_init(group, attributes)
  -> typed allocation backend(view, flags32=4)             [NOT EXECUTED]
  -> original 16-byte initialization in private storage
  -> group accounting                                    [STOP]

kext free wrapper -> IORWLockFree(pointer)
  -> load group pointer
  -> lck_rw_free(pointer, group)
  -> original validation/header updates in private storage
  -> group-accounting helper                              [STOP]
  -> typed free backend(view, pointer)                     [STATIC ONLY]

resolved kext return -> shared STR X0,[X20] candidate
                       X20 -> cached fallback cell         [UNPROVED]
```

The initialization cases begin after an unexecuted allocation backend with declared nonnull private storage. The diagram does not describe a completed native allocation/free transaction. No heap, synchronization, group-accounting, provider, crypto, credential, Mach/IOKit or target-file operation executes natively. All source inputs, IDBs, external `dump.md` and published predecessors remain preserved.

## Assumption register

| ID | Assumption / scope | Dependent results | Falsification probe |
| --- | --- | --- | --- |
| RL1 | The pinned KC and normalized image define this build | All code addresses, metadata and bindings | Verify complete hashes, compiler envelopes, raw bytes and original chain membership; independently match runtime identity |
| RL2 | Normalized pointer data represents the checked original chained pointers | Legacy bank/call targets and candidate continuations | Verify selected original slots and decoded targets; private normalized-pointer execution does not establish hardware PAC success |
| RL3 | A nonnull private object provides 16 accessible bytes after the declared allocation boundary | Initializer/free-validation compositions | Check source-written byte epochs; establish actual runtime allocation, zone capacity, tagging and object lifetime independently |
| RL4 | Attribute fixtures represent local u32 operands; NULL uses the original default word | Flag construction and normal initialized-header checks | Exhaust relevant combinations, vary irrelevant bits and prove the u32 relation; native admissible attributes/types remain separate |
| RL5 | Group-pointer fixtures describe only API-prefix argument formation | Twelve API prefixes and shared-cell ABI | Recover runtime group initialization and identity; a zero file-image cell or a fixture value is not a valid native group |
| RL6 | PAC is abstracted; two stopped kext calls have declared return/clobber models | Allocation-return and free/clear candidates | Preserve call modifiers/slots; verify actual predecessor state, callee preservation and native return behavior before claiming reachability |
| RL7 | Installed SDK declarations describe the nominal public API | Pointer return, void free and 8-byte pointer interpretation | Compile both signatures; SDK equivalence to the original kernel build is unproved |
| RL8 | The finite state-domain and first-five-instruction filter are candidate discovery bounds | Sixty-four store-candidate states | Expand beyond the specified 2648 values/filter, resolve all predecessor state and destination definitions; no full CFG or native input language follows |
| RL9 | The cleanup wrapper returns in the declared model | Source clear after a modeled free call | Establish actual pointer validity and return path; the model does not perform deallocation, group accounting or a native free |

RL1-RL9 qualify all results. The source-prefixed API names below identify exact symbols or installed declarations; they do not attest live objects.

## Primary source and exact interfaces

| Source | Verified identity / coverage |
| --- | --- |
| Normalized kext | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original KC | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Kext source | Four compiler envelopes, four selected spans and four exhaustive banks (1024 byte inputs) |
| Kernel source | Seven original function envelopes, typed-site bytes, two original pointer bindings and three constant spans |
| Primary SDK source | Installed `IOKit/IOLocks.h`, full hash and declaration excerpt retained; compile only |

| Public operation | Kext wrapper | Import stub | Original slot | Kernel wrapper | Exact core target |
| --- | --- | --- | --- | --- | --- |
| `IORWLockAlloc()` | `0xfffffe000a508d7c` | `0xfffffe000a69f104` | `0xfffffe000847c3b0` | `0xfffffe000c4bb6e4` | `lck_rw_alloc_init`, `0xfffffe000bd06180` |
| `IORWLockFree(pointer)` | `0xfffffe000a508d84` | `0xfffffe000a69f114` | `0xfffffe000847c3b8` | `0xfffffe000c4bb780` | `lck_rw_free`, `0xfffffe000bd062b8` |

The allocator kernel wrapper loads X0 from cell `0xfffffe000cb52628`, sets X1=0 and tail-branches to the core allocator. The free kernel wrapper preserves X0, loads X1 from the same cell and tail-branches to the core free function. No exact nlist name for this group cell is present in the checked source; "IOKit group cell" is a role description inferred from these wrappers.

Twelve fresh original API prefixes vary three group fixtures and two input-X0 values. They stop before core entry and preserve full64 argument values. The allocator prefix overwrites input X0 and sets NULL attributes. The free prefix forwards its pointer unchanged and supplies the group in X1. A zero group fixture is a width/argument probe, not evidence of a native-admissible call.

The SDK compile checks `IORWLock *(*)(void)` and `void (*)(IORWLock *)`, with pointer width 8 bytes. It does not establish the public type's build-matched object layout. The original typed-site name includes **`old_t`**; it must not be replaced with an assumed current private definition.

## Typed allocation and runtime prerequisites

The core allocator calls `0xfffffe000bcfefc8` at `0xfffffe000bd061a4` with X0=view `0xfffffe0007e42bd8` and W1=4. This backend's exact symbol name is unknown. Flag value 4 is retained without assigning an unverified flag name.

| View field / source | Original value |
| --- | --- |
| View address | `0xfffffe0007e42bd8` |
| Pointer at view `+0x10` | Original chain -> `0xfffffe000704d290`, string `site.lck_rw_old_t` |
| Word at view `+0x28` | `0x6a`, retained as metadata flags |
| Word at view `+0x2c` | 16, retained as metadata size word |
| View first 16 bytes | Zero in the file image |
| Group cell `0xfffffe000cb52628` | Zero in the file image |

The backend loads its first two operands from the view, can consult per-thread state, and delegates to another allocator. It is not executed. Thus the metadata size word and 16-byte initialization do not establish actual runtime zone capacity, initialized view links or a native object address. The zero initial links/group cell make runtime initialization a specific remaining prerequisite, not an initialized-object snapshot.

The core free path uses the same view and pointer in a tail branch to `0xfffffe000bd7a4b8` after group-accounting return. This backend's exact name is also unknown. Neither backend nor its native heap effect runs in the profiles. No allocation-failure behavior is inferred; all initialization storage fixtures are nonnull.

## Original 16-byte initialization

After the unexecuted backend returns X0=object, the source selects attribute pointer X20 or default `0xfffffe0007e63610` when X20 is NULL. The original default u32 word is zero. For the loaded attribute word A:

```text
F16 = ((A & 0x10000) == 0 ? 0x02 : 0)
    | ((A & 0x20000) == 0 ? 0x40 : 0)
```

| Object offset | Width, bytes | Original initialized value |
| --- | ---: | --- |
| `+0x00` | 8 | Constant bytes `00 00 00 33 00 00 00 00`, from `0xfffffe000700dd08` |
| `+0x08` | 2 | Zero |
| `+0x0a` | 2 | F16, little-endian |
| `+0x0c` | 4 | Zero |

The initialized extent is exactly `[0,16)`: 8+2+2+4=16 bytes. NULL/default attributes produce F16=`0x42`. Sixty-eight original prefixes vary default/explicit attributes, all four relevant bit combinations, four irrelevant-bit patterns, two private placements and two initial fills. The verifier reconstructs all 1088 source-written bytes from ordered writes, including stores whose value equals the initial fill.

Three bit-vector checks establish the flag domain `{0,2,0x40,0x42}`, equivalence of outputs exactly when the two relevant attribute bits agree, and compatibility of all produced word8 values with the inspected free-prefix tests. These are arithmetic/layout properties, not native allocation or lock-state admissibility proofs.

Initialization stops at `0xfffffe000bd061f0`, before group accounting. The remaining static source computes group+`0x14`, requests an atomic increment there and conditionally performs another operation when group word `+4` has bit31 set. The group representation and counter semantics are not established beyond these source operations. No atomic or group-accounting instruction executes in these profiles.

## Composed free-validation prefix

Each initialized 16-byte output is copied exactly into an independent private free-validation case. Original source checks the header/type and state words, then clears the high type byte of word0 and writes marker `0xdddddead` at `+8`. All 68 constructed cases reach the boundary before `BL 0xfffffe000bd03ad0` at `0xfffffe000bd06320`.

| Boundary property | Verified result |
| --- | --- |
| Input object bytes | Exact output from the linked initializer case |
| Object bytes `+0x00..+0x03` | Source-written zero for these initialized cases |
| Object bytes `+0x08..+0x0b` | Source-written little-endian `ad de dd dd` |
| Other eight object bytes | Preserved |
| Helper X0 | Declared group pointer |
| Helper X1 | Group pointer +`0x14` |
| Actual helper/free/heap action | Unexecuted |

The verifier accounts for 544 source-written header bytes and the exact helper arguments. This establishes compatibility between the original initializer and the inspected normal free-validation prefix. It does not establish lock release, a live object, native safe destruction, group ownership, full deallocation or invalid-input behavior. The accounting helper has no exact nlist name in the inspected source.

## Kext allocation/free candidates and modifier limits

A whole-text aligned-word census finds eleven shift-zero `MOVZ X17,imm16` sites for modifiers `0x9f59` and `0x9d3a`. It excludes other registers, loads, multi-instruction modifier constructions and indirect import paths. It is not a complete native call census.

| Call site | Resolved target / status |
| --- | --- |
| `0xfffffe000a531028`, modifier `0x9f59` | Exhaustive bank -> original slot `0xfffffe0008471698` -> `0xfffffe000a508d7c`, allocator wrapper |
| `0xfffffe000a50d254`, same modifier | Exhaustive bank -> `0xfffffe000a560468`, internal helper; excluded as allocator evidence |
| `0xfffffe000a5793b8`, modifier `0x9d3a` | Exhaustive bank -> original slot `0xfffffe0008471518` -> `0xfffffe000a508d84`, free wrapper |
| Eight remaining sites with `0x9d3a` | Unresolved candidates retained individually with raw bytes and compiler-envelope context |

The allocator belongs to the legacy table family: table base `0xfffffe000846c420`, pointer-pool base `0xfffffe00084716e0`. Its constant-bank expression uses key `0xca`, additive `0x996`, constant `0xb9` and index `0xa4f`. The early internal-helper call uses a different expression despite its equal modifier. Neither a modifier nor a compiler-envelope label uniquely identifies a callee.

The allocation return branch computes, for state S:

```text
W24 = (S + 0xa0) XOR 0xb025e4d5
nonnull_index = S XOR (W24 + 0x4fda12ff)    [all u32]
```

The bounded enumeration considers S in `[0,2648)`, corresponding to the chosen table-to-pool address interval. It retains in-range code targets whose first five instructions contain the specified X0 store/move pattern. Sixty-four states select index `0x8b4` and target `0xfffffe000a56d3c0`, which contains `STR X0,[X20]` at `0xfffffe000a56d3c8`. A local proof establishes that, within this domain, index `0x8b4` occurs exactly for `(S & 0xfffffe61) == 0x860`.

One hundred twenty-eight private prefixes execute the original target lookup and return branch for those states and two obfuscation-word patterns. The allocator call is modeled as returning an opaque nonnull private pointer; X1-X17 and NZCV are clobbered. Execution stops before the final authenticated branch. The matching target does not establish a reaching definition of X20, actual state reachability, or publication into the cached cell.

Eight cleanup-fragment cases stop after the original `STR XZR,[X20]` at `0xfffffe000a5793bc`. Their incoming pointer-cell relation is a declared private fixture, and the resolved free wrapper is modeled as returning. The cell is cleared in all cases despite two incidental X0 return-register fixtures and caller-register clobbers. Native deallocation and the actual X20 cell remain unproved. RL6, RL8 and RL9 apply.

## Verification and reproducibility

Independent fresh execution matches 284 retained cases and 7838 source visits, with 31352 source instruction bytes checked. Counts are 68 initializers, 68 linked free-validation prefixes, 12 API argument prefixes, 128 allocation candidates and eight cleanup candidates. Four original banks, four local proofs, two exact API bindings, one typed site, the eleven-site modifier census and two SDK signatures pass verification.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rw_lifecycle.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_rw_lifecycle.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_rw_lifecycle.py
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rw_lifecycle.py
```

These regenerate this increment's outputs; preserve published artifacts and use a distinct output copy for later work. Source extraction/census costs O(B+I+256R+chain work). Replay costs O(C*(B+V+E)) for C cases, B mapped bytes, V source visits and E events. Solver/compiler cost is separate. No native latency, allocation capacity or synchronization bound is inferred.

## Bounded continuation

| Impact | Further question | Evidence needed |
| --- | --- | --- |
| High | Establish cached fallback-cell creation and teardown | Original reaching definitions for both X20 destinations, real dispatcher states and exact association with `0xfffffe000ccceab8` |
| High | Establish runtime typed-view and group initialization | Producers of the zero file-image links/group cell, native build identity and actual runtime values |
| High | Connect allocation/free to lock ownership and shared descriptor use | Complete caller paths, object identity/lifetime and all acquisition/release users |
| Medium | Classify the eight remaining modifier candidates | Original bank/pointer/frame provenance; equal modifiers remain insufficient |
| Medium | Recover group-accounting and heap-domain contracts | Exact source ABI/lifetime analysis of the stopped helper and two unexecuted backends |
| Medium | Expand the candidate-state search | Complete predecessor/CFG analysis beyond the finite interval and first-five-instruction filter |

## Scoped quality gates

| Gate | Result / evidence |
| --- | --- |
| QG1 | Pass: factual technical analysis; no normative premise required |
| QG2 | Pass: RL1-RL9 include dependencies and falsification probes |
| QG3 | Pass for this increment: allocation/free/layout/API-prefix/candidate interfaces covered; cached publication and full objective remain unproved |
| QG4 | Pass: u32/u64 widths, 16-byte writes, metadata/runtime capacity separation, byte epochs and finite complexity specified |
| QG5 | Pass: `old_t` site/current SDK, modifier identity/callee identity, metadata/runtime links, initialized representation/live object and generic store/cached-cell publication separated |
| QG6 | Pass: original functions/slots/metadata/constants, complete bounded census, 284 fresh cases, four proofs and two SDK signatures |
| QG7 | Pass: impact-labeled continuation table |

[Source identity](triage_evidence/rw_lifecycle_source_identity.json), [preservation](triage_evidence/rw_lifecycle_preservation.json) and [machine-readable quality gates](triage_evidence/rw_lifecycle_quality_gates.json) retain final delivery checks. No new incoming/outgoing Mach port, right transfer or native IPC event is established by these kernel-internal interfaces.

A separate provider-startup path publishes an IOLockAlloc result into the cached cell. The X20 destination for the RW allocation candidate in this report remains open. [Cached lock publication and API types](cached_lock_origin_report.md).
