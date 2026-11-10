# IOKit group construction, publication and RW API composition

The original `_IOLibInit` constructs a static group bearing the name `IOKit` and publishes its address to `0xfffffe000cb52628`. That is the group cell consumed by `IORWLockAlloc` and `IORWLockFree` in the [preceding lifecycle analysis](rw_lifecycle_report.md). This resolves the source producer of their group argument. FairPlay's cached fallback RW pointer at `0xfffffe000ccceab8` is a separate object cell; its allocation/publication lineage remains **unknown**.

[Original contracts and census](triage_evidence/iolib_group_contracts.json), [retained private profiles](triage_evidence/iolib_group_profiles.json), [distinct fresh replays](triage_evidence/iolib_group_replays.json), [independent checks](triage_evidence/iolib_group_checks.json) and [two local proofs](triage_evidence/iolib_group_proofs.json) contain the evidence. Addresses describe this build. No native startup, registry, resource allocation, synchronization, heap, provider, crypto or Mach/IOKit operation executes. PAC instructions are abstracted in the private engine. The broad investigation remains active and incomplete.

```text
unnamed startup envelope: BL _IOLibInit; BL _OSlibkernInit
                              |
                              v
_IOLibInit -- ready.bit0=1 --> return
    |
    +-- static group constructor("IOKit", flags)
    |     +-- original clearing / string copy / flag-dependent words
    |     +-- phase >= 4: STOP before registry synchronization
    |     +-- phase < 4: modeled registration, original return
    +-- publish group address ----------------> cell CB52628
    +-- modeled setup / configuration               |
    +-- modeled mutex allocation                    +--> IORWLockAlloc
    +-- original mutex/list/ready publication        |      (group, NULL)
                                                    +--> IORWLockFree
                                                           (pointer, group)

FairPlay cached RW cell CCCEAB8 <-- allocation/store lineage UNKNOWN
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| GI1 | The pinned original KC defines the analyzed build | All addresses, exact symbols and instructions | Rehash the complete KC, compare every function envelope and original data span; runtime identity is separate |
| GI2 | Private mapped memory and abstracted PAC support conditional instruction semantics | All replay results | Compare original bytes at every visited instruction, reject unmodeled calls/system/atomic operations, validate real PAC and reachability separately |
| GI3 | Four declared backend models return and preserve callee-saved registers | Complete cold wrapper and publication order after each model | Clobber caller-saved registers/NZCV; establish actual registration/setup/allocation results independently |
| GI4 | Phase fixtures 0/3 represent the inspected early branch; 4/0xffffffff represent stopped late branches | Early compositions and late-prefix checks | Recover actual startup phase transitions; no late-phase registry locking is emulated |
| GI5 | Flags are tested at 0/0x10000/0x20000/0x30000 and registry tokens at 0/1/0x1234/0xffff | Group word model and bounded header proof | Expand flag/token domains and establish native admissibility; the constructor's raw store uses full low32 return OR flags |
| GI6 | Two environment fixtures are argument/byte-flow probes | Setup ABI and copied vector | File-zero inputs and declared nonzero inputs do not establish valid native setup objects |
| GI7 | The 328-byte written extent is accessible private storage | Complete source-written group reconstruction | Inspect actual runtime group allocation/type; 328 bytes is a minimum written extent, not a `sizeof` claim |
| GI8 | Reference discovery uses an explicit ADRP/immediate-window grammar | Bounded 86-row reference census and sole writer within it | Expand aliases, indexed/writeback forms, other segments and windows beyond 11 instructions; do not infer globally unique publication |
| GI9 | RW API prefixes stop before their core functions | Source-produced group argument composition | Resolve runtime group validity, core allocation/free behavior and FairPlay cached-cell lineage independently |

GI1-GI9 qualify the corresponding results throughout. The fresh verifier reconstructs byte writes independently of the compact group model, checks instruction/event epochs and compares complete fresh runs with retained runs. Replay agreement does not independently prove the execution engine or backend models.

## Primary source and exact identity

| Source / coverage | Verified identity |
| --- | --- |
| Original kernel collection | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized FairPlayIOKit dependency | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Current source extraction | Twelve complete compiler envelopes, eight original data spans, exact-address nlist results and bounded reference census |
| Identity record | [Fresh source identity](triage_evidence/iolib_group_source_identity.json) |

| Entry / cell | Address | Exact nlist name / established role |
| --- | --- | --- |
| IOKit initialization | `0xfffffe000c4b91a8` | `_IOLibInit` |
| Static group constructor | `0xfffffe000bd037e0` | Exact name unknown; source role established below |
| Static group storage G | `0xfffffe000cb524a8` | Exact name unknown |
| Published group cell | `0xfffffe000cb52628` | Exact name unknown; contains G after the source store |
| Registration target | `0xfffffe000bceb1d0` | Exact name unknown; backend not executed |
| Mutex allocator | `0xfffffe000bd03ec4` | `_lck_mtx_alloc_init`; backend modeled |
| RW allocation API | `0xfffffe000c4bb6e4` | `_IORWLockAlloc` |
| RW free API | `0xfffffe000c4bb780` | `_IORWLockFree` |
| Following startup call | `0xfffffe000c47c364` | `_OSlibkernInit` |

Names are exact-address matches, never nearest-symbol assignments. The unnamed caller envelope `0xfffffe000c4bcc70..0xfffffe000c4bced0` directly calls `_IOLibInit` at `0xfffffe000c4bcca8`. Its next instruction, `0xfffffe000c4bccac`, calls `_OSlibkernInit`. This establishes local source ordering, not completed native boot or a guessed name for the parent.

## Group constructor and partial layout

`_IOLibInit` calls the unnamed constructor with X0=G, X1=`0xfffffe00070da7ab` (`IOKit\0`) and W2 loaded from `0xfffffe0007e635c8`. The constructor initializes storage, requests registration, then returns G in X0 on the early branch. The caller stores X0 to the group cell at `0xfffffe000c4b91e8`.

| Group offset | Width / extent, bytes | Source behavior |
| --- | ---: | --- |
| `+0` | 4 | Store 1 |
| `+4` | 4 | Initially zero; after registration, store `low32(return) OR flags32` |
| `+0x18` | Capacity 64 | Copy `IOKit\0` with original `strlcpy`; six bytes copied |
| `+0x60,+0x78,+0xa8,+0xc0,+0xf0,+0x108,+0x120,+0x138` | 4 each | Increment initialized word when flags bit16 is set |
| `+0x90,+0xd8` | 4 each | Increment initialized word when flags bit17 is set |
| `[+4,+0x148)` | 324 | Original clears before subsequent updates |

The union of source writes covers all `[G,G+0x148)`, or 328 distinct bytes. The group cell lies at G+`0x180`, outside that extent. Offset roles beyond the shown operations, native group size and native counter semantics are **unknown**.

The original `strlcpy` at `0xfffffe000be3e3c4`, `strlen` at `0xfffffe000bc9db70` and shared `memcpy`/`memmove` entry at `0xfffffe000c647f10` execute inside the private engine. The string copy is not an API-effect model. All 144 initial-state cases check the six helper-written bytes, including the terminator.

The constructor reads phase word `0xfffffe0007f8b5f0` and compares its unsigned value with 4. Cases below 4 reach the registration call at `0xfffffe000bd0392c` with `(X0=0xfffffe000ca90368, W1=0xffff, X2=G)`. This backend is modeled. Cases at or above 4 stop before `0xfffffe000bd03900`, before the subsequent register/atomic synchronization path. Their group is initialized but not published; no registry call or lock operation executes.

## Wrapper resource ABI and commit sequence

Ready byte `0xfffffe000cba36b0` bit0 controls the initialization guard. All original file inputs listed in the contracts are zero except the name literal. File contents describe initial image bytes, not runtime validity.

| Source call / store | Target / destination | Established operands / transfer |
| --- | --- | --- |
| `0xfffffe000c4b91e8` | Group cell `0xfffffe000cb52628` | Store returned G, 8 bytes |
| `0xfffffe000c4b9210` | `0xfffffe000bdc1800`, exact name unknown | X0=`*[0xfffffe0007f860a8]`, X1=first u64 at `0xfffffe0007f36928`, W2=`0xc0000000`, W3=`0x10`, W4=`0x03004081` |
| `0xfffffe000c4b921c` | `0xfffffe000cb52610` | Store opaque modeled first-setup return, 8 bytes |
| `0xfffffe000c4b9224` | `0xfffffe000bddc5bc`, exact name unknown | X0=first-setup return, W1=`0x60000000`; incidental return register is not consumed as status |
| `0xfffffe000c4b922c` | `0xfffffe000cb52618` | Copy 16 bytes from `0xfffffe0007f36928` |
| `0xfffffe000c4b9238` | `_lck_mtx_alloc_init` | X0=published group, X1=0 |
| `0xfffffe000c4b9240` | `0xfffffe000cba36b8` | Store opaque modeled mutex return, 8 bytes |
| `0xfffffe000c4b924c` | `0xfffffe000cba36c0` | Store two self-pointers, 16 bytes |
| `0xfffffe000c4b9254` | Ready byte `0xfffffe000cba36b0` | Store 1 after all preceding operations |

The setup names, object types, flag meanings and native failure contracts are **unknown**. Their models expose only return/clobber effects needed to inspect caller data flow. In particular, committing ready=1 after modeled calls does not establish successful native initialization or a failure-safe transaction.

Each completed cold run continues in the same guest memory through a second `_IOLibInit` invocation and both original RW API prefixes. The second invocation reads the source-written ready byte=1 and returns without a backend model or global write. `IORWLockAlloc` reads the source-published G and reaches its core boundary with `(X0=G,X1=0)`. `IORWLockFree` reads that same publication and reaches its core boundary with `(X0=declared_pointer,X1=G)`. Read epochs follow the publication epoch. No allocation, deallocation, core synchronization or native lifetime follows from those stopped prefixes.

## Bounded reference census

The extractor scans 2540432 aligned words in the original kernel `__TEXT_EXEC` (10161728 bytes). It finds 1106 ADRP instructions for the cell's page. It inspects at most the next 11 instructions while the base remains unchanged, stopping at any control transfer; only immediate nonindexed/nonwriteback load/store overlaps count.

| Result within this grammar | Count |
| --- | ---: |
| Exact cell-reference instructions | 86 |
| Reads | 85 |
| Writes | 1 |
| Direct B/BL callers of `_IOLibInit` in scanned segment | 1 |

The writer is `0xfffffe000c4b91e8`. Each row retains the source instruction, compiler envelope, base register, direction and width. Other aliases/forms/segments are excluded. These counts do not establish a complete writer set or whole-program startup reachability.

## Verification and reproducibility

| Fresh check | Coverage |
| --- | ---: |
| Initial states | 144 |
| Complete cold wrappers with modeled backend calls | 128 |
| Late-phase stopped constructor prefixes | 16 |
| Warm repeats from source-produced ready=1 | 128 |
| RW API prefixes from source-published G | 256 |
| Total source stages / source visits | 528 / 32432 |
| Original instruction bytes rechecked | 129728 |
| Distinct source-written group bytes summed over cases | 47232 |
| Original helper-written name bytes summed over cases | 864 |
| Modeled backend-call boundaries | 512 |
| Unsatisfiable local refutations | 2 |

The 128 early cases vary four flag combinations, four registry-return tokens, two fills, two phase values and two environment fixtures: `4*4*2*2*2=128`. Sixteen late cases vary four flags, two late phases and two fills. The nonzero environment fixture deliberately changes both the pointer operand and 16-byte copied input. Neither environment fixture is asserted native-admissible.

The two solver queries prove the 8-bit ready guard's bit0/odd partition and a **bounded** u32 header relation: a zero-extended 16-bit token OR flags confined to bits16/17 preserves token/flags and leaves bit31 clear. The latter is not a proof about arbitrary actual registration returns or flag words.

The verifier freshly recreates all cases, compares entire profiles, independently models group bytes, reconstructs all global snapshots from ordered source writes, checks source/model event order and original-byte identity, and reruns both SMT files. It rejects undefined private-stack reads and records all unexecuted boundaries. Time/retained space is `O(B+C*(V+E)+W)` for pinned source B, cases C, visits V, events E and census words W, plus solver-dependent proof cost. Every stage is bounded at 30000 source visits. Widths are bytes and unsigned fixed-width integers; no SI conversion is involved.

```sh
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_iolib_group.py
```

## Bounded continuation and quality gates

| Impact | Remaining question | Discriminating next evidence |
| --- | --- | --- |
| High | Does the resolved FairPlay allocator return populate cached cell `0xfffffe000ccceab8`? | Establish X20 reaching definitions at shared store/free fragments; distinguish generic lock group from allocated RW object |
| High | Which native initialization phase supplies a valid group registration/resource context? | Recover phase transitions and exact backend contracts; separately validate actual boot ordering and results |
| Medium | Are there group publication paths outside the immediate-reference grammar? | Expand alias/data-reference analysis and cross-segment coverage while retaining bounded negative evidence |
| Medium | What native mutex/group lifetime and ordering surround the sample coordinator? | Compose verified startup/group/object identity and caller lifetime; warm replay alone proves no serialization |
| Low | Can the unnamed startup/helper roles receive exact source names? | Exact build-matched symbols or primary source correspondence; do not promote nearby symbols |

QG1 passes for factual technical analysis. QG2 is GI1-GI9 with dependency and falsification probes. QG3 passes for this increment's group construction/publication, resource ABI, startup ordering, census and RW-prefix composition; the broader objective remains incomplete. QG4 passes for fixed widths, byte epochs, counts and bounded complexity. QG5 separates generic group/cached object, image/runtime state, early/stopped phase and modeled/native effects. QG6 uses rechecked primary bytes/metadata, fresh replay and two local proofs. QG7 is the impact-labeled continuation table. [Machine-readable quality gates](triage_evidence/iolib_group_quality_gates.json) and [baseline preservation](triage_evidence/iolib_group_preservation.json) record delivery checks.

The selected startup publisher binds the FairPlay cached cell to a mutex allocation on that path. The shared group operand does not distinguish mutex and RW allocation views. [Cached lock publication and API types](cached_lock_origin_report.md).
