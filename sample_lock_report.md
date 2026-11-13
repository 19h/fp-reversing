# Sample processing: lock adapters, record reuse and preparer admission

The two recovered sample-processing contexts contain a conditional synchronization sequence: preparer status controls entry to an acquisition adapter, the coordinator runs after that call returns, and a release adapter follows the coordinator. The acquisition/release adapters select an explicit mutex, a cached RW lock, or no primitive call. Exact original kernel symbols identify all four primitive endpoints.

This refines the earlier "post-initializer" fixture label in [the builder report](sample_caller_report.md): the calls at `0xfffffe000a64b344` and `0xfffffe000a68f50c` resolve to a selector-conditioned acquisition adapter, not a demonstrated record-zeroing operation. The published fixtures and their explicitly declared post-call frames remain unchanged. The lock primitives are never executed by this investigation. Native acquisition, ownership, lock lifetime, complete serialization and valid request reachability remain **unknown**.

[Contracts](triage_evidence/sample_lock_contracts.json), [lock and gate cases](triage_evidence/sample_lock_profiles.json), [error continuations](triage_evidence/sample_lock_return_profiles.json), [distinct fresh replays](triage_evidence/sample_lock_replays.json), [independent checks](triage_evidence/sample_lock_checks.json), [nine local proofs](triage_evidence/sample_lock_proofs.json) and [SDK compile checks](triage_evidence/sample_lock_sdk_checks.json) retain the evidence. The broad objective remains active and incomplete.

```text
preparer record P: carrier pointer at +0x18
  |
  +-- tested null/unknown source word -> status 0xce515bbf
  |                                      -> caller error dispatch [STOP]
  |
  +-- status == 0x31ae0066 [conditional source route]
       -> caller overwrites P+0/P+8 with lock record
       -> acquisition adapter
            explicit pointer E != 0 -> IOLockLock(E)                 [STOP]
            E == 0, cached G != 0   -> IORWLockWrite(G)              [STOP]
            E == 0, G == 0         -> return without primitive
       -> coordinator record constructed in P; carrier at +0x20
       -> sample coordinator at 0xfffffe000a6247a4
       -> snapshot coordinator status into W26 / W25
       -> caller overwrites P+0/P+8 with release record
       -> release adapter
            explicit pointer E != 0 -> IOLockUnlock(E)              [STOP]
            E == 0, cached G != 0   -> IORWLockUnlock(G)             [STOP]
            E == 0, G == 0         -> return without primitive
```

The diagram combines static sequence with independently bounded executions. No single execution here processes an accepted request through the coordinator and native locks. The status-marker route is a source branch condition, not an observed successful preparer result. The two recognized source words stop before their processing bodies.

## Assumption register

| ID | Assumption / boundary | Dependent results | Falsification probe |
| --- | --- | --- | --- |
| SL1 | The pinned KC and normalized kext define the inspected build | All source addresses, symbols and contracts | Verify both hashes, compiler envelopes, original bytes and chained pointers; match a runtime kext independently |
| SL2 | Declared caller frames and callee-saved state describe the two local contexts | Caller-built records, selectors and reconstructed error continuations | Recover complete predecessor paths and SP changes; compare actual call/return state rather than interpreting a finite fixture as native reachability |
| SL3 | Private record/stack bytes and opaque lock-pointer fixtures are accessible in the local guest | All finite execution effects | Check every private read against fixture/source definitions; establish actual native object allocation and lifetime separately |
| SL4 | PAC is abstracted for private control transfer | Adapter calls and returns | Verify original authenticated slots/modifiers; private branch execution does not establish native PAC success |
| SL5 | Cached cell values and explicit pointers are the stated fixtures | Mutex/RW/no-primitive classification | Trace pointer production and actual source epochs. A native matched pair also requires identity and lifetime across acquisition/release, including fresh cached-cell loads |
| SL6 | Installed SDK declarations describe the nominal API signatures | `void` return and pointer parameter interpretation | The arm64e compile checks four signatures; match the original kernel's build/types before claiming SDK build equivalence |
| SL7 | The preparer selector is `0xa07` in the stated builder contexts | Null/word admission classification and caller error continuations | Check original record codecs, actual caller state and downstream selector predicates; other selectors and the complete source language remain unknown |
| SL8 | Copied preparer output records and declared caller frames form a valid local composition | Twenty-four error continuations | Preserve the exact output bytes and their source-write epoch, then establish the actual caller frame/callee-preservation relation before making full-call-stack claims |
| SL9 | Static sequence describes only the recovered call sites and paths | Conditional bracketing of the sample coordinator | Inventory other coordinator/global-descriptor users, exit paths and lock initialization; these cases do not prove universal serialization |

All executions use private Unicorn memory and original-byte checks. No native lock, synchronization, credential, Mach/IOKit, allocation, mapping, provider, crypto or target-file API runs. The source inputs, IDBs, external `dump.md`, and all published predecessors remain preserved. SL1-SL9 delimit all claims below.

## Source and nominal primitive interfaces

| Source | Identity / coverage |
| --- | --- |
| Normalized kext | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Original KC | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Kext functions | Seven original compiler envelopes: two adapters, preparer, four primitive wrappers |
| Caller/source spans | Nine original spans, with both parent compiler hashes independently checked over 72913 instructions |
| Kernel functions | Four exact entry envelopes and nlist aliases; no primitive code executed |
| Selected tables | Ten exhaustive banks, 2560 byte inputs; original chain membership verified |
| SDK primary source | Installed `IOKit/IOLocks.h`, full hash and exact declaration excerpts retained |

| Nominal API | Wrapper | Stub | Original pointer slot | Exact kernel target | Exact additional alias |
| --- | --- | --- | --- | --- | --- |
| `IOLockLock` | `0xfffffe000a508dd4` | `0xfffffe000a69f094` | `0xfffffe000847c378` | `0xfffffe000bd040f0` | `lck_mtx_lock` |
| `IOLockUnlock` | `0xfffffe000a508de4` | `0xfffffe000a69f0b4` | `0xfffffe000847c388` | `0xfffffe000bd054c4` | `lck_mtx_unlock` |
| `IORWLockWrite` | `0xfffffe000a508d94` | `0xfffffe000a69f144` | `0xfffffe000847c3d0` | `0xfffffe000bd0655c` | `lck_rw_lock_exclusive` |
| `IORWLockUnlock` | `0xfffffe000a508d9c` | `0xfffffe000a69f134` | `0xfffffe000847c3c8` | `0xfffffe000bd08174` | `lck_rw_done` |

Each wrapper is `BTI; B stub`. Each stub computes the listed slot, loads X16 and branches through X16 with X17 as modifier. The verifier independently decodes these instructions and compares exact symbols at the original target; no nearest-symbol attribution is used. The export spelling includes a leading underscore in the retained nlist records.

The compile-only probe checks `void (IOLock *)` for both mutex APIs and `void (IORWLock *)` for both RW APIs. Both pointer widths are 8 bytes for `arm64e-apple-macos13.0`. The SDK hash and assembly are retained; SDK equivalence to the original kernel build remains unproved. A void signature does not give a defined scalar status in X0. No inference about blocking duration or successful acquisition follows from these static bindings. SL6 applies.

## Two 12-byte internal lock records

Both adapters read a 64-bit pointer at record `+0` and a 32-bit encoded selector at `+8`. Their minimum inspected record extent is 12 bytes. This internal record is separate from the coordinator's 96-byte record even when the caller reuses the same address P.

Let p32 be low32(P). All arithmetic below is modulo 2^32:

```text
Acquire key KA = (p32 XOR 0x6133a0c8) * 0x84d77373
Acquire selector = record.word8 + KA

Release key KR = (p32 XOR 0x734a22b2) * 0x8c229611
Release selector = record.word8 XOR KR
```

| Adapter compiler envelope | Inspected selector | Explicit-pointer branch | Null-pointer branch |
| --- | --- | --- | --- |
| `0xfffffe000a5b403c..0xfffffe000a5b4314` | `0x729` | Original table index `0x736` -> `0xfffffe000a5b41d8` | Index `0x729` -> `0xfffffe000a5b4228` |
| `0xfffffe000a5bfc6c..0xfffffe000a5bff88` | `0xc33` | Index `0xc36` -> `0xfffffe000a5bfe30` | Index `0xc33` -> `0xfffffe000a5bfe94` |

For nonnull explicit pointer E, the original calls are acquisition `0xfffffe000a5b4218` and release `0xfffffe000a5bfe84`. X0 is E. Execution stops before those calls.

For null E, both adapters recover the same cached pointer cell `0xfffffe000ccceab8` through original pool slot `0xfffffe00084725d0`, whose raw decoded pointer is cell+4. Each adapter loads the cell's current value G. Nonzero G reaches RW write at `0xfffffe000a5b42f0` or RW done at `0xfffffe000a5bff64`, with X0=G. Zero G reaches the original return without a primitive call. The explicit path takes precedence when both fixtures are nonnull.

The cached lock cell is distinct from the provider cell `0xfffffe000ccceb08` and buffer-descriptor cell `0xfffffe000ccceb10`. Common page placement does not establish object or lifetime equivalence. Neither adapter retains an acquisition token in the inspected input record. Matched native acquisition/release therefore requires additional evidence about pointer stability and ownership. SL5 and SL9 apply.

## Caller-built records and conditional sequence

| Context | State fixture | Preparer selector | Acquisition selector | Release selector |
| --- | --- | --- | --- | --- |
| First | W24=`0x510` | W24+`0x4f7` = `0xa07` | W24+`0x219` = `0x729` | W24+`0x723` = `0xc33` |
| Second | W21=`0x753` | W21+`0x2b4` = `0xa07` | W21-`0x2a` = `0x729` | W21+`0x4e0` = `0xc33` |

Six local SMT queries equate the original mixed Boolean/arithmetic address-key expressions to the compact codecs: two preparer, two acquisition and two release expressions. Three further queries prove that the selector expressions agree for all u32 W when the second context state is W+`0x243`. This algebra does not prove the contexts' original entry reachability.

| Boundary | First caller | Second caller |
| --- | --- | --- |
| Preparer | `0xfffffe000a64b21c` | `0xfffffe000a68f418` |
| Acquisition adapter | `0xfffffe000a64b344` | `0xfffffe000a68f50c` |
| Coordinator | `0xfffffe000a64b498` | `0xfffffe000a68f6b0` |
| Status snapshot | `0xfffffe000a64b49c`, W26 <- record+8 | `0xfffffe000a68f6b4`, W25 <- record+8 |
| Release adapter | `0xfffffe000a64b55c` | `0xfffffe000a68f760` |

The first context obtains a lock-pointer-cell address from frame `SP+0x880`; it then loads E from that cell. The second uses frame `SP+0x3c8` in the same two-load pattern. Their ultimate context types and actual lock objects remain unknown. The caller reloads the cell for release. Native correspondence cannot be inferred from equal synthetic pointer values alone.

Seventy-two fresh caller fragments construct both fields of the 12-byte lock record with original instructions, covering 864 source-written bytes. Other record bytes remain unchanged within each fragment. Twenty-four standalone adapter cases independently exercise the same selector/pointer paths. Across all 96 lock cases, 48 stop before explicit mutex calls, 24 before cached RW calls and 24 return without a primitive.

For the 48 release caller cases, the coordinator-status fixture is loaded before record `+8` is overwritten with the release selector. W26 in the first context and W25 in the second retain the status through the inspected adapter prefix. Both success-marker and error-status fixtures are checked. The first caller subsequently compares saved W26 with `0x31ae0066`; complete post-release native register preservation and later second-caller status use remain outside these stopped cases.

The first carrier candidate remains FP-`0xe8`; the second is carried in X28 in the earlier builder evidence. The lock-call identity resolves an intervening role. It does not by itself establish every carrier-byte write, native callee preservation or the complete H[0] domain. The [carrier-control report](carrier_control_report.md) continues to delimit those questions.

## Preparer entry and source-written error delivery

For selector `0xa07`, original table indices route null source X21 to `0xfffffe000a62173c` and nonnull source to `0xfffffe000a62135c`. The nonnull branch loads a little-endian u32 at `0xfffffe000a621364` and tests two literal words:

| Source state | Original next location | Tested observation |
| --- | --- | --- |
| Null source | `0xfffffe000a62173c` | Writes `0xce515bbf` to preparer-record `+0x24`, then returns |
| Word `0x85283019` | `0xfffffe000a621720` | Stops before continuation processing |
| Word `0x42059342` | `0xfffffe000a621388` | Stops before continuation processing |
| Tested other words 0 and `0xffffffff` | `0xfffffe000a62173c` | Writes `0xce515bbf` to record `+0x24`, then returns |

These literals are internal source-word discriminators; they are not established Mach message IDs, public wire tags or a complete acceptance language. The recognized cases have a zero status field only because their fixture began with zero and execution stops before a status write. That zero is not a successful processing result.

Twenty fresh entry cases cover four record placements and these five source conditions. The original bounds helper executes with declared valid private limits. Sixteen nonnull cases read exactly the first source word before stopping or returning; all 2080 carrier bytes remain unchanged. Twelve cases return the original source-written error status.

Each error record is copied byte-for-byte into two reconstructed caller continuations, producing 24 additional original prefixes. They select these destinations before executing their final authenticated branch:

| Caller | Status equals `0x31ae0066` | Table index | Destination |
| --- | --- | --- | --- |
| First | False, including observed `0xce515bbf` | `0x510` | `0xfffffe000a651758` |
| First | True, static marker route | `0xccc` | `0xfffffe000a64b284`, acquisition-record builder |
| Second | False, including observed `0xce515bbf` | `0x753` | `0xfffffe000a68f770` |
| Second | True, static marker route | `0xe43` | `0xfffffe000a68f448`, acquisition-record builder |

Thus the tested preparer failures select caller error paths before acquisition. The compositions preserve actual preparer-output bytes but use declared caller callee-saved state and frames; SL2 and SL8 prevent treating them as native full-call-stack traces.

## Verification and reproducibility

Independent fresh execution matches all 140 retained cases: 96 lock/caller cases, 20 preparer gates and 24 reconstructed error continuations. They cover 20654 original instruction visits. Checks cover 12288 lock-record bytes, 864 caller-written record bytes, 48 status snapshots and 2080 unchanged carrier bytes. Ten exhaustive banks, four exact primitive bindings, original caller routes, source/compiler hashes, nine SMT queries and four SDK void signatures pass.

```sh
PYTHONPATH=triage_evidence python3 -P triage_evidence/recover_sample_lock.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/probe_sample_lock.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/probe_sample_lock_return.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/prove_sample_lock.py
PYTHONPATH=triage_evidence python3 -P triage_evidence/validate_sample_lock.py
```

These commands require the pinned project dependencies and configured Z3 Python/native bindings, and regenerate this increment's outputs. Preserve the published files and use a distinct output copy for later work. Source extraction costs O(B+I+256R+chain work); finite replay costs O(C*(B+V+E)) for C cases, B mapped source bytes, V visits and E retained events. Solver/compilation cost is separate. The adapter's bounded decision work gives no upper bound on native lock wait time.

## Bounded continuation

| Impact | Further question | Evidence needed |
| --- | --- | --- |
| High | Determine which native objects the two contexts use as explicit locks | Source reaching definitions for the pointer cells, allocation/init/destruction sites and actual reference lifetime |
| High | Establish synchronization of shared descriptor/provider state across all users | Complete caller/global-user census, pointer identity across acquisition/release and all relevant exit paths |
| High | Complete preparer-to-coordinator carrier provenance | Follow recognized continuations only through source-defined state; retain carrier pointer and byte epochs across the recovered lock calls |
| Medium | Recover cached RW-lock initialization and lifetime | Identify producers of `0xfffffe000ccceab8` and ownership/order constraints |
| Medium | Resolve later second-caller status propagation and alternate selectors | Follow original post-release branches and distinguish other dispatcher contexts |
| Medium | Link static sequence to the daemon's actual UserClient transaction | Match runtime kext and calling-task identities; the supplied RAX trace still ends after failed open |

## Scoped quality gates

| Gate | Result / evidence |
| --- | --- |
| QG1 | Pass: factual technical analysis; no normative premise required |
| QG2 | Pass: SL1-SL9 include dependencies and falsification probes |
| QG3 | Pass for this increment: lock/record/preparer-gate/caller-status interfaces covered; full objective remains active |
| QG4 | Pass: u32 arithmetic, 8-byte pointers, 12-byte minimum records, byte footprints and bounded complexity specified |
| QG5 | Pass: acquisition role refines earlier fixture label; void return/status snapshot, literal recognition/acceptance, source sequence/native serialization and record reuse/object identity separated |
| QG6 | Pass: exact source, compiler envelopes, chained pointers, aliases, SDK compile, 140 fresh cases and nine local proofs |
| QG7 | Pass: impact-labeled bounded continuation table |

[Source identity](triage_evidence/sample_lock_source_identity.json), [baseline preservation](triage_evidence/sample_lock_preservation.json) and [machine-readable quality gates](triage_evidence/sample_lock_quality_gates.json) retain delivery checks. No new incoming/outgoing Mach port or emission site is established by these kernel-internal interfaces.

The selected startup path can populate the cached fallback cell from IOLockAlloc. The allocation family is established for that path. The runtime value supplied to either RW call remains unknown. [Cached lock publication and API types](cached_lock_origin_report.md).

The [selector-21 lock/parameter handoff](versioned_lock_handoff_report.md) supplies a reaching caller-built request 0x729 for the acquisition adapter. Arbitrary explicit/cached words retain strict source frontiers; qualified non-NULL branches select the original primitives. Separate declared ordinary void returns and the original NULL/NULL return reach the actual parameter consumer and stop before _initKernelAESHW. This extends caller/record lineage without establishing native object validity, acquisition or a matching startup lifetime.
