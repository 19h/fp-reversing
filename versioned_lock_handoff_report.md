# Selector-21 lock routing and AES-parameter handoff

The selector-21 path now joins its source-built lock record to the acquisition adapter and then to the actual AES-parameter consumer. A non-NULL explicit word selects `IOLockLock`; an explicit NULL selects a separately read cached cell, which selects `IORWLockWrite` or no primitive. Native lock calls remain pending. Separate declared void-return continuations, and the no-primitive path, reach the same parameter adapter and inner prefix, stopping before `_initKernelAESHW`. The inner reads only the previously defined parameter fields at +`0x28` and +`0x24`; all 73 undefined parameter bytes remain unread. [LH1-LH7]

```text
source-built request 0x729, explicit word E from startup cell
  -> original acquisition adapter
       E != 0 --------------------> pending IOLockLock(E)
       E == 0 -> strict cached-cell read
                   -> separate arbitrary cached word G
                        G != 0 ---> pending IORWLockWrite(G)
                        G == 0 ---> original return, no primitive

pending native calls: separate declared ordinary void returns only
  -> original adapter return
  -> reuse record: parameters H3, input D, output D, operation 0x352
  -> stack adapter 0xfffffe000a688ebc / original small probe
  -> inner 0xfffffe000a687ee0
  -> parameter +0x28/+0x24 admission -> STOP before _initKernelAESHW
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| LH-A1 | Pinned original images, preceding receipts and compiler captures identify the source build/epochs. All joins depend on them. | Rehash dependencies, reproduce every preceding prefix exactly, and compare original words/chains. Native daemon/kext build pairing remains unknown. |
| LH-A2 | The earlier distinct 104 B allocation and arbitrary coherent guard/auxiliary origins remain premises. Parameter and frame lineage depend on them. | Preserve the preceding receipts exactly; supply no allocation initialization and retain the 31/73 B source-defined split. Native allocator behavior remains unknown. |
| LH-A3 | Valid private frames/records/objects and abstract authenticated source calls describe the lift. Probe/source-return results depend on these premises. | Original call stack, slot/modifier bindings, return-SP equality, discarded-read epochs and strict unknown reads. Native PAC, faults and probe readability remain unknown. |
| LH-A4 | E and G remain arbitrary u64 origins, qualified only by stated zero/nonzero predicates. Conditional lock routing depends on those predicates. | Keep unqualified symbolic frontiers; prove every resolved symbolic address unique under satisfiable predicates. Non-NULL does not imply a valid native lock or object type. |
| LH-A5 | Separate primitive-return continuations assume an ordinary void return preserving callee-saved registers/SP, with no model memory effects. Their downstream handoff depends on that contract. | Clobber X0-X18 independently, supply no scalar success result, retain pending-call evidence, and compare against the no-primitive source path. Native blocking, acquisition, memory effects and ownership remain unknown. |
| LH-A6 | Mutable controller cells and the adapter seed have the retained finite original-image/reaching-write fixtures. Finite instruction paths/frame sizes depend on them. | Audit every read against its byte epoch; retain original nonzero seed separately from its later publication. Actual runtime values and concurrency remain unknown. |
| LH-A7 | Earlier sample-lock, cached-lock-producer and stack-adapter artifacts provide static context. Context joins depend on their hashes. | Rebind current original slots/symbols and recheck source equations. No native lifecycle, lock-family compatibility or historical source-epoch join is inferred. |
| LH-A8 | Objects/frames/globals have the stated valid extents; D intentionally aliases input and output, while record/header/parameter spans remain disjoint. Data-flow equations depend on these premises. | Exact forked byte epochs, source-defined masks and original field codecs. Pointer stores and local bounds do not establish mapping capacity, native ownership or eventual copy safety. |

## Source-built lock record and conditional primitives

The [parameter report](versioned_aes_parameters_report.md) supplies K=W+`0x160`, request `0x729` and arbitrary explicit word E from `0xfffffe000cccda78`. This increment reproduces that exact reaching state before entering call `0xfffffe000a69db54`, target `0xfffffe000a5b403c`. The inspected acquisition record has minimum extent 12 B: u64 at K+0 and encoded u32 at K+8. [LH2-LH4]

The original adapter updates controller `0xfffffe000ccc3698` and shared controller `0xfffffe000ccc32f8`, then decodes the request. With E unqualified it stops before the pointer-dependent table read at `0xfffffe000a5b41bc`. A source equation over every u64 E gives: [LH3-LH5]

| Predicate | Table index | Original target |
| --- | --- | --- |
| E != 0 | `0x736` | `0xfffffe000a5b41d8` |
| E == 0 | `0x729` | `0xfffffe000a5b4228` |

The explicit-NULL branch stops before loading cached cell `0xfffffe000ccceab8` at `0xfffffe000a5b4274`. No file-backed runtime value is supplied. A separate arbitrary word G reaches another strict symbolic table read at `0xfffffe000a5b4294`. Its source equation gives: [LH3-LH5]

| Predicate, with E == 0 | Table index | Original target / effect |
| --- | --- | --- |
| G != 0 | `0x545` | `0xfffffe000a5b42a0`, then pending RW primitive |
| G == 0 | `0x555` | `0xfffffe000a5b4300`, original epilogue without a primitive |

No concrete value is chosen for either origin. Sixty-four retained uniqueness queries establish selected concrete addresses under the branch predicates. The independent verifier separately checks predicate satisfiability, replays each stored query and rebuilds each expression/value uniqueness proposition. This prevents an inconsistent predicate from making a route appear proved. [LH4-LH5,LH7]

| Original call | Source wrapper | Original import slot | Exact kernel target / nominal API |
| --- | --- | --- | --- |
| `0xfffffe000a5b4218` | `0xfffffe000a508dd4` | `0xfffffe000847c378` | `0xfffffe000bd040f0`, `_IOLockLock` |
| `0xfffffe000a5b42f0` | `0xfffffe000a508d94` | `0xfffffe000847c3d0` | `0xfffffe000bd0655c`, `_IORWLockWrite` |

The wrapper bodies and import stubs are freshly recaptured; exact nlist symbols and original chained pointers bind the nominal APIs. The pending X0 is respectively the unchanged arbitrary E or G. Neither native primitive, wrapper or stub executes in these continuations. [LH3-LH6]

The [earlier sample-lock report](sample_lock_report.md) already recovered this routing from isolated contexts. The new evidence supplies its reaching selector-21 record and subsequent parameter handoff. The [cached-lock-origin report](cached_lock_origin_report.md) separately records a selected `IOLockAlloc` publisher of the fallback cell and its RW consumers. This remains a static lock-family/lifetime question; no cross-family native call, compatible object identity or failure outcome is established here. [LH6-LH7]

## Three qualified return paths and record reuse

The no-primitive branch reaches original `RETAB` at `0xfffffe000a5b4310` without an API return premise. The explicit and cached primitive branches remain pending at their call sites; separate continuations declare an ordinary void return to `0xfffffe000a5b421c` or `0xfffffe000a5b42f4`. They assign arbitrary X0-X18 and no memory effects. No defined X0 status or native lock ownership is supplied. All three source paths return to `0xfffffe000a69db58` with the call-entry SP restored. [LH3-LH5,LH7]

The caller reuses K for an operation record. Let D=W+`0x118` be the preceding 32 B table-derived local constant and H3 the distinct 104 B parameters. All u32 operations below are modulo 2^32: [LH3-LH5]

```text
J = (low32(K) XOR 0xdb228b70) * 0x82f37eeb
operation32 = record.word18 + J
count32     = record.word1c - J - 0x46d8b869
```

| Record field | New reaching definition |
| --- | --- |
| K+0, u64 | H3, stored at `0xfffffe000a69dbb0` |
| K+8, u32 | Earlier encoded lock request remains; no operation-status store yet |
| K+`0x10`, u64 | D, input pointer |
| K+`0x18`, u32 | Encoded operation; canonical value phase-`0x43a`=`0x352` |
| K+`0x1c`, u32 | Encoded count; canonical value 32 B |
| K+`0x20`, u64 | Same D, output pointer |

The minimum new inspected record extent is 40 B. Its input/output pointers intentionally alias; this does not prove a completed in-place AES operation. K+8 still has the old four encoded bytes, `b1303be3`, in the retained placements. Those bytes are not a demonstrated operation success/error status. The status producer later in the inner routine has not executed. [LH3-LH5,LH7]

## Actual parameter consumer and hardware-preparation frontier

Call `0xfffffe000a69dc14` selects stack adapter `0xfffffe000a688ebc` through original slot `0xfffffe000847a978`, IA diversity `0x7787`. X0=K and X1 points to the caller's inner-SP+`0x4d0` cell. The caller initializes that cell with captured seed S before the call; it is a seed input at this epoch, not an already exported stack delta. [LH3-LH6]

The adapter's original controller updates include `0xfffffe000ccc3348`, `0xfffffe000ccc32f8` and the published-seed cell `0xfffffe000ccc30c8`. The retained S is the original-image word `0xe39588de7c77caf1`; its actual runtime value remains unknown. Its source update is `P=S*0x2e95+1 mod 2^64`, and private reservation `A=((P>>56)&0xf0)+16` is 96 B in these fixtures. This agrees with the earlier [stack-delta ABI](core_stack_delta_abi_report.md), whose arbitrary-S domain is 16..256 B. The original small probe executes as a source lift, including its discarded WZR byte read at the future header address. Readability remains LH-A3; no byte is chosen for an undefined discarded read. [LH3-LH7]

With F=adapter-entry SP, fixed reservation is 64 B, header H=F-160 B, and inner body SP=H-448 B. The adapter writes S-`0x100` to H, then call `0xfffffe000a6890b4` selects inner `0xfffffe000a687ee0`, original slot `0xfffffe000847a798`, IA diversity `0x6a0f`. That inner updates its own controller `0xfffffe000ccc7740` and shared controller `0xfffffe000ccc32f8`, retains the coherent guard, and adds `0x100` back to H. The source header equation quantifies over arbitrary S. Its current restoration does not prove final preservation or zero exported delta. [LH3-LH5]

The matching inner key and field decoder recover H3, D, D and operation `0x352`. Two original reads consume previously defined parameter fields: [LH3-LH5,LH7]

| Original read | H3 offset / width | Retained value | Selected source check |
| --- | --- | --- | --- |
| `0xfffffe000a6880d4` | `0x28`, 4 B | `0x1000`=4,096 | Unsigned <=8,192; index `0x3a8` |
| `0xfffffe000a688100` | `0x24`, 4 B | 0 | Offset 0 with normalized count 32; index `0xbea` |

The pointer admission index is `0xba9`; original targets for these three retained checks are respectively `0xfffffe000a6880d0`, `0xfffffe000a6880f8` and `0xfffffe000a688168`. The eight original route entries in the receipt retain these mappings and the lock/error entries separately. The source span predicate is universal over the u32 field at H3+`0x28`; the count-admission certificate uses this retained offset/count pair and does not claim a complete all-input language. [LH5-LH6]

All three qualified return contexts then make 327 source visits each and stop before `_initKernelAESHW`, call `0xfffffe000a6881dc`, target `0xfffffe000a508030`, original slot `0xfffffe000847a920`, IA diversity `0x327a`. Their job-prefix instruction/read/write journals, final boundary, header and seed/delta cell agree exactly for each parent case. This equality is conditional on the explicit primitive-return premises on two paths. It is not native synchronization equivalence. [LH3-LH5,LH7]

The [inner-write frontier](inner_write_frontier_report.md) previously identified this initializer and later copy/fill/hardware calls through local source cuts. This increment supplies a reaching selector-21 path to the initializer. The body is not entered: provider discovery, hardware flags, IV/key reads, global-buffer staging, native AES effects, later record status and final delta remain unknown for this composed path. All 104 H3 bytes retain their preceding mask: 31 defined, 73 undefined. Only 8 B, all previously defined, are read here. [LH2-LH7]

No new Mach message, port/right operation, output-B write or native daemon-kext transaction occurs in these source intervals. The lock words, operation record, nested header and seed/delta cell are private interfaces. Exact native task/connection/right/build pairing remains unknown. [LH3-LH4,LH7]

## Provenance and verification

| ID | Primary evidence |
| --- | --- |
| LH1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every retained instruction word and pointer fixup is original-byte checked. |
| LH2 | Parent parameter receipt SHA256 `4f38b356c30c213c0040f9c536c4bfa19115090c932726f351e015fe38d99968`; exact fresh parent equality precedes each new fork. |
| LH3 | [Extractor/source lift](triage_evidence/recover_versioned_lock_handoff.py): strict origins, qualified unique addresses, original call stack, explicit void returns, original probe and parameter consumer prefix. |
| LH4 | [Compressed receipt](triage_evidence/versioned_lock_handoff_checks.json.zst): eight parent cases / 88 retained intervals, 10,584 visits, 12,416 read bytes, 7,584 write bytes, 200 authenticated transfers and 48 source returns. Repeated reaching-prefix reproduction is excluded from these counts. |
| LH5 | Eight UNSAT source equations / 103 lifted instruction instances, plus 64 conditional uniqueness propositions with satisfiable premises. Matching record/count checks compose the already proved pack/key lemmas in canonical form. No unknown/timeout is accepted as a proof. |
| LH6 | Two fresh original primitive wrapper/stub/import/symbol bindings, eight original route pointers and hashed earlier sample-lock, cached-lock, stack-adapter and inner-frontier check artifacts. Earlier large startup/native models are not rerun or joined. |
| LH7 | [Publication verifier](triage_evidence/verify_versioned_lock_handoff_publication.py): fresh extraction/proofs, independent forked byte epochs, rebuilt uniqueness queries, parameter/read/status/header checks, exact publication delta, preserved originals and decoded-path hygiene. Associated files suffice; no new IDA access, native API or guest execution occurs. |

The eight intervals per parent before job extension comprise 342 visits; the three job prefixes add `3*327=981`, giving `8*(342+981)=10,584` retained visits. The 88 intervals are not 88 complete requests. Each new interval is bounded at 10,000 steps; extraction/audit use O(receipt bytes+C*V+I+Q) time/space plus solver cost capped at 30 s/query. Source captures contain the complete 182-instruction acquisition envelope, 136-instruction job adapter and 1,015-instruction inner body; only retained visits establish reaching execution. Large JSON and the manifest are published as losslessly roundtripped zstd level-22 archives.

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Continue this reaching hardware initializer path. | Strict runtime flag/provider/descriptor origins and original source return/effect contracts; an old cold-init model is not a matching live epoch. |
| High | Determine the complete parameter definition/read lifecycle. | Subsequent reads of H3+2, +0x12, +0x39 and other fields, intervening writes/reset, and actual allocation initialization. |
| High | Establish native lock identity, type and lifecycle. | Matching publication, replacement, acquire/release and object-type epochs for explicit and cached cells; nonzero words are insufficient. |
| High | Close parameter processing, release and selector-21 copyback. | Actual remaining callees, record-status producer, final header/delta, release routing and UserClient gating. |
| High | Establish native daemon-kext exchange pairing. | Matched build/task/connection/rights and one actual transaction epoch; current source models and the historical failed-open trace remain separate. |
| Medium | Track record and output-cell role changes across all users. | Reaching stores distinguishing lock request, operation status, seed input and delta output; static offsets alone do not determine one invariant type. |

- **QG1**: Pass. Factual source, ABI, lifetime and control-flow analysis requires no normative content.
- **QG2**: Pass. LH-A1..LH-A8 give assumptions, dependent results and falsification probes.
- **QG3**: Pass for this increment. Reaching lock routes, conditional return contracts, record reuse, actual parameter admission and hardware-preparation frontier are covered. The full goal remains active.
- **QG4**: Pass. u64 predicates, modular u32 keys/counts, 12/40 B record extents, 64+96+448 B frame decomposition and retained/reproduced accounting are explicit.
- **QG5**: Pass. Pending calls/declared returns, NULL/non-NULL/valid objects, stale encoded request/operation status, seed/delta, initial/final header restoration and static/native epochs remain distinct.
- **QG6**: Pass. Pinned originals/parents, source equations, nonvacuous uniqueness, original bindings and independent byte epochs supply scoped provenance.
- **QG7**: Pass. Remaining hardware, parameter, lock, cleanup/copyback, native pairing and reused-state work is bounded and impact-ranked above.

The subsequent [hardware-admission report](versioned_hardware_admission_report.md) extends the exact no-primitive reaching prefix into the initializer. It retains an arbitrary readiness byte, matching/wait return contracts, actual warm scratch fill and defined-parameter copy demand. Provider absence reaches record status 0xce51ffbe, actual zero adapter delta and a fresh startup-lock read; provider presence stops after publication and before an unknown receiver dereference. Native service readiness, hardware effects and final copyback remain unknown.
