# Selector-21 provider-absent release, cleanup and outer status

Subsequent extension: the [wrapper-return report](versioned_wrapper_error_return_report.md) continues this report's final dispatcher frontier through the original epilogues, count-512 copyback, two remaining free requests and translated wrapper return 0xffff5a5e. It separately checks the UserClient embedded-status store/count gate and zero method result. The historical scope below still ends before the epilogue; native destruction, transport/copyout and daemon transaction pairing remain unknown.

The provider-absent selector-21 path now reaches the dispatcher epilogue after release routing and three separate declared free returns. The original source requests parameter, output-stream and input-stream free in that order. Its inner operation status `0xce51ffbe` is replaced by the release selector; the outer record and dispatcher instead receive `0xce515a38`. After the declared parameter-free return, source stores the same H3 address into auxiliary A+`0x270`. No subsequent H3 dereference occurs in these retained intervals. These are source data-flow and ordering results; native object destruction, lock ownership, auxiliary-field validity and final UserClient copyback remain unknown. [ER1-ER7]

```text
provider-absent return -> operation record status 0xce51ffbe
  -> fresh explicit release word E2 -> rebuild release record
  -> original release adapter
       E2 != 0 ----------------> pending IOLockUnlock(E2)
       E2 == 0 -> fresh G2
                    G2 != 0 ---> pending IORWLockUnlock(G2)
                    G2 == 0 ---> original return, no primitive
  -> qualified ordinary unlock returns / no-primitive return
  -> pending free(H3, parameter type view)
       separate void return + logical retirement
  -> A+0x270 = H3; outer C+0x20 = 0xce515a38
  -> overwrite H2[31..0] -> pending free(H2, stream type view)
       separate void return + logical retirement
  -> overwrite H1[31..0] -> pending free(H1, stream type view)
       separate void return + logical retirement
  -> dispatcher W+0 = 0xce515a38 -> STOP before epilogue
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| ER-A1 | Pinned original images and preceding receipts identify the analyzed build/reaching epoch. All joins depend on them. | Rehash dependencies, reproduce every parent interval exactly, and check original source words, fixups and symbols. Native build/task/provider pairing remains unknown. |
| ER-A2 | The preceding distinct H1/H2/H3 objects, coherent guard/auxiliary origins, finite controller/seed fixtures and stable environment-byte premise remain in force. Cleanup/result paths depend on them. | Preserve preceding byte epochs and H3's 31/73 B definition split; supply no allocator fill or fabricated native object. Runtime global state/concurrency remain unknown. |
| ER-A3 | The extended parent is the explicit-NULL/cached-NULL acquisition path with declared cold matching/wait returns and absent service. This particular reaching path depends on those premises. | Freshly reproduce all parent calls and six hardware-admission intervals. No acquisition ownership or native API result is inferred. |
| ER-A4 | E2 and G2 are fresh arbitrary u64 origins qualified only by zero/nonzero predicates. Release routing depends on those predicates. | Retain unqualified frontiers, prove predicate satisfiability and rebuild each uniqueness proposition. Do not equate them with acquisition words or valid lock objects. |
| ER-A5 | Separate ordinary void unlock/free returns preserve callee-saved state/SP, clobber X0-X18 and have no model memory effects. Downstream continuations depend on those contracts. | Retain pending calls and exact arguments separately; supply no scalar success or native reference effect. Actual ownership, destruction, wait/fault behavior and concurrent effects remain unknown. |
| ER-A6 | Logical retirement is analysis bookkeeping, and valid private frames/records plus logical PAC edges describe the source lift. Retirement/return results depend on these premises. | Reject every source read/write intersecting retired spans; distinguish analysis snapshots from execution. Check source returns against call-entry SP and original pointer provenance across journal resets. |
| ER-A7 | Local codec lemmas compose in canonical form, with selector `0xc33` supplied by this reaching caller. Algebraic and finite route results depend on that scope. | Re-run all six UNSAT queries, original route entries and eight reaching cases. No unknown/timeout is accepted as a proof, and aliased table targets retain distinct indices. |

## Fresh release words and record reuse

The [hardware-admission report](versioned_hardware_admission_report.md) stops at `0xfffffe000a69dcd0`, before a new read of startup cell `0xfffffe000cccda78`. This increment supplies arbitrary E2 there; it does not reuse the earlier acquisition origin. The caller copies E2 to K+0 at `0xfffffe000a69dd14` and overwrites K+8 at `0xfffffe000a69dd1c`. The former parameter pointer and operation status no longer define this reused record. [ER2-ER4]

For record address K, all u32 arithmetic is modulo 2^32:

```text
J = (low32(K) XOR 0x734a22b2) * 0x8c229611
release_selector = record.word8 XOR J = phase + 0x8da
retained phase = 0x359; retained release_selector = 0xc33
```

Separate source equations establish the caller's key identity/pack and matching adapter key/decoder. The canonical composition avoids accepting a timeout on the expanded nonlinear expression. Call `0xfffffe000a69dd84` selects adapter `0xfffffe000a5bfc6c`, original slot `0xfffffe000847a830`, IA diversity `0x0f19`. The 12 B minimum record carries E2 and encoded selector, without an acquisition token or saved operation status in those fields. [ER3-ER5]

The adapter updates its own controller `0xfffffe000ccc7748` and shared controller `0xfffffe000ccc32f8`. It stops before pointer-dependent table read `0xfffffe000a5bfe24` until E2 is qualified. Explicit NULL reaches a strict new read of cached cell `0xfffffe000ccceab8` at `0xfffffe000a5bfef8`; a separate arbitrary G2 then stops before table read `0xfffffe000a5bff18`. [ER3-ER5]

| Source condition | Table index | Original target / effect |
| --- | --- | --- |
| E2 != 0 | `0xc36` | `0xfffffe000a5bfe30`, explicit unlock route |
| E2 == 0 | `0xc33` | `0xfffffe000a5bfe94`, fresh cached-cell route |
| E2 == 0, G2 != 0 | `0x7cb` | `0xfffffe000a5bff24`, cached RW-unlock route |
| E2 == 0, G2 == 0 | `0x7fd` | `0xfffffe000a5bff74`, no primitive |
| Ordinary unlock return | `0x53c` | Same `0xfffffe000a5bff74` epilogue |

The two epilogue indices are distinct original entries with the same target. The source equations quantify over every E2/G2 for this retained selector. No concrete non-NULL pointer is chosen. [ER3-ER6]

| Original pending call | Wrapper / original import slot | Exact kernel target / nominal API |
| --- | --- | --- |
| `0xfffffe000a5bfe84` | `0xfffffe000a508de4` / `0xfffffe000847c388` | `0xfffffe000bd054c4`, `_IOLockUnlock` |
| `0xfffffe000a5bff64` | `0xfffffe000a508d9c` / `0xfffffe000847c3c8` | `0xfffffe000bd08174`, `_IORWLockUnlock` |

X0 remains E2 or G2. Native unlocks do not execute. Separate ordinary void returns, and the original NULL/NULL no-primitive return, reach the same parameter-free arguments. The [sample-lock report](sample_lock_report.md) already established isolated adapter roles; this increment supplies the actual provider-absent selector-21 reaching record and caller cleanup. It establishes no matched native acquire/release pair. [ER3-ER4,ER6-ER7]

## Three cleanup requests and auxiliary publication

Every free boundary below targets `0xfffffe000c4ba368`, exact original symbol `_IOFreeTypeImpl`, through original slot `0xfffffe000847a878`, IA diversity `0x4d6a`. Native free bodies remain unexecuted. The source order below extends the NULL/NULL release branch; the two qualified unlock-return branches separately reach the same first free arguments. [ER3-ER4,ER6-ER7]

| Source order | Original call | X0 type view | X1 object / preceding extent |
| --- | --- | --- | --- |
| 1 | `0xfffffe000a69de14` | `0xfffffe000847b3a0` | H3, distinct 104 B parameter object |
| 2 | `0xfffffe000a5a92e4` | `0xfffffe000847bba0` | H2, distinct 32 B output-stream record |
| 3 | Same call site `0xfffffe000a5a92e4` | Same stream type view | H1, distinct 32 B input-stream record |

Separate ordinary void-return premises conservatively clobber X0-X18 and preserve X19-X29/SP. Logical retirement records the corresponding spans without modifying their bytes. The new source lift and independent audit reject every later source read/write intersecting a retired span. Analysis snapshots preserve evidence bytes; they are not target reads or a native mapping/liveness assertion. [ER3-ER4,ER7]

After the declared parameter-free return, original store `0xfffffe000a69b228` publishes X28=H3 into A+`0x270`. At this epoch H3 is logically retired by the model. No subsequent H3 source dereference occurs before the retained dispatcher frontier. This establishes source-call/store ordering and address identity, without establishing native destruction, an actual invalid access, field ownership or whether other source users may consume that cell. Its native lifetime and wider consumer contract remain unknown. [ER3-ER4,ER7]

The caller overwrites every byte of H2 in descending offset order 31..0 before its free request. After the declared H2-free return, the same original caller cleanup machinery overwrites H1 in descending order before requesting its free. These 64 B are stream-record storage; no input-B or output-B payload write is inferred from them. H3 keeps the earlier 31/73 B definition mask in the evidence snapshot, and the 32 B local constant remains a separate private span. No allocator initialization or native memory retirement is supplied. [ER2-ER4,ER7]

## Outer result and continuation provenance

The retained inner hardware-operation status is `0xce51ffbe`. Release record construction overwrites K+8, so that cell no longer contains the operation result. After the declared parameter-free return, source `0xfffffe000a69d834` instead writes raw u32 `0xce515a38` to outer C+`0x20`. After both stream-retirement continuations, source `0xfffffe000a5a7298` writes the same raw word at dispatcher workspace W+0. [ER3-ER5,ER7]

This outer word equals the earlier [NULL-parameter allocation path](versioned_aes_parameters_report.md) result. That is a same-output/different-path observation, not a proof that the business failures are identical. No business status name is assigned. No arbitrary incidental X0 return from the void API models supplies this result; the original source stores carry it. The final boundary is before dispatcher epilogue `0xfffffe000a5a729c`; wrapper resource release, translated wrapper return and UserClient result/copyback remain outside the executed source intervals. [ER2-ER4,ER7]

Two continuation edges use X22 loaded in a preceding retained interval, rather than a load after the current journal reset. The source lift keeps read provenance; the independent verifier requires the original pointer read to occur in the actual preceding interval. [ER3-ER4,ER6-ER7]

| Branch after stream-free return | Original pointer-read PC / slot | Transfer PC / target |
| --- | --- | --- |
| H2 retirement return | `0xfffffe000a5a90fc` / `0xfffffe00084736c8` | `0xfffffe000a5a9320` / `0xfffffe000a5a9098` |
| H1 retirement return | Same read PC / `0xfffffe0008473910` | Same transfer PC / `0xfffffe000a5a7290` |

Both original format-8 entries are authenticated IA, diversity `0xbe01`. The current transfer still checks the actual target/modifier and original pointer chain. Preserved-register provenance across a declared API return supplies the join; a target-only address match is insufficient. [ER3-ER4,ER6-ER7]

## Provenance and verification

| ID | Primary evidence |
| --- | --- |
| ER1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every retained instruction and pointer fixup is original-byte checked. |
| ER2 | Parent hardware-admission receipt SHA256 `bc9265d25e394e365d782d7cbbab9520eb8852b3298bf26dc0486659f347e81e`; exact fresh reaching-prefix and parent-interval equality precedes each new branch. |
| ER3 | [Extractor/source lift](triage_evidence/recover_versioned_error_release.py): fresh release origins, strict retired-span access checks, original caller/adapter source and separate ordinary void returns. |
| ER4 | [Compressed receipt](triage_evidence/versioned_error_release_checks.json.zst): eight parent cases / 96 intervals, 20,856 visits, 17,496 read bytes, 5,408 write bytes, 672 authenticated transfers and 40 source returns. Reproduced preceding prefixes are excluded. |
| ER5 | Six UNSAT source equations / 65 lifted instruction instances: caller key/pack, adapter key/decoder, explicit and cached routes. Canonical composition lemmas are explicit. Ninety-six additional uniqueness propositions have satisfiable predicates. No timeout/unknown is accepted as proof. |
| ER6 | Complete 199-instruction release envelope, fresh original wrappers/stubs/imports/symbols for both unlock APIs, five original route entries, original typed-free compiler function and exact symbol. |
| ER7 | [Publication verifier](triage_evidence/verify_versioned_error_release_publication.py): fresh extraction, independent forked byte epochs and retirement guards, rebuilt uniqueness, 64 B stream overwrites per parent, auxiliary/status stores, 16 historical pointer-origin joins, exact manifest delta, preserved originals and decoded-path hygiene. Associated files suffice; no new IDA access or native API/guest execution occurs. |

The twelve intervals per parent have 45, 111, 24, 43, 28, 8, 19, 43, 43, 1,164, 1,061 and 18 visits, totaling 2,607; `8*2,607=20,856`. They are forked intervals, not 96 complete native requests. Each new interval is bounded at 10,000 steps. Extraction/audit use O(receipt bytes+C*V+I+Q) time/space plus solver cost capped at 30 s/query. Large JSON and the manifest are losslessly roundtripped zstd level-22 archives.

The independent byte audit checks 20,856 original source words, 17,496 read bytes (352 symbolic), 5,408 write bytes (64 symbolic), 672 authenticated edges and 36,480 snapshot bytes. It rebuilds all 96 uniqueness propositions, checks 512 stream-overwrite bytes across eight parents and validates 16 pointer-origin joins against actual preceding reads. The new symbolic memory writes are exactly the eight 8 B E2 copies into release records. [ER4,ER7]

No new Mach message, port/right operation, input/output-B payload write or native daemon-kext transaction occurs in these source intervals. Lock words, record roles, auxiliary pointer, private stream storage, type views and status cells are kernel-side interfaces. Native task/connection/right/build pairing remains unknown. [ER3-ER4,ER7]

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Establish auxiliary A+0x270's complete lifetime contract. | All publishers, overwrites, consumers and dereference guards in matching object epochs; the retained post-free-request pointer store alone establishes no native invalid access. |
| High | Complete dispatcher/wrapper/UserClient result and copyback. | Reaching epilogue, source result translation, remaining wrapper allocations and exact status/size copyback gates. |
| High | Establish matched native lock lifetime. | Stable acquisition/release identities, object types, publication/replacement, synchronization and actual native API effects. |
| High | Continue the warm parameter/hardware route. | Defined copy effects, subsequent parameter reads, readiness/provider/descriptor/buffer coherence and actual provider effects. |
| High | Pair daemon-kext-provider exchange. | Matched native build/task/connection/rights and one transaction epoch; the historical failed-open trace and these source models remain separate. |
| Medium | Map outer-status collapse across failures. | Complete original error producers, caller recognition/translation and externally observable results; equal raw words alone do not identify equal failures. |

- **QG1**: Pass. Factual source/ABI/data-flow/lifetime analysis requires no normative content.
- **QG2**: Pass. ER-A1..ER-A7 list assumptions, dependent results and falsification probes.
- **QG3**: Pass for this increment. Fresh release records/routes, qualified return boundaries, all three object cleanup requests, auxiliary pointer publication, outer status and dispatcher frontier are covered. The full goal remains active.
- **QG4**: Pass. u64 origins, u32 wrapping, 12 B record and 104/32/32 B object extents, reverse 32-byte overwrites and retained/reproduced accounting are explicit.
- **QG5**: Pass. Acquisition/release epochs, aliased targets/distinct indices, operation/release/outer status, pending API/declared return, logical/native retirement, pointer store/dereference and source/native endpoints remain distinct.
- **QG6**: Pass. Original source/slots/symbols, pinned parents, six source equations, nonvacuous uniqueness and independent byte/retirement/provenance checks supply scoped evidence.
- **QG7**: Pass. Auxiliary lifetime, full copyback, native lock identity, warm processing, transaction pairing and status-collapse work is bounded and impact-ranked above.
