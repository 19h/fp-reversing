# Selector-21 hardware readiness, discovery and parameter demand

The reaching selector-21 path now enters `_initKernelAESHW`. Its first external dependency is an arbitrary runtime readiness byte at `0xfffffe000ccceb00`. Bit 0 selects an immediate zero return or kernel service discovery. The warm continuation zero-fills a 168 B private scratch region and reaches a pending 16 B copy from H3+`0x12`; those source bytes are already defined zeroes. Under separate matching/wait return premises, provider absence returns low32 `0xffffffd8`, writes operation-record status `0xce51ffbe`, exports zero adapter delta and reaches a fresh startup-lock-cell read. A non-NULL service word is published before a receiver dereference whose address remains unknown. Native service discovery, provider validity and hardware effects remain unknown. [HA1-HA7]

```text
selector-21 -> no-primitive lock branch -> operation adapter/inner
  -> initKernelAESHW -> strict readiness-byte read
       separate arbitrary byte F, then qualify bit 0
         bit 0 set   -> return 0 -> original 168 B scratch fill
                                -> pending copy: scratch <- H3+0x12, 16 B
         bit 0 clear -> pending serviceMatching("IOAESAccelerator", NULL)
                         separate arbitrary matching result M
                      -> pending waitForService(M, timeout={0 s, 1 ns})
                         separate arbitrary service result S
                           S == 0 -> return low32 -40
                                  -> record status -> adapter delta 0
                                  -> strict fresh startup-lock-cell read
                           S != 0 -> publish S -> STOP before [S] read
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| HA-A1 | Pinned original images and prior receipts identify the analyzed build and reaching source epoch. All joins depend on them. | Rehash images/dependencies; reproduce preceding source intervals exactly and check original instruction words and chained slots. Actual daemon/kext/provider build pairing remains unknown. |
| HA-A2 | The preceding distinct 104 B object, coherent guard/auxiliary origins, valid frames and finite controller/seed fixtures remain premises. Parameter/return lineage depends on them. | Preserve every prior byte epoch and the 31/73 B definition split; supply no allocator initialization. Runtime mutable state and concurrency remain unknown. |
| HA-A3 | Only the preceding explicit-NULL/cached-NULL no-primitive branch is extended here. This reaching path needs no native lock-return premise. | Reproduce all five parent intervals through the actual initializer frontier. Other lock routes remain covered by the parent report's separate contracts, without asserting a native synchronization join. |
| HA-A4 | F is an arbitrary coherent u8, qualified only by its bit-0 predicate. Warm/cold source paths depend on those predicates. | Retain strict pre-read and unqualified branch frontiers; prove every selected symbolic value unique under satisfiable predicates. A set bit does not imply valid provider/descriptor/buffer globals. |
| HA-A5 | Separate ordinary API-return continuations preserve callee-saved state/SP, clobber X1-X18 and supply arbitrary X0 words M or S, with no model memory effects. Discovery suffixes depend on this contract. | Keep pending calls and return premises separately; choose no concrete dictionary/service pointer, fabricate no object/vtable, and stop on an unknown receiver address. Native side effects, object lifetime and lookup outcomes remain unknown. |
| HA-A6 | Original pure-fill instructions and ordinary source returns describe private byte effects, with logical authenticated edges. Fill/return results depend on valid extents and abstract PAC/fault premises. | Audit source-defined reads, every fill store, disjoint H3/scratch ranges and equal call/return SP. The pending copy executes no imported memory effect. Native PAC, faults and provider execution remain unknown. |
| HA-A7 | Earlier cold-init and inner-write artifacts supply static context rather than a matching native epoch. Context joins depend on their hashes. | Rebind current original call/stub/import/symbol chains and compare exact addresses. Do not carry old fabricated dictionary/provider objects or startup globals into this reaching path. |

## Readiness and warm admission

The [lock/parameter handoff](versioned_lock_handoff_report.md) provides the actual call at `0xfffffe000a6881dc`, target `0xfffffe000a508030`, original slot `0xfffffe000847a920`, IA diversity `0x327a`. This increment reproduces the complete preceding selector-21 prefix and the original no-primitive branch before extending it. The initializer reserves 48 B and stops after eight visits, before reading byte `0xfffffe000ccceb00` at `0xfffffe000a50804c`. No file-backed zero or initialized provider is substituted. [HA2-HA4]

A separate arbitrary F read makes one source visit and stops at `TBZ W8,#0` at `0xfffffe000a508050`. The upper seven bits remain arbitrary in both qualified continuations. [HA3-HA5]

| Predicate | Original route | Retained effect |
| --- | --- | --- |
| `(F & 1) != 0` | `0xfffffe000a508054` | W19=0; ordinary initializer epilogue returns X0=0 |
| `(F & 1) == 0` | `0xfffffe000a50805c` | Build timeout; request matching dictionary |

The warm route reads no provider/descriptor/buffer cell in its initializer prefix. Thus its zero result is source admission through a readiness bit, not a proof that a native provider or buffer exists. It reaches pending fill call `0xfffffe000a68826c`, target `0xfffffe000a687d64`, with X0=inner-SP+`0x98`, X1=0, X2=168 B. A separate extension enters the original pure-fill helper; its stores define exactly those 168 B, and its ordinary source return restores call-entry SP. [HA3-HA4,HA7]

The following actual parameter read is H3+1/u8=1 at `0xfffffe000a688278`. Its original branch and bank-selected route reach the pending copy below; no undefined H3 byte is read. [HA3-HA4]

| Pending call | Target | Arguments / established demand |
| --- | --- | --- |
| `0xfffffe000a68858c` | Copy adapter `0xfffffe000a508cf4`, previously bound to `_kernel_memcpy` | X0=inner-FP-`0x70`=inner-SP+`0x140`; X1=H3+`0x12`; X2=16 B |

Every demanded source byte in H3[`0x12`,`0x22`) was defined zero by the earlier parameter fill. Relative to inner SP, the demanded destination occupies [`0x140`,`0x150`), immediately after the 168 B scratch span [`0x98`,`0x140`) and before the callee-save area at `0x160`. The independent audit checks the source definitions and precise extents separately. The imported copy remains pending, so no destination effect or successful copy is claimed. The H3 mask remains 31 defined and 73 undefined bytes. [HA2-HA4,HA7]

## Cold service interface and timeout

| Original call | Stub / original import slot | Matching kernel target / exact nominal API |
| --- | --- | --- |
| `0xfffffe000a508070` | `0xfffffe000a69f254` / `0xfffffe000847c458` | `0xfffffe000c4ece88`, `IOService::serviceMatching(char const *, OSDictionary *)` |
| `0xfffffe000a508078` | `0xfffffe000a69f244` / `0xfffffe000847c450` | `0xfffffe000c4eb5d8`, `IOService::waitForService(OSDictionary *, mach_timespec *)` |

Fresh stub bytes, original format-8 import-chain entries and exact nlist symbols bind these calls. Matching receives X0=`0xfffffe000790ba3c`, original `IOAESAccelerator` string, and X1=0. The literal is a matching class name; a native returned receiver class remains unknown. [HA1,HA3-HA6]

The cold source stores u64 `0x0000000100000000` at initializer-SP+8, giving bytes `00 00 00 00 01 00 00 00`. The [earlier cold-init report](kext_cold_init_report.md) independently binds the 8 B `mach_timespec_t` layout and kernel duration calculation. Here the reaching source and byte epochs reproduce the argument: [HA3-HA7]

```text
tv_sec = 0; tv_nsec = 1
duration = uint32(tv_sec)*1,000,000,000 ns + int32(tv_nsec)*1 ns
         = 1 ns = 10^-9 s
```

This is the requested duration, without a native elapsed-time or timeout-enforcement measurement. A separate ordinary matching return supplies arbitrary M in X0 and clobbers X1-X18. The next single source instruction sets X1=&timeout; the original waiter receives M unchanged. There is no intervening matching-result NULL check in this two-call sequence. No matching dictionary memory or native acceptance of arbitrary M is inferred. [HA3-HA4,HA6-HA7]

A separate waiter return supplies arbitrary S and clobbers X1-X18. Without a predicate, the continuation stops before `CBZ X0` at `0xfffffe000a50807c`, executing zero new instructions. [HA3-HA5]

## Provider absence and publication frontier

| Predicate | Retained source effect | Stop / limit |
| --- | --- | --- |
| S == 0 | Initializer writes W19=`0xffffffd8`, returns X0=`0x00000000ffffffd8`; signed32 interpretation is -40 | Original consumer error path and operation adapter return; fresh lock-cell read remains pending |
| S != 0 | Store S at provider cell `0xfffffe000ccceb08`, instruction `0xfffffe000a508084` | Stop before `LDR X16,[X0]` at `0xfffffe000a508088`; S remains arbitrary and no receiver/vtable byte is read |

The non-NULL continuation makes three source visits. Publication precedes the receiver vptr load and subsequent nominal retain call; it does not prove a valid object, completed retain, descriptor allocation, buffer mapping or readiness publication. The global cell's eight source-defined bytes remain symbolic extracts of S. No fabricated object body or address is supplied. [HA3-HA4,HA6-HA7]

The consumer transforms the initializer's low32 return R before updating its status accumulator. For arbitrary u32 R, ACC and phase PH, original instructions `0xfffffe000a6881e4..0xfffffe000a68820c` establish: [HA3-HA5]

```text
T = R - (0x635c00cc & (R << 1))       modulo 2^32
new_ACC = ACC + T                    modulo 2^32
index = PH XOR (0x540 if T == 0 else 0)
(T == 0) iff (R == 0)
```

This proof covers every u32 return and rejects any nonzero value that might otherwise appear to satisfy the obfuscated zero gate. It gives no business error name. In the retained absence branch, original instruction `0xfffffe000a6887e4` writes raw operation-record word K+8=`0xce51ffbe`. This replaces the previous encoded lock-request bytes. The later caller compares against `0x31ae0066`; the absent-provider value does not match. [HA3-HA5,HA7]

The inner and stack adapter both return with call-entry SP restored. The nested header retains S_seed, and the caller's seed/delta output cell contains zero. The caller applies that actual zero delta and reaches `0xfffffe000a69dcd0`, a new read of startup cell `0xfffffe000cccda78`. This read is strict: the earlier arbitrary lock-word origin is not reused across the intervening operation/API-return epochs. No post-operation release route, final selector result or UserClient copyback executes here. The zero delta is established only for this retained provider-absent path, not all inner operations. [HA3-HA4,HA7]

## Provenance and verification

| ID | Primary evidence |
| --- | --- |
| HA1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Every retained source word and pointer fixup is original-byte checked. |
| HA2 | Parent handoff receipt SHA256 `98802a68b25b7e78a3f39bd34328f22a1b9c569a09812d04ee2462e181c0eeeb`; fresh equality covers the complete reaching prefix and five parent intervals before each extension. |
| HA3 | [Extractor/source lift](triage_evidence/recover_versioned_hardware_admission.py): strict arbitrary readiness, separate API returns, source fill and return/status/delta propagation. |
| HA4 | [Compressed receipt](triage_evidence/versioned_hardware_admission_checks.json.zst): eight parent cases / 72 bounded intervals, 1,936 visits, 3,184 read bytes, 2,080 write bytes, 48 authenticated transfers and 40 source returns. Reproduced preceding prefixes are excluded from these totals. |
| HA5 | Three UNSAT source equations / 18 lifted instruction instances: timeout/matching arguments, universal return-gate/status accumulator and absence-return width. Thirty-two additional uniqueness propositions resolve selected values under satisfiable predicates. |
| HA6 | Complete freshly recaptured 96-instruction initializer, two original stub/import/symbol bindings, matching literal, and hashed earlier cold-init/inner-write checks. Earlier CPU/API/native models are not joined into this reaching state. |
| HA7 | [Publication verifier](triage_evidence/verify_versioned_hardware_admission_publication.py): fresh extraction/proofs, independent forked byte epochs, rebuilt uniqueness, field-demand/fill/timeout/publication/return checks, exact manifest delta, preserved originals and decoded-path hygiene. Associated files suffice; no new IDA access, native API or guest execution occurs. |

Per parent, the nine retained interval lengths are 8, 1, 43, 113, 6, 1, 0, 67 and 3 visits: total 242, giving `8*242=1,936`. These are intervals across forks, not 72 complete requests. Each interval is bounded at 10,000 steps; extraction/audit use O(receipt bytes+C*V+I+Q) time/space plus solver cost capped at 30 s/query. Large JSON and the manifest are published as losslessly roundtripped zstd level-22 archives.

The independent byte audit checks 1,936 original source words, 3,184 read bytes (136 symbolic), 2,080 write bytes (64 symbolic), 48 authenticated edges and 24,192 snapshot bytes. It rebuilds all 32 uniqueness propositions under satisfiable predicates. The only new symbolic memory publication is the eight 8 B service-word copies; neither API-return premise initializes a dictionary or receiver body. [HA4,HA7]

No new Mach message, right operation, output-B write or native daemon-kext exchange occurs in these retained source intervals. Readiness/provider cells, service-discovery arguments, private scratch, parameter demand, status and delta are kernel-side interfaces. Pending service APIs are not executed; their transitive native behavior remains unknown. [HA3-HA4,HA7]

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Continue warm parameter processing after the demanded copy. | Original copy binding/contract, reaching 16 defined bytes, subsequent parameter reads and global-buffer origins; preserve strict undefined-byte frontiers. |
| High | Establish complete cold provider initialization. | Matching service object/type/vptr, retain/reference contract, runtime kernel_task/PAGE_SHIFT, descriptor preparation and mapped-buffer publication in one epoch. |
| High | Establish readiness coherence and concurrency. | All readiness/provider/descriptor/buffer writers, reset/failure paths and actual synchronization; a set readiness bit alone is insufficient. |
| High | Complete the provider-absent release and selector result. | Fresh post-operation lock origin, release routing, remaining status/free propagation and UserClient copyback gating. |
| High | Pair actual daemon/kext/provider exchange. | Matching native build/task/connection/right and transaction epoch; historical failed-open trace and source-only continuations remain separate. |
| Medium | Classify no-guard matching-result forwarding. | Actual serviceMatching failure contract and waitForService NULL handling before drawing a runtime failure conclusion. |

- **QG1**: Pass. Factual source/ABI/control/data-flow analysis requires no normative content.
- **QG2**: Pass. HA-A1..HA-A7 identify premises, dependent results and falsification probes.
- **QG3**: Pass for this increment. Reaching readiness, warm scratch/parameter demand, cold matching/wait arguments, service publication/absence, record status and actual error-path delta are covered. The full goal remains active.
- **QG4**: Pass. u8 bit predicates, u32 arithmetic, zero-extended -40, byte extents, 48 B initializer frame, 1 ns timeout and retained/reproduced accounting are explicit.
- **QG5**: Pass. Readiness/native readiness, arbitrary/non-NULL/valid object, API premise/source execution, requested/elapsed timeout, scratch/copy destination, stale request/new status and path-specific/general delta remain distinct.
- **QG6**: Pass. Pinned originals/parents, original source/slots/symbols, three source equations, nonvacuous uniqueness and independent byte epochs provide scoped provenance.
- **QG7**: Pass. Parameter, cold-provider, readiness, error cleanup, native pairing and matching-result work is bounded and impact-ranked above.

The subsequent [provider-absent release/cleanup report](versioned_error_release_report.md) continues this exact absence frontier through fresh release words and original unlock routing. Separate void-return premises cover parameter/output-stream/input-stream cleanup requests and reach outer/dispatcher status 0xce515a38. It records H3 publication at A+0x270 after the declared parameter-free return, without a later H3 dereference, and preserves native lifetime uncertainty. This closes the retained absence-path source cleanup through the dispatcher epilogue frontier; final wrapper/UserClient copyback and warm processing remain open.
