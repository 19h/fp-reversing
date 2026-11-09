# Provider-start operation, table initialization and constructor consumer

The original `_cmam7f` provider-start operation now completes in private CPU state, with full instruction/read/write/edge fingerprints independently reproduced. It creates and fills the previously missing512-byte word table, writes table base`0xfffffe000cccda68`, writes mask`0xfffffe000ccceaf8=0xFF`, and sets initialization flag`0xfffffe000cccea88` only after the retained table writes. A source-produced table then feeds36 fresh original consumer components covering all32 aligned eight-byte lookup offsets. This resolves the preceding initializer-data gap under explicit allocator/time/lock/PAC premises. It does not establish native provider registration, a continuous constructor call after startup, or a complete daemon/kext transaction.

Evidence: [original source, type views, bank identities and bound proof](triage_evidence/kext_provider_initialize_source.json), [compact startup profiles and critical store ledger](triage_evidence/kext_provider_initialize_profiles.json), [fresh replay and consumer checks](triage_evidence/kext_provider_initialize_checks.json), [exact registration vtable slots](triage_evidence/kext_provider_initialize_registration.json), [preservation](triage_evidence/kext_provider_initialize_delivery.json) and [quality gates](triage_evidence/kext_provider_initialize_quality_gates.json). This extends the [constructor reply-state frontier](kext_constructor_reply_state_report.md), rather than replacing its declared-reply assumptions.

Analysis date:2026-11-04. Original collection SHA-256:`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized kext SHA-256:`2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Addresses are unslid. Source capture retains nine explicit ranges/10285 instructions, two64-byte AllocType views, two exhaustive256-input selectors and one full-u64 mismatch proof. Registration capture separately retains two original vtable fixups and the original provider-start function. No IDB facts or native target execution are used for new claims. Prior local memory supplies evidence-boundary methodology only.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PI1 | Hash-pinned original files are the intended static build. | Rehash originals and recapture source/type views/fixups. Native daemon/kernel/provider build pairing remains unknown. |
| PI2 | Original logical pointers and zero-backed BSS/private RAM describe a declared uninitialized image state. | Recover loader/native initialization epochs; initial file-backed zeroes do not attest current runtime values. |
| PI3 | Private allocator returns satisfy the requested sizes; opaque lock allocations have distinct identities. Frame/arena reuse on the second call preserves existing bytes. | Vary allocation geometry/outcomes and inspect real allocator contracts. Native lock layout, storage validity, reclamation and ownership remain unknown. |
| PI4 | Logger, calendar time, lock and free effects obey the declared ABI models. | Check exact arguments/effects and per-lock abstract depth in fresh state. Calendar time is1700000000 s plus123456 microseconds; no native clock or synchronization runs. |
| PI5 | PAC and authenticated transfers can be represented by logical edges. | Recheck original words, targets and modifiers; nominal authenticated slots do not prove native authentication or runtime vptr identity. |
| PI6 | The explicit repeated no-argument call is a useful component continuation. | Verify the memory-preserving caller transition and original returns. Native repeated provider-start sequencing, registration and lifecycle validity remain unknown. |
| PI7 | Streaming fingerprints and independent CPU hooks describe the finite modeled runs. | Recompute source/read/write/edge/call streams and full final RAM/BSS hashes. The same CPU backend is used; native/hardware equivalence and untested paths are not implied. |
| PI8 | The consumer components have the declared live-ins and receive exact source-produced table bytes/base/mask. | Check all32 possible aligned offsets plus unaligned/high-bit addresses; join the full constructor predecessor before asserting continuous native use. |

Dependent findings below are conditional on PI1-PI8 as applicable. Mathematical word identities, source-store ordering, finite CPU cases, nominal ABI bindings and native effects are separate evidence classes.

```
provider start: superclass success
                    |
             LSKDKext_start == 0
                    |
             cmam7f / tag1414EE04
                    |
          initialization flag byte == 0?
              /                   \
        construct table         reuse table
              \                   /
            support-lock initialization
                    |
           clear lazy-AES warm flag
                    |
          source lock/callback/unlock
                    |
             cmam7f returns0
                    |
       conditional registerService(0) in caller
```

Original provider-start call sites are`0xfffffe000a50ab90` -> `LSKDKext_start` at`0xfffffe000a5053f4`, then`...ab98` -> `_cmam7f` at`0xfffffe000a5a38cc`. Source tests superclass success and each subsystem result; a nonzero subsystem result follows the failure return. The post-success virtual call is`...abd8`. Both nominal vtables resolve vptr+0x5E0 to exact`IOService::registerService(unsigned int)`, `0xfffffe000c4d8394`. The FairPlayIOKit slot is`0xfffffe000846beb0`; base IOService slot is`0xfffffe0007f89778`. Original pointers are format8, authenticated IA, diversity0x7D59, address diversity1. The caller supplies options0. This is a static conditional association; this increment executes `_cmam7f`, not superclass/LSKD startup, the provider object or registration.

The `_cmam7f` wrapper supplies a16384-byte frame aligned to64 B and a separate4096-byte AllocType arena. It encodes operation0x1414EE04, uses a NULL argument-record pointer, and calls generic dispatcher`0xfffffe000a606728`. The dispatcher calls helper`0xfffffe000a62784c` at`...606f48`; initialization reaches`0xfffffe000a66af38`. Every retained wrapper return requests typed-arena free through view`0xfffffe000847ba60` and frame free with extent16384. These are requests under no-effect free models, not native resource balance.

| Established field/interface | Original writer or boundary | Retained role |
| --- | --- | --- |
|512-byte data allocation | `_IOMallocData` request at`0xfffffe000a66b1e0` | Storage for the address-indexed word table; source writes all512 bytes |
| Table-base cell`0xfffffe000cccda68` | `STR X8,[X9]` at`0xfffffe000a66cb40` | Publishes the allocation pointer |
| Mask u32 cell`0xfffffe000ccceaf8` | `STR W10,[X9]` at`0xfffffe000a66cbb0` | Writes0xFF |
| Final table modification in case0 | `0xfffffe000a66cd74` | Last retained table write, before initialization flag |
| Initialization flag byte`0xfffffe000cccea88` | `0xfffffe000a627d10` | Writes1 after table initialization; gates subsequent table reconstruction |
| Lazy-AES warm flag byte`0xfffffe000ccca078` | `0xfffffe000a607218` | Writes0 on both successful calls |
| Current source lock | Kernel `_IOLockLock` / `_IOLockUnlock` models | Calls use the lock published at`0xfffffe000cccb080`; source continuations`...a5b421c`/`...a5bfe88` |

The table-base selector uses original pool slot`0xfffffe0008472290`, whose raw rebase points to cell+4; source subtraction4 supplies the base cell. Its exhaustive bank is left`0xfffffe000792fcc0`, right`0xfffffe00079391f0`, key0x87, constant0xDF, additive-0x6D. The mask selector uses slot`0xfffffe0008472470`, left`0xfffffe0007949dd0`, right`0xfffffe000792fbc0`, key0x73, constant0x47, additive0x67. Both identities cover all256 byte inputs and retain original raw pointer provenance.

In case0, table-base publication occurs at source visit2667926, mask publication at2667954, final table modification at2668067, initialization flag at6861841 and first wrapper return at6866591. Source visit indices are zero-based event positions. Earlier table writes begin before base publication; later table modifications continue afterward. Consequently, the flag marks a later program epoch than the base/mask stores. This is source ordering, not a native memory-order or concurrency guarantee.

Clearing the AES warm flag after subsystem initialization explains why a later constructor can still enter lazy `IOAESAccelerator` discovery. The two flags are separate state: setting the subsystem initialization flag does not establish hardware attachment. Their native synchronization and all failure/retry epochs remain unknown.

| Case / phase | Selected model premise | Source visits | Original result u32 |
| --- | --- | --- | --- |
|0 /0 | Successful allocations, distinct lock identities | 6866591 | 0 |
|0 /1 | Second call, same memory, frame/arena reused | 5469 | 0 |
|1 | First IOLockAlloc returnsNULL | 1097 | 0xFFFF5BD4 |
|2 | IOMallocData(512) returnsNULL | 1418 | 0xFFFF5BD4 |
|3 | IOMallocData(29) returnsNULL | 6866985 | 0 |

The failure value is-42028 when interpreted as i32; its business error name is unknown. In case1, no table or lock is published. In case2, the earlier lock pointer remains in its cell while table base/mask/initialization flag remain zero; the wrapper requests arena/frame release, with no lock-free request in this retained path. Caller failure cleanup and retries are unresolved. These are modeled NULL outcomes, not observed native OOM behavior.

The29-byte temporary allocation has a different local role from the512-byte table owner. Its NULL case reaches a successful return and still writes all512 table bytes. It produces different final table bytes:511 of512 differ from case0. The branch and subsequent allocation addresses also differ, so this finite comparison does not isolate a specific entropy or content dependency. The table's mathematical/business meaning and full generation semantics remain unknown. The original zero-return `_arc4random` stub and fixed calendar-time inputs retain the preceding report's explicit limits.

The cached phase preserves the table bytes, base, mask and initialization flag and makes no new data/generic allocation, time or logger request. It still requests four additional locks and writes new pointer values into four cells. Calling this complete initialization idempotence would be incorrect. The explicit second caller preserves every RAM/BSS byte; only caller registers/flags and the next entry PC change. Fresh replay verifies the transition's complete RAM/BSS fingerprints. Native repeated-start sequencing is not established.

Distinct opaque lock identities are used within each run. In case0, label allocations L1..L10 in order; the labels are private model identities, not native addresses or Mach names:

| Global lock-pointer cell | First call stores | Cached call store | Original store site |
| --- | --- | --- | --- |
| `0xfffffe000ccceab8` | L1 | No new store | `0xfffffe000a616f98` |
| `0xfffffe000ccceab0` | L2, later L5 | L9 | `0xfffffe000a616f98` |
| `0xfffffe000cccda78` | L3 | L7 | `0xfffffe000a607230` |
| `0xfffffe000cccda70` | L4 | L8 | `0xfffffe000a60723c` |
| `0xfffffe000cccb080` | L6 | L10 | `0xfffffe000a616f98` |

The retained lock/unlock requests use L6 on the first call and L10 on the cached call, matching the cell at`0xfffffe000cccb080`. Their source return continuations are`0xfffffe000a5b421c` and`0xfffffe000a5bfe88`. No native lock body executes; per-object abstract depth returns to zero. Seventeen successful lock allocation instances across the four cases are distinct within their own case; allocations in different cases do not share a namespace. No IOLockFree request occurs in these cases. Pointer replacement is source-verified, but native release balance and the wider ownership of previous values remain unknown. The checks' `lock_publication_sites` ledger includes raw pointer-copy stores; the table above restricts it to global BSS stores.

The earlier constructor consumer derives an address-indexed lookup offset. With source-produced mask0xFF, let a be its incoming derived u64 address. The captured alignment/add/mask/sign-extension sequence at`0xfffffe000a5b5154..0xfffffe000a5b517c` reduces to:

```
offset = (a + 0x50) & 0xF8       u64 modular arithmetic
0 <= offset <= 248
offset % 8 == 0
offset + 8 <= 256
```

The following original instruction at`0xfffffe000a5b5180` reads eight bytes at table_base+offset. The source-derived mismatch query is unsatisfiable over every u64 a under mask0xFF. Thus this consumer uses the first256 bytes of the512-byte backing allocation. Base ownership, native pointer validity and the applicability of the initialized epoch remain separate premises. The proof does not apply to arbitrary native mask values or identify every other table consumer.

Thirty-six original twelve-instruction components receive the exact case0 final512 table bytes and the source-produced base/mask. Inputs cover all32 aligned offsets, plus unaligned and high-bit derived addresses. Each component is freshly replayed with exact read-byte and final-register checks; every loaded u64 matches its source-produced table slice. No table entry is guessed or zero-filled for the join. These are component data transfers from an original initializer output, not continuous full-constructor runs. The constructor's next XOR/rotate/data-codec semantics and hardware-discovery predecessor remain unestablished.

The main execution does not retain millions of repeated JSON trace rows. It records canonical SHA-256 streams and counts for source visits, reads, writes, logical authenticated edges and indirect call registers. Each stream record uses little-endian packed integers: visits contain PC+original word; reads/writes contain PC+address+extent+visit index+observed bytes; edges contain PC+visit index+target+modifier+kind; calls contain PC+target+X0..X7. Scripts define the exact packing. Profiles also retain every unique visited original word/count, all API model events,326 critical memory effects across cases, caller transitions, final cells/table bytes and complete final1 MiB RAM/64 KiB BSS hashes.

An independently implemented fresh CPU executor recomputes these fingerprints, source coverage and final state; it does not reuse the probe executor. This establishes equality of the retained streams and outputs in the common private CPU backend. It is not an instruction-by-instruction hardware equivalence proof. Model events, critical store values, mathematical proof and source-role checks remain reviewable separately from fingerprints.

Main replay verifies13741560 source events,2129058 reads/10866461 B,573153 writes/2472984 B,507592 logical authenticated edges,5415 indirect call events,63 API model events, five wrapper returns and one memory-preserving outer call. Four calendar-model output stores cover24 B. The consumer replay adds432 original instructions,144 reads/1008 B and36 boundaries. Two successful table constructions cover1024 written bytes in total. One full-u64 proof, two exhaustive banks, two type views and two exact nominal registration slots pass their checks. These are finite modeled paths plus the stated mathematical domain, not complete native path coverage.

Reproduction order is recovery, probe, registration capture, validator, seal, owned-manifest publication, then independent publication audit. Scripts use the pinned zut virtual environment and existing Z3 runtime/Python paths already used by preceding increments. Runtime is linear in retained instruction/effect count, apart from timeout-bounded SMT and one original-image/symbol read. Memory is bounded by unique-PC metadata, critical stores, one private1 MiB RAM map and image pages, rather than the full repeated trace. No native target, allocator, logger, clock, lock, provider-registration, IPC or PAC operation executes; original inputs, IDBs and memory stores remain unchanged.

| Impact | Next interface / bounded opportunity | Evidence needed |
| --- | --- | --- |
| High | Continuous startup-to-constructor execution | Carry original startup memory into the real constructor, recover lazy hardware-discovery outcomes and continue past the previous table frontier without recreating objects. |
| High | Owner publication and returned token | Join original nested helper output, list insertion, wrapper result adapter and page/close lookup contracts. Valid table state alone does not establish these. |
| High | Provider stop and resource retirement | Execute original stop after source startup; identify table/lock/global retirement and caller failure cleanup. Pointer replacement does not by itself establish a native leak or balanced release. |
| High | Native peer and registration identity | Establish actual provider object/vptr, superclass/LSKD outcomes, runtime registration, daemon/kernel build pairing and host credentials. The supplied RAX capture remains a failed-open trace. |
| Medium | Table generation and codec semantics | Recover compact generator/word-table identities and later consumers. Distinguish fixed time, zero-return random stub, temporary-buffer fallback and allocation geometry. |
| Medium | Epoch, concurrency and retry contracts | Establish serialization, memory ordering, repeated-start admissibility and recovery after partial initialization; vary opaque allocation geometry and outcomes. |
| Low | Additional schema consumers | Bind every mask/base alias and access width before generalizing the first256-byte bound to other helpers. |

QG1: No normative content is required. QG2: PI1-PI8 register assumptions, dependencies and falsification probes. QG3: This increment covers original startup, table production/publication, cached/allocation outcomes, lock-pointer epochs, the consumer data interface and nominal registration binding; the full goal remains active. QG4: Integer widths, byte extents, modulo domains, time units, counts, stream packing and complexity are explicit. QG5: Table caching versus lock recreation, ready versus AES flags, source order versus native synchronization, component transfer versus continuous reachability and nominal versus runtime registration remain distinct. QG6: Original bytes/fixups/symbols/type views, fresh stream/state replay, explicit critical stores, full-word proof and consumer read-byte oracles supply primary provenance. QG7: Remaining work is bounded and impact-labelled above. All gates pass for this increment; full native constructor/provider/daemon interaction and lifetime remain unknown.
