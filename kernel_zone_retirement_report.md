# Zone retirement, magazine publication and thread continuation

The complete 109-word tail at `0xfffffe000bd74fcc` revalidates an element's zone and displacement, updates thread/CPU accounting, and either publishes the element pointer into a per-CPU magazine or requests a deeper release. A full current magazine can exchange its counts and pointers with a spare. When both are full, an external helper supplies either a replacement cache or a zero result selecting deeper release. These are source contracts; native ownership, authentication, concurrency, helper effects and reclamation remain unknown. [ZT1-ZT7]

This extends the [small retirement dispatch](kernel_retirement_dispatch_report.md), [metadata query](kernel_retirement_query_report.md), [allocator boundary](kernel_allocator_boundary_report.md), [MixedData retirement](mixed_data_retirement_report.md) and [magazine refill](kernel_zone_refill_report.md). No new Mach endpoint or port-right emission is established. This increment concerns a deeper kernel interface reachable from previously recovered retirement paths; a matching daemon transaction is unknown.

## Primary evidence and claim map

Original kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Normalized predecessor kext SHA-256: `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. The original complete retirement body occupies `[0xfffffe000bd74fcc,0xfffffe000bd75180)`: 109 instructions, 436 B, SHA-256 `f4277455a3d1c4bb41c93ad959110320a9137d875a1c404a51eb0f3d166644d2`. It exactly matches the earlier retirement capture. The complete original creator at `0xfffffe000bd772b4` also matches the earlier geometry capture; only its seven multiplier-producing instructions at `[0xfffffe000bd7759c,0xfffffe000bd775b8)` receive new source proofs here. None of the seven queried body/target addresses has an exact original symbol. No new IDA observation was required.

| Claim | Established contract | Dependencies |
| --- | --- | --- |
| ZT1 | Exact point-range, metadata zone equality and modular displacement gate | ZT-A1-A4 |
| ZT2 | Separate u64/u32 multiplier producers; restricted divisibility equivalence for extents 16, 32 and 48 B | ZT-A1-A4 |
| ZT3 | u32 thread nesting increment and u64 per-CPU extent accounting with a 16 KiB stride | ZT-A1-A5 |
| ZT4 | Cache slot, authentication modifier and current/spare magazine counts/pointers determine source publication | ZT-A1-A6 |
| ZT5 | Both-full helper receives zone/cache/base/extent; its ordinary return reloads three spills and tests the full result | ZT-A1-A7 |
| ZT6 | Publication selects nesting error, ordinary return or pending continuation; null-cache paths request deeper release | ZT-A1-A7 |
| ZT7 | Complete tail, multiplier block and nine reused caller words have replayable source obligations and a changed-store counterexample | ZT-A1-A7 |

Evidence: [extractor](triage_evidence/recover_kernel_zone_retirement.py), [instruction audit](triage_evidence/audit_kernel_zone_retirement.py), [delivery verifier](triage_evidence/verify_kernel_zone_retirement_delivery.py), [capture](triage_evidence/kernel_zone_retirement_checks.json.zst), [proofs](triage_evidence/kernel_zone_retirement_audit.json.zst).

Decoded capture SHA-256: `90fed34230be54b6f2ff347030be770874a1866f0fda500b01d8f0a5160e33cd` (110,900 B). Decoded audit SHA-256: `09f811422c510f9288804020176bb6a019914f41f078516d8f9c913e1b1cfaa3` (2,800,050 B).

## Entry ABI and reclassification

| Incoming register | Source operand |
| --- | --- |
| X0 | Zone Z |
| X1 | Statistics base S |
| X2 | Recovered element base P |
| X3 | Element extent E, raw u64 |

The tail allocates a 48 B frame and saves FP/LR. Its point-range predicate is `L <=_u P <_u U`, using the u64 globals at `0xfffffe0007e66e50` and `+8`. This is a point check; it does not independently validate `P+E` or an eight-byte interval. Failure at `0xfffffe000bd75000` reaches the validation-error block.

Let R be u64 at `0xfffffe0007e66f00`, J=`R+((P>>10) AND 0xffffffff0)`, H=u16[J], and B=`0xfffffe000caeb480`. Reclassification computes `Z'=B+192*(H AND 0x3ff)` and rejects `Z'!=Z` at `0xfffffe000bd75030`. It then forms the following exact u64 displacement:

```text
d = (P AND 0x3fff) - u16[Z+0x36]                   (mod 2^64)
if (H AND 0xf000) == 0xe000:
    d = d + (u8[J+2] << 14)                       (mod 2^64)
M = u32[Z+0x30]
accept iff ((low32(d) * M) mod 2^32) <_u M
```

Failure of that final predicate branches at `0xfffffe000bd75060`. All three rejection reasons join `0xfffffe000bd75134`, which requests `0xfffffe000c633aa0` with X0=Z and X1=P at `0xfffffe000bd7513c`. Its callee body, diagnostic behavior and native termination are outside this increment. It is distinct from the two callees in the [earlier diagnostic report](kernel_retirement_diagnostics_report.md).

## Multiplier producer and interpretation limits

The selected creator block starts with `MOV W8,#-1`; this defines X8 as `0x00000000ffffffff`. For incoming creator extent E64=X25 and zone X22, it stores:

| Zone field | Exact producer |
| --- | --- |
| u64 at Z+0x28 | `UDIV64(0xffffffff,E64)+1 mod 2^64` |
| u32 at Z+0x30 | `UDIV32(0xffffffff,low32(E64))+1 mod 2^32` |

ARM UDIV with a zero divisor produces zero; the model encodes that explicitly. Consequently E=0 gives multiplier 1, E=1 gives u32 multiplier 0, and for u16 E>=2 the u32 value is `ceil(2^32/E)`. Allowed native creator extents remain unknown. Three additional exhaustive symbolic obligations establish that, for each selected E in {16,32,48} B and nonnegative displacement d in [0,16383], the modular gate is equivalent to `d mod E=0`. This interpretation does not extend automatically to negative wrapped displacements, the extended-layout domain, arbitrary multipliers or a live allocation. No actual 14 B request is assigned one of those extents without matched geometry/epoch evidence. [ZT2; ZT-A4]

## Accounting and authenticated cache boundary

At `0xfffffe000bd75064`, `MRS TPIDR_EL1` supplies T. The source increments u32[T+0x1c8] modulo 2^32. It reads CPU index I=u16[T+0x1b8], computes A=`S+(I<<14)`, and adds E to u64[A+8] modulo 2^64. The stride is `2^14 B=16,384 B=16 KiB`. These offsets establish machine data flow; the native thread object, CPU migration rules and synchronization are unknown.

The preindexed load at `0xfffffe000bd75090` reads raw u64[Z+0x40] and updates X17 to Z+0x40. A zero raw pointer selects deeper release. Otherwise `MOVK` replaces X17's high 16 bits with `0x8b6b`, followed by AUTDA and another zero test. The exact modifier is `((Z+0x40) AND 0x0000ffffffffffff) OR 0x8b6b000000000000`. AUTDA is an uninterpreted function of raw pointer and modifier in these proofs; neither native authentication nor an equivalence between authentication failure and zero is claimed. The effective cache is C=`AUTDA(raw,modifier)+(I<<14)`. [ZT3-ZT4]

| Cache field | Width | Source use |
| --- | --- | --- |
| C+4 | u16 | Spare count |
| C+6 | u16 | Current count |
| C+8 | u64 | Spare magazine pointer |
| C+0x10 | u64 | Current magazine pointer |
| Global 0xfffffe0007e6a248 | u16 | Capacity K |

If current count n<K, the source first stores u16(n+1) at C+6, then stores P at `current_magazine+8*n` (`0xfffffe000bd750c4` and `0xfffffe000bd750c8`). When current count>=K and spare count s<K, it writes old n to C+4 and old s to C+6; `LDUR Q0`, `EXT #8`, `STUR Q0` exchange the two eight-byte pointers. It then joins the same publication block with s as the index. This records source store order. Atomic publication, reader ordering, lock ownership and cache reuse are unknown.

## Helper custody and continuation ABI

| Transfer | Emission site | Source contract |
| --- | --- | --- |
| Both-full helper 0xfffffe000bd75180 | BL at 0xfffffe000bd7514c | X0=Z, X1=C, X2=P, X3=E |
| Deeper release 0xfffffe000bd756f8 | Tail B at 0xfffffe000bd75170 | X0=Z, X1=P, caller frame restored |
| Nesting error 0xfffffe000c63aec8 | BL at 0xfffffe000bd75120 | Reached when post-publication u32 nesting is zero; callee effects unknown |
| Pending continuation 0xfffffe000be8663c | Tail B at 0xfffffe000bd75130 | Frame restored after decrement to zero and pending bit 2 set; other volatile operands unspecified |

Before calling the both-full helper, the source saves Z, T and P at offsets +8, +16 and +24 relative to the 48 B frame's SP. The ordinary-return cut preserves SP, FP and those caller-owned saved words while allowing arbitrary volatile registers and fresh post-helper memory elsewhere. The source reloads Z/T/P and tests all 64 bits of returned X0. Zero selects deeper release. Nonzero becomes a replacement C; its raw u16 count and current pointer feed the same publication block. There is no repeated capacity comparison on that return path, and count+1 wraps at u16 width. A valid returned cache/count is therefore an unresolved helper contract, rather than a proved native capacity invariant. [ZT5; ZT-A6-A7]

After publication, zero nesting requests the nesting-error callee. Nonzero nesting is decremented modulo 2^32; a result above zero returns normally. A result of zero loads u64[T+0x1c0], reads the byte at that pointer+0x4c, and selects the pending tail when bit 2 is set. Under a coherent direct-cache path, initial nesting 0xffffffff wraps to zero on entry and selects the error; initial zero reaches the pending test; other initial counts are restored by increment/decrement. These arithmetic cases do not prove that the corresponding native initial states occur.

Raw-null and authentication-result-null paths retain the increment and extent accounting when requesting deeper release. The helper-zero path performs no local decrement, but helper effects are unknown, so it does not establish preservation of the pre-call nesting value.

```text
dispatch(Z,S,P,E) -> point/zone/displacement gates
                         |
                  nesting++ ; stats+=E
                         |
                    raw/auth cache
                  /                \
                null             nonnull
                 |          current has room? --yes--> publish P
                 |                  | no                  |
                 |            spare has room? --yes--> swap/publish
                 |                  | no                  |
                 |              helper(Z,C,P,E)           |
                 |             /              \          |
                 |           zero         replacement -> publish
                 v                                         |
            deeper release                    nesting error/decrement
                                              return/pending tail
```

## Verification and assumption register

The audit uses exact fixed-width arithmetic and a shared little-endian byte array for each modeled state, with linked source edges and explicit return cuts. Prefix certificates establish displacement/frame state before a separate universal modular-multiply certificate. Accounting and cache gating are linked directly; current and spare publication certificates begin at their established cache-gate boundaries with arbitrary post-gate memory. They do not reexecute accounting. These are modular source contracts, rather than a single monolithic proof of every instruction under arbitrary external effects. PACIBSP/AUTIBSP/RETAB use conditional identity envelopes; AUTDA remains uninterpreted.

All 32 source counterexample obligations are UNSAT with satisfiable premises; three additional bounded composition obligations and five predecessor formulas are UNSAT. Coverage comprises 116 new source locations and nine reused caller locations, 461 instruction instances and 432 linked-edge obligations. The modified pointer-store control is SAT. Coverage is the union of the individual modular certificates; it is not a native execution trace or a proof of unmodeled callee effects.

Extraction takes O(B+I+S) time/space for original image bytes, instructions and symbol records. Formula construction takes O(I+Q) time/space for instruction instances and expression-DAG nodes. Solver search is separate with a 30 s per-query limit. All widths, instruction counts and byte extents are exact. Replacing the actual pointer-publication store with NOP must admit a SAT counterexample. The delivery verifier reconstructs canonical formula ASTs, replays source/composition proofs and the changed-store control, checks original inputs and exact publication custody, and scans decoded archives for analyst paths.

| ID | Assumption and dependent result | Stress test / falsification probe |
| --- | --- | --- |
| ZT-A1: source identity | The pinned collection, compiler bounds and prior captures supply the selected bytes. All claims depend on identity. | Recapture the complete tail, creator, seven producer words and nine caller words; compare hashes and exact original symbols. |
| ZT-A2: instruction model | Widths, byte-array operations, flags, preindexing, SIMD exchange and control edges represent the selected source. All proofs depend on this model. | Rebuild/re-solve canonical formulas, reject the changed publication store and compare an independent instruction engine. |
| ZT-A3: storage domain | Stack, zone, thread, metadata, statistics, cache and selected magazine windows are valid, nonwrapping and disjoint as declared. ZT1-ZT7 are conditional on these domains. | Check actual mappings and aliases. The model declares separate 512 KiB magazine windows to cover all u16 indices; this is a proof domain, not an observed native allocation size. |
| ZT-A4: geometry/epoch | Metadata and multiplier interpretation use the stated snapshots and creator domain. ZT1-ZT2 do not establish a live allocation identity. | Match P/Z/header/tail/extent/multiplier in one initialized epoch; test negative and extended displacements separately. |
| ZT-A5: thread/accounting snapshot | T, CPU index and accounting cells are coherent through the direct source path. ZT3 and direct nesting composition use this premise. | Inspect CPU migration, writers and synchronization; correlate native TPIDR_EL1 and statistics cells at the same event. |
| ZT-A6: authentication/cache boundary | AUTDA is uninterpreted; pointer validity and disjoint cache storage are assumptions. ZT4-ZT6 do not authenticate native pointers. | Establish the native discriminator, key, pointer result, capacity and magazine ownership separately. |
| ZT-A7: external execution | Ordinary helper return preserves the supplied caller frame/ABI; other helper RAM is fresh. Deeper release, pending/error callees and native return authentication are unexecuted boundaries. ZT5-ZT7 use these limits. | Recover helper/deeper bodies and match actual call/return effects, allocation identity and daemon transaction; reject broader claims until then. |

## Bounded continuation

| Impact | Next evidence | Remaining question |
| --- | --- | --- |
| High | Both-full helper at 0xfffffe000bd75180 | Returned cache/count validity, locking, magazine ownership and helper side effects |
| High | Deeper release at 0xfffffe000bd756f8 with matched P/Z/E | Actual metadata updates, reclamation and reuse epoch |
| High | Matched daemon request, userclient record and kernel allocation | Which transaction reaches this retirement contract |
| Medium | Thread nesting/pending writers and continuation at 0xfffffe000be8663c | Scheduling, CPU affinity and external control of the continuation |
| Medium | Validation/nesting error callees | Diagnostic intent and native termination behavior |
| Low | Extend producer/displacement composition beyond the three bounded cases | Exact domains supporting a general alignment interpretation |

## Scoped quality gates

- **QG1**: Factual source, control-flow and machine-interface claims only.
- **QG2**: ZT-A1-ZT-A7 state assumptions, dependent claims and falsification probes.
- **QG3**: The complete 109-word tail, seven producer words, nine caller words, external requests, return cuts and continuation gates are covered. The full interface goal remains active.
- **QG4**: 109*4 B=436 B; 7*4 B=28 B; 116 new words plus nine reused words; 48 B frame; 192 B zone stride; 16 KiB CPU stride; exact u8/u16/u32/u64 and 128-bit SIMD operations.
- **QG5**: Point/extent checks, source/native effects, uninterpreted authentication, fresh helper memory, local capacity gates and native capacity invariants remain distinct.
- **QG6**: Pinned original bytes, predecessor matches, reconstructed formulas and an altered-source SAT control supply reproducible provenance.
- **QG7**: Ranked continuation covers helper/deeper effects, transaction identity, thread context, diagnostics and the bounded multiplier interpretation.

The [both-full magazine helper](kernel_retirement_magazines_report.md) returns the incoming cache or zero under the ordinary ABI. Every modeled nonzero normal return passes a producer-count reset; linked original-byte components then publish one pointer through C+6/C+0x10. Allocation instead consumes C+4/C+8. Whole-CFG, instruction and list/state evidence retain explicit native synchronization, external-memory-effect, reclamation and transaction-identity limits; no additional Mach endpoint is established.

The [deeper bitmap/metadata release](kernel_zone_bitmap_release_report.md) establishes both free-bit layouts, count-store/underflow order, encoded metadata queue transitions and the original unlock/thread-nesting handoff. Sixteen source proofs and 66 private components retain explicit native exclusion, external-effect, physical-reclamation and daemon-epoch limits; no additional Mach endpoint is established.
