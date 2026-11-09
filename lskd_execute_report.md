# LSKD execution workspace, dispatcher prefix and null-output cleanup

The [four prepared requests](lskd_fields_report.md) now have a checked source lineage into `_TdtbU9WbbSyE1sdsj` and its workspace carrier. The wrapper requests 16384 bytes aligned to64 and a separate 4096-byte typed allocation, writes 52 bytes of a partial 64-byte header, then calls the protected dispatcher. The first output-reference partition is connected to that source-written header. Twenty-four null-output cases return `0xffff5966` through original status stores and cleanup-call preparation.

Allocation/free backends are **register-effect models**; no model writes memory. Native allocation, deallocation, PAC, pointer validity and request processing remain **unknown**. Nonnull-output cases stop before the first protected state; its next typed allocation is identified statically only. No cryptographic/provider, Mach, synchronization or target-file operation executes. The broad goal remains active and incomplete.

[Source contracts](triage_evidence/lskd_execute_contracts.json), [retained cases](triage_evidence/lskd_execute_profiles.json), [distinct fresh replays](triage_evidence/lskd_execute_replays.json), [independent checks](triage_evidence/lskd_execute_checks.json), [six source-derived proof pairs](triage_evidence/lskd_execute_proofs.json), [source identity/static continuation](triage_evidence/lskd_execute_source_identity.json), [preservation](triage_evidence/lskd_execute_preservation.json) and [scoped quality gates](triage_evidence/lskd_execute_quality_gates.json) retain the evidence.

```text
provider's complete source-built request
  -> execution wrapper(request, response_reference)
       -> IOMallocAligned(0x4000,0x40)       [REGISTER MODEL -> R]
       -> IOMallocTypeImpl(view AE20)       [REGISTER MODEL -> A]
       -> unsigned order check(R+0x40,R+0x4000)
       -> original 52-byte header writes
       -> protected dispatcher prefix, selector 0x563
            -> unsigned order check(R+0x80,R+0x4000)
            -> response_reference == 0
                 -> original status store 0x5e5571af
                 -> IOFreeTypeImpl(view AEE0,A) [REGISTER MODEL]
                 -> IOFreeAligned(R,0x4000)     [REGISTER MODEL]
                 -> original return 0xffff5966
            -> response_reference != 0
                 -> STOP before state 0x57f
                    static next call: IOMallocTypeImpl(view AE60)
```

R and A are declared private allocation returns. The static continuation is not replayed. A declared null R stops before its first dependent store, without accessing address0.

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LE1 | Original KC and normalized image identify this build | Code, metadata, symbols and slots | Rehash both, compare exact envelopes/spans and original pointer chains; native runtime identity is separate |
| LE2 | Guarded private memory and abstracted PAC support conditional instruction execution | Replays and source epochs | Reject unknown private reads, unmodeled calls and source escapes; inspect each instruction; native authentication/reachability remain unproved |
| LE3 | Allocation returns and caller-register clobbers match declared models | Workspace/header paths and provider compositions | Verify native allocator/type-view state separately; poison initial storage; models never initialize memory |
| LE4 | Free models preserve callee-saved registers and have no memory effects | Original cleanup arguments and final status forwarding | Inspect actual free backends/lifetime separately; incidental return registers are clobbered; deallocation is not proved |
| LE5 | Private regions are mapped with stated extents; symbolic cells are distinct | Header fields, copies, local proofs | Recover native capacities/aliases; 52 source-written header bytes do not attest a valid native allocation or initialized arena |
| LE6 | Source-key equality and encoding lemmas qualify the shared-key decoded-field proof | Six compositional proofs | Re-lift original slices and compare original/normalized formulas; no monolithic whole-program/native-memory proof follows |
| LE7 | Mutable-global fixtures are stable within a run | Protected targets and return states | Recheck original/zero/noise fixtures and all byte inputs of rules; native concurrency remains separate |
| LE8 | Nonnull-output replay stops before its first protected state | First-state target and unchanged request/output bytes | Continue actual allocation/processing/publication separately; static next-call evidence is not execution or acceptance |
| LE9 | Census covers aligned B/BL and exact aligned qwords in stated segments | Eight direct callers and metadata match | Expand indirect/computed/biased references and modules; four earlier callers are static-only in this increment |
| LE10 | Constructed provider inputs inherit LR4 constructor alignment and LF assumptions; range proof assumes no u64 wrap | 48 source-created request lineages and numeric interval ordering | Check the 48 constructor-record alignments and actual caller state; prove native bounds/lifetime separately; source-only field-key equality itself has no alignment premise |

LE1-LE10 qualify dependent claims. Retained/fresh replay equality shares the engine. Independent partial-byte reconstruction, compact request/header construction, source-key lemmas and original/normalized formulas test additional properties without proving that engine or native model assumptions.

## Primary provenance and allocation interfaces

| Item | Exact source evidence |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| New extraction | Four compiler envelopes, eight spans, ten new bank rules, twelve bank-pointer roots and two first-state slots |
| Exact wrapper | `_TdtbU9WbbSyE1sdsj`, `0xfffffe000a50c508..0xfffffe000a50c980` |
| Dispatcher prefix | Unnamed `0xfffffe000a55f5e4..0xfffffe000a55f818`; later compiler chunks excluded |
| Shared null-output return | `0xfffffe000a510628..0xfffffe000a510650`; original compiler parent retained separately |

| Call site | Exact matching-KC target | Source ABI |
| --- | --- | --- |
| `0xfffffe000a50c6ac` | `_IOMallocAligned` / `_IOMallocAligned_external`, `0xfffffe000c4b9a08` | X0=0x4000 (16384 bytes), X1=0x40 (64-byte requested alignment) |
| `0xfffffe000a50c74c` | `_IOMallocTypeImpl`, `0xfffffe000c4ba154` | X0=allocation view `0xfffffe000847ae20` |
| `0xfffffe000a50c8f8` | `_IOFreeTypeImpl`, `0xfffffe000c4ba368` | X0=free view `0xfffffe000847aee0`, X1=A |
| `0xfffffe000a50c950` | `_IOFreeAligned`, `0xfffffe000c4b9a24` | X0=R, X1=0x4000 |

The two typed views have **identical original 64-byte contents** but distinct addresses. Their name pointer identifies `site.AllocType`, metadata flags word=0xe4 and metadata size word=0x1000 (4096 bytes). Their first16 runtime-link bytes are zero in the file image. The source forms A+0x1000 as an upper pointer; native view initialization, zone capacity, object identity and deallocation correctness remain unknown. Exact nlist equality supplies API names; no nearest-symbol naming is used.

## Partial 64-byte workspace carrier

| Offset | Width, bytes | Original pre-dispatch value |
| --- | ---: | --- |
| +0x00 | 8 | Request pointer |
| +0x08 | 8 | R+0x40 |
| +0x10 | 4 | `u32((u32(R) XOR 0xae0701e7) * 0x952f3cb7) XOR 0x563` |
| +0x14 | 4 | Unwritten / unknown |
| +0x18 | 8 | A |
| +0x20 | 8 | R+0x4000 |
| +0x28 | 8 | A+0x1000 |
| +0x30 | 4 | Raw status; unwritten before dispatch, source-written on null-output return |
| +0x34 | 4 | Unwritten / unknown |
| +0x38 | 8 | Response-reference pointer |

The wrapper's ABI is `(X0=request_pointer,X1=response_reference)` / W0 status. It writes 52 bytes, leaving twelve header bytes unknown before dispatch. The entire remaining workspace and auxiliary allocation remain unwritten in these checked prefixes. Original bytes preserve explicit unknown masks; poison value0xa5 is a fixture, not an initialized source value.

The source caller passes the prepared request address into this header without reading its fields. Across all48 provider compositions, the original 160-byte request and its 1392 total packet bytes remain unchanged after wrapper entry; no subsequent source read of that request extent occurs before the stop. The response-reference pointer is source-zeroed by each actual provider and is forwarded through header+0x38 to dispatcher X24. No response object is published in the checked prefixes. Standalone output references retain their deliberately nonzero prior sentinel.

## Ordering helper and first protected partition

The callable part of `0xfffffe000a561058` is exactly `BTI; CMP X0,X1; B.HI trap; RET; BRK #1`. It checks unsigned address ordering and performs no memory write or allocation. Later shared chunks in its compiler envelope are excluded. Both call sites resolve through their actual original bank-root slots to this same helper:

| Source call | Checked arguments | Difference when nonwrapping, bytes |
| --- | --- | ---: |
| Wrapper `0xfffffe000a50c7a8` | R+0x40, R+0x4000 | 16320 |
| Dispatcher `0xfffffe000a55f7dc` | R+0x80, R+0x4000 | 16256 |

The interval-order proof explicitly assumes `R <= 2^64-1-0x4000`; the helper itself establishes only numeric ordering. These are not proofs of allocation ownership, accessible extents or arena initialization. Sixteen direct helper cases return; eight inverted-order cases stop before BRK, including high-bit inputs that distinguish unsigned from signed comparison.

Original decoder arithmetic recovers selector0x563 and the header pointers. At `0xfffffe000a55f814`, modifier0xe140 authenticates the selected branch:

| Response-reference value | State index / original slot | Target / checked continuation |
| --- | --- | --- |
| Null | 0x563 / `0xfffffe000846ef38` | `0xfffffe000a510628`, source status write and shared return |
| Nonnull | 0x57f / `0xfffffe000846f018` | `0xfffffe000a5247ac`, explicit replay stop before transfer |

This previously identified local partition is now checked against a source-written workspace and actual provider request lineages. The null-output fragment stores `0x5e5571af` at R+0x30. The wrapper loads that word into callee-saved W26, prepares the typed free followed by aligned free, then returns `u32(raw_status - 0x5e561849)`, yielding `0xffff5966`. Free register clobbers cannot replace the saved source status. No dispatcher status effect is modeled.

A declared null R reaches the numeric ordering helper and then stops before the first dependent store at `0xfffffe000a50c7e4`. This is conditional register-return evidence; no null-address access or native OOM behavior is demonstrated. A declared null A is forwarded as0, with A+0x1000=0x1000, and the null-output path still prepares the free call. Native validity/handling of these states remains unknown.

## Nonnull state: static next-allocation evidence

The static continuation at `0xfffffe000a5247ac..0xfffffe000a52486c` prepares `_IOMallocTypeImpl` at call `0xfffffe000a524868`, X0=view `0xfffffe000847ae60`. The original view names `site.LSKDDispatchStream`, flags word0x64 and size word160. Its original 64-byte contents match the earlier request-constructor view at `0xfffffe000847b160`, while their addresses differ.

Two additional static byte-bank rules, each checked for256 byte inputs, bind this call and view. The dispatcher entry's original stack stores at+0x30/+0x38 supply the actual bank roots used by the continuation; biased original slots are retained. The continuation and allocation never execute in this increment. Allocation success, initialization, output publication and whether this is the eventual response carrier remain unknown.

## Caller census, validation and continuation

| Caller | Direct wrapper call |
| --- | --- |
| `LSKDKext_start` | `0xfffffe000a50544c` |
| `LSKDKext_stop` | `0xfffffe000a5054d8` |
| `com_apple_driver_FairPlayIOKit::wT74ohNhs04OyE` | `0xfffffe000a505568` |
| `com_apple_driver_FairPlayIOKit::R2nPsUOYx6h` | `0xfffffe000a5056dc` |
| `eJ7hqOh8Z` | `0xfffffe000a5058e0` |
| `KDGetReEncryptionVault` | `0xfffffe000a505a2c` |
| `sxvHysrIgQq2V` | `0xfffffe000a505c68` |
| `ZURJElCowjwysX` | `0xfffffe000a505eb4` |

A 422089-word aligned B/BL scan finds these eight direct calls. Exact aligned qword `0xfffffe000ce9c248` is linkedit metadata, not another native function-pointer caller. The first four caller prefixes remain static-only here. The source-identity artifact retains exact caller bounds/symbols. Indirect, computed, biased and external-module callers remain outside the census.

| Fresh verification | Count |
| --- | ---: |
| Cases / visits / instruction bytes | 192 / 172564 / 690256 |
| Read / source-write epochs | 33072 / 17100 |
| Register-only models / model memory writes | 432 / 0 |
| Workspace / auxiliary allocation models | 168 / 168 |
| Source workspace headers / summed defined bytes | 120 / 6336 |
| First-state boundaries, null / nonnull | 24 / 72 |
| Original null-output returns / source status bytes | 24 / 96 |
| Typed / aligned free models | 24 / 24 |
| Null-workspace stops / pre-BRK stops | 48 / 8 |
| Actual provider lineages / request bytes preserved | 48 / 7680 |

The defined-byte sum is `96*52 + 24*56 = 6336` bytes; the latter cases add a four-byte original status store. No model writes memory. All completed source returns restore entry SP. The batch covers original/zero/noise globals, two aligned SP placements, null/non-null request/output/allocation returns and twelve unsigned-comparison pairs. All48 provider constructor records satisfy the inherited LR4 alignment condition.

Six original/normalized SMT pairs cover workspace-key agreement, header encoding, decoded fields, output-reference first state, raw status subtraction and nonwrapping interval order. They lift62 original instructions across seven slice instances. The decoded-field proof uses a shared abstract key only after source encoder/decoder equality and record encoding are proved. Independent fresh verification re-lifts the slices and reconstructs every source read/write/snapshot epoch.

Complexity is `O(B+C*(V+E)+W+256R+I)` for source bytes B, cases C, visits V, events E, census words W, rule checks R and lifted instructions I, plus solver-dependent cost. Runs are bounded at30000 visits; each solver at30 s. Replay dependency checks cover64 rule checks/16384 byte inputs, including predecessor rules. The static continuation separately adds2 rule checks/512 byte inputs; these counts do not denote distinct permutation families.

```sh
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_execute.py
```

| Impact | Remaining interface question | Discriminating evidence |
| --- | --- | --- |
| High | Does the nonnull branch's 160-byte allocation become the response stream? | Continue original initialization and exact output-reference publication; static type metadata alone is insufficient |
| High | Where does execution first consume request fields and pointer-valued spans? | Follow the source request address from header+0 to actual reads and consumer ABI |
| High | Does any resulting stream cross a daemon/Mach boundary? | Establish concrete emission/receiver linkage; this increment adds no Mach endpoint or emission |
| Medium | How are auxiliary storage, workspace cursors and native allocation failures handled? | Native view/allocator initialization, later read/write footprints and real lifetime evidence |
| Medium | How do start/stop and variable-span callers prepare their requests? | Follow the four static-only direct caller prefixes and the earlier R2nPsUOYx6h span census |

QG1 passes for factual technical analysis. QG2 is LE1-LE10 with dependencies and falsification probes. QG3 passes for workspace ABI, first partition, source null-output return, allocator/free call preparation and static next allocation; the broad objective remains incomplete. QG4 covers widths, bytes, arithmetic, counts, timeouts and complexity. QG5 separates partial initialization/unknown poison, register model/source status, bounds/ownership, static/executed continuation and null/non-null contexts. QG6 uses primary bytes, exact symbols/slots, 192 fresh cases and six source-derived proof pairs. QG7 is the impact-labeled continuation table. Original inputs, IDBs, external dump.md and published predecessors remain preserved.
