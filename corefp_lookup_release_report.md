# CoreFP caller-managed lookup lock release and failure cleanup

Upstream continuation: the [root-record ingress report](corefp_root_ingress_report.md) reaches the same selected cleanup from original record producer0x5f4584 through adapter0x8fcfa0. Twelve complete private calls forward the root marker into ingress+0x20 after consuming adapter output as an SP adjustment. Unlock result5 remains distinct from the raw record marker and modeled lock ownership.

Caller-context continuation: the [protected-root adapter report](corefp_root_adapter_report.md) establishes that adapter0x8fcfa0 passes its own stack word as rootX1, initialized to the external caller seed minus0x100. Twenty-five complete private failure compositions restore that internal word to the seed, then replace the external word with zero. The direct-root +0x100 observation below concerns the root's immediate parameter; it does not describe the adapter caller's external result. Broader native field semantics remain unknown.

Current continuation: the [cold request1200 failure and fallback report](corefp_request1200_failure_report.md) supplies successful certificate allocation and original payload staging, then completes five parent returns after nonzero request1200 results. The same selected heap/static lock pointer reaches cleanup; record markers, final X0 and cached-name retention remain separate. A sixth fallback prefix stops before entropy while the caller is still active.

Original protected caller 0x8e81c8 produces the lookup record, completes the cold lookup and then releases the selected lock through cleanup wrapper 0x457838 and unlock helper 0x1be978 on seven tested failure paths. The unlock call is at 0x1becc8. Its pointer equals the earlier write-lock argument at 0x20f6cc, including the static fallback when the first allocation fails. This establishes a source release path outside the local lookup routine; native ownership, synchronization and general re-entry remain unknown.

The caller's record result, final X0 and X1-referenced u64 word are separate observable outputs. In the nonzero-unlock-result fixture, the parent record still contains 0x45e2a20f while final X0 retains 5 and the declared lock ledger remains held. Every tested failure leaves the caller u64 word advanced from zero to 0x100 before lookup. No native API or daemon/kext transaction executes. The full interface investigation remains active.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_lookup_release.py), [checks](triage_evidence/corefp_lookup_release_checks.json), [independent auditor](triage_evidence/audit_corefp_lookup_release.py), [audit receipt](triage_evidence/corefp_lookup_release_audit.json), [live-IDB snapshot](triage_evidence/corefp_lookup_release_ida.json) and [publication verifier](triage_evidence/verify_corefp_lookup_release_publication.py) retain this increment. Logical JSON links resolve to `.json.zst` artifacts. The preceding [cold metadata/re-entry report](corefp_cold_metadata_report.md) establishes the local lookup and same-instance cache behavior; the [client-path report](corefp_client_paths_report.md) retains earlier warm caller and larger-request boundaries.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| LR1 | Pinned original CoreFP and supplied daemon bytes identify the compared code. | Check image hashes, all complete source extents, used fixup rows and live readback. Native image selection remains unknown. |
| LR2 | The parent receives a valid private 48 B record with decoded operation 0xc1f7, controlled field zero and two nonnull private referents. X1 points to a zero u64 word. | Independently construct the parent bytes through the original unsimplified key expression and reconstruct all initial CPU/RAM. Upstream public/native reachability and referent semantics remain unknown. |
| LR3 | Both once predicates start incomplete in a sequential private model. | Execute both original callbacks and retain constructor/callback frames; cleanup performs a third once check after completion. Native predicate layout, interrupted initialization and concurrency remain unknown. |
| LR4 | Allocator/pthread/PAC effects are declared models, including a null 760 B certificate allocation after successful lookup. | Compare heap/static-lock, caller-register clobber and unlock results 0/5. The ledger clears only on modeled unlock result zero; it does not establish native acquisition or retirement. |
| LR5 | Bootstrap names/results and unchanged-ID daemon envelope translation retain their previous explicit fixture meanings. | Independently check API effects and repeat original daemon rejection under the frozen second driver. No native namespace, rights translation or kernel endpoint identity is supplied. |
| LR6 | The source-generated unlock record is 8 B aligned and its pointer selects a nonnull supplied lock or the static fallback. | Compare both pointer branches; prove the aligned wrapper/helper key identity and retain an unaligned counterexample. The accessed extent is 12 B; the extra four snapshot bytes are context, not another ABI field. |
| LR7 | The global heap-lock slot does not change between acquisition and cleanup in these executions. | Retain every source access, the wrapper reread at 0x4579ac and exact acquire/release pointer equality. Concurrent replacement and native owner identity require separate evidence. |
| LR8 | The selected ordinary epilogues obey the callee ABI and stack checks do not fail. | Verify SP and X19-X30 restoration, all CPU checkpoints and immediate post-unlock source operands. Final X0 is a retained register result, not an assigned public return type. |
| LR9 | The tested zero u64 input is sufficient for these failure cases only. | Retain the 8 B store at 0x8e830c, its ordering before lookup and its final value. Other initial values, overflow, native workspace semantics and caller rollback policy remain unknown. |
| LR10 | Finite client replay and bounded IDA evidence establish only their recorded scope. | Check seven independent compact oracles, full retained client journals, two UNSAT identities, one SAT domain falsifier and exact live bytes/xrefs. Full daemon RAM replay, native locks/rights and complete successful request processing remain open. |

CoreFP arm64e SHA-256: `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; supplied daemon SHA-256: `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. CoreFP offsets use preferred base zero. Numeric record markers, flags and controls are u32; pointers and the caller word are u64. Sizes are bytes. Fixture values are not native addresses or port names.

## Original parent-to-lookup-to-release sequence [LR1-LR10]

```text
parent 0x8e81c8, valid private operation 0xc1f7
  |
  +-- 0x8e8304..0x8e830c: *X1 := *X1 + 0x100 (u64)
  |
  +-- original stack lookup record: tag 0xba27, flag 9
  |     0x8e851c -> lookup 0x1cdb24
  |       cold callbacks construct/reset state
  |       0x20f6cc: pthread_rwlock_wrlock(selected pointer) [model]
  |       primary/fallback bootstrap [model]
  |       primary success: unchanged-ID metadata rejection [-304]
  |     0x8e8520: original child marker and output slots retained
  |
  +-- discovery failure: preserve failure marker 0x45e2a2e3
  |   or
  +-- discovery success -> malloc(760) at 0x249368 [model returns NULL]
  |                         select marker 0x45e2a20f
  |
  +-- 0x8fc3f0 -> cleanup wrapper 0x457838
  |     decode parent-produced cleanup control
  |     reread heap-lock slot image+0x1d444a8 at 0x4579ac
  |     construct aligned unlock record
  |     0x457aa0 -> unlock helper 0x1be978
  |       once check already complete
  |       supplied pointer nonzero: use it
  |       supplied pointer zero: resolve static image+0x1d27bf0
  |       0x1becc8: pthread_rwlock_unlock(same pointer) [model]
  |
  +-- 0x8fc404: store selected record marker
  +-- normal parent return; X0 retains unlock result
        entry-X1 word remains 0x100 in all seven cases
```

This sequence resolves the previously open source release path for the selected parent failure branches. It does not add an unlock to lookup 0x1cdb24 itself, establish every lookup caller's behavior or prove native second-call feasibility. The successful certificate/request1200 path retained earlier stops before a larger transaction; its complete response/cleanup lifecycle is outside this increment.

The parent produces the lookup record at a stack address with two separate caller-owned u32 output slots. The independent oracle decodes its source-staged control to tag 0xba27 and flag 9. No child lookup record, output pointer or cleanup record is patched to reach the release path. The initial root operation and API results remain declared preconditions.

## Cleanup and unlock record contracts [LR1,LR2,LR6-LR8]

| Boundary / field | Accessed width | Recovered role |
| --- | --- | --- |
| Parent record +0 | 4 B | Final raw marker written at 0x8fc404 |
| Parent record +8 / +32 | 8 B each | Declared nonnull private referents; broader native types unknown |
| Parent record +20 / +24 | 4 B each | Address-keyed operation/control inputs for this parent experiment |
| X1-referenced word | 8 B | Source increments it by 0x100 before lookup; no tested failure rollback |
| Cleanup wrapper input +0 | 4 B | Source reads encoded control at 0x457968; decoded value 0x97413dbe |
| Unlock record +0 | 8 B | Heap-lock pointer reread from image+0x1d444a8, or zero for fallback selection |
| Unlock record +8 | 4 B | Address-keyed control decoded by helper to 0x4cfa |
| Unlock record +12..+15 | Outside accessed contract | Four extra context bytes retained in the 16 B snapshot; not assigned field semantics |

The wrapper reads its input control and constructs a different stack record. Let p=low32(wrapper-input address), all operations modulo 2^32:

```text
wrapper_input_key = (p XOR 0x8b4ea7c9) * 0x0bcb7857
wrapper_control   = raw_input_u32 - wrapper_input_key = 0x97413dbe
unlock_control    = wrapper_control + 0x68bf0f3c = 0x4cfa
```

For q=low32(unlock-record address), the helper key is:

```text
Khelper = ((NOT(q XOR 0xff481ff8)) XOR 0x17d12dda) * 0xb7a7bfff
        = (q XOR 0x1766cddd) * 0xb7a7bfff
decoded = raw_control_u32 XOR Khelper

Kwrapper = (((q OR 0x0a90cea5) + (0xf56f315a OR NOT q))
            XOR 0x1df60379) * 0xb7a7bfff
q AND 7 = 0  =>  Kwrapper = Khelper
```

The first simplification holds for all 32-bit q. The wrapper/helper equality is proved under the source stack-alignment condition, with a separate SAT counterexample to an unrestricted identity: q=0x4a90cea5 yields wrapper key 0xe0c4837a and helper key 0x2febfc88. This counterexample concerns the algebraic domain; it is not an externally reachable input or native failure result.

Helper 0x1be978 reads only +8/4 B and +0/8 B from the supplied record in these runs. It performs no result store to that record. Its caller-provided pointer branch skips static fallback resolution when nonnull. The static case supplies zero, then resolves the same fallback object used by acquisition. The wrapper rereads the global heap-lock slot rather than receiving a distinct lock handle returned by lookup. Pointer matching therefore depends on the retained sequential state, not a proved concurrent ownership transfer.

## Seven complete parent outcomes [LR2-LR9]

| Profile | Lookup result / acquired service name | Lock supplied to unlock helper | Parent record marker | Final X0 / declared lock ledger |
| --- | --- | --- | --- | --- |
| Primary, certificate allocation null | Success; 0x5017, flags 0x0a after metadata -304 | Heap pointer 0x64000000 | 0x45e2a20f | 0 / clear |
| Fallback, certificate allocation null | Success; 0x5034, flags 0 | Same heap pointer | 0x45e2a20f | 0 / clear |
| First lock allocation null, later certificate allocation null | Success; 0x5017, flags 0x0a | Zero; helper selects static image+0x1d27bf0 | 0x45e2a20f | 0 / clear |
| Primary with caller-register clobbering | Success; 0x5017, flags 0x0a | Heap pointer | 0x45e2a20f | 0 / clear |
| Primary with unlock result 5 | Success; 0x5017, flags 0x0a | Heap pointer | 0x45e2a20f | 5 / retained held |
| Primary lookup result 5 | Failure; caller output poison preserved | Heap pointer | 0x45e2a2e3 | 0 / clear |
| Primary 1102, fallback result 5 | Failure; caller output poison preserved | Heap pointer | 0x45e2a2e3 | 0 / clear |

Each profile contains one write-lock call and one unlock call with equal pointer arguments, two cold callbacks and a later completed-predicate check in the unlock helper. Five cases attempt the 760 B allocation; the two lookup failures skip it. All seven return with SP and X19-X30 restored and only the first four bytes of the parent record changed. The caller u64 word remains 0x100 in every case.

The unlock result does not select the final parent record marker on the retained normal epilogues. The helper/wrapper epilogues and parent continuation do not consume or overwrite X0/W0, so the result survives in final X0. The native prototype of the protected parent remains unknown; these observations do not assign that residual register value a public status contract. A current arm64e SDK compile confirms the imported pthread_rwlock_unlock prototype is `int (pthread_rwlock_t *)`; it does not establish the original runtime implementation.

The cleanup path invokes no mach_port_deallocate, free or larger request1200 emission in these profiles. Cached service names remain retained after successful discovery: 0x5017 for primary, 0x5034 for fallback; lookup failures leave the common cache zero. Lock release is distinct from cached-name/right retirement.

## Validation and architectural touch points

The auditor imports no new producer. Seven initial CPU frames and 1654784 B of initial touched RAM are independently reconstructed from original segments, normalized pointers and declared root inputs. Separate sparse replay checks 22812 original client visits, 4954 reads, 2539 writes, 363 PAC models, 113 modeled transitions, 42 construction/callback points, 28 parent/lookup/cleanup handoffs, 14 lock events, four metadata returns and all 1654784 B of final RAM. Seven compact oracles separately check record/control decoding, pointer equality, source field footprints, distinct result channels, preserved registers and early caller-word mutation.

Eighteen retained source spans comprise fourteen complete compiler-bounded functions and four 16 B import stubs, totaling 106600 B. Parent 0x8e81c8..0x8fcf9f accounts for 85464 B; retaining the full body does not imply every branch executed. New cleanup wrapper 0x457838..0x457acb is 660 B and unlock helper 0x1be978..0x1becf7 is 896 B. Fourteen exact instruction checks and two UNSAT queries plus one alignment-domain SAT falsifier support the contracts. The current SDK prototype assertion compiles with exit zero and emits no target artifact.

Four primary-service cases independently repeat the original daemon's unchanged-ID rejection through the frozen second driver: 148 original daemon visits and 152 steps including fixture returns. This retains the preceding scope limit: source execution/reply/PAC comparisons, not a complete daemon CPU/RAM replay. No native source API or Mach transaction executes.

Current MCP readback matches 1792 original bytes. Conventional incoming IDA xrefs identify data pointer cells 0x1d03798 -> unlock helper, 0x1d04f38 -> cleanup wrapper and 0x1d383d8 -> static fallback object. The original format12 rows independently agree. IDA reports no conventional incoming xref for image+0x1d444a8 even though source replay proves the wrapper's compensated-pointer read at 0x4579ac. Therefore the empty xref result is not evidence that the lock slot is unused. The bounded `rwlock` knowledge query returns zero entries without truncation. Partial automatic annotations are not semantic proof; no IDB is mutated.

Reproduction uses the existing analysis Python environment with Unicorn, Capstone and Z3 available:

```text
python -P triage_evidence/recover_corefp_lookup_release.py
python -P triage_evidence/audit_corefp_lookup_release.py
python -P triage_evidence/verify_corefp_lookup_release_publication.py
```

Time and space are O(C*(B+F+V+J+R)), with C profiles, B image bytes, F normalized fixups, V visits, J retained records and R touched RAM. Client execution is bounded at 30000 visits per profile, daemon children at 2000 and each solver query at 30 s. Nontrivial JSON is losslessly compressed with decoded-byte equality checks. Original inputs remain preserved; path scrub includes decoded typed RAM.

## Bounded continuation and self-red-team

| Impact | Discriminating continuation / significance |
| --- | --- |
| High | Continue the successful certificate/request1200 path through response and final cleanup. This increment proves release on selected discovery/allocation failure paths, not all operations or callers. |
| High | Establish native lock construction, owner, unlock result and actual repeated caller ordering. Equal source/model pointers and balanced declared calls do not prove native mutual exclusion or re-entry. |
| High | Follow the parent record marker and final X0 through its upstream caller. Inferring a public error result from only one channel would conflate independently produced values. |
| Medium | Recover the X1-referenced u64 word's upstream lifetime and overflow/rollback policy. Early mutation persists through the tested failures; whether this denotes a workspace cursor, count or another ABI state requires caller evidence. |
| Medium | Recover other cleanup-wrapper controls and other users of the lock slots. The aligned 0x4cfa route is established; arbitrary input records, aliases and concurrent slot replacement remain outside scope. |
| Medium | Establish native service and daemon/kext/deeper lineage. These cleanup calls release a lock, not the cached service name or a demonstrated Mach right. |

**QG1** passes: factual technical analysis requires no normative judgment. **QG2** passes: LR1-LR10 state assumptions and falsification probes. **QG3** passes for the increment: source-staged child inputs, cold acquisition, selected failures, matching-pointer cleanup, result channels, early caller-word mutation and interface limits are retained; the full goal remains incomplete. **QG4** passes: byte extents, u32/u64 arithmetic, alignment, compiler assertion and execution/solver bounds are explicit. **QG5** passes: local lookup versus caller cleanup, helper record extent versus extra snapshot bytes, aligned versus unrestricted key identity, and record marker versus X0 are distinguished. **QG6** passes: original SHA-256, complete source bodies/fixups, independent CPU/RAM journals/oracles, solver/compiler receipts and live readback support the claims. **QG7** passes: the impact table bounds the remaining work. Native ownership, general re-entry, successful-request completion and full daemon/kext/deeper topology remain unknown.
