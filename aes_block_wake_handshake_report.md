# AES block/wake state and placement handshakes

The source beneath AES event selection distinguishes a thread whose state already has bit 2 set from one whose bit 2 is clear. The wake helper rewrites both to a word with bit 2 set, but the ordinary first route returns 0 and the second returns 1, selecting a separate placement routine. Post-switch dispatch supplies the complementary transition: with wait bit 0 still set, it clears bit 2 and decrements a scheduler count. With bit 0 already clear, it takes a requeue path instead. These are source contracts under the assumptions below, not a native lost-wakeup or scheduling proof. The interfaces extend [hashed-event selection](aes_event_wake_selection_report.md), [event registration](aes_event_registration_report.md) and [identified receiver release](kernel_waitq_receiver_report.md). No additional Mach-port endpoint, right transfer or message emission is identified. [BH1-BH8]

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BH1 | Results apply to the pinned original collection and compiler-bounded bodies at preferred virtual addresses. | Rehash the source and compare every retained byte, bound and decoded instruction. A different image/slide needs a new correspondence. |
| BH2 | Queue, request, stack, thread, CPU, auxiliary and paired-counter cells are disjoint and retain their declared identities. | Check actual extents, aliases, pointer provenance, reuse and intervening writers. Fixed-cell symbolic proofs do not resolve arbitrary aliases. |
| BH3 | The two-order comparison starts with state 4 and normal wait mask 1 or 9; auxiliary state bits do not change between phases. | Match the actual mark-wait, optional-pointer and state-flag paths. A satisfiable auxiliary-state control distinguishes the two orders outside this domain. |
| BH4 | Source phases share a declared ownership epoch, and locks/call boundaries return as specified. | Establish real lock ownership, exclusion and admissible concurrent interleavings. The private post-switch phase does not execute a context switch or the complete preceding dispatch body. |
| BH5 | LDADD/CASP use declared single-RMW observations; paired count and category remain stable except for the examined operations. | Inspect native atomic ordering, retries, other writers, underflow/overflow and category changes. Positive global count avoids decrement underflow in the local pair; modular balance alone does not prove admissibility. |
| BH6 | CPU offset and raw clock reads are stable snapshots satisfying the source unsigned guards. | Measure calibration, frequency, migration and monotonicity; trigger neither assertion nor hardware register access in this analysis. Clock units and their SI conversion are unknown. |
| BH7 | Ordinary wake paths have the declared zero auxiliary flags, no optional callback effects and the stated owner/placement ABI models. Modeled callees preserve relevant private fields except their declared outputs. Placement-prefix cases additionally use a declared nonnull candidate and priorities 0,20,96. | Exercise nonzero auxiliary/context/trace flags, real callee writes, owner validation and actual queue placement. Callback signatures are source argument contracts; authentication and target behavior remain unknown. |
| BH8 | Evidence is original-byte recovery, scalar proofs and finite private interpretation. | Obtain a correlated daemon request, provider wait/interrupt, matching thread/event epoch, actual scheduling and returned daemon result. Native completion and the broad investigation goal remain unproved. |

## Primary source and recovered routines

Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Ten complete bodies retain 2651 instructions / 10604 B. Exact entry symbols are absent for these addresses; names in this report describe source roles. The reference data suffices, so no new IDA access or IDB mutation is required. [BH1,BH8]

| Recovered role | Preferred entry | Source interface |
| --- | --- | --- |
| Mark wait | `0xfffffe000bd28280` | Publishes normal wait bits/result; prior interruptibility analysis applies |
| Block wrapper | `0xfffffe000bd28f6c` | Saves continuation/parameter, selects a candidate and invokes it until success |
| Invocation body | `0xfffffe000bd2a064` | Candidate/current interfaces, timing checks, switch boundary and post-switch call |
| Post-switch dispatch | `0xfffffe000bd2a8b8` | Old/new thread accounting and conditional block versus requeue paths |
| Selected-thread stager | `0xfffffe000bd6cbcc` | Previous event/identity clearing and immediate/deferred selection |
| Temporary-queue drain | `0xfffffe000bd6bad0` | Previous deferred scheduler call |
| Wake-state helper | `0xfffffe000bd26ba8` | Rewrites wait state; returns whether its caller should enter placement |
| Placement routine | `0xfffffe000bd27054` | Candidate selection, placement metadata and lower queue-backend interface |
| Scheduler count increment | `0xfffffe000bd22370` | Global u32 increment and conditional auxiliary u64 pair update |
| Scheduler count decrement | `0xfffffe000bd1e688` | Complementary global/pair decrement |

The AES mutex-sleep call at `0xfffffe000bd0c9c4` targets the block wrapper with (X0,X1,W2)=(0,0,0). It stores those first two values at thread+0xe0/+0xe8, calls candidate selector `0xfffffe000bd29140`, then calls the invocation body with (current thread, selected candidate, source reason). A zero invocation result loops to selection. After a nonzero result and mask handling, it returns u32[thread+0xd8]. A successful invocation is therefore not itself the sleep return value. The candidate selector and invocation internals are not fully interpreted here. [BH1,BH4,BH7]

## Wake-state rewrite and caller decision

Let S be the incoming u32 state. The source store at `0xfffffe000bd26c40` is:

```text
W = (S AND 0xfffffeb2) OR 4
  = (S AND NOT 0x14d) OR 4                 [u32]
```

It clears bits 0,3,6,8, sets bit 2 and preserves every other bit. The branch at `0xfffffe000bd26c44` tests saved S, not W. The stager's earlier OR 0x100 therefore disappears in this rewrite. [BH1-BH4]

| Incoming S bit 2 | Ordinary source continuation | Caller consequence |
| --- | --- | --- |
| Set | Sets W22=0 at `0xfffffe000bd26c48`; skips the slow timestamp/count-increment prefix | Returns 0 through `0xfffffe000bd26ef8`; caller bypasses placement |
| Clear | Samples time, stores three epoch fields and calls count increment at `0xfffffe000bd26cc0`; ordinary zero-auxiliary route sets W22=1 | Returns 1; stager or drain calls placement with (thread, raw flags 5) |

Both wake callers test that result and prepare the same raw placement arguments at `0xfffffe000bd6cc80` and `0xfffffe000bd6bb8c`. The immediate/deferred distinction from the preceding report remains: the ordinary stager calls the helper directly for old bit 2 set, whereas old bit 2 clear first uses its temporary queue. In the private ordinary compositions, the latter reaches placement through the drain. This does not define the global meaning of every state bit or prove real runnable membership. [BH3,BH4,BH7]

The slow prefix reads the CPU offset around `MRS s3_4_c15_c10_6`, retries if that offset changed, and requires the resulting u64 raw time to be no less than the CPU-context+0x70 snapshot. It then stores that time at thread+0x278/+0x270/+0x328. The state rewrite precedes this timing guard; the guard path is not a transactional rollback. Category u32[thread+0x1fc]==1 separately publishes raw_time+u32[thread+0x258] at thread+0x260. Native clock units and optional helper effects remain unknown. [BH4,BH6,BH7]

## Post-switch complementary transition

At `0xfffffe000bd2ab7c`, the post-switch body reads the old thread's state. If bit 0 is clear, it refreshes two epoch fields and requests placement through `0xfffffe000bd2abdc`. For the declared zero reason word, the computed raw flags are 0x25. It bypasses the blocked-state store and decrement path. [BH3,BH4]

When bit 0 remains set, `0xfffffe000bd2ac88`..`0xfffffe000bd2acb8` computes:

```text
P = S OR 0x20       if (S AND 0x30) == 0x10; otherwise P = S
blocked_state = P AND 0xfffffffb                         [u32]
runtime_total = old_total + raw_now - old_epoch           [u64 modular]
```

It stores blocked_state, updates thread+0x330, fills thread+0x270..+0x27f with all-one bytes, clears thread+0x2b0 and calls count decrement at `0xfffffe000bd2accc`. Normal states 5 and 0x0d become 1 and 9. The complete post-switch body has additional state, accounting, timer, callback and ownership paths; the private phase starts at the stated branch and ends before the new-thread continuation. [BH2-BH7]

## Matched ordinary ordering comparison

| Phase | Wake before post-switch state test | Post-switch state test before wake |
| --- | --- | --- |
| Normal registration from initial state 4 | 5 or 0x0d | 5 or 0x0d |
| First transition | Wake rewrite ->4; old bit 2 set ->helper result 0 | Post-switch blocked store ->1 or 9; global count G->G-1 |
| Complementary transition | Post-switch sees bit 0 clear; requests requeue with raw flags 0x25 for reason 0 | Staging adds 0x100; wake rewrite ->4; old bit 2 clear ->count G-1->G and helper result 1 |
| Placement-facing interface | Post-switch call `(thread,0x25)` | Wake caller call `(thread,5)` |
| Result within BH2-BH7 | State 4; count G | State 4; count G |

This comparison joins source states and local counter arithmetic. It does not execute the native concurrent sequence, prove a context switch, complete queue placement or establish liveness. If (S&0x30)==0x10, the blocked arm can set bit 5 and the corresponding state words can differ across orders; the SAT control retains this restriction rather than extending the ordinary result to arbitrary state flags. [BH3-BH5,BH8]

## Scheduler count and paired auxiliary fields

Both helpers operate on u32 global `0xfffffe000cad06a0` using LDADD. Increment adds 1; decrement adds -1 modulo 2^32. Their returned W0 is the resulting global count, independently of the auxiliary pair. The wake helper does not use that returned count as its placement decision. Increment also clears byte thread+0x57 bits 0/1. [BH1,BH5]

For nonnull u64[thread+0x2a0], both helpers bypass the paired-field path. Otherwise let A=u64[thread+0x298], K=u8[thread+0x204], and pair address P=A+0x80+112*K. The 112 B stride and offsets are source-derived; the actual object's type, capacity and lifetime remain unknown. [BH2,BH5]

| Operation | Expected u64 pair | Desired u64 pair on successful full-pair comparison |
| --- | --- | --- |
| Increment | (C,H) | (C+1, H if C!=0 else 0xffffffffffffffff) |
| Decrement | (C,H) | (C-1, raw_now if C==1 else H) |

CASP compares both 64-bit lanes, conditionally writes both desired lanes and returns both observed lanes. A failed observation comparison enters the original retry loop; no finite retry bound is proved. The scalar certificates retain all 128 bits and the independent checks include separate low-lane and high-lane mismatches. [BH5]

For an increment from C=0 with H different from all ones, the source samples raw_now. Only raw_now>H adds min(raw_now-H, u64[global `0xfffffe000cb62868`]) to u64[A+0xb8+112*K] using LDADD. Equal and future H snapshots bypass that addition. A same-category decrement/increment pair restores C modulo 2^64. For C=1, the stopped epoch becomes raw_now and the next increment changes it to all ones; for C!=1 the original H is preserved. These are source accounting transitions, not calibrated durations or proof of native scheduler membership. [BH5,BH6]

## Optional callback and placement interfaces

| Source call | Guard / arguments | Interpretation boundary |
| --- | --- | --- |
| Post-switch `0xfffffe000bd2ad28` | Saved state bit 6; pointer=thread+0x2d8; W0=1, X1=thread, X17=0xae56; BLRAA X8,X17 | Raw code 1 associated with the blocked transition; target effects and hardware authentication unknown |
| Wake `0xfffffe000bd26cb8` | Old state bit 6; same pointer; W0=2, X1=thread, X17=0xae56; BLRAA X8,X17 | Raw code 2 associated with wake; shared modifier does not prove a particular callback target |
| Placement backend `0xfffffe000bd27644` | X0=candidate, X1=thread, X2=source placement flags; direct BL to `0xfffffe000bd207c4` | Original preparation executes in six private prefix cases; backend and actual runqueue insertion remain unexecuted |

The ordinary placement prefix saves source flags, checks a lock assertion, refreshes helper-derived thread+0x208 and publishes its selected candidate at thread+0x2b0 before the queue-backend call. The finite cases use a nonnull thread+0x2a0 candidate equal to the declared CPU-context identity, matched generation/owner observations and priorities 0,20,96. Optional helpers remain ABI return models. The complete placement body includes other candidate, priority, tracing and remote-context paths. No whole-routine placement result is claimed. [BH4,BH7]

## Verification

Thirty-four new UNSAT certificates cover 15 source cuts / 58 lifted instructions. Four SAT controls retain auxiliary-state order differences, decrement-zero wrap, a pair epoch mismatch and the insufficiency of the rewritten state alone to infer placement. The publication audit also rechecks the previous 20 wake-selection and 47 event-registration certificates. [BH1-BH8]

| Independent private check | Count |
| --- | --- |
| Complete event-wake compositions with original wake-state helper | 180 |
| Original decrement/increment helper pairs | 24 |
| CASP lane-mismatch observations | 4 |
| Matched ordinary wake/post-switch ordering cases | 8 |
| Placement prefixes to queue-backend frontier | 6 |
| Callback argument cuts, without indirect call execution | 2 |
| Equal/future epoch guards | 3 |

Complete cases interpret the original wrapper, selection, removal, staging/drain, wake-state and applicable counter bodies. They vary saved state, the +0x2a0 bypass, auxiliary count/index and category. Entire thread records with 16 B guards, final saved registers and SP are checked. Owner-accessor returns, locks/masks and whole placement effects remain explicit models with caller-saved clobbers. Hardware counter reads are scalar snapshots; LDADD/CASP are single-RMW interpretations. Logical PAC does not execute authentication. The ordered post-switch cases are declared phases, not native context-switch traces. [BH2-BH8]

```sh
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/recover_aes_block_wake_handshake.py --verify
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=triage_evidence \
  "$PYTHON" -P triage_evidence/audit_aes_block_wake_handshake.py
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_aes_block_wake_handshake_publication.py
```

Source recovery/proof construction costs O(B+I+P) time/space for source bytes B, instructions I and certificate size P; SMT solving is separate. Private interpretation costs O(cases*(source visits+canvas bytes)) time and O(code+private bytes) space. Atomic retry loops and native scheduling have no established finite-time bound. Raw u32/u64 arithmetic, byte extents and uncalibrated clock values remain distinct. [BH1,BH5,BH6]

## Bounded continuation

| Impact | Next source / native evidence | Question resolved |
| --- | --- | --- |
| High | Original `0xfffffe000bd207c4` backend and selected runqueue stores | Actual queue membership beneath the now-resolved placement ABI |
| High | Candidate selector, admitted invocation and switch-to-post-switch ownership transfer | Whether the declared phases match a concrete blocked thread epoch |
| High | Correlated provider interrupt, thread/event identity and daemon result | End-to-end daemon/kext/provider completion |
| Medium | Real counter object layout, class changes and CASP retry/clock observations | Auxiliary accounting lifetime and native ordering |
| Medium | Original callback targets, old bit 6 producers and authenticated slot lineage | Meaning and ownership of raw callback codes 1/2 |
| Low | Nonzero auxiliary/trace paths and optional initial flag+0x43a helper | Generic interface coverage beyond the ordinary path |

## Quality gates

- **QG1**: Factual source and ABI analysis; no normative conclusion required.
- **QG2**: BH1-BH8 list assumptions, dependent results and falsification probes.
- **QG3**: Block/wake state, counts, ordinary ordering, callback and placement interfaces are covered for this increment; the broad goal remains active.
- **QG4**: Widths, modular operations, 128-bit pair comparisons, byte offsets, raw clock limits and complexity are explicit and reproducible.
- **QG5**: Auxiliary states, count wrap, clock guards, retry loops, modeled calls and unexecuted queue/switch behavior are separated.
- **QG6**: Original bytes/bounds, source proofs, independent finite interpretation and publication checks provide distinct provenance.
- **QG7**: Continuations are bounded and impact-ranked; native scheduling and daemon-facing completion remain unknown.

Evidence: [source and certificates](triage_evidence/aes_block_wake_handshake_checks.json.zst), [generator](triage_evidence/recover_aes_block_wake_handshake.py), [independent interpreter](triage_evidence/audit_aes_block_wake_handshake.py), [publication audit](triage_evidence/verify_aes_block_wake_handshake_publication.py).
