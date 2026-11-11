# Original kernel waitq selection and identified-receiver handoff

The [subsequent initialization/enqueue report](kernel_waitq_enqueue_report.md) supplies source-produced type3/type2 state, wait membership and pre-block thread states. It also corrects the singleton node-word threshold to65536 (0x10 shifted left12); the previous4096 description was an arithmetic error. The original captured instruction and zero-word profile outcomes are unchanged.

Original kernel instructions now connect the 44-byte no-senders notification to receiver selection, membership removal, temporary CPU-list staging, receiver message publication and a bounded scheduler fast path. Selection returns one extra preemption hold while leaving the receiver spin lock free. The subsequent release routine acquires that lock, consumes the hold, checks ownership and calls the scheduler routine. This replaces the previous whole selection/release result models. It does not establish native daemon reception or a context switch.

Eleven components cover 34 complete functions / 4147 captured instructions and 14101 original instruction visits. Nine return success through the original notification caller. One stops before entering the scheduler with thread state 0x101; another stops before a source guard's panic callee with DAIF bit9 clear. Independent replay, complete receiver/port/kmsg state oracles and three bounded scalar queries pass. Source, input epochs, remaining primitive effects and native unknowns are separated below.

## Evidence and correspondence

The primary source is the original kernel collection, SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Addresses below are its preferred virtual addresses; offsets and sizes are bytes. There is no correspondence asserted between the private addresses used by the CPU fixtures and native kernel objects.

| Artifact | Evidence |
| --- | --- |
| [Source capture](triage_evidence/kernel_waitq_receiver_source.json) | Complete bodies, compiler function bounds, exact symbols, original words at 16 role sites and five control ranges |
| [CPU profiles](triage_evidence/kernel_waitq_receiver_profiles.json) | Exact producer CPU/RAM transfer, declared environment patches with before images, read/write journals, 125 waitq frames and final states |
| [Independent checks](triage_evidence/kernel_waitq_receiver_checks.json) | Independent input and output oracles, fresh producer replay, fresh original-instruction replay and three scalar proofs |
| [Recovery script](triage_evidence/recover_kernel_waitq_receiver.py) | Source extraction and dependencies |
| [Probe script](triage_evidence/probe_kernel_waitq_receiver.py) | Declared component configuration and execution boundaries |
| [Replay script](triage_evidence/replay_kernel_waitq_receiver.py) | Separate executor using original bytes and recorded primitive contracts; no probe executor import |
| [Validator](triage_evidence/validate_kernel_waitq_receiver.py) | Independent membership, state, pointer, status, lock, nesting and mask expectations |
| [Delivery checks](triage_evidence/kernel_waitq_receiver_delivery.json), [quality gates](triage_evidence/kernel_waitq_receiver_quality_gates.json) | Preservation, owned changes, syntax, provenance and local links |

The entry is the actual no-senders producer's saved call state, case11 of [send-right lifecycle profiles](triage_evidence/kernel_send_right_lifecycle_profiles.json), freshly replayed here. Constructor/cache/copyin/common-send/queue instructions remain original as established in the [queue report](kernel_kmsg_queue_report.md). The populated cache and type/owner geometry are declared epochs from that component. This increment does not join the separate adaptive cache-gate/refill experiments into a native startup-to-delivery run.

The [zut trace report](zut_trace_report.md) remains the historical runtime boundary: five service receive rights were acquired, a matching service was found, and the UserClient open returned 0xe00002c2 with a null connection. No selector26, RPC502 or RPC700 exchange is added by the present kernel components. The trace's guest/host port names are not these private kernel addresses.

## Assumption register

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| WR1 | Original KC bytes, logical chained fixups and compiler bounds identify these routines. All static and CPU results depend on this image identity. | Recapture bodies, words and exact symbols; reject another image hash or altered fixup interpretation. |
| WR2 | A declared type3 outer waitq with an inner type2 singleton, or type1 FIFO outside the native hash array, is a source-admitted component input. Membership results depend on it. Native initialization of these backends is unknown. | Trace the real port/waitq initializer and enqueue path; compare native type, pointer, priority-node and event fields. A different initializer can invalidate a component's native applicability. |
| WR3 | Declared receiver records have free spin locks, marker 0x11, waitq/event fields, capacities and numerical state5; state1 is a separate scheduler-prefix input. Fast scheduler conclusions depend on these fields. | Capture or recover construction of actual blocked receivers. Additional state or pending-work fields can force lower scheduler branches. Do not identify a native blocked daemon thread from state5 alone. |
| WR4 | Current thread, type3 readonly owner, task, zone metadata, bounds and geometry are declared consistent epochs. Accessor and lock results depend on them. | Recover original owner/task allocation and initialization or compare a native snapshot; exercise guard outcomes separately. |
| WR5 | CPU index0, a zero pending-context epoch and three free 16-byte scratch slots apply. Temporary-list selection depends on them. | Recover per-CPU initialization; vary occupied slots, CPU index and pending context. Other slot choices are captured statically but not executed here. |
| WR6 | DAIF masks 0x3c0 and 0x200 are valid modeled entry contexts. Restore behavior is established only for these two masks; mask0 is a guard-prefix experiment. | Replay other admitted contexts and pending-work branches. The helper reduces the saved mask to a Boolean, so exact restoration of arbitrary partial masks must not be inferred. |
| WR7 | Remaining byte-copy, keyed-hash, tag-helper and send-preflight effects have the explicit contracts recorded in the profiles. End-to-caller results depend on them. | Replace each contract with original instructions or an independently captured native effect. No hardware authentication conclusion follows from logical PAC steps. |
| WR8 | CPU execution and independent replay establish conditional instruction semantics, not native scheduling, allocation eligibility, message copyout or authentic FairPlay traffic. | Establish real object initialization, kernel/daemon image identities, receive-side copyout and a correlated native request/reply. No such observation is claimed in this increment. |

## Recovered routine roles

Names in the role column are analytical descriptions. Eleven additions have no exact symbol in the captured symbol table; `_lck_spin_assert` has an exact symbol. A captured complete body does not imply that every branch executed.

| Preferred address | Instructions | Established role / evidence limit |
| --- | ---: | --- |
| 0xfffffe000bd6cf80 | 85 | Build a select-one identify request; call selector; extract and unlink a selected thread from a temporary list; clear its list links and scratch busy byte |
| 0xfffffe000bd6c660 | 223 | Choose nested/direct/hash waitq backend; mask context, acquire nested ticket lock, extract singleton or scan FIFO, stage selection, release lock and mask state |
| 0xfffffe000bd6c9dc | 124 | Follow port/set link structures for additional selection; only the null-chain return executes here |
| 0xfffffe000bd6ce44 | 79 | Scan circular FIFO; match outer waitq identity and event; verify reciprocal links, unlink and stage each admitted match |
| 0xfffffe000bd6cbcc | 158 | Lock receiver; clear wait identity/event; set state bit8 and wait result; stage identified thread in CPU scratch list with an extra preemption hold; release spin lock |
| 0xfffffe000bd6d0d4 | 57 | Release/resume identified thread: mask context, acquire receiver spin, consume extra hold, assert lock ownership, call scheduler, release spin and restore modeled mask |
| 0xfffffe000bd0bfa4 | 24 | Uncontended spin acquisition: increment current-thread nesting and install current thread as lock owner with CASA; contended path remains unexecuted |
| 0xfffffe000bd0c2cc | 29 | Spin release: STLR zero owner, decrement nesting; pending-work and tracing branches remain unexecuted |
| 0xfffffe000be7c458 | 62 | Exact `_lck_spin_assert`; selected mode1 verifies owner and lock type marker |
| 0xfffffe000be81fa8 | 40 | Check DAIF bit9 and enable/mask the 0x1c0 group according to Boolean argument; pending-work loop remains unexecuted |
| 0xfffffe000bd26ba8 | 299 | Rewrite selected thread state; execute state-bit2 fast path under zero auxiliary flags; return0. Slow blocked-state path stops before entry |
| 0xfffffe000bd7e084 | 37 | Current-thread readonly-owner accessor; validates type, bounds, geometry and backlink before returning owner |

The total includes the 22 functions / 2930 instructions from the preceding queue increment. The 12 additions contribute 1217 instructions. The syscall transport, daemon parser and DRM payload semantics are outside these routines' established roles. [WR1-WR8]

## Selection ABI and membership

The original queue calls selection at 0xfffffe000bcc7df8 with `(port+0x10, event=0, wait_result=0, flags=0x40, optional_output=NULL)`. The selector's stack request begins at its SP+8:

| Request offset | Width | Value / role in this component |
| --- | ---: | --- |
| +0x00 | 8 | Event0 |
| +0x08 | 4 | General wait result0 |
| +0x0c | 4 | Flags0x40 |
| +0x10 | 4 | Maximum selections1 |
| +0x14 | 4 | Identify-mode word1; adjacent byte+0x15 can report more available work in other branches |
| +0x18 | 4 | Selected count, initially0 |
| +0x20 | 8 | Pointer to temporary selected-list head cell, initiallyNULL |

Outer waitq low type bits are3. Its +8 pointer names the declared inner queue. The outer +0x10 link chain isNULL; a no-match path calls the port/set traversal helper but exercises only its early return. This supplies no evidence of a real port-set graph or its traversal order.

| Object | Offset | Established field / selected behavior |
| --- | --- | --- |
| Inner waitq | +0x00 u32 | Low type bits2 for singleton priority-root path;1 for FIFO scan |
| Inner waitq | +0x04 u32 | Ticket lock, initial0x144; one original acquire/release cycle per selection call |
| Inner waitq | +0x08 u64 | Root/head; source removes selected membership, preserving unmatched FIFO members |
| Receiver | +0x00/+0x08 u64 | Circular links for FIFO membership, then temporary selected ring, then zero after extraction |
| Receiver | +0x10 u64 | Declared zero singleton priority-node word, below65536; larger-node removal is not executed |
| Receiver | +0x18 u64 | Wait event; FIFO compares against request event |
| Receiver | +0x28 u64 | Waitq identity; FIFO compares against the outer waitq pointer |
| Receiver | +0xa8 u64 | Spin owner; free0 or current thread |
| Receiver | +0xb0 u64 | Lock marker0x11 asserted by original `_lck_spin_assert` |
| Receiver | +0xd8 u32 | General wait result from request+8, here0 |
| Receiver | +0x1f8 u32 | Numerical thread-state word; staged5->0x105, fast release0x105->4 |

FIFO requires `(thread.waitq == outer_waitq) AND (thread.event == requested_event)`. At 0xfffffe000bd6ce98 the source reads identity; at 0xfffffe000bd6cea8 it reads the request event. Link writes at 0xfffffe000bd6cee8 and 0xfffffe000bd6ceec splice neighbors; 0xfffffe000bd6cf18 updates the head; 0xfffffe000bd6cf1c clears extracted links before staging. Reciprocal-link failures lead to BRK in the captured body; those failures were not executed.

Cases5/6 independently leave the first member waiting when respectively its event or its waitq identity differs, then select the second member. Case10 leaves a sole event mismatch waiting and enqueues the message. Unmatched remaining nodes retain valid self-rings. Type2 singleton extraction does not execute these FIFO identity/event guards; its backend invariant is a separate input obligation. Native admissibility of either initialized structure remains unknown. [WR2-WR3]

## Temporary selected list, preemption hold and spin ownership

The stager clears waitq identity at 0xfffffe000bd6cc1c and event at 0xfffffe000bd6cc20. It clears bytes+0xcb/+0x58e, ORs state with0x100, and stores the general wait result. Identify mode prevents immediate scheduler execution inside this routine.

When request+0x20 isNULL and flag bit7 is clear, 0xfffffe000bd6ccd8 increments current-thread nesting. The source derives CPU data from current-thread+0x1b8 and base0xfffffe000cac6e18. Slot offsets0x6c8,0x6d8 and0x6e8 appear in the body. Declared CPU0/free-slot/pending-context state selects head cell0xfffffe000cac74e0. Its +8 busy byte becomes1 at 0xfffffe000bd6cd44. Source then inserts the thread as a circular selected list and unlocks its receiver spin.

After nested-waitq unlock, select-one extracts the result, checks ring links, sets thread[0:16] tozero at 0xfffffe000bd6d0b0, and clears scratch busy at 0xfffffe000bd6d0b4. The head cell and all48 declared scratch bytes end zero in every component. Selected-return frames show nesting2 with spin owner0. The extra hold is therefore not a held receiver spin lock.

```text
Current-thread nesting         Receiver spin         Selected scratch
port held:              1      free                  empty
nested waitq acquired:  2      free                  empty
receiver spin acquired: 3      current thread        empty
identify hold added:    4      current thread        one-thread ring
receiver spin released: 3      free                  one-thread ring
nested waitq released:  2      free                  one-thread ring
select-one returns:     2      free                  cleared
release spin acquired:  3      current thread        cleared
identify hold consumed: 2      current thread        cleared
scheduler fast path:    2      current thread        cleared
receiver spin released: 1      free                  cleared
port released:          0      free                  cleared
```

This is the max-one identify request's uncontended path. The extra increment occurs when the request obtains a scratch head, so it must not be generalized to one hold per thread in arbitrary bulk-selection modes. The independent scalar arithmetic proof is bounded to starting nesting<=0xfffffffc; it proves balance of the stated sequence, not native liveness or contention correctness. [WR3-WR7]

The resume routine's explicit decrement is at 0xfffffe000bd6d120. Its ownership assertion is called at 0xfffffe000bd6d13c and scheduler call at 0xfffffe000bd6d144. At both assertion and scheduler frames, receiver+0xa8 equals the current thread, marker+0xb0 is0x11 and nesting is2. The original spin primitive, ticket-lock primitive and typed owner accessors all execute; no whole waitq, receiver-release, scheduler or lock result model supplies these outcomes.

## DAIF and scheduler boundaries

The nested selector, stager, release routine and mask helper test DAIF bit9. They save or inspect the 0x1c0 group and use original `MSR DAIFSet,#7` / `MSR DAIFClr,#7` instructions. The source state is modeled through Unicorn PSTATE. No native interrupt delivery or exclusion experiment was performed.

| Entry DAIF mask | Executed result | Evidence boundary |
| --- | --- | --- |
| 0x3c0 | Stays0x3c0; fast components return to original caller | Default declared context |
| 0x200 | Staging/scheduler frames0x3c0; selection/release return and final caller0x200 | One tested enable/mask transition; arbitrary partial-mask restoration is not established |
| 0 | Original core reaches guard call0xfffffe000c62a2b0; execution stops before that callee | No receiver mutation or inner lock acquisition; no native panic executed |

The source scheduler writes `(old_state & ~0x14d) | 4` at 0xfffffe000bd26c40. State0x105 takes its bit2 fast branch, bypassing timestamp/runqueue-heavy work. Under zero declared auxiliary flags, it clears several ancillary fields, obtains current readonly owner through 0xfffffe000bd7e084 and returns0. The source owner accessor's validation executes, but the owner epoch is declared. The selected path does not execute the caller's nonzero-result continuation at 0xfffffe000bd27054.

The state1 experiment reaches selection state0x101 and message-pointer publication, then stops immediately before entering 0xfffffe000bd26ba8. At that boundary, nesting is2, receiver spin owner is current thread and the port lock is still held. This prefix is not a successful notification send. It deliberately retains obligations that the slow scheduler path would have to discharge. State5 is described numerically here; it is not evidence that a real waiting fairplayd thread already satisfies the fast path. [WR3-WR8]

## Status and publication remain separate contracts

General wait result+0xd8 is0 for selected threads. Receive status+0x3a0 belongs to the IPC queue contract. The sender returns through a third status channel. With the 44-byte kernel notification, the original size helpers require36 user-message bytes plus8 trailer bytes in these components.

| Case | Declared receivers / context | Selection and queue result | Caller boundary |
| --- | --- | --- | --- |
| 0 | Empty type2 inner | No receiver; circular message enqueue | Send0 |
| 1 | Capacity44 | Select0, receive status0, publish kmsg pointer/sequence | Send0 |
| 2 | Capacity43, no LARGE | Select0, receive0x10004004, required36; kmsg pointer still published | Send0 |
| 3 | Capacity43, LARGE4 | Select0/release; no pointer to0; retry finds empty, enqueue | Send0 |
| 4 | FIFO capacity43/LARGE4, then44 | Select/release0, retry select/release1; publish to1 | Send0 |
| 5 | FIFO event1, then event0/capacity44 | Preserve0, select/release1 | Send0 |
| 6 | FIFO different waitq identity, then matching/capacity44 | Preserve0, select/release1 | Send0 |
| 7 | Capacity44, DAIF0x200 | Select/release0; restore0x200 | Send0 |
| 8 | Capacity44, initial state1 | Selected, pointer published; stop before scheduler entry | Unknown send result |
| 9 | Capacity44, DAIF0 | Guard prefix before inner lock and receiver mutation | Unknown send result |
| 10 | Sole FIFO event1 | Preserve receiver; enqueue message | Send0 |

Message-pointer publication is still at 0xfffffe000bcc7ff8; selection does not itself emit a new Mach message. A receive-too-large status can coexist with sender success, and a pointer-publication prefix can precede an unresolved scheduler path. Neither proves copyout into daemon memory. No additional incoming/outgoing endpoint or Mach emission site is established by this increment. [WR2-WR8; preceding queue report]

## Independent validation and reproducibility

The validator reconstructs every private input patch independently, including before images, from a fresh replay of the no-senders producer. It checks unchanged queue arguments `(port+0x28,kmsg,0x50001,0)`, source SIMD/GP/SP/NZCV entry and explicit DAIF epochs. It predicts final complete receiver records, FIFO membership, inner ticket/head, scratch zeroing, full port/kmsg bytes, task counter and nesting. This includes the retained owner/lock/count obligations at both prefix stops.

Separate fresh CPU replay verifies14101 original visits,3999 reads /26431 bytes,2673 writes /19012 bytes,125 waitq frames,75 queue frames,66 allocator frames,73 notification frames,11 complete final RAM images /11534336 bytes and132 final global ranges. It independently applies11 byte-copy effects /484 bytes. All55 remaining primitive models are explicit:11 copies,22 opaque keyed-hash results,11 tag-helper results and11 preflight results. Their caller-clobber contracts are checked. Logical PAC steps remain a modeling boundary; hardware PAC was not executed.

Three SMT counterexample queries are UNSAT within their recorded scalar domains: FIFO's two guards equal the conjunction of identity/event matching; the scheduler mask removes the staging bit while preserving unmasked bits; and the stated identify/release hold sequence balances without exceeding u32 at its highest increment. These do not quantify over native scheduling, heap membership, interrupts or complete daemon behavior.

```sh
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=triage_evidence \
  "$PYTHON" -P triage_evidence/recover_kernel_waitq_receiver.py
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=triage_evidence \
  "$PYTHON" -P triage_evidence/probe_kernel_waitq_receiver.py
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/validate_kernel_waitq_receiver.py
```

Recovery is O(image+captured source) time and space. Component execution/replay and validation are O(image+visits+RAM+effects), with O(image+RAM+journals) space; SMT involves three fixed-width formulas. FIFO selection is O(number of scanned members) per call for the tested uncontended path. No bound on general scheduler latency, hash/set traversal or lock contention is established. Scripts rewrite their own artifacts; publication checks pin their exact resulting hashes.

## Bounded expansion and next evidence

| Impact | Finding / remaining opportunity | Bound |
| --- | --- | --- |
| High | Recover actual receiver wait/enqueue initialization and thread-state transition into this selector | Required to establish whether the modeled backend and fast state correspond to a waiting fairplayd receiver |
| High | Recover slow scheduler continuation from the retained state0x101 prefix | Current source proof stops before timestamps, runqueue work and possible context switch |
| High | Establish receive-side dequeue/copyout and match its message to daemon RPC dispatch | Internal pointer publication is insufficient for authentic daemon delivery |
| Medium | Temporary scratch occupancy and identify-mode hold form an inter-routine obligation | Extending selection in isolation must preserve the extra hold and final release contract |
| Medium | Port-set and hash structures are present in the original bodies | Null link chain and non-hash FIFO epoch leave these architectural paths unexecuted |
| Medium | Runtime open failure remains upstream of the observed daemon/kext transaction | The historical zut trace cannot supply a successful native interface exchange |
| Low | Numerical state masks recover local semantics without relying on guessed symbolic names | Native flag nomenclature and full state-machine admissibility remain unknown |

QG1: No normative conclusion is needed; this is descriptive interface analysis.

QG2: WR1-WR8 identify all component assumptions, dependent claims and falsification probes.

QG3: Routine roles, incoming caller ABI, membership/control flow, status/data publication, environmental context and reporting are covered for this increment. No new Mach endpoint is asserted. The broader investigation remains active.

QG4: Addresses/offsets/sizes are byte-based, little-endian fields have explicit widths, u32 arithmetic domains are recorded, counts are machine-derived and reproduction commands are supplied.

QG5: Selected-list ownership, extra nesting hold, free-versus-owned spin states, mask restoration, send/receive/wait status and prefix obligations are distinguished. Native backend eligibility and scheduler completion remain explicit unknowns.

QG6: Original KC bodies/words/symbols are recaptured; exact producer CPU/RAM/globals and declared overlays are pinned; independent semantic oracles and CPU replay pass. No native or historical-run provenance is inferred from synthetic components.

QG7: The bounded impact table identifies receive initialization, slow scheduling, copyout, port-set/hash and open-failure opportunities without extending these results to unobserved behavior.


The [block/wake handshake report](aes_block_wake_handshake_report.md) extends the numerical state0x101 frontier with original wake-state and counter bodies over declared private epochs. It establishes the ordinary helper result1 and placement(thread,5) interface. It does not resume the historical notification RAM component or establish native Mach delivery; that component retains its original prefix boundary (BH1-BH8).


The [AES runqueue membership report](aes_runqueue_membership_report.md) extends the prior placement frontier through the original bound-context backend and compact priority-ring insertion. It recovers maximum-increase return semantics, append/prepend flags, two occupancy words, classified/total counters, cumulative class increments and 1112/112/200 B record strides. Twenty-four new UNSAT checks, three abstract SAT controls and 4142 private cases pass, including twelve complete selected placement routes. Generic-backend completion, native ownership/scheduling and matched daemon-kext results remain unknown; the broader goal stays active (RQ1-RQ8).
