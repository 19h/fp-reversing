# Original port, turnstile and receive-wait producers

Original kernel initialization and receive setup now produce the port waitq, turnstile queue, receiver membership, wait result, priority word and thread state consumed by the preceding selection/handoff analysis. Eight families execute 32 producer components and eight sender components: 48 captured complete functions / 5827 instructions, 14669 original instruction visits. Independent full-memory replay, complete declared-record oracles and four bounded scalar proofs pass.

Five families reach the original thread_block call boundary with a receiver enqueued. Three return an abort result without inserting membership. The subsequent original sender consumes each complete producer RAM image without repairing the produced fields: five publish directly to the receiver; three enqueue the message. All eight sender components return0 through the original notification caller. These are separate call/CPU components; no actual block, context switch, concurrent interleaving or authentic FairPlay delivery is established.

The earlier priority-word threshold is corrected: `CMP X8,#0x10,LSL #12` compares against 65536, not4096. The previous zero-word cases are unaffected. A source-produced priority word0x1f00 supplies a counterexample to the earlier numerical description while remaining below the actual threshold.

## Primary evidence and assumptions

The original KC SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Preferred addresses, little-endian offsets and sizes below refer to that image; byte widths are explicit. No IDB or original input changed.

| Artifact | Evidence |
| --- | --- |
| [Source](triage_evidence/kernel_waitq_enqueue_source.json) | 48 complete bodies, exact symbols, 18 role sites, three initialization constants and original turnstile zone specification |
| [Profiles](triage_evidence/kernel_waitq_enqueue_profiles.json) | 32 producer and eight consumer components; exact RAM/global transfers; call and loan overlays; original reads/writes and boundaries |
| [Checks](triage_evidence/kernel_waitq_enqueue_checks.json) | Independent input/output oracles, fresh no-senders producer, 40 original CPU replays, four scalar queries and eight composed sender outcomes |
| [Recovery](triage_evidence/recover_kernel_waitq_enqueue.py), [probe](triage_evidence/probe_kernel_waitq_enqueue.py) | Extraction and explicit component construction |
| [Replay](triage_evidence/replay_kernel_waitq_enqueue.py), [validator](triage_evidence/validate_kernel_waitq_enqueue.py) | Separate executor and semantic checks; no probe executor import |
| [Delivery](triage_evidence/kernel_waitq_enqueue_delivery.json), [quality gates](triage_evidence/kernel_waitq_enqueue_quality_gates.json) | Preservation, owned correction, provenance and scoped gates |

The [preceding waitq report](kernel_waitq_receiver_report.md) establishes selection, temporary staging and release. The [common receive report](kernel_queue_receive_report.md) supplies the prior caller/status analysis and a frozen, separately versioned Apple source correlation. Original instructions, rather than source-version equivalence, establish the new fields and control flow. The [historical zut trace](zut_trace_report.md) still ends with failed UserClient open; this increment adds no events to it.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| WE1 | Original KC identity, compiler bounds and logical fixups identify these routines. All source claims depend on them. | Recapture complete bodies, exact symbols, role words, constants and zone specification; reject an image or mapping mismatch. |
| WE2 | Fresh zero port storage144 bytes and turnstile storage96 bytes are available. Port initialization and raw-allocation result depend on declared storage. | Execute actual allocation and recover zeroing/extent/lifetime guarantees. Original raw-allocation flag0x8004 and zone metadata do not independently attest native allocation success. |
| WE3 | The receiver begins with state4, a free spin lock/marker0x11, declared interruptibility limit, priority, pending-context pointer and no prior wait. Wait-state results depend on this context. | Recover actual thread initialization, pending abort updates and the incoming native frame. Invalid prior wait or state bit7 would reach guards outside these components. |
| WE4 | The source-returned turnstile is explicitly published to receiver+0x30 before receive setup. Loan consumption depends on that call-level patch. | Recover the native thread/turnstile loan producer and its ownership/reference protocol. This publication is not claimed as an original store in the retained call chain. |
| WE5 | Distinct component calls use fresh argument/GP/SIMD states, private SP and current receiver thread; only RAM/globals transfer exactly. | Establish original caller stacks/registers and uninterrupted execution. Initializer calls are reconstructed component entries, not an observed native call sequence. |
| WE6 | Sender entry uses the original no-senders CPU state and a different current thread, with the entire receiver-producer RAM image and globals. Composition results depend on this separate-context join. | Establish CPU assignment, permitted interleaving and scheduler/context transfer. Both modeled contexts use CPU-index0; no admissible concurrent native event order is inferred. |
| WE7 | Raw turnstile allocation, byte copy, opaque keyed hash, tag helper and send preflight obey the explicit contracts; PAC is logical. Caller outcomes depend on these lower effects. | Replace models with source execution or independently captured native effects; attest hardware keys/authentication separately. |
| WE8 | The retained simple44-byte notification, zero receive map, capacity44, zero timeout and selected flags bound the exercised path. | Extend to deadlines, multiple waiters, nonzero inheritors, actual blocking, continuations and receive copyout. Native FairPlay request/reply continuity remains unknown. |

## Recovered producers and call sites

Fourteen added routines contribute1680 instructions. Each addition has no exact symbol at its entry in the captured nlist. Roles are analytical descriptions.

| Preferred address | Instructions | Established role and executed boundary |
| --- | ---: | --- |
| 0xfffffe000bccd170 | 74 | Port initializer; source waitq/header/limit/name/receiver stores; returns with held ticket lock |
| 0xfffffe000bd682cc | 34 | Allocate/init a turnstile; raw allocator return remains modeled; source initialization and unlock execute |
| 0xfffffe000bd68474 | 83 | Prepare turnstile: consume current-thread loan, update type/generation and publish or chain it through supplied cell |
| 0xfffffe000bd28280 | 69 | Mark thread waiting or return abort; effective interruptibility and numerical state/result stores execute |
| 0xfffffe000bd6bc48 | 218 | Assert wait with nested queue locking; call mark-wait, insert membership, set event/identity and update priority/inheritor state |
| 0xfffffe000bd69c78 | 78 | Select numerical priority from turnstile class table; build receiver priority node and insert into heap |
| 0xfffffe000c48b42c | 27 | Meld heap nodes; singleton insertion into an empty root executes |
| 0xfffffe000bd69354 | 77 | Recompute turnstile cached priority from root/inheritor roots; selected no-inheritor path executes |
| 0xfffffe000bd68d08 | 403 | Inheritor propagation/state exchange; zero old/new inheritor path executes |
| 0xfffffe000bccece8 | 44 | Port-dependent inheritor adapter; selected object flags produce NULL inheritor |
| 0xfffffe000bd69ae8 | 100 | Set deferred inheritor context; selected NULL-inheritor branch executes |
| 0xfffffe000bcc83b4 | 88 | Common receive wrapper; original port lock, result branch and block-call setup |
| 0xfffffe000bcc8514 | 298 | Receive-on-thread selector; empty port setup, prepare turnstile and assert wait; status path to caller |
| 0xfffffe000bd69f7c | 87 | Deferred inheritor cleanup; zero pending pointer path executes |

Important original edges are port initialization from the previously recovered allocator context, receive call0xfffffe000bcc8404, turnstile preparation0xfffffe000bcc88cc, assert-wait0xfffffe000bcc8910 and thread-block call0xfffffe000bcc8448. The last callee is not executed. The receive wrapper's continuation=true branch is captured but unexecuted here. [WE1-WE8]

## Initialization, allocation domain and loan

Port input arguments are `(port,receiver_space,label_word,context,flags,name)` with declared label0x101, context0, flags0, receiver-space pointer and name0x303. Name0x303 remains a private argument, not an established Mach endpoint. Raw storage is zero before entry.

| Port field | Source-produced output / origin |
| --- | --- |
| +0x00 u32 | Label0x101 from the controlled argument and policy logic |
| +0x04 u32 | Initial reference count1 |
| +0x10 u32 | Waitq word0x000c000b; low type bits3, with additional original policy bits |
| +0x14 u32 | Held ticket0x01000144; original initialization raises receiver-thread nesting to1 |
| +0x18/+0x20 u64 | Cleared nested pointer/link fields |
| +0x28 u64 | Message head cleared |
| +0x30 u32, +0x38 u16 | Sequence/count remain0 from the explicit zero-storage precondition |
| +0x34 u32 | Receiver-name word0x303 from argument |
| +0x3a u16 | Default queue limit5, source store at0xfffffe000bccd21c |
| +0x48 u64 | Receiver-space pointer, source logical PAC signing and publication |

Original unlock then produces ticket0x01010144 and nesting0. This separates the initializer's held-lock return from a usable unlocked queue; simply copying its initial ticket into a send fixture would retain an extra lock obligation.

The turnstile startup specification identifies fixed zone28, requested size96 bytes, name `turnstiles`. The fixed metadata address is `0xfffffe000caeb480 + 28*192 = 0xfffffe000caec980`, exactly the two-cell view loaded by the allocator wrapper. Raw allocator arguments are declared zone/statistics pointers and flags0x8004. Its return is modeled as96 zero bytes; no native zone allocation occurs.

Source initialization loads constant2 at0xfffffe000700dd68, creates the empty type2 queue, initializes and releases its ticket, sets reference word+0x50 to1 and type/generation word+0x54 to0x100. It returns the supplied storage pointer. Original receive preparation consumes receiver+0x30, clears that loan field, publishes the turnstile at port+0x18 and changes turnstile+0x54 to0x204. Its proprietor field+0x48 receives the port pointer.

The separate loan publication between allocator and receive is explicit, with exact before image and allocation-return identity. Completion of native loan ownership/refcount lifecycle is unknown. In the selected abort paths the turnstile remains attached to the port at the wrapper return; later lifetime handling is outside this increment. [WE2-WE5,WE7]

## Receive wait, interruptibility, abort and priority

The original common receive is called with `(port+0x10,timeout=0,interruptibility,receiver,has_continuation=0)`. It acquires the port ticket. On an empty valid port it writes receive-in-progress0x10004001, prepares the turnstile, writes hint byte receiver+0x58d=2 and calls:

```text
assert_wait(waitq=port+0x10, event=0, interruptibility,
            urgency=0x10, deadline=0, leeway=0, receiver)
```

The wait routine checks prior identity/state, masks the admitted context and locks the nested queue and receiver spin. Let I=`input_interruptibility &3`, C=`u16(receiver+0xc8)&3`, E=`min(I,C)`, and F=`u32(receiver+0x210)`. With the other retained context fields, its original mark-wait predicate is:

```text
abort = (E != 0) AND ((F &0x10) != 0)
        AND ((E == 2) OR ((F &0x20) == 0))
```

When aborting, the general wait result is2, state remains4, hint+0x58d clears, and membership is not inserted. If F bit5 is set on this abort branch, the source clears F bits4/5. The original wrapper converts wait result2 to receive status0x10004005 and returns. No scheduler result model supplies the outcome.

When not aborting, source stores wait result0xffffffff and state `old_state | (E==0 ?0x9:0x1)`. Thus initial4 becomes0x0d for effective0 and5 for nonzero effective interruptibility. Byte+0xcb becomes1 only for effective2. Hint2 transfers from+0x58d to+0x58e, and+0x58d clears.

Original turnstile preparation selects class-table entry4, value4, so insertion consumes the numerical priority from receiver+0x216. It clears links, stores `(priority &0xff)<<8` at receiver+0x10 and inserts the node into the empty root. It stores event0 at+0x18 and outer waitq identity at+0x28, then recomputes the turnstile cached priority. No membership-pointer return model supplies this root. Nonempty multi-node heap melding and nonzero inheritor propagation are captured but unexecuted. [WE3-WE8]

| Family | I / C | F | Priority | Wait outcome / produced state | Original sender consumes produced membership |
| --- | --- | --- | ---: | --- | --- |
| 0 | 0 /2 | 0 | 0 | Before block; state0x0d | Direct publication |
| 1 | 2 /2 | 0 | 31 | Before block; state5 | Direct publication |
| 2 | 1 /2 | 0 | 63 | Before block; state5; DAIF0x200 restored | Direct publication |
| 3 | 2 /2 | 0x10 | 31 | Abort2; state4; F preserved | Message enqueue |
| 4 | 2 /0 | 0x10 | 95 | Effective0; before block; state0x0d | Direct publication |
| 5 | 1 /2 | 0x30 | 31 | Before block; state5; F preserved | Direct publication |
| 6 | 2 /2 | 0x30 | 31 | Abort2; state4; F becomes0 | Message enqueue |
| 7 | 1 /2 | 0x10 | 31 | Abort2; state4; F preserved | Message enqueue |

The numerical state mask and abort predicate come from original words, not guessed symbolic thread-flag names. Their meanings outside the selected context and full native state-machine admissibility remain unknown.

## Corrected priority-word threshold

At0xfffffe000bd6c78c the original singleton extraction compares node+0x10 against0x10 shifted left12:65536. A word containing only its low16-bit priority data is below that threshold. A word with encoded child-pointer bits above bit15 enters the lower heap-removal path. The retained source inserts no children, so the selected priority words0,0x1f00,0x3f00 and0x5f00 all take singleton extraction.

For priority31: `31*256 = 7936 =0x1f00`; therefore4096<=7936<65536. Independent original execution confirms the branch with this produced word. The scalar query proves all u8 priority-only words are below65536; it does not prove arbitrary heap membership or ordering.

The preceding report's field description is corrected in place. Its zero-word source/profile results and hashes remain unchanged; the publication audit records this additional owned report correction separately from the usual six reporting changes. The source instruction capture was already correct. [WE1,WE3,WE8]

## Complete-memory join and bounded control flow

```text
current receiver context R, separate original component calls
  zero port -> original port init (held) -> original unlock
  zero raw turnstile supply -> original turnstile init (unlocked)
  explicit source-result loan publication to R+0x30
      |
  original common receive -> original turnstile preparation
      +-> original mark-wait abort -> wrapper status0x10004005
      |                               no wait membership
      +-> original mark-wait/insertion -> before thread_block
                                      R state5 or0x0d, membership present
      |
      +== exact full RAM/global transfer; no field repair ==+
                                                           |
original no-senders CPU entry, separate current sender T ----+
  original construction/copyin/queue -> source membership selection
      +-> membership present -> identify/release -> fast state4
      +-> no membership      -> message ring enqueue
  original notification caller returns0
```

All producers use a private stack separate from the preserved sender's stack. The sender GP/SP/NZCV/SIMD entry comes from the original no-senders producer. It consumes the entire final receiver-producer RAM image and globals, with no additional private fixture applied at sender entry. Its earlier preparation metadata is retained only as metadata and explicitly not reapplied. The validator checks that no hidden field replacement repairs the join.

Original port ticket cycles end0x04040144, inner tickets0x03030144, task send counter1 and sender nesting0. Five source-produced receiver states reach the original state rewrite and end4; three aborted records remain unchanged by receiver selection while the message becomes queued. All eight callers return0. The general wait result, receive status, sender status and a thread-block boundary are distinct channels.

This establishes a local pre-block handoff contract. Because the actual block/context switch and concurrent sender event are absent, it does not establish native wakeup after a blocked receive. In particular, the prior state0x101 slow scheduler prefix remains unresolved. Priority cache values can remain after singleton removal in this selected identify mode; native deferred reconciliation/lifetime behavior is not inferred. [WE5-WE8]

## Independent validation

The validator reconstructs the prior prepared entry RAM from a freshly replayed no-senders producer and independently specified allocator/port/owner/waitq fixtures. It checks all32 producer RAM origins, before-image patches, explicit ABIs and exact globals. Independent output oracles cover complete declared144-byte port,96-byte turnstile and1536-byte receiver records, including initialization lock obligations, loan consumption, abort/non-abort states, priority and membership. Eight full-RAM sender joins and complete output records are checked separately from CPU trace equality.

Fresh replay verifies14669 original instruction visits,4007 reads /25858 bytes,2940 writes /20440 bytes,40 complete final RAM images /41943040 bytes,520 global ranges,50 producer frames and78 waitq handoff frames. Forty-eight API models remain: eight raw turnstile allocation results and five lower primitive results per sender. Byte-copy effects independently cover352 bytes. Logical authentication/signing remains distinct from hardware PAC.

Four scalar counterexample queries are UNSAT: effective interruptibility is one input and bounded by both; the source abort tree equals the compact predicate; every u8 priority-only node word is below65536; and the retained mark/stage/fast-release state expression returns4. Domains and solver queries are retained. They do not quantify over native timing, liveness, arbitrary initialized heaps, allocation success or full FairPlay behavior.

```sh
# Run from the repository root.

env PYTHONPATH=triage_evidence "$PYTHON" -P triage_evidence/recover_kernel_waitq_enqueue.py
env PYTHONPATH=triage_evidence "$PYTHON" -P triage_evidence/probe_kernel_waitq_enqueue.py
env PYTHONPATH="triage_evidence${Z3_PYTHONPATH:+:$Z3_PYTHONPATH}" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/validate_kernel_waitq_enqueue.py
```

Extraction is O(image+source) time/space. Execution/replay and validation are O(image+visits+RAM+effects), with O(image+RAM+journals) space; four fixed-width solver formulas have separate solver cost. Empty-root heap insertion is constant work in these components. No bound on general heap propagation, contention or scheduler latency follows.

## Bounded expansion and quality gates

| Impact | Further evidence | Resolved boundary |
| --- | --- | --- |
| High | Actual thread-block transition and admissible sender/receiver CPU event order | Separate source-produced pre-block state from wakeup of a blocked daemon |
| High | Native thread/turnstile loan creation and completion | Close the explicit +0x30 publication and attached-turnstile lifetime assumptions |
| High | Receiver copyout and actual daemon RPC dispatch | Connect internal publication to delivered FairPlay messages |
| Medium | Original port allocation and turnstile raw allocation/zeroing | Replace the fresh-storage and allocator-result premises |
| Medium | Multiple receivers, priority children and nonzero inheritor | Extend singleton/no-inheritor contracts to actual priority propagation |
| Medium | Native deadline/continuation/cancellation context | Cover omitted time and scheduler branches |
| Low | State names/private types from an exactly matching source build | Replace numerical labels without weakening original-byte provenance |

QG1: Descriptive technical findings require no normative conclusion.

QG2: WE1-WE8 register assumptions, dependent results and falsification probes.

QG3: Original initialization, receive wait/membership, priority/state/status channels, source-memory joins, correction and reporting are covered for this increment. No new Mach endpoint or emission is asserted; the full investigation remains active.

QG4: Byte widths, little-endian values, shift arithmetic, fixed-zone stride and scalar domains are explicit and reproducible. No native duration is inferred.

QG5: Held initializer return, raw allocation, explicit loan publication, pre-block states, abort status, separate CPU contexts and hardware/native boundaries are distinguished. The earlier4096 description is corrected to65536; its prior zero-case results remain valid.

QG6: Original bodies/words/constants/specification are recaptured. Fresh producer, independent input/output oracles, complete-memory joins, CPU/effect replay and four bounded scalar proofs pass. Native reachability and authentic transport remain unknown.

QG7: The impact table bounds blocking/event-order, loan lifetime, copyout, allocation, multi-waiter, deadline and source-version opportunities.

## Shared core reached by AES pointer events

The [event-registration report](aes_event_registration_report.md) establishes the AES global-hash route into this same original registration core. It preserves the distinction between port event 0 / urgency 0x10 and nonnull AES pointer events / urgency 0, and adds direct-source mark-wait and mutex-result certificates. Shared code and equal hash expressions do not establish equal event identity, queues, native membership or thread epochs (ER1-ER8).
