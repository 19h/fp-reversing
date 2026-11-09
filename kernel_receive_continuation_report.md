# Original kernel receive continuation and trampoline ABI

Original receive setup now installs its asynchronous continuation, enters the original thread-block prefix and stores the continuation/parameter pair before scheduler selection. Source-produced receiver records then pass through the original sender and into an original invocation fragment, stack trampoline and receive callback. The callback reaches the original user receive-results entry in ten components, reaches original guards in two and stops before context-key programming in two.

Independent validation covers 24 producer, six sender and14 dispatch components:57 complete captured functions /7485 instructions and13137 original instruction visits. Four bounded scalar proofs, complete declared-record oracles and44 fresh full-memory CPU replays pass. Scheduler selection/invocation, native blocking, hardware authentication, key programming and user copyout are not established. The invocation-fragment entry and saved stack are explicit premises, not a completed scheduler event.

## Provenance and assumption register

Primary KC SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Addresses are preferred VAs; offsets and extents are bytes, little-endian. Original inputs, IDBs and memory stores remain unchanged.

| Artifact | Evidence |
| --- | --- |
| [Source](triage_evidence/kernel_receive_continuation_source.json) | 57 complete bodies, exact symbols and18 continuation role sites |
| [Profiles](triage_evidence/kernel_receive_continuation_profiles.json) | Original producer/sender/dispatch runs, exact RAM origins, field/frame assumptions, logical authentication events and source journals |
| [Checks](triage_evidence/kernel_receive_continuation_checks.json) | Independent ABIs/state/status/stack/context oracles, fresh producer and CPU replay, four scalar proofs |
| [Recovery](triage_evidence/recover_kernel_receive_continuation.py), [probe](triage_evidence/probe_kernel_receive_continuation.py) | Source capture and explicit component construction |
| [Replay](triage_evidence/replay_kernel_receive_continuation.py), [validator](triage_evidence/validate_kernel_receive_continuation.py) | Independent executor and source/semantic verification; no probe executor import |
| [Delivery](triage_evidence/kernel_receive_continuation_delivery.json), [quality gates](triage_evidence/kernel_receive_continuation_quality_gates.json) | Preservation, owned reporting changes and scoped gates |

The [wait/enqueue producer report](kernel_waitq_enqueue_report.md) supplies port/turnstile initialization, membership and pre-block states. The [common receive report](kernel_queue_receive_report.md) supplies earlier synchronous status/channel evidence and separately versioned primary source/SDK correlation. The [user copyout report](kernel_user_copyout_report.md) analyzes later receive-results code; this increment stops at its entry and does not assert an uninterrupted copyout join. The [zut trace](zut_trace_report.md) still contains no successful FairPlay UserClient transaction or reverse work RPC.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| RC1 | Original KC identity, compiler bounds and logical fixups identify the source epoch. All source results depend on it. | Rehash and recapture all bodies, symbols and role words; reject an image/mapping mismatch. |
| RC2 | Port/turnstile zero storage, raw allocation result, thread fields, loan publication and lower primitive contracts retain the preceding producer premises. | Recover actual allocation/zeroing, loan lifetime, thread initialization and authenticated native objects. |
| RC3 | Fresh component calls and separate sender/receiver CPU contexts transfer RAM/globals exactly but do not establish an admissible concurrent event order. | Establish real CPU assignment, scheduling and original caller stacks. Both retained contexts use index0; no native interleaving is inferred. |
| RC4 | The invocation fragment at0xfffffe000bd2a1d0 receives X19=current receiver, X21/X25=source-stored continuation/parameter. Dispatch conclusions depend on these explicit reconstructed registers. | Execute full scheduler selection/invocation from complete processor/processor-set state and compare the original incoming frame. No whole scheduler return is modeled here. |
| RC5 | Receiver+0x158 names a declared aligned private stack top. The modeled processor context-cache fields and per-thread context words are readable. Stack/entry results depend on this context. | Recover native stack allocation/signing and complete processor ownership/extents. The private stack is not evidence of native stack validity. |
| RC6 | PAC signing/authentication and BLRAA preserve declared logical targets; hardware keys and native authentication are untested. | Validate actual signed pointers and hardware context separately. Mismatches stop before key-register programming; synthetic context words are not captured keys. |
| RC7 | Wait-result/status/state/context variants are controlled ABI probes; only unmodified sender-produced fields constitute the source data joins. | Produce timeout/interruption/cancellation through original scheduler/timer paths. The bit7 experiment does not establish a valid idle/user-receiver state. |
| RC8 | Zero cleanup flag bit13 and selected simple-message/map/size contexts bound the executed callback path. | Recover nonzero cleanup work, original receive-results completion, namespace translation and actual daemon callback dispatch. Native FairPlay delivery remains unknown. |

## Routine roles and coverage

Nine additions contribute1658 instructions. Complete capture does not imply execution of every branch. Scheduler selection is an entry stop; invocation executes only a small declared fragment.

| Address | Instructions | Role / current coverage |
| --- | ---: | --- |
| 0xfffffe000bd28f6c | 117 | Thread-block wrapper: mask context, clear pending low bits, store continuation/parameter, call scheduler selection; prefix executes |
| 0xfffffe000bd29140 | 969 | Scheduler selection body; captured, stopped before entry |
| 0xfffffe000bd2a064 | 435 | Thread invocation body; captured; only source fragment0xfffffe000bd2a1d0 through continuation call executes |
| 0xfffffe000be8b3c4 | 4 | C wrapper forwarding to architecture continuation trampoline |
| 0xfffffe000bc9c300 | 56 | Restore authenticated stack, compare context cache, optionally enable mask group and call authenticated continuation |
| 0xfffffe000bcc89bc | 50 | Receive continuation: map wait result into receive status or validate existing status, then enter completion |
| 0xfffffe000bcdd12c | 7 | Receive completion wrapper: cleanup, X0=0 and call user receive-results |
| 0xfffffe000bccf10c | 18 | Conditional thread cleanup; bit13-clear return executes |
| 0xfffffe000be82048 | 2 | Tail-call adapter to original DAIF mask helper |

The compiler-bounded invocation body also contains another continuation-call path that clears the selected thread's pair at0xfffffe000bd2a340. That path is static evidence here. Other thread-switch, stack-allocation and retirement paths remain unexecuted. [RC1-RC8]

## Continuation installation and block prefix

For a successful wait assertion, common receive with `has_continuation=1` computes callback0xfffffe000bcc89bc, logically signs it with discriminator0xd507 at0xfffffe000bcc8428 and calls thread-block at0xfffffe000bcc8438 with `(continuation,parameter=0,reason=0)`. With flag0 it calls at0xfffffe000bcc8448 with a NULL continuation. A synchronous abort does not enter this block path, even when the continuation flag is1.

Original thread-block code obtains the current receiver, checks DAIF bit9, masks the0x1c0 group when required, clears low five pending-context bits, then stores the pair at0xfffffe000bd29008:

| Receiver offset | Width | Source-produced role |
| --- | ---: | --- |
| +0xd8 | 4 | General wait result; initially0xffffffff on the enqueued path, later0 from original sender release |
| +0xe0 | 8 | Continuation pointer; callback orNULL from actual common-receive branch |
| +0xe8 | 8 | Continuation parameter;0 in these source calls |
| +0x158 | 8 | Saved stack top used later by architecture trampoline; declared for dispatch, not produced by this prefix |
| +0x1f8 | 4 | Numerical thread state;5 or0x0d at the scheduler-selection boundary,4 after selected sender release |
| +0x3a0 | 4 | Receive status; in-progress, success, too-large or mapped receive failure |

The original block call at0xfffffe000bd29030 passes `(receiver,CPU_data,reason_pointer)` to0xfffffe000bd29140. Execution stops before that callee. A source entry mask0x200 becomes0x3c0 at this prefix; restoration has not occurred. Sender and later dispatch contexts are separate explicit CPU entries, so this prefix mask is not silently treated as a completed caller return.

| Producer family | Continuation flag / receive capacity | Original producer boundary | Subsequent original sender |
| --- | --- | --- | --- |
| 0 | 0 /44 | Scheduler-selection prefix; stored pointerNULL | Publishes to receiver; sender returns0 |
| 1 | 1 /44 | Scheduler-selection prefix; stored callback | Publishes status0; sender returns0 |
| 2 | 1 /43 | Scheduler-selection prefix; stored callback | Publishes too-large0x10004004 plus kmsg pointer; sender returns0 |
| 3 | 1 /44, entry DAIF0x200 | Scheduler-selection prefix, mask0x3c0 | Separate sender entry/return mask0x200 |
| 4 | 1 /44, effective interruptibility0 | Scheduler-selection prefix; numerical state0x0d | Source release reaches state4/status0 |
| 5 | 1 /44, abort flag0x10 and effective2 | Common receive returns wait result2/status0x10004005; no continuation installation | No membership; sender enqueues and returns0 |

All producer RAM/global images are transferred exactly into sender components. No receiver field repair is applied at sender entry. The source continuation field survives sender handling. These data joins do not execute scheduler selection or prove that the same native event order occurs. [RC2-RC4]

## Invocation fragment and architecture dispatch ABI

The full invocation body loads a continuation/parameter pair at0xfffffe000bd2a09c. The executed component begins later at0xfffffe000bd2a1d0 with X19=receiver and X21/X25 explicitly reconstructed from the source-stored fields. It executes the original pair clear, state/result loads, argument moves and call. This is a fragment entry with declared registers, not evidence that the intervening scheduler/invocation instructions executed.

| Dispatch boundary | Original ABI / effect |
| --- | --- |
| 0xfffffe000bd2a1d0 | Clear receiver+0xe0/+0xe8 with STP zero |
| 0xfffffe000bd2a1d4..0xfffffe000bd2a1e0 | Read state, compute X3 low bit as `1 & ~(state >>7)`, load u32 wait result into W2 |
| 0xfffffe000bd2a354..0xfffffe000bd2a35c | X0=continuation, X1=parameter, X2=wait result, X3=enable flag; call wrapper |
| 0xfffffe000bc9c308..0xfffffe000bc9c318 | Load saved stack at receiver+0x158; logical AUTDA modifier uses discriminator0x6d42 and field address; assign SP |
| 0xfffffe000bc9c31c | Clear frame pointerX29 |
| 0xfffffe000bc9c3b0..0xfffffe000bc9c3b8 | If X3 nonzero, call original mask helper through adapter with argument1 |
| 0xfffffe000bc9c3bc..0xfffffe000bc9c3c8 | X0=parameter, X1=wait result; BLRAA continuation with modifier0xd507 |

The stack top is declared at a separate16-byte-aligned private address. At callback entry, original SP equals that address and FP is0. The full invocation fragment has already cleared the stored continuation pair. The word at receiver+0xd8 is distinct from receive status at+0x3a0; loading W2 zero-extends its32 bits before forwarding them to the callback's W1 channel.

The enable flag is a numerical source expression. A controlled state0x84 experiment makes it0 and preserves mask0x3c0. Ordinary retained state4 makes it1: the original helper yields mask0x200 from0x3c0, or keeps0x200 when already enabled. State0x84 is an ABI branch probe, not an established valid native user-receiver context.

### Context-cache boundary

Before forwarding the callback, the trampoline compares two64-bit per-thread context words at+0x1d0/+0x1d8 with corresponding processor-cache words at+0x200/+0x208. Equal words bypass the register-programming paths. Equal synthetic nonzero pairs0x55/0x66 exercise the same bypass; zeros are not the equality condition itself.

A first-word mismatch reaches0xfffffe000bc9c338, and a second-word mismatch reaches0xfffffe000bc9c380. Both components stop before the first programming instruction on their respective branches. Source capture retains those branches, but no key/system-register write executes, no native key value is read and no authentication result is inferred. At both stops the saved pair is already cleared and the stack has changed, so they are partial obligations rather than completed continuation calls. [RC4-RC7]

## Receive callback and status projection

The original callback at0xfffffe000bcc89bc receives `(parameter,wait_result)`. It uses W1 to map the general wait result or validate an already-published receive status. The signed comparisons are included in the all-u32 scalar proof, including values with bit31 set.

| Wait result | Existing receive status | Original callback behavior |
| --- | --- | --- |
| 0 | 0,0x10004004 or0x1000400e | Preserve status and call completion |
| 0 | Other values | Original receive-state guard; no completion |
| 1 | Any retained status | Store0x10004003 and call completion |
| 2 | Any retained status | Store0x10004005 and call completion |
| 3 | Any retained status | Store0x10004006 and call completion |
| Other u32 | Any retained status | Original wait-result guard |

The earlier common-receive source/SDK correlation identifies the1/2/3 mappings as receive timeout, interruption and port change. These are controlled wait-result probes here, not native timer/cancellation observations. Status0x1000400e is retained numerically without extending its operation semantics.

On completion, original0xfffffe000bcdd12c calls conditional cleanup0xfffffe000bccf10c. In the retained bit13-clear context the helper returns without its lower operation. The wrapper then sets X0=0 and calls user receive-results0xfffffe000bcdcc7c. Every accepted component stops before entering receive-results. Status remains at receiver+0x3a0; the source-produced too-large record reaches this boundary with status0x10004004, message pointer preserved and X0=0. Thus neither the invocation flag nor X0 at the results entry is a replacement for receive status. [RC7-RC8]

## Component data/control map

```text
original port/turnstile init and receive wait
  +-> abort -> synchronous status return; no installed continuation
  +-> enqueue -> original block prefix stores callback/parameter
                    |
                    +-> STOP before scheduler selection
                    |
                    +== full RAM/global transfer ==+
                                                   |
original no-senders CPU -> original sender/selection/release
  -> thread wait_result0 and receive status0 or too-large
  -> original notification caller returns0
                    |
                    +== full RAM transfer ==+
                                            |
explicit X19/X21/X25 invocation-fragment entry + declared saved stack
  -> original clear/loads/call
  -> stack trampoline
       +-> context mismatch -> STOP before programming
       +-> matched context -> original mask handling
            -> logical authenticated callback
                 +-> invalid result/status -> STOP before guard callee
                 +-> accepted -> cleanup -> STOP before user receive-results
```

No new incoming/outgoing Mach endpoint or emission is established. These are kernel receive-control interfaces beneath the previously established FairPlay transport paths. The diagram's memory transfers preserve data while leaving scheduler event order and native control continuity unproven. [RC2-RC8]

## Validation and reproduction

Independent input plans rebuild the prior prepared RAM from a fresh no-senders producer. All24 producer before images, complete declared144-byte port/96-byte turnstile/1536-byte receiver outputs, block storage, six exact sender joins and14 exact dispatch joins are checked. Independent status, pair-clear, stack-discriminator, callback-argument, mask and context-frontier expectations are separate from CPU trace equality.

Fresh replay checks13137 original instruction visits,3457 reads /22209 bytes,2598 writes /18252 bytes,44 complete final RAM images /46137344 bytes and572 global ranges. It checks96 block/dispatch frames,14 logical saved-stack authentication steps and12 logical authenticated callback edges. Four code-signing steps originate in the non-null asynchronous receive setup. Fourteen dispatch components have no API result models; the36 remaining models belong to raw allocation and sender primitives. Copy effects independently cover264 bytes.

Four scalar counterexample queries are UNSAT: the signed callback branch tree equals the accepted wait/status partition; invocation enable depends only on state bit7; context equality bypasses both reload frontiers; and wait result0 preserves receive status. The last query assumes wait_result32=0; other domains are the recorded complete fixed-width scalar spaces. None proves native reachability, valid stacks, hardware PAC, scheduling or user delivery.

```sh
cd /Users/___/dev/dylex/extracted

env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_receive_continuation.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_receive_continuation.py
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_receive_continuation.py
```

Extraction is O(image+source) time/space. Execution/replay and validation are O(image+visits+RAM+effects), with O(image+RAM+journals) space; four fixed-width solver formulas have separate solver cost. No bound on scheduler selection, contention, context-switch duration or receive latency follows.

## Bounded expansion and quality gates

| Impact | Further evidence | Interface resolved |
| --- | --- | --- |
| High | Original scheduler selection/invocation from complete processor-set state | Replace the explicit invocation-fragment registers and establish actual block/wakeup control continuity |
| High | Full receive-results execution from these produced records | Connect continuation completion to copyout and daemon dispatch |
| High | Original saved-stack allocation/signing and thread/CPU context establishment | Replace stack/context premises without treating logical PAC as native validation |
| Medium | Actual timer/cancellation paths producing wait1/2/3 | Distinguish real event causality from callback status mapping |
| Medium | Bit13 cleanup and nonzero ancillary receive work | Close resource/lifetime branches omitted by the retained context |
| Medium | NULL-continuation return through original caller stack | Extend the synchronous block-return path independently of callback dispatch |
| Low | Matching private types/symbols | Replace descriptive roles while preserving exact source provenance |

QG1: This is descriptive technical analysis; no normative conclusion is needed.

QG2: RC1-RC8 register assumptions, dependent results and falsification probes.

QG3: Continuation storage, block prefix, invocation-fragment ABI, saved-stack/context boundary, callback status projection and original receive-results entry are covered for this increment. Scheduler/copyout completion and the full multi-layer goal remain open.

QG4: Byte extents, field widths, signed/unsigned comparisons, bit7 expression, discriminator construction and fixed-width proof domains are explicit and reproducible.

QG5: Source RAM joins, reconstructed fragment registers, controlled status probes, general wait versus receive status, pair clearing, partial mask obligations and native/hardware boundaries are separated. Unsupported wait/status and context reloads retain explicit source stops.

QG6: Complete original bodies/symbols and role words are recaptured. Fresh producer, independent semantic oracles, full-memory joins, CPU/effect replay and four bounded scalar proofs pass. No native scheduler, authentication, key programming or transport claim follows.

QG7: The impact table bounds scheduling, receive-results, saved-stack/context, timer/cancellation, cleanup, NULL-continuation and source-nomenclature opportunities.
