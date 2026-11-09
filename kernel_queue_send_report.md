# Kernel queue admission, insertion and receiver handoff

The original helper at `0xFFFFFE000BCC7C34` implements queue admission and
post-send flow. Original instructions now run continuously from the earlier
generated-reply caller component through this helper and, when selected,
through insertion at `0xFFFFFE000BCC2BC4`. The previous opaque queue-return
callback is absent from these cases. Dispatcher output, lock/scheduler helpers,
hash returns and logical pointer authentication remain explicit private models.

Three accepted outcomes are distinct: enqueue the message, hand its pointer
to a waiting receiver, or request destruction after the wait queue becomes
invalid. All return queue success in these selected paths. The insertion
helper's zero result does not mean insertion failed: it reports that QoS
propagation stopped before traversing the entire prior ring.

The [reply-send report](kernel_reply_send_report.md) establishes the outer
caller. This increment records the queue helper's return before the caller
handles it. The queue can report timeout/interruption/destination/buffer errors;
the generated-reply caller requests destruction with flag 1, clears its status
and returns zero. This private continuous execution still starts after a
substituted dispatcher return, not at a real daemon request or kernel receiver.
Native scheduler effects, right transfer and receiver-visible delivery are
unknown. No native kernel, IPC, queue or hardware authentication executed.

## Primary evidence

All addresses are unslid VAs in the original collection with SHA-256
`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.
Offsets/constants are hexadecimal; byte extents and counts are decimal.
LC_FUNCTION_STARTS and original bytes establish compiler spans. Exact original
nlist names are unknown for these roles; semantic names are source-correlated.

| Evidence | Scope |
| --- | --- |
| [Source](triage_evidence/kernel_queue_send_source.json) | Eleven functions, 1,187 unique instructions, original symbols and frozen reference provenance |
| [Profiles](triage_evidence/kernel_queue_send_profiles.json) | 146 caller-to-queue cases, full memory journals, helper models and source return cuts |
| [Proofs](triage_evidence/kernel_queue_send_proofs.json) | Eighteen bounded obligations and 36 original/simplified SMT files |
| [Independent checks](triage_evidence/kernel_queue_send_checks.json) | Fresh CPU reconstruction, source/proof rebuilds and SDK compilation |
| [Consumer joins](triage_evidence/kernel_queue_send_consumers.json) | Original-byte verification of producer/reader fields and matching DA authentication context |
| [Preservation](triage_evidence/kernel_queue_send_delivery.json) | Prior baseline and six allowed existing-file changes |
| [Quality gates](triage_evidence/kernel_queue_send_quality_gates.json) | Assumption-qualified QG1-QG7 |

The frozen Apple [ipc_mqueue.c reference](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_mqueue.c)
corroborates the ipc_mqueue_send_locked/post role, reservation semantics,
waiter selection and the distinction between accepted and delivered messages.
The [local copy](triage_evidence/xnu_namespace_reference_osfmk_ipc_ipc_mqueue.c.txt)
and its existing provenance are preserved. An exact native build match is
unknown; the binary, rather than reference field layouts, supplies offsets.
Current SDK assertions corroborate public status/option constants and byte
layouts only. They do not attest the kernel's runtime version.

## Source interfaces and admission

```text
caller BCC724C
  -> queue helper BCC7C34
       +-> reserve count or enter modeled wait machinery
       +-> relock and inspect wait queue
            +-> invalid -> destroy(message,0) request -> success
            +-> identify receiver (modeled)
                 +-> no receiver -> original ring insertion -> success
                 +-> unrelated waiter -> resume request -> search again
                 +-> receive waiter -> compute user extent/trailer/aux limits
                      +-> selected -> message+sequence handoff -> release count
                      +-> too large with option 4 -> error metadata -> retry
  -> queue return cut BCC7250
  -> outer generated-reply cleanup, when required -> caller return 0
```

| Register / source | Recovered contract |
| --- | --- |
| X0 at entry | Q, queue-related structure at destination D+0x28 |
| X1 | Message M; becomes X21 |
| X2 | Full options word; becomes X23 |
| X3 / W3 | Inherited scalar; source gates and deadline arithmetic consume low 32 bits as timeout input |
| BCC7C64 | Recovers destination D=Q-0x28 |
| Q+0 | u64 circular-message-list head |
| Q+8 | u32 sequence |
| Q+0x0C | u32 receiver-name field, source-correlated; native namespace provenance unknown |
| Q+0x10 / +0x12 | u16 reserved-message count / limit |

Let C be the initial u16 count, L the u16 limit, O the options and B the
kernel header bits. Source admission is:

```text
admit = (C < L) ||
        (C <= 0xFFFD && ((O & 0x10000) != 0 || (B & 31) == 18))
```

The reference correlates option 0x10000 with internal send-always and low-five
disposition 18 with a send-once message. Public MOVE_SEND_ONCE=18 is also SDK
checked; no genuine native right is inferred from a fixture's header value.
An admitted path increments the u16 count before unlocking. This count includes
reservations; equality with the number of linked messages is not assumed.
All-word count/limit/increment and hard-bound comparisons are symbolic checks.

When admission fails, source checks timeout-option bit 0x10 and zero W3 first,
returning 0x10000004. It then rejects count >=0xFFFE with 0x1000000D. Thus a
zero-timeout poll takes precedence over the hard-bound error. Other paths enter
turnstile/wait machinery. The reference names W3's scalar mach_msg_timeout_t;
the positive-timeout branch contains the integer factor 1,000,000 for deadline
scaling. That branch and native clock calibration are not executed here, so no
measured timeout duration or exact runtime timebase conversion is established.

| Modeled wait result | Original continuation | Queue result |
| --- | --- | --- |
| 0 | Retry posting after reacquiring lock | Depends on subsequent post state; success in these fixtures |
| 1 | Timeout branch | 0x10000004 |
| 2 | Interrupted branch | 0x10000007 |
| 3 | Destination-restart branch | 0x10000003 |
| Other | Diagnostic path | Not exercised |

These callback results are declared synthetic inputs. In particular the
timeout-result case uses a disabled timer fixture; it proves source handling
of result 1, not a legitimate native timeout under that configuration.

## Original insertion and QoS result channel

At BCC7ED0 the queue helper calls BCC2BC4 with X0=Q, X1=M. The latter runs
from original bytes, including pointer consistency checks and all link writes.

| Initial state | Source transformation |
| --- | --- |
| Empty head | M.next=M; M.previous=M; Q.head=M; return 1 |
| Nonempty ring with head H and tail T=H.previous | M.next=H; M.previous=T; T.next=M; H.previous=M; Q.head retains H |
| Nonempty consistency failure T.next != H | Diagnostic trap; outside the valid-ring profiles |

After insertion, the routine walks backward from M.previous. It compares the
u8 at M+0x3E against each predecessor's +0x3E. A strictly lower predecessor is
raised to M's QoS byte. A predecessor with an equal or higher byte stops the
walk and yields return 0. Reaching M after raising every predecessor yields
return 1. Both outcomes retain the insertion. This is propagation through
existing links, not a sort or a failed enqueue.

The 64 insertion-focused cases cover empty, one-node and two-node rings,
lower/equal/higher new QoS values and early/full backward propagation. Other
cases also reach insertion after waiter retry, admission bypass or awakened
wait. Byte-array proofs check empty and one/two-node link writes at fixed
disjoint placements; a separate all-byte comparison/update proof covers QoS.
No proof assumes all possible corrupted or overlapping ring placements valid.

## Receiver selection and metadata ABI

The identify helper at BD6CF80 is modeled. Its original caller at BCC7DF8
supplies X0=D+0x10, X1=0, W2=0, W3=0x40, X4=0. A NULL result selects enqueue
if a reservation remains. A non-NULL result R whose state at R+0x3A0 differs
from 0x10004001 is passed to resume-like helper BD6D0D4 and the search repeats.
This branch writes no message pointer to that waiter in the selected case.

For a receive waiter, the source reads a logically authenticated map pointer
from R+0x428 (DA discriminator 0x9E54), then computes message and trailer extents.
The profiles use a NULL map with a simple 44-byte kernel message. Original
copy-size helper BCC4BB4 yields u32(44-8)=36, accounting for the header-width
change; it does not establish full copyout or a destination user address.
The complex descriptor/SIMD branches are captured but unexecuted here.

Trailer-size helper BCC2068 extracts `(receive_options >> 24) & 15`:

| Selector | Returned trailer extent in bytes |
| --- | --- |
| 0 | 8 |
| 1 | 12 |
| 2 | 20 |
| 3 | 52 |
| 4 | 56 if u64(map+0x18) < 0xF0000001, otherwise 60 |
| 7 | 64 if u64(map+0x18) < 0xF0000001, otherwise 68 |
| Other | 68 |

Only selector 0 is executed continuously here. The map-dependent size
fragments have an all-u64-word symbolic obligation; the remaining constant
routes are statically decoded. The meaning of map+0x18 and native map ownership
are unknown. These sizes are not inferred from the trailer's advertised extent.

| Receiver location | Width / role |
| --- | --- |
| R+0x388 / +0x38C | u32 receive-message limit / auxiliary limit |
| R+0x390 | u64 receive options |
| R+0x3A0 | u32 receive state: success 0 or too-large 0x10004004 |
| R+0x3A4 | u32 sequence copied from Q+8 |
| R+0x3A8 / +0x3AC | u32 user-message extent / zero-extended u16 auxiliary extent on too-large path |
| R+0x3B0 | u32 receiver-name metadata on declined large receive |
| R+0x3B8 | Logically signed message pointer or NULL |

The ordinary size gate compares u32(message_extent + trailer_extent) against
the receiver limit. Receive option bit 32 additionally checks the auxiliary
limit. Option bit 60 instead combines auxiliary bytes into the first u32 sum.
Arithmetic wraps in u32; native valid allocation/extent invariants remain
separate. The current continuous cases use small extents and test both forms.

If the receiver fits, the source writes success. If it is too small, the
source records sizes and state 0x10004004. In either case, when option bit 2
(public MACH_RCV_LARGE=4) is clear, the receiver is still selected. The source
stores M at R+0x3B8 using a PACDA context with top 16 bits 0x33FF and low 48
bits of R+0x3B8, copies the old Q+8 sequence to R+0x3A4, increments Q+8, requests
receiver resume and decrements the reservation count. Native signing and
thread wakeup are not executed. The too-small-take case retains its error state.

For a too-small receiver with bit 2 set, source instead copies Q+0x0C to
R+0x3B0, sets the message pointer and sequence to zero, requests resume, and
searches again. The selected cases then obtain NULL and enqueue the message.
This distinguishes an error notification without message handoff from a
selected receive that carries both the message pointer and a size error.

An invalid wait queue at D+0x15 bit 0 clear requests destroy(M,0) and returns
success. This is distinct from the outer generated-reply error cleanup's
destroy(M,1). The opaque destroy model does not establish final object lifetime.

## Return, accounting and remaining boundary

The post path requests promotion cleanup with the current thread, unlocks,
obtains a current-task-like object through BD7E9C4, loads its +0x3D0 counter
base and adds the thread's u16 +0x1B8 value shifted left by 14. It atomically
increments the resulting u64 counter at BCC8228 and returns zero. The private
fixtures use index zero and initial counter UINT64_MAX, observing wrap to zero.
An all-u64 counter proof checks the atomic value/result channels; it does not
establish a particular native accounting allocation or concurrent ordering.

The queue return cuts contain 134 successes, six 0x10000004 results, two each
of 0x1000000D, 0x10000007 and 0x10000003. All 146 generated-reply caller returns
are zero after source cleanup as applicable. Native results could differ when
the declared helper, object, timing, allocation or authentication premises fail.

Fresh original-byte checks join these fields to two earlier consumer contracts:

| Field / producer | User receive-results reader | Kernel RPC completion reader |
| --- | --- | --- |
| u32 state at R+0x3A0; BCC7FE4 / BCC7EA4 | BCDCCFC, W0 | BCF5C48, W27 |
| u32 sequence at R+0x3A4; BCC8008 | BCDCD40, W8, then stack+0x20 | No corresponding sequence load established by this captured fragment |
| u64 message at R+0x3B8; BCC7FF8 | BCDCD04, X16 | BCF5C4C, X16 |
| DA context: storage address + top16 0x33FF | BCDCD0C, BCDCD10, BCDCD14 | BCF5C54-BCF5C5C |

The user reader belongs to [normal user receive-results/copyout](kernel_user_copyout_report.md);
the RPC reader belongs to [the separate kernel RPC wait](kernel_rpc_transport_report.md).
Both readers reconstruct the same DA modifier as the queue producer before
AUTDA. The original bytes of both prior consumer captures are rechecked, and
18 exact instruction roles establish three field agreements. This is a static
representation/interface join. Identical live receiver-thread identity,
continuous receiver execution and native authentication are unknown.

The next boundary is execution of the selected receiver continuation and
queued-message dequeue/user-copyout with right translation. A pointer written
into receiver state and a requested resume are not evidence of receiver
execution or user delivery. Generic-dispatch allocation/return remains modeled.

## Validation and assumption register

Independent replay reconstructs each private RAM image and system-register
fixture in a fresh CPU, checks original instruction words, every read/write,
all eight modeled call arguments, return cuts, final registers/SP/NZCV and
logical signing/authentication events. It shares Unicorn with the generator;
it does not reuse the generator executor and is not a second ISA engine.
The validator rebuilds the original capture and 18 obligations, resolves both
saved forms (36 SMT files), and compiles reconstructed layouts and public
Mach constants using the current arm64e SDK.

| Check | Verified count |
| --- | --- |
| Caller-to-queue cases / original instruction visits | 146 / 34,441 |
| Source reads / writes | 10,028 / 6,102 |
| Declared helper-model calls | 1,641 |
| Independently checked source return cuts | 336 |
| Original enqueue executions | 94 |
| Direct receiver message handoffs | 32 |
| Too-large receiver retry cases | 16 |
| Destruction requests across queue/outer caller | 20 |

From this directory, reproduce the bounded checks with:

```sh
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_queue_send.py
```

Time is O(source/artifact bytes + visits + solver/compiler resources); space
is O(collection metadata + one private CPU map + largest profile + DAGs).
The source/probe/proof/replay/validator scripts are retained with dependency
hashes. No original input, IDB or saved analysis memory is modified.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| QS1 | Original image and unslid mapping identify this compiler epoch; all source claims depend on it | Rehash the original and independently recover function bounds/load mappings |
| QS2 | Selected post-dispatch caller frames and distinct reply allocations are valid private premises | Execute upstream caller/generic-dispatch source with complete request/allocation state |
| QS3 | Model callbacks have declared register/return effects and no hidden memory effects; scheduling/locking outcomes depend on them | Recover and execute identify/resume/lock/turnstile helpers with genuine state |
| QS4 | Fixed disjoint queue/message/node/receiver objects bound proofs and profiles | Check aliasing, ownership extents, corrupted rings, count invariants and destruction races |
| QS5 | Logical AUTDA/PACDA steps preserve supplied pointers; handoff target identity is conditional | Attest native keys, discriminators, signed storage and matching runtime epoch |
| QS6 | Receiver map is NULL and message simple in continuous cases; size result 36 is conditional | Execute non-NULL map, complex descriptor/SIMD and auxiliary copyout paths |
| QS7 | Declared wait outcomes are synthetic, including timer-disabled result 1 | Verify real wait-result reachability, positive deadlines, clock calibration and scheduler transitions |
| QS8 | Modeled current-task/counter and thread index describe only a private accounting context | Establish native allocation extent, per-thread index and concurrent counter semantics |
| QS9 | Frozen Apple reference correlates names/semantics but is not an exact native build match | Compare version/UUID/build provenance and additional binary branches before assigning exact names |
| QS10 | Fresh replay shares the CPU engine; all passing results are model/source consistency evidence | Cross-check another ISA implementation and native receiver/user-space observations |
| QS11 | Producer and consumer use the same receiver-record representation, but live thread identity is unestablished | Attest the selected receiver thread and execute its continuation with source-produced fields |

## Bounded continuation and quality gates

| Impact | Further evidence | Interface question |
| --- | --- | --- |
| High | Receiver continuation consuming state/message/sequence and common copyout | When does the kernel pointer become an actual user-visible reply, including rights and trailers? |
| High | Original dequeue path and active receiver namespace | How do linked queue entries, reservation count and destination rights terminate? |
| High | Generic-dispatch allocation/return and real caller predecessor | Can the established receiver and queue contracts be joined without a substituted return? |
| Medium | Waiter identify/resume, lock and turnstile helper bodies | Which state and ordering contracts are hidden by scheduler callbacks? |
| Medium | Port classes 1/2, notification paths, admitted counts >=4096 and cancellation races | Which notification, tracing and destroyed-queue outcomes remain outside the profiles? |
| Medium | Complex messages, map-dependent trailer selectors and positive timeout branch | Which representation/extent/timebase conditions alter receive and wait behavior? |
| Low | Exact symbols or original matching headers | Which source-correlated labels can become exact names? |

QG1: The result is factual technical analysis without a normative conclusion.
QG2: QS1-QS11 list dependencies and explicit falsification probes.
QG3: Queue admission/post, insertion, direct handoff, too-large retry, return
channels and accounting are covered for this increment; the full goal remains active.
QG4: u8/u16/u32/u64 fields, modulo arithmetic, byte extents, code complexity,
SDK assertions and unmeasured timing units are explicit.
QG5: Successful insertion versus QoS return, accepted versus delivered,
destroy flags 0/1, raw queue versus caller return and synthetic timeout versus
native timer behavior are distinguished. Unexecuted branches are explicit.
QG6: Original captures, regenerated source/proofs, independent journals, SDK
checks and frozen primary-reference provenance support the scoped claims.
QG7: The impact table bounds ownership, scheduler, representation and runtime work.
