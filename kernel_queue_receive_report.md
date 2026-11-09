# Common queue receive, dequeue and recipient-state contracts

The original common receive wrapper at `0xFFFFFE000BCC83B4` calls the receive
selector at `0xFFFFFE000BCC8514`. Its queued-message path now executes from
source-produced queue state through original sizing, unlinking, reservation
release, sequence publication, logically signed message storage and receive
accounting. Separate components feed source-produced direct handoffs into the
original user and kernel RPC field readers. These extend the prior
[queue-send and handoff analysis](kernel_queue_send_report.md).

The receive status channel is thread+0x3A0. The selector returns internal
wait-result value 10 when it completes synchronously, including size errors or
an empty zero-timeout poll. The common wrapper leaves that value in X0 on the
selected path; it is not a public Mach receive status. The user caller proceeds
to receive-results and the kernel RPC caller loads thread state. Source values
left in X0 must not replace those fields in an ABI model.

These are private state transfers and original-instruction executions, not a
native sender/scheduler/receiver round trip. New receiver frames, older ring
payloads, locks, scheduler callbacks, object checks, hash outputs and logical
PAC are declared models. Native rights conversion, receiver execution and
user-visible delivery remain unknown. No native kernel, IPC or scheduler runs.

## Primary evidence and reproduction

All addresses are unslid VAs. Original collection SHA-256 is
`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.
Offsets/constants are hexadecimal; byte extents and counts are decimal.
Compiler bounds use LC_FUNCTION_STARTS. Exact original nlist names remain
separate from descriptive source-correlated roles.

| Artifact | Content |
| --- | --- |
| [Source](triage_evidence/kernel_queue_receive_source.json) | Seven functions, 787 unique instructions, reader/caller fragments and original error-state constant |
| [Profiles](triage_evidence/kernel_queue_receive_profiles.json) | 373 source-state transfers with original instruction/memory/helper journals |
| [Proofs](triage_evidence/kernel_queue_receive_proofs.json) | Twenty-one source-lifted obligations and 42 original/simplified SMT files |
| [Checks](triage_evidence/kernel_queue_receive_checks.json) | Fresh independent replay, prefix/state-transfer checks, source/proof rebuilds and SDK assertions |
| [Preservation](triage_evidence/kernel_queue_receive_delivery.json) | Prior baseline preservation and six allowed existing-file changes |
| [Quality gates](triage_evidence/kernel_queue_receive_quality_gates.json) | Scoped QG1-QG7 and native-evidence boundaries |

The frozen Apple [ipc_mqueue.c reference](https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_mqueue.c)
correlates the common receive, receive-on-thread, select-on-thread and wait-result
roles. Its exact native build match is unknown; original bytes supply addresses,
offsets and behavior. Current SDK assertions corroborate public option/status
constants and reconstructed layouts, not the runtime version or private types.

From this directory, reproduce with the existing local interpreter/solver:

```sh
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_queue_receive.py
```

The validator independently rebuilds source/proof obligations and verifies
both saved SMT forms, compiles the reconstructed arm64e layout, validates the
upstream state-transfer prefix and reconstructs every CPU case. Time is
O(artifact/source bytes + private-map cases + visits + solver/compiler resources);
space is O(collection metadata + two private maps + largest profile + DAGs).
Replay shares Unicorn with the generator but does not reuse its executor.

## State provenance and control flow

The seed is the prior 146-case queue-send artifact, whose original queue/insertion
instructions and write journals were independently checked. For each new case,
the generator reconstructs zero-initialized private RAM, applies the seed's
original fixtures and then every source write in journal order. The new validator
checks that this prefix is exact. Queued-receive cases additionally require the
queue bytes at entry to equal the seed's final queue bytes.

The receiver context is then explicitly initialized. Older ring nodes receive
simple-message payloads because the insertion contract did not establish their
payloads; their source-produced links and QoS remain intact. This is a declared
extension of the private preconditions. It does not establish that those payloads
existed in a historical native process. In a populated ring the original selector
takes the older head, not the newly appended reply at the tail.

```text
verified queue-send state
  -> exact fixture/write-log transfer
     +-> new receive frame -> common wrapper -> receive selector
     |    +-> queued head fits / size error accepted
     |    |    -> unlink -> release count -> sequence/message/state -> accounting
     |    +-> too large with option 4
     |    |    -> object/integrity checks with modeled helpers
     |    |    -> metadata + NULL message -> preserve queue
     |    +-> empty -> timeout / modeled wait or block -> thread receive status
     +-> source-produced direct receiver record
          -> original user/RPC reader fragment -> explicit consumer cut
```

There is no modeled common-receive/selector/dequeue callback. Those bodies execute
from original bytes. A fresh CPU and new frame separate the transferred state
from an actual concurrent event order or live thread identity.

## Entry ABI and port/port-set selection

| Argument at BCC83B4 | Recovered role |
| --- | --- |
| X0 | Wait queue W, usually destination D+0x10 |
| X1 | Timeout scalar; source gates and positive-deadline arithmetic consume low 32 bits |
| X2 | Interruptibility value, forwarded to the wait helper |
| X3 | Receiving thread R |
| X4 | Has-continuation flag, selecting a non-NULL continuation on the blocking branch |

The wrapper locks W+4 via BD0AECC and calls BCC8514 with the first four
arguments. The selector loads u64 receive options from R+0x390. It examines
u32(W)&7: type 3 takes a port queue; type 5 asks a modeled prepost helper at
BD6BFB0 for a port wait queue. Other types take a diagnostic path.

| Selection | Original behavior |
| --- | --- |
| Port type 3 | Load head from W+0x18 = D+0x28; if non-NULL, recover D=W-0x10 |
| Port-set type 5, non-NULL prepost result P | Unlock the set, recover D=P-0x10 and load head at P+0x18 |
| Empty port or no prepost result | Test wait-queue validity and timeout/wait conditions |

Sixteen queued cases execute the port-set caller branch with an explicit
prepost return; actual set membership, lock transfer and native prepost list
semantics remain modeled. The selected cases supply R=current-thread in the
private TPIDR_EL1 fixture. This equality is a precondition, not runtime attestation.

## Size gates, message preservation and dequeue

The original helpers BCC4BB4 and BCC2068 execute for queued messages. The
simple 44-byte kernel representation yields a 36-byte user message and an
8-byte trailer for selector zero. Receiver map pointers are NULL. Complex
descriptor/SIMD conversion, alternate trailer selectors and native map ownership
are outside these continuous receive cases.

The u16 auxiliary extent comes from message+0x30. Ordinary mode compares the
u32 message+trailer sum with R+0x388. Receive-option bit 32 additionally compares
the auxiliary extent with R+0x38C; bit 60 instead includes it in the first u32
sum. The symbolic identities cover all words and u32 wrap; profiles use small
representable sizes. Actual user buffer allocation validity is not proved.

| Size outcome | Option 4 clear | Option 4 set |
| --- | --- | --- |
| Fits | Remove head, publish message and success state | Same dequeue path |
| Too small | Remove head, publish message and state 0x10004004 | Preserve queued head/links/count/sequence; publish size metadata and NULL message |

On the preserve path, source BCC8654-BCC8664 copies the u32 receiver-name field
from D+0x34, clears R+0x3B8, and stores user-message/auxiliary extents at R+0x3A8
and +0x3AC. BCC8668-BCC8670 copies the original eight-byte constant from
`0xFFFFFE000700DC70`: u32 state 0x10004004 followed by zero sequence.

Before those stores, BCC8650 calls the original signature-check body BCC222C.
That body executes storage selection, canonical-header/trailer construction and
the final tag comparison. Its object-validation helper BD794C4 and the two
PACGA-fold outputs remain models. The header/trailer inputs are recorded. A
matching comparison under arbitrary declared hash outputs does not establish
native object validity, hardware keys or native integrity acceptance. Older-node
tag bytes are fixture data, not native authenticated records.

The dequeue path validates both neighboring links before mutation. For a
multi-node head H with next N and previous T, it writes T.next=N and N.previous=T,
updates the head to N, and clears H's two link words. A sole node clears the head
and its links. Invalid rings take diagnostic paths outside the profiles.

| Dequeue effect | Original site / width |
| --- | --- |
| Unlink neighbors / clear selected links | BCC86C8-BCC86E8; u64 pointer fields |
| Release reservation | BCC86F0-BCC86F8; u16(D+0x38) decremented |
| Publish sequence | BCC8750-BCC875C; old u32(D+0x30) stored at R+0x3A4, queue value incremented |
| Publish message | BCC87A4-BCC87B0; DA discriminator 0x33FF with low 48 bits of R+0x3B8 storage address |
| Publish receive status | BCC87B4; u32(R+0x3A0) = success or size error |
| Receive accounting | BCC87C4-BCC87D4; task-associated +0x3D8 counter base, thread index<<14, u64 atomic increment |

Count release can notify blocked senders and re-reserve a slot on other paths.
Those notification branches are captured but unexecuted here; entry fixtures
clear the pending-full-waiter flag. The source clears its empty-queue bit when
the head becomes NULL. Current receive-counter fixtures use index zero and
UINT64_MAX, observing wrap to zero. Native accounting allocation and concurrency
semantics remain unknown.

## Thread-state results, blocking and caller readers

| Receive path | Selector/wait value observed | Thread receive state |
| --- | --- | --- |
| Queued fit | 10 | 0 |
| Queued size error, either take or preserve | 10 | 0x10004004 |
| Valid empty queue, option 0x100 and zero timeout | 10 | 0x10004003 |
| Invalid empty queue | 3 | Wrapper writes 0x10004006 |
| Modeled wait/block result 1 | 1 | Wrapper writes 0x10004003 |
| Modeled wait/block result 2 | 2 | Wrapper writes 0x10004005 |
| Modeled wait/block result 3 | 3 | Wrapper writes 0x10004006 |

The current SDK and frozen reference identify 0x10004006 as
MACH_RCV_PORT_CHANGED. The names are corroborating provenance; the original
source's numeric stores remain the direct evidence.

For an empty blocking receive, the selector writes in-progress state 0x10004001,
prepares a turnstile for a port, sets a pending-receive hint and calls BD6BC48
with wait queue, event 0, interruptibility, urgency 0x10, deadline, leeway 0 and R.
The profiles use no positive deadline. A modeled wait result UINT32_MAX makes
the wrapper call thread_block with a NULL continuation; three cases then supply
results 1/2/3. These test status mapping, not native wait-result reachability or
measured scheduling/timeouts. Result 0 directly from assert-wait is a diagnostic
path in this selector and is not supplied.

The wrapper's completed-state gate allows thread status 0, 0x10004004 or
0x1000400E after an awakened result; other values select diagnostics. The gate
has an all-u32 symbolic obligation. The asynchronous continuation BCC89BC is
captured but not executed; has-continuation=true blocking behavior remains open.

| Caller / reader | Source-backed channel |
| --- | --- |
| User call BCDD6D0 | Supplies interruptibility 2 and continuation flag 1; later sets X0=0 and tail-branches at BCDD708 to user receive-results BCDCC7C |
| User reader BCDCCFC / BCDCD04 | Reads u32 state and u64 message from the receiver record; reconstructs DA context 0x33FF |
| Kernel RPC call BCF5C44 | Its next instruction at BCF5C48 loads u32 state into W27; X0 is not its receive-status channel |
| Kernel RPC reader BCF5C4C | Loads and logically authenticates the message using the same R+0x3B8/0x33FF context |

The 64 reader components use actual source-produced direct-handoff fields from
the prior send cases, then execute these reader prefixes in a fresh private CPU.
Their entry thread registers are explicit premises; the cuts precede completion,
rights translation or copyout. Thus field transport is checked beyond the prior
static join, while full receiver execution and final user delivery remain open.

## Validation and assumption register

The 373 cases comprise 298 queued receives (196 dequeues and 102 large-message
preservations), 64 direct-handoff reader components and 11 empty/wait cases.
All 373 upstream fixture/write prefixes are checked. Independent replay checks
49,588 original instruction visits, source reads/writes, eight helper arguments,
declared volatile-register clobbers, return cuts, logical PAC events and final
register/SP/NZCV states. The 21 rebuilt obligations and both saved forms (42 SMT
files) cover arguments, size gates, field publication, unlinking, count/sequence
arithmetic, counter wrap, wait-state mapping and reader authentication contexts.

The state-transfer prefix is verified independently of the generator. The
receiver's selected message, remaining ring links, head/count/sequence, receive
state and accounting are checked separately from trace equality. Preserve cases
require the original queue and ring links to remain unchanged. These checks do
not prove native allocation, concurrency or scheduler effects.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| QR1 | Original collection and unslid mapping identify this source epoch | Rehash original bytes and independently recover mappings/function bounds |
| QR2 | Upstream queue-send fixtures and source-write journals describe a valid private seed | Independently replay the producer and compare actual native queue state |
| QR3 | New receiver frames and current-thread equality are explicit valid private premises | Establish live thread, task, map, namespace and frame ownership |
| QR4 | Older ring-node payloads are declared simple-message fixtures; only their links/QoS came from prior source | Recover native older messages and authenticate their extents, storage and ownership |
| QR5 | Lock, prepost, task, turnstile, object-check and scheduler callbacks have declared effects only | Execute their bodies with complete state, locking and race context |
| QR6 | Logical PAC preserves fixture targets and opaque hash outputs match fixture tag words | Attest native keys, signed storage, object validation and integrity checks |
| QR7 | Receive messages are simple, maps NULL and sizes small/representable in continuous profiles | Exercise complex descriptors, non-NULL maps, other trailer selectors and valid extent boundaries |
| QR8 | Port/set type, validity and pending-waiter flags describe selected private branches | Verify native set membership, cancellation, notification and lock-transfer paths |
| QR9 | Supplied wait/block results are synthetic, with no positive deadline or real scheduling | Observe native wait-result reachability, continuation transfer and calibrated deadlines |
| QR10 | Counter base/index and receiver-reader registers are component premises | Verify native accounting allocation, actual reader frame and source-produced thread identity |
| QR11 | Frozen source-reference roles and current SDK constants corroborate names without exact runtime-build attestation | Match source revision/UUID/build and original private types |
| QR12 | Fresh replay shares Unicorn; byte/semantic checks are source/model consistency evidence | Cross-check an independent ISA implementation and native receiver/user output |

## Bounded continuation and quality gates

| Impact | Further evidence | Interface resolved |
| --- | --- | --- |
| High | Receive-results completion and namespace/right copyout from source-produced receiver fields | Continuous selected-message-to-user delivery and ownership transfer |
| High | Actual sender/receiver thread identity and scheduler/continuation transition | Native event order joining queue insertion or direct handoff to receive execution |
| High | Generic-dispatch allocation/return and complete upstream receive preparation | Full request-to-generated-reply transport without substituted entry/return frames |
| Medium | Signature object-check helper, PACGA context and genuine map/storage validity | Preconditions hidden by object/hash/authentication models |
| Medium | Port-set prepost, count-release notifications, cancellation races and invalid rings | Lock/state/resource contracts outside the selected paths |
| Medium | Positive deadline, continuation=true blocking and complex/auxiliary receive variants | Timing and representation branches outside current execution |
| Low | Exact symbols and matching private headers | Replace descriptive role labels with native names/types |

QG1: This is factual technical analysis without a normative conclusion.
QG2: QR1-QR12 state dependencies and explicit falsification probes.
QG3: Common receive, dequeue/preserve, result-channel mapping and handoff-reader
contracts are covered for this increment; the full multi-layer goal remains active.
QG4: Widths, offsets, u16/u32/u64 wrap, byte extents, SDK assertions and algorithm
complexity are explicit; no measured native duration is inferred.
QG5: Internal wait values versus thread status, take versus preserve, older head
versus appended reply, PORT_CHANGED naming, and model/native boundaries are resolved.
QG6: Original bytes, exact upstream prefix equality, independent replay, rebuilt
SMT, source-reference provenance and SDK compilation support the scoped claims.
QG7: Impact-labeled continuations bound native ownership, scheduler, copyout and
representation work without claiming that those unresolved interfaces are complete.
