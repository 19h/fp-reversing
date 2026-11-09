# Original wake send ingress, sender/context trailer and CF dispatch

The original CF wake packet now reaches original kernel Mach -47 handling,
namespace copy-send conversion, kmsg construction, send-policy checks, enqueue
and two port-set receives in one private kernel namespace. The first receive
returns wake name `0x807`; the second returns the existing service destination
`0x303` or `0x403`. Original CF routes the actual wake return before one service
lookup and the unchanged daemon/application suffix.

The wake output is exactly 92 B: a 24-byte header plus the selected 68-byte
trailer. The trailer carries the explicitly declared task-associated sender
markers and the run-loop value stored in the wake port's context. Original
scalar and auxiliary-vector inputs produce identical scalar wake output and
identical complete CF execution state in the paired cases.

This closes the private component path left open by the
[send-wrapper report](cf_wake_send_wrapper_report.md). Component transfers,
task/allocator epochs, raw backing, lower copy/VM/retirement primitives, opaque
hashes, tag/preflight results, CF/Objective-C runtime contracts and logical PAC
remain explicit. No native exception crossing, Mach IPC, allocation, scheduler,
thread identity, authentication or successful FairPlay operation is established.
The complete daemon-to-kext transaction and broader investigation remain active.

## Primary evidence and reproduction

Retained records: [source capture](triage_evidence/kernel_wake_send_ingress_source.json),
[execution profiles](triage_evidence/kernel_wake_send_ingress_profiles.json),
[independent checks](triage_evidence/kernel_wake_send_ingress_checks.json),
[preservation seal](triage_evidence/kernel_wake_send_ingress_delivery.json) and
[quality gates](triage_evidence/kernel_wake_send_ingress_quality_gates.json).
The [probe](triage_evidence/probe_kernel_wake_send_ingress.py) and
[independent replay](triage_evidence/replay_kernel_wake_send_ingress.py) implement
the new contracts separately; the replay does not import the new probe.

The capture retains 183 complete kernel routines / 24084 instructions and 52
cache routines plus 28 four-instruction import stubs / 4024 instructions. Nine
cache files and two SDK headers are hashed. Every captured body is checked
against current backing bytes. Four arm64e compile-time assertions verify the
68-byte MAC-trailer size and sender/audit/context offsets 12/20/52 using the local
SDK. These are layout checks, not native execution or exact source-revision
attestation. Original daemon, kext C/call listing, analysis and ZUT inputs remain
preserved. Reference files suffice; no new IDA query or database mutation occurs.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_wake_send_ingress.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_wake_send_ingress.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_wake_send_ingress.py
```

Run from `/Users/___/dev/dylex/extracted`. Input packets come from two original
CF/wrapper producer cases, freshly independently replayed. Their final retained
user regions are checked byte-for-byte against the recorded pre-SVC header,
vector and auxiliary regions before transfer. The new kernel starts at the
original handler's function entry with the exact eight-slot argument record.
This pairing is not a live exception-dispatch crossing. Original kernel send
status 0 agrees with the producer's explicitly modeled SVC status 0.

## Assumption register

Execution-derived results depend on WI1-WI7; SDK field nomenclature additionally
uses WI8. Original source-byte/table facts are independent of modeled native
outcomes. Finite cases do not establish exhaustive environmental behavior.

| ID | Explicit premise or boundary | Stress test or falsification probe |
| --- | --- | --- |
| WI1 | Pinned kernel/cache/daemon identities identify the analyzed bytes; effective native image selection is unknown. | Rehash originals/nine cache files, recapture every body and original Mach -47 binding; reject a different hash/UUID. |
| WI2 | Private namespace/task/current-task readonly/type/alignment/sender-record and per-CPU counter epochs are declared. Their native initialization and ownership are unknown. | Execute original current-task/type-5/owner checks, retain all reads/stores; validate explicit pointer/record/multiplier fields and original constructor/member results. |
| WI3 | Raw kmsg backing, copyin, byte-copy, receiver VM/retirement and send tag/preflight primitives retain their declared effects. | Recompute arguments, source bytes, destination before-images, complete patches and volatile clobbers; vector-copyin error returns before allocation/send; altered auxiliary copy is rejected. |
| WI4 | Keyed hash outputs are opaque contracts and PAC is interpreted logically. Native keys, enforcement and authentication are unknown. | Check original hash inputs, authenticated instruction/pointer records and full CPU/journals; hardware/native comparison is a separate requirement. |
| WI5 | Exact CF packet regions/slots and kernel/CF return records may be paired as component contracts. Numeric private addresses do not attest native shared identity. | Freshly replay both producers; compare all header/vector/auxiliary bytes, eight slots, contexts/names, full 2 MiB user epoch and kernel-produced 92-byte return; reject altered origin/receive records. |
| WI6 | Direct function-entry calls and no-pending-work/clock/source-runtime contracts describe the private CF environment. Native callers and concurrency are unknown. | Check complete handoffs, one wake then service lookup, preserved daemon suffix and scalar/vector equality; no internal-PC or header replacement supplies the send result. |
| WI7 | CF collection/allocation/locking and Objective-C pool primitives remain modeled. Native object destruction and cleanup are unknown. | Execute original CF pool wrappers, track the returned token, verify collection state and complete private memory; the remaining token at the boundary is not a native leak claim. |
| WI8 | Local SDK/pinned public definitions provide ABI nomenclature; exact target-source revision equivalence is unknown. | Rehash headers, compile four arm64e layout assertions and compare produced wire bytes independently of names. |

## Architectural path and responsibility boundaries

```text
original CF factory/wake + libkernel producer
  header24, packed slots, optional vector48 + auxiliary40
      |
      | declared transfer of exact original user regions/argument record
      v
original Mach -47 handler 0xfffffe000bcdd73c
  current task -> readonly/type/owner validation -> option classification
  scalar slots OR vector48 copyin/size checks
      v
original send ingress 0xfffffe000bcdd350
  kmsg allocation -> namespace COPY_SEND conversion -> metadata/policy
      v
original common send 0xfffffe000bcc7040 -> queue 0xfffffe000bcc7c34
  wake port 0x807, member of set 0x507
      v
original set receive/copyout: wake92, then existing service148 + OOL29
      |
      | explicit checked Mach-return transfers
      v
original CF run loop: wake route -> one service lookup/source -> daemon
  original pthread boundary OR original run-loop return4
```

No send result is injected at the original kernel handler, send frontend,
namespace conversion, enqueue or receive decision. The listed lower primitives
remain modeled. CF receives checked kernel output through an explicit return
contract. Source-produced names are fixture-local; historical ZUT names and
native port identity are separate. The historical unsuccessful IOKit user-client
open is not turned into a successful daemon-to-kext operation by this result.

| Original routine or location | Evidence-backed role in these cases |
| --- | --- |
| `0xfffffe000bcdd73c` | Mach table -47 handler; eight-slot unpacking, vector classification and send routing |
| `0xfffffe000bd7e9c4` | Original current-task lookup used by ingress and send |
| `0xfffffe000bd41068` | Task-associated readonly pointer/type/owner validation and flags read |
| `0xfffffe000bcdd350` | Original send frontend: allocation, copyin and common-send call |
| `0xfffffe000bcca864` | Original message/descriptor-size validation |
| `0xfffffe000bcd51c0` / `0xfffffe000bcd3620` | Original namespace-right/disposition conversion and associated checks |
| `0xfffffe000bccff4c` | Send-reference bookkeeping and object-reference increment |
| `0xfffffe000bcc4194` | Original sender-record stores and opaque keyed-hash calls |
| `0xfffffe000bccabd4` | Original send-policy classification for header/destination/options |
| `0xfffffe000bcc7040` / `0xfffffe000bcc7c34` | Original common send and queue path |
| `0x1846e13d0` / `0x18471445c` | Exact CF autorelease-pool push/pop wrappers captured; push executes in these consumers |

The original kernel parallel table supplies the `mach_msg2_trap` name. Unnamed
kernel helpers above retain address-based labels; these observed roles do not
recover every branch or justify invented original symbol names.

## Exact ingress and environmental contracts

The kernel argument record is `<8Q>` copied from original libkernel trap slots.
Scalar options are `0x400000011`; vector options are `0x500000011`. Both supply
remote `0x807`, local/voucher/ID/descriptor count/receive name/timeout/priority 0.
Scalar send size is 24 B. Vector send/receive count fields are 2; its message
record still has send size 24 B and its auxiliary record has send size 40 B.
Original handler code derives internal send options
`0x8000000400000011` or `0x8000000500000011` for these epochs.

| Input form | Original user-copy primitive calls during send ingress | Header provenance |
| --- | --- | --- |
| Scalar, header only | None | Original packed trap slots construct the kernel header |
| Vector with auxiliary data | 48 B vector table, then 32 B auxiliary payload | Header fields still come from packed slots; vector supplies data pointers/sizes |
| Vector-table copy failure | 48 B request returns declared error1 | Original handler returns `0x10000002` before send/allocation |

The vector auxiliary copy starts 8 B past the original auxiliary pointer.
Original kernel code supplies its size/reserved header. At the successful send
return, the complete 40-byte record at `WKMSG+216` equals the original dispatch
record, including its opaque marker/context payload. The selected scalar receive
output does not carry these auxiliary bytes. Kernel/native interpretation of
that auxiliary context remains unknown.

Original current-task lookup resolves the declared receiver task. The readonly
helper then reads **task** offset `0x3f8`; its input is not a thread pointer.
It validates the pool range, alignment arithmetic, metadata type 5 and the
record's owner at `+8`, then reads flags at `+0x60`. The private record is 128 B,
owner equals the task, flags are zero, and the declared pool alignment multiplier
at `0xfffffe0007e6d048` is `0x40000`. That multiplier's original file value is
zero; a native initialized allocator epoch is not established. The backing
address is 16 KiB aligned. None of these checks proves the native allocation
extent or original allocation path of this readonly record.

Additional explicit environment fields are:

| Owner field | Declared value or association | Observed use |
| --- | --- | --- |
| Current task `+0x318` | Existing declared private IPC-space association | Namespace lookup and send conversion |
| Current task `+0x320` | Disjoint 32-byte sender-identity observation record | Original trailer producer reads and rearranges fields |
| Current task `+0x3d0` | Private per-CPU send-counter backing | Original common send path |
| Current thread `+0x1b8` | CPU index 0 | Per-CPU counter selection |
| Current task `+0x3f8` | Readonly record with owner/type/flags premises above | Original readonly validation |

The sender observation record contains `<8I>(0x11,0x22,0x33,0x44,0x55,0x66,
0x77,0x88)`. These are explicit test markers, not native credentials or process
identity. Source reads/stores establish the mapping below. Native construction,
ownership and authorization semantics of the input record remain unknown.

## Header normalization, rights and emitted receive bytes

| Stage | Complete relevant header | Size and role |
| --- | --- | --- |
| Original CF input | `<6I>(0x13,24,0x807,0,0,0)` | 24 B, user COPY_SEND destination |
| Original queued kernel header | `<IIQQII>(0x11,32,WPORT,0,0,0)` | 32 B, internal pointer-bearing header |
| Original user receive header | `<6I>(0x1100,24,0,0x807,0,0)` | 24 B, receive name in local-port field |

`WPORT=0x65000c2000`, `WKMSG=0x65000d4000`. The original allocator returns the
wake kmsg using declared raw 256-byte class-24 backing. Namespace entry 8 retains
rights word `0x04030001` and user send uref 1. Original copy-send handling adds a
transient send/object reference: queued port reference and send-reference words
are 2; both return to 1 after receive. This distinction separates an in-transit
reference from the user's retained send right.

At the original send return, wake queue count is 1 and its queue pointer is
WKMSG. After receive the count is zero, sequence is 1, queue limit remains 1,
context remains the run-loop value and namespace rights remain unchanged.
No native ownership/lifetime guarantee follows from these private intervals.

The selected trailer follows the 24-byte user header:

| Trailer offset | Size | SDK field/layout role | Observed value |
| --- | ---: | --- | --- |
| 0 | 4 B | Trailer type | 0 |
| 4 | 4 B | Trailer size | 68 B |
| 8 | 4 B | Sequence number | 0 on this first receive |
| 12 | 8 B | `msgh_sender` | `[0x11,0x33]` |
| 20 | 32 B | `msgh_audit` | `[0x55,0x11,0x33,0x22,0x44,0x77,0x66,0x88]` |
| 52 | 8 B | `msgh_context` | Run-loop/port-context value `0x65000a0000` |
| 60 | 4 B | Filter-ID position | 0 |
| 64 | 4 B | Label position | 0 |

For input words `[a,b,c,d,e,f,g,h]`, original stores supply sender `[a,c]` and
audit `[e,a,c,b,d,g,f,h]`. The context originates in the previously established
wake-port constructor, which stores the run-loop value in `port+0x78`.
The complete 92 B are checked, not only these selected fields. Message ID
remains zero and there is no descriptor or OOL body. Trailer field presence is
not evidence of an authorization decision or native authentication.

## Queue selection and original CF continuation

Original wake enqueue moves its membership link into the ready ring. The root
and timer members remain inactive. Service insertion adds the already queued
service member after wake:

```text
set 0x507 before receives
  inactive: root <-> timer
  ready:    wake <-> service      head=wake

first original receive: wake92   next head=service
second original receive: service148 + OOL29
                                next head=wake
```

After these two receives, both drained wake/service links retain ready bits in
the observed ring, although their queues are drained. This is retained
readiness state over this interval; cleanup or later receive behavior is not
inferred from it. The original service bytes and complete kernel user/OOL
buffers equal the preceding service-only component results.

Four CF consumers receive the checked wake output followed by the checked
service output. Original wake routing occurs before source lookup: there is
exactly one dictionary lookup and one daemon callback, for the later service.
No generic reply send at `0x184757744` occurs. The original daemon instruction
suffix, 160-byte object and final application argument record or return4 match
the prior component cases. Scalar and vector wake paths give identical complete
CF private and lower-stack memory and identical source instruction sequences
for each matched service family.

The original CF pool-push wrapper executes during this continuation and calls
`objc_autoreleasePoolPush` through its original import stub. The lower runtime
returns one declared opaque token `0x123400001`. That token remains outstanding
at each observation boundary; no pool-pop execution is claimed here. Native
object destruction, later cleanup and outer-caller responsibilities remain
unknown. The captured pop wrapper is available for subsequent analysis.

## Verification totals, controls and bounded continuation

| Independent positive replay | Cases | Original instruction visits | Complete final memory checked |
| --- | ---: | ---: | ---: |
| New kernel construction/ingress/send/receives and copyin-error control | 5 | 45316 | 15 MiB |
| New CF wake/service consumers | 4 | 14848 | 12 MiB |
| Original CF/wrapper scalar and vector producers, freshly replayed | 2 | 3120 | 6 MiB |
| Dynamic timer startup | 1 | 170 | 1 MiB |
| Fixed-zone prerequisites | 3 | 618 | 3 MiB |
| Receiver-loan prerequisites | 4 | 216 | 4 MiB |
| Total | 19 | 64288 | 41 MiB |

`45316 + 14848 + 3120 + 170 + 618 + 216 = 64288` visits.
`(15 + 12 + 6 + 1 + 3 + 4) MiB = 41 MiB = 42991616 B`.
Each kernel case checks its complete 1 MiB private RAM and complete transferred
2 MiB CF user epoch. These are exact finite replay counts, not native elapsed
time, error bounds or coverage percentages.

All six altered-record controls fail: original CF header provenance, returned
wake local name, returned sender/audit data, auxiliary payload-copy bytes,
CF wake-return bytes and CF receive provenance. The separate vector-copyin-error
case executes the original early return before send and allocation. Original
readonly/type/owner, disposition conversion, policy, queue and receive paths
execute under their listed premises.

Replay checks all retained GPR/SP/NZCV/SIMD frames, ordered reads/writes,
primitive patches, function-entry/return memory images, final globals, complete
private/user memory and semantic wire/namespace/ring oracles. Its instruction
budget includes every recorded source/API/function-handoff visit and the final
boundary observation. It does not stop solely at an arbitrary instruction limit.
Time/space cost is O(image bytes + instruction visits + memory bytes + journal
bytes). Publication auditing is O(total artifact bytes + links) time with
O(manifest + largest JSON) working memory.

| Impact | Further interface question or pattern | Discriminating evidence |
| --- | --- | --- |
| High | Which daemon/framework caller initiates WakeUp for actual FairPlay work? | Original incoming references, caller arguments and triggering source/mode mutations; the current component path alone does not establish this caller. |
| High | How do zero-timeout queue-full and repeated sends interact with queue limit 1? | Original repeated sends before receive, error/backout paths and unchanged rights; successful single enqueue does not prove coalescing. |
| High | How are task readonly and sender-identity records initialized and owned natively? | Original allocation/publication and lifetime paths; current exact readonly checks and marker propagation are conditional on a declared epoch. |
| Medium | How does the kernel interpret dispatch auxiliary context? | Original auxiliary ingestion/policy/lifetime outside the selected copy and scalar receive output; queued equality is not a semantic decoder. |
| Medium | When are drained ready links demoted after these two receives? | Original subsequent selection/wait paths; retain current final ready bits until that interval is examined. |
| Medium | Who owns the remaining autorelease-pool token and outer cleanup? | Original outer caller and Objective-C lifecycle; current token boundary is not a native leak or destruction proof. |
| Medium | Does native exception dispatch preserve this complete argument/return contract? | Matched native thread/task/image state and actual exception crossing; the static table and private function-entry composition are insufficient. |

The [investigation status](interface_investigation_status.md) retains the complete
daemon/kext/deeper-interface objective. Native caller/identity/ownership,
authentication/PAC, IOKit transaction success and final FairPlay output remain
unknown.

## Quality gates

QG1: The report contains technical findings, explicit models and bounded unknowns;
no normative content is required.

QG2: WI1-WI8 enumerate premises, dependent results and falsification probes.

QG3: The increment covers exact CF packet provenance, original kernel ingress,
rights/header/auxiliary transformations, sender/context production, policy,
enqueue/readiness, two receives and CF/daemon routing. Full-goal completion is
explicitly unestablished.

QG4: Byte/count distinctions, packed LP64 little-endian layouts, four arm64e SDK
assertions, 41 MiB arithmetic and linear validation bounds are reproducible.

QG5: Task readonly is distinguished from thread state; packed headers from user
copyin; auxiliary header from payload; sender markers from native credentials;
port context from sender identity; transient references from user urefs; retained
readiness from queue occupancy; pool-token observation from native cleanup;
private composition from a live exception crossing.

QG6: Complete original recapture, cache/SDK hashes, independent CPU/RAM/journal
replay, matched producers/consumers, original early-error control and six rejected
alterations support the bounded claims. Native success or authentication is not
inferred from synthetic epochs.

QG7: The impact table identifies additional architectural interfaces and the
evidence needed to resolve each without changing the broader investigation scope.
