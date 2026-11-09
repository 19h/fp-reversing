# Original run-loop construction, wake-port ABI and wake-message emission

The original CoreFoundation factory constructs the wake port with a complete
24-byte options record `(flags=0x33, queue_limit=1, reserved=0)` and the run-loop
pointer as guard context. Original kernel construction produces receive/send
rights, queue limit 1 and the matching context. Original CF mode creation joins
that wake port to the same port set as the root, timer and service ports.
`CFRunLoopWakeUp` constructs a 24-byte ID-0 message to this port when its indexed
suppression byte is zero. The factory initializes that byte to one; the original
run loop clears it before receive.

These results extend the [timer construction](kernel_timer_port_create_report.md)
and [actual timer delivery](kernel_timer_expiration_delivery_report.md) evidence.
Wake-message **send returns remain declared models**. No wake packet enters the
kernel send path in this increment, and no native daemon, kernel, scheduler,
Mach IPC, allocator or hardware pointer authentication executes. The original
libkernel `_mach_msg` body is captured but intercepted at entry. Its lower send
implementation, retry behavior and native return feasibility remain unknown.
The `MACH_SEND_INTERRUPTED` case is a counterfactual diagnostic-branch test.
The full investigation remains active.

## Provenance and reproducibility

Primary records are [source capture](triage_evidence/cf_runloop_wake_port_source.json),
[execution profiles](triage_evidence/cf_runloop_wake_port_profiles.json),
[independent checks](triage_evidence/cf_runloop_wake_port_checks.json),
[preservation seal](triage_evidence/cf_runloop_wake_port_delivery.json) and
[scoped quality gates](triage_evidence/cf_runloop_wake_port_quality_gates.json).
The source capture retains original bytes, exact symbol records, import cells,
cache pages, kernel image identity and hashes of nine cache files. It also hashes
the local SDK `mach/port.h` and `mach/message.h`; the SDK supplies nomenclature,
while the captured binaries establish the behavior of this build.

| Original routine or interface | Address | Captured instructions | Role established here |
| --- | --- | ---: | --- |
| `___CFRunLoopCreate` | `0x184717e70` | 100 | Run-loop allocation request, wake-port construction and default-mode setup |
| `_CFRunLoopWakeUp` | `0x18473ae10` | 108 | Indexed suppression gate, header construction, send and status checks |
| `___CFMachMessageCheckForAndDestroyUnsentMessage` | `0x184758964` | 49 | Original selected send-result processing |
| `_mach_msg` | `0x180547f94` | 9 | Captured boundary; invocation result explicitly modeled |
| Kernel queue-limit routine | `0xfffffe000bcc8c60` | 37 | Changes new wake-port limit from default 5 to 1 |
| CF construct import stub | `0x188076b90` | 4 | Original pointer `0x1e2103a98 -> 0x180548e9c` |

The kernel capture contains 172 complete routines / 22410 instructions. The CF
capture contains 47 routines plus 26 four-instruction import stubs / 3768 total
instructions. The newly identified names are exact nlist matches, rather than
names inferred from argument patterns. Original files from the initial analysis
and ZUT are preserved. No new IDA query or database mutation was required.
The ZUT trace remains historical emulator evidence; this replay does not extend
its observed failed user-client open into a successful daemon-to-kext exchange.

Commands from `/Users/___/dev/dylex/extracted`:

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_runloop_wake_port.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_runloop_wake_port.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_runloop_wake_port.py
```

The [probe](triage_evidence/probe_cf_runloop_wake_port.py) and
[independent replay](triage_evidence/replay_cf_runloop_wake_port.py) use separate
implementations of the new contracts. The replay does not import the new probe.
It reexecutes original instructions and checks complete CPU state, ordered
reads/writes, modeled boundaries, host collection state, transition memory
images and complete final private memory. Source capture is reconstructed from
the backing files before validation. Finite cases establish the stated branches,
not exhaustive native execution.

## Assumption register

All execution-derived results depend on WP1-WP4. Cross-layer pairings additionally
depend on WP5; waiting-state wake cases on WP6; SDK names on WP7; status-case
interpretation on WP8. Source-byte and nlist observations do not depend on modeled
send outcomes.

| ID | Explicit assumption or boundary | Stress test or falsification probe |
| --- | --- | --- |
| WP1 | Pinned kernel/cache/daemon bytes identify the analyzed build; native coexistence of all snapshots is unknown. | Rehash originals and nine cache files, recapture complete bodies, compare identities; a differing UUID/hash invalidates address transfer. |
| WP2 | Private task, namespace free chain and source-produced zone records form a declared epoch. Native task/boot initialization is unknown. | Fresh timer startup, three fixed-zone and four loan replays; original constructors and all four memberships; compare final namespace and rings. |
| WP3 | Raw allocation, user copy, VM, hash/tag, lock, CF runtime/string/collection and timer-source contracts retain declared effects. | Recompute arguments, volatile clobbers, patches, before/after CPU and complete memory; corrupt queue limit, context, rights or CF options and require rejection. |
| WP4 | Pointer authentication is interpreted logically. Hardware keys and native authentication remain unknown. | Check original authenticated instruction and pointer targets; native hardware comparison would falsify an incorrect logical model. |
| WP5 | Kernel scalar/name/context returns may be paired with identical CF arguments and private addresses. This is component composition, not a live trap crossing. | Compare all 24 options bytes, four construct slots, context, returned name and three membership slots against independent original-kernel results. |
| WP6 | An external waker can be represented by an explicit function-entry handoff after the original run loop clears its gate. Native concurrent scheduling and the caller of WakeUp remain unknown. | Preserve waiting-state CPU/RAM hashes, enter WakeUp with a disjoint declared stack, prohibit internal-PC edits; trace a real caller separately. |
| WP7 | Local SDK numeric names describe the captured constants. Exact SDK/build source equivalence is unknown. | Hash both headers and assert six numeric definitions; use binary values independently if headers differ. |
| WP8 | Send results are injected at `_mach_msg` entry. Native success, queue-full timeout and interrupted-return reachability are unknown. | Capture exact original header/call tuple; distinguish success/timeout from the explicitly counterfactual interrupted case; execute the lower original send/retry path in a later increment. |

## Construction and shared namespace

The private namespace uses task name `0x103` and the declared free chain
`8 -> 5 -> 6 -> 7 -> 2`. Original code allocates the following names. These are
fixture-local names; equal numbers in an emulator log do not identify equal
objects or rights.

| Name | Object and state | Creation or membership source |
| --- | --- | --- |
| `0x807` | Wake port at `0x65000c2000`; receive/send, uref 1, queue limit 1 | Original construct; member insertion after timer insertion |
| `0x507` | Port set at `0x65000b8000` | Original set allocation |
| `0x607` | Guarded dispatch root port | Original root construction and insertion |
| `0x707` | Timer receive port with separate kernel-held send reference | Original timer construction and insertion |
| `0x303` / `0x403` | Existing queued service destination | Original service insertion and receive |

The wake constructor arguments are `(task=0x103, options_ptr,
context=0x65000a0000, output_name_ptr)`. The options constant at `0x184951c70` is:

```text
offset  size(B)  value
0       4        0x33 = CONTEXT_AS_GUARD | QLIMIT | INSERT_SEND_RIGHT | STRICT
4       4        1
8       16       0
```

Original kernel stores provide a finer distinction than the final snapshot:

| Original store PC | Destination in private wake port | Observed value |
| --- | --- | --- |
| `0xfffffe000bccd21c` | `port+0x3a`, u16 queue limit | Default 5 |
| `0xfffffe000bccb648` | Namespace entry 8, rights word | `0x04030001` |
| `0xfffffe000bcc8cdc` | `port+0x3a`, u16 queue limit | Requested 1 |
| `0xfffffe000bce0630` | `port+0x78`, u64 context | Run-loop pointer `0x65000a0000` |

Final count is zero, queue pointer is zero, guard bits include `0xc00`, and the
send bookkeeping words at `+0x84/+0x88` are both one. The original membership path
links the empty wake port into the inactive control ring. The service link is
ready; delivery of the existing service packet is unchanged in all four cases.

```text
port set 0x507
  inactive head -> root -> timer -> wake -> root
  ready head    -> service (single-member ready ring)

CF run loop
  +0x50  wake 0x807
  mode +0x88 -> set 0x507
  mode +0xac -> timer 0x707
  root queue -> root 0x607
  source dictionary -> service 0x303 or 0x403
```

This increment proves construction and membership of the wake port. It does not
send a wake packet into this kernel queue, rotate its readiness, or copy a wake
message back out.

## Factory data flow

The original factory requests runtime type 43 with 2704 B (`0xa90`) of extra
storage. Observed fields extend through offset `0xa9f`, a 2720 B (`0xaa0`) span.
The runtime allocation/header calculation and physical allocation extent are
unknown; the private backing is 8192 B, with a checked guard at `RL+0xaa0`.
The mode allocation, root construction, timer creation, set registration and
source registration execute their existing original-byte paths.

| Factory store PC | Run-loop field | Value or role |
| --- | --- | --- |
| `0x184717f38` | `RL+0x50`, u32 | Source-returned wake name `0x807` |
| `0x184717f40` | `RL+0x54`, u16 | Zero; WakeUp reads its first byte as an index |
| `0x184717f48` | `RL+0x153`, u8 | Initial suppression value 1 |
| `0x184717f64` | `RL+0xa50`, pointer | Common-mode set |
| `0x184717f8c` | `RL+0xa68`, pointer | Mode registry set |
| `0x184717f90` | `RL+0xa48`, pointer-sized input | Preserved caller context; private value `0x1234` |

The input at `+0xa48` is treated as opaque. Its native thread/owner identity is
unknown. The common set contains original default-mode constant `0x1e233b370`;
the registry contains the original-byte-created mode object. A null runtime
allocation returns null before constructing a port, adding a mode or sending.

## Exact wake emission and return handling

WakeUp validates runtime type 43, locks the run loop, reads index byte `RL+0x54`
and tests byte `RL+0x153+index`. A nonzero byte takes the original unlock/return
path. At index zero the newly created run loop therefore emits no message.
Original run-loop store `0x184757168` changes that byte to zero before receive.
The waiting cases stop before the receive call is consumed, then explicitly
enter original WakeUp with `X0=RL` and a disjoint private stack. The waiting
receive does not return or resume in this increment.

| Emission source | Original PC | Effect |
| --- | --- | --- |
| Wake-name load | `0x18473aefc` | Read u32 from `RL+0x50` |
| First header store | `0x18473af08` | Bits `0x13`, size 24 B |
| Port-name pair store | `0x18473af0c` | Remote `0x807`, local 0 |
| Final header store | `0x18473af10` | Voucher 0, message ID 0 |
| Outgoing send call | `0x18473af30` | Original import stub -> `_mach_msg` boundary |
| Unsent-message helper call | `0x18473af3c` | Original helper processes declared status and header |
| Nonzero return comparison | `0x18473af4c` | Accept `0x10000004` as well as success |
| Unexpected-status boundary | `0x1848d4168` | Stop before original diagnostic body |

The complete header is `<6I>(0x13,24,0x807,0,0,0)`, all values little-endian.
There is no descriptor, body, voucher or reply port in this produced header.
The original call tuple is:

```text
mach_msg(header_ptr, options=0x11, send_size=24 B,
         receive_capacity=0 B, receive_name=0, timeout=0, notify=0)

factory gate=1 -> WakeUp -> unlock/return, zero sends
run loop gate=0 -> declared external-waker entry -> WakeUp
  -> original header stores -> modeled send result
  -> original unsent-message helper
     result 0             -> return
     result 0x10000004    -> return (SDK MACH_SEND_TIMED_OUT)
     result 0x10000007    -> diagnostic boundary (counterfactual)
```

Options `0x11` select send plus send timeout; timeout argument is zero. The
message bits encode a copy-send destination disposition. The SDK name for
`0x10000007` is `MACH_SEND_INTERRUPTED`. Its exposure by the unexecuted lower
wrapper is unknown; this case cannot establish native interruption behavior.
The selected helper cases do not execute message destruction. No native right
cleanup, queue-full condition, delivery, wake latency or synchronization result
is inferred from the injected statuses.

## Validation and bounded continuation

| Independently replayed set | Cases | Original instruction visits | Complete final private bytes checked |
| --- | ---: | ---: | ---: |
| Wake construction/member/service receive | 4 | 27756 | 4194304 |
| CF factory and wake cases | 5 | 5425 | 15728640 |
| Dynamic timer startup prerequisite | 1 | 170 | 1048576 |
| Fixed-zone prerequisites | 3 | 618 | 3145728 |
| Receiver-loan prerequisites | 4 | 216 | 4194304 |
| Total positive replay | 17 | 34185 | 28311552 |

`27756 + 5425 + 170 + 618 + 216 = 34185` visits.
`(4 + 15 + 1 + 3 + 4) MiB = 27 MiB = 28311552 B`.
These are exact replay counts, not time or error-bound measurements. All six
altered controls are rejected: queue limit, guard context, namespace rights,
CF emitted header, CF constructor options and final suppression byte.
Replays and journal checks take O(image bytes + instruction visits + memory
bytes + journal bytes) time and space. Publication auditing is O(total artifact
bytes + link count), with O(manifest + largest JSON) working memory.

| Impact | Additional interface question | Discriminating evidence |
| --- | --- | --- |
| High | Does the emitted wake header traverse the original user-send, copyin, queue and set-receive paths? | Carry these exact original 24 B through original send ingress and compare returned name/header/trailer and ready transitions. |
| High | Which daemon/framework caller requests the wake, and under what source/mode changes? | Original incoming references and caller-to-WakeUp argument/state provenance; native caller identity remains unknown. |
| Medium | Do limit 1, zero timeout and accepted timeout implement wake coalescing? | Original repeated enqueue/full-queue semantics; current values suggest this interpretation but do not establish it. |
| Medium | Can wrapper retry behavior prevent the interrupted diagnostic case? | Original `_mach_msg` lower call and interrupt-option handling; keep the current case counterfactual until resolved. |
| Medium | How do nested run-loop levels select separate suppression bytes? | Trace producers of index byte `RL+0x54`; only index zero is executed here. |
| Low | Which runtime header accounts for extra size versus observed span? | Original runtime allocation layout; current arithmetic alone does not recover allocation extent. |

The remaining daemon-to-kext transaction and deeper FairPlay interfaces remain
in the [investigation status](interface_investigation_status.md). This control
infrastructure result supplies a missing constructor/emitter contract; it does
not establish a successful FairPlay response or DRM operation.

## Quality gates

QG1: The report contains technical observations, explicit models and bounded
hypotheses; no normative content is required.

QG2: WP1-WP8 enumerate assumptions, dependent results and falsification probes.

QG3: This increment covers original wake construction, all four shared-set
memberships, factory data flow, suppression, exact emission PCs/header/call
slots, selected result branches and caller/environment boundaries. Full-goal
coverage remains incomplete and explicitly active.

QG4: Byte units, little-endian layouts, instruction counts, 27 MiB arithmetic
and linear algorithm bounds are reproducible from retained records.

QG5: Queue membership is distinguished from wake delivery; modeled send returns
from native feasibility; runtime extra size from allocation span; fixture names
from historical ZUT names. The interrupted case is explicitly counterfactual.

QG6: Backing-byte recapture, exact nlist records, cache/SDK hashes, independent
replay, preserved original inputs and six rejected alterations support the
bounded claims. No external attribution or IDB label supplies missing proof.

QG7: The impact table identifies bounded additional data/control/runtime
interfaces and the observations required to resolve each. Unknown native
behavior is not reported as established.
