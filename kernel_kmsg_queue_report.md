# Original kernel queue admission, receiver publication and notification return

The whole queue-send return model is removed from the selected original no-senders notification path. Original code now performs type-checked port locking, queue reservation, waiting-receiver handling, circular insertion, owner/task access and task accounting, then returns through the original common sender, wrapper and notification caller. Thirteen components complete that caller return; three stop at explicit deeper policy/wait boundaries. Receiver selection/release, copy/hash/tag/preflight and retirement remain lower models. Native queue membership, receiver execution, authentication, delivery and full FairPlay transport remain unknown. [KQ1-KQ8]

Evidence: [22 complete functions / 2930 instructions and pinned SDK definitions](triage_evidence/kernel_kmsg_queue_source.json), [16 source-notification components](triage_evidence/kernel_kmsg_queue_profiles.json), [fresh producer/replay, full-state oracles and three scalar proofs](triage_evidence/kernel_kmsg_queue_checks.json), [delivery seal](triage_evidence/kernel_kmsg_queue_delivery.json), [quality gates](triage_evidence/kernel_kmsg_queue_quality_gates.json). Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Local references suffice; no new IDA query, IDB/memory-store write or native target/IPC operation occurs.

## Original routines and publication sites

| Entry/site | Established role |
|---|---|
| `0xfffffe000bcc724c` | Original common sender calls queue routine with `(destination+0x28,kmsg,options,timeout)` |
| `0xfffffe000bcc7c34` | Anonymous queue-send routine: admission/reservation, receiver path, enqueue, sender-wait/status handling |
| `0xfffffe000bccc128` | Type/range-check port allocation, then acquire its ticket lock |
| `0xfffffe000bd0aecc` | Original uncontended ticket acquisition with thread-nesting increment |
| `0xfffffe000bd0ab18` | Original owner release and nesting decrement/pending checks |
| `0xfffffe000bcc2bc4` | Original circular kmsg insertion and backward propagation of a priority-like byte |
| `0xfffffe000bcc4bb4` | Original user-message extent calculation; selected noncomplex 44-byte kernel message becomes 36 bytes |
| `0xfffffe000bcc2068` | Original trailer-extent selection; selected values are 8 and 12 bytes |
| `0xfffffe000bd7e9c4` | Validate current thread's owner record and retrieve its task pointer |
| `0xfffffe000bd6c4b0` | Original waitq cleanup/check helper; selected current-thread work flag is clear |
| `0xfffffe000bcc7c7c` | Reserve/increment queue count before releasing the port lock |
| `0xfffffe000bcc2c2c` | Empty-queue head publication; nonempty link publications are at `...2be8` / `...2bec` |
| `0xfffffe000bcc7ff8` | Publish logically signed kmsg pointer into selected receiver at `receiver+0x3b8` |
| `0xfffffe000bcc8008` | Publish receiver sequence from the queue sequence; queue sequence was incremented at `...8004` |
| `0xfffffe000bcc8020` | Decrement queue count after direct receiver publication |
| `0xfffffe000bcc8228` | Increment selected current-task counter with original LDADD |

Nine newly captured complete functions add 859 instructions to the retained 13 functions. Their exact original symbols are absent; role names are behavioral descriptions. Complete capture includes unexecuted contention, complex-message/vector, timed-wait, callback and cleanup branches. [KQ1,KQ8]

These are internal queue/thread publication sites. They do not add a native Mach emission event to the historical zut capture. The source notification remains the previously established 44-byte ID-70 no-senders packet; it is not a newly observed FairPlay work RPC. The common queue call is an architectural touchpoint shared by the existing send facility. [KQ1,KQ7]

## Source origin, port/owner context and lock ABI

Each component imports the complete 1048576-byte RAM, GP/SP/NZCV/SIMD entry state and recorded image globals of the actual original no-senders producer. Source notification call arguments are unchanged at wrapper entry. Original kmsg policy/cache pop/zero check and preparation/copyin run before the original queue call. Raw cache/port/owner/queue epochs are explicit inputs; controlled queue-entry variants are separately recorded after preparation. The prior gate/quota continuations remain separately verified; this increment uses the earlier declared populated-cache epoch. [KQ2,KQ3]

The port lock verifies a 144-byte object extent and allocation/type domain 22 before taking `port+0x14`. This independently matches the original [ipc ports startup specification](kernel_zone_startup_report.md), ID 22 / 144 bytes. The kmsg constructor uses the separate ID-24 / 256-byte domain. Neither ID is a Mach port name or message ID. [KQ1,KQ4]

Declared type metadata also admits the thread owner record as domain 3. The original task accessor checks bounds, geometry, type and the owner-to-thread backlink before reading its task pointer. The geometry multiplier and private owner record come from the earlier [task/map accessor component](kernel_task_map_report.md); native owner production remains unknown. The queue then increments a declared task counter at the selected CPU's 16384-byte stride. [KQ4]

No whole port-lock/unlock model remains. The actual common sender acquires the port lock, so queue entry has nesting 1 and an outstanding ticket. Successful queue components perform two acquire/release cycles, ending with balanced word `0x02020144` and nesting 0. The low lock-control bits, including the bit checked after reacquisition, remain unchanged by those cycles. A scalar proof checks that preservation independently. Contention, pending work, invalidation races and native synchronization are untested. [KQ4,KQ8]

## Queue state, reservation and admission

| Queue-relative field | Port-relative field | Selected role |
|---|---|---|
| `+0x00`, pointer | `+0x28` | Circular message-list head |
| `+0x08`, u32 | `+0x30` | Sequence copied/advanced on direct receiver publication |
| `+0x0c`, u32 | `+0x34` | Identity word copied to selected large-message receiver state |
| `+0x10`, u16 | `+0x38` | Queue admission/reservation count |
| `+0x12`, u16 | `+0x3a` | Configured admission limit |

The selected identity word `0x303` is a synthetic field value, not an established task-local Mach name. Count and configured limit are separate from linked-list length: the routine reserves count before unlocking, and direct handoff later reverses that reservation without inserting a message. Counter-only stress epochs do not establish native reservation histories or native limit eligibility. [KQ3,KQ5]

The original branch tree reduces to:

```text
admit = count < limit
     or (count <= 65533 and
         (queue option bit16 is set or header disposition is 18))
```

Disposition 18 is numerically `MACH_MSG_TYPE_MOVE_SEND_ONCE` in the pinned SDK. The authentic notification's queue options are `0x50001`, including bit 16. Separate controlled option/header variants isolate the option-bit bypass, the send-once bypass and ordinary full-queue behavior. They do not establish new authentic notification/right histories. [KQ3,KQ5]

The high-count check is inside the full-queue branch. With count/limit both 65534, the selected code returns `MACH_SEND_NO_BUFFER`, or immediate `MACH_SEND_TIMED_OUT` when timeout option bit 4 is set with timeout 0. With count 65534 and limit 65535, the below-limit branch instead reserves count 65535 and reaches the large-queue policy boundary. Native upstream permission to configure that limit is unknown. An all-u16/u32/disposition proof checks the compact admission rule against the source branch tree; a second proves an admitted reservation does not wrap the u16 count. [KQ5,KQ8]

For an ordinary-disposition full-queue variant with timeout 0, `MACH_SEND_TIMED_OUT` is immediate: no timed wait has occurred. Without that timeout option, the component sets sender-wait state and stops before a lower wait-preparation call. `MACH_SEND_NO_BUFFER` here identifies a queue-count branch, not an observed heap allocation failure. [KQ5,KQ7]

## Circular insertion and receiver handoff

```text
No selected receiver:
  reserve count -> unlock/relock port -> lower receiver selection returns NULL
    -> original circular insertion -> original unlock -> task counter -> return

Selected receiver:
  original message/trailer size checks
    -> publish status, sequence and kmsg pointer -> lower release/resume request
       -> reverse reservation -> unlock -> task counter -> return

Receiver too small with MACH_RCV_LARGE:
  publish required sizes and selected identity; retain kmsg for retry
    -> lower release/resume request -> try next receiver or enqueue
```

Selection and release/resume are opaque lower calls at `0xfffffe000bd6cf80` and `0xfffffe000bd6d0d4`. Their declared candidate sequence and results do not prove native waitq membership, removal, scheduling or receiver execution. Original code performs the surrounding state checks and publications. [KQ3,KQ6]

Circular insertion writes kmsg next/previous pointers. Empty insertion makes both pointers self-referential and publishes the head. Nonempty insertion appends behind the existing tail while preserving the head. Two old-node cases independently verify all links. A controlled new byte value 7 at kmsg `+0x3e` propagates backward over lower old values 5 and 2; an unchanged zero value does not. This is a priority-like monotone byte role inferred from original comparisons/stores, not a recovered source identifier or an authenticated user-controllable QoS field. [KQ3,KQ5]

The enqueue helper Boolean is distinct from queue-send status. It is 1 for the selected empty transition or successful backward propagation, and 0 for the selected nonempty insertion without propagation. The caller uses it to condition further notification work; every selected successful send still returns 0. Native callback registration and execution remain unknown. [KQ5,KQ7]

For the noncomplex source notification, original size arithmetic gives:

```text
44 kernel-message bytes - 8 header-layout bytes = 36 user-message bytes
36 + 8 default trailer bytes = 44 required receive bytes
36 + 12 selected trailer bytes = 48 required receive bytes
```

| Receiver epoch | Original receiver state | Sender/queue result |
|---|---|---|
| Capacity 44, default trailer | Status 0; kmsg pointer and sequence published | Send 0; reservation reversed |
| Capacity 43, default options | `MACH_RCV_TOO_LARGE`; required size 36; kmsg pointer still published | Send 0; reservation reversed |
| Capacity 43, `MACH_RCV_LARGE` | Too-large status/required size/identity; kmsg not assigned to that receiver | Retry another receiver or enqueue; send 0 |
| Large-reporting receiver followed by capacity-44 receiver | First gets size report; second gets kmsg pointer | Send 0; reservation reversed |
| Capacity 48, trailer-selector value 1 | Original trailer size 12; status 0 and pointer publication | Send 0 |

`MACH_RCV_TOO_LARGE` belongs to receiver state; it can coexist with successful sender return. Original status stores are at `...bcc7ea4` (too large) and `...bcc7fe4` (fits). Original pointer publication uses PACDA with the receiver `+0x3b8` address and discriminator `0x33ff`; authentication is logical only in this CPU model. Payload copyout into user memory, right-name conversion, receiving task identity and receiver-side retirement remain unknown. [KQ5-KQ7]

## Case outcomes and caller/ownership boundary

| Cases | Original outcome |
|---|---|
| 0-2 | Empty/nonempty circular insertion and controlled byte propagation |
| 3-7 | Receiver fit/too-large/report-and-retry and trailer-size paths |
| 8 / 13 | Full counter/limit bypass under original option bit or controlled send-once-only queue ABI |
| 9 / 11 | Immediate send timeout under selected full-queue conditions |
| 10 | Full high-count no-buffer result |
| 12 / 15 | Reserved high count; stop before large-queue policy at `0xfffffe000bcca948` |
| 14 | Stop before sender-wait preparation at `0xfffffe000bd68474`; port lock/nesting remain held |

Ten cases return send 0 and increment the original task counter; six enqueue and four publish to a selected receiver. Three error cases return their original status through the common sender/wrapper to the actual no-senders caller at `0xfffffe000bcd059c`; original cleanup requests occur, but destruction effects remain modeled. Three prefixes do not return a send result. [KQ5,KQ7]

No whole queue, port lock, kmsg allocation, zone pop or zero-check result model remains. Copy/hash/tag/preflight, receiver selection/release and selected cleanup are still declared primitives. A published message pointer or queued list node is evidence of a local ownership transition under those premises, not completed native delivery or retirement. The original raw message/header/body/trailer match the earlier source-produced [allocation/notification report](kernel_kmsg_allocation_report.md), apart from original queue links and explicit internal-header/byte variants. [KQ2-KQ7]

No new incoming/outgoing service endpoint or Mach namespace binding is established. Model port, owner and receiver addresses are private CPU addresses. PID/service names, host-special-port mappings and actual daemon reception remain governed by the earlier reports; the historical zut trace still does not demonstrate selector 26 or RPC502/700. [KQ7]

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
|---|---|---|
| KQ1 | Pinned KC bytes, unwind bounds, zone specifications and separately pinned SDK numeric labels identify this analysis | Rehash original inputs/header; recapture complete bodies, exact sites, type specifications and macro lines; do not assume SDK layout establishes private kernel offsets |
| KQ2 | The original no-senders producer is the entry origin | Freshly replay it; compare complete RAM/globals and GP/SP/NZCV/SIMD entry state; retain exact packet/caller provenance |
| KQ3 | Declared port/queue/receiver state and explicitly modified queue-entry ABI/header/byte are component inputs | Recover actual initialization and membership producers; distinguish unmodified notification call state from after-preparation variants and counter-only stress epochs |
| KQ4 | Type metadata, bounds, owner geometry/backlink, lock-validity and thread/pending epochs admit selected original helpers | Replace fixtures with actual port/owner producers; separately validate invalidation, contention and pending-work paths; native geometry/locking remains unknown |
| KQ5 | Independent count/status/list/receiver oracles describe selected contracts | Verify every source word/effect, full port/kmsg bytes, queue Boolean versus send status, strict receive-capacity boundary and conditional high-count branch |
| KQ6 | Lower receiver selection/release and opaque copy/hash/tag/preflight primitives satisfy the declared call contracts | Recover their original membership/scheduling/authentication producers; do not promote a modeled candidate into an observed native waiting thread |
| KQ7 | Local publication/caller return and cleanup requests do not establish native delivery, name conversion or total lifetime | Join the receiver's actual copyout/retirement and authentic daemon/kext exchange; preserve incomplete policy/wait prefixes and distinct sender/receiver statuses |
| KQ8 | Complete bodies, finite replay and bounded scalar proofs have different scopes | Retain complex messages, other storage classes, timed waits, callback/cleanup and native limit eligibility as unexecuted/unknown; extend only with their prerequisites |

## Bounded further context

| Impact | Finding / remaining opportunity | Consequence |
|---|---|---|
| High | Original queue effects now connect source-built message data to receiver/list publication and caller status | Recover actual waitq selection/release and receiver copyout to extend ownership continuity |
| High | Sender success can coexist with receiver too-large status | Status interpretation requires the stage and object carrying it |
| High | The high-count test is conditional on the configured limit already being reached | A numeric threshold alone does not describe the source admission function; native limit eligibility remains separate |
| Medium | Count is reserved before unlock and reversed on direct handoff | Intermediate count is not simply linked-list length |
| Medium | Type-22/144-byte port validation matches the startup allocation specification | Connect allocation domains to queue interfaces without treating IDs as Mach names |
| Medium | Queue insertion Boolean differs from send status | Preserve notification/priority-change decisions separately from transport results |
| Low | Synthetic identity word `0x303` appears in receiver state | This is a copied component field, not evidence of a new service port |

## Reproduction, independent checks and quality gates

```sh
cd /Users/___/dev/dylex/extracted
export PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages
export Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_kernel_kmsg_queue.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_kernel_kmsg_queue.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kernel_kmsg_queue.py
```

Independent replay imports no probe executor. It verifies 12012 original instruction visits, 3551 reads / 23789 bytes, 2208 writes / 15892 bytes, 104 remaining primitive models, 106 sender/caller frames, 96 allocation frames, 89 queue/port/size/list frames, 16 variant boundaries, 16 final boundaries and 16777216 final RAM bytes. All 16 final SIMD/system states and 176 image-global records are checked. Independent oracles verify all port/kmsg bytes, receiver status/size/pointer/retry state, task counters/nesting, 396 input patch before images and controlled ABI/header variants. Three scalar proofs return `unsat`.

Recovery costs O(image + captured source) time/space. CPU/effect validation costs O(image + visits + RAM + effects) time and O(image + one private RAM map + journals) space. Circular-list/receiver oracles are linear in admitted nodes/candidates. Solver domains/expressions are retained; no solver-complexity bound is asserted.

QG1: no normative conclusion required. QG2: KQ1-KQ8 record assumptions, dependencies and falsification probes. QG3: queue/port/task/receiver/list ABI, original publication sites, status/ownership boundaries and Mach-endpoint limits covered for this increment; full investigation remains active. QG4: byte extents, u16 counts/limits, u32 capacities/status/sequence, u64 pointers/counters and exact size arithmetic are explicit. QG5: reservation/list length, enqueue Boolean/send status, sender/receiver status, selected limit/high-count condition and returned/prefix outcomes remain distinct. QG6: original bytes/specifications, pinned SDK numeric definitions, exact producer state, independent state oracles and full CPU/effect replay provide verified local provenance. QG7: bounded extensions and impact labels are recorded above. Scoped gates pass; native complete FairPlay continuity remains unknown.
