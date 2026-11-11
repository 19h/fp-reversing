# AES hashed-event selection and scheduler handoff

The global event queue uses header bits 5..31 as a conservative OR summary of waiter discriminators. For the direct AES pointer-event route, insertion ORs the event's low 27 bits into that summary. A missing summary bit bypasses scanning; a passing filter still requires exact u64 queue identity and event equality. Matching waiters leave the FIFO before their wait fields are cleared and a scheduler handoff is requested. The source supports immediate and temporary-queue handoffs, selected by the saved thread state and request mode. These results extend [event registration](aes_event_registration_report.md), [event-table startup](event_wait_table_report.md) and [identified Mach receiver selection](kernel_waitq_receiver_report.md). They establish a kernel scheduling interface; this increment identifies no additional Mach-port creation, right transfer or message emission. [WS1-WS7]

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| WS1 | Statements apply to the pinned original kernel collection and compiler-bounded bodies. Addresses are preferred virtual addresses. | Rehash the collection and compare every retained byte, instruction and function bound. A different image or slide requires a new correspondence. |
| WS2 | The direct AES path selects an initialized type-1 queue in the same live global table epoch as registration. | Match root/count reads, 24 B stride, validity byte, header type and actual table backing. Startup publication alone does not establish consumer visibility or lifetime. |
| WS3 | Under admitted locking, the queue summary contains all relevant discriminators. Direct waiters contribute low27(event); indirect waiters can contribute low27(outer identity). | Inventory concurrent insertions/removals and other header writers. A deliberately missing summary bit gives an abstract false-negative control. The local OR proof is not a complete concurrency proof. |
| WS4 | Symbolic queue, request, thread, stack and CPU cells are treated as disjoint objects. Declared rings have reciprocal links, stable identities/events and fewer than 0xffffffff selected members. | Check actual object extents/aliasing, corrupted links, independent writers, lifetime/reuse and count overflow. Original reciprocity guards remain represented; guard failure and pointer validity are not native-tested. |
| WS5 | Private wake cases admit wrapper guards, model DAIF snapshots and use returning lock/mask/scheduler ABI boundaries. | Establish real lock ownership, mask restoration, scheduler side effects and callback return behavior. PAC is a logical identity model; no hardware authentication is tested. |
| WS6 | Thread-state bits and CPU scratch identities are declared snapshots. Immediate versus deferred labels describe source routes, not native execution timing. | Correlate actual blocking transitions, state bit 2, CPU context, temporary-head lifetime and resumption. No symbolic thread-flag name or fairness/liveness property is inferred. |
| WS7 | Scalar proofs and finite instruction interpretation are evidence of source contracts only. | Obtain a matched daemon request, kext/provider operation, event registration, interrupt, wake and returned result. Native daemon/kext transactions, device progress and full-goal completion remain unknown. |

## Primary evidence and routine identities

The source collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Seven complete bodies retain 878 instructions / 3512 B. Their exact entry addresses have no nlist definition in the collection; the role names below are recovered descriptions. The reference bytes suffice, so this increment uses no IDA access or IDB mutation. [WS1,WS7]

| Recovered role | Preferred entry | Source function |
| --- | --- | --- |
| Registration core | `0xfffffe000bd6bc48` | Marks waiting, inserts membership, publishes the summary |
| Wake wrapper | `0xfffffe000bd6e22c` | Validates queue, masks/locks and supplies request flags |
| Request builder | `0xfffffe000bd6c59c` | Constructs local request, calls selector, releases queue, drains deferred members and returns count |
| Selector | `0xfffffe000bd6c660` | Selects direct/indirect queue, tests summary, invokes scanner and refreshes summary |
| FIFO scanner | `0xfffffe000bd6ce44` | Compares identity/event, removes matches and calls stager |
| Selected-thread stager | `0xfffffe000bd6cbcc` | Clears wait fields and chooses immediate versus temporary-queue handoff |
| Temporary-queue drain | `0xfffffe000bd6bad0` | Removes staged members and requests scheduler handoff |

## Summary producer, filter and refresh

Let E be the u64 event, H the u32 queue header, S=H>>5 and L=low32(E)&0x07ffffff. All shifts and OR operations below have their stated integer widths; the queue stride is 24 B. [WS1-WS3]

| Source location | Exact local contract |
| --- | --- |
| `0xfffffe000bd6bcec` | Direct type-1/2 registration retains X28=event; X24=outer queue |
| `0xfffffe000bd6bd88` | Indirect path instead retains X28=outer queue identity |
| `0xfffffe000bd6beb4` / `0xfffffe000bd6bebc` | Registration summary store requires selected queue within [table_root, table_root+24*count), after the source pointer-region guard |
| `0xfffffe000bd6bec4` / `0xfffffe000bd6bec8` | H := H OR (low32(X28)<<5); type/control bits 0..4 remain unchanged |
| `0xfffffe000bd6c7c8`..`0xfffffe000bd6c7d0` | Selector applies the corresponding table-range test for a type-1 queue |
| `0xfffffe000bd6c82c`..`0xfffffe000bd6c834` | Scan iff (L AND NOT S)==0; otherwise bypass FIFO and leave the header unchanged |
| `0xfffffe000bd6c888` | For a nonempty queue after a scan with selected<maximum, replace upper 27 bits with the scanner's OR accumulator |
| `0xfffffe000bd6c884` | selected>=maximum preserves the old summary for a nonempty queue |
| `0xfffffe000bd6c9a8` / `0xfffffe000bd6c9ac` | Empty queue clears upper 27 bits and preserves bits 0..4 |

Registration reaches the summary suffix after a successful mark-wait result and membership publication. For a direct AES waiter, the OR operation contains L and preserves every previously contained discriminator. Consequently the filter cannot reject that event under WS2-WS4. This is a conditional invariant, not a census of all possible header writers. [WS2-WS4]

The filter is a subset test, not equality or an event hash. For example, unmatched events 1 and 2 produce summary 3, which admits event 3. Events 1 and 1+2^27 also have identical L. Full comparisons below distinguish these cases. When L=0, the filter passes even for a zero summary. Nonzero events with low27=0 therefore still reach the ordinary scan. Type-1 queues outside the global table take the unfiltered FIFO call at `0xfffffe000bd6c7e0`; they do not use this summary-refresh branch. [WS2-WS4]

## Exact waiter selection and removal

| Offset / location | Width | Recovered meaning |
| --- | --- | --- |
| thread+0x18 | u64 | Registered full event |
| thread+0x28 | u64 | Registered outer queue identity |
| thread+0 / +8 | u64 each | Next / previous membership links |
| request+0 | u64 | Requested full event |
| request+8 / +0xc | u32 each | Result / source flags |
| request+0x10 | u32 | Maximum selected members |
| request+0x14 | byte, bit 0 | Identify mode |
| request+0x15 | byte, bit 0 | Additional matching member observed at limit |
| request+0x18 | u32 | Selected count |
| request+0x20 | u64 | Address of temporary queue head cell |

The scanner first compares u64[thread+0x28] with the requested outer identity at `0xfffffe000bd6ce9c`; only equality reaches the full event comparison at `0xfffffe000bd6ceac`. For a match below the limit, two reciprocal-link checks precede unlink stores at `0xfffffe000bd6cee8` / `0xfffffe000bd6ceec`. Singleton removal clears the head; removing the current head advances it. `0xfffffe000bd6cf1c` clears the removed thread's two links, then `0xfffffe000bd6cf28` calls the stager. The selected count increments only after that call returns. [WS1,WS4-WS6]

For each unmatched member, the OR accumulator uses its event when its recorded identity equals the inner queue; otherwise it uses that recorded outer identity (`0xfffffe000bd6cf04`..`0xfffffe000bd6cf10`). This distinction matches the registration inputs for direct and indirect routes. The accumulator masks each contribution to 27 bits at `0xfffffe000bd6ce78`. It is not simply an OR of every stored event in a generic mixed queue. [WS3,WS4]

After selecting the maximum, ordinary flags stop scanning. Request flag bit 5 instead continues until the ring ends or a further exact match is found; that further match sets request+0x15 without removing it. For maximum=0, an encountered exact match also sets this byte. The enclosing selector retains the old summary whenever a nonempty queue has selected>=maximum, including continued scans. This avoids shrinking the summary from a partial accumulator. [WS3,WS4]

## AES request and scheduler-facing interfaces

The preceding AES `wakeupGate(...,false)` route supplies maximum=0xffffffff and result=0. With input flags=0, the wrapper supplies raw request flags 4 or 0x14 according to the saved mask state. The builder zeroes identify, additional-match byte, selected count and temporary-head pointer. The complete private wake cases execute that wrapper and builder from original bytes. [WS2,WS5]

```text
hashed queue + full event
          |
          v
 summary contains required bits? -- no --> return without scan
          | yes
          v
 full identity + full event match --> unlink FIFO member
                                          |
                                          v
                                clear wait fields / set result
                                          |
                         identify=0 AND old state bit 2 set?
                              / yes                 \ no
                             v                       v
                  scheduler call boundary    temporary queue insertion
                                                     |
                                      release original queue in builder
                                                     |
                                             temporary queue drain
                                                     |
                                             scheduler call boundary
```

Under the thread spinlock boundary, `0xfffffe000bd6cc1c` / `0xfffffe000bd6cc20` clear identity/event; byte fields +0xcb and +0x58e clear; state+0x1f8 ORs 0x100; and result is written to thread+0xd8. The following decision tests the old state saved in W8. Identify mode or old bit 2 clear selects temporary staging. For the AES flags, identify=0 and flag bit 1 clear; old bit 2 set instead reaches the scheduler call at `0xfffffe000bd6cc78` with X0=thread. [WS4-WS6]

Temporary staging allocates no new thread object. It selects a CPU-context scratch head, increments the current thread's +0x1c8 counter once when first obtaining that head, sets the scratch marker and links selected members there. After releasing the original queue at `0xfffffe000bd6c618`, the builder calls the drain at `0xfffffe000bd6c63c` if the head-cell pointer is nonnull and flag bit 7 is clear. The drain unlinks members, clears their temporary links and reaches the scheduler call at `0xfffffe000bd6bb84`, again with X0=thread. The raw source scheduler result chooses whether to call `0xfffffe000bd27054(thread,5)`. Scheduler internals and actual runnable-state effects are not executed in this increment. [WS5,WS6]

The drain clears the scratch marker and decrements the nesting counter under its source guards. The complete finite cases start that counter at 0, exercise its increment/decrement and finish at 0. Request flags 4/0x14 do not request identified return. The builder returns selected_count+(additional_match_byte&1), modulo 2^32. For its AES maximum, the finite cases return the exact number selected. The earlier primitive's 0-to-48 / nonzero-to-0 translation remains as documented in the registration report. [WS4-WS6]

## Verification and reproducibility

The retained evidence supplies 20 new UNSAT certificates, three SAT discrimination/invariant controls, and 13 source cuts / 39 lifted instructions. The remaining retained instructions support the complete finite source paths, rather than being described as universally lifted. The publication audit rechecks all 47 preceding event-registration certificates and compares retained function bodies with the original collection. [WS1-WS7]

| Independent interpreter check | Count / coverage |
| --- | --- |
| Complete original wake compositions | 1152 |
| Limited selector compositions | 64 |
| Summary-miss complete cases | 352 |
| Passing-filter cases without an exact matching waiter | 464 |
| Immediate scheduler ABI models | 208 |
| Deferred scheduler ABI models | 208 |
| Limited cases containing a different outer identity | 32 |
| Complete-case canvases | Entire thread records with 16 B guards, queue record with 16 B guards, final temporary head/marker/counter, SP and callee-saved registers |

Private cases use count=1, so all chosen events share the same bucket under the preceding hash contract. They include repeated events, high-bit differences, low27-zero nonzero events, empty queues, both declared DAIF states, mixed state-bit-2 values and scheduler return snapshots 0/1. Additional maximum 0/1/2/0xffffffff and flag-bit-5 cases check early stop, additional-match observation and conservative summary preservation. Original insertion OR instructions populate the private header. Declared returning lock/scheduler calls clobber caller-saved registers. Logical PAC, DAIF and returning-call models are explicit; no native locking, interrupt masking, scheduling, Mach transport or device operation occurs. [WS2-WS7]

```sh
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/recover_aes_event_wake_selection.py --verify
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=triage_evidence \
  "$PYTHON" -P triage_evidence/audit_aes_event_wake_selection.py
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_aes_event_wake_selection_publication.py
```

The generator requires O(B+I+P) source/proof-construction time and space, excluding SMT solving, where B is source collection size in bytes, I retained instruction count and P certificate size. Finite interpretation costs O(cases*(executed source visits+canvas bytes)) time and O(code+private bytes) space. The FIFO pass is O(m) for m visited members; deferred draining is O(k) for k staged members, excluding modeled helper costs. No bound on real scheduler latency or native liveness follows. [WS4-WS7]

## Bounded continuation

| Impact | Unresolved interface / next probe | Result it would establish |
| --- | --- | --- |
| High | Follow scheduler body and thread-block transition with the same wait epoch and old state bit 2 | Meaning of the immediate/deferred split and the actual runnable/blocking-state correspondence |
| High | Correlate AES initialization, same event address, registered membership, admitted interrupt and returned provider result | A matched provider transaction beneath the daemon/kext interface |
| High | Establish complete summary/header writer and lifetime coverage under native locking | Whether the local discriminator invariant is maintained across all relevant concurrent operations |
| Medium | Trace CPU scratch selection and nesting against the current-thread/CPU scheduler context | Lifetime, migration and deferred-head ownership boundaries |
| Low | Apply the same source audit to indirect queues and request flags 1/2/7 | Generic interface coverage beyond the direct AES wake composition |

## Quality gates

- **QG1**: Factual source/ABI analysis; no normative conclusion required.
- **QG2**: WS1-WS7 specify assumptions, dependencies and falsification probes.
- **QG3**: Summary producer/filter/refresh, full comparison/removal, request ABI and both handoff routes are covered for this increment; the broad goal remains active.
- **QG4**: u32/u64/27-bit widths, byte offsets/extents, modular return arithmetic and algorithmic costs are explicit and reproducible.
- **QG5**: Mixed discriminators, subset false positives, low27-zero events, empty queues, maximum handling and helper/native boundaries are separated.
- **QG6**: Original bytes and bounds, exact-source certificates, prior certificates, finite instruction interpretation and publication checks provide distinct provenance.
- **QG7**: Continuations are bounded and ranked by impact; native epochs, liveness and daemon-facing completion remain unknown.

Evidence: [source and certificates](triage_evidence/aes_event_wake_selection_checks.json.zst), [generator](triage_evidence/recover_aes_event_wake_selection.py), [independent interpreter](triage_evidence/audit_aes_event_wake_selection.py), [publication audit](triage_evidence/verify_aes_event_wake_selection_publication.py).
