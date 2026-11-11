# AES wake placement and compact runqueue membership

The original queue backend beneath AES wake placement has a bound-context route that inserts the thread into a compact priority ring. In that route, actual membership stores are now recovered and privately interpreted, extending the earlier placement-prefix evidence. The enqueue return is a Boolean maximum-priority increase: 0 can accompany completed insertion. Raw AES wake flags 5 and post-switch flags 0x25 both select append at the existing priority. This establishes source contracts, with native queue membership and scheduling still unknown. No additional Mach endpoint, right transfer or message emission is established. [RQ1-RQ8]

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RQ1 | Results apply to the pinned original kernel collection and compiler-bounded bodies at preferred virtual addresses. All address and instruction claims depend on this identity. | Rehash the collection and compare every retained byte, bound and decoded instruction. A changed image or slide needs a new correspondence. |
| RQ2 | Queue, thread, ring peers, auxiliary records and stack are disjoint, valid and retain their declared pointer identities. Layout and mutation claims depend on this domain. | Check native extents, aliases, intervening writers, reuse, queue ownership and object lifetimes. Fixed-cell proofs do not establish arbitrary pointer safety. |
| RQ3 | The signed 16-bit priority is in 0..127 and existing rings satisfy the stated reciprocal-link invariant. The caller establishes this domain. | Trace real priority producers and all caller guards. The primitive itself has no complete range check. Corrupt-ring cases reach the original BRK frontiers; they do not execute traps. |
| RQ4 | Selected source phases share an ownership epoch; lock assertions and optional callees return according to the explicit ABI models. | Establish actual lock ownership, exclusion, lifetime and concurrent writers. Logical PAC and caller-saved clobbers do not authenticate pointers or execute locking. |
| RQ5 | Generic-route class is 0..5; auxiliary base, class and context index remain stable for the joined record calculations. LDADDH uses a declared single-RMW observation. | Trace class changes, backing allocations, atomic ordering, retries and counter overflow. A SAT control distinguishes records with different base epochs. |
| RQ6 | Complete placement cases use a nonnull bound pointer equal to the declared candidate/current-context identity, matched owner/generation observations, CPU-context state 0 and zero weight-refresh masks. | Exercise different candidates, state words 4/5/6, generation changes, nonzero masks and real optional helper effects. These finite cases do not cover the generic route or remote-context notification. |
| RQ7 | u16/u32 counters use modular arithmetic; validity of native counts and maxima is a separate invariant. | Trace initializers, deletion, rollover and count-to-membership consistency. An abstract control demonstrates u32 wrap. The -1 empty maximum used privately is a snapshot, not a recovered initializer claim. |
| RQ8 | Evidence is original bytes, scalar SMT certificates and finite private instruction interpretation. | Correlate an admitted daemon request, provider wait/interrupt, actual thread/event epoch, runqueue publication, dispatch and daemon result. Native execution, synchronization, PAC and end-to-end completion remain unknown. |

## Primary evidence and routine roles

Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Four complete bodies retain 1556 instructions / 6224 B. Exact entry symbols are absent; these are recovered kernel roles, not asserted original function names or an attribution of the scheduling algorithm to FairPlay cryptography. The original reference bytes suffice; no new IDA access or IDB mutation is used. [RQ1,RQ8]

| Recovered role | Preferred entry | Instructions | Source interface |
| --- | --- | --- | --- |
| Placement backend | `0xfffffe000bd207c4` | 647 | X0=candidate, X1=thread, X2=raw source flags; bound or generic route |
| Compact priority enqueue | `0xfffffe000bd2d5cc` | 57 | X0=queue, X1=thread, X2=raw flags; X0 returns maximum-increase Boolean |
| Context weight refresh | `0xfffffe000bd2173c` | 163 | Called after backend; only its zero-mask continuation is privately executed here |
| Placement | `0xfffffe000bd27054` | 689 | Previous thread/flags ABI; selected complete bound route now executes through enqueue |

```text
AES event wake -> wake-state decision -> placement(thread, 5)
                                             |
post-switch requeue -> placement(thread, 0x25)|
                                             v
                           backend(candidate, thread, flags)
                                  |
                  thread+0x2a0 nonnull?
                       /                    \
                     yes                    no
                      |                      |
          candidate+0x2a0 queue       class/context records
                      |                      |
                      +--> compact enqueue <-+ [selected cached route]
                              |
                      ring links + bitmap + counts
```

The left route is source-executed through return in twelve private placement cases. The right route is covered by branch/counter prefixes and layout cuts, not a complete generic-backend execution. The earlier event-wake and post-switch callers remain established by the [block/wake report](aes_block_wake_handshake_report.md). Their complete compositions with this newly executed placement are not claimed. [RQ2-RQ6,RQ8]

## Backend routing and record joins

At `0xfffffe000bd207fc`, the backend calls the thread+0xa8 lock assertion interface with W1=1. It compares u32[current-thread+0x518] against u32[parent-context+0x10c], where parent-context=u64[candidate+0x20]. It then publishes candidate at thread+0x20 (`0xfffffe000bd20818`). A nonzero u64[thread+0x2a0] selects the bound route, which prepares (candidate+0x2a0, thread, source flags), restores its frame and tail-branches at `0xfffffe000bd20850` to compact enqueue. The two +0x2a0 offsets have distinct bases: the thread field selects the route; the candidate field embeds the queue. [RQ1,RQ2,RQ4,RQ6]

For the null route, the backend reloads the parent context, rechecks owner identity and branches on u8[thread+0x204]. Classes 0..5 select suffixes of six u16 increments at parent+0xae8+2*j. Class k increments every j from k through 5, with modular u16 arithmetic; classes 6 and 255 reach the invalid-class diagnostic frontier in private checks. These are cumulative counters, not six independent single-class increments. The native statistical meaning and admissible rollover remain unknown. [RQ1,RQ5,RQ7]

| Interface / field | Source equation or offset | Evidence boundary |
| --- | --- | --- |
| Cached context test | u8[thread+0x55c] != 0xff and equals u8[parent+0x85e] | Precedes cached class queue route; other flags also select paths |
| Cached class record | parent + 0x2508 + 1112*class | Source cut at `0xfffffe000bd209ac` |
| Embedded compact queue | cached_record + 8 = parent + 0x2510 + 1112*class | Selected nonempty call at `0xfffffe000bd209d8`; empty-count path is separate |
| Auxiliary class record | A + 0x60 + 112*class, A=u64[thread+0x298] | Source cut at `0xfffffe000bd209e4` |
| Earlier paired counter join | auxiliary_record + 0x20 = A + 0x80 + 112*class | Same base/class epoch required by the earlier increment/decrement contracts |
| Earlier elapsed field join | auxiliary_record + 0x58 = A + 0xb8 + 112*class | Raw timing semantics remain those of the earlier report |
| Uncached context-array pointer | u64[auxiliary_record+0x60] | Loaded in the uncached continuation |
| Selected uncached record | context_array + 200*u8[parent+0x85e] | Source cut at `0xfffffe000bd20ac4`; subsequent heap/placement effects remain open |

The repeated class index supplies a conditional join between prior wake accounting and this lower placement backend. It does not prove that separate native observations share A, class or lifetime. All offsets and strides are bytes. [RQ2,RQ5,RQ8]

## Compact queue layout and insertion

| Base | Offset / extent | Width / recovered role |
| --- | --- | --- |
| Queue Q | +0x00 | Signed 32-bit current maximum priority |
| Queue Q | +0x08, +0x10 | Two u64 occupancy words for the declared 128-priority domain |
| Queue Q | +0x18 | u32 total count |
| Queue Q | +0x1c | u32 classified count |
| Queue Q | +0x20 + 8*p | u64 circular-ring head for signed priority p; 128 entries end at Q+0x420 |
| Thread T | +0x00, +0x08 | u64 next / previous links |
| Thread T | +0x214 | Signed 16-bit priority, sign-extended by LDRSH |
| Global `0xfffffe000cad06a8` | +8*(p>>6) | u64 classification word; bit p mod 64 selects classified-count increment |

For an empty selected bucket, stores at `0xfffffe000bd2d60c` and `0xfffffe000bd2d610` publish T.next=T, T.previous=T and bucket.head=T. The source sets the occupancy bit. It compares the signed previous maximum with the sign-extended priority, stores a new maximum only when p is larger, and returns 1 only for that increase. [RQ1-RQ3,RQ7]

For a nonempty bucket, H=head and P=u64[H+8]. The source checks u64[P]==H before mutating the ring. Both insertion variants write T.next=H, T.previous=P, P.next=T and H.previous=T. Bit 0 of flags chooses whether the head changes. The check is one reciprocity guard, not validation of every ring invariant. [RQ2-RQ4]

| Flags bit 0 | Additional head store | Traversal after insertion | Return |
| --- | --- | --- | --- |
| Clear | bucket.head=T at `0xfffffe000bd2d604` | T, previous members in their prior order | 0 for an already nonempty bucket |
| Set | Head unchanged; append stores at `0xfffffe000bd2d658`..`0xfffffe000bd2d660` | Previous members in their prior order, T | 0 for an already nonempty bucket |

Both flags 5 and 0x25 have bit 0 set. They therefore preserve same-priority FIFO order under the declared valid-ring snapshots. After either empty or nonempty insertion, the source increments Q+0x1c when the classification bit is set, always increments Q+0x18, moves X9 to X0 and returns. These increments are u32 modular operations. In 3064 of the 4096 complete private enqueue cases, return 0 accompanies the expected new membership and total-count increment. That return alone cannot establish insertion failure. [RQ2-RQ4,RQ7]

## Complete selected placement route

Twelve private cases extend the preceding placement-prefix checks through the original backend, its tail-branch to the complete enqueue body, the original weight-refresh zero-mask continuation and the original placement epilogue. They use priorities 0,20,96; raw flags 5/0x25; and both classification outcomes. The candidate's state word is 0, owner/generation observations match and the bound pointer selects the declared candidate. This route publishes thread+0x208=3, thread+0x2b0=candidate and thread+0x20=candidate, produces the exact 1056 B queue image, retains a one-member circular thread ring and restores SP and saved registers. [RQ1-RQ4,RQ6]

The weight refresh tests the parent masks at +0xa0/+0xa8; their zero intersection takes its early return. The final tail branch at `0xfffffe000bd2781c` calls the parent+0x100 release interface, represented by a returning ABI model. Lock operations, the helper that supplies thread+0x208 and optional owner/helper effects are not native executions. The placement caller discards the enqueue return before refreshing weights. Other candidate states, generic-backend execution, dispatch and hardware completion remain unknown. [RQ4,RQ6,RQ8]

## Verification

Twenty-four new UNSAT certificates cover 16 source cuts / 72 lifted instruction instances. Three abstract SAT controls retain count wrap, base-epoch mismatch and zero-return insertion. The publication audit rechecks the earlier 34 block/wake and 20 wake-selection UNSAT certificates and compares retained original bodies. [RQ1-RQ8]

| Independent private interpretation | Cases |
| --- | --- |
| Complete compact enqueue: all 128 priorities, four flag values, both classifications, four ring configurations | 4096 |
| Reciprocal-link rejection frontiers, without executing BRK | 2 |
| Original generic route prefix: all six class suffixes, zero/max u16 observations | 12 |
| Invalid-class diagnostic frontiers | 2 |
| Cached/auxiliary/uncached record cuts: six classes, three context indices | 18 |
| Complete selected bound placement through actual compact insertion | 12 |

All 4142 finite cases pass, with 133006 source instruction visits. Complete enqueue cases compare entire queue and thread/peer byte canvases with 16 B guards, exact expected ring order, reciprocal links and preserved saved registers/SP. Complete placement cases compare the entire embedded queue and the stated thread fields/registers. The interpreter imports neither this increment's generator nor Z3. The 128-priority sweep is exhaustive over its selected scalar dimension; it is not exhaustive over native states, rings, flags, aliases or interleavings. [RQ2-RQ8]

```sh
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/recover_aes_runqueue_membership.py --verify
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=triage_evidence \
  "$PYTHON" -P triage_evidence/audit_aes_runqueue_membership.py
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_aes_runqueue_membership_publication.py
```

Source recovery/proof construction costs O(B+I+P) time/space for source bytes B, instructions I and certificate size P; SMT solving is separate. Independent interpretation costs O(cases*(source visits+canvas bytes)) time and O(code+private bytes) space. Offsets, extents and strides use bytes; counters use the stated widths. No clock-to-SI conversion or native scheduling-time bound is inferred. [RQ1,RQ5,RQ7,RQ8]

## Bounded continuation

| Impact | Next source / native evidence | Question resolved |
| --- | --- | --- |
| High | Complete generic backend and uncached context/heap routes | Placement beyond the bound-context and selected cached layouts |
| High | Original candidate selector, priority producers, queue initialization/removal and admitted invocation | Valid ranges, actual owning queue, max/count invariants and dispatch lineage |
| High | Correlated daemon/provider wait/interrupt, thread/event identity, enqueue and daemon result | Concrete cross-layer completion rather than separated source phases |
| Medium | Nonzero weight masks and candidate states 4/5/6 | Refresh, notification and remote scheduling interfaces |
| Medium | Auxiliary class/base changes, counter lifetimes and native atomic observations | Whether accounting and placement records share the required epoch |
| Low | Classification bitmap producers and higher source flag bits | Semantic names for the classified counter and additional placement options |

## Quality gates

- **QG1**: Factual source/interface analysis; no normative conclusion is required.
- **QG2**: RQ1-RQ8 record assumptions, dependent results and falsification probes.
- **QG3**: This increment covers routing, membership writes, queue/record ABIs, return semantics and architectural boundaries; the broad investigation remains active.
- **QG4**: Byte extents, signed priority, modular widths, formulas, case counts and complexity are explicit and reproducible.
- **QG5**: Successful zero returns, malformed rings, class suffixes, modular overflow, modeled calls and unexecuted native paths are separated.
- **QG6**: Pinned primary bytes, SMT certificates, independent instruction interpretation and publication checks provide distinct provenance.
- **QG7**: Further work is bounded and impact-ranked; native scheduling, IPC completion and pointer epochs remain unknown.

Evidence: [source and certificates](triage_evidence/aes_runqueue_membership_checks.json.zst), [generator](triage_evidence/recover_aes_runqueue_membership.py), [independent interpreter](triage_evidence/audit_aes_runqueue_membership.py), [publication audit](triage_evidence/verify_aes_runqueue_membership_publication.py).
