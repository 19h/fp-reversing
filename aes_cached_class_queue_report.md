# AES cached-class construction, enqueue and priority summary

The generic backend's cached-context route now has a source-backed construction and return path. The original constructor creates six generic records and six cached records, initializes 96 heads per queue representation and supplies the context byte used by cached selection. The cached route inserts the thread, publishes its membership flag, conditionally melds a new class into a deadline heap and refreshes the parent priority summary before returning. The return tests a parent-summary increase. Native scheduling, class ownership and daemon/provider completion remain unknown. No additional Mach endpoint, right transfer or message emission is established. [CQ1-CQ8]

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CQ1 | Results apply to the pinned original collection, compiler bounds and preferred addresses. All source claims depend on this identity. | Rehash the collection and compare every retained byte, bound, instruction and shared predecessor body. |
| CQ2 | Header, thread, candidate, owner, class records, ring peers and stack are disjoint and retain their declared identities. Constructor/backend joins depend on this epoch. | Establish native allocations, extents, aliasing, class changes, reuse and intervening writers. Fixed cells and private canvases do not prove arbitrary pointer safety. |
| CQ3 | The selected compact queue uses priorities 0..95, valid reciprocal rings and coherent maxima/counts. The source initializes this range; native caller enforcement remains unknown. | Trace actual priority producers and all callers. Distinguish the preceding abstract 128-value enqueue sweep from evidence of 96 initialized slots. |
| CQ4 | The examined backend path has thread+0x2a0=0, matching non-0xff cached context, class 0..5, zero thread flag bits at +0x53..+0x56, matching owner observations and no enabled trace path. | Exercise mismatched contexts, nonzero flags, invalid classes and actual lock ownership. The uncached backend is not executed by these compositions. |
| CQ5 | Constructor calls return, lower lock assertions are returning ABI models, PAC is logical identity, clock/CPU offsets are stable scalar snapshots and class LDADDH operations are single-RMW interpretations. | Observe real authentication, synchronization, clock migration, retries and concurrent writers. No native atomic or scheduler execution is inferred. |
| CQ6 | Private constructor/backend cases then seed declared occupancy, keys, thread fields and optional skip-bit snapshots. Auxiliary generation flag and generic-class summary mask are zero; the secondary-hint table is zero. | Establish native producers for those observations. Nonzero generation refresh, generic-summary selection and secondary-hint publication remain separate paths; private seeding is not an observed native transition. |
| CQ7 | Heap meld operands are null, identical or valid distinct roots with declared child links; packed child pointers are signed canonical 48-bit values. | Check actual address format, pointer tagging/authentication, root/child ownership, aliases and other heap operations. A SAT control distinguishes noncanonical pointer truncation. |
| CQ8 | Evidence is original bytes, scalar SMT certificates and finite private interpretation. | Match an admitted daemon operation to provider wait/interrupt, thread/event identity, queue insertion, dispatch and daemon result. End-to-end completion and the broad investigation remain unproved. |

## Primary source and routine roles

Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Eight complete bodies retain 1372 instructions / 5488 B. Exact entry symbols are absent; the following names describe recovered roles. Original reference bytes suffice, so no new IDA access or IDB mutation is used. [CQ1,CQ8]

| Recovered role | Preferred entry | Instructions | Execution coverage |
| --- | --- | --- | --- |
| Compact queue initializer | `0xfffffe000bd2d3cc` | 31 | Complete body |
| Paired class-record constructor | `0xfffffe000bd212b0` | 110 | Complete body and six initializer calls per construction |
| Placement backend | `0xfffffe000bd207c4` | 647 | Complete selected cached route |
| Compact enqueue | `0xfffffe000bd2d5cc` | 57 | Complete applicable insertion paths |
| Parent priority refresh | `0xfffffe000bd1ee74` | 77 | Cached summary with generic mask zero |
| Unsigned minimum-deadline meld | `0xfffffe000c48b7c0` | 26 | Complete body over declared roots |
| Candidate constructor | `0xfffffe000bd174a4` | 279 | Initializer argument/call edge only |
| Global constructor | `0xfffffe000c63a924` | 145 | Fixed initializer argument/call edge only |

## Construction establishes two layouts

Let R be the parent context and H=R+0x858 its scheduler header. Constructor `0xfffffe000bd212b0` receives X0=H, X1=owner. It writes signed16[H]=-1, zero counts at H+2/+4, owner at H+8, and u8[owner] at H+6. The last store is R+0x85e, the byte compared with thread+0x55c by the cached-route gate. Its loop creates class indices 0..5 with a 1112 B stride. [CQ1,CQ2]

| Representation / field | Generic record G=H+0x2a0+1112*c | Cached record C=H+0x1cb0+1112*c |
| --- | --- | --- |
| Same addresses in parent coordinates | R+0xaf8+1112*c | R+0x2508+1112*c |
| Class byte / representation byte | G+0=c, G+1=0 | C+0=c, C+1=1 |
| Maximum priority | signed32[G+8]=-1 | signed32[C+8]=-1 |
| Total count | u32[G+0x0c]=0 | u32[C+0x20]=0 |
| Occupancy words | G+0x10/+0x18 | C+0x10/+0x18 |
| Classified count | No corresponding field established here | u32[C+0x24]=0 |
| 96 initialized u64 heads | G+0x20 through G+0x31f | C+0x28 through C+0x327 |
| Embedded heap node / metadata / deadline | +0x420 / +0x430 / +0x438 | +0x420 / +0x430 / +0x438 |
| Additional initialization | +0x440=-1; +0x448=class-table value; +0x450=0 | Same offsets and values |

The generic constructor directly stores its queue fields. For each cached record, it passes C+8 to the compact initializer at `0xfffffe000bd21418`; that callee's queue-relative offsets therefore differ by 8 B from the record-relative layout. These representations share a record stride but have distinct headers. All offsets and extents are bytes. [CQ1,CQ2]

The compact initializer writes maximum=-1 at Q+0, clears Q+8..Q+0x1f, then clears Q+0x20..Q+0x31f: exactly 96 u64 heads. It preserves Q+4..Q+7 and does not initialize Q+0x320 onward. There are 51 stores covering 796 distinct B within an 800 B span. This is an initialized footprint, not a native allocation-size or universal caller-range proof. [CQ1-CQ3]

| Original initializer call | Argument | Recovered interface |
| --- | --- | --- |
| `0xfffffe000bd17510` | candidate+0x2a0 | The preceding branch skips this call for candidate=`0xfffffe000cac6e18` |
| `0xfffffe000c63a9c8` | `0xfffffe000cac70b8` | Equals `0xfffffe000cac6e18`+0x2a0, linking the special global candidate to the same queue offset |
| `0xfffffe000bd21418` | cached_record+8 | Executed once for each of the six constructed cached records |

The earlier [runqueue report](aes_runqueue_membership_report.md) tested the enqueue primitive over an explicitly abstract 0..127 domain. The initialized 0..95 footprint is now recovered from its actual constructor/callee. Algebraically, admitting priority 127 into the cached representation would address C+0x420, the heap-node start; none of the 96 initialized heads overlaps that node. The equality is a domain discriminator, not evidence that priority 127 reaches this route or that a native defect exists. Native range enforcement remains unknown. [CQ2,CQ3,CQ8]

## Cached insertion and first-class publication

The selected backend first validates the thread lock/owner interface, stores candidate at thread+0x20, takes the null thread+0x2a0 route and increments the class suffix counters described previously. A non-0xff u8[thread+0x55c] matching u8[R+0x85e] selects C. It increments u16[R+0x85a], stores the truncated count, then tests the untruncated increment's bit 16. Thus an overflow guard follows the count store; no rollback is inferred. [CQ2,CQ4,CQ5]

```text
paired constructor(H, owner)
  +-- generic[0..5]: header + direct head clearing
  +-- cached[0..5]: compact initializer(C+8)
                         |
              declared private occupancy/key/thread snapshot
                         |
backend cached-context gate -> first class member?
                         /                  \
                       yes                  no
                        |                    |
           class bitmap + optional           |
           deadline-heap publication         |
                        +---------+----------+
                                  v
                         compact enqueue(C+8, T, flags)
                                  |
                 thread+0x50=1; optional generation path
                                  |
                 classified parent count; priority refresh
                                  |
                    return new_summary > old_summary
```

If C's total count is nonzero, the source calls compact enqueue directly at `0xfffffe000bd209d8`. If it is zero, the source first sets class bit c in H+0x270 because the constructor supplied C+1=1. Class 0 then goes directly to enqueue. Other classes conditionally write C+0x438=raw_clock+CPU_offset+u64[class_offset_table+8*c], unless C+2 bit 0 suppresses that write. The numeric clock units and the table's native configuration are unknown. [CQ1,CQ4-CQ6]

For a newly populated nonzero class, `0xfffffe000bd21014`..`0xfffffe000bd21020` clear the heap node's first 16 B and zero-extend its existing u16 metadata into C+0x430. The source calls the original deadline meld with X0=u64[H+0x288], X1=C+0x420 and publishes its returned root at H+0x288. The C+0x448-dependent secondary bitmap branch remains outside these zero-table compositions. [CQ2,CQ5-CQ7]

After enqueue, the backend writes thread+0x50=1. Under the declared zero auxiliary-generation flag, it skips the optional generation/table recalculation. A classified priority also increments u16[R+0x85c]. It snapshots signed16[H], invokes the original parent refresh with X0=H and returns whether the refreshed signed value increased. This return is distinct from the enqueue's queue-local maximum-increase Boolean; it is not an insertion-success code. [CQ2-CQ6]

## Parent class selection and heap-node ABI

For a cached bitmap restricted to class bits 0..5, with coherent occupied-class maxima and generic bitmap H+0x260=0, the refresh follows these source choices. [CQ2,CQ4,CQ6]

| Cached bitmap condition | Cached priority chosen |
| --- | --- |
| No bits | -1 |
| Bit 0 set, bit 1 clear | Class 0 maximum |
| Bits 0 and 1 set | Larger of class 0 and class 1 maxima |
| Bit 0 clear, at least one other bit | Maximum field of the lowest-numbered occupied class |

Classes 2..5 are not all compared to class 0 when bit 0 is set. This is class-specific selection, not a maximum over all six class fields. The source combines the chosen cached value with the generic-summary candidate through a final signed maximum and stores signed16[H]. The generic-summary branch calls another helper and remains unexecuted here. [CQ1,CQ4,CQ6]

| Heap-node offset | Recovered role |
| --- | --- |
| +0 / +8 | Sibling/parent-or-predecessor links, interpreted within the declared rooted snapshot |
| +0x10 low16 | Preserved metadata |
| +0x10 bits63..16 | Low48 child pointer; ASR 16 recovers its signed canonical address |
| +0x18 | Unsigned 64-bit deadline key |

The complete meld returns the other operand for a null left root and returns immediately for a null right root or identical roots. Otherwise it selects the lower unsigned key; equal keys select the right operand. It links the losing root as the winner's first child, repairs an existing first child's +8 link, packs the new child pointer while preserving low16 metadata, and clears the winner's root links. This establishes one intrusive meld primitive, not every operation or invariant of a complete heap implementation. [CQ1,CQ2,CQ7]

## Verification

Thirty new UNSAT certificates cover 21 source cuts / 100 lifted instruction instances. Four abstract SAT controls retain the uninitialized upper-slot domain, hypothetical priority-127 address equality, changed parent-summary epoch and noncanonical pointer truncation. The publication audit also rechecks the earlier 24 runqueue and 34 block/wake UNSAT certificates. [CQ1-CQ8]

| Independent private interpretation | Cases |
| --- | --- |
| Complete compact initializer with guarded patterned canvases | 9 |
| Complete paired constructor, all twelve records and padding compared | 6 |
| Original constructor, declared snapshot, complete cached backend and source callees | 1152 |
| Complete deadline meld, unsigned key extremes, two pointer layouts and existing children | 288 |
| Null/identical-root meld returns | 6 |
| Cached priority refresh: all 64 six-class masks and four priority assignments | 256 |

All 1717 cases pass with 900921 source instruction visits. The 320 empty nonzero-class heap publications are a subset of the 1152 backend compositions. Those compositions vary all six classes, priorities 0/31/64/95, flags 0/1/5/0x25, classification, empty/same-priority/other-priority occupancy and deadline suppression. They execute the original paired constructor and its six initializer calls, then seed the declared snapshot and execute the original backend, enqueue, refresh and applicable meld. Entire 16384 B parent and thread/peer canvases with 16 B guards, restored SP/saved registers and final return are checked. [CQ2-CQ7]

Constructor-only cases compare the entire 14016 B output span, including preserved gaps and all twelve records; saved D8/D9 low64 values are also checked. The 256 summary-only cases seed the scalar fields read by the selected refresh path; they do not populate corresponding rings or establish full-queue invariants. Meld cases compare complete guarded node canvases at both positive and sign-extended negative canonical addresses. The independent interpreter imports neither this increment's generator nor Z3. No private case executes a native queue, lock, PAC, atomic, context switch or IPC operation. [CQ2,CQ5-CQ8]

```sh
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/recover_aes_cached_class_queue.py --verify
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=triage_evidence \
  "$PYTHON" -P triage_evidence/audit_aes_cached_class_queue.py
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_aes_cached_class_queue_publication.py
```

Recovery/proof construction costs O(B+I+P) time/space for source bytes B, instructions I and certificate size P; SMT cost is separate. Private interpretation costs O(cases*(source visits+canvas bytes)) time and O(code+private bytes) space. Counter widths, byte extents and raw clock arithmetic remain distinct; no SI clock conversion or native scheduling-time bound is inferred. [CQ1,CQ5,CQ8]

## Bounded continuation

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High | Native priority producers and caller admission to the 96-head queue | Actual enforcement of the initialized compact-queue domain |
| High | Uncached backend, three lane selectors and per-context embedded nodes | Placement when cached identity is absent or mismatched |
| High | Correlated daemon/provider/thread/event/queue/dispatch observations | Concrete cross-layer completion |
| Medium | Generic-summary helper, class scheduling metadata and original heap removal/rekey | Full parent-summary semantics and record retirement |
| Medium | Auxiliary generation refresh, secondary-hint table and live clock/lock observations | Nonzero paths and actual scheduling epochs |
| Low | Native names/enumerations for class bytes and preserved heap metadata | Semantic labels beyond the recovered numeric ABI |

## Quality gates

- **QG1**: Factual source/interface analysis; no normative conclusion is required.
- **QG2**: CQ1-CQ8 list assumptions, dependent results and falsification probes.
- **QG3**: This increment covers queue construction, cached insertion, heap publication, class summary and return ABI; the broad goal stays active.
- **QG4**: Byte extents, widths, raw clock sums, signed/unsigned comparisons, case counts and complexity are explicit and reproducible.
- **QG5**: The abstract 128-value sweep, 96 initialized heads, alternate headers, optional branches, pointer domain and source/native boundaries are reconciled.
- **QG6**: Original bytes/bounds, scalar certificates, independent complete-source private cases and exact publication checks supply distinct provenance.
- **QG7**: Further work is bounded and impact-ranked; native range enforcement, ownership, scheduling and daemon completion remain unknown.

Evidence: [source and certificates](triage_evidence/aes_cached_class_queue_checks.json.zst), [generator](triage_evidence/recover_aes_cached_class_queue.py), [independent interpreter](triage_evidence/audit_aes_cached_class_queue.py), [publication audit](triage_evidence/verify_aes_cached_class_queue_publication.py).
