# AES uncached context lanes, thread nodes and queue score

The placement backend's uncached route now has a source-backed private construction and insertion path. A 200 B context holds three lane nodes, a secondary priority heap, a waiter list and a generic-class queue node. Each incoming thread contributes two different heap nodes and one waiter-list node. The queue score, thread priority, auxiliary class, context class and parent priority summary have distinct source roles. The examined policy-off score can differ from the parent summary. Native scheduling and matched daemon/provider completion remain unknown; this increment establishes no additional Mach endpoint, right transfer or message emission. [UC1-UC8]

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| UC1 | All source claims refer to the pinned original kernel collection, compiler bounds and preferred addresses. | Rehash the collection and compare every retained bound, byte and decoded instruction, including predecessor overlaps. |
| UC2 | Thread, candidate, parent, auxiliary object, context array, stack and embedded nodes retain disjoint declared identities. Layout and composition results depend on this snapshot. | Establish actual allocations, extents, reuse, aliasing, class changes and intervening writers. Private guarded canvases do not prove arbitrary pointer safety. |
| UC3 | Auxiliary and context classes are 0..5, type and lane are 0..2, tested priorities are nonnegative and scores remain within the 96 initialized generic heads. | Recover all native producers and admission checks. Symbolic byte arithmetic does not establish native range enforcement or classify an out-of-domain write as reachable. |
| UC4 | The selected backend has thread+0x2a0=0, cached byte +0x55c=0xff, matching lock-owner observations and no enabled trace path. | Exercise the mismatching cached-byte alternative, bound placement, owner changes and trace branches. Only the declared uncached route executes here. |
| UC5 | PAC is logical identity; lock assertions return; clock/CPU offsets are stable scalars; LDADDH, LDADD, LDSET and CASP are serialized scalar observations. | Observe authentication, real locks, CPU migration, CASP retries, ordering and concurrent writers. No native atomic, interrupt or scheduling result follows. |
| UC6 | Auxiliary policy byte is zero, score offset is 0 or 1, class secondary-hint table is zero and context/queue records start coherently empty. | Establish the policy, generation, timer and hint producers; execute the nonzero paths. These private values are declared inputs, not native observations. |
| UC7 | Serialized second-thread cases retain one context in its generic class and one lane node in its parent bucket. Both initial thread heap nodes are childless; the second timestamp is later. | Add existing children, multiple contexts, different lanes/classes, equal or reversed timestamps, nonroot heap repair and removal. The current joins do not prove full heap invariants. |
| UC8 | Evidence is original source bytes, scalar SMT certificates and finite private instruction interpretation. | Match an admitted daemon request to provider/event/thread identity, queue placement, dispatch and returned result. End-to-end completion remains unknown and the broad investigation stays active. |

## Primary source and routine roles

Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Eleven complete bodies retain 1348 instructions / 5392 B. Exact entry symbols are absent; names below describe recovered roles. Original reference bytes suffice; no additional IDA access or IDB mutation is used. [UC1,UC8]

| Recovered role | Preferred entry | Instructions | Selected execution |
| --- | --- | --- | --- |
| Placement backend | `0xfffffe000bd207c4` | 647 | Uncached first-context and same-context second-thread routes |
| Paired class constructor | `0xfffffe000bd212b0` | 110 | Complete constructor |
| Compact initializer | `0xfffffe000bd2d3cc` | 31 | Six original calls per constructor |
| Context score | `0xfffffe000bd1ec40` | 141 | Policy-off route |
| Generic summary selection | `0xfffffe000bd1efa8` | 82 | Single occupied generic class, no override |
| Parent priority refresh | `0xfffffe000bd1ee74` | 77 | Generic summary and empty cached mask |
| Unsigned minimum-deadline meld | `0xfffffe000c48b7c0` | 26 | First nonzero-class publication, null prior root |
| Primary thread heap meld | `0xfffffe000c48bb48` | 42 | First node and two-thread join |
| Secondary signed-priority meld | `0xfffffe000c48b42c` | 27 | First node and two-thread join |
| Existing-context rekey | `0xfffffe000bd1ea3c` | 129 | Unchanged score and one-context score increase |
| Parent heap priority raise | `0xfffffe000c48b730` | 36 | Sole-root early return only |

## Record selection and lane interfaces

Let T be the thread, R the selected parent, H=R+0x858, D=u64[T+0x298], a=u8[T+0x204], A=D+0x60+112*a and X=u64[A+0x60]+200*u8[R+0x85e]. The source reads context class c=u8[X+0xc0] and type t=u8[X+0xc4]. Auxiliary class a, context class c and type t are separate fields. The constructor-supplied context index can be 0 or 3 in these cases without changing the 200 B stride. [UC1-UC4]

| Source low-bit condition | Lane l |
| --- | --- |
| (u8[T+0x53] OR u8[T+0x55]) bit 0 set | 0 |
| Otherwise, (u8[T+0x54] OR u8[T+0x56]) bit 0 set | 1 |
| Otherwise | 2 |

Original branches `0xfffffe000bd20af4`..`0xfffffe000bd20b18` and `0xfffffe000bd20f74`..`0xfffffe000bd20f84` implement this precedence. All 16 low-bit combinations are checked through that branch graph, with nonzero upper flag bits. Independent earlier flag tests set thread+0x51/+0x52 and update separate per-owner lane-0/lane-1 statistics; the two tests can both apply even though lane selection has precedence. The 1620 complete first-context cases use one canonical flag pattern per lane. [UC1,UC4,UC5]

| Object | Address / fields | Role |
| --- | --- | --- |
| Embedded lane node L | X+0x18+40*l | Parent-bucket heap node |
| Lane metadata / marker / primary root | L+0x10 / L+0x18 / L+0x20 | Primary rank in metadata bits15..8; marker initially 0xff; root of thread nodes |
| Parent lane/type bucket B | R+0x878+168*l+56*t | Six class roots at B+8*c; class bitmap at B+0x30 |
| Parent lane type bitmap | R+0xa70+8*l | Bit t published by LDSET |
| Context secondary root | X+0x10 | Heap of thread+0x80 nodes |
| Context global-list node | X+0x90 | Nonzero-class context registration |
| Context generic-ring node | X+0xa0 | Queue membership at the context score |
| Context waiter sentinel / tail | X+0xb0 / X+0xb8 | Thread+0x98 intrusive nodes |
| Context class / score / active count / type | X+0xc0 / +0xc1 / +0xc2 / +0xc4 | u8 / u8 / u16 / u8 |

The three 40 B lane records end at X+0x90. The last named field at X+0xc4 lies within the selected 200 B stride; the stride alone does not prove a native allocation contract. On first lane publication the source initializes L's root links, preserves its low16 metadata, melds it into B+8*c, atomically ORs the class/type bits and writes marker=t at `0xfffffe000bd20c64`. Subsequent rank increases call the parent-heap priority-raise helper; only its sole-root early return is executed by the two-thread compositions. [UC1-UC3,UC5,UC7]

## Two heap nodes and a waiter node per thread

| Thread-relative field | Emitted value / function |
| --- | --- |
| T+0x20 / T+0x58 | Candidate pointer / selected lane |
| T+0x60 and T+0x68 | Primary heap links, initially zero |
| T+0x70 | ((u8[T+0x214]) << 8) OR ((source_flags AND 1) XOR 1), then packed child pointer above low16 |
| T+0x78 | Raw clock plus CPU offset |
| T+0x80 and T+0x88 | Secondary heap links, initially zero |
| T+0x90 | Selected priority low8 shifted left 8, then packed child pointer above low16 |
| T+0x98 and T+0xa0 | Appended waiter-list next and previous links |

The secondary priority is u16[T+0x214] when u32[T+0x210] AND 0x1894c6 is nonzero or u8[T+0x53d] is nonzero; otherwise it is u16[T+0x216]. The scalar cuts prove both gate forms and packing. Complete cases exercise the fallback, allowing primary and secondary priority to differ. The preindexed waiter-node store changes the source base to T+0x98; its later load at +0x17c therefore reads T+0x214. It does not identify an additional priority field. Thread+0/+8 are preserved, and the cached membership byte T+0x50 stays zero. [UC1-UC6]

The primary meld selects the larger signed16 key. Equal keys use unsigned timestamps: key bit0 clear prefers the earlier timestamp; bit0 set prefers the later timestamp; equal timestamps retain the left operand. The secondary meld compares signed16 keys and retains the left operand on equality. Both use the already recovered packed child-pointer format: metadata in low16 and a signed canonical 48-bit child pointer in bits63..16. Two-thread cases check both winner choices and corresponding link/metadata writes; arbitrary existing-child and pointer-domain coverage is outside this increment. [UC1,UC3,UC5,UC7]

## Accounting, first publication and existing-context return

```text
backend uncached selection -> context X and lane L
        |
        +-> primary T+0x60 meld -> lane rank -> parent lane/type/class root
        +-> secondary T+0x80 meld -> X+0x10
        +-> waiter T+0x98 append -> X+0xb0 sentinel
        |
        v
auxiliary counts / count-epoch CASP / context and parent counts
        |
        +-- first context -> score -> generic class publication -> refresh
        |
        +-- existing context -> tail rekey -> score changed?
                                               |          |
                                              yes         no
                                               |          |
                                      move same node    return 0
                                      then refresh
                                               |
                                  return parent summary increased
```

The uncached route increments classified u16[R+0x85c] when the primary priority's classification bit is set, u16[D+0x50], u16[X+0xc2] and u16[R+0x85a]. It updates the 128-bit count/epoch pair at A+0x30/+0x38 with CASP: count increases by one, and epoch becomes raw-now only when the previous count was zero. This pair differs from the earlier wake-helper pair at A+0x20/+0x28. The second private insertion preserves the first epoch (107) while its thread timestamp becomes 207. Numeric clock units remain unknown. Count stores precede the examined overflow guards; no rollback is inferred. [UC1,UC3-UC7]

First publication calls the context score helper. With policy byte u8[A]=0, it uses the secondary root's priority byte plus u8[A+0x40], returning the low8 sum. That byte becomes X+0xc1. Generic record G=R+0xaf8+1112*c contains a 96-head ring queue from the preceding constructor report; the backend inserts X+0xa0 at G+0x20+8*score. Source modifier 4-(source_flags AND 2) is 4 or 2 and selects append/prepend behavior for occupied rings. Only singleton context rings execute here, so the compositions cannot distinguish their ordering. [UC1-UC3,UC6,UC7]

For c>0 the first context also appends X+0x90 to H+0x10/+0x18 and publishes G+0x420 through the original deadline meld. Its declared table gives deadline 107+1000+c in raw units. The backend sets the generic class bit at H+0x260, increments the per-class global active-context count at `0xfffffe000cb62930`+4*c and stores H at X+8. These are context registrations, not per-thread registrations. The selected parent refresh calls the original generic-summary helper and derives its result from a selected context's secondary-root priority, rather than that context's offset-adjusted queue score. For example, base 31 plus offset 1 gives score 32 while parent summary is 31. [UC1,UC5-UC7]

An existing context follows the tail branch at `0xfffffe000bd20db4` to `0xfffffe000bd1ea3c`. With unchanged score and modifier bit0 clear, it returns zero after accounting; no parent refresh occurs. A score increase removes the same X+0xa0 node from its old priority ring, updates occupancy/maxima, reinserts it and refreshes the parent summary. The generic context count, global active-context count and global context-list membership remain one in these serialized joins; the context's thread count becomes two. The return reports an increase in parent summary, not insertion success. [UC1,UC5-UC7]

## Verification

Twenty-five new UNSAT certificates cover 20 source cuts / 90 lifted instruction instances. Three abstract SAT controls distinguish queue score from parent priority, auxiliary class from context class, and modular u16 counter wrap. They do not establish native reachability. The publication audit also rechecks the preceding 30 cached-class and 24 runqueue UNSAT certificates. [UC1-UC8]

| Independent private interpretation | Cases |
| --- | --- |
| Constructor, declared empty context, complete first-context backend and source callees; guarded parent/auxiliary/context/two-thread canvases | 1620 |
| All low-bit lane-selector paths with nonzero upper bits | 16 |
| Original first insertion followed by second-thread insertion and original tail rekey | 216 |

All 1852 cases pass with 1941220 interpreted source-instruction visits and 8928 recorded scalar LDADD/LDSET/CASP observations; this observation count excludes LDADDH. First-context cases vary all six context classes, three lanes, three types, primary/base pairs (0,0), (64,31), (95,64), source flags 0/1/2/5/0x25 and classification. Auxiliary class, offset and context index vary as declared functions of those inputs, not as an exhaustive independent Cartesian product. Second-thread cases use four primary/base transitions, all six classes, three lanes and flags 0/1/2. Fifty-four increase the score; 162 retain it. Complete guarded 16384 B parent, 1024 B auxiliary, 200 B context and two 1552 B thread records are compared, with SP/saved-register restoration, scalar statistics and per-class active counts. No private case executes a native queue, PAC, lock, atomic, context switch, device or IPC operation. [UC2-UC8]

```sh
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/recover_aes_uncached_context_queue.py --verify
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=triage_evidence \
  "$PYTHON" -P triage_evidence/audit_aes_uncached_context_queue.py
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_aes_uncached_context_queue_publication.py
```

Recovery costs O(B+I+P) time/space for source bytes B, instructions I and certificate size P; SMT cost is separate. Interpretation costs O(cases*(source visits+canvas bytes)) time and O(code+private bytes) space. Byte offsets, widths, signed comparisons and raw-clock arithmetic remain explicit; no conversion to SI time is established. [UC1,UC5,UC8]

## Bounded continuation

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High | Correlated daemon/provider/event/thread/context/dispatch observations | Concrete cross-layer completion and identity |
| High | Actual priority/class/type/index/score producers and caller admission | Native enforcement of record and 96-head domains |
| High | Nonzero auxiliary policy, generation and timer paths | Full context score and temporal policy semantics |
| Medium | Multiple contexts, occupied destination rings, nonroot raises and removal/rekey | Ordering, heap maintenance and retirement beyond singleton contexts |
| Medium | CASP mismatch/retry, CPU migration and real lock/clock observations | Concurrent accounting and scheduling epochs |
| Low | Native class/type enumerations and metadata names | Labels beyond the recovered numeric ABI |

## Quality gates

- **QG1**: Factual interface/source analysis requires no normative conclusion.
- **QG2**: UC1-UC8 state assumptions, dependent results and falsification probes.
- **QG3**: This increment covers uncached placement, embedded nodes, accounting, score, generic summary and serialized rekey; the broad investigation stays active.
- **QG4**: Widths, byte extents, raw-clock arithmetic, case counts and complexity are reproducible.
- **QG5**: Auxiliary/context class, primary/base/score/summary, preindexed field identity, singleton ordering and source/native boundaries remain distinct.
- **QG6**: Original collection bytes, scalar certificates, independent instruction interpretation and exact publication checks supply provenance.
- **QG7**: Remaining work is bounded and impact-ranked; native scheduling, concurrent ownership and matched daemon completion remain unknown.

Evidence: [source and certificates](triage_evidence/aes_uncached_context_queue_checks.json.zst), [generator](triage_evidence/recover_aes_uncached_context_queue.py), [independent interpreter](triage_evidence/audit_aes_uncached_context_queue.py), [publication audit](triage_evidence/verify_aes_uncached_context_queue_publication.py).

## Context score policy and scheduler attribution increment

The [context-score policy report](aes_context_score_policy_report.md) recovers nonzero-category aging, accounting normalization, timestamped offset caching, the wake-to-accounting field join and configuration/table conversion. Thirty-two new UNSAT checks, four abstract SAT controls and 3681 private cases pass, including policy-enabled first/second placement, controlled pair mismatches and original configuration/converter execution. A pinned Apple source comparison supports qualified Clutch-scheduler names and refines the earlier policy-byte label to a candidate group category. Exact compiled revision, actual option admission, native concurrency/scheduling and matched daemon/provider completion remain unknown (SP1-SP8).
