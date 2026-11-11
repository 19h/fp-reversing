# Context score policy, wake accounting and scheduler attribution

The previously recovered context-score helper now has a source-backed nonzero-category path: elapsed-period aging, accounting normalization, a piecewise offset and a timestamped cache feed the generic queue score. Original wake accounting writes one of those same inputs. A recovered configuration routine supplies the offset parameter, timing tables and shared accounting threshold. The binary's configuration string and a qualified comparison with Apple's pinned source support Clutch-scheduler naming for this deeper dependency; exact compiled symbol identities and matched daemon/provider completion remain unknown. No new Mach endpoint, port-right transfer or message emission is established. [SP1-SP8]

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SP1 | All binary claims refer to the pinned original collection, compiler bounds and preferred addresses. | Rehash the collection and compare retained bytes, instructions, bounds, literals and predecessor overlaps. |
| SP2 | Context, group record, thread, heap root, parent, input tables and stack retain their declared identities and extents. | Establish native allocations, aliases, type relationships, reuse and intervening writers. Guarded private records do not prove arbitrary pointer safety. |
| SP3 | Proofs use explicit bit widths; finite standalone inputs include arithmetic extremes and combinations whose native admission is unknown. Queue compositions keep category/class/index coherent and resulting scores within the initialized 96 heads. | Recover actual category, active-count, priority and offset producers and range checks. A mathematical counterexample is not a reachable native condition. |
| SP4 | Timestamp arguments and global/table observations are stable scalars for each declared phase. F is a declared u32 conversion scalar, not a measured native clock calibration. | Observe actual clocks, CPU migration, startup order, configuration changes and source/native time correspondence. |
| SP5 | PAC is logical identity; CASP is one scalar full-pair comparison; injected pair writers are private inputs. Trace is disabled. | Observe real authentication, memory ordering, concurrent updates and debug callbacks. No retry liveness or finite native retry bound is proved. |
| SP6 | Configuration cases model the option-reader result/output and a returning timeshare initializer, then execute the original converter. Placement cases retain matched generation/owner observations. | Execute the actual parser, initializer and nonzero generation refresh; determine admissible option values and invocation order. |
| SP7 | Apple's pinned source is a semantic comparison, not an exact-build identification. Candidate routine/field names depend on that correspondence. | Match compiled revision, configuration, layouts, callers and differing branches; reject names where those comparisons disagree. Exact entry symbols are absent. |
| SP8 | Byte recovery, scalar certificates and private instruction interpretation are distinct from native execution. | Correlate a daemon operation with provider/event/thread identity, accounting, queue placement, dispatch and response. The cross-layer goal remains active. |

## Original source and naming comparison

Kernel collection SHA-256: `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Six complete bodies retain 1129 instructions / 4516 B. No new IDA access, IDB mutation or native execution is used. [SP1,SP8]

| Recovered role | Preferred entry | Instructions | Selected coverage |
| --- | --- | --- | --- |
| Context score | `0xfffffe000bd1ec40` | 141 | All 129 instructions outside the disabled trace block visited across private cases |
| Scheduler-count/wake increment | `0xfffffe000bd22370` | 53 | Unbound, initially zero run-count path; positive/equal/future stopped epoch |
| Placement backend | `0xfffffe000bd207c4` | 647 | First and second thread in one context, category 1..5 |
| Existing-context rekey | `0xfffffe000bd1ea3c` | 129 | Policy-enabled score change and source queue update |
| Configuration | `0xfffffe000bd24c94` | 46 | Complete selected flow with declared external returns |
| Six-entry time-table converter | `0xfffffe000bd21468` | 113 | Original full body and sentinel branches |

The original NUL-terminated string at `0xfffffe000704ec40` is `sched_clutch_bucket_group_interactive_pri`. Its caller passes the parameter's address and size 1, supplies fallback 8, initializes four tables and sets a shared threshold. Apple's [pinned implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/sched_clutch.c) has matching formulas, configuration and table contents. This supports the following inferred correspondences, not symbol recovery or exact revision identity. [SP1,SP7]

| Binary entry / region | Candidate source correspondence |
| --- | --- |
| `0xfffffe000bd1ec40` | `sched_clutch_bucket_pri_calculate`, including inlined aging/accounting/cache work |
| `0xfffffe000bd1ea3c` | `sched_clutch_bucket_update` |
| `0xfffffe000bd207c4` | `sched_clutch_processor_enqueue`, containing the thread-insertion machinery |
| `0xfffffe000bd24c94` | `sched_clutch_init` |
| `0xfffffe000bd21468` | `sched_clutch_us_to_abstime` |

The placement entry first reads incoming X0+0x20, stores that incoming pointer at thread+0x20 and selects its +0x2a0 compact queue on the bound route. Its candidate name therefore describes the processor-enqueue wrapper rather than an isolated inner thread-insert function. [SP1,SP7]

That comparison suggests CPU-used and CPU-blocked meanings for the accounting pair, and a group category for the byte previously called a policy byte. The earlier category-zero cases remain valid private executions; they do not establish a global policy-disable switch. Public-source SHA-256: `0a4c7c24704ebc0dc1f3e950103b3896a4a6308ccee31d2783818f53e6b405c0`, 241161 B. The public counterpart does not establish this binary's caller admission, synchronization or scheduling outcome. [SP7,SP8]

## Input and paired-field interfaces

Let X be the 200 B context and A=u64[X] its 112 B group record. The helper takes X0=X and X1=timestamp N. Empty u16[X+0xc2] returns zero. Otherwise b is u8[u64[X+0x10]+0x11] when that secondary heap root is nonnull, or zero for a null root. The returned score is a byte sum; this helper does not store X+0xc1. Its placement/rekey caller performs that publication. [SP1-SP3]

| Address | Width | Binary role |
| --- | --- | --- |
| A+0 | u8 | Category p; zero bypasses aging/accounting and returns b+u8[A+0x40] modulo 256 |
| A+0x20 / +0x28 | Two u64 | Run-count/stopped-epoch pair used by the preceding wake helpers |
| A+0x30 / +0x38 | Two u64 | Pending count C / pending epoch E, used by placement and aging |
| A+0x40 / +0x48 | Two u64 | Cached offset I / cached timestamp S |
| A+0x50 / +0x58 | Two u64 | Accounting inputs U / V; qualified used/blocked interpretation above |
| `0xfffffe000cb62930`+4*p | u32 | Active-context/load observation, sign-extended for period arithmetic |
| `0xfffffe000cb62900`+8*p | u64 | Period base Bp |
| `0xfffffe000cb62870`+8*p | u64 | Period scale Qp |
| `0xfffffe000cb62868` | u64 | Shared accounting threshold L and wake-time addition cap |
| `0xfffffe000ca9068c` | u8 | Offset/divisor parameter d |

The prior [uncached-context report](aes_uncached_context_queue_report.md) distinguishes auxiliary class/index, context class and record category by their actual fields. The new placement compositions choose matching category/class/index 1..5; standalone arithmetic cases do not impose native type invariants. No index bounds check is established inside this helper. [SP2,SP3]

## Recovered arithmetic and retry phases

All unqualified arithmetic below is unsigned modulo 2^64. The active-count load is u32 then sign-extended to 64 bits. Define div0(a,z)=floor(a/z) for z!=0, and 0 for z=0, matching the declared A64 UDIV interpretation. This zero case differs from Z3's unqualified bit-vector division-by-zero value. [SP1,SP3,SP5]

```text
context nonempty -> category p
       |
       +-- p=0 -> cached offset byte -----------------------+
       |                                                    |
       +-- p!=0 -> pending epoch CASP/retry                  |
                       |                                    |
                       v                                    |
                 accounting CASP/retry                      |
                       |                                    |
                       v                                    |
                 offset ratio -> cache CASP/retry -----------+
                                                            |
                                                   return (b+I) mod 256
                                                            |
                                                 caller publishes/rekeys
```

For nonzero p, a nonzero active count permits pending aging. The source computes period P=Bp+Qp*sign_extend(active_count). If N<=E or N-E<P, it retains k=0. Otherwise k=div0(N-E,P) AND 255 and attempts CASP (C,E)->(C,E+k*P). Both observed lanes feed the retry comparison. The count is preserved by this aging update; placement can have incremented it before the call. A changed observed epoch can make the next iteration give up. The low8 quotient is used in the epoch advance itself: an abstract 256 periods at P=1 can advance the epoch by zero. No native reachability or defect follows. [SP1,SP3-SP5]

Accounting updates are skipped only when k=0 and (U+V) modulo 2^64 is below L. Otherwise, if that modular sum is at least L, u=floor(U/10) and v=floor(V/10); if below L, u=U and v=V. The actual UMULH/shift reciprocal is `0xcccccccccccccccd`, and an integer quotient/remainder certificate proves the divide-by-ten identity for the full u64 domain. [SP1,SP3]

| Accounting condition | Desired U value; desired V is v |
| --- | --- |
| v>=u | max(0, u-div0((v*k) mod 2^64,d)), with unsigned saturating subtraction |
| v<u | div0(((v*d mod 2^64)*u) mod 2^64, (u*k+v*d) mod 2^64) |

CASP compares the original U,V pair, not the normalized intermediate values. A mismatch supplies both new observations and repeats normalization/adjustment. The threshold and divisor are loaded before this loop; the period quotient k is retained. Products and denominator sums retain machine-width wrap, including a possible zero denominator in the abstract domain. [SP1,SP3-SP5]

After accounting, the source reloads U,V and calculates candidate J. [SP1,SP3]

| Reloaded accounting condition | Candidate J before the low8 mask |
| --- | --- |
| U=V=0 | u8[A+0x40] |
| V>U | d+div0(((V-U)*d) mod 2^64,V) |
| V<=U and at least one nonzero | div0((V*d) mod 2^64,U) |

The cache phase loads the full pair I,S. If S>=N it uses the observed cached I, even if J differs. If S<N, the desired offset is I when S=0 and J otherwise; desired timestamp is N. Consequently the first zero-timestamp publication preserves the initial offset, then later timestamps can replace it. A cache mismatch reuses the already computed J while observing new I,S; a new S>=N bypasses further CASP. The final return is (b+I) modulo 256. [SP1,SP3-SP5]

## Wake accounting joins the same V field

For an unbound thread T, the wake increment selects A=u64[T+0x298]+0x60+112*u8[T+0x204]. Starting from run count zero and a stopped epoch H different from all ones, it changes the A+0x20/+0x28 pair to count 1 / epoch all ones. If raw-now>H, it adds min(raw-now-H,L) to A+0x58 with LDADD. This is the V input subsequently read by the score helper; the same global L also controls its normalization gate. The pairing is source-derived, while actual thread/group identity and scheduling epochs remain native premises. [SP1,SP2,SP4,SP5]

Eighteen private sequences execute the original increment at raw-now=107 and the original score at timestamp 207. They vary stopped epoch 50/107/200, cap 0/37/1000 and divisor 0/8. Thus the source connection is checked across positive, equal and future stopped epochs, including a zero addition. This establishes a serialized data-flow interface, not execution-time calibration or a concurrent wake/dispatch trace. [SP4,SP5,SP8]

## Configuration and environmental control

At `0xfffffe000bd24cc4`, the configuration body calls the option reader with the recovered string, output pointer `0xfffffe000ca9068c`, length 1 and flag 0. Its context argument is u64[`0xfffffe0007f8b6e8`]+0x6c. A zero result stores fallback 8; a nonzero result retains the output byte. Actual parser admission, boot context and privilege surface remain unknown from these modeled returns. The string and qualified public comparison establish a configuration touch point, not an externally callable daemon API. [SP1,SP6,SP7]

| Converter source / destination | Six source u32 values, by index 0..5 |
| --- | --- |
| `0xfffffe000ca90690` -> `0xfffffe000cb628d0` | all-ones, 0, 37500, 75000, 150000, 250000 |
| `0xfffffe000ca906a8` -> `0xfffffe000cb628a0` | all-ones, 8000, 4000, 2000, 1000, 0 |
| `0xfffffe000ca906c0` -> `0xfffffe000cb62870` | 10000, 10000, 10000, 10000, 4000, 2000 |
| `0xfffffe000ca906d8` -> `0xfffffe000cb62900` | all-ones, 10000, 37500, 75000, 150000, 250000 |

The converter emits six u64 values and maps input 0xffffffff to output 0xffffffffffffffff. For the retained tables and each tested frequency scalar F, other outputs equal floor(input*F/1000000). Its complete original body executes in 30 configuration cases with F=0/1/24000000/1000000000/4294967295, option results zero/nonzero and supplied output byte 0/8/255. Threshold L becomes floor(F/2) at `0xfffffe000bd24d2c`. These are private numeric conversions; a native tick-to-SI-time calibration is not established. [SP1,SP4,SP6]

The collection file contains parameter byte 8, zero output tables, zero active counters and frequency scalar zero. Those file observations do not imply a configured native system has zero timing values. Startup and later writers are not closed. The direct configuration body and its call sites were recovered after a bounded immediate-store locator; no complete alias/indirect-write census is claimed. [SP1,SP4,SP6]

## Verification

Thirty-two new UNSAT certificates cover 29 source cuts / 102 lifted instruction instances. Four abstract SAT controls retain low8 period advance, division-by-zero interpretation, modular-sum gating and cached-offset reuse. The publication audit also rechecks the preceding 25 uncached-context and 34 block/wake UNSAT certificates. [SP1-SP8]

| Independent private interpretation | Cases |
| --- | --- |
| Full trace-off score paths and guarded record/root canvases | 3520 |
| Empty-context returns | 4 |
| Quotient boundaries, zero periods and large timestamp differences | 40 |
| Controlled low/high pair mismatches and retry give-up | 9 |
| Original wake increment followed by score calculation | 18 |
| Original constructor, first placement, second placement and tail rekey with category 1..5 | 60 |
| Original configuration and four original converter invocations | 30 |

All 3681 cases pass with 368889 interpreted source-instruction visits and 4245 recorded scalar pair observations. The score matrix independently varies categories 0/1/2/5, active counts 0/1/2/0x80000000/0xffffffff, divisor 0/1/8/255, eleven accounting pairs and four cache timestamps. Priority, period parameters, threshold and epoch use declared dependent assignments, not a full Cartesian sweep of every input. Controlled scripts produce eleven mismatches across all three original CASPs, including a future/current timestamp that gives up retry. Every one of the 129 trace-off score instructions is visited across the cases; the twelve trace-block instructions at `0xfffffe000bd1ee44`..`0xfffffe000bd1ee70` remain unexecuted. Instruction visitation is finite coverage, not universal equivalence. [SP2-SP6]

Queue compositions compare complete guarded parent, auxiliary object, context and two-thread canvases through the original first/second insertion, score and rekey. They retain one context per class and matched generation values; multi-context ordering and generation refresh remain separate. Configuration cases compare the complete contiguous output-table/threshold region, preserved input tables, parameter result, restored SP/saved registers and exact converter call arguments. External option-reader/timeshare bodies are modeled ABI boundaries. [SP2,SP5,SP6]

```sh
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/recover_aes_context_score_policy.py --verify
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=triage_evidence \
  "$PYTHON" -P triage_evidence/audit_aes_context_score_policy.py
env Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" \
  "$PYTHON" -P triage_evidence/verify_aes_context_score_policy_publication.py
```

Recovery costs O(B+I+P) time/space for source bytes B, instructions I and certificate size P, excluding solver cost. Interpretation costs O(cases*(visits+canvas bytes)) time and O(code+private bytes+bounded observations) space. The public source is pinned and hash-checked separately; its availability is an external reproduction prerequisite. [SP1,SP7]

## Bounded continuation

| Impact | Next evidence | Question resolved |
| --- | --- | --- |
| High | Matched daemon/provider/event/thread/group/queue/dispatch observations | Concrete cross-layer completion |
| High | Exact compiled XNU revision, configuration and native type/category invariants | Strengthen or falsify scheduler names and real score domains |
| High | Real boot-option parser, configuration invocation and clock initialization | Native parameter admission and SI time correspondence |
| Medium | CPU-used producer, group/category initialization and accounting readers | Complete U/V provenance and interpretation |
| Medium | Concurrent pair writers, multi-context queues and generation updates | Ordering, retry behavior and scheduling epochs |
| Low | Enabled debug trace and native symbol metadata | Optional observability and exact naming |

## Quality gates

- **QG1**: Factual source and interface analysis requires no normative conclusion.
- **QG2**: SP1-SP8 state assumptions, dependent results and falsification probes.
- **QG3**: This increment covers nonzero-category score policy, wake data flow, configuration and qualified scheduler attribution; the broad goal remains active.
- **QG4**: Widths, modular operations, zero division, raw times, numeric conversion, counts and complexity are explicit.
- **QG5**: Low8 quotient advance, zero-stamp cache retention, adjacent output-table guards, file/runtime values and qualified names remain distinct.
- **QG6**: Original bytes and literals, scalar proofs, independent instruction cases, pinned primary-source comparison and exact publication checks supply provenance.
- **QG7**: Continuation is bounded and impact-ranked; native concurrency, scheduling and daemon/provider completion remain unknown.

Evidence: [source and certificates](triage_evidence/aes_context_score_policy_checks.json.zst), [generator](triage_evidence/recover_aes_context_score_policy.py), [independent interpreter](triage_evidence/audit_aes_context_score_policy.py), [publication audit](triage_evidence/verify_aes_context_score_policy_publication.py).
