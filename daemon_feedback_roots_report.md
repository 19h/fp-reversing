# Feedback store roots and controller-cell equations

The destination of the feedback store at `0x100b21374` is `0x1010b7cc0` for every u32 selector input under the original image/table premises. It is the same cell addressed by the initializer's SP+0x2b0 pointer. The two preceding controller destinations are `0x1010b6590` and `0x1010c4670`. This resolves the source-level destination gap in the [constructor-descriptor report](daemon_constructor_descriptor_report.md); the initializer-to-current-caller epoch remains unknown. [FR1-FR4; FR-A1-FR-A3]

Three original instruction spans cover 256 low-byte partitions each, retaining 24 symbolic upper bits per partition. The resulting 768 cases cover the full u32 domain of each selector; they are arithmetic lifts, not new guest execution intervals. They retain 13,568 selector instruction instances and 3,328 original read instances. Four nonvacuous obligations pass, including a separate universal controller-update equation. [FR1-FR4; FR-A1-FR-A4]

```text
original tables and decoded pool rebases
  selector 1, any u32 -> 1010b6590 -> load A / u64
  selector 2, any u32 -> 1010c4670 -> load B / u64
                          |
                  d = B-A-(FP-28)
                          |
       A' = (d*m) XOR k; B' = (d XOR k)*m
                          |
                   two u64 stores

caller-provided readable cell -> old / u64
                          |
                  payload = old*2ecd+1
                          |
  selector 3, any u32 -> 1010b7cc0 <- payload / u64
                          ^
                          |
  initializer [SP+2b0] ----+

Current initializer/caller epoch and contemporaneous-global equality UNKNOWN.
```

| Evidence | Primary artifact and scope |
| --- | --- |
| FR1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; [extractor](triage_evidence/recover_daemon_feedback_roots.py) retains the complete feedback phase, four 256 B tables and seven original pool rebases. |
| FR2 | [Constructor-descriptor checks](triage_evidence/daemon_constructor_descriptor_checks.json.zst), logical SHA-256 `9d044ed5285d1fb392fb01eb10e016b19d8ba312435793760e28376c9bc50d3f`, establish the initializer root, caller copy shape and feedback payload equation. |
| FR3 | [Feedback-root checks](triage_evidence/daemon_feedback_roots_checks.json.zst): complete partitions, original per-load evidence, root identities, controller equations and retained SMT queries. |
| FR4 | [Publication verifier](triage_evidence/verify_daemon_feedback_roots_publication.py): fresh source/table/fixup/partition reconstruction, query comparison, exact manifest delta, preserved inputs and decoded path checks. |

## Exact root mappings

| Role | Original source span / pool load | Pool slot | Decoded target plus u64 bias | Effective cell / actual use |
| --- | --- | --- | --- | --- |
| Controller A | `0x100b21238..0x100b21278`; load `0x100b21270` | `0x1010aa0c8` | `0x104ad7793 + 0xfffffffffc5dedfd` | `0x1010b6590`; u64 read `0x100b2127c`, u64 store `0x100b21300` |
| Controller B | `0x100b2128c..0x100b212cc`; load `0x100b212c4` | `0x1010a1e00` | `0x1146e2efe + 0xffffffffec9e1772` | `0x1010c4670`; u64 read `0x100b212d0`, u64 store `0x100b21304` |
| Feedback destination | `0x100b2132c..0x100b21374`; load `0x100b21368` | `0x1010a3eb0` | `0x17b4b9402 + 0xffffffff85bfe8be` | `0x1010b7cc0`; u64 store `0x100b21374` |

All additions wrap modulo 2^64. Original on-disk pool words are chained rebases; the decoded targets above are independently checked against their pointer-format-12 fields. Seven verified slots comprise these three roots and four table-address loads. The first selector supplies W13=`0xbb`; the second selector uses that same value. Its intervening original instructions preserve W13. [FR1-FR4; FR-A1-FR-A3]

| Table-pair role | Left table / 256 B | Right table / 256 B | Inner XOR byte | Final low-byte selector |
| --- | --- | --- | --- | --- |
| Controller A | `0x100fc4130` | `0x101031ea0` | `0xbb` | `0xbb`, then add `0x1032` |
| Controller B | `0x100fc4130` | `0x101031ea0` | `0xbb` | `0xbb`, then subtract `0x27` |
| Feedback | `0x101031da0` | `0x100e99900` | `0x86` | `0x58`, then add `0x452` |

These constants follow from the original selector instructions and all input partitions. They do not depend on a sampled controller value. The table-address loads also pass through original rebases and sign-preserving biases; each original byte and decoded read is retained. [FR1-FR4; FR-A1-FR-A3]

## Controller and feedback dataflow

Let A and B be the u64 values read at `0x100b2127c` and `0x100b212d0`, and f be X29 at the arithmetic phase. With `m=0x0a5cd4cf` and `k=0x73d046208eaed1a6`, the original instructions `0x100b212d4..0x100b21304` establish:

```text
d  = u64(B - A - (f - 0x28))
A' = u64(d*m) XOR k
B' = u64((d XOR k)*m)
[1010b6590] / u64 = A'  at 100b21300
[1010c4670] / u64 = B'  at 100b21304
```

W11's earlier u32 construction zero-extends m into X11; it is not a sign-extended multiplier. The prologue sets f=`u64(entry_SP-0x10)`, so the subtracted address term f-0x28 is `u64(entry_SP-0x38)`. The source mixes this frame-dependent address into the controller updates. This does not establish a time source, entropy source or security property. [FR1-FR4; FR-A1-FR-A4]

After the two stores, `0x100b21308` loads old through X19, the saved caller X1 pointer. The prior source proof gives payload=`u64(old*0x2ecd+1)`. The newly resolved selector proves that `0x100b21374` writes this payload to `0x1010b7cc0`, independently of the u32 input produced by the intervening controller arithmetic. The same phase still reserves `16*((payload>>60)+1)` B of additional stack, as previously proven. [FR1-FR4; FR-A1-FR-A4]

The source caller loads the SP+0x2b0 pointer, dereferences it at `0x1008a2708`, and copies the value to private SP+0xbdc8 at `0x1008a2710`. This connects the root-cell producer, local copy shape and wrapper destination at the source-interface level. A complete current call/epoch join is still unknown. The precise statement is `global_cell <- u64(caller_supplied_old*0x2ecd+1)`; equality of caller_supplied_old with a contemporaneous global value is not established. [FR1-FR4; FR-A2-FR-A4]

## Verification, assumptions and remaining interfaces

For every selector, the lift seeds an arbitrary u32 as `concat(symbolic_upper24, concrete_lower8)`. It executes the original integer instructions separately for lower8=0..255. Address truncation and arithmetic normalization remove the symbolic upper bits before each table read. A read that remains symbolic, falls outside the four retained tables, or names an unlisted pool slot is rejected. The final effective address is constant in every partition. The third selector additionally preserves the arbitrary symbolic u64 payload through the actual store. [FR1-FR4]

The partitions cover `256*2^24=2^32` inputs per selector. Thus the 768 cases cover three independent full u32 domains; they do not represent 768 native executions. Each root obligation combines all corresponding partition conclusions. Normalization already makes the root conclusions constant; the retained UNSAT queries certify those reduced conclusions. The universal controller equation separately retains symbolic A, B and frame pointer. All four queries first check satisfiable premises and use a 30 s timeout. [FR1-FR4]

The construction costs O(256*selector words + retained source + query DAG) time/storage, excluding solver search complexity and publication input I/O. Four unique tables occupy `4*256 B=1024 B`. Every pointer, offset, table extent and stack reservation is in bytes; integer formulas declare u32/u64 modular widths. No target API, allocation, free, filesystem operation, IPC, hardware PAC or IDB mutation executes. Retained original evidence suffices; IDA is not accessed. [FR1-FR4]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FR-A1: Exact original image, tables and fixup interpretation apply | All effective roots and equations | Verify source SHA, all retained words/table bytes and all seven independently decoded original rebases; reject unlisted reads. |
| FR-A2: The prior source phases retain their published conditional scope | Initializer root identity, private copy and payload equation | Pin the prior receipt; keep initializer/current-caller epoch and contemporaneous-global equality unknown. |
| FR-A3: Full word inputs are partitioned exactly | Input-independent selector destinations | Check all 256 distinct low bytes, preserve 24 symbolic upper bits, reject symbolic read addresses, compare complete reconstructed cases and queries. |
| FR-A4: Sequential integer phase semantics apply | Controller and feedback store values | Preserve explicit u32 zero extension and u64 wraparound; source roots do not establish native atomicity, synchronization, PAC success or concurrent ordering. |

| Impact | Bounded next evidence | Present limit |
| --- | --- | --- |
| High | Join the actual initializer and current caller epoch | The SP+0x2b0 producer and feedback destination match; current continuous custody remains unknown. |
| High | Establish callers and custody of the old-value pointer | A caller-supplied old value is proven; equality with a contemporaneous global value is unknown. |
| High | Recover the controller cells' complete read/write and synchronization interfaces | Three roots and this sequential update phase are established; native scheduling and complete users remain unknown. |
| High | Connect local S/U/F records to actual Mach/IOKit buffers | No new port, transferred right, external emission or daemon-kext transaction pairing is established here. |
| Medium | Complete the descriptor consumer's counter-dependent operation | Counter recovery is known; complete downstream semantics remain unknown. |

**QG1**: factual source/interface analysis. **QG2**: FR-A1-FR-A4 state dependencies and falsification probes. **QG3**: the destination gap and controller arithmetic are covered; the full interface goal remains active. **QG4**: input-domain counts, widths, byte units and complexity are explicit. **QG5**: source root identity, caller-old value and native epoch/concurrency are separate. **QG6**: fresh source/table/fixup/partition/query and publication verification qualify primary evidence. **QG7**: impact-labeled adjacent work and unknown interfaces are explicit.

Follow-up: The [feedback-caller report](daemon_feedback_callers_report.md) establishes both authenticated source call targets and their argument interfaces, checks all 152 retained success records, and proves the caller/helper address-key codec and descriptor-pointer recovery. Three complete u32 selector domains use 768 partitions; seven source obligations include an explicitly recorded key-lemma composition. The record writer assigns 54 B; six observed bytes are inherited and four remain undefined. No new guest bytes or intervals are added; current epoch and native Mach/IOKit pairing remain unknown.
