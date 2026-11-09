# Original auxiliary-record emitters and conditional caller pipelines

Nine original source fragments emit the private record consumed through adapter `0x100ABCA64` and entry `0x100A59BB4` under explicit bank-root and incoming-phase premises. They cover all four singleton auxiliaries from the [dispatcher report](daemon_output_base_report.md) and the interval's lower endpoint, `0x38ACBB2A`. Thirty-six declared contexts continuously execute original producer -> adapter -> entry -> selected record save, with no fixture PC transitions. Native producers of the required bank roots and saved phase words remain unknown. This is a conditional source call map, not evidence of nine native invocations or external control. [AC1-AC12]

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [36 original-instruction profiles and specifications](triage_evidence/daemon_aux_callers_profiles.json), [literal census, contracts, roots and raw readback](triage_evidence/daemon_aux_callers_contracts.json), [29 source obligations](triage_evidence/daemon_aux_callers_proofs.json), [fresh replay and checks](triage_evidence/daemon_aux_callers_checks.json), [preservation](triage_evidence/daemon_aux_callers_delivery.json), [scoped gates](triage_evidence/daemon_aux_callers_quality_gates.json).

## Emitters, input provenance and call locations

F denotes SP at the particular producer cutpoint; FP denotes its incoming X29. The same symbols do not assert a shared frame epoch between rows. All offsets in the following tables are hexadecimal bytes. Each auxiliary store writes u32 at P+0x14, where P is the emitted record base.

| Producer start | Auxiliary store PC | Call PC | Decoded auxiliary | Record P | Input pointer loaded from |
| --- | --- | --- | --- | --- | --- |
| `0x1002BE620` | `0x1002BE66C` | `0x1002BE6D8` | 0xBAD70E19 | FP-0x100 | u64 F+0x2330 |
| `0x10039C894` | `0x10039C8C4` | `0x10039C92C` | 0x2BE18A5D | FP-0x100 | u64 F+0x2328 |
| `0x1004F6738` | `0x1004F67A4` | `0x1004F682C` | 0x2BE18A5D | F+0x10CB8 | u64 F+0xAAC8 |
| `0x1005C82F4` | `0x1005C8358` | `0x1005C83DC` | 0xD79BC5DE | F+0x10CB8 | u64 F+0xA8F0 |
| `0x1005DEDFC` | `0x1005DEE6C` | `0x1005DEEF0` | 0x38ACBB2A | F+0x10CB8 | u64 F+0xA8B8 |
| `0x100654BF8` | `0x100654C70` | `0x100654CC8` | 0x2BE18A5D | FP-0xA8 | u64 F+0x30 |
| `0x1007FA8D0` | `0x1007FA940` | `0x1007FA9C4` | 0xBAD70E19 | F+0x10CB8 | u64 F+0xA980 |
| `0x100857AE4` | `0x100857B6C` | `0x100857BFC` | 0xEEDD0B20 | F+0x10CB8 | u64 F+0xA910 |
| `0x100933248` | `0x1009332AC` | `0x100933310` | 0xBAD70E19 | FP-0xA8 | u64 F+0x38 |

The source passes P in X0 and a separate cursor cell in X1. The full input-pointer word survives in P+8. Its allocation, contents and native owner are unknown. No input-byte dereference occurs before the selected save boundary in these profiles. The source itself supplies the auxiliary constants; a native caller producing an arbitrary value in the broad interval is not established. [AC2,AC3,AC10]

| Call PC | X1 cursor-cell address | Decoded mode equation |
| --- | --- | --- |
| 0x1002BE6D8 | F+0x2488 | Literal 0x471C |
| 0x10039C92C | F+0x2480 | Literal 0x471C |
| 0x1004F682C | F+0xBB90 | M |
| 0x1005C83DC | F+0xBBA0 | M |
| 0x1005DEEF0 | F+0xBB98 | M |
| 0x100654CC8 | FP-0xC0 | N |
| 0x1007FA9C4 | F+0xBB88 | M |
| 0x100857BFC | F+0xBBA8 | M |
| 0x100933310 | FP-0xB8 | N |

```text
M = u32(MEM64[F+0x9D0]) - 0x25D8       modulo 2^32
N = MEM32[F+0x6C] - 0x4395             modulo 2^32

M == 0x471C  iff low32(MEM64[F+0x9D0]) == 0x6CF4
N == 0x471C  iff MEM32[F+0x6C] == 0x8AB1
```

These equivalences cover every u64/u32 saved word respectively. Upper 32 bits of the F+0x9D0 word do not affect the emitted mode; tests vary them through zero, 0xF1E2D3C4, 0x80000000 and 0xFFFFFFFF. Their possible use elsewhere in the caller is outside this record equation. Actual saved-word writers and synchronization remain unknown. [AC3,AC4]

## Record equations, untouched fields and alignment

All nine constructors implement the same address-derived representation in the declared aligned frame domain:

```text
K(P)              = u32((low32(P) XOR 0xDC40790B) * 0x5973A279)
record.u32[0]     = decoded_mode XOR K(P)
record.u64[8]     = input_pointer
record.u32[20]    = decoded_auxiliary + K(P)       modulo 2^32
```

Each full producer proof covers arbitrary input-pointer bits and arbitrary saved phase, using valid fixed record/input cells. It also proves that record bytes +4..+7 and +16..+19 are unchanged by the constructor. The latter is the result field: these callers do not initialize it before the internal call. The callee's later result publication is a distinct epoch, outside the new stopping point. The accessed record extent remains 24 bytes. [AC2,AC3,AC5]

The opaque Boolean/arithmetic key forms differ between emitters. Their common key identity is proved for arbitrary 64-bit SP/FP bases satisfying base&15=0. FP-0x100 records are then 16-byte aligned; FP-0xA8 and F+0x10CB8 records have residue 8 modulo 16 and are 8-byte aligned. Valid nonwrapping ownership of accessed cells is a separate premise.

An unconstrained proof for `0x1002BE628..0x1002BE65C` failed at FP=`0x6800064001`, P=`0x6800063F01`. Its [rejected query](triage_evidence/daemon_aux_callers_rejected_unaligned_key.smt2) remains SAT. A further source theorem establishes exactly `caller_key==K(P) iff P is even` for this fragment. The declared aligned frames satisfy that condition. This is an algebraic domain boundary; no misaligned native invocation or defect is established. Other key fragments are only claimed over the stated aligned-base domain. [AC5]

## Conditional bank roots and authenticated slots

Each call computes a byte-dependent bank expression. With Q:u8, source arrays L/R and immediate k:

`C = Q XOR R[L[Q] XOR k]`.

All eight distinct rules below collapse to one C for every Q. The source then uses table index additive+C and slot `TABLE+8*index`, with TABLE=`0x101039EF0`. These premises select index 0xCD2E, original slot `0x1010A0860`, target `0x100ABCA64`, IA diversity 0xCA54 and address diversity zero. [AC6,AC7]

| Calls / labels | L | R | k | Additive | C |
| --- | --- | --- | --- | --- | --- |
| 2BE | 0x100FC4130 | 0x101031EA0 | BB | CC73 | BB |
| 39C | 0x100E99A00 | 0x100F4E390 | 78 | CC8D | A1 |
| 4F6, 5C8 | 0x100FC4130 | 0x101031EA0 | 4E | CC2F | FF |
| 5DE | 0x100E99700 | 0x100F4E190 | 81 | CCE6 | 48 |
| 654 | 0x100E99800 | 0x100F4E290 | 61 | CD15 | 19 |
| 7FA | 0x100FC4130 | 0x101031EA0 | A3 | CCBC | 72 |
| 857 | 0x101031DA0 | 0x100E99900 | 86 | CCD6 | 58 |
| 933 | 0x100E99A00 | 0x100F4E390 | 54 | CC78 | B6 |

The root values are declared compatibility premises. Their exact register/frame consumers are retained in the specifications: for example, 857 reads L/R through F+0x5F0/F+0x5E0, whereas 4F6/5C8/7FA use F+0x968/F+0x960. Native frame writers and epoch continuity are unproved. A bounded 13-array compatibility census also admits the reversed L/R orientation for 2BE; its byte identity alone cannot choose the native orientation. The other rows have one matching ordered pair within that pool, which does not establish uniqueness outside it. [AC6,AC8]

The adapter's internal call at `0x100ABCC98` uses original slot `0x1010A0FC0`, target `0x100A59BB4`, IA diversity 0x1803. The original stack-probe call at `0x100A59BE4` runs the frozen 108-byte helper snapshot through its established special ABI. Source prologues and authenticated transfers are handled logically in private execution; hardware authentication and native loader binding remain unobserved. [AC7,AC9]

## Continuous record handoff and retained boundaries

```text
original producer, declared caller frame / bank roots / phase
  -> write mode, input pointer, auxiliary into P
  -> BLRAA at one of nine source call sites
  -> adapter 0x100ABCA64, same P in X0
  -> BLRAA 0x100ABCC98 -> entry 0x100A59BB4
  -> original stack probe and record decoder
  -> selected auxiliary branch
  -> STR X0,[SP,#0x24F8], where X0 == original P
  -> STOP immediately after that source store
```

| Auxiliary emitted by these callers | Record-save island reached |
| --- | --- |
| 0xD79BC5DE | 0x100B74138 |
| 0xBAD70E19 | 0x10064CEA8 |
| 0x2BE18A5D | 0x10097C778 |
| 0x38ACBB2A | 0x100B2CF64, interval route at its lower endpoint |
| 0xEEDD0B20 | 0x100A2E3A0 |

All 36 profiles preserve P across both internal calls and store it at the actual callee F+0x24F8. The whole caller/adapter/callee path executes from its selected producer start in one CPU state; no fixture PC changes connect the components. This extends the preceding isolated dispatcher and its earlier 39C caller evidence to eight further original emitter fragments under their explicit premises. It does not establish their native predecessors or return behavior after the save. [AC2,AC9,AC10]

The earlier RPC502 cleanup also uses an address expression SP+0x10CB8 with a different record contract. That shared expression does not identify this 24-byte epoch with its cleanup fields. Likewise, the separate 720-byte cleanup checkpoint still lacks the producer of its saved F+0x24F8 word; these new source paths do not supply that unknown word. Registry publication, Mach/IOKit port ownership and driver joins remain unproved. [AC10-AC12]

## Census and validation limits

A raw aligned scan finds 12 adjacent `MOVZ Wn,low16; MOVK Wn,high16` materializations of the four singleton constants and interval lower endpoint. Nine feed the described auxiliary stores; three are comparator constants in the callee. Computed values, other materialization sequences and regions outside original text are excluded.

The exact `MOV X17,#0xCA54; BLRAA X8,X17` census contains 16 sites. Nine are the current conditional caller components. Seven remain unclassified: `0x10030ACB0`, `0x100480CC4`, `0x100524870`, `0x1006AC3E0`, `0x100821C44`, `0x100A8FF30`, `0x100D9AE44`. Other call-register/modifier forms are outside this census. [AC8]

| Original slot sharing diversity 0xCA54 | Target |
| --- | --- |
| 0x1010A0670 | CoreFoundation `_CFBooleanGetTypeID` |
| 0x1010A0860 | 0x100ABCA64 |
| 0x1010A0880 | 0x100461120 |
| 0x1010A0960 | 0x100412CD8 |

These original collisions preclude using the modifier alone as a target identity. The new source bank equations, original slot and actual private execution target are checked together. No full caller-graph completeness or semantic ownership is inferred from a compiler address interval. [AC7,AC8]

Twenty-nine source obligations produce 58 original/simplified UNSAT files: nine aligned key identities, the exact even-address condition for 2BE, nine full record equations with untouched-word checks, two phase predicates and eight full-u8 bank/slot identities. The bank lookups are encoded as balanced byte multiplexers over original 256-byte arrays; each rule is also exhaustively checked over 256 concrete byte inputs, totaling 2,048 inputs. The rejected unconstrained-key query remains separate SAT evidence.

Thirty-six primary private CPU profiles span four contexts per emitter. Fresh replay uses another initialized CPU state with different unused backing and audits every recorded read/write and final boundary. It checks 16,654 source visits: 14,980 daemon instructions and 1,674 instructions from the frozen stack-probe helper. There are 2,930 checked reads, 1,404 writes, 300 logical control edges and 72 logical PAC operations. Record construction, same-record entry and actual source-written save each receive 36 checks. The two CPU passes share the Unicorn ISA engine; source equations and exhaustive original-byte identities provide separate semantic checks. Neither pass executes a native target or host API. Six read-only IDA ranges corroborate 1,536 original bytes. [AC1-AC9]

Reproduce with the pinned interpreter/Z3 environment used in the preceding report:

```sh
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_aux_callers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_aux_callers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_aux_callers.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_aux_callers.py
```

IDA JSON and the rejected hypothesis are retained captures. Time is O(text words + cases*source visits + byte tables + solver resources); space is O(one CPU map, retained journal/census and BV DAGs). The source-visit limit is 20,000 per probe; every reported case reaches its stated boundary before the limit. Extents/offsets are bytes; machine quantities use little-endian u32/u64 and modular arithmetic where stated. Private addresses are fixtures.

## Assumption register

| ID | Premise or bounded assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- | --- |
| AC1 | Pinned daemon, original fixups and frozen helper snapshot identify the consumed source | All PCs, code and import/dispatch identities | Rehash image/dependencies; verify every retired daemon opcode and six raw IDA ranges |
| AC2 | Valid declared caller frames, record/cursor cells and pointer-source cells apply at producer cutpoints | Full record emission and private paths | Prove arbitrary payload/phase values at fixed cells; vary placements, counters and unused backing |
| AC3 | Source mode is literal471C or follows the specified saved-phase equation | Matching record decode and branch | Prove both all-word equations and exact471C predicates; actual writers remain unknown |
| AC4 | High saved-phase bits are independent inputs for the SP+9D0 family | Low32-only mode contract | Vary four upper32 patterns; do not infer their uses outside the producer span |
| AC5 | Key identities are used over16-byte-aligned SP/FP bases | Common caller/callee key | Retain odd-address SAT query; prove2BE equality iff even and nine aligned-domain identities |
| AC6 | Root pairs are explicit compatibility premises; controller words are stable during private single-thread execution | Conditional adapter target | Prove all256 byte inputs per rule; audit consumed root cells; establish native writers/epochs before promotion |
| AC7 | Original slots/modifiers plus source target arithmetic authorize logical edges | Two internal call entries and stack probe | Decode original fields; retain four CA54 collisions; hardware PAC/native loader remain unobserved |
| AC8 | Literal/pool censuses are bounded subsets | Nine emitters, seven unclassified calls and candidate root uniqueness | Expand computed encodings/register forms and bank pool; do not equate literal coverage with full graph coverage |
| AC9 | Frozen helper ABI and modeled private environment apply | Continuous CPU prefixes | Execute original helper snapshot, compare preservation and all effects; disclose shared CPU engine |
| AC10 | Input ownership and later record/caller epochs remain unknown | Saved input and output-base scope | Follow original allocation and continuous predecessor paths; no payload bytes are read in the new interval |
| AC11 | Native alternative callers, initialization and synchronization are unproved | External control and occurrence | Recover actual saved-phase/root writers and caller reachability |
| AC12 | No new port or daemon/kext transaction is established | Architectural transport scope | Require original transport calls, rights/dispositions and message/record continuity |

## Bounded continuation targets

| Impact | Evidence target | Uncertainty resolved |
| --- | --- | --- |
| High | Establish writers of F+9D0/F+6C and each bank-root field in matching epochs | Actual mode, target and native source callers |
| High | Trace each input-pointer source cell to allocation or borrowed owner | Input formats, extents and lifetime |
| High | Continue from these established record saves toward the 720-byte allocation path | Missing output-base epoch join |
| Medium | Classify the seven remaining literalCA54 calls and computed call variants | Broader caller graph and target collisions |
| Medium | Follow completed record consumers into original transport adapters | Mach/IOKit ownership and daemon/kext/deeper linkage |

- QG1: Pass for factual technical analysis.
- QG2: Pass; AC1-AC12 give premises, dependencies and falsification probes.
- QG3: Pass for this increment; the broad interface objective remains active and incomplete.
- QG4: Pass; widths, byte offsets, alignment domains, modular arithmetic and complexity are explicit.
- QG5: Pass within scope; rejected unaligned algebra is corrected, and conditional roots, actual source stores, shared CPU engine and native gaps are distinguished.
- QG6: Pass; original code/fixups/banks, captured journals, raw IDA bytes, source identities and fresh CPU replay provide provenance.
- QG7: Pass; remaining callers, owners and transport joins are impact-labeled.
