# Caller-record provenance and the auxiliary dispatcher

Five of the seven literal F+0x24F8 spill candidates are now classified as saves of the original caller record in the declared mode-0x471C component. Four are selected by exact auxiliary values; the fifth is selected by the inclusive interval `0x38ACBB2A..0x7FFFFFFF`. Every other u32 auxiliary value reaches the shared result store with raw result `0x8B3DC651`. This partition is proved over all 2^32 auxiliary values under the retained non-NULL record/table/frame premises. It does not establish a native caller for every route or identify the output base in the separate 720-byte cleanup epoch. [OB1-OB10]

Primary source: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [nine symbolic dispatcher paths](triage_evidence/daemon_output_base_dispatch.json), [five byte-decoding continuations](triage_evidence/daemon_output_base_branches.json), [record origins, original fixups and candidate intervals](triage_evidence/daemon_output_base_contracts.json), [14 source obligations](triage_evidence/daemon_output_base_proofs.json), [independent A64 checks](triage_evidence/daemon_output_base_checks.json), [preservation](triage_evidence/daemon_output_base_delivery.json), [scoped gates](triage_evidence/daemon_output_base_quality_gates.json).

## Recovered private record and source caller

The retained source caller at `0x10039C894` constructs a record at P=`caller_FP-0x100`, then passes P in X0 through adapter `0x100ABCA64` to callee `0x100A59BB4`. This is the existing [mode471C record/cursor interface](daemon_descriptor_producers_report.md), now connected to the spill census and the shared output tail. In the source component:

```text
K(P) = u32((low32(P) XOR 0xDC40790B) * 0x5973A279)
mode = record.u32[0] XOR K(P)
aux  = record.u32[20] - K(P)             # modulo 2^32
```

| Record-relative offset | Width | Established role |
| --- | ---: | --- |
| +0 | 4 bytes | Encoded mode; retained caller selects decoded 0x471C |
| +4..+7 | 4 bytes | No role established |
| +8 | 8 bytes | Input-byte pointer; non-NULL premise for the new dispatcher |
| +16 | 4 bytes | Raw result, written by `0x10095F074` |
| +20 | 4 bytes | Auxiliary word stored as aux+K(P), decoded at `0x1006583D8` |

The maximum observed field endpoint is 24 bytes. This is an accessed-layout contract, not an identified native structure type or wire format. The caller at `0x10039C8C4` writes auxiliary constant `0x2BE18A5D` through its address-derived representation. Its source therefore establishes that particular route; it does not provide external control of arbitrary auxiliary values. The new alternatives are separately declared component inputs at `0x1006583B0`, before this auxiliary read. They do not patch or resume a frozen execution with a different caller-produced value. [OB2,OB3,OB8]

For the 24 retained non-NULL prefixes, X0 has no source write from callee entry through the instruction before `0x10097C778`. The original stack-probe helper's executed instructions are included in that audit. At `0x10097C778`, the source stores P at F+0x24F8. The corresponding incoming branch is `0x100B09218`, original slot `0x10105C0C0`, IA diversity 0x9FED. Six fresh CPU replays of retained prefixes include NULL/non-NULL, fast/walking stack probes, counter and placement variants. [OB2,OB4]

## Complete auxiliary partition under mode 0x471C

The source uses signed comparisons internally. The following exact conditions describe the resulting u32 domain; the stated interval has the same signed and unsigned ordering because both endpoints are nonnegative signed32 values.

| Decoded auxiliary condition | Original spill PC | Source action at the boundary |
| --- | --- | --- |
| `aux == 0xD79BC5DE` | `0x100B74138` | `STR X0,[SP,#0x24F8]` |
| `aux == 0xBAD70E19` | `0x10064CEA8` | `STR X0,[SP,#0x24F8]` |
| `aux == 0x2BE18A5D` | `0x10097C778` | `STR X0,[SP,#0x24F8]` |
| `0x38ACBB2A <= aux <= 0x7FFFFFFF` | `0x100B2CF64` | `STR X0,[SP,#0x24F8]` |
| `aux == 0xEEDD0B20` | `0x100A2E3A0` | `STR X0,[SP,#0x24F8]` |
| All other u32 values | `0x10095F074` | Store raw u32 `0x8B3DC651` at P+16 |

```text
source caller -> adapter -> entry 0x100A59BB4
  |
  +-- NULL input: previously established shared result/epilogue path
  |
  `-- non-NULL input -> auxiliary decoder at 0x1006583B0
       |
       +-- four singleton conditions / one inclusive interval
       |     -> save original P at F+0x24F8
       |     -> common eight-byte input decoding
       |     -> stop before CoreFoundation data-import read
       |
       `-- complementary u32 domain
             -> P+16 := raw 0x8B3DC651
             -> shared canary/epilogue tail
```

There are nine symbolic control paths: five selected paths and four paths comprising the complementary domain. All pairwise intersections are UNSAT, and their union covers every u32. The interval contains `0x80000000-0x38ACBB2A = 1,196,639,446` values. The four singleton values lie outside it, leaving `4,294,967,296-1,196,639,446-4 = 3,098,327,846` default values. These counts are exact. The decoded auxiliary's semantic unit and original operation names remain unknown. It is not classified as a Mach message ID or IOKit selector. [OB3,OB5]

A first interpretation incorrectly treated representative value `0x7BED772D` as a singleton. The solver returned counterexample `aux=0x7484EEAB`; both values take the interval route. The rejected query is preserved separately as a [SAT hypothesis artifact](triage_evidence/daemon_output_base_rejected_singleton.smt2), outside the 28 accepted UNSAT files. Interval equivalence and the corrected complementary domain are independently rebuilt and verified. [OB5]

The default raw word is compatible with decoded zero under the previously recovered XOR-0x8B3DC651 representation. No original error name or semantic success contract is assigned here. In particular, the range-selected spill does not first define W23 in the new cutpoint projection; only the default output claim requires W23=0x8B3DC651. [OB3,OB5]

## Common byte flow and CoreFoundation boundary

All five selected branches continue through their actual record spill and converge on the existing byte-packing code. For eight borrowed input bytes b0..b7:

```text
U = BE64(b0,b1,b2,b3,b4,b5,b6,b7)
word_at_F_plus_2A70 = U XOR 0x9898989898989898 XOR 0xE3B88695C0D52DBC
```

The theorem covers all 64 input bits for each branch, including every auxiliary value in the interval. The continuations retain eight independent input-byte variables and 28 unavailable frame-byte variables. They neither assign concrete source values to these bytes nor derive their native producers. Observed input consumption is eight bytes; no complete input format or later size contract follows from that prefix. [OB6]

| Route | Accepted source visits from 0x1006583B0 | Common stopped interface |
| --- | ---: | --- |
| 0xD79BC5DE | 423 | Before data-import pointer read at `0x1009D0624` |
| 0xBAD70E19 | 411 | Same |
| 0x2BE18A5D | 439 | Same |
| Inclusive interval | 421 | Same, with auxiliary retained symbolically throughout the interval |
| 0xEEDD0B20 | 430 | Same |

Original slot `0x1010A7E18` binds `_kCFAllocatorDefault` from `/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation`. It is an unauthenticated format-12 bind, ordinal 9 in the import table, with import-table addend `0x6AE8388F` (1,793,603,727), inline addend zero. The stopped read would load that relocated reference; no native imported address or object contents are supplied. This is an imported-data boundary, not an executed CoreFoundation function call. The nonzero-addend handling and later rwlock route for the retained 0x2BE18A5D case remain in the preceding descriptor-producer evidence. [OB1,OB6,OB8]

## Frame identity, shared tail and remaining candidates

For callee entry SP=S, the prologue saves 96 bytes and reserves 0xDEF0=57,072 bytes, so F=`S-0xDF50`, FP=`F+0xDF40`. The shared epilogue at `0x10095F090..0x10095F0AC` restores all twelve saved GPRs and advances SP by 0xDF50=57,168 bytes. An all-u64 component proof covers arbitrary saved words and preserves X0. Canary validation, a valid saved link and hardware pointer authentication remain separate premises for an actual return. [OB4,OB7]

Compiler function-start intervals do not determine ownership of these fragments. For example, `0x10097C778` lies numerically in interval `0x10097BD24..0x10097CA44`, whose entry reserves 0x300 bytes. The retained source path instead enters at `0x100A59BB4` and reaches the spill with its 57,168-byte frame. Similarly, the shared result store lies numerically in interval beginning `0x100948104`, whose entry reserves 0x670 bytes. Actual paths, saved state and SP relations establish these component frame identities. The seven interval observations are retained without promoting their address envelopes to semantic function bounds. [OB4,OB7]

The two other literal stores remain distinct candidates: `0x10027147C` stores X8 loaded through the pointer from SP+0x9D0; `0x10075E378` stores X12 loaded from X9+0xA0 by a paired load. Their frame epochs and relationship to the result object remain unknown. The literal census excludes paired/aliased/computed-base stores and SP movement. [OB9]

The [720-byte cleanup continuation](daemon_cleanup_return_report.md) has compatible FP/F geometry and reaches the same store after loading its unknown F+0x24F8 word. These facts do not establish a continuous predecessor from any newly classified spill into that allocation/cleanup path. Its eight unavailable output-base bytes remain unavailable; no frozen symbolic checkpoint or report is rewritten to identify them with P. Registry publication and daemon/kext/deeper transport joins remain unknown. [OB9,OB10]

## Validation and reproducibility

Fourteen source obligations yield 28 original/simplified UNSAT files. They cover the four singleton routes, inclusive interval, exact complement, coverage, pairwise disjointness, default raw result, record-address key, auxiliary decoding, twelve-register epilogue, common all-input64 word and five saved-record fields. The rejected singleton query remains SAT with its explicit counterexample.

Independent Unicorn execution checks 93 dispatcher cases, including comparison endpoints/neighbors, all nine paths, signed boundaries, the counterexample and deterministic random u32 values. Thirty-two continuation witnesses vary input/frame bytes and include both interval endpoints and interior values. Together they check 18,630 A64 instructions, 2,880 reads, 1,130 writes and 451 logical authenticated edges. The 93 dispatcher witnesses additionally execute the owned boundary store and check its destination/value. Six unmodified caller-prefix replays check 2,709 retained source visits, including 279 instructions from the frozen original stack-probe helper. These finite witnesses do not prove native reachability or hardware PAC. Five fresh read-only IDA ranges match 640 original bytes. [OB1-OB7]

With the pinned interpreter/Z3 environment from the preceding report:

```sh
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/daemon_output_base_dispatch.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_output_base.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/prove_daemon_output_base.py
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_output_base.py
```

IDA JSON and the rejected hypothesis are retained captures. Time is O(source visits + artifact bytes + BV expression/solver resources); space is O(defined cells, pending path states and expression DAGs). A source path stops at 1,000 visits or a nonfinite/unmodeled address/control interface; all reported selected paths reach the stated boundary before that limit. The nine-path proof establishes complete u32 coverage only for the explicitly declared mode/non-NULL/frame/table component. Machine quantities are little-endian u32/u64 except the explicitly big-endian input assembly. Arithmetic wraps at the stated widths.

## Assumption register

| ID | Premise or bounded assumption | Dependent results | Stress test or falsification probe |
| --- | --- | --- | --- |
| OB1 | Pinned original image/fixups and captured raw IDA bytes identify this binary | Source PCs, decoded imports and tables | Rehash image/dependencies; compare five raw ranges and original bind/rebase fields |
| OB2 | Retained caller prefixes define the original record and frame route | P preservation and 0x2BE18A5D spill provenance | Audit all 24 non-NULL prefixes for X0 writes, source SP changes, call arguments and spill bytes; replay six prefixes |
| OB3 | Mode0x471C, non-NULL input, declared table/frame roots and fixed relevant cells apply at the new cutpoint | All-u32 auxiliary partition | Rebuild source semantics and all path predicates; change mode/root context as a new investigation |
| OB4 | Original prologue, stack-probe snapshot and source instructions provide logical frame continuity | F/FP relations and record-save locations | Check source-defined SP deltas and actual helper instructions; compiler address envelopes are insufficient |
| OB5 | A sampled auxiliary value is not a path predicate | Four exact matches, one interval and default output | Retain the SAT counterexample; prove route equivalence, complement, coverage and pairwise disjointness |
| OB6 | Eight borrowed input bytes and 28 unavailable frame bytes are independent symbolic inputs in new continuations | Common packing and external-data frontier | Prove all-input64 word; vary private witnesses; stop before unmodeled imported object contents |
| OB7 | Valid nonwrapping saved-frame cells and original scalar semantics apply | Twelve-register/57,168-byte epilogue contract | All-u64 saved-word proof; original-opcode replays; native canary/PAC/return target remain unproved |
| OB8 | Alternative auxiliaries are component premises; actual caller39C894 supplies one fixed value | External-control and native-caller scope | Find actual producers/callers for other auxiliaries before asserting external controllability |
| OB9 | Equal offsets/shared tail/compatible geometry do not establish an epoch join | Two remaining candidates and 720-byte output-base gap | Require continuous source control and matching frame/record identities; preserve the frozen unknown word |
| OB10 | Native registry publication and Mach/IOKit correlation remain unknown | Overall architectural scope | Follow original ownership/record/transport adapters and actual port-right/message emissions |

## Bounded continuation targets

| Impact | Evidence target | Uncertainty resolved |
| --- | --- | --- |
| High | Find original callers producing the other three singleton auxiliaries and interval values | Native operation selection and external control |
| High | Continue each branch through the imported-data and subsequent library/lock interfaces | Branch-specific semantics beyond the shared eight-byte word |
| High | Establish continuous source control into the 720-byte allocation and back through the shared result object | Actual output-base/owner/caller epoch |
| Medium | Recover the two non-X0 spill candidates and computed-base/pair-store alternatives | Completeness beyond the literal subset |
| Medium | Follow established result-object consumers into original transport adapters | Cross-layer publication and Mach/IOKit joins |

- QG1: Pass for factual technical analysis.
- QG2: Pass; OB1-OB10 give premises, dependencies and falsification probes.
- QG3: Pass for this increment; the full interface objective remains active and incomplete.
- QG4: Pass; widths, byte extents, exact cardinalities, endian order and complexity are explicit.
- QG5: Pass within scope; the rejected singleton is corrected, and component, frozen-path, native and transport evidence remain distinct.
- QG6: Pass; original bytes/imports/fixups, source journals, IDA readback, SMT and independent CPU execution provide provenance.
- QG7: Pass; remaining interface and provenance opportunities are impact-labeled.
