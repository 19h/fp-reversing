# Shared protected-core operation dispatcher

For decoded tag `0x6CF4`, the shared core has an exact operation partition under the captured private setup environment: six singleton operations, one unsigned interval, and their complement. Five singleton paths first require borrowed-record bytes; arcade subscription and registration first reach logging queries. The complementary operation set writes a raw result at protected-record offset `+24` and restores the entry stack. This establishes internal routing, not external admission of arbitrary operation values. [CD1-CD10]

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. New evidence: [first-use checkpoint](triage_evidence/daemon_core_dispatch_source.json), [symbolic source paths](triage_evidence/daemon_core_dispatch_symbolic.json), [fourteen proof pairs](triage_evidence/daemon_core_dispatch_proofs.json), [fresh continuous CPU checks](triage_evidence/daemon_core_dispatch_checks.json), [publication preservation](triage_evidence/daemon_core_dispatch_delivery.json), and [scoped quality gates](triage_evidence/daemon_core_dispatch_quality_gates.json). No fresh IDA query was necessary; the original backing image and retained source evidence suffice for this increment.

## Entry, parameterization and ownership

The preceding [shared-root report](daemon_shared_roots_report.md) establishes entry `0x10061A2D0`, tag decoding and the common setup. The new checkpoint is immediately before the operation's first source read, `0x1004C244C`. A fresh replay captures all GPRs, SP and NZCV there. The 447 preceding source visits contain no read or write overlapping the operation's four bytes. Thus varying this explicit unread entry argument preserves the checkpoint; it does not assign missing frame or borrowed-record contents. [CD1-CD3]

| Item | Private value / representation | Established scope |
| --- | --- | --- |
| Protected record P | `0x6800064000` | Private fixture address; no native ownership claim |
| Decoded tag | `0x6CF4` | Fixed for this partition |
| Operation field | P+12, u32, little-endian | Raw `operation XOR K(P)` |
| Key | `u32((low32(P) XOR 0xEAAE0AC9)*0x7398180B)` | Retained original-source theorem |
| Borrowed record B | `0x6800001000`, loaded from P+16/u64 | Pointee contents and native extent unavailable |
| Entry stack E | `0x6800060000` | Private fixture address |
| Core frame F | `0x680004F230 = E-69072` | Same initialized frame epoch |
| Checkpoint defined bytes | 479 | Reconstructed private fixtures/source writes and declared parent image state |

The private model permits the prospective result store at P+24. Its minimum accessed endpoint is P+28; the native allocation extent is unknown. The diagnostic B-relative window is 4096 bytes solely for classifying stopped accesses; it is not an established borrowed-record size. [CD3,CD6]

```text
retained wrapper evidence                new continuous CPU witnesses
  RPC502       -> operation BC84919B  --+
  arcade61471  -> operation D5525452  --+-> entry 61A2D0
  register41471-> operation 22F7B5AA  --+     -> first operation read 4C244C
                                            -> common source setup
                                            -> operation decision tree
                                               +-- five borrowed-input frontiers
                                               +-- two logging-call frontiers
                                               `-- default result + stack restore

native sender/admission and later transport/deeper-core joins remain separate
```

## Exact operation-to-frontier map

All operation bounds below are unsigned u32 and inclusive. The seven selected rows and the default complement cover all 4,294,967,296 operation words, are mutually disjoint, and account for thirteen source paths. Six source paths converge on the default epilogue. The proofs are conditional on the captured private setup environment and nonzero addresses for the three nonweak exports. They quantify over the operation and opaque export addresses, not over arbitrary native runtime-global values. [CD2-CD5]

| Operation set | Cardinality | Selected handler entry | First required interface, before execution |
| --- | ---: | --- | --- |
| `0x8799A4F1` | 1 | `0x100501BDC` | `0x100501C04`: read 4 bytes at B+0 |
| `0x8F7506EE` | 1 | `0x1005EB7BC` | `0x1005EB7E8`: read 4 bytes at B+0 |
| `0xA70E6EB4` | 1 | `0x100592EBC` | `0x100592EE0`: read 8 bytes at B+0 |
| `0xAD952088` | 1 | `0x1004666EC` | `0x1004666FC`: read 4 bytes at B+0 |
| `0xBC84919B` | 1 | `0x1007FC57C` | `0x1007FC58C`: first 8-byte read at B+8 in an LDP instruction |
| `0xD5525452` | 1 | `0x1005AAEE8` | `0x1005AAF60`: BLRAA to `_os_log_type_enabled` |
| `[0x22F7B5AA,0x7FFFFFFF]` | 1,560,824,406 | `0x1005A8588` | `0x1005A8618`: BLRAA to `_os_log_type_enabled` |
| All other u32 values | 2,734,142,884 | `0x100528DD8` | Raw u32 store at `0x100528DDC`, then stop before RETAB `0x100528E20` |

Check: `6 + 1,560,824,406 + 2,734,142,884 = 4,294,967,296 = 2^32`. The large interval is an internal routing region. It does not establish that every member is a supported operation or externally supplied message ID. The four newly distinguished input-head handlers have unknown higher-level functions until their caller provenance and consumed record schemas are recovered. [CD4,CD8]

The RPC502 route is the singleton BC84919B and follows original authenticated targets `0x100610388 -> 0x1005283AC -> 0x100524A58 -> 0x1006126C4 -> 0x1007FC57C`. This independently agrees with the [RPC502 report](daemon_rpc502_report.md). The new exploration stops before the first unavailable borrowed byte; it does not rerun the subsequent audit/PID, file or deeper-core paths. [CD5,CD8]

For registration41471, original wrapper instructions at `0x100006ADC` and `0x100006AE0` construct `0x22F7B5AA`; `0x100006AE4..6AE8` encode/store the secondary control word beside tag6CF4. These bytes are retained in the [registration source contracts](triage_evidence/created_port_contracts.json) and are checked against the original image in this increment. The constructor lies exactly at the inclusive interval's lower endpoint. `0x22F7B5A9` instead belongs to the default set. For subscription61471, the [retained wrapper contract](arcade_subscription_report.md) constructs D5525452, which selects a separate singleton branch. [CD5,CD8]

## Imported-data and call contracts

The common setup references `_mach_task_self_` before selecting a handler. The original slot denotes an imported address with an encoded addend; it does not directly supply the contents of the exported variable. [CD5,CD7]

| Source location | Original binding / source action | Recovered value |
| --- | --- | --- |
| `0x1004C24FC`, slot `0x1010A39C8` | Nonweak, unauthenticated bind to libSystem `_mach_task_self_`; total addend `0x7BF13863` | Opaque export address plus addend |
| `0x1004C2500..2508` | Add u64 bias `0xFFFFFFFF840EC79D` | Exactly the opaque export address, modulo u64 |
| `0x1004C250C` | Store u64 at F+0x348 | Address of `_mach_task_self_`; no contents read here |
| Slot `0x1010AAAD0` | Nonweak bind to libSystem `__os_log_default`; total addend `0x51B3D66E` | Opaque logging-object address plus addend |
| `0x1005A8618` / `0x1005AAF60` | BLRAA X8,X17; slot `0x1010A0478` | `_os_log_type_enabled`; IA diversity `0x5278`, address diversity 0 |

All thirteen paths preserve the task-data import address in the F+0x348 store. At both logging frontiers, the full symbolic expressions prove `X0=address(__os_log_default)`, `W1=0`, `X8=address(_os_log_type_enabled)` and `X17=0x5278`. The log object's bias is `0xFFFFFFFFAE4C2992`, cancelling its addend exactly. The imported functions are not called, and the exported data objects are not dereferenced by the new analysis. Native export addresses, logging results and `_mach_task_self_` contents remain unknown. [CD5,CD7]

Opaque export addresses retain shared symbolic identity across their uses. No numerical native address is chosen to make routing succeed. CPU witnesses separately instantiate explicit fake addresses for checking arithmetic and memory effects; these assignments are test inputs, not recovered target values. Private stack-canary fixtures remain the declared parent environment. [CD2,CD7,CD9]

The default paths store raw `0x74C29DEE` through the original protected-record pointer at P+24/u32. They then compare the declared private guard, restore GPRs and saved SIMD low64 values, and restore SP=E. Execution stops before RETAB. The raw word is distinct from a native Mach status or port name. Under the retained wrapper's XOR `0x8B3DC651` status codec it decodes to `0xFFFF5BBF`; no independent standard error-name identification or native return is established here. [CD5,CD6,CD9]

## Validation and reproducibility

Fourteen counterexample obligations are UNSAT in both original and simplified SMT files: seven exact route sets, default complement, complete coverage, pairwise disjointness, default raw result, restored entry SP, task-import address cancellation, and both logging-call target/argument contracts. Source reconstruction and the symbolic path product are rebuilt and compared with retained outputs. Original bytes and import fixups remain the provenance for all selected edges. [CD1-CD5,CD7]

Fresh CPU replay starts at `0x10061A2D0`, changes the explicitly unread operation field in the entry fixture, and follows original source to each frontier. It covers 33 operation values, including every singleton, adjacent values, interval boundaries, signed32 extremes and all thirteen path samples. Four private-byte/export-address variants produce 132 passing continuous cases: 220,848 source visits, 47,120 reads, 30,012 writes, 768 logical control edges and 132 checked boundaries. No frontier call or return executes. Checkpoint capture and replay share Unicorn; the dispatcher uses separate Z3 scalar semantics. Hardware PAC, native API behavior and full all-state setup invariance are untested. [CD1,CD9]

With the previously pinned environment:

```sh
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
 Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
 /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_core_dispatch.py
```

The source capture and symbolic/proof generators can be regenerated with the same environment using `capture_daemon_core_dispatch.py`, `daemon_core_dispatch_symbolic.py` and `prove_daemon_core_dispatch.py`. Time is O(source visits + cases*visits + BV/solver resources); space is O(one CPU map/journal + symbolic states and expression DAGs). Exploration limits are 5000 visits per path, 200000 total visits, fewer than256 states and at most8 finite alternatives per split; no limit frontier occurs in the retained product. Byte extents, integer widths and cardinalities are exact. [CD4,CD9]

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| CD1 | Pinned daemon/helper artifacts define the analyzed instructions and prefix | Rehash inputs; fresh original-byte replay and regenerated checkpoint; changed source falsifies reuse |
| CD2 | Tag6CF4 and captured private setup/global context are fixed; complete route map depends on this context | Vary controller/header/setup inputs in a new source run; a different selected slot bounds this map's applicability |
| CD3 | Operation is an explicit entry argument unread before the checkpoint | Audit all earlier overlapping reads/writes; zero overlaps across447 visits; either overlap invalidates the parameterization |
| CD4 | Symbolic scalar/NZCV semantics and finite splitting represent the visited source | Rebuild fourteen obligations; prove coverage/disjointness; replay all paths, adjacent values and signed boundaries |
| CD5 | Original chained fixups and additive biases identify logical targets/data addresses | Decode original words/import table; compare source loads, modifiers and target arguments; mismatch rejects the edge |
| CD6 | Private output storage permits the P+24 store; native extent and B contents remain unknown | Stop before B reads; require P+28 for a real result owner; recover wrapper allocation/ownership before native claims |
| CD7 | Nonweak export addresses are nonzero opaque u64 values; exported contents unavailable | Quantify address cancellation/arguments; vary fake address assignments in CPU checks; stop before any opaque-address dereference |
| CD8 | Wrapper constants identify known operations but do not expose the whole internal domain externally | Recover caller construction/admission for each operation; absence of a caller leaves function/admission unknown |
| CD9 | Private CPU models validate bounded source effects; logical PAC is not hardware authentication | Four memory/address variants, independent source equations, guard equality and boundary checks; native behavior remains outside evidence |
| CD10 | Port/transport and later auxiliary-emitter epochs require separate joins | Trace a source-continuous producer/consumer and right provenance; imported addresses or equal scalars alone do not establish a join |

## Bounded continuation and impact

| Impact | Next target | Information resolved |
| --- | --- | --- |
| High | Recover native-wrapper provenance and record heads for operations8799A4F1,8F7506EE,A70E6EB4,AD952088 | Higher-level functions, pointer/length/owner fields and actual external control |
| High | Establish controller/global-state invariance of this decision tree from original bank equations | Whether the exact partition extends beyond the captured setup environment |
| High | Join operation-specific continuations to the nine auxiliary emitters in the same frame epoch | Which source-established operation actually reaches parser/720-byte/digest facilities |
| Medium | Track future reads of F+0x348 and the imported task-data object | Actual task-name loads and downstream Mach API use, if present |
| Medium | Match default P+24 output decoding to each wrapper's allocation/return contract | Native owner extent and status propagation without assigning a standard error meaning |
| Low | Retain diagnostic handler labels keyed by operation until schema/caller evidence exists | Prevent unsupported semantic names from obscuring distinct branches |

No new Mach message, right transfer, destination port or IOKit selector is established. Existing host-special-port17/34 RPC502 evidence and host-special-port31 arcade registration/subscription evidence remain separate in the [Mach-port report](mach_ports_report.md). The common protected core is an internal control interface; the cross-layer transport joins still require their own producer/consumer evidence. [CD8,CD10]

## Quality gates

QG1: Factual source, arithmetic, interface and evidence-boundary analysis; no normative content required.

QG2: CD1-CD10 identify assumptions, dependent results and falsification probes.

QG3: Operation routing, input/output contracts, import/call sites and cross-layer implications are covered for this increment; the full investigation remains active and incomplete.

QG4: u32/u64 modular arithmetic, exact byte extents, source PCs, cardinality calculation and reproducible algorithms/complexity are explicit.

QG5: Interval versus singleton, imported address versus data contents, private output permission versus native extent, and symbolic coverage versus native admission are distinguished.

QG6: Original source/fixups, retained wrapper source, regenerated products, fourteen proof pairs and fresh CPU witnesses provide traceable provenance; no fresh IDA or native observation is claimed.

QG7: Impact-labeled bounded continuations address additional data-flow, control-flow, environmental and architectural questions.
