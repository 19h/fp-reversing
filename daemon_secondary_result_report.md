# fairplay-client result types, state bits and the next adapter

The second Security query's consumer tests CFNumber and then CFString using
full 64-bit CFTypeID comparisons. Its numeric branch requests signed 32-bit
conversion. Conversion return zero produces marker 0x31; nonzero produces
0x32. The numeric payload is a separate four-byte output, not that Boolean
conversion result. Marker 0x32 leads to a frame-state OR with 0x8 and a further
private adapter, which invokes the previously recovered Boolean adapter with
key string `FairPlay-CoreML-Client`.

For recovered marker-0x31 paths, the earlier first-query state matters: the
retained state-zero cases stop before clearing an unavailable borrowed output
owner, whereas retained state=2 cases reach malloc(32). These are conditional
source behaviors, not native authorization, memory-fault or allocation
findings. Third-query results, String conversion/parsing and final admission
remain unknown.

## Evidence and reproduction

This extends the [two-adapter flow](daemon_entitlement_flow_report.md) and
[first result consumer](daemon_entitlement_result_report.md). Primary daemon:
`/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
All source addresses below are unslid VAs. Original files suffice; no fresh
IDA query, IDB mutation or native target/framework/IPC operation was performed.

Evidence comprises [32 value/error profiles](triage_evidence/daemon_secondary_result_profiles.json),
[28 type/conversion profiles](triage_evidence/daemon_secondary_result_type_profiles.json),
[original contracts and ledgers](triage_evidence/daemon_secondary_result_contracts.json),
[13 source proof pairs](triage_evidence/daemon_secondary_result_proofs.json)
and [independent replay checks](triage_evidence/daemon_secondary_result_checks.json).
These API outcomes are declared private models, not observations from the
annotated RAX trace. Simultaneously non-NULL value/error is a counterfactual
robustness input with native feasibility unestablished.

From `/Users/___/dev/dylex/extracted`, apply this prefix to the scripts in order:

```text
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
 Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
 /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/<script>

probe_daemon_secondary_result.py
probe_daemon_secondary_types.py
recover_daemon_secondary_result.py
prove_daemon_secondary_result.py
validate_daemon_secondary_result.py
```

## Result gates and exact interfaces

At 0x1002382E8, SecTaskCopyValueForEntitlement queries `fairplay-client`.
CMP/CCMP at 0x1002382F0/0x1002382F8 form the exact condition
`value != NULL && error == NULL`. In the retained selector context this
selects index 0x594B when true, otherwise 0x5949. The local proof quantifies
all pairs of 64-bit value/error words, with readable error-cell and retained
register premises. Native returned object values remain unknown.

```text
fairplay-client query @ 0x1002382E8
  |
  +-- NULL value or non-NULL error ----------------------------+
  |                                                          |
  +-- CFNumber type comparison, 64 bits                       |
      |                                                      |
      +-- match: CFNumberGetValue(type=3, out32)                |
      |            return 0 -> marker 31 ----------------------+--> cleanup
      |            return nonzero -> marker 32 -> cleanup      |
      |                                                       |
      +-- mismatch: CFString type comparison, 64 bits           |
                    mismatch -> marker 31 ---------------------+
                    match -> CFStringGetCString(...,32,ASCII)
                             [unmodeled frontier]

marker 31 -> test prior frame state
             zero -> borrowed-output zeroing frontier
             nonzero -> malloc(32) frontier in retained state=2

marker 32 -> frame state |= 8
             token copy -> private bridge 0x1004586D8
             token copy -> Boolean adapter 0x10046EF4C
                           key: FairPlay-CoreML-Client
                           [stop before CFString constructor]
```

| Call PC | Imported interface | Original slot | IA discriminator |
| --- | --- | --- | --- |
| 0x1002382E8 | SecTaskCopyValueForEntitlement | 0x10109FFA0 | FE9E |
| 0x10003B330 | CFNumberGetTypeID | 0x1010A0ED0 | 6A24 |
| 0x10003B388 | CFGetTypeID | 0x1010A0020 | C89B |
| 0x100013450 | CFStringGetTypeID | 0x10109FD98 | 46A2 |
| 0x1000134A0 | CFGetTypeID | 0x1010A0020 | C89B |
| 0x10000B734 | CFNumberGetValue | 0x1010A0B28 | 8642 |
| 0x10014C658 | CFStringGetCString | 0x1010A12A8 | 7208 |

Original authenticated words have key IA and addrdiv=0. In particular, 46A2
also appears on an unrelated free binding; the actual source-loaded slot
0x10109FD98 identifies CFStringGetTypeID here. A discriminator alone does
not identify the interface.

| Gate | Match index/target | Other index/target |
| --- | --- | --- |
| query value non-NULL, error NULL | 594B / 0x10003B2BC | 5949 / 0x1000235D8 |
| CFNumber type | BB08 / 0x10000B6AC | BB3A / 0x1000133BC |
| CFString type | 644E / 0x10014C5DC | 5946 / 0x1000746D0 |

The contracts retain exact original slots for these targets. Both type
comparisons use CMP X24,X0. The modeled wrong types deliberately share the
expected IDs' low 32 bits and differ in their high 32 bits. Fresh CPU replay
rejects those matches; the source proofs cover every 64-bit ID pair. Abstract
type IDs are not native CoreFoundation type-ID observations.

## Numeric and String output contracts

Let F be the protected-core frame and R=F+0x10CB8. In the private placement,
F=0x680004F230 and R=0x680005FEE8. Frame offsets are hexadecimal bytes;
ordinary sizes are decimal bytes. These are harness placements, not native
fixed addresses.

| Interface location | Recovered contract |
| --- | --- |
| CFNumberGetValue X0 | Returned value object |
| X1=3 | kCFNumberSInt32Type |
| X2 | Pointer loaded through second record R+0x10; retained F+0x1280 |
| Conversion output extent | Four bytes, signed 32-bit representation |
| API return | Boolean conversion outcome, separate from the output word |
| Result marker | R+0x18; source writer 0x100067240 |
| CFStringGetCString X0 | Returned String object |
| X1 | Second child FP-0x80; retained 0x680004F1A0 |
| X2=32, X3=0x600 | Buffer capacity 32 bytes, ASCII encoding 0x600 |

Pinned installed MacOSX27.2 SDK CFNumber.h defines type 3 as signed 32-bit
and documents that unsuccessful/lossy conversion can still write a numeric
approximation. The compile-only [C probe](triage_evidence/daemon_secondary_result_sdk.c)
and [LLVM output](triage_evidence/daemon_secondary_result_sdk.ll) check the
type constant, four-byte output width, 32-byte String buffer and ASCII
argument. Header hashes/compiler command are in the contracts. This SDK is
not version-matched to the target runtime; it does not establish native
conversion behavior for these opaque model objects.

The numeric marker sequence at 0x10000B738..0x10000B744 reduces to
`marker = W0 == 0 ? 0x31 : 0x32`. The all-u32 return-word proof is local;
the modeled ABI returns use canonical 0/1. Both successful and failed
conversion models write independently declared output words 0, 1, 80000000
or FFFFFFFF. Their prior four-byte destinations are source-undefined, and
that definedness transition is recorded as an API effect, not an initial
fixture or a source store. Model output/return correlations are not claimed
to be feasible for a single native CFNumber.

No source read overlaps F+0x1280..+0x1283 before any of the 60 final
boundaries. Thus the converted value has not yet been consumed in these
recovered prefixes. This is not a final-policy independence claim. The String
path stops before CFStringGetCString: returned bytes, termination on failure,
subsequent parsing, range handling and its output marker remain unknown.

## Cleanup, state bits and borrowed output owners

| Second-query case/model | Second marker | Recovered next stage |
| --- | --- | --- |
| NULL value / error present / both non-NULL / wrong Number-and-String type | 31 | Prior-state-dependent continuation |
| CFNumber conversion returns zero | 31 | Same continuation, even with a modeled numeric output write |
| CFNumber conversion returns nonzero | 32 | OR state with 8, then next private bridge/key |
| Type query unmodeled | unknown | Stop before CFNumberGetTypeID |
| CFString type match | unknown | Stop before CFStringGetCString |

The ordered release requests are value (if non-NULL) at 0x100074734, error
(if non-NULL) at 0x1000DCD50, task at 0x1001120C0 and key at 0x10015EB78,
all through CFRelease slot 0x1010A02E0 / IA 1883. Fresh replay checks 132
such second-query requests. Native reference counts and deallocation effects
are unknown.

The prior report establishes the first query's OR-0x2 writer. On numeric
conversion return nonzero, 0x1007F797C now writes the additional exact equation
`u32(F+0x6ADC) := old_state OR 8`, universally proved for all u32 prior words.
The sampled first-false and first-true cases therefore reach state 0x8 and 0xA,
respectively. This is source state accumulation; no grant/rejection meaning
is assigned to these bits.

For marker 31 with retained prior state zero, execution reaches:

```text
0x10057A770: X9 := u64(F+1A30)
0x10057A774: u64(X9) := 0             [stop before this write]
0x10057A778: X9 := u64(F+7098)
0x10057A77C: u64(X9) := 0             [static next store]
```

The preceding operation's symbolic state proves, for all borrowed input
bytes in that path, `u64(F+1A30)=u64(B+38)` and
`u64(F+7098)=u64(B+40)`. Earlier source checks those pointer words for nonzero.
Their ownership/writable extents are not established by that predicate.
The 18 state-zero profiles stop before the first write. Separate local
proofs establish each isolated eight-byte zero store under a readable-frame
and writable-owner premise; they do not prove both stores can execute for
arbitrary aliasing or native addresses. Eighteen corresponding retained
state=2 profiles instead stop before malloc(32). No native pointer fault or
complete returned operation status is inferred.

## Next private records and CoreML-named key

After marker 32, source calls copy32 at 0x1007F79F0, moving the original
token from F+C080 to F+C100, then builds another protocol at R. It calls
entry 0x1004586D8 at 0x1007F7A84 through slot 0x1010A0998 / IA 8250.
This caller produces 20 field bytes within a 24-byte span; it is not the
second query's 40-byte record type.

| New bridge-record offset | Source-written field |
| --- | --- |
| +00, eight bytes | Token pointer F+C100 |
| +0C, four bytes | `(phase24+0xD64D96E8) XOR K24(R)` |
| +10, eight bytes | Pointer to the shared state word F+6ADC |

`K24(R)=u32((low32(R) XOR 0x7CF28BE0)*0x83918153)`. The builder equation is
universally proved over its phase and token-pointer words. The caller's
retained phase component gives the unmasked value 0xB3D4; the complete bridge
result protocol is not assigned from this caller-side codec alone.

Inside that bridge, copy32 at 0x100345354 moves the same token to
0x680004F178. Call 0x10034547C then invokes 0x10046EF4C with a new 40-byte
record at 0x680004F1A0. Its key pointer is 0x100FD5565, containing the complete
23-byte NUL-inclusive ASCII string `FairPlay-CoreML-Client`; its token field
points to the new copy. Two new all-256-bit copy proofs and fresh replay
establish this lineage. The entry reaches selector 8BB2 and stops before
CFStringCreateWithCStringNoCopy at 0x10033376C. No third native entitlement
query or value is observed, and the key's name alone establishes no CoreML
framework call or model-processing activity.

## Assumptions, verification and bounded continuation

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SR1 | Pinned source VA mapping, bytes and original fixup/import tables identify the target. | Rehash source and independently decode used words/imports; reject opcode or binding mismatches. |
| SR2 | Retained predecessor frame, source-defined cells and declared file/BSS/controller/allocator state define these contexts. | Check frozen source prefixes and vary backing/controller contexts; establish native initialization separately. |
| SR3 | Query refs/errors, abstract type IDs, conversion returns/outputs and constructor objects are declared models. Native correlations/feasibility are unknown. | Retain unmodeled frontiers; test same-low32/different-high32 IDs, error/value combinations and signed32 bit patterns; do not promote them to native API observations. |
| SR4 | API models preserve X18..X29 and vary X0..X17/NZCV; complete vector/ABI clobber coverage is not claimed. | Fresh CPU replay verifies stack, arguments and effects with changed undefined-byte backing; widen clobbers before stronger ABI claims. |
| SR5 | Local owner-store theorems require readable frame cells and writable pointees. Sequential arbitrary aliases and native owner extents are outside them. | Strict-stop before unknown owner writes; inspect each pointer's input lineage; analyze real pointee/alias contracts before asserting complete zeroing. |
| SR6 | Reused record addresses and marker/control fields have distinct epochs. | Compare first/second/bridge/third layouts and scope API/type lookups to the correct query epoch; verify masks and exact store widths. |
| SR7 | Current SDK declarations justify compile-only argument/type interpretation, not target runtime implementation. | Recompile the pinned probe and hash headers/LLVM; match target frameworks before native conversion claims. |
| SR8 | PAC is logically resolved; native key state, authenticated token origin, entitlement values, final admission and framework IPC remain unknown. | Verify actual loaded slots/modifiers and full token copies; recover receiver provenance and runtime transport independently. |

All 60 fresh A64 replays pass: 99,380 source visits, 21,486 reads, 6,416
source writes, 2,272 logical edges, 1,000 declared API transitions and 196
separate API-output effects. All 2,257 unique visited instructions match
original bytes. Sixty source prefixes match retained predecessors. Thirty-six
marker-31 and eight marker-32 returns are checked; the other 16 profiles stop
at unmodeled type/conversion APIs. Thirteen original and thirteen simplified
SMT files independently solve UNSAT. Only the local statements have universal
quantification; the profiles are finite witnesses.

The independent validator initially selected the first query's CFGetTypeID
while checking the second query's modeled type pair. Its lookup is now
restricted to the second-query epoch, and all checks were rerun. This was a
verifier error, not a target discrepancy. Store preflight also stops before
an unavailable owner, preserving an unexecuted terminal instruction rather
than logging a partially attempted access as completed source execution.

Probe/recovery/replay cost is O(total visits + source/artifact bytes), with
O(one private CPU map + journals) space. BV proofs add solver resources and
expression-DAG storage. Extents are bytes and equations use fixed-width
modular integers; no native timing or physical-unit estimate is asserted.

| Impact | Next investigation | Required evidence |
| --- | --- | --- |
| high | Complete the String conversion/parser branch. | Buffer-write/termination contracts, exact parser call and overflow/range/result handling. |
| high | Follow the FairPlay-CoreML-Client adapter and bridge return. | Constructor/query outputs, marker/flag writers and subsequent state-bit consumers in the new record epoch. |
| high | Establish B+38/B+40 pointee types and writable extents. | Their original caller/MIG field construction, actual owners and alias/lifetime constraints. |
| high | Join state bits 2/8 to final object/status publication. | Complete downstream return/allocation/ownership flow; current markers and malloc requests are insufficient. |
| medium | Establish deeper Security/CoreFoundation IPC and authenticated token origin. | Matching runtime implementations and receiver/trailer provenance; API names and equal token bytes do not identify Mach ports or native sender attribution. |

No new incoming/outgoing Mach port, emission site or right disposition is
established. The entitlement/key strings are not bootstrap endpoints.

QG1: Pass for factual source/interface analysis; no normative judgment is required.

QG2: Pass for this increment; SR1-SR8 record premises, dependencies and falsification probes.

QG3: Pass for this increment; second-result types, conversion ABI/output, cleanup, state, borrowed output owners and next private interface are covered. The broad goal remains active and incomplete.

QG4: Pass; widths, exact extents/counts, fixed-width equations, reproducible commands and algorithmic complexity are explicit.

QG5: Pass within scope; API epochs, marker versus payload, record reuse, undefined output bytes, isolated versus sequential owner writes and native gaps are distinguished.

QG6: Pass; original bytes/fixups/imports, primary installed SDK declarations, 26 SMT readbacks and fresh CPU replay support the scoped claims.

QG7: Pass; impact-labeled continuations cover the String parser, third key, owners, final state and deeper IPC.

Publication evidence: [preservation](triage_evidence/daemon_secondary_result_delivery.json)
and [scoped quality gates](triage_evidence/daemon_secondary_result_quality_gates.json).
