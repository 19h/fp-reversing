# Entitlement result consumer and caller predicate

The record40 path now has a recovered result schema: after querying
`com.apple.private.fpsd.client`, it accepts a non-NULL value with no error,
checks that its full 64-bit CFTypeID equals CFBooleanGetTypeID(), and stores
the Boolean byte through R+0x10. It writes marker 0x5C for either Boolean
value; the recovered NULL/error/type-mismatch paths write 0x5B. These are
source-level interface results. Native entitlement values, authenticated
sender attribution and the meaning of the caller's selected destinations
remain unknown.

This extends the [record40 consumer report](daemon_record40_consumer_report.md)
and the [MIG handover report](daemon_mig_handover_report.md). Original files
were sufficient; no new IDA query or database mutation was needed. The
annotated RAX trace is historical transport evidence; these result cases
are explicitly declared private API models, not observations from that log.

## Primary evidence and reproduction

The original `/Users/___/Downloads/zut/fairplayd.arm64e` SHA-256 is
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
Addresses below are unslid VAs in this file. Original opcode bytes, chained
fixup words/import bindings, selected table slots, output writers and API
event order are recorded in the [contracts](triage_evidence/daemon_entitlement_result_contracts.json).
The [profiles](triage_evidence/daemon_entitlement_result_profiles.json) retain
all source visits and read/write journals, including each modeled API output
at its actual call epoch. No native framework, daemon, kext, Mach send or
right-transfer operation was executed for this increment.

From `/Users/___/dev/dylex/extracted`, run each script in this order with:

```text
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
 Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
 /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/<script>

probe_daemon_entitlement_result.py
recover_daemon_entitlement_result.py
prove_daemon_entitlement_result.py
validate_daemon_entitlement_result.py
```

The pinned installed MacOSX27.2 SDK headers CFBase.h and CFNumber.h are
primary evidence for CFTypeID and Boolean declarations. Their paths/hashes,
the exact arm64e compiler command and its successful exit status are in the
contracts. The [C probe](triage_evidence/daemon_entitlement_result_sdk.c)
asserts sizeof(CFTypeID)=8 bytes and sizeof(Boolean)=1 byte; its
[LLVM output](triage_evidence/daemon_entitlement_result_sdk.ll) preserves an
i64 type comparison. This SDK has not been version-matched to the target's
loaded framework runtime.

## Recovered interface

R is the 40-byte caller record. R+8 is a one-byte marker; R+0x10 is a pointer
to a separate one-byte flag. In the private placement, R=0x680005FEE8 and
the flag address is 0x6800051F2F. Those addresses are harness placements,
not native daemon addresses. The source initializes the flag to zero at
0x10033369C. The earlier report proves the key string and 32-byte audit
token flow to SecTaskCreateWithAuditToken and the query argument cells.

```text
SecTaskCopyValueForEntitlement @ 0x1002B7728
  |
  +-- value == NULL OR error != NULL -----------+
  |                                           |
  +-- CFBooleanGetTypeID @ 0x10030ACB0          |
      CFGetTypeID(value) @ 0x10030AD04          |
        |                                     |
        +-- 64-bit IDs unequal ---------------+--> marker 5B
        |
        +-- IDs equal
            CFBooleanGetValue @ 0x10052BCC4
            flag := low8(return) @ 0x10052BCCC
            marker := 5C
  |
  +-- conditional object-release requests
      marker write @ 0x1004B115C
      return to 0x1004C464C
      predicate := (flag == 0) OR (marker == 5B)
```

The query gate uses CMP/CCMP/CSET at 0x1002B7730..0x1002B773C. Its condition
is exactly `value != 0 && error == 0`. Under the retained register values
from this selector's source path, the selected index is 0xA7C7 when true
and 0xA7E1 otherwise. The [five proof pairs](triage_evidence/daemon_entitlement_result_proofs.json)
prove the gate for every pair of 64-bit value/error words, the type test
for every pair of 64-bit type IDs, the low-byte stores, and the caller test
for all 65,536 flag/marker byte pairs. These are local equations with the
readable-cell and retained-register premises listed below.

| Source call PC | Imported interface | Exact slot | IA discriminator |
| --- | --- | --- | --- |
| 0x1002B7728 | SecTaskCopyValueForEntitlement | 0x10109FFA0 | FE9E |
| 0x10030ACB0 | CFBooleanGetTypeID | 0x1010A0670 | CA54 |
| 0x10030AD04 | CFGetTypeID | 0x1010A0020 | C89B |
| 0x10052BCC4 | CFBooleanGetValue | 0x1010A0438 | 887B |
| 0x100496084 | CFRelease(value) | 0x1010A02E0 | 1883 |
| 0x1004BE234 | CFRelease(error) | 0x1010A02E0 | 1883 |
| 0x100376A04 | CFRelease(task) | 0x1010A02E0 | 1883 |
| 0x1003ECB40 | CFRelease(key string) | 0x1010A02E0 | 1883 |

All listed authenticated slots have addrdiv=0 and key IA in the original
words. The CFBooleanGetTypeID call resolves one previously unclassified
literal-CA54 candidate in the [auxiliary-caller inventory](daemon_aux_callers_report.md).
It is not the auxiliary-record adapter in this context. A discriminator
alone does not identify a target; the source-loaded slot and original bind
establish this classification. Historical reports remain frozen.

| Branch meaning in this selector context | Table index | Original slot | Target |
| --- | --- | --- | --- |
| value non-NULL, error NULL | A7C7 | 0x10108DD28 | 0x10030AC58 |
| other query result | A7E1 | 0x10108DDF8 | 0x1004D6C58 |
| Boolean type match | 8A97 | 0x10107F3A8 | 0x10052BC5C |
| type mismatch / common value-release path | 5397 | 0x101063BA8 | 0x100496028 |
| caller predicate true | 961D | 0x101084FD8 | 0x1004B4F2C |
| caller predicate false | 960F | 0x101084F68 | 0x1004B3E6C |

## Finite conditional profiles and cleanup

Each row has four distinct environment/register-clobber contexts. The
non-NULL object words and returned type IDs are abstract model values.
The wrong-type model has the same low 32 bits as the Boolean type ID and
different high 32 bits; all four contexts select the mismatch path.

| Declared query/type/value model | Source visits per case | Final flag | Marker | Caller predicate if evaluated | Ordered release requests |
| --- | --- | --- | --- | --- | --- |
| NULL value, NULL error | 479 | 00 | 5B | true | task, string |
| NULL value, non-NULL error | 504 | 00 | 5B | true | error, task, string |
| non-NULL value and error | 532 | 00 | 5B | true | value, error, task, string |
| non-NULL value, NULL error; type API unmodeled | 402 | 00 | unknown | unknown | none before boundary |
| non-NULL value, NULL error; wrong CF type | 547 | 00 | 5B | true | value, task, string |
| CFBoolean false | 580 | 00 | 5C | true | value, task, string |
| CFBoolean true | 580 | 01 | 5C | false | value, task, string |

The simultaneous non-NULL value/error case is a counterfactual robustness
input; native API feasibility is not established. The unmodeled row stops
before CFBooleanGetTypeID at 0x10030ACB0. Its marker remains undefined in the
source-definedness model; the physical backing byte is not evidence of a
marker result. All other rows return to the original caller.

The byte writer at 0x10052BCCC is STRB W0: its equation is low8(X0), proved
for all 64-bit return words. The finite Boolean models use canonical 0 and
1. No claim is made about arbitrary noncanonical native Boolean values.
Release entries are source-issued calls with opaque objects; native
reference counts, frees and framework-internal IPC are not observed.

The caller's CCMP immediate supplies Z=1 when the flag is zero. Therefore
Boolean-false/marker-5C and marker-5B cases share predicate=true, whereas
Boolean-true/marker-5C selects predicate=false. This polarity is established
without assigning success, rejection, authorization or grant meanings to
either destination. The proof covers the predicate and slot selection;
these profiles stop at the caller entry before executing that predicate.

## Assumption register and falsification probes

| ID | Explicit premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| ER1 | Original-file VA mapping and bytes are authoritative for static claims. | Rehash source and independently decode used original fixup/import words; a byte or binding mismatch invalidates the corresponding claim. |
| ER2 | Selector 8BB2, retained dispatch registers and caller record come from the previously proved path. Native invocation is not assumed. | Compare original predecessor/key-token ledgers; test another selector independently rather than transporting these constants. |
| ER3 | Pointer cells used by local equations are readable with the specified contents. This conditions all five local proofs. | Change cell definitions/addresses and rebuild proofs; independent replay checks the actual modeled addresses/read epochs. |
| ER4 | Allocator words, constructor objects, query results, error output and type/Boolean results are declared private API models. All continued profiles depend on them. | Stop with an API unmodeled; the strict type frontier is retained. Replace one model result at a time and replay; no result establishes native feasibility. |
| ER5 | API callbacks preserve X18..X29, vary X0..X17 and NZCV, and return at call+4. Models do not cover vector-register clobbers or all ABI states. | Fresh CPU replay verifies retained registers and all recorded effects with different uninitialized backing patterns; widen the clobber domain before any general ABI claim. |
| ER6 | PAC is resolved logically from the actual slot, target and modifier. Native key state is unknown. | Independently decode key/addrdiv/discriminator and compare the source-loaded target; hardware authentication success remains outside these results. |
| ER7 | Installed SDK declarations describe this ABI probe, not the target's runtime version. Native sender and policy destination meanings remain unknown. | Match the target framework/runtime and authenticated receive-token provenance, then follow both caller destinations in the same source epochs. |

## Verification, scope and continuation

[Independent checks](triage_evidence/daemon_entitlement_result_checks.json)
rebuild the original-source equations and SDK contracts and freshly replay
28 profiles: 14,496 instruction visits, 3,060 reads, 880 source writes,
320 logical edges, 188 explicitly declared API transitions, and 28 separate
API error-output word effects. All 620 unique visited source instructions
match the original bytes. All private reads are source-defined or explicit
fixtures; no uninterpreted private read bytes were consumed. Five original
and five simplified SMT files are UNSAT. These counts are finite witnesses;
only the local BV statements have universal quantification.

The error-output effect is applied after verifying its prior zero bytes at
the query call. It is not an initial fixture, source store or hidden PC
transition. API callbacks do not call host frameworks. The SDK probe only
compiles. Probe/recovery/replay cost is O(total source visits + artifact
bytes), with O(one private CPU map + journals) space; BV proof cost adds
solver resources and DAG storage. Quantities are byte extents or fixed-width
modular integers, with no physical-unit calculation or estimated native
timing claim.

| Impact | Bounded next investigation | Evidence needed |
| --- | --- | --- |
| high | Establish what 0x1004B4F2C and 0x1004B3E6C do after this query. | Continuous source-epoch joins through both original destinations; distinguish mode choice from any final admission effect. |
| high | Link the copied token to an actual authenticated receive trailer. | Receiver-specific bounds, message/trailer provenance and unbroken source copies; equal bytes alone do not establish sender attribution. |
| medium | Determine whether the Security calls introduce deeper IPC. | Matching framework implementation and transport evidence; import names alone do not identify Mach ports or emitted rights. |
| medium | Resolve additional CA54 candidates by loaded slots. | Complete bank/source-register context and original binding, rather than discriminator matching. |
| medium | Analyze reuse of the paired shared header after this callee. | Epoch-specific 32/64-bit reads/writes and initialization/concurrency premises. |

No new incoming/outgoing Mach port, emission site or right disposition is
established by this increment. The corresponding [port report](mach_ports_report.md)
retains the previously established transports. The entitlement name is not
a bootstrap endpoint.

QG1: Pass for factual interface analysis; no normative judgment is required.

QG2: Pass for this increment; ER1-ER7 enumerate assumptions, dependencies and falsification probes.

QG3: Pass for this increment; result schema, exact interfaces/slots, control/data flow, cleanup and port-evidence boundary are reported. The broad interface objective remains active and incomplete.

QG4: Pass; byte widths, u32/u64 equations, reproduction commands, complexity and finite versus universal coverage are explicit.

QG5: Pass within scope; NULL/error/type/Boolean cases, undefined marker boundary, caller polarity, ABI clobber limitations and unproved native effects are separated without unresolved contradictory claims.

QG6: Pass; original bytes/fixups/imports, installed primary SDK declarations, ten SMT readbacks and independent A64 replay support the scoped claims.

QG7: Pass; bounded opportunities and impact are listed above.

Publication evidence: [preservation](triage_evidence/daemon_entitlement_result_delivery.json)
and [scoped quality gates](triage_evidence/daemon_entitlement_result_quality_gates.json).
