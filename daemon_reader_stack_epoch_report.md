# Shared-core stack epoch through the keyed reader and builder finish

The selected subscription route carries the shared-core frame base F to keyed-reader entry0x100847998 and common builder finish0x10090a400. Under normal stack-probe/import/helper returns and the retained chosen control edges, F=entry_SP-0x10dd0. Source reserves68944 B of locals below128 B of saved state. The reader preparation's sparse frame accesses fit that source-reserved local region; their upper bound leaves24328 B before its end. This establishes conditional source placement, not native mapped/initialized ownership. [SE1-SE8]

The new evidence is a source-interval audit of twelve historical profiles, not a fresh replay. It inspects6367 ordered intervals/966122 instruction instances,149 unique intervals and11901 unique path/prefix instruction sites. Nine calls per profile enter the same5497-instruction helper; each subtracts/restores192 B and returns to the same parent SP under the declared return premise. Thirty-six separately recaptured lookup/reader ranges contain no SP write or call, supplying a source-only SP-preserving extension for the unobserved found-value path. [SE2-SE6]

Evidence: [source intervals,call/return associations and frozen events](triage_evidence/daemon_reader_stack_epoch_source.json), [21-query certificate and premise counterexample](triage_evidence/daemon_reader_stack_epoch_checks.json), [extractor](triage_evidence/recover_daemon_reader_stack_epoch.py), [validator](triage_evidence/validate_daemon_reader_stack_epoch.py), [preservation](triage_evidence/daemon_reader_stack_epoch_delivery.json), [scoped gates](triage_evidence/daemon_reader_stack_epoch_quality_gates.json). Adjacent contracts: [preparation footprint/cache map](daemon_reader_context_footprint_report.md), [existing-value reader](daemon_existing_scalar_reader_report.md), [entry/miss/population](daemon_scalar_field_population_report.md), [shared-core initialization](daemon_shared_roots_report.md), [protected adapter](daemon_xpc_core_bridge_report.md), [retained subscription route](arcade_subscription_report.md).

| Evidence | Verified scope |
| --- | --- |
| Original thin image | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Captured core prefix |18 instructions,including saved-state allocation,probe call and two local-reservation SUBs |
| Ordered source audit |12 profiles,6367 interval instances,966122 source-audited instruction instances |
| Deduplicated source |149 path intervals/11885 unique path sites;prefix adds16 previously uncounted sites,11901 unique sites total |
| Internal helper |108 calls,each with192 B reserve/restore;one call depth inside the audited core path |
| Imported calls |180 modeled calls inside path intervals;12 entry stack-probe records are separate |
| Source-only extension |36 referenced ranges/2422 instruction instances,1549 unique sites,zero SP writes/calls |
| Universal components |21 UNSAT queries,one SAT premise counterexample,five altered-ledger controls |

Addresses/offsets/constants are hexadecimal; extents use B. E is SP at0x10061a2d0,F is the post-reservation working SP and K is the reader's working SP. Numeric SP formulas use u64 modular arithmetic; ordinary interval containment additionally assumes nonwrapping valid storage. Frozen profile addresses and model import targets are not native identities.

## Entry allocation and special stack-probe interface

At0x10061a2d4,the pre-indexed STP D11,D10 reserves128 B. The following stores save the other two SIMD low64 values and twelve GPRs in that area. At0x10061a2f4,FP is set112 B above that SP. The prefix then forms W9=0x10d50=68944 B before the probe call. Its size input is W9; the source does not put this size in X0.

| Source site | Interface/effect |
| --- | --- |
|0x10061a2f8 /0x10061a2fc | MOV/MOVK form W9=0x10d50 |
|0x10061a300..0x10061a308 | X17=0x1010b1e28; X16=[X17] |
|0x10061a30c | BLRAA X16,X17; original slot binds libSystem/___chkstk_darwin |
|0x10061a310 | SUB SP,SP,#0x10,LSL#12: reserve65536 B |
|0x10061a314 | SUB SP,SP,#0xd50: reserve3408 B |

The original probe pointer is an authenticated bind with IA key,diversity0 and address diversity enabled. The call supplies the slot address as X17. This is a source/fixup correspondence; hardware authentication and the live callee remain untested. The historical model explicitly skips probing and preserves registers. The geometry proof requires the real call,if considered,to return with SP preserved. [SE1,SE3,SE5]

The byte arithmetic is:

```text
saved state       = 128 B
local scratch     = 16*4096 B +3408 B = 68944 B =0x10d50 B
total reservation = 128 B +68944 B = 69072 B =0x10dd0 B

F  = E -69072 B
FP = E -16 B = F +0x10dc0 B

local scratch: [F,F+0x10d50) = [F,E-128 B)
saved state:  [F+0x10d50,E)
```

The retained [shared-root contract](daemon_shared_roots_report.md) independently supplies this geometry and source writers for the initial phase/table fields. The present increment extends the SP epoch to a particular reader/builder route; it does not relabel all protected-core operations or all native callers as equivalent.

## Ordered event audit and return premises

The retained route reaches core entry through adapter0x10065ffd8. After the probe event,the auditor starts at0x10061a310 and ends at the first builder-finish transfer after keyed-reader entry. Each interval is bounded by recorded PAC/control events. Its bytes are recaptured from the pinned image; every source site belongs to the recorded visited-site set. The decoder verifies that no unrecorded branch/call/return/system transfer occurs inside an interval. A PACIBSP event is handled as its own single-instruction interval.

For an imported call,the next source interval starts at call_site+4 under the normal-return/SP-preservation premise. For an internal call,the auditor records that return address,visits the helper entry/body and pairs RETAB with the expected caller continuation. The source helper saves/restores LR; correct return-target lifetime and authentication remain premises. A structural interval audit does not prove every target-selection expression or actual native return. [SE2-SE5]

The only SP writes after the initial saved-state reservation are:

| Region | Original SP writer(s) | Effect |
| --- | --- | --- |
| Post-probe core |0x10061a310,0x10061a314 |-65536 B,-3408 B,establish F |
| Called helper |0x100444e00 |-192 B relative to current caller SP |
| Called helper return |0x10044a3d8 |+192 B before RETAB |

All other captured daemon instructions preserve SP. Nine helper calls per profile are balanced; no internal helper is nested in another within this audited path. The helper's PACIBSP entry SP and RETAB exit SP agree,which is compatible with its SP-modifier convention. This does not prove possession of a native PAC key or successful authentication.

The source-derived minimum SP inside these original daemon intervals is E-69264 B=F-192 B. It is not the minimum SP of the entire native call chain: imported-callee internals are outside the audit and can use additional stack. The helper's temporary frame is [F-192 B,F),separate from the core locals. Unwrapped helper-frame geometry additionally requires E>=0x10e90; the local-area containment queries use E>=0x10dd0.

| Imported modeled name | Occurrences across12 profiles |
| --- | --- |
|libSystem/_malloc |120 |
|libSystem/_free |12 |
|libSystem/_os_log_type_enabled |12 |
|libSystem/___strcpy_chk |12 |
|CoreFoundation/_CFMachPortGetPort |12 |
|libSystem/_strnlen |12 |

These names come from pinned historical import records; the current audit does not freshly establish every native binding or implementation. The probe's original binding is separately decoded above. An explicit SAT control permits one imported call to return with SP advanced16 B and thereby breaks the final-frame equality. That abstract control demonstrates the need for the preservation premise; it is not evidence of a native ABI violation.

## Reader entry, both value branches and builder finish

Every audited profile has:

```text
core allocation -> SP=F
   |
   +-- selected subscription path and builder constructors
   |      imported calls: assumed normal SP-preserving return
   |      nine internal helper calls: source192 B reserve/restore
   |
   +-- keyed reader entry0x100847998: SP=F
            |
            +-- retained miss route -> population -> builder finish: SP=F
            |
            +-- found-value route: source-only no-SP-write extension
```

The source-only extension comprises ten first-match lookup ranges,nineteen existing-reader ranges and seven keyed-entry/found-frontier ranges. All36 have no SP write and contain no call; their control transfers are BRAA. Any normally completed finite concatenation within that checked block set preserves its incoming SP. Earlier entry/lookup/type/extent contracts supply the selected routing premises; arbitrary branch targets outside that set are not covered. [SE4,SE6]

Thus K=F is now source-compatible for the selected reader continuation rather than inferred from equal offsets or compiler-function membership. The retained corpus still contains zero executions of the found-value branch. Its reader/preparation semantics remain conditional source results; the extension is not a new execution witness.

The endpoint0x10090a400 is a common builder finish inside the protected-core workflow. It is not the outer protected-core return. The audit does not claim SP has been restored to E there; it is still F. Later result/stack-budget return protocols remain bounded by their earlier reports.

## Reader accesses within source-reserved locals

For nonwrapping source storage,the preparation's two envelopes satisfy:

| Region | F-relative interval | Placement result |
| --- | --- | --- |
| Preparation frame writes |[0x7e8,0x9bc) | Inside local scratch |
| Preparation frame reads |[0x9d8,0xae48) | Inside local scratch;188 B of sparse actual reads |
| Borrowed u32 output cell |[0x601c,0x6020) | Inside local scratch under the earlier caller contract |
| Missing-field helper argument |[0x10cb8,0x10cc8) | Inside local scratch under the earlier population contract |
| Saved guard |[0x10d38,0x10d40) | Prior shared-root guard location |
| Saved registers/SIMD low64 |[0x10d50,0x10dd0) | Above local scratch |

The read envelope's headroom is exactly:

```text
68944 B -44616 B =24328 B =0x5f08 B
```

These relations establish source geometry only. Source SP subtraction is not an OS mapping observation. Fit does not initialize prior input cells,establish writability of every owner,prevent BUF/OUT/frame aliasing,attest a stack canary or prove native access completion. The25 prior context-value producers remain unresolved. [SE3,SE6,SE7]

The earlier [metadata caution](daemon_reader_context_footprint_report.md) remains applicable: the compiler container at0x10065ffd8 has a64 B entry-prefix reservation,while the active selected workflow enters the separate large-frame core. The current source/event join supplies the appropriate conditional stack epoch; it does not turn compiler containment into frame ownership.

## IPC and architectural limits

This is the shared-core subscription operation from the earlier MIG61471 analysis. Reuse of the same core entry by RPC502 or other operations does not transfer their wire grammar,caller admission or selected control path. The source-audited CFMachPortGetPort call remains the earlier port-name accessor; no new right allocation/transfer/emission is established by this SP audit. Native incoming/outgoing endpoints and selector26/RPC502/700 pairing remain unresolved.

No target/native execution,new emulation,native API/IPC,IDA access,IDB mutation or memory-store update occurred. The historical event records/model addresses remain distinct from native control/port/ownership evidence.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| SE1 | Original source,probe fixup and frozen producer/profile identities are pinned. | Rehash source/generator/base probe; recapture each source interval and original probe pointer; reject altered source/control records. |
| SE2 | Ordered frozen events identify the selected intervals and modeled normal continuations. | Check every terminal instruction,all intervening control transfers,visited-site inclusion and internal call/RETAB pairing. This is not full data/control replay. |
| SE3 | Stack-probe and imported calls preserve SP on normal return; required owners permit execution. | Source prologue geometry and explicit import-preservation SAT counterexample; require actual native mapping/callee/PAC evidence before stronger claims. |
| SE4 | Internal helper returns normally to the paired caller with stable saved LR/slots. | Inspect complete5497-instruction body and its only two SP writes; retain hardware PAC and memory-alias premises. |
| SE5 | Capstone register/control metadata correctly identifies every source SP effect. | Recapture opcodes,retain all149 interval disassemblies and exact SP-writer ledger; unsupported SP writes/control transfers reject the audit. |
| SE6 | Earlier selected entry/lookup/reader/population contracts and same-frame routing apply. | Check36 no-SP-write/call ranges and milestone equalities; do not generalize to arbitrary outside blocks or the outer core return. |
| SE7 | Ordinary unsigned range containment uses valid nonwrapping storage. | Explicit E>=0x10dd0 bounds in containment queries; distinguish local reservation,actual mappings,initialized bytes and imported-callee stack use. |
| SE8 | Native endpoint/admission,prior-context producers and broad goal completion remain unknown. | Require same-build owner/caller/port/PAC evidence; preserve zero retained found-value executions and conditional scopes. |

## Complexity and validation scope

The auditor takes O(event instances+unique source bytes+source instruction instances checked for visited-site inclusion) time,with O(unique decoded intervals+event ledgers) storage. It performs structural source decoding and literal-SP arithmetic; it does not interpret general data instructions or execute a target CPU. The universal queries quantify SP arithmetic over arbitrary E with separate nonwrapping conditions for geometry. Solver time is additional,limited to15000 ms per query.

Twenty-one UNSAT queries cover probe register/modifier construction,core geometry,helper SP restoration,twelve profile milestone chains,four local-area containment checks,read-envelope headroom and saved-guard separation. One SAT premise control and five altered-ledger controls retain the evidence boundaries. Path and extension source-site counts have explicit overlap; they are not added as disjoint byte ranges.

## Bounded continuation opportunities

| Impact | Next target | Question resolved |
| --- | --- | --- |
| High | Actual native core-entry/SP/probe/return observations and caller owners. | Mapped stack lifetime and normal-return premises beyond source geometry. |
| High | Prior writes of the25 context inputs and all frame/TABLE roots. | Initialization and constraints on the recovered affine cache inputs. |
| High | Remaining builder fields/serialization consumers and same-build native selector26/RPC502/700 endpoints. | Complete representation/ownership transfer and daemon-kext/deeper pairing. |
| Medium | Other protected operations and adapter return-budget epochs. | Whether their SP lifetimes and caller-specific protocols share this geometry. |
| Low | Broaden source SP-effect checks to unrelated decoder entries. | Reusable frame invariants without assuming common compiler ownership. |

## Scoped quality gates

- QG1: Technical source/SP/interface facts require no normative conclusion.
- QG2: SE1-SE8 identify dependencies and falsification probes.
- QG3: Selected core-to-reader/builder-finish SP epoch,source-only found-reader extension and local geometry are covered; native ownership and broad interface completion remain unproved.
- QG4:128/68944/69072/192/69264 B reservations,44616 B read bound,24328 B headroom,u64 arithmetic and nonwrapping predicates are explicit.
- QG5:21 accepted UNSAT queries,one SAT premise control and five altered-ledger controls separate source audit,normal-return assumptions,metadata containment and actual native execution.
- QG6: Original bytes/fixups,frozen ordered events,producer identities and source-linked literal-SP semantics provide provenance; no new target/runtime execution occurred.
- QG7: Continuations remain bounded and impact-labeled; native pairing and full goal completion remain unknown.
