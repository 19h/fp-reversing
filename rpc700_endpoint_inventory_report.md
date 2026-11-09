# RPC700 receiver search: cache references and frozen endpoint inventory

A broader read-only inventory still does not establish a host-special slot34 publisher or RPC700 receiver. The pinned shared cache contains one verified slide-chain reference to the user host-special getter and none to the setter. Its recovered shared getter stub has three direct caller sites, selecting slots 2, 2, 1. Separately, 880 successful Apple-job queries in two launchd domains report 2038 endpoints and eighteen host-special associations, none for slot34. These are bounded source and observation results, not proof that slot34 is vacant or unused [EI1-EI7].

[Original cache inventory](triage_evidence/rpc700_endpoint_inventory_source.json), [frozen native observations](triage_evidence/rpc700_endpoint_inventory_observations.json), [checks](triage_evidence/rpc700_endpoint_inventory_checks.json), [capture](triage_evidence/recover_rpc700_endpoint_inventory.py), [validator](triage_evidence/validate_rpc700_endpoint_inventory.py), [delivery](triage_evidence/rpc700_endpoint_inventory_delivery.json), [quality gates](triage_evidence/rpc700_endpoint_inventory_quality_gates.json).

This extends the [three-job publication snapshot](rpc700_publication_report.md), [host-special registration implementation](host_special_registration_report.md) and [conditional mode/slot/RPC mapping](text_pager_interface_report.md). The kext's mode1/slot17/RPC502 versus other-mode/slot34/RPC700 relationship remains conditional. The earlier three direct provider callers pass mode1; this increment does not find an alternate-mode constructor.

```text
Original cache v5 chain reference at 0x1e2103890
  -> host_get_special_port implementation 0x180548a54
       ^
       | authenticated shared stub 0x188079af0
       +-- crash reporter setter helper: selector2
       +-- crash reporter array getter: selector2
       +-- dispatch host-port initializer: selector1

Frozen launchd metadata: system + gui/501, listed com.apple. jobs
  -> 880 job queries -> 2038 endpoints -> 18 host associations
                                      -> slots17/31 for FairPlay
                                      -> no printed slot34 in this scope

Kernel slot34 contents / receiver / RPC700 processing: UNKNOWN
```

## Pinned static sources and cache coverage

Cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. The original libsystem_kernel UUID is `f2bceb9a-0fec-3c92-b6ea-8e37157050a8`. Original file hashes, image-header bytes, image-table bytes, mapping records, slide-info hashes and selected scan-range hashes are retained. All addresses are preferred static addresses, not native loaded pointers [EI1].

The cache image table contains 4113 entries. All corresponding original Mach-O headers are parsed. Declared `__got` and `__auth_got` sections contain 1815207 words. None of the five matching verified slide-chain slots below belongs to any declared image section. The earlier GOT-only negative result is therefore narrower than the final chain inventory. Zero-size image-declared stub sections likewise do not describe the shared stubs used by these recovered callers [EI2,EI3].

| Exact exported target / role | Implementation | Verified v5 slot(s) |
|---|---|---|
| `_host_get_special_port` | `0x180548a54` | `0x1e2103890` |
| `_host_set_special_port` | `0x18056895c` | None in scanned chains |
| `_mach_ports_lookup`, control | `0x180553a14` | `0x1e2103b60`, `0x2696d45a8` |
| `_mach_ports_register`, control | `0x18054f880` | `0x1e2103b68`, `0x2daa3cd40` |

All fourteen mappings with slide metadata use version5. Walking every original page chain visits 30802349 encoded pointers. The five matches above are independently rechecked through the existing page-chain membership reader. Two known libxpc Mach-call pointer slots are positive controls. This excludes further references to these exact target addresses among those chains. Absolute/non-chain values, interior targets, computed calls, dynamically obtained pointers, separately loaded images and other address spaces remain outside that exclusion [EI2].

Thirty-six executable mappings with raw mapping flag bit3 set contain 2477972 aligned candidate starts for the selected 16 B ADRP/ADD/LDR/BRAA stub shape. The scan finds one matching getter stub at `0x188079af0`. Original instructions compute slot `0x1e2103890`; its authenticated word decodes to `0x180548a54`. This stub and its pointer are outside image-declared sections in the captured headers. The raw flag and selected instruction shape delimit this scan; other code forms are not excluded. Hardware pointer authentication is not exercised [EI3].

## Direct caller sites and Mach emission boundary

The immediate B/BL scan covers 65480381 aligned words in every executable mapping portion from which an architectural signed-imm26 branch could reach the getter implementation, setter implementation or discovered getter stub. The upper source boundary includes `target+2^27 B`, which is reachable using displacement `-2^27 B`. Selected candidates are independently decoded and assigned to original compiler-bounded bodies [EI3,EI4].

| Original nlist role | Caller entry | Call site | W1 / W2 / X3 immediately before call |
|---|---|---|---|
| `_os_crash_set_reporter_port` | `0x181ed4660` | `0x181ed46b8` | -1 / 2 / SP+12 B |
| `_os_crash_get_reporter_port_array` | `0x181ed4728` | `0x181ed4778` | -1 / 2 / SP+8 B |
| `__dispatch_mach_host_port_init` | `0x185537c74` | `0x185537ca0` | -1 / 1 / SP+12 B |

The first two bodies belong to original libsystem_darwin; the third belongs to libdispatch. All three transfer through the shared getter stub. SDK constants name selectors1/2 `HOST_PORT`/`HOST_PRIV_PORT`, and node-1 `HOST_LOCAL_NODE`. Their values, types and call-site argument widths are verified; actual returned names, rights and native caller outcomes are unknown. The word `set` in the crash-reporter helper's name does not turn this selected host getter call into a host-slot publication call [EI4].

No direct B/BL to either host-special API implementation occurs in these scanned source ranges, and no direct setter call is found. This does not exclude indirect setter calls, other wrappers, external executables such as launchd, other architectures or runtime-generated code. It also does not identify RPC700's receiver [EI3].

The fresh getter/setter bodies retain their known Mach transport calls at `0x180548acc` and `0x1805689e4`, respectively, both targeting `0x18055a894`. Their request/reply IDs remain412/512 and413/513 as documented in the prior registration report. This increment identifies additional original library call sites, without sending a host-special request or a FairPlay protocol message. A destination name, reply right and embedded/returned port descriptor remain distinct objects [EI4,EI7].

## Frozen native observation scope

The two domain queries ran from `2026-11-05T18:25:51.841748+00:00` through `18:25:51.867591+00:00`. Job queries ran from `18:26:33.821148+00:00` through `18:26:37.332934+00:00`. The combined observation window is approximately 45.5 s; the job-query batch approximately 3.51 s. These are query timestamps, not simultaneous host-slot observations [EI5].

| Domain | Listed service rows | Selected `com.apple.` labels | Successful job queries |
|---|---:|---:|---:|
| `system` | 443 | 428 | 428 |
| `gui/501` | 481 | 452 | 452 |
| Total | 924 | 880 | 880 |

Commands use only `/bin/launchctl print`. Four workers query labels from the frozen domain listings. Full stdout lengths/hashes, timestamps and exit statuses are retained; structural root fields and complete endpoint blocks are retained as text and independently reparsed. Unrelated environment text and non-Apple service identities are omitted. Full raw stdout is not retained, so its stored hash is capture metadata, not an independently replayable full-output attestation [EI5].

This selection excludes other users/domains, labels outside the exact `com.apple.` prefix, unmanaged processes, externally hosted endpoints outside selected job output, jobs appearing after domain enumeration and hidden/unprinted kernel state. Every selected query succeeded, so this cohort has no query-error ambiguity. That is not a whole-system service/registration census [EI5,EI6].

## Printed host-special associations

| Printed index | Service | Printed active |
|---|---|---:|
| 10 | `com.apple.system.Kernel[UNC]Notifications` | 0 |
| 11 | `com.apple.automountd` | 1 |
| 12 | `com.apple.lockd` | 0 |
| 13 | `com.apple.tailspind.ktrace_background` | 1 |
| 14 | `com.apple.sandboxd` | 1 |
| 15 | `com.apple.KernelManagementPingServer` | 1 |
| 17 | `com.apple.unfreed` | 1 |
| 18 | `com.apple.MobileFileIntegrity` | 1 |
| 19 | `com.apple.gssd` | 0 |
| 23 | `com.apple.sysdiagnose.kernel.ipc` | 0 |
| 24 | `com.apple.ReportCrash.DirectoryService` | 1 |
| 27 | `com.apple.resource_notify.host` | 1 |
| 29 | `com.apple.security.AppleSystemPolicy.mig` | 1 |
| 30 | `com.apple.FileCoordination.kernel.ipc` | 1 |
| 31 | `com.apple.arcade.fpsd` | 1 |
| 33 | `com.apple.mmaintenanced.server` | 0 |
| 35 | `com.apple.doubleagentd` | 0 |
| 36 | `com.apple.diskimagespawner` | 0 |

There are eleven active and seven inactive associations in these records. All eighteen print `managed=1`. A printed host association can therefore coexist with `active=0`; it must not be treated as a direct reading of a kernel slot. The previously recovered launchd publisher can update its local index cache after a failed setter, which is another reason to keep metadata and proven kernel mutation distinct [EI5,EI6].

FairPlay still prints six endpoints, with `com.apple.unfreed` associated with17 and `com.apple.arcade.fpsd` with31. The two managed-app jobs each print two endpoints, with no host-special association. Their four endpoint records now have `active=0, watching=1`; the earlier 12:12:31 UTC snapshot had `active=1, watching=0`. This establishes a difference between two timestamped printed states, not its cause, exact transition time, a kernel-port lifetime or an RPC700 relationship. Reused printed handle values do not prove the same underlying object across epochs [EI6].

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| EI1 | Pinned cache image table/files delimit static claims; no native loaded-image pairing is assumed. Addresses and source inventory depend on this scope. | Rehash used files and header/table bytes; compare all 4113 image addresses and original UUID/nlist bindings. A changed image/cache invalidates extrapolation. |
| EI2 | Original v5 page chains delimit pointer enumeration, with target addresses taken from exact exports. Negative reference findings depend on that domain. | Walk all fourteen slide-bearing mappings; recheck five matches through the separate membership reader; find the two known Mach-call control slots; reject changed target. Non-chain/dynamic/interior references remain excluded. |
| EI3 | Raw bit3 executable mappings and the selected four-instruction shape delimit stub discovery; direct B/BL encoding/range delimit the branch census. | Verify every eligible mapping/range and all candidate bytes; decode selected stubs/calls; prove signed-imm26 round-trip including its negative endpoint; reject branch-word and range-end changes. Indirect/other-shape paths remain open. |
| EI4 | Original compiler starts and valid ABI arguments delimit selected caller interpretations. Actual objects, rights and hardware PAC are unknown. | Retain seven complete bodies; check original names and immediate node/index/output-pointer instructions; compare transport bodies to prior bytes; compile public types; reject selector alteration. |
| EI5 | Frozen launchctl output represents the named domain/job at each recorded query time. Parsing and printed-state findings depend on this observation boundary. | Independently reparse all 2038 retained endpoint blocks, reconcile880 labels/queries, validate times/statuses/hashes; reject missing query or altered field. Full raw output is not retained and the queries are not atomic. |
| EI6 | Printed endpoints/indices/handles are metadata, with no proven native slot occupancy or kernel-object identity. Temporal comparison is limited to the two snapshots. | Require native registration/ownership history and object identity before assigning a receiver; absence, inactive metadata and getter success are separate outcomes. Other domains/labels remain outside the cohort. |
| EI7 | Prior kext mode, provider and message-family results retain their published boundaries. No new alternate-mode producer or successful transaction is inferred. | Preserve prior bytes/reports and frozen observations; keep slot17/RPC502, slot31 service and unknown slot34/RPC700 separate; reject an asserted receiver identity. |

## Bounded additional context

| Impact | Pattern / implication | Remaining boundary |
|---|---|---|
| High | Shared stubs and authenticated pointer slots can lie outside every original image-declared section. | GOT/stub-section-only searches cannot exclude these cache-optimized references; arbitrary computed calls remain unknown. |
| High | The expanded job cohort still has no printed34, while current cache caller selectors are1/2. | Actual slot34 registration, native alternate-mode use and receiving implementation remain unknown; no vacancy/non-use conclusion follows. |
| Medium | Host association, endpoint activity and successful kernel registration are distinct. | Eleven active/seven inactive printed associations do not attest kernel objects or setter outcomes. |
| Medium | Managed-app endpoint states changed between snapshots. | No causality, precise event time, message delivery or receiver assignment is established. |
| Low | The direct-branch lower displacement endpoint affects the upper source scan boundary. | Auxiliary decoder coverage is separate from complete control-flow reachability. |

## Validation and quality gates

Fresh static recapture passes. Seven complete bodies contain 513 instructions/2052 B. Fourteen selected instruction assertions cover three call-site argument groups and two transport calls. Eleven SDK assertions pass in one syntax-only compilation. One scalar query is unsatisfiable over the complete aligned signed-imm26 displacement domain. Eight evidence alterations are rejected. All880 selected job queries and2038 endpoint blocks are checked without native re-query. Preserved capture-code text and original read-only command arguments distinguish observation provenance from static checks.

Capture is O(B+I+C+W) time for cache bytes B, image/header metadata I, chain entries C and selected branch words W. Heap space is O(retained metadata + matches + largest selected stub mapping + largest parsed artifact); source enumeration does not retain every one of the 30.8 million pointers. Read-only virtual mappings additionally require O(largest mapped backing-file size) address space; resident mapped pages depend on the operating system. Observation collection uses four workers, O(output bytes) parsing time and O(retained endpoint text) storage. Publication/audit costs O(total artifact bytes + local links). Addresses and encoded pointers are64 bit; Mach names are32 bit; instructions are4 B; indices are dimensionless. The solver proves auxiliary address arithmetic only, not whole-machine semantics.

Native launchd interrogation occurs in this increment:882 read-only queries. A global claim of zero native IPC would be inaccurate. No FairPlay protocol requests, recovered-code execution/emulation, registration changes, entitlement changes, kernel-port-object inspection or IDB mutation are performed by the analysis. Native process background execution and ownership remain unobserved.

QG1: Factual interface, metadata and routine analysis requires no normative premise.

QG2: EI1-EI7 state assumptions, dependent findings and falsification probes.

QG3: The increment covers the declared cache reference/stub/direct-caller census and frozen selected-domain endpoint inventory. Receiver identity, alternate-mode use and the full interface goal remain unproved and active.

QG4: Counts, widths, byte ranges, UTC windows, ABI types, signed branch endpoints and complexity are explicit and checked.

QG5: Declared sections versus shared cache areas, pointers versus direct branches, names versus objects, metadata versus registration, active versus inactive and time-separated snapshots remain distinct.

QG6: Original bytes/table/UUID/nlist, exact exports, independent membership/endpoint checks, frozen command metadata, SDK compilation, solver query and file/tool hashes are retained. Local evidence sufficed; no new IDA fact is asserted.

QG7: Impact-labeled shared-stub, registration/activity, temporal-state and branch-boundary findings are bounded above. No successful daemon/kext exchange or RPC700 ownership claim is made.
