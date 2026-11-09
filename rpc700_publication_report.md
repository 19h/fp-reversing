# RPC700: bounded launchd publication and native environment observations

At 2026-11-05 12:12:31 UTC, read-only `launchctl print` reported running fairplayd with host-special endpoints17 and31. The running managed-app daemon and GUI agent each had two endpoints, none printed with a host-special association. A nonrecursive census of931 plists in four launchd directories found19 `HostSpecialPort` declarations covering18 distinct indices, with no34. These observations do not establish slot34 vacancy or an RPC700 receiver. The receiver and a native alternate-mode caller remain **unknown**.

This extends the [original RPC700 namespace and candidate analysis](rpc700_namespace_report.md), whose kernel getter, mode selection, SDK names and candidate exclusions remain unchanged. It adds native environment inspection, not a FairPlay request or successful daemon/kext exchange.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| RP1 | The four enumerated directories delimit this census |931-file negative declaration result | Enumerate per-user, embedded/XPC, alternate volume and generated job sources separately; a declaration there falsifies any wider absence claim |
| RP2 | plistlib and Apple's read-only plutil conversion preserve the selected plist values | Labels, MachServices and19 declarations | Rehash every original and recapture; compare parser outputs for disputed entries |
| RP3 | launchctl's selected text represents the named domain/job at the recorded instant | Running states, ten endpoints and two host associations | Repeat explicitly as a new timestamped observation; do not overwrite the frozen snapshot |
| RP4 | Printed endpoint handles are observation-local values of unspecified namespace here | Handle inventory only | Resolve actual IPC namespace and kernel objects independently; equality with a guest handle is not identity evidence |
| RP5 | Current kernel UUID is a useful corpus discriminator | UUID agrees with analyzed collection | Verify mapped kernel bytes/build and kext identity separately; UUID equality does not attest every runtime byte |
| RP6 | launchctl's program path identifies a configured executable, not its mapped slice | Job-to-path context | Obtain native loaded-image UUID/hash evidence before assigning the analyzed daemon's exact code to this live process |
| RP7 | Effective service listings and disk declarations are different evidence | Absence of printed34 does not prove vacancy | Check actual host slot registration/ownership through authorized observation or recover the programmatic setter and caller statically |
| RP8 | Static prior mode-selection analysis applies only to its pinned input | Conditional mode1/17/502 versus other/34/700 relationship | Recheck original bytes and caller mode provenance; a current running job alone does not prove that branch executed |

## Native publication snapshot

The [frozen observations](triage_evidence/rpc700_publication_observations.json) contain command arguments, start/end UTC timestamps, exit codes, full-output SHA-256/length, selected root fields and complete endpoint blocks. Unrelated environment/resource text is omitted. All three commands exited0 without stderr; all ten endpoints printed `active=1`, `managed=1`, `reset=0`, `hide=0`, `watching=0`. The snapshot spans 12:12:31.725246 through12:12:31.741320 UTC. PIDs and endpoint handles can subsequently change [RP3,RP4].

| Domain/job | State/PID at snapshot | Program |
| --- | --- | --- |
| system/com.apple.fairplayd | running/17762 | /System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd |
| system/com.apple.managedappdistributiond | running/67387 | /System/Library/Frameworks/ManagedAppDistribution.framework/Support/managedappdistributiond |
| gui/501/com.apple.managedappdistributionagent | running/67386 | /System/Library/Frameworks/ManagedAppDistribution.framework/Support/managedappdistributionagent |

| Job | Endpoint | Printed handle | Printed host-special association |
| --- | --- | --- | --- |
| fairplayd | com.apple.fairplayd.xpc |0x11a7df | none |
| fairplayd | com.apple.unfreed |0x2603 |17 (fairplay) |
| fairplayd | com.apple.fairplayd |0xfad0b | none |
| fairplayd | com.apple.fpsd.sim |0x125893 | none |
| fairplayd | com.apple.fpsd |0x1262f3 | none |
| fairplayd | com.apple.arcade.fpsd |0x2503 |31 (fairplayd) |
| managedappdistributiond | com.apple.managedappdistributiond.xpc |0x10605b | none |
| managedappdistributiond | com.apple.managedappdistributiond.xpc.agent |0x123f5b | none |
| managedappdistributionagent | com.apple.managedappdistributionagent.xpc.legacy |0x14d61b | none |
| managedappdistributionagent | com.apple.managedappdistributionagent.xpc |0x12cf4b | none |

The configured fairplayd path agrees with the prior framework location; live daemon/kext mapped-image identity is not established [RP6]. The current `sysctl -n kern.uuid` output is `9B65BD6E-027B-34D1-A22B-AC03DCCFFC84`, equal after case normalization to the analyzed kernel UUID [RP5]. Six printed fairplayd endpoints do not imply six registration calls in the analyzed main: the prior five-service code recovery and this effective listing describe different scopes. The `.xpc` endpoint requires its own producer/consumer linkage.

```text
Pinned static kext mode selection        Native launchd snapshot
 mode == 1 -> slot17 -> RPC502  ........ com.apple.unfreed, host17
 mode != 1 -> slot34 -> RPC700  ........ receiver UNKNOWN
                                      com.apple.arcade.fpsd, host31
                                      managed-app jobs: four endpoints
                                      no printed host association there

Dots mean contextual correspondence, not an observed message or port identity.
```

## Declaration census and parser edge case

The [source census](triage_evidence/rpc700_publication_source.json) includes each original path, byte length, SHA-256, parser selection, label/program fields, MachServices and every recursively found `HostSpecialPort`. Roots are `/System/Library/LaunchDaemons`, `/System/Library/LaunchAgents`, `/Library/LaunchDaemons`, `/Library/LaunchAgents`; selection is only immediate `*.plist` files [RP1]. This excludes user Library directories, nested bundles, generated declarations and programmatic host registration.

Python parsed930 files. `/System/Library/LaunchAgents/com.apple.familycircled.plist` has `<?xml version=1.0 encoding=UTF-8?>`, rejected by plistlib's XML parser. `/usr/bin/plutil -convert json -o - <path>` exited0 and supplied the remaining parsed values. It has no HostSpecialPort. The original was not rewritten. Its original96-byte prefix and fallback-output hash/length are retained [RP2]. Treating the Python exception as a missing file would have overstated coverage.

| Declared index | Mach service | Declaring job label |
| --- | --- | --- |
|9 | com.apple.auditd | com.apple.auditd |
|10 | com.apple.system.Kernel[UNC]Notifications | com.apple.kuncd |
|11 | com.apple.automountd | com.apple.automountd |
|12 | com.apple.lockd | com.apple.lockd |
|13 | com.apple.tailspind.ktrace_background | com.apple.tailspind |
|14 | com.apple.sandboxd | com.apple.sandboxd |
|15 | com.apple.KernelManagementPingServer | com.apple.kernelmanagerd |
|17 | com.apple.unfreed | com.apple.fairplayd |
|18 | com.apple.MobileFileIntegrity | com.apple.MobileFileIntegrity |
|19 | com.apple.gssd | com.apple.gssd |
|23 | com.apple.sysdiagnose.kernel.ipc | com.apple.sysdiagnose; two plists |
|27 | com.apple.resource_notify.host | com.apple.symptomsd |
|29 | com.apple.security.AppleSystemPolicy.mig | com.apple.security.syspolicy |
|30 | com.apple.FileCoordination.kernel.ipc | com.apple.FileCoordination |
|31 | com.apple.arcade.fpsd | com.apple.fairplayd |
|33 | com.apple.mmaintenanced.server | com.apple.memory-maintenance |
|35 | com.apple.doubleagentd | com.apple.filesystems.doubleagentd |
|36 | com.apple.diskimagespawner | com.apple.diskimagespawner |

These are disk declarations, not a census of kernel port objects. The installed SDK's `HOST_MANAGEDAPPDISTD_PORT=34` remains a naming lead from the previous report. No receiver assignment follows from the shared word `managedappdistribution` [RP7,RP8].

## Verification and reproducibility

[Recovery](triage_evidence/recover_rpc700_publication.py) records the original census and one frozen observation. It deliberately refuses to overwrite an existing observation. [Validation](triage_evidence/validate_rpc700_publication.py) recaptures the static census, independently parses the saved endpoint blocks and checks exact declarations, UUID and reported fields. It does not re-query launchd. Eight controls alter slot34, file count, parser outcome, active state, host17, endpoint count, UUID or target-effect scope; all are rejected. This checks artifact consistency and the stated bounded interpretation, not launchd's internal implementation or native FairPlay functionality.

```sh
python3 triage_evidence/validate_rpc700_publication.py
python3 triage_evidence/verify_rpc700_publication_publication.py
```

The recovery and validator cost O(B+T) time and O(N+L) space, where B is scanned plist bytes, T is selected observation text bytes, N is retained census metadata and L is the largest parsed plist/text. The publication audit costs O(A+K) time for total artifact bytes A and local links K. SHA-256 checks are byte-based; indices/counts are dimensionless integers. No new target instruction execution, target emulation, FairPlay request, service change, kernel-port-object attestation or successful RPC502/700/selector26 exchange occurs. Native launchd interrogation and native plist/sysctl inspection do occur; a global claim of zero native IPC would be inaccurate.

## Bounded continuation

| Impact | Evidence gap | Next discriminating analysis |
| --- | --- | --- |
| High | RPC700's actual receiver and non-mode1 producer unknown | Recover original host-special setter callers and alternate-mode constructor provenance; distinguish configured publication from actual port ownership |
| High | Live slot34 occupancy unknown | Add timestamped ownership/registration evidence; preserve a null slot, unavailable observation and absent disk declaration as separate outcomes |
| Medium | Managed-app FairPlay relationship remains a locator | Trace original `fairplayContextWithError:` callers and dispatch targets into CoreFP; require a message/selector link before assigning RPC700 |
| Medium | fairplayd.xpc has no producer linkage here | Recover its XPC entry and application dispatch separately from five classic Mach service registrations |
| Low | One parser exception would have hidden coverage | Retain native-parser fallback and original hashes; investigate other formats only if additional roots are included |

## Quality gates

QG1: Factual interface/environment analysis; no normative conclusion.

QG2: RP1-RP8 state dependencies and falsification probes.

QG3: This increment covers publication declarations, three live job observations, endpoint handles and the slot34 evidence boundary. The full investigation remains active.

QG4: Counts, byte hashes, UTC timestamps and complexity are explicit; nineteen declarations differ from eighteen indices and ten live endpoints.

QG5: Parser failure/fallback, disk/runtime distinction, task versus host namespace, configured versus mapped image, absent versus vacant and classic versus XPC services are separated.

QG6: Original plist hashes, selected native command output, inspection-tool hashes, kernel UUID and previous pinned binary analysis supply provenance. Unknown receiver and mapped-image identity are explicit.

QG7: Impact-labeled continuation is bounded to discriminating interface evidence.

[Delivery preservation checks](triage_evidence/rpc700_publication_delivery.json) and [quality metadata](triage_evidence/rpc700_publication_quality_gates.json) cover this increment only. The original input files and prior evidence remain preserved except for the explicitly owned report/index/publisher updates.
