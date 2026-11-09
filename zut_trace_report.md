# fairplayd: evidence from the zut trace and reconstruction artifacts

The supplied trace establishes service receive-right acquisition, discovery of a matching FairPlayIOKit service, and an unsuccessful UserClient open. The open reply contains `0xe00002c2` (`kIOReturnBadArgument`) and a null connection port. It does not establish a selector-26 transaction or a kernel-to-daemon RPC502/700 exchange. The most useful next investigation is the open failure and the host task identity used by the bridge.

## Scope, provenance, and assumptions

Analysis date: 2026-11-01. `T:n` means line n of [/Users/___/Downloads/zut/annotated-strace-rax-user.txt](/Users/___/Downloads/zut/annotated-strace-rax-user.txt). The producer command was supplied by the user:

```sh
rax-user --strace --strace-pc --strace-mach-msg fairplayd.arm64e &> annotated-strace-rax-user.txt
```

The capture has 1,748 lines; SHA-256 `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`. Its exact producer version, runtime configuration, host kernel build, and host kext image are unknown. The daemon was not rerun. No input, IDB, or RAX source was changed.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| A1: the supplied capture corresponds to the stated command and has no omitted events within its recorded interval | Observed sequence and bounded absence claims | Preserve its hash; repeat with producer hash, configuration, timestamps, and output continuity recorded. There is no independent attestation of the historical run. |
| A2: standard Darwin arm64 little-endian Mach message layouts apply | Field names, rights, MIG routine names | All 44 printed message headers were decoded from hex and checked against their annotations. Descriptor lengths and 22 request/reply pairs were checked. Primary XNU definitions provide a separately versioned interpretation. |
| A3: the inspected current RAX implementation explains the historical bridge | Host task/credential explanation, locally synthesized host-special-port failure | Current source commit and file hashes are recorded; compare the historical executable/build to this source. These explanations remain conditional until matched. |
| A4: inspected XNU implementation paths apply to the host kernel | Candidate explanation of `BadArgument` through `initWithTask` failure | XNU source is pinned, but is not established as the running host revision. Match the host build and inspect its implementation/logs. |
| A5: matching section bytes permit reuse of the loaded daemon's code addresses | Static code correlation with the zut image | UUID and all 13 `__TEXT` section hashes match. Data outside those sections, runtime rebases, PAC state, signature identity, and ASLR still require separate checks. |

[Decoded capture and section comparisons](triage_evidence/zut_trace_decoded.json), [live IDB identity snapshot](triage_evidence/zut_idb_identity.json), [XNU source manifest and derived MIG IDs](triage_evidence/zut_xnu_reference.json), and [candidate RAX source identity](triage_evidence/zut_rax_context.json) retain the supporting data. The decoder checks raw bytes rather than trusting the printed field annotations.

## Binary correspondence

| Property | zut thin image | Loaded daemon IDB `6b117c693e3b` |
| --- | --- | --- |
| Input | `/Users/___/Downloads/zut/fairplayd.arm64e` | Recorded input `/Users/___/Downloads/fairplayd`; unavailable at analysis time |
| Whole-file SHA-256 | `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` | Recorded input SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7` |
| Mach-O UUID | `204741e9-b89f-32b4-9321-51f3975c7cac` | Same |
| Preferred base | `0x100000000` | Same |
| `__TEXT,__text` | 14,849,960 bytes; SHA-256 `94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e` | Same address, length, and bytes |
| Other `__TEXT` sections | 12 sections, including constants, stubs, embedded plist, and unwind data | All 12 hashes match |

The whole-file hash difference is now resolved: `/Users/___/Downloads/fpx/fairplayd` has the IDB-recorded universal-file SHA-256, and its arm64e slice at file offset 3407872, length 17668912 bytes, is byte-for-byte identical to the zut thin image. The IDB-recorded input path remains unavailable, but the original container is present at this alternate path. See [container identity](triage_evidence/daemon_container_identity.json). [A5]

## Observed sequence and ports

All port names below are guest task-local names unless explicitly marked host. A numeric equality across namespaces does not identify the same port. Five service-name requests use ID `1073742030` (`0x400000ce`), and replies use `536870912` (`0x20000000`). Each request includes the bootstrap port as a `COPY_SEND` descriptor. Each reply transfers a receive right. This is evidence of acquiring server endpoints, consistent with check-in; it is not an incoming FairPlay work request. The exact private XPC operation name is not independently established.

| Service string in request | Send / reply lines | Receive right delivered | Subsequent insertion into guest port set `0x1003` |
| --- | --- | --- | --- |
| `com.apple.unfreed` | 1500 / 1516 | `0xe03`, descriptor at T:1525 | T:1539 |
| `com.apple.fairplayd` | 1541 / 1557 | `0x1303`, T:1566 | T:1573 |
| `com.apple.fpsd` | 1575 / 1591 | `0x1403`, T:1600 | T:1607 |
| `com.apple.arcade.fpsd` | 1609 / 1625 | `0x1503`, T:1634 | T:1641 |
| `com.apple.fpsd.sim` | 1643 / 1659 | `0x1603`, T:1668 | T:1675 |

The outgoing service requests go to guest bootstrap send right `0x707`; the bridge logs host destination `0x80b` and host reply port `0xc03`. Replies arrive on guest special reply port `0xb03`. Earlier, task special-port selector 4 returned `0x707` (T:1354-1364). Selector 4 is `TASK_BOOTSTRAP_PORT` in the primary [task special-port definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/task_special_ports.h#L76). The later task special-port selector 10 receives `0xa03` (T:1391-1402); this is the debug-control slot, not host slot 17.

```text
guest bootstrap 0x707 -- named service requests --> bridge host 0x80b
guest reply     0xb03 <-- receive rights ----------- host reply 0xc03
                              |
                 0xe03, 0x1303, 0x1403, 0x1503, 0x1603
                              |
                       guest port set 0x1003

guest host 0xc03 -- host_get_io_main --> guest IOKit main 0x1703
                                              |
                           matching -> iterator 0x1803
                                              |
                             next -> service 0x1903
                                              |
                              open type 0 -> result 0xe00002c2
                                             connection MACH_PORT_NULL
```

The IOKit sequence is:

| Send / reply lines | Request / reply IDs | Routine | Destination and result |
| --- | --- | --- | --- |
| 1677 / 1681 | 205 / 305 | `host_get_io_main` | Guest host `0xc03` returns send right `0x1703` |
| 1687 / 1692 | 2877 / 2977 | `io_server_version` | Guest `0x1703` -> bridge host `0xf03`; result 0, version `0x134647a` |
| 1699 / 1709 | 2881 / 2981 | `io_service_get_matching_services_bin` | Same destination; returns iterator send right `0x1803` |
| 1715 / 1720 | 2802 / 2902 | `io_iterator_next` | Guest iterator `0x1803` -> host `0x1103`; returns service send right `0x1903` |
| 1726 / 1736 | 2862 / 2962 | `io_service_open_extended` | Guest service `0x1903` -> host `0x1503`; connection null, result `0xe00002c2` |

The routine IDs were independently derived from subsystem base 2800 and the preprocessed routine/skip sequence in the pinned primary [device.defs](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/device/device.defs). The binary matching dictionary contains `IOProviderClass = com_apple_driver_FairPlayIOKit` (T:1699-1706). The returned service's registry identity and binary UUID were not queried; its equivalence to the statically analyzed kext is unknown.

The host reply port for these IOKit calls is `0x1603`, while the guest reply port is `0x507`. Host `0x1503`, used as the service destination, is unrelated to the identically numbered guest receive right for `com.apple.arcade.fpsd`. Likewise, host reply `0x1603` does not identify the guest `com.apple.fpsd.sim` endpoint.

## Exact open failure and interpretation

The 80-byte request has two descriptors: guest task `0x203`, disposition `COPY_SEND`, and an OOL region with address 0 and length 0. The connection type at message offset `0x40` is 0; the explicit NDR record is at `0x44`; the properties count at `0x4c` is 0. The 52-byte reply has one port descriptor, name 0; its result at `0x30` is little-endian `c2 02 00 e0`. The transport trap returns 0 (T:1742). Application-level open failure therefore coexists with transport success. Apple's [IOReturn definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/IOKit/IOReturn.h#L138) identify this result as `kIOReturnBadArgument`.

Under the inspected XNU implementation, the normal complex reply's result corresponds to `*result`, populated after `service->newUserClient(...)`; early invalid-owning-task checks instead return a routine error. This shape favors investigating UserClient construction over assuming a malformed Mach header. It does not identify the particular failing check on an unmatched host build. [A2, A4; primary IOUserClient.cpp lines 4119-4182 and 4333-4338 in the source manifest.]

An entitlement failure remains a concrete candidate despite the `BadArgument` label. In the supplied kext, `initWithTask` at `0xfffffe000a5040d4` returns false when all three relevant entitlements are absent or no entitlement equals `kOSBooleanTrue` (C:7563-7640). The generic [IOService::newUserClient implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/iokit/Kernel/IOService.cpp#L7732) maps a false `initWithTask` result to `kIOReturnBadArgument`. This establishes compatibility with the observed error, not its cause. [A4, A5; host kext equivalence remains unproved.]

Current RAX source maps an exported guest `KObject::Task` to the emulator's host task (`bridge/translate.rs:112-122`, `bridge/host.rs:381-383`), and describes service-visible credentials/audit identity as belonging to the host process (`bridge/mod.rs:1-14`). [A3] Static `codesign -d --entitlements :- fairplayd.arm64e` finds `com.apple.private.FairPlayIOKitUserClient.access = true` in the guest file. That does not establish this entitlement on the emulator's actual host task. The capture reports UID/EUID 501 and GID 20 (T:1454-1459); the embedded plist instead specifies `mobile`. Kernel rejection logs and the effective host-task entitlements were not captured.

After the failed open, guest service and iterator rights are deallocated (T:1743,1745), and the emulator reports exit status 0 (T:1748). Exit status alone is not evidence of successful driver initialization. The preceding `stat64`/`mkdir` failures are `EACCES` (T:1479-1480); their path strings are not printed, so the affected directory is unknown.

## Host special-port 17 and reverse RPC limits

The only captured `host_get_special_port` request is T:1489, with local node -1 and selector **1**, followed by `KERN_INVALID_ARGUMENT`. It is not a lookup of slot 17. Current RAX's local MIG handler rejects this host-privileged operation when called through its guest host interface (`mig/host.rs:156-166`); source applicability is conditional on A3. This result does not show that native host slot 17 is absent.

The matching embedded plist at preferred address `0x101034841` declares `com.apple.unfreed` with `HostSpecialPort = 17`. Primary [host special-port definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/host_special_ports.h#L92) name slot 17 `HOST_UNFREED_PORT`. Together with the observed unfreed receive right, this identifies a specific endpoint-publication hypothesis. Publication and native slot contents during this historical emulator run were not captured. A subsequent [native launchctl snapshot](triage_evidence/native_fairplayd_launchctl.txt) reports `com.apple.unfreed` active on slot17; the kext port-object correspondence and an actual RPC exchange remain unproved. See [current port-resolution evidence](kernel_port_resolution_report.md). The embedded job declaration is not evidence that this manually launched emulator received the declared launchd configuration.

There are 22 printed sends and 22 replies. No captured send ID is 502, 700, or `io_connect_method` 2865. No downstream selector-26 exchange is demonstrated. The trace observes daemon-side operations only; it is not a kernel-wide Mach capture and cannot exclude other kernel traffic or later behavior outside the recorded interval.

The repeated transport PC `0x180547c20` locates the trap in shared library code. It is not the daemon's call site. Exact daemon emission addresses remain unknown in this capture. Capture LR, a caller backtrace or ordered call edges, the application's load base, and resolved authenticated import targets to map each request to IDA. The previously established kext emission sites remain static findings, not observed events in this trace.

## Packed trap arguments and repeated observations (2026-11-01)

The subsequent [user-library trap report](user_trap_interface_report.md) independently rechecks all44 printed hex headers and matches all22 send headers to Mach2 packed arguments: bits/size, remote/local names, voucher/ID and descriptor count. There are27 printed Mach2 trap records. Five pairs have identical arguments, first return0x80000001, an intervening host reply, then return0, with no additional bridge-send log. They correspond to the five named-service requests.

Current RAX defines0x80000001 as internal RESTART, prints it before handling it, backs the ARM64 PC up4 bytes and resumes a receive stage that skips sending. This conditionally explains the extra observations; historical producer identity remains unknown. They do not establish five additional host sends or a guest-visible error. [Packet/source audit](triage_evidence/zut_trap_argument_audit.json) retains all27 records, five pairs, source hashes/snippets and the preserved trace hash. The printed PC equals RET after this cache's SVC at0x180547c1c; historical module identity remains unverified.

## Other useful artifacts and reliability checks

| Artifact | Reusable evidence / method | Boundary |
| --- | --- | --- |
| `fp-harness/README.md`, `docs/USER_GUIDE.md` | Image-checked execution, ordered observations, checkpoints, strict lifting, SMT queries, counterexample replay | Synthetic imports, seeded state, and disabled PAC restrict conclusions |
| `fp-harness/reports/loop_validation/FINDING.md`, `verified.json`, proof and observation files | Previously recorded compact decision for `[0x100e1b5c0,0x100e1b5e8)`: unsigned interval membership selects indices `0xf0` / `0x4c3`; documented 17 continue / 1 exit sequence | Artifacts were inspected, not rerun; proofs fix other inputs, and the recurrence is one modeled run |
| `fpd/`, `fpd_out/` | Candidate block discovery and dispatch exploration | `cpu.py` uses fixed tags/stripping for PAC; `emu.py` models objects/imports and optionally zero-maps invalid reads. These observations do not validate hardware PAC or native service behavior |
| `evidence.json`, `trace.txt`, `graph.dot` | Small MIG guard fixture at `0x100004530` | Four branch mnemonics in the first two files are wrong; consult bytes and corrected decoder output |
| `fpt` | Earlier trace with a similar bridge/open/exit sequence | No hex bodies or PCs sufficient to decode its open result; do not infer identical status from its reply size |
| `assc.txt` | IDA Assist context-compaction notes | No target-specific FairPlay evidence found in its inspected introduction |

The native words at `0x100004540`, `0x10000454c`, `0x100004558`, and `0x100004568` encode `B.NE`; the older annotations say `bcc`. Live IDA independently agrees with `B.NE`. Consequently, the guards compare for equality, and the annotated less-than interpretation is incorrect. [Machine-readable audit](triage_evidence/zut_trace_decoded.json) retains the four addresses, words, old annotations, and decoded conditions. The older files were preserved.

## Revised investigation order

1. Establish the open failure cause: record the RAX executable/build, host kernel and kext UUIDs, effective host-task entitlements, and UserClient construction logs. Correlate the normal error reply with the actual `initWithTask` path. This distinguishes the bridge's execution identity from the signed guest image and avoids treating all `BadArgument` results as wire-format errors.
2. Add daemon caller attribution at `IOServiceOpen`, `IOConnectCallStructMethod`, `bootstrap_check_in`/its resolved implementation, and Mach send/receive boundaries. Record resolved target, LR, arguments, output status, and module slide. This supplies the emission addresses absent from `--strace-pc` alone.
3. Establish native `com.apple.unfreed` / host-slot-17 publication and compare the destination right with the kext RPC502 sender's first argument. Correlate right identity across namespaces rather than numeric port names.
4. After establishing a successful UserClient open, capture selector 26 through completion with input/output bytes, the pointed-to guest memory ranges, and corresponding kernel memory-descriptor handling. Link this with the existing static provider route before assigning payload semantics.
5. Independently use `fp-harness` for bounded recovery of the RPC502 stub at `0x1000050c8` and implementation `0x100422d48`. Seed ABI-valid requests, vary length/tag/error boundaries, and preserve model dependencies. The available loop proof demonstrates the method's local utility, not the meaning of these routines. Resolve the kext's unmatched RPC700 receiver separately.

## Bounded additional findings

| Impact | Finding | Consequence |
| --- | --- | --- |
| High | Actual host task identity can differ from guest file identity | Investigate runtime entitlement checks before interpreting startup failure as FairPlay protocol failure |
| High | `BadArgument` can be an initialization/entitlement failure | The generic constructor maps false `initWithTask` to this code; the status is not uniquely diagnostic |
| High | Older guard annotations change the branch condition | Reusing them can produce incorrect request-validation schemas |
| Medium | Matching UUID and section hashes bridge two different file hashes | Reuse verified code addresses while separately tracking signatures, data, and runtime fixups |
| Medium | Native publication remains distinct from receive-right acquisition | Acquiring guest `com.apple.unfreed` does not establish a usable native host-slot-17 endpoint |
| Low | Repeated nonzero trap return is followed by a successful reply | The `0x80000001` lines alone are not evidence of failed service acquisition |

## Reproduction and quality gates

```sh
cd /Users/___/dev/dylex/extracted
python3 triage_evidence/analyze_zut_trace.py
```

The decoder runs in O(T + B) time and space for trace size T and binary size B; section counts and message counts are bounded by these inputs. It validates 44 raw headers, descriptor extents, 22 pairings, UUID, all 13 section hashes against the saved live-IDB snapshot, and four legacy conditional-branch encodings. It does not re-query IDA, validate historical runtime completeness, or execute the target.

QG1: no normative conclusion required. QG2: assumptions and falsification probes recorded. QG3: directory usefulness, ports, interaction boundary, obfuscation tools, and next steps covered. QG4: offsets and sizes are bytes; integers decoded little-endian; ID derivation reproducible. QG5: hash, namespace, transport/application-status, and legacy-disassembly discrepancies resolved within stated bounds; failure cause remains explicitly unknown. QG6: capture, live IDB, local source, and pinned primary XNU provenance recorded. QG7: additional findings and impacts bounded above.

## Subsequent static kernel-client context (2026-11-01)

[text_pager_interface_report.md](text_pager_interface_report.md) adds a separate text-pager route through the matching kernel collection, including app-context construction, page decryption and close. This does not add events to the historical RAX trace: its UserClient open still fails, and its bounded absence of selector26/RPC502/RPC700 remains unchanged. The earlier fp-harness memory provides a bounded control-flow validation methodology; its synthetic/PAC and frozen-state limits do not validate the newly recovered native interfaces.

## Original daemon attribution of the five named requests (2026-11-01)

[daemon_registration_report.md](daemon_registration_report.md) independently decodes the same five service names from original daemon data and recovers their ordered calls into `_bootstrap_check_in`, the existing-name CF wrapper, main/default-mode source insertion and stored CF-object fields. The extractor compares every name including NUL against preserved raw ID0x400000ce payloads. This strengthens the API-level check-in attribution while leaving the private XPC operation encoding and historical caller stack unverified.

The original setup routine checks only the last registration status; private earlier-failure cases still attempt the remaining names. The captured five replies themselves remain successful receive-right transfers. Synthetic failure semantics do not add failures to the historical trace, and its later UserClient open failure and absence of FairPlay work RPCs remain unchanged.
