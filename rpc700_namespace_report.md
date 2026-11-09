# RPC700: kernel special-port ABI and bounded receiver candidates

The matching kernel's exported `host_get_special_port` accepts indices1 through36 and forwards ordinary special-port values through an unnamed reference-copy callee. Slot34 therefore passes its local range guard. Successful return does not establish a live endpoint: the recovered source path can store null with status0.

The installed SDK names slot34 `HOST_MANAGEDAPPDISTD_PORT`. That name supplies a receiver-search lead, not a registration or target-build identity. The inspected managed-app-distribution launchd plists declare XPC services without HostSpecialPort entries. Two associated arm64e executables have no direct Mach/MIG/host-special-port imports. Fifty integer patterns resembling common MIG headers fail the declared schema gates. A related cached framework supplies no matching GOT target among the selected exported Mach/host/MIG/XPC names checked. **RPC700's receiver remains unknown.**

This increment extends the [conditional kext selector recovery](kernel_port_resolution_report.md) and [text-pager mode provenance](text_pager_interface_report.md). All three previously recovered direct provider callers still pass mode1; this work does not establish an alternate-mode caller or a native RPC700 exchange.

## Assumption register

| ID | Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| N1 | The pinned kernel collection and files are the intended corpus | Addresses, instructions and available interfaces | Rehash collection, executable slices, SDK header, cache files and plists; attest live object/slice pairing separately |
| N2 | Original compiler boundaries and exact exported symbols identify the displayed kernel routines | Getter/self ABI and unnamed callee boundaries | Re-read complete LC_FUNCTION_STARTS ranges and original nlist matches; do not substitute a nearby symbol for the unnamed callee |
| N3 | The manually reviewed scalar translation matches the pinned instructions | Complete32-bit range and64-bit sentinel proofs | Check original SUB/CMN/B.LO and ADD/CMP/B.LO widths; rerun bounded SMT queries |
| N4 | Kernel locking, PAC, address-tagging and valid object/out-pointer prerequisites hold | Conditional table load, copied value and successful output store | Inspect actual lock/PAC/MMU/object state; this increment executes none of those facilities |
| N5 | Installed SDK macro names provide context only | Slot34 managed-app candidate selection | Compile macro assertions and retain header bytes; require actual registration, object identity and matching implementation before assigning a receiver |
| N6 | Original import tables and selected cached GOT slots delimit the stated direct-link search | Negative candidate evidence | Parse all selected imports and GOT chains; inspect dynamic lookup, Objective-C/Swift dispatch, reexports, other modules and providers separately |
| N7 | The common32-byte MIG subsystem prefix and40-byte descriptor shape is applicable to a candidate | Header-pattern rejection | Retain every candidate and failed gate; recognize the known RPC502 table as a positive control; custom/computed/other-layout servers remain outside this exclusion |
| N8 | Captured plists describe declarations rather than runtime registration | Service-name and HostSpecialPort distinctions | Match current effective launchd configuration and programmatic registration history; plist absence is insufficient to prove slot vacancy |

[Contracts and candidate inventory](triage_evidence/rpc700_namespace_contracts.json) retain three complete original kernel ranges, exact symbols, two local proofs, source/plist identities,5174 import records,50 header candidates and298 cached GOT records. [Fresh verification](triage_evidence/rpc700_namespace_checks.json) rechecks those sources, proof results, SDK compilation and bounded searches. No target code, native IPC, synchronization or IDB operation executes. [N1-N8]

## Kernel special-port boundary

| Interface | Original address | Established ABI |
| --- | --- | --- |
| Exact `_host_priv_self` | `0xfffffe000bcf27ac` | Returns address `0xfffffe000cad0238` in X0 |
| Exact `_host_get_special_port` | `0xfffffe000bcf258c` | X0 host handle; W2 index; X3 output-pointer; incoming node register is not consulted by the recovered local instructions |
| Ordinary-slot reference-copy callee, exact symbol unknown | `0xfffffe000bcd00bc` | Consumes X0; returns null/dead sentinel inputs unchanged; normal object path contains reference-counter operations |

The getter begins with W0=4. A null host handle returns through the epilogue with that value and no output store. The index test computes `t=(index-37) mod2^32`, then uses the carry from adding36. Its accepted domain is exactly unsigned `1 <= index <= 36`, proved over all32-bit index patterns. Outside that range it returns4 without storing the output. The symbolic error name is not needed for these raw-value findings. [N2,N3]

The getter uses a lock field at host-handle+8, current-thread state from `TPIDR_EL1`/thread+`0x518`, and control global `0xfffffe000cb0bc50`. Its table base is formed from original instructions as `0xfffffe000cad0248`; indexing uses zero-extended low32(index) multiplied by8. The code also modifies address high bits with `MOVK ... #0x2bad` and authenticates loaded data pointers with `AUTDA`. These operations are retained in the source record. A plain logical table offset is not proof of the native effective dereference address or successful authentication. [N2-N4]

| Slot | Logical element address before high-bit/tag handling | Installed SDK name | Independently captured publication context |
| --- | --- | --- | --- |
| 17 | `0xfffffe000cad02d0` | `HOST_UNFREED_PORT` | Fairplayd plist declares `com.apple.unfreed`, HostSpecialPort17 |
| 31 | `0xfffffe000cad0340` | `HOST_FAIRPLAYD_PORT` | Fairplayd plist declares `com.apple.arcade.fpsd`, HostSpecialPort31 |
| 34 | `0xfffffe000cad0358` | `HOST_MANAGEDAPPDISTD_PORT` | No HostSpecialPort declaration in the two inspected managed-app plists; actual slot owner unknown |

The kernel handles indices1,2 and3 through distinct branches. Indices17,31 and34 share the ordinary branch at `0xfffffe000bcf2678`, calling the unnamed routine above. Its first guard is `(X0+1 mod2^64)<2`, proved equivalent to input0 or all64 bits set. Those inputs return unchanged. For a null slot34 value, the original getter/callee path therefore reaches the output store with null and status0. This is a conditional source composition, not an observation of slot34's contents. [N2-N4]

At `0xfffffe000bcf267c..2684`, the getter saves the returned value, clears W0 and writes the value through the supplied output pointer. Thus three separate facts are required for a working RPC destination: getter status0, a usable returned port reference, and the intended endpoint identity. The earlier kext status guard establishes only its local status predicate. [N2-N4]

```text
host_priv_self -> host handle
  -> host_get_special_port(handle, node, index, out)
       -> handle/index guard
       -> lock / table load / pointer authentication
       -> index-specific reference conversion
       -> output store + status0
  -> kext chooses RPC502 or RPC700 under its separate mode predicate
```

The two kernel exports are exact nlist bindings. The callee at `0xfffffe000bcd00bc` has no exact name in the scanned nlist records. Its local counter/sentinel behavior supports a reference-copy role; the report does not assign it a confirmed exported function name or complete object-lifetime contract. [N2,N4]

## SDK and managed-app-distribution lead

The [captured installed header](triage_evidence/rpc700_host_special_ports.h) defines the three names above and maximum36. A fresh arm64e compile-only [probe](triage_evidence/rpc700_host_constants.c) verifies those numeric macros against the installed SDK. Agreement with the kernel's numeric upper bound does not establish that every SDK semantic name matches the target kernel's registrations. No source-version identity is inferred. [N1,N5]

| Candidate declaration | Program | Declared Mach services |
| --- | --- | --- |
| `com.apple.managedappdistributiond` LaunchDaemon | `/System/Library/Frameworks/ManagedAppDistribution.framework/Support/managedappdistributiond` | `com.apple.managedappdistributiond.xpc`, `com.apple.managedappdistributiond.xpc.agent` |
| `com.apple.managedappdistributionagent` LaunchAgent | Same Support directory, executable `managedappdistributionagent` | `com.apple.managedappdistributionagent.xpc`, `com.apple.managedappdistributionagent.xpc.legacy` |

Neither inspected managed-app plist includes HostSpecialPort in those service entries. This says nothing about later programmatic registration, loaded-library activity, another job or effective runtime configuration. [N8]

| arm64e candidate slice | UUID | Parsed import records | Common header-pattern candidates | Passing declared gates |
| --- | --- | ---: | ---: | ---: |
| managedappdistributiond | `2ed78e46-6ca7-3ebe-88d3-191d006e1384` | 2587 | 25 | 0 |
| managedappdistributionagent | `e1409c36-ae4b-35af-9e0e-265ab4e5c5d5` | 2587 | 25 | 0 |

The complete parsed import lists contain none matching the stated `host_(get|set)`, `mach_` or `mig_` search. They do contain direct XPC connection creation, resume, event-handler and synchronous reply-send imports. This establishes imported interfaces; it does not identify which calls execute or rule out transitive/dynamic Mach use. FairPlay-related strings and selector `fairplayContextWithError:` are retained as locators, without assigning receiver or routine semantics from strings alone. [N6]

The header scan checks8-byte-aligned prefixes whose ID interval contains700, with a bounded maximum interval/reply size. Candidates then require a data section, an original chained pointer in the first field, a local compiler-start target and a descriptor-array extent fitting the section. All50 candidates fail at least one declared gate. The known daemon RPC502 table at `0x1010381c0` passes the same gates as a positive control. These results exclude those50 patterns as instances of the stated schema; they do not establish absence of all RPC700 handling. [N7]

The original cached `ManagedAppDistribution` framework has UUID `62826bfc-8744-303f-9754-032bd2e3f832` and4102 compiler starts. Its298 GOT records were checked against original cache-v5 chain membership. None resolves to the selected exported names beginning `host_`, `mach_`, `mig_` or `xpc_connection_` in the inspected libsystem_kernel, libsystem_c and libxpc images. Indirect calls, Objective-C/Swift dispatch, interior targets, wrappers and other libraries remain outside that negative match. Four consumed cache files are fully hashed. [N1,N6]

## Verification and bounded continuation

Fresh checks cover three original kernel functions, two exact symbol bindings, two complete scalar-domain proofs, three original plists, two arm64e slices,5174 import records,50 rejected header patterns, one known positive MIG control,298 GOT records and four cache-file hashes. The SDK compile exits0. No new target emulation or native endpoint observation is claimed.

```sh
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_rpc700_namespace.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc700_namespace.py
```

Extraction/verification is O(B+N+F+E) for pinned source bytes, symbols/imports, fixups and exports, with space bounded by source/pointer tables. Each solver has a60000 ms timeout. Slots/indices are u32, table elements and returned values are8 bytes, and sentinel arithmetic is modulo `2^64`. Static compiler spans are not a proof of all cross-function control or runtime policy.

[Preservation](triage_evidence/rpc700_namespace_preservation.json) checks1166 prior artifacts with only six permitted reporting/index/aggregator changes. [Scoped quality gates](triage_evidence/rpc700_namespace_quality_gates.json) retain final readback. Other published analytical files remain frozen; the broad interface investigation remains active.

| Impact | Further requirement | Evidence needed |
| --- | --- | --- |
| High | Actual slot34/RPC700 receiver | Native port-object identity and registration history, plus matching receiver bytes and dispatch |
| High | Alternate-mode caller and complete kext reachability | Computed/external caller recovery and intact mode/record/port aliases through dispatch |
| Medium | Managed-app FairPlay routines | Resolve retained selector/string locators to callers, providers and request/result records; names alone are insufficient |
| Medium | Effective lookup/ownership behavior | Native locking/PAC/MMU context, live copied reference, replacement and release histories |

QG1: factual analysis. QG2: N1-N8 assumptions and probes. QG3: special-port ABI and bounded receiver-search increment covered; full goal active. QG4: u32/u64 domains, byte offsets, proof scope and complexity explicit. QG5: SDK labels, declarations, candidate patterns, compatible schemas and runtime endpoints remain distinct. QG6: original kernel/slice/cache/header/plist bytes, exact symbols, fresh proofs and compile/readback. QG7: impact-bounded continuation above.
