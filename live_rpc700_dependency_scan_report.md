# RPC 700 receiver search in managed-app dependencies

The four installed managed-app executable slices have identical direct dependency names and load kinds. Their shared-cache dependency closure contains 801 images. The audit found zero conventional MIG tables with a callable ID 700 entry among the eligible sections. Three records passed the common-header and local demultiplexer-pointer gates. Their selected fields lead to Objective-C data or SwiftUI metadata routines. The current shared cache has one verified host-special getter pointer and three direct callers of its veneer, using slots 2, 2 and 1. The cache scan found zero pointers or direct branches to the exact host-special setter export. The slot 34 publisher, live port object and RPC 700 receiver remain unknown. [Current kext mode and emission](live_fairplay_constructor_mode_report.md) [Current slot publication and executable scan](live_rpc700_publication_report.md)

```text
FairPlayIOKit alternate constructor -> host slot 34 -> RPC 700 receiver unknown

managed-app executables -> static load closure -> conventional MIG receiver scan
                                                              |
                                              zero ID 700 entries passed
```

## Images and bounds

| Installed executable | arm64e UUID | arm64e.x1 UUID | Load declarations per slice |
| --- | --- | --- | ---: |
| `managedappdistributiond` | `87fa0a7a-a279-3ebc-9448-f44f09938b46` | `99b71f5a-53b0-3c24-9ece-92824766d81f` | 76 |
| `managedappdistributionagent` | `1fbd34ea-1b52-3f7f-889a-d77d2d4ae985` | `e171f291-0d7a-3e5f-9c37-7c7909079dad` | 76 |

The original load-command lists match Apple `dyld_info -dependents` in all four slices. Each has 17 weak declarations. Dependency traversal follows load, weak, reexport, upward and lazy load commands by exact install-name match in cache UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`. The 801 images contain 11,098 dependency declarations. All unresolved edges point to four weak dependencies absent from the cache and filesystem at the declared names. This is a static graph. Process loader decisions and dynamically opened images are unknown.

The table census reads 283,959,680 B in 15,890 declared file-backed sections from 794 images. Seven images contribute no eligible section. The census considers 8 B-aligned records in non-instruction sections with at least 32 B available, an ID range satisfying `0 <= start <= 700 < end <= 4796`, and a maximum reply extent from 36 B through 1 MiB. The installed arm64e SDK verifies the 32 B prefix and 40 B routine descriptor. The gates require the descriptor array to fit the same section, a chained demultiplexer pointer to a local compiler start, and a chained stub pointer to a local compiler start in the ID 700 record.

| First failed gate | Candidate records |
| --- | ---: |
| Descriptor array leaves the section | 5,349 |
| Demultiplexer field lacks a verified cache chain member | 5,024 |
| Demultiplexer target is outside local compiler starts | 81 |
| ID 700 stub field lacks a verified cache chain member | 1 |
| ID 700 stub target is outside local compiler starts | 2 |
| All gates pass | 0 |

## Final candidate checks

| Header-shaped address | Image and proposed range | Original evidence |
| --- | --- | --- |
| `0x1eebf8798` | AppKit `__AUTH,__objc_data`, [388, 872) | The proposed ID 700 stub points to `0x1e211ddf8`, in a read-only, non-executable mapping. |
| `0x1eed6e6a8` | SwiftUI `__AUTH,__objc_data`, [452, 840) | The first pointer resolves to the ObjC metadata update function for `SwiftUI.ImageAttachmentCell`. The proposed ID 700 slot contains eight zero bytes. |
| `0x1eed6e798` | SwiftUI `__AUTH,__objc_data`, [452, 704) | The first pointer resolves to the ObjC metadata update function for `SwiftUI.AppKitToolbarItem`. The proposed stub resolves to `_swift_deletedMethodError` in libswiftCore. |

The cache scan independently accepts libxpc's `_do_notify_subsystem` at `0x1e240c7f8`. Its original cache pointers map ID 71 to demultiplexer `0x184bf4814` and stub `0x184bc837c`. The separate thin-image positive control confirms the previously established fairplayd ID 502 table at `0x1010381c0`. These controls exercise both the cached pointer form and the executable's own fixups. [FairPlay daemon MIG contract](live_fairplay_rpc_abi_report.md)

## Current cache host-special API references

The v5 slide-chain walk checks 31,008,790 entries in 14 mappings. The target addresses come from the installed libsystem_kernel export trie. The getter `0x180549a54` has one verified chain slot at `0x1e20f35d0`. The setter `0x1805699e0` has zero. The registered-port lookup and register controls have two chain slots each.

Among 2,514,836 eligible veneer starts, the getter has one verified ADRP/ADD/LDR/BRAA veneer at `0x188079b00`. A signed-immediate B/BL scan checks 65,480,385 original executable words in architectural reach of the getter, setter or veneer. All three hits call the getter veneer and use local node -1.

| Caller | Call PC | Slot |
| --- | --- | ---: |
| `_os_crash_set_reporter_port` | `0x181ef06b8` | 2 |
| `_os_crash_get_reporter_port_array` | `0x181ef0778` | 2 |
| `__dispatch_mach_host_port_init` | `0x1855b9ca0` | 1 |

The current results reproduce the earlier cache's reference pattern at new addresses. The branch and chain scans bound direct references to the enumerated entries. A publisher in an external executable, a computed call, a custom demultiplexer or another receiver process remains possible. None of the scans observes the contents of host slot 34 at runtime. [Earlier cache and launchd endpoint inventory](rpc700_endpoint_inventory_report.md)

## Assumptions and verification

| Assumption | Dependent result | Falsification check |
| --- | --- | --- |
| A1. The installed files and cache UUID identify the analyzed cohort. | Executable identities and dependency closure. | Recheck slice hashes and UUIDs, compare load names with `dyld_info`, and resolve each required edge. An image outside the cache requires separate inspection. |
| A2. An in-scope conventional receiver uses the SDK layout and local chained function pointers. | Zero passing ID 700 tables. | Compile field and stride assertions, verify the cached ID 71 and thin-image ID 502 controls, and inspect the three final candidates. A custom demux or a table outside these gates changes the scope. |
| A3. The selected forms cover the claimed host-special references. | One getter pointer and three direct caller sites. | Resolve exact exports, validate chain membership and veneer bytes, and decode the call instructions and slot operands independently. |
| A4. Dependency declarations describe static reachability. | Scope of the candidate census. | A mapped-image inventory could test which declared and dynamically loaded images actually participate in the two running jobs. Such evidence was unavailable in this audit. |

High impact attaches to ruling out the conventional local MIG-table hypothesis within the declared cohort. Medium impact attaches to the fresh getter and setter reference counts. Native owner and message attribution require runtime endpoint evidence. The offline audit reads original code and data without invoking the candidate daemons. Its traversal and scans take O(B + F + W + E) time for scanned bytes B, chain entries F, branch words W and dependency edges E, and retain O(S + E + C) records for sections S and candidate records C. The largest section read and the cache mapping inputs bound additional working storage. QG1 and QG3 cover factual scope and the receiver and publisher surfaces, QG2 and QG5 the assumptions and negative gates, QG4 the byte layouts, QG6 the original image and SDK checks, and QG7 the bounded implications. [Audit source](triage_evidence/audit_live_rpc700_dependencies.py) [Audit receipt](triage_evidence/live_rpc700_dependencies_audit.json.zst)

```sh
python3 -B triage_evidence/audit_live_rpc700_dependencies.py "$FAIRPLAYD_THIN"
```
