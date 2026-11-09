# Job factories, callback-table lineage and MachServices construction

The callback table recovered in the [endpoint lifecycle report](endpoint_job_lifecycle_report.md) belongs to several creation paths. The previously selected producer is specifically a UUID-keyed child-instance factory. Ordinary plist import independently installs the same eight callbacks and domain cookie. The original `MachServices` property route now joins that ordinary job creation to the endpoint constructor, fixed endpoint callback and owning job. This establishes a conditional static route for the FairPlay plist declarations; the effective native factory, job record, endpoint objects and successful port publication remain unknown [JF1-JF4].

The six previously unclassified callback entries now have bounded roles: lifecycle-event dispatch, reset eligibility/cleanup, endpoint removal, socket-source creation, socket-source removal and installation/source attachment. Complete event-selector meanings, admission policy and native scheduling remain unknown. [Original capture](triage_evidence/job_factory_lineage_source.json), [checks](triage_evidence/job_factory_lineage_checks.json).

## Provenance and scope

The original `/sbin/launchd` SHA-256 is `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`. Slice UUIDs are `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71` and `62af2b7d-327e-334a-a1d7-83777efc3c12`. Capture contains 70 distinct compiler-bounded bodies: 64 launchd bodies across both slices and six cached libxpc bodies, totaling 16814 instructions and 67256 B. Seventy selected launchd words require byte-checked LLVM decoding; 4894 original fixups independently match `dyld_info`. Cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`; libxpc UUID is `f6d8fb8f-6ba0-3857-b356-21c448c954a1`. Runtime slice selection and hardware pointer-authentication behavior are unknown [JF6].

All table, callback, schema-block and import bindings below are derived from original bytes. Private function names are analytical roles. The current FairPlay plist is independently parsed with `plistlib` and Apple's `plutil`; its bytes and complete parsed contents match the earlier frozen file evidence. The earlier launchctl snapshot is not refreshed or treated as a current observation.

```text
ordinary plist import
  -> prepare 8 callbacks + domain cookie (72 B)
  -> job import/admission
     -> job creation -> base initialization -> J[0x218..0x257], J.cookie
        -> iterate plist properties
           -> typed schema lookup of MachServices dictionary
              -> global block -> nested dictionary iteration
                 -> callback at J+0x230
                    -> endpoint constructor -> endpoint callback/cookie = fixed_fn/J
     -> job installation -> callback at J+0x250
        -> source attachment / conditional endpoint publication

UUID instance request/lookup
  -> child-instance factory -> same callback table
     -> cloned endpoints -> fixed endpoint callback/cookie = fixed_fn/child
     -> child linked to parent
```

Each arrow is a selected original producer/consumer or call edge. This diagram does not assert that a native FairPlay request traversed the entire route.

## Table producers and instance distinction

The bounded locator finds eight exact-address references to the endpoint-wrapper function per slice, occupying seven functions. Every site belongs to a complete ordered eight-entry table installation: 16 tables and 128 callback slots across both slices. One function prepares two tables. The locator covers adjacent ADRP+ADD/ADR references and aligned direct B/BL instructions in `__text`; it excludes aliases, nonadjacent address construction, indirect producers and other images [JF1,JF6].

| Producer role | arm64e | arm64e.x1 | Tables per slice / evidence boundary |
|---|---|---|---|
| UUID child-instance factory | `0x100029b84` | `0x1000292a8` | 1; UUID search, parent list, clone path |
| Ordinary plist import | `0x10002ba58` | `0x10002b134` | 1; parse/path/Label operations and job-import call |
| Deferred service-stub materialization | `0x10002c490` | `0x10002bb60` | 1; bundle population and original stub diagnostics |
| Bundle service import | `0x10002c6a8` | `0x10002bd78` | 1; bundle identifier/path and XPCService diagnostics |
| Job-import alternate-domain retry | `0x10002f4e8` | `0x10002eb4c` | 2; second import is conditional on raw status134 and domain checks |
| Socket-event/inetd instance path | `0x1000308f0` | `0x10002fee8` | 1; socket/inetd diagnostics; full socket policy unknown |
| Submitted job-dictionary import | `0x100039a90` | `0x100038f8c` | 1; Label, caller formatting and common job-import call |

The UUID factory checks input domain against parent+0xf8, searches parent+0xc8 children by UUID at child+0x1a8, and can reuse an existing child. Its creation branch clones parent endpoint records, writes the fixed endpoint callback and new child cookie, links the new child into parent+0xc8, and stores parent at child+0x100. Optional overrides and one-shot properties have further checks. Thus this producer cannot by itself identify the ordinary FairPlay job [JF1,JF2].

There are three aligned direct call sites per slice:

| Caller role / bounded evidence | arm64e call site | arm64e.x1 call site |
|---|---|---|
| Explicit instance request; reply required, `instance` UUID, existing-child comparison | `0x100025ce4` | `0x100025558` |
| Larger job request handler; `instance-uuid` path observed during analysis | `0x10003edb0` | `0x10003e1f4` |
| Larger endpoint lookup handler; instance lookup/creation path observed during analysis | `0x10005a188` | `0x1000591e8` |

All three containing handlers are captured as complete compiler-bounded bodies. Their selected instance-call edges and original strings are retained; their complete policy and branch semantics are not recovered. No exhaustive indirect-caller census is inferred.

## Ordinary plist-to-endpoint contract

Ordinary import prepares the table at SP+0x48 and stores the domain pointer at SP+0x88, exactly 64 B after the first callback. It passes the table in X4 to the common job importer. The importer initially saves it in X26, spills it to its SP+0x30, then reuses X26 for a separate parsing/diagnostic context. Before job creation, it reloads the table into X4. Job creation preserves that incoming X4 through X28 and its SP+0x40, then reloads X4 before base initialization. Its X6 and the base initializer's X7 carry the separate context. Installation receives that context in X2; the callbacks are already stored in J. The base copies 64 callback bytes to J+0x218 and the trailing 8 B cookie to J+0x258 [JF1,JF3].

| Layer | arm64e | arm64e.x1 | Selected contract |
|---|---|---|---|
| Common job importer | `0x100003c04` | `0x100003bc8` | Plist dictionary, domain/path/admission context, callback table |
| Job creation | `0x100007104` | `0x100007038` | Label/Program/arguments processing; table forwarded to base |
| Base initializer | `0x100005094` | `0x10000504c` | Copy callbacks and cookie into J |
| Property-context constructor | `0x10001a66c` | `0x10001a15c` | Allocate24 B; store J/context/third capture at+0/+8/+16 |
| Property iterator/schema initializer | `0x100007be0` | `0x100007b14` | Lazy typed schema registration, then property dispatch |
| Schema registration | `0x100051de8` | `0x100050f08` | Key and handler record inserted into selected type map |
| Typed schema dispatch | `0x10000d664` | `0x10000d49c` | Dictionary type selects map+0x68; handler block loaded from record+8 |
| MachServices outer block | `0x10000bb18` | `0x10000b9b0` | Iterate the MachServices dictionary with job/context captures |
| Per-entry iterator | `0x10000bb88` | `0x10000ba20` | Restore captures, forward name/value and context |
| Per-entry adapter | `0x10000691c` | `0x100006874` | Load J+0x230 and cookie J+0x258; call endpoint-wrapper callback |
| Job installation | `0x100051824` | `0x100050944` | After additional checks, set J.domain and call J+0x250 with cookie |

`MachServices` is registered in the dictionary map with the global block at `0x100081b10` in each slice. The original chained binding identifies `__NSConcreteGlobalBlock`; the authenticated invoke pointer at block+16 resolves to the corresponding outer block above. This is a data binding plus an original authenticated indirect-call consumer, not a native invocation observation. Other original bindings separately identify bool, int64, string, array and dictionary type handles [JF3,JF6].

Job creation first constructs a 24 B property-context record. Its original constructor stores incoming J and diagnostic context at+0/+8, stores a third capture at+16 and retains the nonnull job. The caller passes this record to `_xpc_dictionary_apply_f`; the property callback loads J/context from that same pair. Allocation success and balanced lifetime remain dependencies.

The cached libxpc adapters establish the callback argument transfer independently of import spelling:

| Cached role | Original address | Selected transfer |
|---|---|---|
| `_xpc_dictionary_apply_f` | `0x184b715c8` | Stack state contains dictionary, function pointer and caller context |
| `_xpc_dictionary_apply` | `0x184b75434` | Stack state contains dictionary, block and Boolean-result address |
| Common dictionary walker | `0x184b71610` | Selected bucket-chain walk supplies entry/state to its adapter |
| Function adapter | `0x184b7172c` | Get key; load value from entry+0x10; invoke function(key,value,context) |
| Block adapter | `0x184b755d4` | Get key; load value; invoke block+16 with(block,key,value) |
| Key accessor | `0x184b96260` | Inline/indirect-key selection; tag3 has a further tail helper |

The adapters compare dictionary+0x1c shifted right4 with the saved iteration value and have diagnostic/fatal continuations on mismatch. The walker also has a conditional additional iteration backend. Key tag3's tail helper, that backend, map/hash internals and actual object validity are not newly recovered. The selected adapter ABI and context transfer are established; complete dictionary semantics and native iteration success are not [JF2,JF3].

The outer block captures J and the parsing context at stack-block+32/+40, iterates the MachServices dictionary, and the nested iterator forwards `(J,name,value,context)`. The per-entry adapter loads J+0x230 and invokes it with X0=J, X1=name, X2=value, X3=0, X4=context and X5=J.cookie. A conditional same-name implicit-endpoint check can reject before that call. A NULL callback result sets J+0x580 bit0. Therefore a declared entry does not imply successful endpoint creation.

The selected table makes J+0x230 the previously recovered endpoint wrapper. That wrapper replaces X3 with the fixed endpoint callback and X5 with J before calling the endpoint constructor. The constructor stores J at E+0x60 and fixed callback/J at E+0x90/+0x98. This joins the ordinary plist path to the endpoint reason0/1 lifecycle ABI. Type checks, allocation, property parsing, later publication and native object identity remain separate prerequisites [JF2-JF4].

## Callback-role correspondence

| Index / J offset | arm64e | arm64e.x1 | Recovered role and limit |
|---|---|---|---|
| 0 / +0x218 | `0x100029f84` | `0x1000296a8` | Lifecycle-event dispatcher; raw selectors0/1/4/5/7/8, source/list/count transitions; complete producer-side selector semantics unknown |
| 1 / +0x220 | `0x10002a35c` | `0x100029a50` | Demand/pending-reason gate, established previously |
| 2 / +0x228 | `0x10002a510` | `0x100029c04` | Reset eligibility/conditional cleanup; checks unmanaged/PID-local and active endpoint lists, returns0 or EBUSY16 |
| 3 / +0x230 | `0x10002a6a8` | `0x100029d9c` | Endpoint construction with fixed callback and owning-job cookie |
| 4 / +0x238 | `0x10002a70c` | `0x100029e00` | Forward X2 to endpoint-removal helper |
| 5 / +0x240 | `0x10002a714` | `0x100029e08` | Socket-source construction/status check; successful record linked at J+0xc0 |
| 6 / +0x248 | `0x10002a7f8` | `0x100029eec` | Unlink socket-source record, helper cleanup and Objective-C release |
| 7 / +0x250 | `0x10002a850` | `0x100029f38` | Installation/source attachment; socket activation-count increment and conditional endpoint publication |

Callback0's original diagnostics name will-spawn ordering and service initialization. Selector4 stores its u32 input at J+0x178/+0x17c and may consume an XPC array; selector1 clears J+0x124 after list/flag updates. Selected selectors tail into the earlier deactivation/removal/rearm helpers. These local effects do not define every event's native ordering or caller ABI [JF2,JF5].

Callback5 passes J as X0 to the socket constructor at `0x10001bfd4` / `0x10001b9c8`. That constructor preserves the argument and stores it at source S+0x38. After checking status S+0xe0, callback5 links S into J+0xc0. The later installation callback walks that list, loads owner K=S+0x38, and performs a u16 load/add/store at K+0x12c before marking owner flag+0x180 bit3 and calling a source helper. In the selected unmodified constructor lineage, K=J. Actual lifetime, callbacks and other field writers remain unknown [JF2,JF5].

This is a producer-side counterpart to the earlier signed16 activation-count deactivation. The increment truncates to 16 bits at the store; a valid runtime count domain and balanced increments/decrements are not established. It is not a kernel port-reference operation, nor proof of a native arithmetic failure.

## FairPlay configuration correspondence

The on-disk plist SHA-256 remains `ca21543400f3ead9e96d2434f968184b6acd2e1e3de57322ca3da663831eae3c`. The following are verified declarations, not observed current right identities [JF4].

| Declaration | Value |
|---|---|
| Label | `com.apple.fairplayd` |
| Program | `/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd` |
| UserName / GroupName | `_fpsd` / `_fpsd` |
| `com.apple.unfreed` | Dictionary containing HostSpecialPort17 |
| `com.apple.arcade.fpsd` | Dictionary containing HostSpecialPort31 |
| `com.apple.fairplayd` | true |
| `com.apple.fpsd` | true |
| `com.apple.fpsd.sim` | true |
| `com.apple.fairplayd.xpc` | true |
| KeepAlive | Dictionary containing Crashed=true |
| EnablePressuredExit / EnableTransactions | false / false |
| EnvironmentVariables | DYLD_PAGEIN_LINKING=`0` |
| MultipleInstances / _Conclave / DaemonNotifications | Keys absent |

The same generic property schema recognizes `_Conclave` and `DaemonNotifications`, while this plist has neither key. Their recognition and the previously found Exclaves deregistration import do not establish a FairPlay Exclaves registration. Absent keys do not prove effective defaults, absence of programmatic configuration or absence of child instances. The KeepAlive dictionary is not interpreted as unconditional restart; its policy consumer remains a separate question. Host-special registration and the kernel-facing slot17/RPC502 route remain covered by the [registration report](host_special_registration_report.md) and [kernel port-resolution report](kernel_port_resolution_report.md).

## Assumption register and falsification probes

| ID | Assumption / dependent result | Falsification or stress test | Remaining boundary |
|---|---|---|---|
| JF1 | Located table stores are the applicable producer lineage | Check all128 slots, exact stack offsets, all seven producer bodies, ordinary importer and separate UUID child linkage | Native factory choice and aliases/indirect producers unknown |
| JF2 | Job, endpoint and source records retain their owner/cookie identities | Trace base copy, constructor writes, socket owner store, source list and count load/store; retain removal paths separately | Other writers, lifetime and interleavings unknown |
| JF3 | Typed property dispatch selects the recovered MachServices handler | Verify 24 B context production, cached function/block adapters, type bindings, schema map+0x68, global block fixups, nested captures and J+0x230 call | Allocation, additional dictionary/key backends, map initialization and actual native parsing success unknown |
| JF4 | Current declaration bytes are relevant to the effective FairPlay job | Rehash and compare both parsers and complete frozen plist; distinguish current file from frozen launchctl output | Effective overrides, running instance, slice and kernel object identity unknown |
| JF5 | Callback labels describe only recovered local effects | Preserve raw event selectors, diagnostics, EBUSY result and socket-owner count producer; do not infer event scheduling from table position | Full selector producers, balanced counts and native callback order unknown |
| JF6 | Pinned binary/tool versions support bounded static claims | Recapture original bodies, decode contiguous bytes, compare4894 fixups, compile SDK widths/constants and reject altered evidence | Hardware PAC/x1 semantics and exhaustive whole-image semantic recovery unknown |

## Further interface questions

| Impact | Question | Concrete anchor |
|---|---|---|
| High | Effective ordinary FairPlay job/endpoint object lineage | Bind J.domain, J+0x218 table and six endpoint names to a single runtime epoch; current declarations alone do not supply this |
| High | FairPlay launch policy, executable inputs and conditional restart | Pair KeepAlive/Crashed property consumption, callback0 event producers, start gate and argv/environment production |
| High | Exclaves configuration lineage | Pair _Conclave/DaemonNotifications schema handlers with J+0x570 production and notification register/deregister calls; current FairPlay plist lacks both keys |
| Medium | Socket activation and removal balance | Pair source+0x38 owner production, installation increment, source callbacks and the earlier deactivation/removal paths |
| Medium | Retry-domain and instance distinctions | Recover raw status134 producer and effective alternate-domain choice; distinguish requested UUID child from ordinary imported job |
| Low | Wider producer census | Extend exact-address locators to nonadjacent address formation, data tables and indirect factories without treating numerical offset matches as type identity |

## Validation and quality gates

Fresh source recapture matches the saved capture. Verification checks 267 selected instruction occurrences, all 128 table slots, 4894 fixups, eight installed-SDK assertions in one arm64 compilation, complete contiguous byte/decoder records and six rejected evidence alterations. SDK assertions cover pointer/integer/port-name widths and EBUSY16/EINVAL22/EALREADY37. The negative controls alter evidence metadata only. No recovered target execution, emulation, native IPC, spawn, service configuration, port mutation or IDB mutation occurs. [Recovery](triage_evidence/recover_job_factory_lineage.py), [validator](triage_evidence/validate_job_factory_lineage.py), [delivery](triage_evidence/job_factory_lineage_delivery.json), [quality gates](triage_evidence/job_factory_lineage_quality_gates.json).

Static capture/search is O(B+F+I+L) time/space for original bytes B, fixups F, selected instructions I and locator records L. Acyclic endpoint/source list walks are O(n) in visited records; cookie/table access uses fixed offsets. Full parser, allocator and map complexity is not inferred from these local call edges.

QG1: Descriptive technical analysis requires no normative premise.

QG2: JF1-JF6 register assumptions, dependent results and falsification probes.

QG3: Producer families, ordinary/instance distinction, callback roles, typed MachServices path and FairPlay declarations are covered; the full interface objective remains active.

QG4: Pointers/cookies are 64 bit; status/reason fields 32 bit; activation count 16 bit. Table 64 B plus cookie 8 B equals 72 B; instruction bytes equal 16814*4=67256 B. The property context is three 8 B fields, totaling24 B.

QG5: Shared callback roles do not imply shared native object identity. Ordinary import, child creation, declared services, effective policy and native publication remain distinct.

QG6: Original bytes/fixups/imports, diagnostics, current plist bytes, independent plist parsers and installed SDK checks provide provenance. No source/build equivalence or target execution is inferred.

QG7: Further interface questions have bounded anchors and impact labels; native effects and complete goal coverage remain unproved.
