# Exclaves notification contracts and the captured unsupported trap boundary

The captured kernel collection's trap88 entry targets a complete three-instruction handler that unconditionally returns `KERN_NOT_SUPPORTED` (46). Original libkernel Exclaves boot and daemon-notification register/deregister wrappers reach that entry through SVC selector-88. Launchd explicitly tolerates46 in its boot wrapper; notification registration sets its success flag only on0. This is a concrete static boundary for these images, not a native Exclaves-support observation [EN1]. [Original capture](triage_evidence/exclaves_notification_contract_source.json), [checks](triage_evidence/exclaves_notification_contract_checks.json).

The previous unidentified job+0x570 field is a copied Conclave identifier string. `_Conclave` produces it; `DaemonNotifications` creates marked endpoint records; publication and removal pass the identifier, endpoint name and port name to the two Exclaves wrappers. The same identifier independently feeds a local spawn-attribute setter. This closes the configuration/register/deregister correspondence identified in the [endpoint lifecycle report](endpoint_job_lifecycle_report.md) and [job factory report](job_factory_lineage_report.md). Native initialization, effective job/endpoint identity, registration and FairPlay use remain unknown.

## Source identities and scope

Launchd SHA-256 is `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`; slice UUIDs are `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71` and `62af2b7d-327e-334a-a1d7-83777efc3c12`. Kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. Original import bindings, pointer chains, exports and compiler-bounded bytes are retained. Runtime image selection and hardware authentication remain unknown [EN1,EN6].

Capture contains40 complete bodies:30 launchd, eight cached libkernel and two kernel bodies;7688 instructions/30752 B. Thirty-three launchd words require byte-checked LLVM decoding. Both slices'4894 fixups independently match `dyld_info`. Four exact import targets have one aligned direct B/BL caller per slice. Three immediate STR-x+0x570 sites per slice belong to the setter and clone functions; aliases, wider stores and other images are excluded from that locator [EN6].

```text
_Conclave string -> job identifier J+0x570
                    +-> child clone duplicates identifier
                    +-> local spawn attribute string at private attr+0xf8
                    +-> endpoint registration/removal

DaemonNotifications dictionary -> policy predicate8 -> entry iterator
  -> common endpoint wrapper -> E.requested(bit9)=1
  -> publication -> register(0, identifier, endpoint_name, port_name)
       +-> return0: E.registration(bit12)=1
       +-> error: log; publication can continue
  -> removal -> conditional deregister(...) -> clear registration bit

boot/register/deregister wrappers -> SVC -88 -> original trap-table handler
                                            -> return46 unconditionally
```

The final edge describes the captured registry and code. Applying it to an actual process requires matching loaded images, dispatch and callback initialization; no native request is issued.

## Property and owner-field correspondence

| Role | arm64e | arm64e.x1 |
|---|---|---|
| `_Conclave` property callback | `0x10000c3cc` | `0x10000c264` |
| Identifier setter | `0x1000068a0` | `0x1000067f8` |
| String duplication wrapper | `0x100015da4` | `0x100015a38` |
| `DaemonNotifications` callback | `0x10000c3d8` | `0x10000c270` |
| Per-notification entry iterator | `0x10000c4a8` | `0x10000c334` |
| Policy predicate dispatcher | `0x100003708` | `0x1000036d8` |
| Endpoint publication | `0x10003012c` | `0x10002f730` |
| Endpoint removal | `0x10002fd84` | `0x10002f3b8` |
| Spawn-attribute preparation | `0x10002369c` | `0x100022f58` |
| Boot wrapper | `0x100027370` | `0x100026b48` |

The original typed schema registers `_Conclave` in its string map+0x38, with global block `0x100081f10`; `DaemonNotifications` belongs to the dictionary map+0x68 with block `0x100081f50`. Their authenticated invoke pointers resolve separately in each slice. The Conclave callback forwards `(job,string)` to the setter. The installed SDK defines `MAXCONCLAVENAME=128`; the setter's direct strlen result must be below128 B, excluding NUL. Length0 is accepted by this local check. A length of128 B or more logs and returns before replacing the prior field [EN2,EN3].

On the selected replacement path, a nonnull prior J+0x570 is freed and cleared, then a local wrapper invokes the original `_strdup` import and stores its result at J+0x570. The wrapper's NULL/errno handling includes a diagnostic/crash frontier; allocation success and native lifetime are not assumed. The captured job-clone body separately duplicates a nonnull parent+0x570 into child+0x570. This proves string lineage, not inheritance of every endpoint flag or successful child registration [EN2].

The notification callback invokes policy predicate8 before dictionary iteration. Its diagnostic says that DaemonNotifications requires a valid Conclave, but the predicate's code is a policy test over job/global flags and a selected lookup with raw selector32. It is not a test that J+0x570 is nonnull or nonempty. Identifier presence is checked separately during publication. Complete policy-lookup meaning remains unknown [EN3].

The nested iterator captures job and diagnostic context, rejects an empty endpoint key or strlen>=128 B, then loads the endpoint-construction callback from J+0x230 and cookie from J+0x258. It uses the same wrapper established in the job-factory report. A nonnull endpoint result gains E+0x58 bit9 and has E+0xa0 bit4 cleared; a rejected name/NULL result marks job+0x580 bit0. Thus property parsing, endpoint creation and backend registration are distinct stages [EN2,EN3].

## Registration, publication and removal

Publication first has name-conflict, ownership, domain and special-port checks. In its selected notification path, E+0x58 bit9 requests registration. If the owning job's identifier is NULL, publication logs and clears that request bit. Otherwise, a later name helper is called with selector1; port names0 and0xffffffff fail the recovered unsigned validity test. For an accepted name, the call arguments are `(0, job.identifier, endpoint.name, port_name)` [EN2-EN4].

| API emission | arm64e call site | arm64e.x1 call site | Selected arguments |
|---|---|---|---|
| Exclaves boot | `0x100027388` | `0x100026b60` | First argument0, phase0 |
| Notification register | `0x100030464` | `0x10002fa68` | 0, J+0x570, E+0xa8 name, returned port name |
| Notification deregister | `0x10002ff2c` | `0x10002f554` | 0, J+0x570, E+0xa8 name, returned port name |
| Set Conclave spawn attribute | `0x10002378c` | `0x100023048` | Attribute-object address, J+0x570 |

Only register return0 sets E+0xa0 bit12. Nonzero status is formatted through `mach_error_string`, then rejoins later publication. The selected common suffix can still return0 and set E+0x58 bit5. Consequently, the publication flag and a successful publication return are insufficient evidence of Exclaves notification registration [EN3,EN4].

Removal requires the selected published path and notification request bit9 plus registration bit12. It obtains the owner through E+0x60, checks the identifier, calls the name helper with selector2, validates the numeric name and emits deregister. Both an error return and selected skipped-call paths converge on clearing bit12. That local clear does not establish backend deregistration or right retirement. The name-helper selector difference is retained; complete send-object history and right balance are not newly proved [EN2,EN4].

These calls carry an existing numeric port name. The recovered Exclaves API path uses a control trap with a pointer/extent pair. It does not construct a Mach message containing port descriptors, and this increment establishes no receive-right transfer or native notification delivery.

## Cached control wrappers and record geometry

| Cached role | Original address | Selected control literal / effect |
|---|---|---|
| `_exclaves_boot` | `0x18055a018` | W1=0x05000000; incoming phase moved to W2; other auxiliary arguments zero |
| `_exclaves_daemon_notification_register` | `0x18055a3f4` | W1=0x15000000; X3=record pointer; W4=260 B |
| `_exclaves_daemon_notification_deregister` | `0x18055a520` | W1=0x16000000; same record geometry |
| `__exclaves_ctl_trap` | `0x180547cd8` | X16=-88, SVC0x80, return |
| `_posix_spawnattr_set_conclave_id_np` | `0x18055edbc` | Local string allocation/copy into private attribute+0xf8 |
| `___libkernel_platform_init` | `0x18054dd18` | Replace string-function-table cell with incoming pointer; return0 |

The register/deregister wrappers reject NULL identifier or endpoint pointers and invalid numeric port names with raw Mach status4. They call a replaceable string-table member+0x78 with bound128 and require the returned value<=127 for both names. Member+0x58 receives each source, destination and capacity128. These operations have an initialization/callback-semantics premise [EN3].

| Reconstructed notification-record field | Offset / capacity |
|---|---|
| Identifier field | +0,128 B |
| Endpoint-name field | +128,128 B |
| Numeric port name | +256,4 B |
| Total extent passed to trap | 260 B (0x104) |

The wrappers zero the260 B region, prepare the two fields through callbacks and store the low32 port-name bits at+256. They pass first API argument through X0, the control literal through W1, X2=0, X3=record address, W4=260 and X5-X7=0. The compiled record is explicitly a reconstruction of those instructions, not a claimed canonical private SDK type. No record is constructed for native emission [EN3,EN6].

The callback cell is originally named `__libkernel_string_functions` at `0x1ed83e8c8`. Its verified cache chain points to `__libkernel_generic_string_functions` at `0x1e212b988`. That file-default table has named generic strlcpy/strlen targets at+0x58/+0x60, but raw zero at+0x78. The four-instruction platform initializer can replace the cell. Thus the original default alone cannot justify a working bounded-length callback for notification registration. The effective initialized table and its producer are unknown; the default is not treated as live state [EN3].

## Trap registry, widths and unsupported handler

The original Mach trap88 registry row contains eight arguments and14 u32 words. Its authenticated handler pointer at `0xfffffe0007efb858` resolves to `0xfffffe000bcf0138`; its munger pointer resolves to `0xfffffe000bf088dc`. The separate name-table pointer yields `_exclaves_ctl_trap`. These are fresh original pointer/byte checks, rather than attribution from an unverified function label [EN1,EN6].

The captured munger widens the first two u32 values to64-bit slots and shifts the remaining six u64 values backwards into their slots. Input argument extent is therefore 4+4+6*8=56 B, or14 u32 words; expanded storage is8*8=64 B. The260 B pointed record is separate from those argument slots.

```text
0xfffffe000bcf0138  bti c
0xfffffe000bcf013c  mov w0, #0x2e
0xfffffe000bcf0140  ret
```

This complete handler has no argument-dependent branch, data load, record copy, port lookup or backend registration call. Its return value is46 for every argument state that reaches it. Native dispatch may have other effects before/after the handler; none is inferred from these three instructions. Under the captured dispatch binding and conforming wrapper callbacks, reaching this handler cannot produce the register wrapper's success0. Early wrapper rejection is a separate status4 path [EN1,EN3].

Launchd's boot wrapper skips its failure diagnostic for both0 and46. This explains a deliberate unsupported-result continuation without establishing why this build lacks the implementation. Other kernel images, trap replacement, current runtime support and all other Exclaves facilities are outside this conclusion.

## Separate spawn-attribute path and status domains

When J+0x570 is nonnull, launchd's attribute-preparation body calls the Conclave setter and has a nonzero-result assertion frontier. The cached setter validates the attribute handle, uses string-table member+0x60 to obtain length, requires<=127, and allocates128 B through a separate runtime function table if private attribute+0xf8 is empty. It stores/reuses that pointer and copies with capacity128 through string member+0x58. This API performs local attribute storage; it does not invoke the captured Exclaves control trap. Subsequent spawn serialization and its kernel consumer are unknown [EN3,EN5].

| Status producer | Domain / verified constants |
|---|---|
| Exclaves wrapper preflight | Mach `KERN_INVALID_ARGUMENT=4` |
| Captured trap handler | Mach `KERN_NOT_SUPPORTED=46` |
| Conclave spawn-attribute setter | Errno EINVAL22, ERANGE34, ENOMEM12; success0 |

These status domains must remain separate. The unsupported control handler does not prove that the local attribute setter fails, that every Conclave-related spawn path is unsupported, or that FairPlay uses either path.

The current FairPlay plist still matches SHA-256 `ca21543400f3ead9e96d2434f968184b6acd2e1e3de57322ca3da663831eae3c` and contains neither `_Conclave` nor `DaemonNotifications`. Effective overrides, programmatic configuration and actual job state remain unknown. This increment therefore establishes a generic optional interface and a captured build boundary, not a FairPlay protected-processing connection [EN1,EN5].

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test / falsification probe | Remaining boundary |
|---|---|---|---|
| EN1 | Captured cache, launchd and kernel registry describe the relevant dispatch path | Pin identities; verify trap name, raw row, two authenticated pointers, munger and complete constant-return handler | Effective loaded image, native dispatch and runtime support unknown |
| EN2 | Job/endpoint/identifier/name refer to one valid object epoch | Trace setter free/clear/duplicate, clone writer, common endpoint callback, request/registration flags and removal | Other writers, endpoint history, allocation and balanced retirement unknown |
| EN3 | Parsing and string callbacks have the required initialized semantics | Separate policy predicate8 from identifier presence; verify map types, length/name arithmetic, default table+0x78 zero and replacement initializer | Effective table, platform initialization, pointers, allocator and complete policy unknown |
| EN4 | Local registration state corresponds to backend effects only when justified | Preserve success-only set, error continuation and clear-after-attempt; record distinct name-helper selectors | Actual registration/deregistration, port identity, delivery and right balance unknown |
| EN5 | Generic Conclave interface is relevant to FairPlay or protected processing | Rehash current plist, retain absent keys and separate local spawn setter from control trap | Effective overrides, native job, spawn consumer and FairPlay attribution unknown |
| EN6 | Bounded locators and reconstructed geometry support only stated claims | Recapture all bodies/bytes, compare4894 fixups, compile SDK constants/geometry, solve full scalar domains and reject altered evidence | Hardware PAC/x1 semantics, exhaustive alias/writer census and canonical private types unknown |

## Further interface questions

| Impact | Remaining question | Concrete anchor |
|---|---|---|
| High | Runtime image/support correspondence | Compare the effective kernel build/entry with this pinned constant-return trap before interpreting user-space imports as available backend support |
| High | Conclave spawn serialization | Trace private attribute+0xf8 through the original spawn serializer and kernel consumer; control-trap result alone does not resolve this interface |
| High | String-table initialization | Recover the actual platform table passed to `___libkernel_platform_init`, especially bounded-length member+0x78 |
| Medium | Policy predicate8 | Resolve raw lookup selector32 and its producer, preserving the separate identifier-presence check |
| Medium | Notification object lifetime | Bind successful registration, numeric name, flags and deregistration to one object epoch on a matching supporting image |
| Low | Wider configuration producers | Extend the immediate-field locator to aliases/whole-record writes without treating matching offsets as object-type identity |

## Validation and quality gates

Fresh recapture matches the source. Checks pass202 selected instruction occurrences,13 SDK assertions in one arm64 compilation, three full-domain scalar proofs,4894 fixup comparisons and six rejected evidence alterations. Scalar proofs cover the u32 CMN port-name predicate, u64 length/capacity equivalence and u16 registration-bit set/clear formulas. They do not execute target records or reproduce a native failure. The SDK verifies public constants/widths and the explicitly reconstructed260 B C geometry [EN6].

No recovered target code, emulation, SVC, IPC, spawn, service/port mutation or IDB mutation executes. [Recovery](triage_evidence/recover_exclaves_notification_contract.py), [validator](triage_evidence/validate_exclaves_notification_contract.py), [delivery](triage_evidence/exclaves_notification_contract_delivery.json), [quality gates](triage_evidence/exclaves_notification_contract_quality_gates.json).

Capture/search is O(B+F+I+L) time/space for bytes B, fixups F, selected instructions I and locator records L. Direct strlen/setter work is O(n) in identifier length, plus allocator/backend costs; fixed scalar/flag operations are O(1). Complete parser, callback and native scheduler complexity is not inferred.

QG1: Descriptive interface analysis requires no normative premise.

QG2: EN1-EN6 record dependent results, falsification probes and unknowns.

QG3: Identifier production, property-to-endpoint route, register/deregister sites, record/argument ABI, initialization premise, spawn attribute and kernel boundary are covered; the full objective remains active.

QG4: Names use byte lengths excluding NUL; capacities128 B, record260 B, trap arguments56/64 B and code7688*4=30752 B are explicit. Mach and errno statuses remain separate.

QG5: File-default versus initialized table, request versus successful registration, local flag clear versus backend effect, local spawn attribute versus control trap and generic interface versus FairPlay use remain distinct.

QG6: Original bytes, chains, exports, trap registry/name, current plist, installed primary SDK and checked scalar domains supply provenance. Runtime support is not inferred.

QG7: Continuations have bounded anchors and impact labels. No native unsupported-result demonstration, backend notification or protected-processing claim is made.
