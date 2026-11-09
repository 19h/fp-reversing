# Repair notification, keybag resync and deeper AMS contracts

The alternate repair route now has an original appstoreagent consumer: XPCEventRelay converts a distributed event into an NSNotificationCenter notification; ArcadeManager reconstructs ASDRepairOptions and schedules RepairApplicationTask. This local route does not invoke the NSXPC broker's peer-capability predicate. Effective sender restrictions at launchd/distnoted/event delivery remain unknown; this finding does not establish admission of an arbitrary sender. [EV1-EV4]

The independent `com.apple.fairplayd.resync-fpkeybag` dispatch callback creates RefetchKeybag. The source chain reaches an `authorizeMachine` bag URL, response fields `keybag` and `diversitybag`, AMSKeybag, four obfuscated context/import/disposal routines, and an account-pair distributed notification. These extend the architectural map beyond daemon/kext transport. Native repair, filesystem mutation, account/network access, protected import and notification delivery have not run.

## Evidence, identities and bounded validation [EV1, EV5]

The agent is the original arm64e UUID `f79c256d-2b9d-36a6-bfba-d2a880093cc6`, SHA-256 `acd4f4a37478bb584aa58cfef9f5461c834b90a5fc578487702d74dad137a536`, established in the [receiver report](appstore_receiver_report.md). The reference dyld cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. Reference AppStoreDaemon UUID is `af31bfba-e128-3621-975e-75b02b3de4be`; AppleMediaServices UUID is `1b464993-f0e2-3804-b412-a6cc8091798c`.

| Retained source / experiment | Coverage |
| --- | --- |
| Agent original compiler ranges | 29 ranges, 1293 direct call edges, 135 original stubs |
| AppStoreDaemon option codecs | Six complete functions, 146 direct edges, 38 original target/stub records |
| AppleMediaServices | 19 complete functions, 220 direct edges, 66 original target/stub records |
| Private event cases | 17 cases: seven plain relay, one notifyd relay, one observer scheduling, eight option reconstruction |
| Private AMS import caller | Eight cases: nil input, context zero/error, import error, NULL pointer, zero/one/two output records |

[Contracts](triage_evidence/appstore_events_contracts.json) retain bytes, original nlist names, import/selector fixups, cache version5 chain membership, exact constants and caller ABI. [Event cases](triage_evidence/appstore_events_profiles.json) and [AMS cases](triage_evidence/ams_keybag_profiles.json) retain every visited original instruction and byte hash. The private models bypass PAC and explicitly implement host API results; task execution, protected algorithms and actual delivery remain outside these experiments.

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_appstore_events.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_appstore_events.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_ams_keybag.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_appstore_events_delivery.py
```

No original input, target binary, IDB or frozen earlier probe is modified. Cache faults in the AMS probe can map only successfully read original cache pages; guessed zero pages are not substituted. Unknown code/API targets and writes outside the private stack/heap stop execution.

## Distributed event relay and local observer [EV2-EV4]

```text
reference ASDRepairService alternate route
  -> distributed repair notification with option userInfo
  -> launchd/distnoted delivery [effective sender admission unknown]
  -> XPCEventRelay plain distributed handler
  -> NSNotificationCenter local repair notification
  -> ArcadeManager observer
  -> dispatch_async(captured notification)
  -> reconstruct ASDRepairOptions
  -> TaskQueue.addOperations(..., waitUntilFinished=1)
  -> RepairApplicationTask [execution/effects outside private cases]
```

| Agent address | Original role |
| --- | --- |
| `0x100140c10` | Event-stream installation routine |
| `0x100140ca8` | Installs `com.apple.distnoted.matching`, global block `0x10058cc10`, invoke `0x100140dfc` |
| `0x100140d1c` | Installs `com.apple.distnoted.matching.trusted`, block `0x100572640`, invoke `0x1001410d4` |
| `0x100140d90` | Installs `com.apple.notifyd.matching`, block `0x10058cc30`, invoke `0x1001415a4` |
| `0x10004d8b0` | ArcadeManager registers `_handleRepairBundleIDNotification:` for `com.apple.appstored.ASDRepairBundleID` on NSNotificationCenter |
| `0x10004d880` | `isHRNMode` bit0 skips this observer-registration branch; the mode's full semantics are unknown |
| `0x100058718` | Observer entry; extracts queue through original ivar cell `0x1005dbd4c`, initial offset64 bytes |
| `0x1000587a0` | Dispatches a block capturing the notification at block+32; invoke `0x1000587c4` |

The installer requests global queue identifier `0x15`, flags0, before installing the three event handlers. This identifies the requested API inputs, not effective scheduling or ordering. The trusted stream's name is a declaration; its selected body accepts UserInfo as either XPC dictionary or data and uses property-list decoding on its data branch. Complete producer authentication and all trusted-stream parse results are not established.

The plain handler rejects NULL/non-dictionary events, then reads the string under original symbol `__xpc_event_key_name`. The reference libxpc export at `0x1e0613df0` independently resolves this key to `XPCEventName`. It fetches nested dictionary `UserInfo` and checks its XPC type. A valid dictionary reaches `_CFXPCCreateCFObjectFromXPCObject` at `0x100140ff0`, then local `postNotificationName:object:userInfo:` at `0x1001410b4`, object=NULL. Missing/wrong-type UserInfo still reaches `postNotificationName:object:` at `0x100140f84`. A modeled NULL CF conversion reaches the userInfo-form post with NULL userInfo; actual CF failure reachability and Objective-C exception behavior remain unknown.

The notifyd relay checks event type/name and posts a local name-only notification at `0x1001416f4`. This is separate from the startup routine's direct notify_register_dispatch subscription below. The existence of both source paths does not prove duplicate delivery or two keybag refresh operations.

The agent plist places the repair event in the plain distributed stream. The shown plain relay and queued reconstruction contain no call to SecTaskCopyValueForEntitlement or the broker predicate `0x100125684`. Broker authorization, notification producer admission, launch-event selection and local observer activation therefore require separate provenance evidence.

## Notification option schema and route differences [EV3-EV5]

Reference `ASDRepairOptions copyUserInfoDictionary` at `0x1be16a2ac` supplies the posting route's dictionary. The consumer is original queued block `0x1000587c4`.

| Key | Reference writer | Original consumer |
| --- | --- | --- |
| `bundleID` | Object value | Reads first; used only if bundlePath is NULL; an internal-policy branch may substitute a configured identifier when absent/empty |
| `bundlePath` | Object value | A non-NULL value selects `initWithBundlePath:` at `0x1000589ac`; this has priority over bundleID |
| `status` | `numberWithInt:` from signed32 fairplayStatus | If object exists, calls unsignedIntValue then setFairplayStatus at `0x100058a00`; the setter consumes low32 bits |
| `exitReason` | `numberWithUnsignedInteger:` | unsignedIntegerValue, then setExitReason at `0x100058a34`; nil query modeled as0 |
| `isBackground` | `numberWithBool:` | No lookup in the complete queued consumer |
| `forceRevoke` | Written only under reference internal-security-policy condition | Read/set at `0x100058acc` only under the agent's independent internal-policy condition |
| `forceUpsell` | Written only under reference internal-security-policy condition | Read/set at `0x100058a88` only under the agent's independent internal-policy condition |

All dictionary keys are original literal strings with retained chain provenance. The inspected writer emits no accountDSID, claimStyle or relaunchOptions field; the consumer reads none of those keys. No dictionary-wide type/schema validator is visible before these dynamic Objective-C value messages. Unknown-type objects, conversion exceptions and framework-side initializer checks are not modeled as success.

For status `-42352`, the reference NSNumber carries signed32 `0xffff5a90`; unsignedIntValue returns the same32-bit pattern, and the original setter stores signed32 `-42352`. A private case with input `(2^32 + 0xffff5a90)` also stores `-42352`; this is a modeled NSNumber conversion, not proof of every producer's type behavior. The tested exitReason value `2^64-1` remains u64 `18446744073709551615` in the explicit setter model.

Private cases establish path priority, identifier fallback, absent/zero status, absent fields, low32 conversion and conditional force flags. An extra-fields case confirms no isBackground/accountDSID/relaunchOptions lookup on that path. Constructor/property APIs are explicit models; the report makes no claim that absent bundle inputs result in an actual successful repair.

After reconstruction, `0x100058b10` calls private RepairApplicationTask constructor `0x1000d3458` with X1=options, X2=NULL log-key argument. `0x100058bcc` calls `addOperations:waitUntilFinished:` with one task and W3=1. This differs from RepairService's asynchronous `addOperation:` handoff in the [receiver report](appstore_receiver_report.md). The private queue model records the wait request without executing a task or blocking; real completion, deadlock and scheduling consequences remain unknown.

## Keybag resync, authorization request and response imports [EV2, EV6]

| Agent source location | Contract |
| --- | --- |
| `0x10012462c` | notify_register_dispatch for exact C string `com.apple.fairplayd.resync-fpkeybag`; token output points into the owning object; queue from another ivar; block `0x1005720a8` |
| `0x100124ce0` | Direct dispatch callback; creates RefetchKeybag and sets byte at object+32 to0 |
| `0x1000f1610` | RepairService refreshKeybagWithReplyHandler: queues a refresh block |
| `0x1000f17e8` | Service's queued refresh sets RefetchKeybag byte+32 to1 |
| `0x1000fb004` | Account selection, byte+32 branches and promise/error paths; complete selected source retained |
| `0x1000fb778` | Calls appstoredService `recentBagWithCompletionHandler:` |
| `0x1000fc258` | Constructs AuthorizeMachine with W2=2, W3=RefetchKeybag byte+32 and X4=returned bag |
| `0x10018e670` | Requests URLForKey: with original `authorizeMachine` key |
| `0x10018e68c` | Calls requestWithMethod:URL:parameters:, W2=4, X3=selected URL, X4=parameters; method enum's nominal name is unknown |
| `0x10018ea3c`, `0x10018ec2c` | Selected response fields `keybag` / `diversitybag` reach AMSKeybag importKeybagWithData:error: |

The request path also configures account, client information, Anisette type and a trusted-URL flag through original selectors. The parameter routine `0x10018f100` references account DSID, device GUID/name and secure-token APIs, plus internal helpers. Exact effective URL, network method semantics, parameters, account identity, token provenance, response authenticity and server protocol remain unknown. No account/network APIs execute.

## AMS protected ABI and returned-record ownership [EV6, EV7]

Reference image is `/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices`; all addresses in this section belong to that reference cache image, not appstoreagent/fairplayd despite similar low address digits.

| Original name / address | Caller-established nature and contract | Evidence boundary |
| --- | --- | --- |
| `_df35957c4e0`, `0x19ca0d0e4` | Called with existing contextID u32 at `0x19c600124`; zero status retains the context, nonzero selects error/destroy handling | Local context-validation role; complete algorithm/state semantics unknown |
| `_XtCqEf5X`, `0x19c9e12a0` | Called at `0x19c6002e0` after path validation: X0=NULL, X1=stack+32, X2=`/Users/Shared/SC Info`, X3=object+8 contextID cell; zero status selects continuation | Context-creation role from caller; complete input/output ownership and stack-record schema unknown |
| `_ha0dkchaters6`, `0x19c9ec168` | Called at `0x19c64891c`: W0=contextID, X1=NSData bytes, X2=NSData length u64, X3=output pointer64 cell, X4=output count32 cell; W0 status0 selects output handling | Keybag import caller ABI; cryptographic/persistence/IPC algorithm not recovered |
| `_jEHf8Xzsv8K`, `0x19ca1dd68` | Called at `0x19c648a18` with returned record pointer after account-pair handling | Disposal role; allocator/deep release contract remains unknown |

`AMSFairPlayContext contextID` at `0x19c6006fc` loads W0 from object+8; it is a u32 context identifier, not a pointer64. The import block initializes pointer output toNULL and count output to0. A nonzero import status creates an AMS error with outer code505, incorporating the signed32 underlying status in its description. A zero status with NULL output pointer sets success; a non-NULL pointer is disposed even when count is0. Nil input data selects success without context/import calls in this framework block; the inspected agent response path has a separate non-NULL field condition.

| Returned record offset | Width / consumption |
| --- | --- |
| +0 | u64 purchaser account ID, passed in X3 |
| +8 | u64 downloader account ID, passed in X2 |
| +16 | u64 family ID, passed in X4 |
| +24 | Eight bytes unused by this caller; meaning unknown |
| Stride | 32 bytes; loop counterX22 compared unsigned against zero-extended output count32 |

The caller builds AMSFamilyAccountPair objects via `initWithDownloaderAccountID:purchaserAccountID:familyID:`. One/two-record private cases use distinct values at every field, including sentinels in the unused+24 field, to verify permutation and stride. The output count is not a proven allocation extent; its consistency with the protected algorithm's actual buffer remains unresolved. The private model limits itself to the supplied finite records.

The wrapper `importKeybagWithData:error:` at `0x19c648678` executes its import block through exact bound dispatch_sync at `0x19c6487c8`, with a retained queue from self+8 and byref success/error cells. Normal return copies error if caller supplied an output pointer and reads a success byte. Reentry, actual queue identity and synchronization/exception behavior remain unverified. The Swift-facing adapter tail-dispatches the same selector.

## Account-pair notification emission and environmental touch points [EV6-EV8]

After nonempty account-pair construction, the import caller invokes AMSFamilyContentDeletionEvent. Its payload helper `0x19c602970` creates an array of dictionaries with unsigned64 NSNumber values and wraps it under key `pairs`. The class identity is established by original cache class chains/exports, not inferred from a selector name.

| Payload key | Source |
| --- | --- |
| `pairs` | Array of per-account dictionaries |
| `did` | downloaderAccountID, returned record+8 |
| `fid` | familyID, record+16 |
| `pid` | purchaserAccountID, record+0; this key is not a process identifier here |

Original `+[AMSFamilyContentDeletionEvent postDistributedNotificationWithAccountPairs:]` at `0x19c602914` gets the distributed CF notification center at `0x19c602934` and calls exact bound CFNotificationCenterPostNotification at `0x19c60294c`, name `com.apple.StoreServices.SSVFamilyContentDeletionNotification`, object=NULL, userInfo=constructed payload, deliverImmediately=false. This is a newly established framework emission boundary; the underlying Mach transport send, numerical port rights, recipients and content-deletion effects remain unknown. The eight AMS private cases stop at a modeled class method and do not execute this CF emission.

Context validation `_validateFairPlayPath` at `0x19c6003a0` uses `/Users/Shared/SC Info`, checks directory existence, and can request directory creation. It reads `com.apple.FinderInfo` through exact getxattr at `0x19c6005d4` into an initially zeroed32-byte buffer, then ORs byte8 with `0x40` and calls exact setxattr at `0x19c6005fc` with size32, position0 and options1. No getxattr-result test intervenes before the byte operation; setxattr's result is tested. This establishes a conditional metadata/error-flow dependency without establishing native permissions, actual mutation, data loss or a defect. Complete xattr/directory policy remains open.

## Assumption register, bounded opportunities and quality gates

The later [protected AMS/CoreFP report](ams_core_report.md) resolves the disposal routine to exact `_free` plus two mutable-cell writes and a NULL/status partition. It decodes the context wrapper's48-byte record/operation0xc4b,shared once/200-byte lock initialization,CoreFP load/five symbol lookups and certificate-bearing public-call boundary. These refine the caller roles above without establishing native import,persistence,transport or certificate validation.

| ID | Assumption / dependent results | Stress test / falsification probe | Status |
| --- | --- | --- | --- |
| EV1 | Original selected image, cache, nlist/metadata and pointer chains define these reference contracts | Rehash agent; verify exact cache UUIDs, chain membership, selector/literal bytes and compiler spans | Original bytes verified; runtime pairing unknown |
| EV2 | Declared launch streams/direct registration select the displayed callbacks | Bind actual launch domain, producer/consumer, event registration status, HRN mode, queue and methods to the retained images | Local source mapping verified; actual publication/delivery unknown |
| EV3 | Notification input types and option API models explain the stated reconstruction | Vary missing/wrong types, name/UserInfo conversion, bundle priority, numeric width and internal policy; inspect initializer failures/exceptions | 17 finite original cases; complete native schema/exception behavior unknown |
| EV4 | External event provenance is preserved before the local relay | Recover distnoted/launchd/event authorization and producer identity; compare trusted/plain routes | Local absence of broker predicate verified; sender admission unknown |
| EV5 | Reference copyUserInfoDictionary and agent consumer form the route's schema | Attest loaded framework/agent pairing and compare all effective keys/setters | Original writer/consumer fields retained; actual runtime dictionary unknown |
| EV6 | Account/bag/network and AMS callback contracts apply to the route | Verify effective account, bag URL, method enum, request/response validation, framework/class replacement and callback ordering | Static reference chain; no account/network/import operation observed |
| EV7 | Explicit context/import/output/disposal models preserve the selected caller ABI | Vary nil/context/error/pointer/count/record cases; recover protected outputs, allocator and native lifetime before promoting claims | Eight private cases; protected algorithm and native lifetime unknown |
| EV8 | Cache path/xattr literals and call inputs describe the context environment | Inspect original get/set error paths and matching SDK/kernel contracts; establish actual path policy when authorized | Source values verified; native directory/xattr state/effects unknown |

| Impact | Next concrete evidence |
| --- | --- |
| High | Recover plain/trusted event producer admission, payload origin and native NSXPC/notification port rights before relating these routes' authorization |
| High | Follow AMSFamilyContentDeletionEvent receivers and bind their actions to account identities; do not interpret payload `pid` as a process ID |
| High | Recover `_ha0dkchaters6`, context creation/checking and record disposal beyond caller semantics, including actual persistence and daemon/kext IPC |
| High | Resolve appstored recent-bag service, authorizeMachine request/response schema, secure-token context and response-field validation |
| Medium | Complete notification option loss/defaults, internal-policy asymmetry, object-type exceptions and synchronous task-wait consequences |
| Medium | Trace resync notification producers, status/token output, queue/reentry and restart/lifetime behavior |
| Medium | Recover SC Info directory and FinderInfo get/set failure semantics and actual allocation/record-count relationship |

Extraction is O(B+I+F+S) for retained bytes, instructions, fixups and symbols. Finite probes are O(C*K), C=25 across two harnesses, K<=4000 instructions per case; mapped memory is O(P) original pages plus bounded private heap/stack. Returned record iteration is O(N) time and O(N) constructed objects for countN, conditional on a valid returned extent. All offsets/lengths are bytes; u32/u64 and signed32 widths are explicit. No execution timing or native scheduling claim is derived.

QG1 descriptive technical scope; QG2 EV1-EV8 with dependency/probe/status; QG3 passes for the event/keybag increment while the full objective remains active; QG4 original widths/layouts/counts and bounded algorithms; QG5 broker admission/event provenance, local reconstruction, task scheduling, protected import, callback and delivery remain distinct; QG6 original source/cache/chain/nlist metadata and25 finite original-byte readbacks; QG7 impact-labeled continuation. [Checks](triage_evidence/appstore_events_profile_checks.json), [quality gates](triage_evidence/appstore_events_quality_gates.json), [manifest](triage_evidence/interface_manifest.json).
