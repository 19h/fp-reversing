# Daemon AppStore repair adapter, broker and environment-dependent IPC

The daemon's previously unfinished bundle-prefix continuation assembles an AppStore repair request. Original adapter`0x100002134` constructs ASDRepairOptions,sets exitReason16 and a FairPlay status,then calls ASDRepairService with an empty global reply block. Six unchanged144-byte service responses complete the private daemon61571 buffer with status0/decision1 after an explicit normal repair-return model. No native repair, framework call, callback or IPC executes.

The installed reference AppStoreDaemon framework exposes two routes: a queried string equal to`Aqua` selects a repair-service remote proxy; a non-equal result or query error selects a distributed notification. The default broker's named Mach service is `com.apple.appstoreagent.xpc`. Actual runtime route, numerical Mach names, endpoint objects and right transfers remain unknown.

## Original adapter and ABI [AR1, AR2]

| Daemon instruction / object | Established role |
| --- | --- |
|`0x100002134..0x1000021bc` |Complete compiler-bounded repair adapter; X0=C-string bundle prefix,X1=status scalar |
|`0x100002154` |NSString `stringWithUTF8String:` |
|`0x100002164` |`objc_alloc(ASDRepairOptions)` |
|`0x10000216c` |`initWithBundlePath:` |
|`0x100002178` |`setExitReason:` with X2=16 |
|`0x100002184` |`setFairplayStatus:` with the saved status argument |
|`0x100002190` |`ASDRepairService.defaultService` |
|`0x1000021b8` |Tail dispatch `repairAppWithOptions:replyHandler:` |
|Block`0x101038020` |32-byte global block,flags`0x50000000`,invoke`0x1000021bc` |
|Invoke`0x1000021bc` |Exactly one RET; supplied reply values are unused |

Original selector slots and AppStoreDaemon class/import fixups corroborate these roles. The adapter name is descriptive; no IDB function was renamed. [Original daemon/cache contracts](triage_evidence/appstore_repair_contracts.json) retain three daemon spans,seven stubs and the block's original fixups.

For all six current144-byte response cases, the adapter receives raw64`0x00000000ffff5a90`. Reference property metadata declares `fairplayStatus` as `Ti,N,V_fairplayStatus`; its setter at`0x1be16ab00` stores W2 at object+12 and its getter loads W0. Thus the stored value is signed32:

```text
0xffff5a90 =4294924944 unsigned32
4294924944 -2^32 =-42352 signed32
```

`exitReason` is declared `TQ,N,V_exitReason`; setter`0x1be16aaf0` stores X2 at object+48. All ten original property names/attributes are retained through independently decoded cache chains. This prevents interpreting the FairPlay status as the positive64-bit register value4294924944.

## Broker and outgoing remote interface [AR3]

Reference library: `/System/Library/PrivateFrameworks/AppStoreDaemon.framework/Versions/A/AppStoreDaemon`, UUID`af31bfba-e128-3621-975e-75b02b3de4be`; cache UUID`2bd06591-e751-3e84-963f-b08dab6af23a`. Twenty-four complete selected functions,199 direct call edges and52 retained target/stub records cover the local adapter/proxy/notification/broker scope. Direct internal or unresolved targets are explicitly distinguished from resolved imports/selectors.

| Original reference location | Architectural contract |
| --- | --- |
|Default-broker block`0x1be1440f0` |Supplies original constant`com.apple.appstoreagent.xpc` to broker initialization at`0x1be144118` |
|Broker `_connect` `0x1be1442c8` |Creates NSXPCConnection; service name from broker+32 |
|Connection initializer`0x1be144304` |`initWithMachServiceName:options:`; options0; connection stored at broker+8 |
|Resume`0x1be14440c` |Resumes the constructed connection after interface/handler setup |
|`getRepairServiceWithError:` `0x1be15eed0` |Uses a synchronous broker proxy and `getRepairServiceWithReplyHandler:` to obtain a repair service |
|Repair helper`0x1be1640fc` |Gets repair service,then `remoteObjectProxyWithErrorHandler:` |
|Remote dispatch`0x1be1644bc` |`repairAppWithOptions:replyHandler:` on that proxy |

The protocol is named `ASDRepairServiceProtocol` in original framework metadata/nlist records. These are logical NSXPC service/interface contracts; the actual underlying send/receive rights and port-emission syscalls are not established here. The broker Mach-service name belongs to the selected reference route, not an observed kernel port object.

Some private framework helpers are compiled direct calls with register layouts established from their call sites rather than the ordinary Objective-C selector slot. In particular the notify helper is called with X0=self,X1=options,X2=callback; the asynchronous-proxy helper takes X0=self,X1=error block. Their nlist method-style labels alone do not establish an additional `_cmd` register.

## Environment-dependent notification route [AR3, AR4]

The public repair method at`0x1be1641e0` calls the exact bound `_vproc_swap_string` at`0x1be164238`, with inputs NULL,key6,NULL,&string. The key's nominal enum name is unknown. The returned string is compared with original literal`Aqua` through a chained `__platform_strcmp` target at`0x1be1642a0`.

```text
ASDRepairService.repairAppWithOptions:replyHandler:
  +-- query returns normally with string equal to "Aqua"
  |     -> broker repair service -> remote proxy -> repair request
  |
  +-- query error or string differs
        -> options representation
        -> distributed notification
        -> sleep request1s
        -> callback(1,NULL,NULL)
```

| Reference instruction / constant | Notification route |
| --- | --- |
|Notify helper`0x1be1644ec` |Selected from the non-Aqua/error branch |
|Constant object`0x1e6c48a58` |`com.apple.appstored.ASDRepairBundleID`,37 bytes |
|Post`0x1be1645a8` |NSDistributedNotificationCenter `postNotificationName:object:userInfo:options:`; object NULL,userInfo from options,options2 |
|Sleep`0x1be1645c0` |NSThread `sleepForTimeInterval:` with binary64 value1.0s |
|Reply invocation`0x1be16462c` |If callback exists,arguments1,NULL,NULL |

Original class/export chains identify NSDistributedNotificationCenter and NSThread. The installed SDK defines option2 as `NSDistributedNotificationPostToAllSessions`; layout/constant assertions compile for arm64e. No notification or sleep runs. The posting route neither proves that a recipient repairs the application nor authenticates any notification consumer. The returned callback values and the daemon's empty callback do not establish repair success.

## Completed private result and remaining kernel boundary [AR2]

The six [receipt-response cases](triage_evidence/arcade_receipt_reply_profiles.json) use original daemon instructions to convert the application prefix `/private/synthetic/ArcadeFixture.app`,assemble options `{bundlePath:prefix,exitReason:16,fairplayStatus:-42352}`,and reach the repair method with the original global block. Private models record that intended request and return normally without invoking a framework or callback.

After that explicit return, every case completes MIG61571 with size40,status0,decision1. The provisional decision1 is retained; unlike the developer-response path,no zero-decision store at`0x1004d7b0c` occurs. Original status/NDR/size stores at`0x100005544`,`0x100005554`,`0x100005560` complete the buffer. The actual CF reply send and kernel transaction do not run. Previously recovered kernel control flow selects its task-related action for a completed status0/word1; this increment does not observe that action natively.

Transport success,receipt outcome,repair request assembly,repair completion and the kernel action therefore remain separate states. A six-case private match does not establish native service availability or lifetime.

## Assumption register, continuation and quality gates

The subsequent [receiver report](appstore_receiver_report.md) identifies the original co-installed appstoreagent listener, peer audit-token/SecTask construction and separate repair-service vending gate. The configured policy requires `Repair` in the peer's `com.apple.private.appstored` array; daemon embedded XML declares that capability, while effective entitlements remain unknown. It also follows the queued task's Arcade-before-FairPlay selection and conditional account/status predicate. This closes part of the receiver/authorization gap below; actual NSXPC port rights/serialization, notification consumption and repair effects remain open.

The later [event/keybag report](appstore_events_report.md) resolves the local notification consumer and original copyUserInfoDictionary schema. The consumer does not read the written isBackground field and gates force flags on its own internal policy. It queues one task with waitUntilFinished=1. The notification stream's effective external admission and actual repair completion remain unknown; these local contracts do not establish equivalent authorization to the broker route.

| ID | Assumption / dependent claims | Falsification probe | Status |
| --- | --- | --- | --- |
| AR1 |Daemon source/selectors/block define the displayed adapter |Rehash file,decode original import/selector slots and one-instruction callback |Original bytes verified |
| AR2 |Opaque options/service and normal-return models preserve the displayed completion |Vary allocation/initializer/framework returns and caller-saved effects; independently inspect actual repair events |Six private completed cases; no native request/callback |
| AR3 |Reference framework/cache method and broker metadata correspond to runtime |Attest loaded UUIDs,method replacement,broker selection and actual connection state |Static reference verified; runtime pairing unknown |
| AR4 |Queried string comparisons select the displayed route |Inspect actual key6 output and errors without conflating them with the service's host special ports |Local branch recovered; actual environment/route unknown |

| Impact | Next evidence |
| --- | --- |
| High |Bind the effective environment and broker instance to the notification versus remote route |
| High |Recover appstoreagent repair-service receiver,protocol serialization and listener/port transfers |
| High |Trace notification consumers,options representation,receipt repair effects and result authentication |
| Medium |Complete proxy/error/callback lifetimes,broker reconnect/invalidation and1s-delay consequences |
| Medium |Link native repair/CF reply/task-action event ordering while keeping namespaces and ownership separate |

QG1 descriptive scope; QG2 AR1-AR4 with probes; QG3 passes for this increment,full goal active; QG4 exact32/64-bit properties,37-byte name,1s request and SDK declarations; QG5 remote/notification/native/model/result stages separated; QG6 original bytes,nlist,chains,SDK and source-pinned cases; QG7 impact-labeled continuation. [Checks](triage_evidence/arcade_receipt_profile_checks.json), [gates](triage_evidence/arcade_receipt_quality_gates.json), [manifest](triage_evidence/interface_manifest.json).
