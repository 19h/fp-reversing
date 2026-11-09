# appstoreagent receiver, peer capability and repair selection

The original co-installed appstoreagent supplies the receiving side of the daemon's AppStore repair route. Its broker listener configures and resumes an NSXPC connection, then returns true. Repair-service vending has a separate peer capability gate: the connection's audit token creates a SecTask, the `com.apple.private.appstored` entitlement must be an array, and that array must contain `Repair`. The repair policy supplies no alternate Boolean entitlement key. The daemon's embedded XML declares `["Repair"]` for this entitlement. Effective runtime entitlements, connection identity and numerical Mach rights remain unknown. [AS1-AS4]

The receiver queues a RepairApplicationTask. The inspected selection sequence tries ArcadeRepair before FairPlayRepair when a repair object is not already selected. ArcadeRepair has an account-dependent acceptance path and a five-value signed32 status set; the daemon's current repair status `-42352` is outside that set. Twenty-five private original-byte cases and two local SMT proofs corroborate these limited policy contracts. No native listener, account query, entitlement query, repair operation or target IPC executes. The broad interface investigation remains active.

## Source identity and reproducibility [AS1]

| Source | Original identity |
| --- | --- |
| `/System/Library/PrivateFrameworks/AppStoreDaemon.framework/Support/appstoreagent` | Universal SHA-256 `7c05d92bfb7281bea6ce612cc01db143952c8691a6de8c93b325b6b6091c1a9c`; 19772320 bytes |
| Selected arm64e slice | File offset 6848512; 6501568 bytes; SHA-256 `acd4f4a37478bb584aa58cfef9f5461c834b90a5fc578487702d74dad137a536`; UUID `f79c256d-2b9d-36a6-bfba-d2a880093cc6` |
| Launch-agent declaration | `/System/Library/LaunchAgents/com.apple.appstoreagent.plist`; SHA-256 `614637685e78f2b3403776607c1f1e3f75816c486c46edf12cb21c4ad47d7512` |
| Extracted metadata | 10899 compiler function starts; 41985 format12 chained pointers, independently walked and matched to dyld_info; 529 classes and 2264 methods |
| Selected analysis corpus | 103 complete compiler ranges; 1600 direct call edges; 169 retained original stubs; four policy/error constants and eight interface fixups |

Addresses below are unslid virtual addresses in this selected slice. The [inventory](triage_evidence/appstore_agent_inventory.json), [complete recovered Objective-C metadata](triage_evidence/appstore_agent_objc_metadata.json) and [selected contracts](triage_evidence/appstore_agent_contracts.json) retain source bytes, original chain words, selectors, type encodings and range hashes. The extraction parses code-signature metadata; it does not authenticate signatures or decode DER entitlements. These are original-file reference claims, not an attestation of loaded runtime methods.

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/appstore_agent_reader.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_appstore_agent.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_appstore_agent.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_appstore_agent_delivery.py
```

These commands read the original binary/plist and write owned analysis artifacts. The emulator maps private copies of original image bytes and four permitted original functions; unknown functions/APIs and the instruction limit stop the probe. PAC operations are explicitly bypassed, API results are modeled, and no native service/framework call is made.

## Named endpoint, listener and admission [AS2-AS4]

The previously recovered reference broker calls `initWithMachServiceName:options:` for `com.apple.appstoreagent.xpc`, options0. The agent plist declares that exact Mach service and restricts loading to `Aqua`; it also subscribes to the alternate repair notification `com.apple.appstored.ASDRepairBundleID`. This corroborates both logical routes from the [repair adapter report](appstore_repair_report.md). The framework's key6 string query and the launch-agent session restriction are separate observations; their runtime equivalence is unproved.

```text
fairplayd: ASDRepairOptions(path, exitReason=16, status=-42352)
  |
  +-- reference Aqua route -> com.apple.appstoreagent.xpc
  |                            |
  |                     XPCServiceBroker listener
  |                            |
  |                     XPCServiceClient
  |                            |
  |                     auditToken -> SecTask
  |                            |
  |                     appstored array contains "Repair"?
  |                            |
  |                     RepairService singleton
  |                            |
  |                     queued RepairApplicationTask
  |
  +-- alternate route -> distributed repair notification
                           |
                    declared agent launch event
                    actual consumer/effects unknown
```

| Original receiver location | Established role |
| --- | --- |
| `0x100100ea8..0x10010108c` | `XPCServiceBroker listener:shouldAcceptNewConnection:` |
| `0x100100ef0` | Calls private client constructor `0x1000b2bfc` with X0=client class, X1=connection, X2=catalog; ordinary `_cmd` is absent |
| `0x100100f74` | Sets exported interface from bound ASDServiceBroker class |
| `0x100100f88` | Sets exported object to the constructed XPCServiceClient |
| `0x100100fa8` | Sets remote interface from bound ASDNotificationCenter class |
| `0x100101000`, `0x100101008` | Installs invalidation block, then resumes connection |
| `0x10010106c` | Sets return W0=1 on the normal listener path |
| `0x1000b2dfc` | Obtains 32-byte connection auditToken using indirect result X8=stack buffer |
| `0x1000b2e18`, `0x1000b2e28` | Gets processIdentifier; constructs XPCServiceEntitlements from token and PID |
| `0x100125478` | Calls original bound SecTaskCreateWithAuditToken with the copied token |
| `0x1001254b0` | Queries `com.apple.private.appstored`; the result must have CFArray type before storage at context+8 |

The connection is stored weakly at client+24; the catalog is strong at client+16; the entitlement context is stored at client+40. The context stores the capability array at+8, SecTask at+16 and diagnostic PID as u32 at+24. Peer authorization is therefore tied to the connection token in these original calls; a task's embedded XML alone does not establish the effective values returned by SecTask.

The listener's true return does not establish that an arbitrary peer obtains the repair object. Actual NSXPC port allocation, right transfer, audit-token origin, publication syscall, effective interface serialization and method replacement remain unknown. API setup locations above are not Mach emission locations.

## Repair-object vending and capability predicate [AS3-AS5]

| Original instruction / record | Contract |
| --- | --- |
| Startup `0x100124044` | Stores the retained `Repair` token and NULL alternate key through pair setter `0x100163f84`; catalog pair offset432 bytes |
| Startup `0x100124058` | Copies factory block `0x10058ca08` to catalog offset136 bytes |
| `getRepairServiceWithReplyHandler:` `0x1000b3be8` | Obtains factory at catalog+136 and policy pair through `0x100163f34`; passes them and callback to `0x1000b3088` |
| `0x1000b3110` | Calls capability predicate `0x100125684` on client+40 with the policy pair |
| `0x1000b3114` | Requires predicate W0 bit0 before factory invocation at `0x1000b3124` |
| Factory invoke `0x100124afc` | Supplies RepairService class and tail-calls singleton getter `0x1000f12e0` |
| `0x1000b3144` | Calls reply block with X1=constructed service, X2=NULL error |
| Failure paths | NULL factory replies with error code512 and `Service is not available.`; rejected capability replies with code505 and `Not entitled for this service.` |

The helper's private register ABI is X0=client, X1=factory block, X2=capability token, X3=alternate Boolean entitlement key, X4=reply block. The local CFG confirms that removing the gate call makes the factory invocation unreachable; the following TBZ explicitly enforces its low bit. This proof excludes exceptions, callback internals and runtime replacement.

The general predicate first calls `containsObject:` on the stored capability array. Its original CMP/CSINC/TBNZ sequence returns the membership result immediately when membership bit0 is set or the alternate key is NULL. Otherwise it queries that alternate key, requires a CFBoolean value and normalizes its Boolean result. The repair pair uses a NULL alternate key, so its displayed contract is array membership in `Repair`; there is no Boolean alternate for this configured repair service.

The daemon thin image's embedded XML has `com.apple.private.appstored = ["Repair"]`; the exact entitlement blob hash and binary hash are retained in the contracts. Signature authentication, DER equivalence and effective peer SecTask entitlements are unknown. Two private general-predicate fixtures model a non-NULL query-error output: the original code logs it but can still accept a separately supplied true CFBoolean. Whether that joint API result is reachable is unknown; this is a conditional caller contract, not a native failure finding.

## Queued repair ABI and conditional selection [AS4-AS6]

`RepairService repairAppWithOptions:replyHandler:` at `0x1000f1378` retains options/callback, builds a block with captures options, log-key and reply, calls `dispatch_block_create` with flags `0x24` at `0x1000f1444`, then `dispatch_async` on service+8 at `0x1000f1454`. The queued block `0x1000f14a8` constructs RepairApplicationTask through private constructor `0x1000d3458`, sets a copied completion block and calls TaskQueue's underlying `addOperation:` at `0x1000f1560`. This is asynchronous scheduling, not completion evidence.

Task `mainWithCompletionHandler:` at `0x1000d3544` resolves an application from options.bundleID if present, otherwise options.bundlePath. In the inspected no-preselected-repair sequence, it calls ArcadeRepair's `shouldAttemptToRepairApplication:options:logKey:` at `0x1000d36ac`; if no object is selected it tries FairPlayRepair at `0x1000d36f4`. The selected object's `repairApplication:completionHandler:` is dispatched at `0x1000d3854`. A pre-existing repair field bypasses this selection sequence; initialization and all writers are not exhaustively proved.

ArcadeRepair's class predicate at `0x1001285b0` queries `ams_activeiTunesAccount`. If no account is active and application helper `0x10004c20c` classifies the app as Arcade, it returns true before reading the supplied status. Otherwise it requires that same classification, obtains options.fairplayStatus through `0x10012880c`, and applies the following common signed32 partition:

| Signed32 | Raw u32 | Common Arcade acceptance |
| --- | --- | --- |
| -42587 | `0xffff59a5` | true |
| -42585 | `0xffff59a7` | true |
| -42584 | `0xffff59a8` | true |
| -42110 | `0xffff5b82` | true |
| -42112 | `0xffff5b80` | true |
| -42352 | `0xffff5a90` | false |

The original arithmetic is `delta = (status + 0xa65b) mod 2^32`; accept when `(delta <= 3 unsigned AND delta != 1)` or status equals either `0xffff5b82` or `0xffff5b80`. Both the initial branch and repeated final branch have this set; a QF_BV counterexample query is unsatisfiable over all 32-bit status inputs. This proves the local arithmetic, not complete repair behavior.

The application helper uses metadata `isArcadeApp`; an internal-security-policy branch can consult a separate bundle-ID set. Private fixtures force the internal-policy API false. FairPlayRepair rejects Arcade-classified apps and has beta/internal-policy/status dependencies; its helper `0x100034fe8` can use a supplied nonzero status under an internal policy, otherwise it calls `0x100035ecc`. That adapter gates on metadata platform2 and passes a filesystem path to protected internal routine `0x1003afe84`. The protected routine's full semantics and IPC remain unknown. A shared status or repair name alone does not identify its protocol.

## Port and environmental footprint [AS2]

| Declaration | Named interfaces / meaning |
| --- | --- |
| Broker and legacy | `com.apple.appstoreagent.xpc`, `com.apple.appstoreagent.legacy` |
| Store interfaces | `com.apple.aps.appstoreagent`, `com.apple.storekitservice`, `com.apple.appstored.xpc.storequeue` |
| On-demand interfaces | `com.apple.ondemandd.appreview`, `.client`, `.appinstall`, `.devtools`, `.CacheDelete`, `.launchservices`, `.odrctl` |
| Other endpoints | `com.apple.appstoreagent.CacheDelete`, `com.apple.usernotifications.delegate.com.apple.AppStore` |
| Distributed launch event | Exact repair notification `com.apple.appstored.ASDRepairBundleID` |
| notifyd launch event | `com.apple.fairplayd.resync-fpkeybag` |
| Session / lifetime | LimitLoadToSessionType=[Aqua], EnableTransactions=true, EnablePressuredExit=true, ProcessType=Adaptive, RunAtLoad=false |

All14 MachServices values are true in the original plist. The suffix notation in the on-demand row expands under prefix `com.apple.ondemandd`; complete exact strings are retained in the inventory. This is a declared activation surface, not observed publication of14 live ports. The agent's embedded XML also declares Mach-lookup exceptions for `com.apple.fpsd`, `com.apple.fairplayd` and `com.apple.fairplayd.xpc`; actual lookups, outgoing port names and receive/send emission locations remain unknown. The resync event and lookup names identify additional feedback paths for investigation without proving traffic on them.

## Assumptions, bounded continuation and quality gates

The subsequent [event/keybag report](appstore_events_report.md) follows the distributed repair notification through XPCEventRelay, the local observer and queued option reconstruction. It also traces resync-fpkeybag through RefetchKeybag, authorization, AMS context/import/disposal routines and a family-content-deletion notification. The local notification path differs from broker vending in both authorization provenance and option preservation; effective external event admission remains unknown.

| ID | Assumption / dependent results | Falsification probe | Current status |
| --- | --- | --- | --- |
| AS1 | Original files, selected slice, format12 pointers and compiler boundaries establish this reference receiver | Rehash universal/slice/plist; independently walk chain starts and compare original words, metadata and instruction spans | Verified original bytes; native load identity unknown |
| AS2 | Installed plist describes the relevant agent's deployment configuration | Bind job/domain/session and actual ports to this executable UUID and plist; inspect effective launch events | Static declarations verified; runtime publication unknown |
| AS3 | Original NSXPC token/SecTask calls and configured catalog pair govern this route | Attest effective methods, peer audit token, catalog writers and effective entitlement result | Static local chain verified; complete runtime provenance unknown |
| AS4 | Reference framework's repair proxy reaches this protocol implementation | Verify loaded framework/agent pairing, export serialization, service object identity and actual selected environment branch | Logical name/selector correspondence verified; actual connection unknown |
| AS5 | Private API/BOOL/CFType models and PAC bypass preserve stated local branches | Vary member/key/value/error/type/task cases; enable logging paths; compare independent source/native observations when authorized | 12 predicate cases; two local SMT proofs total; no hardware PAC/API reachability proof |
| AS6 | Modeled account/classification/status inputs explain the displayed Arcade predicate | Vary account, application metadata, internal-policy result and all repair-field writers; distinguish selection from repair effects | 13 Arcade cases; status predicate proved over all u32; full task/repair execution unknown |

| Impact | Additional evidence / unresolved boundary |
| --- | --- |
| High | Recover protocol object encoding/decoding and effective token-to-peer identity; numerical Mach rights and emission sites remain missing on this NSXPC leg |
| High | Trace the distributed repair notification consumer and reconstruction/validation of ASDRepairOptions; the plist subscription alone does not establish equivalent authorization |
| High | Recover account-dependent Arcade repair effects and protected FairPlay adapter `0x1003afe84`; bind any feedback RPC to the existing daemon/kext request tables |
| Medium | Trace `com.apple.fairplayd.resync-fpkeybag`, lookup exceptions, refresh-keybag selector and their port/context/lifetime dependencies |
| Medium | Complete catalog replacement, service construction failures, queue lifetime, callback/error ownership and repair-field writer coverage |

Extraction is O(B+F+M+I) for image bytes, fixups, methods and selected instructions; the local CFG reachability check is O(V+E); finite probes are O(C*K) with C=25 cases and K=3000 instructions per case, with private memory O(B). SMT solver complexity is separate; these are fixed-width QF_BV queries. Widths and sizes above are bytes or stated u32/signed32/u64 values; there is no timing inference from the private model.

QG1 descriptive analysis; QG2 AS1-AS6 include dependencies/probes/status; QG3 passes for this increment with the broad goal active; QG4 original register widths, offsets, hashes and bounded algorithms; QG5 listener admission, service vending, account/status selection, scheduling and completion kept distinct; QG6 original bytes/chains/metadata/plist, two SMT proofs and finite original-byte readbacks; QG7 impact-labeled continuation. [Verification checks](triage_evidence/appstore_agent_profile_checks.json), [quality gates](triage_evidence/appstore_agent_quality_gates.json), [owned manifest](triage_evidence/interface_manifest.json).
