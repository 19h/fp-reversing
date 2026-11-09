# notifyd startup, admission and paired notification state

This increment connects original libnotify public calls to original notifyd startup,selectors,stubs,workers and collection routines in two private guests. The three ADID-name sequences now obtain registration/checkin replies from original server code,post through the original server,observe its counter update through an explicit shared-byte alias,and cancel through the original server. Transport headers,audit tokens,external API results and scheduling remain declared fixtures. This is a complete private source pipeline for the stated cases,not a native transaction.

The [transport report](notify_ipc_report.md) supplies the previous source identities,Mach emission catalog,MIG layouts and local parser controls. The [ADID notification report](adid_notification_report.md) supplies upstream akd cache use and the separately scoped adid post fragment. Those protected-provider predecessors are not established by this increment. The daemon/kext/deeper-facility investigation remains active.

```text
original notifyd main
  collections + shared arrays + internal IPC-version name
  queues + channels + publisher + process-monitor declarations
                  |
original libnotify public entry
  raw Mach buffer -> [modeled header/audit transport]
                  -> original selector -> original MIG stub -> original worker
                  <- [framework header + original reply body]
  original client reply parser
                  |
  [declared shared-object byte alias between private guests]
                  |
  original notify_check -> changed flag -> upstream cache consumer

Publisher callback,reason2 (explicit delivery):
  mach-notifs channel <- internal receive-name output
  request channel     <- bootstrap service receive-name output
```

A1-A12 delimit every source/fixture/native inference below. All addresses are unslid.

## Evidence and execution scope

Original notifyd universal SHA256 remains `79105a37b75d37f43ea0190ae1f5307f775446730774ee76b62a3484b8166c15`;selected arm64e subtype`0x80000002` SHA256 remains `aeeae7016d04af9b2a08f0491559ac0291ec3954fd93bdf167c30607d44fae23`,UUID `d27ffd43-6f5d-3882-8bcf-4853e8a0b288`. The original cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`;libnotify UUID is `266b92ef-8350-347c-9086-b53ba04523cf`.

The [stateful provider engine](triage_evidence/probe_notifyd_admission.py), [paired producer](triage_evidence/probe_notifyd_pairs.py), [publisher producer](triage_evidence/probe_notifyd_events.py), [paired profiles](triage_evidence/notifyd_admission_profiles.json), [publisher profiles](triage_evidence/notifyd_event_profiles.json) and [contracts](triage_evidence/notifyd_admission_contracts.json) retain source identities,actual original instructions,whole compiler ranges,materialized pages,format12/v5 members,explicit API outputs and per-call state snapshots. Original collection code runs on both sides. No registration/name/client/process record is injected to make the successful paired paths work.

The provider runs from original main `0x1000052b8` to `_dispatch_main` at`0x100005f6c`. Main does not return;later private invocations use separate call frames while retaining its constructed global/heap state. No native event loop,thread,sandbox,file operation,Mach operation,entitlement query or target loader executes. External callback declarations are retained without automatic delivery. The four explicit publisher-handler calls are separately labeled.

## Startup and architectural interfaces

| Boundary | Original site | Source-created state / declared external result |
| --- | --- | --- |
| Disable library notification recursion mode | `0x1000052ec` |`notify_set_options(0x08000000)`;external library effect modeled |
| Trace /sandbox /resource setup | `0x1000052f4`, `0x10000530c`, `0x10000532c` |Trace mode`0x100`;sandbox profile`com.apple.notifyd`;16-byte setrlimit input;declared result0 |
| Signal setup | `0x100005338..0x100005368` |Five source signal calls retained;no native dispositions changed |
| Collection initialization | `0x1000053d4..0x100005440` |Original string/64-/32-bit sets and64-bit map;key offsets8,16,64,8,16 |
| Shared sizing | `0x1000053a8..0x1000053b4` |Declared page size16384 bytes;source divides by4 ->4096 u32 slots |
| CLI override | `0x100005528..0x100005540` |Original `-shm_pages` parsing;declared `atoi("0")=0` produces slot_count0 |
| Bootstrap check-in | `0x100005610` |Requests `com.apple.system.notification_center`;writes declared receive name`0x5902` to global`0x100014254` |
| Shared object open/map | `0x100005658`, `0x100005678`, `0x100005730` |New-object fixture:first open(flags2)=-1,second(flags`0x202`)=fd72;mode`0644`;ftruncate16384;mmap READ|WRITE,SHARED |
| Shared initialization | `0x100005774..0x1000057f0` |Source zeros counters/reference array,writes PID311 in counter[0],reference[0]=1,last_slot0 |
| Workloop/channel creation | `0x1000057fc`, `0x100005d68`, `0x100005d98` |Source creates workloop declaration and channels `com.apple.notifyd.mach-notifs` /`com.apple.notifyd.channel` |
| Publisher | `0x100005db4..0x100005dec` |`com.apple.notifyd.matching`,handler,error handler,throttling64 and activation declarations |
| Configuration lookup | `0x100005894` |Declared `stat` failure for `/etc/notify.conf`;config parser is not executed;controlled-name policy remains empty |
| Process monitor | `0x100003138..0x100003224` |Original registration creates process source/record and callback declarations;native process-death/cancel callbacks are not delivered |

Default startup registers the internal name `com.apple.system.notify.ipc_version` before user registration. Its source-allocated nameID is0 in these cases. The subsequent ADID name receives ID1. The shared-object,bootstrap,queue,FD,port and publisher values are private fixtures;their actual native identities/rights are unknown.

The publisher's source global block at`0x100010a68` contains invoke pointer`0x100006104`. Four explicit calls exercise reason0,1,2 and3. Reason0 stops at opaque `_xpc_get_type` on the owned event object. Reason1 executes original64-bit map deletion for absent subscriber42 and returns. Reason3 returns without API calls. Reason2 executes these connections:

| Channel creation /callback | Connected receive-name source | Original connect site |
| --- | --- | --- |
| `mach-notifs`,callback`0x100006034` |Global`0x100014250`,written by original port-construction path with fixture name`0x5904` | `0x100006264` |
| `channel`,callback`0x10000609c` |Global`0x100014254`,written by bootstrap check-in with fixture name`0x5902` | `0x100006298`,tail branch |

Both calls pass send name0 and initial message0. Callback reason2 is an explicit input to the captured original handler;native publisher semantics,scheduling and actual connection are not established. This refines channel creation versus connection and separates the internal notification receive name from the service receive name.

## Constructed records and lookup keys

| Source object | Allocation /field | Established local meaning |
| --- | --- | --- |
| Name record |`0x1000010f4`:calloc(1,73+strlen(name)) |72-byte fixed portion followed by name bytes and NUL;source-shape layout,not a recovered native typedef |
| Name+8,u64 |Constructor`0x10000111c` |Points to inline name at base+72 |
| Name+16,u64 |Constructor`0x10000113c` |NameID from old global counter;source increments counter for next allocation |
| Name+48/+52,u32 |Literal store`0x100001148` |Default word`0x333` and shared-slot all-ones |
| Name+56,u32 |`0x100000f5c..0x100000f64` |Client count increment during registration |
| Name+60,u32 |Constructor`0x10000114c`;post`0x100000d28` |Generation initialized1;post increments modulo2^32 |
| Client record |`0x100000fa4`:calloc(1,88) |Original linked-list/lookup record |
| Client+48,u64 |`0x100000fc8` |Name-record pointer |
| Client+64,u64 |`0x100000fc4` |`(uint64_t(uint32_t(pid))<<32)|uint32_t(token)` |
| Client+72,u32 |`0x100008f50..0x100008f68` |Last RPC-sampled name generation |
| Client+79,u8 |Registration/delivery helpers |Low nibble describes source registration flavor;other delivery bits separately retained |

Original cache set lookup returns key-field pointers;original provider offsets recover record bases. A full64-bit proof verifies PID/token packing over all32-bit components. Wrong-PID cancellation with the same token leaves the original registration alive in the retained sequence;later legitimate posting/polling and cancellation still complete. This supports the composite-key ABI without assigning audit fixtures native authenticity.

The [compile-only source layouts](triage_evidence/notifyd_admission_layouts.c) and [arm64e assembly](triage_evidence/notifyd_admission_layouts.s) assert72-/88-byte shapes and offsets. Opaque fields retain opaque names. Allocation request size is distinct from native allocator usable capacity.

## Paired registration, posting, polling and cancellation

For each of `com.apple.adid.midchangedV1`, `com.apple.adid.midchangedV1.5` and `com.apple.adid.midchangedV3`,the retained complete sequence is:

```text
register -> initial check1 -> unchanged check0
         -> cached-ID post -> changed check1 -> unchanged check0
         -> cancel -> invalid-token check(status2)
```

Original server checkin1023 produces version3,PID311,status0. Original registration1012 produces16384-byte shared size,slot1,nameID1,status0. The original client consumes these outputs rather than an independent reply table. Original cached-ID posting1009 writes counter[1]=2 at`0x1000099d8` and advances the name generation at`0x100000d28`. Explicit shared aliasing transfers those provider bytes to the client guest;the original client changed-path reads and comparison produce1. Original cancellation1016 decrements the slot reference at`0x100003620`,unlinks/releases the source client record and returns;the client then rejects the retired token.

The transport adapter supplies effective message size,a52-byte audit trailer,framework reply header,API result0,and shared-byte aliasing. It selects the stub by executing original selector`0x100008dfc`;the stub and complete worker execute. The libdispatch demux and native kernel are not executed. One-way posts/cancellations do not deliver a server application reply to the client. Complete native process-monitor retirement and asynchronous cleanup remain unknown.

## Admission behavior under the declared configuration

All ordinary-name cases below depend on the explicit absent-configuration premise. No conclusion about actual installed `/etc/notify.conf`,native sandbox policy,effective credentials or arbitrary sender reachability follows.

| Case | Source/API premise | Retained outcome |
| --- | --- | --- |
| Ordinary ADID name |Audit UID0,501 or502;posting PID2222;valid source nameID1;no configured controlled names |All three advance the registered counter;next original client check1 |
| `user.uid.501.fixture` |Posting audit UID0 or501 |Counter advances;next check1 |
| Same UID namespace |Posting audit UID502,flags0 |Counter unchanged;next check0 |
| Namespace mismatch at registration |Audit UID502 registering `user.uid.501.fixture` |Original server application status7;original client returns7 |
| Missing UID delimiter |Audit UID501 registering `user.uid.501x` |Status7;the source requires end-of-name or`.` after the formatted UID prefix |
| Root override |UID502,nonzero post flags,`com.apple.notify.root_access` fixture NULL/false/true |NULL/false preserve the UID-scoped denial;true permits the retained update |
| Restricted posting |Name`com.apple.private.restrict-post.fixture`;matching generated entitlement fixture NULL/false/true |NULL/false leave counter unchanged;true advances counter |
| Unreached sandbox API model |Two otherwise identical name-post cases vary `_sandbox_check_by_audit_token` fixture result |No tested path calls that API;both results are identical;other MIG/native gates remain untested |

The source namespace helper `0x100000890` uses signed-decimal `%d` formatting of the32-bit UID for the `user.uid.` prefix and tests the following byte for NUL or`.`. The retained namespace controls use UIDs0,501 and502;high-bit UID formatting/native validity is not established by these finite cases.

The restricted-post helper `0x100001818` recognizes the32-byte prefix `com.apple.private.restrict-post.` and constructs an entitlement key with the52-byte prefix `com.apple.private.darwin-notification.restrict-post.` followed by the suffix. It uses a257-byte buffer and rejects returned key lengths greater than256 before querying an entitlement. A204-byte suffix produces a256-byte key and succeeds under a true fixture. Suffix lengths205,207 and208 reject without an entitlement query,despite declared true values for those keys. A bounded full-domain local formula verifies the204-byte threshold for client-representable suffixes.

The root helper `0x100005124` queries `com.apple.notify.root_access`;the cached-post stub applies its Boolean result only in the nonzero-flags/non-root branch. These are explicit Boolean/API result fixtures,not effective entitlements. Diagnostic file opens are modeled as NULL to let the original denial path return without native file output.

Original `notify_post` returns0 for both admitted and denied one-way posts under transport result0. The original server still controls whether the counter changes. Thus client API success is not a policy/delivery receipt. The named-event feedback edge must be evaluated from provider state and later polling,not the one-way API status alone.

## Conditional state witnesses

### No-shared-memory fallback and nameID0

Original main accepts `-shm_pages 0` through its normal argument parser;the declared `atoi` input is exactly`"0"`. It does not fabricate an invalid OS page size or inject a slot-count global. The supplied installed launchd declaration has no such argument;actual native use of this option is unknown.

| Stage | Original output /state |
| --- | --- |
| Startup |Shared slot_count0;internal IPC-version name allocated as ID0 |
| ADID registration1012 |Plain fallback constructs ADID record ID1;reply has shared size/slot all-ones,nameID0,status0 |
| Original client registration |Consumes reply successfully;uses RPC1002 polling |
| First /second RPC checks |Changed1 /0 from target ID1 generation1 and per-client sample |
| Original client cached-ID post1009 |Wire nameID0;provider advances IPC-version record0 generation1->2;ADID record1 remains generation1 |
| Subsequent RPC check |Changed0 |
| Name-based post1010 control |Original provider resolves the intended ADID name and advances ID1 generation1->2 |
| Subsequent RPC check |Changed1 |

The [independent record ledger](triage_evidence/notifyd_admission_checks.json) establishes the two distinct source-constructed names,IDs and generation transitions. This is a conditional ABI/state witness in a supported source argument branch. Actual deployed arguments,loaded client/provider versions,native sender authority and complete native consequences remain unknown. It is not promoted to a native defect.

### Failed-registration slot-reference side effects

The check-registration worker assigns/initializes a shared slot and increments its reference before the later name/client registration helper returns application status7. Three normal public registration attempts from UID502 for `user.uid.501.fixture` each return7. After the third,the source reference-array head is `[1,1,1,1]`:slot0's startup reference plus slots1,2 and3. No target name record was constructed in those attempts. The slot side effects are independently reconstructed from source stores and declared API writes.

The retained calls contain no rollback of those three slot references. Process-death callbacks,subsequent slot reuse,restart and asynchronous reclamation are outside the executed sequence. This establishes a bounded failed-registration state effect,not a native resource-leak or exhaustion claim.

## Verification

The [validator](triage_evidence/validate_notifyd_admission.py) independently reconstructs provider allocation contents,free/reallocation state,DATA globals,shared counters,name IDs/generations and slot-reference heads. Post-store bytes are captured after each original store,including16-byte stores;the ledger does not infer upper vector bytes from Unicorn's scalar write-hook argument. Every retained allocation/global/shared snapshot must match the independent ledger.

It also verifies fresh original instruction/range/UUID/page/fixup bytes,the raw/effective message transform,audit bytes,source-produced reply bodies,declared shared alias snapshots,client changed/status outputs,source-captured publisher block,receive-name/channel pairing and four arithmetic queries. The formulas cover PID/token packing,restricted-key extent,next-slot bounds and CLI page-to-byte modular arithmetic;they do not prove native path feasibility. SDK assertions compile source-shape records only.

There are27 complete paired-case fixtures with108 original client calls and188 original selector/stub calls,plus27 original main prefixes. Four publisher cases add four main prefixes and four explicit handler calls. Every sequence is freshly replayed. All340573 assertions pass across324694 original-instruction visits,81 paired client transport messages,4783 source stores,264 API output effects,2418 independently reconstructed allocation snapshots and310 name-record snapshots. Exact current assertion/visit/ledger counts are in the [checks](triage_evidence/notifyd_admission_checks.json) and [quality gates](triage_evidence/notifyd_admission_quality_gates.json). The [preservation ledger](triage_evidence/notifyd_admission_preservation.json) covers all870 prior artifacts,with only five reporting indexes/status and the manifest aggregator allowed to change.

For bounded source bytes B,materialized page bytes P,original visits V,recorded writes W and owned allocation bytes A,extraction/replay/ledger processing costs O(B+P+V+W+A) time and retained space. Each client call is capped at200000 guest steps,each provider invocation at300000 steps,owned allocations at512 and65536 bytes per request,and each solver query at30000 ms. ASCII fixture names avoid applying the text-model result to arbitrary invalid byte strings.

## Assumption register

| ID | Assumption /dependent results | Stress test /falsification probe |
| --- | --- | --- |
| A1 | Pinned installed reference images supply original implementation;all source results | Match actual loaded slices,UUIDs,slides/cache and integrity before native pairing |
| A2 | Declared startup API results construct private state;startup/paired paths | Original main,collections and constructors execute;unknown APIs stop;native external effects/scheduling remain unproved |
| A3 | `stat(/etc/notify.conf)=-1`;ordinary-name permission results | Execute original parser with separately declared root-owned config records and compare controlled-name/ACL behavior;current native file contents unknown |
| A4 | Eight audit words are transport inputs;UID/PID/admission cases | Match kernel-produced audit metadata and effective peer identity;the fixtures establish no spoofability/authenticity |
| A5 | Header/trailer/framework delivery is explicit;cross-image messages | Verify actual kernel/libdispatch transfer,filtering,reply identity and rights before native promotion |
| A6 | Cross-guest byte copy represents a declared shared object;polling bridge | Attest native object/mapping/epoch identity and concurrent publication;two guests do not share native VM |
| A7 | External NDR/allocator/collection bindings retain known source/model split | Fresh format12/v5/byte checks and original collection code;NDR input matches prior source bytes;native PAC/library selection unknown |
| A8 | Bounded owned allocator is a model;record/slot effects | Independent request-size/byte/lifetime ledgers;native capacity/layout/reclamation require separate evidence |
| A9 | ASCII names and reviewed bounded string models cover selected cases | Original client string helper executes;provider byte/length comparisons are independently checked;invalid byte/Unicode domains remain untested |
| A10 | Entitlement NULL/false/true and logging NULL are explicit external results | Original query/key/Boolean/status consumers execute;native effective entitlements and diagnostic output are unknown |
| A11 | Legacy tested paths and explicit publisher reasons delimit control flow | Zero observed sandbox-post API calls is a finite-case result;execute other MIG families and native activation/callback lifecycle |
| A12 | CLI0/failed-slot witnesses have only stated local consequences | Normal source argument parsing and complete calls preserve provenance;attest deployed arguments,process callbacks,reuse,restart and native outcome before defect promotion |

## Bounded continuation

| Impact | Next source investigation | Unresolved interface |
| --- | --- | --- |
| High | Original configuration parsing,controlled-name creation and permissions | Root ownership/mode checks,rule ordering,prefix matching,owner/group/access fields and native effective file |
| High | Native source/cache/peer/port and transport reconciliation | Actual service/right identity,audit metadata,loaded images,header/trailer transfer,shared object epochs and full protected operation |
| Medium | Plain-fallback reply/nameID ownership and alternate clients | Whether other callers avoid the cached0 path,scope of CLI0 deployment and compatible fallback semantics |
| Medium | Failed registration,process-death,slot reuse and retirement | Reference rollback/reclamation,monitors,repeated denial and complete asynchronous lifetime |
| Medium | Publisher reason0 and notification callbacks | Event object/subscriber schema,admission,remaining token/Mach/signal/FD delivery,backpressure and cancellation |
| Medium | Other MIG families and sandbox API callsites | Which operations consume the additional sandbox/entitlement gates and their relationship to legacy post paths |
| Low | Diagnostic/environment/CLI variants | Existing shared object,open/map failures,other page counts,log output and source configuration axes |

QG1-QG7 pass for the stated increment:descriptive scope,falsifiable assumptions,bounded coverage,byte/width/unit consistency,separated source/model/native claims,fresh provenance plus independent ledgers/replays,and impact-labeled continuation. The full goal remains active and incomplete.
