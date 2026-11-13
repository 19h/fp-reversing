# libnotify and notifyd: transport, shared counters and Mach interfaces

Daemon registration continuation: The [notification-registration report](daemon_notification_registration_report.md) identifies original daemon polling registrations for com.apple.adid.midchangedV1/V1.5/V3 and the corresponding baseline/cancellation sites. It does not establish actual registration, native port identities or a call-to-message mapping. The installed provider differs from the historical image used by the archived ADID evidence.

Daemon-side continuation: The [four-output helper report](daemon_environment_outputs_report.md) recovers three original daemon notify_check call sites and their cached token cells. Native registrations, notification names and daemon/library build pairing remain unknown. The reference transport recovered below therefore does not establish a daemon call-to-message mapping.

This increment resolves the reference implementation beneath the three ADID invalidation names. The installed `libsystem_notify.dylib` looks up `com.apple.system.notification_center`, registers check tokens with message1012, and maps `apple.shm.notification_center`. Successful shared-counter checks emit no Mach message. The original notifyd image contains the corresponding registration/checkin stubs, a fresh-slot counter initializer, audit/admission interfaces, an active Mach notification sender and a separate Mach-notification MIG subsystem.

The [earlier ADID notification/cache report](adid_notification_report.md) establishes the upstream akd/client and adid/local-post sites and their conditional name match. This increment extends its previously unresolved transport boundary. It does not establish effective native credentials, actual process/cache pairing, complete notifyd admission, successful full provider requests, or a native notification transaction. All addresses below are unslid source addresses. I1-I12 delimit dependent results.

```text
akd original CoreADI client                     adid local post fragment
  register/check three names                       notify_post(name)
             |                                           |
             v                                           v
      libsystem_notify reference implementation
        | bootstrap lookup: com.apple.system.notification_center
        | Mach1023 checkin; Mach1012 register-check
        | one-way Mach1009 cached nameID /1010 name post
        v
      notifyd reference image
        | audit token / name / sandbox / entitlement interfaces
        | registration worker -> shared slot initialized to1
        | accepted-post source path -> counter increment
        v
 apple.shm.notification_center -> client polling -> cached OTP refresh

Separate active-delivery path:
 notifyd client/port records -> Mach24-byte message, ID=client token
       send-possible request66 -> separate Mach-notification MIG table
```

The diagram's accepted-post and delivery edges are source-level interfaces. Native posting authority, admission, mapped-object identity and end-to-end delivery remain unknown.

## Original sources and evidence

| Source | Identity / coverage |
| --- | --- |
| Installed dyld cache | UUID `2bd06591-e751-3e84-963f-b08dab6af23a`; original file/section pages and independent v5 chain membership |
| `/usr/lib/system/libsystem_notify.dylib` | UUID `266b92ef-8350-347c-9086-b53ba04523cf`;126 compiler functions,23 exports,137 nlists,42 own const/GOT chain members,1902 direct branch edges,101 bound veneers and64 direct `_mach_msg` emission sites |
| `/usr/sbin/notifyd` universal | SHA256 `79105a37b75d37f43ea0190ae1f5307f775446730774ee76b62a3484b8166c15`;375104 bytes |
| Selected arm64e slice | Subtype `0x80000002`,file offset `0x1c000`,size129344 bytes;SHA256 `aeeae7016d04af9b2a08f0491559ac0291ec3954fd93bdf167c30607d44fae23`;UUID `d27ffd43-6f5d-3882-8bcf-4853e8a0b288` |
| notifyd source extraction |141 compiler functions,174 imports,276 format12 chain members,158 original import stubs,701 external direct edges;independent fixup walk cross-checked against `dyld_info` |
| Original launchd declaration | `/System/Library/LaunchDaemons/com.apple.notifyd.plist`;MachServices declares `com.apple.system.notification_center`;ProgramArguments `/usr/sbin/notifyd`;System session;PublishesEvents `com.apple.notifyd.matching` |

The [client inventory](triage_evidence/notify_ipc_inventory.json), [provider inventory](triage_evidence/notifyd_ipc_inventory.json), [contracts](triage_evidence/notify_ipc_contracts.json), [client profiles](triage_evidence/notify_ipc_profiles.json) and [provider profiles](triage_evidence/notifyd_ipc_profiles.json) retain original bytes, source ranges, fixups, instructions and explicit fixture boundaries. The launchd entry is a declaration, not evidence of a current published receive right. Embedded signature extraction does not authenticate a signature.

## Names, token state and shared mapping

| Boundary | Original site / local contract |
| --- | --- |
| Public registration | `_notify_register_check:0x180593b38`;original context constructor `0x1805984f4` initializes600 bytes and embedded collections |
| Service discovery | Original `_bootstrap_look_up2` boundary requests `com.apple.system.notification_center`;modeled result name `0x5902` |
| Checkin | Emission `0x18059d9c0`;message1023;original provider stub `0x10000a8e4` ->worker `0x100002f94`;worker writes version3,modeled process PID311,status0 |
| Registration | Emission `0x180593fc4`;message1012;provider stub `0x100009c3c` ->worker `0x100001c7c` |
| Shared mapping | Helper `0x18059a6c8`;`shm_open("apple.shm.notification_center",0,...)`;`mmap(0,16384,PROT_READ,MAP_SHARED,fd72,0)`;close fd72;mapping stored at context+`0x250` |
| Client context | Service name at+`0x180`;server PID at+`0x70`;token counter begins1,first retained token2;token collection+`0x1a8`,key-field offset20 |
| Check-token node | Flags32 at+`0x18`,shared slot32 at+`0x1c`,last sampled counter32 at+`0x20`;low flag nibble1 selects retained shared path |
| Provider globals | Slot count32 `0x1000142a0`;last slot32 `0x1000142a4`;shared counter pointer `0x1000142a8`;slot reference-count pointer `0x1000142b0` |
| Fresh shared slot | Worker `0x100001e00..0x100001e0c` writes1 to counter[slot];slot reference increment `0x100001e14..0x100001e1c`;outputs bytes=slot_count*4 and slot at `0x100001e44/48` |
| Retained name reuse | Worker looks up existing name and uses its slot32 at record+`0x34` when not all-ones;fresh-slot initialization does not describe every reuse/wrap case |

The source main derives slot_count from page size/4. The private16384-byte mapping fixture therefore represents4096 u32 entries;it does not prove the native mapping size or shared object identity. The client reads shared word0 for server-PID comparisons on selected maintenance paths. Its sequential mapping/PID behavior does not establish restart correctness.

Original libsystem_collections functions execute in the private client guest, including initialization, hashing, lookup, insertion and deletion. Original `_mig_strncpy_zerofill:0x1805494d4..0x180549548` also executes. They are not replaced by dictionary or name-copy models in the retained cases. Allocation, locks, once callbacks, entitlement queries, bootstrap lookup, transport, mapping and other admitted external APIs retain explicit models. Original context and once-block callbacks execute;hardware PAC and native concurrency do not.

## Mach request/reply ABI and emission sites

| Request | Original client emission | Send bytes | Receive capacity bytes | Options | Body / direction |
| --- | --- | --- | --- | --- | --- |
|1023 checkin | `0x18059d9c0` |24 |56 |`0x314003` |Header only;reply1123 has48-byte body-bearing message |
|1012 register-check | `0x180593fc4` |`44+align4(count)` |64 |`0x304003` |NDR+reserved32+count32+variable name+client token32;reply1112 is56 bytes |
|1002 RPC check fallback | `0x1805947a0` |36 |52 |`0x304003` |NDR+client token32;reply1102 retained size44 |
|1009 cached-name post | `0x1805970bc` |44 |0 |`0x200001` |NDR+nameID64+flags32;one-way |
|1010 uncached-name post | `0x1805a2900` |72 for V1 fixture |0 |`0x200001` |Variable-name one-way post;retained case stops at opaque transport |
|1016 cancellation | `0x1805a2c38` |36 |0 |`0x1` |NDR+client token32;one-way |

The [complete static emission catalog](triage_evidence/notify_ipc_contracts.json) enumerates all64 direct client `_mach_msg` sites with enclosing compiler ranges, original branch instructions, authenticated import veneers and exact bound exports. Only the cases above have retained public-entry execution in this increment. Static presence of other sites does not establish their prerequisites or native reachability.

At the intercepted client `_mach_msg` API boundary, `header.msgh_size` is zero and the send size is the separate X2 argument. The destination field is the declared service-name fixture `0x5902`. RPC local/reply field is the declared special-reply-name fixture `0x5901`;one-way local field is zero. These integers are private names,not observed native rights or kernel objects. Do not deliver the raw zero-size header to the server as an already valid received message.

For cross-image registration parsing,the fixture explicitly sets effective `msgh_size=send_size` and appends a52-byte audit trailer. A separate framework reply-header fixture supplies reply ID and port fields. Original stubs then construct their result body. The native wrapper/kernel header transformation and libdispatch demultiplexing are not executed in this bridge. Existing [user trap contracts](user_trap_interface_report.md) and [kernel namespace contracts](kernel_namespace_report.md) remain separate evidence,not automatic proof of this transaction.

| Reply / field | Offset bytes | Width bytes |
| --- | --- | --- |
| Common Mach header /NDR /kernel status |0 /24 /32 |24 /8 /4 |
| Checkin version /PID /application status |36 /40 /44 |4 /4 /4 |
| Registration shared size /slot /nameID /application status |36 /40 /44 /52 |4 /4 /8 /4 |
| RPC check changed /application status |36 /40 |4 /4 |

The nameID64 at44 is aligned to4 bytes in the wire structure. The [SDK compilation source](triage_evidence/notify_ipc_layouts.c) and [arm64e assembly](triage_evidence/notify_ipc_layouts.s) verify layouts against pinned SDK headers. Original pointer-derived NDR bytes at `0x1eb065de0` equal `0000000001000000`;the provider import-data binding in the guest remains an explicit matching fixture.

## Polling, posting and local lifetime

At `0x180594520`,the original shared path reads counter[slot] and compares it with node.last. Equality yields changed0. Inequality stores changed1,reads the counter again at `0x1805946b4`,and publishes that second value as node.last at `0x1805946b8`. Thus there are two sampled reads on the changed path. Under stable sequential input,the next unchanged check yields0. A concurrently changing second value can differ from the first;native ordering and lost/coalesced events are not established by the sequential guest.

The three name-specific lifecycle sequences each produce changed results1,0,1,0 across initial,unchanged,explicit external update,and unchanged-after-update calls. The slot0-value control yields initial0. The retained fresh-slot source write of1 explains the normal initial1 input;it does not imply that every arbitrary shared-memory state must return1. A mathematical full2^32 counter wrap aliases the previous value;the case supplies the aliased counter directly and does not emulate2^32 native posts.

A successful one-way cached post under transport result0 leaves shared memory unchanged in the client guest;the subsequent check remains0 until an external update is explicitly supplied. The server source path at `0x1000099c8..0x1000099d8` increments the relevant slot after preceding lookup/audit/admission predicates. This source increment is not connected to an executed complete admitted post in this increment.

When registration replies supply all-ones shared size/slot,the retained original client uses RPC1002 for the check. Two registrations of the same name allocate tokens2 and3;each has its own last-sampled state and emits its own cancellation1016. Successful cancellation removes the local token;subsequent check/cancel returns status2. With the selected synthetic cancellation send error `0x10000003`,cancellation still returns0 and the local token becomes invalid. Native server cleanup/right consequences remain unknown. A selected post send error reaches an unmodeled `_vasprintf` diagnostic boundary;its eventual public return is unknown.

## Provider MIG and external control

| Subsystem | Header /selector /routine array | Range | Non-null /holes |
| --- | --- | --- | --- |
| Notify requests | `0x1000104d0` /`0x100008dfc` /`0x1000104f0` |[1000,1033) |31 /1000,1001 |
| Mach notifications | `0x100010348` /`0x100008af0` /`0x100010368` |[64,73) |6 /64,67,68 |

Each routine descriptor is40 bytes,stub pointer+8,max_reply_msg32 at+32. Notify-request max reply is56 bytes;Mach-notification max reply is36 bytes. The six notification stubs cover65 port-deleted,66 send-possible,69 port-destroyed,70 no-senders,71 send-once and72 dead-name. Complete callback state transitions are not established here.

Original pointer members bind demux-array `0x100014000` to notify subsystem `0x1000104d0`,and `0x100010280` to notification subsystem `0x100010348`. Original wrappers invoke `_dispatch_mach_mig_demux` at `0x1000060c8` and `0x100006060`,respectively,with one subsystem pointer. The framework API itself remains opaque. [Contracts](triage_evidence/notify_ipc_contracts.json) retain all42 rows,37 non-null stubs and all701 original external direct edges.

| Provider architectural boundary | Original site | Evidence level |
| --- | --- | --- |
| Sandbox initialization | `0x10000530c` |Main source call;effective sandbox unknown |
| Service bootstrap check-in | `0x100005610` |Main source call;native publication not executed |
| Shared object open/map | `0x100005658`, `0x100005678`, `0x100005730` |Main source calls;native object/permissions unknown |
| Mach channel creation | `0x100005d68`, `0x100005d98` |Two source `_dispatch_mach_create_f` calls |
| Mach channel connection | `0x100006264`, `0x100006298` |Source `_dispatch_mach_connect` calls;second is a tail branch |
| Entitlement interfaces | `0x1000018ac`, `0x100005174` |Original `_xpc_copy_entitlement_for_token` callers |
| Post counter update | `0x1000099d8` |Original conditional source store after admission-related calls |

Original strings include `com.apple.private.restrict-post.`, `com.apple.notify.root_access`, `user.uid.`,and diagnostic rejection messages. The retained cached-name post stub performs audit extraction,name lookup and permission/helper calls before the source counter increment. These facts establish admission touch points;they do not determine whether an arbitrary caller may post the three ADID names. Effective token contents,namespace state,entitlement results and complete caller-to-helper predicates remain unknown.

## Parser boundary controls

Checkin1023 rejects complex messages or size other than24 with status-304. It requires trailer type0 and declared trailer size greater than31;otherwise status-309. The source then loads32 audit bytes from trailer+20,through byte51. Both declared-size32/backed52 and declared-size51/backed52 controls execute the original worker. This is a local guard/read contract,not a native out-of-bounds finding:every supplied buffer is backed by52 trailer bytes,and actual kernel trailer production remains outside this fixture.

The original worker's48-byte reply equals the explicit48-byte checkin reply consumed by the original client parser. Only the header and external data/API prerequisites are modeled. Client versions0 and2 reach an original `brk` guard;versions3,4 and all-ones pass the retained version comparison. Malformed reply ID,complex bit,size and kernel status reach opaque `_mach_msg_destroy`;their full native cleanup/public results are unknown.

Registration1012 numeric validation accepts count<=512 and size=`44+align4(count)`. The source NUL search at `0x100009cb4` spans `min(size,552)-40` bytes,including token/padding bytes for shorter messages. Worker token is read at `40+align4(count)`. Three source-generated ADID-name packets and four length controls reach original worker `0x100001c7c` with the expected name,token and copied audit token. Execution stops at that worker boundary.

For a72-byte message with count28,the search spans32 bytes. A constructed28-byte non-NUL name plus token2 is accepted by the parser;the worker receives28 `A` bytes followed by byte02. Token0 supplies a NUL immediately after the28 bytes. Token all-ones supplies no NUL and is rejected. Count27 with a NUL outside its declared span can also pass. These are bounded parser/ABI witnesses;complete registration,admission,ownership and native consequence remain unknown.

The original client string helper truncates512-/513-character input names to511 characters plus NUL on the wire;the original client still returns0 under the supplied successful server reply. Source-generated name lengths511,512 and513 therefore have identical name bytes at the provider boundary. Full client-name-record versus server-name identity consequences require further lifecycle analysis;no native defect is established.

## Active delivery and port/right helpers

| Original helper /site | Recovered local interface |
| --- | --- |
| Sender `0x1000012a4`,Mach emission `0x100001374` |24-byte header;bits19=COPY_SEND;size24;remote=argument3;local/voucher0;message ID=client_record.u32+`0x40` |
| Sender options |Global flags at `0x100014220` bit1 clear ->`0x11`=SEND_MSG+SEND_TIMEOUT;set ->`0x91` additionally arms SEND_NOTIFY |
| Sender suspended port record |Port_record.u32+12 bit0 suppresses send;increments client byte+`0x4e`,ORs byte+`0x4f` with`0x60` |
| Sender success |Clears top2 bits of client byte+`0x4f` |
| Timeout `0x10000004` |Without global bit1 ->local status45;with bit1 ->local success0,client flags OR`0xe0`,port-record bit0 set;other selected send error ->46 |
| Construct `0x100001574` |`mach_port_options_t`:MPO_QLIMIT2,queue limit16,remaining fields0;context0 |
| Insert `0x10000158c` |Same constructed name as name/right argument;disposition20=MAKE_SEND |
| Request notification `0x100001624` |Watched name=argument1;ID66=SEND_POSSIBLE,sync0,notify name=global `0x100014250`,disposition21=MAKE_SEND_ONCE;old-right output checked |

Seven sender entry profiles and three port-helper entry profiles execute original helpers with explicit owned client/port records and kernel-result fixtures. One sender and one construct control stop at opaque boundaries. The task/name values `0x5801`, `0x5903`..`0x5906` are private fixtures. SDK static assertions establish the constants and24-byte options layout. These helpers describe active delivery/backpressure interfaces;they do not imply that `notify_register_check` creates an actively delivered Mach notification port.

## Assumption register and falsification probes

| ID | Assumption /dependent results | Stress test or falsification probe |
| --- | --- | --- |
| I1 | Installed reference images represent the implementation under study;all source address and ABI results | Compare actual loaded image UUIDs/slices/cache and slides;different images invalidate native pairing,not the pinned source observations |
| I2 | Verified v5/format12 materialization supplies original pointer targets;all private branches | Independent walks,`dyld_info` comparison,full source ranges/page hashes;native PAC authentication remains unknown |
| I3 | Explicit allocator/lock/once/environment/API models bound client execution;all path profiles | Execute original constructor,collection and MIG string functions;stop unknown APIs/native instructions;vary admitted API results;no native capacity or concurrency claim |
| I4 | Bootstrap/reply/FD/Mach names are private fixtures;all port/message profiles | Native right/object/namespace capture would replace `0x5901` etc.;do not equate names across tasks |
| I5 | Declared replies and transport statuses are inputs;successful client continuations | Checkin reply body is corroborated by original provider execution;other replies retain synthetic status/slot/nameID prerequisites |
| I6 | Effective request size,trailer and framework header are supplied explicitly;cross-image parser bridges | Execute/verify actual wrapper/kernel/libdispatch transformation before native bridge promotion;raw API headers retain size0 |
| I7 | Counter epochs/slot mapping are explicit and stable per retained call;polling outputs | Initial0/1/all-ones,update,wrap-alias and repeated checks;source fresh-slot1 and post increment pinned;actual admitted-post publication/order unknown |
| I8 | Provider parser worker boundary and bounded memchr model delimit registration;name/token witnesses | Independent byte search plus NUL/token controls;complete worker/startup/native transport required before any consequence claim |
| I9 | Provider startup/admission evidence is source-level unless explicitly executed | Trace bootstrap,shared-object permissions,effective audit/entitlement/sandbox and full original startup;strings alone do not establish authority |
| I10 | Active sender/helper records are explicit owned entry fixtures | Opaque/success/suspended/timeout/error controls;recover actual registration caller,record construction,right ownership and SEND_POSSIBLE callbacks |
| I11 | Sequential two-sample counter interpretation does not establish native ordering | Vary samples between the two reads and recover acquire/release/locking across provider/client;counter wrap/slot reuse/restart need separate epochs |
| I12 | Static inventories/proofs/fresh replays cover stated local contracts,not the full goal |64 static client send sites,42 MIG rows,complete source/fixup checks and fresh finite cases;recover remaining API modes,handlers and native lifecycle |

## Verification and bounded continuation

The [validator](triage_evidence/validate_notify_ipc.py) checks original identities,all267 compiler function ranges,original instructions/fixups,all static64 client Mach sites,158 provider stubs and701 external edges. It independently checks raw packet fields,registration name truncation,per-token sampled counters,effective-header transforms,provider reply bytes,sender packet/flags and right-helper arguments. Four fresh `unsat` queries cover the notify selector range,registration numeric extent equivalence,two-sample counter equations and32-bit wrap identity. They prove only their encoded local formulas.

The retained set comprises34 client sequences/87 original public calls and85 provider entry profiles,with complete fresh replay of every case. All215637 assertions pass across179397 client and2280 provider original-instruction visits,69 client Mach emissions and42 shared-counter reads. The [checks](triage_evidence/notify_ipc_checks.json) and [quality gates](triage_evidence/notify_ipc_quality_gates.json) carry exact assertions/visit counts. Extraction/validation costs O(B+F+I+E+V) time and O(B+F+I+E+V) retained space,where B is bounded source/page bytes,F compiler ranges,I unique instructions,E edges and V replay visits;string searches are bounded by512 bytes,client calls by200000 steps and provider entries by10000 steps. Each of four solver queries has a30000 ms timeout. SDK verification is compile-only. No native target,loader,service,IPC,notification,port or synchronization API executes. The [preservation ledger](triage_evidence/notify_ipc_preservation.json) records prior-artifact/input preservation and the six allowed index/aggregator updates.

| Impact | Bounded next investigation | Unresolved contract |
| --- | --- | --- |
| High | Execute original notifyd startup/registration and post admission under separately bounded APIs | Effective audit/entitlement/sandbox,name namespace,slot/nameID ownership and accepted-post -> shared counter bridge |
| High | Connect actual client wrapper/kernel/libdispatch header/trailer transfer | Message options,reply identity,right transfer,trailer authenticity and service/process/cache pairing |
| Medium | Complete SEND_POSSIBLE and other six notification callbacks | Backpressure,queued/coalesced delivery,port death,cancellation,reference transfer and retry lifetime |
| Medium | Follow short-name NUL scope and long-name wire aliasing through real worker/client records | Logical name identity,admission key,slot sharing and cleanup;native consequence remains unknown |
| Medium | Recover shared-memory restart/reuse/concurrent publication | PID epochs,mapping replacement,slot ownership,two-load sampling and counter wrap |
| Low | Expand remaining libnotify modes and context feature gates | Plain/signal/FD/Mach/dispatch/state/monitor APIs,introspection/restricted-engine diagnostics and effective environment |

QG1-QG7 pass for this stated increment:descriptive scope,explicit falsifiable assumptions,bounded requirement coverage,reproducible byte/width/layout formulas,separated source/fixture/native boundaries,verified original provenance,and impact-labeled continuation. The broader daemon/kext/deeper-facility goal remains active and incomplete.
