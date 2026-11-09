# notifyd filesystem monitors, deferred callbacks and publication

Original notifyd now connects declared filesystem events to original libnotify polling through two distinct source paths. Configuration monitors publish by name through `0x1000051dc`; per-client path monitors resolve a saved PID/token key through `0x100008990`. In the retained write-plus-mtime case, the original VNODE callback merges `0x102`, schedules one delayed resume, and the subsequent original client checks return changed1 then unchanged0. No native filesystem event, credential change, scheduling, Mach operation or daemon execution is established.

The source also distinguishes a credential-helper early exit that leaves a bound imported cache flag zero, and a zero-active-watcher branch that skips the compactor's per-watcher cancellation loop. These are source-level continuation and ownership findings. Native effects, other owners, operational consequences and defect feasibility remain unknown. M1-M12 delimit dependent results. The wider daemon/kext/deeper-facility objective remains active and incomplete.

```text
original configuration parser       original check-registration request1012
           |                                      |
 deferred Block,invoke712c               service.path parser8a24
 zero audit32,trusted flag later          audit32,mask,PID/token key
           +------------------+-------------------+
                              |
                    original monitor constructor
                              |
              root/parent/leaf VNODE watcher lists
                              |
     declared VNODE data + declared stat/realpath/credential results
                              |
               original VNODE callback85c4/rebuild7724
                              |
               filtered data -> DATA_OR merge
                  first event -> suspend + after(100 ms)
                              |
                 declared timer/callback delivery
                  /                           \
        config Block86ec               per-client Block8990
       internal named post              saved-client lookup
                  \                           /
                    original shared-slot store
                              |
                  explicit cross-guest byte alias
                              |
                  original notify_check ->1,then0
```

## Primary evidence and scope

The [source contracts](triage_evidence/notifyd_monitor_contracts.json), [40 finite sequences](triage_evidence/notifyd_monitor_profiles.json), [independent checks](triage_evidence/notifyd_monitor_checks.json) and [quality gates](triage_evidence/notifyd_monitor_quality_gates.json) retain original bytes and declared inputs separately. The [new engine](triage_evidence/probe_notifyd_monitor.py) extends frozen startup/policy/transport engines; the [case producer](triage_evidence/probe_notifyd_monitor_cases.py), [source recoverer](triage_evidence/recover_notifyd_monitor.py) and [validator](triage_evidence/validate_notifyd_monitor.py) are reproducible artifacts. Previously published producers, profiles and reports are preserved.

| Original source | Identity /meaning |
| --- | --- |
| `/usr/sbin/notifyd`,selected arm64e slice |SHA256 `aeeae7016d04af9b2a08f0491559ac0291ec3954fd93bdf167c30607d44fae23`;UUID `d27ffd43-6f5d-3882-8bcf-4853e8a0b288` |
| Original cache |UUID `2bd06591-e751-3e84-963f-b08dab6af23a`;independent v5-chain materialization |
| Original libnotify |UUID `266b92ef-8350-347c-9086-b53ba04523cf`;public registration/check/cancel code executes |
| Original libbsm |UUID `a01677ab-bd20-3c62-8b0f-c805062f95bd`;audit decoding executes from original code |
| Sandbox imported data |`_SANDBOX_CHECK_NO_REPORT` at original cache `0x18fe64ae4`,bytes `00000040`,value `0x40000000`;provider format12 bind slot `0x100011040` |
| Libinfo imported data |`_gL1CacheEnabled` at original cache `0x1eb162ff8`,bytes `01000000`,reference value1;provider format12 bind slot `0x1000110a0` |

Sandbox image UUID is `041a67c3-6f5d-3406-8f91-4e212953e967`;libinfo UUID is `840f592c-740f-3965-b23a-a11a234c6aba`. The original data references initialize private bound variables. Runtime values, source-image slides and native interposition remain unknown. An explicit L1-initial0 control is retained.

The previous [configuration/state report](notifyd_policy_report.md) captured four system monitor declarations for `/etc/localtime`, `/etc/hosts`, `/etc/services` and `/etc/protocols`. The new callback cases use declared `/model/file` paths and finite filesystem maps. No present host file is watched or modified; those captured configuration declarations are not promoted to daemon-loaded or live-event state. The [ADID notification report](adid_notification_report.md) supplies the broader feedback context; these filesystem callbacks do not establish a new direct ADID or FairPlayIOKit request path.

## Recovered routines and callback contracts

All addresses below are unslid notifyd addresses. The contracts pin 23 complete compiler functions, enumerate 39 direct incoming edges to those selected functions across all 141 compiler functions, and enumerate 198 direct outgoing edges from the selected functions. This exhausts those direct branch sets only. Block callback targets and descriptors are established separately from source-built captures and original descriptor bytes; arbitrary indirect callers remain outside that enumeration.

| Function /callback | Established source role |
| --- | --- |
| `0x10000712c` |Deferred configuration Block:lookup name,construct monitor,duplicate name,install named-publication callback,activate source,dispose original token vector |
| `0x1000073bc` |Allocate112-byte monitor,split/join absolute path components,initial rebuild,create DATA_OR source,then write low10 mask and optional configuration flag |
| `0x100007690` |Original once callback:realpath `/var/db/timezone/zoneinfo`,save duplicated result and length at globals `0x100014410`/`0x100014418` |
| `0x100007724` |Metadata/access rebuilding,path watcher attachment,action selection,masking,coalescing and delayed resume declaration |
| `0x100008194` /`0x1000084f0` |Find/create72-byte watcher by path/follow key;append monitor reference |
| `0x1000085c4` |VNODE callback:test cancellation,get data,fstat,compare/update two timespec pairs,rebuild attached monitors |
| `0x100008148` |Delayed callback:clear pending flag,resume DATA_OR,release retained monitor reference |
| `0x1000086ec` |Configuration DATA_OR callback:load saved name and captured UID/GID,tail-call internal named post |
| `0x100008a24` /`0x100008700` |Automatic service.path grammar and per-client monitor installation |
| `0x100008990` |Per-client DATA_OR callback:lookup saved PID/token key,increment associated shared slot where applicable,invoke client delivery helper |
| `0x100007ff0` |Per-client metadata helper using imported cache flag,groups,password record,thread credential requests,stat and group restoration request |
| `0x1000072f0` |Monitor reference decrement/retirement;detach,compact,free record-owned memory and release DATA_OR |
| `0x100007c94` /`0x100007cf8` |Detach monitor from watcher lists;compact lists/global array and conditionally cancel/dispose unused watchers |
| `0x100007f98` /`0x1000086e4` |Async watcher disposer and separate VNODE cancellation FD-close callback |

The original Block header occupies32 bytes. The descriptor supplies the copied extent,including a 36-byte FD capture;rounding every capture to40 bytes would lose that ABI distinction.

| Callback | Descriptor | Declared Block size | Capture after header |
| --- | --- | --- | --- |
| Deferred configuration712c |`0x100010260` |40 bytes |Token-vector pointer64 at+32 |
| VNODE event85c4 |`0x1000102e8` |40 bytes |Watcher pointer64 at+32 |
| VNODE cancel86e4 |`0x100010308` |36 bytes |FD32 at+32 |
| Delayed resume8148 |`0x1000102c8` |40 bytes |Monitor pointer64 at+32 |
| Watcher disposer7f98 |`0x100010b08` |40 bytes |Watcher pointer64 at+32 |
| Configuration publication86ec |`0x100010b28` |48 bytes |Monitor pointer64 at+32,UID32/GID32 at+40/+44 |
| Per-client publication8990 |`0x100010328` |40 bytes |Monitor pointer64 at+32 |

The10 observed descriptor records include three additional32-byte startup Blocks. Block copies and callback delivery are explicit guest models;native retain/copy/dispose helpers,dispatch ownership and queue ordering are not inferred.

## Monitor, watcher and filesystem ABI

These are source allocation layouts with unresolved fields retained as unknown. They are not SDK-defined public structures.

| Monitor offset | Width | Observed meaning |
| --- | --- | --- |
| `+0x00` /`+0x08` |64 /64 bits |Joined component-path pointer /allocated path capacity |
| `+0x10` |32 bytes |Copied audit token |
| `+0x30` /`+0x38` |32 /64 bits |Component count /component-pointer array |
| `+0x40` /`+0x44` |32 /32 bits |Current type/status /flags and low10 action mask |
| `+0x48` |64 bits |DATA_OR source pointer |
| `+0x50` |64 bits |Duplicated configuration notification name,when used |
| `+0x58` |8 bytes |Unknown |
| `+0x60` |64 bits |Saved per-client PID/token key,when used |
| `+0x68` |32 bits |Reference count;initialized1 |

Monitor allocation is112 bytes. Status values in the decoded classification are0(no current type/access-denied outcome),1(regular),2(symlink),3(directory),4(other). Repeated/trailing slashes are normalized in the retained joining control;this does not establish general dot/dotdot or symlink canonicalization of the stored path. Relative-path construction returns NULL. Rebuild guards capacity against `0x402`,using `0x401`-byte bounded path buffers;long-path completeness is unproved.

| Watcher offset | Width | Observed meaning |
| --- | --- | --- |
| `+0x00` |64 bits |Duplicated path |
| `+0x08` /`+0x0c` |32 /signed32 bits |Follow/deduplication key /FD |
| `+0x10` /`+0x20` |16 /16 bytes |Saved mtime /ctime timespec pairs |
| `+0x30` |64 bits |VNODE dispatch source |
| `+0x38` /`+0x40` |32 /64 bits |Monitor-reference count /pointer array |

Watcher allocation is72 bytes. The source opens paths with `O_EVTONLY=0x8000`;the symlink variant adds `O_SYMLINK=0x200000`,producing `0x208000`. It declares a VNODE source with mask `0x7f` on the stored workloop. Watcher count/array globals are `0x100014400`/`0x100014408`. Lookup compares path and follow value;raw delete bit1 changes the follow field to2,altering later lookup matching.

The [compile-only source shapes and SDK checks](triage_evidence/notifyd_monitor_layouts.c) and [assembly](triage_evidence/notifyd_monitor_layouts.s) verify monitor112,watcher72,Block32/36/40/48,stat144,timespec16,stat mtime+48/ctime+64,the open flags,VNODE mask and `SYS_initgroups=243`. The represented unknown fields are not assigned additional semantics.

## Events, masking and coalescing

| Input /source bit | Meaning /boundary |
| --- | --- |
| VNODE bits1,2,4,8,`0x10`,`0x20`,`0x40` |SDK NOTE_DELETE,WRITE,EXTEND,ATTRIB,LINK,RENAME,REVOKE;their OR is declared source mask `0x7f` |
| Synthetic `0x100` |Original callback observes changed mtime pair and ORs this bit |
| Synthetic `0x200` |Original callback observes changed ctime pair and ORs this bit |
| Rebuild `0x80` |Source status transition to an available type in the retained missing-target/parent-event control |
| `0x20000000` in monitor flags |Configuration flag,bypassing selected checks on subsequent rebuilds |
| `0x10000000` in monitor flags |Pending delayed resume;avoids another suspension/delay declaration in the same batch |

The two synthetic metadata bits are monitor-local additions;no claim is made that they are kernel NOTE values. Event handling also uses watcher-path equality,status transitions and special raw bits. Thus `raw_data & mask` alone is not a complete event-selection algorithm. In the symlink control,a raw write on the resolved target does not publish,while a subsequent raw write on the link watcher does. The retained missing-target control publishes `0x80` after a parent event plus declared target creation.

After that source selection,the local filtering/coalescing stage is:

```text
selected = source_action_bits & flags & 0x3ff
if selected != 0:
    if (flags & 0x10000000) == 0:
        flags |= 0x10000000
        request_suspend(DATA_OR)
        refs = u32(refs + 1)
        request_after(dispatch_time(0,100000000 ns),captured_monitor_block)
    request_merge_data(DATA_OR,selected)

on explicitly delivered delayed Block:
    flags &= 0xefffffff
    request_resume(DATA_OR)
    release_monitor_reference()
```

This local stage is O(1) time/storage per action,excluding filesystem/credential APIs and watcher rebuilding. The model accumulates OR data in O(1) space per source. Native delivery count/order,deadline realization,suspension balance under concurrency and integer wrap feasibility remain unknown.

| Finite control | Original source /client observation |
| --- | --- |
| Write2 plus changed mtime |Merge `0x102`;checks1(initial),1(after publication),0(repeated check) |
| No data,unchanged metadata |No publication;checks1,0,0 |
| mtime-only /ctime-only /both pairs |Synthetic bits produce publication under default mask |
| Two events2 then8 before batch end |Two merge requests,one suspend,one delayed Block,one resume;one declared DATA_OR delivery |
| Two completed batches |Two suspend/delay/resume requests and two changed polling results |
| Mask2,events8 then2 |Checks1,0,0,1,0 |
| Mask`0x100`,write2 then changed mtime |Checks1,0,0,1,0 |
| Declared cancelled VNODE |Original cancellation guard returns before event data/stat processing;checks1,0,0 |

The delay argument is exactly100000000 ns =100 ms =0.1 s. `_dispatch_time`'s returned value is an opaque fixture;no conversion of its representation into host time is inferred. DATA_OR consumption and callback scheduling are explicit actions,not hidden behavior of the model.

## Registration, credentials and environmental controls

The automatic prefix is `com.apple.system.notify.service.` (32 bytes),followed by `path:`. Without another colon,the remainder is the path and default mask is`0x3ff`. With another colon,the syntax is `path:MASK:PATH`:original code calls signed `strtol(...,base0)` on the first field and starts the path after the second colon. The retained hexadecimal masks are `0x2` and`0x100`. A path followed by a mask is not the same grammar.

Original check registration reaches parser`0x100008a24`,installation`0x100008700`,and constructor with copied source audit32 and configuration argument0. The monitor saves the source client's64-bit `(PID32 <<32)|token32` key at+96. A 16-byte auxiliary record with type2 and monitor pointer is installed through a16-bit client index into global array`0x100014258`. This index,key,nameID,FD and dispatch-source pointer are distinct from a Mach port name.

The configuration callback supplies zero audit32,configuration argument1 and mask`0x3ff`. Constructor calls the first rebuild at`0x1000075a0`,then creates DATA_OR at`0x1000075b8`,and only afterward writes configuration flag at`0x1000075d4`. Therefore the first rebuild does not yet have that flag. In the initial-sandbox-denial control,the initial metadata status is0;the next event rebuild bypasses that sandbox check and publishes after recovering status1. This ordering is directly retained;native interpretation of a zero audit token is unknown.

For per-client paths,the sandbox API call at`0x1000077cc` carries operation `file-read-metadata`,filter`0x40000001`,copied audit32 and variadic path. The filter includes original imported `_SANDBOX_CHECK_NO_REPORT=0x40000000` plus1. Sandbox denial and modeled EACCES both preserve status0/no publication in the retained write controls. API outcomes are fixtures,not recovered effective sandbox policy.

For the tested non-root,non-timezone regular path,the metadata helper performs:

| Original site | Request /source behavior |
| --- | --- |
| `0x100008050..0x100008054` |Save imported `_gL1CacheEnabled`,write0 |
| `0x100008068` |`getgroups(16,buffer)`;negative return takes early result1 |
| `0x100008078` /`0x100008088` |`getpwuid(uid)`,then `initgroups(username,gid)` |
| `0x10000808c` |Restore saved L1 value before testing `initgroups`'s negative return |
| `0x10000809c` |`pthread_setugid_np(uid,gid)` request |
| `0x1000080ac` /`0x1000080bc` |Selected lstat/stat request |
| `0x1000080cc` |`pthread_setugid_np(-101,-101)` restoration-marker request;u32 arguments `0xffffff9b` |
| `0x1000080e0` |`syscall(243,count,saved_groups,0)` request;arm64 variadic arguments are read from stack |
| `0x1000080e4..0x100008104` |Restore-groups failure ->1;stat success ->0;stat failure plus errno13 ->2;other stat failure ->1 |

Both thread-credential request results are not tested in this helper. Their native effects remain unknown. The original rebuild specifically treats helper result2 as the denied case;general helper result1 is distinct. The getgroups,password,initgroups and restore-groups failure controls consequently retain publication in their declared otherwise-successful metadata environment;this is not a native access-control bypass claim.

On `getgroups` failure,the branch at`0x10000806c` reaches result1 without restoring L1. The initial1 fixture ends0;the initial0 control remains0. Password-record NULL and negative `initgroups` controls restore the saved1. The byte ledger independently accounts for44 original bound-global stores across the matrix. No claim is made that an actual process has the reference initial value or that a later unrelated path cannot restore it.

The once callback stores a declared canonical timezone prefix;later `strncasecmp` compares exactly its saved length. The retained 25-byte prefix `/var/db/timezone/zoneinfo` bypasses the credential-stat helper for both a matching descendant and `/VAR/DB/TIMEZONE/ZONEINFOx/fixture`. This demonstrates lexical,case-insensitive prefix comparison without a subsequent separator check in that branch. The path is a declared realpath result;native canonical prefixes,path existence and consequences remain unknown. A UID0 control also skips the credential-stat helper.

## Publication and Mach interfaces

| Interface | Original location | Established transfer |
| --- | --- | --- |
| Client checkin1023 |libnotify emission `0x18059d9c0` |24-byte request,original selector/stub under declared header/audit transport |
| Client check registration1012 |Emission `0x180593fc4` |Name-bearing request;96 bytes for `fixture.path`,larger for service.path names |
| Configuration publication |Block`0x1000086ec` ->internal`0x1000051dc` |Saved name,UID0/GID0;shared increment at`0x100005254`,then name generation/client delivery through`0x100000cf4` |
| Per-client publication |Block`0x100008990` |Resolve saved key,increment referenced name's shared slot at`0x100008a00` where check flavor applies,tail delivery helper`0x100000a40` at`0x100008a20` |
| Public check |Original shared reads,including `0x180594520` |Reads declared shared alias;retained successful checks emit no new request |
| Client cancellation1016 |Emission `0x1805a2c38` |36-byte one-way request;original worker/cancellation/release chain executes |

The per-client callback targets a resolved client record;its counter is associated with that client's name and must not be assumed private to one subscriber. It does not call the named generation-post routine in these paths. The configuration callback does. Neither publication is modeled by injecting an RPC1009/1010 post.

No new direct Mach-send site is established by the retained VNODE/DATA_OR polling callbacks. Other registration flavors can reach the previously recovered active-delivery helper/sender boundary;see [notify IPC](notify_ipc_report.md),including sender`0x1000012a4` and24-byte emission`0x100001374`. Those alternate monitor-registration/delivery prerequisites are not exercised here. Incoming service fixture`0x5902`,reply fixture`0x5901`,shared alias and audit production retain the earlier explicit transport assumptions;no native right identity is inferred.

The VNODE and DATA_OR source handles are dispatch interfaces. The VNODE handles100 onward in these fixtures are declared FDs,not additional incoming/outgoing Mach ports. The source declares DATA_OR creation at`0x1000075b8`,VNODE creation at`0x100008268`,VNODE handler installation at`0x100008348` and cancellation handler installation at`0x100008394`. These are architectural touch points,not observed native kernel deliveries.

## Cancellation, retirement and zero-count branch

Monitor release decrements a nonzero reference count and retires when the result is zero;an already-zero count also takes retirement. A pending delay increments refs1->2. Both an explicit configuration-helper release and original public client cancellation reduce it2->1;the subsequently delivered original delayed callback reduces it1->0 and retires. These sequences establish the local reference handoff,not a general concurrency or overflow proof.

Per-client cancellation is reached through original request1016 and original worker/cancellation functions. Configuration release is an explicit helper-entry control;its complete upstream caller prerequisites are not claimed. Source release detaches monitor references,compacts watcher state,frees monitor-owned allocations and releases DATA_OR. Per-client cancellation separately requests DATA_OR cancellation at`0x1000035bc`.

| Removal control | Source-owned state after retained sequence |
| --- | --- |
| Last configuration monitor released |Monitor retired;global watcher count0;three watcher records and three declared FDs remain live;this compactor declares no per-watcher cancel/disposer callbacks |
| Last per-client monitor cancelled |Same watcher-count/record/FD outcome;DATA_OR cancellation request is separately recorded |
| Last monitor cancelled while delayed |Monitor survives at ref1 until delayed callback;then retires with the same zero-count watcher branch |
| One monitor released while another survives |Shared root watcher remains;two unused watchers receive cancel requests and copied disposer Blocks;explicitly delivered disposers free their records;separate captured cancel callbacks close their two FDs;three surviving watcher FDs remain |

In compactor`0x100007cf8`,the active watcher count is compared with the previous count. When the active count is zero,the branch at`0x100007e54` targets`0x100007f14`,then frees/replaces the global pointer array and writes count0. It bypasses the per-watcher cancellation/disposer loop containing cancel`0x100007ebc` and async declaration`0x100007efc`. When at least one watcher remains,the retained control enters that loop for unused watchers.

The disposer at`0x100007f98` releases the VNODE object and frees watcher-owned memory. The separate36-byte cancellation Block invokes close at`0x1000086e8`. A source-creation-NULL VNODE control instead closes the just-opened FD at`0x1000083ec`. DATA_OR-creation NULL reaches the explicitly stopped NULL-handler boundary;no native crash is inferred.

These controls identify where this source path does and does not transfer cancellation/FD-close work. Outstanding dispatch ownership,already queued callbacks,other release paths,native FD lifetime and possible resource accumulation remain unknown. In particular,absence of cancellation in the retained compactor path does not prove absence of every native cleanup owner.

## Independent verification and preservation

The validator independently reconstructs original instruction streams,complete compiler ranges,cache page chains,selected direct edges,import slots,original data/strings/descriptors,allocation lifetime and bytes,provider DATA,shared memory,imported L1 data,source records,Block copies,FD state,dispatch declarations/requests and original client polling deltas. Every callback entry and frame comes from a source-built captured Block. Filesystem updates,event data,DataOR consumption and scheduling actions are explicit in the chronological journal.

Four local bitvector queries establish low10 masking,metadata-bit composition,release-zero predicates and pending-flag set/clear identities. They do not prove native scheduling,concurrency or reachability. The SDK check is compile-only. All 40 cases are freshly replayed: 339 provider original calls and 156 client public calls, 495 calls total. The matrix includes one deliberately bounded DATA_OR-NULL stop;all other retained provider paths complete to their declared return/startup boundaries.

All 589469 assertions pass across 549454 original-instruction visits, 11786 source stores, 2489 explicit API output effects, 9586 reconstructed allocation snapshots, 634 monitor/watcher record snapshots, 2471 copied-Block snapshots, 2168 dispatch-source snapshots, 339 FD-state snapshots, 44 imported L1 stores, 82 paired messages and 132 explicitly delivered captured callbacks. Exact counts and source/fixture boundaries remain in the checks/quality artifacts.

Ledger validation costs O(B+P+I+V+W*V+A+D) time and O(B+P+I+V+W+A+D) retained space for original bytes B,pages P,unique instructions I,visits V,stores W,total allocation/snapshot bytes A and explicit declarations D. The W*V term bounds the current linear source-visit membership check for every retained store. Finite original-code replay has the separately recorded invocation/step budgets. Source invocation budgets remain 300000 provider/200000 client steps,512 owned allocations,65536 bytes per allocation request and 64 entries for guarded observed lists. Copied Blocks are limited to 128 bytes and a bounded private copy region. Each solver timeout is30000 ms. These harness bounds are not asserted native limits.

The [preservation record](triage_evidence/notifyd_monitor_preservation.json) checks all 909 prior artifacts against the [prior manifest](triage_evidence/notifyd_monitor_prior_manifest.json): 903 remain byte-identical;only the five reporting indexes/status and manifest aggregator change. All three supplied original inputs remain identical. Original sources,configuration,external dump.md,IDBs and published evidence artifacts are not written. The [current manifest](triage_evidence/interface_manifest.json) is refreshed separately and retains goal status active.

## Assumption register

| ID | Assumption /dependent results | Stress test /falsification probe |
| --- | --- | --- |
| M1 | Pinned executable/cache/SDK supply these source contracts | Reconcile loaded slices,UUIDs,slides,bindings and header epoch before native pairing |
| M2 | Declared config/filesystem maps represent finite inputs | Retain actual prior configuration separately;measure effective configuration/open identity and real file-event prerequisites independently |
| M3 | stat/realpath/open/errno/event results are explicit | Missing target,symlink,metadata-pair,denial,NULL-source and cancelled-source controls;native inode/FD/kernel-event relationships remain unknown |
| M4 | Block extent/capture copying follows original descriptor data | Original32/36/40/48 extents,exact byte ledgers and captured callbacks;native retain/dispose helpers and PAC authentication require separate evidence |
| M5 | Deferred,timer,DataOR,disposer and cancel delivery are explicitly scheduled | Two-event coalescing,two batches and pending-cancel controls;native ordering/concurrency/suspension/close timing remain unproved |
| M6 | Audit tokens/header/trailers/shared aliases are declared transport inputs | Execute original decoding/selector/stubs;attest native sender identity,admission,rights and mappings before operational claims |
| M7 | Imported sandbox/L1 reference bytes initialize private variables | Fresh original export/bind data plus L1-initial0 control;native mutable values/interposition/global ownership remain unknown |
| M8 | Credential/stat/group API results drive local source branches only | getgroups/password/initgroups/EACCES/restore failure controls;no native credentials,group restoration success or access-policy consequence inferred |
| M9 | Allocator/string/conversion/dispatch APIs are bounded models | Independent ownership/byte/FD/Block ledgers and all fresh replays;allocation failure,long paths,locale and native dispatch state remain outside retained domains |
| M10 | Last-monitor versus surviving-monitor controls delimit cleanup claims | Complete original public client cancel plus explicit configuration-helper release;other owners and native resource disposition remain unknown |
| M11 | Retained public registration uses check/poll flavor | Trace shared-slot writes and original checks;exercise Mach/signal/FD flavors separately before extending delivery or port claims |
| M12 | Finite witnesses/local formulas do not complete the protected transaction | Establish upstream ADID/fairplayd predecessors,actual service/credential/rights context and native daemon/kext lifecycle separately |

## Bounded continuation

| Impact | Further interface | Precise unresolved question |
| --- | --- | --- |
| High | Native monitor/resource ownership | Which native owner retires last-monitor VNODE records/FDs after the zero-count branch,and what ordering does dispatch enforce? |
| High | Complete protected notification predecessors | Which successful daemon/kext/provider operations cause the ADID posts,and which clients observe them through real rights/mappings? |
| Medium | Credential/libinfo environment | Is getgroups failure reachable with a nonzero runtime L1 flag,and which later paths restore it or depend on it? |
| Medium | Alternate registration/delivery | Do service.path names under Mach/signal/FD registration preserve these monitor prerequisites,and where do notification rights/backpressure enter? |
| Medium | Canonical timezone prefix | What exact native realpath prefix is stored,and how do path identity,separator/case behavior and sandbox outcomes interact? |
| Medium | Configuration flag timing and errors | How are zero-audit first rebuilds interpreted natively,and what do actual source/allocation/open failures do across startup/reload? |
| Low | Remaining path/parser boundaries | Dot components,long paths,colon-containing paths,numeric conversion edges and unknown monitor fields |

QG1-QG7 pass for the stated increment:descriptive analysis;M1-M12 assumptions and falsification probes;bounded interface coverage;consistent byte/bit/time/layout calculations;explicit error/ownership/ordering distinctions;fresh provenance,independent ledgers,all replays,SDK compilation and local formulas;impact-labeled continuation. No native defect or broad-goal completion is claimed.
