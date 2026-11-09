# notifyd configuration, controlled names and state IPC

A read-only capture found `/etc/notify.conf` present,owned by UID0/GID0,mode`0644`,557 bytes,SHA256 `87e607d6a1eb69bfb76c9136db7b38f2e27f66966a9dbd815104fab2695a01ca`. Original notifyd parses those captured bytes into two controlled prefixes,four deferred monitor declarations and five initial-state declarations. The resulting policy preserves the three ordinary ADID-name feedback sequences in the paired guest. This replaces the missing-file premise for these new reference-file cases;it does not establish what the running daemon loaded.

The [previous paired report](notifyd_admission_report.md) remains valid under its explicit missing-config fixture. This increment adds original parsing,policy ordering,owner/group/access semantics,metadata/grammar controls,64-bit state get/set IPC and original libbsm audit decoding. All native credentials,endpoint/right identities,configuration epochs,transport and scheduling remain unresolved. P1-P13 delimit dependent results. Addresses are unslid.

```text
captured config bytes + declared stat/FILE results
                 |
          original main/parser
        /           |             \
 controlled names   initial state  deferred monitor blocks
        |           |             |
 registration/post  get/set IPC    native execution unproved
        \           /
         original workers -> counters/state -> original client
```

## Provenance and reference policy

The [captured file](triage_evidence/notifyd_policy_reference.conf) and [capture metadata](triage_evidence/notifyd_policy_reference.json) retain exact bytes,ownership,mode,inode,mtime and a stable before/after read. No source file or target configuration was written. The [profiles](triage_evidence/notifyd_policy_profiles.json), [contracts](triage_evidence/notifyd_policy_contracts.json), [provider extension](triage_evidence/probe_notifyd_policy.py), [paired producer](triage_evidence/probe_notifyd_policy_pairs.py) and [validator](triage_evidence/validate_notifyd_policy.py) preserve the source/fixture boundary.

Original notifyd selected slice SHA256 remains `aeeae7016d04af9b2a08f0491559ac0291ec3954fd93bdf167c30607d44fae23`,UUID `d27ffd43-6f5d-3882-8bcf-4853e8a0b288`. Cache UUID remains `2bd06591-e751-3e84-963f-b08dab6af23a`. Original libbsm image `/usr/lib/libbsm.0.dylib`,UUID `a01677ab-bd20-3c62-8b0f-c805062f95bd`,now supplies executed audit-token helpers rather than modeled field extraction in the new provider guest. Nine audit-helper export bodies are pinned;the retained paths execute the required subset. Audit bytes remain explicit transport fixtures,without native authenticity.

| Captured directive | Original parsed result |
| --- | --- |
| `reserve com.apple.system. 0 0 rwr-r-` |Controlled prefix;UID0,GID0,mask`0x113` |
| `reserve com.apple.system.clock_set 0 266 rwrwr-` |Controlled prefix;UID0,GID266,mask`0x133`;sorted before the shorter system prefix |
| Four `monitor` lines |Names for timezone and system-info hosts/services/protocols;paths `/etc/localtime`,`/etc/hosts`,`/etc/services`,`/etc/protocols`;original registration and deferred callback declarations |
| Five `set` lines without value |Battery-saver,low-power and high-power names initialized with state0;no explicit numeric setter call in the two-token form |

The three ADID names do not begin with either controlled prefix. In each reference-file paired case,original registration,post,counter update,check and cancellation complete under the declared API/transport environment. The clock-set rule grants effective GID266 write access in the retained tests;effective GID20 is denied. The executed helper compares the decoded effective GID;it does not evaluate a supplementary-group list. A `clock_setx` suffix still matches the clock-set prefix:matching is raw prefix matching,without an added boundary delimiter. `com.apple.system2.clock_set` matches neither captured prefix.

Original nameIDs depend on creation order. Parsing configuration creates names before the later ADID registration,so the earlier missing-config nameID examples are not universal identifiers. NameIDs are64-bit application lookup keys,not Mach port names.

## File and parser admission

| Source boundary | Original site | Local contract |
| --- | --- | --- |
| Config metadata |`0x100005894` |`stat("/etc/notify.conf",...)`;stat failure skips parsing |
| Owner |`0x10000589c` |Loaded UID32 at stat+16 must equal0 |
| Mode |`0x1000058a4..0x1000058a8` |Loaded mode16 at stat+4;bit1 set skips parsing |
| Open |`0x1000058bc` |`fopen(...,"r")`;NULL skips parsing |
| Read |`0x100005900` |`fgets(buffer,1024,stream)`;up to1023 data bytes plus NUL per call |
| Chunk editing |`0x100005918..0x100005924` |Computes strlen and removes the last byte unconditionally |
| Token append/disposal |`0x10000723c` /`0x1000070d0` |Original allocated NULL-terminated pointer vector with duplicated token strings |
| Command dispatch |`0x100005a10..0x100005a70` |ASCII case-insensitive command comparison;`monitor`,`set`,`reserve`,`quit` |
| Controlled-name insertion |`0x100001184` |Original reallocated pointer array,descending string order,deduplication by name-record identity |

The [compile-only layouts](triage_evidence/notifyd_policy_layouts.c) and [assembly](triage_evidence/notifyd_policy_layouts.s) verify `struct stat` size144,mode+4,UID+16,GID+20,size+96,`S_IWOTH=2` and`S_IWGRP=16`. The source metadata gate tests other-write bit1;it does not test group-write bit4 in that branch. Root-owned mode`0664` is parsed in the fixture,while mode`0666` and non-root ownership skip parsing. Open failure and missing-file controls also skip parsing. This source gate is not a complete native file-identity,symlink,ownership-epoch or sandbox proof.

A local16-bit formula verifies the tested mode mask and its invariance when group-write is toggled. The capture's actual mode`0644` passes that local metadata predicate;actual daemon startup/read results remain unknown.

## Directive grammar and token boundaries

| Directive | Source token-count/field behavior |
| --- | --- |
| `reserve NAME [UID [GID [ACCESS]]]` |Requires at least2 tokens;UID/GID default0,mask defaults`0x333`;extra tokens after ACCESS are ignored by this handler |
| `set NAME [VALUE]` |Accepts exactly2 or3 tokens;three-token form parses signed64 decimal with declared `atoll` behavior,then stores its64-bit representation |
| `monitor NAME PATH ...` |Requires at least3 tokens;original code registers the name and schedules a block retaining the token vector |
| `quit ...` |Case-insensitive command comparison terminates the retained config-reading loop;later bytes need not be consumed |

Source whitespace bitmap`0x0000000100000201`,guarded by character<=32,recognizes byte0,HT and space. NUL terminates C strings;the separator controls use HT and space. Repeated separators preserve empty fields. A comment is skipped when `#` is the chunk's first byte;there is no general inline-comment removal in the retained tokenizer. Extra trailing comment tokens happen to be ignored by the tested `reserve` field handler.

| Explicit control | Original result |
| --- | --- |
| Leading space before `reserve` |First token is empty;directive is unrecognized;no controlled rule is added |
| Two spaces after `reserve` |Tokens include empty NAME;the tested shifted fields yield an empty controlled prefix with access0;ordinary non-root registration is denied |
| HT separators |Same field sequence as single spaces |
| `RESERVE` command |Recognized by command comparison |
| CRLF after full-grant ACCESS |CR remains in the field,whose length is7;source selects access0 |
| No final newline after full-grant ACCESS |Final `w` is removed;five-character field selects access0 |
| First-byte comment /blank line |Skipped in retained controls |
| `quit` before a rule |Later rule is not applied |

These are source/parser witnesses with declared file bytes. The captured reference file uses normal LF-terminated lines and does not contain the malformed controls. Chunk splitting of longer lines,NUL/invalid-byte inputs,locale behavior,allocation failures and native consequences require separate evidence.

## Controlled-name records,ordering and updates

Controlled array pointer is global`0x100014210`;count32 is global`0x100014224`. Entries point to source-created name records. The relevant record fields remain name pointer64+8,UID32+40,GID32+44 and access32+48. Original constructor and collection code execute;the array and records are not injected.

Original insertion compares the new name against existing names and inserts before the first lexicographically smaller name. The matcher walks that descending order and uses the first matching prefix. Parent-then-child and child-then-parent configuration orders produce the same sorted array and selected specific rule in the retained controls. Duplicate entries reuse the existing record.

`reserve` updates are selective. UID/GID are written together only when their bitwise OR is nonzero. Access is written only when its decoded value differs from default`0x333`. Consequently:

- A later UID0/GID0 pair does not clear an existing nonzero pair through this branch.
- A later `rwrwrw` default mask does not reset an existing access0 mask.
- `reserve NAME` with all defaults need not add a controlled record.

The duplicate-rule controls retain one record with access0 in both tested orders,including the case labeled `ordering_duplicate_child_last_allows`;the observed result contradicts the label's initial hypothesis. The checks use actual token vectors,record fields and independent policy state,not that hypothesis.

## Permission composition and namespace precedence

The common permission helper is `0x100000890`. For a valid name,UID0 bypasses the remaining tested policy. A name beginning `user.uid.` takes the source UID-prefix branch before controlled-table matching. Its matching UID can register/post even when a parsed controlled prefix has access0;a different UID is rejected by the namespace check. Controlled rules do not override that branch in the retained cases.

For the first matched controlled rule and operation op1(read/registration) or op2(write/post/state setter),the source permits when any of these terms is true:

```text
(uid == owner && (access & op) != 0)
 || (gid == group && (access & (op << 4)) != 0)
 ||                 (access & (op << 8)) != 0
```

An absent earlier-class grant does not stop evaluation of later grant terms. Matching owner with no read bit can receive the other-read grant;matching group with no write bit can receive the other-write grant. Both controls complete original registration/post feedback. A32-bit formula independently reduces the source CMP/CCMP branch flags to this expression for op1/2.

Six ACCESS positions contribute bits1,2,`0x10`,`0x20`,`0x100`,`0x200`. Only lowercase `r` or `w` at its respective position contributes a bit. A field with length other than6 selects0;unknown six-character letters also select0. A48-bit formula verifies the six-byte decoder,including its owner-bit CINC/CSEL sequence.

| Reference/custom case | Retained registration/post result |
| --- | --- |
| Captured config +each ADID name |Registration0,post transport0,next changed1 |
| System parent prefix,UID501/GID20 |Read registration succeeds;post leaves counter unchanged |
| Clock-set prefix,GID266 |Read/write grants allow update |
| Clock-set prefix,GID20 |Read succeeds;write denied |
| Custom owner501/group20,mask`0x13` |Owner writes;other UID with group20 reads but does not write;unmatched UID/group fails registration7 |
| Root UID0 |Retained deny-mask controls permit through root branch |

All credentials are supplied audit-token bytes. Original libbsm code decodes them;no native credential acquisition,forgery feasibility or arbitrary sender reachability is established.

## Configuration state and Mach1017/1019

Original config `set` feeds the nameID-based setter`0x100000e48`. On success it writes name_record+24,state64,and +32,the declared opaque `_mach_absolute_time` tick value. The three-token controls cover0,1,-1,`9223372036854775807` and a numeric-prefix input`12junk`. The two-token form leaves initial state0/timestamp0 in its retained record. No conversion of opaque ticks to SI time is inferred.

| Interface | Original client emission /provider | Wire contract |
| --- | --- | --- |
| Get state1017 /reply1117 |`0x1805960a4`;stub`0x10000a1dc` |40-byte request:NDR+nameID64@32;receive capacity56;48-byte reply:kernel status32@32,state64@36,application status32@44;options`0x304003` |
| Set state1019 |`0x180597d34`;stub`0x10000a4d8` ->worker`0x1000027c8` |52-byte one-way request:NDR,nameID64@32,state64@40,flags32@48;options`0x1`;no application reply delivered |

The original client getter consumes original provider reply bytes. Initial values0,1,all-ones and signed64 maximum round-trip. An allowed setter changes17 to`0x1122334455667788`;subsequent getter returns the new value. In a read-allowed/write-denied case,the setter API still returns0 under transport result0,but subsequent getter returns17. Root and group266 controls permit the update. The setter does not advance the sampled notification counter in these paths;the later `notify_post` determines changed feedback separately.

The legacy setter stub supplies worker argument5=0,so its optional sandbox-check branch is not entered in these cases. Root/restricted-post/access checks and other MIG variants remain distinct source boundaries;absence of this optional call does not establish effective native sandbox policy.

The identifier getter has a different local admission shape. With configuration creating `fixture.state=17` and a deny controlled rule,the original client check registration returns7. A separately supplied message1017 with the known source nameID1 still returns state17/application status0. Its retained stub path decodes audit metadata and looks up the ID without executing common permission helper`0x100000890`. Missing all-ones nameID returns state0/status1. These controls establish identifier-based read behavior under explicit header/audit/nameID inputs. Native endpoint admission,identifier availability,actual policy and consequences remain unknown;no native disclosure or defect is claimed.

## Independent verification

The validator checks fresh binary/cache/compiler bytes,pointer members,original audit-helper bodies,source strings,stat/state SDK layouts and four local formulas. A separate parser/policy model reconstructs chunk editing,token vectors,directive updates,ordering and grant decisions. A separate memory ledger applies declared API writes and actual post-store bytes to reconstruct allocation lifetime/content,DATA globals,shared counters and controlled records. Original source stores are not replaced with expected policy results.

All58 complete fixtures are freshly replayed,including295 original client public calls,396 original selector/stub calls and58 original main prefixes. All894657 assertions pass across838798 original-instruction visits,20066 source stores,1680 API output effects,20697 independently reconstructed allocation snapshots,413 controlled-record snapshots and196 paired client transport messages. These include16 paired client state messages;two additional direct nameID controls are recorded in provider calls. Exact assertions,source visits,ledger counts and state-message counts appear in the [checks](triage_evidence/notifyd_policy_checks.json) and [quality gates](triage_evidence/notifyd_policy_quality_gates.json). The [preservation ledger](triage_evidence/notifyd_policy_preservation.json) covers all889 prior artifacts;only five reporting indexes/status and the manifest aggregator may change.

Extraction/replay/verification costs O(B+P+I+V+W+A) time and retained space for bounded source bytes B,page bytes P,unique instructions I,visits V,writes W and owned allocation bytes A. Providers are capped at300000 guest steps per invocation,clients at200000;owned allocations are capped at512 and65536 bytes per request;token/control vectors have64-entry guards. Each solver has a30000 ms timeout. These analysis limits are not native implementation limits.

## Assumption register

| ID | Assumption /dependent results | Stress test /falsification probe |
| --- | --- | --- |
| P1 | Pinned reference program/cache/SDK supply source semantics | Match actual loaded slices,UUIDs,slides,headers and integrity before native pairing |
| P2 | Captured current file is a reference input,not loaded daemon state | Compare actual startup/configuration epoch and open identity;capture explicitly records loaded-state unproved |
| P3 | stat/FILE/open/read results are declared API inputs | UID/mode/open/absent controls and exact streamed-byte checks;native identity/type/symlink/TOCTOU remain open |
| P4 | Startup and callbacks execute only where explicitly invoked | Full original main returns to modeled dispatch boundary;monitor/scheduling/reload/process-death behavior requires separate execution |
| P5 | Header,audit and shared-object transfer are explicit | Original audit decoding improves interpretation,not authenticity;attest native credentials,right transfer and mapping epochs |
| P6 | ASCII names,op1/2 and six-byte field semantics bound policy claims | Independent byte/flag formulas and owner/group/other controls;invalid-byte/locale domains remain open |
| P7 | Original ordering/selective updates determine first-prefix rule | Reversed insertion and duplicate-rule controls;do not assume every later field overwrites prior state |
| P8 | Grammar controls are explicit fixtures | Actual reference uses ordinary LF lines;long chunks,NULs and malformed-input/native consequences require separate evidence |
| P9 | Owned allocator/reallocf/string/number/tick APIs are bounded models | Independent lifetime/byte ledgers;native capacity,failure behavior,locale,overflow and timing are unproved |
| P10 | State-get control supplies a known valid source nameID | Missing-ID control and complete original path;native ID availability,endpoint authority and consequence are unknown |
| P11 | One-way API result0 conveys declared transport result | Subsequent original getters/polls distinguish accepted/denied state;no server policy receipt inferred |
| P12 | NameIDs depend on parsed source state and are not port identities | Compare config-dependent construction order and actual namespace/right objects before pairing |
| P13 | Formula/replay coverage is local and finite | Upstream akd/adid protected predecessors,all alternate MIG modes,VFS monitors,native transaction and full goal remain open |

## Bounded continuation

| Impact | Further investigation | Unresolved interface |
| --- | --- | --- |
| High | Reconcile actual daemon-loaded config/image/credential/endpoint state | Current file capture versus effective policy epoch,service rights and native admitted calls |
| High | Follow nameID-based state readers and alternate setters | Which native callers obtain IDs,where admission is enforced,other MIG variants and application semantics |
| Medium | Execute deferred monitor blocks and VFS callbacks | Path parsing,FD/inode/event ownership,filesystem-to-notification publication and cleanup |
| Medium | Complete group-write/file-identity and malformed-config boundaries | Actual writer sets,stat/open identity,chunk splitting,NUL/locale/allocation-failure handling;native consequence unproved |
| Medium | Bind all three ADID classes in one upstream client/provider lifecycle | Config-dependent IDs,baseline polling,per-record invalidation and protected-provider post predecessors |
| Medium | Extend state/counter/lifetime concurrency | Restart/reload,process monitors,slot reuse,ordering and native object retirement |

QG1-QG7 pass for the stated increment:descriptive analysis,falsifiable assumptions,bounded coverage,consistent byte/width/layout arithmetic,separated source/fixture/native claims,fresh provenance/independent models/ledgers/replays,and impact-labeled continuation. The broader daemon/kext/deeper-facility goal remains active and incomplete.
