# Original CF source scheduling, port-set insertion and later dispatch

Original `CFRunLoopAddSource` instructions connect a version1 source's port to
the mode dictionary and request insertion into the mode's separate port set.
Four private compositions subsequently execute the original run loop and its
dictionary lookup wrappers against state produced by those registration calls.
The lookup result is no longer an independently supplied source pointer.
Stateful collection backends and Mach traps remain explicit models. [SS1-SS8]

Original source order also separates CF bookkeeping from membership success:
the dictionary update precedes `_mach_port_insert_member`; a declared returned
value4 reaches subsequent source/run-loop bookkeeping without rollback in this
path. This establishes local source behavior under the stated model, not native
failure feasibility or a native service consequence. The whole FairPlay
transaction and effective native registration remain unknown.

## Assumption register

| ID | Assumption | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| SS1 | Pinned original cache/kernel/daemon corpus is the selected implementation | Addresses, functions, bindings and original instruction composition | Recapture28 bodies, ten stubs, nlists and nine cache-file hashes; attest actual loaded-image pairing separately |
| SS2 | The declared version1 source, CF port object, existing mode and empty collection fixtures are consistent inputs | Original scheduling route and getter result | Check every field and argument; recover actual source construction, CF cache history, mode lookup/creation and object signatures rather than inferring native objects from these fixtures |
| SS3 | Declared BasicHash backends implement the stated dictionary/set/bag operations | Association persistence, duplicate detection and later lookup | Independently recompute all state from original call arguments and check bucket outputs/bag counts; replace backends with original allocation/hash/retain/release implementations separately |
| SS4 | Declared Mach type/member trap results and task name apply | Selected preflight, membership success/error and continuation | Execute original wrappers, check all trap arguments/results and original branch order; establish actual task namespace/rights, port-set objects and trap behavior separately |
| SS5 | Explicit function-entry order installer -> AddSource -> internal run loop applies to the four compositions | Shared association state reaches original receiver/daemon | Verify full CPU/memory/state handoffs with only public arguments changed; recover the actual daemon startup through these calls separately |
| SS6 | Pinned direct-receiver kernel packets can be supplied at the declared port-set Mach receive boundary | Message bytes consumed by the scheduled source | Freshly replay four original kernel producers and check exact148+29 transferred bytes; actual kernel receive through this port set is not exercised and remains unknown |
| SS7 | Prior CF primitives, clocks/no-work, allocation, library-binding and logical PAC contracts apply | Remaining CF/daemon/application continuation | Replay complete journals, unchanged original instruction suffixes and model frames; attest native helper effects, concurrency, runtime epochs and hardware authentication separately |
| SS8 | Registration return, original run-loop return and pre-pthread stop delimit observations | Return, ownership and processing scope | Verify complete final memory and backend state; continue actual thread/environment/output/disposal paths before claiming successful FairPlay processing or a completed round trip |

## Primary source and evidence

[Source capture](triage_evidence/cf_source_scheduling_source.json) retains28
complete original cache functions, ten original16-byte import stubs and2309
captured instructions. Nine full cache-file hashes, exact nlists and original
chained-pointer records pin the source. The selected cache UUID remains
2bd06591-e751-3e84-963f-b08dab6af23a. The complete AddSource body is261
instructions at0x18472d934..0x18472dd48 (exclusive end). [SS1]

[Profiles](triage_evidence/cf_source_scheduling_profiles.json) contain four
schedule-to-consumer compositions, four declared member-error controls, and
duplicate-source, invalid-source and zero-port controls. Original dictionary,
set and bag wrappers execute; the lower BasicHash operations are modeled.
Original libkernel type/member wrappers execute down to modeled trap entries.
No native CoreFoundation, Mach IPC, source registration, thread API or hardware
PAC executes. The journal field `public_handoffs` names harness-to-function
entry setup. `___CFRunLoopRun` and `_voucher_init` are internal routines;
their complete native callers are not executed. AddSource is the public CF API. Original binaries, supplied trace and IDBs are preserved.
[Independent checks](triage_evidence/cf_source_scheduling_checks.json) recapture
source and replay every case without importing the new probe. [SS1-SS8]

The earlier [daemon registration report](daemon_registration_report.md) locates
the original daemon's AddSource call at0x100315300, after named check-in and CF
source creation. This increment starts AddSource with declared public inputs;
it does not execute that entire startup chain or prove actual cache/object
identity. The preceding [run-loop report](cf_runloop_handoff_report.md) retains
the receive/source/daemon caller ABI and runtime assumptions. [SS2,SS5,SS7]

## Field and callback contracts

All offsets below are bytes. CF object/source pointers are64 bits; Mach names
used here are32 bits. Addresses are preferred unslid source addresses, while
0x6500... values in profiles are private fixture addresses. [SS1,SS2,SS4]

| Object / field | Original consumer or writer | Recovered role |
| --- | --- | --- |
| CFMachPort+0x14 | 0x1847e8924: `LDR W0,[X0,#0x14]`; 0x1847e8928: `RET` | Exact two-instruction `___CFMachPortGetPort` callback; returns u32 name |
| Source+0x08, bit3 | AddSource validity branch after port-type preflight | Admission to collection/mode scheduling in this path |
| Source+0x60 | AddSource -> original CFBagAddValue | Bag associating source with run loops; model preserves counts |
| Source+0x68 | AddSource compares to1 | Version1 scheduling path |
| Source+0x70 | Original authenticated getter call | Getter info argument, declared CFMachPortRef |
| Source+0xa0 | AddSource authenticated call, discriminator0x922c | Version1 getPort callback |
| Source+0xa8 | Prior original DoSource1/perform path | Version1 perform callback |
| Mode+0x60 / +0x68 | Original CFSetContainsValue / CFSetAddValue | Source0/source1 collections in the recovered branch |
| Mode+0x80 | Original CFDictionarySetValue / CFDictionaryGetValue | Local-name -> source association |
| Mode+0x88 | Original member call and later receive-helper caller | Mode's u32 port-set receive facility |

The two mode collections, dictionary and source bag already exist in these
fixtures. Their allocation branches are captured but not exercised. Mode lookup
returns the declared existing mode. The mode-name fixture follows the ordinary
mode path, rather than the separate common-modes branch. Native object
construction, common-mode propagation and asynchronous invalidation remain open.
[SS2,SS3,SS7]

## Original scheduling order and Mach boundaries

```text
CFRunLoopAddSource(runloop, source, modeName)
  -> version1 getPort(info) -> u32 sourceName
  -> mach_port_type(task, sourceName, &type) [original wrapper, modeled trap]
  -> source-validity check
  -> existing-mode lookup [model]
  -> contains(source0/source1); add to source1 [original wrappers]
  -> getPort(info) -> sourceName
  -> dictionary[sourceName] = source [original wrapper, stateful backend]
  -> mach_port_insert_member(task, sourceName, modePortSet)
       [original wrapper, modeled trap]
  -> source bag adds runloop [original wrapper, stateful counted backend]
  -> return from original AddSource

explicit internal run-loop function-entry call, retaining CPU/RAM/backend state
  -> Mach receive(modePortSet) [declared kernel-packet transfer]
  -> returned local name = sourceName
  -> original dictionary/get-bucket wrappers read registration-produced entry
  -> DoSource1 -> perform -> original daemon callback
```

| Original site | Checked operation |
| --- | --- |
| 0x18472d9dc | First getPort callback call; preflight name |
| 0x18472d9f8 | Shared type stub0x188076bc0 -> `_mach_port_type`0x18054a938 |
| 0x18054a958 | Original type wrapper calls trap entry0x180547cc0 |
| 0x18472dbd0 | Add source to mode's source1 set |
| 0x18472dbe8 | Second getPort callback call; registration name |
| 0x18472dc00 | `_CFDictionarySetValue`0x1846dcc44 with (modeDictionary,u32Name,source) |
| 0x18472dc18 | Shared member stub0x188085b80 -> `_mach_port_insert_member`0x180549f50 |
| 0x180549f70 | Original member wrapper calls trap entry0x180547af8 |
| 0x18472dc1c | Immediately adds source-lock address to X0; no immediate branch on returned W0 |
| 0x18472dc50 | `_CFBagAddValue`0x18472dd48 with (sourceBag,runloop) |
| 0x1847576f4 | Later original run-loop dictionary lookup, keyed by returned local name |

The source task binding cell0x1e01c8b30 decodes through its original v5 chain to
global0x1ed83e960, exact original nlist `_mach_task_self_`. Its file value is0;
the private runtime fixture sets the u32
task name to0x103. Type/member stubs have separate checked original binding
cells0x1e2103b50 and0x1e2103ae8. No current native task name is inferred. [SS1,SS4]

The original trap-entry bytes also establish these exact static system-call
sites. Each three-instruction stub sets X16, executes `SVC #0x80`, then returns.
The16-byte helper captures include those12 bytes and the next stub's first
instruction; the latter is not attributed to the preceding stub. Execution in
this increment is modeled at entry, before any of these trap instructions run.
[SS1,SS4]

| Trap entry | X16 selector | Original SVC address | Original return address |
| --- | --- | --- | --- |
| 0x180547cc0, type | -0x4c (-76) | 0x180547cc4 | 0x180547cc8 |
| 0x180547af8, insert member | -0x16 (-22) | 0x180547afc | 0x180547b00 |

Type preflight normally returns status0 and mask0x20000 through its output
pointer. Original bit testing then skips the dispatch-monitor construction
branch. The zero-name control instead declares type status4 and leaves the
initialized output0. Type/member wrappers retain their original special
0x10000003 fallback comparison; that fallback is not exercised here. Trap
entries are modeled before executing a target system instruction. [SS4,SS7]

The mode port set is private name0x503; ordinary source names are0x303 or0x403.
These names are deliberately distinct. Successful member models record the
pair (portSet,sourceName). The receive contract asserts that pair exists and
supplies the verified kernel packet whose returned local field identifies the
source. The kernel producers themselves receive directly from their declared
service names. Thus packet-byte provenance is verified, but this is not an
original-kernel port-set dequeue experiment or native namespace bridge.
[SS4,SS6]

## Collection producer-to-consumer contract

`CFDictionarySetValue` executes its original non-ObjC wrapper and calls the
declared BasicHash setter at0x1846dcd84. The model records the original name and
source arguments. Later `CFDictionaryGetValue` at0x1846ddc8c and
`CFBasicHashFindBucket` at0x1846ddd5c both execute original instructions. The
selected lower bucket finder at0x18489b724 reads the same model dictionary and
writes a32-byte bucket record to the original X8 output address. The original
getter selects its returned pointer using bucket fields+0x10/value and
+0x18/count. Neither the callback source nor a direct GetValue return is injected
at the run-loop lookup. [SS3,SS5,SS7]

This moves the modeling boundary to explicit lower collection operations. It
does not establish native BasicHash backing layout, hash/collision behavior,
allocation, reference counts or object signatures. CF type/PAC checks are
separate declared helper contracts; the run-loop type helper returns43. Backend
snapshots retain the complete dictionary, set membership, source-bag counts and
modeled port-set pairs, independently recomputed by the replayer. [SS2-SS4,SS7]

## Bounded controls and interpretation

| Case group | Cases | Original visits per case | Checked result |
| --- | ---: | ---: | --- |
| Schedule -> RPC502 | 2 | 3828 | Produced mapping reaches original application/libbsm; stop before pthread |
| Schedule -> RPC700 | 2 | 1226 | Produced mapping reaches unrecognized daemon route; null generic reply; original run-loop result4 |
| Member trap returns4 | 4 | 302 | Dictionary/source1/bag persist; no modeled member pair; stop at registration return |
| Add same source twice | 1 | 460 | Two type preflights, one mapping/member/bag insertion; duplicate set membership skips second insertion |
| Source-validity bit clear | 1 | 100 | Getter/type preflight executes; no mode/collection publication |
| Getter returns0 | 1 | 237 | Source1 set and source bag update; no dictionary entry or member insertion |

The member-error cases demonstrate returned-status handling, not native failure
reachability. The source1/dictionary updates precede the call; the later source
bag update still executes with returned W0=4. No rollback occurs in this tested
path. A registration API return is not a recovered semantic success flag: this
public API is void, and incidental X0 values are not promoted to business status.
No receive is attempted after the error, duplicate, invalid or zero-port controls.
[SS2-SS4,SS8]

The independently hashed local SDK
[CFRunLoop.h](/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/CoreFoundation.framework/Versions/A/Headers/CFRunLoop.h)
declares AddSource's void return at line85 and names result4
`kCFRunLoopRunHandledSource` at line39. This supplies primary API declaration
context; exact SDK-to-cache build correspondence is not established. The named
result still describes run-loop source handling rather than daemon RPC recognition.

The getter/type preflight precedes the source-validity test in the original
body. Duplicate scheduling repeats that preflight before discovering existing
membership. These ordering facts do not establish native callback reentrancy,
object invalidation or resource consequences. [SS2,SS4,SS7]

Prior stack execution changes unused receive-buffer bytes. In the ordinary
compositions,48 bytes at buffer offsets3008..3055 differ from the old padding
fixture because original registration wrappers used that stack range. The
received148 bytes and29 OOL bytes retain their exact oracles, with the known
voucher-header normalization. Complete final8192-byte user observations and all
private memory are independently replayed. Unused capacity is not message
payload; no outgoing disclosure is established. [SS5-SS7]

## Verification and reproduction

Four fresh kernel replays check10652 original visits; all11 new replays check
12113 visits,2698 reads /16293 bytes,1611 writes /11694 bytes,1029 complete CPU
frames and156 recomputed lower scheduling contracts. Total visits across the
two phases are22765. Final private memory covers
11*(1048576+2097152)=34603008 bytes (33 MiB). Sixteen explicit function-entry
handoffs are checked; four composed consumers retain the exact original
DoSource1/daemon/application instruction suffixes from the prior source-only
cases. Four altered-evidence controls are rejected: instruction word, member
trap result, lookup bucket value and final dictionary. [SS1-SS8]

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_source_scheduling.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_source_scheduling.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_source_scheduling.py
```

Run from the extracted directory with the pinned files and existing private
Unicorn/Capstone environment. Source, profiles and checks are generated;
validation requires `all_checks_pass=true`. Time/space are
O(image+source visits+RAM+journals), with linear streamed cache-file hashing.
The independent implementation shares the frozen loader and prior replayer;
it recomputes backend state and checks all model patches, instead of accepting
the saved final association as its input. [SS1,SS3,SS7]

## Bounded continuation

| Impact | Missing interface evidence | Discriminating next step |
| --- | --- | --- |
| High | Actual daemon-created CF source/object/mode epoch | Continue original creation and startup into AddSource; establish callback cache history and actual mode collection creation |
| High | Actual kernel port-set membership and receive dequeue | Recover source-produced port-set objects, insertion and set-based receiver path with matching task namespace; compare returned local name with the CF dictionary key |
| High | Successful recognized processing and reply correlation | Continue the original thread/environment/output route and correlate reply right/ID/payload with the kext receiver |
| Medium | Original CF hash/backing/ownership behavior | Replace BasicHash and mode/type helper contracts with original state construction and runtime implementations |
| Medium | Native member-error feasibility and recovery | Establish actual task/right/type prerequisites and any caller/runtime repair; local retained bookkeeping alone gives no native consequence |
| Low | Other scheduling epochs | Recover common-mode recursion, monitor creation, invalidation/removal and concurrent replacement with consistent source/object state |

## Scoped quality gates

QG1: Descriptive source, data-flow and ABI analysis requires no normative premise.

QG2: SS1-SS8 record assumptions, dependent results and falsification probes.

QG3: This increment covers source scheduling, collection producer/consumer flow,
Mach type/member wrappers, port-set identity boundaries and respective reports.
The broader interface goal remains incomplete and active.

QG4: Offsets/extents are bytes, names are u32, pointers are u64, exact visit and
memory totals reproduce, and no tick-to-time conversion is inferred.

QG5: CF bookkeeping, trap success, native membership, daemon recognition,
source-handled status and successful FairPlay output remain distinct. Historical
unused-buffer padding is not treated as a message-payload oracle.

QG6: Original source/nlists/fixups, nine cache hashes, four kernel producers,
ordered journals, complete memory/state and independent replay support the
bounded claims. Source pairing and native namespace epochs remain assumptions.

QG7: High/medium/low follow-ups identify remaining construction, namespace,
ownership and alternate scheduling evidence without claiming native effects.

[Preservation seal](triage_evidence/cf_source_scheduling_delivery.json),
[quality gates](triage_evidence/cf_source_scheduling_quality_gates.json) and
[current manifest](triage_evidence/interface_manifest.json) retain publication
provenance. The complete interface goal remains active.
