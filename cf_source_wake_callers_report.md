# CF source signaling, wake callers and daemon descriptor interfaces

The original `CFRunLoopSourceSignal` body marks a source using a first-nonzero
timestamp at source+0x58. Its selected body does not invoke the source's perform
callback, call `CFRunLoopWakeUp`, or send a Mach message. A separate named local
routine, `__CFRunLoopSourceWakeUpRunLoops`, copies the source's run-loop bag,
unlocks the source, then invokes a callback which tail-branches to
`CFRunLoopWakeUp`. These are distinct control and data contracts.

A complete direct B/BL scan of this CoreFoundation `__text` finds 26 wake sites
in 25 containing routines and seven calls to the source wake-all helper in five
file-descriptor callback routines. All five helper callers also contain original
calls to `CFRunLoopSourceSignal`. Neither queried spelling of the wake-all helper
is present in the captured export trie. This establishes concrete local caller
context without treating the helper as an exported API.

The daemon's raw chained import table contains five CFFileDescriptor interfaces,
plus AddSource and CFMachPortInvalidate, while the queried named wake/signal
imports are absent. The file-descriptor imports are a separate concrete lead;
their daemon callers, descriptor origin, effective callbacks and native use are
unknown. They are not equated with the five version-1 Mach service sources.

Ten original private CF executions and fresh downstream/prerequisite replays
check 27224 original instruction visits and 41 MiB of complete final private RAM.
Six deliberately altered evidence records are rejected. These results establish
bounded private behavior, not native daemon/kext IPC, scheduling, authentication,
CF collection semantics, object ownership, queue-full behavior or successful
FairPlay processing. The broader objective remains active.

## Original evidence and reproduction

[Source capture](triage_evidence/cf_source_wake_callers_source.json),
[private profiles](triage_evidence/cf_source_wake_callers_profiles.json),
[independent checks](triage_evidence/cf_source_wake_callers_checks.json),
[preservation seal](triage_evidence/cf_source_wake_callers_delivery.json) and
[quality gates](triage_evidence/cf_source_wake_callers_quality_gates.json) retain
exact original bytes, nlist records, caller locations, raw import records,
authenticated binds, all CPU/register frames, memory journals and complete final
private snapshots. The [probe](triage_evidence/probe_cf_source_wake_callers.py)
and [independent replay](triage_evidence/replay_cf_source_wake_callers.py) implement
the new contracts separately; the replay does not import the new probe.

Preferred addresses refer to the captured cache UUID
`2bd06591-e751-3e84-963f-b08dab6af23a`, CoreFoundation UUID
`7fe5392e-ff16-31e1-8552-3a45c6b68224`, and daemon thin arm64e UUID
`204741e9-b89f-32b4-9321-51f3975c7cac`, SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
The capture retains 88 complete cache routines plus 28 four-instruction import
stubs, totaling 9407 captured instructions. Nine cache files are freshly hashed.
The full scanned CF section is 2138924 B / 534731 four-byte words, starting at
`0x1846d86a0`; its complete digest is retained. No new IDA query or mutation is
needed because original reference bytes and prior contracts suffice.

Run from `/Users/___/dev/dylex/extracted`:

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_cf_source_wake_callers.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_cf_source_wake_callers.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_cf_source_wake_callers.py
```

## Assumption register

Static byte/table results depend on SC1 and the stated SC8 census boundaries.
Private execution-derived results depend on SC1-SC7. No inference of native
caller reachability or object identity is made from those results.

| ID | Explicit premise or boundary | Stress test / falsification probe |
| --- | --- | --- |
| SC1 | Pinned original daemon/cache/kernel bytes identify the analyzed images; native image pairing is unknown. | Rehash originals/nine cache files, rebuild capture, independently decode branch census and raw imports; reject changed SHA/UUID. |
| SC2 | Source/helper entries are declared calls after original run-loop creation and AddSource; the waiting call uses a separate declared stack. Native caller and thread history are unknown. | Preserve full CPU/RAM at each handoff, compare prior kernel constructor/member returns with freshly replayed downstream prefix; recover actual daemon call sites separately. |
| SC3 | The selected source has declared runtime type46, validity bit3 and bag association; source construction/lifecycle remains modeled. | Test invalid bit, missing and empty bags; retain original type checks, loads and source field snapshots. |
| SC4 | Lower bag count/elements/allocation/capacity/add/bucket contracts supply declared private hash state. Native hash allocation, copying, retain/release and mutation are unknown. | Execute original Copy/Apply/BasicHashApply/block bodies; verify all lower arguments/patches, NULL allocation, duplicate multiplicity, guard and complete RAM; reject altered element bytes. |
| SC5 | Clock values100 and200 are opaque declared ticks; mutex effects are modeled and CAS runs without competing writers. | Execute original CASAL, check timestamp100 after both signals; invalid source makes no clock call. No conversion to seconds or concurrency claim. |
| SC6 | PAC instructions are interpreted logically; runtime keys and hardware enforcement are unknown. | Check exact original instructions, pointer targets and full CPU/RAM; an altered callback target frame is rejected. |
| SC7 | SVC return values are declared per-call inputs. Matching downstream kernel execution is a component comparison, not a live exception crossing. | Check exact24-byte header/eight packed slots and fresh downstream scalar send/set receive; reject altered status; retain timeout as supplied, not native queue-full proof. |
| SC8 | Census covers only direct B/BL in this CF text and a bounded ADRP/ADD callback pattern; raw import absence covers only this daemon's named import table. | Independently disassemble the entire section with skip-data enabled, check every target/site, inspect full caller bodies/export trie; indirect, data, dynamic-resolution and other-image references remain unknown. |

## Layer and event relationships [SC1-SC8]

```text
fairplayd original named imports
  +-- CFMachPort registration -> version-1 source -> service port/set receive
  |      original requested callback 0x100425f78
  |
  +-- five CFFileDescriptor imports
         daemon call sites / descriptor / effective callbacks: unknown

captured CF file-descriptor callback bodies
  -> CFRunLoopSourceSignal(source)             [timestamp only in selected body]
  -> local source WakeUpRunLoops(source)
       lock -> valid/bag tests -> CFBagCreateCopy -> unlock
       -> CFBagApplyFunction(copy, callback, NULL)
          -> CFBasicHashApply -> original bag block, per multiplicity
             -> callback 0x1847b7c9c -> CFRunLoopWakeUp(runloop)
                -> suppression test -> original mach_msg/libkernel/SVC
                   SVC status is intercepted in these private cases

fresh separate downstream component replay
  original scalar Mach -47 -> copy-send -> queue -> wake/service set receives
```

The first branch follows the [daemon registration report](daemon_registration_report.md)
and [source scheduling report](cf_source_scheduling_report.md). The lower kernel
comparison follows the [wake ingress report](kernel_wake_send_ingress_report.md).
No new execution composes an actual file-descriptor daemon caller, descriptor
notification, or five-service callback into this generic helper path.

## Exact selected routine and field contracts [SC1-SC7]

| Original address | Exact symbol / role |
| --- | --- |
| `0x184751bcc` | `_CFRunLoopSourceSignal`; type46 check, mutex, valid-bit test, trace calls and first-nonzero timestamp |
| `0x184751c90` | `CASAL X8,X0,[X22]`, X22=source+0x58, expected0 and new clock value |
| `0x1847b79c8` | `__CFRunLoopSourceWakeUpRunLoops`; named local helper, not found in queried export spellings |
| `0x1847b7a18` | Original call of `_CFBagCreateCopy` with allocator and source+0x60 bag |
| `0x1847b7a24` | Original source-unlock call before bag callbacks |
| `0x1847b7a44` | Original `_CFBagApplyFunction(copy,0x1847b7c9c,0)` call |
| `0x1847b7aa0` | `_CFBagCreateCopy`; original count/elements/copy/add/type wrapper, lower storage/hash effects declared |
| `0x184779b58` | `_CFBagApplyFunction`; builds original stack block with callback/context captures |
| `0x18471c4a0` | `_CFBasicHashApply`; iterates nonempty buckets, calls original block |
| `0x184794ee0` | `___CFBagApplyFunction_block_invoke`; repeats callback for bucket multiplicity |
| `0x184794f10` | Original authenticated indirect callback call; value -> X0, context -> X1 |
| `0x1847b7c9c` | `___CFRunLoopSourceWakeUpLoop`; one original B to `0x18473ae10` |
| `0x18473ae10` | `_CFRunLoopWakeUp`; original run-loop suppression and wake emission |
| `0x18473af30` | Outgoing original `mach_msg` call when wake is admitted |
| `0x180547c1c` | Original libkernel SVC, intercepted; signed Mach selector -47 |

| Source offset | Width / meaning established here |
| --- | --- |
| `+0x08` | 8 B state load; bit3 admits selected source operations |
| `+0x10` | Mutex-address argument; native mutex storage/effects not executed |
| `+0x58` | 8 B first nonzero signal timestamp, set with original CASAL |
| `+0x60` | 8 B run-loop bag reference |
| `+0x68` | 8 B version field; inherited Mach-source fixture value1 |
| `+0x70` | 8 B info value passed to trace calls in Signal |
| `+0xb0` | Authenticated pointer passed as trace data in Signal; not invoked by that body |

The inherited private global at `0x1ed891742` changes original byte0 to2.
Signal therefore skips the conditional initializer and diagnostic helper; their
native initialization/diagnostic effects are not covered. Allocator, stack-guard
and stack-probe cells retain their recorded runtime overlays. The captured
copy-debug byte at `0x1eb15a9e8` remains its original0, so the debug-description
branch is not taken. These environmental premises are included in SC2-SC4.

Neither selected source operation tests the version field at+0x68. Executing
them with the inherited version-1 fixture does not identify a native descriptor
source or establish its construction/version.

The helper does not test the source+0x58 timestamp before applying the bag.
Thus helper-without-signal can wake a run loop while its timestamp remains0.
Signaling twice preserves100 when the clock contract returns100 then200. These
are separate operations; neither event count nor pending work is inferred from
the nonzero timestamp. A void API's leftover X0 is not assigned status meaning.

The original bag-copy wrapper uses a stack value array for counts below257;
the tested counts are0,1,2. A 64-byte guarded private hash record supplies the
selected backend fields, including occupied-bucket count at+0x14 and index1 at
+0x1a. Original Copy sets bit0x40 at copy+8 and assigns type4 through a declared
runtime boundary. Original Apply creates a stack block whose captures+0x20 and
+0x28 hold wake callback and NULL context. The bucket contract supplies value at
+0x10 and multiplicity at+0x18; original block instructions perform repetition.
These record extents and header fields are private fixture contracts, not a
complete native CF object ABI or an allocator-size claim.

## Complete direct wake branch census [SC1,SC8]

Every row is a direct original B/BL to `0x18473ae10` in the scanned section.
Original containing intervals and exact nlist names are retained; a compiler
function interval is not assumed to recover every human-written routine.

| Site | Kind | Containing start | Exact nlist name |
| --- | --- | --- | --- |
| `0x18471be28` | BL | `0x18471bbd0` | `_CFRunLoopAddTimer` |
| `0x18477f50c` | BL | `0x18477ebac` | `___CFSocketManager` |
| `0x18477fd84` | BL | `0x18477ebac` | `___CFSocketManager` |
| `0x184780f6c` | BL | `0x184780a40` | `___CFSocketPerformV0` |
| `0x1847842e8` | B | `0x184784250` | `_CFRunLoopStop` |
| `0x184795370` | BL | `0x1847950fc` | `_CFRunLoopTimerSetNextFireDate` |
| `0x1847a8d14` | BL | `0x1847a8984` | `_CFSocketInvalidate` |
| `0x1847a92cc` | BL | `0x1847a91e0` | `__wakeUpRunLoop` |
| `0x1847b6078` | B | `0x1847b6074` | `___CFFileDescriptorSchedule` |
| `0x1847b7c9c` | B | `0x1847b7c9c` | `___CFRunLoopSourceWakeUpLoop` |
| `0x1847dcfdc` | BL | `0x1847dc510` | `___CFPasteboardHandleMessageFromDaemon` |
| `0x1847ed4b8` | B | `0x1847ed418` | `__CFRunLoopStopMode` |
| `0x18481e5c4` | BL | `0x18481e380` | `___CFPasteboardCreateUniquePromiseFileURL_block_invoke` |
| `0x18481e76c` | BL | `0x18481e614` | `___CFPasteboardCreateUniquePromiseFileURL_block_invoke_2` |
| `0x1848215c0` | BL | `0x184821448` | `___CFPasteboardResolvePromisedData_block_invoke` |
| `0x1848217a4` | BL | `0x18482172c` | `___CFPasteboardResolvePromisedData_block_invoke.237` |
| `0x184821804` | BL | `0x1848217d0` | `___CFPasteboardResolveAllPromisedData_block_invoke` |
| `0x184829b90` | BL | `0x184829a80` | `____onqueue_CFPasteboardShowIndirectApprovalDialogIfNecessaryForPasteboard_block_invoke` |
| `0x184829e28` | BL | `0x184829d24` | `____onqueue_CFPasteboardShowApprovalDialogIfNecessaryForPasteboard_block_invoke` |
| `0x18482a460` | BL | `0x18482a29c` | `____onqueue_CFPasteboardRequestDataFromDaemon_block_invoke.737` |
| `0x184832bbc` | B | `0x184832b6c` | `_____CFRunLoopRun_block_invoke` |
| `0x184842534` | BL | `0x184842338` | `_boundPairRead` |
| `0x184842968` | BL | `0x1848428f4` | `__wakeRunLoops` |
| `0x184842acc` | BL | `0x184842a44` | `_performUnlockParamsAndDealloc` |
| `0x184842da8` | BL | `0x184842c54` | `_boundPairWrite` |
| `0x1848c300c` | BL | `0x1848c2e6c` | `___65-[_CFXPreferences _setupNewDaemonConnection:invalidationHandler:]_block_invoke_2` |

## Source-helper callers and daemon imports [SC1,SC8]

| Direct source-helper call / tail branch | Containing routine | Exact nlist name |
| --- | --- | --- |
| `0x1847b6008` | `0x1847b5f10` | `___CFFileDescriptorCreateRunLoopSource_block_invoke` |
| `0x1847b6028` | `0x1847b5f10` | `___CFFileDescriptorCreateRunLoopSource_block_invoke` |
| `0x1847b6204` | `0x1847b6190` | `___CFFileDescriptorEnableCallBacks_block_invoke` |
| `0x1847b6290` | `0x1847b6190` | `___CFFileDescriptorEnableCallBacks_block_invoke` |
| `0x1847b79b8` | `0x1847b7954` | `___CFFileDescriptorCreate_block_invoke_2` |
| `0x1847c946c` | `0x1847c9404` | `____CFFileDescriptorInduceFakeReadCallBack_block_invoke` |
| `0x18480fa80` | `0x18480fa1c` | `___CFFileDescriptorCreate_block_invoke_4` |

The seven original Signal call sites in those five caller bodies are
`0x1847b5ffc`, `0x1847b601c`, `0x1847b61f8`, `0x1847b626c`,
`0x1847b7994`, `0x1847c9448`, and `0x18480fa5c`. Captured full bodies retain
conditional flags and shared tails; adjacency is not substituted for path
feasibility. A bounded ADRP/ADD scan finds the callback materialization at
`0x1847b7a2c`/`0x1847b7a30`; original PACIZA, argument moves and the Apply call
are retained. This is not an exhaustive census of indirect/data references.

Raw `LC_DYLD_CHAINED_FIXUPS` imports format2 contains243 records. Selected
original bind slots use pointer format12, library ordinal5/CoreFoundation,
IA authentication and zero table/pointer addends:

| Imported interface | Original slot | Original word | Diversity / address-diverse |
| --- | --- | --- | --- |
| `_CFFileDescriptorGetNativeDescriptor` | `0x10109fea0` | `0xc00880970000008f` | `0x8097` / 0 |
| `_CFMachPortInvalidate` | `0x1010a0188` | `0xc008029000000080` | `0x0290` / 0 |
| `_CFFileDescriptorEnableCallBacks` | `0x1010a0798` | `0xc008e0470000005d` | `0xe047` / 0 |
| `_CFFileDescriptorInvalidate` | `0x1010a0a88` | `0xc008e0470000004d` | `0xe047` / 0 |
| `_CFRunLoopAddSource` | `0x1010a0c08` | `0xc0081a3c00000045` | `0x1a3c` / 0 |
| `_CFFileDescriptorCreateRunLoopSource` | `0x1010a1448` | `0xc00863f900000020` | `0x63f9` / 0 |
| `_CFFileDescriptorCreate` | `0x1010b1c30` | `0xc0090000000000ac` | `0x0000` / 1 |

The queried names `_CFRunLoopWakeUp`, `_CFRunLoopSourceSignal`,
`_CFRunLoopRemoveSource`, `_CFRunLoopSourceInvalidate` and
`__CFRunLoopSourceWakeUpRunLoops` have no raw named import record. This does not
exclude framework-internal calls, runtime resolution, encrypted names, inherited
callbacks or other indirect use. Import presence does not prove execution.

## Private cases and independent validation [SC1-SC7]

| Case | Original visits | Timestamp, opaque ticks | Original wake callbacks | Intercepted SVC visits |
| --- | ---: | ---: | ---: | ---: |
| signal_only | 1366 | 100 | 0 | 0 |
| signal_twice | 1424 | 100 | 0 | 0 |
| signal_then_wake | 1863 | 100 | 1 | 1 |
| helper_without_signal | 1805 | 0 | 1 | 1 |
| suppressed | 1466 | 100 | 1 | 0 |
| invalid_source | 1359 | 0 | 0 | 0 |
| missing_bag | 1390 | 100 | 0 | 0 |
| empty_bag | 1561 | 100 | 0 | 0 |
| copy_null | 1467 | 100 | 0 | 0 |
| duplicate_bag | 2135 | 100 | 2 | 2 |

The duplicate case supplies statuses0 then`0x10000004`; original callbacks and
sends occur twice. It does not establish native queue saturation, coalescing,
concurrent signaling or the feasibility of those supplied statuses. The
suppressed case reaches the original wake callback once, but the original
run-loop gate prevents a send. Missing/empty/invalid/copy-NULL cases remain
distinct, including whether signaling still writes a timestamp.

The private source path produces the same24-byte copy-send header and seven
non-pointer trap slots as the separately replayed downstream scalar producer:
`<6I>(0x13,24,0x807,0,0,0)` and eight-slot form
`[header,0x400000011,0x1800000013,0x807,0,0,0,0]`.
The header pointer varies with the actual original nested stack frame. Name
`0x807` is private fixture-local; it is not a historical RAX port-name claim.

| Fresh positive replay | Original visits | Complete final private memory checked |
| --- | ---: | ---: |
| Ten source/bag/wake cases | 15836 | 30 MiB |
| One downstream original kernel scalar ingress/set receive | 10384 | 3 MiB |
| One timer-zone startup | 170 | 1 MiB |
| Three fixed-zone prerequisites | 618 | 3 MiB |
| Four receiver-loan prerequisites | 216 | 4 MiB |
| Total | 27224 | 41 MiB = 42991616 B |

All original visits are matched to source bytes. Replay independently recomputes
full GPR/SP/NZCV/SIMD frames, memory read/write journals, entry hashes and patches,
collection states, lower-call clobbers, complete final snapshots, callback
multiplicity, timestamp and SVC contracts. Six separate alterations are rejected:
signal instruction, timestamp snapshot, bag element patch, source entry premise,
callback target frame and SVC status. Negative-control visits are excluded from
positive totals. Capturing88 routines is distinct from executing every routine.

The census runs in O(T + E log N) time for T text words, E matched edges and N
function starts, plus input hashing and captured-body decoding. Its retained
state is O(E + C), where C is captured code/pages/metadata. Probe/replay use
linear interval searches. With H full-memory hash/handoff operations, the general
bound is O(V*F + I + (H+1)*R + J) time and O(I + R + J) space for V visits, F
captured routine intervals, mapped image bytes I, private RAM R and retained
journals J, plus input hashing. The scripts' simpler linear-memory bound fixes
H to these bounded case budgets. These are algorithm bounds, not native timing
claims.

## Bounded context and discriminating next work

The [historical ZUT trace](zut_trace_report.md) independently records five
check-ins and an unsuccessful FairPlayIOKit user-client open. It contains no
observed selector26/RPC502/700 transaction. This increment does not add a native
trace, convert that failure into success, or identify a live port owner.

| Impact | Further discriminating evidence / explicit boundary |
| --- | --- |
| High | Resolve fairplayd callers of the five original CFFileDescriptor slots, then recover descriptor creation, requested callback/context, source version/mode and return/lifetime paths. This can distinguish a shutdown/environment source from FairPlay service traffic without assuming either. |
| High | Connect actual daemon/framework caller provenance to the wake port separately from version-1 CFMachPort delivery. Recover indirect callback/block creation and effective object history; import absence cannot close that question. |
| High | Continue the existing daemon/kext transaction at the unresolved application/environment boundaries and correlate an actual service request/reply with user-client selector and deeper kernel facilities. Successful transaction and native identity remain unknown. |
| Medium | Recover original CFFileDescriptor dispatch/source producers and source invalidation/removal; check when bag membership, copied references and callback re-enablement change. These are separate from the modeled lower hash backend. |
| Medium | Recover the CFRunLoopRun wake block at `0x184832b6c` (direct wake tail at `0x184832bbc`) and its block captures/registration, distinguishing deadline-driven wake from file-descriptor notifications. |
| Low | Extend direct-reference census to other cache images and data/authenticated pointer tables; quantify the expanded coverage rather than treating this one-text census as whole-system completeness. |

QG1: Scope contains descriptive binary/interface analysis; no normative judgment
is required.
QG2: SC1-SC8 state dependencies, stress tests and falsification boundaries.
QG3: This increment covers routine roles, incoming caller context, outgoing send
location, named daemon interfaces, field/ABI contracts, control/data/environment
boundaries, retained artifacts and discriminating next work. The full goal is
explicitly incomplete.
QG4: Byte extents, instruction counts, sums and41 MiB conversion are reproducible;
clock ticks are opaque, with no unsupported time conversion.
QG5: Signal, wake callback, SVC, kernel delivery and native caller identity are
kept distinct; NULL/empty/invalid/duplicate/suppressed edges and imported-versus-
executed evidence are explicit. No conflicting claim is promoted to native proof.
QG6: Claims use original bytes/nlist/export/import records, fresh capture,
independent original execution and retained earlier registration/trace evidence.
QG7: High/medium/low bounded extensions identify concrete missing evidence and
their architectural effect. All gates pass for this increment only.
