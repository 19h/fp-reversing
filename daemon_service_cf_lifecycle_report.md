# Original daemon service registration through CF source1 invalidation

The original first-service check-in helper now creates the actual CFMachPort
object and version-1 source used by the later signal callback in the same private
epoch. It registers that source in the actual constructed loop/default mode and
stores the object in header+0x18. The original descriptor callback subsequently
passes that stored object to original CFMachPortInvalidate. Original source1
removal deletes its dictionary/set associations and reaches the original
mach_port_extract_member wrapper and trap entry. The callback then invalidates
the descriptor/source0, stops/wakes the loop and returns to original CF.

This replaces the opaque first-service reference in the earlier
[daemon/descriptor bridge](daemon_cf_descriptor_bridge_report.md) with an
originally constructed, registered and stored object. Typed helper entry,
bootstrap results, raw runtime/collection/retention/lock/Mach results and logical
PAC remain explicit premises. No native startup, IPC, right retirement, reference
count, scheduler or successful FairPlay exchange is established. The broader
interface goal remains active.

## Primary evidence and reproduction

Retained evidence comprises [source, imports and original ranges](triage_evidence/daemon_service_cf_lifecycle_source.json),
[eight combined execution cases](triage_evidence/daemon_service_cf_lifecycle_profiles.json),
[semantic/ABI checks](triage_evidence/daemon_service_cf_lifecycle_checks.json),
[preservation seal](triage_evidence/daemon_service_cf_lifecycle_delivery.json),
and [quality gates](triage_evidence/daemon_service_cf_lifecycle_quality_gates.json).
The [probe](triage_evidence/probe_daemon_service_cf_lifecycle.py) extends the
frozen descriptor bridge. The [checker](triage_evidence/replay_daemon_service_cf_lifecycle.py)
performs fresh shared-engine repetition and separately written service identity,
state, output-byte, register and collection/member oracles. Repetition shares
the engine and lower models; it is not an independent emulator implementation.

Daemon thin-image SHA-256 remains
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
CF UUID is `7fe5392e-ff16-31e1-8552-3a45c6b68224`; cache UUID is
`2bd06591-e751-3e84-963f-b08dab6af23a`. The fresh capture checks 141 complete
cache routines and 29 original import stubs, totaling 13030 instructions, across
nine hashed cache files. Twelve daemon CF slots are logically bound to exact
captured exports. Eleven additional daemon registration windows and 13 inherited
daemon ranges are byte-checked; those windows are not 24 distinct executed
routines. Every executed daemon instruction is checked against the pinned image.
No new IDA query or database mutation was needed.

```sh
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_service_cf_lifecycle.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/probe_daemon_service_cf_lifecycle.py
env PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_service_cf_lifecycle.py
```

## Assumption register

Execution-derived conclusions depend on SR1-SR8 as applicable. Native facts
outside the stated bounds remain unknown.

| ID | Assumption / dependent conclusions | Stress or falsification probe |
| --- | --- | --- |
| SR1 | Pinned code, original fixups and logical CF export bindings identify the selected pairing. | Fresh recapture, nine file hashes, twelve bind/export pairs, original instruction checks and rejected binding alteration. Native loader choice and hardware PAC remain unknown. |
| SR2 | Original initializer, check-in helper and descriptor setup use explicit typed component entries; caller CPU joins retain one memory epoch. | Complete tracked entry/return frames, address-encoded record control, original publication and callback return. Whole-main and all-five-service reachability are not established. |
| SR3 | Bootstrap input name/status/output name are declared at the original API boundary. | Zero/nonzero status, high-bit returned name, output bytes and encoded helper status. Native service-manager transaction and name/right provenance remain unknown. |
| SR4 | Runtime creation, CF array/hash/retention and raw storage satisfy the selected models. | Actual original constructors, complete40/72-byte contexts, object/source identity, null object/source variants, guards and before/after model checks. Native reference counts and allocation/retirement remain unknown. |
| SR5 | Main/TSD registration, fork/once fields, locks and public run-loop lower contracts remain warm/private. | Original GetMain/public wrappers, actual loop/mode fields, stored pointers and tracked CPU/RAM. Native main-thread identity, initial registration and concurrency remain unknown. |
| SR6 | Mach type/insertion/extraction statuses drive explicit membership backend effects. | Successful/failed insert and failed extract, exact task/name/set arguments, original wrapper/trap prefix and retained control members. Modeled state is not a native namespace or kernel right-release proof. |
| SR7 | Descriptor readiness, event output, source0 scheduling, dispatch and wake SVC results retain inherited explicit contracts. | Signal15 versus other signal, actual callback without pointer substitution, original source0 removal and seven intercepted wake SVC visits. Native event feasibility and wake delivery remain unknown. |
| SR8 | Fresh repeat shares frozen loaders/lower models; new service contracts are checked separately. | Full repeat equality,157 recomputed lower contracts, SDK assertions and twelve rejected alterations. Service-message callback delivery, universal paths and a successful daemon/kext exchange remain unproved. |

## Original object and control-flow chain

```text
original initializer -> constructed CF loop
explicit original check-in helper entry, control 0x2e4c
  -> bootstrap_check_in("com.apple.unfreed") -> declared receive name
  -> original daemon wrapper -> actual CF CreateWithPort
  -> actual CF CreateRunLoopSource(version1, info=service object)
  -> original GetMain/AddSource(default)/Release(source)
  -> original store: header+0x18 = service object
original descriptor setup -> actual descriptor/source0 registration
original public CF RUN -> source0 dispatch -> original descriptor callback
  -> actual descriptor lookup/kevent/rearm
  -> signal15: load header+0x18 -> actual CFMachPortInvalidate
       -> actual SourceInvalidate / RemoveSource(version1)
       -> dictionary/set removal / original extract-member wrapper
  -> actual descriptor/source0 invalidation -> GetMain/Stop/wake
  -> original callback return to CF 0x1847b7e04 -> public cleanup
```

The service callback requested at 0x100425f78 is stored in the created CF object.
It is not called in these cases. The callback actually executed is the descriptor
callback 0x10044f23c; no incoming service message or application dispatch is
generated by this increment. Existing
[CF receive and daemon routing evidence](cf_receive_report.md) remains separate.

| Original daemon site | Observed operation |
| --- | --- |
| `0x10044011c` | Shared check-in helper entry with explicit control 0x2e4c |
| `0x10044038c` | bootstrap_check_in request and u32 output name |
| `0x100001fdc` | Original wrapper requests CF object with common callback and zero context |
| `0x10031733c` | Create the CF Mach-port run-loop source |
| `0x100315264` / `0x100315300` | GetMain / AddSource(default) |
| `0x10031534c` / `0x100315354` | Release local source reference / store CF object to destination |
| `0x1001f4d0c` | Signal route calls CFMachPortInvalidate using the stored first-service object |
| `0x1847b7e04` | Actual descriptor callback return into original CF |

The initializer, check-in and descriptor-setup component joins restore
declared caller frames. The descriptor callback returns through its original
incoming linkage, with no replacement CPU or service-pointer patch at return.
The callback-entry patch list is empty: the service pointer comes from the
earlier original store. These cases establish construction-to-callback object identity. Whole-main and
all-five-service reachability remain outside the bounded execution.

## Data, ABI and lifetime identities

The selected 40-byte helper record contains destination pointer+0, name pointer+8,
encoded status u32+16, reserved u64+24 and address-encoded control u32+32. Its
incoming control decodes as:

```text
(encoded_u32 + 0x316f29c1 * ((record_address & 0xffffffff) ^ 0x987eac8a)) & 0xffffffff
  = 0x2e4c
```

The retained [registration recovery](daemon_registration_report.md) supplies the
first-service name/destination pairing. Here that record is an explicit typed
input, not a replay of the five-service caller. The helper's status word is
0x6263fc55 on the selected successful chain and 0x6263578d on check-in/object/source
failure. A residual X0 is not promoted to that encoded record status.

| Location | Actual identity or value in successful registration |
| --- | --- |
| Header `0x1010c4cd8` +0x18 | Service object SOBJ=`0x65000e1000` |
| Header+0x50 | Separate descriptor FDO=`0x65000c0000` |
| Service object+0x14 | Declared u32 service name 0xe03, or high-bit variant0x80000e03 |
| Service object+0x28 | Cached service source SSRC=`0x65000e2000` |
| Service object+0x30 /+0x40 | Original common callback 0x100425f78 / null context info |
| Service source+0x68 /+0x70 | Version1 / SOBJ |
| Service source+0xa0 /+0xa8 | Original getPort 0x1847e8924 / Perform 0x184784050 |
| Mode source1 set and dictionary | SSRC and service-name -> SSRC association |
| Descriptor source0 info | FDO; separate source SRC=`0x65000a8000` |

The original daemon wrapper supplies all 40 context bytes as zero. Original CF
constructs the full 72-byte source1 context: version1, info=SOBJ, CFRetain,
CFRelease, description, equality, hash, getPort and Perform. Original source
construction stores those callbacks and info into SSRC. Public context widths
and callback offsets are SDK-checked; object offsets are image-specific private
layout observations. A raw CFMachPort allocation is 128 B and a raw source is 184 B
under the declared runtime contracts.

The bootstrap data binding has import addend0x7da61013. Original instructions
cancel that addend before dereference; the modeled bootstrap call sees declared
input name 0x1703. That fixture is distinct from timer 0x707. Bootstrap output name,
task-self0x103, set0x507 and root/timer/wake names0x607/0x707/0x807 are private
values/contracts, not observations of a live host namespace. The kernel-produced
control-facility contracts are inherited retained evidence; the entire kernel
constructor is not reexecuted in this increment.

## Source1 removal and the Mach boundary

Original CFMachPortInvalidate changes service state 0 through1 to2, removes the
object from its private CF registry and detaches its cached source. Original
SourceInvalidate clears source validity and detaches the run-loop bag. Original
RemoveSource obtains the stored service name, removes its dictionary entry,
requests membership extraction and removes SSRC from the source sets. The
attempt to remove it from source0 returns false; source1 removal returns true.
The descriptor/source0 removal later acts on SRC, not SSRC.

| Original location | Contract and evidence boundary |
| --- | --- |
| CF call `0x184779330` | Original CFDictionaryRemoveValue `0x18473094c` executes; lower hash storage remains modeled |
| CF call `0x184779348` | Original mach_port_extract_member request through stub `0x188085b70` |
| Stub chained cell `0x1e2103ab8` | Original authenticated chain/export resolves to `0x18054b360` |
| Library call `0x18054b380` | Original wrapper reaches trap entry `0x180547b04` with(task,name,set) |
| Trap prefix at `0x180547b04` | Static MOV X16,-23 / SVC0x80 / RET; return is supplied at entry before these instructions execute |

The initial handwritten -22 expectation was rejected by the original-byte
assertion and corrected to the captured -23 selector. The published validator
asserts the exact original prefix. New extraction SVC instructions are not
executed; the seven intercepted original SVC visits counted below are the
existing outgoing loop wake calls.

On failed modeled extraction, CF registry/dictionary/set removal still occurs,
while the membership backend retains the service member. Failed insertion can
likewise coexist with an otherwise published CF source association. These are
conditional status-propagation/state distinctions, not native leak, reachability
or ownership findings. Control members remain unchanged in every case.

New CreateWithPort objects keep receive/send ownership bits clear under the
runtime model, consistent with the [CF lifetime report](cf_mach_port_retirement_report.md).
No service right-deallocation call or original service destructor executes here.
After successful signal invalidation, header+0x18 still contains SOBJ, now with
state 2 and detached source. The source info still contains SOBJ after source
invalidity. Numeric stored references alone do not establish native lifetime or
a dangling access. Primitive CFRelease does not establish reference retirement.

## Finite cases and validation

The private CF registry starts empty. Effective callback identity therefore
matches the original request in these cases; native preexisting cache history
remains unknown. There are eight combined cases:

| Case | Original visits | Final service CF/source state | Final service member |
| --- | ---: | --- | --- |
| registered_signal15 |34525 | object 2; source invalid; associations removed | absent |
| registered_other_signal |27814 | object 0; source valid; associations retained | present |
| bootstrap_failure |32619 | no service object/source published | absent |
| source_creation_failure |33236 | constructed object invalidated during helper failure; no source published | absent |
| CF_object_failure |32795 | no service object/source published | absent |
| member_insert_failure |34525 | CF registration published, then removed on signal; insertion/extraction statuses4 | absent |
| member_extract_failure |34525 | object 2; source invalid; CF associations removed; extraction status5 | retained |
| high_service_name |34525 | same successful signal removal with u32 name 0x80000e03 | absent |

Successful registration status is established by the encoded record and original
publication, not by native delivery or membership success. The seven signal
cases use public void CFRunLoopRun; residual internal stopped result2 is not a
public return value. The other-signal case uses the specific-mode wrapper and
handled result4. All cases execute one original descriptor callback and return
to the same original CF continuation.

Fresh repetition checks 264564 original visits, 39088 ordered reads, 19283 ordered
writes/after-images and 16140 stored tracked-CPU-frame records. The frame count
includes repeated observations retained in different evidence lists; it is not
a count of unique CPU states. Independent service checks verify:

| Oracle | Count |
| --- | ---: |
| Successful object/source/dictionary identity chains |5 |
| Complete public 40-byte / source1 72-byte context records |13 |
| Original descriptor callbacks with stored service and CF return |8 |
| Final registry/dictionary/source0/source1/membership states |8 |
| Ordered service registration/removal sequences |8 |
| Recomputed lower state, output patches and tracked CPU contracts |157 |
| Original context-arena tails and service-object guards |8 |

Final checked private RAM is
8 * (3145728 + 2441216) B = 44695552 B. The first term is the CF arena/lower stack;
the second is the inherited daemon mutable regions. Service object/source/record
and guards lie within those regions. Selected global overlays and observations
are additional evidence, not a snapshot of all mutable shared-cache pages.
The original arena check verifies 100 records of 896 B, each with an untouched
zero-backed 876-byte prefix and original 20-byte tail, under the declared storage
fixture. It does not exercise populated context-record cleanup.

Six direct SDK headers are hashed and 20 arm64e compiler assertions pass. They
cover Mach-name width, public context sizes/offsets, helper/header analyst
layouts, event fields/constants, void invalidation and bootstrap/extract-member
API types. Selected header hashes do not pin the entire transitive SDK/toolchain.
Logical PAC, native exceptions and target scheduler state remain outside the
tracked private CPU model.

Twelve alterations are rejected: stored service identity, source1 Perform
context, cross-epoch info pointer, encoded registration status, callback pointer
substitution, dictionary retirement, failed-extract membership, lower CPU
contract, original CF return, object guard, ordered write after-image and CF
import target. Journal/CPU repetition shares the engine/lower models; separate
service oracles and fresh SDK/source checks add different evidence without
establishing native behavior.

Time is O(S + V*F + J + H*R) and space O(S + J + R), for source/capture bytes S,
visits V, fixed tracked-frame extent F, journal bytes J, case count H and RAM R.
Original registry scans are linear in registry count; native backend complexity
and contention remain outside that instruction-only bound. Publication adds a
full owned-artifact hash/link/JSON audit.

## Bounded continuation opportunities

| Impact | Remaining interface | Concrete next evidence |
| --- | --- | --- |
| High | Registered service source1 -> incoming request -> original common callback | Carry a checked original-kernel packet into this actual registered source/loop epoch; preserve numeric name, source info, message/trailer and callback identity through lookup and dispatch. |
| High | Actual kernel membership removal and right state | Extend from the original -23 trap entry into matching kernel namespace/member handlers with preserved task/name/set state; keep extraction distinct from deallocation. |
| High | Whole-main and five-service registration flow | Recover the caller gates and original record construction into this component, including the existing last-service-status behavior; avoid inferring all-service success from one helper. |
| High | Successful daemon/kext/deeper-facility transaction | Connect the retained user-client/RPC/application contracts to a successful source-pinned request/reply; the supplied ZUT trace still records failed open rather than that exchange. |
| Medium | Cache reuse, retention and destruction | Replace primitive runtime/hash/CFRelease boundaries and preserve reused callback/context/ownership across registration and shutdown. |
| Medium | Native failure and concurrency histories | Establish which insertion/extraction statuses and invalidation races occur natively before attributing retained members or lifetime effects. |
| Low | Populated records and additional service/source variants | Recover live 896-byte record producers and repeat the identity join for other named services and nondefault/common modes. |

## Quality gates

QG1: Pass for factual technical analysis; no normative conclusion is required.

QG2: Pass for this increment: SR1-SR8 state dependencies and falsification probes.

QG3: Pass for the bounded original first-service helper, CF object/source1
registration, stored callback reference, removal and membership-request chain.
The full interface goal is incomplete.

QG4: Pass: exact public/private byte extents, u32 names, encoded control/status,
SDK types, disjoint RAM arithmetic and algorithm bounds are reproducible.

QG5: Pass within scope: component joins, shared-engine repetition, service versus
descriptor callbacks, invalidity versus extraction versus retirement, failure
cases, fresh-cache premise and corrected -23 selector remain explicit.

QG6: Pass: pinned original daemon/cache bytes and fixups, fresh capture/hashes,
SDK compilation, complete repeat and independent service oracles are retained.
No native startup, namespace, lifetime, IPC or hardware PAC proof is claimed.

QG7: Pass: bounded high/medium/low continuation opportunities are listed above.
