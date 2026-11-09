# Receive-right name reuse and service guard restoration

The original kernel has a conditional mechanism connecting launchd's retained endpoint name to its notification69 return path. Generic right copyout first searches the receiving IPC space for the same port object; receive publication can reuse that entry. For the selected service class/state, publication requires the chosen name to equal a saved name and reloads a saved64-bit context while setting guard/strict bits. The context is held in a separate service-label record, surviving clears of the live port context. This resolves the selected static restoration mechanism behind launchd's later guard assertion. Actual native registration, name identity, metadata admission, delivery, guard state and right balance remain unknown. [Original source](triage_evidence/receive_name_guard_source.json), [checks](triage_evidence/receive_name_guard_checks.json).

The [notification69 report](port_destroyed_return_report.md) established the producer, launchd receiver and assertion call but left the lower restoration mechanism open. This report extends that analysis and the [service factory](launchd_service_endpoint_report.md), [namespace](kernel_namespace_report.md) and [reply namespace](kernel_reply_namespace_report.md) reports. The last two include separately bounded earlier private executions; none are newly executed or promoted to native evidence here.

## Pinned source and scope

Launchd universal SHA-256 is `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`; slice UUIDs are `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71` and `62af2b7d-327e-334a-a1d7-83777efc3c12`. Kernel collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. Library UUID, exact exports/nlist, original fixups, SDK and inspection-tool hashes are captured. Private function names below are analytical roles; original absent nlist entries remain absent.

The capture contains36 complete compiler-bounded bodies,4186 instructions and16744 B: ten launchd,21 kernel and five cache bodies. Ten selected launchd words use LLVM decoding. Both launchd slices are inspected independently; no x1 hardware/ISA/PAC equivalence follows. No recovered target, emulation, namespace operation, guard API, IPC, port destruction or IDB mutation executes. SDK compilation, static decoding and scalar checks execute.

```text
construction: name N, context C
   +-> live port flags/context
   +-> label { saved_context=C, saved_name=N }

launchd activation -> unguard -> live context=0; label retained
receive right elsewhere -> qualified destruction -> state4; live context=0
kernel copyin -> link to notification destination -> state6; label retained
descriptor copyout
   -> existing entry lookup by same port object, or entry allocation
   -> selected service/state6 branch
       -> receiver metadata prerequisites
       -> selected_name == label.saved_name
       -> live guard+strict bits, live context=label.saved_context
   -> receiver name/space and RECEIVE entry publication
   -> transferred name returned to launchd
launchd -> strict guard assertion against saved endpoint context C
```

This is a conditional static sequence [NG1-NG6], not a demonstrated native round trip. The existing namespace entry and the label are separate objects; sharing a numeric name in separate tasks is insufficient identity evidence.

## Kernel routine correspondence

| Analytical role | Original start | Selected contract |
|---|---|---|
| Port construction | `0xfffffe000bce00b8` | Saves name/context in applicable label |
| Guard installation | `0xfffffe000bce0624` | Live context+guard/strict flags |
| Unguard core | `0xfffffe000bce0894` | Context comparison then live clear |
| Port destruction | `0xfffffe000bccdbb4` | Qualified notification path retains label, clears live context, selects state4 |
| Kernel-form message copyin | `0xfffffe000bcc6b10` | MOVE_RECEIVE handling and destination link |
| Kernel right copyin | `0xfffffe000bcc9718` | Selected states3/4 accepted on MOVE_RECEIVE branch |
| Link/circularity traversal | `0xfffffe000bcc08ec` | Calls destination/state setter on selected admitted branch |
| Destination/state setter | `0xfffffe000bcccf0c` | States3/4 become5/6, with metadata pointer retained |
| Descriptor copyout | `0xfffffe000bcc5564` | Plain port descriptor calls generic right copyout |
| Generic right copyout | `0xfffffe000bcc9c1c` | Reuse/allocation then receive publication |
| State snapshot/locking | `0xfffffe000bccc258` | Returns state word and authenticated metadata pointer |
| Entry reuse selector | `0xfffffe000bcd308c` | Owner/name fast path or reverse object lookup |
| Reverse object lookup | `0xfffffe000bcbdf9c` | Exact object comparison, entry/name output |
| Existing entry lookup | `0xfffffe000bcbbf50` | Index, extent, rights and generation checks |
| Entry reservation | `0xfffffe000bcbc0f0` | Separate fallback allocation path |
| Receive publication | `0xfffffe000bcd5e24` | Conditional service guard restore and namespace mutation |
| Thread owner-context resolver | `0xfffffe000bd7e9c4` | Supplies object for receiver metadata prerequisite; full structure meaning unassigned |
| Guard attribute assertion core | `0xfffffe000bce0f44` | Flavor/count, guard+strict and context checks |

Complete bodies, selected sites, original raw policy rows and API registry bindings are retained in the [capture](triage_evidence/receive_name_guard_source.json). This is not exhaustive recovery of all lower lock, allocator, owner-context, hash insertion/removal, task-policy or asynchronous lifetime effects.

## Separate saved and live guard records

| Object / field | Width, B unless stated | Original producer / consumer |
|---|---|---|
| Launchd endpoint+0x70 | 8 | Send-object helper stores construction context; activation/reset load it |
| Kernel live port+0x78 | 8 | Guard install, unguard, destruction and conditional restoration |
| Kernel live port+0x10 bits10/11 | 1 bit each | Guard-present/strict operations; assert core tests both |
| Kernel service label+8 | 8 | Constructor saves context; receive publication reloads it |
| Kernel service label+0x10 | 4 | Constructor saves name; receive publication compares chosen name |
| Kernel port+8 metadata pointer | 8, authenticated | Preserved across selected receiver-state changes; interpreted as label in qualified service branch |

In the applicable type2/type4 constructor branch, `0xfffffe000bce0500` stores the newly allocated u32 name at label+0x10 and `0xfffffe000bce0504` stores the caller's context at label+8. The lower guard helper stores that context at live port+0x78, sets bit10 and sets bit11 from its strict input. Launchd stores its original context at endpoint+0x70 at `0x10005cc44` / `0x10005bc14`. The [factory report](launchd_service_endpoint_report.md) establishes its counter/options provenance [NG1].

The unguard core resolves the receive name, requires bit10 and compares live context against the supplied64-bit value. Its selected success branch clears port+0x78 and masks both bits10/11 off. It does not clear the label's saved fields in that body. The notification-producing destruction suffix also clears the live context and both bits, while retaining the previously authenticated metadata pointer in port+8. Thus a zero live context does not imply deletion of the separate saved service context [NG1,NG3].

## From destruction state4 to message-linked state6

The selected destruction suffix writes receiver-state4 into the low three bits of byte1 of the port state word and republishes the preserved metadata pointer. Kernel right copyin accepts states3/4 for this MOVE_RECEIVE branch and unlocks without clearing that preserved pointer. The plain-port descriptor branch in kernel message copyin calls the link traversal for MOVE_RECEIVE when the destination receiver differs from its kernel-space comparator. Circularity/locking and other link prerequisites remain significant; link success is not assumed merely from descriptor disposition16 [NG3,NG4].

The traversal calls `0xfffffe000bcccf0c` at `0xfffffe000bcc0b78`. The setter requires old state3 or4, acquires a destination object hold, writes an authenticated destination pointer at port+0x48, and changes3->5 or4->6 while preserving unrelated state bits and the metadata pointer. The full32-bit state-word formula is proved under old-state3/4. Reference/lock instructions are captured, but complete native balance and locking behavior are not proved.

On ordinary descriptor copyout, the original code obtains disposition from the descriptor, passes raw mode2 and a NULL optional guarded-descriptor argument to generic right copyout at `0xfffffe000bcc57d4`. Therefore the plain notification path does not depend on receiving an explicit guarded-port descriptor containing a new context. Receive publication's separate service-label branch can restore the saved context even with that optional argument NULL [NG1,NG4].

## Conditional name reuse in the receiving namespace

Generic right copyout calls the reuse helper before fallback entry reservation for MOVE_RECEIVE. Send-once has a separate bypass. The reuse helper's owner/name fast path applies when receiver state is1/2 and its authenticated receiver-space pointer matches the supplied space. Otherwise it calls reverse lookup with that space and the exact port-object pointer. The notification return state6 uses the reverse-lookup branch [NG2].

Reverse lookup decodes the namespace table and walks its object hash. A candidate's authenticated object pointer must compare equal to the supplied pointer. The success branch returns both the entry pointer and the canonical u32 name:

```text
name = u32((entry_index << 8) | (entry_bits >> 24) | 3)
```

The name's generation bits agree with the existing-entry helper's `(entry_bits & 0xfc000000) | 0x03000000` comparison against `name << 24`; a full32-bit proof verifies that relationship. Extent, entry rights, object validity, authentication, hash maintenance and unchanged generation remain separate prerequisites. A reverse-lookup match is not manufactured from the saved label name.

When reuse succeeds, generic copyout passes the returned name/entry to receive publication. Otherwise entry reservation supplies a potentially new name/entry. In receive publication, the captured suffix writes the chosen name into port+0x34, writes the receiver space into authenticated port+0x48 and ORs RECEIVE bit0x20000 into the existing entry flags. SDK constants independently match SEND0x10000/RECEIVE0x20000. The suffix includes reference/hash-maintenance operations for a preexisting send entry; it is not a native balance proof [NG2,NG3].

For the qualified service-state6 branch, a nonzero saved label name must equal that chosen name before restoration proceeds. A mismatch reaches a diagnostic path. Consequently the static successful restoration branch requires equality with the saved name; it does not prove that every native copyout finds the retained launchd send entry. The earlier setup's MAKE_SEND operation and this reuse mechanism fit a conditional same-name return contract [NG1,NG2].

## Conditional guard restoration and exact prerequisites

Receive publication's selected restore branch checks these facts in order:

1. The object's low-byte class is2 or4.
2. Its saved receiver-state low three bits equal6.
3. The thread owner-context resolver returns an object whose+0x608 pointer is nonzero and whose pointed byte+0x28 bit0 is set. The complete structure and feature-bit nomenclature remain unknown; this is not labeled an entitlement check.
4. The label's saved name at+0x10 is nonzero. A zero value skips this restoration branch.
5. The chosen namespace name equals that saved name.

The branch then ORs0xc00 into the live flags at `0xfffffe000bcd5f1c`/`...5f20` and copies label+8 to port+0x78 at `...5f24`/`...5f28`. Unrelated flags survive this OR. Later publication still has object-class/state/policy and lifetime prerequisites. Original policy rows2/4 have flag words0x3f8/0x2fc; no complete symbolic policy taxonomy is assigned [NG3,NG4].

The original owner-context resolver performs its own range/metadata/backpointer checks before returning a pointer from its validated record. Those bytes and its complete body are captured. Its native inputs, metadata epoch and the+0x608 feature producer are not established. The restore mechanism is therefore conditional on this receiver-specific environmental state, not unconditional for every recipient of a receive right.

## Unguard and assertion IPC/ABI contracts

| Interface / emission site | Contract |
|---|---|
| Launchd activation unguard | arm64e `0x100046ef4`; x1 `0x1000461b8`; task/name/saved64-bit context |
| Public unguard wrapper | `0x180565fb4`; trap first, fallback only on0x10000003 |
| Cached unguard trap | `0x180547bdc`; selector-42, SVC0x80 |
| Original trap42 | Pointer slot `0xfffffe0007efb408`; handler `0xfffffe000bcdbf4c`, tail-call to unguard core |
| Cached unguard MIG implementation | `0x18056e2e0`; RPC3234, simple request44 B/user and52 B/internal; status reply36 B/user |
| Original RPC3234 stub | `0xfffffe000bd875ac`; exact internal52 B, no complex bit; calls unguard core |
| Launchd strict assertion helper | `0x10000cf4c` / `0x10000cda8`; flavor8, two natural_t words, saved context |
| Public assertion export | `0x180566034`; tail branch to original MIG implementation `0x18056ee44` |
| Cached assertion MIG implementation | RPC3242; count<=17, variable inline info, status reply36 B/user |
| Original RPC3242 stub | `0xfffffe000bd86e7c`; checks extent/count then calls core `0xfffffe000bce0f44` |

The user assertion request layout is header24 B, NDR8 B, name4 B, flavor4 B, count4 B, then `count*4 B` inline info. Thus its actual extent is `44+4*count B`, maximum112 B. The internal kernel extent is `52+4*count B`, maximum120 B. Launchd count2 yields52/60 B user/internal. A full u32 proof verifies the original stub's exact size/count predicate, including the bounded count17. These are storage-layout calculations, not generated or emitted request packets.

The assertion core accepts flavor8 and requires count>=2. With valid receive-name lookup, its success branch requires live bit10, live bit11 and equality between live64-bit context and the first64 bits of supplied info. It neither reinstalls those guard bits nor changes the live context on the success branch. Missing guard or mismatch uses separate diagnostic paths; actual native exception/termination behavior is not tested. Launchd's helper reaches BRK1 on a nonzero API status. The caller's ignored unguard status and other diagnostic/continuation paths remain as documented in the notification/handoff reports [NG4,NG5].

The guard restoration and the later assertion are different operations at different layers: the kernel service copyout branch writes the saved state; launchd subsequently asks the kernel to check it. A scalar proof verifies that restoration's0xc00 OR satisfies the two guard-bit tests and that context equality remains necessary. It does not prove runtime reachability or uninterrupted state preservation.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Static stress test / falsification probe | Remaining boundary |
|---|---|---|---|
| NG1 | One service label and context link construction, handoff and return | Check distinct live/saved fields, constructor stores, unguard/destruction clears and preserved pointer through states4/6 | Actual object/label epoch, label retirement/replacement and native context history unknown |
| NG2 | Retained send entry remains in launchd's reverse map with unchanged generation | Follow exact object comparison, name reconstruction, existing-entry checks and fallback allocation; independently prove generation formula | Actual reverse-map membership/name identity unknown; a shared numeric name alone is insufficient |
| NG3 | Port, space, entry and label remain valid through locking/publication | Preserve complete bodies and reference/lock/hash operations; distinguish state transition, entry reuse and later publication | Native locks, interleavings, growth, ownership and full lower helper effects unknown |
| NG4 | Receiver metadata and object-policy gates admit the selected service branch | Preserve raw+0x608/+0x28 checks, class/state gates, saved-name comparison and original policy rows | Metadata producer/feature name, runtime recipient and admission unknown |
| NG5 | Restored context/flags survive to launchd's assertion | Verify writer/checker field identity and exact predicate; distinguish API result and local fail-stop helper | Native timing, other writers, exception delivery and guard state unknown |
| NG6 | Captured versions, decoders and SDK apply to the investigated environment | Pin hashes/UUIDs, independently decode both slices, compare4894 fixups and compile24 SDK assertions | Runtime slice, cross-version equivalence and hardware PAC/ISA unknown |

## Bounded continuation context

| Impact | Remaining interface question | Concrete next anchor |
|---|---|---|
| High | Which receiver context admits automatic restoration? | Trace the owner-context object's+0x608 pointer and byte+0x28 bit0 producer; resolve its structural/type nomenclature |
| High | Does the retained send entry persist through the actual service handoff? | Join MAKE_SEND insertion, reverse-map publication/removal and label lifetime for the same object; keep native identity separate |
| High | What job action follows the returned endpoint? | Follow launchd callback+0x90/reason1 and the asynchronous bit4 branch through readiness/relaunch state |
| Medium | Which port/space holds are consumed on each path? | Trace reference/hash-maintenance callees and separate successful reuse, allocation, cancellation and label retirement |
| Medium | How do flags interact with generic guarded descriptors? | Keep the NULL optional-argument plain notification path distinct from the separate supplied guard-info branch |
| Low | Which additional service classes use these records? | Extend raw policy/class mapping while preserving type2/type4 evidence boundaries |

## Validation and quality gates

Source recapture matches the capture. Checks pass119 selected instruction assertions,24 SDK assertions in one arm64 compilation, four full-domain scalar queries,384 finite guard/context formula inputs and six rejected evidence alterations. Both slices'4894 fixups independently match dyld_info. Complete contiguous bytes and decodes cover all4186 instructions; ten LLVM-only words remain explicit. [Recovery](triage_evidence/recover_receive_name_guard.py), [validator](triage_evidence/validate_receive_name_guard.py), [delivery](triage_evidence/receive_name_guard_delivery.json), [quality gates](triage_evidence/receive_name_guard_quality_gates.json).

Recovery is O(B+F+I) time/space for source bytes B, fixups F and selected instructions I. Reverse-map lookup is O(k) in its probe-chain length k; its hash/table shape and native population are separate. Entry-name generation and guard predicates are O(1) time/space. Four fixed-width solver queries have explicitly stated scalar domains; no general solver complexity bound or target-execution proof is claimed.

QG1: Descriptive binary interface analysis; no normative premise required.

QG2: NG1-NG6 register dependent claims, falsification probes and remaining unknowns.

QG3: Selected saved/live context flow, receiver-state transitions, namespace name reuse, IPC locations and exact assertion ABI are reported; the full goal remains active.

QG4: Names/flags/counts are32 bit, context/pointers64 bit; extents are B and all user/internal size formulas are explicit. SDK and solver checks match those domains.

QG5: Conditional restoration is distinct from unconditional return; namespace identity, label lifetime, metadata admission, generic guarded descriptors, assertion and actual runtime state remain separate.

QG6: Pinned original binaries, actual exports/nlist/fixups, installed primary SDK headers, original-byte recapture and checked instructions provide provenance. No unverified private symbol name is asserted.

QG7: Continuation anchors have bounded scope and impact labels. Native sender/receiver identity, ownership and successful FairPlay processing remain unknown.
