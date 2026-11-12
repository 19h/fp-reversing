# CoreFP network-registry reader and lazy six-byte getter

Original CoreFP routine 0x8754 enumerates `IONetworkController` matches, obtains each node's parent in the `IOService` plane and requests its `IOMACAddress` property. It copies six bytes from each nonnull property into image+0x1d443c0. Getter 0x86c0 initializes this cache through a global `dispatch_once` Block and copies it only when unsigned low32(capacity) >= 6 and image+0x1d25200 is zero. Cache bytes describe the last successful property read; status describes the last processed iteration. A later failure can preserve earlier bytes while making the getter return zero. These are original-byte contracts under declared external API models. Actual registry contents, native Mach rights, incoming callers and daemon/kext linkage remain unknown.

## Evidence and assumption register

The [producer](triage_evidence/recover_corefp_network_identity.py), [checks](triage_evidence/corefp_network_identity_checks.json), [independent auditor](triage_evidence/audit_corefp_network_identity.py), [audit receipt](triage_evidence/corefp_network_identity_audit.json) and [publication verifier](triage_evidence/verify_corefp_network_identity_publication.py) retain this increment. Logical JSON links resolve to compressed `.json.zst` artifacts. The [preceding selector and optional-input report](fpsd1201_key_routes_report.md) remains a separate interface frontier.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| NI1 | The pinned original image, compiler bounds and format12 rows identify the source. | Check universal/slice SHA-256, complete function bytes, all selected stubs and original fixups. Substituting an installed image invalidates the claim. |
| NI2 | CF/IOKit values, allocation results, handle outputs and return codes are explicit fixtures. | Independently reconstruct initial RAM and API effects; vary allocation/query/parent/property failures and enumeration order. Native registry and endpoint identity require separate observations. |
| NI3 | Nonnull property fixtures represent CFData containing at least 6 B. | Verify exact X0..X3 and copy extent. The complete block contains no CF type/length query; a different native property representation is outside this model. |
| NI4 | `dispatch_once` is a sequential callback model that writes the done word after normal callback return. | Check original Block invocation target, callback entry/return and three same-instance repeats. Native concurrency, memory ordering and interrupted callbacks remain untested. |
| NI5 | Authenticated branches use original decoded slots and normalized targets. | Check every original IA/address-diversity row, reaching slot modifier and complete CPU frame. Native PAC acceptance remains unknown. |
| NI6 | Output is a valid, disjoint writable fixture with an 8 B diagnostic window. | Check the exact 6 B write footprint and two preserved poison bytes; vary low32 capacity, including nonzero high32. Null, overlapping and native object lifetimes are outside the fixture. |
| NI7 | Finite empty/one/two-node profiles support tested loop behavior; the compact recurrence generalizes only the retained source transitions. | Independently predict API/release order and final cache/status. Larger enumeration and concurrent registry mutation need separate checks. |
| NI8 | The clobber fixture varies X1..X17 and NZCV at modeled returns while preserving the remaining context. | Replay its full CPU/RAM journal. It does not constitute a complete calling-convention preservation proof. |
| NI9 | Current SDK declarations/layouts aid ABI interpretation, not historical implementation identity. | Compile arm64e pointer, CFIndex, CFRange and IOKit handle assertions; retain header hashes and primary-reference hashes. Version-pairing with the original image remains unknown. |
| NI10 | Caller reachability and downstream identity use are unestablished. | Recover incoming code/data references and consumers before connecting these six bytes to request1201, a protected parent, or a daemon/kext transaction. |

Universal SHA-256: `68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f`. Arm64e slice SHA-256: `8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`. Addresses below are relative to preferred image base zero. Original source retained and independently checked totals 784 B: getter 148 B, Block invoke 440 B, dispatch thunk 20 B and eleven complete 16 B authenticated stubs. This increment uses original file evidence; it does not claim a fresh live-IDB check.

## Control and data flow [NI1-NI10]

```text
getter 0x86c0(output, capacity)
  |
  +-- predicate != UINT64_MAX --> thunk 0x15d1580 --> dispatch_once
  |                                                  |
  |                      global Block invoke 0x8754 <-+
  |                          |
  |                          +-- match IONetworkController
  |                          +-- optional IOPropertyMatch dictionary
  |                          |       IOPrimaryInterface = true
  |                          +-- query iterator
  |                          +-- zero six-byte cache on query success
  |                          +-- for each node
  |                          |     parent in IOService plane
  |                          |     parent.IOMACAddress -> six-byte cache
  |                          +-- final iteration status -> global status
  |
  +-- low32(capacity) >= 6 AND status == 0
          true: cache -> output[0..5], return 1
          false: preserve output, return 0
```

| Original location | Exact recovered role | Source/effect location |
| --- | --- | --- |
| 0x86c0..0x8753 | Complete getter; boolean return in X0 | Warm capacity/status gate 0x86d0..0x86e0; cold continuation gate 0x8738..0x8748 |
| 0x8754..0x890b | Complete registry-reading Block invoke | Enumeration and cache/status stores below |
| 0x15d1580..0x15d1593 | Loads predicate and global Block, branches to dispatch_once stub | X0=image+0x1d443c8, X1=image+0x1c80028 |
| 0x1d443c0 | Six-byte cache; original backing zero | Clear at 0x8820 and 0x8824; API destination at 0x88b8 |
| 0x1d443c8 | Eight-byte once predicate; original backing zero | Getter tests addition of one for zero; done value UINT64_MAX |
| 0x1d25200 | u32 status; original value 5 | Query result stored at 0x880c; iteration result at 0x88e0 |
| 0x1c80028 | 32 B global Block literal | Flags 0x50000000, reserved zero, invoke cell +0x10 -> 0x8754 |
| 0x1c80008 | Block descriptor | Reserved zero, size 32 B; signature `v8@?0` |
| 0x1d1c1e8 / 0x1d1c208 / 0x1d1c228 | CFString objects | `IOPrimaryInterface` / `IOPropertyMatch` / `IOMACAddress` |

The Block's flags encode global and signature fields, consistent with the [LLVM Apple Block ABI](https://clang.llvm.org/docs/Block-ABI-Apple.html). Its original isa bind is `_NSConcreteGlobalBlock`; invoke is an IA authenticated rebase with address diversity. The complete thunk supplies the predicate and literal directly. The callback is a lazy initializer; invocation at image startup is not established. Apple's [libdispatch once implementation](https://raw.githubusercontent.com/apple-oss-distributions/libdispatch/main/src/once.c) supports callback-then-completion interpretation, while the retained sequential model does not reproduce native synchronization.

## Architectural API boundary and handle directions [NI2-NI5,NI9]

| Call site | API / outgoing arguments | Incoming result / source use |
| --- | --- | --- |
| 0x8780 | IOServiceMatching("IONetworkController") | Matching dictionary M, or null |
| 0x87b0 | CFDictionaryCreateMutable(default, 0, type-key callbacks, type-value callbacks) | Nested dictionary F, or null |
| 0x87d0 | CFDictionarySetValue(F, "IOPrimaryInterface", true) | No source-used result |
| 0x87e4 | CFDictionarySetValue(M, "IOPropertyMatch", F) | No source-used result |
| 0x87ec | CFRelease(F) | No source-used result |
| 0x8804 | IOServiceGetMatchingServices(mainPort, M, &iterator) | W0 status; u32 iterator at stack+8 |
| 0x882c / 0x886c | IOIteratorNext(iterator) | u32 node handle, or zero at exhaustion |
| 0x8884 | IORegistryEntryGetParentEntry(node, "IOService", &parent) | W0 status; u32 parent handle on success |
| 0x88a0 | IORegistryEntryCreateCFProperty(parent, "IOMACAddress", default, 0) | CF property pointer, or null |
| 0x88b8 | CFDataGetBytes(data, CFRange{0,6}, cache) | Six modeled bytes written into cache |
| 0x88c0 | CFRelease(data) | No source-used result |
| 0x885c / 0x8864 / 0x88ec | IOObjectRelease(parent / node / iterator) | Returned status ignored by this source |

`mainPort` is loaded through `_kIOMainPortDefault`; the fixture supplies zero. The [Apple IOKitUser header](https://raw.githubusercontent.com/apple-oss-distributions/IOKitUser/main/IOKitLib.h) declares this as the default communication main-port argument. It describes matching-dictionary consumption and caller release responsibilities for iterators, parent entries and CF properties. The source's release calls are established; native ownership and implementation-side consumption are not independently executed here.

The exact match class is `IONetworkController`, followed by a parent query in the `IOService` plane. No evidence in this increment establishes the returned parent's native class, presence of its `IOMACAddress`, or compatibility across operating-system versions. A familiar alternative class hierarchy cannot be substituted for the observed string and parent operation.

The arm64e compiler check establishes 8 B pointers and signed CFIndex, 16 B CFRange with fields at +0/+8, and 4 B `mach_port_t`, `io_object_t` and `io_iterator_t`. Original 0x88b8 reaches X0=data, X1=0, X2=6 and X3=cache, consistent with the verified CFDataGetBytes prototype and split CFRange argument. Header hashes, exact compiler stdin, exit code and primary-source body hashes are in the receipt. No compiler output artifact is emitted.

| Import stub | Import name | Original pointer slot |
| --- | --- | --- |
| 0x15d15f4 | _CFDataGetBytes | 0x1d1c478 |
| 0x15d1614 | _CFDictionaryCreateMutable | 0x1d1c488 |
| 0x15d1634 | _CFDictionarySetValue | 0x1d1c498 |
| 0x15d1694 | _CFRelease | 0x1d1c4c8 |
| 0x15d16d4 | _IOIteratorNext | 0x1d1c2e8 |
| 0x15d16e4 | _IOObjectRelease | 0x1d1c2f0 |
| 0x15d16f4 | _IORegistryEntryCreateCFProperty | 0x1d1c2f8 |
| 0x15d1704 | _IORegistryEntryGetParentEntry | 0x1d1c300 |
| 0x15d1714 | _IOServiceGetMatchingServices | 0x1d1c308 |
| 0x15d1724 | _IOServiceMatching | 0x1d1c310 |
| 0x15d18c4 | _dispatch_once | 0x1d1c3e0 |

Each stub's original authenticated pointer uses IA, diversity zero and address diversity one. Replay checks the source-produced slot address as the BRAA modifier, rather than replacing it with a zero modifier. Pointer authentication itself remains modeled.

These are API-level handle directions and call sites. No native Mach name, right disposition, message header or IOKitLib-internal message emission is recovered by these fixtures. The block performs no IOServiceOpen or FairPlayIOKit user-client method call. Its registry interface does not establish daemon/kext exchange or change the earlier [Mach-port evidence](mach_ports_report.md).

## Cache/status recurrence and edge cases [NI2-NI8]

```text
if matching dictionary is null: status = 5
else:
    try to add nested primary-interface filter
    status, iterator = query(matching dictionary)
    if status == 0:
        cache = six zero bytes
        status = 5
        for node in iterator:
            status, parent = get_parent(node, "IOService")
            if status == 0:
                property = get_property(parent, "IOMACAddress")
                status = 5
                if property is nonnull:
                    cache = first six bytes of property
                    status = 0
                release parent
            release node
    release iterator
```

The matching-null path also reaches the iterator-release site with its initialized zero handle. Failed nested-dictionary allocation continues with M without installing the nested filter. Query failure preserves the prior six-byte cache. Query success clears it before enumeration. A property success overwrites all six bytes; no successful iteration short-circuits enumeration. Error results from the delivered release-error fixture do not change the source's final status.

| Delivered case | Final cache | Status | Getter result for capacity 6 |
| --- | --- | --- | --- |
| Query success, empty iterator | Zero bytes | 5 | 0, output untouched |
| A then B, both valid | B | 0 | 1, copies B |
| A valid then missing property | A | 5 | 0, output untouched |
| A valid then parent error | A | 0xe00002c7 | 0, output untouched |
| Missing/parent error then B valid | B | 0 | 1, copies B |
| Matching dictionary null | Initial diagnostic cache | 5 | 0, output untouched |
| Query error | Initial diagnostic cache | 0xe00002c0 | 0, output untouched |
| Nested filter allocation null, valid A | A | 0 | 1, copies A; query still runs |

A=`020000000001` and B=`020000000002` are fictional test data. No hardware identity is observed. Getter capacity uses only W1: 0x100000006 succeeds when status is zero; 0x100000005 fails. It loads 4+2 B, stores the high 2 B at output+4 and then the low 4 B at output. Exactly two diagnostic trailing bytes remain unchanged.

The cold path invokes initialization before capacity admission. Thus capacity 5 can initialize the cache while returning zero. A same-instance second call with capacity 6 copies the cache without another API call. Under NI4, a failed callback also marks once complete, and a second call does not retry. Warm profiles with the done word execute no modeled API call, including rejected lengths and nonzero status.

Target enumeration takes O(n) time and O(1) explicit scratch/cache space for n nodes, excluding external library allocations. Producer and auditor conservatively use O(C*(B+F+V+J+R)) time/space for C cases, original image B, fixups F, visits V, journals J and retained RAM R. Each case is bounded at 5000 original visits; SMT, network reads and compiler checks have separate 30 s, 20 s and 30 s timeouts respectively.

## Independent validation

The auditor imports frozen replay infrastructure but does not import this increment's producer. It independently reconstructs original-backed initial RAM, asserts all 27 initial CPU frames, replays every retained original instruction and data access, validates complete API/PAC frames and effects, and compares final touched pages. A separate compact semantic oracle predicts every call/release sequence, cache/status and all 30 getter returns.

| Check | Verified quantity |
| --- | --- |
| Profiles | 27: 18 cold, 9 warm; three cold same-instance repeat profiles |
| Original visits / reads / writes | 3547 / 804 / 361 |
| Authenticated branch models / external and control models | 266 / 287 |
| Independently checked initial / final RAM | 548864 B / 548864 B |
| Full initial CPU frames / getter returns | 27 / 30 |
| Original source checked | 784 B |
| Exact instructions / UNSAT obligations | 14 / 3 |
| arm64e ABI syntax/layout compile | Exit 0; no output artifact |

The three UNSAT results prove the u64 done-word identity, low32 capacity/status predicate and split-copy byte equivalence. They do not prove external API behavior. No native target, API, Mach IPC or database mutation executes in this increment.

## Bounded continuation and quality gates

| Impact | Remaining question | Discriminating next evidence |
| --- | --- | --- |
| High | Where is getter 0x86c0 called and where do its six bytes flow? | Original code/data reference recovery and caller argument/consumer traces; do not infer identity binding from the property name. |
| High | Does the actual matched node's parent provide the requested data? | Version-pinned registry topology and property type/extent observations, separately from private replay. |
| High | Who initializes the preceding optional-input globals? | Reaching writers for image+0x1d44409 and image+0x1d32e18. The cache/predicate stores here are distinct and do not resolve that frontier. |
| Medium | Which native endpoints and rights implement these registry calls? | Matched IOKitLib implementation and native message/right observations at those library boundaries. |
| Medium | Does concurrent or interrupted once execution alter observed availability? | Version-matched libdispatch ordering and native concurrent behavior; sequential callback fixtures cannot decide it. |
| Low | How do longer enumerations and cleanup failures behave? | Additional original-byte loop profiles and external-implementation checks with retained provenance. |

**QG1** passes for factual technical content. **QG2** passes with NI1-NI10 and falsification probes. **QG3** passes for this registry/cache increment; the full investigation remains active. **QG4** passes with explicit byte widths, u32/u64 predicates, reproducible counts and bounded complexity. **QG5** passes with last-success data versus last-iteration status, cold/warm ordering and native unknowns separated. **QG6** passes with original-byte/fixup hashes, independent replay, SDK checks and linked primary sources. **QG7** passes with the impact-ranked continuation table. This is partial progress toward the cross-layer interface goal.
