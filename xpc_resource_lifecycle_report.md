# XPC resource disposal, sent descriptors and transaction lifetime

The captured cache closes the selected successful-context disposal gap: request and reply dictionaries dispatch to different context offsets; packing moves voucher and transaction responsibility into the serializer; a status-zero sent event marks descriptors sent and clears remaining serializer resources. The prior unnamed flag helper is `__xpc_transaction_end`. Original dispose-table bindings and two reference-counter stages are recovered. These are conditional source contracts; native reference/right balance, Objective-C IMP lookup, concurrency, delivery and daemon-kext success remain unknown [XL1-XL7].

Evidence: [original source capture](triage_evidence/xpc_resource_lifecycle_source.json), [checks and lifetime models](triage_evidence/xpc_resource_lifecycle_checks.json), [reader](triage_evidence/recover_xpc_resource_lifecycle.py), [validator](triage_evidence/validate_xpc_resource_lifecycle.py), [preservation](triage_evidence/xpc_resource_lifecycle_delivery.json), and [quality gates](triage_evidence/xpc_resource_lifecycle_quality_gates.json). Cache UUID remains `2bd06591-e751-3e84-963f-b08dab6af23a`; daemon SHA-256 remains `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The [incoming producer](xpc_receive_context_report.md), [reply transport](xpc_reply_transport_report.md), and [daemon cleanup](daemon_xpc_reply_lifecycle_report.md) define inherited interfaces. Forty-six preceding cache ranges/19540 B and 21 daemon fragments/2172 B are freshly recaptured. No recovered code, native message or process-control request executes.

```text
request E owns context at +58
    | create_reply moves 24 B, clears E context
    v
reply R owns context at +60; E and R hold separate P references
    | pack consumes port name; moves voucher and transaction flag
    v
serializer S owns pending header / voucher / transaction responsibility
    | status 0                         | invalid destination
    v                                  v
mark descriptors sent             release without sent marker
clear voucher / end transaction    disposal requests message cleanup
    |                                  |
    +---------- later disposal --------+
          header destruction gated by sent marker
```

Offsets in the diagram are hexadecimal. Resource ownership means the selected source cleanup responsibility under the stated lifetime assumptions, not an observed native reference/right balance.

## Original dispose bindings and reference-count boundary

`-[OS_xpc_object dealloc]` is the original nlist identity of the body at `0x184b6ee44`. For a recognized non-tagged class C, its selected table address is:

```text
slot = 0x1e2418f70 + 2 * (C - 0x1ed891ab0) + 0x60
modifier = (slot & 0x0000ffffffffffff) | 0xa020000000000000
```

| Original type | Class pointer | Dispose slot | Exact original target |
|---|---|---|---|
| Base | `0x1ed891ab0` | `0x1e2418fd0` | `__xpc_base_dispose`, `0x184b6efe4` |
| Data | `0x1ed891d30` | `0x1e24194d0` | `__xpc_data_dispose`, `0x184b6f174` |
| Dictionary | `0x1ed891f60` | `0x1e2419930` | `__xpc_dictionary_dispose`, `0x184b6f3e8` |
| Serializer | `0x1ed8920a0` | `0x1e2419bb0` | `__xpc_serializer_dispose`, `0x184b7207c` |

Each slot is a verified cache-v5 chain member. Its encoded bits 34..49 match `0xa020`; the selected dealloc call loads the slot and calls with the source's slot/diversity modifier at `0x184b6ef38`. Hardware authentication is not executed. Tagged-object and class-fallback paths are captured without assigning them the ordinary dictionary/data semantics.

The selected `_xpc_retain`/`_xpc_release` class-range paths bind to `__os_object_retain` and `__os_object_release_without_xref_dispose`. This describes the canonical data/dictionary/serializer branch; connection objects have additional release cases. Allocation through `__os_object_alloc_realized` initializes both fields below to 1 after the class-instance allocation returns normally:

| Field | Original transition | Terminal condition |
|---|---|---|
| object+`0x0c`, u32 | External-reference retain/release | Release with old value 1 branches to internal release |
| object+`0x08`, u32 | Internal-reference release | Release with old value 1 branches to object disposal |
| Either field equal to `0x7fffffff` | Relevant primitive returns without its atomic update | Immortal/saturated sentinel for this source path |

Atomic updates return the old count. Nonpositive signed old counts take separate error branches; the store/update may precede that branch. Positive ordinary counts and valid object/atomic lifetime are prerequisites, not native observations. For example, insertion retain plus setter-temporary release can leave a data value referenced by its dictionary, but actual current counts are unknown.

`__os_object_dispose` at `0x1855148dc` performs an acquire load through object+8 and branches to selector stub `0x188009bf0`. That stub supplies X1=`0x1f4b86030`, whose bytes are `dealloc\0`, then branches to `0x188000800`. This establishes a dealloc-selector request. Native Objective-C method lookup, selected IMP, subclass behavior, final superclass dispatch and allocation retirement remain unproved; the named dealloc implementation above is not asserted to execute for every release.

## Dictionary, node, data and payload disposal

Dictionary disposal visits exactly seven bucket heads at object+`0x20` through +`0x50`. It saves node+0 before invoking the node helper, then advances using the saved next pointer. The mode-specific tail follows bucket traversal:

| Low mode bits | Source cleanup tail |
|---:|---|
| 0 or 3 | No received/reply context cleanup in this routine |
| 1, bit 3 clear | `__xpc_received_message_destroy(E+0x58)` |
| 1, bit 3 set | Release payload at E+`0x98`; dequeue/free auxiliary nodes from E+`0xf0`; then received-message cleanup |
| 2 | `__xpc_message_request_destroy(R+0x60, R+0x58)`; then release non-NULL R+`0x58` connection reference |

Received-message cleanup first destroys its 24 B request portion, then releases the associated connection at context+24. Thus E+`0x70` and R+`0x58` are separate references after reply creation retains P; clearing E's first 24 context bytes does not clear E+`0x70`.

Node helper `0x184b6f4e4` has an important type exception: kind 2 at node+`0x18` returns without unlinking, releasing its value or freeing the node. Other kinds unlink next/previous links, poison those two fields with all-one words, release value at +`0x10` and call free. Kind 3 additionally releases +`0x20`. Therefore bucket visitation does not imply every visited node is freed. Valid finite chains, writable links and correct ownership remain prerequisites. The lazy auxiliary path separately uses exact export `_OSAtomicDequeue`, releases node+8 and frees the popped node; no whole native queue/concurrency model is supplied.

Data disposal loads dispatch-data backing at object+`0x18` and tail-calls dispatch_release. The payload dealloc method conditionally releases backing at +8; for payload kind 1 with a non-NULL dispatch message at +`0x28`, it obtains the Mach header, calls mach_msg_destroy and releases the dispatch message before superclass dispatch. These are nested cleanup API requests, not proof that every underlying byte range or Mach right is retired.

## Serializer resource move, sent-event status and cleanup

The incoming producer and reply packer establish this specific resource correspondence:

| Resource | Request | Reply | Packed serializer | Cleanup operation |
|---|---|---|---|---|
| Reply name | E+`0x58`, low32 | R+`0x60`, low32 | Header destination field | Context deallocate before packing; header cleanup if still uncommitted |
| Voucher | E+`0x60` | R+`0x68` | S+`0x80` | `_os_release`, then zero S+`0x80` |
| Transaction responsibility | E+`0x68` bit 1 | R+`0x70` bit 1 | S+`0x9c` bit 4 | `__xpc_transaction_end`, then clear bit 4 |
| Connection | E+`0x70` | R+`0x58`, separately retained | Separate submission reference | Context/dictionary and submission releases have separate source sites |

Packing clears the consumed reply name, voucher field and transferred transaction flag in R. The serializer is installed as the dispatch message context by the previously captured packer. `__xpc_connection_handle_sent_event` obtains that context; when present, it passes P, dispatch message, serializer and raw u32 status to `__xpc_connection_release_message` at `0x184b77c5c`.

| Raw status | Selected source behavior |
|---|---|
| 0 | Call `__xpc_serializer_clear_sent_descriptors`, then release submission's P and serializer references |
| `0x10000003` | Release those references without clearing sent descriptors; SDK names this `MACH_SEND_INVALID_DEST` |
| Other statuses | Separate retained classification/error paths; no general normal cleanup result is assigned |

Clear-sent at `0x184b71e54` requires object+`0x10` bit 0 clear and S+`0x9c` bit 0 set. It conditionally clears S+`0x40` when flag bit 2 is set, sets flag bit 1, and tail-calls serializer cleanup. These prerequisites and status 0 are source conditions, not an observed native send result or peer-processing result.

Serializer disposal later loads its dispatch-message field S+`0x18`. With a message and sent bit 1 clear, it obtains the header, invokes a local-name/disposition cleanup helper and requests mach_msg_destroy; with sent bit 1 set it skips those operations. Both paths release the dispatch message and continue to serializer cleanup. A marked-sent header is therefore treated differently from an uncommitted header. The callback/queue epoch deciding this marker remains unknown natively.

Serializer cleanup at `0x184b71eb4` handles four distinct resources:

| Field | Conditional operation |
|---|---|
| S+`0x40`, callback | If non-NULL, require flags intersect `0x4c`; call with S+`0x20` base and S+`0x28` extent, then clear callback field |
| S+`0x50`, pointer array; count +`0x58` | Release eligible non-NULL/non-tagged entries, free array and clear array field |
| S+`0x80`, voucher | `_os_release`, then clear field |
| S+`0x9c` bit 4 | Transaction-end call, then clear bit |

The pointer-array count need not be zeroed for the next call to skip that branch: its pointer field is cleared. The normal voucher/transaction cleanup requests do not repeat on a second pass through the cleared fields. This is a source metadata/call-order property, not proof against concurrent mutation, aliases, duplicate ownership or invalid callbacks. The recognized callback-flag cases are not all assigned allocator semantics here.

For a valid declared lifecycle, the finite models distinguish four phases: request only; reply created but not yet packed; packed and uncommitted; packed and marked sent. They track context deallocate requests versus header destruction versus a sent marker separately. They do not equate those three events with identical native right effects. Request/reply P releases account for the creation retain only under the model's explicit ownership assumptions.

## Transaction counter and process-lifetime requests

Original nlists identify `__xpc_transaction_begin` at `0x184ba0a7c`, `__xpc_transaction_end` at `0x184ba0af0`, and their implementations at `0x184b885c8`/`0x184b88700`. The wrappers obtain the once-initialized context and lock context+`0xb0` around the implementation. Native once state, context identity and lock epoch remain unknown.

| Implementation | Counter at context+`0xac`, u32 | Relevant branch |
|---|---|---|
| Begin | Store old+1 modulo 2^32 | Unsigned carry takes error path; in the valid nonnegative domain, old=0 can request dirty=1 |
| End | Store old-1 modulo 2^32 | Signed old<=0 takes error path; old=1 can request dirty=0 |

The counter store precedes the noted branch in each implementation. The begin/end inverse proof is deliberately bounded to initial counts `0..0x7ffffffe`: the intermediate count is positive signed32, no begin carry occurs, and a matching normal end restores the original word. No all-u32 successful-counter claim is made.

The dirty requests additionally require context byte+`0xa8` equal to 1. They call `_getpid`, then exact `_proc_set_dirty` with W1=1 for the first active transaction and W1=0 for the last end. On the last-end path, after the dirty operation, context byte+`0xaa` equal to 1 selects exact `__exit` with W0=0. Other source branches include optional initialization/dispatch activity. This increment binds these process-control requests without issuing any of them or inferring native process termination/restart policy.

The incoming unpack wrapper calls transaction-begin for its selected request classes and sets context flag bit 1. The earlier context move, reply creation, packing and cleanup now identify where that responsibility travels and which normal paths request its end. Exceptions, concurrent requests, alternate transports and native resource balances retain separate scopes.

## Assumption register

| ID | Assumption and dependent findings | Stress test / falsification probe |
|---|---|---|
| XL1 | Pinned cache/daemon inputs define the selected source path. | Rehash used files/UUIDs; recapture all inherited cache/daemon spans and bindings. Native daemon/cache image pairing remains separate. |
| XL2 | Recognized class and table-selection prerequisites hold for the object epoch. | Verify four dispose slots, range pointers, original class/symbol identities and slot modifier; establish native class/IMP lookup and PAC separately. |
| XL3 | Object counts, links, fields and callbacks have valid owned lifetime. | Trace allocator/retain producers and all references; preserve old-count, sentinel and node-kind exceptions. Do not infer native safety or uniqueness from finite models. |
| XL4 | Context/serializer moves and clears occur in the declared normal lifecycle without concurrent mutation. | Check request/reply offsets, port extraction, voucher/flag handoff and second cleanup pass; recover alternate transport and exceptional predecessors separately. |
| XL5 | Sent-event status and serializer preconditions select the declared branch. | Check zero/invalid-destination classification, sent-bit update and cleanup suppression. Establish actual dispatch callback epoch/syscall result before native delivery claims. |
| XL6 | Transaction once-context/lock identity is stable and the bounded counter domain holds. | Recover context flags/count producers, use explicit overflow/nonpositive boundaries, and inspect native lock/concurrency state before global balancing or exit claims. |
| XL7 | API release/deallocate/destroy/dirty/exit requests are distinct from their native effects. | Establish actual references/rights, kernel result and process state before retirement, policy or daemon-kext success claims. |

## Bounded context, verification and quality gates

| Impact | Established observation | Remaining boundary |
|---|---|---|
| High | Context cleanup now joins request, reply and serializer voucher/transaction responsibility. | Actual resource/reference/right balance and concurrent epochs remain unknown. |
| High | Status-zero sent marking suppresses later message destruction and clears remaining serializer resources. | Native status, receiver processing and dispatch scheduling remain unknown. |
| High | Transaction transitions conditionally request dirty-state changes and last-end exit. | Once-context flags, native admission, process effects and restart behavior remain unknown. |
| Medium | Disposal uses exact class/table slots and two separate counter stages. | Native Objective-C lookup, subclass behavior and actual counts remain unknown. |
| Medium | Node kind 2 skips free; lazy auxiliary nodes follow a different pop/release/free path. | Full ownership/type producers and concurrent queue semantics remain unknown. |

Capture retains 24 complete compiler bodies, 1026 instructions/4104 B, twenty exact import bindings, four dispose-table bindings, two class-range pointers and one selector stub. Forty-six prior cache ranges/19540 B, 21 daemon fragments/2172 B and ten daemon call bindings match original bytes. `_OSAtomicDequeue` is bound by its original export; no compiler interval is invented where this reader has no function-start entry.

Checks pass 103 exact instruction assertions, eleven SDK assertions/one compilation, four unsatisfiable scalar queries, forty finite lifecycle cases, 1093 finite node-kind cases over representative kinds 0/2/3, eight counter boundaries, all 256 low-byte dictionary flag patterns and eight rejected evidence alterations. Models are conditional scalar/ownership ledgers and call counts; no recovered CPU path or malformed native fixture executes.

Recovery costs O(S+F+E+C) time/space for selected bytes S, function-start metadata F, export/nlist metadata E and traversed pointer chains C, plus streaming hashes over H source bytes. Verification adds O(I+M) for instructions I and finite model cases M. Compiler/solver costs are separate; each query has a 10 s timeout. For valid finite bucket/auxiliary chains, disposal issues O(k+a) local work for k visited bucket nodes and a popped auxiliary nodes; seven buckets are fixed. Deallocator internals, payload/descriptor destruction, concurrent progress and process-control effects are outside that bound. Sizes/offsets are B and widths/signedness are explicit.

QG1: Factual interface/lifetime analysis requires no normative premise.

QG2: XL1-XL7 state assumptions, dependent results and falsification probes.

QG3: Selected dictionary/node/data/payload disposal, dispose-table/refcount boundary, serializer sent/cleanup paths and transaction/process requests are covered. Full native interfaces and the broad goal remain active.

QG4: u32 counters/flags/status, u64 object fields/slot arithmetic, context offsets, seven bucket heads, sentinel values, signed comparisons and bounded transaction inverse are checked.

QG5: Canonical versus special class routes, node visitation versus freeing, metadata clearing versus native ownership, sent marker versus delivery, transaction arithmetic versus global balancing and process request versus native effect remain distinct.

QG6: Original bytes/compiler spans, cache chain-member pointers, export/nlist identities, selector bytes, fresh prior/daemon recaptures, SDK/tool hashes and retained proofs/models provide provenance.

QG7: Impact-labeled ownership/sent/process/counter/node observations are bounded above. No native authorization, complete reference/right retirement, successful exchange or full-goal completion is claimed.
