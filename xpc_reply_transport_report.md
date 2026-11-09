# XPC reply context, copied data and Mach2 transport handoff

The captured cache implementation supplies the lower boundary missing from the [daemon reply report](daemon_xpc_reply_lifecycle_report.md): create_reply moves a 24 B context, packing consumes its 32-bit port-name field, and a nonzero extracted name selects remote disposition 18 (`MOVE_SEND_ONCE`) and message ID `0x20000000`. A conditional dispatch path reaches the original Mach2 wrapper and trap -47. The data setter explicitly copies the full size_t extent into newly requested storage before returning normally. These are static contracts for the pinned cache; actual daemon/cache pairing, port identity/right validity, allocation ownership, scheduling and delivery remain unknown [XT1-XT7].

Evidence: [original capture](triage_evidence/xpc_reply_transport_source.json), [instruction/SDK/scalar checks](triage_evidence/xpc_reply_transport_checks.json), [reader](triage_evidence/recover_xpc_reply_transport.py), [validator](triage_evidence/validate_xpc_reply_transport.py), [preservation](triage_evidence/xpc_reply_transport_delivery.json), and [quality gates](triage_evidence/xpc_reply_transport_quality_gates.json). Cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`; daemon SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Twenty-one preceding daemon fragments/2172 B and ten call bindings are freshly rechecked. No new IDA query, target execution/emulation or Mach request occurs.

```text
request E                       reply R
  context [E+58,E+70) --move24-->   [R+60,R+78)
  source cleared                 remote connection R+58 <- retain(E+70)
                                          |
daemon send(peer P,R)                      v
  -> extract u32 name, clear 4 B -> serializer / header
  -> enqueue(P, packed)          -> dispatch result wrapper
                                      | direct gates      | other
                                      v                   v
                              Mach2 vectors          queue/try-drain
                              wrapper -> trap -47    scheduling boundary
```

Offsets in this diagram are hexadecimal. E and R are dictionary objects, P is a connection object, and the extracted u32 is a task-relative Mach name. Their representations are distinct.

## Original implementation identities

Addresses are unslid in the captured cache. Names below come from its export trie and/or original nlist records; they are not inferred from a different source release.

| Routine | Address | Role in this path |
|---|---|---|
| `_xpc_dictionary_create_reply` | `0x184b80820` | Move request reply context and retain associated connection |
| `_xpc_dictionary_set_data` | `0x184b7447c` | Create copied data object, insert and release temporary reference |
| `_xpc_data_create` | `0x184b6e0fc` | Empty/small/VM storage paths and explicit full-width copy |
| `_xpc_data_create_with_dispatch_data` | `0x184b6e30c` | Retain dispatch data and store its extent |
| `__xpc_dictionary_insert` | `0x184b6d310` | Retain a non-NULL inserted value in the selected insertion path |
| `_xpc_connection_send_message` | `0x184b7901c` | Type checks, pack and enqueue; no public result value |
| `__xpc_connection_pack_message` | `0x184b77790` | Consume reply port, check connection correspondence and form header |
| `__xpc_dictionary_extract_reply_port` | `0x184b70cdc` | Read/clear u32 name subject to dictionary mode/context flag |
| `_xpc_dictionary_get_remote_connection` | `0x184b77864` | Mode-dependent connection field |
| `__xpc_serializer_pack` | `0x184b70d20` | Serialize fields, transfer another context word and initialize header |
| `__xpc_connection_enqueue` | `0x184b79150` | Select dispatch send wrapper and handle its result |
| `_dispatch_mach_send_with_result` | `0x18552ea5c` | Submit, distinguishing immediate status from pending reason 10 |
| `__dispatch_mach_send_msg` | `0x18552e844` | Direct reply gates or queue/try-drain submission |
| `__dispatch_mach_msg_send` | `0x185532504` | Reply-specific header preservation and Mach2 vector arguments |
| `__dispatch_mach_send_push_and_trydrain` | `0x185533200` | Separate queue, concurrency and scheduling frontier |
| `_mach_msg2_internal` | `0x18055a894` | Original raw-call and interruption-retry wrapper |
| `_mach_msg2_trap` compiler body | `0x180547c18` | X16=-47; SVC at `0x180547c1c`; RET |

All 24 captured compiler bodies decode completely: 2454 instructions/9816 B. Fourteen import stubs are resolved through verified cache-v5 chain membership to exact exports/original symbols. The two class pointer slots resolve to `__xpc_type_dictionary` and `__xpc_type_connection`. Capturing a complete body does not prove every input path or every internal callee's semantics.

## Reply-context move and port consumption

`create_reply` first checks dictionary type, `(u32[E+0x1c] & 3)==1`, and a nonzero **u64** at E+`0x58`. This predicate is not equivalent to a nonzero low32 port name. On the selected normal allocation path, it requests a 128 B dictionary object and sets its low mode bits to 2, preserving the other flag bits.

| Field | Request, mode 1 | Reply, mode 2 |
|---|---|---|
| Low mode bits | E+`0x1c` | R+`0x1c` |
| 24 B context | E+`0x58` | R+`0x60` |
| Associated connection pointer | E+`0x70` | R+`0x58` |
| Extracted u32 port name | E+`0x58` | R+`0x60` |
| Context flag byte | E+`0x68` | R+`0x70` |

Instructions `0x184b8089c..0x184b808b0` copy 16 B plus 8 B, then zero exactly the 24 source bytes. E+`0x70` lies outside that cleared range. If that connection pointer is non-NULL, the code retains it and stores the result in R+`0x58`. A numeric offset therefore changes meaning with dictionary mode: R+`0x70` is inside context, whereas E+`0x70` is the connection field. The remaining context fields are not all assigned semantic names here.

The extract helper accepts mode 1 or 2, selects the corresponding context offset, and tests bit 0 of context+`0x10`. If set, or if the mode is neither 1 nor 2, it returns zero without clearing a name. Otherwise `0x184b70d0c` loads W0 and `0x184b70d10` stores WZR: **four bytes** are cleared, independently of whether the loaded name is zero. No Mach syscall occurs in this helper. The field consumption is not itself kernel right retirement.

The packer calls extraction before retrieving the dictionary's associated connection. With a nonzero extracted name and non-NULL associated connection, that connection must equal its explicit P argument to stay on the normal branch; mismatch takes `0x184b77854`. A NULL associated connection does not trigger that comparison failure. The exact runtime P/name association remains unknown.

## Full-width copied data and retained value

The daemon supplies D and unsigned64 O to the setter at `0x100bd6a5c`. The cache setter passes them unchanged as `_xpc_data_create(D,O)`; neither X3 nor the copy length is truncated to W registers.

| O, in B | Selected implementation | Explicit copy call |
|---|---|---|
| 0 | Wrap captured dispatch-data-empty object; no source read on this path | None |
| 1 through 16384 inclusive | `_dispatch_data_create_alloc` requests backing storage; wrap/retain it | `0x184b6e218`, destination returned through stack cell, source D, extent O |
| Greater than 16384 | `_vm_allocate`, then dispatch-data wrapper with VM-deallocation destructor | `0x184b6e19c`, allocated destination, source D, extent O |

Both copy sites bind through stub `0x18806ca70` to original `__platform_memmove` at `0x18555cd60`. The large path uses page-rounded allocation arithmetic and the full O for copying. Extreme sizes in the boundary models classify this branch only; they do not establish successful allocation, nonoverflowing capacity, valid source extent or completion. For O>0 and D=NULL, the source takes a separate API-error path. The O=0 path does not require reading D.

The data wrapper stores the dispatch-data pointer at object+`0x18`, stores its reported length at +`0x28`, and calls dispatch_retain. The setter inserts the resulting XPC value through `__xpc_dictionary_set_value`/`__xpc_dictionary_insert`, then releases its temporary XPC reference. The selected non-NULL insertion retains the value at `0x184b6d524` before storing it in the dictionary entry at +`0x10`.

Thus the pinned successful normal path explicitly copies bytes before the daemon later frees D, and preserves a separate dictionary-owned object reference. This resolves the preceding report's implementation-copy gap **for this cache and these prerequisites**. It does not prove native image pairing, actual allocation identity, validity/lifetime of D during the copy, D/M distinctness, or correct output initialization by the shared core [XT1,XT3,XT5]. No native alias or malformed fixture is run.

## Mach header production and conditional destination

The daemon's send site is `0x100bb4d08`, passing saved peer P and R. The cache's public send calls its packer at `0x184b790a0` with third argument W2=0. In the packer this is the local/reply-name input W19, so it remains zero for this caller. W20 holds the extracted reply name, denoted p below.

| User header field | Offset, B | p nonzero | p zero |
|---|---:|---|---|
| Remote disposition, bits 0..4 | 0 | 18, `MOVE_SEND_ONCE` | 19, `COPY_SEND` |
| Local disposition, bits 8..12 | 0 | 0 | 0 |
| Serialized complex bit | 0 | Preserved | Preserved |
| msgh_remote_port | 8 | p | Initially 0; channel route may replace it |
| msgh_local_port | 12 | 0 | 0 |
| msgh_voucher_port, initial value | 16 | 0 | 0 |
| msgh_id | 20 | `0x20000000` | Initializer value `0x10000000` |

The original 16 B header initializer at `0x184bb3350` contains remote=0, local=0, voucher=0, ID=`0x10000000`. The serializer separately supplies size and complex/descriptor state. The packer overrides the reply ID at `0x184b77818`, merges the remote/local dispositions and writes both names at `0x184b77838`. Public SDK assertions establish the 24 B user header, offsets, 32-bit names and disposition constants.

The serializer also reads and clears the context's +8 u64 and stores it at serializer+`0x80`. It transfers context flag bit 1 into serializer byte+`0x9c` bit 4 and clears the source bit. The +8 word's full role and subsequent disposal are not newly proved. No context word is silently equated with a port name or trusted identity.

At enqueue, `(header byte[1] & 0x1f)==0` selects `_dispatch_mach_send_with_result` at call PC `0x184b79218`; a nonzero local disposition selects the async-reply variant at `0x184b791ec`. This caller's zero local disposition takes the former branch on normal serialization. The dispatch wrapper calls `__dispatch_mach_send_msg` at `0x18552ea8c`. It can report reason 10 when the lower submission remains pending; immediate results take a separate status/reason conversion. These internal results are not returned by the public void send API.

The lower dispatcher permits the direct reply path when remote disposition is 18, its recognized local reply-name field is zero, channel-context u32 at +`0x58` is zero, and connection u32 at +`0x50` bit 28 is clear. Otherwise it reaches queue/try-drain at `0x18552e9c8`. Native values of these state fields are unknown.

In `__dispatch_mach_msg_send`, remote disposition 18 branches around the ordinary-channel destination overwrite at `0x1855325f0`. Consequently its retained direct reply path uses p in the header, rather than deriving the destination from P's normal send-port cell. P still participates in correspondence checks, dispatch state and lifetime. This establishes why the public connection argument alone is insufficient to identify the reply destination.

## Conditional Mach2 emission ABI

For that direct path from this caller, submission flags are 1 plus either 0 or `0x40000`, according to captured TLS state. Their bit 1/2 tests stay clear. The reply path bypasses the ordinary voucher/auxiliary setup; two 24 B vector records are still constructed at SP+`0x60` and SP+`0x78`. The first references the serialized header and its u32 byte size, with zero receive address/capacity; the second references the initialized auxiliary scratch with zero send length and zero receive address/capacity.

| Register at call `0x18553287c` | Conditional value |
|---|---|
| X0 | Address of the two vector records |
| X1 | `0x0000000500000001` or `0x0000000500040001` |
| X2 low32 / high32 | Header bits / vector count 2 |
| X3 low32 / high32 | p / local name 0 |
| X4 low32 / high32 | Voucher name 0 / ID `0x20000000` |
| X5 | Descriptor count if complex, otherwise 0 |
| X6 | 0 |
| X7 | 0 |

Stub `0x18808c4f0` resolves to `_mach_msg2_internal` at `0x18055a894`. Its initial original call at `0x18055a8dc` reaches `0x180547c18`, which loads X16=-47 and issues SVC at **`0x180547c1c`**. The wrapper masks low option bits `0x440`; neither listed direct-path option contains those bits. Retained retry branches are covered separately by the [prior wrapper report](cf_wake_send_wrapper_report.md); this increment captures their original body without executing it.

The two vector records occupy 48 B. Their count is not the serialized message's byte size. A pointer is u64, each header port name is u32, and packed register pairs remain two distinct u32 fields. No actual p, right ownership, native trap crossing, admission, receiver invocation or successful exchange follows from these source contracts.

## Assumption register

| ID | Assumption and dependent findings | Stress test / falsification probe |
|---|---|---|
| XT1 | The pinned cache defines the inspected implementation; applying it to fairplayd requires separate native image pairing. | Rehash used cache files/UUIDs and original daemon calls; inspect actual process image identity before a native linkage claim. |
| XT2 | Dictionary type/mode/context and normal allocation/return prerequisites hold for the selected path. | Verify all guards, both mode-dependent layouts and 5120 mode/flag/name models; recover the incoming producer and runtime object state. |
| XT3 | D/O and allocations satisfy the copy APIs, and dependencies preserve their declared ABI/lifetimes. | Trace shared-core output writers, bounds, allocation failure/rounding and aliases; do not infer valid capacity from a branch classification. |
| XT4 | P and any associated connection satisfy correspondence and remain live through submission. | Check the packer's conditional equality branch and lower retain/state fields; establish the actual callback/queue epoch separately. |
| XT5 | Copy and dictionary retain observations apply to successful normal returns with a non-NULL value. | Check explicit memmove arguments, wrapper retain, insertion retain and temporary release; distinguish NULL/error paths and native ownership. |
| XT6 | Direct emission requires the stated dispatch/TLS/header gates; queued submission is a different frontier. | Check both send wrappers, queue branch, reply-specific overwrite bypass and every vector field. Acquire native state before assigning a live route/result. |
| XT7 | Mach names/dispositions and original SVC sites do not by themselves prove rights, delivery, authorization or kext processing. | Establish actual namespace/right epochs, native syscall outcome and receiver processing; retain slot34/RPC700 and selector26 gaps separately. |

## Bounded context and validation

| Impact | Established observation | Remaining boundary |
|---|---|---|
| High | Reply routing can consume context and use a send-once destination distinct from the normal connection destination. | Incoming context producer, actual p/right and native pairing remain unknown. |
| High | The pinned setter explicitly copies O B and retains a separate value before later daemon buffer cleanup. | Output validity/ownership and allocator/alias contracts remain unknown. |
| High | The selected direct route reaches a precise Mach2 call and SVC site. | Dispatch state, syscall outcome, native delivery and daemon-kext exchange remain unknown. |
| Medium | Mode-dependent offsets overlap semantically and extraction clears only 4 of 24 context bytes. | Remaining context fields and complete right/resource retirement need further tracing. |
| Medium | A pending internal reason and a void public API separate submission from delivery. | Queue draining, error callback behavior and peer observation remain unknown. |

Validation passes 104 exact instruction assertions, eighteen SDK assertions/one compilation, three unsatisfiable scalar queries, 5120 port models, eight length classifications, four 24 B context models and eight rejected evidence alterations. Cache pointers are decoded only after page-chain membership is verified. These checks support the stated scalar/path contracts; they are not native target tests.

Recovery cost is O(S+F+E+C) time/space for selected bytes S, function-start metadata F, export/nlist metadata E and traversed pointer-chain entries C, plus streaming hashes over H source bytes. Verification/finite modeling adds O(I+M), for instructions I and model cases M. Compiler/solver costs are separate; each query has a 10 s timeout. Normal data copying costs O(O) time under the memory-copy ABI; serialization/dispatch/allocator internals and concurrent queue draining are not assigned a bound here. Evidence sizes are B; offsets, widths and signedness are explicit.

QG1: Factual interface analysis requires no normative premise.

QG2: XT1-XT7 state assumptions, dependencies and falsification probes.

QG3: Context movement/consumption, copied data/retention, header fields, conditional dispatch and Mach2 handoff are covered. Broad native-interface completion remains unproved.

QG4: u32 names, u64 pointers/extents, 24 B header/context/vector sizes, 48 B vectors, disposition constants and packed slots are verified.

QG5: Nonzero u64 context versus low32 name, request/reply offset roles, logical connection versus actual destination, copy versus native ownership, queued versus delivered and scalar models versus execution remain distinct.

QG6: Original cache bytes, compiler ranges, export/nlist identities, chain-member pointers, original daemon recapture, SDK/tool hashes and retained queries provide provenance. Native gaps are explicitly unknown.

QG7: Impact-labeled context-routing, byte-copy, SVC, field-overlap and queue observations are bounded above. The full goal remains active.
