# XPC ingress, request-context production and audit-token lineage

The captured libxpc implementation joins the received Mach header to the context consumed by the [reply transport](xpc_reply_transport_report.md). A successful ordinary receive moves the u32 name at received-header+8 through a 64 B temporary record into request-dictionary+`0x58`. The audit token is copied separately from the aligned trailer into dictionary+`0x78`; the daemon's existing getter call then copies those 32 B into its audit buffer. Connection-kind and configured peer-requirement checks precede unpacking. These are conditional static source contracts; actual kernel trailer provenance, native daemon/cache pairing, policy results, right validity and delivery remain unknown [RC1-RC7].

Evidence: [original capture](triage_evidence/xpc_receive_context_source.json), [checks and models](triage_evidence/xpc_receive_context_checks.json), [reader](triage_evidence/recover_xpc_receive_context.py), [validator](triage_evidence/validate_xpc_receive_context.py), [preservation](triage_evidence/xpc_receive_context_delivery.json), and [quality gates](triage_evidence/xpc_receive_context_quality_gates.json). Cache UUID remains `2bd06591-e751-3e84-963f-b08dab6af23a`; daemon SHA-256 remains `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Twenty-four prior cache bodies/9816 B and fifteen daemon ranges/6492 B are freshly recaptured, including fifteen daemon call bindings. No target code, native message, authorization callback or IDB mutation is executed.

```text
received header H+8  -> temporary C+0  -> request E+58
        cleared4          cleared32         |
                                           v
                                     reply R+60 -> outgoing destination

H + round4(size) + 14 -> C+20 -> E+78 -> daemon audit buffer SP+3c4
                                                   |
                                                   v
                                       prior A70 audit/entitlement path

connection P -> retain / C+18 -> E+70 -> retained reply connection R+58
```

Diagram offsets are hexadecimal; lengths are decimal B. Header name, object pointer, audit token and policy decision remain separate data types.

## Original entry points and receive routing

| Original symbol | Unslid address | Established role |
|---|---|---|
| `__xpc_connection_mach_event` | `0x184b77fa0` | Ordinary Mach event classification and event dispatch |
| `__xpc_connection_unpack_message` | `0x184b77dfc` | Peer checks, voucher acquisition, receive and connection audit update |
| `_xpc_receive_mach_msg` | `0x184b720ec` | Header predicate, temporary context, payload and graph unpacking |
| `_xpc_receive_mach_msg_validate_hdr` | `0x184b89370` | Exact ID/name/disposition predicate |
| `__xpc_payload_create_from_mach_msg` | `0x184b723dc` | Retained dispatch-message payload wrapper |
| `__xpc_graph_unpack_impl` | `0x184b725f4` | Conditional dictionary creation and context transfer |
| `__xpc_received_message_set_connection` | `0x184b789f0` | Connection reference in the temporary record |
| `__xpc_connection_check_peer_requirement` | `0x184b9415c` | Kind-2 identity comparison and optional requirement/cache gate |
| `_xpc_dictionary_get_audit_token` | `0x184b72b64` | Mode-dependent raw 32 B getter |
| `_xpc_connection_get_audit_token` | `0x184b82f58` | Locked copy of cached connection audit token |
| `__xpc_connection_call_event_handler` | `0x184b79fb8` | Block or function handler invocation |
| `_xpc_connection_set_event_handler` | `0x184b75db8` | Copied-block request and conditional handler publication |
| `__xpc_received_message_destroy` | `0x184b72c90` | Request cleanup followed by connection-reference release |
| `__xpc_message_request_destroy` | `0x184b72cdc` | Conditional reply-name/voucher/flag cleanup |

An original-text direct BL/B census covers all 72021 words of libxpc's `__text`, finding three calls to unpack: ordinary event `0x184b783fc`, synchronous reply `0x184b776cc`, and asynchronous reply `0x184b7b914`. All three containing bodies are captured. This census excludes indirect references and code outside that text section.

For the selected ordinary event, X0=P, X1=reason and X2=dispatch message. Reason 2 reaches received-message classification. With P+`0x108` bit 3 clear and byte P+`0x60` zero, IDs `0x10000000`, `0x30000000` and `0x40000000` reach the unpack call. ID `0x20000000` takes a distinct ordinary-event cleanup route; the synchronous/asynchronous reply callers instead route that ID to unpack. Other notification/handshake/error branches retain separate scopes. The standalone header predicate below is therefore not the whole ordinary-event routing predicate.

## Temporary record and dictionary ownership transfer

After the header predicate succeeds, receive loads size and the u32 field at H+8, then **clears exactly four bytes** at H+8 (`0x184b72170`). Let n be the loaded u32 size. Trailer base is:

```text
T = H + ((zero_extend64(n) + 3) AND 0x00000001fffffffc)
```

The arithmetic uses X registers: n=`0xffffffff` rounds to `0x100000000`, not zero. This is a source address calculation, not proof that the backing message/trailer has that capacity or a valid trailer type/size.

C denotes SP+`0x10` in `_xpc_receive_mach_msg`:

| C offset, B | Size, B | Established producer | Request destination |
|---:|---:|---|---|
| 0 | 4 | Received-header H+8 u32 name | E+`0x58` |
| 4 | 4 | Zero | E+`0x5c` |
| 8 | 8 | Voucher argument, obtained by `_voucher_copy` in unpack | E+`0x60` |
| 16 | 1 | `(caller flag ? 2 : 0) OR (ID==0x40000000 ? 4 : 0)` | E+`0x68` |
| 17 | 7 | Overlapping zero stores cover all seven bytes | E+`0x69` |
| 24 | 8 | Associated connection P, retained by helper | E+`0x70` |
| 32 | 32 | Two 16 B loads from T+`0x14` and T+`0x24` | E+`0x78` |

The context initially zeroes C+24 before optional connection assignment. For the ordinary P path, the helper distinguishes an XPC connection from other object types, requests the corresponding retain, releases an old non-NULL C+24 reference, and writes P. The capture binds the connection-specific retain to `__os_object_retain_with_resurrect`.

The graph path has selector/preamble/version/root and payload prerequisites. On its selected successful dictionary paths, mode low bits become 1. Instructions `0x184b728e8..0x184b72908` move C[0,32) into E[`0x58`,`0x78`) and zero those **32 source bytes**. They separately copy C[32,64) into E[`0x78`,`0x98`) without clearing that audit source. The 24 B reply context is the first 24 B of the moved record; the adjacent 8 B connection field is not part of the later 24 B reply move.

For this producer, the context's first u64 is precisely zero_extend64(name), and flag bit 0 is clear. Consequently the earlier create_reply nonzero-u64 test is equivalent to a nonzero u32 name **under this producer contract**; extraction is not diverted by context bit 0. This closes the prior generic context-width uncertainty for this path. It does not extend to arbitrary dictionaries or the alternate bit-0 transport.

The exported `__xpc_dictionary_set_remote_connection` at `0x184b8839c` requires mode 1, context flag bit 0 set, and a nonzero first u64 before reaching its setter helper. Those prerequisites differ from the ordinary producer above. It is not used as a substitute explanation for ordinary C+24 assignment.

The payload wrapper retains the dispatch message, distinguishes inline data from a selected OOL representation, and tracks remaining 12 B port descriptors. Graph unpacking checks selector<4, a selector-indexed preamble word, version 5 and dictionary root tag `0xf000` on the context-bearing path. Lazy/eager value extraction and complete dictionary field semantics remain separate prerequisites. No complete format-admission or pointer-validity claim is derived from these individual checks.

## Header predicate, audit getters and daemon boundary

The standalone header helper computes ROR32(ID-`0x10000000`,28). Its exact full-u32 predicate is:

| ID | Additional predicate |
|---|---|
| `0x10000000`, `0x20000000`, `0x40000000` | Name at H+8 is zero, or low five header bits equal 18 |
| `0x30000000` | Name at H+8 is zero |
| All other u32 patterns | False |

The zero-name branch does not constrain those disposition bits. Other header bits, trailer validity, body capacity, graph decoding, connection state and policy are outside this helper's predicate. These are received-header fields; no native right or sender identity is inferred from a nonzero integer or disposition constant.

The original dictionary audit getter first checks dictionary type, then selects by low mode bits:

| Mode | 32 B output source |
|---:|---|
| 1 | Dictionary+`0x78`, ordinary received request audit |
| 3 | Dictionary+`0x58`, a different object layout |
| 0 or 2 | Sentinel: all bytes `ff`, except four zero bytes at output+`0x14` |

The sentinel's zero word is PID word 5; it is not an all-zero audit token. Original libbsm exports `audit_token_to_pid` and `audit_token_to_pidversion` independently load token+`0x14` and token+`0x1c`. SDK assertions establish audit_token_t=32 B, audit trailer=52 B and its audit field at offset 20 B. The source copies token bytes without deriving them from dictionary fields or the daemon's `data` payload.

The [daemon listener report](daemon_xpc_listener_report.md) supplies the existing call at `0x100b27ea8`, passing E and SP+`0x3c4`. Under mode 1 and matching cache implementation, that buffer receives the 32 B copied from T+`0x14`. The [A70 bridge report](daemon_xpc_core_bridge_report.md) separately copies this buffer into B72+24 for the shared-core/entitlement path. This is a static byte lineage, not proof of a kernel-authenticated native token, an entitlement value or a policy outcome.

After successful receive, unpack also locks P+`0x58` and copies the same two trailer vectors into P+`0x68` and P+`0x78`. The connection audit getter subsequently copies these cached 32 B under that lock. Dictionary audit is per-object storage; connection audit is mutable cached storage. Their equality requires the same receive epoch and absence of an intervening update.

## Peer identity and configured requirement gate

`__xpc_connection_check_peer_requirement` runs before `_xpc_receive_mach_msg` in the unpack wrapper. For connection u32 P+`0x18` equal to 2, it locks P+`0x58` and compares:

| Value | Cached connection field | Incoming trailer field |
|---|---|---|
| PID, raw u32 | P+`0x7c` | T+`0x28` |
| PID version, raw u32 | P+`0x84` | T+`0x30` |

Either mismatch selects a false result after the source's reporting/internal-error branch. Other connection-kind values skip these two comparisons. This describes a conditional check, not the initialization, authenticity or freshness of the cached fields.

The subsequent configured requirement is controlled by pointer P+`0xf0`:

```text
identity stage accepted?
  no -> false
  yes -> requirement absent? -> true
           present -> map128 hit? -> true
                        miss -> requirement callback
                                  zero -> false
                                  nonzero -> insert value 1, true
```

The map is addressed at P+`0xd8`. Its exact imported operations are `_os_map_128_find` and `_os_map_128_insert`. Both key halves are signed extensions of the raw PID and PID-version u32 words into X registers. Callback function pointer is at requirement descriptor+`0x18`, context at descriptor+`0x10`; X1 points to a reconstructed full 32 B audit token and X2 is the caller-supplied result/error-object cell. Callback return is tested as W0!=0. Callback implementation, requirement installation, cache epochs and actual acceptance remain unknown.

The source predicate reduces to identity && (!requirement || cache_hit || callback_nonzero), with callback reached only after an identity pass and a requirement/cache miss. That identity is `kind!=2 || (PID_equal && PIDversion_equal)`. These formulas assume all relevant calls return normally and describe local control only. The unpack wrapper's rejection branch returns a distinct object rather than a newly unpacked dictionary; downstream event type checks retain their existing scope.

## Handler publication and cleanup

The selected ordinary event calls the event-handler dispatcher at `0x184b78410` with P and the unpack result, then releases its local result reference. With handler-kind byte P+`0x28` equal to 1, the dispatcher authenticates the block at P+`0x20`, loads invoke from block+`0x10`, passes the block as X0 and event as X1, and calls at `0x184b7a024`. The function-handler alternative passes the event in X0 through a different authenticated call at `0x184b7a04c`.

The captured set_event_handler calls its copy helper, signs the returned pointer for P+`0x20` with discriminator `0x9974`, and can publish it together with kind 1 using CASPL at `0x184b75e54`. Contention/configuration can instead select the pending-handler/dispatch path; native atomic completion and scheduling are unproved. This connects the source layout to the daemon's previously recovered block installation and callback ABI conditionally; actual copied-block identity and hardware authentication remain unknown.

On a later unpack failure after context construction, `__xpc_received_message_destroy` invokes request cleanup and releases its associated connection reference. For ordinary flag bit 0 clear and a nonzero first context word, request cleanup calls `_mach_port_deallocate` at `0x184b72d44` with the captured task-self value and the context name. It separately releases a non-NULL voucher through `_os_release`, and context flag bit 1 selects an additional helper at `0x184ba0af0`. Alternate flag-bit-0 transport has its own callback branch. These are conditional cleanup API requests, not proof of native right retirement or balanced reference counts. Full dictionary disposal after a successful ownership move remains a separate boundary.

## Assumption register

| ID | Assumption and dependent findings | Stress test / falsification probe |
|---|---|---|
| RC1 | Pinned cache/daemon bytes define this source path; native image pairing remains separate. | Rehash cache files/UUIDs, prior cache spans and daemon bytes/calls; establish live image identity before native linkage claims. |
| RC2 | Received message, trailer and payload allocations have the extents/lifetimes required for each selected load. | Preserve full-u64 rounding including the 2^32 B boundary; recover dispatch receive allocation/trailer production and native capacities. Header predicate alone does not prove these prerequisites. |
| RC3 | Selected graph/allocator/copy/retain calls return normally and maintain the declared ABI. | Trace lazy/eager field decoding, allocation outcomes, pointer aliases and all producer predecessors; keep context transfer conditional on success. |
| RC4 | Mode, cached connection fields and event/handler state belong to the same relevant epoch. | Check both audit getters and the mutable connection update; verify actual callback installation, queue scheduling and intervening receives before equality claims. |
| RC5 | Kind-2 identity and configured requirement/cache inputs have their declared values. | Check raw field offsets, both signed map keys, callback arguments and local gate truth table. Requirement producer, callback semantics and native acceptance remain unknown. |
| RC6 | Ordinary flag bit 0 clear and zero upper name word distinguish this context from alternate transports. | Check all 64 temporary bytes, 32 B source clearing, 24 B later reply move and 4 B port extraction; do not substitute the alternate set_remote API. |
| RC7 | Static audit/port lineage and API calls are distinct from native kernel identity, right ownership, authorization and delivery. | Join actual trailer generation, namespace/right epochs, syscall results and receiver processing; retain separate selector26/RPC502/RPC700 gaps. |

## Bounded context, verification and quality gates

| Impact | Established observation | Remaining boundary |
|---|---|---|
| High | Header name -> temporary -> request -> reply -> outgoing-name lineage now joins conditionally. | Actual received name/right and native transport pairing remain unknown. |
| High | Trailer audit -> request audit -> daemon buffer -> prior shared-core audit path is a separate byte lineage. | Native trailer authenticity, entitlement value and final policy remain unknown. |
| High | Kind-2 PID/version and optional map128/callback checks have explicit order and arguments. | Initialization, callback implementation, cache lifetime and actual acceptance remain unknown. |
| Medium | Dictionary and connection audit storage differ by object, offset and update epoch. | Concurrent native updates and current process identity remain unknown. |
| Medium | Header predicate, ordinary-event routing, graph success and handler delivery are separate stages. | Complete deserialization and native event execution remain unknown. |
| Medium | Port/voucher/connection cleanup and context movement identify distinct resource operations. | Complete successful-dictionary disposal, right/reference balance and additional flag helper semantics remain unknown. |

The capture retains 22 complete compiler bodies, 2431 instructions/9724 B and twelve exact import bindings. It recaptures 24 prior cache bodies/9816 B, fifteen daemon ranges/6492 B and fifteen daemon call bindings. The direct BL/B census covers 72021 original text words and independently checks each matched branch with Capstone.

Verification passes 105 exact instruction assertions, fourteen SDK assertions/one compilation, four unsatisfiable scalar queries, 2560 finite header cases, sixteen 64 B context models, 64 policy-gate cases, twelve rounding boundaries, four getter modes and eight rejected evidence alterations. These are source/SDK/scalar checks; no recovered CPU path, policy callback, native packet or malformed target fixture executes.

Recovery costs O(S+F+E+C+W) time/space for selected bytes S, function-start metadata F, export/nlist metadata E, traversed pointer chains C and censused text words W, plus streaming hashes over H source bytes. Verification/model generation adds O(I+M) for instructions I and model cases M. Compiler/solver costs are separate; each scalar query has a 10 s timeout. The selected context/audit moves and local header/gate work have fixed byte footprints; payload decoding, map lookup, allocation, policy callbacks and concurrent delivery are outside a fixed-runtime claim. All extents/offsets are B and integer widths are explicit.

QG1: Factual interface and data-flow analysis requires no normative premise.

QG2: RC1-RC7 state assumptions, dependent results and falsification probes.

QG3: Incoming route, context producer/move, audit copies/getters, peer gates, conditional callback ABI and failure cleanup are covered. Complete native interfaces and the broad goal remain active.

QG4: u32 received names/sizes, u64 pointers/rounding, 24 B reply context, 32 B audit/moved prefix, 64 B temporary record, 52 B audit trailer and signed map keys are checked.

QG5: Header predicate versus overall admission, raw audit bytes versus authenticated native identity, per-object versus cached audit, generic versus ordinary context, API cleanup versus native retirement and static callback ABI versus actual delivery remain distinct.

QG6: Original cache bytes, compiler spans, export/nlist/chain bindings, fresh prior-source/daemon recaptures, original libbsm field loads, SDK/tool hashes and retained proofs/models provide provenance.

QG7: Impact-labeled port/audit/gate/epoch/delivery/resource observations are bounded above. No native authorization, successful exchange or full-goal completion is claimed.
