# FairPlay XPC reply emission, signed status, and local cleanup

The selected post-A70 return path creates an XPC reply, attaches `data` only for the internal zero-status marker, writes signed64 `status`, calls `_xpc_connection_send_message` with the saved peer at **`0x100bb4d08`**, and releases the reply object. It then conditionally frees the output/request buffers, destroys a finite owned record chain, clears Q's owner slot, and reaches the guarded handler epilogue. This establishes conditional API emission and local call-order contracts, not native delivery, actual port names, authorization or a successful daemon/kext transaction [RL1-RL7].

Evidence: [original capture](triage_evidence/daemon_xpc_reply_lifecycle_source.json), [checks and queries](triage_evidence/daemon_xpc_reply_lifecycle_checks.json), [capture script](triage_evidence/recover_daemon_xpc_reply_lifecycle.py), [validator](triage_evidence/validate_daemon_xpc_reply_lifecycle.py), [preservation](triage_evidence/daemon_xpc_reply_lifecycle_delivery.json), and [quality gates](triage_evidence/daemon_xpc_reply_lifecycle_quality_gates.json). Daemon SHA-256 remains `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The [preceding bridge](daemon_xpc_core_bridge_report.md), [linked lookup](daemon_xpc_iteration_report.md), and [listener/peer](daemon_xpc_listener_report.md) reports define the inherited context. Local references suffice; no new IDA query or target execution is performed.

```text
protected return -> event and peer present?
                       | no             | yes
                       |                v
                       |          create_reply(event)
                       |              | NULL
                       |              +-----------------------+
                       |              | non-NULL              |
                       |              v                       |
                       |       raw status == 8b3dc651?         |
                       |          | yes         | no           |
                       |          v             |              |
                       |       set data         |              |
                       |          +-------------+              |
                       |          v                            |
                       |    set signed64 status                |
                       |    send(peer,reply), release(reply)   |
                       +--------------+------------------------+
                                      v
                       free output / free copied request
                       free node buffers / nodes / Q
                       clear Q owner -> guard -> restore / RETAB
```

## Reply construction and API emission sites

The source context after the fallback adapter has W21=`0xa236`, W20=the u32 result loaded from the protected record, X13=the saved event, and SP+`0xc0`=the saved peer. The guard at `0x100dbdd48` uses CMP/CCMP with fallback NZCV=4; it selects cleanup exactly when the event or peer pointer is NULL. No pointer validity, native identity or authorization follows from non-NULL [RL2-RL4].

`0x100a85cdc` loads the two A70 output cells: output buffer D from SP+`0x408` into X21 and unsigned64 length O from SP+`0x6e8` into X22. These are the cells whose addresses were supplied at B72+56/+64. The length's valid production and D's ownership remain shared-core output prerequisites; the source loads them before the result-marker test.

| Call site | Exact interface / original slot | Established arguments |
|---|---|---|
| `0x100a85d44` | `_xpc_dictionary_create_reply`, `0x1010a1098`, IA/e200 | X0=original event dictionary E; result R in X0 |
| `0x100bd6a5c` | `_xpc_dictionary_set_data`, `0x1010a0850`, IA/485b | X0=R; X1=`data`; X2=D; X3=O, full 64 bits |
| `0x100bb4cb8` | `_xpc_dictionary_set_int64`, `0x1010a1808`, IA/11d8 | X0=R; X1=`status`; X2=sign-extended decoded result |
| `0x100bb4d08` | `_xpc_connection_send_message`, `0x1010a08c8`, IA/5e4e | X0=saved peer P from SP+`0xc0`; X1=R |
| `0x100bb4d50` | `_xpc_release`, `0x1010a01a8`, IA/a88b | X0=R |

The `data` key is the same literal at `0x100e86130`, five bytes including NUL. The `status` key is seven bytes at `0x100f18410`; pool slot `0x1010a2df8` rebases to `0x14e6953f3`, then bias `0xffffffffb288301d` gives that literal. Both pointers, byte sequences and original fixups are retained.

If create_reply returns NULL, the path skips setters/send/release and enters cleanup. The local SDK documents NULL for a dictionary without a reply context and for an already consumed reply context; this branch is not assigned solely to allocation failure. The create-reply declaration marks its successful result retained. The set_data declaration uses a size_t extent and permits NULL bytes when length is zero. Thus a successful marker alone does not establish the setter's D/O preconditions.

The SDK send interface returns void and provides no successful-delivery indication. Its message is logically copied by the connection; the documentation permits subsequent dictionary modification. This public API contract does not independently prove the matching native library, precise byte-storage retention, allocator ownership, or receiver invocation. In particular, this increment does not establish the implementation-level copy/retention behavior of set_data before the later buffer free [RL5-RL7].

## Exact status and object epochs

Let S be the raw protected-result u32. At `0x100a7c9c0`, equality with `0x8b3dc651` selects the data setter; all other S values skip it. Both paths reach the same common block with W24=`0x4ef0`. The instructions at `0x100bb4bf8..0x100bb4c10` reduce for every S to:

```text
decoded32 = S XOR 0x8b3dc651
wire status value = int64(sign32(decoded32))
data attached iff decoded32 == 0
```

| decoded32 bit pattern | Signed64 value written by the setter |
|---|---:|
| `0x00000000` | 0 |
| `0x00000001` | 1 |
| `0x7fffffff` | 2147483647 |
| `0x80000000` | -2147483648 |
| `0xffffffff` | -1 |

These are scalar identities/model cases, not observed replies or a public error-code enumeration. The data field's contents/schema and actual returned result remain unknown. Error-status replies still set status and reach the send API when E, P and R satisfy their guards.

| Register/cell epoch | Established role |
|---|---|
| X21 after output-cell loads | Core output buffer D |
| X23 during data setter | Saved reply R, allowing X0 restoration after the void API |
| X21 at `0x100bb4cb0` onward | Saved reply R; its earlier D meaning no longer applies |
| X22 before data setter | Full-u64 output length O; later overwritten by control arithmetic |
| SP+`0x408` | Retains D until its conditional free/zero |
| SP+`0x240` | Reply-continuation scratch, later reused to save Q for destruction |

The same physical register is not treated as a single persistent object across these epochs. The saved peer P is read from its own cell for the send; it is not replaced by D, Q or R.

## Port direction and lower transport boundary

The [listener report](daemon_xpc_listener_report.md) establishes the logical `com.apple.fairplayd.xpc` listener, a peer callback and an event handler capturing P. The selected reply uses that saved peer **as the connection argument** and a dictionary created from E's reply context. The listener object, peer connection, event dictionary and reply dictionary have distinct source roles.

This identifies the daemon-to-peer reply API boundary and exact emitter PC. It does not identify a task-relative Mach name, kernel port object, send/send-once right, descriptor disposition or actual mach_msg/mach_msg2 site. Libxpc's use of the reply context and its lower port routing require separate implementation/runtime evidence. A 64-bit xpc_connection_t/object pointer is not a 32-bit mach_port_t. Releasing R is an XPC-object operation, not itself proof of a particular Mach-right retirement.

## Buffer, node and collection cleanup

Cleanup is reached after the send/release sequence, when E or P is NULL, or when reply creation returns NULL. All targets below are exact `_free` bindings with IA/46a2; call arguments and original bank cases are separately checked.

| Site | Conditional source argument / following state |
|---|---|
| `0x10095b888` | D from SP+`0x408`, if non-NULL; then that cell is zeroed |
| `0x100c3dc10` | Copied request M from SP+`0x820`, if non-NULL; then that cell is zeroed |
| `0x100aaee2c` | Current node's buffer at node+24, if non-NULL; then node+24 is zeroed |
| `0x100ade90c` | Current node; next was saved from node+0 in X26 before either free |
| `0x10094e050` | Q, after its chain is exhausted; owner slot is then zeroed |

The collection owner is addressed through X20=&(SP+`0x898`). The destructor checks that slot pointer, then its Q value. Q+0 supplies the first node. Each loop saves next, conditionally frees the buffer, frees the node, and assigns current=next. The Q value is saved independently at SP+`0x240` while X22 walks the chain. On exhaustion, free(Q) precedes `STR XZR,[X20]`.

During this destructor X19 holds the dispatch-table base while W28/W27 carry local control. The final continuation restores X28 from X19 and the original operation word from SP+`0x234`, then branches through a saved return target. Table identities and register roles are not carried unchanged from the preceding reply phase.

For a valid finite acyclic chain of k owned nodes, with b non-NULL owned buffers, the source issues k node frees, b buffer frees and one Q free, then clears the owner. For Q=NULL it returns without freeing Q. These are conditional call-order contracts; actual deallocation, pointer distinctness, allocator provenance and native mutation are not proved. Separate output/request free roles do not prove that D and M are different allocations. No alias, duplicate-owner or malformed native fixture is executed [RL3-RL5].

## Guarded return

Saved return table index `0xb66` selects `0x100c577b8`. Its normal branch compares the saved guard at FP-`0x60` with the word obtained through import slot `0x1010b1e18` (`___stack_chk_guard`), adds `0xee0` to SP, restores X19-X30 from the inherited frame and pops the final `0x60` B before RETAB. If entry SP was E and current S=E-`0xf40`, then `S+0xee0+0x60=E` modulo 2^64.

Guard mismatch branches to `0x100c577f0`, whose BL targets stub `0x100e2aad0`. The stub loads original slot `0x1010b1d00` -> `___stack_chk_fail`, authenticated IA with diversity 0/address diversity 1, using the slot address as branch modifier. This differs from the scalar ad=0 call discriminators above. The capture retains the guard-hook transfer and full 16 B stub; no native guard value or hardware authentication is tested. Normal return is conditional on frame/guard preservation and successful RETAB. No conventional X0 result is assigned.

## Assumption register

| ID | Assumption and dependent findings | Stress test / falsification probe |
|---|---|---|
| RL1 | Pinned original daemon and preserved preceding captures define this build/path. | Rehash originals; recapture all ranges and 1360 inherited entry bytes; independently compare fixup membership and selected records. Require native image pairing separately. |
| RL2 | Original banks/table words, returned control state and callee-preserved registers retain the declared values. | Exhaust 3072 byte inputs over twelve banks; verify ten calls, 29 branches and guard transfer; reject altered peers/targets/modifiers. Hardware PAC remains untested. |
| RL3 | E/P/R, output D/O, stack owner and cleanup objects have valid lifetime/ownership for the selected APIs. | Trace core writers of B72+56/+64, allocation sizes, aliases, object retention and lower XPC implementation before claiming native safety, distinct allocations or right retirement. |
| RL4 | This is the post-fallback frame epoch, with S/FP restored as expected and the collection owner initialized. | Recover every returned-budget, alias and alternate-mode predecessor; do not apply these scalar states to all entries sharing cleanup blocks. |
| RL5 | Signed32 decode, 64-bit extent, finite owned chain and saved-next recurrence match source. | Four scalar queries, SDK signatures and 511 finite-chain models; verify read-before-free/slot clearing. Cycles, duplicate ownership and unproved aliases are outside the termination/once-per-node contract. |
| RL6 | API emission/SDK semantics are distinct from delivery and successful operation. | Follow matching libxpc storage/retention and Mach transport, then actual peer/reply epochs; obtain actual protected result and output schema before success claims. |
| RL7 | Prior audit/entitlement/kext contracts retain their own conditional scopes. | Do not infer trusted identity, final policy or daemon/kext exchange from marker zero, a queued reply call, or object cleanup. |

## Bounded context, validation and quality gates

| Impact | Established pattern | Remaining boundary |
|---|---|---|
| High | Saved-peer send PC and reply fields close another static leg after the protected handoff. | Actual Mach routing, reply-context use, delivery and native processing remain unknown. |
| High | Status is sign32-decoded into signed64; only decoded zero attaches data. | Namespace/meaning of actual codes and output payload schema remain unknown. |
| High | Output/request cleanup and finite-chain destruction have explicit calls/order. | Allocator provenance, alias/ownership, mutation and XPC byte retention remain unknown. |
| Medium | The same registers/cells change from output values to reply/control/destructor state. | Cross-epoch interpretation requires the producer and consumer, not a global field name. |
| Medium | The normal handler path restores its source frame and checks the guard. | Actual guard equality, native return and hardware PAC remain unproved. |

The capture retains 21 fragments, 543 instructions/2172 B, twelve banks/3072 inputs, ten resolved calls, 29 branch bindings, eight imports, one guard transfer and 34 selected pointers. Independent current dyld_info output matches 61737 memberships and selected lines. Checks pass 57 instruction assertions, eleven SDK assertions/one compilation, four unsatisfiable scalar queries, sixteen Boolean reply cases, 511 finite-chain cases, five status-width cases and eight rejected evidence alterations. No recovered code executes or is emulated, and no native target/transport/IDB state changes.

Capture/checking costs O(B+F+I+256K+M) time/space for image bytes B, fixups F, instructions I, bank cases K and finite model cases M. Solver/compiler costs are separate; scalar queries each have a 10 s timeout. The retained callback path has fixed local reply work plus O(k) cleanup for a valid finite chain; XPC copying, allocator internals and transport costs are outside that bound. Scalar workspace is O(1). Publication/audit is O(total artifact bytes + local links). Sizes are B and integer widths are explicit.

QG1: Factual interface/data-flow analysis requires no normative premise.

QG2: RL1-RL7 specify assumptions, dependent results and falsification probes.

QG3: Selected reply creation, field/status ABI, emitter/release, buffer/chain cleanup and guarded return are covered; full native interfaces and the broad goal remain active.

QG4: Signedness, full-u64 output length, pointer/object/name widths, byte offsets, branch values and frame equation are checked.

QG5: API send versus delivery, marker zero versus actual success, pointer versus Mach name, role versus allocation identity, reply release versus right retirement, and conditional return versus native return remain distinct.

QG6: Original bytes/fixups, exact imports/literals, inherited frame match, SDK/tool hashes and retained proofs/models provide provenance. Unknown native states are not supplied.

QG7: Impact-labeled reply, signed-status, ownership, epoch and return observations are bounded above. No authorization outcome, actual exchange or full-goal completion is claimed.
