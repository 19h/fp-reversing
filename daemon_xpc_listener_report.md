# fairplayd.xpc listener, callbacks and protected application ABI

Selected original startup fragments request `com.apple.fairplayd.xpc` with the main dispatch-queue object and listener flag 1, install peer callback `0x10000778c`, and activate the listener. That callback installs event callback `0x10044d2fc` and resumes each supplied peer object. The recovered event paths request cancellation or forward a local message/peer record through adapter `0x100ba80a8` to protected entry `0x100b27b78`. Its captured prefix requests a 32 B audit token from the incoming event [DL1-DL7].

This supplies a static implementation counterpart for the sixth named endpoint in the [frozen endpoint inventory](rpc700_endpoint_inventory_report.md), alongside the earlier [five classic Mach-service registrations](daemon_registration_report.md). Native whole-startup reachability, loaded-image/port identity, actual peer delivery, authentication and successful protected processing remain unknown.

[Original source capture](triage_evidence/daemon_xpc_listener_source.json), [checks](triage_evidence/daemon_xpc_listener_checks.json), [read-only IDA snapshot](triage_evidence/daemon_xpc_listener_ida.json), [capture script](triage_evidence/recover_daemon_xpc_listener.py), [validator](triage_evidence/validate_daemon_xpc_listener.py), [delivery seal](triage_evidence/daemon_xpc_listener_delivery.json), [quality gates](triage_evidence/daemon_xpc_listener_quality_gates.json).

```text
selected startup fragments
  create_mach_service("com.apple.fairplayd.xpc", main_queue, 1)
    -> set listener handler -> activate
         peer block, invoke 0x10000778c
           -> target queue from captured object
           -> install event block, invoke 0x10044d2fc
           -> resume supplied peer
                event type == error?
                  yes: invalid-error singleton? -> cancel peer
                       other error object       -> forward record
                  no: second type == dictionary? -> forward record
                                                 -> otherwise cancel peer

forward: local 32 B record -> stack adapter -> protected entry
         aligned control word -> internal selector 0x77a0
         named audit-token getter -> local 32 B destination
         downstream payload, reply and authorization semantics UNKNOWN
```

## Original identities and retained source

The thin input is `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. The selected IDA database reports universal-input SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`, ARM processor and image base `0x100000000`. Six read-only IDB ranges, totaling 2820 B, match the original thin image. This is selected-byte agreement; it does not attest every IDB byte or a native loaded slice [DL1].

Four complete compiler-bounded spans and eleven selected fragments contain 1623 decoded instructions / 6492 B. A complete compiler span means the original `LC_FUNCTION_STARTS` interval is retained; it does not establish complete semantic recovery of every block in that interval. Fresh `dyld_info` output agrees on all 1005 compiler starts and all 61737 fixup-catalog memberships; selected pointer entries are independently compared. Source records retain 42 used pointer words, thirteen import bindings, ten biased bank-pointer origins and fifteen resolved call sites [DL1,DL3].

All 7424 byte-index checks for 29 labeled bank cases pass. These are case occurrences, including repeated bank identities. Each selected mapping has the form `u8(i XOR right[left[i] XOR key])`, constant over all 256 possible i values. This removes the selected byte-index dependence on mutable scalar states. The bank addresses, pointer table, frame/register inputs, original bindings and call-site authentication modifiers remain prerequisites. The same modifier or key can occur on unrelated calls; neither alone identifies a target [DL2,DL3].

Addresses throughout are preferred static virtual addresses. No IDB rename, patch, emulator invocation, FairPlay request or native listener operation is performed by this increment. IDA knowledge-store search tools were unavailable; current metadata and raw-byte observations are retained without asserting a new knowledge-store recall result [DL7].

## Listener and peer setup sites

| Selected role | Original API site | Established argument contract |
|---|---|---|
| Named listener creation | `0x1000935e4` | X0=`com.apple.fairplayd.xpc`, X1=main-queue object, W2=1 |
| Listener handler installation | `0x1000b2878` | Incoming listener object and stack block whose invoke is `0x10000778c` |
| Listener activation | `0x1000b28c8` | Saved listener object in X0 |
| Peer target queue | `0x100007948` | Supplied peer in X0, block capture at+32 in X1 |
| Peer event-handler installation | `0x100007a70` | Supplied peer and stack block whose invoke is `0x10044d2fc` |
| Peer resume | `0x100007ab0` | Supplied peer in X0 |

The startup code reaches the exact imported `xpc_connection_create_mach_service`; SDK flag `XPC_CONNECTION_MACH_SERVICE_LISTENER` is1. The actual C string starts at `0x100f23670` and occupies 24 B including NUL. IDA's string list groups the preceding byte `0x37` with the text; the reduced pointer selects the following byte, so that prefix is not passed as part of the service name [DL1,DL2].

The two startup fragments are flattened continuations with inherited register/stack inputs. The source artifact records their declared frame contract, including table/pool and byte-bank pointers. Their source-to-argument reductions are conditional on that contract and intact object/register continuity. Whole-main traversal, preservation across every intervening path and native creation/activation outcomes are not proved [DL2]. The self-contained peer callback separately establishes its own original pointer-bank setup and three API arguments.

## Callback block layout and imported data objects

The listener and peer blocks each have descriptor size 40 B. Original descriptors at `0x101038348` and `0x1010382e8` contain reserved 0, size 40 and signature pointer to bytes `v16@?0^v8`. Their selected reconstructed layout is:

| Offset | Width | Listener block at SP+`0x1c0` | Peer event block at SP |
|---|---|---|---|
| 0 | 8 B | Signed stack-block class pointer | Signed stack-block class pointer |
| 8 | 4 B | Raw flags `0x40000000` | Raw flags `0x40000000` |
| 12 | 4 B | Reserved0 from the paired store | Reserved0 from the paired store |
| 16 | 8 B | Signed invoke `0x10000778c` | Signed invoke `0x10044d2fc` |
| 24 | 8 B | Descriptor pointer | Descriptor pointer |
| 32 | 8 B | Main-queue object capture | Supplied peer-object capture |

The first invoke receives block in X0 and supplied peer in X1. It loads the queue capture at `0x1000078e8`. The second invoke saves its block/event inputs at SP+8/+16; its forwarding/cancellation continuations read the captured peer from block+32. These are object pointers. Numerical Mach names, kernel objects and actual block-copy/connection ownership are not recovered from them [DL3,DL4].

| Exact imported data symbol | Original positive import addend | Original signed adjustment |
|---|---|---|
| `__dispatch_main_q` | `0x44ef996b` | `0xffffffffbb106695` |
| `__NSConcreteStackBlock` | `0x78801bdb` | `0xffffffff877fe425` |
| `__xpc_type_error` | `0x256d84e2` | `0xffffffffda927b1e` |
| `__xpc_type_dictionary` | `0x63f36eae` | `0xffffffff9c0c9152` |
| `__xpc_error_connection_invalid` | `0x4319569e` | `0xffffffffbce6a962` |

Each pair sums to zero modulo 2^64. A full-width proof checks all five for arbitrary resolved base addresses. Native loader/interposition, object identity and pointer authentication remain separate. Fifteen selected call sites also match the original authenticated pointer record's key/address-diversity/modifier fields; this is static metadata consistency [DL3].

## Event classification and cancellation/forwarding

The event callback calls exact `_xpc_get_type` at `0x10044d4f8`. Its first comparison is with the imported error-type object. The non-error continuation calls that getter again at `0x1001c8e6c`, then compares with the dictionary-type object. Error events instead compare the event pointer itself with the canonical invalid-connection error object [DL3,DL4].

| Selected condition | Reduced table index / continuation | API or next boundary |
|---|---|---|
| First type equals error type | `0xa777` -> `0x1002fa1ac` | Compare event with invalid-error object |
| Error event equals invalid-error object | `0x68fd` -> `0x1001bce68` | Cancel captured peer at `0x1001bceb8`; selected return index `0x3a8a` |
| Other error event | `0x68f4` -> `0x100288b38` | Construct forwarding record |
| First type differs from error type | `0xa7d7` -> `0x1001c8e2c` | Second type query |
| Second type equals dictionary type | `0xab7f` -> `0x100288b38` | Construct forwarding record |
| Second type differs from dictionary type | `0xaba5` -> `0x1001572a8` | Cancel captured peer at `0x100157324` |
| Common selected return | `0x3a8a` -> `0x10016b184` | Stack-guard check and frame restoration |

The two type queries are distinct observations in the source. The eight Boolean model cases do not require an unproved invariant that their results stay equal across an arbitrary runtime mutation. Cancellation requests use the peer captured in the block, with no newly recovered numerical Mach destination. Error forwarding therefore also reaches the shared adapter; this is broader than a dictionary-only interpretation. Lower runtime handling and all downstream policy remain open [DL4,DL6].

## Local message record and internal selector

At `0x100288b38`, selected forwarding paths construct a record at R=SP+`0x38` and pass it to adapter `0x100ba80a8` at call `0x100288c78`. The event and peer pointers come from saved callback inputs and block capture, respectively [DL4].

| Record offset | Width | Reconstructed field / source |
|---|---|---|
| 0 | 8 B | Address-dependent encoded header |
| 8 | 8 B | Saved event pointer |
| 16 | 8 B | Peer pointer from block+32 |
| 24 | 4 B | Address-dependent internal control word |
| 28 | 4 B | Unwritten padding/word; value unknown |

This is a reconstructed 32 B local ABI object. Its fields do not establish the XPC dictionary's serialized keys, data encoding or wire command IDs. The adapter preserves R in X0 and supplies an auxiliary stack slot through X1 when calling protected entry `0x100b27b78` at `0x100ba82e8`. Original pointer metadata verifies discriminator `0xf401` for this target. A different bank pair with the same key would select another target; the original pair and modifier are both checked [DL3].

Let r=low32(R), with R aligned to 8 B; all expressions below wrap modulo 2^32. The callback's control-word expression reduces to:

```text
code = 0xba209ef7 * (r XOR 0xe732d262) + 0x77a0
```

The original protected entry reconstructs the same address-dependent term and subtracts it from the word at R+24. The result in W27 is exactly `0x77a0` for every aligned 32-bit address pattern, as proved from the unreduced instruction-matched expressions. This selector belongs to the local ABI. Its relation to a serialized operation remains unknown [DL4,DL5].

The prefix subsequently reads the message pointer from R+8 and the peer from R+16. Under selector`0x77a0`, its message-pointer predicate reduces to index`0x77a0` for non-NULL, reaching `0x100b09274`, or `0x77ae` for NULL, reaching `0x100b12c30`. These are static control frontiers. Valid XPC-object prerequisites remain explicit; no native NULL or malformed-object experiment is performed.

## Stack adapter and audit acquisition

The adapter's ordinary entry/return path begins at `0x100ba80a8` and returns at `0x100ba830c`; its retained compiler span extends through `0x100ba8510`. Additional bytes in that compiler span are retained without assigning them complete semantics. The selected ordinary path reads a 64-bit seed V through incoming X1, allocates an aligned local stack region, stores V-`0x50` in its local slot, and passes that slot to the protected entry. The captured entry adds`0x50` back before its later work [DL5].

For arbitrary 64-bit V and a 32-bit post-call slot value q, the selected formulas are:

```text
hint = ((top4((V * 0x2ec5 + 1) mod 2^64) << 4) + 31) AND 0x1f0
     in {16, 32, ..., 256} B
delta = ((q - low32(V)) mod 2^16) * 16 B
      in {0, 16, ..., 1048560} B
```

The adapter publishes delta as 64 bits through its original X1 output pointer. The caller reads it and adjusts SP. A scalar proof establishes these ranges/alignment; it does not establish the post-call value, valid stack mapping, full callee writes or whole-application frame restoration. The initial entry adjustment alone is not proof that the entire callee leaves the slot unchanged [DL5].

The protected entry's selected prefix calls local helper `0x10046faf8` at `0x100b27e3c` with destination SP+`0x3c4`, W1=0 and W2=32. It then calls exact `_xpc_dictionary_get_audit_token` at `0x100b27ea8`, with the incoming event in X0 and that destination in X1. SDK `audit_token_t` is 32 B, alignment 4 B, consistent with this local destination. The prefix saves the peer pointer separately at SP+`0xc0`. Its non-NULL continuation calls `_xpc_get_type` at `0x100b092dc` [DL4,DL6].

The named getter connects this receiver analysis to the prior [libxpc dictionary/audit-metadata contract](launchd_audit_context_report.md). Actual getter output bytes, trailer/connection provenance for this daemon's event, same-epoch peer identity and authorization consumers remain unknown. A getter call and a correctly sized destination do not attest an authenticated native caller [DL6]. The protected entry's original compiler interval is `0x100b27b78..0x100ba80a8` (525616 B); most payload and reply behavior in that interval remains opaque.

## Assumption register

| ID | Assumption and dependent findings | Stress test / falsification probe |
|---|---|---|
| DL1 | Pinned original thin image and selected universal-input IDB delimit static claims. Addresses and byte interpretations depend on this scope. | Rehash originals; compare compiler starts/fixup memberships independently; match six IDB ranges. Require separate native loaded-image evidence before assigning these bytes to a running process. |
| DL2 | The two inherited startup frames contain the explicitly declared bank/table/register values and preserve the relevant objects across their selected paths. Startup reductions depend on this partial contract. | Recover every predecessor, frame producer and alias/write before asserting whole-main reachability. Current main fragments and callback pointer setup are retained; native entry/creation continuity remains unproved. |
| DL3 | Original bank bytes, selected pointer records and ABI-preserved state remain intact. Static call/branch reductions depend on those values. | Exhaust all 256 indices for 29 cases, verify original slot/addend/target and authentication metadata, reject a changed bank or a wrong-bank callee. Hardware PAC remains untested. |
| DL4 | Callback objects/records are valid and disjoint; component frames and callee-saved registers satisfy their ABI. Event/peer forwarding depends on this. | Compare exact saves/loads, descriptors, callback addresses and selected continuations; compile reconstructed layouts; reject callback/size/flag changes. Native object delivery, aliasing and lifetime remain unknown. |
| DL5 | R is 8 B-aligned; address/control arithmetic has the recorded 32/64-bit widths. Selector and stack formulas depend on those restrictions. | Prove the unreduced formulas over all declared bit patterns; retain the unwritten record word and unknown post-call slot value; do not generalize scalar bounds to native memory validity. |
| DL6 | Public API names/layouts supply interface meaning; actual token contents, peer provenance, native admission and downstream protected behavior are unknown. | Follow the named audit getter and later consumers into their actual object/epoch before assigning authorization. Current token destination size and calls establish an acquisition boundary only. |
| DL7 | Prior endpoint/registration results keep their stated evidence scope. Current tools expose no IDA knowledge-store search method. | Preserve prior artifacts; retain actual IDA metadata/bytes without inventing recall results; keep logical service correspondence separate from observed native port identity and successful exchanges. |

## Bounded additional context

| Impact | Pattern / consequence | Remaining boundary |
|---|---|---|
| High | The sixth named endpoint has distinct listener/peer/event callbacks and a protected application path. | Whole native startup, actual receive/send syscalls, port objects and delivery remain unknown. |
| High | Other error objects share the application-forwarding continuation with dictionary events. | Lower object handling, payload parsing, replies and policy decisions remain unproved. |
| High | Audit acquisition and peer capture are separate inputs to the protected prefix. | Token authenticity, peer/port pairing, authorization use and cross-request lifetime remain unknown. |
| Medium | The aligned local control word recovers selector`0x77a0`, while a separate slot carries stack adjustment. | Internal record/control ABI is established within its model; serialized command and complete stack/memory effects remain unknown. |
| Low | Modifier constants and bank keys recur across unrelated call sites. | Both pointer-bank provenance and matching original auth metadata are required for each target assignment. |

## Validation and quality gates

Fresh recapture, 1623 instruction decodes, 60 selected instruction assertions, 21 SDK assertions, three unsatisfiable scalar queries, eight classifier cases and eight rejected evidence alterations pass. Four complete compiler spans, eleven fragments, 29 bank cases/7424 byte inputs, fifteen resolved calls, nine branch bindings, 42 selected pointers, 1005 compiler starts, 61737 fixup memberships and six IDB ranges/2820 B are retained. Models and proofs are analyst-written bounded semantics; no recovered machine code is executed or emulated in this increment.

Capture/verification is O(B+F+I+256K) time/space for image bytes B, fixup metadata F, selected instructions I and bank cases K; SDK/solver costs are separate. Each scalar query has a 10 s timeout. The peer callback is straight-line at its selected API boundaries; event continuations use the explicit classifier/ABI assumptions. Original startup and the protected application's larger CFG are not proved by these local checks. Publication/audit is O(total artifact bytes + local links). All extents are in B; widths and alignment domains are explicit.

QG1: Factual endpoint, routine and data/control-flow analysis requires no normative premise.

QG2: DL1-DL7 identify assumptions, dependent findings and falsification probes.

QG3: Conditional startup setup, callback records, event classifier, cancellation/forwarding sites, local application ABI and audit-acquisition prefix are covered. Full interface recovery and native end-to-end interaction remain active and unproved.

QG4: Byte extents, pointer levels, 32/64-bit arithmetic, block/record fields, proof domains and complexity are checked and reproducible.

QG5: Complete compiler spans versus complete semantics, startup frame contracts versus native execution, XPC objects versus Mach names, internal selectors versus wire schema, API cancellation versus lower right retirement, and audit acquisition versus authentication remain distinct.

QG6: Original bytes/fixups, exact imports, independent dyld_info starts/memberships, IDB byte matching, SDK/tool hashes and solver queries provide provenance. Unavailable knowledge-store access and all native gaps are explicit.

QG7: Impact-labeled endpoint, error-forwarding, audit/peer and local-ABI patterns are bounded above. No actual peer admission, successful daemon/kext processing or broad-goal completion claim is made.
