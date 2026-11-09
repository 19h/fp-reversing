# XPC consumer routing and the A70E6EB4 protected-core bridge

The selected XPC path now supplies the previously unresolved upstream phase for the `0xa70e6eb4` constructor. Its fallback branch builds a 72 B record containing the copied request, full 64-bit length, saved peer, 32-byte audit token and two local output addresses. It invokes adapter `0x10065ffd8` with primary tag `0x6cf4` and operation `0xa70e6eb4`, reaching the same protected-core entry used by the retained MIG paths. This is a conditional static caller/callee connection. Native delivery, credentials, authorization outcome, complete getter semantics and a successful daemon/kext exchange remain unknown [CB1-CB7].

Evidence: [original source and prior-byte recaptures](triage_evidence/daemon_xpc_core_bridge_source.json), [checks and retained queries](triage_evidence/daemon_xpc_core_bridge_checks.json), [capture](triage_evidence/recover_daemon_xpc_core_bridge.py), [validator](triage_evidence/validate_daemon_xpc_core_bridge.py), [preservation](triage_evidence/daemon_xpc_core_bridge_delivery.json), and [quality gates](triage_evidence/daemon_xpc_core_bridge_quality_gates.json). The pinned daemon SHA-256 remains `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Local references suffice; no new IDA read, native request, recovered-code execution or emulation is performed.

```text
XPC event / saved peer / audit-token acquisition
  -> dictionary data -> copied request M, full length L
  -> parser / linked lookup / local consumer word V
       +-- V=88594abe -> acquisition record593d + captured header token
       +-- V=ab924931 -> separate malloc(16) branch
       `-- other V -> B72(request,length,peer,audit,outputs)
                       + protected F32(tag6cf4,operationa70e6eb4,B72)
                       -> adapter65ffd8 -> core61a2d0
                            -> retained A70 record/token consumers
                            -> conditional SecTask entitlement-query path
```

## Local consumer partition

V is the u32 loaded from local SP+`0x82c`. Its complete production by the value getter is not yet proved. The [lookup report](daemon_xpc_iteration_report.md) establishes the preceding local interfaces; it does not establish that every caller error writes V or that a remote sender can select arbitrary V [CB4,CB6].

| V bit pattern | Selected target | Established next role |
|---|---|---|
| `0x88594abe` | `0x100aa689c` / index `0xa637` | Copy audit token; build acquisition record; call `0x10043e280` |
| `0xab924931` | `0x100c54704` / `0x2d1b` | Initialize local slots and request malloc(16 B); later behavior unknown |
| All other u32 values | `0x100a86c64` / `0x2d1d` | Build fallback records and enter shared protected adapter |

The signed split at `0x100d281e0` compares V against `0xab924931`. The lower equality reduces to `0x88594abe`; the upper equality is exactly `0xab924931`. A bit-vector proof covers all 2^32 patterns. Both unmatched paths establish **W19=`0x4f79`**. These are local control values, not recovered wire opcodes, public error codes or semantic command names.

## Request, peer and audit record

Let S be the selected current frame SP, B=S+`0x850`, and F=FP-`0xa0`. The inherited [listener](daemon_xpc_listener_report.md) and [payload](daemon_xpc_payload_report.md) contracts supply the saved peer, audit destination, copied buffer M and encoded L.

| B72 offset | Width | Source-produced field / producer |
|---|---:|---|
| +0 | 8 B | M from SP+`0x820`; stored at `0x100a86c90` |
| +8 | 8 B | Full unsigned L, recovered from SP+`0x498` XOR `0x0753df66dd8ff1b7`; store `0x100a86c94` |
| +16 | 8 B | Saved XPC peer pointer from SP+`0xc0`; store `0x100a86c9c` |
| +24 | 32 B | Token bytes from SP+`0x3c4`; copy call `0x100a86d04` |
| +56 | 8 B | Address S+`0x408`; store `0x100a86d10` |
| +64 | 8 B | Address S+`0x6e8`; store `0x100a86d14` |

The last two fields are addresses of local output cells. Their complete result types/initialization and eventual ownership are unknown; they are not assigned Mach-port types. The full L forwarding is distinct from the preceding low32(L)-byte copy. Its downstream extent interpretation remains to be traced, without inferring a native fault or accepted oversized request.

At call `0x100a86d04`, X0=source token, X1=B+24 and W2=32. Exact bank selection resolves local helper `0x10046f89c` / slot `0x10109fc88`, IA modifier `0x34a1`. Its loads use X0 and stores use X1: this is source-first, unlike the usual imported memcpy argument order. No imported memcpy identity is assigned.

| Selected call | Source/destination residues modulo 8 B | Source-established 32 B copy path |
|---|---|---|
| Fallback `0x100a86d04` | 4 / 0 | Four iterations of eight byte load/store pairs |
| Special branch `0x100aa6928` | 4 / 4 | Four-byte prefix, three 8 B pairs, four-byte tail |

These residues follow from 16 B-aligned S and offsets `0x3c4`, `0x868` and `0x784`. Two explicit path ledgers retain 43 load/store instances. Original pair operands and counter arithmetic are checked; each path covers offsets 0-31 exactly. Two symbolic 256-bit copy obligations prove unchanged token contents under the disjoint-buffer/path assumptions. The complete 604 B/151-instruction helper is retained, but arbitrary lengths, overlap and other alignments are outside these copy theorems [CB3-CB5].

## Protected F32 and shared adapter

For r=low32(F), define K=`u32((r XOR 0xeaae0ac9)*0x7398180b)` and U=S+`0x270`. The current fallback builder produces:

| F offset | Width | Established representation |
|---|---:|---|
| +0 | 8 B | U XOR `0x1c0b9f7ce10f2255` |
| +8 | 4 B | `0x6cf4 XOR K` |
| +12 | 4 B | `0xa70e6eb4 XOR K` |
| +16 | 8 B | B72 pointer |
| +24 | 4 B read after return | Result slot not produced before the call; higher bytes remain unknown |

The earlier [operation-head report](daemon_operation_heads_report.md) proved this constructor's tag equals `0x6cf4` iff its incoming phase is `0x4f79`, while leaving that upstream phase unresolved. The current consumer partition supplies exactly that phase. Three retained original obligations for the aligned prekey, field codec and phase equivalence are freshly re-solved, with original source bytes independently recaptured. This closes that **static upstream phase/target gap** under CB1-CB5; the historical reports' native admission/setup limits remain in force.

| Call site | Original slot / modifier | Resolved target and arguments |
|---|---|---|
| `0x100a86e3c` | `0x1010a0638` / IA `0xea64` | `0x10065ffd8`; X0=F, X1=&local stack-delta word |
| `0x10066022c` | `0x1010a17b8` / IA `0xedd6` | `0x10061a2d0`; X0 remains F, X1 points to adapter-local budget storage |
| `0x100aa6a14` | `0x10109fe88` / IA `0x6aa4` | `0x10043e280`; separate acquisition record below |
| `0x100c54774` | `0x10109ff58` / IA `0x6aa4` | Exact `_malloc`, W0=16 B |

X1 at the shared-core call is a budget/output protocol pointer, not B72. B72 travels through F+16. Static register-access checks establish that the adapter does not replace X0 before the call. The returning adapter prefix ends at `0x100660254` (159 instructions); its compiler interval continues to `0x100873194` (2175420 B total). The prefix is not labeled a complete compiler function or complete semantic recovery.

The caller reads a runtime word through cell `0x1010c4d68`. No native value is assigned. For its incoming 64-bit seed V, the adapter's local hint is:

```text
hint = ((top4((V*0x2e95+1) mod 2^64)<<4)+31) AND 0x1f0
     in {16,32,...,256} B
temporary budget initially V-0xe0
delta = low16(u32(returned_budget)-low32(V))*16 B
      in {0,16,...,1048560} B
```

The caller applies delta to SP, then reads raw u32 F+24 through FP. The actual returned budget, complete core effects, restoration, result meaning and downstream cleanup remain unknown. Arithmetic bounds do not attest native stack mapping or successful return [CB3-CB5].

## Conditional policy and synchronization correspondence

The retained [shared-core dispatcher](daemon_core_dispatch_report.md) maps operation `0xa70e6eb4` to `0x100592ebc`, under its declared setup/export assumptions. Its [handover](daemon_mig_handover_report.md) reads B+0/+8/+56/+64, copies B+24's 32 bytes and requires B+0, B+56 and B+64 to be non-NULL for the deeper path. These fields now have concrete XPC-side producers. Under a valid nonwrapping owner frame and the preceding successful M allocation, both local output addresses and M satisfy that pointer partition. This is not proof of their full pointee lifetime or of every shared-core global premise.

The retained [record40 consumer](daemon_record40_consumer_report.md) follows the same A70 token into a query for `com.apple.private.fpsd.client`: conditional CFString creation, `SecTaskCreateWithAuditToken`, then `SecTaskCopyValueForEntitlement`. Those reports' imported-data and modeled framework-result assumptions are preserved; no framework experiment is replayed here. The new evidence links the upstream XPC token/record producer to that retained source contract. Actual token bytes, trusted sender provenance, created task identity, entitlement value and final authorization remain unknown [CB6-CB7].

The special `0x88594abe` branch instead reads the pointer-sized contents of global header `0x1010c4cd8`+16, stores that token at acquisition-record+8, and encodes control `0x593d` at +0. Its aligned prekey normalizes to `r XOR 0x987eac8a`, followed by multiplier `0x316f29c1`. The exact callee is the acquisition adapter previously analyzed in the [synchronization report](daemon_iokit_sync_report.md): once handling and a conditional write-lock request. The captured token is a new caller-side source; it is not equated with that report's different IOKit primary cell or a native lock object. This branch also copies the same token32 into S+`0x784`. Copying a token or requesting acquisition does not prove an authorization decision or successful native locking.

## Getter and transport boundaries

Additional getter fragments are retained as locators: a buffer-length gate at `0x100ca22c0`, a 232-instruction two-byte decoder at `0x1009e57e0`, and its u16 store to SP+`0x8ce` at `0x100be4ee0`. Full writer/mask correspondence, getter output initialization and extraction remain unproved in this increment. The earlier physical decoder/reference material under `/Users/___/Downloads/fpx/analysis` supplies useful locators, but equivalent semantics are not transferred between differently obfuscated readers without fresh comparison.

No new Mach send/receive, port extraction, descriptor/right transfer, XPC reply emission or IOKit request is established by these caller fragments. Peer pointers, token bytes, budget words, local outputs and synchronization tokens remain distinct from Mach names. The shared core is also used by retained MIG paths; this does not equate their wire schemas or endpoint admission policies. A successful native daemon/kext transaction remains unproved.

## Assumption register

| ID | Assumption and dependent findings | Stress test / falsification probe |
|---|---|---|
| CB1 | Pinned daemon and preserved prior captures define the source build. | Rehash original; recapture current and 49 prior ranges/19016 B; compare independent function starts/fixups. Require native build pairing separately. |
| CB2 | Original bank/table values and authentication metadata hold. | Exhaust 1792 byte inputs over seven cases; verify six original call words and nine branch bindings; reject wrong target/modifier. Hardware PAC is untested. |
| CB3 | Current S/FP alignment, valid nonwrapping stack owner, object lifetime and declared disjoint copies hold. | Verify prologue/frame origins and all alias writes; retain unwritten result/padding; do not generalize copy paths, delta ranges or local addresses into native mappings. |
| CB4 | Inherited XPC getter/peer/token/frame values survive the selected path; V is an arbitrary local word, not a proved wire command. | Recover full getter, error-output initialization, every predecessor/alias and the successful return protocol before asserting native continuous execution or external control of V. |
| CB5 | W/X arithmetic, source-first copy direction, aligned record codec and formal proof cuts match source. | Fresh scalar queries, token-bit ledgers, compiler boundaries and SDK layouts; remove alignment to retain the prior counterexample boundary. |
| CB6 | Retained A70 setup, token consumer and framework contracts keep their original conditional scope. | Establish actual core globals, allocator/task/string results, matching frameworks and policy outputs before claiming native SecTask/entitlement outcomes. |
| CB7 | Token lineage, logical service association and reused adapters do not by themselves establish sender identity or cross-level exchange. | Match real event/audit/peer/port epochs and full request/reply traces; keep kext, MIG, XPC and local record contracts separate. |

## Bounded additional context and validation

| Impact | Established pattern | Remaining boundary |
|---|---|---|
| High | XPC fallback supplies the former phase4f79/tag6cf4/A70 constructor gap. | Shared-core runtime setup and native continuity remain unproved. |
| High | Request, full L, peer, audit and outputs converge in one 72 B record. | Downstream extent interpretation, identity, output ownership and replies are unknown. |
| High | A retained token-to-entitlement-query path now has this upstream source connection. | Framework results and final authorization remain unknown. |
| Medium | The special branch reuses acquisition code with a distinct header-derived token. | Native token/lock identity and concurrency remain unknown. |
| Medium | Copy paths differ by alignment; the adapter compiler interval greatly exceeds its returning prefix. | Whole-helper/whole-function semantic claims remain excluded. |

Fourteen retained ranges contain 968 instructions/3872 B, including one complete 604 B copy-helper compiler function. Seven bank cases cover 1792 inputs; six calls, nine branch bindings and 14 selected pointers are checked. Independent current output matches 1005 compiler starts and 61737 fixup memberships. Forty-nine prior ranges/19016 B match the original image. Checks pass 50 selected instruction assertions, 17 SDK assertions/one compilation, ten unsatisfiable queries (including three freshly re-solved prior originals), eleven boundary-word models, two copy paths/43 entries and eight rejected evidence alterations.

Capture/checking costs O(B+F+I+256K+R) time/space for image bytes B, fixups F, current instructions I, bank cases K and prior reference bytes R. Solver/compiler costs are separate. Two fixed 32 B copy paths take O(32) time/O(1) scalar workspace; no general overlap theorem follows. Publication/audit costs O(total artifact bytes + local links). All extents are in B and arithmetic widths are explicit. No recovered code executes or is emulated; no native target/framework/IPC/IDB state changes.

QG1: Factual interface analysis requires no normative premise.

QG2: CB1-CB7 identify dependent findings and falsification probes.

QG3: The local consumer partition, token copies, B72/F32 records, selected targets, old phase gap and conditional policy correspondence are covered. Full getter, dispatch/response and native interaction remain active.

QG4: Full-u64 L versus low32 copy extent, source/destination order, copy alignment, record offsets, stack formulas and compiler extents are checked.

QG5: Local V versus wire command, current static connection versus retained framework models/native execution, phase-gap resolution versus complete policy proof, and returning prefix versus compiler function remain distinct.

QG6: Original bytes, independent current fixups/starts, freshly solved original queries, prior range recaptures, SDK/tool hashes and explicit ledgers provide provenance. Unknown native values are not supplied.

QG7: Impact-labeled bridge, record, policy, synchronization and boundary observations are bounded above; no completed authorization, native exchange or full-goal claim is made.
