# Daemon arcade XPC reply type, status width and data boundary

The original daemon checks a non-null reply's XPC type, requires an existing signed64`status` object, and uses only the lower32 status bits in the recovered local zero predicate. Null/error/missing/wrong-type/nonzero-low32 cases do not reach `xpc_dictionary_get_data` in the tested paths. Sixteen finite private cases stop at an Objective-C path-conversion call; none completes the final61471 policy decision or emits a native reply. See the [companion service report](arcade_service_report.md) for the server side.

The later [policy/private completion report](arcade_policy_report.md) adds a source-produced96-byte reply that completes the original daemon stub with status0/decision0,and separately identifies a raw64 response field consumed through a32-bit comparison. Those new cases do not change the scope or stopped outcomes of the16 frozen profiles below;native IPC remains unexecuted.

The subsequent [receipt report](arcade_receipt_report.md) supplies144-byte responses that reach daemon [AppStore repair assembly](appstore_repair_report.md). Explicit private repair-return models then complete61571 with status0/decision1. Thus the stopped NSString path below is now connected to ASDRepairOptions/Service,not merely diagnostic handling;actual repair and native IPC remain unexecuted.

## Provenance and preparation [RP1, RP2]

The daemon source remains `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Five fresh read-only IDA windows match the original instruction bytes at`0x10074e158`, `0x100755b58`, `0x10072a148`, `0x1008348f8` and`0x1008ed718`. This supplements original-image evidence; no IDB was modified. See [readback](triage_evidence/arcade_reply_live_ida.json) and [original ranges/proofs](triage_evidence/arcade_xpc_contracts.json).

A fresh original initialization under the frozen subscription/base models completes after5668177 instruction/API steps. Its owned private checkpoint has a recorded SHA-256, source/dependency hashes, visited source-page hashes and explicit API log. Each reply case restores that state and runs the original61471 stub/application through the outgoing request and its own synthetic reply. No target process, host IPC, framework, loader, target filesystem operation or synchronization API executes. The checkpoint is synthetic private memory, not a native process snapshot. See [initialization provenance](triage_evidence/arcade_reply_initial_state.json), [reply harness](triage_evidence/probe_arcade_reply.py) and [sixteen profiles](triage_evidence/arcade_reply_profiles.json).

## Incoming reply contract [RP2-RP4]

| Stage | Original call instruction / check | Established fact |
| --- | --- | --- |
| Request/reply boundary |`0x10077e614` |`xpc_connection_send_message_with_reply_sync`; continuation`0x10077e618` receives the modeled result |
| Reply type |`0x10074e190` |Calls`xpc_get_type(reply)` after the non-null path; dictionary comparison follows |
| Status presence |`0x100755b84` |Calls`xpc_dictionary_get_value(reply,"status")`, then tests returned object for NULL |
| Status type |`0x10072a174` |Calls`xpc_get_type(statusObject)`; compares against`_xpc_type_int64` |
| Status value |`0x100834924` |Calls`xpc_int64_get_value`; API return is signed64 in X0 |
| Local zero predicate |`0x100834928..0x100834980` |Uses W0, discarding X0 bits63:32; conditional codec and table branch below |
| Response data |`0x1008ed748` |Calls`xpc_dictionary_get_data(reply,"data",&length)` |

These are logical XPC objects/keys. They do not reveal an underlying Mach port name or message descriptor layout. Existing [Mach port reporting](mach_ports_report.md) continues to distinguish XPC handles from the anonymous CF endpoint and kernel kobject rights.

Under the recorded entry values W22=`0x708e`, W26=`0x60cc`, the exact32-bit arithmetic after `xpc_int64_get_value` is:

```text
s       = low32(status64)
shift   = (0x708e XOR 0x708f) AND 31 = 1
encoded = (0x60cc + s - ((s << shift) AND 0x167b8ca2)
           + 0x8b3d6585) mod 2^32
        = s XOR 0x8b3dc651
branch  = (encoded == 0x8b3dc651) <=> (s == 0)
```

The codec proof ranges over all64 status bits with these explicit entry premises; the zero-equivalence proof ranges over all32 low bits. Both counterexample queries are unsatisfiable. The native instruction widths independently establish that this local predicate does not compare all64 bits. Universal recovery of the incoming register constants across every daemon state is not claimed.

| Signed64 synthetic status | Low32 | Reaches response-data API |
| --- | --- | --- |
|0 |`0x00000000` |Yes |
|1 |`0x00000001` |No |
|-1 |`0xffffffff` |No |
|4294967296 =2^32 |`0x00000000` |Yes |
|-4294967296 =-2^32 |`0x00000000` |Yes |
|4294967297 =2^32+1 |`0x00000001` |No |
|-42049, -42052, -42023 |Nonzero |No |

The last three values match the service's conditional error statuses. That correlation does not establish a successful transaction or a native producer of the high-bit status fixtures. A nonzero signed64 whose low32 bits are zero passes this local gate; subsequent data/policy checks still apply.

## Finite type, data and continuation observations [RP2, RP5]

| Case group | Observed local result |
| --- | --- |
| Null reply |No reply-type/data API; continues toward Foundation path conversion |
| XPC error reply |Type checked; no status/data retrieval |
| Dictionary without`status` |Status lookup returns NULL; no signed64 getter/data retrieval |
| Status object of dictionary type |Status type checked; no signed64 getter/data retrieval |
| Signed64 status with nonzero low32 |Getter reached; data API not reached |
| Status zero;`data` missing |Data API returns NULL/length0; no payload read |
| Status zero; present empty data |Data pointer/length0 returned; no payload read |
| Status zero; four zero bytes |Data API reached; no payload byte dereferenced in this case |
| Status zero;14-byte scalar frame |All14 defined bytes read by original code, within the supplied extent; later path conversion still reached |

The14-byte fixture is key0, tag`0x9777`, length4, payload BE32`0x8b3dc651`, structurally encoding scalar0 under the recovered codec. It is a parser fixture, not an established successful arcade response schema. Bounds/unknown-memory guards stop any read outside defined reply/heap bytes. Passing these cases does not prove safety or validity of all response records.

All16 cases reach `_objc_msgSend` through veneer return PC`0x100002158`, with receiver binding`Foundation/_OBJC_CLASS_$_NSString`, selector`stringWithUTF8String:` at`0x101034436`, and the prefix `/private/synthetic/ArcadeFixture.app`. The supplied source path was `/private/synthetic/ArcadeFixture.app/Contents/MacOS/Game`. Thus original code performs a bundle-prefix transformation before this boundary. The method itself is not invoked. Whether this leads to fallback validation, receipt processing, final rejection or another path is unknown; classifying it as completed diagnostic/error handling would overstate the evidence.

Each stopped snapshot still contains provisional output word1 at reply+36. The stub/application has not returned, so the snapshot's initially prepared reply header/status and word are not a completed MIG reply or final subscription result. The kernel's previously recovered action on a completed status/decision must not be attached to these unfinished cases.

## Reproduction and evidence limits

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_arcade_reply.py --build-snapshot
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_arcade_reply.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/arcade_service_reader.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_arcade_service.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_arcade_xpc_delivery.py
```

These commands use source-pinned analyst-side readers, Unicorn, Z3 and Clang. The service reader runs Apple's binary parser `dyld_info`; it never loads or executes the service. The initializer checkpoint is loaded only as an owned, hash-checked private artifact. Rebuilding it requires regenerating dependent reply and service profiles. Layout checks compile declarations for arm64e without linking/running target code. Extraction is O(B+F+I+S), with bytes B, fixups F, instructions I and SDK metadata S. A reply case is capped at2000000 private steps; initialization at10000000. Retained profiles/page sets determine analysis storage. SMT cost is separate from these linear extraction bounds.

## Assumption register

| ID | Assumption / dependent claims | Stress test or falsification probe | Status |
| --- | --- | --- | --- |
| RP1 |Current thin file and five IDA windows represent the investigated daemon |Rehash backing file, compare original bytes and selected runtime slice |Original/current IDA windows verified; runtime slice unknown |
| RP2 |Fresh private state, PAC bypass and opaque API models preserve the displayed paths |Vary API failures/caller-saved clobbers, library state and concurrency; compare native behavior independently |16 finite cases; no native/universal equivalence |
| RP3 |Entry W22=`0x708e`, W26=`0x60cc` for the displayed codec |Checkpoint registers immediately after the getter; establish full predecessor constants for all other states |All reached cases match; broader predecessor proof open |
| RP4 |Synthetic signed64/type results describe the intended API contract |SDK declaration compile; vary upper/lower bits and wrong/missing types |Signed64 getter declaration and selected width/type cases passed |
| RP5 |Minimal scalar data is structurally meaningful for parser exploration |Construct actual successful server output, vary tags/keys/nesting/extents and trace final decision |14-byte framing/read evidence only; successful response schema unknown |

## Bounded continuation and quality gates

| Impact | Next evidence | Purpose |
| --- | --- | --- |
| High |Continue the stopped NSString/bundle-prefix path with source-resolved Objective-C targets |Determine final output/status, fallback semantics and connection to kernel task action |
| High |Recover successful companion reply-data fields and feed the exact bytes through this path |Complete both sides of the XPC ABI and distinguish transport success from application success |
| High |Prove incoming status-codec register constants across alternate control states |Extend the conditional arithmetic theorem beyond the tested prefix |
| Medium |Resolve daemon event block`0x100460008`, connection reuse and disposal |Recover asynchronous error/lifetime behavior around synchronous calls |
| Medium |Vary caller-saved register clobbers, allocations and CF/Foundation failures |Test private-model ABI/definedness assumptions |
| Medium |Observe a matching native connection/right lifecycle and actual service eligibility |Bind logical XPC objects to real transport ports without conflating guest/native namespaces |

QG1 passes for descriptive analysis. QG2 registers RP1-RP5 and probes. QG3 passes for this reply-envelope increment; the broad objective is incomplete. QG4 supplies exact widths, equations, layouts, compile checks and complexity. QG5 separates signed64/low32 behavior, absent/wrong types, short data and unfinished MIG output. QG6 retains source/fixup/SDK/IDA/proof/private provenance. QG7 supplies impact-labeled continuation. See [checks](triage_evidence/arcade_xpc_profile_checks.json), [quality gates](triage_evidence/arcade_xpc_quality_gates.json) and [current manifest](triage_evidence/interface_manifest.json).
