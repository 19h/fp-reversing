# CoreADI adid: receiver, entitlement classifier and CoreFP error ABI

The original provider now has a recovered per-peer setup path, event callback, audit-token/data adapter, protected context gate and local `adi-client` classifier. Fifty entitlement bit patterns pass the inspected classifier. The CoreFP 28-byte request reaches the provider's original header decoder under explicit initialized-prefix fixtures. Six source request/error-response pairs connect provider output to CoreFP's original return value.

The broad daemon/kext/deeper-interface investigation remains active. Native endpoint identity, full provider startup, successful operations, complete ownership and legacy Mach compatibility remain unknown.

## Source identity and assumption register

Provider: `/System/Library/PrivateFrameworks/CoreADI.framework/adid`, universal SHA-256 `58eeb13dade3e1867641345b38961344fe53e6319928a1503bdb3315681fe929`; selected arm64e SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. Provider addresses below are original preferred virtual addresses, base `0x100000000`. CoreFP offsets retain the base-zero convention and identity in the [client-path report](corefp_client_paths_report.md).

IDA Assist was unreachable during this increment. Original file bytes, chained pointers, static tools, SDK/compiler evidence and bounded private execution supply the findings. Target executables, native loaders/frameworks, host IPC, host environment queries and host synchronization APIs were not executed.

| Assumption | Dependent findings | Stress test / falsification boundary |
| --- | --- | --- |
| A1: pinned originals define the reference images | Addresses, strings, imports, pointer targets and source pairing | Fresh image hashes, all 11451 chain members, independent `dyld_info`, retained instruction bytes and complete compiler bounds agree. Actual loaded image selection remains unknown. |
| A2: function-start bounds and supplied local entry arguments define these experiments | Peer setup and event-handler roles | Complete small bodies and source visits are retained. The block capture and installed callback are checked. Main-to-listener publication and native block ownership are not established. |
| A3: declared PAC, lock, sequential-atomic, allocator/mapping, randomness and API models permit the selected continuations | Initialization prefix and continued execution | Initial opaque boundaries, failed mapping, cold context, vector boundary and explicit continued cases are separate. Compiler output corroborates the modeled XOR3 operation and audit aggregate ABI. Hardware PAC, concurrent ordering and native API behavior remain unverified. |
| A4: the recovered numeric conversion prefix applies to the local classifier | The 50-value set and numeric/string cases | Source cases check constant `0x3f4f8085` and shift 1. Full 32-bit SMT covers the arithmetic and signed decision CFG. Every listed bit pattern reaches original header reads. This is a local gate result, not a complete native authorization policy. |
| A5: explicit XPC, audit and Security results represent the stated private cases | Entitlement lookup, parsing and response pairing | The exact 32 audit bytes reach original Security/audit boundaries. Numeric, string, absent and other-type boundaries are retained. Effective native peer entitlements, Security failures and all conversion errors remain unknown. |
| A6: the retained startup-prefix state can seed an isolated receiver experiment | Context-enabled parsing and deeper facilities | The original prefix publishes the context pointer and stops at `getuid`. It is not full startup. A NULL installation-environment case reaches an unresolved private read and is retained without a native fault claim. |
| A7: the observed input/output bytes establish a local ABI between these originals | Six error pairs, parser status and cleanup | Exact request bytes and source-produced response bytes are compared across images. Endianness, three-byte and NULL-data controls differ as reported. Native XPC delivery, live service identity, successful operations and legacy Mach compatibility remain unobserved. |

Evidence: [original inventory](triage_evidence/adid_inventory.json), [static contracts and full mapping](triage_evidence/adid_receiver_contracts.json), [provider cases](triage_evidence/adid_receiver_profiles.json), [initialized-prefix snapshot](triage_evidence/adid_initialized_context_snapshot.json), [paired CoreFP cases](triage_evidence/adid_client_pair_profiles.json), [checks](triage_evidence/adid_receiver_checks.json) and [quality gates](triage_evidence/adid_receiver_quality_gates.json). Long visit/event streams use lossless zlib/base64 encoding; original ordered-byte digests and decoding code are retained.

## Pointer format and receiver chain [A1-A3]

This provider uses `DYLD_CHAINED_PTR_ARM64E` format 1, with 16-bit bind ordinals and absolute unauthenticated rebase addresses. Authenticated rebase targets are image offsets. Import format 2 supplies signed import addends. These differ from CoreFP's format-12 userland pointers. All 11451 members and 129 imports match independent static-tool output, including large data-symbol addends. The image declares 99 compiler function starts.

```text
launchd declaration: com.apple.adid -> CoreADI adid
  [native publication and main-to-listener chain remain unknown]

local peer setup 0x1000009f8
  -> set target queue -> install captured-peer event block -> resume
  -> callback 0x100029fc8
     -> classify event / handle invalid connection
     -> adapter 0x1000aa0ec
        -> create reply -> get audit token[32] -> get data
        -> encoded private record[48] -> core 0x1001661f8
           -> initialized context -> adi-client classifier
           -> input header -> effective UID/setup branch -> arguments
        -> reply data -> send reply -> release/encoded disposal
```

| Boundary | Original callsite / recovered argument |
| --- | --- |
| Peer target queue | `0x100000bdc`; peer from setup X1, queue from block capture +32 |
| Install peer event handler | `0x100000d00`; stack block invoke `0x100029fc8`, capture +32 is that peer |
| Resume peer | `0x100000d40` |
| Event type | `0x10002a1bc`; dictionary path queries again at `0x10002a37c` |
| Exact invalid-error identity | Source comparisons at `0x10002a204` / `0x10002a2b8`; the private invalid event cancels its captured connection and returns |
| Create reply | `0x1000aa3f0`; NULL result reaches cancellation at `0x1000aa680` |
| Extract audit token | `0x1000aa4c0`; 32 bytes copied into the protected call context |
| Extract input field | `0x1000aa598`; key `data`, pointer plus 64-bit size output |
| Enter protected core | Parent `0x1000aa8fc` -> `0x1001661f8` |
| Set outgoing field | `0x1000aa9fc`; key `data`, pointer and byte count |
| Send XPC reply | `0x1000aaa70` |
| Release reply | `0x1000aaac0`; subsequent encoded disposal call at `0x1000aab50` |

The peer-setup and handler entries use their explicit local block arguments. No shared native object identity is assigned to private fixture names. Other event types return outside the protected-record handler. Generic error-object continuations depend on explicit modeled reply API results; they do not establish native XPC error-object behavior.

## Protected record and initialization gate [A1,A3,A6]

| Offset | Width | Observed role |
| --- | --- | --- |
| 0 | 32 bits | Address-encoded operation |
| 4 | 32 bits | Core status output |
| 8 | 64 bits | Input byte pointer |
| 16 | 64 bits | Output-pointer cell address |
| 24 | 64 bits | Address-encoded input byte count |
| 32 | 64 bits | Pointer to copied audit token |
| 40 | 64 bits | Output-length cell address |

For record address R, all following arithmetic is modulo 2^64, with `low32` truncation for the operation:

```text
H = ((((0xfe69be85c31ad656 OR (R << 1)) - R
       + 0x80cb20bd1e7294d5) XOR 0x1f6967cae97a38fd)
     * 0x255e728d)
encoded operation = 0x0d5b - low32(H)  [modulo 2^32]
encoded input size = input size + H
```

The full-width SMT obligation checks these local inverse arithmetic relations. It does not prove every core operation or input contract.

Getter `0x1000621d4` resolves context cell `0x1002dd2e8`; three exhaustive 256-input bank identities independently resolve its protected state/cell pointers. At `0x10006234c` the getter loads the cell and branches on zero. Cold cases with reported input sizes 0, 27, 28 and 29 return core status `0xffff5036` (-45002), NULL output and zero output size before any input payload read. They therefore provide no payload-schema rejection evidence.

An original startup prefix performs two modeled 65536-byte anonymous mapping requests at `0x100011b78`, sets the context cell at `0x10001218c`, initializes protected state using five modeled random words, and stops at `getuid`, callsite `0x100014374`. Its DATA/heap/mapping snapshot seeds the continued cases. This initialization is an explicit partial prefix. The failed-mapping branch reaches `ptrace` request 31 and the constructed query `kern.hv_vmm_present`; no host query occurs.

## Entitlement conversion and exact local classifier [A1,A4,A5]

| Stage | Original boundary / result |
| --- | --- |
| Extract peer PID | `audit_token_to_au32` at `0x100168c3c`; only PID output requested in the observed call |
| Construct key | `CFStringCreateWithCStringNoCopy` at `0x100168e18`; literal `adi-client`, encoding `0x600` |
| Create Security task | `SecTaskCreateWithAuditToken` at `0x100169100`; copied peer audit token |
| Retrieve entitlement | `SecTaskCopyValueForEntitlement` at `0x1001691c8` |
| Numeric form | Type-ID checks, then `CFNumberGetValue` at `0x1001699e0`, type 3 = `kCFNumberSInt32Type` |
| String form | CFString conversion and `strtoul` at `0x1001698bc`, base 10; retained suffix/end-pointer check |
| Diagnostic peer path | `proc_pidpath` at `0x100169ac8`, PID from the audit extraction, capacity 4096 bytes |
| Classifier | Signed 32-bit branch tree starting `0x100169ad4` |

The local numeric fold is `n + C - ((n << 1) AND 0x7e9f010a)`, with C=`0x3f4f8085`, modulo 2^32. It is exactly `n XOR C` over the complete 32-bit domain. The original signed CFG has 50 listed keys, a separate zero-value key C, and an unlisted remainder. The CFG/membership equality is independently discharged by SMT. Values below are 32-bit bit patterns after signed conversion; high-bit patterns denote negative signed values.

| Entitlement value bits | Encoded classifier key |
| --- | --- |
| `0x3d4f2a70` | `0x0200aaf5` |
| `0x3334658e` | `0x0c7be50b` |
| `0x322dbcc2` | `0x0d623c47` |
| `0x31034e37` | `0x0e4cceb2` |
| `0x30f19e1e` | `0x0fbe1e9b` |
| `0x2927be59` | `0x16683edc` |
| `0x28422035` | `0x170da0b0` |
| `0x276af5d6` | `0x18257553` |
| `0x278e1e62` | `0x18c19ee7` |
| `0x2698cb0a` | `0x19d74b8f` |
| `0x257a338f` | `0x1a35b30a` |
| `0x247a7928` | `0x1b35f9ad` |
| `0x23e9469d` | `0x1ca6c618` |
| `0x221d76c5` | `0x1d52f640` |
| `0x22ce38ca` | `0x1d81b84f` |
| `0x2156a653` | `0x1e1926d6` |
| `0x20aa484f` | `0x1fe5c8ca` |
| `0x193b923c` | `0x267412b9` |
| `0x19a9bedc` | `0x26e63e59` |
| `0x186d9789` | `0x2722170c` |
| `0x18f46381` | `0x27bbe304` |
| `0x176bc846` | `0x282448c3` |
| `0x169c295c` | `0x29d3a9d9` |
| `0x1525f36e` | `0x2a6a73eb` |
| `0x14e33aa2` | `0x2bacba27` |
| `0x14b5378f` | `0x2bfab70a` |
| `0x132b99c7` | `0x2c641942` |
| `0x12cd4b6c` | `0x2d82cbe9` |
| `0x1103fb2a` | `0x2e4c7baf` |
| `0x09eb86c2` | `0x36a40647` |
| `0x7f1e8925` | `0x405109a0` |
| `0x73223b03` | `0x4c6dbb86` |
| `0x66509c60` | `0x591f1ce5` |
| `0x58e6a405` | `0x67a92480` |
| `0x4eb6517e` | `0x71f9d1fb` |
| `0x41c05a92` | `0x7e8fda17` |
| `0xbdd072fe` | `0x829ff27b` |
| `0xbc0cd56f` | `0x834355ea` |
| `0xb86d9a5d` | `0x87221ad8` |
| `0x9a1a5b57` | `0xa555dbd2` |
| `0x92d5b25c` | `0xad9a32d9` |
| `0x8b26bc33` | `0xb4693cb6` |
| `0xfa6fde94` | `0xc5205e11` |
| `0xf6079b58` | `0xc9481bdd` |
| `0xf31cfb29` | `0xcc537bac` |
| `0xeb8fe111` | `0xd4c06194` |
| `0xe82823a7` | `0xd767a322` |
| `0xe063d901` | `0xdf2c5984` |
| `0xde29996d` | `0xe16619e8` |
| `0xc4e15197` | `0xfbaed112` |

Every listed numeric pattern reaches exactly the 12 original byte loads for the request header before the effective-UID API boundary. A listed complete decimal string reaches the same boundary. In the retained string controls, `1` retains the numeric-one classification, while `1junk` reaches the zero-value classification despite `strtoul` consuming the initial digit. String overflow, all malformed encodings and all Security/CF failure results remain open.

A listed value with modeled `proc_pidpath` failure also reaches header decoding. The inspected suffix branches on the encoded entitlement value, rather than the return status of this diagnostic lookup. A successful process-path lookup does not make an unlisted entitlement pass.

## Provider error response and CoreFP pairing [A4,A5,A7]

```text
CoreFP original constructor: one of -8,-6,-5,-4,-3,-2
  -> XPC data[28], exact bytes retained
  -> provider with unlisted adi-client value 1
     -> no payload reads
     -> core status 0, output length 4
     -> data = ff ff 4f f2 -> send reply
  -> original CoreFP response parser
     -> W0 = 0xffff4ff2 (-45070) -> modeled cleanup -> return
```

Six provider cases use the exact six original client requests. Their adapter/core status is zero, while their four-byte big-endian application status is `0xffff4ff2`. These two status layers are distinct. All six source responses are passed to the original CoreFP parser; all return the same 32-bit application status. The original source reaches reply setting, sending, release and encoded disposal under the stated API models. Complete native ownership and send-failure behavior remain unknown.

| Client response control | Original CoreFP private result |
| --- | --- |
| Actual provider `ff ff 4f f2` | `0xffff4ff2` |
| Counterfactual little-endian `f2 4f ff ff` | `0xf24fffff` |
| Counterfactual four-byte zero only | 0; successful application semantics remain unknown |
| Reported response extent 3 bytes | `0xffff5016` |
| NULL data pointer | `0xffff5028` |

The client parser preserves the source response's big-endian 32-bit status. The constructor's opaque X1 value is still not assigned a pointer, account or identity meaning.

## Header, effective UID and deeper context [A3-A7]

The listed-value path reads header bytes 0..11 in order, matching the client words `[1,0x632b8d6e,1]` in big-endian form. It then calls `audit_token_to_euid` at `0x10016cb30`. The modeled nonroot case reaches `lstat("/var/db/.AppleSetupUser")` at `0x10016cc24` after only those 12 payload reads. Its complete setup-file policy remains unknown.

With modeled effective UID zero, the original path reads all 28 client bytes and reaches the deeper write lock at `0x1001057a0`, object `0x1002dc9d0`. Continued lock fixtures reach `getenv("__OSINSTALL_ENVIRONMENT")` at `0x100107650`. With private value `1`, original code constructs `/Users/Shared/adi/adi-00000000.pb` and reaches `lstat` at `0x1001237dc`. No host environment or file operation executes.

With a NULL environment result, the incomplete-prefix fixture reaches an unresolved read at `0x10010a050`, with X21 zero and effective address `0xf76afc6a130e5888`. The additional context/registration needed by that path is unknown. This is retained as a private initialization boundary, without a native defect or reachability claim.

The image imports IOKit service/open/call APIs, but this increment does not connect the examined operation to an actual IOKit call. The legacy 56-byte Mach-1200 receiver and underlying XPC Mach-message/right ABI also remain unknown.

## Validation and bounded continuation

The increment passes **80120 assertions** across **126 provider cases and 10 client-pair cases**. Fresh readback covers 11451 original fixups, 129 imports, 14608 provider and 2018 CoreFP instruction records, 2877757 retained provider source visits, three exhaustive byte banks and three full-domain SMT obligations. Original supplied inputs and IDBs remain preserved. These checks support the stated local claims; they do not complete the broad investigation.

The [arm64e layout and ABI model](triage_evidence/adid_receiver_layouts.c) compiles against the installed SDK. Fresh compiler output matches the [retained assembly](triage_evidence/adid_receiver_layouts.s), including `eor3.16b` for XOR of three 128-bit vectors and X6/stack lowering for the optional audit PID output. This corroborates the explicit private instruction/API models; it is not a native provider execution.

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/adid_reader.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_adid_receiver.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_adid_receiver.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_adid_client_pair.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_adid_receiver_delivery.py
```

Static recovery/readback is O(B+F+R+V+256K) time and O(B+F+R+V) space for image bytes B, fixups F, retained code R, source visits V and bank identities K. The acyclic classifier is bounded by its retained source CFG. Private cases have explicit 100000- or 2000000-hook caps; CoreFP pair cases retain the inherited 30000-hook cap. SMT cost is separate, with 30 s/query limits. Byte widths and modular arithmetic are explicit; native timing is not measured.

| Impact | Next discriminating evidence |
| --- | --- |
| High | Complete provider startup after `getuid`, main-to-listener registration, process context callbacks and native namespace/peer identity. Recover the unresolved normal-environment context before promoting any failure. |
| High | Recover successful semantics for all six selectors and the remaining two 64-bit request fields; connect actual callers to X1's meaning. |
| High | Recover complete Security/CF conversion failures, list provenance/writers and subsequent effective-UID/setup policy; the 50-value local gate is not full authorization. |
| High | Establish whether the co-installed provider implements the client's legacy Mach fallback; compare actual server schemas and port/right ownership. |
| Medium | Follow persistent-record path construction, allocation/locking, file metadata, permissions, framing and lifecycle under normal and installation environments. |
| Medium | Connect protected operations to IOKit provider names, user-client types/selectors and deeper hardware or kernel facilities. Imports alone do not establish these routes. |
| Medium | Recover reply-send errors, restart/cancellation, request/reply object lifetime and underlying libxpc Mach emission/descriptor contracts. |

QG1-QG7 are scoped to the stated increment and assumptions. The broad interface objective remains active and incomplete; no external source-analysis blocker is asserted.

## Startup and lifecycle continuation

The [startup report](adid_startup_report.md) continues original main from the initialization prefix to the XPC listener and CF run loop. It connects main's generated block to peer setup and the message handler, preserves opaque shared-to-private record transfers and recovers the SIGTERM consumer/teardown path. With the same request/instruction models, the early checkpoint still reaches the unresolved read, while the listener checkpoint advances to `lstat("/var/db/fpsd/adi")`. This strengthens the private initialization-context distinction without assigning a native defect. Native pairing, successful operation semantics, remaining persistence/field contracts and ownership remain open.
