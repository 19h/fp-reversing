# Arcade peer authorization, developer path and private protocol completion

Original companion code applies a `com.apple.fp.receipt` requirement to the code reference selected by the XPC peer's audit token. This is separate from both the connection's Apple-anchor/identifier requirement and the target application's path in the serialized payload. Modeled authorization success reaches a developer-signature check on that path. A modeled true result produces a96-byte response that completes the original daemon61471 stub with status0 and decision0. A modeled false result constructs the application's `_MASReceipt/receipt` path and reaches an original receipt class method. These are static contracts and finite private executions; native authorization, file/signature/receipt validity and actual IPC remain unknown.

The later [receipt/CMS report](arcade_receipt_report.md) extends the false branch through original receipt methods and conditional ownership conflicts. Its144-byte failure responses complete private status0/decision1 buffers and assemble the [AppStore repair request](appstore_repair_report.md). The earlier case counts and scopes below remain unchanged;complete native policy remains unknown.

## Evidence identities and scope [AP1, AP2]

The companion slice remains SHA-256`fed08b800dc88a83fb71b81008791faab457dca99b514ea01aed2fb6fffee694`, UUID`49af318e-c43d-3b3c-a874-3a602525133f`. The daemon slice remains SHA-256`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses in the following service tables belong to the companion, not the overlapping daemon VAs. Original instruction bytes are checked throughout private execution.

The installed reference cache UUID is`2bd06591-e751-3e84-963f-b08dab6af23a`; StoreFoundation UUID is`720edc42-efd7-37fa-a929-53d4163c0b11`. Cache code, original nlist names, selector stubs, version5 pointer-chain membership and exact Security/CoreFoundation exports are retained independently. Runtime pairing and Objective-C method replacement are unknown.

Artifacts: [original contracts](triage_evidence/arcade_policy_contracts.json), [service policy profiles](triage_evidence/arcade_service_policy_profiles.json), [daemon roundtrip profiles](triage_evidence/arcade_policy_roundtrip_profiles.json), [original Objective-C metadata](triage_evidence/arcade_service_objc_metadata.json). The frozen earlier [service](arcade_service_report.md), [reply](arcade_reply_report.md), [subscription](arcade_subscription_report.md) and [kernel registration](created_port_report.md) reports provide the preceding boundaries.

## Three identities and two peer gates [AP2, AP3]

| Subject | Source and check | Evidence boundary |
| --- | --- | --- |
| XPC connection peer |`xpc_connection_set_peer_code_signing_requirement` with Apple anchor plus identifier`com.apple.fairplayd` or`com.apple.lskdd` |Previously recovered literal/local zero-status gate; native enforcement unobserved |
| Peer code reference |Connection audit token ->`kSecGuestAttributeAudit` ->`SecCodeCopyGuestWithAttributes` ->`SecCodeCheckValidity` with receipt entitlement requirement |Original current data flow; Security results are explicit private inputs |
| Target application/file |Kernel-produced path -> daemon serialized field -> original service parser ->`isSignedByDeveloperFileAtPath:basicCheck:` |Path is payload data, distinct from the connection peer; actual file check unexecuted |

The new requirement is a45-byte original constant string:

```text
(entitlement ["com.apple.fp.receipt"] exists)
```

Its CFString object is`0x100065b80`, flags`0x7c8`, character address`0x10005fee7`; the class/string fixups are decoded from original bytes. The requirement explicitly asks for existence. The reference daemon's embedded XML declares this entitlement; effective native entitlements and signature validity remain unverified.

| Companion call | Instruction | Arguments established by original code / finite flow |
| --- | --- | --- |
| Guest lookup |`0x10000d53c` |Host NULL, audit-attribute dictionary, flags0, output code reference at SP+`0x460` |
| Requirement parse |`0x10000d5e8` |Original CFString, flags0, output requirement at SP+`0x3d8` |
| Dynamic validity |`0x10000d68c` |The guest-lookup code reference, flags0, the parsed requirement |
| CF releases |`0x10000d6f0`, `0x10000d750`, `0x10000d7f0`, `0x10000d87c` |On the modeled success path: attributes, audit data, requirement and code reference; native retain accounting is not modeled |

Original status arithmetic uses constant`C=0x662255dd` and mask`0xcc44abba=(C<<1) mod2^32`:

```text
encoded(s) = (s + C - ((s << 1) AND 0xcc44abba)) mod 2^32
           = s XOR C
encoded(s) == C  <=>  s == 0
```

The two status-codec SMT queries are unsatisfiable for counterexamples over all32 bits. Connecting them to each native gate uses the recorded predecessor constants: W21=`0x177`, entry W22=`0xd1`, W23=`0x662254aa` after setup and W26=`C`. Checkpoints retain these values at each reached gate. Full recovery of these premises across every startup/control state remains open.

| Private Security case | Later API behavior / reply |
| --- | --- |
| Guest lookup status-67050 |Requirement/validity skipped; signed64 reply status-67050 |
| Requirement parse status-50 |Validity skipped; signed64 reply status-50 |
| Validity status-67050 |Signed64 reply status-67050 |
| All three statuses0 with non-null outputs |Continues to target-path developer check |
| Counterfactual guest success with NULL code |Reaches validity call with NULL code; stopped before that API |
| Counterfactual parse success with NULL requirement |Reaches validity with optional NULL requirement and modeled0; continues to developer check |

Success-with-NULL cases deliberately violate the successful output-object premise of the corresponding creation API. They expose local reliance on that premise; they do not establish native reachability or a policy bypass. SDK documentation states guest-lookup failure leaves its output unchanged. The fixture does so; the original output slots were zero before these calls.

## Target developer-check and receipt branch [AP2, AP4]

The service's original helper at`0x100000dc8` calls `NSFileManager.defaultManager`, creates an NSString from the parsed full executable path and invokes `isSignedByDeveloperFileAtPath:basicCheck:` at`0x100000e6c`, with basicCheck1. The exact fixture path is:

```text
/private/synthetic/ArcadeFixture.app/Contents/MacOS/Game
```

The installed reference StoreFoundation implementation supplies the following static chain:

| Reference-cache method / boundary | Address | Recovered behavior |
| --- | --- | --- |
|`-[NSFileManager(ISAdditions) isSignedByDeveloperFileAtPath:basicCheck:]` |`0x1c6fd6d8c` |Sets progress-handler argument to NULL; forwards through original selector stub |
|Developer wrapper |`0x1c6fd6ce8` |Checks file existence; wraps an80-byte original requirement blob; calls `_isFileSignedAtPath:withRequirement:basicCheck:` |
|Four-argument helper wrapper |`0x1c6fd6b74` |Sets progress callback to NULL and forwards |
|Full static-signature helper |`0x1c6fd6648` |File-existence guard; `SecRequirementCreateWithData`; URL creation; `SecStaticCodeCreateWithPath`; flags; `SecStaticCodeCheckValidity`; Boolean status conversion and cleanup |
|Static validation call |`0x1c6fd68d4` |Code object, selected flags, parsed requirement; W0==0 becomes Boolean true |

Five original cache stubs resolve exactly to `CFDataCreateWithBytesNoCopy`, `SecRequirementCreateWithData`, `CFURLCreateWithFileSystemPath`, `SecStaticCodeCreateWithPath` and `SecStaticCodeCheckValidity`. The80-byte blob at`0x1c6ff7320` is retained with its hash; its human requirement expression is unknown. The method name supplies a developer-signature role, not a decoded certificate policy.

The helper selects flags1 when basicCheck is0, flags7 for a nonzero basicCheck. A full32-bit arithmetic proof and arm64e SDK compile corroborate the selection and flag constants. For the service's argument1, flags7 combine `kSecCSCheckAllArchitectures` with `kSecCSBasicValidateOnly`. The latter includes `kSecCSDoNotValidateExecutable` and `kSecCSDoNotValidateResources`. This is the declared reference API validation scope, not an observed native validation result. The callback path exists in the full helper; the recovered service route supplies NULL.

When the private developer-result input is false, original service code copies into a1024-byte stack buffer, trims the executable-path suffix and appends the original literal`/_MASReceipt/receipt`. It reaches:

```text
FP_ISPurchaseReceipt.receiptWithContentsOfFile:
    /private/synthetic/ArcadeFixture.app/Contents/_MASReceipt/receipt
```

The Objective-C call is at`0x100000f20`; original metadata maps the class method to`0x1000011e8`, with type encoding`@24@0:8@16`. No file is read and the method is not invoked in this increment.

## Recovered Objective-C implementation names [AP1, AP5]

Original relative method lists recover53 methods across seven classes; all53 implementation pointers match original `LC_FUNCTION_STARTS`. No IDB names are changed. These are source metadata names, rather than analyst-invented stripped-symbol names.

| Class | Instance / class methods | Selected original implementation mappings |
| --- | --- | --- |
|`FP_ISPurchaseReceipt` |19 /1 |`receiptWithContentsOfFile:` ->`0x1000011e8`; `initWithContentsOfFile:` ->`0x100001228`; `_decodeReceiptData:toDecodedMessage:` ->`0x10000186c`; `_verifySignatureForSignedData:onDate:` ->`0x100001e68` |
|`FP_asn1ReceiptToken` |8 /1 |Receipt-token metadata and methods retained |
|`FP_asn1Token` |6 /3 |Base token methods retained |
|`FP_asn1SetToken` |4 /0 |Set token methods retained |
|`FP_asn1SequenceToken` |4 /0 |Sequence token methods retained |
|`FP_asn1IntegerToken` |3 /0 |Integer token methods retained |
|`FP_asn1OSToken` |4 /0 |Octet-string token methods retained |

The complete mapping also identifies trust-policy, certificate-OID, token parsing, expiration-date, revoked/VPP and receipt-attribute accessors. Method names establish implementation identity and triage targets; complete method semantics are not inferred from their names.

## Source-produced response and completed private daemon stub [AP2, AP6]

With successful modeled Security results and developer-result true, original service code reaches `_xpc_dictionary_set_data` at`0x100010428` with96 bytes, `_xpc_dictionary_set_int64` at`0x1000104bc` with status0, then the send boundary at`0x10001050c`. This model does not send anything. Both the normal and scalar-clobber service cases produce identical response bytes.

| Response record | Tag / raw payload |
| --- | --- |
|Root`0x7976211a` |`0x9777`, four zero bytes |
|Root`0xfd2821c7` |`0x50db`,48-byte nested span |
|Nested`0xf6964e3e` |`0x9777`, BE32`0xac868405` |
|Nested`0x1fe19f29` |`0x8485`, BE64`1` |
|Nested padding key0 |`0x50db`, six zero bytes |
|Root padding key0 |`0x50db`,14 zero bytes |

These raw wire values remain separate from internal XOR-decoded scalar representations. The exact request bytes emitted by the daemon equal the service fixture input; the exact96 response bytes are then supplied as the daemon's synthetic synchronous XPC result. The unmodified response completes the original daemon stub:

| Daemon original write | Location / resulting field |
| --- | --- |
|Provisional decision1 |`0x10051e4f4` -> reply+36 |
|Decision0 |`0x1004d7b0c` -> reply+36 |
|Application status0 |`0x100005544` -> reply+32 |
|NDR bytes |`0x100005554` -> reply+24 |
|Completed reply size40 |`0x100005560` -> header+4 |
|Stub return |Private return sentinel, X0=0; reply ID61571 |

```text
kernel-supplied path -> daemon original serializer -> service original parser
    -> peer audit / receipt-entitlement gates [explicit synthetic results]
    -> target developer check [explicit true]
    -> original96-byte response -> daemon original parser / policy continuation
    -> decision0 -> completed MIG61571 buffer: size40, status0, decision0
```

This completes a private source-to-source protocol case. CF/Mach/XPC transport, native PAC, real file/signature validation and a running kernel transaction are not executed. The reply's numeric port names are fixture values, not recovered real endpoint identities. Previously recovered kernel control flow takes its normal epilogue for a completed status0/decision0 result; no such native delivery is claimed here.

Response-field replacements are retained separately as synthetic parser/policy probes. They alter only the eight raw bytes for key`0x1fe19f29`; they are not source-produced server replies. All eleven cases show the selected raw64 value stored at`0x1005a99c0` into SP+`0xb30`; the later `LDR W10,[SP,#0xb30]` at`0x1008b35ec` and `CMP W10,#1` at`0x1008b35f0` consume only32 bits. A fourth SMT proof corroborates this local little-endian64-store/32-load projection over all64 input bits, conditional on the reached field/slot relationship. This is separate from the earlier signed64 XPC `status` truncation.

| Raw64 response field | Reached local u32 comparison | Finite daemon outcome |
| --- | --- | --- |
|1, unchanged source reply; normal and scalar-clobber producers |1==1 |Both complete:status0,decision0,size40 |
|`0x100000001`, `0x8000000000000001` |1==1 |Both complete:status0,decision0,size40 |
|0,2,257,65537,`0x100000000`,`0x8000000000000000`,UINT64_MAX |Low32 differs from1 |All stop at Foundation path conversion; provisional decision1,application/stub unfinished |

Four daemon cases therefore complete,including two unmodified source-produced replies. The other seven remain unfinished paths. Successful cases subsequently reach a native byte checkpoint at`0x100580978` with candidate1 versus comparison byte0 and W27=`0x8b3dc651`,before the zero-decision continuation. The complete response-field-to-policy contract across all states remains open; the finite outcomes and local load-width theorem do not establish native policy behavior. See [roundtrip profiles](triage_evidence/arcade_policy_roundtrip_profiles.json).

## Model stress tests, reproduction and assumptions

The service true/false developer cases additionally replace X1-X17 after every modeled external return, replace X0 for void models and set NZCV=`0xa0000000`. X18 and SIMD registers are preserved; stack-probing's special ABI is excluded. True still produces the identical96-byte reply, and false still reaches the identical receipt path. These are finite scalar ABI stress tests, not full AAPCS/runtime/concurrency equivalence.

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_arcade_service_policy.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_arcade_policy_roundtrip.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_arcade_policy.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_arcade_policy_delivery.py
```

Frozen parent harnesses and initialization remain unchanged. Each service case runs fresh main/peer-registration prefixes. Extraction is O(B+F+I+M); private phases are capped at2000000 steps. Defined private heap bytes, lifetimes, payload extents, unknown imports and system instructions remain guarded. Modeled string operations cover fitting, bounded private buffers only; native library overflow behavior is not evaluated. SMT cost is separate.

| ID | Assumption / dependent claims | Stress test / falsification probe | Status |
| --- | --- | --- | --- |
| AP1 |Pinned service/daemon bytes and metadata describe the investigated files |Rehash source, re-decode original method/fixup entries and match compiler starts |Current files verified; runtime slice/registration unknown |
| AP2 |Explicit Security/Objective-C/XPC models and PAC bypass preserve the displayed finite paths |Separate failure stages, NULL-success counterfactuals, scalar clobbers and unchanged-byte replay |Finite cases only; no native authentication/IPC |
| AP3 |Recorded control constants connect Security arithmetic to the three local gates |Capture each reached gate, prove full32-bit codec under these premises, recover alternate predecessors |Premises checked in reached cases; all-state predecessor proof open |
| AP4 |Installed StoreFoundation method corresponds to the target's effective selector implementation |Compare runtime cache/UUID/method resolution; examine replacements and actual library pairing |Original cache/nlist/selectors/bindings verified; runtime pairing unknown |
| AP5 |Original relative method metadata maps selectors to the displayed implementations |Independently decode relative offsets, chained selector slots, types and53 compiler entries |53 mappings verified; names do not prove complete semantics |
| AP6 |Source-produced96-byte response is relevant to the current request/policy prefix |Exact request/response byte comparison, completed original stub, separate mutated-response probes |Private protocol case complete; native transaction unknown |

## Bounded continuation and quality gates

| Impact | Next evidence | Interface consequence |
| --- | --- | --- |
| High |Execute/recover original receipt class path below`0x1000011e8`, with explicit file-data boundaries |Connect non-developer application receipts, CMS/trust/expiration results and response construction |
| High |Recover complete response-field and decision-byte data flow across all relevant states |Extend finite response probes into a justified schema/policy contract |
| High |Match actual peer/service/cache/slice and effective entitlements |Attest runtime authorization and endpoint identities |
| Medium |Decode the80-byte StoreFoundation requirement from verified format/opcode sources |Replace the method-name interpretation with exact certificate-policy semantics |
| Medium |Extend scalar perturbation to SIMD, API failures and complete object/port lifetimes |Assess additional ABI/model and ownership dependencies |
| Medium |Trace kernel event/wait/retry and daemon asynchronous callback alongside this completed private case |Connect result propagation to the remaining kernel/CF/XPC lifecycle |

QG1 passes for factual analysis. QG2 registers AP1-AP6 and probes. QG3 passes for this authorization/developer/private-reply increment; the full goal is incomplete. QG4 retains widths, extents, equations, SDK flags and complexity. QG5 separates peer versus target identity, model/counterfactual inputs, private completed reply versus unfinished mutated cases, and cache pairing. QG6 retains original metadata/bytes/chains, SDK, arithmetic and source-pinned private evidence. QG7 supplies impact-labeled continuation. See [profile checks](triage_evidence/arcade_policy_profile_checks.json), [quality gates](triage_evidence/arcade_policy_quality_gates.json) and [current manifest](triage_evidence/interface_manifest.json).
