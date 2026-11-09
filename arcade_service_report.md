# CoreFP arcade companion service: identity, peer gate and request boundary

This increment connects the daemon's recovered XPC request to original code in the installed `com.apple.fpsd.arcadeservice` executable. The service installs an Apple-anchor/identifier requirement on each peer connection, gates handler installation on the setter's 32-bit return status, and processes the daemon-produced packet far enough to pass the peer audit token to `SecCodeCopyGuestWithAttributes`. Original static evidence, arithmetic proofs and finite private models are separate below. Native peer authentication, actual XPC delivery and the final subscription decision are unknown. The full interface investigation remains active.

The subsequent [policy report](arcade_policy_report.md) extends that stopped guest-lookup boundary through a receipt-entitlement requirement,developer check and receipt path. One original96-byte response under explicit policy models completes the daemon's private stub with status0/decision0;complete native policy remains unknown. Earlier cases/counts below remain scoped to this report's frozen first increment.

## Source identity [SV1]

| Item | Exact observation |
| --- | --- |
| Bundle | `/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/XPCServices/com.apple.fpsd.arcadeservice.xpc` |
| Executable | `Contents/MacOS/com.apple.fpsd.arcadeservice`, 1649248 bytes |
| Universal SHA-256 | `91ff94a78b525339eaa5f0f94a0358adb173e891d4de0e6ba6ad59ca089d44f4` |
| Selected architecture | CPU `0x100000c`, raw subtype `0x80000002`, file offset704512, length469600 bytes |
| Selected slice SHA-256 | `fed08b800dc88a83fb71b81008791faab457dca99b514ea01aed2fb6fffee694` |
| Selected UUID | `49af318e-c43d-3b3c-a874-3a602525133f` |
| Entry / compiler bounds | `0x100003380`; first main range ends at`0x1000034fc` |
| Original code coverage |70 `LC_FUNCTION_STARTS` ranges retained; extracting all ranges is not semantic recovery of all70 functions |
| Original fixups |1163 walked chain members, pointer format12, imports format1; independently decoded words match Apple's `dyld_info` |
| Bundle plist | Identifier/executable `com.apple.fpsd.arcadeservice`; version1; `XPCService.ServiceType=System` |

The other slices are x86_64 subtype3 and ARM64 raw subtype`0x8000000c`; neither is substituted for the selected image. The selected slice has no`LC_ENCRYPTION_INFO_64`. The plist does not establish effective UID, sandbox state or running service identity.

The installed CoreFP `fairplayd` universal file has SHA-256`4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`, exactly matching the investigation's universal daemon. This establishes co-installed file correspondence; the process-selected slice and runtime library/service pairing remain unknown.

Embedded CodeDirectory identifiers are `com.apple.fpsd.arcadeservice` for the service and `com.apple.fairplayd` for the daemon slice. The service signature has CodeDirectory, requirements and CMS wrapper blobs, without embedded XML/DER entitlement slots. The daemon XML declares, among other entries, `com.apple.arcade.fpsd`, `com.apple.fp.receipt`, `com.apple.private.FairPlayIOKitUserClient.access` and `AvpFairPlayUserClient.access`. DER is retained as a hash but not decoded; signatures and effective entitlements were not authenticated. Identifier strings alone do not prove satisfaction of the peer requirement. See [inventory and signature metadata](triage_evidence/arcade_service_inventory.json), [retained selected slice](triage_evidence/arcade_service.arm64e) and [original functions](triage_evidence/arcade_service_original_functions.json).

## Entry, connection gate and block ABI [SV2, SV3]

Addresses below belong to the companion service, not the numerically overlapping daemon image.

| Role | Original instruction / argument evidence |
| --- | --- |
| XPC entry |`0x1000034f8` calls `_xpc_main`; X0 is callback`0x1000034fc` |
| Peer callback |`0x1000034fc` saves the incoming connection in X19 |
| Install peer requirement |`0x10000369c`; X0=incoming connection; X1=`0x100060df0` |
| Status predicate |`0x1000036a0` compares W0 with0; selected indices`0xfa`/`0x10c` |
| Zero-status continuation |Original authenticated slot`0x100064840` ->`0x1000036c4` |
| Nonzero-status continuation |Original authenticated slot`0x1000648d0` -> epilogue`0x100003818` |
| Install event block |`0x1000037c4`; block invoke`0x1000030d0`, captured peer at block+32 |
| Resume peer |`0x100003814`; X0 is the same incoming connection |

The literal supplied to the requirement setter is:

```text
(anchor apple) and (identifier "com.apple.fairplayd" or identifier "com.apple.lskdd")
```

Six exhaustive 256-input byte-bank checks resolve the original selectors. The call table base is`0x100064070`. Its selected imports are independently decoded from original format12 words; the main import diversity is`0xb1dc`, requirement setter`0xc061`, handler setter`0xbb8a`, and resume`0xb6b3`. The status-index SMT query is unsatisfiable for any counterexample over all32 input bits:0 chooses`0xfa`, every nonzero value chooses`0x10c`. Thus local handler installation/resume is gated on successful installation of the requirement. This does not authenticate any real peer. See [call slots, banks and proofs](triage_evidence/arcade_xpc_contracts.json).

| Block offset, bytes | Width | Observed field |
| --- | --- | --- |
|0 |u64 |`_NSConcreteStackBlock` reference under the private import model |
|8 |u32 |flags`0x40000000` |
|12 |u32 |reserved0 |
|16 |u64 |invoke`0x1000030d0` |
|24 |u64 |descriptor`0x100064050` |
|32 |u64 |incoming peer connection |

The40-byte block layout and public API status widths compile against the installed arm64e SDK. Private event tests copy the observed block bytes into analyst-owned memory, preserving its capture. This models the callback arguments without claiming native block-copy, retain or scheduling behavior.

## Request decoding, peer audit and guest lookup [SV3-SV5]

```text
daemon 0x10077e614: synchronous XPC request { data: 160-byte blob }
                         |
                         | unaltered bytes in a private fixture
                         v
service event 0x1000030d0, block+32 = peer connection
    -> xpc_get_type(event)
    -> xpc_dictionary_get_data(event, "data", &length)
    -> original record parser / dispatch
    -> xpc_connection_get_audit_token(peer, &token32)
    -> CFDictionary + CFData(token32)
    -> SecCodeCopyGuestWithAttributes(NULL, attributes, 0, &code)
                         |
                         +-- stopped before guest lookup result
```

| Service boundary | Call instruction | Established data flow |
| --- | --- | --- |
| Event type |`0x10000428c` |Synthetic event handle ->`_xpc_get_type` |
| Request payload |`0x1000044e8` |Key`data`; native out-length slot; exact daemon-produced160 bytes supplied |
| Peer audit token |`0x10000cf90` |Captured peer, rather than payload bytes, is X0 to `_xpc_connection_get_audit_token`; token destination receives32 bytes in the explicit model |
| Attribute dictionary |`0x10000d28c` |`CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks)` |
| Audit data |`0x10000d444` |`CFDataCreate(NULL,token,32)` |
| Audit attribute |`0x10000d4e0` |`CFDictionarySetValue(attributes,kSecGuestAttributeAudit,auditData)` |
| Guest lookup |`0x10000d53c` |Host NULL, the constructed attributes, flags0, output code-reference pointer |

The exact packet came from the daemon's original serializer under the fresh initialization fixture; it was not reconstructed by the service harness. The service reaches guest lookup after120265 private instruction/API steps, with every visited original instruction checked against the selected slice. This establishes finite cross-image interoperability through parsing and peer-identity preparation. It does not establish lookup success, subsequent code validity/requirements, receipt validity or policy outcome.

The explicit token fixture is eight little-endian u32 words`[501,501,20,501,20,1234,100,1]`. No real process/token lookup ran. `kSecGuestAttributeAudit` is represented by an opaque typed private object. The allocator-default NULL value is independently present in the installed reference CF cache; pairing with the target remains an assumption. See [allocator reference](triage_evidence/arcade_service_allocator_reference.json) and [source-pinned service cases](triage_evidence/arcade_service_peer_profiles.json).

## Conditional reply envelope and NULL reply [SV3, SV6]

| Synthetic event / input | Reached local status | Boundary reached |
| --- | --- | --- |
| XPC error object; forced reply creation success |signed64 -42049 |Status-only send boundary; forced reply eligibility is counterfactual for a non-dictionary event |
| Dictionary missing`data`; reply context modeled present |signed64 -42052 |Status-only send boundary |
| Dictionary with present zero-byte data |signed64 -42023 |Status-only send boundary |
| Exact160-byte daemon packet |unknown |Guest lookup boundary before result |
| Error event; reply creation NULL |No send |Private cleanup returns |
| Dictionary missing`data`; reply creation NULL |No send |Private cleanup returns |

The common reply sequence calls `_xpc_dictionary_create_reply` at`0x10000e6c0`, sets signed64`status` at`0x1000104bc`, and reaches `_xpc_connection_send_message(peer,reply)` at`0x10001050c` when the synthetic reply object exists. The two NULL cases execute original free/return paths without a send. The send cases stop before transport and subsequent cleanup.

The SDK states that reply creation returns NULL without a dictionary reply context. Consequently the error-object success case demonstrates the internal status computation and conditional envelope only; it is not an observed native error reply. The NULL error case is the matching supported-result fixture. No raw Mach name, underlying XPC transport port object or native right lifetime is recovered here. Those remain distinct from the established41471/51471/61471 Mach interfaces.

## Assumption register

| ID | Assumption / dependent claims | Stress test or falsification probe | Status |
| --- | --- | --- | --- |
| SV1 |Pinned installed service and daemon files are relevant companions; identity section |Compare runtime executable UUID/slice and effective service job with these hashes; an alternate binary falsifies runtime pairing |Files verified; runtime pairing unknown |
| SV2 |Original chain decoding and bank identities recover the named targets |Independent chain walk versus`dyld_info`, import-table decode, six complete byte domains and status-index SMT |Passed for these sources |
| SV3 |Single-thread private execution, PAC bypass, explicit API results and preserved non-result registers suffice for the finite paths |Vary caller-saved clobbers/API failures and audit words; inspect native scheduling/PAC separately |Finite cases verified; no universal/native equivalence |
| SV4 |Opaque CF object and constant models preserve the displayed argument relationships |Replace CF creation with NULL/failure; compare actual allocator/constant bindings and object semantics |Successful opaque creations modeled; failures beyond current scope |
| SV5 |The recovered daemon packet supplies the expected request schema |Exact artifact-byte comparison and original service parsing; vary keys/tags/extents and verify subsequent guest/receipt logic |One160-byte cross-image packet reaches guest lookup; full schema unknown |
| SV6 |A reply context exists in successful dictionary-reply fixtures |Explicit NULL creation in two cases; SDK declaration and documented eligibility; native transport observation |NULL paths passed; error-object forced success is counterfactual |

## Bounded continuation and quality gates

| Impact | Further evidence | Interface significance |
| --- | --- | --- |
| High |Continue from`SecCodeCopyGuestWithAttributes` result through `SecRequirementCreateWithString` / `SecCodeCheckValidity` call sites |Separate connection peer requirement from application/guest policy; imports alone do not establish their use |
| High |Recover actual successful service `data` construction and daemon consumption |Connect serialized result fields to the final61471 decision and kernel task action |
| High |Bind native service instance, selected slice, effective identity and transport ports |Convert file-level correspondence into actual endpoint and ownership evidence |
| Medium |Trace receipt/CMS/certificate/trust methods and StoreFoundation calls |Imports and selectors expose a receipt-verification lead; their full semantics remain unknown |
| Medium |Vary reply context, allocation failures and caller-saved register models |Define lifecycle and ABI dependencies beyond the successful private models |
| Low |Compare the other ARM64 subtype and x86_64 slice |Find structural correspondence without assuming semantic equivalence |

QG1 passes for descriptive analysis. QG2 registers SV1-SV6 with probes. QG3 passes for this increment; the full goal is incomplete. QG4 covers widths, byte layouts, SDK compilation and source-bound arithmetic. QG5 separates NULL/error eligibility, models and stopped policy boundaries. QG6 retains original files/chains, SDK, proofs and source-pinned finite cases. QG7 supplies impact-labeled continuation. See [checks](triage_evidence/arcade_xpc_profile_checks.json), [machine-readable gates](triage_evidence/arcade_xpc_quality_gates.json), [daemon reply report](arcade_reply_report.md), [subscription report](arcade_subscription_report.md) and [current manifest](triage_evidence/interface_manifest.json).

