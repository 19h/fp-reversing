# akd: named ADID clients, request/reply ABI and source-to-Avp bridge

Original `akd` metadata and code assign ten named operations to ten previously numeric ADID commands. Two additional complete C entries produce commands without a proved incoming caller. Together, these identify client producers for twelve of the fourteen recovered provider commands. This establishes contextual meanings for DSID, IDMS routing info, SPIM, CPIM, MID, OTP, SIM, SRM, PTM, TK and provisioning session fields. Original C symbol names remain unknown.

The source's embedded signature declares `adi-client` as **string `"347420559"`**, not a CFNumber. Its decimal value is `0x14b5378f`, one of the provider's recovered accepted patterns. Twelve private client/provider pairs execute the original string conversion, command selection, reply production and client reply parser using this exact declaration. These are separate private guests with explicit API fixtures. Effective runtime credentials, selected runtime slice, native IPC and successful provisioning remain unknown.

```text
akd: AKNativeAnisetteService / AKAppleIDCodeGenerator
  | original ObjC selector -> direct C call
  v
statically linked C client -> data = BE32(1,command,1) || body
  | com.apple.adid / synchronous XPC API
  | exact byte bridge between separate private guests
  v
adid: original callback -> audit/entitlement/context -> command tree
  |                                     |
  | four-byte status reply              | 76e89210, explicit VMM1
  v                                     v
original client reply reader       Avp type0 -> method100 /144 bytes
  |                                [opaque API boundary]
  +-> scalar/span/session outputs

CoreFP routing setter -> same adid collection value interface
fairplayd <-> FairPlayIOKit: prior separately established interfaces
Avp <-> primary FairPlayIOKit coupling: unknown
```

## Original sources and extraction

| Source | Exact identity / coverage |
| --- | --- |
| `/System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/Support/akd` | Universal SHA-256 `b672326beefc8cce30c2f6f2e071bdc965ca9538a728ab3d5376e0db0f73c5f6`; 13910640 bytes; three slices |
| Selected akd arm64e subtype `0x80000002` | Offset 4505600, extent 4719376 bytes; SHA-256 `097f11648c43cb0e360dcee4be9aa87d46153779f0ae21ea318883310a5a552a`; UUID `43016122-1388-34e5-a9aa-208d90ed00f8`; unslid base `0x100000000` |
| Alternative arm64e subtype `0x8000000c` | Offset 9240576, extent 4670064 bytes; SHA-256 `b18c54aed6b36d7c6e8b6767e66f965acd9081f2ca65734b28d4c27cf9b0b2c7`; runtime selection unknown |
| Co-installed adid selected slice | SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`; UUID `4d24325f-3529-39b1-bbf8-64bbcf406049` |
| Original akd structure | 10039 function starts, 1575 imports, 37439 independently walked format-12 chained fixups, 309 classes, 3422 methods |
| Static semantic neighborhoods | 34 complete compiler ranges; ten higher-level methods, 525 direct B/BL edges, 55 original bound stubs |
| Shared-cache search | UUID `2bd06591-e751-3e84-963f-b08dab6af23a`; all 4113 listed images and all export terminal names, including reexports |

No `_ADI` import is used by these clients: the C implementations are inside `akd`. The co-installed CoreADI directory contains the daemon and resources; the cache has no CoreADI-named image and no export beginning `_ADI`/`__ADI` or containing `CoreADI`. This is a bounded original-cache result; runtime or filesystem-wide absence is not established. All addresses below belong to the selected original slice and are unslid. Identical numerical client/provider addresses refer to different images.

Primary evidence: [original reader and inventory](triage_evidence/akd_client_inventory.json), [independent fixup reference](triage_evidence/akd_client_fixups.txt), [embedded declarations and codesign extraction](triage_evidence/akd_client_entitlements.json), [raw entitlement XML](triage_evidence/akd_client_entitlements.xml), [complete static contracts](triage_evidence/akd_adid_contracts.json), [all cache export terminals and hashes](triage_evidence/akd_adid_cache_exports.json). These are local original-binary sources; no external naming reference supplies the recovered mappings.

## Named operations and exact producer layouts

Every request begins with **12 bytes: `BE32(1), BE32(command), BE32(1)`**. The table describes the remaining producer bytes. `bytes[N]` means exactly N supplied bytes, without a trailing NUL. Count widths are 32 bits; DSID and routing-info widths are 64 bits; session width is 32 bits. The Objective-C method labels are original metadata; C role names are analyst mappings.

| Role | Original named method | ObjC entry | Direct C target | Raw command | Request body |
| --- | --- | --- | --- | --- | --- |
| Get routing info | `+[AKADIProxy getIDMSRoutingInfo:forDSID:]` | `0x10010db10` | `0x1002f86d8` | `85fe63b0` | DSID64 |
| Set routing info | `+[AKADIProxy setIDMSRoutingInfo:forDSID:]` | `0x10010db48` | `0x10030f600` | `632b8d6e` | DSID64, routingInfo64 |
| Request OTP | `+[AKADIProxy requestOTPForDSID:outMID:outMIDSize:outOTP:outOTPSize:]` | `0x10010db80` | `0x100308278` | `cfe0b46a` | DSID64 |
| Query provisioning | `+[AKADIProxy isMachineProvisioned:]` | `0x10010dc00` | `0x1002d8790` | `b0eda7af` | DSID64 |
| Start provisioning | `+[AKADIProxy startProvisioningWithDSID:SPIM:SPIMLength:outCPIM:outCPIMLength:outSession:]` | `0x10010dc30` | `0x1002e1b74` | `716bd86c` | DSID64, SPIMLength32, SPIM bytes |
| End provisioning | `+[AKADIProxy endProvisioningWithSession:PTM:PTMLength:TK:TKLength:]` | `0x10010dc88` | `0x100302898` | `0b2b3196` | session32, PTMLength32, PTM bytes, TKLength32, TK bytes |
| Destroy session | `+[AKADIProxy destroyProvisioningSession:]` | `0x10010dcd8` | `0x1002dd3a0` | `55a637c0` | session32 |
| Synchronize | `+[AKADIProxy synchronizeWithDSID:SIM:SIMLength:outMID:outMIDLength:outSRM:outSRMLength:]` | `0x10010dd08` | `0x1002ed22c` | `a54951ec` | DSID64, SIMLength32, SIM bytes |
| Erase provisioning | `+[AKADIProxy eraseProvisioningForDSID:]` | `0x10010dd6c` | `0x1002fd5c8` | `7715488c` | DSID64 |
| Generate login code | `+[AKAppleIDCodeGenerator generateLoginCode:]` | `0x1000519f0` | `0x1002d3d84` | `385b2ce8` | DSID64 from the declared active-DSID method result |
| Unnamed C entry | No proved incoming caller | none | `0x1002e7d04` | `72096fe6` | empty; header-only 12 bytes |
| Unnamed C entry | No proved incoming caller | none | `0x1002f3944` | `76e89210` | BE32(0), BE32(11), ASCII `vmtohostmsg`; total request 31 bytes |

The two remaining provider commands are **`9679d4b5` and `a8471cad`**. Their original client producers are unknown. The negative caller scan for the two unnamed entries covers every text B/BL, ADR, adjacent ADRP+ADD and chained pointer target. Computed or nonadjacent reference construction remains possible; the negative scan does not establish dead code.

The local `+[AKADIProxy dispose:]` entry `0x10010dbd0` calls C `0x1003026f8`, which tail-calls imported `_free` at `0x100302884`. It emits no IPC in the retained execution. Its nominal method encoding contains an integer return; a meaningful native return value is unknown because `_free` is void. The model supplies zero to continue; that value is not assigned API semantics.

## Connection, data and reply emission sites

Each recovered producer constructs the exact service string `com.apple.adid`, a modeled dispatch queue and connection flags zero. The table records source API call sites, not underlying `mach_msg` instructions. Incoming native port names, send/receive rights and libxpc serialization remain unknown. Model object addresses are private guest fixtures.

| Role | `_xpc_dictionary_set_data` | `_xpc_connection_create_mach_service` | `_xpc_connection_send_message_with_reply_sync` |
| --- | --- | --- | --- |
| Get routing info | `0x1002fa500` | `0x1002fa5e8` | `0x1002fa754` |
| Set routing info | `0x100311998` | `0x100311aa0` | `0x100311c10` |
| OTP | `0x10030b0d4` | `0x10030b204` | `0x10030b3a4` |
| Provisioning query | `0x1002da290` | `0x1002da38c` | `0x1002da4f8` |
| Provisioning start | `0x1002e45b0` | `0x1002e46d4` | `0x1002e4854` |
| Provisioning end | `0x1003057fc` | `0x10030593c` | `0x100305abc` |
| Session destruction | `0x1002def30` | `0x1002df048` | `0x1002df1ac` |
| Synchronization | `0x1002f0130` | `0x1002f024c` | `0x1002f0404` |
| Erasure | `0x1002ff528` | `0x1002ff638` | `0x1002ff7c0` |
| Login code | `0x1002d5a40` | `0x1002d5b34` | `0x1002d5cc4` |
| Unnamed `72096fe6` | `0x1002e95ac` | `0x1002e96a8` | `0x1002e9830` |
| Unnamed `76e89210` | `0x1002f5cc4` | `0x1002f5e10` | `0x1002f5f9c` |

Provider callback `0x100029fc8` receives the exact client `data` bytes through the existing modeled audit/data adapter. Provider `_xpc_dictionary_set_data` at `0x1000aa9fc` and reply request at `0x1000aaa70` return `data` to the pending modeled client API. The provider inner record wrapper reports status zero and output length four in the twelve completed pairs; the callback's final X0 is incidental and is not interpreted as that wrapper status. The four reply bytes carry the application result.

## Argument forwarding, identifier gates and reply ABI

The original synchronization proxy loads its ninth Objective-C argument from entry SP and forwards it as C X6: the `outSRMLength` pointer. Original code `0x10010dd08..0x10010dd6c`, actual guest arguments and resulting count32 writes establish this. Nominal Objective-C encoding offsets are metadata; they are not physical native stack offsets.

Routing get/set accept exactly the 64-bit bit patterns representing **-8, -6, -5, -4, -3, -2**. The source predicate is `i=(DSID+8) mod 2^64; i<=6 && ((0x7d>>(i mod32))&1)`. Original windows begin `0x1002f87f8` and `0x10030f724`. Login C entry instead accepts **DSID -16 through -1 and non-NULL output pointer**, from CMN/CCMP at `0x1002d3e90..0x1002d3f14`. Two full-64-bit SMT queries prove the stated gate reductions against all input patterns; neither gate assigns an ordinary account interpretation to reserved negative DSIDs.

Every reply reader first consumes BE32 status. Nonzero `ffff501f` is propagated unchanged in the ten finite named-operation controls. Zero status then selects the operation-specific continuation:

| Operation | Locally accepted zero-status reply tail | Observed result / output scope |
| --- | --- | --- |
| Routing get | BE64 routingInfo | Supplied `1122334455667788` becomes the same scalar64; returns zero |
| Login code C entry | BE32 code | Supplied `12345678` writes four bytes; adjacent sentinel bytes preserved; returns zero |
| Provisioning start | BE32 CPIMLength, CPIM bytes, BE32 session | Supplied 3-byte `abc` allocates CPIM, writes length3 and session `12345678`; returns zero |
| OTP | BE32 MIDLength, MID bytes, BE32 OTPLength, OTP bytes | Supplied `abc` and `WXYZ` allocate/populate both outputs, then reach opaque notification registration |
| Synchronization | BE32 MIDLength, MID bytes, BE32 SRMLength, SRM bytes | Supplied `abc` and `WXYZ` allocate/populate both outputs; returns zero |
| Routing set / provisioning query / end / destroy / erase | none required in the status-only controls | Returns zero locally for a four-byte zero reply |

These supplied zero-status bytes establish client reader behavior. They are not provider-generated valid provisioning records, OTPs, sessions or driver responses. The complete accepted response language, trailing-byte policy, all allocation failures and native ownership remain unknown. Supplying the session before the CPIM span produces `ffff5016`; zero status without required fields also produces `ffff5016`. Routing-get replies of zero, one or three bytes are separate retained truncation controls.

Output initialization is operation-specific. Before modeled allocation failure, OTP and synchronization clear four output slots: pointer64/count32/pointer64/count32. Start clears its CPIM pointer/count but leaves the session output sentinel unchanged. Routing get preserves its output sentinel; login C clears its four-byte output. The modeled allocator NULL result gives `ffff5035`. These observations do not promise identical output state after every later failure.

Dictionary-NULL controls stop at the original `_xpc_dictionary_set_data(NULL,...)` API boundary. No native fault or successful invalid API call is inferred. All API and allocation observations distinguish live outputs from bytes retained after a modeled free.

OTP's original call at **`0x100309b14`** supplies name **`com.apple.adid.midchangedV1`** from `0x100347d23` and token-output cell **`0x100450548`** to `_notify_register_check`. The API remains opaque. Notification registration success, subsequent token checks, matching producer emission and native Mach rights remain unknown.

## Paired original client/provider executions

The exact emitted client bytes become the provider request in a separate guest. Its exact reply bytes complete the pending client synchronous API at unchanged PC/SP/LR. The pending API has a stop observation and a completion observation; this does not mean the original send instruction executed twice. Fresh uninterrupted client runs with the same reply reproduce the complete ordered original instruction stream and output/allocation observations.

All pairs use the original declared entitlement **string `347420559`**, with original `_CFStringGetCString` call `0x100169814` and `_strtoul` call `0x1001698bc`, radix10, result `0x14b5378f`. Audit identity, process path, initialized peer checkpoint, files and OS API behavior remain explicit fixtures. The modeled process path is not an assertion that the native peer is akd.

| Original client producer | Provider reply bytes | Client returned u32 | Interpretation established |
| --- | --- | --- | --- |
| Get routing info | `ffff4ffb` | `ffff4ffb` | Exact status propagation |
| Set routing info | `ffff501f` | `ffff501f` | Exact status propagation |
| OTP | `ffff4ffb` | `ffff4ffb` | Exact status propagation |
| Provisioning query | `ffff4ffb` | `ffff4ffb` | Exact status propagation |
| Provisioning start | `ffff5018` | `ffff5018` | Four-byte SPIM control reaches source constructor and minimum-length failure |
| Provisioning end | `ffff5037` | `ffff5037` | Finite supplied-session/body error |
| Session destruction | `ffff501f` | `ffff501f` | Finite supplied-session error |
| Synchronization | `ffff4ffb` | `ffff4ffb` | Exact status propagation |
| Erasure | `ffff4ffa` | `ffff4ffa` | Finite provider result |
| Login code C entry | `ffff4ffb` | `ffff4ffb` | Exact status propagation |
| Unnamed `72096fe6` entry | `00000000` | `00000000` | Existing modeled per-EUID unlink route |
| Unnamed `76e89210` entry, base environment | `ffff5024` | `ffff5024` | Existing environment-gated result |

In the named provisioning-start pair, original 96-/176-byte construction preserves DSID `1122334455667788` in nested+8 under XOR `da8ca8cae5dfbd2d`, initializes nested+`0x98` to encoded zero and nested+`0xa0` to audit EUID plus `0x46d726`. This establishes the earlier unnamed input blob's **SPIM** role and separates DSID from audit EUID and session32. The prior [collection value-update proof](adid_context_lookup_report.md) connects the named routing setter to nested+`0x98`: it is contextually an **IDMS routing-info value** for this operation. Universal object typing or native object ownership is not established.

## Original vmtohost producer to Avp method 100

The complete C entry `0x1002f3944` emits:

```text
00000001 76e89210 00000001 00000000 0000000b
766d746f686f73746d7367
```

This is 31 bytes, including the 11-byte literal `vmtohostmsg` without NUL. Under explicitly modeled successful VMM value1, time 1700000000 s, random result `0x12345678`, bounded allocations and IOKit results, the full original provider callback reaches:

| Boundary | Original source | Observed contract |
| --- | --- | --- |
| Avp connection open | `0x10002b854` | Type0; connection-output/cache cell `0x1002dd290` |
| Avp method | `0x100058a1c` | Selector100; same input/output pointer; input144 bytes; output-size64 initialized144 |
| Method response | Opaque API boundary | No result supplied; no provider reply emitted in this profile |

This joins a complete original client producer to the existing [source-built Avp packet interface](adid_avp_packet_report.md). It adds no native caller for that client entry and no Avp implementation, accepted hardware response or Avp-to-primary-kext coupling. The provider also accepts the earlier header-only environment fixture; the new client tail proves additional producer bytes, not that the provider consumes those trailing fields.

## Higher-level AuthKit context

Original `AKNativeAnisetteService` code provides further source naming and data-flow anchors. The ten complete methods and every selected direct edge/stub are retained, rather than inferred from string proximity alone.

| Original method | Entry | Source references / direct interface context |
| --- | --- | --- |
| `_tq_processStartProvisioningResponse:error:completion:` | `0x100015560` | CFString `Response` and `spim`; `initWithBase64EncodedString:options:` selector; original provisioning-start selector call |
| `_tq_processEndProvisioningResponse:error:cpimBytes:provisioningContext:completion:` | `0x100016b00` | `Response`, `ptm`, `tk`, `X-Apple-I-MD-RINFO`; original route-setter and provisioning-end selector calls |
| `_tq_anisetteDataForDSID:withError:` | `0x100013dd8` | Original OTP selector call; data/base64 conversions; `setMachineID:` and `setOneTimePassword:` |
| `_tq_anisetteDataWithRoutingInfoForLastKnownDSIDWithError:` | `0x100013bac` | Original routing-getter selector and `setRoutingInfo:` |
| `_cleanUpCPIMBytes:provisioningContext:` | `0x1000174fc` | Original dispose and session-destruction selector calls |
| `_tq_syncAnisetteWithSIMData:completion:` | `0x100018e40` | Original synchronization selector |
| `_tq_eraseAnisetteWithCompletion:` | `0x100019aa4` | Original provisioning-erasure selector |
| Three provisioning/sync URL constructors | `0x100019e94`, `0x10001a2b4`, `0x10001aad8` | URL-bag `urlForKey:completion:` and request-construction selectors retained |

These are static method/edge/selector references. Their complete higher-level CFG, asynchronous blocks, network protocol, authenticity policy and runtime object dispatch remain unknown. No network transaction was performed.

## Assumption register and falsification probes

| ID | Assumption / dependent results | Stress test or falsification probe |
| --- | --- | --- |
| K1 | Selected subtype `0x80000002` is the analysis source; all address/ABI mappings depend on it | Hash/UUID and universal-slice readback; runtime slice attestation could require analyzing subtype `0x8000000c` separately |
| K2 | Original method metadata plus direct calls identify contextual roles | Re-read all relative fields, selector pointers and BL targets; an alternate runtime implementation would limit native dispatch claims |
| K3 | Independent fixup reference plus explicit import models resolve guest targets | Fresh whole-table dyld_info comparison and original stub bytes; native loader/PAC behavior could differ |
| K4 | Declared original string entitlement is a useful source-derived credential fixture | Independent codesign/XML parsing plus source conversion; inspect effective runtime entitlement/audit identity before native admission claims |
| K5 | Explicit queue/XPC/reply models supply the documented external API semantics | Vary replies/NULL dictionary/allocator controls; compare native API serialization/object typing when authorized |
| K6 | Private full-method/C entry execution establishes local behavior, not upstream native reachability | Scan original incoming references; recover computed callers and real selected instance dispatch |
| K7 | Finite producer layouts and full-width gate reductions remain distinct | Independent bytes at lengths0/1/4/27/64, truncations and full64 SMT; test length/capacity/alias extremes separately |
| K8 | Supplied zero-status replies reveal client reader/output behavior | Wrong-order, short and error controls; obtain provider-generated accepted records before assigning protocol success |
| K9 | Exact byte bridging preserves modeled client/provider local contracts | Unchanged pending PC/SP/LR and fresh uninterrupted stream/output comparison; native XPC rights/lifetime remain separate |
| K10 | Existing initialized peer/API/filesystem/VMM/time/random models permit the observed provider continuations | Fresh full callback/event replay; native prerequisites or different environment/state may select other paths |
| K11 | Cache search covers all listed images and all terminal names, including reexports | Fresh independent recursive trie walk over4113 images; other files/cache versions/runtime private symbols can falsify broader absence claims |
| K12 | Notification and higher-level static references identify interfaces without establishing asynchronous effects | Recover notification producer/check/reset sites, block CFG and caller admission; observe effective event ordering separately |

## Validation and bounded continuation

The [fresh verifier](triage_evidence/validate_akd_adid_delivery.py), [explicit check ledger](triage_evidence/akd_adid_checks.json) and [scoped quality gates](triage_evidence/akd_adid_quality_gates.json) cover 98 retained client cases, twelve completed private pairs, one opaque request-to-Avp bridge, twelve fresh uninterrupted client reply replays, twelve additional client boundary/output replays, five fresh complete provider pair replays, one fresh complete VM-to-Avp replay and two new full64 SMT proofs. Original-byte/hash readback, all37439 fixups,3422 methods and4113 image export tries are checked afresh. All 104724 assertions pass, including 91119 original instruction records, 100 complete compiler-range records and 771982 retained source visits across the separate namespaces. No native target/loader/IPC/IOKit/notification or target-side file/environment/synchronization operation was executed. Independent metadata utilities were executed only for display.

Complexity: original extraction/catalog and retained verification are O(B+F+M+V+E) time/space for binary bytes B, fixups F, methods M, visited original instructions V and export-trie bytes E. Private runs have explicit instruction caps, at most8192 bytes per client allocation/data extent and bounded model ownership. Each SMT query has a 30 s timeout. These bounds describe this workflow; they do not establish native resource bounds.

| Impact | Next evidence | Interface consequence |
| --- | --- | --- |
| High | Accepted SPIM source/grammar, successful provider CPIM/session path and actual PTM/TK producer | Converts named staging into complete provisioning/session/lifetime contracts |
| High | Avp method100 implementation and accepted response, then primary-kext coupling | Resolves the remaining driver-side semantic boundary and deeper data transfer |
| High | Effective akd/adid credentials, runtime slice/image/endpoint pairing | Distinguishes original embedded declarations from native admission and port identity |
| High | Original producers/callers for `9679d4b5`, `a8471cad` and two unreferenced C entries | Completes the currently recovered command surface and reachability map |
| Medium | `com.apple.adid.midchangedV1` producer, token checks/reset, emission sites and delivery order | Establishes cache invalidation/event feedback and associated Mach interfaces |
| Medium | AuthKit NSXPC listener/exported protocol, caller admission and higher-level asynchronous CFG | Connects external clients/network responses to the recovered local C operations |
| Medium | Legacy Mach fallback, XPC serialization/rights, complete retry/error/ownership/alias/capacity paths | Completes transport and object lifetime contracts across the same command set |
| Low | Equivalent analysis of alternative arm64e slice and other cache versions | Tests portability of the recovered mappings |

QG1-QG7 pass for this explicitly bounded increment: descriptive content; K1-K12 assumptions/probes; stated requirement coverage; exact widths/byte units and reproducible algorithms; separated native/model/callback/wrapper/output semantics; original-source provenance with fresh independent checks; impact-labeled continuation. The [preservation readback](triage_evidence/akd_adid_preservation.json) verifies all 808 prior artifacts: 802 remain byte-identical; only the five root indexes/status files and manifest aggregator change. All three supplied inputs remain unchanged. The broader interface investigation remains active and incomplete.
