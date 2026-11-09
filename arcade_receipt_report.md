# Arcade receipt construction, CMS ABI and conditional ownership conflicts

Original receipt methods now connect the non-developer service path to file-data acquisition, CMS decoding, token parsing and certificate/trust checks. Nine private service cases distinguish missing/empty receipt data from CMS API boundaries. Six source-produced144-byte replies pass unchanged through the daemon to AppStore repair-request assembly and completed MIG61571 buffers with status0/decision1 under explicit repair-return models.

Two caller/callee ownership conflicts are established conditionally against the installed reference Security image: the caller does not initialize the decoder output slot before Create, while the reference Create failure path leaves it unwritten; and the caller destroys a context after a nonzero Finish result, while the reference Finish deallocates that context on every local normal-return path. Native library pairing and failure reachability remain unknown. These findings are not native memory-corruption observations.

## Sources and evidence boundaries [RC1-RC3]

The companion arm64e slice remains SHA-256`fed08b800dc88a83fb71b81008791faab457dca99b514ea01aed2fb6fffee694`, UUID`49af318e-c43d-3b3c-a874-3a602525133f`. Twenty complete `FP_ISPurchaseReceipt` method ranges,138 direct call edges and70 original authenticated/Objective-C stubs are retained. Method identities come from original relative lists; imported targets come from original chained fixups.

The reference cache UUID remains`2bd06591-e751-3e84-963f-b08dab6af23a`; Security UUID is`9010a058-749b-39ad-8881-438bf88ecb6a`. Four exact Security exports and the chained libsystem_malloc `_free` target support the lifetime comparison. Code/fixups/exports and model results are separate. No native receipt file, Objective-C runtime, CMS decoder, Security check, host loader or IPC executes.

Primary artifacts: [original contracts/call graph](triage_evidence/arcade_receipt_contracts.json), [nine receipt cases](triage_evidence/arcade_receipt_profiles.json), [six daemon continuations](triage_evidence/arcade_receipt_reply_profiles.json). Earlier [policy](arcade_policy_report.md) and [service](arcade_service_report.md) reports supply the preceding peer/developer gates; [AppStore repair](appstore_repair_report.md) supplies the downstream interface.

## Non-developer helper and receipt object ABI [RC2, RC4]

The original service helper at`0x100000dc8` receives:

| Register | Observed role / representation |
| --- | --- |
|X0 |Parsed executable C-string pointer |
|W1 |Inclusive path count; fixture57 bytes for56 characters plus NUL |
|X2 |Writable16-byte buffer; later populated from `getOpaqueDSIDBuffer` when a receipt exists |
|X3 |Writable64-bit word; receipt path uses `getAdamID`, `intValue`, then signed32-to64 extension |
|X4 |Writable64-bit object slot; receipt path stores `expirationDate` result |
|X5 |Writable byte; developer-check Boolean |
|X6 |Writable u32 kind; developer-true path writes1 |

Zero mandatory pointer/count arguments return raw32`0xffff5bd9` (-42023). With the other guards satisfied, W1 greater than1002 selects a status0 exit without the receipt work. This is local instruction behavior, not a complete filename-validation contract. The tested57-byte input passes these guards.

The developer-false path constructs `/private/synthetic/ArcadeFixture.app/Contents/_MASReceipt/receipt` and dispatches the original class method `receiptWithContentsOfFile:` (`0x1000011e8`), then instance initializer `initWithContentsOfFile:` (`0x100001228`). Original class_ro declares an80-byte instance. Private allocation zeroes those80 bytes and supplies a synthetic unauthed isa; NSObject init is an explicit identity model. The original initializer checks path length, acquires NSData through `dataWithContentsOfFile:` at`0x100001284`, and checks data length before decoding.

| Accessor | Original implementation / representation |
| --- | --- |
|`getAdamID` |`0x100001354`, object at self+`0x28` |
|`expirationDate` |`0x100001f8c`, object at self+`0x10` |
|`getOpaqueDSIDBuffer` |`0x100001374`, address self+`0x40`,16-byte copy in the helper |
|`getBundleID` |`0x10000135c`, process-global buffer`0x100068da0` |
|`getReceiptType` |`0x100001368`, process-global buffer`0x100068e9f` |

The token parser mutates receipt fields and globals before the initializer's later trust-result check. Global-buffer ownership, termination and concurrency require further recovery; an accessor name does not prove complete attribute semantics.

## CMS calling contract and ownership [RC1-RC3]

`_decodeReceiptData:toDecodedMessage:` spans`0x10000186c..0x10000192c`. Its original calls are:

| Call instruction | Imported function | Original argument/result use |
| --- | --- | --- |
|`0x1000018ac` |`SecCmsDecoderCreate` |X0-X6=0, X7=&local decoder slot at SP+8; W0 nonzero selects cleanup |
|`0x1000018d8` |`SecCmsDecoderUpdate` |X0=decoder, X1=NSData bytes, X2=64-bit length; W0 nonzero selects cleanup |
|`0x1000018e8` |`SecCmsDecoderFinish` |X0=decoder, X1=caller's message-output pointer; W0==0 returns Boolean1 |
|`0x1000018f8` |`SecCmsDecoderDestroy` |Reloads decoder slot; called when non-null after any preceding failure |

These are the private `SecCms*` interfaces, not the public `CMSDecoder*` API. The decode wrapper does not initialize its own decoder slot before Create. Its caller separately initializes the message-output slot to NULL.

| Exact reference export | Original range | Relevant local contract |
| --- | --- | --- |
|Create |`0x184fbeb08..0x184fbec4c` |Saves output address X7 in X19. Only explicit output store is`0x184fbebd8`; failure entry`0x184fbebf0` cannot reach that store |
|Update |`0x184fbed08..0x184fbedc0` |Rejects NULL context or length with bit63 set; failure may destroy/clear internal decoder state while retaining the outer context |
|Finish |`0x184fc3a4c..0x184fc3b04` |Success writes the message output; every local normal-return path passes `_free(inputContext)` at`0x184fc3ad4` |
|Destroy |`0x185157040..0x18515708c` |Dereferences outer-context fields, destroys retained internals and tail-calls the same deallocator |

The deallocation stub`0x18806c3d0` resolves through an independently verified version5 chain to `_free` at`0x181e7a6f0`, libsystem_malloc UUID`496cd265-a448-3071-803a-64c9743b3cda`. Removing the Finish free-call node from its original local CFG makes every normal return unreachable. This proves local normal-return domination, assuming external calls return normally; it does not execute deallocation.

Two conditional conflict witnesses:

```text
Create nonzero, output not written:
  original caller reads old SP+8 -> non-null -> Destroy(old pointer)
  private witness: old value0x7007edf8, an analyst-owned stack address
  stopped at unknown-context Destroy boundary

Create0 -> Update0 -> Finish nonzero:
  reference Finish retires outer context -> caller reloads same pointer
  -> Destroy(retired context)
  stopped before Destroy dereference/deallocation
```

The Create-failure model leaves the output untouched, matching the inspected reference path. The Finish-failure model retires the outer context before returning, matching reference CFG/data flow. In contrast, Update-failure leaves the outer context alive; the caller's subsequent Destroy retires it once. This distinction prevents treating all CMS failures as the same ownership state.

The assigned CMS statuses are independent synthetic inputs, including -26275. The two-byte data fixture`30 00` is not passed to a native decoder. No claim is made that those bytes produce any particular native status, that either problematic failure occurs in a running service, or that the target actually uses this reference library.

## Parsing and trust touch points [RC1, RC5]

The initializer decodes, invokes `_parseReceiptFromMessage:`, extracts signed data, then calls `_verifySignatureForSignedData:onDate:`. The parse helper gets message content and dispatches a token reader; the root identifier comparison is17. Full token/receipt schema remains incomplete.

The method named `_verifySignatureForSignedData:onDate:` (`0x100001e68`) requires a non-null certificate array with count3 and a positive `_checkArray:containsCertificateWithOID:` result for original literal`1.2.840.113635.100.6.2.1`. It creates trust, calls local policy and anchor helpers, and conditionally sets a verification date when the provided date object is non-null. The complete policy/anchor semantics and placement of CMS content/signature authentication remain unresolved.

At`0x100001f60`, the method calls `SecTrustEvaluate` and consumes its output result. The result slot starts at0; the returned W0 status is not separately tested in the inspected suffix. Original CMP/CCMP/CSEL accepts result1 or4, returning0; other results return the unsigned sentinel65535. One full32-bit SMT proof and SDK declarations corroborate the local predicate and names `kSecTrustResultProceed`/`kSecTrustResultUnspecified`. This is a trust-result contract, not proof of complete receipt-signature verification.

## Nine private cases and source-produced failure response [RC2, RC4]

| Case | Original-code boundary/outcome |
| --- | --- |
|Missing file-data object |Receipt initializer returns NULL; helper returns status0;144-byte response |
|Present empty NSData |Length guard returns NULL; same144-byte response |
|Two-byte data, CMS unmodeled |Stops at original Create API boundary |
|Objective-C allocation NULL |Nil initializer result; same144-byte response |
|Missing data with scalar clobbers |Same144 bytes and helper outputs |
|Create nonzero, untouched output |Unknown-context Destroy boundary |
|Update nonzero |One valid context destruction; same144-byte response |
|Finish nonzero |Retired-context Destroy boundary |
|Explicit CMS success, absent message content |Original parse fails; message destroyed; same144-byte response |

For the six response-producing cases, original helper outputs retain16 zero bytes, a zero u64 word, a NULL date object, developer byte0 and kind2. The144-byte packet contains nested raw keys`0x1fe19f2a`/tag`0x8485`/u64 zero, `0x1fe19f2b`/tag`0x50db`/16 zero bytes, and `0x1fe19f29`/tag`0x8485`/u64 two, plus the previously observed status/padding records. Equal zero fields alone do not prove every field's complete semantic mapping.

All six unchanged packets reach daemon repair assembly. Under explicit private options/service/normal-return models, the original daemon completes61571:size40,status0,decision1. The repair request contains the bundle prefix,exitReason16 and signed32 fairplayStatus-42352. See [AppStore repair report](appstore_repair_report.md). Actual repair, callbacks, CF/Mach transmission and the kernel's task action do not execute.

## Assumptions, bounded continuation and quality gates

| ID | Assumption / dependent claims | Falsification probe | Status |
| --- | --- | --- | --- |
| RC1 |Pinned method metadata, bytes and bindings identify the current files |Rehash originals, re-decode all20 methods/70 stubs, compare runtime slices independently |Files verified; runtime selection unknown |
| RC2 |Original-method dispatch, zeroed private instances, identity NSObject init and opaque API models preserve finite paths |Vary runtime method replacement, object initialization, API failures and register clobbers |Nine cases; no runtime/whole-API equivalence |
| RC3 |Reference Security Finish/Create contracts apply to the companion's effective library |Match actual loaded Security/cache and reproduce actual failure outputs independently |Conditional ownership conflicts; native pairing/reachability unknown |
| RC4 |Synthetic file/CMS results represent the displayed boundary inputs |Use actual receipt bytes only with an independently validated decoder; vary missing/empty/data and API stages |No native file/decoder result inferred from synthetic bytes |
| RC5 |Local trust-result predicate is interpreted under the inspected suffix |Trace signer/content authentication, policies, anchors, optional date and actual Trust API outputs |Local predicate proved; full receipt validation incomplete |

| Impact | Next evidence |
| --- | --- |
| High |Establish effective Security pairing and actual decoder failure transitions before promoting either ownership conflict to a native defect |
| High |Recover CMS signer/content authentication and complete trust/receipt attribute constraints |
| High |Connect valid non-developer receipt values through response fields and the daemon's final policy |
| Medium |Trace shared global-buffer lifetime/termination and optional verification-date behavior |
| Medium |Complete object/message/decoder cleanup, SIMD/API failure and concurrent-client behavior |

QG1 descriptive scope; QG2 RC1-RC5 with probes; QG3 passes for this increment while the broad goal remains active; QG4 widths, byte extents,80-byte layout, CFG complexity and trust arithmetic; QG5 ownership-stage/native-model/zero-field boundaries separated; QG6 original metadata, fixups, cache exports, CFG, SDK and source-pinned finite cases; QG7 impact-labeled continuation. [Checks](triage_evidence/arcade_receipt_profile_checks.json), [gates](triage_evidence/arcade_receipt_quality_gates.json), [manifest](triage_evidence/interface_manifest.json).
