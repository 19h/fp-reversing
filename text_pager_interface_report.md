# FairPlay app-context, text-pager, and conditional RPC interfaces

This increment connects a named kernel client to the obfuscated FairPlay app-context interface. `AppleFairplayTextCrypterSession::fairplayOpen` invokes provider vtable offset `0x8d8`, resolving to `ycJai39mD8` and then `_fcHfFIGhsx`. That wrapper carries separate origin and mode words. All three recovered direct provider callers pass mode 1. The previously recovered conditional host/RPC selectors compare that mode against 1, selecting slot17/RPC502 rather than the alternate slot34/RPC700 case. Complete dispatcher reachability and destination-port lifetime remain unknown.

The native page-decrypt and close callers additionally establish useful roles for `_EQlZPp` and `_oh70aLVr`. No cryptographic algorithm or complete private object implementation is assigned from these interfaces.

## Evidence and assumption register

Analysis date: 2026-11-01. Addresses are preferred static virtual addresses, not live ASLR addresses. Kext SHA-256 is `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`; matching collection SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| T1: the recorded files and live IDB represent the intended image | Address and instruction associations | Recheck SHA-256, UUID and byte snapshots; the verifier checks original bytes. Current native identity observations are separately recorded in the interface reports. |
| T2: the receiver uses the recovered nominal C++ vtable | Named virtual-call targets | Read the live authenticated receiver/vptr and target. Static vtable resolution does not prove runtime receiver type, override behavior, or PAC success. |
| T3: the ordinary arm64 calling convention and indicated inherited frame apply at each slice | Constructor fields and scalar forwarding | Compare original stores/loads, caller prologues, frame writes and all predecessor paths. Cross-slice reachability is conditional, not an execution observation. |
| T4: pinned public XNU declarations describe the conventional field meanings | CPU type/subtype, origin names, kernel routine-name candidates | Match the exact target source/build or independently trace every originating input. Raw field widths, constants, and instructions remain authoritative. |
| T5: unmodeled aliases do not overwrite the request record between inspected uses | End-to-end interpretation of the three RPC scalars and mode | Recover intervening writes and call side effects. Present scalar associations are conditional on record identity and intact fields. |
| T6: caller output addresses are valid | Wrapper publication of a token through X5 | Check all callers and failure paths. The wrapper performs the observed store before its own final status transform. |

Primary native evidence: [wrapper snapshots](triage_evidence/app_context_wrappers_native.json), [provider snapshots](triage_evidence/app_context_providers_native.json), [live cross-references](triage_evidence/app_context_live_xrefs.json), and [collection instructions, symbols and original fixups](triage_evidence/app_context_collection_native.json). The capture contains 12 ranges, 48 exact pointer bindings, and five live-IDB/original-byte comparisons. [Symbol search](triage_evidence/app_context_collection_symbols.json) covers all 362 fileset entries for the stated name patterns. This is a bounded name search, not complete architectural recovery.

## Kernel hook and pager callbacks

```text
kernel loader/remap consumer
  | {filename, cputype, cpusubtype, origin}
  v
text_crypter_create callback
  -> IOTextCrypter::createSession
  -> AppleFairplayTextCrypter::newCryptSession
  -> session::fairplayOpen
  -> FairPlay provider+0x8d8 -> fcHfFIGhsx(..., origin, mode=1, out)
                                      |
                         conditional slot17 / RPC502 path
                                      |
                          compatible daemon MIG502 stub

pager page callback -> provider+0x8a8 -> EQlZPp(token, offset, src, dst)
pager end callback -> sessionDidEnd/cache removal -> release
  -> session::free -> fairplayClose -> provider+0x8b0 -> oh70aLVr(token)
```

The diagram combines confirmed local calls with the explicitly conditional dispatcher path. It does not establish an observed round trip into the daemon.

| Boundary | Native location | Established behavior |
| --- | --- | --- |
| Hook installation | `0xfffffe000b12d164`-`...178` | Forms authenticated pointer to `IOTextCrypter::createSession` at `0xfffffe000b12c778`, discriminator `0xbcad`; calls import stub `...b12e07c` |
| Kernel hook setter | `0xfffffe000bd14690` | Exact `_text_crypter_create_hook_set` symbol; stores X0 at `0xfffffe000cb502d0` |
| Provider discovery | `0xfffffe000b12d17c`-`...1a8` | Matches literal `com_apple_driver_FairPlayIOKit`, calls exact `serviceMatching`/`waitForService`/`safeMetaCast` imports, saves provider at crypter+`0x98`; timeout record is qword30, conventionally `{seconds=30,nanoseconds=0}` |
| Crypter registration | `0xfffffe000b12d1b8`-`...1c4` | Registers literal `com.apple.unfree` through `IOTextCrypter::registerCrypter` |
| Kernel consumer 1 | function-start range `0xfffffe000c35a618`-`...a974`, call `...a77c` | Loads installed hook; passes crypt-data record at SP+`0x48`, origin constant1, two W-register scalar fields, filename pointer; X0 is pager-info storage |
| Kernel consumer 2 | function-start range `0xfffffe000c2b6598`-`...6954`, call `...67ec` | Same hook/discriminator and record layout, origin constant2, filename and two W-register scalar fields |
| Successful pager-info construction | `0xfffffe000b12c7ec`-`...c810` | Writes page callback `0xfffffe000b12ca18` at+0, end callback `0xfffffe000b12ca8c` at+8, session at+`0x10`; callbacks are authenticated with distinct discriminators |

These two otherwise unnamed kernel function ranges are bounded by the kernel's `LC_FUNCTION_STARTS` (23,033 entries), not by nearest exported names. Their behavior corresponds to `set_code_unprotect` and `mremap_encrypted`, respectively, in the pinned [loader source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/mach_loader.c#L3479) and [remap source](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_mman.c#L1670). Those names are source-correlated interpretations under T4; neither has an exact start symbol in this collection.

The pinned [page-decrypt header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/page_decrypt.h#L44) names the fields `filename`, `cputype`, `cpusubtype`, and `origin`, and defines origin0/1/2 as ANY/APP_LAUNCH/LIBRARY_LOAD. Native constants1 and2 are read directly from `0xfffffe000700dc38` and `...dd68`. Its `pager_crypt_info` also contains a refcount after the three fields written here; the 24-byte callback prefix is not a claim that the complete structure is 24 bytes. Source files and hashes are [saved locally](triage_evidence/app_context_public_sources.json); the exact target-source revision remains unknown.

The crypter identifier `com.apple.unfree` and launchd Mach service `com.apple.unfreed` are different strings in different namespaces. The latter's slot17 declaration is independently observed in [native service evidence](triage_evidence/native_fairplayd_services.json).

## App-context constructor and scalar ABI

The actual provider vptr is the vtable symbol `0xfffffe000846b8c0` plus16. Original format-8 chained words resolve these entries exactly:

| vptr offset | Slot address | Provider routine | Call into protected code |
| --- | --- | --- | --- |
| `0x880` | `0xfffffe000846c150` | `DCkic(char const*, rp6S0jzg**)`, `0xfffffe000a504dbc` | `fcHfFIGhsx(name,-1,-1,0,1,out)` |
| `0x8d0` | `0xfffffe000846c1a0` | `xhU6d1(char const*,long long,long long,rp6S0jzg**)`, `0xfffffe000a504ee4` | `fcHfFIGhsx(name,cpu,subtype,0,1,out)` |
| `0x8d8` | `0xfffffe000846c1a8` | `ycJai39mD8(...,FPAppDecryptOrigin_,...)`, `0xfffffe000a504f28` | `fcHfFIGhsx(name,cpu,subtype,origin,1,out)` |
| `0x8a8` | `0xfffffe000846c178` | `bvqhJ`, `0xfffffe000a504e4c` | `EQlZPp(token,offset,src,dst)` |
| `0x8b0` | `0xfffffe000846c180` | `QnR91`, `0xfffffe000a504e88` | `oh70aLVr(token)` |
| `0x8e0` | `0xfffffe000846c1b0` | `Kp0289aEmoqcAa`, `0xfffffe000a504f68` | `_sk3kcwm3l2(token,AVDDecryptParams*)`; separate AVD interface |

The saved full-text direct-transfer scan and fresh IDA cross-references agree on the three direct `_fcHfFIGhsx` callers: `...a504dd8`, `...a504f18`, `...a504f58`. No stored reference to its entry appears in the saved local function-pointer catalog or live data xrefs. Computed indirect callers or external callers are not disproven by this coverage.

At `_fcHfFIGhsx` entry `0xfffffe000a66a7e0`, incoming X0/X1/X2/W3/W4/X5 are saved and repacked into a 40-byte record at SP+`0x40`. Stores at `...aa84`-`...aa98` establish fields omitted from the C export's visible locals:

| Record offset | Width | Meaning / provenance |
| --- | ---: | --- |
| `0x00` | 8 bytes | Name address, incoming X0 |
| `0x08` | 4 bytes | Output token read after dispatcher returns |
| `0x0c` | 4 bytes | Unrecovered word; no initialization asserted |
| `0x10` | 8 bytes | CPU type scalar, incoming X1 |
| `0x18` | 8 bytes | CPU subtype scalar, incoming X2 |
| `0x20` | 4 bytes | Origin, incoming W3 |
| `0x24` | 4 bytes | Mode, incoming W4 |

`...a66aaf8` forms the record address; `...a66ab00` saves it at generic-frame+`0x28`; `...a66ab50` calls dispatcher `0xfffffe000a606728`. The operation tag is `0xd11612f2`, with normalized secondary state `0x3e784ff5`, as independently derived in [dispatch algebra](triage_evidence/dispatch_algebra.json). Dispatcher `...a606860`/`...864` saves generic-frame+`0x28` at FP-`0xe0`.

The text session's `fairplayOpen` calls provider+`0x8d8` at `0xfffffe000b12da9c`. It obtains the name through exact `OSString::getCStringNoCopy`, uses **LDPSW** at `...da5c` to sign-extend the two stored 32-bit CPU fields into X2/X3, loads origin through W4, and passes the output address in X5. The provider drops `this`, forwards origin into W3, and inserts **mode=1 into W4**. Origin2 therefore does not itself select the alternate mode branch.

## Conditional slot and RPC selection

This extends the [existing special-port proof](kernel_port_resolution_report.md). It identifies the mode's origin without asserting every intervening flattened transition.

| Selection site | Input | `mode == 1` | `mode != 1` |
| --- | --- | --- | --- |
| Host lookup, `0xfffffe000a60abbc`/`...ac10` | u32 at argument-record+`0x24`; compare value locally proven1 | W2=17 at `host_get_special_port` call `...acb8` | W2=34 |
| RPC preparation, `0xfffffe000a60b7ec`/`...b7f0` | Same indicated record+`0x24`; W11=conditional base`0x8ea` | Table index`0x906` -> `...b820` -> RPC502 call `...b8a8` | Index`0x8ea` -> `...d334` -> RPC700 call `...d3bc` |

The origin and two CPU fields have separate forwarding loads: at `...b7ec`, W5 receives origin from+`0x20`; at `...b800`, X3/X4 receive the two 64-bit fields from+`0x10`/`0x18`. RPC502's client stores X3/X4/X5 at `...a5a20c4`/`...20c8`. Under T3/T5 this supplies semantic candidates for the formerly anonymous wire scalars:

| Scalar | Kernel request offset | Daemon request offset | Representation on this text-pager path |
| --- | --- | --- | --- |
| CPU type | `0x40` | `0x38` | Sign-extended int32 in a 64-bit field |
| CPU subtype | `0x48` | `0x40` | Sign-extended int32 in a 64-bit field |
| Origin | `0x50` | `0x48` | Zero-extended uint32 in a 64-bit field |

For example, a hypothetical CPU subtype bit pattern `0x80000002` becomes wire scalar `0xffffffff80000002` after LDPSW, rather than `0x0000000080000002`. This illustrates the representation rule; that subtype was not observed in a request.

The subsequent [request/VM recovery](kext_port_vm_report.md) resolves the ordinary constructor's OOL payload as the filename including NUL, subject to readable bounded input and adequate staging capacity. The extent is the zero-extended, wrapped u32 `low32(strlen(name))+1`. Local scratch+`0x28` holds a `vm_map_copy_t` created from staging in `ipc_kernel_map`; it is not a direct filename pointer. Reserved CPU-sentinel branches and complete allocation-capacity arithmetic remain separate unknowns.

The conditional scalar base has additional evidence: following the proven host-success W20=`0x43f`, block `...ad28` yields W22=`0xa9c`, W23=2. If the branch reaches `...ae40`, its later W20=`0x26d` is saved at SP+`0x178`. Block `...b55c` writes `(0x26d xor 0xa87)=0x8ea` to SP+`0x100`; `...b7dc` reloads it for the RPC selection. Not all transitions connecting those blocks are proven. SP+`0x178` contains pointers on other operation paths, so treating it as one universal field would be incorrect.

RPC502's Mach emission remains `0xfffffe000a5a20f8`; RPC700's remains `0xfffffe000a5a2368`. Slot34's actual endpoint, alternate-mode callers, and the RPC700 receiver remain unknown. The observed native launchd declaration for slot17 and the compatible daemon MIG502 stub do not establish the identity of a kernel port object obtained during this path.

## Token publication, status mapping, and session lifetime

At `...a66ab58`, the constructor wrapper loads **W8** from record+8; at `...ab60`, it stores **X8** through incoming X5. This publishes a zero-extended 32-bit value through the nominal C++ `rp6S0jzg **` output. It is evidence for an opaque token representation; dereference semantics or a native pointer identity are not established.

The wrapper publishes that value before its final status processing. Dispatcher-encoded statuses `0xce5159fd` and `0xce5159fa` enter the same local branch, which replaces either with `0xce515b8a`. Final XOR`0x31ae0066` therefore merges decoded values `0xffff599b` and `0xffff599c` into `0xffff5bec`. Other return paths retain their own values. It then calls exact `_IOFreeTypeImpl` with type descriptor `0xfffffe000847ba60` and the saved allocation, followed by `_IOFreeAligned(frame,0x4000)`. These local frees concern constructor scratch, not the published token's backing object.

The 56-byte `AppleFairplayTextCrypterSession` allocation has observed fields: crypter+`0x10`, token+`0x18`, copied `OSString`+`0x20`, two CPU words+`0x28`/`0x2c`, origin+`0x30`. Construction rejects unsigned origin>=3 through a cold failure routine; the complete cold-path body is not characterized here. `fairplayOpen` initializes its token field to zero and stores the returned token only on zero provider status.

`AppleFairplayTextCrypter::newCryptSession` uses an IOLock and cached OSArray. It searches under the lock, releases the lock to create/open a new session, reacquires the lock, and searches again before insertion. If another session now matches, it retains the existing session and releases the newly created one. Exact collection bindings resolve the array/iterator/retain/release calls.

`findExistingSession` at `0xfffffe000b12d49c` compares the filename using exact `OSString::isEqualTo(char const*)`, then the two 32-bit CPU words. The inspected comparison path does not read origin+`0x30` or crypt-data+`0x10`. A hit returns the existing session, so this local cache can reuse a context without reopening it for a changed origin. Whether callers permit the same identity across origins, and whether deeper policy intentionally treats them alike, remain unknown. No defect conclusion follows from this observation.

The page adapter `0xfffffe000b12d6a8` loads provider from crypter+`0x98`, token from session+`0x18`, and invokes provider+`0x8a8` at `...d6f4`, arranging `(token, uint64_offset, src, dst)` after `this`. It converts any nonzero protected return to raw `0xe00002bc`; zero stays zero. `_EQlZPp` therefore has a confirmed page-decrypt role at this caller boundary, without recovery of its complete implementation.

The end callback invokes `sessionDidEnd`, then releases its session reference. The subclass removes a matching cached session when the observed retain count is <=2. Session `free` calls `fairplayClose`, releases its name and crypter references, and enters the superclass free path. `fairplayClose` checks a nonzero token and tail-calls provider+`0x8b0` -> `_oh70aLVr(token)` at `...b12dbac`. This establishes the close/finalization role of that protected entry; its internal ownership and port release remain unresolved. Provider+`0x888` -> `_fd9eLZ4` is a different entry and is not substituted for this observed close call.

AppleAVD supplies an additional concrete consumer: `getFPADSCryptInfo` at `0xfffffe0008d1b7b4` loads its provider from object+`0x268`, dereferences the supplied token slot, and tail-calls provider+`0x8e0` at `...b7f0` with an `_AVDDecryptParams *`. This joins the nominal context type to video decryption metadata; its full data layout and hardware contract remain unknown.

## Reproduction, bounded findings, and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/capture_app_context_interfaces.py
python3 triage_evidence/verify_app_context_contracts.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/verify_app_context_marshalling.py
clang -target arm64e-apple-macos13.0 -std=c11 -fsyntax-only \
  triage_evidence/app_context_layout_contracts.c
```

[Validation](triage_evidence/app_context_contract_validation.json) records 17 byte-range checks, agreement between saved native branch coverage and live IDA caller xrefs, four exhaustive 256-input bank identities, the 40-byte constructor schema, and conditional `0x8ea`/`0x906` indices. [Symbolic byte-origin verification](triage_evidence/app_context_marshalling_validation.json) additionally follows 13 decoded native instructions through five input-field transfers and the zero-extended output store, with entry-save preservation and dispatcher-output assumptions stated explicitly. Compile-time assertions verify the native-offset representations. The source-to-register formulas are manually audited; these checks do not execute the target, prove hardware PAC, or close all path/alias obligations. Complexity is O(B+S+F+D) time/space for bytes B, symbols S, fixups F and captured disassembly D. Cache lookup is O(M) time/O(1) traversal state for M cached sessions; array allocation and iterator implementation have separate costs.

The [hook candidate scan](triage_evidence/text_crypter_kernel_hook_refs.json) illustrates one falsification: candidate `0xfffffe000becad88` redefines X8 before its store and actually accesses `0xfffffe000cb112d0`. It is excluded from verified hook references. This scan is bounded to ADRP followed within eight instructions by an immediate u64 load/store; it does not claim exhaustive reference recovery.

| Impact | Additional finding |
| --- | --- |
| High | A named encrypted-text client now connects CPU architecture/origin metadata to the protected constructor and conditional RPC502 interface. |
| High | Mode and origin are separate fields; a library-load origin of2 still follows the provider's mode1 interface. |
| Medium | The session cache omits origin from its inspected identity comparisons and avoids reopening on a hit. This is a behavior/reuse boundary, not a defect finding. |
| Medium | A nominal pointer-typed API publishes a 32-bit token; layout-compatible C++ names alone do not establish object-pointer semantics. |
| Medium | Constructor status merging and page-adapter status collapsing erase different information at different layers. |
| Medium | Text pages and AppleAVD metadata consume the same nominal context family through different provider slots. |

QG1 factual technical analysis; no normative content required. QG2 assumptions and probes above. QG3 this increment covers the constructor, named kernel clients, pager lifecycle, scalar forwarding and alternate-mode gap; the broad investigation remains active. QG4 byte widths, signed extension, bounds and complexity are explicit and layout-checked. QG5 origin/mode, crypter/service-name and callback-prefix distinctions are resolved; unresolved paths are labeled unknown. QG6 original bytes, exact symbols/fixups, live xrefs and pinned reference-source interpretations are separated. QG7 bounded additional findings are listed above.
