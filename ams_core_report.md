# Protected AMS core, context records and dynamic CoreFP ABI

The protected AMS record-disposal routine now has a compact source-established contract: it updates two mutable64-bit cells, returns `0xffff5bd9` for NULL, otherwise calls the exact cached `_free` target once and returns0. The context-creation wrapper packs a48-byte record, encodes operation`0xc4b` using the record address, invokes original helper`0x19c237b30`, and decodes its32-bit returned status. Eight exhaustive byte-bank checks and two fixed-width SMT proofs support these local mappings. [AC1-AC3]

Private original execution of creation, validation and import converges on the same once/lock initialization and dynamic CoreFP loader. The observed setup resolves five names present in the independently parsed original CoreFP export trie; its first export call is `lxpgvVMLd0S7uRl`. Under an explicitly modeled zero return with private global outputs preserved, it next calls `WIn9UJ86JKdV4dM`, passing an embedded891-byte DER certificate. No native CoreFP load, symbol resolution, export call, IOKit or target IPC executes. The full interface investigation remains active.

## Identities, evidence and reproduction [AC1, AC4]

| Original source | Identity / retained scope |
| --- | --- |
| Reference dyld cache | UUID`2bd06591-e751-3e84-963f-b08dab6af23a` |
| AppleMediaServices | UUID`1b464993-f0e2-3804-b412-a6cc8091798c`; five complete protected/compiler ranges plus loader range in static contracts;29 complete functions visited across private cases |
| CoreFP universal dylib | `/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP`, resolving to Versions/A/CoreFP;95235760 bytes; SHA-256`68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f` |
| CoreFP arm64e slice | File offset33849344,length30797904 bytes; SHA-256`8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c`; UUID`9061ddc3-93b4-3824-914f-9cc97d708d58`; preferred base0 |
| CoreFP metadata | Eight original exports,1602 compiler function starts; all eight exported function ranges retained |

[Pointer inventory](triage_evidence/ams_core_pointer_inventory.json), [bank/record/target contracts](triage_evidence/ams_core_contracts.json), [CoreFP file/export inventory](triage_evidence/corefp_library_inventory.json) and [private profiles](triage_evidence/ams_core_profiles.json) retain original bytes, pointer words and selected chain membership, export identities and exact frame/edge observations. Addresses with prefix`0x19c...` in the AMS sections are unslid reference-cache VAs. CoreFP file addresses such as`0xe160` are preferred-base offsets in a different image; they are not AMS/fairplayd addresses.

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/ams_core_reader.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/corefp_library_reader.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_ams_core.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_ams_core.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_ams_core_delivery.py
```

The cache probe materializes original version5 pointers in private pages, explicitly bypasses PAC and stops at unknown external interfaces, syscalls or disallowed writes. Allocator/once/lock/dlopen/dlsym/export outcomes are separately specified by each fixture. Original function/page data are deduplicated; each profile references the exact retained pool and records visited original instructions. No native target/API or loader is invoked.

## Pointer capabilities and classification limits [AC1, AC2]

The two selected AMS const sections contain29034 independently walked original chain members. They contain713 occurrences of85 distinct external targets in executable mappings; all85 have exact exported-value bindings. Of these,83 are compiler function starts, one is the exact `__platform_strcmp` stub, and one is the data export `__objc_empty_cache` in a const section. The last is not classified as a callable routine. The AMS image-header address is excluded from the external inventory.

| Capability group in the selected pointer tables | Exact exported values present |
| --- | --- |
| IOKit | IOMainPort,IOServiceMatching,IOServiceGetMatchingServices,IOIteratorNext,IOServiceOpen,IOConnectCallStructMethod,IOObjectRelease |
| Bootstrap / XPC | bootstrap_look_up,xpc_connection_create_mach_service,activate,event handler,synchronous message/reply,dictionary data/value operations |
| File / VM / environment | fopen/fread/fwrite/fseek/ftell/fclose,mkdir,mmap/munmap,vm_deallocate,sysctlbyname,MGCopyAnswer,time/gettimeofday |
| Synchronization / events | pthread_once,rwlock init/wrlock/unlock,dispatch once/queue creation,notify register/check/cancel,yield functions |
| Memory / CF | malloc/malloc_type_malloc/free,checked memset,CF type/string/data/number/URL operations |

These entries establish original bindings and investigation leads. They do not prove that `_ha0dkchaters6`, context creation or any particular runtime path invokes each capability. Direct shared-cache import stubs used by the loader are additional evidence outside this selected const-section catalog. Actual IOKit selectors, service instances, XPC service strings, Mach ports/right transfers and emission locations below this protected core remain unresolved.

## Record-disposal routine: decoded control and side effects [AC2, AC3]

Original `_jEHf8Xzsv8K` is at`0x19ca1dd68..0x19ca1df1c`. Its byte-bank transform has form `D(i) = i XOR B[A[i] XOR k]`, where only an8-bit index is consumed. Every bank pair is checked for all256 inputs, not for one captured global state.

| Disposal bank | Constant D(i) | Resolved role |
| --- | --- | --- |
| First mutable-cell selection |`0xe7` | Pointer cell`0x1e0f75858` ->`0x1ebbfdbf4`, used with bias-4 |
| Second mutable-cell selection |`0xb6` | Pointer cell`0x1e0f754b8` ->`0x1ebbfdf14`, used with bias-4 |
| Code-table selection |`0x18` |`0x1e0f75730` ->`0x1e449a4cc`, used with bias-12 |
| Final free target |`0x85` | Table index`0x1184+0x85=0x1209`; slot`0x1e44a3508` ->`0x181e7a6f0`, exact libsystem_malloc `_free` |

NULL selects table index`0x870`, slot`0x1e449e840`, target`0x19ca1df0c`. Non-NULL selects index`0x886`, slot`0x1e449e8f0`, target`0x19ca1deb0`. A64-bit pointer partition proof is unsatisfiable for any counterexample to this selection. The original authenticated branch/call modifiers are retained; no hardware authentication result is inferred.

The two actual cells are`0x1ebbfdbf0` and`0x1ebbfdf10`. Before the pointer test, original instructions write the same value to both:

```text
S = post-prologue SP; arithmetic modulo 2^64
new = ((old_cell2 - old_cell1 + S + 8) XOR 0xa0fb9d7d32f316e4)
      * 0x74b92847
cell1 = new
cell2 = new
if pointer == NULL: return 0xffff5bd9
free(pointer) at original call 0x19ca1df00
return 0
```

The cells are therefore not omitted from the recovered contract. Six private cases vary NULL/owned pointer, initial64-bit cell values and stack alignment. All match the original cell stores and return partition; owned cases reach one explicit modeled `_free`. The actual imported record's allocation validity and concurrent cell behavior remain unknown. This advances the previously opaque disposal role in the [event/keybag report](appstore_events_report.md).

## Context-creation record and decoded operation [AC2, AC3]

Original `_XtCqEf5X`, `0x19c9e12a0..0x19c9e14a0`, uses four other constant bank outputs: first cell`0xeb`,second cell`0x62`,target index`0xa0`,table index`0x36`. Pointer slot`0x1e4499ad8` resolves authenticated target`0x19c237b30`; wrapper call is`0x19c9e1464`. This is a local protected helper, not a dynamically imported API.

| Record offset from post-prologue SP+8 | Width | Original role |
| --- | --- | --- |
| +0 |64 bits | Original X1, caller-provided stack-record pointer in AMSFairPlayContext |
| +8 |32 bits | Encoded operation |
| +12 |32 bits | No wrapper initialization established |
| +16 |64 bits | Original X3, context-ID output-cell pointer from caller |
| +24 |64 bits | Original X0, NULL in the inspected AMSFairPlayContext caller |
| +32 |32 bits | Encoded returned status, written by backend/model |
| +36 |32 bits | No wrapper initialization established |
| +40 |64 bits | Original X2, SC Info path pointer |

The48-byte layout compiles for arm64e. The wrapper computes, with `p=low32(record_address)`:

```text
encoded_op = ((p XOR 0x0df1d93a) * 0x7f12daa3 + 0x00000c4b) mod 2^32
```

The backend's original OR/AND/SUB/XOR sequence subtracts the matching address term. A full32-bit SMT proof establishes decoded operation`0xc4b` for every record-address low word. Fresh backend execution also observes W20=`0xc4b` at`0x19c237c80`. This is an operation codec, not a proof of native context creation.

After backend return, the wrapper loads record+32 and XORs`0x0ef7dc36` into W0. Four explicit backend-status models,0/1/`0xffffffff`/`0xffff5a90`, round-trip exactly through original wrapper instructions. Their caller-provided output cell is not synthesized by these models. Complete record definedness, backend allocation/persistence and effective context-ID lifetime remain open.

## Shared initialization, failure paths and CoreFP loading [AC3-AC5]

```text
context create / context validate / keybag import
  -> common original support path
  -> pthread_once(control=0x1ebbfd8d8, initializer=0x19c200808)
  -> malloc(200)
  -> pthread_rwlock_init(private allocation, NULL attributes)
  -> original loader routine
  -> dlopen(CoreFP path, 5)
  -> five dlsym lookups
  -> lxpgvVMLd0S7uRl(global pointer)
  -> [explicit modeled zero return, outputs preserved]
  -> WIn9UJ86JKdV4dM(mode, pointer/record inputs, DER certificate, buffers)
```

| Original AMS boundary | Established input / effect in the private cases |
| --- | --- |
|`0x19c212e18` | pthread_once control`0x1ebbfd8d8`,callback`0x19c200808` |
|`0x19c1fa264` | Exact `_malloc`, size200 bytes |
|`0x19c1fa300` | pthread_rwlock_init with allocated pointer,NULL attributes; SDK sizeof(pthread_rwlock_t)=200 |
|`0x19c1f5c60` | dlopen(`/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP`,5) |
|`0x19c20e2f0` | First resolved CoreFP call,`lxpgvVMLd0S7uRl`; X0=`0x1ebbfd6ec` |
|`0x19c20e690` | Subsequent `WIn9UJ86JKdV4dM` boundary under explicit initial-export return0 |

Installed SDK constants establish flags5 as RTLD_LAZY|RTLD_LOCAL. The source's first external stop was Darwin `____chkstk_darwin`; its separate private model preserves live registers and bounds the requested private stack extent. The once model calls the original initializer, records completed state privately and guards reentry. Locks are abstract private objects, not native pthread objects. Successful malloc bytes are deliberately poisoned`0xa5`; a separate NULL allocation profile follows the original failure path.

| Private condition | Original creation-wrapper result |
| --- | --- |
| First200-byte allocation modeled NULL |`0xffff5bd4` |
| CoreFP dlopen modeled NULL |`0xffff5a5c` |
| First dlsym modeled NULL |`0xffff5a5c` |
| First CoreFP export modeled return1, no output effects |`0x00000001` |

These are conditional finite results, not native OOM/loader failures or defect findings. The29 profiles comprise14 normal private returns,11 exact external API stops and four CoreFP export-call stops. No unexplained emulator exception is accepted as completed evidence.

## Five resolved names versus eight available exports [AC4, AC5]

| AMS dlsym call | Requested C symbol | Matching original CoreFP offset |
| --- | --- | --- |
|`0x19c1f5c78` |`WIn9UJ86JKdV4dM` |`0xe160` |
|`0x19c1f5c94` |`X46O5IeS` |`0xbf2c` |
|`0x19c1f5cb0` |`YlCJ3lg` |`0xbc14` |
|`0x19c1f5ccc` |`lxpgvVMLd0S7uRl` |`0xcd20` |
|`0x19c1f5ce8` |`dku592fbFAj` |`0xd33c` |

The original trie also exports `fdjkDSAFjklaf2s` at`0xc4d4`, `uvbOOqb28APZ` at`0xde88`, and `wnnzAiOPdQe2` at`0xcf74`. Their availability is established; use by these AMS paths is not. The Mach-O export names have their original C underscore prefix in the inventory. Preferred-base offsets and source bytes identify the actual original functions without assigning semantics from obfuscated names.

The first call's X0 points into mutable AMS data. Its full pointee schema and the export's required output effects remain unknown. Private continuation models only the32-bit return and preserves the private original global bytes. This conditional continuation reaches a later call; it does not prove a valid native postcondition or successful library transaction.

## Certificate-bearing public call and ABI widths [AC5, AC6]

At the subsequent `WIn9UJ86JKdV4dM` boundary, creation and import profiles observe mode W0=7, X1=`0x1ebbfd6a0`, a private record pointer in X2, certificate pointer X3=`0x19cb1a483`, W4=`0x37b` and further private pointers in X5-X7. The source export at CoreFP`0xe160..0xe450` stores W0 and W4 as32-bit fields and X1/X2/X3/X5/X6/X7 as64-bit fields in its internal frame. These widths are static evidence; the full public parameter types and internal record semantics remain unknown.

The snapshot pointed to by X2 begins with u32 value2. The X7 pointee begins with u64 value`0x800` in the inspected private cases. These values are retained as observations rather than named enum/capacity contracts. Live X8 contains the modeled call target and is not counted as a ninth argument. Distinct stack addresses across creation/import snapshots do not establish different buffer ownership.

Original DER at`0x19cb1a483` begins`30 82 03 77`:887 content bytes plus4 header bytes=891=`0x37b`, matching the actual W4 input. [Certificate bytes](triage_evidence/ams_core_certificate.der) and [offline parser output](triage_evidence/ams_core_certificate.json) retain SHA-256`115f3a2ba390e70f833e5843dbe1b516348d4df047c86f08979dc8fa6767103d`.

| Parsed certificate field | Original value |
| --- | --- |
| Subject CN |`StoreAgentStub.4caf201221af0001af000001` |
| Subject OU |`Apple FairPlay` |
| Issuer CN |`Apple FairPlay AAA Certification Authority` |
| Serial |`4CAF201221AF0001AF000001` |
| notBefore |`2021-01-05T17:51:37Z` |
| notAfter |`2026-01-06T17:51:37Z` |

The notAfter field precedes the analysis date. Certificate chain/signature authentication, effective validation date/policy, protocol role and trust decision have not been established. Offline parsing is not a native Security/CoreFP validation result.

## Assumptions, bounded continuation and quality gates

| ID | Assumption / dependent results | Stress test / falsification probe | Current status |
| --- | --- | --- | --- |
| AC1 | Original cache/image/chain/trie records define these reference targets | Rehash sources; check original words, selected independent chain membership, exported values and complete function spans | Original reference identity/bytes verified; runtime selection unknown |
| AC2 | Immutable byte-bank contents and sequential local arithmetic select the displayed targets | Exhaust all256 byte indices; vary full-width state/stack; inspect writes, biases and any runtime mutation of banks/tables | Eight bank checks,two SMT proofs; native bank integrity/PAC/concurrency unknown |
| AC3 | Private API/state/relocation models explain the displayed paths | Vary null allocation,once/lock/reentry/state/status; preserve unknown outputs; reject unknown code and compare original bytes/pages | 29 explicit private profiles; no native target/API execution |
| AC4 | The pinned installed CoreFP file supplies the library intended by the original AMS loader | Attest actual dyld selection,architecture,search/override state and loaded UUID/bytes | Exact path and matching file exports verified; actual load/pairing unknown |
| AC5 | Modeled loader/export returns preserve the displayed caller continuation | Inspect real export output contracts and caller-saved effects; vary return/output states; recover all subsequent parameter schemas | Five exact lookups and four stopped export calls; no native export behavior |
| AC6 | Embedded DER extent/parser output describes the actual certificate argument | Re-extract original891 bytes,match header/W4,parse independently and establish actual verification policy | Exact source bytes/offline parse; trust/protocol semantics unknown |

| Impact | Next evidence |
| --- | --- |
| High | Recover `lxpgvVMLd0S7uRl` and `WIn9UJ86JKdV4dM` record/output semantics,then bind CoreFP's downstream service/IOKit calls to daemon/kext interfaces |
| High | Resolve actual per-call IOServiceOpen/IOConnectCallStructMethod and XPC/bootstrap table consumers; catalog membership alone is insufficient |
| High | Recover certificate-bearing protocol messages,mode7,record value2 and buffer/length ownership; establish effective authentication/validation policy |
| High | Complete `_ha0dkchaters6` successful import,record allocation extent and persistence/lifetime contracts |
| Medium | Complete once/lock allocation failures,initialization retry,mutable-cell concurrency and authenticated pointer behavior |
| Medium | Recover remaining CoreFP export users,unresolved private parameter types and exact runtime library/port identity |

Chain extraction is O(B+P+E) for bytes,pointer members and export names. Each bank check is O(256); SMT cost is separate. Private execution is bounded by50000 instructions per case with O(P) private original pages and bounded stack/heap. Pointer and source-range pools are deduplicated. Sizes/offsets are bytes; u32/u64 modular arithmetic and certificate UTC timestamps are explicit. No timing or native scheduling result is inferred.

QG1 descriptive scope; QG2 AC1-AC6 with dependencies/probes/status; QG3 passes for this protected-core/dynamic-ABI increment with the full objective active; QG4 exact widths/record/SDK compile and algorithms; QG5 callable versus data bindings,side effects,private outcomes and native postconditions separated; QG6 original source/chain/trie bytes,eight exhaustive banks,two SMT proofs and29 private readbacks; QG7 impact-labeled continuation. [Checks](triage_evidence/ams_core_profile_checks.json), [quality gates](triage_evidence/ams_core_quality_gates.json), [manifest](triage_evidence/interface_manifest.json).

## Subsequent CoreFP source recovery

The [CoreFP export/initialization/Mach report](corefp_exports_report.md) resolves the first export as a version-output routine:original instructions return u32[6,8,3],matching bundle6.8.3,with four stores across three mutable cells. Two isolated source-output transfers now carry its exact12 bytes/status into the original AMS caller and reach the mode7/certificate call. This supersedes the opaque initial-export return0 assumption for that local effect;native shared-image pairing remains unknown. The same report recovers the larger public argument record,initialization/allocation prefix and five separate CoreFP Mach request builders. Full certificate protocol,protected caller reachability and endpoint identity remain open.
