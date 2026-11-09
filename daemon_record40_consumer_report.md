# Record40 consumer: audit-token task and entitlement query

The40-byte consumer at `0x10046EF4C` is now connected to a specific Security-framework query. Its actual caller-side key is `com.apple.private.fpsd.client`. Under explicitly modeled non-NULL string/task construction, source reaches `SecTaskCopyValueForEntitlement` at `0x1002B7728`, passing that key's modeled CFString and a task created from the supplied32-byte audit token. Entitlement retrieval and the native authorization outcome remain unknown. [RC1-RC10]

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Evidence: [strict and modeled profiles](triage_evidence/daemon_record40_consumer_profiles.json), [source/bindings/literal/SDK contracts](triage_evidence/daemon_record40_consumer_contracts.json), [eleven proof pairs](triage_evidence/daemon_record40_consumer_proofs.json), [fresh replay/readback](triage_evidence/daemon_record40_consumer_checks.json), [SDK C probe](triage_evidence/daemon_record40_consumer_sdk.c), [arm64e LLVM output](triage_evidence/daemon_record40_consumer_sdk.ll), [preservation](triage_evidence/daemon_record40_consumer_delivery.json), and [scoped gates](triage_evidence/daemon_record40_consumer_quality_gates.json). No fresh IDA query was needed; the pinned image, retained caller and installed primary SDK headers suffice for this increment.

## Caller fields and exact library interfaces

The [preceding handover report](daemon_mig_handover_report.md) establishes the40-byte record at R=F+0x10CB8 and its entry call at0x1004C4648. The new profiles begin at that call with source-produced private bytes. Additional callee controller values and writable-image backing are declared private environments; this is not a rerun of native MIG delivery or a universal setup-state proof. [RC1,RC2]

| Record field | Recovered use on this path |
| --- | --- |
| R+0/u64 | Pointer to the complete NUL-terminated key string in the caller frame |
| R+8/u8 | Output marker; a source writer is reached on the modeled constructor-NULL returns |
| R+0x10/u64 | Address of a separate output byte; callee clears it before the first framework call |
| R+0x18/u32 | Encoded selector; caller/callee composition gives0x8BB2 |
| R+0x20/u64 | Pointer to the32-byte token copied again for SecTask construction |

The key occupies30 source-defined bytes including NUL at F+0xBFC0. The byte ledger identifies each original caller writer and proves the literal independent of the borrowed input bytes in the retained caller context. The earlier observation of52 defined bytes in a wider candidate window did not establish a structure there; the first30 are now specifically a C string. No contents beyond its NUL are required by this string contract. [RC3,RC5]

| Source call PC | Original slot | Interface and source arguments |
| --- | --- | --- |
| `0x10033376C` | `0x1010A0598`, IA/D471 | `CFStringCreateWithCStringNoCopy(allocator,keyCString,0x600,contentsDeallocator)` |
| `0x10047D9AC` | `0x1010A0330`, IA/2A84 | `SecTaskCreateWithAuditToken(allocator,token32)`; token passed indirectly in X1 |
| `0x1002B7728` | `0x10109FFA0`, IA/FE9E | `SecTaskCopyValueForEntitlement(task,keyString,errorOut)` |
| `0x1003ECB40` | `0x1010A02E0`, IA/1883 | `CFRelease(keyString)` request in the modeled task-NULL cleanup path |

Address diversity is zero at these source slots. The framework calls are not executed natively. Allocator references, created objects and returned task handles are explicit model inputs/results; no model token is asserted to be a real CF/Security object. [RC4,RC6]

```text
retained A70E6EB4 caller
  keyCString = "com.apple.private.fpsd.client" + NUL
  token32: B+18 -> F+5D68 -> F+C080 -> F+C0A0
  record40 -> call46EF4C
       |
       +-- decode selector8BB2 -> shared fragment333680
       +-- clear output byte through R+10
       +-- read imported allocator data objects
       `-- CFStringCreateWithCStringNoCopy
              +-- NULL model -> marker5B -> caller
              `-- non-NULL model -> copy token32 to child SP+50
                    `-- SecTaskCreateWithAuditToken
                          +-- NULL model -> release string request
                          |                -> marker5B -> caller
                          `-- non-NULL model
                                -> SecTaskCopyValueForEntitlement [stop]

native token identity, entitlement value and final policy decision: unknown
```

## Encoding, token ABI and imported data

The constructor's0x600 argument is an encoding selector, not a byte count. The installed [CFString header](/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.2.sdk/System/Library/Frameworks/CoreFoundation.framework/Headers/CFString.h) defines `kCFStringEncodingASCII=0x0600` and the four-argument constructor prototype. It also permits a NoCopy constructor to copy internally; physical aliasing of the original buffer is not assumed. The [CFBase header](/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.2.sdk/System/Library/Frameworks/CoreFoundation.framework/Headers/CFBase.h) identifies `kCFAllocatorNull` as an allocator suitable when the supplied buffer should not be freed. The target runtime's allocator-object contents are not recovered. [RC4,RC9]

The strict profiles stop before the exported `_kCFAllocatorDefault` data read at0x1003336F8. Continued profiles separately supply explicit64-bit words for `_kCFAllocatorDefault` and `_kCFAllocatorNull`, then stop before the string call or apply a declared return model. A local source theorem quantifies over both64-bit word values and proves their unchanged passage to X0/X3, with X1=the key address and W2=0x600. This establishes argument flow, not validity of arbitrary bit patterns as native allocator objects. [RC4,RC6]

The [SecTask header](/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.2.sdk/System/Library/Frameworks/Security.framework/Headers/SecTask.h) declares the audit token by value. The compiled arm64e probe copies32 bytes and passes a pointer to that copy, matching the source. At0x10047D950 the original copy helper receives the record's token pointer, child SP+0x50 and count32; X1 is explicitly set to SP+0x50 at0x10047D998 before the task call. The43-visit aligned copy path preserves all256 token bits for arbitrary contents. Eight modeled task-construction instances independently check the copied argument against the original B+0x18 bytes. [RC3,RC7,RC9]

Per the SDK, the created SecTask represents the task associated with the supplied token. This path's native sender/trailer provenance is not established merely by the32-byte match. The internal A70E6EB4 constructor's upstream phase/control join remains incomplete, and its token must not be equated with a trusted live Mach sender without that missing provenance. [RC7,RC10]

At the entitlement-query frontier, X0 is the modeled task, X1 the modeled string, and X2 points to child FP-0x60. Original0x10046F0B0 initializes that8-byte error-output cell to zero. A source theorem proves the query argument/save pattern for arbitrary task/string reference words and frame addresses. The API's return value, error output and entitlement type/value are unobserved. [RC4,RC6]

## Selector and cross-range control flow

The original pre-key expression at0x10046F070..F098 normalizes for every u64 R to `low32(R) XOR0xC6D66014`. The following source MADD decodes the u32 field as `stored24 + preKey32*0x6B86592F`. Composing this with the retained caller's `stored24=phase21-K40(R)-0xA5D` gives selector `phase21-0xA5D=0x8BB2` for phase21=0x960F. No pointer-alignment restriction is needed for these local arithmetic identities; readable native storage is a separate premise. [RC3,RC4]

The non-NULL R+0x10 pointer in the actual caller selects original slot0x10107FC80 ->0x100333680 at BRAA0x10046F13C, IA/7908. That target lies outside the `LC_FUNCTION_STARTS` interval `[0x10046EF4C,0x10046F89C)`. The source trace supplies the cross-range edge; containing-function metadata alone would miss this continuation. Alternative selector/pointer combinations are not native admission evidence. [RC2,RC8]

Three other calls in the listed function interval have separately resolved conditional bank contracts: CFArrayGetValueAtIndex at0x10046F658, CFNumberGetTypeID at0x10046F6C4 and CFGetTypeID at0x10046F744. The bank capture checks every byte input at each pair, as well as the string constructor's pair:1024 inputs total. Their exact slots/imports are established under the recorded bank/table roots. Their connection to the eventual8BB2 entitlement-value handling is not proved by these profiles, which stop before retrieval. [RC8]

## Shared state and output-marker interpretation

The callee performs u64 writes at0x10046F068 ->0x1010C4EB0 and0x10046F06C ->0x1010C4670. If the preloaded words are A/B and H=child FP-0x58, both receive:

```text
new = u64(((A - H + B) XOR 0x73D046208EAED1A6) * 0x0A5CD4CF)
```

The formula is proved for arbitrary u64 A,B and FP. The second cell is the protected core's earlier u32 control-word source, so the function introduces an actual shared-state write across the caller/callee boundary. Widths differ: these writes are64-bit; earlier bank-control consumers read32 bits. Native initialization, concurrency and synchronization semantics remain unknown; the formula alone does not identify a lock, secret or authorization state. [RC2,RC4,RC10]

The output byte through R+0x10 is cleared by STRB at0x10033369C before the string constructor. In both modeled constructor-NULL paths, STRB at0x1004B115C writes0x5B to R+8 and returns to0x1004C464C with the separate flag still zero. This marker is therefore also produced without reaching entitlement retrieval. It is not, on its own, proof of an entitlement or authorization outcome. [RC5,RC6]

The preceding caller's predicate remains exactly `flag==0 OR marker==0x5B`; its true target is0x1004B4F2C. The conditional NULL returns satisfy that local predicate, but the higher-level meaning of this target and the final operation result are not inferred. No failure-to-grant or failure-to-deny security conclusion follows from this partial path. [RC6,RC10]

| Explicit profile mode | Cases | Frontier/result |
| --- | ---: | --- |
| Strict | 4 | Before unavailable imported allocator data at0x1003336F8 |
| Allocator words supplied | 4 | Before string constructor at0x10033376C |
| String result NULL | 4 | Marker5B, flag0; return to original caller |
| String result non-NULL | 4 | Before SecTask construction at0x10047D9AC |
| String non-NULL, task result NULL | 4 | String-release request; marker5B, flag0; caller return |
| String/task results non-NULL | 4 | Before entitlement retrieval at0x1002B7728 |

API return models clobber X0-X17 and NZCV with recorded patterns while preserving the declared callee-saved state. Vector-register clobbers are not varied. CFRelease is a recorded request with no modeled native refcount effect. The models demonstrate source behavior under declared outcomes; they do not establish native allocation failures, successful objects, resource effects or framework delivery. [RC6]

## Validation, assumptions and reproducibility

Eleven source obligations produce22 original/simplified UNSAT files: key input/decode and caller composition; paired-state update; constant key bytes; allocator/string arguments; the full token copy; task arguments; query arguments; zero error-cell initialization; and marker-byte storage. The installed SDK27.2 C probe compiles for `arm64e-apple-macos11.0`, asserting token size32, allocator-reference size8 and ASCII selector0x600. Header and LLVM hashes are recorded. This establishes the probe ABI, not a target-framework-version match. [RC1-RC9]

Fresh independent replay checks24 profiles,6260 source visits,1184 reads,552 writes,96 logical control edges and24 boundaries, including28 declared API model transitions. It checks395 unique original instructions, eight token-argument instances, eight conditional marker returns and four entitlement-query frontiers. Strict profiles require all private-read bytes to be source-produced or explicitly declared. Fresh backing patterns preserve unproduced bytes as unknown rather than filling result slots. [RC2,RC5,RC6]

With the preceding pinned Python/Z3 environment, run `probe_daemon_record40_consumer.py`, `recover_daemon_record40_consumer.py`, `prove_daemon_record40_consumer.py` and `validate_daemon_record40_consumer.py` under `triage_evidence/`. The validator recompiles the SDK probe, rebuilds contracts/proofs and independently replays each profile. Time is O(profile/source bytes + visits + BV/compiler/solver resources); space is O(one CPU map/journal + expression DAGs). Byte widths and counts are exact.

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RC1 | Pinned backing image/fixups identify source and imports | Rehash original bytes; verify chained words and every visited opcode; regenerate bank selection |
| RC2 | Caller-private bytes and declared callee environments define the tested checkpoint | Four controller/private-byte patterns per mode; strict definedness; native universal setup-state invariance remains unproved |
| RC3 | The actual caller's key/control/token fields match the retained source epoch | Prove30 constant bytes and selector composition; compare all256 token bits; preserve the unresolved upstream phase4F79 join |
| RC4 | Local source equations and argument cuts compose as recorded | Rebuild11 obligations and22 SMT files; distinguish mathematical pointer words from valid native objects/storage |
| RC5 | Private record/input/output cells are valid for their stated accesses | Preserve unproduced result/padding bytes; stop before unknown reads; source writer ledgers identify marker/flag producers |
| RC6 | Allocator/API values are explicit models, not native observations | Keep strict stops; NULL/non-NULL cases; scratch-GPR/NZCV clobbers and fresh replay; actual framework effects and vector-clobber invariance remain open |
| RC7 | A 32-byte token matches data transport but does not establish live sender identity | SDK/LLVM indirect-by-value ABI, original source copy and byte snapshots; trace native message/trailer or other producer before identity claims |
| RC8 | Function ranges, bank candidates and actual paths are separate evidence | Retain the cross-range333680 edge; four bank pairs cover1024 byte inputs; do not infer reachability of secondary type probes |
| RC9 | Installed SDK declarations/probe are relevant ABI evidence | Pin headers/compiler output; record compile target and successful assertions; runtime-framework version matching remains unknown |
| RC10 | Entitlement key, global-state formula and marker do not themselves establish access policy | Stop before value retrieval; follow type/value checks and final caller branches with matching owner/control epochs |

## Bounded continuation and quality gates

| Impact | Next target | Information resolved |
| --- | --- | --- |
| High | Consume the entitlement-query return at0x1002B772C | Accepted value types, actual flag writes, NULL/error handling and final policy use |
| High | Trace the32-byte token's native producer through the auxiliary constructor | Whether it comes from authenticated Mach/XPC metadata or another supplied source |
| High | Follow caller target0x1004B4F2C and its alternative with concrete result-channel provenance | Meaning of marker/flag combinations and final operation result |
| Medium | Recover writers/consumers of C4EB0/C4670 beyond this entry | Cross-function state epochs and native environment constraints |
| Medium | Inspect CF/Security implementation boundaries when matching binaries become available | Framework-internal IPC, object ownership and any deeper port interactions |
| Low | Correlate secondary CFArray/CFNumber probes after actual query continuation | Possible entitlement-value schema without guessing its type from the key |

QG1: Factual source/API/ABI analysis requires no normative content.

QG2: RC1-RC10 record dependencies and falsification probes.

QG3: Record40 selector, key, token transport, entitlement-query interface, shared-state writes and conditional marker returns are covered for this increment; the full goal remains active and incomplete.

QG4: u8/u32/u64 domains,32-byte aggregate transport, encoding versus length, modular formulas and complexity are explicit.

QG5: Entitlement key versus endpoint name, token bytes versus sender identity, marker versus decision, and modeled outcomes versus native effects are distinguished.

QG6: Original bytes/fixups, source lemmas, SDK/LLVM, strict journals and independent replay provide traceable provenance.

QG7: Impact-labeled continuations cover policy consumers, upstream provenance, shared environment and framework interfaces. No new source-level Mach send/right transfer or IOKit selector is established.
