# FPSD1200 PID extraction, FPDI dictionary and process-local identity path

The original FPSD1200 path now executes the selected cached libbsm PID extractor and reaches a second entitlement key, `com.apple.private.fairplay.FPDI`. Its dictionary helper copies the dictionary, tests `client-identifier`, converts a selected String value into a 256-byte UTF-8 temporary, and optionally inspects `capabilities` as an Array. The following caller uses the previously recovered process-local buffer/mask, then reaches the once/lock adapter and a request to allocate 44800 bytes. These are private original-code observations under declared Security/CF and environment fixtures. No native credentials, complete authorization, allocation result, Mach emission or successful FairPlayIOKit transaction is established. [FI1-FI8]

This extends the [admission-prefix report](fpsd1200_admission_report.md). The preceding first entitlement gate is still executed in each case; its imported API results remain fixtures. All 25 cases stop at explicit boundaries and produce no complete application reply. The full multi-level interface investigation remains active.

## Assumption register

| ID | Assumption / dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FI1 | The pinned daemon bytes and selected IDA spans identify the reference. All addresses and recovered roles depend on this identity. | Rehash original bytes, decoded fixups, three constant strings and 78 live IDA span hashes. Runtime module pairing remains separate. |
| FI2 | The selected installed-cache libbsm body is composed with this daemon through its logical import. PID results depend on this explicit pairing. | Recheck cache/library UUIDs, exact export, full 140-byte body and all executed library visits. The current cache differs from the earlier retained cache; no native loader pairing is inferred. |
| FI3 | Private request/stack/object mappings, original pointer normalization, skipped PAC and preserved-register stack probes implement the declared machine. All continuations depend on these models. | Independently replay GP/SP/NZCV checkpoints, full terminal stack/private hashes, all image writes and additional `paciza` skips. Native authentication, stack probing and concurrent scheduling remain unknown. |
| FI4 | SecTask/CF APIs have the explicitly recorded fixture results and memory effects. Dictionary, type and conversion branches depend on these premises. | Vary NULL task/value, error object, wrong type, failed dictionary copy, missing key, failed conversion, empty String and Array counts. An inconsistent ContainsKey-true/GetValue-NULL control is labeled and excluded from native API conclusions. |
| FI5 | The audit bytes are fixture input; token word5 is not an observed native process identity. Token-copy and PID conclusions depend on this distinction. | Compare every complete 32-byte transfer, all optional output pointers and PID output bytes, including PID values 0, 1, 123 and `0xffffffff`. Establish matched native message/trailer and task lifetime separately. |
| FI6 | The retained producer buffer is explicitly composed into this prefix, without native temporal continuity. Cache-dependent continuations depend on that composition. | Compare a matched no-buffer/reference-buffer pair, two retained buffer snapshots, every table/context read and exact initial pointer/mask writes. Recover actual initialization, lifetime and synchronization separately. |
| FI7 | The single-thread once fixture invokes the original initializer at a disjoint stack placement; lock operations return the selected modeled status. Allocation-boundary observations depend on these premises. | Check four original callback invocations/returns, callee-saved registers, SP restoration, original global writes and exact lock/allocation arguments. Native pthread state, lock behavior and allocation completion are untested. |
| FI8 | Finite profiles, recorded caller phases and SDK declarations delimit this result. Local status, selector and ABI interpretations depend on their stated scope. | Rerun five local UNSAT queries, enumerate 17 bank identities, retain 800 unpaired bank reads and rehash three SDK headers. Recover capability elements, later validation and complete output producers separately. |

## Primary provenance [FI1-FI3,FI8]

| Object | Identity / assertion |
| --- | --- |
| Original daemon arm64e slice | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base `0x100000000` |
| Read-only live IDA | Input metadata SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`; all 78 selected instruction-span hashes agree with the slice. Input and thin-file hashes differ; selected-byte agreement is the assertion. |
| Current cache / libbsm | Cache UUID `8b1e17c6-72d6-3017-91a4-916022e3612e`; library UUID `ccdec355-884e-36f6-a571-7291f637b936`; logical image `/usr/lib/libbsm.0.dylib` |
| Current exact export | `_audit_token_to_au32`, `0x206c3f758..0x206c3f7e4`, 140 bytes / 35 instructions; SHA-256 `76ed6c9a5a2b1b51e22d1fd36ca9802e734187970d71868438eb981b52e613e5` |
| Earlier libbsm comparison | The [earlier application report](daemon_request_application_report.md) used different cache/library UUIDs and export address `0x20638d758`; the selected body hash is identical. This is body agreement, not runtime interchangeability. |
| Daemon source catalog | 78 maximal contiguous spans, 6468 instructions / 25872 bytes, including three separately identified unretired read-guard instructions; spans are not independent C functions |
| Original pointers | 218 rebases and 26 bind/import records checked against original format12 words, including signed addends; constant-string pointer records checked separately |

Primary artifacts: [source, profiles and certificates](triage_evidence/fpsd1200_identity_checks.json.zst), [fresh IDA readback](triage_evidence/fpsd1200_identity_ida_readback.json.zst), [producer](triage_evidence/recover_fpsd1200_identity.py), [independent replay/oracles](triage_evidence/audit_fpsd1200_identity.py), [publication audit](triage_evidence/verify_fpsd1200_identity_publication.py). IDA knowledge-store search returned no relevant operation-specific fact for this frontier. No IDB mutation occurred.

## Original interfaces and control flow [FI1-FI7]

```text
original FPSD1200 carrier and first entitlement preflight
  -> 0x100581f2c -> selected original libbsm -> PID output
  -> 32-byte token copy -> adapter 0x10049c710
       -> SecTask from the same token
       -> com.apple.private.fairplay.FPDI
       -> Dictionary type -> Dictionary copy
       -> client-identifier key -> selected String conversion
       -> capabilities key -> selected Array inspection
       -> explicit value/dictionary/task cleanup
  -> local record status at +20 -> caller continuation
       |
       +-> missing buffer/mask: stop before read through address zero
       |
       +-> declared retained buffer: original byte transformations
             -> once adapter / original callback fixture
             -> opaque write-lock fixture
             -> malloc(44800) [stop before implementation]

one-element capabilities fixture
  -> CFArrayGetValueAtIndex(array, 0) [stop before implementation]
```

No CPU/stack reset or protected-output replacement is introduced at the PID, dictionary or following caller boundary. The library slot `0x1010a0500` is explicitly bound to the selected cached body in private memory. All other unknown imports stop execution.

| Original site / entry | Recovered role and exact observation |
| --- | --- |
| `0x100581f2c` | Calls the libbsm import with X0 pointing to 32 token bytes; X1..X5 and X7 NULL, X6 nonnull, first stack argument NULL |
| `0x100581f30` | Original daemon return after the library writes token bytes20..23 through X6; residual X0 is not interpreted as status |
| `0x100581f80` | Further original 32-byte token copy before the identity helper |
| `0x100582074` | Calls adapter `0x10049c710` with a 24-byte observed record and a delta cell; record+0 is a destination pointer, +8 a copied-token pointer, +16 an encoded control word, +20 a later local result |
| `0x1004d7ca8` | New `SecTaskCreateWithAuditToken` call from another exact copy of the same audit token |
| `0x100526a50` | `SecTaskCopyValueForEntitlement` using the original FPDI constant-string object and a zero-initialized writable error-result cell |
| `0x10040a818` / `0x10040a868` | `CFDictionaryGetTypeID` and `CFGetTypeID` comparison for the copied entitlement value |
| `0x1004be1a8` | `CFDictionaryCreateCopy(NULL, value)`; API result is modeled as a separate object or NULL |
| `0x100525b74` / `0x100581b48` | `CFDictionaryContainsKey` / `CFDictionaryGetValue` for `client-identifier` |
| `0x100581b90` / `0x100581be4` | String type comparison for the selected client value |
| `0x100531724` | `CFStringGetCString(value, temporary, 256, 0x08000100)`; the rehashed SDK names this encoding UTF-8 |
| `0x100480e9c` / `0x1005ad8d8` | Presence test / selected value lookup for `capabilities` |
| `0x1005ad920` / `0x1005ad96c` | Array type comparison for that selected value |
| `0x100452564` / `0x10046f658` | Array count, then first element at index0 in the one-element fixture; execution stops before the element API implementation |

The library executes 19 of its 35 captured instructions per case. Its sole enabled output is the 32-bit token word at byte offset20. The terminal-information helper branch is unvisited because its output pointer is NULL. All 250 original 32-byte copy calls and every SecTask token match their profile's original audit bytes. None demonstrates that native Security would create the modeled objects or return the modeled entitlement values.

## Constant strings, local result and cleanup [FI1,FI4,FI8]

| Constant-string object | Literal bytes | Length / literal address |
| --- | --- | --- |
| `0x1010b1a58` | `com.apple.private.fairplay.FPDI` | 31 bytes at `0x101033cc3` |
| `0x1010b1a78` | `client-identifier` | 17 bytes at `0x101033d13` |
| `0x1010b1ad8` | `capabilities` | 12 bytes at `0x101033ce3` |

The evidence checks original object bytes, decoded pointer records, literal terminators, flags/length fields and IDA's normalized literal pointers. IDA's class-reference pointer is retained as observed metadata, without treating it as a native object identity. Type IDs 99/7/88 and all CF objects are explicit fixture values, not recovered native CF constants.

| Controlled condition | Original helper observation |
| --- | --- |
| New task NULL; FPDI lookup NULL/error; wrong dictionary type; copy NULL; missing client key | Local word `0x3eb2e254` at record+20 |
| Selected String conversion returns false | Distinct local word `0x3eb2e276` |
| Selected String conversion succeeds, with capabilities absent | Local word `0x3eb38698`; selected caller path |
| Selected client value has another type | The inspected helper skips String conversion and can return the same local matching word; later identity validation remains unresolved |
| Capabilities absent, empty Array, or selected non-Array type | Distinct inspected branches converge on the local matching word under their fixtures; this is not a complete capability policy |
| ContainsKey true but client value NULL | Explicit inconsistent-API control; no native CF behavior or valid dictionary state is inferred |
| One-element capabilities Array | Reaches first element lookup; element content, interpretation and later result unknown |

At `0x100582090..0x100582178`, the caller compares record+20 against `0x3eb38698`. Under recorded W22=`0x55e4`, W16=`0x5bf6`, W25=`0x7e48`, equality selects slot `0x7e63` / `0x10062d24c`; inequality selects slot `0x7e48` / `0x10062a78c`. The local words are not assigned business error names or equated with the outer MIG status. This increment produces no complete reply from any case.

Explicit new release sites include `0x100607b88` for a modeled error, `0x1003a4ce0` for the original entitlement value, `0x10063b298` for its dictionary copy and `0x1003c4674` for the new task. The array/string values are obtained through dictionary getters; no native retain count, complete ownership or library-internal effect is inferred from the fixture objects. Release order and NULL-dependent omissions are retained per case.

## Shared process-local state and later initialization [FI3,FI6,FI7]

The [earlier buffer publication](daemon_buffer_consumer_report.md) established source stores of a buffer pointer into `0x1010c8268` at `0x100315478`, then u32 255 into `0x1010c67d4` at `0x100315484`. The new identity path reads those same cells. The retained producer snapshots are taken from [object initialization context](triage_evidence/daemon_object_initialization_context.json.zst); only their 512 buffer bytes are copied into a disjoint private region, with the pointer and mask explicitly set. Other retained snapshot fields are provenance, not additional initialized runtime state.

Without those two declared values, selected paths reach read-through-zero guards at `0x1003c3254`, `0x100625eac` or `0x10058e484`. Execution stops before the read. This is a missing private-environment dependency, not evidence of a native NULL dereference. The matched reference cases use identical request/API fixtures and differ by the declared buffer context. With it, ten profiles perform 70 checked buffer reads; two distinct retained buffer snapshots reach the once boundary. Every observed read agrees with its selected snapshot.

The source applies address-dependent byte transformations to the helper destination and a later caller temporary. The observed bytes differ by representation/snapshot; the caller temporary is not identified as plaintext or a wire payload. Local source queries bound selected 8-byte table reads under mask255: two forms use offsets at most248, while one separately bounded form has exclusive read end at most263 bytes. These queries do not classify every transformation or establish a complete codec inverse.

| Site / object | Established next architectural interface |
| --- | --- |
| `0x10043e508` | `pthread_once(0x1010b8cd0, 0x10040ebd4)` in the original acquisition adapter `0x10043e280` |
| `0x10040ebd4` | Original initializer executed in four explicit single-thread invocation fixtures, with a 256-byte stack gap and verified callback return/SP/callee-saved state |
| `0x100361df4` | `pthread_rwlock_wrlock(0x1010b7478)`; three profiles supply a record-only success result |
| `0x100419178` | Original `malloc` call with X0=`0xaf00`=44800 bytes in those three profiles; stopped before allocation |

The once/lock adapter is also documented in the [IOKit synchronization report](daemon_iokit_sync_report.md). Reaching a shared adapter does not identify the same operation, lock owner, session or endpoint. The new call chain supplies no allocation result and no initialized 44800-byte arena. Native once state, lock storage/lifetime, allocator behavior and later registry/provider use remain unknown.

## Verification, Mach context and quality gates

Independent replay does not import the identity producer. It checks every original visited instruction and API event, all recorded admission and identity CPU checkpoints, original library transfer/return, all original copies, complete terminal stack/private hashes, provider/global reads and original image writes. The new five UNSAT certificates concern the recorded local selector, three selected mask bounds and token word5 extraction. Seventeen adjacent-family bank identities cover all 4352 byte inputs and 2842 observed pair uses; 800 unpaired reads remain observations. They do not constitute complete selector or whole-program verification.

| Independent check | Exact coverage |
| --- | --- |
| Profiles / stopped boundaries | 25 / 15 missing-environment read guards and 10 imported boundaries |
| Original instruction visits | 138461 total: 137986 daemon and 475 libbsm |
| Imported events | 564, including controlled effects and unexecuted terminal boundaries |
| CPU checkpoints | 425 admission and 311 identity checkpoints |
| Original token copies | 250 complete 32-byte copies |
| Terminal stack/private comparison | 14745600 bytes across the 25 cases; repeated private extents, not native mapping sizes |
| Original initializer / cache reads | Four original once callbacks / 70 provider-buffer reads |

No input OOL payload byte is read in these 25 prefixes. The original received-local-name and response destination remain carried from the earlier MIG path, without a new endpoint identity or port producer. No new `mach_msg` send, right disposition conversion, successful output port/OOL producer or native IPC completion is established. Dictionary/API success and a matching local helper result do not establish complete service authorization.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/recover_fpsd1200_identity.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/audit_fpsd1200_identity.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/verify_fpsd1200_identity_publication.py
```

Generation reuses the retained live IDA attestation; a fresh IDA read is separate. Source/replay cost is O(C(B+F+K)+R+256N) time and O(B+F+C*K+R) retained space for cases C, image bytes B, fixups F, bounded visits K, evidence R and bank identities N; solver cost is separate, capped at 15 s/query. Byte extents and modular widths are exact. JSON archives use ultra22 compression with round-trip checks. The publication audit checks the exact owned manifest delta, three preserved original inputs and analyst-path scrubbing.

| Gate | Scoped result |
| --- | --- |
| **QG1** | Pass: factual technical interface analysis. |
| **QG2** | Pass: FI1-FI8 identify dependencies and falsification probes. |
| **QG3** | Pass for this increment: PID library call, FPDI/field interfaces, local status/control, explicit cleanup, shared-buffer dependency and once/lock/allocation boundaries are covered. Full goal incomplete. |
| **QG4** | Pass: exact byte counts, modular widths, source offsets and terminal states reproduce. |
| **QG5** | Pass within scope: changed cache identity, skipped nonmatching types, conversion error, inconsistent getter control, missing environment and unretired guard instructions remain distinct. |
| **QG6** | Pass: original bytes/fixups, live IDA readback, cache body/export, SDK declarations, independent replay and publication checks support the claims. |
| **QG7** | Pass: the following impact-ranked work preserves unresolved native and cross-layer requirements. |

| Impact | Further discriminating evidence |
| --- | --- |
| High | Continue the original allocation/initialization and registry/provider route from `0x100419178`, preserving the current frame and its identity/PID inputs. Establish actual IOKit arguments and output producers. |
| High | Recover capability element interpretation from `0x10046f658`, remaining schema constraints and later identity validation; do not equate a local matching word with authorization. |
| High | Establish actual runtime Security, audit/service/task context and buffer initialization/lifetime before attributing native admission, credentials or concurrency behavior. |
| Medium | Recover exact record controls, converted-value lifetime and full address-dependent byte transformations, including all unpaired bank observations. |
| Medium | Join native allocation/lock/error cleanup and retry behavior to the existing client/receive-loop ownership contracts. |
| Low | Compare this FPDI dictionary path with other operation tags using independently pinned carrier identities; common helper addresses do not unify endpoint policy. |

This is one completed investigation increment; the full daemon/kext/deeper-interface goal remains active.
