# CoreADI adid: header/selector codecs, context identity and error production

The subsequent [context-gate report](adid_context_gate_report.md) resolves additional state-view and guard details. The local vector loop has a reversible per-byte model;original stores overwrite early tag edits before consumption. Under state0xd5b,the observed tag equality selects the error path. Late field alternatives are explicit inconsistent private states and do not establish valid native contexts or faults. The exact inverse,mutation ledger and pointer/branch proofs are retained there.

The provider's original header/argument transforms, a local six-selector set, setup-marker property-list interface, per-user filename selection and final payload-error producer are now connected. The earlier byte comparison selects cleanup; it is not the producer of -45025. Three requests retaining private state still produce that payload error, and all 50 previously listed numeric entitlement patterns reach it under the completed baseline fixture. Successful operation semantics and native endpoint/provider pairing remain unknown. The full investigation remains active.

## Identity, assumptions and evidence

Addresses are preferred virtual addresses in the provider arm64e image, base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. The [receiver](adid_receiver_report.md), [startup](adid_startup_report.md) and [request/persistence](adid_request_report.md) reports pin the earlier source and state. These addresses are distinct from fairplayd, CoreFP and the kext.

Original reference files, SDK headers and the installed account declaration were read. Analyst declarations were compiled to assembly, local SMT queries were solved, and original source instructions ran in bounded private Unicorn memory. No native target, loader, IPC, target-persistence, environment or synchronization API was executed. Supplied inputs and IDBs remain preserved.

| Assumption | Dependent result | Stress test / falsification boundary |
| --- | --- | --- |
| C1: the pinned image and SDK declarations describe the inspected reference objects | Every address, symbol, constant and width | Fresh instruction/function/fixup/literal/SDK readbacks agree. Actual runtime image and implementation remain unknown. |
| C2: the retained private state and declared PAC/vector/API models permit these continuations | Finite source execution and response paths | Six fresh executions, including a retained-state sequence, match retained source/event streams. They use the same declared emulator/API models, not an independent emulator or native execution. |
| C3: captured local prefixes apply to the arithmetic reductions | Five full-domain codec/set proofs | Source operands/constants and concrete instruction windows are checked. The proofs cover only their declared bit-vector domains and prefixes, not whole-request admission or successful algorithms. |
| C4: explicit audit identities, marker statuses and virtual filesystem metadata describe the stated cases | UID/path/marker control | Audit EUID 265/501 agrees with the supplied token words. Marker alternatives, parent directories, records, zero/-1 values and missing/wrong-type keys are separated. Native files, permissions, namespace replacement, errno/TLS effects and credentials remain unobserved. |
| C5: bounded CF object/type/data models describe the selected parser interface | Marker schema and numeric-output data flow | Source receives the exact analyst XML bytes. Python plistlib and explicit CF outcomes are fixtures; they do not prove native parser acceptance. Numeric false-return/output-cell cases isolate local control and do not reproduce a native conversion. |
| C6: the installed account declaration supplies configuration context | UID 248 / setup-account association | `/etc/passwd` declares `_mbsetupuser` UID/GID 248 and home `/var/setup`. This is not a live credential query or proof that source resolves that account by name. |
| C7: captured record windows are observations, not complete native types | Context-record prefix and status cells | Producer stores and the address key corroborate selected fields. Other bits remain untyped, including apparent addresses. Diagnostic reads are bounded to mapped private memory; an earlier instrumentation-only read failure was corrected and the cases regenerated. |
| C8: resetting callback arguments while retaining all private memory/API models describes the stated repeated-request experiment | Three-request sequence | Source streams differ while all three payloads remain -45025. Native reentry, allocation, CF/XPC object lifetime, port rights, concurrency and independent messages are not established. |

Artifacts: [profiles](triage_evidence/adid_context_profiles.json), [static contracts/proofs](triage_evidence/adid_context_contracts.json), [fresh checks](triage_evidence/adid_context_checks.json), [quality gates](triage_evidence/adid_context_quality_gates.json), [producer](triage_evidence/probe_adid_context.py), [SDK declarations](triage_evidence/adid_context_layouts.c), [compiler output](triage_evidence/adid_context_layouts.s), [setup-account declaration](triage_evidence/adid_setup_account.json) and [validator](triage_evidence/validate_adid_context_delivery.py).

## Header and argument contract [C1-C3]

The 28-byte client request has three big-endian u32 words, followed by two big-endian 64-bit fields. The first 64-bit field has the six negative client values; the second remains semantically opaque.

At `0x10016a800`, the assembled header word N enters the following u32 expression:

```text
H(N) = (N XOR 0xf577f73e) + 0x0acedfe8
       + ((N << 1) & 0xeaefee7c)                mod 2^32
     = N + 0x0046d726                          mod 2^32
```

A full 32-bit-domain proof establishes the reduction. Every retained header-prefix observation matches the constants and the original big-endian word. The following rejection results are finite source observations; the proof does not establish the entire parser's accepted language.

| Controlled header change | Retained payload reads | Reply bytes | Signed i32 |
| --- | --- | --- | --- |
| Word 0: 0, 2 or `0xffffffff`, other words unchanged | 4 bytes | `ffff5026` | -45018 |
| Magic: 0 or `0x632b8d6f`, other words unchanged | 12 bytes | `ffff5025` | -45019 |
| Word 2: 0 or 2..8, other words unchanged | 12 bytes | `ffff5024` | -45020 |
| Client words `[1,0x632b8d6e,1]` | Later reaches all 28 bytes | Continues into persistence/context processing | Successful operation remains unproved |

These invalid-header fixtures do not reach lstat. They distinguish rejection layers from the later -45025 result.

The two assembled 64-bit fields pass through the original fold ending at `0x1001af170`:

```text
A(N) = N + 0xda8ca8cae5dfbd2d
       - ((N << 1) & 0xb5195195cbbf7a5a)        mod 2^64
     = N XOR 0xda8ca8cae5dfbd2d
```

The full 64-bit proof and every retained operand pair agree. This establishes an encoding transform, not a pointer or identity type for the opaque field.

## Local selector partition [C1-C3]

The source at `0x1001ca3fc` applies this partition to the encoded first argument:

```text
j = (selector XOR 0xda8ca8cae5dfbd2d)
    + 0xda8ca8cae5dfbd30                       mod 2^64
member = (j <= 7 unsigned) AND ((1 << j) & 0xeb) != 0
```

A full 64-bit-domain proof establishes the exact set:

| Signed selector | j |
| --- | --- |
| -8 | 5 |
| -6 | 7 |
| -5 | 6 |
| -4 | 1 |
| -3 | 0 |
| -2 | 3 |

This local set exactly matches the earlier CoreFP constructor set. It does not prove server admission, entitlement sufficiency, operation success or a complete function-level dispatch mapping.

## Context-record prefix [C1-C3,C7]

Original bridge `0x1001459b0` invokes the large context routine `0x100104e90`. The retained observation window is 64 bytes; that is not an asserted allocation/type size. The inspected producer constructs selected fields using a key derived from low32(record_address):

```text
K32 = ((low32(record_address) XOR 0x075d910d) * 0xd756578d) mod 2^32
```

The alternative source expression uses OR-minus-AND, XOR and multiplication; its full 32-bit reduction is proved. For record address `0x7a037b58`, K32 is `0x6a77f3d1`.

| Offset | Width | Observed source-supported interpretation |
| --- | --- | --- |
| +0 | 4 bytes | Status cell; context return stores `0x0059248f` at `0x1001247fc` in the baseline |
| +4 | 4 bytes | XOR-keyed control word; baseline raw `0x6a77ff29` decodes to `0x0cf8` |
| +8 | 1 byte | Add-keyed tag; `(raw + K32) & 255` gives `0x62` |
| +9 | 1 byte | Add-keyed tag; same reduction gives `0x38` |
| +12 | 4 bytes | Producer writes a key-added control word; full semantic role unknown |
| Remaining observed bits | Various | Unknown; snapshot values and apparent address-shaped fields are not promoted to a complete ABI type |

The returned status numerically matches the caller's retained expected marker. The caller also has a conditional-comparison shortcut; equality alone is not a complete context-success proof. Native status meaning, all record variants, object construction and lifetime remain open.

## Setup-marker parser and record identity [C1,C2,C4-C6]

```text
audit EUID, no setup marker
  -> per-user discovery: /Users/Shared/adi/adi-XXXXXXXX.pb

setup marker present
  -> marker parent/context -> marker bytes -> no-copy CFData
  -> immutable property-list parse -> dictionary/type checks
  -> key kBuddingRunningForUID -> signed32 numeric output
  -> zero/default handling -> per-user record filename
```

| Original interface | Site | Contract / retained observation |
| --- | --- | --- |
| First marker query for the nonroot path | `0x10016cc24` | `/var/db/.AppleSetupUser` |
| Fallback query | `0x10016ccd4` | `/var/setup/.AppleSetupUser` |
| CFData wrapping | `0x1001061ac` | Original bytes, signed 64-bit CFIndex extent, `kCFAllocatorNull` as bytesDeallocator |
| Property-list parsing | `0x100106248` | Imported allocator, CFData, options zero (`kCFPropertyListImmutable`), format/error outputs NULL |
| Dictionary lookup | `0x1001063ac` | Original CFString key `kBuddingRunningForUID` |
| Numeric conversion | `0x100106510` | `CFNumberGetValue`, type 3 (`kCFNumberSInt32Type`), four-byte output cell initially 248 |
| Record discovery | `0x1001088fc` | Uppercase eight-digit hexadecimal field in the observed paths |

The SDK states that `kCFAllocatorNull` prevents the CFData wrapper from freeing its bytes. This identifies the requested ownership contract, not the complete native buffer/CFData lifetime. The native parser implementation was not executed.

| Identity / parser fixture | Observed subsequent filename |
| --- | --- |
| Audit EUID 265, both markers absent | `adi-00000109.pb` |
| Audit EUID 501, both markers absent | `adi-000001F5.pb` |
| Missing key, parser failure, string `501` or Boolean true | `adi-000000F8.pb` |
| Numeric 265, successful declared conversion | `adi-00000109.pb` |
| Numeric 501, successful declared conversion | `adi-000001F5.pb` |
| Numeric -1, successful declared signed32 conversion | `adi-FFFFFFFF.pb` |
| Numeric zero, successful declared conversion | `adi-000000F8.pb` |

The audit EUID, rather than the opaque request field, explains the first two filename changes. This finite evidence does not prove every UID-to-path transformation. Present-marker cases use the marker's parent (`/var/db` or `/var/setup`) before the CF parser. Missing/wrong-type/zero cases select value 248 in the retained paths. The installed `_mbsetupuser` declaration independently matches UID/GID 248 and home `/var/setup`; no account lookup by name is inferred.

The retained source immediately after numeric conversion does not branch on its Boolean return. Two explicitly synthetic false-return cases distinguish an unchanged output cell from a written value 501: the former yields `...00F8.pb`, the latter `...01F5.pb`. They demonstrate local output-cell consumption, not actual native conversion behavior. The SDK documents that lossy/out-of-range conversion can return false while placing its best conversion in the output; exact native rounding/range behavior remains unknown here.

Supplying zero-sized per-user record metadata for the advanced UID fixtures completes a -45025 reply. Modeling reads of the seeded opaque private record and an analyst empty property list also retains that result. Those files are not established as valid production records or as a successful operation prerequisite.

## Final status producer, serialization and cleanup [C1-C3,C7]

The final encoded payload error is selected at `0x10019be08` as `0x005874c0 - 0x12 = 0x005874ae`, stored in a private status cell at `0x10019c0b4`, and loaded into W5 at `0x10019cfc0`. The preceding captured comparison at `0x10019bde0` has equal operands `0x16e4e4d3`; the upstream helper's complete semantics and native prerequisite remain unknown.

The earlier status cell holds `0x0058748a`, loaded at `0x10019cc18`. It is distinct from both final encoded status `0x005874ae` and expected marker `0x0059248f`. The private byte comparison at `0x10021abe8` selects cleanup branches through original authenticated slots `0x1002c97b8` / `0x1002c97d0`, resolving to `0x10021ac54` / `0x10021ac1c`. It is not assigned the role of producing -45025.

The original serializer folds an encoded u32 N and writes four big-endian bytes. Its full 32-bit reduction is:

```text
T = N + 0x99556a80
    - ((0x3f4db6e2 + (N << 1)) & 0x335d1e1e)  mod 2^32
wire_u32 = T XOR 0x99ae8f0f
         = N - 0x0059248f                       mod 2^32

N = 0x005874ae -> wire_u32 = 0xffff501f -> signed i32 -45025
```

| Stage | Original source site |
| --- | --- |
| Serialize bytes at buffer offsets 1,0,2,3 | `0x1002028a8`, `0x1002028bc`, `0x1002028c4`, `0x1002028d0` |
| Copy to final reply buffer | `0x1001fcca8` |
| Return the original 48-byte core record | `0x1000aa910`; wrapper status zero and output extent four |
| Set dictionary key `data` | `0x1000aa9fc`; `ff ff 50 1f` |
| Request reply emission | `0x1000aaa70`; `xpc_dictionary_send_reply` |

The byte-store order, final copy and XPC payload agree. Wrapper status zero and the signed payload error remain distinct. A symbolic error name and successful producer path are unknown. Native libxpc Mach message emission and port/right identity are not established by these source/API observations.

## Retained-state and entitlement controls [C2,C4,C8]

Three requests reuse private mutable memory and API models, resetting only callback arguments, stack/return entry and observation counters. Their hook counts are 45844, 42543 and 42312; all emit `ffff501f`, with different complete original-instruction digests. This excludes a change to a different payload result in this particular three-request model, not all warm-state behavior.

All 50 locally listed numeric entitlement bit patterns were tested through the completed baseline context. They all emit -45025, while their source streams reflect classifier differences. This does not prove full entitlement equivalence, native caller admission or absence of other operations/providers.

## Verification and bounded continuation

The increment passes **35124 assertions** across **106 private cases**, **5 full-domain local proofs**, 19386 unique original instruction records, 13 compiler-bounded ranges and 4104105 retained source visits. Six fresh replay runs total 276361 hooks. The source API records total 7230; fresh SDK compilation returns zero.

Fresh readback covers original instruction bytes, complete ordered source streams, compiler-bounded ranges, chained pointers, cleanup branch slots, the original CFString object/characters, account declaration and SDK headers/assembly. Six fresh runs check baseline error production, numeric output consumption and the complete three-request sequence. The earlier instrumentation-only failure is absent from the regenerated sequence; unclassified bits remain untyped.

```text
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_adid_context.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_adid_context.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_adid_context_delivery.py
```

Readback uses O(B+F+R+V) time/space for source image bytes B, fixups F, unique instructions R and visits V. Every private request has a 300000-hook cap; SMT has separate 30 s/query caps. Counts, byte extents and integer widths are exact. Native timing, parser equivalence, allocation and concurrency are not measured.

| Impact | Further discriminating evidence |
| --- | --- |
| High | Recover the upstream helper/record meaning behind comparison `0x10019bde0` and final status production, then obtain a valid successful operation path and concrete IOKit provider/selector calls. |
| High | Establish complete persistent-record schemas and identity binding; resolve the opaque request field, context-record variants and real request/response object construction. |
| High | Pair real client/provider images, credentials, bootstrap/Mach endpoints and libxpc transport; complete legacy Mach compatibility and the separate FPSD certificate route. |
| Medium | Recover complete setup-marker policy, CF parser/conversion edge behavior, buffer ownership and release; distinguish declared account context from runtime identity. |
| Medium | Extend retained-state tests to independent messages, identities and valid data; establish native allocator/errno/metadata/concurrency/shutdown behavior and full port/block/object lifetime. |

QG1-QG7 apply to these stated claims and assumptions. The broad interface objective remains active and incomplete.
