# FPSD1200 audit-token and entitlement admission prefix

The original FPSD1200 carrier now reaches its backend without replacing the protected dispatcher. It decodes phase `0x6cf4` and operation `0xad952088`, then queries Security using an exact copy of the received 32-byte audit token. The first entitlement key is `fairplay-client`, accepting the selected numeric/text conversion paths; failure enters a separate Boolean lookup for `com.apple.private.fpsd.client`. Sixteen controlled failures return through original frames with status `0xffff5bbb` and zero adapter stack delta. Eleven other cases stop before the next audit-PID extraction call. These are original-code/private-environment results, not native authorization or certificate acceptance. [FA1-FA8]

This extends the [FPSD1200 serializer/wrapper/parser contract](fpsd1200_contract_report.md). Its successful 212-byte replies still use protected-output fixtures. This increment establishes selected real failure producers and the preflight path preceding further payload processing; it does not establish a successful FairPlayIOKit operation.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| FA1 | The pinned daemon slice and its selected IDA code spans identify the reference. All addresses, data literals and roles depend on this identity. | Rehash the original image, independently recapture source bytes and compare 51 fresh IDA span hashes. Native module pairing remains separate. |
| FA2 | Normalized original format12 pointers and bypassed PAC preserve the selected private control transfers. All private continuations depend on this model. | Decode 182 rebase words and 21 bind/import records, including signed addends; retain original modifiers and compare fresh replay visits. Native pointer signing/authentication is untested. |
| FA3 | Fixed disjoint private request/stack/object regions and preserved-register stack-check imports provide the modeled environment. Frame/record and return observations depend on these fixtures. | Compare GP/SP/NZCV checkpoints, original copy bytes and complete terminal stack/private hashes; recover native mappings, probing, aliases and concurrency separately. |
| FA4 | CF/Security/type/conversion/cleanup APIs return the explicitly recorded fixture values and memory effects. Admission branches depend on these premises. | Vary NULL/error/type/conversion/Boolean cases; replay every callsite and argument independently. No entitlement, credential, CF object or effective native API result is obtained. |
| FA5 | The received audit bytes represent the fixture input, not a demonstrated kernel credential. Security call identity and provenance depend on this distinction. | Compare all 32 bytes at every copy and SecTask call, including zero and all-one controls. Establish matched native trailer production and sender/task lifetime before attributing actual authority. |
| FA6 | Recorded phase/table values hold at each source cut. Lifted selector and marker equations depend on those phases. | Check source operands and every phase checkpoint; rerun eight UNSAT queries and two SAT premise controls. These are local algebra certificates, not a whole-program/native theorem. |
| FA7 | The installed SDK header explains source-level SecTask contracts, without identifying the runtime Security implementation. Sender/task terminology depends on this source context. | Rehash the header and exact declarations; determine actual runtime library/version, revocation and API failure semantics separately. |
| FA8 | Finite traces and sampled pointer extents delimit this result. General interface/ownership and byte-bank claims depend on their stated coverage. | Independently replay 27 cases, exhaust 17 bank composition identities and retain 864 unpaired bank observations. Unknown/interleaved lookups and later processing are not promoted to complete semantics. |

## Primary provenance [FA1,FA2,FA7]

| Object | Identity / evidence |
| --- | --- |
| Original daemon arm64e slice | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; preferred base `0x100000000` |
| Read-only live IDA | Input metadata SHA-256 `4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7`; all 51 selected source-span hashes agree with the slice. Selected-byte agreement is the assertion used here; the input and thin-file hashes differ. |
| Security source context | Installed SDK logical header `Security/SecTask.h`, SHA-256 `f10e7bc0490568fef3e542d10fd0a8b4d0d657f090d5841782e325faecb4bd68`; declarations retained in the checks |
| Source extent |51 maximal contiguous visited spans, 4346 original instructions, 17384 bytes; these are not 51 independent C functions |
| Original pointer context |182 format12 rebases and 21 binds/imports, with original target words and signed import/pointer addends checked |

Primary artifacts: [source, proofs and profiles](triage_evidence/fpsd1200_admission_checks.json.zst), [live IDA hashes](triage_evidence/fpsd1200_admission_ida_readback.json.zst), [producer](triage_evidence/recover_fpsd1200_admission.py), [independent event replay/oracles](triage_evidence/audit_fpsd1200_admission.py), [publication audit](triage_evidence/verify_fpsd1200_admission_publication.py). Historical IDA memories were used as leads; the recovered operation-specific path is checked against original bytes and fresh IDA hashes. No IDB mutation occurred.

The SDK declares a SecTask created from the Mach-message audit token, with NULL indicating creation failure, and an entitlement-copy API returning an owned CF value. Its NULL result can indicate a missing entitlement or an error. Consequently a modeled NULL lookup below is not a native finding that a sender lacks an entitlement. These declarations establish source context; the exact runtime Security implementation remains unknown.

## Original control and data flow [FA1-FA6]

```text
original FPSD1200 demux/stub/wrapper
  -> adapter 0x10065ffd8 -> shared core 0x10061a2d0
  -> phase 0x6cf4 / operation 0xad952088
  -> operation leaf 0x1004666ec
  -> second protected record / adapter 0x1004d4268
  -> nested entry 0x1004bd65c -> preflight 0x10052db58
       |
       +-> fairplay-client helper 0x100414874
       |     exact audit copy -> SecTask -> entitlement value
       |     number/string conversion -> marker 7f or 7e
       |
       +-> 7f ------------------------------------+
       |                                          |
       +-> 7e -> private Boolean fallback         |
                   same original audit bytes      |
                   true --------------------------+
                   other -> encoded failure       |
                                                  v
                              audit_token_to_au32 at 0x100581f2c
                              [stop before imported implementation]

failure -> original protected return -> adapter delta 0
        -> status ffff5bbb -> MIG input deallocation fixture
        -> original 36-byte error reply
```

No CPU/register/stack reset occurs at the protected adapter or operation leaf. The original wrapper-produced carrier and 104-byte payload remain in the same private machine. The payload's received-local-name word, application word, audit token, OOL address/count and output destinations therefore come from the preceding MIG path. The fixture using application word 2 and declared OOL extent 756 reaches the same audit-PID boundary; it supplies readable private backing bytes and does not replay the actual certificate. No input OOL byte is read in any of these 27 prefixes. That is a finite ordering/data-flow result, not a bound on later payload access.

| Entry / continuation | Recovered role and source-backed relationship |
| --- | --- |
|`0x10065ffd8` | Shared protected adapter; receives the original carrier and delta cell; calls core at `0x10066022c` |
|`0x10061a2d0` | Shared core prefix; original decoding reaches operation `0xad952088` in W1 at `0x1005283ac` |
|`0x1005765e8` | Exact operation comparison under phase `0x6567`; matching selector `0x865f` reaches `0x1004d0640` |
|`0x1004d0640` | Payload NULL/non-NULL split; the selected nonnull payload reaches slot `0xa823` /`0x1004666ec` |
|`0x1004666ec` | FPSD1200 record marshalling: loads incoming fields and output destinations, copies the audit token, builds the next protected record and calls `0x1004d4268` at `0x100466a08` |
|`0x1004d4268` /`0x1004bd65c` | Nested protected adapter/entry; uses a second stack-probe fixture of 4640 bytes, following the shared core's 68944-byte request |
|`0x10052db58` | Admission preflight staging; copies the token and invokes the first entitlement helper at `0x10052ddcc` |
|`0x100414874` | Audit-token/key helper; its passed record contains the audit pointer at +0, original key C-string pointer at +8 and returned marker byte at +16. Converted numeric storage is separate from that key pointer; no numeric output schema is inferred from it. |
|`0x1004de208` | Fallback continuation after the first helper fails; creates a new SecTask from another exact copy of the same 32 audit bytes |
|`0x100581dd0` | Joined path after the first helper or fallback passes; copies the token twice and reaches the audit-PID extraction boundary |

The shared phase and operation labels now have actual decoder/route observations, replacing the preceding report's opaque-boundary treatment for this prefix. They do not name the complete FairPlay algorithm. Arbitrary continuation fragments inside the protected core are not assigned independent C prototypes.

## Security, CF and conversion boundaries [FA4,FA5,FA7]

All sites below are original indirect callsites. Exact import names, selected format12 records and PAC modifiers remain in the evidence. The API implementations are fixtures; the callsites and their arguments are original instructions.

| Original callsite | Exact imported boundary | Established argument/data flow |
| --- | --- | --- |
|`0x100414b90` |`CFStringCreateWithCStringNoCopy` | Allocator 0, original literal `fairplay-client` at `0x100e36a91`, encoding `0x600`, modeled allocator-null object |
|`0x1000ed438` |`SecTaskCreateWithAuditToken` | Allocator 0; X1 points to an exact 32-byte copy of the received audit token, matching the SDK's indirect aggregate ABI context |
|`0x1000fe9a8` |`SecTaskCopyValueForEntitlement` | The first modeled SecTask/key objects; writable error-result cell supplied |
|`0x1000d9590` /`0x1000d95e0` |`CFNumberGetTypeID` /`CFGetTypeID` | Compare expected Number type identity with the returned entitlement value's type |
|`0x1000ed940` |`CFNumberGetValue` | Value object, numeric type code 3, writable 32-bit destination; its Boolean return controls helper success |
|`0x1000d99ac` /`0x1000d9a04` |`CFStringGetTypeID` /`CFGetTypeID` | Alternate String-type comparison |
|`0x100124c54` |`CFStringGetCString` | Value object, 32-byte buffer, encoding `0x600`; conversion result gates the textual route |
|`0x1000b7a44` |`strtol` | Converted buffer, writable end-pointer cell, base 10; its result is later stored with a 32-bit store at `0x100054a0c` |
|`0x1004de2bc` |`SecTaskCreateWithAuditToken` | Fallback creates another task object from the same original 32 audit bytes |
|`0x1005b9e98` |`CFStringCreateWithCStringNoCopy` | Literal `com.apple.private.fpsd.client` at `0x100e5c240`; separate modeled key object |
|`0x1005b9f00` |`SecTaskCopyValueForEntitlement` | Fallback task/key; error pointer NULL |
|`0x100524870` /`0x1005248c0` |`CFBooleanGetTypeID` /`CFGetTypeID` | Require Boolean type on the fallback value |
|`0x100555148` |`CFBooleanGetValue` | Its true/false result selects the fallback result marker |
|`0x100581f2c` |`audit_token_to_au32` | X0 points to the copied audit token; X1..X5 and X7 are NULL, X6 is nonnull, first stack argument NULL. The earlier [original libbsm ABI recovery](daemon_request_application_report.md) identifies this selected output as PID. This increment stops before the imported implementation. |

### First helper result and numeric/text semantics

On the recorded helper paths, byte 7f indicates success and 7e indicates failure. At `0x10052ddd0..0x10052de54`, original code compares the returned byte against the phase-derived 7e. Equal selects fallback `0x1004de208`; unequal selects `0x100581dd0`. The consumer predicate alone accepts any unequal byte: an abstract SAT control preserves that distinction from the helper's established two-marker domain.

| Controlled API/type condition | Original local result |
| --- | --- |
| Number type, conversion returns true; written values 0, 1, 2 or `0xffffffff` | Helper byte 7f; direct audit-PID boundary |
| Number conversion returns false, with no write or a modeled write of 1 | Helper byte 7e; fallback queried |
| String type, C-string conversion true, base 10 parse end points to final NUL | Helper byte 7f; direct audit-PID boundary |
| C-string conversion false | Helper byte 7e; fallback queried |
| Modeled parse end is NULL or points to a non-NUL byte | Helper byte 7e; fallback queried |
| Unknown first-value type, NULL first lookup, task creation failure or key creation failure | Selected failure route reaches fallback; exact call/release sequences vary |
| Fallback Boolean type and true | Joins audit-PID boundary |
| Fallback NULL task/value, wrong type or false | Original encoded failure and 36-byte reply |

The direct numeric gate checks conversion success rather than a particular converted integer in the inspected control cut. Later use of converted data remains unknown. The text route tests a nonnull end pointer and NUL at that pointer; the controlled empty-string case reaches the same successful helper path with parse result 0. It therefore does not establish a strict nonempty decimal grammar. A controlled 64-bit parse result `0x100000001` follows the original 32-bit result store; this is a local width observation, not a public output contract. Native libc/CF parsing, overflow/errno semantics, actual entitlement value types and later value use remain unverified.

### Explicit cleanup and environmental boundaries

The fixture error object is passed to `CFRelease` at `0x1000380ec`. First-path value/task/key release sites include `0x100009294`, `0x10014c7ec` and `0x1000a035c`; fallback value/task/key release sites include `0x100473620`, `0x1004a9088` and `0x1005b0b38`. The profile records preserve which releases occur for each NULL/type/failure condition. These calls establish explicit local actions, not native CF retain counts or complete resource ownership. Separate opaque names are used for distinct modeled objects.

The first token bytes 0..31, a zero token and an all-one token are each transferred exactly under their declared API fixtures. Varying those bytes while supplying task/entitlement results does not attest that Security would create those objects or return those values natively. Endpoint access, audit-trailer provenance, sender identity, credentials, task reuse and current entitlements remain unestablished.

## Original return, stack delta and Mach context [FA3-FA6]

In the 16 returning cases, original code writes encoded result `0x74c29dea` to carrier+24. The outer wrapper's XOR `0x8b3dc651` produces `0xffff5bbb`, signed -42053. Its business error name is unknown; it is not assigned a POSIX or MIG error label.

The adapter initially stores `seed-224 mod2^64` in its internal scratch cell. Before original return, the core restores the full seed in that cell. At `0x100660230..0x10066023c`, the adapter computes `((low32(scratch)-low32(seed)) AND0xffff)<<4`, yielding zero. Thus the 16 failure paths establish the zero delta through original instructions, replacing the preceding contract report's zero-delta fixture for these paths only. A second SAT control confirms that an arbitrary unrestored low16 difference need not yield zero; no general native stack-delta invariant is asserted.

| Interface / location | New observation and bound |
| --- | --- |
| Received-local-name and response destination | Preserved from the preceding original MIG path; no new endpoint identity or port producer is established |
| Original error serialization | The 16 failures produce a 36-byte reply with the source-decoded nonzero application status |
|`0x10000468c` | Original call to `mig_deallocate(input_OOL_address,input_count)` is reached after these application returns; the API is modeled, then original address/count clearing executes |
| Successful port/OOL outputs | Not produced on these completed nonzero-status paths; the 11 other cases stop before PID extraction and do not produce replies |
| Mach emission | No new `mach_msg` send call or native transport executes in this prefix; reply preparation is separate from the outer send operation |

The client reply parser and outgoing disposition 19/received 17 distinction remain in the [previous contract](fpsd1200_contract_report.md). This increment does not identify a FairPlayIOKit connection by a task-local name or claim that a successful entitlement query implies complete service authorization.

## Verification and quality gates

An independent replay uses the frozen image loader but separate PAC transfer, event handling and checkpoint logic. It does not import the admission producer. It replays 108443 original instruction visits, 405 import events, 513 GP/SP/NZCV checkpoints and 200 original 32-byte copy calls. Terminal comparisons cover 15925248 stack/private bytes across 27 cases. All first/fallback SecTask tokens and all copy destinations match the corresponding original 32 input bytes.

Seventeen adjacent-family bank composition identities pass all 4352 byte inputs and cover 2296 observed pair uses. Another 864 lookup reads are retained as unpaired observations, including reused/interleaved setup values; automatic pairing does not certify them or imply a complete protected-selector analysis. The eight UNSAT queries concern carrier-label cancellation, operation/non-null selectors, Number-conversion marker, first-helper consumer, restored scratch delta and status round trip. Two SAT controls demonstrate the helper-domain and scratch-restoration premises. Original code/operand, format12/import, SDK declaration and 51 IDA-span comparisons are rechecked independently of those algebra claims.

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/recover_fpsd1200_admission.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/audit_fpsd1200_admission.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="triage_evidence:$Z3_PYTHONPATH" Z3_LIBRARY_PATH="$Z3_LIBRARY_DIR" "$PYTHON" -P triage_evidence/verify_fpsd1200_admission_publication.py
```

The generator reuses the retained IDA attestation; a fresh live IDA read is separate. JSON archives are compressed with the required ultra22 policy after round-trip checks. The publication audit verifies the exact owned manifest delta, the three preserved original inputs and absence of analyst-machine path literals. Extraction/replay is O(C(B+F+K)+R+256N) time and O(B+F+C*K+R) retained space for cases C, image bytes B, fixups F, bounded visits K, retained evidence R and bank identities N. Solver time is separately capped at 15 s per query. Byte extents and 32-/64-bit modular arithmetic are exact; no native timing, hardware/PAC, concurrent scheduling or statistical claim is made.

| Gate | Scoped result |
| --- | --- |
| **QG1** | Pass: factual technical interface analysis. |
| **QG2** | Pass: FA1-FA8 state dependencies and falsification probes. |
| **QG3** | Pass for this increment: operation routing, audit propagation, both entitlement paths, conversion/fallback controls, actual failure return and next external boundary are covered. The full goal remains active. |
| **QG4** | Pass: exact arithmetic, source offsets, copied extents and terminal states reproduce. |
| **QG5** | Pass within scope: empty text, wide parse result, false conversion with a write, NULL/error lookup, unknown type, failed task creation and partial bank pairing remain distinguished. |
| **QG6** | Pass: original bytes/fixups, read-only IDA hashes, SDK declarations, independent replay and publication checks support the stated claims. |
| **QG7** | Pass: impact-ranked architectural continuation below preserves unresolved native and cross-layer requirements. |

| Impact | Further evidence needed |
| --- | --- |
| High | Continue the exact audit-PID call/return and subsequent provider/library/IOKit path, preserving the original FPSD1200 carrier and frame. Determine which modes and converted values influence the later operation. |
| High | Recover actual Security/CF implementation, error handling and matched native audit/service/task context before attributing effective admission or credentials. |
| High | Establish real output producers, zero/nonzero status conditions, returned OOL allocation and port-right provenance; this prefix has not reached a successful daemon-kext transaction. |
| Medium | Recover the complete numeric/text helper contract, overflow/errno behavior, converted-value lifetime and unpaired/interleaved selector data flow. |
| Medium | Join failed preflight cleanup to outer receive-loop and client ownership behavior under native errors/restarts and concurrent task/object lifetime changes. |
| Low | Compare the distinct request 1000/1200 and other application wrappers by their own carrier tags and identities; numerical request IDs do not unify endpoint policy. |

This is one completed investigation increment. The full multi-level interface goal remains active and incomplete.
