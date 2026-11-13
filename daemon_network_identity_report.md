# Daemon network-interface identity cache and IOKit port boundaries

Routine `0x1000040a8` is a six-byte network-interface identity cache. Its cold source tries BSD names `en0`, `en1`, then `en0`, with different filtering modes. Nested helper `0x10000425c` iterates matching services, examines `IOBuiltin`, gets a parent in the `IOService` plane and requests six bytes from `IOMACAddress`. These names, exact import bindings and original instruction bytes establish the local roles. A zero nested result does not prove a fresh MAC read: the missing-MAC-property path returns zero without writing output. [NI1-NI4]

The eight retained positive process-path cases remain stopped before an undefined S+`0x858` pointer. The network helpers are verified from separate entries; this report establishes no continuous native process-path-to-network join, actual hardware identity or FairPlayIOKit transaction. Cold fallback ordering below is original-source analysis; cache controls stop before the first import, and nested controls execute separately under declared API fixtures. [NI2-NI4]

```text
Retained process-path positive continuation
  -> STOP 0x1005a8cd4 before undefined u64 S+0x858

Separate cache helper entry 0x1000040a8
  ready-byte bit 0 set -> optional six-byte copy -> return full ready byte
  bit 0 clear -> IOMainPort -> en0 / mode 1
                 fallback -> en1 / mode 0
                 fallback -> en0 / mode 0
  nested zero status -> ready := 1; cache := six local bytes

Separate nested entry 0x10000425c
  iterator -> IOBuiltin handling -> IOService parent
           -> IOMACAddress property -> CFDataGetBytes(range={0,6}, output)
           -> release CF objects and registry handles
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| NI-A1 | The pinned original thin daemon identifies this build. All address claims depend on that identity. | Rehash the original file, source spans, complete text and original format-12 words/imports. Other builds remain unknown. |
| NI-A2 | Separate helper entry registers, private backing and cache bytes are declared fixtures. Cache controls depend on those premises. | Exhaust all 256 flag bytes with NULL/non-NULL output, two SP placements and strict byte definedness; preserve all eight retained stops without adding roots. |
| NI-A3 | Nested API returns and output writes are explicit ABI fixtures. Registry-path controls depend on them. | Stop before every original import call; record return/output premises and independently verify exact register, flag and byte-state joins. No native handles or property objects are supplied. |
| NI-A4 | The compared current SDK describes the named APIs and arm64e call shapes. Type/ownership terminology depends on that comparison. | Compile width/prototype assertions and a six-byte CFData call; retain relative-header hashes and assembly. Historical SDK/runtime pairing remains unknown. |
| NI-A5 | Original authenticated imports are classified from source fixups and stubs. No hardware authentication is assumed. | Independently decode ADRP/ADD/LDR/BRAA, the GOT-slot modifier and format-12 key/diversity/address-diversity fields. |
| NI-A6 | Single-invocation source order identifies local writes. Concurrent visibility and cache freshness are unknown. | Preserve ready-before-data order and missing-property no-write behavior; require same-build ordered native observations for lifetime/concurrency claims. |
| NI-A7 | This publication changes only its explicit owned paths. Preservation claims depend on exact manifest comparison. | Verify original inputs, receipt/source pins, unchanged entries, compressed round trips and raw/typed/decoded-payload path hygiene. |

## Recovered routine roles and cache ABI

| Original location | Recovered local role | Evidence boundary |
| --- | --- | --- |
| `0x1000040a8` | Optional six-byte identity output; cold lookup and global cache | X0 is optional output; W0 returns the full flag byte |
| `0x10000425c` | Iterator/filter/parent/MAC-property helper | W0 iterator, W1 filtering mode, X2 output; low32 result is status |
| `0x1010c570a` | Readiness byte | Only bit 0 controls warm bypass |
| `0x1010c570b` through `0x1010c5710` | Six cached identity bytes | Four-byte and two-byte loads/stores; no larger structure inferred |
| `0x1010a1718` | Authenticated dispatch pointer to outer helper | IA diversity `0xe9e4`, address diversity 0 |
| `0x1010b19f8` | Constant CFString `IOBuiltin` | Original string pointer and length 9 |
| `0x1010b19d8` | Constant CFString `IOMACAddress` | Original string pointer and length 12 |

The outer helper reserves 64 B; let H be its inner SP. Its optional caller output is preserved in X19. If bit 0 of the readiness byte is set, it skips every API call. With non-NULL output, the source loads four bytes from cache+1 and two from cache+5, writes the final two output bytes first at `0x10000423c`, then the first four at `0x100004240`. The return at `0x100004244` zero-extends the entire readiness byte. Flags 3 and 255 therefore return 3 and 255, rather than normalized 1. NULL output suppresses only that copy. [NI2-NI4]

The cache-population source first stores readiness=1 at `0x100004214`, then four bytes at `0x10000421c` and two at `0x100004224`. The six source bytes are H+[0,6), reused as an output buffer for the nested helper. The initial main-port output also occupies H+[0,4). This reuse and the missing-property no-write branch mean that nested zero status alone cannot establish fresh identity bytes. No native freshness failure or race is claimed. [NI2-NI3]

## Cold selection and status flow

| Stage | Matching name / mode | Main-port output | Matching iterator output | Nested call |
| --- | --- | --- | --- | --- |
| Primary | `en0`, mode 1 | H+0 | H+8 | `0x100004120` |
| First fallback | `en1`, mode 0 | H+12 | H+8 | `0x1000041cc` |
| Final fallback | `en0`, mode 0 | H+12 | H+8 | `0x1000041f4` |

The primary `IOMainPort` status is not tested before the four-byte port-name load at `0x1000040dc`. The two fallback main-port calls test W0 for nonzero before matching. Each matching call tests its low32 status. The primary nested low32 zero branches to cache publication after iterator release; the first fallback does likewise, otherwise it enters the final fallback. The final nested zero publishes; nonzero exits to the optional cached-byte copy and full flag-byte return. The exact failure routes are retained in the complete source region. [NI2-NI3]

Several error routes load H+8 and request `IOObjectRelease` without a source initialization of that cell in this routine before the matching API. The compared SDK promises the iterator output on success. Error-path output definedness therefore depends on the imported implementation or prior state, which are unknown here. Cache-entry controls stop before the first import and do not substitute an error-path iterator. [NI2-NI4]

## Iterator filtering, MAC data and cleanup

The nested helper reserves 96 B; let N be its inner SP. It saves iterator, mode and output in X22, X23 and X20. `IOIteratorNext` returns a 32-bit object name; zero returns literal status 5. In mode 1, a present `IOBuiltin` property is passed to `CFBooleanGetValue`, released, and a zero W25 result releases the service and advances the iterator. A missing property proceeds directly to the parent lookup. In mode 0, a present property is still evaluated and released, but its Boolean result does not control selection. These are exact local rules, not proof that any particular interface is built-in. [NI2-NI4]

`IORegistryEntryGetParentEntry` looks up the first parent in `IOService`, writing its 32-bit name at N+12. Nonzero low32 status skips the property stage, releases the service and returns that status. On zero status, the code requests `IOMACAddress` on the parent. A non-NULL property reaches `CFDataGetBytes(property, CFRange{0,6}, output)` at `0x100004370`, then `CFRelease`. The parent and selected service are released. The helper returns the saved parent-lookup status. If the MAC property is NULL, it skips the data copy and still returns zero. [NI2-NI4]

No local `CFGetTypeID`, `CFDataGetTypeID` or `CFDataGetLength` call appears in either complete helper. The extraction length is a fixed 6 B; property type and length are imported/environmental contracts, not validated by this slice. The absence statement covers these two complete instruction ranges only. [NI2-NI3]

| Separate control | Mode | Result W0 | Six-byte output | Established distinction |
| --- | --- | --- | --- | --- |
| Empty iterator | 1 | 5 | Unchanged | No service selected |
| False built-in then exhausted | 1 | 5 | Unchanged | False property is skipped |
| Parent lookup failure fixture | 1 | 9 | Unchanged | Parent status propagated |
| Missing MAC property | 1 | 0 | Unchanged | Zero status does not imply copy |
| Present MAC property | 1 | 0 | `0123456789ab` | Declared six-byte API output |
| False built-in | 0 | 0 | `0123456789ab` | Mode 0 ignores Boolean selection |
| False then true built-in | 1 | 0 | `0123456789ab` | Releases skipped service and advances |
| Missing built-in property | 1 | 0 | `0123456789ab` | Missing property is not rejected |

The bytes and numeric handles in these controls are synthetic premises. No native CF object, registry property or Mach right is constructed. API-return joins clobber caller-saved registers/flags, preserve X18 through X29, restore the original SP and use each original call's next PC. Void CF calls retain explicit arbitrary X0 values. [NI2-NI3]

## Mach-name flow and exact API-call locations

| Name channel | Original call sites | Machine channel / output | Subsequent local use |
| --- | --- | --- | --- |
| IOKit main port | `0x1000040d8`, `0x100004140`, `0x100004184` | `IOMainPort(0,&name32)`; H+0, H+12, H+12 | Four-byte name passed as W0 to matching helpers |
| Matching iterator | `0x1000040fc`, `0x100004168`, `0x1000041ac` | `IOServiceGetMatchingServices(main,dict,&iterator32)`; H+8 | Passed as W0 to nested helper; caller releases it |
| Iterator service | `0x100004288`, `0x1000042e8` | `IOIteratorNext(iterator32)` returns W0 | Property lookup; release or next iteration |
| Registry parent | `0x100004338` | `IORegistryEntryGetParentEntry(service,"IOService",&parent32)`; N+12 | Parent property lookup and release |
| BSD matching dictionary | `0x1000040ec`, `0x100004158`, `0x10000419c` | X0 CF dictionary reference | Passed to matching-services API; not a Mach-name output |
| Registry CF property | `0x1000042bc`, `0x100004310`, `0x100004358` | X0 CF object reference | Boolean/data API and CFRelease; not a Mach-name output |

| Release role | Original `IOObjectRelease` call sites |
| --- | --- |
| Outer matching iterator | `0x10000410c`, `0x10000412c`, `0x100004174`, `0x1000041b8`, `0x1000041d8`, `0x100004200` |
| Skipped nested service | `0x1000042e0` |
| Nested parent | `0x100004380` |
| Selected nested service | `0x100004388` |

The current SDK makes `mach_port_t`, `io_object_t`, `io_iterator_t` and `io_registry_entry_t` four-byte names. It documents matching dictionaries as consumed by `IOServiceGetMatchingServices`, returned iterator/service/parent handles as caller-release objects, and created property containers as requiring `CFRelease`. Those are API contracts; this report verifies local call sites, not native right retirement. No `mach_port_deallocate` call for the main-port outputs appears in these helpers. [NI2-NI4]

These are API output and consumption locations. No direct Mach send/receive instruction or message routine appears in the two complete helpers; API-internal emission sites, destination identities, receive rights and dispositions are unknown. The interfaces concern general IOKit registry/network state. No FairPlayIOKit provider match, user-client connection or daemon-kext message is established by this helper. [NI2-NI4]

## Original stub and caller accounting

All ten used import stubs consist of ADRP X17, ADD X17, LDR X16 and BRAA X16,X17. Their original authenticated format-12 bind words use IA, diversity 0 and address diversity 1: the modifier source is the GOT-slot address, not a literal diversity-only value. The harness stops at each original direct BL before executing its stub. Independent raw-word decoding verifies the slot calculation and the authentication metadata. The outer dispatch-table pointer uses a different contract: slot `0x1010a1718`, index `0xcf05`, IA diversity `0xe9e4`, address diversity 0. [NI2-NI3]

The complete 14,849,960 B text scan checks 3,712,490 aligned A64 words. It finds the three direct calls to the nested helper at `0x100004120`, `0x1000041cc` and `0x1000041f4`, and no direct B/BL to the outer helper. The full original fixup list contains one pointer to the outer helper, at the dispatch slot above. Indirect computed targets, runtime-created pointers and other instruction forms are outside this census. No caller epoch or live reachability follows from a table pointer alone. The earlier exploratory initializer-compatible continuation is not a retained-source join and is not used to establish such a claim. [NI2-NI3]

## Provenance and verification

| ID | Primary evidence / role |
| --- | --- |
| NI1 | Original thin daemon SHA256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; all addresses are preferred virtual addresses. |
| NI2 | [Extractor](triage_evidence/recover_daemon_network_identity.py) and [checks](triage_evidence/daemon_network_identity_checks.json.zst): both complete helpers, strings, stubs, original fixups, text census, strict journals and three source equations. |
| NI3 | [Independent auditor](triage_evidence/audit_daemon_network_identity.py) and [audit](triage_evidence/daemon_network_identity_audit.json.zst): scalar source lift, register/flag/byte checks, retained and API-premise joins, raw stub decoding and compile-only SDK comparison. |
| NI4 | Current SDK `IOKitLib.h`, `IOTypes.h`, `CFData.h` and `CFBase.h`; relative-header hashes, exact C assertions and arm64e assembly are retained in NI3. Historical SDK/runtime identity remains unknown. |
| NI5 | Unchanged [process-path checks](triage_evidence/daemon_pidpath_consumer_checks.json.zst) and [report](daemon_pidpath_consumer_report.md): eight positive boundaries reconstructed without new roots. |
| NI6 | [Publication verifier](triage_evidence/verify_daemon_network_identity_publication.py): owned delta, manifest preservation, source/receipt pins, archive round trips and path hygiene. |

Eight retained continuations, 512 cache controls and eight separate nested controls yield 592 intervals, 9,077 source visits, 2,744 reads, 3,512 writes and 280 logical edges. The 512 cache controls exhaust 256 flag bytes times NULL/non-NULL output: 256 warm returns and 256 pending first-main-port calls. Nested controls comprise 72 intervals. Independent replay checks 309,408 register values including SP, 9,669 NZCV values, 15,256 read bytes, 26,608 write bytes and 16 authenticated edges. Three nonvacuous source equations prove the arbitrary 48-bit copy, full-byte return and bit-zero predicate. Sixteen original fixup records, ten stubs, 33 direct call sites and two constant CFStrings pass source checks. The current arm64e SDK compilation succeeds. [NI2-NI4]

Warm cache handling and fixed fallback count use O(1) time and storage. Mode-1 iteration uses O(K) time for K returned services and O(1) auxiliary state, assuming each imported operation terminates. The source sets no finite K bound. Extraction/auditing use O(T+C*(I+E)+S+Q) time and space for text words T, cases C, visits I, effects E, captured source S and queries Q, excluding solver cost; queries have a 30 s limit. Large JSON uses zstd level 22 with exact decompression checks. [NI2-NI3, NI6]

## Bounded continuation

| Impact | Open question / pattern | Required evidence |
| --- | --- | --- |
| High | Original caller-to-network join | Same-SP-epoch reaching definitions for S+`0x858`, additional bank roots and every overlapping write; retain the current undefined-root stops. |
| High | Native identity freshness | Ordered matching/parent/property results and exact six-byte output extent; distinguish missing-property zero status from a completed data read. |
| High | Daemon-kext transaction identity | Match provider, connection/task, selector, buffers and ordered request/return identity; general IOKit network queries alone do not establish the pairing. |
| Medium | Main-port and error-path iterator lifetime | Same-build IOKit implementation/contract and ordered name-right observations, including failed calls' output definedness. |
| Medium | Cache publication visibility | Establish synchronization and concurrent callers before interpreting ready-before-data stores as a native concurrency outcome. |
| Medium | Property representation | Same-build property type/length provenance and CF ABI behavior; six-byte extraction is fixed, but no local type/length guard is present. |
| Low | Additional computed callers | Broaden from direct B/BL and original fixup targets to source-proved computed dispatches without treating modifier matches as target proof. |

## Scoped quality gates

**QG1** passes for factual source/interface analysis. **QG2** passes with NI-A1..NI-A7. **QG3** passes for this increment's routine roles, port-name outputs, call locations, cleanup, environmental inputs and local control/data flow; the full goal remains active.

**QG4** passes with byte extents, explicit 32/64-bit channels, source-order stores and complexity. **QG5** passes within scope: the retained root is undefined, missing-property zero status does not imply fresh bytes, failed-call output state remains unknown, and cold fallback analysis is separated from the finite entry/nested controls. **QG6** passes with pinned original bytes/imports, independent replay and current SDK declarations. **QG7** passes with the impact-ranked continuation table. No native API, IPC, allocation/free, hardware PAC or IDB mutation executes. [NI1-NI6]
