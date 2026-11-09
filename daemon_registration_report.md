# fairplayd service registration, stored CF objects and startup status

Original daemon instructions now connect five named bootstrap check-ins to the common CFMachPort wrapper, main-run-loop source insertion and five stored CF object fields. The names and order match the supplied zut trace. This closes the local registration-chain gap for those five names, conditional on normal startup gates, original pointer/table contents, returning callees and the framework cache behavior documented below.

The service routine attempts all five registrations without checking the intermediate status field. It returns the last helper's status word. Consequently an earlier registration failure followed by final success selects the same recovered `main` continuation as complete success. Failed registrations leave their destination CF-object fields unchanged. These are local control/data contracts; actual native failure feasibility, endpoint availability, stale-object use and resource-loss consequences remain unknown.

## Provenance and assumption register

Analysis date: 2026-11-01. Addresses are preferred static virtual addresses in the original arm64e thin image `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. The image's LC_MAIN entry is `0x100413bb4`. The universal-image relationship remains documented in [interface_abi_report.md](interface_abi_report.md).

[Native contracts](triage_evidence/daemon_registration_contracts.json) retain19 instruction ranges, eight of which exactly match consecutive original LC_FUNCTION_STARTS boundaries; the others are explicit continuation/stub spans. A compiler interval or IDA function is not assumed to be an entire logical human-written routine. Evidence includes27 exhaustive256-input selector banks,27 exact instruction assertions, eight bit-vector proofs, eleven fresh IDA byte matches, original format12 pointers/import addends, five string decoders and SDK layout compilation.

[Private profiles](triage_evidence/daemon_registration_profiles.json) and [706 explicit assertions](triage_evidence/daemon_registration_profile_checks.json) cover14 bounded fixtures. Original instructions execute only in private Unicorn mappings. Host bootstrap, CoreFoundation, callbacks and port operations do not execute. The source image and IDBs are not modified. [Fresh byte readback](triage_evidence/daemon_registration_live_ranges.json) is independent of the [service-routine decompilation](triage_evidence/daemon_registration_services_ida.json) and [helper decompilation](triage_evidence/daemon_registration_checkin_ida.json). Decompiler artifacts are locators, with inherited-register and frame caveats; automatically appended analysis diagnostics were excluded.

| ID | Assumption | Dependent results | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| G1 | This original arm64e image is the intended daemon implementation | Addresses, strings, calls and stored-field mapping | Recheck SHA/UUID, original LC metadata, fixups and fresh IDA bytes; attest loaded slice and code integrity | Original identity/readbacks verified; live pairing unknown |
| G2 | Ordinary ABI preservation and8-byte-aligned record addresses apply | Main's scalar/control-word derivation and indirect local edges | Inspect predecessor register writes, call preservation, stack movement and native PAC; run unaligned formula counterexamples separately | Aligned arithmetic proved; native PAC and full startup execution unknown |
| G3 | Original selector banks, encoded string cells and dispatch words retain the inspected values | Constant call destinations and exact service names | Recheck original chains and all256 selector inputs; recover all runtime writers and observe actual values | Original values verified; full writer/lifecycle audit incomplete |
| G4 | Explicit bootstrap/CF/runtime-data models apply only to the stated private fixtures | Finite success/failure sequences and argument forwarding | Rehash executable pages; stop at unreviewed continuations/imports/system instructions; vary statuses, null results, initial outputs and stack location |14 private fixtures verified; native reachability unknown |
| G5 | The returned CF object has the requested callback, or the reused object's callback is established separately | Effective service -> common callback -> five MIG families | Inspect the actual CFMachPort registry and object history; reject inference from passed callback alone | Requested callback proved; runtime effective callback unknown on cache reuse |
| G6 | Historical zut capture corresponds to the supplied command and preserved bytes | Comparison of five names/order and observed receive rights | Rehash capture, decode raw message payloads, match producer/modules and caller stack | Names/order independently match; historical caller attribution remains conditional |
| G7 | Framework/source APIs return normally and meet their resource contracts | Publication order, local releases and continuation after failures | Inspect framework abort/invalidation/monitor/reentrancy paths and successful native receives; account for receive names and CF references separately | Local calls/order verified; complete native ownership unknown |
| G8 | Prior once/initialization/allocation gates admit the recovered main continuation | Whole-startup relevance and eventual operation after registration | Trace the complete initializer and pre-registration helper, effective environment, namespace rights and next continuation | Local caller chain/gates recovered; complete initialization and later startup remain open |

IDA knowledge-store [recall](triage_evidence/daemon_registration_ida_recall.json) supplied wrapper locators. Its unrelated-layout main/global fact was not applied to this image. Existing names, comments and accepted-memory confidence are not original-symbol or execution evidence.

## Five names and exact stored-field mapping

The registration collection's header address is `0x1010c4cd8`. The destinations below hold **64-bit CFMachPortRef values**, not32-bit Mach names or kernel port pointers. Adjacent header fields are not assigned service meanings without separate evidence.

| Service | Service-routine helper call | Header offset, bytes | CF object destination | Historical guest receive name |
| --- | --- | ---: | --- | --- |
| `com.apple.unfreed` | `0x100538040` |24 | `0x1010c4cf0` | `0xe03` |
| `com.apple.fairplayd` | `0x10053823c` |32 | `0x1010c4cf8` | `0x1303` |
| `com.apple.fpsd` | `0x100538444` |40 | `0x1010c4d00` | `0x1403` |
| `com.apple.arcade.fpsd` | `0x10053865c` |48 | `0x1010c4d08` | `0x1503` |
| `com.apple.fpsd.sim` | `0x10053882c` |64 | `0x1010c4d18` | `0x1603` |

The last column is a separate historical observation from [zut_trace_report.md](zut_trace_report.md); it does not assign those numbers to the static CF cells or current kernel objects. The preserved trace SHA-256 is `78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e`. The extractor independently finds each decoded name including NUL in the five raw message payloads with ID`0x400000ce`, in the same order. Static API attribution supports check-in interpretation; the exact private XPC operation encoding and historical call stack remain separate requirements.

| Service | Original encoded bytes address | Bytes including NUL | Native u8 decoder |
| --- | --- | ---: | --- |
| unfreed | `0x100f496e0` |18 | `(0x6c - 5*b) mod256` |
| fairplayd | `0x100f57dc0` |20 | `(0x35*b + 0x32) mod256` |
| fpsd | `0x100fd7e70` |15 | `(0xf1*b - 0x4f) mod256` |
| arcade.fpsd | `0x100ffe830` |22 | `(0xd3*b - 4) mod256` |
| fpsd.sim | `0x100f2bde0` |19 | `b XOR 0xfc` |

The94 encoded bytes and their original pointer-cell/fixup provenance are retained. Each decoded string has the expected terminator. Native arithmetic is wider before STRB; the stored byte is reduced modulo256. These names come from actual code/data references, independently of the embedded launch plist.

## Main continuation and private calling convention

```text
LC_MAIN 0x100413bb4
    -> bootstrap wrapper 0x1004412b4
         -> pthread_once(control=0x1010b70c8, initializer=0x10045053c)
    -> native status gate
    -> 0x1000a352c -> pre-registration helper 0x100437c18
    -> native second gate -> 0x100083778
         -> stack adapter 0x100539234
              -> five-service routine 0x100537b90
                   -> check-in helper 0x10044011c, five times
```

Original selector-bank/fixup decoding establishes the listed call targets. The once wrapper calls at `0x1004414e8`, signs the initializer literal and reads initialization status at `0x1010b6360`; nonzero once return substitutes`0x74c29cef`. Main's first success comparison uses`0x8b3dc651`. These facts do not constitute complete recovery of initializer`0x10045053c` or pre-registration helper`0x100437c18`, which has additional allocation/state work and continuations.

The main success continuation constructs W23=`0x26de+0x6b67=0x9245`, preserved across its helper call under G2. At`0x100083778`, it encodes the next private record's word+4 using its address. The complete-domain aligned-pointer proof establishes that the five-service routine decodes this word to`0xf44a7867`. Its first child record then decodes to helper state`0x2e4c`; the native fixtures observe that state for all five constructed records. The proofs constrain record address modulo8 to0. They do not establish hardware authentication or arrival through every upstream gate.

The stack adapter at`0x100539234` takes the original record in X0 and an in/out frame-seed pointer in X1, creates a bounded local scratch extent, subtracts240 bytes from its temporary seed and calls the service routine at`0x100539464`. That routine adds240 bytes back. The adapter publishes a16-byte-aligned low16-bit frame delta to its caller. Under normal service return with the shown temporary-seed update, a full64-bit proof establishes that this delta is zero for every initial seed; the local scratch extent remains a separate calculation. These frame operations are part of the private ABI; IDA's apparent standalone prototypes for inherited-register continuations are not accepted as actual source signatures.

The check-in helper consumes this40-byte selected prefix:

| Offset, bytes | Width | Role |
| --- | ---: | --- |
|0 |64 bits | Pointer to destination CFMachPortRef cell |
|8 |64 bits | Pointer to decoded service name |
|16 |32 bits | Out encoded local status |
|20 |32 bits | Unknown/padding in this prefix |
|24 |64 bits | Reserved/input field explicitly zeroed by the service caller |
|32 |32 bits | Address-encoded control word |
|36 |32 bits | Unknown/padding |

The selected header prefix is72 bytes. [Layout assertions](triage_evidence/daemon_registration_layouts.c) compile against the local arm64e SDK and validate these partial structures, Mach-name width and bootstrap/source API types. They are analyst layouts, not recovered original C declarations.

## Check-in, CF source insertion and publication

| Native site | Operation / arguments |
| --- | --- |
| `0x10044038c` | `_bootstrap_check_in(bootstrap_port,record.name,&receiveName)`; u32 receive-name output initialized0 |
| `0x1003ad234` | On zero check-in status, call wrapper`0x100001f9c` with the received u32 name |
| `0x100001fdc` | Wrapper invokes `_CFMachPortCreateWithPort(NULL,name,0x100425f78,zeroContext,&shouldFreeInfo)` |
| `0x10031733c` | On nonnull CF object, `_CFMachPortCreateRunLoopSource(NULL,object,0)` |
| `0x100315264` | On nonnull source, `_CFRunLoopGetMain()` |
| `0x100315300` | `_CFRunLoopAddSource(mainLoop,source,kCFRunLoopDefaultMode)` |
| `0x10031534c` | `_CFRelease(source)` for the local source reference |
| `0x100315354` | Store the CF port object into the destination cell |
| `0x1001f531c` | Store the encoded helper status into record+16; restore/return |

The bootstrap-port and default-mode imported data bindings carry addends`0x7da61013` and`0x7ed8f1f2`. Native adjustments`-0x7da61013` and`-0x7ed8f1f2` cancel them modulo`2^64` before dereference. Original import-table decoding and a bit-vector proof establish that cancellation. Ignoring import addends would misidentify addresses or fault a private model.

```text
name -> bootstrap_check_in -> u32 receive name
                               |
                     CF create-with-port wrapper
                               |
                     CFMachPortRef, new or cached
                               |
                 source -> main loop / default mode
                               |
                release local source; store CF object
```

All five registrations request callback`0x100425f78` with a zero40-byte context. [cf_receive_report.md](cf_receive_report.md) establishes that a cached object can preserve an earlier callback/context. Thus this mapping establishes requested registration and local storage; effective callback identity needs actual cache history under G5. Under the ordinary requested-callback case, [daemon_receive_interface_report.md](daemon_receive_interface_report.md) supplies all-five-family routing. That does not imply every service authorizes every family: application stubs still receive header+0x0c's local receive name, and deeper policy remains unresolved.

## Failure propagation and resource boundaries

| Failure/result | Local helper behavior | Destination cell |
| --- | --- | --- |
| Nonzero bootstrap status | Skip CF construction; write`0x6263578d` status | Unchanged |
| Null CF object | Skip source creation; write`0x6263578d` | Unchanged |
| Null source | `_CFMachPortInvalidate(object)` at`0x1001ce8cc`, then `_CFRelease(object)` at`0x1001ce910`; write`0x6263578d` | Unchanged |
| Nonnull source / normally returning APIs | Add/release source; publish CF object; write`0x6263fc55` | Returned object |

These are encoded record-status values. A leftover X0 from the last imported call is not promoted to the service routine's semantic status. In particular, the null-object/source fixtures can end with X0=0 while the record contains the failure word.

The complete service-routine span has exactly five BLRAA helper sites. Its only load of the child's status field `[x29-0x78]` is`0x100538830`, after the fifth call;`0x100538838` copies that word to its caller. Native inspection and the private failures establish that it does not aggregate earlier statuses.

| Private sequence | Final record word | Main gate at`0x100083974` |
| --- | --- | --- |
| All five succeed | `0x6263fc55` | `0x10009697c` |
| First check-in fails; later four succeed | `0x6263fc55` | `0x10009697c` |
| Final check-in fails | `0x6263578d` | `0x100027310` |
| Every check-in fails | `0x6263578d` | Final-status rule; separate direct service fixture |

The original main comparison reduces to expected word`0x6263fc55`; its success index is`0xad28`, otherwise`0x9245`. A full32-bit status proof and the three main-continuation fixtures check both targets. The next continuations' complete behavior remains open; neither target is assigned an unverified high-level outcome.

Failure fixtures seed all five destination cells with distinct nonnull sentinels and verify preservation; ordinary initial-file fixtures start them at0. This establishes output definedness, not a native stale-pointer dereference or resource-leak finding. The selected helper has no explicit Mach-name deallocation call on these failure paths. CF invalidation/release, receive-right ownership, dispatch monitors, outer cleanup and restart behavior require separate accounting; a CF object, local source reference, namespace receive name and queued message resources are distinct scopes.

## Additional created-port caller and remaining interfaces

Original continuation`0x1005757cc` invokes the no-input wrapper`0x100001f50` at`0x100575840`, through a separately resolved exhaustive byte bank and authenticated slot. That wrapper calls `_CFMachPortCreate` at`0x100001f8c`, requesting the same common callback and zero context. It is distinct from the five existing-name bootstrap registrations. The protected caller's complete input/frame, returned-object lifetime, raw-port consumers and possible message-descriptor use remain unknown. It is not assigned to header+0x38, a named bootstrap service or RPC1200 without further evidence.

| Impact | Next evidence / bounded implication |
| --- | --- |
| High | Match the five static CF fields to actual objects, their registry/cache history, receive rights and host special-port publication. Original requested callback and historical guest numbers do not prove current kernel destination identity. |
| High | Trace the remaining startup gates and continuations`0x10009697c`/`0x100027310`, including IOKit discovery/open and later run-loop entry; establish native consequences of earlier registration failure and destination preservation. |
| High | Complete successful and failure ownership for acquired receive names, CF objects, source/monitor state, incoming OOL mappings and port rights; identify outer cleanup before any leak/stale-use conclusion. |
| High | The later [arcade handshake report](created_port_report.md) resolves caller`0x100575840` as41471 -> new anonymous CF endpoint -> kernel51471 registration ->61471 subscription upcall. Continue its policy callback,subscription application and complete ownership. |
| High | Resolve RPC700's receiver and application service/audit authorization. The requested common callback does not contain ID700. |
| Medium | Follow the installed `_bootstrap_check_in` implementation into XPC/bootstrap transport and launchd policy, comparing exact packet construction with the preserved trace. Current static API attribution is not historical producer attestation. |
| Medium | Audit writes to string/pointer cells and collection fields, registration reentry, asynchronous invalidation and replacement, preserving CF-cache reuse semantics. |
| Low | Classify additional authenticated-call candidates only after native table resolution. PAC modifier values and standalone decompiler prototypes do not identify semantic callees. |

## Reproduction and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_daemon_registration.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_daemon_registration_delivery.py
```

The verifier re-extracts original ranges/fixups/strings, runs eight SMT queries, checks preserved trace payloads and eleven IDA byte ranges, compiles partial SDK layouts, verifies executable-page/source hashes and validates706 assertions across14 private fixtures. The fixture instruction limit is30000; observed completed paths stay below it. Original code mappings are nonwritable; imported APIs, bootstrap/default-mode cells and object results are explicit private models. Unreviewed native continuations, imports, target system instructions and invalid accesses stop execution. The full once callback, native bootstrap server, CF internals and daemon callback are not executed by these fixtures.

Extraction is O(B+F+I+T) time/space for original bytes B, fixups/function starts F, retained instructions I and trace bytes T; solver cost is separate. Service construction/attempt count is fixed at five, with94 decoded string bytes; nested bootstrap/framework costs and waits have no derived finite bound. Each fixture has bounded mapped memory and instruction budget. The SDK bootstrap header is retained as [primary API context](triage_evidence/daemon_registration_sdk_bootstrap.h.txt), with its exact local source path/hash in the contracts.

QG1 factual technical scope. QG2 G1-G8 state dependencies, probes and current limits. QG3 passes for this local registration/startup-gate increment; the broad interface objective remains active. QG4 byte extents, arithmetic widths, alignment, imported addends, compiled layouts and complexity are explicit. QG5 names/objects, requested/effective callback, per-service/final status, record/X0 result and native/trace/private evidence are separated. QG6 original files/LC ranges/fixups, fresh IDA, retained trace, SDK, eight proofs and page-hashed fixtures support bounded claims. QG7 impact-labeled continuation is above. [Machine-readable gates](triage_evidence/daemon_registration_quality_gates.json) record this increment; full-goal completion remains false.
