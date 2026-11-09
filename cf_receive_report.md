# CoreFoundation reception, registration caching and daemon callback ABI

The available installed dyld cache supplies the previously missing framework side of the daemon's CFMachPort interface. Its receive helper requests an AV trailer, initially offers 3072 bytes, grows storage on `MACH_RCV_TOO_LARGE`, and forwards the received buffer with the header's inline size to the CFMachPort callback. The callback size excludes the trailer. The run loop frees grown inline storage after dispatch; this operation does not establish disposal of the message's OOL mappings or port rights.

All eleven recovered MIG requests have fixed inline sizes of 24..164 bytes. Their original size guards were rechecked: each request plus the requested 68-byte trailer fits in the initial 3072-byte capacity. Thus the earlier synthetic 112-byte-capacity RPC502 truncation witness does not describe this ordinary fixed-size framework path, subject to F1-F5 below. This closes a capacity prerequisite, not a native transaction or authorization proof.

A separate finding changes how registration evidence must be interpreted: `CFMachPortCreateWithPort` can return an existing cached object for the same numeric name without replacing its callback or context. Passing `0x100425f78` at registration is therefore insufficient to establish the effective callback on a reused object. The later [daemon registration recovery](daemon_registration_report.md) establishes five local named check-in/wrapper/source chains and stored CF fields; actual cache history and namespace/object identity remain active requirements.

## Provenance and assumption register

Analysis date: 2026-11-01. Addresses are preferred, unslid virtual addresses. The available cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`; CoreFoundation UUID is `7fe5392e-ff16-31e1-8552-3a45c6b68224`. Its path is `/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation`. The inspected libsystem_kernel UUID is `f2bceb9a-0fec-3c92-b6ea-8e37157050a8`. Actual loaded-image pairing, runtime interposition, PAC state and port-object identity are unknown.

The original daemon thin-image SHA-256 remains `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. Two fresh read-only IDA wrapper ranges match original bytes. The matching kernel collection SHA-256 remains `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, kernel UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84`.

[Original-byte contracts](triage_evidence/cf_receive_contracts.json) retain 23 complete compiler-bounded CF ranges, two libkernel voucher-hook ranges, 49 exact instruction assertions, eleven original stub/fixup/export resolutions, eleven daemon request-size guards, six bit-vector proofs, four physical cache-file hashes, SDK compile results and original daemon imports. [Fresh wrapper readback](triage_evidence/cf_receive_live_wrappers.json), [wrapper xrefs](triage_evidence/cf_receive_daemon_wrapper_xrefs.json) and [IDA knowledge recall](triage_evidence/cf_receive_ida_recall.json) are retained separately. Recall supplied locators; stale routing descriptions were not accepted as new evidence.

| ID | Assumption | Dependent results | Stress test / falsification probe | Status |
| --- | --- | --- | --- | --- |
| F1 | Available daemon/kernel/cache images are the intended implementation combination | Cross-image chain, addresses and trailer correspondence | Recheck SHA/UUID, original function boundaries and fixups; attest loaded images, slides and bindings | Static identities verified; runtime pairing unknown |
| F2 | Ordinary initialized CF runtime path and valid runtime objects apply | Locking, source lookup and callback ordering described below | Inspect CF flags at `0x1ed891742`, source/object validity, actual registry and mode collection; exercise initialization/rejection alternatives | Private fixtures seed initialized flags=2; full initialization/concurrency unknown |
| F3 | Fixed-size requests retain their validated inline size across successful ordinary scalar receive | Full trailer coverage for the eleven MIG forms | Recheck original size guards and native packer; vary size, map width, error status, scalar/vector route and kernel-generated inputs | Eleven native guards verified; runtime receive unobserved |
| F4 | ABI-preserving original control transfers, relocation and PAC contracts hold | Indirect callback path and context fields | Match original import words, cache v5 chains, callback signing/authentication discriminators and live PAC | Original instructions verified; private execution bypasses PAC |
| F5 | Runtime voucher hooks and intervening callees preserve the relevant message/trailer bytes | Original kernel audit prefix reaches the daemon/application unchanged | Resolve `___libkernel_voucher_init` input, inspect table+0x18/+0x20 callbacks and observe post-adoption native bytes | Hook boundary recovered; installed runtime targets/effects unknown |
| F6 | Explicit helper/object/allocation/callback models describe only their stated private fixtures | 42 finite execution profiles and 229 checks | Rehash all original executable pages; stop on unknown reads/writes/code; vary validity, rights, cache reuse, statuses and context functions | Finite private cases verified; no native reachability claim |
| F7 | Numeric service-name registration and cached-object history are established separately | Published endpoint -> effective CF object -> daemon callback assignment | Five local check-in/wrapper/source chains are now recovered in [daemon_registration_report.md](daemon_registration_report.md); match actual cached objects, kernel endpoints and right generations | Local requested registration verified; runtime effective assignment unknown |
| F8 | Opaque application implementations obey their shown output and resource contracts | Successful request OOL/right lifetime and actual reply validity | Trace allocations, descriptor ownership, output lengths and cleanup for every implementation; recover RPC700 receiver | Unknown beyond prior per-routine evidence |

## Native function and call boundaries

| Boundary | Original address | Established contract |
| --- | --- | --- |
| Daemon create wrapper | `0x100001f50`; call `0x100001f8c` | Null allocator, signed callback `0x100425f78`, zeroed 40-byte context, Boolean output |
| Daemon existing-name wrapper | `0x100001f9c`; call `0x100001fdc` | Incoming u32 name, same callback/context, returned CF object |
| Public create / internal body | `0x184752484` / `0x184812774` | Public thunk sets hidden W4=1; internal body allocates receive right, inserts send right, then creates CF object |
| Public with-port / internal body | `0x18472cfe8` / `0x1848121b0` | Public thunk sets hidden W5=1; query right type, registry lookup/new object, validity check |
| Create cached run-loop source | `0x18472d178` | Version1 context, `info=CFMachPortRef`, cached-source reuse/replacement |
| Generic source creation | `0x18472d31c` | Version1 context perform+0x40 is signed into source+0xa8 |
| Get source port | `0x1847e8924` | Reads u32 CFMachPort+0x14 |
| Internal run loop | `0x184756e7c` | Stack receive buffer, source lookup, inline-size forwarding, voucher context and grown-buffer cleanup |
| Service Mach port | `0x184758a28` | Six input arguments, fixed initial capacity, receive/error/retry behavior |
| Source1 dispatch | `0x184758bc8` | Source validity, locked state transition, authenticated perform lookup and handled Boolean |
| Source1 perform bridge | `0x184758ec0` | Calls perform `(message,size,defaultAllocator,info)` and stores returned reply pointer |
| CFMachPort perform | `0x184784050` | Calls user callback `(CFMachPortRef,message,inlineSize,contextInfo)`; returns null framework reply |
| Boost creation | `0x1847841ec` | Reads TSD13; when nonnull, creates type37 object and retains the voucher through `_os_retain` |

The internal original names `__CFMachPortCreate4` and `__CFMachPortCreateWithPort4` are nlist names; the suffix does not establish an ABI version. Original cache fixups resolve the receive stub `0x188076b60` to exported `_mach_msg` at `0x180547f94`. The [user-library/trap report](user_trap_interface_report.md) covers that library's downstream packet/trap ABI and runtime hook table.

```text
daemon registration wrapper
    -> CF cached/new port object -> version1 run-loop source

Mach receive -> CF service helper -> buffer + local receive name
                                      |
                     run-loop source lookup / TSD13 voucher
                                      |
                         DoSource1 -> perform bridge
                                      |
                         CFMachPortPerform / optional TSD12 boost
                                      |
                   daemon callback 0x100425f78
                       -> five MIG families -> application
                       -> daemon reply send 0x100035184
                                      |
                   CF restores context; frees grown inline buffer
```

The full run loop, actual source lookup and application callback were not executed. Two fixtures stage original service, original source/perform, and original run-loop cleanup phases with explicitly constructed private objects. This tests value forwarding and order across those phases, not a native receive transaction.

## Registration and source context

The with-port constructor initially writes `shouldFreeInfo=true`, then calls `_mach_port_type`. Its admission predicate is:

```text
status == 0 && (types_u32 & 0x00070000) != 0
```

| Type bit | Value | Admitted by this predicate alone |
| --- | ---: | --- |
| SEND | `0x10000` | Yes |
| RECEIVE | `0x20000` | Yes |
| SEND_ONCE | `0x40000` | Yes |
| PORT_SET | `0x80000` | No |
| DEAD_NAME | `0x100000` | No |
| None / failed query | 0 / nonzero status | No |

Admission does not prove possession of a receive right. The actual receive-name lookup has separate namespace/right checks in [kernel_namespace_report.md](kernel_namespace_report.md). Private cases cover each row and a failed type query.

Under the global registry lock at `0x1ed890a88`, the constructor scans the registry referenced by `0x1ed890e90`. A matching object's u32 name at+0x14 causes retain/reuse without substituting the new callback or context; `shouldFreeInfo` remains true. An invalid matched object is released and returns null in the selected path. A new object stores the callback at+0x30, context info at+0x40 and context retain/release at+0x70/+0x78; it clears `shouldFreeInfo` after creation. The new-context retain callout occurs while the registry lock is held. The daemon's zero context supplies no such callout.

The public hidden monitor flag is 1. SEND/SEND_ONCE type bits can enter monitor initialization and dispatch-source construction; RECEIVE-only fixtures skip that branch. The fixture's dispatch-source allocator explicitly returns null, so successful monitor construction, asynchronous invalidation, name reuse and dispatch-source teardown are not validated here.

`CFMachPortCreateRunLoopSource` rejects an invalid port, retains/reuses an existing valid source at CFMachPort+0x28, or releases an invalid cached source before replacement. Original instructions construct this full 72-byte version1 context:

| Context offset, bytes | Meaning / original value |
| --- | --- |
| 0 | version=1 |
| 8 | info=CFMachPortRef |
| 16 / 24 | CFRetain `0x1846db030` / CFRelease `0x1846e1278` |
| 32 | description `0x18481206c` |
| 40 / 48 | equality `0x1847791a0` / hash `0x18472e5f0` |
| 56 | getPort `0x1847e8924` |
| 64 | perform `0x184784050` |

Generic source creation authenticates and re-signs the version1 perform pointer into source+0xa8 with storage-address discriminator `0xc0b6`; DoSource1 uses that same discriminator, verifies the authenticated address against its stripped value, and prepares the perform call. Version0 has a different signature discriminator (`0x8a15`) at the same storage offset. The fixtures seed an unsigned pointer and bypass PAC, so the original instructions establish the contract but private execution does not validate a signature.

## Receive ABI, options and growth arithmetic

The installed `___CFRunLoopServiceMachPort` takes:

| Register | Role |
| --- | --- |
| X0 / W0 | Receive name; may denote the run loop's selected receive facility, not necessarily one CFMachPort's name |
| X1 | In/out message-buffer pointer |
| X2 | Out u32 live/local receive name |
| X3 / W3 | Timeout bit pattern |
| X4 | In/out voucher-adoption state |
| X5 | Optional out copied voucher-object pointer |

The initial capacity is always `0xc00` = 3072 bytes. `_mach_msg` emission at `0x184758ac4` uses `(buffer,options,0,capacity,receiveName,timeout,0)`. It is receive-only: send size and notify name are zero. Timeout `0xffffffff` selects options `0x07000806`; other u32 values select `0x07000906`, adding receive-timeout bit `0x100`. Both contain receive, large-message, voucher and AV trailer selector7 bits. No elapsed-time behavior was measured.

| Receive result | Native continuation |
| --- | --- |
| 0 | Return true, preserve buffer output, publish received header+0x0c as live name |
| `0x10004004`, TOO_LARGE | Allocate/reallocate grown buffer; release optional copied voucher before retry |
| `0x10004003`, TIMED_OUT | Free grown storage if owned; clear buffer/live-name outputs; return false |
| Other, including fixture body-error `0x1000440c` | Enter original cold failure routine `0x1848d4550`; diagnostic/BRK, without normal callback delivery |

For a reported u32 inline size S, original instructions compute:

```text
t_u32 = (S + 68 bytes) mod 2^32
C_u64 = (zero_extend(t_u32) + 3 bytes) & 0x00000001fffffffc
```

For `S <= 0x02ffffbc`, the complete-domain proof establishes `S+68 <= C <= S+71`, alignment to 4 bytes, and `C < 2^32`. That condition agrees with the previously recovered ordinary Mach2 vector primary-send guard; it is not asserted for every kernel-originating message. For all u32 S, the unconditional arithmetic bound is `C <= 2^32` and 4-byte alignment. These are arithmetic results, not allocation/reachability results.

| Private reported S, bytes | Computed C, bytes | Interpretation |
| --- | ---: | --- |
| 4096 | 4164 | First allocation receives null old pointer; original stack buffer is excluded |
| 8192 after prior growth | 8260 | Realloc receives previously owned heap pointer |
| `0xfffffffc` | 64 | u32 addition wraps; deliberately out-of-normal-bound synthetic case |
| `0xffffffbb` | 4294967296 | u32 sum=`0xffffffff`; u64 rounding reaches 4 GiB; fixture stops before allocation |

No finite retry limit or decreasing timeout/deadline is visible in this helper. The same timeout is passed on each retry. Its safe-reallocation entry passes a null recovery context; failed allocation reaches `___CFReallocationFailed` and BRK1. The general reallocation implementation also supports a recovery callback when a nonnull context is supplied elsewhere; this call site does not supply one.

## Trailer coverage, callback size and ownership

The matching native kernel packer selects 68 trailer bytes for map64 AV selector7. The run loop passes `LDR W4,[message+4]` to DoSource1 at `0x184757708`, hence the callback receives inline size U, not U+68. These fixed inline sizes are independently backed by eleven freshly retained load/compare/reject instruction triples:

| MIG ID | Inline U, bytes | U+68, bytes |
| --- | ---: | ---: |
| 1200 | 64 | 132 |
| 1201 | 164 | 232 |
| 1202 | 84 | 152 |
| 1203 | 100 | 168 |
| 1204 | 24 | 92 |
| 1000 | 60 | 128 |
| 1001 | 160 | 228 |
| 1002 | 80 | 148 |
| 502 | 80 | 148 |
| 41471 | 40 | 108 |
| 61471 | 64 | 132 |

Maximum required capacity is `164+68 = 232 bytes <= 3072 bytes`, leaving 2840 bytes of capacity. For RPC502, audit bytes occupy request offsets `[100,132)` and fit in the complete delivered extent `[0,148)`. The kernel's null-task audit template contains eight zero u32 words; the original packer/template are retained in this increment, with the full provenance path in [kernel_user_copyout_report.md](kernel_user_copyout_report.md). F5 remains necessary because runtime voucher hooks are an intervening callout boundary.

The earlier U=80, T=52, B=112 truncation witness remains a valid synthetic packer case, but B=112 is not this helper's ordinary fixed-size capacity. This does not establish completeness for arbitrary malformed sizes, vector/aux routes, unsupported maps, changed libraries, partial-body errors or externally modified callback buffers.

DoSource1's Boolean means a valid source was handled, not that the application ran or accepted a request. A valid source with an invalid CFMachPort, or a null perform pointer, returns handled=true in private cases without calling the daemon. `___CFMachPortPerform` returns null even when the modeled daemon callback returns `0xdeadbeef`; the source bridge writes that null into the generic reply pointer. Consequently the generic framework reply send at `0x184757744` is not used by this normal CFMachPort perform path. The daemon separately emits its own replies at `0x100035184`.

| Resource | Established disposal boundary | Remaining contract |
| --- | --- | --- |
| Original stack inline buffer | Not passed to realloc/free in the selected helper/cleanup | Full run-loop frame lifetime/native validity |
| Grown inline receive buffer | Free on timeout; after successful callback, run-loop `0x1847577c4` frees nonnull buffer differing from original stack pointer | Exceptional unwinding/reentrancy paths |
| Generic framework reply pointer | CFMachPort perform returns null; other source1 perform APIs may return a reply | Other source types and their allocator/send failures |
| OOL receiver mappings | Freeing inline storage does not dispose mappings referenced by descriptors | Successful application lifetime, especially502/61471 |
| Message port rights | No generic `mach_msg_destroy` established by these selected normal CF cleanup paths | Daemon/application error/success ownership and monitors |
| Daemon's separately allocated reply | Managed by daemon callback paths already recovered | Full successful outputs and transfer/disposition semantics |

The daemon's five explicit incoming-OOL cleanup stubs and its error-dependent destruction remain documented in [daemon_receive_interface_report.md](daemon_receive_interface_report.md) and [interface_abi_report.md](interface_abi_report.md). No resource-leak conclusion follows from the absence of generic body destruction in these framework slices.

## Voucher/TSD context and external callouts

After each `_mach_msg`, the service helper calls `_voucher_mach_msg_revert(previousState)`, then `_voucher_mach_msg_adopt(message)`, and stores the returned state. If an optional copy-output pointer exists and adoption state differs from -1, it calls `_voucher_copy`; otherwise that output becomes null. A copied voucher is released before a TOO_LARGE retry. This is separate from audit-token bytes and from the adopted-state scalar.

Original libkernel adopt/revert veneers load runtime table `0x1ed83e8d8` and tail-call authenticated members+0x18/+0x20 when present. Empty adoption returns -1. The original cache chain points to the 48-byte empty table, but `___libkernel_voucher_init` can replace it; runtime callbacks are unknown. The fixtures cover both sentinel state and a modeled non-sentinel state, including optional-copy suppression and release-before-retry. They do not execute those runtime callbacks or prove their effects on message bytes.

The run loop installs the copied voucher in TSD slot13 before source dispatch (`0x1847576c0`) and restores the previous value afterward (`0x184757788`), using an `_objc_release` cleanup pointer. Boost creation reads TSD13 and retains that voucher via original `_os_retain`. CFMachPort perform temporarily caches a newly created boost at object+0x60 only when the old value is null and the new value is nonnull. For a valid port on that branch, it places the boost in TSD12 before the daemon callback and clears TSD12 afterward. Existing cached boost and temporary new boost have separate reference scopes; all four old/new-null combinations and the invalid-port case are checked.

If a context retainer exists, perform retains info under its object lock, unlocks before the daemon callback, then invokes the associated releaser afterward. A release-only context does not cause an unmatched per-call release. These context callouts are absent in the daemon's zero context. Actual QoS, voucher propagation, monitor scheduling and downstream behavior are not established from the object names or private reference models.

## Reproduction, bounded continuation and quality gates

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/probe_cf_receive.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_cf_receive_delivery.py
```

The verifier re-extracts original contracts, runs six SMT queries, syntax-checks the SDK layout for `arm64e-apple-macos13.0`, checks all private executable-page hashes, validates 229 assertions across 42 profiles and refreshes the owned artifact manifest. Compile assertions cover the 40-byte CFMachPort context, 72-byte source1 context, callback type, 24-byte user header, 68-byte trailer and option constants. No host framework, target callback, native IPC, target loader or IDB mutation executes.

Extraction costs O(B+S+I+H) time and O(B+S+I) space for selected bytes B, original symbols S, instructions I and streamed source-hash bytes H; solver complexity is separate. Each private profile is limited to 30000 instructions and bounded mapped memory; the 4 GiB boundary is stopped before allocation. Constructor lookup scales with registry count; receive retries have no derived finite bound. Message-copy cost scales with delivered bytes; allocation, scheduling and nested callback costs are outside that simple bound.

[Historical/SDK source manifest](triage_evidence/cf_receive_references.json) pins Apple CF-1153.18 files and local SDK headers. Historical CFRunLoop's helper has a seven-argument interface including buffer size; this installed implementation has six arguments and initializes its own capacity. Historical source is nomenclature/context evidence, not a substitute ABI. Exact installed source revision is unknown.

| Impact | Further interface / falsification target |
| --- | --- |
| High | Trace every service registration through bootstrap result, cached-object history and run-loop insertion; match destination kernel objects/name generations rather than inferring from callback arguments. |
| High | Recover successful incoming OOL/right disposal for502/61471. Inline-buffer free and message-body destruction are distinct operations. |
| High | Recover actual voucher-table initialization, adopt/revert callouts, TSD cleanup and boost/dispatch monitor effects; test native runtime module pairing and observed post-hook trailer bytes. |
| High | Identify RPC700's receiver and per-service application authorization. The common callback's five families do not include700. |
| Medium | Recover run-loop mode/port-set updates, asynchronous invalidation, reentrancy and complete CF object/dispatch-source destruction; constructor admission alone is broader than receive-right ownership. |
| Medium | Bound oversized retry sequences and abnormal status/allocation behavior using actual kernel-generated sizes; synthetic u32-wrap witnesses do not establish native feasibility. |
| Low | Match exact installed CF source/build and preserve the known historical ABI difference in future annotations. |

QG1 factual technical scope. QG2 F1-F8 retain dependent results, probes and status. QG3 passes for this installed-cache receive/registration increment; the full interface objective remains active. QG4 byte extents, register widths, contexts, alignment, arithmetic and complexity are explicit. QG5 callback size versus allocation/delivery, source handled status versus application invocation, cached versus new registration, inline storage versus message resources, and native versus modeled runtime effects are separated. QG6 original files, nlist/exports/fixups, fresh IDA ranges, SDK, six proofs and source-hashed finite fixtures retain provenance. QG7 impact-bounded continuation is above. [Machine-readable quality gates](triage_evidence/cf_receive_quality_gates.json) and [profile assertions](triage_evidence/cf_receive_profile_checks.json) record the verified increment. No full-goal completion claim is made.
