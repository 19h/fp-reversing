# Launchd service endpoint construction, right ownership and receive callbacks

The selected service send-object path in both original launchd slices constructs its underlying endpoint through `_mach_port_construct`, supplies service-name/domain metadata, and wraps the returned name using XPC disposition 17. The user library can use trap -24 or a distinct Mach RPC3231 fallback; both reach the same original kernel construct core. A conditional dispatch Mach-receive source uses the resulting name and invokes a constructor-supplied callback/cookie pair. These findings extend the [host-special publication path](host_special_registration_report.md) and [dual-slice correspondence](launchd_variant_binding_report.md). They establish static interface contracts, not a native endpoint, receiver, right balance or successful FairPlay exchange. [Original source capture](triage_evidence/launchd_service_endpoint_source.json), [checks](triage_evidence/launchd_service_endpoint_checks.json).

## Identity and scope

Launchd universal SHA-256 is `1ba04f6d568343f1be0467e5ef0a4700c4b204b49182eb38f0de636efb176168`; the two slice UUIDs remain `f5ce73f2-36d5-3916-8ab0-ee0d6c8a1d71` and `62af2b7d-327e-334a-a1d7-83777efc3c12`. Cache UUID is `2bd06591-e751-3e84-963f-b08dab6af23a`. Kernel SHA-256 is `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, UUID `9b65bd6e-027b-34d1-a22b-ac03dccffc84`. Full file/slice/tool/header/dependency hashes, cache source files and library UUIDs are retained in the [capture](triage_evidence/launchd_service_endpoint_source.json). Native PID 1 slice selection remains unknown after the prior frozen metadata query returned `EPERM`; no new process query was made.

The capture covers 24 launchd bodies, nine user-library bodies and five kernel bodies: 38 complete compiler-bounded spans, 1,997 instructions and 7,988 B. Of the launchd words, 23 in x1 require LLVM decoding; original-byte coverage and the earlier decoder limitations remain explicit. No recovered construction function, target trap/request, recovered callback, XPC initializer, kernel construct path, or host-special setter was invoked for this increment. Static inspection tools and SDK compilation ran locally. [Counts and scoped checks](triage_evidence/launchd_service_endpoint_checks.json).

## Role and call-site mapping

Analytical names below do not imply recovered C++/C structure names or complete function semantics. Addresses are unslid and slice-specific. [Complete spans](triage_evidence/launchd_service_endpoint_source.json).

| Role | arm64e start | arm64e.x1 start |
|---|---|---|
| Service constructor | `0x100047064` | `0x100046328` |
| Send-object helper | `0x10005cb6c` | `0x10005bb3c` |
| Send-name helper | `0x100046c28` | `0x100045ef8` |
| Options/service-info factory | `0x10000ce68` | `0x10000ccc4` |
| Construct result/name adapter | `0x10000ce10` | `0x10000cc6c` |
| Construct status adapter | `0x10000cdc4` | `0x10000cc20` |
| Domain classifier | `0x10002f94c` | `0x10002efb0` |
| Mach-receive source setup | `0x10005cd90` | `0x10005bd60` |
| Source event block | `0x100047abc` | `0x100046d38` |
| Source cancellation block | `0x100047af0` | `0x100046d60` |
| Byte+8 liveness assertion helper | `0x1000549f4` | `0x100053aa8` |
| Endpoint diagnostic builder | `0x100046ca8` | `0x100045f6c` |

| Operation / emitted request | arm64e site | arm64e.x1 site |
|---|---|---|
| Invoke options/service-info factory | `0x10005cc40` | `0x10005bc10` |
| Call `_mach_port_construct` | `0x10000cde8` | `0x10000cc44` |
| Wrap returned name, disposition17 | `0x10005cc4c` | `0x10005bc1c` |
| Conditional receive-source setup | `0x10005cc6c` | `0x10005bc3c` |
| Call `_dispatch_source_create` | `0x10005cdd4` | `0x10005bda4` |
| Activate source | `0x10005ce90` | `0x10005be60` |
| Later ordinary host-special setter | `0x10003055c` | `0x10002fb60` |

```text
service constructor
  +0x90 callback <- incoming X3
  +0x98 cookie   <- incoming X5
       |
send-object helper, creation mode1
       |
24 B options + pointer to 256 B service-info + u64 guard context
       |
_mach_port_construct
  +-- trap -24 ---------------------> copyin(options,24 B) --+
  +-- status0x10000003 -> RPC3231 ---> OOL options,24 B ------+--> kernel construct
                                                               |
                                                   copyin(service-info,256 B)
                                                               |
                                        service label + guarded port allocation
       |
returned u32 name -> XPC MOVE_SEND wrapper -> service+0x68
       +--> name getter -> host setter RPC413 -> host slot (prior report)
       +--> conditional MACH_RECV dispatch source
              event -> callback(service,0,cookie)
              cancel -> release captured objects
```

The diagram composes static argument and call contracts. It does not establish one native allocation/publication/callback epoch, a final receive-right owner, or that any particular FairPlay job reaches this creation branch [SE1,SE2,SE5].

## Service object state and creation selection

| Object field | Width / role in selected paths | Producer or consumer |
|---|---|---|
| `+0x60` | 64-bit affiliation/context pointer | Constructor saves incoming X0; creation reads owner byte+`0x583` and owner+`0xf8` |
| `+0x68` | 64-bit XPC send-object pointer | Fast-path read, created-object store, later name extraction |
| `+0x70` | 64-bit guard-context counter value | Stores the counter value used for the construct request |
| `+0x80` | 64-bit receive-source pointer | Assert-empty check followed by source store |
| `+0x90` | 64-bit callback pointer | Constructor stores incoming X3; event block branches through it |
| `+0x98` | 64-bit callback cookie | Constructor stores incoming X5; event block supplies it in X2 |
| `+0xa0` | 16-bit flags | Creation branches and conditional receive-source gate |
| `+0xa8` | Address passed as NUL-terminated service name | Factory length/copy path; complete allocation/layout not inferred |

An existing object at `+0x68` returns immediately. With no object, low-three-bit mode1 selects creation, mode2 returns the current object (possibly NULL), mode4 reaches the force-without-port diagnostic, and remaining values reach a distinct diagnostic tail. Creation tests flag bits3 and0 on assertion/crash paths; bit5 takes the canceled-endpoint diagnostic path without reaching the factory in the captured branch. These branch records describe this helper, not all endpoint states. [Exact selected instructions](triage_evidence/launchd_service_endpoint_checks.json).

On the selected creation branch, a global u64 counter at `0x100089a38` is loaded, incremented modulo 2^64 and stored back. Its **old** value is passed to the factory in X4 and saved to service+`0x70`. The captured update uses ordinary load/add/store instructions; global uniqueness under concurrency, initialization, wraparound handling and native scheduling are unknown. This is not a random nonce or cryptographic-authentication claim [SE3].

The helper chooses base flags `0x37` when service flag bit13 is clear, affiliation byte+`0x583` bit6 is clear, and owner-query selector4 returns bit0 set. Otherwise it chooses `0x2037`. Selector4's broader semantic meaning is not newly established. The factory ORs `0x400` into the base flags. [Source and branch checks](triage_evidence/launchd_service_endpoint_source.json).

## Construction ABI and nested records

| Factory input | Argument carrier | Selected send-object caller |
|---|---|---|
| Base option flags | low32 X0 | `0x37` or `0x2037` |
| Queue limit | W1 | 6 |
| Service string address | X2 | service+`0xa8` |
| Domain value, truncated to one byte | low8 X3 | Classifier result 1,2 or5 on its ordinary return paths |
| Guard context | X4 | Old u64 counter value |

The classifier reads the `+0x68` pointer of its input object. In both slices it returns1 for pointer equality with `0x1000895c8`,2 for equality with any of `0x1000896d8`, `0x100089650`, `0x1000898f8`, and5 for equality with `0x100089760`. The other captured path reaches a diagnostic helper. SDK field nomenclature establishes a service domain byte; the human-facing meanings of those global domain objects remain unknown. [Classifier bodies](triage_evidence/launchd_service_endpoint_source.json).

The factory's record construction matches the installed primary SDK declarations:

| Record / field | Offset, B | Extent, B | Produced value |
|---|---|---|---|
| `mach_port_options_t.flags` | 0 | 4 | `0x437` or `0x2437` for this caller |
| `mach_port_options_t.mpl` | 4 | 4 | Queue limit6 |
| `mach_port_options_t.service_port_info` | 8 | 8 | Pointer to stack service-info record |
| Remaining union storage | 16 | 8 | Zero |
| Complete options record | 0 | 24 | Above fields |
| `mach_service_port_info_data_t.mspi_string_name` | 0 | 255 | Name bytes plus terminator |
| `mach_service_port_info_data_t.mspi_domain_type` | 255 | 1 | Low8 classifier value |
| Complete service-info record | 0 | 256 | Above fields |

Nine original vector stores zero all 255 name bytes before the copy, writing 256 B in total because byte239 is covered twice. The domain byte255 is not zeroed by those stores; a separate byte store supplies it. Two independently checked store footprints retain this distinction. `strlen > 254` selects the literal `<endpoint name too long>`; otherwise the original name pointer is selected. `___strlcpy_chk` receives capacity255 and destination-size255. These are byte counts, not Unicode character counts. [Store footprints and SDK assertions](triage_evidence/launchd_service_endpoint_checks.json).

SDK flag names for the common `0x437` combination are `MPO_CONTEXT_AS_GUARD (1)`, `MPO_QLIMIT (2)`, `MPO_INSERT_SEND_RIGHT (16)`, `MPO_STRICT (32)` and `MPO_SERVICE_PORT (0x400)`. `0x2437` additionally sets `MPO_ENFORCE_REPLY_PORT_SEMANTICS (0x2000)`. These are requests to the construct API. A successful native allocation, actual task-local right name, guard enforcement, or right ownership is not established [SE1-SE3]. [Captured primary SDK header hashes and compilations](triage_evidence/launchd_service_endpoint_checks.json).

The status adapter obtains W0 from the import-bound `_mach_task_self_` variable and rearranges options/context/output arguments into `_mach_port_construct(task,options,context,&name)`. Its local status3/6 branch requests assertion/crash handling. The outer result adapter initializes the four-byte output name to zero, returns it on status0, and takes a `brk #1` path for nonzero status. Failed construction is not silently converted to a successful nonzero name in this captured adapter. No live failure was induced. [Adapters](triage_evidence/launchd_service_endpoint_source.json).

## Trap and Mach RPC3231 routes

The cached public wrapper at `0x180548e9c` calls trap veneer `0x180547b10`, which loads X16=-24 and issues `svc #0x80`. Only return `0x10000003`, the SDK value of `MACH_SEND_INVALID_DEST`, selects the tail-call to `__kernelrpc_mach_port_construct` at `0x18056df38`. That comparison does not mean every fallback is caused by an unsupported syscall: the captured kernel trap can produce the same status on its task-conversion failure. [Wrapper and trap bodies](triage_evidence/launchd_service_endpoint_source.json).

The MIG client calls `_mach_msg2_internal` at `0x18056dfcc`; its request ID is3231 (`0xc9f`), expected reply3331 (`0xd03`). The original kernel subsystem entry3231 resolves through an authenticated format8 pointer to `0xfffffe000bd87808`, which checks the kernel-side request and calls the same construct core at `0xfffffe000bce00b8`. [Registry record, original pointer and bodies](triage_evidence/launchd_service_endpoint_source.json).

| Message component | User offset / extent, B | Kernel offset / extent, B |
|---|---|---|
| Complete request | 0 /60 | 0 /68 |
| OOL options descriptor | 28 /16 | 36 /16 |
| NDR record | 44 /8 | 52 /8 |
| Inline guard context | 52 /8 | 60 /8 |
| Complete successful reply | 0 /40 | 0 /48 |
| Return code | 32 /4 | 40 /4 |
| Returned name | 36 /4 | 44 /4 |

The OOL descriptor points to exactly24 B of options, uses type1 (`MACH_MSG_OOL_DESCRIPTOR`), copy1 (`MACH_MSG_VIRTUAL_COPY`) and deallocate0. Request bits are `0x80001513`; the service-info pointer inside those options is a separate nested user address, not another OOL descriptor. The successful reply returns a numeric name inline; it is not a reply port descriptor transferring a right. The prior generic transport/copyout reports cover deeper mechanics separately. [Raw descriptor/header constants](triage_evidence/launchd_service_endpoint_source.json), [public SDK and derived kernel layouts](triage_evidence/launchd_service_endpoint_checks.json).

The direct trap copies24 B of options from user memory before invoking the core, and copies a four-byte name back on success. In the MIG route the checked OOL descriptor supplies the options pointer; the core separately copies256 B through the nested service-info pointer. Thus transport of the outer options record does not itself prove availability or validity of the nested bytes. This increment does not prove native message delivery, task conversion, mapped-address validity or PAC success [SE4].

## Kernel metadata and guard boundary

For service-port type, the construct core has caller-state gates before accepting service information. The captured path reads current-task state and either the full pointer or its low32 representation according to another task flag; target-build caller/state meanings and actual acceptance for the native launchd instance are unknown here. This report does not equate an SDK-valid options record with permission to create a service port. [Complete original construct body](triage_evidence/launchd_service_endpoint_source.json).

The service-info copy uses `_copyin` with256 B at `0xfffffe000bce0560`. `_strnlen` receives maximum255; a result greater than254 reaches the invalid-argument path. The core rejects the selected context-guard-without-strict combination `(flags & 0x21) == 1`; both factory values include the strict bit. The domain byte at copied-record+255 participates in selection of the internal label/port class; no complete native policy outcome is inferred.

For the path that invokes label helper `0xfffffe000bcd6b60`, an optional authenticated callback at global `0xfffffe0007e5c518` receives the copied service-info pointer and an output-cookie address. Callback failure takes a cleanup/status return; a missing callback supplies a null cookie. The helper allocates name length+1 B, copies the NUL-terminated name to a pointer at label+`0x18`, stores the domain byte at label+`0x15`, and stores the label pointer through the caller's output record. Hook registration, callback identity, native allocation and policy acceptance remain unknown [SE4].

The core extracts option bit4 for the lower allocator's inserted-send-right argument and bit5 for the guard helper's strict argument. Guard helper `0xfffffe000bce0624` stores the supplied context at port+`0x78` on its applicable path. The earlier [root-port construction report](kernel_root_port_construct_report.md) recovers lower allocation/namespace and guard mechanisms under different caller options; those finite private cases are not replayed or relabeled as this service-port request.

## XPC name adoption, access, copy and disposal

| Original routine | Address | Recovered interface behavior |
|---|---|---|
| `_xpc_mach_send_create` | `0x184b737d8` | Selects disposition19 and branches to the disposition-aware initializer |
| `_xpc_mach_send_create_with_disposition` | `0x184b737e0` | Selected disposition17 path allocates wrapper and stores supplied name; no reference-increment/insert call on this path |
| `_xpc_mach_send_get_right` | `0x184b74268` | Class check, then load u32 object+`0x18`; wrong class returns0; extracted sentinel reaches diagnostic tail |
| `_xpc_mach_send_copy_right` | `0x184b7f7d0` | For its ordinary name path, calls `mach_port_mod_refs(...,SEND,1)` before returning name |
| `__xpc_mach_send_extract_right` | `0x184b77378` | Class check and atomic exchange of object+`0x18` with `0xfffffffe` |
| `__xpc_mach_send_dispose` | `0x184b742c0` | Atomic exchange of object+`0x18` with `0xffffffff`; selected old-name domain calls `mach_port_deallocate` |

Disposition17 is `MACH_MSG_TYPE_MOVE_SEND` in this API context. For a normal supplied name the initializer adopts it without an extra send-reference request. Disposition19 takes a `mach_port_mod_refs(task,name,SEND,1)` path; disposition20 uses `mach_port_insert_right(task,name,name,MAKE_SEND)`. The six original cache-stub bindings establish these exact API names and the object allocator/class helpers. Allocation requests32 B and stores the u32 name at+`0x18`. This is a static ownership-operation contract, not measured native right counts. [Functions and import fixups](triage_evidence/launchd_service_endpoint_source.json).

| Old/supplied u32 name | Initializer direct-allocation branch | Getter on correct class | Disposal deallocation branch |
|---|---|---|---|
| 0 | Direct, regardless of disposition | Returns0 | Skips deallocation |
| 1..`0xfffffffd` | Direct for disposition17; other dispositions take their checks/operations | Returns stored name | Calls deallocate |
| `0xfffffffe` | Direct for disposition17 | Extracted-name diagnostic path | Skips deallocation |
| `0xffffffff` | Direct, regardless of disposition | Returns stored dead name | Skips deallocation |

Four full-domain bit-vector proofs cover the initializer's `CMN`/conditional-compare name tests, its direct-allocation branch, the disposal range, and the receive-source flag gate. In particular, the initializer's ordinary unsigned comparison domain includes `0xfffffffe`, whereas disposal's deallocation domain stops at `0xfffffffd`; treating every nonzero name as a live right would conflate these cases. An original authenticated cache slot at `0x1e24197f0` points to the named dispose routine. The generic release-to-dispose dispatch and actual destruction timing are not newly traced here [SE5]. [Proof queries and results](triage_evidence/launchd_service_endpoint_checks.json).

## Receive source and callback ownership

After creation, `(u16(service_flags) & 0x402) == 2` requests receive-source setup: bit1 set and bit10 clear, with other bits unconstrained by this test. The type argument resolves to `__dispatch_source_type_mach_recv`; W1 is the extracted port name, W2 is raw mask `0x8000`, and X3 is a queue loaded from a global. This report does not assign an undocumented name to that mask. Setup sets dispatch context to the service, retains the XPC object, registers event/cancel blocks, activates the source, checks service byte+8 through the liveness helper, retains the service, and stores the source at service+`0x80` after an empty-field assertion. Actual registration/activation or callback scheduling is unknown. [Bodies and bindings](triage_evidence/launchd_service_endpoint_source.json).

The event block captures the source at block+32, calls `dispatch_get_context`, loads callback/cookie from service+`0x90`/+`0x98`, and branches through X3 using `braaz`. Its outgoing arguments are X0=service, W1=0, X2=cookie. The cancellation block captures source/XPC object at block+32/+40, obtains the service context, runs the same liveness helper, releases the service and XPC object, and tail-calls `dispatch_release(source)`. Neither path shown here directly calls `mach_port_destruct`; the ownership of the receive right after source cancellation and all other teardown paths remain unknown. No cancellation was induced [SE2,SE5].

## Assumptions, falsification and bounded continuation

| ID | Assumption / dependent result | Stress test or falsification probe | Status |
|---|---|---|---|
| SE1 | Pinned files are the implementation under study | Recapture file/slice/cache/kernel bytes, 4894 fixups, original symbols and tool hashes; independently attest loaded images if needed | Captured static identities verified; native slice unknown |
| SE2 | The selected creation branch is relevant to publication/lifecycle | Compare both slices, input/field/call edges and block targets; trace a particular service object across construction and publication to test native applicability | Static linkage verified; FairPlay-specific object epoch unknown |
| SE3 | Counter, options and byte-record construction are interpreted at stated widths | Check all stores, overlap, two SDK modes, exact scalar branch records and wrap semantics; concurrency or additional writers can falsify uniqueness assumptions | Widths verified; uniqueness, initialization and native lifetime unknown |
| SE4 | Outer options and nested service-info contracts compose | Check trap24, MIG3231 layouts/registry, core copy256 and label helper; native task/address/policy observation would test actual acceptance | Static boundaries verified; native acceptance/copy/PAC unknown |
| SE5 | XPC operations and captured callback/release edges inform ownership | Compare original get/copy/extract/dispose paths, sentinel proofs and optional source gate; complete generic destruction and receive-right handoff could change the final ownership account | Selected operations verified; actual reference balance and receiver unknown |
| SE6 | Manual scalar formulas accurately represent selected instructions | Pin each relevant branch/width, run four unsatisfiability checks, reject eight altered evidence records; architectural/native tests would independently test execution behavior | Scalar domains verified; no hardware or whole-path execution proof |

| Impact | Remaining interface question | Discriminating next evidence |
|---|---|---|
| High | Does launchd transfer the receive right to fairplayd, and when does the daemon become receiver? | Follow check-in/receive-right handoff and service-object identity to the already recovered daemon registrations; a shared numeric name alone is insufficient |
| High | Which service/host slot receives managed RPC700? | Correlate static publication and handoff with existing read-only native service/port observations; neither a cache entry nor factory request proves slot34 ownership |
| Medium | Who registers the service-label callback at `0xfffffe0007e5c518`? | Trace the hook producer and its output-cookie/lifetime interface; no native policy modification is needed |
| Medium | Where is the guarded receive right finally destroyed or transferred? | Trace service/source teardown and generic XPC disposal separately; this increment recovers selected send-reference operations only |
| Low | Does the global counter have other writers or an earlier initializer? | Original-byte xrefs/store census, with synchronization and epoch boundaries retained |

## Reproduction and quality gates

From the extracted directory: `/Users/___/Downloads/zut/.venv/bin/python triage_evidence/validate_launchd_service_endpoint.py`. Static recapture and verification require the original launchd/cache/kernel files and pinned installed tools. No native target or protected IPC operation is run. Time/space are O(B+F+I) for bytes B, fixups F and selected instructions I; selected record-footprint checking is a fixed256 B operation. Solver results are separately bounded manual formulas, not end-to-end behavioral proof. [Recovery](triage_evidence/recover_launchd_service_endpoint.py), [validator](triage_evidence/validate_launchd_service_endpoint.py).

Validation passes 269 instruction assertions, 36 SDK assertions in two compilations, four full-domain scalar queries, two byte-store footprints and eight rejected evidence alterations. The latter are evidence-corruption sensitivity checks, not a vulnerability reproduction or exhaustive decoder test. Both slice fixup sets independently match `dyld_info` (4894 total). [Detailed checks](triage_evidence/launchd_service_endpoint_checks.json).

QG1: Factual implementation/interface analysis; no normative judgment required.

QG2: SE1-SE6 identify assumptions, dependent results and falsification probes.

QG3: This increment covers endpoint construction, trap/MIG fallback, nested metadata, selected right operations and conditional callback ABI. Native creation/publication, receiver identity, complete teardown, slot34/RPC700 and successful daemon/kext processing remain unknown; the full goal is active.

QG4: Names/flags/statuses are 32 bit, context/pointers 64 bit, domain8 bit, service flags16 bit; record offsets/extents are B. SDK and scalar checks support the stated widths.

QG5: Outer OOL versus nested user copy, request versus success, adopted versus copied right, name versus port object, sentinel values and callback registration versus delivery remain distinct.

QG6: Original bytes, imports, authenticated pointers, nlist names, subsystem record, SDK/tool hashes, compile commands and proof queries are retained. No inferred exact native policy outcome is presented as observed.

QG7: The impact-labeled continuation table preserves handoff, policy-hook, teardown and counter gaps.

Publication: [prior manifest](triage_evidence/launchd_service_endpoint_prior_manifest.json), [preservation seal](triage_evidence/launchd_service_endpoint_delivery.json), [quality gates](triage_evidence/launchd_service_endpoint_quality_gates.json), [seal script](triage_evidence/seal_launchd_service_endpoint.py), [independent publication audit](triage_evidence/verify_launchd_service_endpoint_publication.py), [current corpus manifest](triage_evidence/interface_manifest.json). Scoped gates do not assert full-goal completion.
