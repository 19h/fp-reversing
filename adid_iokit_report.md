# CoreADI adid: IOKit providers, method-26 framing and connection state

Two source paths connect the installed CoreADI provider to IOKit. At the first observed transport boundary, helper `0x1000208fc` uses a cached `kern.hv_vmm_present` query: the primary class receives a 16-byte descriptor for a 96-byte record, while an optional Avp stage receives 96 bytes directly. The [extended caller report](adid_iokit_caller_report.md) establishes that the nonzero-query path can perform the Avp stage and then a separate primary stage. The earlier first-boundary observation does not establish an exclusive choice for the entire helper. A separate helper at `0x10002af70` returns an Avp connection through an encoded output pointer; its newly corroborated caller emits selector 100. The two Avp paths have different cache cells. Complete upstream/native caller reachability and connection identities remain unknown.

The descriptor form corroborates the supplied FairPlayIOKit selector-26 ABI. This is a source-level bridge between the provider and kext contract. No native driver call, successful kext transformation or end-to-end fairplayd transaction was executed. The wider investigation remains active.

## Source identity, assumptions and evidence

All provider addresses are preferred virtual addresses in the selected arm64e slice, base `0x100000000`, SHA-256 `ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf`, UUID `4d24325f-3529-39b1-bbf8-64bbcf406049`. Its source is `/System/Library/PrivateFrameworks/CoreADI.framework/adid`. The universal file SHA-256 is `58eeb13dade3e1867641345b38961344fe53e6319928a1503bdb3315681fe929`; the selected slice starts at file offset 3719168 and contains 3047808 bytes. These addresses are distinct from fairplayd, CoreFP and the kext. The prior [context](adid_context_report.md), [receiver](adid_receiver_report.md), [CoreFP client](corefp_client_paths_report.md) and [trace](zut_trace_report.md) reports establish the earlier boundaries.

| Assumption | Dependent results | Stress test / falsification boundary |
| --- | --- | --- |
| H1: pinned provider bytes, fixups, supplied kext export and SDK describe the inspected references | Addresses, imports, literals, ABI widths and provider/kext correspondence | Fresh instruction/function/fixup readbacks, independent dyld_info, SDK compile and three preserved input hashes agree. Effective runtime image pairing remains unknown. |
| H2: retained private memory and declared PAC/vector/API models permit the selected continuations | Finite source paths and cache observations | Nine fresh runs reproduce complete ordered source/event streams, including two retained-state sequences. These use the same declared models; they do not independently validate Unicorn, hardware PAC or native APIs. |
| H3: address-keyed records and output pointers supplied by the analyst describe the indicated local helper inputs | Recovered helper roles and status/output fields | Original local codecs, invalid pointers, encoded NULL, correctly owned output and four full-domain local proofs are checked. Native caller construction and reachability remain unknown. |
| H4: modeled query statuses/values and sequential dispatch_once describe the explicit cases | First-boundary class/framing selection and query-byte caching | Values 0, 1, 2, query error and retained-state calls distinguish nonzero testing, error preservation and once reuse. Native query results, concurrent once behavior and every writer remain unknown. |
| H5: modeled IOKit object names, acquisition statuses and release events describe the finite fixtures | Port-name flow, acquisition, output and release observations | Acquisition-stage stops, failures, empty iteration, completed success and fresh iterator generations are retained. All numeric names are private fixtures; effective rights, object identity and complete native ownership are unknown. |
| H6: error and identity-response transport models define the stated counterfactuals | Method-26 status, retry, warm-cache and recovery behavior | Error returns `0xe00002c7`; identity-response returns zero without changing bytes. No kext algorithm, cryptographic response or actual operation success is implied. |
| H7: local arithmetic and record/control catalogs are interpreted only within their observed prefixes | Four codec proofs, six record headers and 56 control targets | Source constants/bytes and complete bounded parsing agree. Raw field semantics, full accepted languages and successful algorithms remain unknown. The 56 local targets are not assigned public operation numbers. |
| H8: embedded entitlement XML is declaration evidence | Two true entitlement declarations and class/key correspondence | Manual selected-slice SuperBlob/XML parsing agrees with independent codesign content display. Signature validity, trust, effective credentials and authorization remain unknown. |
| H9: captured, completed private continuations delimit the reported lifecycle behavior | Warm reuse, retries and local missing-release observations | Deep-copied per-run object state and retained-state sequences prevent later fixture mutation from rewriting earlier observations. Native close/deallocation, exception paths, reentry and concurrency remain unknown. |

Artifacts: [profiles](triage_evidence/adid_iokit_profiles.json), [static contracts](triage_evidence/adid_iokit_contracts.json), [source producer](triage_evidence/probe_adid_iokit.py), [static recoverer](triage_evidence/recover_adid_iokit.py), [fresh checks](triage_evidence/adid_iokit_checks.json), [quality gates](triage_evidence/adid_iokit_quality_gates.json), [validator](triage_evidence/validate_adid_iokit_delivery.py), [analyst ABI declarations](triage_evidence/adid_iokit_layouts.c), [compiled assembly](triage_evidence/adid_iokit_layouts.s) and [embedded entitlement XML](triage_evidence/adid_iokit_entitlements.xml).

## Architectural boundary [H1-H6,H8]

```text
CoreFP ADID request -> adid XPC receiver -> persistence/context processing
                                                |
                                  complete caller path unknown
                                                |
           caller 0x1000590ac -> helper 0x1000208fc, record basis 0x25
                                                |
                  dispatch_once -> kern.hv_vmm_present query
                                                |
                    cached byte != 0? -- no --+  |
                         | yes                |  |
                  AvpFairPlayDriver            |  |
                  IOServiceOpen(type 0)        |  |
                  cache 0x1002dcee4            |  |
                  selector 26, direct 96 B     |  |
                         |                    |  |
                         +--------------------+  |
                                                |
                 com_apple_driver_FairPlayIOKit <--+
                  IOServiceOpen(type 0), cache 0x1002dcc84
                  selector 26, descriptor 16 B -> record 96 B
                                                |
       supplied FairPlayIOKit UserClient/provider -> task-aware copy
                         -> PRnut72j9 -> copy back
                                                |
                      protected core / deeper facilities / RPC

caller 0x100058654 -> helper 0x10002af70 -> AvpFairPlayDriver, type 0
                      cache 0x1002dd290 -> decoded stack output
                      caller then emits selector 100
```

The last kext edge uses the separately corroborated [selector-26 and kernel RPC contracts](interface_abi_report.md). Reaching a matching provider API does not establish which protected operation, host slot or RPC family its record selects. The two class names are exact strings. The supplied kext C contains `com_apple_driver_FairPlayIOKit` at line 5704 and the access key at line 5625; its task initialization is at line 7540. No Avp implementation is supplied by that C export.

The selected provider's embedded XML declares both `com.apple.private.FairPlayIOKitUserClient.access = true` and `AvpFairPlayUserClient.access = true`. These declarations support the architectural association. They do not establish effective process entitlement values or a successful native open.

## Routine roles and input records [H1-H3,H7]

The role labels below are analytical descriptions; no IDB rename is asserted.

| Original range / site | Corroborated local role | Remaining boundary |
| --- | --- | --- |
| `0x1000208fc..0x10002197c` | Optional Avp stage followed by primary initialization, connection acquisition, selector-26 requests and local status/cache update | Full native callers and record semantics |
| `0x10002af70..0x10002ba5c` | Separate Avp connection acquisition and decoded caller-output store | Full native callers, connection lifetime and use of returned name |
| `0x100001250` | Once callback querying `kern.hv_vmm_present` and conditionally storing a Boolean byte | Other writers, runtime query result and concurrent execution |
| `0x100001f9c`, `0x100058d48` | Local path from the first helper to dispatch_once | Broader independent callers |
| `0x100049804` | Constructs the retained 96-byte tagged record | Semantic meaning of its raw keys and payloads |
| `0x10001f654` / call `0x10001f908` | Primary selector-26 transport using a 16-byte descriptor | Real driver response and successful transformation |
| Call `0x10004967c` | Avp selector-26 transport using the record directly | Avp provider implementation and response contract |

For the first helper, the analyst-owned record at address P has an address-keyed first u32:

```text
R[0:4] = 0x25 XOR (((low32(P) XOR 0x08f753d6) * 0x255e728d) mod 2^32)
R[4:8] = local encoded status output
```

The retained fixture has more bytes; no additional input-field role is assigned from that fact. The null-pointer control stops at an original read at `0x100020a50` in private memory. This is an instrumentation boundary, not a demonstrated native fault.

For the separate Avp helper:

```text
K(P) = ((low32(P) XOR 0x834674ac) * 0x0a42990d) mod 2^32
R[0:4] = K(P) + 0x10fd                         mod 2^32
R[4:8] = local encoded status output
R[8:16] = actual_output_pointer + 0x4a98f233707acdc1 mod 2^64
decoded = R[8:16] + 0xb5670dcc8f85323f           mod 2^64
```

The decode at `0x10002ba00` precedes a four-byte store at `0x10002ba04`. Encoded NULL is `0x4a98f233707acdc1`; it bypasses acquisition. A literal zero field is not encoded NULL: the private continuation acquires a connection and then attempts an unmapped output write. The valid fixture uses output address `0x7b01c100`, receives name `0x5804`, and writes raw status `0x0059248f`. These are private addresses/names.

The full-domain local proofs cover record arithmetic, output-pointer round-trip/NULL, the byte decoder and query-byte selection. They do not prove the entire helper input grammar. The encrypted 18-byte class string at `0x1002b8750`, read at `0x10002b50c`, decodes bytewise as `(-93*b - 58) mod 256` to `AvpFairPlayDriver` followed by NUL; the inverse is `11*(d+58) mod 256`.

## Query predicate, classes and distinct caches [H1-H4,H6]

The first helper calls `0x100001f9c` at `0x100020b40`; that path calls `0x100058d48` at `0x100002204` and dispatch_once at `0x100059020`. The original token is `0x1002dd2b8`, the static block is `0x1002c4060`, its invoke address is `0x100001250`, and descriptor `0x1002c40a0` declares size 32 bytes. The fixture executes that original invoke body; it does not replace the query callback with a guessed byte.

The original sysctlbyname call is at `0x100001464`. Its name is `kern.hv_vmm_present`, output extent is four bytes, and new-value pointer/size are zero. On return status zero, the store at `0x1000014fc` writes `(value_u32 != 0)` to byte `0x1002dd2e0`. On query error, that store is bypassed and the old byte is preserved. The cold private byte is zero. The earlier [startup predicate](adid_startup_report.md) at `0x10002ba5c` has its own value comparison and byte encoding; it must be analyzed separately.

| Explicit query case | Query-byte result | First observed matching call / class | Open output cache | First selector-26 call / input extent |
| --- | --- | --- | --- | --- |
| Status 0, value 0, cold byte 0 | 0 | `0x100021208`, `com_apple_driver_FairPlayIOKit` | `0x1002dcc84` | `0x10001f908`, 16 bytes |
| Status 0, value 1 | 1 | `0x100020f70`, `AvpFairPlayDriver` | `0x1002dcee4` | `0x10004967c`, 96 bytes |
| Status 0, value 2 | 1 | Same Avp path | `0x1002dcee4` | Same 96-byte path |
| Query error, cold byte 0 | Preserved 0 | Same primary path | `0x1002dcc84` | Same 16-byte path |
| Separate helper `0x10002af70` | No class selection assigned from this query | `0x10002b63c`, `AvpFairPlayDriver` | `0x1002dd290` | Returns connection; no method-26 call in this helper |

The nonzero-query cases in this report stop at their first IOConnect boundary. The [extended caller cases](adid_iokit_caller_report.md) model that return explicitly and observe a subsequent primary matching/open/descriptor call in all four stated two-stage controls. Thus this table describes the first boundary, not an exclusive whole-helper route.

The query proof establishes error preservation and nonzero testing for its declared local branch domain. A cold error selecting the primary class does not establish that every error does so: a previously nonzero byte is preserved. Class-name equality also does not make the two Avp cache cells or native connections identical.

## Port-name acquisition and API emission sites [H1,H2,H5]

These are the provider's original IOKit API call sites. They are not raw Mach send instruction addresses. The [user/trap report](user_trap_interface_report.md) separately recovers reference IOKit framework message construction, including open IDs 2862/2962 and external-method IDs 2865/2965. Actual loaded-framework pairing and underlying native emission remain unknown.

| API / direction within provider | First helper site | Separate Avp helper site | Explicit modeled flow |
| --- | --- | --- | --- |
| IOMainPort: output name | `0x100020d38` | `0x10002b474` | X0=0; X1 points to four-byte output; fixture name `0x5801` |
| IOServiceMatching: class to dictionary | `0x100021208` or `0x100020f70` | `0x10002b63c` | Exact class above; private opaque dictionary model |
| IOServiceGetMatchingServices: output iterator | `0x10002129c` | `0x10002b6d8` | Main-port name and matching dictionary; output iterator `0x5802` |
| IOIteratorNext: return service name | `0x100021338` | `0x10002b768` | Iterator `0x5802` returns service `0x5803` in successful fixture |
| IOServiceOpen: task input and connection output | `0x100021458` | `0x10002b854` | Service `0x5803`, modeled mach_task_self name `0x5810`, type 0; output connection `0x5804` |
| IOConnectCallStructMethod: connection input | `0x10001f908` or `0x10004967c` | Not observed in this helper | Connection `0x5804`, selector 26, same input/output buffer and owned output-size cell |
| IOObjectRelease: service | `0x1000217a0` | `0x10002b8ac` | Service `0x5803` in completed successful acquisition paths |
| IOObjectRelease: iterator | `0x10002184c` | `0x10002b940` | Iterator `0x5802` in completed successful acquisition paths |
| Caller output store | No returned-connection field assigned | `0x10002ba04` | Decoded owned caller pointer receives four-byte connection name |

The SDK compile checks `mach_port_t`/IOKit object and status widths of four bytes and `size_t` of eight bytes on arm64e. Names `0x5801..0x5810` are analyst fixtures. Neither task-local names nor embedded cache addresses establish a native kernel port object, send/send-once/receive disposition, reference count or external principal. No additional raw Mach port or message descriptor is inferred from a pointer-sized field.

## Method-26 data contract [H1-H3,H5-H7]

For the primary path the actual retained input bytes are:

```text
50 05 00 7e 00 00 00 00  60 00 00 00 00 00 00 00
|---- A: little-endian u64 ----| N:u32 LE | T:u32 LE |
A = 0x7e000550 (private mapped address), N = 96 bytes, T = 0
```

The input and output structure pointers are equal. Input extent and initial output-size value are both 16 bytes. The source constructs the 96-byte pointed record before calling the transport. The supplied FairPlayIOKit UserClient/provider accepts the corresponding 16-byte `{u64 A,u32 N,u32 opaque}` shape, obtains task-aware memory access, copies N bytes into its processing buffer, invokes `PRnut72j9` and copies back. The final u32 remains opaque despite being zero in this fixture. See [the established ABI report](interface_abi_report.md) and [task/VM copy report](kext_port_vm_report.md).

For the optional Avp stage, input and output pointers are also equal, but the structure itself is the 96-byte record and initial output size is 96 bytes. A fresh comparison confirms that its bytes equal the primary path's pointed record. The Avp implementation is unknown; the 16-byte FairPlayIOKit ABI must not be transplanted onto its direct 96-byte input.

The retained record is parsed with a bounded 10-byte header: key BE32, tag BE16, payload extent BE32. Offsets and extents below are bytes.

| Offset | Raw key | Tag | Payload extent | Payload bytes |
| --- | --- | --- | --- | --- |
| 0 | `0x744b91e8` | `0x9777` | 4 | `73eba01e` |
| 14 | `0x074912a4` | `0x9777` | 4 | `00000001` |
| 28 | `0x81028a5f` | `0x9777` | 4 | `00000000` |
| 42 | `0x0219bc34` | `0x9777` | 4 | `00000000` |
| 56 | `0x918ae3cd` | `0x9777` | 4 | `00000000` |
| 70 | `0x00000000` | `0x50db` | 16 | Sixteen zero bytes |

Extent check: `5*(10+4)+(10+16)=96 bytes`; no trailing bytes remain. These are raw record keys. Their semantic meanings are unknown. The earlier daemon parser's staging/key transform is separate; structural similarity does not establish key identity, a metadata-query operation, or a UUID/nonce type for the last field.

## Completion, retries and release observations [H2,H5,H6,H9]

The transport models deliberately bracket the local continuation. `return_error` returns `kIOReturnUnsupported = 0xe00002c7` and leaves bytes unchanged. `identity_success` returns zero and also leaves bytes unchanged; it is a counterfactual transport control. No kext transform executes in either model.

| Retained experiment | Source-hook counts | Established private behavior |
| --- | --- | --- |
| Separate Avp acquisition, then same helper with retained state | 708, 224 | First call acquires/releases service and iterator, caches connection at `0x1002dd290`, sets byte `0x1002dd220=1` and writes caller output; second returns cached `0x5804` with no IOKit API calls |
| Primary method-26 error twice | 42673, 42452 | Both enumerate, open and call selector 26; once callback is not repeated; raw record status is `0x00587c93` |
| Primary identity-response twice | 80450, 983 | First raw status is `0x0059248f` and byte `0x1002dcc80` changes `0x40` to `0x41`; second bypasses IOKit and once APIs |
| Primary error, then identity-response with new fixture connection, then warm call | 42673, 80229, 983 | Second call reopens using fixture name `0x5814`, replaces cache `0x1002dcc84`, changes the same state byte to `0x41`; third bypasses IOKit APIs |

Both primary error and identity-response continuations release the acquired service at `0x1000217a0` and iterator at `0x10002184c`. They also retain the observed write `0x78` to byte `0x1002dcc98`. Encoded record status must be distinguished from the raw IOKit return: relative to `0x59248f`, error status `0x587c93` differs by -43004. This arithmetic does not identify a complete public error-code specification.

The separate Avp helper's modeled main-port failure, matching-services failure, empty iteration and service-open failure complete with a non-success local status and leave caller output untouched. The completed empty-iterator and open-failure continuations have no observed explicit release of iterator `0x5802`; open failure does release the service. This establishes a local release imbalance in those completed private paths. A native leak, implicit ownership transfer or complete object-lifetime defect is unknown. The primary retry sequence likewise shows no connection-close API in its retained continuations; complete ownership must be recovered before assigning a leak.

Each new modeled enumeration creates a fresh iterator generation. Earlier object-model snapshots are deep copies. This prevents iterator exhaustion or later release mutations in the fixture from manufacturing retry or lifetime conclusions. Dispatch_once models a single sequential callback and completed-token reuse; it does not model concurrent native scheduling.

## Further control-flow context [H1,H2,H7]

The prior context-error path uses a 224-byte table at `0x100266cec`: 56 signed 32-bit relative offsets with base `0x10019bb2c`. Original guards at `0x10019bacc` and `0x10019bb18` bound W19 to 0..55. Every retained table target is independently recomputed from source bytes in the new contract catalog.

The existing context fixture visits local states `28,4,3,37,10,9`. State 28 targets `0x10019e484` and consumes the `0x1002dcb68+24` field with sentinel `0x6fac17cb61e34e69`; its earlier status is `0x0058748a`. State 37 targets `0x10019bdb4` and consumes the `0x1002dcb68+0` field with tag `0x16e4e4d3`, preceding final `0x005874ae`. Paired local states save continuation/load status slots. This explains additional control structure around the earlier failure while preserving the distinct earlier and final statuses. The table is a local control/continuation catalog; 56 public operations or a VM instruction set have not been established.

An authenticated-branch modifier search produced candidates sharing modifiers with unrelated imported functions. Modifier equality alone is insufficient to establish target binding. The API checks instead retain source call instructions, their resolved import fixups and the explicit private import dispatch ordinal.

## Verification and bounded continuation

The [fresh validator](triage_evidence/validate_adid_iokit_delivery.py) passes 9314 assertions across 31 private cases, 8655 unique original instruction records in 14 compiler ranges, 563370 retained original visits and 189 source API records. It freshly solves four local full-domain bit-vector queries, checks 11 source windows, independently displays the selected-slice entitlement XML, recompiles the analyst ABI declarations and reproduces nine complete source/event runs totaling 196625 hook steps. Replay uses the same explicit API/PAC/vector models; the independent part is fresh artifact/source readback and execution, not native behavioral equivalence. The three original input hashes remain unchanged.

The bounded record parser checks remaining extent before each 10-byte header and payload. For B input bytes and R records it takes O(B+R) time and O(B+R) output space, with B=96 here. The verifier takes O(B+F+R+V) time/space over loaded source/artifact bytes B, fixups F, retained records R and instruction visits V; each private execution has a finite hook cap. No native target, loader, IOKit, Mach, target-file/environment or synchronization API was invoked.

| Impact | Next unresolved boundary | Concrete evidence that would resolve it |
| --- | --- | --- |
| High | Native image/provider/port pairing | Match actual provider slice, effective credentials, framework implementation, matched registry service and UserClient connection to observed call/reply objects |
| High | Real callers of the two helpers | Recover source record producers and all branch/table paths from the XPC/persistence core to helper entry; verify actual basis values, output pointer construction and record ownership |
| High | Semantic bridge from 96-byte record to protected kext operation | Follow raw-key consumers through `PRnut72j9`, transformations and reply records; correlate the selected operation with host-slot 17/34 and RPC502/700 control rather than class-name similarity |
| High | Valid responses and successful operations | Recover authentic response grammar and relevant persistent state; replace the explicit identity-response control with independently corroborated source behavior |
| Medium | Avp provider implementation and two-cache relationship | Locate the matching Avp driver image/ABI, then recover users and retirement of both Avp cache cells separately |
| Medium | Resource and concurrency lifetime | Account for iterator/service/connection rights, all cleanup/exception/retry paths, once invalidation, every cache/query-byte writer and concurrent access |
| Medium | Upstream context record and local states | Recover constructors of `0x1002dcb68` fields and local state transitions to resolve the earlier/final statuses without promoting local indices to operation IDs |
| Low | Additional declaration and string families | Inventory further provider entitlements, class literals and authenticated import banks, checking each against concrete source calls |

QG1-QG7 pass for this explicitly bounded increment: descriptive content; H1-H9 assumptions/probes; requested routine, port-name, ABI/control/data/context coverage; reproducible widths/extents/proofs; separated provider/framing/status/lifetime cases; primary source/fixup/SDK provenance; and impact-labeled continuation. Full native contracts, successful algorithms and complete architectural coverage remain unknown. The full goal remains active and incomplete.
