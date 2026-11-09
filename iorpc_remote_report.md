# Remote IORPC: service association, queue destination and shared Mach transport

Original platform builders now reach the remote IORPC helper through an explicitly declared IOService ancestor and service/server association. Source consumes a modeled queue selection and destination-reference result, prepares a kernel-form header and calls either the existing common kernel RPC transport or a send-only helper. Conditional transport returns exercise original release ordering, ownership-dependent cleanup, reply validation, error extraction and outer caller readback. Queue selection, port references, object conversion and transport remain modeled; native ports, remote delivery and platform success are unknown. [RM1-RM8]

```text
original capitalized platform builder -> original OSMetaClassBase::Invoke
  declared IOService ancestor
  service+0x28 -> expansion+0x28 -> link[0] -> IOUserServer
  -> original remote helper 0xfffffe000c595bf8
     target service + method ID -> declared selected queue
     queue+0x10 -> queue data+0x28 -> declared ipc_port pointer
     declared reference copy -> original header destination store
     -> common kernel RPC 0xfffffe000bcf59e0 [body unexecuted]
        or send-only 0xfffffe000bcf55dc [separate component]
     -> declared transport outcome/reply
     -> port release request -> queue release request
     -> conditional conversion cleanup or original reply validation
  -> original platform caller return / power-output reader

Same common RPC transport as FairPlay RPC502/700; different caller policy.
Queue-to-FairPlay host-special-port identity: unknown.
```

[Original source and bindings](triage_evidence/iorpc_remote_source.json), [16 CPU profiles](triage_evidence/iorpc_remote_profiles.json), [independent replay and oracles](triage_evidence/iorpc_remote_checks.json), [preservation](triage_evidence/iorpc_remote_delivery.json) and [scoped gates](triage_evidence/iorpc_remote_quality_gates.json) provide evidence. The [local IORPC report](platform_iorpc_report.md) supplies source-built packets/replies. The [existing common transport report](kernel_rpc_transport_report.md) supplies separately recovered thread reply-port and copyin/send contracts. The [zut capture](zut_trace_report.md) is not extended by these CPU cases.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RM1 | The pinned collection supplies original code, symbols, compiler bounds and fixups. | Rehash and recapture 100 retained/new functions, 9148 instructions and 31 bindings. Verify common-transport and reference-copy bytes against the prior independently retained records. |
| RM2 | The nominal AppleARMIODevice has a declared IOService ancestor shortcut, terminating service ancestry and private service/expansion/link/server associations. | Recover original metaclass construction, actual ancestry and field producers. The shortcut supplies an ancestor match, not an authentic immediate-superclass claim. Native receiver identity/lifetime remain unknown. |
| RM3 | The selected queue, fallback field and port pointer are declared inputs; queue lookup and port-reference copy return explicit modeled results. | Recover initialized queue metadata, method selection, fallback ownership, actual port type/epoch and reference effects. Pointer equality and a modeled non-NULL result do not attest a usable right. |
| RM4 | Request object conversion and reply/cleanup conversion are no-effect models; the request array-output word remains source-initialized zero. | Recover conversion bodies, object/descriptor/right mapping and real allocation/cleanup effects. Current headers establish the caller ABI, not a deliverable native message. |
| RM5 | Kernel transport returns and message_moved outputs are declared. Normal replies transfer exact prior source-produced buffers; one remote error record has explicitly substituted fields. | Observe actual send/receive, moved ownership, receiver construction, reply bytes and conversion. The error record is a valid declared layout input, not an observed server error. |
| RM6 | Two one-way cases directly enter the generic remote helper with an exact source-built request/context, explicit flags 0x8d and a lower private stack. | Establish actual one-way callers and their flags. The three capitalized platform builders themselves supply ordinary request/reply flags; no one-way use by those callers is claimed. |
| RM7 | Retain/release, logical PAC and native synchronization remain modeled; current-thread and private object reservations inherit prior premises. | Match native references, authentication, concurrency and object extents. Request/reply mode does not execute the common transport's thread reply-port machinery in these cases. |
| RM8 | Earlier source-correlated transport names and SDK declarations remain separately versioned. Runtime route, remote service, device identity and daemon join are unknown. | Match the actual build, queue endpoint, receiving process and right identity across namespaces. Shared transport code does not identify a shared destination or protocol. |

## Primary source, typed anchors and anonymous routines

Collection: `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`; SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Twelve complete functions / 1615 instructions are added to the prior capture. The resulting 100 functions / 9148 instructions include statically captured conversion/transport bodies that are not executed by these probes. No IDB is changed.

| Original entry | Evidence-supported role | Name/provenance limit |
| --- | --- | --- |
| 0xfffffe000c5957d4 | OSMetaClassBase::Invoke; selects local/remote handling | Exact original nlist name, retained from prior increment. |
| 0xfffffe000c595bf8 | Remote IORPC queue/destination/transport/reply helper | Exact name unknown; role follows original callers and complete 286-instruction body. |
| 0xfffffe000c596070 | Service/method queue lookup and reference-return paths | Exact name unknown; 148 instructions captured, body modeled in this increment. |
| 0xfffffe000c5962c0 | Request object-conversion interface | Exact name unknown; 390 instructions captured, body unexecuted. |
| 0xfffffe000c5968d8 | Reply/object conversion and cleanup modes | Exact name unknown; 259 instructions captured, body unexecuted. |
| 0xfffffe000c596d64 | Reply-cleanup interface | Exact name unknown; 41 instructions captured, body unexecuted. |
| 0xfffffe000bcd00bc | Port reference-copy helper | Exact name unknown; same 74 original instructions as prior namespace report; no exported name is assigned. |
| 0xfffffe000bcd0448 | ipc_port_release_send | Exact nlist binding; no native release executes. |
| 0xfffffe000bcf59e0 | Common kernel RPC transport | Same 274 original instructions as the prior FairPlay transport record. |
| 0xfffffe000bcf55dc | Kernel send-only helper | Exact name unknown; original 55-instruction wrapper prepares/copies/sends a kernel message. |

Exact metaclass anchors identify IOUserServer at 0xfffffe000cb5b928, OSAction at 0xfffffe000cb52328 and IOService at 0xfffffe000cb5c060. Two additional compared anchors, 0xfffffe000cb52440 and 0xfffffe000cb52468, have no exact symbol in the scanned nlist and retain unknown class identity. Original source records these distinctions rather than assigning inferred names.

The IOUserServer nominal vptr is 0xfffffe0007f56050; its +0x5d8 slot targets exact IOService::getState at 0xfffffe000c4dedf0. The real three-instruction getter reads server+0x48. The helper tests bit 0 of that result and the server+0xf8 fallback field; it is not an isInactive call. Server and queue retain/release slots resolve to exact OSObject methods. Seven new authenticated IA/address-diverse slots and the exact server/queue vtable definitions are recaptured. [RM1-RM3]

## Service, server and queue data flow

For the exercised route, original Invoke recognizes the supplied IOService ancestor and follows three loads:

| Stage | Original field/use | Evidence boundary |
| --- | --- | --- |
| Service expansion | service+0x28 | The new fixture patches exactly this eight-byte field in the prior device object. |
| Associated link | expansion+0x28 | Raw private structure; full type/producer unknown. |
| Server receiver | link[0] | Supplies X0 to the remote helper. |
| Queue candidate | Lookup using target service and 64-bit method ID | Selected result modeled; complete lookup source captured. |
| Fallback queue | server+0xf8 | On NULL lookup result, original code retains this non-NULL queue before use. |
| Queue data | queue+0x10 | Declared nominal queue with exact IODispatchQueue vptr 0xfffffe0007f354a8. |
| Destination source | queue_data+0x28 | Opaque declared kernel port pointer passed to the reference-copy interface. |

At the queue-lookup call, X1 is the target service and X2 is the method ID. Observed X0 still equals the IOService metaclass address; the captured lookup body does not use its incoming X0 before replacing it. No unsupported C++ receiver signature is inferred from this residual register.

Fourteen cases execute original platform builders and original Invoke to the server helper. Two separate generic one-way components reuse the prior original request/context and explicitly change only flags before entry, with a stack lowered by 2048 bytes to preserve those source-produced bytes. Neither path executes the local Dispatch/adapter/device/controller chain. The local path's temporary clear/restore of current-thread+0x378 does not occur on these selected remote paths; the private word remains unchanged. [RM2,RM6,RM7]

## Outgoing destination and exact emission locations

After successful declared reference-copy and request conversion, original source writes the request header:

| Source site | Store/call | Established local contract |
| --- | --- | --- |
| 0xfffffe000c595d70 | u32 at message+0 | 0x80001513 for request/reply; 0x80000013 for one-way. |
| 0xfffffe000c595d74 | Two u64 stores at +8/+0x10 | Destination = reference-copy return; initial local endpoint = NULL. |
| 0xfffffe000c595d80 | Eight bytes at +0x18 | Voucher word zero and message/version ID 0x4da2b68c. |
| 0xfffffe000c595e08 | BL 0xfffffe000bcf59e0 | Request/reply transport call site. |
| 0xfffffe000c595da4 | BL 0xfffffe000bcf55dc | Send-only transport call site. |

Thirteen transport frames verify these complete outgoing header bytes and exact pre-call arguments. Low destination disposition is 19; request/reply adds local disposition 21, consistent with the prior copyin disposition analysis. The complex bit is set. Actual descriptor conversion is modeled, so the zeroed descriptor reservation and object-reference payload remain private fixtures; these bytes are not claimed to be a native deliverable request or emitted right. [RM3,RM4,RM8]

| ABI input | IORPC caller here | Prior FairPlay RPC502/700 caller |
| --- | --- | --- |
| Common transport entry | 0xfffffe000bcf59e0 | Same exact source entry. |
| Send size | 92 bytes clock/power; 100 bytes PSD | 88 bytes. |
| Receive capacity | 128 bytes clock/PSD; 132 bytes power | 400 bytes. |
| W3 interruptibility input | 0 | 1. |
| X4 policy input | 0 | 0x2000000000, bit 37. |
| X5 message_moved output | Non-NULL private u32 pointer | NULL. |
| Destination producer | Selected queue's data+0x28 and reference-copy return | Separately recovered protected destination acquisition. |

Send-only inputs are message, send size, raw option value 0x50001, zero, and a message_moved output pointer. No confirmed public symbol is assigned to the stripped send helper.

The common transport's separately recovered body obtains its receive endpoint from current-thread+0x3f0, creates it when absent and inserts it into the internal kmsg header. This is a distinct stage from the IORPC caller's initial local=NULL store and from the queue-derived remote destination. The existing source body also sends at 0xfffffe000bcf5ba8. These static joins establish shared implementation and separate endpoint roles; the current CPU cases stop/model the common transport at entry and do not execute thread-port allocation, right conversion, sending or receiving. No new runtime port object or task-local name is observed. [RM7,RM8]

## Return, ownership signal and reply contracts

After a declared transport return, original code requests exact ipc_port_release_send on the copied destination, then requests queue release. Nine cases verify this order. The fallback-frontier case instead stops with its prior queue-retain request recorded; no completed send or balanced native lifetime is inferred at that frontier.

| Conditional input | Source-established result |
| --- | --- |
| Nonzero transport return, message_moved=0 | Port/queue release requests, then conversion interface with modes (0,1) on the original request; returned status propagates. |
| Same nonzero return, message_moved=1 | Same release requests; request conversion cleanup is skipped. |
| NULL method queue, valid fallback | Original fallback queue retain and destination preparation reach the transport frontier. |
| NULL method queue and NULL fallback | Return 0xe00002d8 before port copy/conversion/transport. |
| Server state bit 0 set and NULL fallback | Return 0xe00002d7 before queue lookup. |
| Declared NULL port-reference copy | Queue release request; return 0xe00002d8 before conversion/transport. |

The message_moved branch is a caller ownership decision. Supplying its value does not transfer an actual right or establish real transport consumption. Reference models perform no native retain/release or counter effect. [RM3-RM5,RM7]

For the supplied noncomplex normal replies, original remote validation checks version 0x4da2b68d, minimum inline size 60 bytes and matching 64-bit method ID, and requests conversion with modes (1,1). The original outer capitalized wrapper then applies its stricter exact method-specific size, descriptor-count and objectRefs checks. Power's four-byte output reaches the original caller through that outer reader. The normal reply buffers are copied exactly from prior source-generated local replies; actual remote construction and conversion remain unknown.

Saved request flags govern whether reply validation occurs. The original ordinary builders supply 0x80, and remote Invoke ORs masks 0x04 and 0x01 to produce 0x85. Separate one-way components supply 0x8d and take the send-only branch, bypassing response validation. Reply flags 8 in an ordinary response do not retroactively make the request one-way.

One declared error reply sets size=68 bytes, flags=0x48 and a u32 result 0xe00002bc at content+0x18. Original source selects conversion modes (0,1), extracts that result and propagates it through the outer caller. One declared nonzero normal-reply conversion result requests reply cleanup and a second conversion with modes (0,1), then returns raw 0x2e. These are conditional record/return contracts; no native server error, successful converter effect or global return-code taxonomy is established. Descriptor-bearing reply paths and lower conversion internals remain unexecuted. [RM4,RM5]

## Additional static action adapter

Original 77-instruction helper 0xfffffe000c595ac4 is captured but not executed. Under its OSAction-associated path, it compares the content method ID with state+0x10, obtains target at state[0], replaces the method ID with state+8 and writes the target into content object reference zero. When Remote bit 0 is set, source requests target retain and action release before returning the target. Nonmatch/null-target leaves the action pointer as the result. Exact OSAction metaclass provenance supports this conditional role; authentic action-state producers, lifetime and callers remain unknown. This adds a concrete method/object rewriting opportunity for subsequent analysis without treating raw dispatch words as Mach rights. [RM1,RM7,RM8]

## Verification and bounded continuation

Sixteen fresh independent CPU replays verify 4012 original instruction visits, 937 writes / 7176 bytes, 971 reads / 7343 bytes, 128 logical authentication steps, 98 indirect edges, 16 boundaries, 2656 final object images, 32 source-global images, 112 environmental-global images and 16 final RPC buffers. Eighty declared API models have 14 separately recorded memory effects / 680 bytes. Frame checks cover 16 remote entries, 15 queue lookups, 14 port copies, 21 conversion entries, 13 transport frontiers/calls, 20 reference frames and one reply cleanup.

The 158 prior actor images transfer exactly before explicit fixtures. Per case, 157 remain byte-identical; the device image matches exactly after the single declared +0x28 pointer patch. All 2528 such comparisons pass. Allocation accounting and DMA metadata remain unchanged; no new jobs or DMA objects are created. No native transport body, port operation, platform effect or hardware PAC executes.

Run: `PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_iorpc_remote.py`. Complexity is O(image bytes + visits + journal events + object bytes) time and O(image bytes + journals + private RAM) space. Addresses/offsets are hexadecimal; sizes are exact integer bytes; one byte is 8 bits. No latency, scheduling or hardware measurement is inferred.

| Impact | Remaining evidence | Architectural purpose |
| --- | --- | --- |
| High | Authentic metaclass/service-link/server/queue producers and native endpoint identity | Determines whether this conditional remote route exists for the investigated accelerator. |
| High | Request/reply object-conversion bodies and descriptor/right publication | Replaces no-effect conversion models with actual representation and ownership contracts. |
| High | Common transport under this policy and actual receiving process | Establishes native delivery, reply endpoint and object identity rather than shared code alone. |
| High | Actual controller and historical RAX UserClient-open context | Connects platform effects and daemon/kext evidence beyond the recorded BadArgument/null connection. |
| Medium | Method queue search, fallback metadata and action-state producers | Resolves selected queue and method/object rewriting from authentic initialized state. |
| Medium | Unknown class anchors, other remote routes and descriptor-bearing replies | Extends the bounded route coverage while preserving unresolved type/transport joins. |

QG1: Descriptive technical evidence is sufficient for this increment.

QG2: RM1-RM8 enumerate premises, dependent results and falsification probes.

QG3: This increment covers conditional service-to-server routing, queue destination/header emission locations, the shared-transport ABI, selected cleanup/reply paths and static action adaptation. The full daemon/kext/native goal remains active.

QG4: Pointer chains, fixed widths, request/reply sizes/capacities, four-byte ownership/output fields, exact transfers and replay totals are reproducible.

QG5: Queue selection, port reference, destination store, reply endpoint, modeled transport, moved signal, conversion and platform success remain distinct. Unknown class identities and unexecuted paths are explicit.

QG6: Original bytes/symbols/fixups, prior byte-identical transport joins, producer packets, independent A64 replay and preserved inputs support the bounded claims. Source-correlated roles are distinguished from exact names; no IDB is changed.

QG7: Impact-labelled continuation covers remaining native object/port, representation, transport, action and daemon joins. Scoped passage does not establish native delivery or a complete FairPlay transaction.
