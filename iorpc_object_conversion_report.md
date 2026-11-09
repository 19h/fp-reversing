# IORPC object/port conversion and IOMachPort registry

Original request and reply conversion bodies now execute in the conditional remote IORPC chain. The outgoing port branch resolves an object through an IOMachPort registry, creates a private send-reference counter transition, clears object-reference storage and writes a signed port descriptor. Reverse conversion can recover the associated object and independently request descriptor-right release. A source-created registry node feeds subsequent cache-hit and collision cases. Native allocation, locks, object reference effects, port creation, send release and transport remain modeled; no native port, right or delivery is established. [OC1-OC8]

```text
source request object[0] -> original object-to-port helper
  object-address hash -> 4096 registry buckets -> IOMachPort node
  miss: original 40-byte node construction + model port allocation
  hit: source compares node.object and port type
  -> original port association/check + source counter increments
  -> clear request object[0] -> signed descriptor port, type/disposition fields
  -> original remote header/caller -> declared kernel transport

separate source-produced converted packet
  original reverse converter -> authenticate descriptor port
  restore=1: original port -> IOMachPort -> associated object
  release=1: request send-reference release; clear descriptor pointer
```

[Original source and bindings](triage_evidence/iorpc_object_conversion_source.json), [16 profiles](triage_evidence/iorpc_object_conversion_profiles.json), [independent replay/oracles](triage_evidence/iorpc_object_conversion_checks.json), [preservation](triage_evidence/iorpc_object_conversion_delivery.json) and [scoped gates](triage_evidence/iorpc_object_conversion_quality_gates.json) retain the evidence. This replaces the whole-converter models in the [remote IORPC report](iorpc_remote_report.md) for the selected port and zero-reference reply paths. The [earlier kernel transport report](kernel_rpc_transport_report.md) remains the separate source of common transport/right-copyin analysis. The historical [zut capture](zut_trace_report.md) remains unchanged.

## Assumption register

| ID | Premise and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| OC1 | The pinned collection supplies original code, symbols, compiler bounds and fixups. | Rehash and recapture 110 retained/new functions, 9642 instructions, 35 bindings and registry/constants bytes. Match a different runtime build separately. |
| OC2 | Prior conditional service/server/queue/hierarchy and transport premises carry forward. | Match authentic field producers, endpoint identity and native send/receive. Descriptor conversion does not establish a real queue or delivered message. |
| OC3 | Registry lock, bucket table, node metaclass count, allocation cache and zone globals use explicitly declared private epochs. | Recover authentic initialization, concurrent users and runtime global values. Only the uncontended selected lock path is exercised. |
| OC4 | Lower allocation returns declared private storage; port creation supplies a 256-byte active type-0x29 port fixture with an IOMachPort backlink. | Match zone extents, actual constructor state, port type/active/reference fields and ownership. Private reservation size and modeled initial counters are not native allocation proof. |
| OC5 | Port locks, object retain/release/taggedRetain and ipc_port_release_send remain no-effect models. Original send-reference counter instructions execute. | Match actual reference effects, lock ownership, port notifications and retirement. Do not infer balanced native counters or absence of leaks from these models. |
| OC6 | Standalone converter cases transfer exact source-built request/converted packets, with explicit consume/restore/release or nullable inputs and a separate lower stack. | Establish actual callers and ownership epochs before applying these component modes. They are not resumed native exchanges. |
| OC7 | One case substitutes NULL at object-to-port entry without executing that helper's body. Its original caller then returns zero with the object slot preserved. | Establish whether an authentic helper path can return NULL for this object/type. The case is conditional caller behavior, not a native failure or deliverable-message claim. |
| OC8 | Logical PAC, block ABI, metadata/zone epochs and native synchronization remain conditional; no native registry/port/IPC operation or IDB mutation occurs. | Verify actual PAC acceptance, runtime objects/build and native observations before an end-to-end FairPlay claim. |

## Source identities and recovered routine roles

Collection: `/Users/___/Downloads/fpx/img4_dump/kernelcache.macho`; SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`. Ten complete functions / 494 instructions are added to the prior capture. Complete original bytes/disassembly, exact symbols separately from inferred roles, globals and chained slots are retained.

| Original entry | Established role | Provenance boundary |
| --- | --- | --- |
| 0xfffffe000c5962c0 | Outgoing object-to-descriptor conversion | Original 390-instruction body; selected port branch executes. |
| 0xfffffe000c5968d8 | Descriptor-to-object conversion and cleanup modes | Original 259-instruction body; port and zero-reference reply paths execute. |
| 0xfffffe000c56114c | Object-address hash, IOMachPort cache lookup/create and port return | 87 original instructions; miss/hit/collision paths execute under declared epochs. Exact function name unknown. |
| 0xfffffe000c561300 | 40-byte IOMachPort node construction and object association | 79 original instructions; ordinary zero-cache allocation path executes. Exact function name unknown. |
| 0xfffffe000bcf4fa0 | Port type/backlink check and send-reference creation call | 53 original instructions; selected active-port path executes. Exact name unknown. |
| 0xfffffe000bccfc94 | Counter updates in the selected send-reference path | 28 original instructions; no native port operation executes. Exact name unknown. |
| 0xfffffe000be351d0 | Port type/backlink -> IOMachPort -> associated object | 81 original instructions; selected valid private port path executes. Exact name unknown. |
| 0xfffffe000be35a54 | Type-specific port-allocation adapter | 28 original instructions; auxiliary initialization executes, lower allocation is modeled. |
| 0xfffffe000c444e0c | OSObject::init | Exact nlist binding; original BTI/MOV W0,1/RET executes. |
| 0xfffffe000c49f41c | _Block_object_dispose | Exact nlist binding; ordinary stack-byref cleanup branch executes. |

Exact definitions identify vtable 0xfffffe0007f502c8 as IOMachPort, with object vptr at +0x10 = 0xfffffe0007f502d8, and metaclass 0xfffffe000cb53450 as IOMachPort::gMetaClass. Four new authenticated slots resolve node retain/release/init and device taggedRetain to their exact OSObject names. No exported name or kernel kobject enumeration name is assigned to raw selector 0x29 without further provenance. [OC1,OC4]

## Registry hash, source construction and cache reuse

For object pointer P, original instructions compute:

```text
x = u32((P >> 4) * 0x5052acdb)
index = (x XOR byte_reverse_u32(x)) AND 0x0fff
head = *(0xfffffe000cb53478 + 8*index)
```

This selects 4096 eight-byte buckets, a 32768-byte table extent. The source formula follows captured instructions; the CPU cases cover the selected object and one same-index collision, not exhaustive registry populations. Private object 0x650002a000 hashes to index 1280. Collision identity 0x6500072360 independently hashes to the same index. A declared decoy node precedes the source-created real node; original traversal follows node+0x10 past its nonmatching object and resolves the real node.

The miss case executes original node construction, port-allocation adapter, list publication and accounting:

| Field/event | Source-established value or operation |
| --- | --- |
| Allocation request | 40 bytes, flags 0x41004; declared zeroed lower-backend result replaces a 0x5a reservation. |
| Node vptr | Logical signed IOMachPort vptr 0xfffffe0007f502d8. |
| Node+0x08 | u32 base reference word 1. |
| Node+0x0c | Mapping flag byte 1, set by original cache-creation caller. |
| Node+0x10 | Previous bucket head; becomes next-node link. |
| Node+0x18 | Returned private port pointer. |
| Node+0x20 | Associated original object; source PAC diversity 0xba96. |
| Bucket publication | Original store at 0xfffffe000c5611e8. |
| Allocation accounting | Original +40-byte update, 9728 -> 9768 bytes. |
| IOMachPort metaclass count | Original +1 under declared zero epoch. |

The original auxiliary port adapter supplies raw creation inputs `(node,0x129,aux,0)`. Lower port construction is modeled. Its preceding source writes two u64 auxiliary words `(1,0)` into a declared 16-byte private reservation; actual zone extent is unknown. The node's taggedRetain request and all lower reference effects remain modeled.

Case 0's complete actor and registry-global images feed later cases exactly. Cache hits allocate no new node and preserve the source-produced metaclass/accounting epoch. The declared registry lock path uses emulated current-thread+0x518 as an opaque u32 owner token, acquires a zero lock word and restores it to zero. Slow locking, concurrency and native thread identity are unproved. [OC3-OC5]

## Object port, destination port and descriptor representation

The new object port is a distinct private fixture from the queue destination used by the remote transport. Object-port association checks type byte 0x29, active bits and the port+0x50 wrapper pointer against the selected IOMachPort node. Its source authentication modifier combines that field location with `0x29 XOR 0x5a = 0x73`. Hardware PAC acceptance remains unknown.

Original selected counter instructions increment u32 fields at port+0x84 and +0x88 and atomically increment +0x04. Starting from declared values `(reference word=1, +0x84=0, +0x88=0)`, the miss case ends with `(2,1,1)`; a subsequent hit ends with `(3,2,2)`. Release calls remain no-effect models, so these images do not establish a balanced native lifetime or real send-right consumption. Source offsets/arithmetic are established separately from complete native field initialization and semantics. [OC4,OC5]

For a non-NULL exported object and non-NULL returned port, original request conversion performs:

| Location relative to request message | Source result |
| --- | --- |
| Object slot +0x4c | Cleared to zero; objectRefs metadata count remains 1. |
| Descriptor pointer +0x24 | Object port pointer, logically signed with diversity 0x01ab using descriptor-slot context. |
| Descriptor word +0x2c | 0x00110000 in these zero-initialized port cases. |
| Descriptor word +0x30 | Zero. |

The low descriptor fields therefore contain disposition/type bytes rather than an object pointer, while the original object-reference storage has been cleared. Nine original remote-chain cases carry these source-produced descriptors to the transport frontier/call model. The object port and queue destination occupy different roles and fields; no equality/inequality of authentic native endpoints is inferred from private addresses.

Remote request conversion supplies consume=0. A separate consume=1 component executes the original conditional object release request before clearing the object slot. A NULL object yields a NULL port descriptor with the same disposition word. The declared NULL-return substitution at the object-port helper instead leaves the original object slot and zero descriptor fields unchanged while the converter returns zero. This last case demonstrates a local return/field contract only; authentic NULL reachability and native transport acceptance remain unknown. [OC6,OC7]

## Reverse conversion, restoration and release modes

Standalone reverse components use the exact converted packet and matching registry actor epoch from the source transport-frontier case. Original conversion first clears object-result storage, authenticates a non-NULL port descriptor and, when restoration is requested, invokes the original type-0x29 reverse helper. That helper checks active/type/backlink state, retains the IOMachPort wrapper, obtains its signed object field, requests object retain, then releases the wrapper before returning the object. Those reference requests are recorded no-effect models.

| Restore input | Release input | Final object slot | Final descriptor pointer | Source reference requests |
| --- | --- | --- | --- | --- |
| 1 | 1 | Associated original object | NULL | Wrapper retain, object retain, wrapper release; send release. |
| 1 | 0 | Associated original object | Preserved port | Wrapper retain, object retain, wrapper release. |
| 0 | 1 | NULL | NULL | Send release. |
| 0 | 0 | NULL | Preserved port | No object or send reference request on this selected path. |

Thus restoration and descriptor-right release are independent inputs. These components establish the selected port ABI; actual port/reference effects, native ownership transfer and all descriptor classes remain outside the executed scope.

The ordinary remote reply has objectRefs=0 and descriptor count=0. Its original conversion body now returns zero without an object/port API model, after which original remote validation and the outer caller reader continue. A supplied remote-error reply exercises its zero-reference conversion mode before error extraction. The unmoved transport-error path now executes the real cleanup converter: it requests release of the converted object port and clears the descriptor. With message_moved=1 that cleanup remains skipped. [OC2,OC5,OC6]

## Verification and bounded continuation

Sixteen fresh independent CPU replays verify 6288 original instruction visits, 1442 writes / 11033 bytes, 1668 reads / 12040 bytes, 200 logical authentication steps, 71 indirect edges, 16 boundaries, 2768 final object images, 32 source-global images, 112 environmental-global images, 96 registry-global images and 16 RPC buffers. Twenty-three original converter entries, 47 registry/block/port frames, three allocation frames, eight object-reference frames and 24 port-lock frames are checked.

Eighty-one remaining API models have 16 separately recorded memory effects / 1100 bytes. Whole request/reply-conversion models are absent from all 16 cases. Their replacement covers valid port descriptors and zero-reference replies; serialization/OOL branches, real zones, port construction internals, native release, actual locks and transport remain unresolved. All actor producers and 90 transferred registry-global images are checked exactly. Native identity, delivery and hardware effects remain unknown.

Run: `PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_iorpc_object_conversion.py`. Extraction/replay time is O(image bytes + visits + journal events + object bytes), with space O(image bytes + journals + private RAM). Hash evaluation is O(1); a bucket lookup is O(k) for k examined nodes. Addresses/offsets are hexadecimal; sizes are exact integer bytes; one byte is 8 bits. No timing or concurrency measurement is inferred.

| Impact | Remaining evidence | Architectural purpose |
| --- | --- | --- |
| High | Native registry/zone initialization, object wrapper publication and actual port construction | Replaces declared private epochs with authentic object/port identity and lifetimes. |
| High | Real reference release, port notifications, locking and transport consumption | Establishes ownership balance beyond the current source increments and release requests. |
| High | Serialization/OOL conversion and its inverse | Extends the selected port-descriptor contract to other object classes and nested representations. |
| High | Native remote service identity, controller effects and historical RAX open context | Connects these conditional lower interfaces to actual daemon/kext/platform behavior. |
| Medium | Slow/concurrent hash locking, metaclass/cache lifecycle and collision population | Extends the selected uncontended registry epoch without asserting general native behavior. |
| Medium | Authentic NULL-port return and other caller modes | Resolves the conditional field/status behavior without inferring failure semantics from a substituted return. |

QG1: Descriptive technical evidence is sufficient for this increment.

QG2: OC1-OC8 enumerate premises, dependent results and falsification probes.

QG3: This increment covers original port conversion, IOMachPort construction/cache lookup, selected counter operations, restoration/release modes and integrated reply/cleanup paths. The full daemon/kext/native goal remains active.

QG4: Hash widths, 4096 buckets, 40-byte requests, pointer/PAC contexts, field offsets, independent modes and exact replay/transfer totals are reproducible.

QG5: Object port, queue destination, wrapper, object reference, descriptor, source counter increment and modeled release remain distinct. Unexecuted descriptor classes and native lifetime gaps are explicit.

QG6: Original bytes/symbols/fixups, exact IOMachPort definitions, source-created producer snapshots, packet/field oracles and fresh CPU replay support the bounded claims. No native kernel/IPC/PAC effect or IDB change occurs.

QG7: Impact-labelled continuation covers remaining initialization, representation, ownership, locking, transport and daemon joins. Scoped passage does not establish a native FairPlay transaction.
