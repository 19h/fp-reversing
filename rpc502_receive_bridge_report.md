# RPC502: VM-copy conversion, packed request and daemon guard bridge

The original kernel descriptor conversion and packing now produce an RPC502
request that is consumed by the original fairplayd MIG502 guard and argument
marshaller in a separate private CPU. The bridge checks the 88-byte kernel
representation, 80-byte user representation, 68-byte trailer, receiver OOL address,
descriptor flags, repeated extent, audit token and application-call arguments.
It stops before the application executes.

Under the declared namespace/VM models, 32 packets reach the application-call
boundary. Sixteen additional kernel-success packets are rejected with -300
(MIG_TYPE_ERROR) because entry-list validation enlarged the descriptor extent
while the repeated extent remained unchanged. This is a verified representation
compatibility constraint. It is not an observed native failure of an ordinary
FairPlayIOKit request: the actual runtime copy representation is unestablished,
and the original copy-in factory contains an extent-preserving kernel-buffer path.

Another 64 packets carry modeled VM body errors. Their daemon-guard components
also reject, but actual framework forwarding of a nonzero kernel receive result
is not established. All VM, namespace, copyout, allocator and PAC premises remain
explicit. No native IPC, VM operation, application call or live exchange executes.

## Primary evidence and reproduction

Kernel addresses are unslid VAs in collection SHA-256
`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`.
Daemon addresses are preferred VAs in the thin image SHA-256
`4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`.
Offsets/constants are hexadecimal; byte extents and counts are decimal.
Original function bounds and exact nlist results remain separate from descriptive
role names. No fresh IDA query, IDB modification or saved-memory write was needed.

| Artifact | Evidence |
| --- | --- |
| [Source](triage_evidence/rpc502_receive_bridge_source.json) | Six kernel functions/1,603 instructions and the original 77-instruction daemon guard/marshalling interval |
| [Kernel profiles](triage_evidence/rpc502_receive_bridge_profiles.json) | 112 original-source runs with declared namespace and VM effects |
| [Daemon profiles](triage_evidence/rpc502_receive_bridge_daemon_profiles.json) | 112 packet-consuming guard components, application/error cuts and argument journals |
| [Proofs](triage_evidence/rpc502_receive_bridge_proofs.json) | Eighteen obligations and 36 original/simplified SMT files |
| [Checks](triage_evidence/rpc502_receive_bridge_checks.json) | Fresh kernel/daemon replay, independent packet oracle and SDK compilation |
| [Copy-in provenance](triage_evidence/rpc502_receive_bridge_copyin.json) | Original kext call arguments, copy-in wrapper and conditional kernel-buffer factory fields |
| [Preservation](triage_evidence/rpc502_receive_bridge_delivery.json) | Baseline preservation and six allowed existing-file changes |
| [Quality gates](triage_evidence/rpc502_receive_bridge_quality_gates.json) | Scoped QG1-QG7 and explicit native limitations |

From this directory, using the existing interpreter and solver:

```sh
env PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_rpc502_receive_bridge.py
```

Time is O(source/artifact bytes + visits/effects + compiler/solver resources);
space is O(collection metadata + one private CPU map + largest profile + DAGs).
Fresh replay uses separate executors and an independent byte-layout oracle, while
sharing Unicorn as its ISA engine. It checks every original word, source read/write,
modeled call argument/clobber/output, caller handover, private copy and final state.

## Upstream object provenance and bounded interpretation

The [kext filename-copy report](kext_port_vm_report.md) establishes the ordinary
constructor's `strlen`, wrapped u32 length-plus-NUL, staging in ipc_kernel_map and
`vm_map_copyin(map,staging,extent,0,&copy)`. The OOL field passed to kernel RPC is
a VM-copy object, not the original filename virtual address. The
[kernel RPC transport](kernel_rpc_transport_report.md) signs that pointer for
internal descriptor storage under the kext policy; its type-1 copyin path advances
over the already prepared descriptor.

Fresh original-byte inspection adds these factory constraints:

| Source | Established conditional behavior |
| --- | --- |
| BDD1594-BDD15A0 | Public copy-in wrapper normalizes destroy-source W3 to Boolean and branches to BDD15A4 |
| BDD16B4-BDD16D8 | A small-copy path requires selected option bits clear, extent <=32,768 bytes and an aligned start meeting the map interval check |
| BDD183C-BDD1868 | Further map interval/global conditions precede the buffer path |
| BDD1F0C | Factory stores the input extent X23 at copy+0x20 |
| BDD1F14-BDD1F18 | Factory stores type 3 at copy+0x2D |
| BDD1F20-BDD1F28 | Factory signs/stores the backing-buffer pointer at copy+0, DA discriminator 0xB7AF |

These static factory fields agree with the extent-preserving kernel-buffer cases.
The complete factory is not executed here; runtime map/global conditions and the
actual request's copy type are unknown. Entry-list expansion remains conditional
on type 2 reaching this transport. The VM-copy fixtures initialize fields used by
the executed validator; a genuine complete backing object and native mapping
semantics are not inferred from those fields alone.

## Executed bridge and explicit model boundaries

```text
source-schema 88-byte complex request + private queue/object frames
  -> original common receive and user receive-results
  -> original header conversion
       +-> modeled reply-name/entry output -> source namespace publication call
       +-> source destination-name conversion
  -> original descriptor loop BCC5564
       -> logical descriptor AUTDA, discriminator 0x5D4F
       -> original VM-copy validator BDD148C
       -> declared VM mapping/allocation/overwrite effects
       -> source descriptor address/extent and error aggregation
  -> original packing + declared private copyout
  -> exact packet/mapped-buffer transfer into separate daemon CPU
  -> original MIG502 guard
       +-> application-call argument boundary (application not executed)
       +-> -300 descriptor/extent rejection
```

The setup extends the earlier [receive-delivery model](kernel_receive_delivery_report.md)
with a complex request fixture following the recovered RPC502 schema. It does not
execute the kext constructor, generic-dispatch allocation or transport copyin.
Queue links/count/sequence come from the verified single-message producer fixture;
message content and receiver/space/map/port metadata are declared preconditions.

The request uses native internal dispositions 17/18, destination object D and
reply object P. Its reply-name entry helper supplies user name 0x203 and a private
namespace-entry pointer through declared output parameters. Original source then
calls its publication backend, consumes selected counters and rebuilds the header.
The destination receive name 0x107 is read from D+0x34 after receiver-space matching.
Backend validity, actual namespace entry creation and native rights remain modeled.

## Descriptor validation, mapping and failure contracts

For the type-1 descriptor, source BCC5664-BCC5698 loads and logically authenticates
the VM-copy pointer with the descriptor storage address and discriminator 0x5D4F,
widens its u32 extent to u64 scratch storage, and calls BDD148C.

The original validator executes its non-wrapping 48-byte span/pool-bound checks
and indexed zone-metadata check. It uses `(pointer>>10)&0xFFFFFFFF0` as an index
offset, masks the loaded u16 metadata by 0x3FF and requires class 0x13. The pool
bounds and metadata table are explicit private fixtures; passing these checks is
not evidence of a genuine native allocation or accepted hardware authentication.

| Copy kind at +0x2D | Original extent rule |
| --- | --- |
| 3, source-correlated kernel buffer | copy.size at +0x20 must equal original descriptor extent N |
| 2, source-correlated entry list | N <= copy.size C <= round_up(N, map page size); validator writes C back to u64 extent scratch |
| Other or inconsistent size | Validator false; descriptor loop takes a diagnostic path outside these profiles |

The fixtures use map page shift 14. The symbolic entry-list obligation covers all
u32 N and u64 C under that fixed page-shift premise; other map shifts are not
established by the execution set. Kernel-buffer extent stays N. Entry-list cases
use C=N or N+1, both within the permitted page rounding for the selected N.

| Source call | Recovered argument contract / declared effect |
| --- | --- |
| BCC56E8 -> BDCB374 | `(map,&address,copy,C,1)`; direct mapping model supplies address and backing bytes on success |
| BCC5878 -> BDC1CD4 | `(map,&base,allocation_span,0x14000000)`; unaligned entry-list path reserves a modeled receiver region |
| BCC58B0 -> BDD048C | `(map,target,copy,C,0)`; overwrite model supplies C bytes on success |
| BCC58C8 -> BDC1EC0 | On overwrite failure, deallocation request for the allocated base/span |
| BCC58F8 -> BDC6308 | Failed mapping requests VM-copy discard, then clears descriptor address/extent |

All entry-list profiles take the unaligned-size branch; offset is zero, and the
allocation span rounds to 16,384 bytes. The descriptor still carries C, not the
allocation span. Successful models write a private mapped address and declared
payload bytes. These effects do not execute real allocation, mapping, consumption
or deallocation; the raw final integer arguments 1/0 are retained without assuming
that the model establishes their complete native ownership semantics.

The loop publishes a u64 receiver address and low32(validated extent) in the
descriptor. On mapping error 6 it accumulates mask 0x400; other nonzero errors
accumulate 0x1000. Its result is zero for mask zero, otherwise
`0x1000400C | accumulated_mask`. Original receive-results continues selected
partially converted body packets through packing. Packet bytes and receive status
therefore remain separate evidence channels.

## Packed request and Mach-name directions

| Field | Kernel offset/width | User64 offset/width |
| --- | --- | --- |
| Header | +0, 32 bytes | +0, 24 bytes |
| Descriptor count | +0x20, u32 | +0x18, u32 |
| OOL pointer / receiver address | +0x24, u64 VM-copy pointer | +0x1C, u64 receiver virtual address |
| Descriptor flags | +0x2C, u32 | +0x24, u32 |
| Descriptor extent | +0x30, u32 | +0x28, u32 |
| NDR | +0x34, 8 bytes | +0x2C, 8 bytes |
| Repeated extent | +0x3C, u32 | +0x34, u32 |
| CPU / subtype / origin | +0x40/+0x48/+0x50, u64 each | +0x38/+0x40/+0x48, u64 each |
| Total inline extent | 88 bytes | 80 bytes |

Original 64-bit descriptor packing preserves the 16-byte descriptor extent but
contracts the header by 8 bytes. It rebuilds the flags as
`(F & 0xFF00FF00) | (((F>>8)&0xFF)==1 ? 1 : 0)`, producing 0x01000101 from
0x01000100. The deallocate byte is reconstructed from the copy method; it is not
an invariant copy of the sender's byte. The source-lifted identity covers all u32
flag words under the selected type-1/3 packing path.

| User header role | Modeled name / original conversion provenance |
| --- | --- |
| Remote/reply name at +8 | 0x203, supplied by the modeled reply namespace-entry helper |
| Local/receiving-service name at +0x0C | 0x107, source load from destination D+0x34 after receiver-space equality |
| Dispositions | User bits 0x80001112, rebuilt from internal send/send-once fields |
| Message ID | 502 |

These are recipient-namespace name fixtures, not native names inferred from
kernel pointers. The source consumes destination send/object counters and
temporarily increments/decrements the reply-object count around entry publication.
Native acquisition, reference ownership and successful namespace entry creation
are not proved by the source-side arithmetic or modeled outputs.

The packet carries 80 inline bytes plus a fully delivered 68-byte AV trailer:
148 bytes in a private 3,072-byte-capacity receive. Trailer type is zero; sequence
is the original queue value UINT32_MAX; security words are (0,1); the eight audit
words are zero; receiver context is the declared u64 fixture. The kernel template
and original writer supply those bytes in the model. Hardware authentication,
initiating-user identity and native library pairing remain unestablished.

## Daemon guard, argument ABI and error interpretation

The original stub at 0x1000050C8 performs its checks in this order:

| Guard | Original site | Failure category |
| --- | --- | --- |
| Complex bit set | 1000050C8-1000050CC | Framing rejection -304 |
| One descriptor | 1000050D0-1000050D8 | Framing rejection -304 |
| Inline size 80 | 1000050DC-1000050E4 | Framing rejection -304 |
| Descriptor type byte 1 | 1000050E8-1000050F0 | MIG_TYPE_ERROR -300 |
| Descriptor extent equals repeated extent | 1000050F4-100005100 | MIG_TYPE_ERROR -300 |
| Trailer type zero and advertised extent >31 | 100005118-10000512C | Trailer-error path, outside these supplied packets |

The current SDK corroborates MIG_TYPE_ERROR=-300 and MIG_BAD_ARGUMENTS=-304.
The guard does not validate the complete descriptor flag word or scan filename
bytes. The components stop before the application call at 0x1000051F8; they do
not dereference the OOL filename. Actual readable/NUL-terminated backing remains
an application precondition. The model provides a filename-plus-NUL prefix of
length 8 or 37, with any modeled expansion bytes separately declared.

| Application boundary location | Source-derived argument |
| --- | --- |
| W0 | Receiving-service name 0x107 |
| X1 | Receiver OOL address supplied by mapping |
| W2 | Descriptor extent, after equality guard |
| X3 / X4 / X5 | u64 CPU / subtype / origin fields, fixture values 0x100000C / 0 / 1 |
| X6 | Pointer to the 32-byte audit copy on the stub stack |
| X7 | Reply-buffer+0x44, fixed record0 destination |
| Entry stack +0 | Reply-buffer+0xCC, fixed record1 destination |
| Entry stack +8/+0x10 | Reply-buffer+0x1C / +0x178, first OOL output address/count pointers |
| Entry stack +0x18/+0x20 | Reply-buffer+0x2C / +0x17C, second OOL output address/count pointers |

The original vector loads/stores copy all 32 audit bytes from user offsets
100..131 into the stack argument. Those bytes are within the 148-byte delivered
packet. A byte-array proof covers all 256 token bits. The deeper PID-zero predicate
is documented in [daemon_rpc502_report.md](daemon_rpc502_report.md); reaching this
call boundary is not application success, complete policy acceptance or authorization.

| Scenario, 16 cases each | Kernel result | Packed descriptor extent | Daemon component |
| --- | --- | --- | --- |
| Type 3, mapping success | 0 | N | Application boundary |
| Type 3, mapper error 6 | 0x1000440C | 0 | -300 |
| Type 3, mapper error 5 | 0x1000500C | 0 | -300 |
| Type 2, C=N, overwrite success | 0 | N | Application boundary |
| Type 2, C=N+1, overwrite success | 0 | N+1 | -300; repeated extent remains N |
| Type 2, overwrite error 6 | 0x1000440C | 0 | -300; allocated-region cleanup requested |
| Type 2, allocation error 6 | 0x1000440C | 0 | -300; overwrite not called |

Only the kernel-success expansion row supplies a normal-status packet rejected
solely by the repeated-extent guard. Actual copy-type/factory provenance remains
an explicit prerequisite. The VM-error rows establish packet/status/control-flow
contracts, not normal framework dispatch of error receives.

If the previously recovered callback/demultiplexer receives a recognized RPC502
request and its stub returns a nonzero simple error, it preserves the reply right
by clearing request.remote before generic request destruction. Its ordinary error
reply uses ID602 and the received reply name. That reaction is retained in
[daemon_receive_interface_report.md](daemon_receive_interface_report.md), not
executed in these guard components. No incoming mapping leak or native error reply
emission is inferred from the stopped application/error boundary.

## Validation, assumptions and continuation

Fresh replay checks 108,488 original kernel visits and 2,992 daemon guard visits.
The independent oracle checks all 4,096 private receive-buffer bytes, mapped
payloads, descriptor fields, original VM arguments, cleanup requests, counters,
copied audits and application arguments. It also checks exact packet/mapping
transfer into each daemon component. The 384 declared namespace/VM effect events
and 168 private copyout calls are independently replayed. Eighteen rebuilt
obligations and 36 saved SMT files pass; reconstructed 88/80-byte layouts and
public constants compile for arm64e.

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| RB1 | Original collection/thin image and static mappings identify these compiler epochs | Rehash bytes, UUIDs, fixups and function boundaries |
| RB2 | Request fixture follows the recovered kext RPC502 schema; constructor/copyin are not executed | Execute original sender preparation and compare every pointer, extent, scalar and right |
| RB3 | Queue, receiver, map, space and port frames satisfy the selected private contracts | Establish live ownership, native namespace state and actual receiver identity |
| RB4 | Copy-pool bounds and class metadata are private fixtures; passing source checks does not prove genuine allocation | Attest native VM-copy provenance and complete object/payload fields |
| RB5 | Logical PAC preserves supplied targets and arbitrary hash outputs match fixture tags | Validate native signed storage, hardware keys and integrity behavior |
| RB6 | Namespace-entry/name/publication helpers have their declared outputs/effects | Execute native entry allocation, locking, right transfer and rollback paths |
| RB7 | VM allocation/mapping/overwrite supply declared pointers/payloads; failure models make no hidden writes | Execute real receiver-map operations, partial failures, consumption and cleanup |
| RB8 | Page shift 14 and selected sizes/offsets bound the entry-list cases | Verify actual source/receiver page shifts, map intervals and alignment |
| RB9 | Actual sender copy type is unknown; expansion relevance depends on type 2 reaching this transport | Trace the complete copy-in factory under real map/global conditions |
| RB10 | Exact packet transfer directly to MIG502 models a consumer boundary, not CF forwarding | Observe installed framework, receive status handling, voucher hooks and demux selection |
| RB11 | Application ABI reaches a stopped call boundary only; filename backing and policy remain separate | Trace readable/NUL data, application effects and full reply/ownership lifecycle |
| RB12 | Fresh replay shares Unicorn and SDK/private views are not exact native header provenance | Cross-check another ISA engine and a matched native exchange |

| Impact | Further evidence | Interface resolved |
| --- | --- | --- |
| High | Full sender copy-in factory and actual map/copy type | Whether an ordinary kext filename object always preserves extent or can use the expansion case |
| High | Native namespace/VM/copyout and installed CF forwarding | Which names, bytes, rights and statuses reach the real daemon |
| High | Application/response construction and kernel reply copyout/ownership join | Complete RPC502 round trip rather than an input-call boundary |
| Medium | Native reply-entry and VM mapping helper bodies | Hidden lifetime, locking, consumption and rollback effects |
| Medium | Port-set, voucher, foreign-space and multi-descriptor cases | Alternatives outside the one-descriptor source path |
| Low | Exact source revision/private types | Replace descriptive role names with exact native nomenclature |

QG1: Factual technical analysis requires no normative conclusion.
QG2: RB1-RB12 identify dependencies and explicit falsification probes.
QG3: Selected RPC502 descriptor conversion, packing and MIG input ABI are covered;
the full daemon/kext/deeper objective remains active.
QG4: Widths, byte extents, alignment/page premises, modular arithmetic, complexity,
SDK layouts and reproduction are explicit.
QG5: Kernel success versus VM body error, descriptor versus repeated/allocation
extent, guard versus application acceptance, and factory versus runtime provenance
are separated. Native forwarding and expansion reachability remain unestablished.
QG6: Original bytes, source-state models, fresh dual-image replay, independent
packet oracle, rebuilt SMT, factory capture and SDK checks support the scoped claims.
QG7: The impact table bounds sender provenance, native transport and reply work.
