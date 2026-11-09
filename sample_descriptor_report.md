# Global media descriptors: concrete factory, copy ABI and lifecycle boundaries

The four global media descriptors use `IOMemoryDescriptor::withAddressRange`, whose matching kernel implementation allocates the nominal `IOGeneralMemoryDescriptor` class and packs one 16-byte address/length record. A null task selects raw memory type `0x20`; a nonnull task selects `0x10`. The previously unnamed read/write vtable entry points are two-instruction thunks into exact `IOMemoryDescriptor::readBytes` and `writeBytes` symbols. Original wrappers forward full64 address, length, offset and count values.

[Original contracts](triage_evidence/sample_descriptor_contracts.json), [retained models](triage_evidence/sample_descriptor_profiles.json), [distinct fresh replays](triage_evidence/sample_descriptor_replays.json), [independent checks](triage_evidence/sample_descriptor_checks.json), and [four local proofs](triage_evidence/sample_descriptor_proofs.json) support this increment. It extends the [AES handoff](kext_aes_handoff_report.md) and [dispatch-context](kext_aes_dispatch_report.md) reports. Source addresses are unslid; modeled pointers/results are explicitly declared fixtures. Offsets and extents are bytes.

```
caller address, length, kernel task pointer
  -> create helper, options 2 or 3
  -> withAddressRange
       -> IOGeneralMemoryDescriptor allocation
       -> { address64, length64 }, count 1, offset 0
       -> task null? type 0x20 : type 0x10
       -> initWithOptions(..., options | type, mapper = NULL)
       -> initialization false: release new object -> NULL
  -> global descriptor pointer
       -> prepare(0)
       -> readBytes / writeBytes
       -> complete(0)
       -> release()
```

The diagram lists available interfaces, not a proved ordering across every caller. The helpers do not themselves enforce that whole lifecycle. Native mappings, copied data, reference counts, serialization and valid caller states remain unknown. No additional Mach-message emission or port-right lifetime event is established.

## Primary source and verification scope

| Source | Identity / coverage |
| --- | --- |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Matching original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Original wrappers | 26 compiler-bounded functions, with normalized/original byte equality |
| Kernel implementation context | 7 compiler-bounded functions; factory, allocator, initializer and copy thunks/bodies |
| Class dispatch | 7 nominal authenticated vtable slots |
| Installed SDK | Pinned `IOMemoryDescriptor.h`; compile-only arm64e record/constant/virtual-call probe |
| Related adapter | Original 540-byte prefix at `0xfffffe000a5c22b8`, two exhaustive bank identities |

Private executions abstract authentication and API results. The factory's allocation, initializer and failure release are models at the original call sites. Wrapper copy methods do not access the declared task, address or buffer sentinels. The AES bridge stops before its target wrapper. No native task access, mapping, copy, crypto, reference or IDB operation executes. [Final source readback](triage_evidence/sample_descriptor_source_identity.json) and [prior-artifact preservation](triage_evidence/sample_descriptor_preservation.json) cover delivery.

## Four globals and exact helper locations

The suffixes in the helper columns below have prefix `0xfffffe000`. The global addresses are written in full. Options are raw factory argument bits.

| Group | Global | Options | Create | Prepare | Read | Write | Complete | Release |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Sample sizes | `0xfffffe000ccc7858` | 2 | `a509948` | `a5099b8` | `a509a60` | `a509b00` | `a509c08` | `a509bd4` |
| Samples | `0xfffffe000ccc7860` | 3 | `a509980` | `a509a0c` | `a509ab0` | `a509b50` | `a509c48` | `a509ba0` |
| Input | `0xfffffe000ccc7868` | 2 | `a509cc0` | `a509cf8` | `a509da0` | `a509e90` | `a509f48` | `a509ee0` |
| Output | `0xfffffe000ccc7870` | 3 | `a509c88` | `a509d4c` | `a509df0` | `a509e40` | `a509f88` | `a509f14` |

| Helper kind | Exact call/transfer position relative to entry | Behavior |
| --- | --- | --- |
| Create | +0x18, direct call | `withAddressRange(address64, length64, options32, task *)` |
| Prepare | +0x3c, authenticated call | Receiver from global, direction 0; normalizes low32 status |
| Read/write | +0x44, authenticated call | Receiver, offset64, pointer64, count64 |
| Complete | +0x3c, authenticated tail transfer | Receiver, direction 0; no local normalization |
| Release | +0x30, authenticated tail transfer | Receiver; `OSObject::release()` has void return semantics |

Thus the sample-size completion transfer is at `0xfffffe000a509c44`. Its source-context caller at `0xfffffe000a6257e8` was established in the preceding dispatch report. This identifies a transfer into the helper, not a native completion event.

## Concrete class and factory record

Stub `0xfffffe000a69f1e4`, imported slot `0xfffffe000847c420`, binds exactly to `0xfffffe000c53a934`, symbol `__ZN18IOMemoryDescriptor16withAddressRangeEyyjP4task`. Original code loads `IOGeneralMemoryDescriptor::gMetaClass` at `0xfffffe000cb53108` and dispatches its virtual allocator at +0xa8.

The nominal metaclass vtable symbol is `0xfffffe0007f42fe8`. Slot `0xfffffe0007f430a0` binds to `IOGeneralMemoryDescriptor::MetaClass::alloc()` at `0xfffffe000c538da4`. Its original allocator installs signed vptr `0xfffffe0007f446c0`, which is `__ZTV25IOGeneralMemoryDescriptor` (`0xfffffe0007f446b0`) +16. The source fallback allocation size is `0xb0 = 176` bytes; native zone state and actual allocation extent remain unknown.

| Initializer argument | Source value |
| --- | --- |
| X0 | Newly allocated descriptor |
| X1 | Address of stack record `{address64, length64}` |
| W2 | Range count 1 |
| W3 | Offset 0 |
| X4 | Original kernel `task *` argument |
| W5 | Raw caller options OR selected type bits |
| X6 | Mapper pointer 0 |

The installed SDK compile probe verifies a 16-byte `IOAddressRange`, with address at +0 and length at +8, both 8 bytes: `2 * 8 = 16` bytes. The original factory's `STP X0, X1, [SP]` independently establishes its packing. Forty-eight fresh initializer-call records verify 768 source-defined range bytes.

The initializer is exact `IOGeneralMemoryDescriptor::initWithOptions(void *, unsigned int, unsigned int, task *, unsigned int, IOMapper *)`, target `0xfffffe000c537720`, nominal vptr +0x138. Allocation null returns null without an initializer call. For a nonnull object, the factory tests bit 0 of the initializer result; false requests release and returns null, while true returns the object. Sixty fresh factory cases cover declared null allocation and canonical low32 Boolean results with varied upper X0 bits. No object is allocated or released natively.

## Task-dependent address interpretation

| Raw options | Task pointer | Added type | Initializer W5 | Installed SDK labels |
| --- | --- | --- | --- | --- |
| 2 | Nonnull | `0x10` | `0x12` | Virtual type, direction Out |
| 3 | Nonnull | `0x10` | `0x13` | Virtual type, direction InOut |
| 2 | Null | `0x20` | `0x22` | Physical type, direction Out |
| 3 | Null | `0x20` | `0x23` | Physical type, direction InOut |

The type selection and OR operation are original instruction facts; the SDK probe corroborates the names `kIOMemoryTypeVirtual`, `kIOMemoryTypePhysical`, `kIODirectionOut` and `kIODirectionInOut`. The task argument's nullness participates in address interpretation. Its input provenance, native admissibility and mapping/access policy are not established here. A kernel `task *` is the interface parameter in this exact C++ symbol; these helpers do not emit a task-port name or Mach message.

Options belong to the particular API namespace. In the preceding IOBuffer factory, raw `0x10` matched the SDK's physically contiguous allocation flag. In this `IOMemoryDescriptor` initializer, type `0x10` matches the SDK virtual-address type. Equal numeric bits across those API arguments do not establish equal semantics.

## Exact copy-method binding through unnamed thunks

| General descriptor vptr offset | Original slot | Entry target | Direct tail target and exact symbol |
| --- | --- | --- | --- |
| +0x208 | `0xfffffe0007f448c8` | `0xfffffe000c5361d4` | `0xfffffe000c5314ec`, `IOMemoryDescriptor::readBytes(unsigned long long, void *, unsigned long long)` |
| +0x210 | `0xfffffe0007f448d0` | `0xfffffe000c5361cc` | `0xfffffe000c5312b8`, `IOMemoryDescriptor::writeBytes(unsigned long long, void const *, unsigned long long)` |

Each entry target is `BTI C; B <named body>`. This resolves the method identity beyond the earlier SDK-only correlation. The vtable entry still has no exact nlist name; its named direct branch destination supplies the primary binding. The installed SDK probe independently emits offsets 520/528 (`0x208`/`0x210`) and signature diversities `0xfc00`/`0x507b`.

For both read and write helpers, original incoming `(X0 offset, X1 buffer, X2 count)` becomes `(X0 descriptor, X1 offset, X2 buffer, X3 count)`. Offset, pointer and count retain all 64 bits. The helpers forward the resulting IOByteCount without a local count clamp or normalization. Actual transferred bytes and lower implementation validation remain unknown; fresh result models do not copy data.

## Wrapper status and global-state effects

| Operation | Source-established local result/effect |
| --- | --- |
| Create | Stores the factory result into its global, including null; returns 0 for nonnull or raw `0xffff5bd4` for null |
| Prepare | Returns 0 when callee W0 is zero; otherwise raw `0xffff5bd4` |
| Read/write | Forwards full64 IOByteCount result; no own global write |
| Complete | Tail-forwards to the IOReturn method; no own global write |
| Release | Tail-forwards to void `OSObject::release()`; no semantically defined status result; no own global write |

`int32(0xffff5bd4) = 0xffff5bd4 - 2^32 = -42028`. Its business error name is unknown. Upper X0 bits do not participate in the prepare wrapper's W0 test; the local proof and declared high-X0/zero-W0 cases establish that width behavior.

Forty-eight create fixtures begin with a declared nonnull previous global. The create wrapper overwrites the cell without a local release request. Release and complete fixtures leave the stored pointer unchanged. These are observations of the helper bodies under models, not a demonstrated native leak, stale-pointer use or double release. Original caller ordering, ownership transfer, eventual resets and synchronization remain unknown.

## Pointer equality and sample AES handoff

`InputIOMDEqualsOutputIOMD` at `0xfffffe000a509fc8` compares the two global object pointers and returns Boolean equality. Its four fresh cases include two null pointers, equal nonnull pointers, unequal pointers and null/non-null. Object-pointer equality alone does not identify backing pages or validate an object.

`performAESonSamplesIOMD` at `0xfffffe000a509fe8` performs an ordinary tail branch at `0xfffffe000a50a010` into `performAESonIOMD` (`0xfffffe000a508534`). It maps six incoming arguments as follows:

| Incoming sample helper | Descriptor wrapper argument |
| --- | --- |
| Samples global D | X0 input descriptor = D; X1 output descriptor = D |
| X0 | X2 length64 |
| X1 | X3 opaque IV pointer |
| X2 | X4 operation, consumed as low32 downstream |
| X3 | X5 opaque key-data pointer |
| X4 | X6 offset A64 |
| X5 | X7 offset B64 |

Four fresh bridge cases stop before entering the AES wrapper and verify these full-width transfers. The earlier handoff report establishes the next wrapper's provider-register/stack mapping, including null callback/context fields. No key/IV bytes, hardware operation, accepted protected request or end-to-end data transfer is established.

## Related record adapter `0xfffffe000a5c22b8`

The inspected 540-byte prefix establishes a separate partial record contract. Minimum accessed record extent is 56 bytes because it reads a qword at +0x30.

| Offset | Width | Prefix role |
| --- | --- | --- |
| +0x08 | u64 | Object operand for unsigned comparison |
| +0x10 | u64 | Pointer whose nullness affects the next state index |
| +0x28 | u32 | Encoded selector |
| +0x30 | u64 | Comparison limit |

It computes, modulo 2^32:

```
K = (low32(record) XOR 0x7abbf985) * 0xded29631
decoded_selector = record_u32[+0x28] XOR K
```

A local proof recovers the original mixed-Boolean address identity. Two bank identities over all 256 inputs select the common table base and the bounds helper at `0xfffffe000a687ecc`. The helper receives `(object + 0x1580) mod 2^64` and limit; `0x1580 = 5504` bytes. It returns for unsigned first operand <= limit and traps otherwise. No actual object extent or native bound event is proved.

After that helper returns, the prefix selects signed32 index `decoded_selector XOR (0xa3 * (pointer_at10 == 0))`, then tail-transfers with modifier `0x9e2`. Later branches and the adapter's complete business role remain unresolved. Its relation to the global descriptor helpers beyond the previously identified source call contexts remains unknown; no complete adapter execution is attempted.

## Verification and reproduction

| Check | Result |
| --- | --- |
| Original source contexts | 26 kext functions, 7 kernel functions, 7 nominal slots |
| Fresh cases | 276, totaling 6136 original instruction visits |
| Wrapper / factory cases | 216 / 60 |
| Create requests | 96; 48 begin with declared nonnull prior globals |
| Prepare / read / write observations | 16 / 36 / 36 |
| Completion / release tail observations | 12 / 12 |
| Equality / bridge cases | 4 / 4 |
| Factory range records | 48, 768 source-defined bytes; 24 null-task and 24 nonnull-task type records |
| Factory failure release requests | 24, modeled |
| Local proofs / adapter bank inputs | 4 unsatisfiable queries / 512 exhaustive byte inputs |
| SDK probe | Compile-only exit 0 |

The command used before publication follows. Published outputs remain frozen; independent reproduction requires a separate copy of the source/evidence tree.

```
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_sample_descriptor.py
```

The verifier re-reads source, compiler bounds, symbols, pointer chains and SDK evidence, checks range-write epochs and argument movement, creates fresh model cases, and rechecks local proofs. Cost is O(B + N + C*I + E) time and retained space for source bytes B, processed symbols N, cases C, bounded visits I and events E, plus compiler and solver-dependent fixed-word work. Address/task/buffer sentinels exercise widths and are not accepted native inputs.

## Assumption register and falsification probes

| ID | Assumption / boundary | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| M1 | Pinned kext/KC and compiler bounds identify this build | All source and target bindings | Rehash originals; compare whole helper bytes, exact symbols, branches and chain membership |
| M2 | Nominal General descriptor/metaclass vptrs are declared object fixtures | Modeled wrapper/factory dispatch only | Trace actual construction/runtime receiver state separately; original allocator vptr installation is statically pinned |
| M3 | Allocation, initialization, copy, prepare, complete and release results are models | Return classes and local global-state effects | Null/error/high-width result cases; no native mapping, data or reference effect inferred |
| M4 | Authentication is abstracted for the private models | Conditional original instruction paths | Retain original tags and targets; hardware authentication remains separate evidence |
| M5 | Installed SDK corroborates labels/layouts without asserting historical private ABI equality | Type/direction labels and 16-byte layout context | Compile pinned headers; use matching original STP, type selection and exact named targets as primary evidence |
| M6 | Caller ordering, aliases, valid globals and serialization are unknown | No complete lifetime or descriptor-aliasing claim | Recover caller traces, resets and ownership transfer before assigning native lifetime effects |
| M7 | Bridge arguments are opaque scalars/pointers | Full64 descriptor handoff only | Stop before AES target; retain callback/provider evidence in the preceding report; no key/IV contents recovered |
| M8 | Adapter bounds/selector analysis covers only its prefix | Partial record and branch contract | Exhaustive bank identities and local address proof; full predecessors, object validity and later branches remain unknown |

## Bounded continuation

| Impact | Next investigation | Contract resolved |
| --- | --- | --- |
| High | Recover media-helper callers and task-pointer provenance | Address ownership and originating command/session context |
| High | Establish prepare/complete/release ordering and global resets across a full caller path | Actual descriptor lifetime coordination |
| High | Recover the related record adapter's selector branches | Its connection to media descriptor creation/use and completion |
| Medium | Trace sample-size buffer contents and sample length/offset consumers | Data format and descriptor extent relationships |
| Medium | Recover equality-helper callers and their branch effects | Same-object handling and per-role preparation/retirement |

## Scoped quality gates

QG1 passes for factual technical analysis. QG2 passes with M1-M8, dependent results and falsification probes. QG3 passes for global descriptor/helper/factory ABI, sample bridge and partial related adapter; native mapping, complete lifetime and the broad goal remain incomplete. QG4 passes for explicit widths/bytes, option arithmetic, source epochs and bounded complexity. QG5 passes with nominal/native state, task pointer/port identity, API option namespaces, release-register/void semantics and partial/full lifecycle separated. QG6 passes through original bytes/symbols/thunks/slots, 276 fresh cases, four proofs and compile-only SDK evidence. QG7 passes with impact-labeled continuation. [Machine-readable gates](triage_evidence/sample_descriptor_quality_gates.json) cover delivery.
