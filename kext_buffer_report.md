# Kernel AES buffer descriptor: factory, accessor and cleanup contracts

The two previously unresolved buffer calls in `initKernelAESHW` now have original kernel vtable bindings: `+0x218` is `IOGeneralMemoryDescriptor::prepare(unsigned int)` and `+0x308` is `IOBufferMemoryDescriptor::getBytesNoCopy()`. The companion `cleanupKernelAESHW` calls `complete(0)` at `+0x220` before releasing the descriptor, conditional on both descriptor and cached byte pointer being nonnull. These findings establish the descriptor lifecycle beneath FairPlayIOKit; native provider construction, actual preparation and hardware transfer remain unknown.

Evidence comprises [original contracts](triage_evidence/kext_buffer_contracts.json), [getter profiles](triage_evidence/kext_buffer_profiles.json), [cleanup profiles](triage_evidence/kext_buffer_cleanup_profiles.json), [fresh independent checks](triage_evidence/kext_buffer_checks.json), [getter replays](triage_evidence/kext_buffer_replays.json), [cleanup replays](triage_evidence/kext_buffer_cleanup_replays.json), and [two local proofs](triage_evidence/kext_buffer_proofs.json). This extends the [cold initialization report](kext_cold_init_report.md). Source addresses are unslid virtual addresses; private fixture addresses are explicitly identified as modeled. All structure offsets and extents below are bytes.

```
initKernelAESHW
  -> nominal provider retain
  -> IOBufferMemoryDescriptor::inTaskWithOptions
       -> metaclass alloc -> initWithPhysicalMask(..., physicalMask = 0)
       -> failed initialization: release -> NULL
  -> prepare(0)
  -> getBytesNoCopy() -> cached buffer pointer
  -> readiness byte = 1

cleanupKernelAESHW
  -> descriptor present?
       -> cached pointer present? -> complete(0) -> cached pointer = 0
       -> release descriptor -> descriptor = 0
  -> provider present? -> release provider -> provider = 0
  -> readiness byte = 0; return 0
```

The diagram describes source control flow and nominal call bindings. Private fixtures abstract API results and authentication; they do not establish native reachability of arbitrary field/global combinations. No new daemon port identity or Mach-message emission is identified in the examined kext bodies.

## Source provenance and class binding

| Source | Identity / scope |
| --- | --- |
| Normalized kext | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Matching original kernel collection | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Associated decompilation | Original `com.apple.driver.FairPlayIOKit.c`, SHA-256 `dfb28b99b293db95a78a5d2dd20f6fcf1a95f1a53245b99a090370e7a3327f08`; initializer excerpt at lines 13069-13134 pinned in contracts |
| Installed SDK | Three primary Kernel.framework headers pinned; arm64e C++ syntax-only constant/width probe passes |

Original bytes, exact symbols and chained-pointer membership establish nominal dispatch. No live object, PAC acceptance, whole IDB integrity or native allocation/preparation/reference effect is attested. No target binary or kernel API is executed natively. Only the original getter leaf and original cleanup control flow execute in guarded private memory; cleanup call effects and authentication are modeled. Dependencies and final [source readback](triage_evidence/kext_buffer_source_identity.json) are pinned.

| Original object/vtable interface | Source address | Established relation |
| --- | --- | --- |
| Factory | `0xfffffe000c526070` | Exact `IOBufferMemoryDescriptor::inTaskWithOptions(task *, unsigned int, unsigned long, unsigned long)` |
| `gMetaClass` | `0xfffffe000cb5bdb0` | Factory loads this exact class instance and dispatches virtual +0xa8 |
| Metaclass vtable symbol | `0xfffffe0007f410b0` | Nominal vptr is symbol +16; slot +0xa8 is `IOBufferMemoryDescriptor::MetaClass::alloc()` at `0xfffffe000c525694` |
| Metaclass constructor | `0xfffffe000c525c48` | Installs the metaclass vptr; source advertises instance size `0xe8 = 232` |
| Descriptor vtable symbol | `0xfffffe0007f85d70` | Nominal descriptor vptr is `0xfffffe0007f85d80` |
| Class vptr installers | Allocator `0xfffffe000c525694`; constructors `0xfffffe000c525cd0`, `0xfffffe000c525d04`, `0xfffffe000c525f70`, `0xfffffe000c525fc0` | Each explicitly signs and stores descriptor vtable symbol +16 |

This is a source construction chain for the nominal class. Runtime metaclass initialization and actual receiver vptrs remain unknown. The descriptor's 232-byte source class size is distinct from the 104-byte `site.FPAESParameters` allocation in the preceding report.

## Exact virtual slots and call sites

| Offset from descriptor vptr | Original slot | Exact target | Pointer diversity | Kext use |
| --- | --- | --- | --- | --- |
| +0x28 | `0xfffffe0007f85da8` | `OSObject::release()` at `0xfffffe000c4451d0` | `0x3a87` | Cleanup call `0xfffffe000a508654` |
| +0x218 | `0xfffffe0007f85f98` | `IOGeneralMemoryDescriptor::prepare(unsigned int)` at `0xfffffe000c5353b4` | `0xf5b3` | Initializer call `0xfffffe000a508108`, W1 = 0 |
| +0x220 | `0xfffffe0007f85fa0` | `IOGeneralMemoryDescriptor::complete(unsigned int)` at `0xfffffe000c534a2c` | `0x9285` | Cleanup call `0xfffffe000a508630`, W1 = 0 |
| +0x268 | `0xfffffe0007f85fe8` | `IOBufferMemoryDescriptor::initWithPhysicalMask(task *, unsigned int, unsigned long long, unsigned long long, unsigned long long)` at `0xfffffe000c524bdc` | `0x1c03` | Factory dispatch at `0xfffffe000c5260f8` |
| +0x308 | `0xfffffe0007f86088` | `IOBufferMemoryDescriptor::getBytesNoCopy()` at `0xfffffe000c524b60` | `0xf4f4` | Initializer call `0xfffffe000a508170` |

All five entries are authenticated format-8 chained pointers with verified original chain membership. The metaclass allocator and nominal provider release add two further entries. The latter uses `IOService` vtable symbol `0xfffffe0007f89188`, nominal +0x28 bound to `OSObject::release()`, called at `0xfffffe000a508680`.

Two base-class negative controls establish why the concrete class matters: nominal `IOMemoryDescriptor` vtable symbol `0xfffffe0007f44080` has `___cxa_pure_virtual` at +0x218 and a reserved `OSMetaClassBase` method at +0x308. A generic `IOMemoryDescriptor` label alone does not provide the recovered buffer binding.

## Factory arguments, options and failure ABI

| Caller value | Factory entry register | `initWithPhysicalMask` register |
| --- | --- | --- |
| Kernel task through original `_kernel_task` cell | X0 | X1 |
| Raw options `0x13` | W1 | X2 carries the saved value; original caller zero-extends W1 |
| Capacity `0x14000 = 81920` | X2 | X3 |
| Runtime alignment expression from preceding report | X3 | X4 |
| Physical mask 0 | No factory argument | X5 = 0 |
| Newly allocated descriptor | Factory allocator result | X0 |

The factory first tests allocation for null. For a nonnull result it invokes virtual +0x268; bit 0 of returned W0 selects success. Success returns the allocated descriptor. Failure invokes nominal release at +0x28 and returns null. No lower allocation or initialization path is privately executed here.

The compile-only installed SDK probe verifies:

```
kIODirectionNone = 0
kIODirectionInOut = 3
kIOMemoryPhysicallyContiguous = 0x10
3 | 0x10 = 0x13
kIOMemoryKernelUserShared = 0x10000
0x13 & 0x10000 = 0
sizeof(IOOptionBits) = 4; sizeof(IOByteCount) = 8
```

Thus the raw request matches the installed SDK's bidirectional and physically contiguous flags; it does not include that SDK's kernel/user shared option. These labels are corroborating SDK context, not proof of physical allocation success, a user mapping, or equality between this SDK version and every private ABI in the original kernel build. The SDK documents direction 0 as selecting the descriptor's specified direction. Original `prepare` instructions are retained, but its synchronization, wiring and lower calls are not executed.

The supplied C decompilation already shows options `0x13`, capacity `0x14000` and `1 << PAGE_SHIFT_CONST`. Its `@PTN` summaries at factory call `0xfffffe000a5080d4` instead mark arguments 1, 2 and 3 as `C(0)`. Original instruction assignments contradict those annotations. The source-defined raw values and runtime alignment expression remain authoritative; no zero option/capacity/alignment is inferred from `@PTN`.

## Original getter semantics and data flow

Let B be the descriptor pointer, F the u8 at B+0xe0, T the u32 at B+0x20, D the u64 at B+0xb8, and Q the u64 at B+0x60. The original 56-byte leaf implements:

```
if F & 0x40:
    return 0
if T & 0xf0 == 0x20:
    return D
return load_u64(Q)
```

The type comparison in the pseudocode is `(T & 0xf0) == 0x20`. Each return transfers a 64-bit pointer value; the leaf performs no copy, allocation, extent check or reference operation.

| Path | Exact data reads | Return |
| --- | --- | --- |
| F bit 6 set | B+0xe0/u8 only | Null |
| Bit 6 clear; masked T equals 0x20 | B+0xe0/u8, B+0x20/u32, B+0xb8/u64 | D |
| Other masked T | B+0xe0/u8, B+0x20/u32, B+0x60/u64, Q/u64 | First qword addressed by Q |

The private getter fixture supplies a 232-byte poisoned object, explicitly initializes only the observed fields and an 8-byte indirect table, and rejects any other data access or any source write. Returned values are opaque declared u64 values, including full-width and null sentinels; native pointer validity and constructor reachability are unproved. All 256 flag bytes crossed with all 16 relevant type nibbles yield 4096 cases. Fifteen additional cases exercise u64/null sentinels. Two solver identities cover the bit-vector selector and invariance under changes to unused flag/type bits. Those are local semantic proofs, not whole initialization proofs.

After `prepare` returns W0 = 0, original kext code stores the getter result at `0xfffffe000ccc7848`. It then passes literal status 0 to the local status helper and sets readiness byte `0xfffffe000ccceb00` to 1. There is no intervening test of the returned byte pointer. This is a local conditional control-flow result; lower factory/prepare invariants may constrain the getter result. A native null cached pointer with readiness 1 has not been established.

If `prepare` returns nonzero W0, the initializer substitutes signed32 -22 (`0xffffffea`) for its own status. Factory null yields signed32 -40 (`0xffffffd8`). The exact original prepare error is not propagated by this wrapper. The preceding report retains the absent-provider -40 and close-layer -42006 results as distinct interfaces.

## Cleanup ordering and global state

| Global | Source address | Cleanup rule |
| --- | --- | --- |
| Descriptor | `0xfffffe000ccceb10` | If nonnull, nominal descriptor release is requested and the global is zeroed |
| Cached byte pointer | `0xfffffe000ccc7848` | Zeroed only inside the descriptor-nonnull and byte-pointer-nonnull branch, after `complete(0)` |
| Provider | `0xfffffe000ccceb08` | If nonnull, nominal provider release is requested and the global is zeroed |
| AES readiness | `0xfffffe000ccceb00` | Unconditionally zeroed |
| Close readiness / registry | `0xfffffe000ccca078` / `0xfffffe000cccca58` | Separate state; no writes in this cleanup body |

Nineteen guarded cleanup fixtures cover all 16 combinations of initial readiness 0/1 and descriptor/byte-pointer/provider presence, plus three declared nonzero `complete` returns with all objects present. The model checks original call-site targets against nominal source vtables and records the requested calls without invoking native methods. It abstracts PAC, supplies call results, and records logical retirement without executing native reference effects.

Every case returns 0 and clears readiness. Completion precedes descriptor release, which precedes provider release when each is present. Seven completion requests, 22 release requests and 48 source global writes are verified in both retained and fresh runs. All three modeled nonzero completion results are ignored by the cleanup control flow. In four declared descriptor-null/cached-pointer-nonnull states, the cached pointer remains unchanged. Those states are fixture coverage, not established native orphan pointers or a demonstrated lifetime defect.

The initializer's local failure branches do not themselves invoke this cleanup function. Caller reachability, serialization, retry policy, complete/prepare pairing across all callers and eventual cleanup remain unknown. The presence of a cleanup routine alone does not prove that every partial initialization reaches it.

## Verification and reproduction

| Check | Verified result |
| --- | --- |
| Original contexts | 3 kext ranges, 12 compiler-bounded kernel functions |
| Dispatch | 5 descriptor slots, 1 metaclass slot, 1 provider slot, 2 base-class negative controls |
| Type construction | 5 original descriptor vptr installers |
| Getter replay | 4111 distinct fresh cases, 30712 source instruction visits, 14 original instructions |
| Getter data reads | 10152 events, 44207 bytes |
| Getter branches | 2053 null, 133 direct, 1925 indirect |
| Cleanup replay | 19 distinct fresh cases, 616 source instruction visits |
| Cleanup calls | 7 modeled completion requests, 22 modeled release requests |
| Local solver work | 2 unsatisfiable counterexample queries |
| Installed SDK probe | Syntax-only compilation exit 0; 3 primary headers pinned |

The verification command used for this increment is below. Published outputs are frozen; independent reproduction requires a separate copy of the evidence tree.

```
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_kext_buffer.py
```

The verifier re-reads original source, symbols, slots, compiler-bounded functions and primary headers; rechecks the local SMT queries; and creates fresh getter and cleanup replay records. Its work is O(B + C*I + E) time and retained space for source bytes B, cases C, bounded per-case instruction count I and recorded events E, plus compiler work and solver-dependent fixed-word proof work. The solver does not establish native memory validity, API availability or receiver identity.

## Assumption register and falsification probes

| ID | Assumption / evidence boundary | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| D1 | Pinned kext/KC and original compiler bounds identify this build | Address, symbol, instruction and nominal slot mappings | Rehash sources; compare exact symbols and selected original pointer-chain membership |
| D2 | Runtime class initialization has not been observed | Nominal factory/class dispatch only | Recover initializer registration and actual receiver vptrs; native PAC remains separate evidence |
| D3 | Getter fields and indirect qword are explicitly declared fixture inputs | Private getter returns and read sets | Poison unassigned bytes; reject unexpected reads/writes; exercise all decision bits and full-width sentinels |
| D4 | Local source lift preserves original branch and word widths | Two getter SMT identities | Independently pin all 14 getter instructions, compare fresh machine-code runs and recheck emitted SMT |
| D5 | Installed SDK labels are corroboration, not historical private-layout proof | Option names, direction context and documented API role | Recompile pinned headers; keep original raw bits authoritative; inspect matching target implementation before assigning allocation effects |
| D6 | Cleanup globals and object presence are declared; PAC and call results are modeled | Cleanup order, writes and ignored-return observations | All 16 presence/readiness combinations, nonzero completion results, known-field guards and fresh original control-flow replay |
| D7 | Native preparation, ownership and hardware operations are unobserved | No complete initialized-buffer or native lifetime claim | Recover actual factory/prepare predecessors, caller serialization and eventual cleanup edges |
| D8 | Runtime page shift and alignment remain unknown | Capacity request only; no page count or fixed alignment | Trace original runtime shift initialization and actual allocation arguments separately |

## Bounded continuation

| Impact | Next investigation | Interface resolved |
| --- | --- | --- |
| High | Trace callers of `cleanupKernelAESHW` and partial-init unwind | Eventual retirement and prepare/complete pairing |
| High | Recover `performHWAESOnBuffer` descriptor/provider call arguments and callbacks | Buffer descriptor handoff into IOCryptoAcceleratorFamily |
| High | Trace cached byte pointer producers/consumers with original extents | Actual buffer data flow and offset/length contract |
| Medium | Recover matching factory/prepare initialization invariants | Whether null getter outcomes are excluded for this request |
| Medium | Trace serialization and retry around initialization globals | Ordering guarantees and valid lifecycle states |
| Medium | Compare companion LSKD initialization/cleanup independently | Shared ABI versus separate state and lifetime |

## Scoped quality gates

QG1 passes for factual technical analysis. QG2 passes with D1-D8, dependencies and falsification probes. QG3 passes for the descriptor factory/accessor/cleanup increment; complete native initialization and the broad interface goal remain incomplete. QG4 passes for explicit widths, bytes, exact option arithmetic, event counts and complexity. QG5 passes with nominal/actual receiver, declared/native state, logical/native retirement, raw/SDK-labeled options and source/annotation distinctions explicit. QG6 passes through original bytes, exact symbols, chain membership, source constructors, fresh private runs, two local proofs and compile-only header checks. QG7 passes with impact-labeled continuation. [Machine-readable gates](triage_evidence/kext_buffer_quality_gates.json) and [prior-artifact preservation](triage_evidence/kext_buffer_preservation.json) cover this delivery.
