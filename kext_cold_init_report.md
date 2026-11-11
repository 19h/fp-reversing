# FairPlayIOKit cold initialization and IOAESAccelerator dependency

The cold path from `_oh70aLVr` reaches IOAESAccelerator discovery after allocating and partially initializing a `site.FPAESParameters` object. This establishes a deeper kernel service dependency of the close wrapper. Under an explicitly modeled absent provider, original instructions request release of the temporary object and return `0xffff5bea`; neither the close initialization flag nor its registry pointer becomes nonzero. Successful initialization and native service behavior are unknown.

Evidence: [original byte/descriptor/kernel contracts](triage_evidence/kext_cold_init_contracts.json), [retained private executions](triage_evidence/kext_cold_init_profiles.json), [distinct fresh replays](triage_evidence/kext_cold_init_replays.json), and [independent checks](triage_evidence/kext_cold_init_checks.json). This extends the [close-wrapper record report](kext_close_report.md). All addresses below are unslid source virtual addresses. All offsets and extents are bytes unless specified otherwise.

```
_oh70aLVr, close flag = 0
  -> _IOMallocTypeImpl(site.FPAESParameters), declared extent 104
  -> original initialization: 31 distinct bytes
  -> a688ebc -> a5a1cc4 -> a687ee0 -> a508030
  -> serviceMatching("IOAESAccelerator", NULL)
  -> waitForService(dictionary, {0 s, 1 ns})
       +-- modeled NULL -> adapter -40 -> typed release -> close 0xffff5bea
       `-- nonnull branch, static only -> retain -> buffer capacity 81920
```

The shortened addresses in this diagram share prefix `0xfffffe000`. There is no new Mach-message or user-space port emission established in this increment. The matching dictionary and service pointers are kernel object interfaces; they do not establish a daemon Mach port identity.

## Source identity and evidence boundary

| Source | SHA-256 | Use |
| --- | --- | --- |
| Normalized `com.apple.driver.FairPlayIOKit` | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Original instructions, descriptors, literal and imported slots |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Allocator/waiter bodies, symbols and selected chained pointers |
| Installed SDK `mach/clock_types.h` | Pinned in contracts | Compile-only timeout layout check; matching kernel instructions independently establish consumption |

The private execution engine checks consumed original instruction bytes, traces source writes and reads, and stops at unmodeled external calls. It abstracts PAC and selected API results. No native allocator, IOKit operation, reference operation, loader, target daemon, Mach operation, credential operation or IDB mutation is executed. Source file reads and SDK syntax compilation are verification operations. All dynamic conclusions depend on A1-A5 below.

## Typed allocation and partial object layout

| Interface | Original address | Established contract |
| --- | --- | --- |
| Allocation wrapper | `0xfffffe000c4ba154` | Exact symbol `_IOMallocTypeImpl`; reads descriptor flags at +40 and selects raw W1 `0x8004` for this descriptor |
| Allocation descriptor | `0xfffffe000847b460` | +16 points to `site.FPAESParameters`; +40 u32 `0x64`; +44 u32 `0x68` |
| Allocator backend | `0xfffffe000bcfeb8c` | Zero descriptor-zone-pointer branch passes `size_word & 0xffffff`, here 104, to its lower allocator |
| Free descriptor | `0xfffffe000847b3a0` | Same site name, flags and size words; distinct original descriptor |
| Free wrapper | `0xfffffe000c4ba368` | Exact symbol `_IOFreeTypeImpl`; failure path supplies free descriptor in X0 and original object pointer in X1 |

The private model supplies 104 bytes at `0x6100000000`. Descriptor size and the zero-zone-pointer fallback are verified; actual native zone state, allocation extent and allocation success remain unknown. Raw flags have no assigned semantic names. The complete original C structure is unknown.

| Object offset | Width | Source value | Original store or source |
| --- | --- | --- | --- |
| +0 | u8 | 1 | `0xfffffe000a5c023c` |
| +1 | u8 | 1 | `0xfffffe000a5c0240` |
| +18 through +33 | 16 | zero bytes | Original fill helper `0xfffffe000a687d64`, called at `0xfffffe000a5c02b8` |
| +36 | u32 | 0 | Paired store at `0xfffffe000a5c024c` |
| +40 | u32 | 4096 | Paired store at `0xfffffe000a5c024c` |
| +44 | u32 | 0 | `0xfffffe000a5c0250` |
| +56 | u8 | 0 | `0xfffffe000a5c0244` |

These are 31 distinct initialized bytes over 15 store events per case. Other bytes have no inferred field meaning. Two allocation models are compared: poisoned bytes marked unknown until source-written, and a declared known-zero allocation. All four corresponding path pairs have identical source visits and call register/target projections. This bounds dependence on unwritten bytes in these paths; it does not establish the native allocator's initialization policy.

The only recorded object reads are **+40/u32 = 4096** at `0xfffffe000a6880d4` and **+36/u32 = 0** at `0xfffffe000a688100`. Both read original source-written bytes. They are not reads of the two one-byte header fields. Unknown, out-of-extent or logically retired heap access stops execution.

## IOAESAccelerator discovery and timeout ABI

| Kext call site | Local stub / imported slot | Matching kernel target | Arguments |
| --- | --- | --- | --- |
| `0xfffffe000a508070` | `0xfffffe000a69f254` / `0xfffffe000847c458` | `0xfffffe000c4ece88`, `IOService::serviceMatching(char const *, OSDictionary *)` | X0 points to original `IOAESAccelerator` literal at `0xfffffe000790ba3c`; X1 = 0 |
| `0xfffffe000a508078` | `0xfffffe000a69f244` / `0xfffffe000847c450` | `0xfffffe000c4eb5d8`, `IOService::waitForService(OSDictionary *, mach_timespec *)` | X0 = matching result; X1 points to source-built 8-byte timeout |

The matching result is an opaque declared dictionary pointer `0x6200000000` in continuation models; no dictionary contents are invented. Original code builds timeout bytes `00 00 00 00 01 00 00 00`. A compile-only arm64e SDK probe verifies `sizeof(mach_timespec_t) = 8`, field offsets 0 and 4, widths 32 bits, and signed nanoseconds. The matching kernel waiter loads the two words, sign-extends nanoseconds and computes:

```
duration_ns = uint32(tv_sec) * 1,000,000,000 + int32(tv_nsec)
            = 0 * 1,000,000,000 + 1
            = 1 ns = 10^-9 s
```

This exact integer calculation describes the requested duration for this source-built argument. It does not measure native wait latency, scheduling, rounding, timeout enforcement or provider readiness. Six original timeout records and six fresh counterparts are checked against preceding source-write epochs, covering 48 source-defined timeout bytes per retained/fresh set.

The waiter body calls virtual +0x28 on the dictionary after its inner wait and, for a nonnull result, virtual +0x28 on that service. The kext's nonnull branch subsequently calls virtual +0x20 on its service. Original `OSObject` and `IOService` nominal vtables both bind +0x20 to `OSObject::retain()` and +0x28 to `OSObject::release()`. Four format-8 authenticated pointer entries are verified for original chain membership and exact symbols. These are nominal bindings: actual receiver vtables, PAC acceptance, reference counts and destruction behavior remain unknown. The API-result models do not execute those reference operations.

## Provider absence and distinct initialization states

| Boundary or result | Established behavior under the model |
| --- | --- |
| `waitForService` result | Declared NULL; no native provider lookup |
| Adapter `0xfffffe000a508030` | Original return X0 `0xffffffd8`, signed32 -40 |
| Free call site `0xfffffe000a5c0804` | Target `_IOFreeTypeImpl`; X0 `0xfffffe000847b3a0`, X1 original allocation |
| Before-free cases | Stop at the external boundary; no release effect inferred |
| Logical-release cases | Model retires the private allocation; original close wrapper returns X0 `0xffff5bea`, signed32 -42006 |
| Close initialization flag `0xfffffe000ccca078` | Final byte remains 0 |
| Shared close registry pointer `0xfffffe000cccca58` | Final qword remains 0 |

Error business names are unknown. Logical retirement is a fixture bookkeeping action, not a native free. The tested cold failure does not establish the prior close report's declared flag1/null-registry configuration as a naturally reached state. Conversely, failure in this one modeled environment does not prove initialization always fails.

## Nonnull provider continuation: static interface only

| Source interface | Established source contract | Unknown |
| --- | --- | --- |
| Provider publication | Service stored at `0xfffffe000ccceb08`, followed by virtual +0x20 | Actual provider type, lifetime and PAC |
| Buffer allocator binding | Stub `0xfffffe000a69f1f4`, slot `0xfffffe000847c428`, target `0xfffffe000c526070`, exact `IOBufferMemoryDescriptor::inTaskWithOptions(task *, unsigned int, unsigned long, unsigned long)` | Native allocation result |
| X0 | Value through `_kernel_task` cell `0xfffffe0007f8b0a0`, imported via slot `0xfffffe000847c608` | Runtime task pointer |
| W1 | Raw options `0x13` | Semantic option names |
| X2 | Capacity `0x14000 = 81920` bytes | Physical backing or usable device extent |
| X3 | `sign_extend64(1U << (runtime_PAGE_SHIFT_CONST & 31))` | Runtime shift and resulting alignment |
| Shift binding | Slot `0xfffffe000847c5b0` points to `_PAGE_SHIFT_CONST` at `0xfffffe0007e6d9c0`; original file word is zero | Runtime initialized word; no 16 KiB alignment is asserted |
| Descriptor publication | Result stored at `0xfffffe000ccceb10` | Descriptor validity |
| Virtual +0x218 | W1 = 0; subsequent W0 == 0 check | Exact virtual method binding |
| Virtual +0x308 | Output stored at `0xfffffe000ccc7848` | Exact virtual method and output representation |
| Local status helper | `0xfffffe000a508c78` logs nonzero u32 status and returns Boolean `status == 0` | Business meaning of other statuses |
| AES initialization flag | Bit 0 at `0xfffffe000ccceb00`, tested at `0xfffffe000a50804c`; success store at `0xfffffe000a5081a8` | Complete successful initialization |

The AES flag and close flag are distinct addresses. This branch is inspected statically and is not privately executed with a fabricated provider object. No successful cryptographic operation, authenticated object, accepted request or device state is established.

## Reproduction and validation

For reproduction, set `PYTHON` to the analysis interpreter and use a separate evidence tree; published evidence files are frozen:

```
PYTHONPATH=triage_evidence "${PYTHON}" -P triage_evidence/validate_kext_cold_init.py
```

| Validation | Result |
| --- | --- |
| Distinct fresh cases | 8: two allocation models times four stopping/continuation stages |
| Fresh original instruction visits | 18404 across 1278 distinct source instructions |
| Original source contexts | 4 kext ranges and 4 kernel functions |
| ABI metadata | 2 typed descriptors, 5 original import/data bindings, 4 nominal reference slots |
| Heap audit | 120 source store events; 248 distinct initialized bytes summed over cases; 16 heap read events |
| Stops and returns | 2 matching boundaries, 2 wait boundaries, 2 release boundaries, 2 complete failure returns |
| Adapter failures | 4 original returns of signed32 -40 |
| SDK layout compile | Exit 0, syntax-only |
| Native execution / successful provider / complete initialization | None / unknown / unproved |

The algorithm reads pinned source, runs each declared original prefix in private memory, checks its byte epochs and API boundaries, and compares a newly created replay with its retained case. For source bytes B, visits V, events E and SDK/source context S, verification costs O(B + V + E + S) time and retained space, plus bounded selected pointer-chain traversal and compiler work. There are no new solver proofs or exhaustive native path claims.

## Assumption register and falsification probes

| ID | Assumption or explicit boundary | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| A1 | Pinned normalized kext and matching KC represent this analyzed build | All address, symbol and ABI mappings | Rehash original sources; reject changed bytes, symbols or pointer-chain membership |
| A2 | Cold fixture starts with close flag 0 and original file-defined global bytes | Observed cold path and zero final states | Recover native predecessor writes; compare a separately established initialized state |
| A3 | Allocation returns a private 104-byte object; native zone and success unknown | Partial layout and downstream private paths | Original fallback-size check; poison/zero paired paths; stop on unknown or out-of-extent access |
| A4 | `serviceMatching` returns the declared opaque dictionary when continuation is enabled | Wait ABI and provider-absent continuation | Stop before matching; retain matching-failure branch as unknown; inspect actual matching implementation separately |
| A5 | Wait returns NULL, with optional logical free; native API internals absent | Adapter/close failure and private retirement | Stop before wait/free in independent stages; recover nonnull path with independently bound objects before assigning effects |
| A6 | PAC and selected API semantics are abstracted | Conditional original instruction traces only | Native authentication and object-dispatch observation would be separate evidence |
| A7 | SDK layout applies only as compiled; matching kernel body supplies independent consumption evidence | `{0,1}` argument and 1 ns requested duration | Recompile pinned header and compare original waiter loads/conversion; do not infer actual elapsed time |
| A8 | Positive-path vtables, runtime globals and method identities are unknown | Static buffer/reference descriptions only | Bind actual provider/descriptor vtables and runtime shift; verify initialization predecessor and ownership before execution |

## Bounded continuation

| Impact | Next investigation | Contract resolved |
| --- | --- | --- |
| High | Bind descriptor virtual +0x218/+0x308 from matching original vtables | Preparation, buffer publication and deeper provider interface |
| High | Trace nonnull provider initialization with source-established object construction | Relationship between AES flag, close flag and shared registry state |
| Medium | Recover service-matching failure and allocation-failure source branches | Additional cold environmental outcomes and cleanup |
| Medium | Recover writers of `_PAGE_SHIFT_CONST` and relevant kernel initialization context | Runtime buffer alignment without assuming the platform page size |
| Medium | Trace buffer and provider finalizers with exact reference ABI | Ownership across initialization, close and unload |
| Low | Compare other callers of `site.FPAESParameters` descriptors | Reuse of the partial field layout; no shared semantics inferred from the name alone |

## Scoped quality gates

QG1 passes for factual technical analysis. QG2 passes with A1-A8 and dependent results above. QG3 passes for this cold allocation/discovery/failure increment; the broad interface goal remains active and incomplete. QG4 passes for explicit byte widths, exact timeout units, source epochs and complexity. QG5 passes with warm/cold flags, logical/native release, requested/elapsed timeout and static/executed positive paths separated. QG6 passes through original bytes, symbols, chained slots, compile-only layout and eight distinct fresh replays. QG7 passes with impact-labeled bounded continuation. [Machine-readable gates](triage_evidence/kext_cold_init_quality_gates.json), [source readback](triage_evidence/kext_cold_init_source_identity.json) and [prior-artifact preservation](triage_evidence/kext_cold_init_preservation.json) cover this delivery.


The [shared operation preflight](lskd_operation_preflight_report.md) now binds original W1 values 1,2,4,5 to a no-op hook followed by an `initKernelAESHW()` record wrapper. Nonzero initializer low32 results enter the prior conditional return path unchanged; zero continues operation dispatch. The continuing source recovers original X2/X4-low32, saves the address of cached-byte cell CCC7848, and establishes count thresholds 32/16 for W1=1/5 with units still unknown. Native epochs, full operation meanings and daemon transport remain open.
