# RPC502 support runtime: synchronization, VMM inquiry and CoreKE bridge

After the recovered CSR/BootPolicy marker join, the daemon enters another protected support subsystem. It lazily constructs two read/write-lock objects, queries `kern.hv_vmm_present`, and conditionally loads CoreKE. The two dynamically requested obfuscated names exactly match the installed framework's exports. The first reached CoreKE call has two u32 arguments and a third 64-bit argument carrying a private record address.

The VMM branch controls this local loader path. It is not a complete FairPlay rejection predicate: the VMM-positive synthetic fixture continues to a sidecar-file open boundary. The subsequent [sidecar analysis](rpc502_sidecar_report.md) traces its nontext prefix to skipped fixture-stack bytes and recovers policy-state/path dataflow plus fstat/errno edges. Separate split-halving and valid native pathname prerequisites remain unknown. No native daemon/library call, host sysctl, loader operation or target file open was executed.

## Provenance and assumption register

Analysis date: 2026-11-01. Daemon arm64e SHA-256 remains `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. [Contracts](triage_evidence/rpc502_runtime_contracts.json) retain 13 bounded daemon ranges, 14 exhaustive selector-bank checks, 12 original import bindings, four SMT queries, 16 private fixtures and the original CoreKE export-wrapper bytes. These ranges are not all independent human-written functions.

The installed standalone framework is `/System/Library/PrivateFrameworks/CoreKE.framework/Versions/A/CoreKE`; the requested framework path resolves to that file. [Source identity](triage_evidence/coreke_source_identity.json) records the universal file and all three slices. The selected CPU subtype `0x80000002` slice is an exact 24,933,296-byte extraction, SHA-256 `599489ea7723871105bf043a18e90ffdc936387d09c80eb7def4f1d9b048bd2a`, UUID `251d4cfe-e97e-38e1-994d-7196fc69e8a2`. The other ARM slice has subtype `0x8000000c`; both original ARM export tables are retained. Actual running-process slice selection and ASLR/PAC state are unverified.

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| R1: supplied daemon and installed CoreKE builds are the intended participants | Cross-image identity and ABI interpretation | Recheck original hashes, universal slice offsets, UUIDs, export tries and runtime selection. File identity does not attest a loaded module. |
| R2: the recovered encoded-frame/tag protocol and inherited registers remain intact | Support routing, gate reductions and local constants | Trace predecessors/aliases and packet construction; validate decoded control word 0x8601b00b and table bases. The second mask proof requires an eight-byte-aligned frame pointer. |
| R3: finite synthetic API seeds/models describe only their declared fixtures | Observed routes, argument values and stops | Vary BootPolicy/CSR/VMM/status inputs; remove each model. The fixtures bypass PAC, model stack probing, use a zero-filled stack and permissive private image mappings. |
| R4: standard API declarations apply to runtime libraries | Lock sizes, loader flags and call interpretation | Inspect matching libraries and effective ABI. Current SDK hashes and compile-only assertions are separate from exact runtime-source provenance. |
| R5: serial abstract once/lock behavior is sufficient for each selected fixture | Initialization/callback and lock sequence observations | Exercise contention, recursion, cancellation and failures. Native opaque synchronization representations are not synthesized; reads of modeled opaque state stop execution. |
| R6: the simple synthetic filename is not evidence of a valid application bundle/path | Sidecar boundary only | Use source-proven path construction and valid native inputs; explain the five 0x98 bytes before interpreting the resulting path. Native malformed-input reachability remains unknown. |

The [private probe](triage_evidence/daemon_rpc502_context_probe.py) extends the earlier bounded fixture through explicit BootPolicy/once/allocation/lock/sysctl/loader models. CoreKE code is never mapped for execution by these fixtures; returned export values are private stopping trampolines. Original CoreKE bytes are inspected statically.

## Recovered cross-layer sequence

```text
RPC502 CSR/BootPolicy marker join
                 |
       protected support subsystem
                 |
       two pthread_once controls
                 |
       two 200-byte rwlock objects
                 |
       write-lock / loader inquiry
                 |
       sysctl kern.hv_vmm_present
          +------+----------------------------+
          |                                   |
    success, value 1                    other local result
          |                                   |
    diagnostic / skip                   dlopen CoreKE
          |                                   |
    continue caller                     dlsym two exports
          |                                   |
    sidecar open boundary               call first export
    (path unresolved)                   (CoreKE execution unmodeled)
```

The outer subsystem uses dispatch base `0x1010ab1a0`, pool `0x1010ab960`, different selector banks and different encoded comparison frames from the earlier RPC502 core. Original fixups and exhaustive bank identities support the recovered references; similar obfuscation does not establish identical object types or algorithms.

## Lazy synchronization objects and lifecycle boundary

| Object / event | Original identity or call site | Established role |
| --- | --- | --- |
| First once control | `0x1010c5350` | Initial bytes match LP64 `PTHREAD_ONCE_INIT`; initializer `0x100ddb5d4` |
| Second once control | `0x1010c5340` | Same initial signature; initializer `0x100de3608` |
| First once emission | Tail branch `0x100de53a8` | Calls exact `_pthread_once`; inherited return address leads back to `0x100de82ac` |
| Other once emissions | `0x100ddfff4`, `0x100de00f8` | Same second control/initializer pair on the inspected routes |
| Typed allocation | `0x100de68e8` | `_malloc_type_malloc(200, 0x01000040bef03554)` |
| Lock initialization | `0x100de69f8` | `_pthread_rwlock_init(allocation, NULL)` |
| Pointer publication | `0x100de6a84` | Stores selected allocations in cells `0x1010c5730` and `0x1010c5720` in the successful fixtures |
| Write-lock call / unlock call | `0x100de846c` / `0x100de861c` | Exact pthread read/write-lock APIs via original authenticated binds |

The native zeroing loop starts at `0x100de6960`. Under R2, its decoded step is exactly 1; it writes byte indices 0..199, then selects the exit at index 200. The complete allocation is therefore written before the observed initialization call. The current SDK independently gives `sizeof(pthread_rwlock_t)=200` and `sizeof(pthread_once_t)=16`; these are ABI consistency checks, not evidence of a native API call.

The finite successful loader fixture completes both once initializers, initializes both locks, acquires the first lock across the sysctl/loader sequence and releases it before the CoreKE call boundary. The second once control is then reused without repeating its initializer in the serial model. Complete native synchronization, startup/shutdown, destruction, contention and cancellation behavior remain unknown.

With modeled lock-init results 11 or 12, both finite fixtures reach the sysctl boundary without a modeled write-lock acquisition. This exposes a resource-failure/lifecycle branch for further analysis; it does not prove native reachability, a race, a leak or failed synchronization under real concurrency.

## Exact VMM-name decoding and loader predicate

At `0x100de15ec`..`0x100de16e4`, native code transforms 20 bytes from original source `0x101032123`:

```text
decoded_byte = (27 * encoded_byte - 17) modulo 256
result       = "kern.hv_vmm_present\0"
```

The source pointer cell `0x1010c5360` has original fixup provenance. The inverse `(decoded_byte+17)*19 modulo 256` is checked for all 256 byte inputs. This is a compact affine string decoder, not an identified cryptographic primitive.

The call at `0x100de1794` is exact `_sysctlbyname`: X0 points to that decoded name; X1 points to an initially zero u32; X2 points to an extent initialized to 4 bytes; X3/X4 are zero. No write request is supplied. The actual sysctl value was not queried.

Under R2, the native mixed arithmetic and encoded comparisons reduce to:

```text
sysctl return == 0 AND returned u32 == 1 -> diagnostic path
all other local combinations            -> CoreKE load path
```

The full 32-bit status/value domain is checked with SMT after reducing the original encoded frames; pointer-mask identities are checked separately over 64-bit pointers, with the stated alignment condition. The diagnostic at `0x100de1ab0` calls `_puts` with a literal stating that ASMF in a virtual machine is unsupported on macOS/iOS. The literal's acronym is not expanded here. Neither branch is assigned a complete FairPlay acceptance meaning.

## Encoded comparison helper semantics

Helper `0x100ddc63c` uses a 56-byte frame prefix and writes a u32 continuation index at +0x34. For frame pointer p:

```text
E   = (p xor 0xae333fd8c3a9d321) * 0x44a8b7e9 modulo 2^64
lhs = u64(frame+0x10) - E
rhs = u64(frame+0x20) - E
leaf_address = u64(frame+0x28) + E
```

All arithmetic wraps at the specified width. With e=low32(E), the two recovered leaves are:

| Leaf | Predicate | Encoded result stored at frame+0x34 |
| --- | --- | --- |
| `0x100ddc6e8` | `(u32(frame+0x18) xor e)&1` selects unsigned lhs>rhs; otherwise lhs==rhs | `(predicate ? u32(frame+8)+e : u32(frame)+e) xor (u32(frame+4) xor e)` |
| `0x100ddc6c4` | `(u32(frame)+e)&1` selects unsigned lhs>=rhs; otherwise lhs!=rhs | `(predicate ? u32(frame+4) xor e : u32(frame+0x18) xor e) xor (u32(frame+8)+e)` |

The first VMM frame partitions status zero/nonzero into indices 0x0d/0x1f. The second selects 0x1b for the diagnostic or 0x1d for loading. Original table entries, native constructor expressions, frame snapshots and four SMT files are retained. [Finite stack-write provenance](triage_evidence/rpc502_vmm_stack_writers.json) also identifies the frame-field stores; zero-filled model memory is not substituted for those native writes.

## Dynamic CoreKE interface and obfuscated exports

`dlopen` at `0x100de1b58` requests `/System/Library/PrivateFrameworks/CoreKE.framework/CoreKE` with flags 5, consistent with current-SDK `RTLD_LAZY|RTLD_LOCAL`. The [current cache inventory](triage_evidence/coreke_cache_inventory.json) has no CoreKE image-path entry; the standalone framework file exists. No runtime load was attempted.

| Symbol | Daemon dlsym call / publication | Original selected CoreKE slice | Observed wrapper inputs |
| --- | --- | --- | --- |
| `IWvA5fm4IwMS88oQXDANCS` | `0x100de1c2c` / cell `0x1010c5738` | Export `_IWvA5fm4IwMS88oQXDANCS` at image-relative `0x11b4` | W0, W1 and X2 are captured into a 24-byte internal record |
| `JY0DfiUyFiVcNw89R4t` | `0x100de1d30` / cell `0x1010c5718` | Export `_JY0DfiUyFiVcNw89R4t` at image-relative `0x1418` | X0 is captured into a 16-byte internal record |

The first wrapper stores an internal operation value at +0, X2 at +8, W0 at +0x10 and W1 at +0x14. The second stores its internal operation value at +0 and X0 at +8. Both route into protected CoreKE code and return a low-32-bit result from their local frame. These observed widths/records do not establish complete C prototypes, operation names, pointed-record schemas or error namespaces.

At daemon call `0x100de9c6c`, native code explicitly sets W0=10, derives W1, forwards X20 in X2 and uses `BLRAAZ`. The finite successful loader fixture reaches `IWvA5fm4IwMS88oQXDANCS(10, 0x5b737be3, private_record_address)` and stops before any CoreKE instruction. The same boundary/argument prefix is observed for modeled BootPolicy modes 0/1/2/3, BootPolicy failure and CSR bit0 set. These finite agreements do not prove full policy independence or successful context construction.

## Sidecar-file boundary and unresolved path bytes

With modeled VMM value 1 and the diagnostic output discarded privately, the fixture reaches exact `_open` at `0x100d94494`, flags 0, consistent with `O_RDONLY`. It stops before opening a host file. The third argument register is not interpreted as a meaningful mode argument for this flags value.

The captured path bytes are:

```text
\x98\x98\x98\x98\x98/SC_Info/etic/fixture.bin.sinf
```

The input seed was `/synthetic/fixture.bin`. The open therefore concerns a constructed sidecar path, not an established direct open of the original filename. The [subsequent sidecar report](rpc502_sidecar_report.md) explains the five leading0x98 bytes through a policy-derived scan start and unwritten prefix bytes in the zero-filled fixture stack. It separately observes split-halving for an application-shaped input and reaches fstat/errno after explicit modeled open results. The model's stack/custom ABI assumptions and valid native framing remain material. No valid native sidecar path, file access, memory defect or exploitability conclusion follows from these artifacts.

## Finite fixtures, reproduction and quality gates

The [runner](triage_evidence/run_rpc502_context_profiles.py) retains 16 independent profiles, with at most three concurrent processes. Staged profiles stop at PAC/once/allocation/lock/sysctl boundaries. Subsequent profiles vary VMM status/value, BootPolicy mode/status, CSR configuration and lock-init results. Each process has a 200,000-instruction budget; the largest retained fixture uses fewer than 30,000 instructions.

The models are explicit: private opaque BootPolicy values and seeded status/mode; three literal callback-signing bypass sites; two serial once pairs; bounded private allocation with unknown-byte reads blocked; abstract serial rwlock states with opaque-state reads blocked; optional exact-name sysctl results; and optional loader/export trampolines. They do not execute real BootPolicy/CoreKE or invoke the target's synchronization, sysctl, loader, logging, IPC or file operations on the host. Analyst process/file IO remains separate. Original daemon instructions execute only in Unicorn private memory.

```sh
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/run_rpc502_context_profiles.py
/Users/___/Downloads/zut/.venv/bin/python triage_evidence/recover_rpc502_runtime.py
clang -target arm64e-apple-macos13.0 \
  -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
  -std=c11 -fsyntax-only triage_evidence/rpc502_runtime_layouts.c
```

The explicit sysroot is required by this compiler invocation; the initial command without it did not find pthread.h. [Layout assertions](triage_evidence/rpc502_runtime_layouts.c) verify SDK synchronization sizes/flags and the recovered CoreKE record prefixes without executing APIs. Extraction is O(B+F+D+P) time/space for original bytes B, fixups F, retained instructions D and profile evidence P; hashing is streamed where needed, and SMT cost is solver-dependent. The byte decoder is O(N) time/O(1) auxiliary space; the 200-byte zero loop is linear in its fixed allocation extent.

| Impact | Additional finding / remaining obligation |
| --- | --- |
| High | Original dynamic symbol names join fairplayd to two exact obfuscated CoreKE exports and expose their argument-record boundaries. Protected CoreKE semantics and results remain open. |
| High | The VMM predicate selects a local loader branch; a different inspected branch continues to sidecar processing. A global rejection claim would exceed the evidence. |
| High | The subsequent sidecar report explains the synthetic prefix through skipped bytes; complete global state lifetime, split control and native path prerequisites remain required. |
| Medium | Once controls, typed rwlock allocations, publication cells and lock-init failure fixtures expose synchronization/lifecycle dependencies. Native concurrency and ownership are not validated. |
| Medium | The support subsystem's 56-byte comparator and new tables differ from earlier 48-byte comparison frames. Similar arithmetic encoding does not justify merging their ABIs. |

QG1 factual technical scope. QG2 R1-R6 and falsification probes explicit. QG3 this increment covers support synchronization, VMM inquiry, encoded comparisons, CoreKE loading/exports and the next file boundary; the full original objective remains active. QG4 widths, alignment, extents, compiled layouts and complexity are explicit. QG5 local/global policy, failed query/positive value, opaque API state, alternate slices and malformed synthetic sidecar bytes are separated. QG6 original bytes/fixups/export tries, source hashes, exhaustive banks, SMT and finite profile readbacks retain distinct provenance. QG7 bounded impact-labeled expansions and remaining interfaces are listed above.

[Machine-readable delivery checks](triage_evidence/rpc502_runtime_quality_gates.json) retain the current proof, profile, compile and integrity results. Earlier exploratory context snapshots outside the 16-profile contract list are preserved as historical artifacts and are not additional current validation cases.
