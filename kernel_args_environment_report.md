# KernelArgs, executable-header production and environment compaction

The captured dyld implementation connects its `KernelArgs` input to the executable-header and vector fields later supplied through [ProgramVars](initializer_programvars_report.md). Its selected environment-pruning routine removes entries beginning with the exact bytes `DYLD_`, compacts pointers in place, and relocates the Apple-vector span. This predicate preserves the three `XPC_` inputs used by the previously recovered [libxpc port-selection paths](registered_port_consumers_report.md). Effective native input values, policy decisions and later mutations remain unknown [KA1-KA6].

[Original capture](triage_evidence/kernel_args_environment_source.json), [checks and bounded models](triage_evidence/kernel_args_environment_checks.json), [capture script](triage_evidence/recover_kernel_args_environment.py), [validator](triage_evidence/validate_kernel_args_environment.py), [delivery seal](triage_evidence/kernel_args_environment_delivery.json), [quality gates](triage_evidence/kernel_args_environment_quality_gates.json).

```text
KernelArgs input
  +0x00: mapped-header pointer -> Header::fromDyldMapped -> Process.header
  +0x08: observed 8 B argc load -> Process.argc (4 B) / argv count (8 B)
  +0x10: argv[], NULL, environment[], NULL, apple[], NULL
                       |
                       v
ProcessConfig::Process at config+0x10
  -> Security constructor at config+0x150
       -> selected policy/embedded-command callbacks
       -> conditional DYLD_ pointer compaction
  -> RuntimeState.config at +8
       -> prepare -> ProgramVars -> libc accessor cells -> libxpc inputs

The kernel producer, native mapping/epoch and effective vector contents
are outside the established static chain.
```

## Identities, original roles and evidence boundaries

Dyld file SHA-256 is `3bbd2bc4d7f315fafec3cc51d6f0def403ce1149e3fb99e53b21ee19776d7401`. Selected arm64e and arm64e.x1 UUIDs are `3721f73b-6239-3955-9231-625bf089baa0` and `d038ad32-39e7-3d41-a8e7-106921edcaf0`. FairPlay arm64e SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`, UUID `204741e9-b89f-32b4-9321-51f3975c7cac`. Addresses below are preferred static addresses; dyld's preferred text base is zero [KA1].

| Original role | arm64e | arm64e.x1 |
|---|---|---|
| `KernelArgs::findEnvp()` | `0x350b0` | `0x33164` |
| `KernelArgs::findApple()` | `0x350e0` | `0x33194` |
| `ProcessConfig` constructor C2 | `0x35120` | `0x331d4` |
| `ProcessConfig::Process` constructor | `0x35850` | `0x33904` |
| `ProcessConfig::Security` constructor | `0x36894` | `0x34938` |
| `Security::pruneEnvVars` | `0x36d80` | `0x34e1c` |
| `Header::fromDyldMapped` | `0x8c9a8` | `0x88004` |
| `Header::header()` | `0x8a348` | `0x859e0` |
| Selected `string_view::starts_with` | `0xcfdc` | `0xc978` |
| Original `__simple_getenv` | `0x4e34` | `0x4dac` |
| Security embedded-environment callback | `0x36c18` | `0x34cb4` |
| `Header::forEachDyldEnvVar` | `0x91f14` | `0x8d528` |
| `RuntimeState` constructor | `0x34080` | `0x32158` |

Original mangled nlist names are retained, including both aliases for the selected string-view comparator and `_strlen`/`__platform_strlen`. The source captures 15 complete bodies per slice, totaling 2505 instructions / 10020 B. All selected dyld bytes match independent LLVM word output; 29 selected words require LLVM instead of the available Capstone decoder. All 6752 compiler starts match independent `dyld_info` output. Six complete bodies also equal the prior ProgramVars capture. These establish identities and selected source correspondence, not whole-function or hardware-ISA equivalence [KA1,KA3].

## Observed input layout and nested fields

The constructor saves incoming KernelArgs in X24 and loads the header pointer from `[X24]`. It loads 8 B at `[X24+8]`, writes the low 32 bits into the public argc field, and retains the full loaded word as the argv span count. This is an observed load/store contract; the kernel's serialization and padding contract is not established here. The model assumes a nonnegative representable argc, valid NULL-terminated vectors and disjoint readable input/output objects [KA2].

| Field | KernelArgs input | Process offset | ProcessConfig offset | Output extent |
|---|---|---|---|---|
| Header span | Pointer at `+0`, 8 B load | `+0` | `+0x10` | Pointer/byte-count pair, 16 B |
| argc | Word at `+8`, 8 B load | `+0xa8` | `+0xb8` | 4 B |
| argv span | Vector begins at `+0x10` | `+0xb0` | `+0xc0` | Pointer/count pair, 16 B |
| Environment span | After argv terminator | `+0xc0` | `+0xd0` | Pointer/count pair, 16 B |
| Apple span | After environment terminator | `+0xd0` | `+0xe0` | Pointer/count pair, 16 B |

The original outer constructor passes `config+0x10` to the Process constructor, then `config+0x150` and the Process reference to Security construction. `RuntimeState` construction stores its incoming configuration reference at `state+8`. This joins the nested offsets above to the prior `prepare` and initializer-callback accesses; the later argc load is 4 B while vector pointers are 8 B [KA2,KA4]. Reconstructed SDK-checked prefix structures describe only the listed fields, not complete canonical private object sizes.

For normal arm64e, let K be the KernelArgs address, N the observed argc, E the number of environment entries, and A the number of Apple entries. With 8 B pointers:

```text
argv address        = K + 16 B
environment address = K + 16 B + 8 B * (N + 1)
                    = K + 8 B * (N + 3)
apple address       = K + 16 B + 8 B * (N + E + 2)
```

The routines scan from `argv[N+1]` until the environment terminator. `findApple` separately scans that environment and then the Apple vector. The Process constructor contains corresponding inlined scans and stores. They do not validate `argv[N]` before using N to locate the environment. Termination and address validity are assumptions, not consequences of the scalar identities [KA2].

The arm64e.x1 `findEnvp` and Process constructor use `ADDPT` at `0x3318c` and `0x339b8`, respectively, where normal arm64e uses `ADD`. Its compactor and `__simple_getenv` also use `ADDPT` at `0x34f28` and `0x4e3c`. LLVM records these original encodings. The finite address/layout models and ordinary 64-bit pointer identities apply to normal arm64e only; x1 pointer semantics are unproved [KA3].

## Executable-header span producer

At `0x358cc` / `0x33980`, the Process constructor calls `Header::fromDyldMapped` with the pointer loaded from KernelArgs offset 0, then stores returned X0/X1 as its first 16 B field. The helper leaves X0 unchanged and computes X1 as:

```text
header bytes = 28 B if magic == MH_MAGIC (0xfeedface), otherwise 32 B
span bytes   = header bytes + zero_extend_u32(sizeofcmds at header+20 B)
```

The result lies between 28 B and 4294967327 B under those observed integer operations. This arithmetic bound does not validate the mapped extent, load-command sequence, header magic, native executable identity or lifetime. Values other than `MH_MAGIC`, including unrecognized magic words, select the 32 B arithmetic branch. The same constructor calls the helper again for a separate dyld-self span; that second call is not another KernelArgs-header observation [KA2,KA4].

The prior report's `Header::header()` getter later checks wrapper length greater than 27 B before returning the stored pointer. The span calculation and getter bound together remain weaker than a mapped-image validity proof. The actual input pointer and its same-epoch relation to native FairPlay remain unknown [KA5].

## Selected pruning gate and pointer transformation

After its original policy and embedded-header-environment callback frontiers, the Security constructor tests bit 0 of its bytes `+0x22`, `+0x23`, `+0x24`. The selected `pruneEnvVars` call occurs only if all three tests are clear, at `0x36ac8` / `0x34b68`. The named `getAMFI` call is retained as a policy frontier; its actual result and the effective native decision are unknown. Raw byte offsets are used instead of assigning unverified canonical policy-field names [KA4,KA5].

The compactor begins at the environment pointer, takes E and A from the Process spans, and iterates E+A+2 pointer slots: environment entries, environment NULL, Apple entries, Apple NULL. Prefix classification is restricted to indices less than E. A matching entry increments a 32-bit removal counter. Every later retained pointer is copied to `index - sign_extend(removals)` once that counter is nonzero. Selected pair stores then publish the new environment count and Apple pointer/count [KA2,KA4].

For representable counts and valid inputs, its compact model is:

```text
D = 0
for i in [0, E+A+2):
    if i < E and C_string(pointer[i]) begins with "DYLD_":
        D += 1
    else if D != 0:
        pointer[i-D] = pointer[i]
new environment count = E-D
new apple pointer      = environment pointer + 8 B * (E-D+1)
new apple count        = A
```

Retained order and both terminators are preserved in the bounded models; pointed-to strings are not rewritten or freed by this selected body. Vacated tail slots are not explicitly cleared. Removing a pointer from the active span therefore does not establish erasure of the bytes or all stale pointer copies. The captured routine also contains bounds traps and `-1` span-count handling outside the ordinary model domain. No native malformed-input or failure experiment is performed [KA2,KA4].

| Input bytes | Selected prefix classification |
|---|---|
| `DYLD_PAGEIN_LINKING=0`, `DYLD_`, `DYLD_=1` | Removed when the pruning call is reached |
| `XPC_FLAGS=1` | Preserved by this predicate |
| `XPC_NULL_BOOTSTRAP=1` | Preserved by this predicate |
| `XPC_SERVICES_UNAVAILABLE=1` | Preserved by this predicate |
| `DYLD`, `dyld_A=1`, `_DYLD_A=1`, empty string | Preserved by this predicate |

Matching is case-sensitive and requires the five-byte prefix, without requiring `=`. The original `string_view::starts_with` first checks length, then calls its original comparator. The retained `__simple_getenv` instead searches NULL-terminated entries for a complete requested name followed by `=` and returns the value pointer for the first match. Prefix removal and exact-key retrieval are distinct contracts [KA4]. This does not prove that no other loader/library code filters or changes `XPC_` entries [KA5].

## Process environment versus embedded loader commands

Security construction separately invokes `Header::forEachDyldEnvVar` on the executable-header wrapper. Its original callback is retained and is distinct from scanning the Process environment vector. Public SDK `LC_DYLD_ENVIRONMENT` is `0x27`. A fresh parse and independent `otool -l` comparison agree on all 30 FairPlay load commands and zero commands of this type [KA1,KA6]. This is an absence claim about the captured file, not an assertion about the native header selected through KernelArgs or embedded commands in every loaded image.

The current launchd plist and the [guest RAX trace](zut_trace_report.md) remain separate evidence sources. The plist's declared `DYLD_PAGEIN_LINKING=0` does not establish the effective native environment or which pruning branch ran. This increment adds no Mach-message emission or port observation; it clarifies an upstream control-input boundary for registered-port/bootstrap selection and the daemon's imported bootstrap data. Slot34/RPC700 receiver identity, successful selector26/RPC502/RPC700 processing and native daemon/kext exchange remain unknown [KA5,KA6].

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| KA1 | Static claims apply to the pinned dyld slices and FairPlay file. Native image pairing is not assumed. All addresses and absence claims depend on this scope. | Rehash originals, UUIDs and slices; compare 6752 compiler starts and 30 load commands independently; reject changed UUID and fabricated embedded command. |
| KA2 | Ordinary models use valid readable disjoint objects, terminated vectors/C strings, nonnegative argc and counts at most INT32_MAX, with valid extents. Layout, compaction and bounded arithmetic results depend on these restrictions. | Compile observed input/output widths and offsets; test 125 sentinel layouts, 2555 deletion/Apple layouts and ten prefixes; prove scalar bounds under explicit constraints; reject argc load-width alteration. Invalid/sentinel counts remain excluded. |
| KA3 | Ordinary address models apply only to normal arm64e. x1 ADDPT/PAC semantics are unproved. Cross-slice claims are source/field/call correspondences. | Preserve all four selected ADDPT sites and raw LLVM words; reject an altered x1 mnemonic; do not reuse ordinary ADD proofs as x1 authentication/address proofs. |
| KA4 | Reconstructed fields and compact algorithms describe selected accesses/branches, not complete private types or the entire loader policy. | Match original names, bytes, loads, gates, stores, callback and call targets in both slices; retain complete selected bodies and named AMFI frontier. |
| KA5 | Native KernelArgs producer, header/mapping identity, actual environment, policy outcome, epoch and later mutation are unknown. No native port-branch conclusion follows from the static predicate alone. | Establish same-epoch upstream records, effective vectors and policy/loaded-image observations before assigning native values; plist or file absence alone cannot satisfy this probe. |
| KA6 | Prior ProgramVars and port/RAX results retain their stated boundaries. No successful native exchange is inferred. | Rehash the prior manifest and trace; fresh-recapture six prior bodies; distinguish embedded file commands, guest packets and native namespace identities. |

## Bounded additional context

| Impact | Pattern / consequence | Remaining boundary |
|---|---|---|
| High | Selected DYLD-only filtering preserves the XPC inputs that affect bootstrap/registered-port selection. | Actual native inputs and every later writer/filter are unknown. |
| High | Header span construction plus a length-checked getter is weaker than executable identity or mapped-extent validation. | Kernel-side pointer production, header validation elsewhere and native mapping lifetime remain unestablished. |
| Medium | Removing environment entries shifts the following Apple vector, requiring a new published pointer even though Apple strings are retained. | x1 pointer instructions, exceptional counts and native alias/concurrency behavior are outside the ordinary model. |
| Medium | Embedded `LC_DYLD_ENVIRONMENT` and process environment are separate channels. | Zero embedded commands is proved only for the pinned FairPlay file. |
| Low | Pointer compaction preserves stale tail slots and string bytes. | This is selected-body behavior, not a claim about later cleanup or whole-process erasure. |

## Validation and quality gates

Fresh recapture equality passes for 30 complete bodies, 2505 instructions / 10020 B, 29 selected LLVM-only words, 6752 independently compared compiler starts and six prior bodies. The checks contain 144 instruction assertions, 25 SDK assertions in one syntax-only compilation, three unsatisfiable scalar queries, 125 sentinel-layout models, 2555 compaction models and ten prefix classifications. All 511 deletion masks for environment lengths 0..8 are crossed with Apple lengths 0..4. The compaction model follows selected copy order and is checked against a separate list-filter oracle. These finite models execute analyst-written semantics; they do not execute or emulate recovered target code and do not prove all unbounded paths. Six altered evidence controls are rejected.

The header-length query checks an arithmetic range; the environment-address query checks a modular 64-bit identity; the compaction query checks count/sign-extension and Apple-offset identities for counts at most INT32_MAX. None proves termination, mapped memory, whole-function equivalence or native admission. SDK checks establish public Mach-O constants/header extents, C++ prefix behavior and explicitly reconstructed prefix offsets; they do not supply a canonical KernelArgs/Process declaration.

Capture is O(input bytes + compiler starts + selected instructions) time/space. For valid vectors, `findEnvp` is O(E) time; `findApple` is O(E+A) time; each uses O(1) auxiliary space. Selected pruning is O(E+A+sum of environment C-string lengths) time and O(1) auxiliary space, excluding library implementation details. The bounded validator intentionally enumerates O(2^M * B * (M+B)) compaction work for maximum environment length M=8 and five Apple lengths B=5. Fixed SMT formulas have no asserted general solver-runtime bound. Manifest publication/audit is O(total artifact bytes + local links). Extents are in B, pointers/count spans are 64 bit, the removal counter is 32 bit, and sign-extension restrictions are explicit.

QG1: Factual interface, control/data-flow and routine analysis requires no normative premise.

QG2: KA1-KA6 identify assumptions, dependencies and falsification probes.

QG3: The increment covers observed input layout, nested header/vector producers, selected pruning gates/transformation and embedded-command absence. Full interface recovery remains active; native end-to-end processing is unknown.

QG4: Input/output widths, byte offsets, pointer-count arithmetic, SDK constants and bounded proof/model domains are explicit and reproducible.

QG5: Normal versus x1 address semantics, 8 B input load versus 4 B argc output, span arithmetic versus image validity, exact lookup versus prefix pruning, selected mutation versus all writers, and process versus embedded environment remain distinct.

QG6: Original bytes/nlist/UUID, compiler starts, independent load-command output, SDK/tool hashes, compact models and solver queries are retained. Local original evidence sufficed; no new IDA result is asserted.

QG7: Impact-labeled header/environment, vector relocation, embedded channel and tail-storage patterns are bounded above. No native IPC, effective input, hardware PAC or broad-goal completion claim is made.
