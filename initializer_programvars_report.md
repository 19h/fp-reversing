# Dyld constructor arguments, ProgramVars and libc accessor provenance

The original dyld and cached libraries supply a static producer chain for the executable-header cell used by libmacho and libxpc role selection. On the selected default path, dyld initializes a 40 B record at `RuntimeState+0x88`, passes it as constructor argument X4, and libSystem forwards it to libc. Original `__program_vars_init` copies the five fields into libc accessor cells. The executable header is a direct pointer; the other four fields point to libdyld-owned variables [PV1-PV4]. This resolves a static producer frontier in the [registered-port consumer report](registered_port_consumers_report.md). Native FairPlay header identity, initialization branch, effective environment and resulting bootstrap port remain unknown [PV5,PV6].

[Original bytes and metadata](triage_evidence/initializer_programvars_source.json), [reproducible checks](triage_evidence/initializer_programvars_checks.json), [capture script](triage_evidence/recover_initializer_programvars.py), [validator](triage_evidence/validate_initializer_programvars.py), [delivery seal](triage_evidence/initializer_programvars_delivery.json), [quality gates](triage_evidence/initializer_programvars_quality_gates.json).

```text
dyld ProcessConfig values + executable-header wrapper
  -> prepare: RuntimeState.ProgramVars at +0x88
       -> direct initializer callback: X0..X4
       -> helper +0xc8: X1..X5 -> X0..X4
            -> libSystem initializer: incoming X4
                 -> libc initializer: incoming X3 -> X0
                      -> __program_vars_init: five libc cells
                           -> _NSGetMachExecuteHeader
                                -> getsectbyname -> libxpc role selection
                           -> argc/argv/environ/progname accessors

Static contracts above require the recorded image, path and initialization epoch.
No native header, environment or port identity is inferred from file defaults.
```

## Original identities and coverage

All addresses are preferred static virtual addresses. Dyld's selected slices have preferred `__TEXT` base zero; their small addresses are not native runtime addresses. The original daemon declares `/usr/lib/dyld` in `LC_LOAD_DYLINKER`. This establishes a declared loader path, without proving which loader/slice/cache the historical RAX run or a native daemon used [PV1,PV5].

| Original input | Identity |
|---|---|
| `/usr/lib/dyld`, universal file | SHA-256 `3bbd2bc4d7f315fafec3cc51d6f0def403ce1149e3fb99e53b21ee19776d7401` |
| dyld arm64e | UUID `3721f73b-6239-3955-9231-625bf089baa0`; slice offset 1179648 B, size 1474960 B |
| dyld arm64e.x1 | UUID `d038ad32-39e7-3d41-a8e7-106921edcaf0`; slice offset 2670592 B, size 1458496 B |
| Original shared cache | UUID `2bd06591-e751-3e84-963f-b08dab6af23a` |
| Cached libdyld | UUID `7addd814-2c61-3d07-b047-e6fdd97ba360` |
| FairPlay arm64e | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; UUID `204741e9-b89f-32b4-9321-51f3975c7cac` |

The capture includes 24 dyld and 15 cached complete compiler-bounded bodies: 6255 instructions, 25020 B. Both slices' 6752 compiler starts match independent `dyld_info` output. All selected dyld words match LLVM's original bytes; 37 words require LLVM because the available Capstone decoder does not decode them. Full-image LLVM warnings outside selected words remain outside the selected decode claim. Original nlist names, library UUIDs, three authenticated helper-vtable bindings, two authenticated cached stubs, five SDK header hashes, tool hashes and used cache-file hashes are retained. There is no whole-function semantic-equivalence or hardware-PAC claim [PV1,PV3].

## Producer record and ownership

`ProgramVars` is a reconstructed private record name/layout. The public SDK supplies accessor prototypes, not this private declaration. A compiled reconstruction establishes size 40 B, alignment 8 B and the offsets below on the selected arm64 ABI [PV2].

| Record offset / RuntimeState offset | Reconstructed value | libc cell | libdyld value storage | Value-storage width |
|---|---|---|---|---|
| 0 / `+0x88` | `mach_header_64 *` | `0x1ed84eda0` | Header value itself | 8 B |
| 8 / `+0x90` | `int *` | `0x1ed84edc0` | `0x1ed83b0f8`, original `_NXArgc` | 4 B |
| 16 / `+0x98` | `char ***` | `0x1ed84edf0` | `0x1ed83b100`, original `_NXArgv` | 8 B |
| 24 / `+0xa0` | `char ***` | `0x1ed84ed98` | `0x1ed83b108`, original `_environ` | 8 B |
| 32 / `+0xa8` | `char **` | `0x1ed84edb8` | `0x1ed83b118`, original `___progname` | 8 B |

Libdyld's original `setDefaultProgramVars(ProgramVars&)` at `0x180467a28` writes only offsets 8,16,24,32. It does not supply the header field. Its stores at `0x180467a40` and `0x180467a4c` install the four storage addresses, not the argc/argv/environment/program-name values. Original `prepare` subsequently writes those values through the pointers: argc uses a W-register store; the other three use X-register stores [PV2,PV4].

On that path, `prepare` loads the configuration pointer from `RuntimeState+8`, calls original `mach_o::Header::header()` on `config+0x10`, and stores the result into `RuntimeState+0x88` at `0x33540` / `0x31744`. The helper checks its wrapper length at `+8` against 27 B, traps for lengths at most 27 B, and otherwise loads the pointer from wrapper offset 0. It does not validate a Mach-O magic, executable identity, mapping lifetime or native cache pairing. The upstream wrapper's actual contents remain unknown [PV4,PV5].

## Libdyld helper interface and version gates

| Original object/interface | Preferred address / offset | Selected meaning |
|---|---|---|
| `__DATA_CONST,__helper` | `0x1e2122d28`, size 8 B | Helper object containing authenticated vptr |
| Original vtable symbol base | `0x1e2122d60` | `__ZTVN5dyld416LibSystemHelpersE` |
| Vtable address point | `0x1e2122d70` | After the two preceding 8 B header words |
| Version method | Slot `+0`, target `0x1804678c0` | Returns W0=8 |
| Default record setter | Slot `+0xb0`, target `0x180467a28` | Writes four value-storage pointers |
| Initializer helper | Slot `+0xc8`, target `0x180467a80` | Removes C++ object argument and calls X6 |
| `__TPRO_CONST,__dyld_apis` | 8 B section; exact address in capture | Receives RuntimeState pointer on selected prepare path |

The object vptr and all three methods are verified members of original cache slide chains. Original pointer encodings and authentication diversity are retained. The captured `prepare` loads the corresponding method slots; selected source discriminators match the encodings for the object/default-setter path. This records static binding expectations, not hardware authentication or native interposition [PV3].

`prepare` locates literal `__TPRO_CONST,__dyld_apis` and `__DATA_CONST,__helper`, requires section sizes of 8 B, stores the helper address at `RuntimeState+0xb0`, and calls its version method. The selected default setter path requires helper version greater than 6. The initializer callback uses the delegated helper path only after its separate state-byte/configuration checks and version at least 8. These are distinct gates; version 7 is sufficient for the default setter but not this delegated call. Configuration/image comparisons and fallback branches remain captured; their complete policy is not reconstructed [PV3,PV4].

## Constructor ABI and forwarding sites

The selected direct callback loads argc/argv/envp/apple from configuration offsets `+0xb8/+0xc0/+0xd0/+0xe0`, supplies `RuntimeState+0x88`, and invokes the initializer. The delegated path supplies the same five values shifted by one register, followed by the function pointer in X6. Original `callInitializer` performs `X0=X1; X1=X2; X2=X3; X3=X4; X4=X5`, then `BLRAAZ X6` at `0x180467aa4`. The straight-line register equivalence is proved for arbitrary 64-bit inputs; argc is separately observed loaded as 32 bits [PV2,PV3].

| Constructor field | Direct call argument | Helper entry argument | Original source |
|---|---|---|---|
| argc | W0 | W1 | Configuration `+0xb8`, 4 B load |
| argv | X1 | X2 | Configuration `+0xc0` |
| envp | X2 | X3 | Configuration `+0xd0` |
| apple vector | X3 | X4 | Configuration `+0xe0` |
| ProgramVars pointer | X4 | X5 | RuntimeState `+0x88` |
| Initializer pointer | Indirect target | X6 | Load base plus zero-extended 32-bit initializer offset |

| Original role/site | arm64e | arm64e.x1 |
|---|---|---|
| `prepare` entry | `0x32930` | `0x30be8` |
| Process constructor | `0x35850` | `0x33904` |
| RuntimeState constructor | `0x34080` | `0x32158` |
| Initializer walk | `0x5e184` | `0x5a498` |
| Initializer callback entry | `0x633d0` | `0x5f4ac` |
| Delegated initializer emission | `0x63514` | `0x5f5f0` |
| Direct initializer emission | `0x63534` | `0x5f610` |
| `mach_o::Header::header()` | `0x8a348` | `0x859e0` |
| Header-field store | `0x33540` | `0x31744` |

The block's captured `+0x28` field points to load-base storage and `+0x30` supplies RuntimeState. The initializer address calculation is 64-bit addition of load base and zero-extended W1. A scalar proof establishes independence from the upper 32 bits of the offset register, without proving a valid callable address. Named JIT/prebuilt dispatch and initializer-enumerator bodies are retained as architectural call frontiers; complete graph reachability and alternative initializer representations are not claimed [PV3-PV5].

Original libSystem initializer at `0x2cbbed264` is registered by its original initializer-offset section. It saves incoming X4 in X20, forwards X3=X20 to the libc initializer through the authenticated stub at `0x2d00a0840`, with the call at `0x2cbbed308`. The selected normal ordering places libkernel initialization before libc and libxpc initialization after libc. Libc entry `0x1805c483c` moves its incoming X3 into X0 at `0x1805c4854` and calls `__program_vars_init` at `0x1805c4858`. This is a conditional registered path, without native execution evidence [PV1,PV3,PV4].

The captured legacy libc entry `0x1805e8158` builds a separate 64 B stack-local initializer record beginning with integer 1 and rearranges arguments before calling the libc initializer. Its complete incoming prototype and registration/use remain unknown; it does not establish an alternative native FairPlay startup path [PV4,PV5].

## libc copy and role-selection boundary

Original `__program_vars_init` at `0x1805c48a8` is 14 instructions, without a call. Its actual order is: load record fields 2 and 3; publish argv cell; load fields 0 and 1; publish argc and environment cells; load field 4; publish program-name and header cells. Header publication occurs at `0x1805c48d8`. The scalar/word-memory proof respects this order and assumes stable, aligned, disjoint input/output objects. Early stores precede later loads, so arbitrary overlap is outside the proof [PV2].

| Public SDK accessor / original symbol | Entry | Selected return |
|---|---|---|
| `_NSGetMachExecuteHeader` / `__NSGetMachExecuteHeader` | `0x1805a6020` | Header pointer from cell `0x1ed84eda0` |
| `_NSGetArgc` / `__NSGetArgc` | `0x1805ab7cc` | `int *` from cell `0x1ed84edc0` |
| `_NSGetArgv` / `__NSGetArgv` | `0x1805ab7c0` | `char ***` from cell `0x1ed84edf0` |
| `_NSGetEnviron` / `__NSGetEnviron` | `0x1805a5f68` | `char ***` from cell `0x1ed84ed98` |
| `_NSGetProgname` / `__NSGetProgname` | `0x1805aa9b8` | `char **` from cell `0x1ed84edb8` |

The double underscore in retained nlist names includes Mach-O's external-symbol decoration; public C identifiers above have one underscore. Libmacho's default-header lookup uses the header accessor through an authenticated stub. Libxpc's role markers and environment inputs then control the registered-port versus task-bootstrap paths already mapped in the prior report. File-default zero cells, the daemon's absent role-marker sections and the launchd plist's single environment key do not prove the effective runtime state [PV5,PV6].

This increment adds no Mach-message emission, port creation or port-name observation. Its architectural contribution is provenance for initialization inputs controlling the previously recovered RPC3403/3404/3409 and bootstrap/check-in paths. The original [RAX trace](zut_trace_report.md) remains guest evidence: no successful selector26, RPC502 or RPC700 round trip, actual slot34 receiver, or native daemon/kext transaction is established [PV6].

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| PV1 | Selected original files/slices/cache are the subjects of static claims; no native pairing assumed. All addresses/bindings depend on this scope. | Rehash original inputs, UUIDs, slice extents and used cache files; independently compare all compiler starts; reject altered slice UUID. |
| PV2 | ABI uses 8 B pointers and 4 B int; copy proof assumes stable, aligned, disjoint record/cells. Field/ownership and copy results depend on this. | Compile SDK accessor types/layout; reject offset, cell and width alterations; SMT actual ordered word-memory operations. Arbitrary aliases remain excluded. |
| PV3 | Selected normal call sites and authenticated bindings are interpreted statically. Conditional argument flow depends on reaching them with matching objects. | Retain complete bodies, original names, vtable/stub slide-chain membership; reject helper-target alteration; prove register shuffle. Native PAC/reachability remain unknown. |
| PV4 | Reconstructed private field names describe selected accesses, not a complete canonical private structure. Producer semantics are limited to selected default path. | Compare exact loads/stores, header bound/trap, version gates and fallback edges in both slices; no semantics assigned to uncaptured upstream objects. |
| PV5 | Native header/slice, image interposition, effective environment and initialization epoch are unknown. No native branch inference depends solely on absent daemon sections. | Require same-epoch loaded-image/header and accessor observations to establish native values; static declaration or file zeros cannot satisfy this probe. |
| PV6 | Prior port/RAX findings retain their published boundaries. No new port identity or successful FairPlay exchange is inferred here. | Rehash trace and prior manifest; keep guest packet IDs, constructor values and native namespace identity separate. |

## Bounded additional context

| Impact | Pattern / consequence | Bounded evidence gap |
|---|---|---|
| High | Header provenance controls which image libxpc searches for role-marker sections. | Native wrapper/header/image and exact initialization epoch are unknown. |
| High | Environment accessor points to shared value storage; a plist key set alone does not fix all effective runtime inputs. | KernelArgs production, mutations and libxpc parser policy are not fully reconstructed. |
| Medium | Version 7 versus 8 separates default-record construction from delegated initialization. | Actual native helper version/selection is unknown; captured helper returns 8. |
| Medium | Legacy libc initialization and dyld fallback paths expose separate startup contracts. | No complete alternate-path prototype, registration or FairPlay use established. |
| Low | Private reconstructed fields can be checked against five public typed accessors. | This does not prove canonical private type names or whole-structure layout beyond the recovered record. |

## Validation and quality gates

Fresh recapture equality passes. Thirty-nine complete bodies/6255 instructions/25020 B, 6752 independently compared compiler starts, 37 selected LLVM-only words, 144 instruction assertions, 16 SDK assertions in one syntax-only compilation, three unsatisfiable equivalence queries and six rejected evidence alterations pass. Negative controls change evidence JSON only; no target code, messages or host configuration are exercised. Original inputs and prior artifacts are retained except the six declared index/publisher updates; publication hashes and preservation counts are independently audited.

Capture/decode validation is O(input bytes + compiler starts + selected instructions); storage is O(capture size). The five-field/register proofs have fixed-size formulas; no general SMT runtime bound is asserted. Manifest publication and independent preservation audit are O(total artifact bytes + local links), with memory bounded by the manifest and largest parsed artifact. Widths are in bits, extents in B; all address arithmetic is explicitly 64 bit and the initializer offset is zero-extended from 32 bits.

QG1: Factual interface/routine analysis; no normative premise required.

QG2: PV1-PV6 identify assumptions, dependent results and falsification probes.

QG3: This increment covers static producer, constructor argument, library storage/accessor and role-selection interfaces. Full daemon/kext/deeper-interface investigation remains active; exhaustive recovery and native success are unknown.

QG4: Byte extents, register widths, pointer levels, SDK declarations and bounded proof domains are checked; reconstructed private layout is explicit.

QG5: Direct/delegated paths, version gates, wrapper length versus identity, header versus value pointers, selected default versus legacy/fallback, and disjoint versus overlapping objects remain distinct.

QG6: Original bytes, compiler starts, nlist/UUID, authenticated chain metadata, hashes, SDK compilation and solver queries are retained. No new IDA/knowledge-store result is asserted; local reference evidence sufficed for this increment.

QG7: Impact-labeled header/environment/version/alternate-entry context is bounded above. No native IPC, initialization, hardware PAC or broad-goal completion claim is made.
