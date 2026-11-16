# Boot-environment pointer publication and inline tree initialization

The guarded routine at `0xfffffe000c5e6620` publishes the bootargs pointer consumed by the recovered option parser. Main calls it at `0xfffffe000c639b98` with mode 0 and the destination of its original 1152 B bootargs copy. The store at `0xfffffe000c5e6690` supplies global `0xfffffe0007f8b6e8`. The same routine publishes serialized-tree bounds inline. This establishes the missing source producer and its actual main caller; it does not establish uninterrupted native startup or a daemon-controlled input path. [EP1-EP7]

```text
external entry X1 bootargs                 external entry X2 shared header
  earlier cold-entry evidence               earlier cold-entry evidence
              |                                         |
main X0 -> original memcpy, 1152 B         main X1 -> original memcpy, 856 B
              |                                         |
  bootargs copy 0xfffffe0007e6d1e0         header copy 0xfffffe0007e6d660
              |
main 0xfffffe000c639b98: X0=0, X1=bootargs copy
              |
guarded publisher 0xfffffe000c5e6620
  first call -> saved bootargs/tree/video fields
  mode low32=0 -> saved tree bounds -> inline tree-global stores
              |                         |
              |                  stop before later tree/clock helper
              |
later main source reads global bootargs+0x6c -> option parser
  actual intervening continuation remains unexecuted here

initialized mode low32!=0 -> restore frame -> tail-call context helper
  X1 is a context at these calls; it does not replace saved bootargs
```

| Claim | Established result | Dependencies |
| --- | --- | --- |
| EP1 | Pinned source capture, exact aliases and bounded direct-branch census | EP-A1 |
| EP2 | Actual main caller, copy provenance and bootargs-pointer producer | EP-A1-EP-A3 |
| EP3 | Guard, mode predicate, field widths and context-tail contract | EP-A1-EP-A4 |
| EP4 | Inline tree publication and relationship to the separate generic initializer | EP-A1-EP-A4 |
| EP5 | Later main option-parser call sites consume the saved pointer | EP-A1, EP-A5 |
| EP6 | Local source proofs, independent byte checks, replay and controls | EP-A1-EP-A6 |
| EP7 | Mach/daemon boundary and bounded continuation | EP-A1-EP-A7 |

Primary provenance is kernel collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, original compiler starts, nlist entries and instruction/literal bytes. The preserved normalized kext has SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. Supplied reference data sufficed; no IDB was read or modified. Four source intervals match the retained [boot-header capture](kernel_boot_header_handoff_report.md) byte for byte without regenerating its historical SDK-dependent evidence. [EP1]

Artifacts: [capture producer](triage_evidence/recover_kernel_boot_environment_publication.py), [private executor](triage_evidence/probe_kernel_boot_environment_publication.py), [independent byte contracts and replay](triage_evidence/replay_kernel_boot_environment_publication.py), [source audit](triage_evidence/audit_kernel_boot_environment_publication.py), [delivery verifier](triage_evidence/verify_kernel_boot_environment_publication_delivery.py), [capture](triage_evidence/kernel_boot_environment_publication_checks.json.zst), [audit](triage_evidence/kernel_boot_environment_publication_audit.json.zst). Decoded capture: 268593 B, SHA-256 `346ede2a25d0801840efd6af68d44f47617b4b091a904581ab4081e4004eae74`. Decoded audit: 2772248 B, SHA-256 `c7ba26d27e131a78cb18f5fd698ff02deb1c4d8e108e4d2adb3ce94227083ebe`. [EP6]

## Source boundaries and callers

Nine half-open intervals contain 1526 words / 6104 B. Role names below are descriptive when the exact nlist name is unknown. [EP1]

| Original interval | Words | Exact name / role | Executed unique PCs |
| --- | ---: | --- | ---: |
| 0xfffffe000c639a40..0xfffffe000c63a3e0 | 616 | Main boot continuation; name unknown | 87 |
| 0xfffffe000c5e6620..0xfffffe000c5e6b1c | 319 | Guarded boot-environment publisher; name unknown | 76 |
| 0xfffffe000c660ad4..0xfffffe000c660bf8 | 73 | Earlier tree/list/callback initializer; name unknown | 0 |
| 0xfffffe000c6622b8..0xfffffe000c662324 | 27 | Separate generic tree initializer; name unknown | 0 |
| 0xfffffe000be3e3c4..0xfffffe000be3e450 | 35 | _strlcpy | 23 |
| 0xfffffe000bc9db70..0xfffffe000bc9dbe0 | 28 | _strlen | 25 |
| 0xfffffe000c647f10..0xfffffe000c6480c0 | 108 | _memcpy / _memmove aliases | 55 |
| 0xfffffe000be75bf0..0xfffffe000be7607c | 291 | Secondary context caller; name unknown | 0 |
| 0xfffffe000c65c050..0xfffffe000c65c0c4 | 29 | Cold-entry block; name unknown | 0 |

The direct-branch census scans all 2558561 aligned words in the file-backed kernel `__TEXT_EXEC` (10161728 B), `__TEXT_BOOT_EXEC` (27396 B) and `__KLD` (45120 B) segments. Independent Capstone decoding checks all 208326 B/BL candidates and reproduces these four target matches. Indirect calls, other filesets and external callers are outside this completeness boundary. [EP1,EP6]

| Emission PC | Target | Source argument contract | Evidence status |
| --- | --- | --- | --- |
| 0xfffffe000c639b98 | 0xfffffe000c5e6620 | X0=0; X1=0xfffffe0007e6d1e0 | Original main prefix and copies execute |
| 0xfffffe000c63a1ac | 0xfffffe000c5e6620 | X0=1; X1=0xfffffe000cac7520 | Caller bytes and local source proof; surrounding continuation unexecuted |
| 0xfffffe000be75e4c | 0xfffffe000c5e6620 | X0=1; X1=0 | Caller bytes and local source proof; surrounding continuation unexecuted |
| 0xfffffe000c65c080 | 0xfffffe000c660ad4 | X0=saved external entry X1 | Prior cold-entry evidence; unchanged captured source |

There are zero direct B/BL matches to `0xfffffe000c6622b8` within the stated scan. This does not prove that it is globally unreachable. Both actual boot paths initialize the tree globals inline: early setup at `0xfffffe000c660b04/0c/18/28`, and the guarded publisher at `0xfffffe000c5e6724/2c/38/48`. The [previous serialized-tree](kernel_secure_dt_execution_report.md) and [option-parser compositions](kernel_boot_option_execution_report.md) started at the separate initializer as an explicit fixture epoch. Their initializers must not be relabeled as observed native callers. [EP1,EP4]

## Pointer and field publication

The actual main prefix executes the two original copies at `0xfffffe000c639ab0` and `0xfffffe000c639ad0`. It publishes the copied bootargs pointer at global `0xfffffe0007ef9168` through PC `0xfffffe000c639ab8`, and the copied header pointer at `0xfffffe0007f8b5e0` through PC `0xfffffe000c639ad8`. Main retains the copied bootargs in X19 and supplies it as the publisher's second argument. X2 is captured as register residue and is not a third publisher argument. [EP2]

Let S=`0xfffffe0007f8b648` and A=the publisher's second argument. The first-publication path is selected by u32[S]==0. The source saves the full mode register in X20; the two mode branches test W20, hence only its low 32 bits. [EP3]

| Destination | Width | First-publication value | Store PC |
| --- | ---: | --- | --- |
| 0xfffffe0007f8b5e8 | 4 B | 2 | 0xfffffe000c5e667c |
| S | 4 B | 1 | 0xfffffe000c5e668c |
| S+0xa0 = 0xfffffe0007f8b6e8 | 8 B | A | 0xfffffe000c5e6690 |
| S+0x98 | 8 B | u64[A+0x60], saved tree base | 0xfffffe000c5e6698 |
| S+0xa8 | 8 B | zero-extended u32[A+0x68], saved tree extent | 0xfffffe000c5e66a0 |
| S+8 | 8 B | u64[A+0x28] | 0xfffffe000c5e66a8 |
| S+0x10 | 16 B | Exact bytes A+0x38..A+0x48 | 0xfffffe000c5e66b0 |
| S+0x20 | 8 B | u64[A+0x48] | 0xfffffe000c5e66bc |
| S+0x28 | 8 B | u64[A+0x50] & 255 | 0xfffffe000c5e66bc |
| S+0x88 | 1 B | ((u32[A+0x50] >> 8) + (u32[A+0x50] >> 24)) & 3 | 0xfffffe000c5e66cc |
| S+0x89 | 1 B | (u8[A+0x52]+1) modulo 256 | 0xfffffe000c5e66d8 |
| S+0x30 | 8 B | u64[A+0x30] | 0xfffffe000c5e66e0 |
| S+0x38 | 25 B in this call | `BBBBBBBBGGGGGGGGRRRRRRRR` plus NUL | Original strlcpy at 0xfffffe000c5e66f4 |

The source supplies strlcpy capacity 64 B. Its original strlen and memcpy execute; the 24-character literal plus NUL occupies 25 B and leaves the other 39 B of this destination unchanged. This is a format-string role inferred from bytes and adjacent packed state; exact source type/field names are unknown. No broader strlcpy size/branch contract is established by the single fixed-capacity call. [EP3,EP6]

| Guard at entry | Low32(mode) | Selected prefix behavior |
| --- | --- | --- |
| 0 | 0 | Publish all first-call fields, then initialize tree globals from saved tree pair |
| 0 | Nonzero | Publish all first-call fields, restore frame, tail-call context helper |
| Nonzero | 0 | Retain first-call fields, initialize tree globals from saved tree pair; new X1 does not replace bootargs |
| Nonzero | Nonzero | Retain first-call fields, restore frame, tail-call context helper with X0=original X1 |

The context helper boundary is `0xfffffe000c5e5d98`; the actual tail branch is at `0xfffffe000c5e6670`. Its effects are not modeled or executed here. The two later mode-1 callers therefore have source-level context contracts conditional on the initialization guard already being set. This increment does not prove the guard's complete native lifetime or scheduling. [EP3,EP-A3]

Mode 0 loads saved base/extent from S+0x98/S+0xa8, tests unsigned 64-bit addition carry at `0xfffffe000c5e6718/1c`, then writes u64 base/extent/end at `0xfffffe0007f8b508/+8/+16` and u32 nonnull flag at +24. The end is base+extent; the flag depends only on base!=0. Carry selects `0xfffffe000c5e6afc` before these stores. First-call state publication precedes that carry gate, so this is not an all-or-nothing environment transaction. The private carry fixture stops before diagnostic setup and never dereferences its tree base. [EP3,EP4]

Successful mode-0 prefixes stop before helper `0xfffffe000c5e5894`, reached by the original BL at `0xfffffe000c5e674c`. The subsequent tree walks, clock derivation, string extraction and final platform tail remain outside executed coverage. [EP4,EP-A5]

## Later parser consumers and validation

Local source proofs cover four later main call sites. These consume u64[`0xfffffe0007f8b6e8`]+0x6c as X0 and call the recovered parser `0xfffffe000c5e48a4` with W4=0. Their intervening control flow is not executed by this increment. [EP5]

| Call PC | Original key address / bytes | X2 output | W3 |
| --- | --- | --- | ---: |
| 0xfffffe000c639c0c | 0xfffffe00070644e0 / icdsb | 0xfffffe0007ef9164 | 4 |
| 0xfffffe000c639c3c | 0xfffffe0007062148 / user_ts_jop | Current main SP+0x30, source default 1 | 4 |
| 0xfffffe000c639c78 | 0xfffffe0007062154 / diversify_user_jop | 0xfffffe0007e6d154 | 4 |
| 0xfffffe000c639cb4 | 0xfffffe0007062167 / sptm_stability_hacks | 0xfffffe0007e6d159 | 1 |

These strings are independently read from the pinned collection during delivery verification. The prior [option-parser execution](kernel_boot_option_execution_report.md) establishes selected scanner semantics, while this increment establishes the producer and local consumer address calculations. The two experiments retain their explicit call-frame boundaries; they are not one uninterrupted native boot. The 1152 B copy does not alone establish the command-line field's declared capacity or its original content producer. [EP2,EP5]

Nineteen nonvacuous local source queries are UNSAT, covering 107 distinct source PCs/instruction instances and 88 linked-edge obligations. They cover guard/mode branches, first-call fields, exact 16 B vector transfer, packed arithmetic, string-copy ABI, inline tree carry/publication, all three actual platform callers and four option consumer ABIs. Each premise set is SAT before the negated contract is added. These are local obligations; full-function correctness is not inferred. [EP6]

Nine private components pass 97 independent semantic checks. Four start at actual main and execute both complete copies; two start at a declared platform call frame with guard zero; three transfer the exact mutable image output of the first main case into declared re-entry frames. They include null tree base, maximum u32 tree extent, packed-field wrap, tree addition carry, mode `0x100000000`, ignored replacement arguments and mode-1 null/CPU contexts. No tree-reader or parser return is modeled. [EP6]

Independent formulas compare all 115200 mutable image bytes cumulatively and 9398016 private bytes outside the explicit 4352 B stack guard cumulatively. Fresh replay checks all private RAM, including the stack, and every mapped image page by SHA-256: 9437184 private bytes and 417792 image bytes cumulatively. These memory counts overlap and describe repeated checkpoints, not disjoint native allocations. The model grants four mutable image regions totaling 12800 B per case; native allocation/ownership is unknown. [EP6]

Replay imports no executor and checks 3419 original source visits, 266 distinct PCs, 1287 reads, 1532 writes, 35 original call entries, nine final SP/NZCV/GPR boundaries and 288 final SIMD registers. Initial Q0-Q31 are explicitly zero. Eight declared no-RAM registration returns occur across the four main cases; their caller-saved clobber formulas and preserved registers are independently checked. PACIBSP/AUTIBSP/RETAB and address PAC/XPACI are logical envelopes; native authentication is unproved. [EP6]

Four NOP controls are rejected at the bootargs-pointer store `0xfffffe000c5e6690`, packed-field byte store `0xfffffe000c5e66d8`, tree-valid flag store `0xfffffe000c5e6748` and main copied-bootargs publication `0xfffffe000c639ab8`. They are excluded from positive totals. The three captured opaque words and strlen UDF padding are unexecuted. Executed publisher coverage is 76/319 PCs; it stops before later helper effects. [EP6]

Capture/census costs O(K+W+I+N) time/space in collection bytes K, scanned words W, captured bytes I and symbol records N. Proof construction costs O(I+Q) in source/formula DAG Q; SMT search is separate with a 30 s/query bound and no polynomial claim. Private execution, byte checks and replay cost O(V+J+M) time/space in visits V, journals J and mapped bytes M. All widths and arithmetic are exact little-endian bit vectors; extents are in bytes and no statistical error estimate applies. Nontrivial JSON uses `zstd --ultra -22 -q -T1`, decoded roundtrip verification and nested path hygiene. [EP6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| EP-A1: Pinned image, compiler intervals and exact aliases identify this build | EP1-EP7 | Rehash nine source intervals, four prior matches, literals and all three scanned segments; no cross-build equivalence |
| EP-A2: Bounded private buffers and poisoned mutable state instantiate the stated call frames | EP2-EP7 | Full copies, width extremes, carry/null cases, whole-region formulas and complete replay; authentic inputs and native owner extents unknown |
| EP-A3: First publication assumes guard zero; re-entry assumes the transferred guard remains nonzero | EP2-EP7 | Original guard/mode proofs, exact three predecessor transfers and context/ignored-argument cases; complete native guard lifetime unknown |
| EP-A4: Registration returns and PAC envelopes support only conditional private execution | EP2-EP7 | Eight validated no-RAM returns, original nonvolatile-register custody, final SIMD/SP/NZCV checks; native helper and PAC effects unknown |
| EP-A5: Local later consumer proofs do not establish uninterrupted main continuation | EP4-EP7 | Check exact caller/consumer words and arguments; stop before unexecuted helpers and keep prior fixture epochs explicit |
| EP-A6: Independent byte formulas, local lifting and fresh replay validate this increment | EP6,EP7 | Nineteen nonvacuous proofs, 97 checks, all journals/pages and four altered-source rejections; shared decoder/emulator limits remain |
| EP-A7: Boot-environment publication does not establish daemon influence or a Mach transfer | EP7 | Correlate matched daemon/user-client/kernel epochs and rights; no new port or transfer observed here |

No new incoming/outgoing Mach port, port right or Mach-message emission PC is established. The emission PCs in the caller table are kernel function-call instructions, not Mach sends. Existing endpoint evidence remains in the [Mach-port inventory](mach_ports_report.md). Direct fairplayd control over these boot inputs and the original bootloader content producer remain unknown. [EP7]

| Impact | Bounded next work | Discriminating evidence |
| --- | --- | --- |
| High | Execute the publisher's real post-publication tree/clock/string helpers on bounded serialized-tree fixtures | Replace the explicit helper cut and establish the later platform return |
| High | Join that return to main's pre-enumeration parser calls and the existing topology composition | Remove the initializer/main fixture substitution with original caller continuity |
| Medium | Trace writes to the initialization guard and the separate tree initializer's address references | Determine broader lifetime and indirect-call boundaries within a stated scope |
| Medium | Correlate boot-environment state with a matched FairPlay daemon/user-client/kernel transaction | Establish whether these environmental inputs affect the observed interaction |
| Low | Compare equivalent publisher contracts in another identified build | Separate stable ABI from build-specific layout; no equivalence assumed |

**QG1**: Factual source/interface analysis; no normative content required. **QG2**: EP-A1-EP-A7 list dependencies and falsification probes. **QG3**: Producer, callers, modes, widths, tree-global stores, later consumers and IPC limits covered for this increment; full goal remains active. **QG4**: Reproducible hashes, exact widths, byte extents, algorithms and complexity stated. **QG5**: Pointer/context roles, full64 saved mode versus low32 predicate, partial publication, static consumers and private/native boundaries separated. **QG6**: Original image bytes, exact symbols, independent decoding, source queries and replay retained. **QG7**: Impact-ranked continuation bounded above. All gates pass for this increment; authentic startup, later helpers and matched daemon/kernel execution remain unknown.

## Original platform-return follow-up

The later-helper cut is now replaced in a separate continuous experiment: original range/cache, CPU-clock, identity/chosen and diagnostic bodies return into actual main, followed by original timer and four parser calls. The earlier registration/PAC/native premises remain explicit; enumeration is the new stop boundary. See the [platform environment execution report](kernel_platform_environment_execution_report.md) for source intervals, contracts, assumptions and remaining boundaries.


## Initialized-data and continuous thread-handoff follow-up

The [bootstrap state-composition report](kernel_bootstrap_state_composition_report.md) preserves the prior zero-page fixture and establishes its pre-store null-destination boundary. A separately declared original initialized topology page permits continuous main/platform/timer/enumeration/post-helper/thread-copy/setter execution, without a call-frame epoch or later state repair. The paired input/register comparison, original pointer fixups, post-helper default 2, selected CPU ordinal, logical register custody and remaining selector0e/native/Mach boundaries are explicit.


## Startup registry and mach_ipc registration follow-up

The [startup registry ABI increment](kernel_startup_registry_abi_report.md) captures all 3519 original initialization records and 115 distinct kernel callback bodies, their authenticated pointer metadata, phase names and 22 tree/boot-option tunable descriptors. Original main now continues through timebase/trace, complete sorting, its first actual tunable callback/return and cursor publication. Three private runs establish absent/property/option precedence; entry 123 registers the previously analyzed MIG hash initializer at phase 14 (`mach_ipc`), rank zero, argument zero. Phase-14 execution, remaining callback effects, native startup/PAC lifetime and a matched FairPlay/Mach transaction remain unknown; the full goal remains active.
