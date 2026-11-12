# Selector-21 output stream, reused record and private stack adapter

The selected mode-2 source path initializes a second 32 B `FPByteArrayStreamInternal` object around the existing 512 B output-B span. It passes that object, the input stream, task and workspace pointers through the reused W+`0x60` record to adapter `0xfffffe000a69ee38`. The adapter's selected inner target is `0xfffffe000a6890dc`. Its stack-delta cell and the record's status field are separate return channels. Sixteen conditional source continuations and 27 UNSAT source queries establish this increment; neither the adapter nor a native transaction executes. [OS1-OS7]

```text
unchanged reader prefix -> pending second 32 B allocation
                                  |
               +------------------+------------------+
               |                                     |
       distinct object H2                        null control
       wrap existing output-B                    overwrite H1[0..31]
       pack W+0x60 record                        STOP before typed free
       STOP before adapter
               |
       separate static adapter proof
       private header S-0xb0 -> inner entry restores S
       final header Q -> exported delta -> caller SP adjustment
               |
       remaining inner effects / output writes unknown
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| OS-A1 | Pinned KC, normalized kext and parent receipts identify the same build and source epochs. All joins depend on this premise. | Rehash dependencies, reproduce each parent prefix exactly, compare original/normalized instructions and decode original chained pointers. Different builds invalidate the mapping. |
| OS-A2 | The earlier fresh input-stream return is inherited. The second call either returns a distinct valid 32 B object or null with the declared ordinary call ABI. Continuations depend on these models. | Clobber X1-X18 independently, preserve callee-saved registers, supply no heap contents, and retain the null case as counterfactual. Native return feasibility is unknown. |
| OS-A3 | Prior missing frame bytes retain coherent arbitrary origins; new private reads must already have source definitions. Source independence depends on this memory model. | Reproduce the parent origin model, introduce no new origins, reject unspecified new reads and symbolic non-frame writes, and independently reconstruct all byte epochs. |
| OS-A4 | Record, objects, frame, data spans and globals have valid, disjoint, nonwrapping extents under the stated fixed-cell model. Memory equations depend on this premise. | Check byte extents and both placements; preserve unknown object-tail bytes. Native IOKit input/output aliasing remains unknown. |
| OS-A5 | Original table arrays remain stable. Bank cuts quantify over arbitrary controller-derived u32 selectors, independently of each mutable controller read. Target reductions depend on this premise. | Prove each cut's two byte addresses/index arithmetic and exhaust all 256 original byte inputs for each of five rules. Do not freeze controller globals to image values for universal proofs. |
| OS-A6 | A64 widths, little-endian cells, W-register zero extension and masked register shifts describe the selected source. Arithmetic and finite continuations depend on these semantics. | Re-run source equations, including a universal register-shift check, and compare original instruction bytes. Replace the record key only after proving its source expression equals the canonical key. |
| OS-A7 | Probe/inner calls return ordinarily with their required ABI and valid stack extents. Exported-delta interpretation is conditional on those events. | Keep the pending call unexecuted; distinguish header entry restoration from final preservation. Actual Q, actual delta, PAC/probe behavior and completed response remain unknown. |

## Second object and allocation-result paths

The [reader report](versioned_stream_words_report.md) stops before `_IOMallocTypeImpl` at `0xfffffe000a5a8218`, X0=`0xfffffe000847b8e0`, static requested size 32 B. This increment reproduces all eight parent cases field-for-field, then separately declares the second return. It does not allocate or initialize target memory through an allocator. H1 is the first stream object; H2 is the declared distinct second object. G is the dispatcher body SP and FP=G+`0x250`. [OS2-OS4]

The distinct-object path makes 187 new source visits per case and stops before call `0xfffffe000a5a8508`. It initializes exactly the first 28 B of H2; its last 4 B remain unspecified. For an arbitrary u32 capacity N and pointer D, the constructor equations are: [OS3-OS5]

| Object offset | Source-defined value | Retained N=512 case |
| --- | --- | --- |
| `+0x00`, u64 | Existing output-B pointer D | R+`0x38` points to the existing output-B span |
| `+0x08`, u32 | N*`0x13509fb7`+`0x4552bd62` mod 2^32 | `0xe6922b62` |
| `+0x0c`, u32 | N+`0x13496211` mod 2^32 | `0x13496411` |
| `+0x10`, u32 | `0x0c69aa47` | Initial encoded cursor/control word |
| `+0x14`, u32 | `0xbd904c34` | Differs from H1's initial `0xbd904c36` by bit 1 |
| `+0x18`, u32 | `0x31ae0066` | Initial encoded status/control word |
| `+0x1c`, 4 B | No source definition | Unknown |

Stores occur at `0xfffffe000a5a82a8`, `0xfffffe000a5a82fc`, `0xfffffe000a5a8310` and `0xfffffe000a5a831c`. The complete constructor proof covers arbitrary N, rather than only 512. Its original `LSL W9,W12,W9` at `0xfffffe000a5a82c4` uses the low five count bits; the selected count is 1. A separate query verifies the masked shift and zero extension over arbitrary operands. The local lift adds this instruction form without changing frozen parent interpreters. [OS3,OS5]

The G+`0x148` cell again changes role: the prior output pointer is replaced by u32 `0x692` at `0xfffffe000a5a82b8`; G+`0x134` receives 1 at `0xfffffe000a5a82c0`. Frame offsets are phase-dependent scratch storage, rather than a persistent record schema. The complete meanings of the differing stream `+0x14` bits remain unknown. [OS4]

Each null-return control takes 1,071 new source visits. At `0xfffffe000a5a921c`, 32 byte stores overwrite H1 in reverse address order, offsets 31 down to 0. The bytes are a nonzero overwrite pattern, not a zero fill. The path stops before `_IOFreeTypeImpl` at `0xfffffe000a5a92e4`, X0=`0xfffffe000847bba0`, X1=H1, modifier `0x4d6a`. This distinct static free view has name `site.FPByteArrayStreamInternal`, flags `0x64` and size 32 B. No actual free or post-free result is supplied. H2 remains entirely undefined in the null controls. [OS4,OS6]

## Reused W+0x60 record and matching decoder

C=W+`0x60` is reused for the next private operation. At `0xfffffe000a5a8508`, X0=C and X1=FP-`0x68`=G+`0x1e8`. The original slot is `0xfffffe000847ab18`, chained word `0x80102bbe0369ae38`, target `0xfffffe000a69ee38`, IA diversity `0x2bbe`. It remains a pending call in all eight distinct-object cases. [OS4,OS6]

Let m=R.u32[`+0x08`] (mode), j=R.u32[`+0x0c`] (marker), p=the current W24 phase, and t=u32[FP-`0xe4`]. The marshalling slice `0xfffffe000a5a8320..0xfffffe000a5a8450` reads R+0, R+8 and R+12. It does not read the generated word at R+`0x10`. All following scalar operations are modulo 2^32. [OS3-OS5]

```text
K(C) = (low32(C) XOR 0x6133a0c8) * 0x84d77373
f(t) = ((t XOR 0x2ef3cd08) + 0xd10c32f8)
       XOR ((t XOR 0xfab34999) + 0x054cb667)
       XOR ((t XOR 0xe5ee84f7) + 0x1a117b09)
```

| Record field | Written value / normalized consumer |
| --- | --- |
| C+`0x00`, u64 | H2, output stream |
| C+`0x08`, u64 | A, auxiliary base |
| C+`0x10`, u64 | W+`0x100`, workspace subspan |
| C+`0x18`, u32 | C18+K = m+`0x10289de0` |
| C+`0x1c`, u32 | C1c+K = j*`0x59c51537`+`0x4f301f03` |
| C+`0x20`, u32 | Later caller-read result cell; this pack does not write it |
| C+`0x28`, u64 | W+`0x4000`, workspace end |
| C+`0x30`, u32 | C30-K = f(t)+`0x492f18ff` |
| C+`0x34`, u32 | C34 XOR K = p+`0xfaf7b49c` |
| C+`0x38`, u64 | H1, input stream |
| C+`0x40`, u64 | A+`0x1000`, auxiliary end |
| C+`0x48`, u64 | Task from R+0 |

The key is proved from the original caller arithmetic at `0xfffffe000a5a838c..0xfffffe000a5a83c0`. A separately lifted inner prefix at `0xfffffe000a68920c..0xfffffe000a689244` derives exactly the same K from incoming C, removes the key and stores the four normalized words at inner-SP+`0x314`, `0x408`, `0x350` and `0x45c`, respectively. The source proof composes this decoder with the caller pack over arbitrary C, mode, marker, prior word and phase under OS-A4. These are established representations; full operation-level field meanings remain unknown. [OS3,OS5]

In the selected baseline epoch, m=2, j=`0xb4d3a486`, p=`0x667`. The four normalized words are `0x10289de2`, `0xb64575cd`, `0x1781189a` and `0xfaf7bb03`. The latter two are not assigned protocol/version meanings. The task pointer is a private record field; no transfer of a Mach right follows from this store. [OS4]

## Final text function and selected adapter targets

The adapter is the final `LC_FUNCTION_STARTS` entry. Its complete body is `0xfffffe000a69ee38..0xfffffe000a69f064`, 139 instructions / 556 B, ending in RETAB. The `__text` end and `__auth_stubs` start both equal `0xfffffe000a69f064`. A next-function-only extractor fails at this terminal entry; this increment bounds it with the original text section instead. This is a capture boundary correction, not an inferred extension into stubs. [OS1,OS3,OS6]

Five source cuts prove their byte addressing and index arithmetic over arbitrary u32 selector inputs. Exhaustive original bank identities then resolve all 1,280 low-byte inputs. Controller values may differ at each read; immutable array correspondence is OS-A5. [OS5-OS6]

| Adapter selection | Pool/table index | Original pointer target / effective access |
| --- | --- | --- |
| First controller address | POOL `0x161` | `0xfffffe000ccc30dc`; LDUR/STUR at -4 accesses `0xfffffe000ccc30d8` |
| Second controller address | POOL `0x1c` | `0xfffffe000ccc32fc`; LDUR/STUR at -4 accesses `0xfffffe000ccc32f8` |
| Published arithmetic word | POOL `0x141` | `0xfffffe000ccc32f4`; STUR at -4 writes `0xfffffe000ccc32f0` |
| Inner function | TABLE `0xf2d` | `0xfffffe000a6890dc`; slot `0xfffffe000847a888`, IA diversity `0x4d6a` |
| Inner table base | POOL `0x33` | TABLE+12; final LDUR offset -12 cancels the bias |

The adapter updates the first two mutable controller globals at `0xfffffe000a69ef24` and `0xfffffe000a69ef28`. It publishes an affine function of the caller-cell word to `0xfffffe000ccc32f0` at `0xfffffe000a69ef74`. The selected caller read that same word at `0xfffffe000a5a84b4` and copied it to FP-`0x68` at `0xfffffe000a5a84b8`. The retained original epoch supplies `0x8137bc5b6dfd9a21`; this image/fixture value is not a universal runtime constant. The adapter proof quantifies over arbitrary captured S. [OS4-OS6]

The shared import at `0xfffffe000847c618` selects `__chkstk_darwin` at `0xfffffe000a5a1cc4`; the adapter calls it at `0xfffffe000a69ef94` with the derived private size in X8/X9. The [previous stack-adapter report](core_stack_delta_abi_report.md) establishes the bounded small-probe contract for this exact import/body. The present continuation does not execute the probe or assume that ordinary caller-clobbered registers survive arbitrary callees. [OS6-OS7]

## Header, private stack reservation and exported delta

Let F be adapter-entry SP, also the caller's pre-call SP. The fixed prologue uses 48+16=64 B, so its body SP is K=F-64 B and FP=F-16 B. Let S=u64[X1] captured into X21. Arithmetic is modulo 2^64 until the stated u32/low16 projection. [OS3,OS5]

```text
P = S * 0x2e95 + 1
A = ((P >> 56) AND 0xf0) + 16       # bytes, aligned 16; 16 <= A <= 256
H = F - 64 - A                     # private header / inner argument X1
u64[H] = S - 0xb0                  # adapter initialization
u64[H] += 0xb0                     # inner entry, before record decoding
```

The inner call at `0xfffffe000a69f03c` receives X0=the original record and X1=H, conditional on the exact probe contract and ordinary return. The inner entry reserves a further `0x660` B fixed frame and restores the header at `0xfffffe000a689200..0xfffffe000a68920c`. This proves entry restoration, not preservation through the remaining inner routine. Neither an actual complete inner result nor a normal return is modeled. [OS3,OS5,OS7]

On an ordinary inner return, let Q=u32[H]. The adapter's original `SUB W8,W8,W21; UBFIZ X8,X8,#4,#16` and store through saved X19 implement: [OS5]

```text
D = 16 * ((Q - low32(S)) mod 65536)  # bytes
u64[caller_cell] = D
0 <= D <= 1048560 B; D mod 16 = 0
D == 0 iff low16(Q) == low16(S)
```

The maximum is 16 B*65,535=1,048,560 B (`0xffff0`). Upper header bits do not affect D. The adapter resets SP to FP-32 B, restores its saved pairs and applies the literal 48 B final writeback, recovering F independently of D. Only the caller suffix at `0xfffffe000a5a8514..0xfffffe000a5a8524` then adds D to its own SP. At `0xfffffe000a5a8524`, it separately reads C+`0x20` into W14 for the following status comparison. Incidental X0, the caller-cell delta, private reservation A and record result are distinct channels. Actual zero delta remains unknown. [OS3,OS5,OS7]

Neither source continuation writes output-B. The distinct-object cases stop before the adapter; the separate static prefix/adapter proofs do not establish later output stores, final output count, cleanup completion, UserClient copyback, a new port or any IPC emission. The full cross-layer goal remains active.

## Provenance and verification

| ID | Primary evidence |
| --- | --- |
| OS1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`; original compiler/section boundaries. |
| OS2 | Parent reader receipt SHA256 `6d716dcc1ffc8a2d2d19f078a433f130b3e387198894c5fce291ae825c46b9ed`, with transitive strict/preparation/dispatcher pins. Eight parent cases are freshly reproduced for each new return fixture. |
| OS3 | [Extractor and local A64 lift](triage_evidence/recover_versioned_output_stream.py): 27 UNSAT queries, 198 lifted instruction instances, complete 139-instruction adapter and 90-instruction inner prefix. |
| OS4 | [Compressed receipt](triage_evidence/versioned_output_stream_checks.json.zst): 16 cases, 10,064 new instruction visits, 6,688 read bytes, 3,424 write bytes and 296 recorded authenticated transfers. The earlier reader-prefix visits are excluded from these new totals. |
| OS5 | Source equations cover arbitrary-capacity construction, register shifts, caller key/record pack, matching decoder, affine word, private size, header entry restoration, exported delta and caller delta/status channels. Bank-cut address/index proofs compose with exhaustive original tables. |
| OS6 | Five original bank rules, 1,280 inputs, terminal text/stub boundary, original authenticated call/import records and the null-cleanup type view. |
| OS7 | [Publication verifier](triage_evidence/verify_versioned_output_stream_publication.py): fresh extraction/proof equality, independent byte epochs and snapshots, exact publication delta, original-file preservation and decoded-content/path checks. Original files suffice; no new IDA access or native execution occurs. |

The independent epoch check covers 10,064 original instruction words, 6,688 read bytes (64 symbolic), 3,424 write bytes (32 symbolic) and 2,304 snapshot bytes. The inherited arbitrary bytes retain their source identities; no new origin or allocator-initialized byte is introduced. The 32 B null-path overwrite includes the previously unspecified 4 B object tail. [OS4,OS7]

Run the extractor, verify/compress the receipt with zstd level 22, refresh the manifest, and run the publication verifier with the pinned project dependencies. Cost is O(receipt bytes+C*V+I+256R) time/space plus solver cost, capped at 30 s/query. Each new case is bounded at 2,000 source steps.

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Follow `0xfffffe000a6890dc` to its first output-B write and result producer. | Original branch selections, stream getters/writers and C+`0x20` reaching definitions. |
| High | Establish final header preservation. | Inner stores/calls and aliases against H's low 2 B on reaching return paths; entry restoration alone is insufficient. |
| High | Join output count and cleanup with selector-21 copyback. | Source return path, R+`0x40` update, wrapper copyback and UserClient status gate. |
| High | Establish native build/task/connection/right pairing. | A matched actual transaction and ownership epoch; source record task pointers do not provide it. |
| Medium | Generalize terminal-function extraction locally. | Compiler starts plus exact text-end/stub boundaries, with rejection of non-text captures; frozen parent extractors remain unchanged here. |

- **QG1**: Pass. Factual source/interface analysis requires no normative content.
- **QG2**: Pass. OS-A1..OS-A7 register premises, dependent results and falsification probes.
- **QG3**: Pass for this increment. Construction, null cleanup frontier, marshalling/decoder, terminal-function bounds and private stack/result ABI are covered. The full goal remains active.
- **QG4**: Pass. u32/u64 arithmetic, 28/32 B definitions, 139*4=556 B capture, 16..256 B reservation and 16*65,535 B delta maximum are explicit.
- **QG5**: Pass. Source paths, modeled returns, object/data storage, frame phases, header entry/final state, status and stack delta remain distinct.
- **QG6**: Pass. Original bytes/chains, pinned receipts, arbitrary-input equations, exhaustive tables and independent byte epochs supply scoped provenance.
- **QG7**: Pass. Remaining inner/output, header, copyback, extraction and native-pairing work is bounded and impact-ranked above.
