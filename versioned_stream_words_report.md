# Selector-21 stream words, header tests and output-stream preparation

A separate symbolic source continuation now passes the prior frame-read frontier without choosing values for the missing bytes. It reads all 12 B before the marker, decodes canonical u32 words `0x00fb1958`, `4` and `1`, and prepares the existing output-B buffer and capacity 512 B before a second 32 B stream allocation. Six new frame words retain coherent arbitrary byte origins; the original W24 origin is also retained. On this selected source path, none controls a branch, address, decoded word, non-frame store value or allocation argument. No original guest, second allocator or native transaction executes. [SW1-SW7]

```text
unchanged strict prefix -> original stop before FP-0xe8 read
                            |
                  separate symbolic frame-origin model
                            |
  input-B [0..3] -> word 0 -> low24 / bit30 header checks
          [4..7] -> word 1 -> ones-complement intermediate
         [8..11] -> word 2 -> further selected source control
                            |
                  input cursor field commits +12
                  read R.outputB / R.capacity
                            |
                  STOP before second 32 B stream allocation
```

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| SW-A1 | Hash-pinned KC, normalized kext and prior receipts identify these builds and epochs. All joins depend on it. | Fresh original/normalized instruction agreement, original pointer decoding and receipt/dependency hashes. Changed builds invalidate this mapping. |
| SW-A2 | The prior declared fresh distinct 32 B allocation and ordinary call ABI supply the strict prefix. Reader continuation depends on that premise. | Reproduce all fields of each of the eight prior strict cases, including allocator-register clobbers and their original stop. No second allocation result is modeled. |
| SW-A3 | Missing bytes in the body's 512 B local frame may be represented by independent arbitrary u8 symbols, reused on overlapping/repeated reads. Symbolic continuation depends on this byte model. | Preserve source-defined masks, confirm repeated-read coherence and leave missing cells outside the frame forbidden. No concrete fill or native initialization is asserted. |
| SW-A4 | Fixed cells, input/output spans and declared heap storage retain their stated nonaliasing and nonwrapping ownership. Memory/source equations depend on it. | Independent byte epochs, address checks and two object/frame placements. Native IOKit input/output aliasing remains unknown. |
| SW-A5 | The retained phase is mode 2 with the previously admitted operation and 16 B transformed input. Finite path results depend on it. | Two daemon fixtures, two placements/global fixtures, baseline/generated-word-bit profiles; universal decoder/header equations are separate from finite paths. Other modes' admission is not inferred. |
| SW-A6 | A concrete symbolic expression at each selected observable establishes independence from the arbitrary frame origins within this source model. Path claims depend on its A64 instruction semantics. | Reject unknown address/control/call observations; prohibit symbolic non-frame store values; independently reconstruct byte epochs and re-run all source equations. Native execution equivalence remains unknown. |
| SW-A7 | Matching static type-view fields identify the same allocation class, conditional on runtime bookkeeping and valid native authentication. Allocation interpretation depends on it. | Original name/flags/size and chained pointers; distinct view addresses and unknown native first-pointer state remain explicit. |

## Frame origins and selected-path independence

The earlier [stream-initialization report](versioned_stream_initialization_report.md) stops at `0xfffffe000a5a731c`. This increment reproduces those eight strict prefixes exactly before starting a separate symbolic slice. G is the dispatcher body SP and FP=G+`0x250`. The slice introduces six groups of missing bytes: [SW2-SW4]

| Body-frame word | First new read | Initial model status |
| --- | --- | --- |
| G+`0x168` / FP-`0xe8` | `0xfffffe000a5a731c` | Four unspecified source bytes. |
| G+`0x10c` | `0xfffffe000a5a7340` | Four unspecified source bytes. |
| G+`0x120` | `0xfffffe000a5a7344` | Four unspecified source bytes. |
| G+`0x124` | `0xfffffe000a5a7348` | Four unspecified source bytes. |
| G+`0x9c` | `0xfffffe000a5a7404` | Four unspecified source bytes. |
| G+`0x148` | `0xfffffe000a5a7970` | Four unspecified source bytes. |

Each byte has a stable symbolic identity. Reads do not mark the original bytes initialized; subsequent original stores can define expressions in other frame locations. Together with the earlier arbitrary W24 u32, these are 224 unconstrained origin bits. Source arithmetic and frame copies can retain them, while all selected controls, addresses, decoded words and non-frame store values are concrete. The slice makes no assignment to any origin. This establishes conditional independence on this selected source path, not native definite assignment or a complete operation. [SW3-SW4]

The previously stopped guest and strict symbolic receipts remain unchanged. The new analysis is not a concrete replay through unspecified bytes. Unknown heap bytes, external bytes and addresses remain forbidden. Eight cases add 5,088 reader instruction visits after 1,552 repeated strict-prefix visits, totaling 6,640 post-first-allocation source visits. The preceding preallocation slices are recorded separately. [SW2-SW4]

## Four-byte decoder and header control

The source reads bytes at `0xfffffe000a5a7450`, `0xfffffe000a5a7460`, `0xfffffe000a5a746c` and `0xfffffe000a5a7480`. For arbitrary bytes b0..b3, its resulting W11 is: [SW3,SW5]

```text
canonical = BE32(b0 XOR 0xcd, b1 XOR 0xcd,
                 b2 XOR 0xcd, b3 XOR 0xcd)
W11 = canonical XOR 0x31ae0066
```

This equation is proved over all 2^32 byte combinations from the original instructions, including their mixed masks and final XOR. Canonical is the mathematical normalized word; it is not an additional wire field or native-memory store. The separate index equation recovers the byte index from the source's obfuscated local counter. [SW3,SW5]

| Input-B bytes / offsets | Canonical u32 | Original resulting W11 |
| --- | --- | --- |
| `cd36d495` / 0..3 | `0x00fb1958` | `0x3155193e` |
| `cdcdcdc9` / 4..7 | `4` | `0x31ae0062` |
| `cdcdcdcc` / 8..11 | `1` | `0x31ae0067` |

All eight retained cases read these three groups in order. The first two getter bases are D with relative indices 0 and 4; the third uses the adjusted base D+8 with relative index 0. Their absolute offsets remain 0..11, before the `0x4d` marker at offset 12. The first word's original tests normalize to `(canonical & 0x00ffffff)==0x00fb1958`, followed by `(canonical & 0x40000000)==0`. The latter is specifically bit 30; it is not a check of the entire high byte. [SW3-SW5]

| Source decision | True target / table index | False target / table index |
| --- | --- | --- |
| Low24 match, transfer `0xfffffe000a5a7860` | `0xfffffe000a5a7864` / `0xcc1` | `0xfffffe000a5a7cb8` / `0xc87` |
| Bit30 clear, transfer `0xfffffe000a5a78b8` | `0xfffffe000a5a78bc` / `0xe58` | `0xfffffe000a5a7f40` / `0xe2c` |

The second canonical word is 4. A further proved source projection at `0xfffffe000a5a7954` compares its ones-complement, `0xfffffffb`, with 7; the following CSET uses unsigned higher-than. Treating that intermediate as the ordinary count 4 would invert the relevant comparison. The complete field meaning and the third word's operation-level meaning remain unknown. A protocol/version label is not assigned. [SW3,SW5]

At `0xfffffe000a5a7ff4`, the input stream's `+0x10` word changes from `0x0c69aa47` to `0x0c69aa53`, a modular increase of 12. This is one observed deferred field commit after the three 4 B reads, rather than three credited object-field updates. The source slice does not write input-B. [SW4]

## Output-B preparation and next allocation

Original instructions `0xfffffe000a5a80ec..0xfffffe000a5a80f8` load the previously marshalled argument record R, then R+`0x38` and R+`0x40`. The source equation proves that these become X11 and W12 respectively. The [core-entry contract](versioned_core_entry_report.md) identifies them as the output-B pointer and the copied initial count/capacity. [SW2-SW5]

| Interface field | Established value / location |
| --- | --- |
| Existing output-B storage | R+`0x38`; the retained output-B pointer, distinct from the 32 B stream object |
| Declared capacity | R+`0x40`; 512 B, distinct from the 16 B input count |
| Saved output-B pointer | `STR X11,[SP,#0x148]` at `0xfffffe000a5a816c` |
| Next call | `0xfffffe000a5a8218` -> `_IOMallocTypeImpl`, target `0xfffffe000c4ba154`, modifier `0xd0c8` |
| Allocator argument X0 | Type view `0xfffffe000847b8e0` |
| Type name / flags / requested size | `site.FPByteArrayStreamInternal` / `0x64` / 32 B |
| Captured X1 | Prior input-stream object pointer; not a second argument to this allocator |

The SP+`0x148` slot changes role: an earlier 4 B unspecified word is carried through the parser; the later 8 B store defines an output-buffer pointer in that location. It is not one persistent native field. Two exhaustive bank identities, 512 byte inputs, resolve the allocator and its new type view. The allocator uses the same function-pointer slot as the earlier stream allocation, but a distinct static view address. Matching names/flags/sizes do not establish native bookkeeping equivalence. [SW4-SW6]

The second allocation remains pending. No new output buffer, output-B byte write, updated output count, completed UserClient response, Mach port or IPC emission is established here. The source has prepared a stream wrapper for the existing output-B storage; it has not allocated a new 512 B data buffer.

## Provenance and verification

| ID | Primary evidence |
| --- | --- |
| SW1 | Original KC SHA256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; normalized kext `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c`. |
| SW2 | Parent stream receipt SHA256 `be35ea79704879200c95fb057b0d7a8cb4809c55405238b5affa4fde6fc9efff`, plus the pinned dispatcher/preparation receipts. Every selected strict prefix is re-derived and compared field-for-field. |
| SW3 | [Extractor and symbolic reader](triage_evidence/recover_versioned_stream_words.py): coherent missing-byte origins, six UNSAT source equations / 89 lifted instructions, strict unknown-observable and non-frame-store checks. |
| SW4 | [Compressed receipt](triage_evidence/versioned_stream_words_checks.json.zst): eight cases, 6,640 source visits, 4,992 read bytes, 1,696 write bytes, 272 source-slice authenticated transfers and 24 decoded word observations. Source initialization is never inferred for the 192 origin-byte entries across the eight cases. |
| SW5 | Universal four-byte decoder/index, low24/bit30 guards, second-word complement projection and output-B field equations; finite words/cursor updates are separately recorded. |
| SW6 | Two exhaustive bank rules / 512 inputs, eight pending allocator pointer checks, four static header-control slots and the original third stream type view. |
| SW7 | [Publication verifier](triage_evidence/verify_versioned_stream_words_publication.py): fresh case/proof equality, independent symbolic byte epochs, repeated-origin coherence, forbidden-read/address controls, exact publication delta, compression and decoded-path hygiene. Original files suffice; no IDA mutation or new guest execution occurs. |

Run the extractor, verify and compress its receipt with zstd level 22, then run the publication verifier with the pinned project dependencies. Time/space cost is O(receipt bytes+C*V+I+256R), plus solver cost capped at 30 s/query. Each new reader continuation is bounded at 2,000 source steps.

| Impact | Further bounded work | Required evidence |
| --- | --- | --- |
| High | Follow the second stream's initialization and first output write. | Declared allocation contract, exact output cursor/count fields, cleanup and copyback source. |
| High | Recover the three words' complete operation semantics. | Selected consumer transitions, additional source-defined messages and producer correspondence beyond this finite payload. |
| High | Establish native daemon/UserClient admission, right ownership and pairing. | Matching build/task/connection/right epoch and an actual transaction. |
| Medium | Resolve native frame definitions and typed-view initialization. | Reachable predecessor writers and runtime view state; symbolic nondependence does not prove initialization. |

- **QG1**: Pass. Factual source/interface analysis requires no normative content.
- **QG2**: Pass. SW-A1..SW-A7 register premises, dependencies and falsification probes.
- **QG3**: Pass for this increment. Symbolic frame provenance, reader decoding/control, cursor commit and output-stream ABI are covered; the full goal remains active.
- **QG4**: Pass. Byte extents, BE32 normalization, u32 arithmetic, unsigned comparisons and old/new visit counts are explicit.
- **QG5**: Pass. Strict fixtures, arbitrary origins, canonical/encoded/complement words and pending/native results are distinct.
- **QG6**: Pass. Original bytes, pinned epochs, source equations, static chains and model premises are traceable.
- **QG7**: Pass. Further data/control/output and native-ownership work is bounded and impact-ranked above.
