# Full private boot initializer and collection-state publication

The original boot initializer now returns in a complete raw-image private CPU case after 43400376 source visits. It performs all 1036413 fixup stores, publishes the primary collection-header bank, visits 362 child images, applies 511000 zero-slide metadata stores, publishes four root range words and stores the boot slide. Independent replay matches every streamed instruction/read/write/fixup/PAC receipt, all final GPRs/SP/NZCV, private RAM and all 4967 mapped image pages. The final image equals the corrected fixup projection plus eight declared global words. Hardware PAC, native boot and composition into the existing continuous startup case remain unknown. [BE-A1-BE-A7]

```text
raw pinned collection + declared private registers/stack
  -> original boot initializer
  -> 1036413 original fixup stores, logical PAC
  -> kind-1 header/slide/minimum bank publication
  -> root command walk
       +-> 362 child command/symbol walks, then return
       +-> root segment/section/fileset slide stores
  -> four root range words
  -> boot-slide global and initializer return
  -> complete independent replay + corrected-image/global oracle

existing continuous logging case: preserved, no state handoff yet
```

Primary evidence is collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`, [captured source and root segment/global receipts](triage_evidence/kernel_boot_initializer_execution_checks.json.zst), [proof/execution/replay/image audit](triage_evidence/kernel_boot_initializer_execution_audit.json.zst), and the original raw bytes read by the [recovery module](triage_evidence/recover_kernel_boot_initializer_execution.py). The [producer](triage_evidence/probe_kernel_boot_initializer_execution.py), [independent replay](triage_evidence/replay_kernel_boot_initializer_execution.py), [audit](triage_evidence/audit_kernel_boot_initializer_execution.py) and [delivery verifier](triage_evidence/verify_kernel_boot_initializer_execution_delivery.py) reproduce the case. Earlier [fixup projection](kernel_boot_fixup_projection_report.md), [initializer-pointer signing](kernel_initializer_pointer_signing_report.md) and [logging execution](kernel_early_logging_execution_report.md) retain their separate scope. Original inputs and the shared historical page reader remain unchanged. No IDB was queried or changed.

| Function entry | Recovered role | Captured words / executed distinct PCs |
| --- | --- | ---: |
| `0xfffffe000c66058c` | Boot initializer: discover collection/slide, fix pointers, publish state and return | 338 / 287 |
| `0xfffffe000c6626e4` | Kind-selected collection-header/slide/minimum publisher | 143 / 129 |
| `0xfffffe000c660e6c` | Root segment/section/fileset relocation, optional child traversal and range publication | 223 / 184 |
| `0xfffffe000c660bf8` | Child segment/section relocation and selected nlist64 value adjustment | 157 / 138 |
| Total | Four original compiler-bounded bodies | 861 / 738 |

These names describe recovered behavior; no exact original symbol was found at the four entries. The capture contains 3444 B. Unvisited branches remain captured source, not executed coverage. This case begins at the boot initializer, after the earlier cold-entry caller's admission. It does not execute the complete cold entry or later kernel main. [BE-A1-BE-A3]

The CPU maps 1048576 B of zeroed private RAM at `0x6a00000000`, initializes SP=`0x6a000f0000`, LR=`0x6a000ff000`, NZCV=0 and all other GPRs to the recorded deterministic u64 pattern. Raw collection pages are mapped lazily with emulator read/write/execute permission; this models byte access, not native page protection. The raw stack-guard cell at `0xfffffe000cacb000` is zero. PACIBSP/RETAB are logical call-frame envelopes; IA/DA pointer-signing instructions retain logical target bits after validating target, modifier and key. No native key or cryptographic signature is supplied. Under these premises the initializer derives slide zero and root header `0xfffffe0007004000`, then executes every loop iteration without contraction or synthesized loop result. [BE-A1-BE-A3]

| Executed quantity | Exact count |
| --- | ---: |
| Source visits | 43400376 |
| Source reads / writes | 4664940 / 1548546 |
| Original nonoverlapping 8 B fixup stores | 1036413 |
| Fixup target extent | 8291304 B |
| IA / DA logical signing instructions | 908962 / 2741 |
| PACIBSP / RETAB envelopes | 3 / 3 |
| Original function entries | 365 |
| Boot / bank / range / child entries | 1 / 1 / 1 / 362 |
| Zero-slide image stores | 511000 |
| Published global words / domain | 8 / 64 B |
| Remaining private-stack write events | 1125 |
| Final mapped image pages / extent | 4967 / 20344832 B |
| Private RAM compared | 1048576 B |

Fixup admission and calculation retain the earlier source contract: format 8 in this corpus, cache level zero, base plus low 30 bits, bit-63 signing selection, packed key/diversity/address-diversity modifier, and next step four times the 12-bit next field. Every original encoded word is checked against ordered parser metadata at its load, every signing input against that word's target/modifier/key, and every u64 store before and after execution. A separately decoded 39 B-per-record stream matches the CPU's complete fixup stream and all 681 prior chain-page receipts. All eight page-crossing pointers are actually stored across their page boundary. No IB/DB signing instruction occurs in this corpus; their retained local source proofs remain separate. [BE-A2-BE-A4]

At the kind-1 bank call, X0=1, X1=`0xfffffe0007004000`, X2=0 and LR=`0xfffffe000c660a58`. The later range call has X0=root header, X1=slide zero, W2=0, X3..X6=`0xfffffe0007e6d160`, `0xfffffe0007e6d168`, `0xfffffe0007e6d170`, `0xfffffe0007e6d178`; X7 and two stack output-pointer arguments are null. LR=`0xfffffe000c660a90`. The actual call entries are retained with all eight register arguments, SP and visit index. Every child call receives its original fileset header in X0, zero slide in X1 and LR=`0xfffffe000c660f34`. [BE-A3-BE-A5]

| Source store PC | Image field / role | Stores |
| --- | --- | ---: |
| `0xfffffe000c660974` | Fixup pointer slot | 1036413 |
| `0xfffffe000c660f4c` | Root segment_command_64.vmaddr, command+24 | 9 |
| `0xfffffe000c660f68` | Root section_64.addr, section+32 | 2 |
| `0xfffffe000c660eec` | Fileset entry vmaddr, command+8 | 362 |
| `0xfffffe000c660db8` | Child segment_command_64.vmaddr, command+24 | 1836 |
| `0xfffffe000c660dd4` | Child section_64.addr, section+32 | 4746 |
| `0xfffffe000c660e58` | Selected child nlist64.n_value, entry+8 | 504045 |
| `0xfffffe000c662744`, `0xfffffe000c662764`, `0xfffffe000c6627dc` | Primary header, slide, minimum bank words | 3 |
| `0xfffffe000c661180`, `0xfffffe000c661190`, `0xfffffe000c661198`, `0xfffffe000c6611a4` | Four requested range words | 4 |
| `0xfffffe000c660a94` | Boot-slide word | 1 |

The root helper adds slide modulo 2^64 to root segment vmaddr, section addr and fileset vmaddr. Mode bit 0 bypasses the child call when set, while retaining the fileset vmaddr update. This case uses mode zero, traversing all 362 children. The child helper adjusts its segment/section fields and derives the symbol table from relocated __LINKEDIT.vmaddr + LC_SYMTAB.symoff - __LINKEDIT.fileoff. It advances nlist64 entries by 16 B and adds slide to n_value only when the unsigned n_type byte at entry+4 is at most 0x1f. All 504045 encountered symbols meet that predicate in this pinned case. These are mechanical field relations; symbol binding validity and arbitrary malformed-table admission are not established. [BE-A1-BE-A5]

Independent raw load-command/symbol parsing reproduces the six metadata-store PC counts, all child header arguments and each child's segment/section/symbol counts. The source performs 511000 metadata writes even though slide is zero; the producer checks every such write against the original raw u64. Therefore these stores preserve bytes in this case. This is stronger than omitting zero-slide loops in the model, but does not qualify a nonzero-slide whole initializer. [BE-A3-BE-A5]

| Published u64 address | Source-produced value | Recovered meaning |
| --- | --- | --- |
| `0xfffffe0007f8b528` | `0xfffffe0007004000` | Primary collection header |
| `0xfffffe0007f8b548` | `0x0` | Primary bank slide |
| `0xfffffe0007f8b568` | `0xfffffe0007004000` | Primary minimum nonempty root segment address |
| `0xfffffe0007f8b5a8` | `0x0` | Boot slide |
| `0xfffffe0007e6d160` | `0xfffffe0007004000` | Minimum address, all nonempty root segments |
| `0xfffffe0007e6d168` | `0xfffffe000e860000` | Maximum exclusive end, all nonempty root segments |
| `0xfffffe0007e6d170` | `0xfffffe0007004000` | Minimum nonwritable root segment address, excluding __LINKEDIT |
| `0xfffffe0007e6d178` | `0xfffffe000c664000` | Maximum exclusive nonwritable root segment end, excluding __LINKEDIT |

Range classification reads maxprot at segment-command offset 56, rather than initprot at offset 60. The writable mask is maxprot & 2. The all-segment maximum includes __LINKEDIT; the nonwritable pair excludes it. Only root segments feed these aggregates. The publication tail supports seven optional u64 outputs: the four pairs' first four values above, two additional executable-range accumulators and an additional end accumulator. All-nonnull and all-null local source paths are proved; this boot case requests only the first four. No general interpretation or native consumer of the unrequested last three outputs is asserted here. [BE-A2-BE-A5]

| Nonempty root segment | vmaddr | VM size, B | maxprot / initprot |
| --- | --- | ---: | --- |
| __TEXT | `0xfffffe0007004000` | 32768 | 1 / 1 |
| __PRELINK_TEXT | `0xfffffe000700c000` | 14811136 | 1 / 1 |
| __DATA_CONST | `0xfffffe0007e2c000` | 13238272 | 1 / 1 |
| __DATA_SPTM | `0xfffffe0008acc000` | 475136 | 1 / 1 |
| __TEXT_EXEC | `0xfffffe0008b40000` | 61980672 | 5 / 5 |
| __TEXT_BOOT_EXEC | `0xfffffe000c65c000` | 32768 | 5 / 5 |
| __PRELINK_INFO | `0xfffffe000c664000` | 3833856 | 3 / 3 |
| __DATA | `0xfffffe000ca0c000` | 4145152 | 3 / 3 |
| __LINKEDIT | `0xfffffe000ce00000` | 27656192 | 1 / 1 |

For example, the all-segment maximum is `0xfffffe000ce00000 + 27656192 B = 0xfffffe000e860000`. The nonwritable non-__LINKEDIT maximum is the __TEXT_BOOT_EXEC end, `0xfffffe000c65c000 + 32768 B = 0xfffffe000c664000`. These are address intervals and byte extents, not time or performance measurements. [BE-A1-BE-A5]

All 4967 final mapped pages match a separate oracle: start with the corrected logical fixup projection and apply the eight expected u64 global values. This includes every one of the prior 2565 fixup projection pages. Only `0xfffffe0007e6d000` and `0xfffffe0007f8b000` differ from that projection; two of the eight published words already have their zero value. The 64 B figure denotes the publication domain, not 64 changed bytes. X19..X29 and SP return exactly to their declared initial values, and the final boundary is the declared LR sentinel; final NZCV is `0x60000000`. [BE-A3-BE-A5]

Twenty-four nonvacuous QF_AUFBV obligations cover 135 instruction instances at 95 PCs. Thirteen rederive the prior fixup/publisher relations from the newly captured source. Eleven add the six modular slide-store relations, unsigned symbol-type gate, maxprot read/mask, mode gate and seven-output all-null/all-nonnull paths. These local proofs use opaque key-specific signing functions. They are distinct from the concrete complete boot case and do not prove termination or memory safety for arbitrary collection metadata. [BE-A2-BE-A5]

Two fresh single-word NOP controls preserve the positive initial registers/private RAM and all other raw image bytes. Removing the store at `0xfffffe000c660974` is rejected after 5642 source visits with zero fixups stored. Removing the format-8 shift at `0xfffffe000c660994` is rejected after 5656 visits and one fixup: it selects slot `0xfffffe0007e2c272` instead of `0xfffffe0007e2c278`. These controls stop on their first discriminating invariant failure, rather than being presented as complete boot runs. [BE-A4-BE-A5]

The producer retains compact count/hash receipts, not an event-by-event journal of 43 million visits. Little-endian stream encodings are Q PC + 4 instruction bytes; Q PC,Q address,I byte count + exact bytes for reads/writes; the prior 39 B fixup encoding; and Q PC,Q modifier,Q logical target,Q slot for pointer-signing events. Counted PACIBSP/RETAB call-frame envelopes are checked by source replay and final state separately. Independent replay uses a fresh CPU and raw mapping, imports no producer implementation and regenerates all five streams, per-PC counts, call entries, final registers/flags/private RAM and page hashes. The delivery verifier rebuilds the complete producer/replay pair, source obligations, independent corpus/image oracle and both controls. These checks qualify this declared case; matching hashes do not establish universal execution equivalence. [BE-A2-BE-A5]

| Stream | SHA-256 |
| --- | --- |
| Source | `34941792f914f824cfef12433122b82d9d3ed909616197e543c8f0be47bd10e0` |
| Reads | `7cecd665146ae129b1d088e6783ed38dea4fc6df0788c93c85cb370c9d43402d` |
| Writes | `af229728b08871444d23d091629cff512b12eb1cfb098f9516bf0832a756e713` |
| Fixups | `669a923f520e4a9c3f57e3f9e2dbd283e6c9adf29f8bf81b8e1194b1bad48083` |
| Pointer signing | `fa1fd3bc0d8de685c551e4feabd01fe6c0c96ebf0bcaf9019dffe0773fa0239b` |

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_boot_initializer_execution_checks.json` | `b6d865f8f6cea524ce91d98d1c9c0a0befecaa9369d8fe3b7b1260517ef5c0db` |
| `kernel_boot_initializer_execution_audit.json` | `c16129440f9ba3d4df4140d4e74b4c2f939c6fa3d7652fae58d4935927c6333c` |

The previous continuous logging case and all historical journals remain unchanged. Its inherited poisoned header premise is not silently replaced by these source-produced globals. This increment establishes the complete boot initializer's returned private state; the explicit handoff into a newly declared main/startup epoch remains outstanding. Likewise, initializer-pointer signing does not invoke FairPlay constructors. No incoming/outgoing Mach right, message ID, transport status or port-emission location is added here. Native daemon/provider/kext transaction identity remains unknown, and the full interface goal remains active. [BE-A6-BE-A7]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| BE-A1: Pinned original collection defines raw code/metadata/guard | Source, addresses and corpus | Rehash image and every captured body; independently parse root/child headers and symbols |
| BE-A2: Declared AArch64 model and opaque PAC functions bound proof semantics | Local universal relations and logical execution | Reconstruct 24 nonvacuous source obligations; hardware key/signature outcomes unknown |
| BE-A3: Recorded GPRs/SP/NZCV, raw lazy pages, permissive mappings and zeroed private RAM define the case | Complete initializer return and exact counts | Fresh CPU replay from identical premises; cold-entry admission and native permissions unknown |
| BE-A4: Ordered format-8/cache-0 nonoverlapping chains define this profile | All fixup stores and target projection | Match every raw word, PAC input and before/after store; independently rebuild full fixup stream and 681 chain receipts |
| BE-A5: Independent replay/corpus/page oracle plus compact hashes qualify this case | Final state and zero-slide metadata claims | Rebuild 4967 final pages, child counts, globals and both rejected source mutations; arbitrary metadata/nonzero-slide whole boot unproved |
| BE-A6: Earlier startup and shared reader remain frozen | Preservation and continuity boundary | Exact manifest ownership/prior artifact checks; new boot-to-main handoff required before claiming composition |
| BE-A7: Returned private boot state is not callback/native FairPlay execution | Transport and full-goal limits | Establish callback admission/lifecycle and matching rights/messages/statuses across real or explicitly modeled epochs; unknown |

| Impact | Bounded next work | Discriminating evidence |
| --- | --- | --- |
| High | Compose source-produced boot state into a separate main/startup case | Exact raw-to-fixed-to-global page custody and explicit epoch handoff; preserve poisoned regression |
| High | Join module-table signing and FairPlay class initialization | Original caller admission, callback invocation, class object stores and lifecycle effects |
| High | Continue matched daemon/provider/kext IPC | Actual receive/send right custody, descriptors, IDs, result/status and emission sites across the same transaction |
| High | Audit other historical reader consumers mapping crossing pages | Corrected read/write intervals and page hashes; current reader scope is not universal |
| Medium | Broaden boot admission | Nonzero slides, other cache levels, multi-start metadata, malformed bounds, protection transitions and hardware authentication |

Execution/replay time is O(V+R+W+F+P), where V is source visits, R/W are source memory events, F is fixup records and P is mapped-page bytes. Corpus/symbol oracles add linear collection/fixup/symbol work; source-index membership uses the fixed 861-word capture. Retained receipt storage is O(source PCs + call entries + mapped pages + child headers + fixup index), not O(V) event records. The existing image parser retains its million-fixup index; full mapped RAM is 20344832 B plus 1048576 B private RAM. SMT search is separate, bounded to 30 s per query. No native execution speed is inferred.

**QG1**: Factual technical analysis; no normative content required. **QG2**: BE-A1-BE-A7 state dependencies and falsification probes. **QG3**: Complete declared boot call, source helper roles, image/global data flow, control/ABI boundaries and Mach limits covered; full goal active. **QG4**: Counts, byte extents, u64 arithmetic, pointer/field widths and separate source/CPU/corpus totals reproducible. **QG5**: Raw/corrected/executed state, zero-slide writes/changed bytes, logical/native PAC and returned boot/continuous startup distinguished. **QG6**: Pinned raw source, independent complete replay, full corpus/page oracle and source mutations retained. **QG7**: Impact-ranked bounded continuation included.
