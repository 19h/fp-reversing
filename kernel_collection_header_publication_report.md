# Kernel-collection header publication behind the logging boundary

The pointer consumed by logging at `0xfffffe0007f8b528` belongs to a kernel-collection header bank. Original boot code calls an indexed publisher with kind 1, a derived collection-header pointer and slide. The publisher records the header, slide and minimum LC_SEGMENT_64 VM address plus slide; its paired getter uses the same kind mapping. Nine local source queries, 70 independently replayed CPU cases and two rejected source mutations establish this contract. The previous continuous startup still contains its poisoned fixture and remains unchanged at the logging read; full native boot custody is unknown. [KC-A1-KC-A7]

```text
original boot initializer 0xfffffe000c66058c
  slide = linked kernel header - first segment VM address
  collection header = linked root header + slide
  intervening original fixup logic: captured, not executed here
  BL 0xfffffe000c6626e4 (W0=1, X1=header, X2=slide)
    kind map -> header / slide / minimum-address banks
      kind getter 0xfffffe000c5e5600
      original main -> early registration helper
      logger -> header+12 comparison with 12
```

Primary evidence: original kernel collection SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`; [source and census](triage_evidence/kernel_collection_header_publication_checks.json.zst); [proof/CPU audit](triage_evidence/kernel_collection_header_publication_audit.json.zst); and the preserved [continuous logging result](kernel_early_logging_execution_report.md). All claims use the original bytes; no IDB was queried or changed. Setter/getter names below are recovered roles, not exact nlist names. The original diagnostic strings are `Invalid KC Kind @%s:%d` and `kcformat.c`.

| Source | Recovered interface / evidence |
| --- | --- |
| `0xfffffe000c6626e4..0xfffffe000c662920` | 143-word publisher: W0 kind, X1 header pointer, X2 slide |
| `0xfffffe000c5e5600..0xfffffe000c5e5688` | 34-word getter: W0 kind, X0 selected header pointer |
| `0xfffffe000c66058c..0xfffffe000c660ad4` | 338-word boot initializer; pointer/slide prefix and direct publisher call captured |
| `0xfffffe000c660a54` | Sole direct publisher branch found in the scoped census; W0=1, X1=X20, X2=X19 |
| `0xfffffe000c639a94` / `0xfffffe000c639a98` | Original main loads bank 0 and passes it to helper `0xfffffe000c47cce0` |
| `0xfffffe000c47cce0` | Header-command consumer: count at +16, commands at +32, IDs 0x19 and 0x80000035 inspected; full registration effects unexecuted here |
| `0xfffffe000c48fc90` / `0xfffffe000c48fc98` | Logger loads bank 0, then reads the header word at +12 before comparing with 12 |

The kind gate computes `u32(W0-1)` and rejects values at least 3. Thus only low-32-bit kinds 1,2,3 return normally; upper X0 bits are ignored. Original u64 map entries at `0xfffffe00070303b0` are 0,1,3. The source's signed-32-bit offset checks select ordinary pointers for these three map values; the recovered contract does not extend to altered maps. Each selected field is u64, with an 8 B stride. [KC-A1-KC-A4]

| Low-32-bit kind | Bank index | Header slot | Slide slot | Minimum-address slot |
| --- | ---: | --- | --- | --- |
| 1 | 0 | `0xfffffe0007f8b528` | `0xfffffe0007f8b548` | `0xfffffe0007f8b568` |
| 2 | 1 | `0xfffffe0007f8b530` | `0xfffffe0007f8b550` | `0xfffffe0007f8b570` |
| 3 | 3 | `0xfffffe0007f8b540` | `0xfffffe0007f8b560` | `0xfffffe0007f8b580` |
| Unselected index 2 | 2 | `0xfffffe0007f8b538` | `0xfffffe0007f8b558` | `0xfffffe0007f8b578` |

Let `H` be the caller's header pointer, `S` the u64 slide and `M` the unsigned minimum of the u64 values at command+24 for every command whose ID is 0x19. The publisher stores `H`, `S` and `(M+S) mod 2^64` in the selected row. It reads the u32 command count at H+16, begins at H+32 and advances by each command's u32 size at +4. With no matching segment command, M remains UINT64_MAX, so the third field is `(S-1) mod 2^64`. The source uses an eight-command loop plus a remainder; finite cases exercise both. Command bounds/validity remain explicit input premises, not properties established by this helper. [KC-A3-KC-A5]

For each successful setter case, exactly 24 B of the 96 B bank area are updated; all other 72 B, including the unselected index-2 cells, retain their declared initial bytes. Each corresponding getter case starts from the setter's exact 96 B result. Invalid kinds stop before the original panic BL at `0xfffffe000c66291c` or `0xfffffe000c5e5684`; they neither read header data nor change bank bytes. Those stops are not returns, so callee-saved restoration is asserted only for normally returning cases.

The boot prefix loads the first segment VM address from `0xfffffe000700c038` and derives `X19 = 0xfffffe000700c000 - value`, `X20 = 0xfffffe0007004000 + X19`, modulo 2^64. A source query proves these equations for every u64 loaded value. In the pinned image, that segment VM address is `0xfffffe000700c000`, hence slide 0 and collection header `0xfffffe0007004000`. The actual 26848 B header/command block has 375 commands, including nine segments; its minimum segment VM address is the same root-header address. A kind-1 setter case therefore publishes that root pointer, zero slide and that minimum address. This resolves the object role and producer formula without claiming execution of the intervening boot fixups. [KC-A1-KC-A2, KC-A5-KC-A6]

The census examines all 2558561 aligned words in the three named file-backed kernel executable segments `__TEXT_EXEC`, `__TEXT_BOOT_EXEC` and `__KLD`. It finds one direct B/BL to the publisher and 32 adjacent ADRP/LDR pairs addressing the primary header slot. This is completeness for those instruction patterns within those segments. It excludes nonadjacent references, aliases, indirect calls and other fileset images; absence of another simple store is not a universal no-other-writer claim. The earlier longer-window exploratory scan found an additional load candidate, which is outside the retained adjacent-pair census. [KC-A1-KC-A2]

The 70 CPU components are 35 setter/getter pairs: eight header layouts, four kind/slide selections per layout and three invalid kinds. Layouts cover no commands, ignored commands, one segment, 7/8/9 commands, 16 segments and the actual original collection. The four selections are kind 1/slide 0, kind 2/slide 0x12345000, kind 3/slide UINT64_MAX and X0=0x100000001/slide 0x1000. Synthetic records exercise source behavior and are not attested native files. Each pair is two separately declared caller cases sharing exact bank bytes; 32 pairs return normally and three stop at their respective panic boundaries. Full native caller/boot epoch continuity remains unknown.

Nine nonvacuous QF_AUFBV source obligations cover the kind gate, three header/slide publications with bank preservation, three mapped getters, the empty-minimum sentinel publication and the boot pointer/slide formula. They cover 166 instruction instances at 68 distinct PCs. They do not constitute a universal proof of the complete load-command loop. Independent host parsing and fresh CPU replay cover that loop over the finite layouts.

All 11965 source visits, 3700 reads and 184 writes replay independently. The replay compares all 31 final general registers, SP, NZCV, all 96 bank bytes and the complete 1048576 B private-RAM digest per component: 6720 bank bytes and 73400320 private bytes across the matrix. There are 318 semantic assertions and 35 exact setter-result/getter-input bank handoffs, including the three invalid-kind pairs whose getters do not read the banks. NOP controls at header store `0xfffffe000c662744` and minimum-address store `0xfffffe000c6627dc` preserve the declared initial fields and fail the bank oracle. No native boot/IPC operation executes.

The [continuous logging case](kernel_early_logging_execution_report.md) remains unchanged: its slot is still the inherited poisoned fixture, so the pending dereference is not silently repaired. The next concrete integration requires source-produced boot-state custody and qualification of the earlier registration helper currently represented by a retained no-RAM leaf contract. Neither the header pointer nor its publisher is a Mach-port emitter in this evidence. Native right/message identities and FairPlay transaction correspondence remain unknown. [KC-A6-KC-A7]

| Artifact | Logical SHA-256 |
| --- | --- |
| `kernel_collection_header_publication_checks.json` | `2c7dbd22ad753073b62080426aeb1327c442161a3a3080912015330e8db818c3` |
| `kernel_collection_header_publication_audit.json` | `419cd2452ad7d9776a140b0a8991aaadbf69fa74c23d72d6d15054db230f55cc` |

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| KC-A1: Pinned collection defines source, map and records | All source/header claims | Rebuild byte capture, map, header and original diagnostics; reject image drift |
| KC-A2: Scoped direct-pattern census defines caller/reference coverage | Caller and adjacent-load counts | Rescan all named executable words; extend separately for aliases, other images and indirect control |
| KC-A3: Original kind map is immutable in these cases | Bank selection and frame conditions | Verify exact 0,1,3 u64 map; preserve all 96 bank bytes outside selected stores |
| KC-A4: Supported architectural semantics and logical PAC bound source execution | Source lemmas and returns | Fresh independent CPU replay, full registers/RAM and NOP controls; hardware authentication unknown |
| KC-A5: Header records have the declared bounded command layouts | Minimum-address calculation and finite loops | Independent command parser; zero/ignored/7/8/9/16-command and original-header cases; no native malformed-input admission claim |
| KC-A6: Separate publisher/getter cases do not establish full boot continuity | Application to the poisoned logging case | Execute/qualify intervening boot fixups and registration effects before composing a new startup state |
| KC-A7: Header custody does not establish Mach/FairPlay transport | IPC limits | Pair native daemon/provider/kernel epochs, rights, payloads, statuses and PCs; unknown |

| Impact | Bounded next work | Discriminating evidence |
| --- | --- | --- |
| High | Qualify original early registration on the published collection header | Command/segment/fileset effects replacing the retained no-RAM leaf premise |
| High | Compose a source-produced boot-state startup case | Explicit bank handoff, preserved old poisoned regression case and verified logger return |
| High | Continue nonzero timer, CPU and Mach startup | Original return/conversion and actual right emission/custody |
| Medium | Resolve kinds 2/3 and header-bank consumers | Native callers, image identity, lifetimes and additional getter references |
| Medium | Extend producer/reference census | Nonadjacent/aliased/indirect and other-fileset coverage |

**QG1**: Factual technical analysis; no normative content required. **QG2**: KC-A1-KC-A7 list dependencies and falsification probes. **QG3**: Slot nature, source producer/getter, map, caller, arithmetic, finite memory effects and continuous/Mach limits covered; full goal active. **QG4**: u32/u64 domains, byte strides/extents and modular arithmetic explicit. Work is linear in scanned/source/command/journal/RAM bytes; SMT search separate. **QG5**: Returning/panic cases, valid low bits/ignored upper bits, synthetic/original headers and separate/native epochs distinguished. **QG6**: Original bytes, census, source queries, independent host parsing/CPU replay and source mutations retained. **QG7**: Impact-ranked bounded continuation included.
