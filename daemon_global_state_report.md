# Self-text window selection and encoded global-state interfaces

The globals previously observed at `0x1010CA2A8` and `0x1010C6800` initially hold the daemon specimen's **own `__TEXT,__text` start and size**. The subsequent 411-instruction block selects a bounded window inside that section and replaces them with an encoded window address and length mask. Two other globals receive encoded range/offset values.

For this specimen the window length is **32,768 bytes**. Its relative start offset is **`Q & 0xE21000`**, where Q is the source-defined u64 at F+`0x358`. There are 32 possible offsets for unrestricted Q, determined by bits 12,17,21,22,23. Eight sealed continuations select eight distinct offsets; all 32 occur in isolated source execution. This does not establish a native distribution or complete generator reachability.

The selected window's later readers and its relationship to daemon IPC, driver payloads or integrity checks remain unknown. The callback-revisit frontier at unknown F+`0x4A0` remains unresolved. The full investigation remains active.

## Primary evidence and assumption register

Primary specimen: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are preferred virtual addresses. The [source contracts](triage_evidence/daemon_global_state_contracts.json) retain fourteen source spans, two original fixups, two exhaustive 256-input banks and the original Mach-O section header. The earlier [buffer-consumer](daemon_buffer_consumer_report.md) and [state-generator](daemon_prng_output_report.md) artifacts remain frozen.

The [IDA probe](triage_evidence/daemon_global_state_live_ida.json) and [retry](triage_evidence/daemon_global_state_ida_retry.json) both report an unavailable authenticated bridge worker. **Fresh IDB verification is unavailable for this increment.** Original-image bytes, sealed A64 journals, source proofs and independent isolated execution supply the new evidence; the failed probes are not counted as matching rows.

| ID | Assumption or boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| GS1 | The pinned image is the intended specimen | Section identity, source PCs and codecs | Rehash specimen, source spans and original fixups |
| GS2 | The earlier sealed source contexts apply | Eight observed publications | Recheck all411 block opcodes/visits and match observed values against new compact formulas |
| GS3 | Readable image/header bytes retain the earlier loader model | Self-image metadata | Compare original section fields at offsets 0xD0/0xD8 with guest reads and initial stores |
| GS4 | Header/frame/global cells are valid, mapped and appropriately distinct | Generic source-local memory contracts | Match actual field addresses and widths; scalar proofs do not validate arbitrary pointer mappings |
| GS5 | Recovered entry W9=0x8A9B8560 and shared source bases apply | Prekey and complete block | Record actual registers in a full replay; vary scalar inputs and control-bank inputs in isolation |
| GS6 | Declared API inputs/clobbers and four F/H representations delimit whole-path coverage | Observed Q and selected offsets | Retain zero/reference tuples and address placements; native startup/ASLR remain unknown |
| GS7 | Original fixups supply abstract decoded values | Encoded destination addresses | Verify original format-12 words and all 256 bank inputs; native PAC is not established |
| GS8 | u32/u64 source semantics, including masked variable shifts, are adequate | Floor log2, ranges and codecs | Original/normalized SMT pairs and independent complete-block A64 execution |
| GS9 | `S>16` and P+S does not wrap | Window-containment theorem | Exercise size boundaries; retain 105 isolated cases outside the containment domain |
| GS10 | Q is an unrestricted u64 for generic offset statements |32 possible current-image offsets | Enumerate all 32 offsets with two upper-word values; actual generator/native distributions remain unknown |
| GS11 | Source-local normalization identities compose at explicit boundaries | Compact411-instruction semantics | Prove prekey, log, comparison phase, split, intermediate XOR and all four publication codecs |
| GS12 | No concurrent writer interleaves with the selected sequence | Temporal global roles | Census readers/writers and synchronization; observed order alone does not prove a native publication protocol |
| GS13 | Live-IDB corroboration is unavailable | Provenance boundary | Preserve both failed bridge probes; refresh live bytes when the bridge is available |
| GS14 | Earlier evidence remains frozen except six reporting/publisher paths | Preservation | Check 3,134 prior artifacts, exactly six changes and the three original supplied inputs |

Whole-path observations depend on GS1-GS8. Containment additionally requires GS9. Possible-offset statements use GS10; source composition uses GS11. Native lifetime/concurrency remain bounded by GS12, and GS13 is a verification limitation rather than a supporting premise.

## Section metadata and source publication

The original `section_64` header at file offset `0xB0` identifies `__TEXT,__text`:

| Field | File / guest address | Value |
| --- | --- | --- |
| Section header | File `0xB0`; selected guest `0x1000000B0` |80-byte `section_64` |
| `addr`, offset+32 | File `0xD0`; guest `0x1000000D0` | `0x100001058` |
| `size`, offset+40 | File `0xD8`; guest `0x1000000D8` | `0xE297A8` =14,849,960 bytes |
| Section end, exclusive | addr+size | `0x100E2A800` |
| Segment `vmaddr` field | Selected guest `0x100000080` | `0x100000000` |

Source `0x10031ED34..0x10031ED64` reads the segment vmaddr and section addr/size. Its generic scalar rule is:

```text
P = u64(section_addr + runtime_base - segment_vmaddr)
S = section_size
```

It stores P into `0x1010CA2A8` at `0x10031ED5C`. The selected nonzero-size continuation stores S into `0x1010C6800` at `0x1003875B8`. All eight retained paths have zero slide and match the original section header. Generic address arithmetic is proved; native image discovery, slide and malformed-header handling are not established by these observations.

## Complete window-selection semantics

Analysis block label: `select_self_text_window_and_encode_globals`; no IDB symbol is changed. The block is `0x1003F1390..0x1003F19FC`,411 original A64 instructions. Define S/P as the initial size/start globals and Q as the u64 read from F+`0x358`. Arithmetic is modulo2^64; `n` below is a signed mathematical index with sentinel -1:

```text
V = u64(S - 16)
n = -1 if V == 0 else floor_log2(V)
k = min(n, 15)
L = 1 << (u64(k) & 63)                 # A64 register-shift rule
Delta = 0 if n < 15 else (1 << n) - 32768
r = Q & u64(V - L) & 0xFFFFFFFFFFFFF000
A = u64(P + r)
```

For `S>16`, n is 0..63, `L=2^min(n,15)` and 1<=L<=32,768 bytes. The source containment theorem, additionally requiring non-wrapping P+S, is:

```text
P <= A
A + L <= P + S - 16
r % 4096 == 0
```

The 4096 value is a relative-offset grid in this algorithm; it does not establish the operating system's hardware page size. The section start is not on that grid: its low 12 bits are0x058, which every selected window address retains.

The generic source formula intentionally retains edge behavior. At S=16, V=0, n=-1 and the register shift gives L=2^63. Sizes below16 wrap V. These isolated inputs validate the actual arithmetic; the containment theorem does not apply. They are not observations of malformed-header reachability or native failure handling.

The148-instruction prekey block reduces to `(S-16) XOR 0x840204B3D6B78667`. The following99-instruction block recovers floor_log2 with sentinel -1 and its comparison phase. Separate source proofs establish the split/clamp and the offset expression. The complete block publishes four process-global cells and introduces no new API call.

## Four global codecs and temporal roles

| Cell | Initial / earlier role | Writer in the window block | Published u64 |
| --- | --- | --- | --- |
| `0x1010B70D8` | Additively encoded zero in the original image | `0x1003F1850` | `u64(Delta + 0x00E2C06C277E3E38)` |
| `0x1010B83A0` | XOR-encoded zero in the original image | `0x1003F18F8` | `r XOR 0x34936DC72AFD2F98` |
| `0x1010CA2A8` | Section start P, from `0x10031ED5C` | `0x1003F19DC` | `A XOR 0x12AF5504870A589F` |
| `0x1010C6800` | Section size S, from `0x1003875B8` | `0x1003F19F8` | `(L-1) XOR 0xFFF0C012A7A730EC` |

The source decodes an intermediate offset as `r XOR 0xACA72517860A6000`, then produces the two externally stored offset/address forms. All four codec identities are proved for arbitrary u64 scalar inputs. This is address/value encoding; no cryptographic property is inferred.

The section start/size globals change representation and meaning over time. Their final values cannot be read as the original raw section address/size. Similarly, F+`0x358` previously held an arena cursor; here its eight-byte source write at `0x1002475BC` supplies Q. Neither location supports a permanent object-member type solely from its offset.

The two destination addresses at `0x1010B70D8` and `0x1010B83A0` are materialized through original pool entries and constant biases. The source contracts verify both fixups and all 256 inputs of each byte-bank selector. These are process-local memory destinations, not Mach ports.

```text
own Mach-O section fields -> raw section start / size globals
                                      |
state-generator consumers -> Q ----> window selection
                                      |
                    four encoded range / address globals
                                      |
                    later consumers remain unresolved
```

The full block also reads the earlier controller words through F+`0x390`/+`0x398` and original byte banks. Their two dispatch banks select the same respective destination for every byte input. The meaning and lifetime of the encoded globals' later readers, concurrent access and cleanup remain unknown.

## Current-specimen reduction and finite offsets

For the exact original section:

```text
S       = 0xE297A8 bytes
V=S-16  = 0xE29798 bytes
n       = 23
L       = 2^15 = 0x8000 = 32,768 bytes
Delta   = 2^23 - 2^15 = 0x7F8000 bytes
V-L     = 0xE21798 bytes
r       = Q & 0xE21798 & ~0xFFF = Q & 0xE21000 bytes
```

The last expression denotes a numeric byte offset: Q is dimensionless selection material and the selected integer is interpreted in bytes. Bits12,17,21,22,23 determine r, giving `2^5=32` possible offsets for unrestricted Q. The complete list is retained in the [contracts](triage_evidence/daemon_global_state_contracts.json). No probabilistic or entropy estimate is assigned to this count.

The minimum offset is 0 and the maximum is `0xE21000`. The maximum selected end is `0x100E2A058`, leaving `0x7A8`=1,960 bytes before the section end. The generic proof guarantees a minimum 16-byte end margin under its domain; this specimen's mask/grid leaves a larger margin.

Changing Q's upper32 bits leaves all four publications unchanged for this specimen. The source proof is local to the current section size; larger hypothetical sections can use additional Q bits. The 32-offset result does not prove that every offset is reachable from native entropy/state or that the selected region is uniformly distributed.

The sealed zero/reference cases select eight distinct offsets, reconciled directly with their source journals. The additional [full-prefix observation replay](triage_evidence/daemon_global_state_observations.json) records 22 scalar checkpoints and reproduces its complete previously sealed continuation. At its window-block entry W9 is `0x8A9B8560`; the derived n is 23 and Delta is `0x7F8000`.

## Verification and scope

[Sixteen source-proof pairs](triage_evidence/daemon_global_state_proofs.json) cover 385 lifted instruction visits plus the explicit mathematical containment obligations. The [independent checker](triage_evidence/daemon_global_state_checks.json) solves all 32 original/normalized SMT files, verifies three nonempty premise witnesses, matches the Mach-O section fields, rechecks all411 block opcodes in each of eight sealed continuations and reconciles all 32 global publication values.

[Independent isolated A64 execution](triage_evidence/daemon_global_state_replays.json) runs the complete 411-instruction block over 1,434 declared inputs:589,374 source visits,27,246 reads and5,736 writes. There are 207 distinct size values, including power-of-two boundaries, sizes0..18, the actual size and u64 extremes. The current32 offsets each execute with two upper-word variants; individual Q bits and deterministic hash patterns add coverage. A fresh isolated case reproduces the observed full-prefix selection.

Containment applies to 1,329 isolated cases. The other 105 cases retain actual arithmetic outside that theorem's size/non-wrap domain; they do not count as successful containment checks. The original block executes 411 source instructions without a native API, Mach/IOKit operation or pointer-authentication instruction in these isolated runs.

The source window block is O(1) time/space for fixed 64-bit words. The compact model uses a floor-log/CLZ operation and scalar arithmetic; a portable width-dependent implementation can use O(log w) time and O(1) extra space for w-bit words. Test tooling scales with cases, image pages and source visits; each SMT query is bounded to 30 s. These counts are software observations, not native timings.

[Preservation](triage_evidence/daemon_global_state_preservation.json) and [scoped gates](triage_evidence/daemon_global_state_quality_gates.json) retain the prior manifest and original inputs. No native target import, entropy/clock provider, Mach message, IOKit request or IDB mutation executes in this increment.

## Bounded continuation opportunities

| Impact | Investigation | Discriminating evidence |
| --- | --- | --- |
| High | Follow readers of the encoded address/mask/offset/span cells | Prove inverse codecs and actual accesses to the selected self-text bytes; establish whether consumers perform checks, indexing or another operation |
| High | Resolve the callback-revisit F+0x4A0 frontier | Recover its writer or preserve unknown-copy provenance while excluding unknown-dependent addresses/control |
| High | Connect selected-window/global values to daemon/kext interfaces | Def-use evidence into established port/message/user-client fields |
| Medium | Recover the two state-word consumers that build Q | Complete source formulas and caller-key roles; retain the current high-word irrelevance result without generalizing to other sizes |
| Medium | Expand self-image discovery and lifetime contracts | Header/segment/section selection, slide, nonzero-size branch, synchronization and replacement/cleanup |
| Medium | Refresh source spans in the loaded IDB | Matching authenticated bridge worker and exact source-byte readback; both present probes were unavailable |
| Low | Search for the normalized floor-log/range/codec patterns | Source equivalence and data provenance across other flattened blocks |

## Scoped quality gates

| Gate | Result |
| --- | --- |
| QG1 | Pass: factual technical analysis |
| QG2 | Pass: GS1-GS14 with dependencies and falsification probes |
| QG3 | Pass for this increment: self-section provenance, complete window formula, four codecs, domains, finite offsets and publication reconciliation; full objective active |
| QG4 | Pass: u64 wrapping/shift rules, byte widths,32,768-byte window,4096-byte offset grid,16-byte theorem margin and current1,960-byte margin explicit |
| QG5 | Pass: temporal roles, zero/small-size edge behavior, containment domain, unrestricted-Q/native distribution and unavailable-IDB/source evidence distinguished |
| QG6 | Pass for source/A64 scope: original image/header/fixups, sealed source journals, original/normalized SMT and independent complete-block execution; fresh IDB verification unavailable |
| QG7 | Pass: bounded impact-labeled continuation table |

Full-goal completion is false.
