# Allocation predecessors, classifier interval and marker provenance

Original source computes the previously assumed allocation phase instead of requiring it at A035F0: from analyst cutpoint `0x100AEE5C8`, saved mode471C and a nonzero u64 presence field select `0x100B67258`; two source predicates admit decoded u32 classifier **2..200 inclusive**, then reach `0x100A035F0` with W8=621B. A separate original-source bank identity resolves the saved marker address to `0x1010C8254`. These are conditional source contracts. The actual predecessor/caller of AEE5C8, the incoming frame producers and the classifier's native meaning remain **unknown**. The full daemon/kext/deeper-interface investigation remains active. [CP1-CP12]

The original ARM64e source SHA-256 is `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; read-only IDA target is `6b117c693e3b`. Evidence: [contracts/census](triage_evidence/daemon_creation_predecessors_contracts.json), [source proofs](triage_evidence/daemon_creation_predecessors_proofs.json), [private A64 cases](triage_evidence/daemon_creation_predecessors_replays.json), [checks](triage_evidence/daemon_creation_predecessors_checks.json), [preservation](triage_evidence/daemon_creation_predecessors_preservation.json), and [scoped gates](triage_evidence/daemon_creation_predecessors_quality_gates.json).

The [preceding allocation report](daemon_object_creation_report.md) has one corrected narrative statement. Its earlier text described W22=40C7 from an isolated proof fixture as executed removal state. All 18 retained private removal journals actually reach the lazy gate with **W22=0817**, loading callback `0x100B353A4` from `0x10103DFA8`, IA/56F7. The candidate creation path instead uses W22=07E9 and callback B280C8. Slot40C7 targets C02F3C with IA/3459; it is valid in the separate caller dispatch, but is not the observed callback lookup. Original journals, producers, proofs and historical quality-gate hashes remain unchanged; the current preservation record explicitly accounts for the corrected report.

| Assumption | Dependent result | Stress test / falsification probe |
|---|---|---|
| CP1: Exact source and original fixups are authoritative | All addresses, banks and bindings | Rehash source, decode original words/imports and compare 704 fresh IDB bytes |
| CP2: AEE5C8 is an analyst cutpoint with the documented frame inputs | New source composition | Recover its actual caller; no entry from a transport request or the common prelude is claimed |
| CP3: Saved mode at SP+273C is471C | Specific phase621B and table indices | Prove the generic mode/presence equation; vary presence0/1/u64MAX and retain native mode producer as unknown |
| CP4: u64 slot SP+2A48 is a presence value; u32 slot SP+2A50 is the raw classifier | Presence and interval gates | Test zero/nonzero scalar values and all u32 classifier equations; pointer, length and enum interpretations remain unknown |
| CP5: Frame slots, marker/cell owners and controller roots have the declared private layout | A64 paths and imported malloc outcomes | Reject undefined private reads, vary backing/frame placement, clobber caller GPRs at malloc; no native allocator executes |
| CP6: The same frame epoch preserves SP+26C8 from9D0454 to AEE5E0 | Marker address attribution to later reads | Check subsequent source stores, frame stability and preserved slot; establish the actual branch into AEE before claiming continuous reachability |
| CP7: The original bank roots have the recovered values | Marker and u32-global addresses | Exhaust both 256-byte identities, verify original pool words and full64 negative biases |
| CP8: Common-prelude register/pointer roles survive into the candidate creation frame | Conditional reset destinations | Rebuild all18 retained contexts; prove A035F0 saves and B280C8 store widths; actual invocation remains unknown |
| CP9: A census candidate executes from its listed preceding-terminal start | Thirteen bounded exclusions | Preserve all original bytes; test joint phase/index constraints; middle-entry paths, computed modifiers and native frame compatibility remain outside this filter |
| CP10: Logical original PAC metadata is the validation boundary | Dispatch identity | Match IA key, modifier and address-diversity zero; native authentication remains unknown |
| CP11: Source journals are finite private executions | Reporting correction and context reuse | Rebuild register epochs from compressed journal payloads; do not promote private state to native observations |
| CP12: Neighboring globals and matching field values do not establish one native type | Descriptor-neighborhood and object-header hypotheses | Trace concrete readers/writers/publication before merging structures or assigning the classifier to object+0 |

At AEE5C8, source loads marker pointer SP+26C8 into X15, copies SP+2A48 to SP+2D78 and copies raw classifier SP+2A50 to SP+2FAC. It also saves several incoming registers and resets local slots. For u32 mode S, u64 presence N and arithmetic modulo2^32:

```text
R = u32(S + 0xE293B0BF)
f = (R XOR (N==0)) & 1
I = u32(S + 0x475D) XOR (0xE8*f)
```

For S=471C, N=0 selects index8E79 -> ADD9A8. N!=0 selects8E91 -> B67258, and its first source AND computes `R & 0x1D6C6A3F = 0x621B`. Both original slots carry IA/44BE. This removes the need to assign phase621B between those fragments; the initial frame remains a declared premise. [CP2-CP5]

Let H be the raw u32 at SP+2A50 and `D=H XOR 0x8B3DC651`. The obfuscated arithmetic reduces to:

| Source gate | Computed value / predicate | Taken continuation |
|---|---|---|
| B67258..B672F0 | D; unsigned D<201 | indexADD1, slot101090D78 -> B6DE10 |
| First predicate false | D>=201 | index621B, slot10106AFC8 -> ADD9A8 |
| B6DE10..B6DEAC | u32(D-2); CMN/CSET LO tests u32(D-2)<FFFFFFFE | index9BD7, slot101087DA8 -> A035F0 |
| Second predicate false | D=0 or1 | index621B -> ADD9A8 |

All three classifier-dispatch slots use IA/0156/ad=0. The composed condition is unsigned **2<=D<=200**; this is199 admitted values. CMN W9,#2 is modeled specifically: carry clear iff unsigned W9<FFFFFFFE. Its result is independently checked by original A64 execution around the wrap boundary. Raw H remains saved at SP+2FAC. No source evidence here assigns D a native type, enum name, allocation size or object-header role. [CP3,CP4,CP10,CP12]

```text
AEE5C8, saved mode471C
  +-- presence=0 --------------------------> ADD9A8 frontier
  +-- presence!=0 -> B67258
                       +-- D>=201 --------> ADD9A8 frontier
                       +-- D<201 -> B6DE10
                                      +-- D=0/1 -> ADD9A8 frontier
                                      +-- D=2..200 -> A035F0, W8=621B
                                                       +-- marker0 -> lazy-lock frontier
                                                       +-- marker1 -> malloc(872)
```

Marker aliases and stability premises from the preceding report still apply. New compositions use marker0/1 and stop before lock creation/acquisition calls or at the earlier malloc-result frontiers. They perform no fixture phase changes between source fragments. All ADD9A8 cases stop on entry; final rejection status is unknown.

Two independent original-bank identities recover process-local addresses:

| Source save | Left / right byte banks | Key / constant / pool index | Original pool word target + u64 bias | Result |
|---|---|---|---|---|
| 9D0454 -> SP+26C8 | 100FC4130 / 101031EA0 | BB / BB /1189 | 12E36048B + FFFFFFFFD2D67DC9 | marker1010C8254 |
| 9D0350 -> SP+26E8 | same | A3 /72 /1298 | 16D542B72 + FFFFFFFF93B856C6 | u32-global address0x1010C8238 |

Pool slots are1010AA5A8 and1010AAE20. Both are ordinary original chained rebases; no authenticated-pointer meaning is assigned to their biased intermediate values. Each bank is checked for all256 inputs. All arithmetic in the table is u64 modulo2^64; the negative high bits in the biases are essential. Source9D0408..9D0444 preserves X15 between the first bank result and the marker save. The marker is in `__DATA,__common`, a section with S_ZEROFILL type; this describes image storage, not an observed native marker value. [CP6,CP7]

The common prelude stores its selected continuation at SP+2A68 using9D02AC/9D02B0 and reloads it at9D0774 before an IA/E30D branch. Index49D would select AEE5C8. The inspected18 retained contexts instead select index49C ->9F0108. Therefore they establish source-produced pointers and frame roles, **not a continuous path into AEE5C8**. Twelve intervening stores are checked against target-slot overlap, and the marker slot is unchanged after9D0454 through the inspected prelude end. A native producer of the required continuation remains unknown. [CP2,CP6,CP11]

Conditional common-context and reset mapping:

| Location / field | Source role | Exact effect or limitation |
|---|---|---|
| X4 -> A03610 -> SP+26C0 | 1010C67C0 lock cell | Existing lock/creator interface; incoming preservation is a premise |
| X5 -> AEE5DC -> SP+21A8 | 1010C5754 active-key counter | Separate from the three reset stores |
| X26 -> A03604 -> SP+24A8 | 1010C67D0 outer key bound | Separate from the inner bound |
| X23 -> A035F8 -> SP+2698 | 1010CA2B0 inner payload bound | B280D4 stores u32 zero |
| SP+26E8 from9D0350 | 1010C8238, functional meaning unknown | B280DC stores u32 zero |
| X7 -> A035FC -> SP+26B0 | 1010C9288 payload-array pointer | B280E4 stores u64 zero |
| SP+26C8 from9D0454 | 1010C8254 marker byte | AEE5E0 loads its address; later source reads use X15 |

Four isolated private callback cases verify the exact4/4/8-byte stores and preserved upper32 canaries for the two u32 owners. These cases do not establish callback invocation. With phase471C, the reset fragment's next slot is1A39 -> B7C108, IA/B7E0; its complete subsequent path remains outside this increment. The shared C02F3C trampoline branches through X19 using IA/56F7, explaining why callback identity must be tracked independently of the gate's physical address. [CP8,CP10]

Relative to prior descriptor anchor G=1010C8218, addresses1010C8238 and1010C8254 are numerically G+20 and G+3C. This proximity is a bounded structural lead. It does not prove that the globals share one allocated object or native structure. Likewise, the accepted classifier has not been connected to the removal object's u32 header. [CP12]

The original-text census finds18 aligned literal `MOV X17,#0156; BRAA` pairs. Under each listed fragment-start/table premise,13 are excluded from directly entering A035F0 with W8=621B: two branch through X8, forcing its low32 to A035F0; two leave constant phase232D/0; eight fail joint source phase/index constraints; and B67258 cannot directly select9BD7 even though it reaches the second classifier. Four other starts remain unexcluded by this filter:088A30,08C174,2827D8 and2BC394. B6DE10 is the selected conditional predecessor. Middle entries, computed modifiers, other bases and native frame compatibility remain unknown. Census inclusion alone is not caller evidence. [CP9,CP10]

No new Mach port, send/receive right, message ID, IOKit selector or emission site is established. These are local frame, classifier, marker, registry and heap interfaces. Their actual request/transport caller and historical RAX-trace association remain unknown.

Validation passes for11 original source spans,18 census spans,25 used/named original fixups,two exhaustive banks/512 byte inputs,18 rebuilt retained contexts,23 source-proof pairs/46 persisted UNSAT queries,23 freshly rebuilt obligations and311 lifted instructions. All819 persisted private A64 cases/105,796 source visits are recomputed; four further cases add719 visits. Four fresh IDB ranges cover704 raw bytes and151 display rows, including four undecoded byte rows. The source lift and Unicorn are separate instruction engines; repeated Unicorn execution checks freshness. No native target, allocator, lock operation, IPC or hardware PAC executes; no IDB is mutated.

Reproduce with the same pinned Python/Z3 environment as the preceding report, running `recover_daemon_creation_predecessors.py`, `prove_daemon_creation_predecessors.py`, `replay_daemon_creation_predecessors.py` and `validate_daemon_creation_predecessors.py` from `triage_evidence` via Python's `-P` option and the documented PYTHONPATH. Complexity is O(text bytes + retained source events + replay visits + solver resources) time and O(largest evidence JSON + one emulator map) space; each solver query has a30 s timeout. Frame offsets are hexadecimal, store/owner extents are in bytes, and classifiers/phases are explicitly u32 or u64.

| Impact | Further interface question | Decisive evidence |
|---|---|---|
| High | Who selects prelude continuation49D and supplies the AEE frame? | Continuous caller/source path, without replacing an internal phase or selected continuation |
| High | What does classifier D represent? | Trace raw SP+2A50 producer and saved SP+2FAC consumers into the candidate object/records |
| High | How do reset, lock cleanup and marker publication compose? | Execute actual B280 invocation through the common cleanup adapter and identify marker pointer restoration |
| High | How is the872-byte allocation initialized and published? | Establish SP+3620 producer and full returned-pointer continuity to registry storage |
| Medium | Are marker reads/writes serialized? | Actual upstream synchronization owner and all marker writers; byte stores alone establish no ordering guarantee |
| Medium | Do G+20/G+3C belong to the descriptor? | Independent field consumers and concrete structure lifetime/layout evidence |

QG1 passes for factual analysis. QG2 is covered by CP1-CP12 and their probes. QG3 passes for this increment; the full objective remains active. QG4 covers u32/u64 arithmetic,199-value interval,4/4/8-byte stores,source counts and solver limits. QG5 separates source-proof fixtures,retained private executions,candidate frame continuity,unclassified fields and native gaps. QG6 uses original bytes/fixups,rebuilt journals,source proofs,A64 cases and fresh IDB raw bytes. QG7 retains the impact-bounded continuations above. Machine-readable gates are issued after preservation and semantic checks pass.
