# fairplayd: missing bank producers and descending masked-byte copying

The three pointer banks required at the record-extension frontier have nominal setup producers: SP+0x390 selects `0x10102fa10`, SP+0x398 selects `0x100eebf60`, and SP+0x3a0 selects `0x100fd8250`. Their consumer implements a descending byte copy with an XOR mask indexed by the destination offset's low nibble. Original-source equations establish the predecremented counter, input/output addresses, byte transformation and post-store exit decision. The three fields remain undefined in all 608 retained normal frontiers; the setup/current-frame reaching definition and native caller epoch remain unknown. [RB1-RB6; RB-A1-RB-A6]

At the retained frontier, the pending input index is 19 and the destination bias is 165 B. If the nominal bank definitions and memory admissions apply, the remaining twenty stores cover buffer offsets 184 down to 165 B and produce the exact conditional byte vector retained in RB3. This increment introduces no bank/root bytes into the prior states and executes no new target interval. A twenty-byte extent and the contextual `itgr` literal do not establish an integrity algorithm or public record schema. [RB2-RB5; RB-A2-RB-A6]

| Evidence | Primary provenance and scope |
| --- | --- |
| RB1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original loop, producer projections, pool words and dispatch words are recaptured. |
| RB2 | [Shared setup](daemon_shared_roots_report.md), [bank origins](daemon_constructor_bank_origins_report.md), [record extension](daemon_record_extension_report.md) and [child loop](daemon_child_loop_report.md). Exact parent receipt hashes are pinned in RB3. Prior full admission corpora are not rerun. |
| RB3 | [Extractor](triage_evidence/recover_daemon_record_banks.py), [checks](triage_evidence/daemon_record_banks_checks.json.zst): memory-aware source projections, eight frozen setup profiles, 608 retained frontier exports, immutable bank bytes, mask and bounded literal-store census. |
| RB4 | [Auditor](triage_evidence/audit_daemon_record_banks.py), [receipt](triage_evidence/daemon_record_banks_audit.json.zst): independent projected source replay, original external bytes/fixups, ten nonvacuous UNSAT obligations, finite controls and conditional predictions. |
| RB5 | [Publication verifier](triage_evidence/verify_daemon_record_banks_publication.py): fresh extraction/audit, canonical SMT comparison, exact manifest delta, preservation of three original inputs and decoded path hygiene. |
| RB6 | [ABI](interface_abi_report.md), [ports](mach_ports_report.md) and [CoreFP paths](corefp_client_paths_report.md): transport and external caller boundaries. These private setup/byte-writing blocks establish no new Mach right or daemon-kext transaction. |

Decoded receipt SHA-256 values are `50000b634bd81018868350c194f60e49992dded73a2a6996764f0af345c40f48` (RB3) and `c22bc57d3c84cde88ea1b5e1a8097d5ba20b23a58fe1004b1f7c653a307098fd` (RB4).

## Bank producers, nominal values and memory epochs

All pointers and addresses use u64 modular arithmetic. Scalar counters/offsets use u32 modular arithmetic; stored bytes reduce modulo 2^8. B denotes bytes. F is a frozen setup frame and K is the later retained constructor frame. Equality F=K, intermediate preservation and native loader contents remain unproved. The following are nominal decoded-image values and source/profile compatibility mappings. [RB1-RB5; RB-A1-RB-A4]

| Frame field | Setup store | Final pool load / slot | Decoded pool word | Added u64 bias | Nominal bank |
| --- | --- | --- | --- | --- | --- |
| F+0x390 | `0x1004c335c` | `0x1004c3348` / `0x1010a59a0` | `0x172c9b51a` | `0xffffffff8e3944f6` | `0x10102fa10` |
| F+0x398 | `0x1004c2afc` | `0x1004c2aec` / `0x1010a5160` | `0x1050b5a12` | `0xfffffffffbe3654e` | `0x100eebf60` |
| F+0x3a0 | `0x1004c28e8` | `0x1004c28c8` / `0x1010a5e18` | `0x14e2b0edf` | `0xffffffffb2d27371` | `0x100fd8250` |

Each selected decoder suffix establishes `field=loaded_word+bias` for every u64 loaded word. For a zero-extended byte selector s, its pool address is POOL+8*(s+a), with addends `0x7c0`, `0x61b` and `0x854`, respectively, and POOL=`0x1010a1960`. The eight retained setup profiles establish the actual selected slots and field values through complete register-and-memory dependency projections. The affine suffix theorem alone does not establish a runtime selector or loaded word. [RB3-RB5; RB-A1-RB-A4]

The projections also retain eight-byte setup stores at `0x10061a44c` to `0x1010b8dc8` and `0x10061a454` to `0x1010c4670`. Later bank selection reads four low bytes from these controller locations. Of the 704 store/read byte links, 512 are frame bytes and 192 are these global-controller bytes. The replay checks both widths byte-for-byte; later controller reads are not treated as independent external inputs in these frozen projections. Native concurrent modification and caller epoch remain unknown. [RB3-RB5; RB-A2-RB-A4]

The three dependency projections contain 108, 110 and 103 instruction visits per profile, respectively. Backward selection follows both register definitions and exact overlapping memory stores. Forward byte links connect private reads to their actual selected last writers, rather than substituting equal-valued cells. Across eight profiles this gives 24 field instances, 2,568 selected instruction visits and 704 store/read byte links. Independent replay seeds unrelated registers with zero, consumes the retained external reads, checks computed read addresses and every selected store, and verifies 1,616 original external bytes. These are frozen-path projections, without a new whole-setup execution or an arbitrary-controller all-path theorem. [RB3-RB5; RB-A2-RB-A4]

| Reused frame cell | Earlier writer | Consuming read | Later writer | Recorded epoch distinction in the first profile |
| --- | --- | --- | --- | --- |
| F+0x990 | `0x1004c25d8`, 4 B | `0x1004c2ac4`, 4 B | `0x1004c2b44`, 4 B | Read `0x9f`; later cell value `0x122e`. The read precedes the F+0x398 publisher. |
| F+0x998 | `0x1004c251c`, 4 B | `0x1004c3064`, 4 B | `0x1004c31a8`, 8 B | Read `0x86460b9c`; later eight-byte value `0x100fb0710`. The overwrite occurs before the F+0x390 publisher, after its selector-producing read. |

All eight profile ledgers preserve these writer/read/overwrite orderings. Later cell snapshots therefore cannot replace the earlier read definitions when recovering the bank selectors. The second F+0x998 store changes the recorded field width and nominal interpretation; no fixed global type is assigned to that offset. This is source/profile memory reuse, without a native lifetime or concurrency conclusion. [RB3-RB5; RB-A2-RB-A4]

The aligned `__text` census examines 3,712,490 instruction words and finds 39, 34 and 31 literal `STR Xn,[SP,#offset]` candidates for +0x390, +0x398 and +0x3a0. Each named setup writer is present. The total 104 candidates do not share a proven frame: pair stores, other widths/forms, computed aliases and SP movement are outside this census. Neither the census nor the frozen setup proves a reaching definition at K. [RB3-RB5; RB-A1-RB-A4]

## Local byte-writer and counter equations

Let C be the decoded incoming u32 count, encoded as `raw=C XOR 0x8b3dc651`, and let B be the u32 destination bias. At fixed phase W13=`0x6613`, original prefix `0x10084fcc4..0x10084fdb8` produces:

```text
i = u32(C - 1)
W11 = i XOR 0x8b3dc651
W14 = i XOR 0x313680c7

o = u32(B + i)
n = o AND 15
input byte = *(input_base + zero_extend64(i))
output address = output_base + zero_extend64(o)
```

The original prefix theorem quantifies over every u32 C, including zero. Its consequence at C=0 is wrap to `0xffffffff`; a valid positive-count execution theorem requires C>0 and separate input/output admission. This selected loop contains a predecrement and a post-store termination decision. No zero-count claim is transferred from the earlier pretested `vers` loop. [RB1, RB3-RB5; RB-A1-RB-A5]

| Consumer PC | Width | Exact source touch point |
| --- | --- | --- |
| `0x10084fdbc` | 1 B | Input at input_base+i, loaded before the current missing-bank frontier. |
| `0x10084fdcc` | 8 B | Load bank A from K+0x390. |
| `0x10084fdd4` | 1 B | A[n]. |
| `0x10084fdd8` | 8 B | Load bank B from K+0x3a0. |
| `0x10084fde0` | 1 B | B[n]. |
| `0x10084fde4` | 8 B | Load bank Cbank from K+0x398. |
| `0x10084fdec` | 1 B | Cbank[n+3]. |
| `0x10084fe0c` | 1 B | Store `input XOR A[n] XOR B[n] XOR Cbank[n+3] XOR low8(n OR (n<<5)) XOR 0x23`. |

A and B require sixteen indexed bytes. The third bank uses offsets 3 through 18 B; RB3 captures nineteen bytes from its nominal base. These are local source read windows, not recovered native object extents. With the original nominal bank bytes, the composite mask is:

| n | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M[n], hexadecimal | 41 | 14 | 0b | 8f | d1 | 13 | ba | 89 | 1a | 2b | 81 | 1d | e8 | 45 | 08 | d7 |

Thus the local byte equation is `out[o]=in[i] XOR M[o AND 15]`. The mask selection is periodic in the destination offset modulo sixteen; it is independent of the input byte. Applying the same XOR at the same position recovers the input byte. One symbolic obligation checks the sixteen immutable bank rows for every eight-bit input; 4,096 finite byte/nibble involution controls provide a separate algebra check. This equation does not classify the complete record construction or a cryptographic algorithm. [RB3-RB5; RB-A1-RB-A4,RB-A6]

After the byte store, the comparison at `0x10084fe10` tests whether i=0. The resulting table index is `W13 XOR (0x45 if i==0 else 0)`. At the current phase, the original dispatch words establish:

| Condition | Index | Original slot | Target | IA diversity |
| --- | --- | --- | --- | --- |
| i!=0 | `0x6613` | `0x10106cf88` | `0x10084fcc4`, next decrement/copy | `0x6f79` |
| i=0 | `0x6656` | `0x10106d1a0` | `0x1008d3490`, previously recovered optional output/status path | `0x6f79` |

These original format-12 authenticated words have address-diversity zero and key IA. Their logical target/modifier compatibility is established; hardware authentication remains unknown. Input base X9, output base X10, destination bias W8, phase W13 and SP are unchanged by this loop's source writes to registers. Memory aliases and external modifications remain separate preservation premises. [RB1-RB5; RB-A1-RB-A5]

```text
positive count C
       |
       v
 i = C-1; encode i; load input[i]
       |
       v
 read three banks at (B+i) AND 15
       |
       v
 output[B+i] = input[i] XOR M[(B+i) AND 15]
       |
       +-- i != 0 --> C = i --> decrement/copy
       |
       +-- i == 0 --> optional coordinate output / status path
```

For C>0, the widened unsigned rank C decreases to C-1 without underflow. If each body and logical transfer is admitted and preserves its bases/bias/banks, exactly C stores occur, at descending indices C-1 through zero. The destination interval additionally requires widened B+C<=2^32 and sufficient storage; these conditions prevent offset wrap. Body admission, native time and a complete handler return do not follow from the counter theorem. [RB3-RB5; RB-A3-RB-A5]

| Selected loop contract | Earlier `vers` loop | Current masked-byte loop |
| --- | --- | --- |
| Counter order | Ascending 0 through C-1 | Descending C-1 through zero |
| Termination test | Before the body | After the byte store |
| Zero count | Source gate skips the body | Direct prefix entry wraps; excluded from the positive-count theorem |
| Body | Byte decoder and packed scalar fields | One byte copied with a position-dependent XOR |
| Shared completion target | Optional coordinate/status path | Original zero-index route selects that same path; current frontier has not executed the route |

The comparison concerns selected source contracts and the retained `itgr` context, not an exhaustive tag taxonomy. Whether this path later reaches the clear-mask/itgr further-work target `0x100705fb8` remains unknown. [RB2-RB5; RB-A5-RB-A6]

## Retained frontier and conditional twenty-byte result

All 608 normal exports from RB2 still stop at `0x10084fdcc`. They have K=`0x6800060100`, input_base=K+0xc4b0, output_base=`0x66000d0000`, B=165 B, i=19 and n=8. The postdecremented raw counter is `0x8b3dc642`, decoding to 19, and the index-comparison literal is `0x313680c7`. The twenty input bytes are defined in the retained state, and the output owner is 224 B. The current pending destination is output_base+184 B. All twenty-four bank-field bytes at K+0x390/+0x398/+0x3a0 remain undefined. No bank initialization is silently inserted. [RB3-RB5; RB-A2-RB-A5]

```text
defined retained input20:
38 11 6d e8 13 d1 f4 09 8e ee 3d 71 c6 c4 d2 6e 80 cd c5 f1

conditional output at offsets 165..184, ascending display:
2b ab e4 f2 38 50 e9 e1 cb e6 ea 30 d2 cf 5d bf 93 77 4c eb

first pending store: i=19, o=184, n=8; f1 XOR 1a = eb
actual source store order, if admitted: 184,183,...,165
```

All 608 retained inputs and predictions agree byte-for-byte. These predictions depend on the nominal banks and on future body/memory admission; they are not twenty newly observed stores. The input vector's earlier producer, its native epoch and its higher-level meaning remain unknown in this increment. The masked copy can be composed with the prior output/status contract only after its remaining memory and continuation premises are established. [RB3-RB5; RB-A2-RB-A6]

## Validation, assumptions and bounded continuation

Independent projection replay checks 2,568 original instructions, 544 reads and 144 writes across 24 field instances, plus 1,616 original external bytes and 704 reconstructed store/read byte links. Eleven pool fixups and two authenticated route fixups are checked against original words/import-format metadata. Ten nonvacuous UNSAT obligations cover counter/index normalization, exact consumer addresses and nibble bounds, stored byte, exit selection, immutable mask collapse, three all-u64 affine pool decoders, positive rank decrease and nonwrapping destination bounds. A missing private writer and a one-bit alteration of the mask are rejected by independent source controls. Five scalar counter controls include 0, 1, 2, 20 and 2^32-1; zero is retained as an excluded-domain wrap control. [RB3-RB5]

Extraction costs O(profile_visits*fields + text_words + parent_bytes + retained_exports + selected_events) time. Selected replay and symbolic translation are linear in selected visits and expression-DAG size, excluding solver search; each solver query has a 30 s limit. Stored evidence, parent receipts and one frontier export bound the working data outside the solver. Archives use zstd with decoded round-trip verification. The prior 2,530,408-visit constructor replay is a pinned dependency and is not repeated here. [RB2-RB5]

Existing reference data suffice; IDA is not accessed. No new target interval, native API, allocator, IPC, hardware PAC or database mutation executes. No new incoming/outgoing Mach port, right transfer or emission location is established. Native same-frame bank custody and daemon-kext transaction pairing remain unknown. [RB2-RB6; RB-A1-RB-A6]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RB-A1: Pinned image, bank bytes, pool/fixup metadata and parent receipts apply | Producer values, mask, source equations and routes | Rehash all artifacts; recapture original instructions/arrays/words; reconstruct source obligations and fixup decoding. |
| RB-A2: The frozen setup paths and retained frontier admissions describe their stated environments | 24 producer instances, memory epochs and 608 conditional predictions | Rebuild backward register/memory projections and forward last-writer links; replay selected reads/stores; preserve all earlier API/root premises. Do not identify F with K by equal offsets or values. |
| RB-A3: Readable, separated, coherent memory and output ownership apply to each body | Masked stores, source preservation and destination bounds | Establish every bank/input/output range; falsify with aliasing, changed bytes or missing owner/definition. The frontier's bank fields are still undefined. |
| RB-A4: Nominal decoded pool/bank values and logical authenticated routes apply | Concrete mask and target compatibility | Prove affine loaded-word identities, verify original words and separate arbitrary loaded values; require native loader/PAC/lifetime evidence for native claims. |
| RB-A5: Positive count, stable bases/bias/phase/banks and normal body/transfer completion apply | Exactly C descending stores, shared completion and twenty-byte prediction | Check C=0,1,2,20,2^32-1; prove rank decrease and nonwrapping bounds; establish future body admission and caller continuity independently. |
| RB-A6: Local copying and a contextual tag/extent do not establish public schema or external identity | Interpretation of itgr, input20 and daemon/kext interaction | Recover the twenty-byte producer and independent consumers; join native initializer/current caller and matched Mach/IOKit buffers to kext handlers. |

| Impact | Bounded next evidence | Current limitation |
| --- | --- | --- |
| High | Join original bank setup to the current constructor frame, including intervening writes and frame geometry | Producers are identified; K's twenty-four bank bytes are still undefined. |
| High | Recover the last writers and algorithmic producer of the twenty-byte input at K+0xc4b0 | Defined retained input and local copy are known; upstream meaning and native epoch are unknown. |
| High | Match the published J+0x68 object and its consumer to daemon Mach/IOKit requests and kext completion | No new transport identity or paired transaction is established. |
| Medium | Admit the remaining byte bodies and follow optional output/status into itgr-specific further work | Original route compatibility is known; no new body or completion execution is claimed. |
| Medium | Test alternative loaded bank words, aliasing and direct zero-count entry separately | Mask, range and positive-count premises are explicit; arbitrary native environments remain unestablished. |
| Low | Extend the 104-site literal census to pair/aliased/other-width stores with frame identity | Current census is intentionally single-form and does not prove all-path preservation. |

**QG1**: factual source, ABI and data/control-flow analysis. **QG2**: RB-A1-RB-A6 list dependencies and falsification probes. **QG3**: three bank origins, local masked copy, descending control and retained predictions are covered; the full interface investigation remains active. **QG4**: byte units, widths, modular arithmetic, count/range bounds and complexity are explicit. **QG5**: setup/current-frame compatibility, memory reuse, direct zero-count wrap, conditional predictions and shared completion are distinguished. **QG6**: pinned primary artifacts, original bytes/fixups, independent replay and fresh source proofs establish provenance. **QG7**: impact-labeled adjacent interfaces and unknowns are enumerated.

## Record-input provenance follow-up

The [record-input provenance increment](daemon_record_input_origin_report.md) establishes the actual producers of the twenty-byte input used here: S[0:2] || T16 || S[18:20]. The formatter stores are observed in retained parent source traces, while the masked-copy result above remains conditional on the still-missing banks and memory admission. No new post-frontier interval executes.
