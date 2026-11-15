# Hash-input reader, private continuation ABI and protected-node decoding

The earlier saved-address use at `0xfffffe000a63ddb4` belongs to a shared tagged-node reader. In the selected caller phase, that reader searches a linked container, decodes a ten-byte protected-memory header, accepts a specific transformed type, requests exactly the decoded payload length from `_IOMallocData`, copies that many decoded bytes and publishes the result through scratch+0x128. Its saved continuation is exactly the [discriminator hash gate](userclient_discriminator_origin_report.md) at `0xfffffe000a6570c4`.

The second output is an **encoded payload length**, separate from the primary status in W23. The selected allocation/copy path adds no NUL byte. Whether upstream construction guarantees a terminator in the copied payload remains unknown. These are conditional instruction contracts; no native fault, successful transaction, original field identity or object ownership follows from them.

## Primary evidence and validation

| Artifact | SHA-256 of decoded content | Scope |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Pinned instruction/data image |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original instructions, symbols and pointer-format-8 chain custody |
| [Checks](triage_evidence/userclient_input_reader_checks.json.zst) | `83c8787a3213a9e08cf0f415069c2876177008b640451d79f5c9364fbbcff273` | 41 spans, 730 selected instructions, 36 terminal transfers, two bank rules and eight alternate retag sites |
| [Audit](triage_evidence/userclient_input_reader_audit.json.zst) | `89210b2bfb3b55ab6aee4462effdcd4dd695e2a4874e72c61f07c99fdc206815` | 39 new nonvacuous UNSAT obligations, three predecessor formula rechecks, 12,947 proof instruction instances |
| `_IOMallocData` adapter | `0bc800f390215db6847c0e74814ad727ac2d56d59c4b8c04eed740b600efd0dd` | Complete 36-instruction adapter at `0xfffffe000c4ba60c`..`0xfffffe000c4ba69c` exclusive |

The [extractor](triage_evidence/recover_userclient_input_reader.py) compares the selected words with both images and retains the predecessor's complete 50,634-instruction `_PRnut72j9` container hash. The [audit](triage_evidence/audit_userclient_input_reader.py) covers every selected PC, proves 38 instruction obligations and one integer copy-index certificate, and exhaustively checks both 256-input bank compositions. Eight instruction obligations establish the exact alternate MOVK transforms; the main decoding/copy obligations assume the explicit normal pointer branches. No native pointer authentication or alternate-address dereference is simulated.

Three frozen predecessor formulas are re-solved for the raw-status gate, nullable input gate and null-input discriminator store. They are not fresh full predecessor replays. Four altered-evidence equality controls reject a changed source word, bank constant, length-channel description and unsupported termination claim. These controls test custody comparison, not semantic native mutations. The [delivery verifier](triage_evidence/verify_userclient_input_reader_delivery.py) reconstructs the receipts and checks current publication custody. No target code or IDB executes or changes.

| Claim | Established result | Principal dependencies |
| --- | --- | --- |
| IR1 | Four saved output-cell addresses and caller-specific tag/continuation request | IR-A1, IR-A2 |
| IR2 | Shared reader private output/continuation ABI and linked-node search | IR-A1-IR-A4 |
| IR3 | Protected-memory byte transform and tag comparison channel | IR-A1-IR-A5 |
| IR4 | Ten-byte header, low16 type, encoded length and widened extent predicate | IR-A1-IR-A5 |
| IR5 | Exact accepted/rejected transformed types and separate primary status | IR-A1-IR-A5 |
| IR6 | Original allocator pointer and exact L-byte request, with ordinary return cut | IR-A1, IR-A2, IR-A4, IR-A6 |
| IR7 | Reverse decoded copy, one-byte stores and exact output/hash continuation | IR-A1-IR-A6 |
| IR8 | No additional terminator in the selected copy; upstream termination unknown | IR-A1-IR-A7 |
| IR9 | Private-interface boundaries, computational costs and open external identity | IR-A1-IR-A8 |

## Caller and private continuation interface

C denotes the current scratch base X2, S the current source base X4 and F the current SP epoch. O is the incoming container pointer in X22; its native type and original producer remain unknown. J is a search node, B its buffer, N its declared u32 buffer extent, L the decoded u32 payload length and Z an abstract allocator result. These labels describe local access contracts, not recovered public structure definitions.

```text
caller: tag request + address(C+0x128) + address(S+0xaa8) + index0x133
    |
shared entry: retain outputs and outer continuation C+0x298
    |
search O -> J -> J.next ...; protected tag comparison
    |
matched J -> buffer B and extent N -> protected 10-byte header
    |
type/extent gates -> encoded length M = L XOR 0x31ae0066
    |
_IOMallocData(L) -> Z -> decode/copy bytes L-1 ... 0
    |
store Z at C+0x128; W23 = 0x31ae0066
    |
resume C+0x298 = 0xfffffe000a6570c4 -> hash input gate
```

| Cell / register at the selected phase | Width | Action / meaning |
| --- | --- | --- |
| F+0x478 | address64 | C+0x128; root at `0xfffffe000a635d5c`..`0xfffffe000a635d60` |
| F+0xd8 | address64 | S+0xaa8; root at `0xfffffe000a635bdc`..`0xfffffe000a635be0` |
| F+0x700 | address64 | C+0x400; root at `0xfffffe000a636154`..`0xfffffe000a636158` |
| F+0x7c0 | address64 | C+0x728; root at `0xfffffe000a635bf4`..`0xfffffe000a635bf8` |
| C+0x158 | address64 | Retained caller pointer-output address C+0x128 |
| C+0x160 | address64 | Retained encoded-length-output address S+0xaa8 |
| C+0x298 | address64 | Outer continuation `0xfffffe000a6570c4` |
| C+0xc8 | address64 | Inner search continuation `0xfffffe000a662ee0` |
| C+0x758 | address64 | Matched-node output address C+0x400 |
| C+0x2b0 | pointer64 | Current search node J |
| C+0x400 | pointer64 | Matched J or null |
| C+0x728 | pointer64 | Selected B |
| C+0x88 | pointer64 | Accepted body pointer B+10 |
| S+0xc78 | cursor64 | Search setup zero; accepted header/body cursor 10+L |
| S+0x90 | value16 | Transformed decoded type, stored by STRH |
| S+0xaa8 | value32 | Encoded length M, not primary status |
| W23 | value32 | Primary raw-status channel |
| F+0x9ec | value32 | Separate saved-status source reloaded after allocation; domain remains unknown |

At `0xfffffe000a63dd84`..`0xfffffe000a63ddcc` exclusive, entry W24=0x7795e3ce produces continuation index0x133 and shared-reader entry index0x2c4. W9 carries encoded-tag request0x2685a3ce; W0=0x19 and W27=0x37 are also passed, but their semantic meanings are unknown. In particular, 0x37 is not established as this reader's decoded type. The caller BRAA modifier is 0x73ed. Shared entry stores the two output addresses and the original table target at index0x133. The outer resume at `0xfffffe000a663114`..`0xfffffe000a66311c` exclusive loads C+0x298 and uses BRAA modifier0x3aa3.

The search installs its own continuation/output cells. It loads J from O+0, advances through J+0 on a decoded tag mismatch and stores the match through C+0x758. The callback's opaque pool value in X22 is not the matched-node identity: that identity survives in C+0x400. Empty search publishes null through that cell and takes the common output-clear path. Finite traversal requires a stable terminating chain; the one-step proof does not establish native acyclicity.

| Accessed search-node member | Width | Meaning supported by these accesses |
| --- | --- | --- |
| J+0 | 8 B | Successor pointer |
| J+0x10 | 4 B | Declared buffer extent N |
| J+0x18 | 8 B | Protected-memory buffer pointer B |
| J+8 / other gaps | unknown | No identity or field semantics established here |

The accesses span 32 B. They do not prove allocation size or native C++ type. This layout is separate from the 16 B UIDList publication node containing discriminator and marker words. No type identity is inferred from a structural resemblance to earlier tagged-node observations.

## Protected-memory decoding and header contract

For each address a in the admitted normal pointer branch, the captured code decodes a byte with the following unsigned64 arithmetic. K26 is the current X26 key; its original producer is unknown.

```text
KEY20 = 0x4dae26df20976138
t(a) = (ROR64(a AND 0xfffffffffffffff8, 8) + K26) XOR KEY20
mask8(a) = low8(t(a) >> ((a AND 7)*8))
D(a) = stored_byte(a) XOR mask8(a)
```

Addition wraps modulo2^64 and variable shifts use the source's AArch64 width rules. The normal branches and stable protected-memory/key view are explicit proof premises. Each alternate MOVK replaces the pointer's upper16 bits with0xc8a2 while preserving low48; all eight transforms are proved separately. This does not establish that the retagged address is natively readable, equivalent or reachable. The first search decode assumes selected-phase X20=KEY20; the later header preparation explicitly assigns that constant.

Let D0..D9 be decoded bytes at B+0..B+9. BE16/BE32 denote unsigned big-endian assembly. These are protected in-memory fields; an external serialized packet layout is not established.

| Offset | Extent | Decoded value / source channel |
| --- | --- | --- |
| +0 | 4 B | BE32(D0..D3); comparison channel XOR0x31ae0066 must equal0x2685a3ce |
| +4 | 2 B | Type T=BE16(D4,D5) XOR0x365e; STRH stores low16 at S+0x90 |
| +6 | 4 B | L=BE32(D6..D9); decoded word channel M=L XOR0x31ae0066 |
| +10 | L B | Decoded payload copied to Z |

The request therefore corresponds to plaintext tag0x172ba3a8 in this transform. Its business meaning is unknown. The generic word decoder at `0xfffffe000a63713c`..`0xfffffe000a63724c` exclusive is reused for tag, header word and length. The type decoder at `0xfffffe000a639310`..`0xfffffe000a6393c4` exclusive establishes low16(W8), not normalized upper16; the following STRH makes low16 the contract. Length preparation at `0xfffffe000a639b34`..`0xfffffe000a639bb8` exclusive reads offsets6..9.

The header gate at `0xfffffe000a662f84`..`0xfffffe000a663028` exclusive requires N>=10 with cursor0. It saves encoded extent N+0x2e8366f85c5b16d6 modulo2^64. The payload gate at `0xfffffe000a63c400`..`0xfffffe000a63c490` exclusive requires unsigned64(N)>=10+unsigned64(L), with both u32 operands widened before addition. This prevents arithmetic wrap of 10+L in that predicate. It does not itself prove readable memory: tag search has already read four bytes, so header-storage validity remains an independent premise.

| Transformed type T | Selected behavior |
| --- | --- |
| 0x6685 | Extract B+10, save M and request the allocation/copy path |
| 0xb2db | Alternate cursor/length path; subsequent type gate rejects and clears outputs with W23=0xce515ae1 |
| 0xa129 | Same alternate-length/rejection behavior |
| Any other u16 | Reject at the type switch before pointer extraction |

The type switch is at `0xfffffe000a63c498`..`0xfffffe000a63c4c0` exclusive. Encoded length is stored through the saved caller address at `0xfffffe000a63de50`..`0xfffffe000a63de64` exclusive. These numeric types remain unnamed; neither an identity string nor an entitlement field is established.

## Allocation, reverse copy and status boundaries

The allocation request at `0xfffffe000a63df08`..`0xfffffe000a63df88` exclusive reloads M and passes X0=zero_extend32(M XOR0x31ae0066)=L. The E-bank composition selects index0xf10, original slot `0xfffffe000847a7a0`, target `0xfffffe000c4ba60c` and IA modifier0xca0c. Original symbols identify `_IOMallocData` and `_IOMallocData_external`. The complete adapter retains the size, calls `0xfffffe000bcfe5b8` and performs conditional accounting/instrumentation. It is captured for identity/custody; no complete allocator semantics or execution is claimed.

The return proof cuts the ordinary call: X0-X18 and X30 become arbitrary, X0 is then the abstract result Z, and X19-X29/SP and saved cells retain the explicit ordinary-ABI/storage premises. It proves the source's Z-null gate and reload of W23 from F+0x9ec. This is not proof of all callee memory effects or native zero-size allocation behavior.

For nonnull Z, the source takes the direct publication path if L=0. For L>0 it initializes unsigned64 counter i=L. Each iteration at `0xfffffe000a63e0a0`..`0xfffffe000a63e10c` exclusive performs:

```text
i := i-1
Z[i] := decode_byte(B+10+i)  # STRB at 0xfffffe000a63e0ec
if i != 0: repeat
publish Z through C+0x158; W23 := 0x31ae0066
resume saved outer continuation
```

The universal step proof covers1<=old_i<=L, preserves the body/key/result/loop state, and establishes the exact byte store and loop target. The separate linear-integer certificate maps iteration j to index L-1-j,0<=j<L, reaches zero on the last iteration and excludes index L. Under stable valid input/result storage and the normal pointer branch at each iteration, induction gives exactly L decoded stores at indices L-1..0. The selected path requests L bytes, not L+1, and has no additional terminating-byte store. Payload content or an earlier construction invariant could supply a NUL; neither is established here.

| Outcome | Pointer output C+0x128 | Encoded length S+0xaa8 | Primary status / continuation |
| --- | --- | --- | --- |
| Selected successful copy | Z | L XOR0x31ae0066 | W23=0x31ae0066; hash gate |
| L=0, abstract nonnull allocator result | Z; no copy | 0x31ae0066 | Same publication; native allocation/content behavior unknown |
| Common clear path | 0 | 0x31ae0066, encoding length0 | W23 remains the separate path-specific status; hash gate |
| Empty node search | 0 | 0x31ae0066 | W23=0xce515bda; hash gate |
| Types0xb2db/0xa129 | 0 | 0x31ae0066 | W23=0xce515ae1; hash gate |
| Null allocation | 0 | 0x31ae0066 | W23 reloaded from F+0x9ec; domain unknown; hash gate |
| Null incoming container | Outputs unchanged by this entry/resume path | Outputs unchanged | W23=0xce515bbf; direct hash-gate resume |

In particular, not every failure clears outputs. The predecessor's raw-status gate admits only0x31ae0066, then its independent null-pointer gate rejects null input even if the saved status happened to equal success. That composition remains conditional on stable caller cells and continuation phase. No length value participates in the earlier captured hash loop. Without an upstream termination invariant, this increment cannot bound that hash traversal by L or infer a native fault.

## Original private table slots

The following mapping records the dispatcher pointers actually used by the selected spans. Indices are internal continuation/branch indices, not IOKit selectors or Mach message identifiers. All original slot words, pointer-format-8 metadata and terminal transfer words are retained in the checks receipt.

| Private index | Original pointer slot | Target |
| --- | --- | --- |
| 0x1f | `0xfffffe0008473018` | `0xfffffe000a639b30` |
| 0x6a | `0xfffffe0008473270` | `0xfffffe000a662ee0` |
| 0x133 | `0xfffffe00084738b8` | `0xfffffe000a6570c4` |
| 0x13d | `0xfffffe0008473908` | `0xfffffe000a63c3fc` |
| 0x179 | `0xfffffe0008473ae8` | `0xfffffe000a638350` |
| 0x181 | `0xfffffe0008473b28` | `0xfffffe000a63d624` |
| 0x22d | `0xfffffe0008474088` | `0xfffffe000a6630e0` |
| 0x22e | `0xfffffe0008474090` | `0xfffffe000a637128` |
| 0x22f | `0xfffffe0008474098` | `0xfffffe000a656ef0` |
| 0x23f | `0xfffffe0008474118` | `0xfffffe000a63dff0` |
| 0x241 | `0xfffffe0008474128` | `0xfffffe000a663110` |
| 0x252 | `0xfffffe00084741b0` | `0xfffffe000a63930c` |
| 0x2c4 | `0xfffffe0008474540` | `0xfffffe000a662a28` |
| 0x2e3 | `0xfffffe0008474638` | `0xfffffe000a63c494` |
| 0x2e6 | `0xfffffe0008474650` | `0xfffffe000a6630e0` |
| 0x49a | `0xfffffe00084753f0` | `0xfffffe000a662ab4` |
| 0x50c | `0xfffffe0008475780` | `0xfffffe000a662c60` |
| 0x50d | `0xfffffe0008475788` | `0xfffffe000a662c44` |
| 0x52d | `0xfffffe0008475888` | `0xfffffe000a662c00` |
| 0x542 | `0xfffffe0008475930` | `0xfffffe000a662a80` |
| 0x54e | `0xfffffe0008475990` | `0xfffffe000a663110` |
| 0x572 | `0xfffffe0008475ab0` | `0xfffffe000a63de4c` |
| 0x590 | `0xfffffe0008475ba0` | `0xfffffe000a63de68` |
| 0x630 | `0xfffffe00084760a0` | `0xfffffe000a662be0` |
| 0x63e | `0xfffffe0008476110` | `0xfffffe000a662b00` |
| 0x659 | `0xfffffe00084761e8` | `0xfffffe000a63e09c` |
| 0x68f | `0xfffffe0008476398` | `0xfffffe000a63e110` |
| 0x6b0 | `0xfffffe00084764a0` | `0xfffffe000a63deb8` |
| 0x7b4 | `0xfffffe0008476cc0` | `0xfffffe000a662f24` |
| 0xa05 | `0xfffffe0008477f48` | `0xfffffe000a6630e0` |
| 0xa91 | `0xfffffe00084783a8` | `0xfffffe000a63df04` |
| 0xadf | `0xfffffe0008478618` | `0xfffffe000a662f80` |
| 0xb01 | `0xfffffe0008478728` | `0xfffffe000a6630e0` |
| 0xcc2 | `0xfffffe0008479530` | `0xfffffe000a66302c` |
| 0xe07 | `0xfffffe0008479f58` | `0xfffffe000a637138` |
| 0xe21 | `0xfffffe000847a028` | `0xfffffe000a63c4f0` |
| 0xe5d | `0xfffffe000847a208` | `0xfffffe000a63e084` |
| 0xe65 | `0xfffffe000847a248` | `0xfffffe000a63e110` |
| 0xe91 | `0xfffffe000847a3a8` | `0xfffffe000a63d680` |
| 0xeb6 | `0xfffffe000847a4d0` | `0xfffffe000a662c44` |

The separate search callback value uses F-bank composition(key0x87, constant0xdf, additive-0x93) to select pool index0x4c at `0xfffffe0008472160`. The original unauthenticated pointer is `0xfffffe000847bce4`; bias-4 gives opaque value `0xfffffe000847bce0`. Both 256-input bank identities are exhaustively checked. This pool value does not replace C+0x400 as the matched-node output.

## Architectural scope and cost

This increment establishes an internal reusable search/decoder/copy facility and its caller-specific private continuation ABI inside `_PRnut72j9`. It establishes no new incoming/outgoing Mach port, message emission site, right transfer or successful daemon-kext exchange. Those remain tracked in [Mach ports](mach_ports_report.md), [interface ABI](interface_abi_report.md), [context/task flow](context_descriptor_task_flow_report.md) and [investigation status](interface_investigation_status.md). Original container construction, key production, external field identity and payload lifetime remain unknown.

For a stable finite chain of K visited nodes and admitted payload of L B, selected search/header/copy work is O(K+L), excluding allocator cost and wider dispatcher work. Search decodes four tag bytes per visited node; matched header processing decodes ten more bytes, including re-reading the four-byte tag; copy decodes L bytes. The selected header/copy state uses O(1) auxiliary space plus the L B allocation. A following hash traversal adds O(U), where U is the readable prefix through its first NUL. U is not bounded by L here; a NUL inside the copied L bytes would supply that additional bound. Zero-size/non-null allocator returns are abstract seams, not observed native behavior.

Extraction takes O(B+I+256R) time/space for captured bytes B, decoded instructions I and R bank rules. Proof construction takes O(instruction instances+query DAG); SMT search is separate, with30 s/query limits. The index certificate uses exact integers and the instruction model uses explicit u8/u16/u32/u64 widths. No timing or native memory-use measurement is claimed.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| IR-A1: Pinned images, original fixups/symbols and predecessor receipts | IR1-IR9 provenance | Fresh dual-image comparison, complete container/adapter custody, dependency hashes, reconstructed formulas and four altered-evidence comparisons |
| IR-A2: Selected W24/token/phase, stable C/S/F epochs and retained output/continuation cells | IR1-IR9 composition | Recover all incoming edges and intervening cell effects; current literal roots and continuations do not establish full native reachability |
| IR-A3: Stable readable finite container chain and correctly identified node/buffer fields | IR2-IR4, IR7-IR9 | Universal next/match/empty gates; recover constructor, allocation identity, cycle/termination and locking contracts before asserting native structure identity |
| IR-A4: Nonnull nonwrapping distinct frame/scratch/source/node/buffer/result ranges, separated from immutable image | IR1-IR9 memory contracts | Explicit symbolic separation and address obligations; trace escaped aliases and native callee memory effects; declared N does not prove earlier tag-read validity |
| IR-A5: Stable K26/KEY20 view and normal pointer branches during selected decodes/copy | IR3-IR8 | Universal byte/type/length obligations and eight separate alternate MOVK transforms; recover key origin and native retag-address compatibility before generalizing |
| IR-A6: Ordinary allocator return preserves callee-saved registers/SP and retained storage; valid writable result extent for L>0 | IR6-IR8 | Exact original symbol/adapter capture, caller-saved havoc, all-result64 gate and every-counter64 copy step; native allocator and zero-size semantics remain open |
| IR-A7: Payload termination, business identity and ownership are unknown | IR8, IR9; limits on hash composition | Trace the original payload producer and content contract, length ownership and deallocation; the selected exact-L copy does not supply a termination invariant |
| IR-A8: Saved-status domain, original marker producer, synchronization and daemon correlation remain unknown | IR9 external scope | Follow F+0x9ec aliases/callees, source+0x20 production, all list/table writers and correlated successful selector26/context transactions |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Original O/J/B constructor and encoded-tag0x2685a3ce payload producer | Establish field identity, external influence, readable extent and termination contract |
| High | K26 producer and alternate retag address semantics | Connect the protected-memory reader to its storage/key lifecycle |
| High | Allocation publication consumers and deallocation paths | Establish lifetime/ownership for C+0x128 beyond the selected hash use |
| High | F+0x9ec escaped aliases and source+0x20 producer | Close saved-status domain and independent original tunnel-marker channel |
| Medium | Other shared-reader callers and output-cell combinations | Determine reusable reader/type ABI without conflating caller-specific fields |
| Medium | Correlated fairplayd/provider/selector26 transactions and synchronization | Bind private field contracts to observed successful cross-layer behavior |
| Low | Other uses of transformed types0x6685/0xb2db/0xa129 | Identify reuse after constructors and common object epochs are established |

## Quality gates

- **QG1**: Factual instruction, data-flow and interface analysis requires no normative conclusion.
- **QG2**: IR-A1-IR-A8 enumerate assumptions, dependent claims and falsification probes.
- **QG3**: Selected request/search/header/type/extent/allocation/copy/publication/resume paths are covered; the wider interface goal remains active.
- **QG4**: Byte extents, low16 versus temporary32, u32-to-u64 widening, exact L request/copy, reverse-index induction and algorithmic costs are explicit.
- **QG5**: Encoded length versus status, two node layouts, protected-memory versus wire format, normal versus retagged addresses, common clear versus null-container resume and zero-size allocator seams remain distinct.
- **QG6**: Original dual-image words, symbols/fixups, 39 nonvacuous formulas, three predecessor rechecks, 512 bank inputs and four custody controls support the bounded claims.
- **QG7**: Ranked continuation retains constructor/termination, key/retag, ownership, saved-status/marker and daemon-correlation boundaries.

## Container-staging increment

The [upstream container-staging report](userclient_container_staging_report.md) closes saved pointer/low32-size staging, the matching protected byte transform, shared parser entry/output/continuation cells and original16 B `site.FPTTLV` allocation metadata. It covers the complete empty parser path. Nonempty construction of the matched node and decoded-tag0x172ba3a8 field identity remain open; no termination guarantee is added.

## Record-node construction increment

The [upstream record-node constructor](userclient_record_nodes_report.md) supplies original 32 B FPTTLVNode allocation metadata and stores total extent at+0x10 and buffer at+0x18, matching the reader's accessed layout. Full header production, payload copy and list publication are still required to establish runtime producer-consumer identity.

## Protected record-writer increment

The [writer-side construction](userclient_record_writer_report.md) now proves a matching protected ten-byte header and type0x6685 exact-L payload copy using the same address-keyed mask. Writer/reader formula compatibility is established under matching epochs; publication of this node into the live reader list and original field identity remain unknown.

## Record lookup and publication increment

The [publication caller](userclient_record_publication_report.md) reuses the same protected tagged-node search with arbitrary tag T, output C+0x628 and return index0x7b. It establishes conditional list publication of the writer node and selected retirement requests; live consumer epochs, original field identity and native ownership remain open.

## Staged metadata and cursor increment

The [metadata follow-up](userclient_record_metadata_report.md) establishes this increment. The producer-side staged header now matches the recovered protected ten-byte record representation and transformed type0x6685 body source. Shared word callbacks differ between tag and length phases; full native reader linkage remains conditional.

## Parser cleanup increment

The [cleanup follow-up](userclient_parser_cleanup_report.md) establishes this increment. It supplies conditional producer-side failure/status/output and retained-list retirement context. Native reader/container identity remains a separate premise.
