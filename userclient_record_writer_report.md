# Protected record-header writer and type-6685 payload copy

The selected constructor writes a complete ten-byte protected header into its new buffer: a big-endian32 tag word, big-endian16 type and big-endian32 payload length, each protected with the destination address's byte mask. The four-byte writer is invoked twice, at offsets 0 and 6, with the type stores at offsets 4 and 5. Its output matches the previously recovered reader encoding under the stated key/storage premises.

For transformed type `0x6685`, the following path skips copying exactly when decoded length L is zero. Otherwise it copies exactly L protected payload bytes from retained source P into buffer offsets10 through L+9, removing the source-address protection and applying destination-address protection. The selected path reaches `0xfffffe000a655ef0` after either zero-length bypass or the final copy step. The continuation's lookup/list-publication/cleanup behavior and the original metadata/body producers remain unknown. The wider interface investigation remains active.

## Evidence and validation

| Artifact | SHA-256 of decoded content | Coverage |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Pinned instructions and normalized data |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original instructions and chained private table pointers |
| [Checks](triage_evidence/userclient_record_writer_checks.json.zst) | `7aafa0ddba91a2f8f2a4894e72da60756202f97f153247eba88d3f07c1c1a344` | 10 spans, 260 selected instructions, six terminal transfers and two saved-control cells |
| [Audit](triage_evidence/userclient_record_writer_audit.json.zst) | `0f55c6456491252ba0ed20cc8a4b4d687c5261645a60180a9967b4e6a1385df3` | 16 new nonvacuous UNSAT obligations, five predecessor rechecks, 4,408 proof instruction instances |

The [extractor](triage_evidence/recover_userclient_record_writer.py) compares selected bytes with both images and rechecks the complete 50,634-instruction `_PRnut72j9` container hash. It captures original table pointers, a 319-instruction token-retention envelope and five exact-offset literal-SP access sites. The [audit](triage_evidence/audit_userclient_record_writer.py) freshly reconstructs the preceding [node-constructor evidence](userclient_record_nodes_report.md), composes its source through writer setup, and covers 260 new and 331 predecessor PCs. The 319-instruction envelope is checked separately; the modeled predecessor-PC count is 331. All six captured alternate MOVK sites have independent pointer-bit-transform proofs.

Five frozen predecessor formulas are re-solved: writer setup, reader tag/type/length decoding and the reader's finite reverse-index certificate. These are formula rechecks; the writer proofs additionally execute the selected predecessor source through setup. Four altered-evidence equality controls reject a changed instruction byte, header extent, serialization description and unsupported list-publication claim. They test custody equality, not native behavior. The [delivery verifier](triage_evidence/verify_userclient_record_writer_delivery.py) reconstructs the receipts and checks publication custody. No target code executes, no native PAC authentication is tested and no IDB is changed.

| Claim | Established result | Dependencies |
| --- | --- | --- |
| RW1 | Source roots and exact fixed saved writer controls | RW-A1-RW-A3 |
| RW2 | Four protected tag bytes and type-writer continuation | RW-A1-RW-A5 |
| RW3 | Two protected type bytes and selected length bridge | RW-A1-RW-A5 |
| RW4 | Four protected length bytes; complete ten-byte header preserves node fields | RW-A1-RW-A5 |
| RW5 | Type-6685 path recovers exact L and zero/nonzero dispatch | RW-A1-RW-A5 |
| RW6 | Universal protected payload-copy step and exact exit/backedge | RW-A1-RW-A6 |
| RW7 | Finite indices cover exactly L payload bytes; zero input performs no payload copy | RW-A1-RW-A6 |
| RW8 | Alternate retag transforms and scoped literal-SP inventory | RW-A1-RW-A3, RW-A5, RW-A8 |
| RW9 | Reader compatibility, cost and architectural limits | RW-A1-RW-A8 |

## Channel definitions and composition boundary

C is the selected scratch base, S the source-state base and F the current SP epoch. H is the retained 16 B container, J the new 32 B typed node, Z its buffer and P the retained body source. T is the encoded tag32 channel, U the transformed type16 channel, E the encoded length32 channel and `L=E XOR 0x31ae0066`. The preceding constructor supplies J+0x10=L+10 as u32, J+0x18=Z, C+0x6b8=J, C+0x348=P and the writer setup. The constructor's exact gate requires `L<=0xfffffff5`.

The current composition begins at the preceding post-header cut. T/U/E and P are not yet proved to originate at particular byte offsets of the original staged input. The special pair T=0x31ae0066 and U=0x6685 selects the earlier success bypass; the modeled constructor path therefore excludes that pair. The header-writing results otherwise admit every tag32/type16 value and every admitted length32 value.

The fixed byte protection is:

```text
K0 = 0x02e859d27e491464
K1 = 0x4dae26df20976138
mask8(a) = low8(((ROR64(a AND ~7, 8) + K0) XOR K1)
                >> ((a AND 7)*8))
protected_byte(a, plain8) = plain8 XOR mask8(a)
```

Arithmetic wraps modulo2^64. The main word/copy proofs take the source's normal pointer branches. Valid separated nonwrapping storage and stable address/key epochs are premises. Native retagged-address equivalence is not assumed.

```text
constructor + writer setup
             |
  word writer: Z[0..3], plaintext BE32(T XOR success)
             |
  type writer: Z[4..5], plaintext BE16(U XOR 0x365e)
             |
  bridge -> same word writer
             |
  word writer: Z[6..9], plaintext BE32(L)
             |
  type dispatch: selected U == 0x6685
             |
       L == 0 ? ---- yes -------------------+
             | no                          |
  P[L-1..0] -> protected Z[L+9..10]          |
             |                             |
       final counter == 1 -----------------+
                                           |
                            continuation 0xfffffe000a655ef0
                            lookup / linking / cleanup: open
```

This is a private protected-memory representation. The recovered byte order does not by itself establish an external wire format or a Mach-message body contract.

## Fixed saved controls and writer selection

At `0xfffffe000a6355f4`..`0xfffffe000a6355fc` exclusive, W15 is assigned token0x886a1ca3. A319-instruction dual-image envelope through `0xfffffe000a635af8` has no control transfer or SP/X15/W15 write. The selected saved-control arithmetic at `0xfffffe000a635af8`..`0xfffffe000a635b20` exclusive proves:

| Cell | Width | Source expression and value | Consumer |
| --- | --- | --- | --- |
| F+0x570 | 8 B | `(0x8d0 XOR 0x8dd)*0xa7 = 0x87b` | Payload count preparation and copy backedge |
| F+0x60c | 4 B | `(0x886a1ca3+0xb6b8b058) mod2^32 = 0x3f22ccfb` | Type writer masks with0xc0dd373d ->0x439 |

Retention of these cells through the intervening dispatcher remains a stable-epoch/alias premise. The syntactic whole-container inventory records one exact literal-SP store and one exact literal-SP load for F+0x60c, and one store plus two loads for F+0x570. It does not enumerate overlapping/paired/indexed accesses, other-base aliases, calls or other SP epochs. Counts therefore do not prove absence of intervening writes.

The first word-writer entry is `0xfffffe000a654c64`; its captured body begins at `0xfffffe000a654c68`. On the first invocation, its offset arithmetic resolves to0 and the selected continuation index is0x152, targeting the type writer at `0xfffffe000a655068`. That writer uses the proved masked saved control0x439, writes the type bytes and selects the bridge at `0xfffffe000a654c44`. The bridge restores X0=K0 and selects the same word writer. The next word offset resolves to6; continuation index0x16c selects type dispatch at `0xfffffe000a654e70`.

## Exact ten-byte header stores

W23 initially carries T XOR0x14ac30f9. The shared word writer's four byte constants form0x2502309f. Their composition gives `(T XOR 0x14ac30f9) XOR 0x2502309f = T XOR 0x31ae0066`. The second invocation supplies E XOR0x14ac30f9 instead, producing plaintext E XOR0x31ae0066=L. The type setup supplies the high and low byte transforms for U XOR0x365e.

| Buffer offset | Plaintext byte | Original store PC |
| --- | --- | --- |
| 0 / 6 | High byte of T XOR success / L | `0xfffffe000a654ccc` |
| 1 / 7 | Next byte of T XOR success / L | `0xfffffe000a654d18` |
| 2 / 8 | Next byte of T XOR success / L | `0xfffffe000a654d74` |
| 3 / 9 | Low byte of T XOR success / L | `0xfffffe000a654db0` |
| 4 | High byte of U XOR0x365e | `0xfffffe000a6550b8` |
| 5 | Low byte of U XOR0x365e | `0xfffffe000a6550e4` |

Each store writes one byte XOR mask8(Z+offset). The proofs establish the exact address and value for all ten store instances, not merely equality on sampled headers. They also preserve J's two zero pointer-width fields, u32 total extent, buffer field, retained P and the metadata channels used by later dispatch.

The [reader](userclient_input_reader_report.md) separately decodes protected bytes into BE32 tag XOR success, BE16 type XOR0x365e and BE32 length XOR success. Applying those recovered decoding expressions to the writer's representation returns channels T, U and E. This establishes formula/source compatibility under matching keys, stable storage and caller epochs. It does not establish that a live reader reaches this particular J; list publication remains open.

## Selected type-6685 payload path

The first type gate compares U with0xa129 and branches to `0xfffffe000a655434` for inequality. The secondary gate there compares U with0x6685 and enters `0xfffffe000a655d38` on equality. Thus the selected payload proof takes U=0x6685. Other types have different source paths and are outside this copy claim. No business name is assigned to either magic type value.

The constructor's S+0x100 channel is `zero_extend32(L)+0x41a549061921706d` modulo2^64. The payload-size gate reads its low32 bits and proves that its obfuscated reduction is `L XOR 0x1921706d`. Equality with0x1921706d therefore tests exactly L==0, including lengths whose earlier low32 addition wraps. Zero L selects `0xfffffe000a655ef0`; nonzero L selects preparation at `0xfffffe000a655df4`.

Preparation loads Z through J+0x18 and P from C+0x348. Using the saved0x87b control, it recovers X10=zero_extend32(L), X8=Z and X9=P, then requests the reverse-copy entry at `0xfffffe000a655e2c`. A symbolic low32 read is explicitly extracted from the actual preceding64-bit store, rather than seeded as an unrelated value.

For every admitted old counter `1<=c<=L` and every protected source byte q8, the source step at `0xfffffe000a655e30`..`0xfffffe000a655eec` exclusive proves:

```text
source_address      = P + c - 1
destination_address = Z + c + 9
stored_byte         = q8 XOR mask8(source_address)
                         XOR mask8(destination_address)
next_counter        = c - 1
next_entry          = 0xfffffe000a655ef0  if c == 1
                      0xfffffe000a655e2c  if c > 1
```

The byte load is at `0xfffffe000a655e58`; the byte store is at `0xfffffe000a655ecc`. P/Z, K0/K1, the table root and saved loop control survive the selected loop step. The source arithmetic uses an apparent different input key and an extra0x8d byte XOR; the universal store proof reduces their combination to the same mask8 source decoder. It does not assume that the apparent input/output expressions are equivalent.

An independent finite-index obligation proves that after j completed steps, `i=L-1-j`, with0<=j<L, lies in0..L-1, reaches0 exactly at j=L-1 and decreases by1 while another step remains. Destination index i+10 lies in10..L+9. Together with the exact initial count and branch proof, this covers exactly L source bytes and L destination payload bytes. Header stores cover0..9; no payload byte is written at index L+10.

For zero L, the path skips the copy body and requires no readable P payload extent. For nonzero L, the proof requires a readable stable P..P+L-1 region separated from the writable buffer and retained state. No additional NUL byte is introduced by this header/copy sequence. Whether the supplied payload contains a decoded terminator remains unknown.

## Pointer retags and original private table

Four conditional retag sites occur in the word writer, which executes twice, and two occur in the payload-copy step. The main byte/address proofs require the normal branches. Separate proofs establish each captured alternate MOVK transform as `new_pointer=(old_pointer AND 0x0000ffffffffffff) OR 0xc8a2000000000000`. Native readability, alias equivalence and PAC/BTI behavior remain unknown.

| Private index | Original slot | Target |
| --- | --- | --- |
| 0x152 | `0xfffffe00084739b0` | `0xfffffe000a655068` |
| 0x16c | `0xfffffe0008473a80` | `0xfffffe000a654e70` |
| 0x2c9 | `0xfffffe0008474568` | `0xfffffe000a654c44` |
| 0x439 | `0xfffffe00084750e8` | `0xfffffe000a654c64` |
| 0x757 | `0xfffffe00084769d8` | `0xfffffe000a655df4` |
| 0x76a | `0xfffffe0008476a70` | `0xfffffe000a655ef0` |
| 0x87b | `0xfffffe00084772f8` | `0xfffffe000a655ef0` |
| 0x8d0 | `0xfffffe00084775a0` | `0xfffffe000a655e2c` |

These are private table indices, not Mach message IDs or IOUserClient selectors. Indices0x76a and0x87b share a target but originate in the zero-size gate and final copy step respectively; their incoming control registers are not interchangeable merely because the pointer target matches.

## Architectural scope and cost

The selected source chain now constructs the protected header and, for type0x6685, populates its payload buffer from retained P. The original metadata/body producers, complete original staged-input extent contract, node lookup/insertion/replacement, cursor advancement, allocation/free pairs and native lifecycle remain open. No new Mach right, port endpoint, message emission site or successful daemon-kext transaction is established. Existing external-interface evidence remains in [Mach ports](mach_ports_report.md), [interface ABI](interface_abi_report.md) and [investigation status](interface_investigation_status.md).

Header construction has 10 byte stores and O(1) selected work. For admitted type0x6685, payload copying takes O(L) time, L byte reads, L byte stores and O(1) auxiliary state. Total selected serialized storage is L+10 B, matching the prior buffer request. This excludes staging/container/node allocations, allocator cost, native ownership and later continuation work. Extraction/inventory take O(B+I) time/space; proof construction takes O(instruction instances+query DAG), with SMT search separate and30 s/query limits.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| RW-A1: Pinned images, original table pointers, predecessor scripts and receipts | RW1-RW9 | Fresh dual-image/full-container checks, fresh node evidence, reconstructed formulas, original targets and four custody controls |
| RW-A2: Stable C/S/F epochs, selected predecessor phase/root values, F+0x570/F+0x60c retention | RW1-RW9 | Token def-use envelope and actual producer proofs; follow intervening aliases/calls and all incoming paths rather than inferring retention from literal-access counts |
| RW-A3: AArch64 W/X, shifts, TST, branches and byte-store semantics match the model | RW1-RW9 | All-tag32/type16/length32 proofs, fixed controls, all-counter64/byte8 step and explicit low32 extraction |
| RW-A4: Prior ordinary allocation cuts and valid separated H/J/Z storage | RW2-RW7, RW9 | Caller-saved havoc and source node-field proofs; establish actual allocator effects, object identity and lifetime |
| RW-A5: Normal pointer branches, stable address-key epochs and nonwrapping buffer extent L+10 | RW2-RW9 | Exact byte addresses/values and six alternate bit-transform proofs; establish native retag/storage behavior before generalizing |
| RW-A6: Type0x6685 and readable stable nonoverlapping P payload for L>0; origin of P remains unknown | RW6, RW7, RW9 | Exact source/destination/counter proofs and finite induction; recover body producer, cursor bounds and native aliases |
| RW-A7: Reader uses the matching key/encoding and intended node/storage epoch | RW9 compatibility | Separately re-solved reader formulas plus writer-derived bytes; prove list publication and live consumer linkage |
| RW-A8: Literal-SP inventory is syntactic; complete type dispatch, publication, cleanup, termination and external control remain unknown | RW8, RW9 limits | Trace continuation0xfffffe000a655ef0, other type branches, cursor/input producers, allocation/free pairs and correlated daemon/provider exchanges |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Common continuation `0xfffffe000a655ef0` | Recover tag lookup, duplicate policy, node publication and processing continuation |
| High | Body P at C+0x280 -> C+0x348 and metadata producers | Establish original staged-byte provenance, field identity and cursor/length bounds |
| High | Parser cursor advancement and failure cleanup | Close complete nonempty parse and allocation ownership rather than extrapolating from this selected writer |
| High | Original caller and successful daemon/provider exchange | Establish external influence and cross-layer correlation |
| Medium | Other type cases after `0xfffffe000a654e70` | Characterize different payload representations and width checks |
| Medium | Native retag/key epochs and overlapping-input behavior | Determine whether the model's storage/pointer premises hold in the actual execution environment |
| Low | Wider syntax inventories around the two saved controls | Locate aliases while preserving the distinction between counts and semantic absence |

## Quality gates

- **QG1**: Factual instruction, data-flow and interface claims require no normative conclusion.
- **QG2**: RW-A1-RW-A8 enumerate dependencies and falsification probes.
- **QG3**: Protected header construction, selected type dispatch, exact payload-count recovery, universal copy step and finite coverage are established; the full interface objective remains active.
- **QG4**: u16/u32/u64 channels, low32 overlap, big-endian fields, modulo arithmetic, byte extents, exact indices and scoped costs are explicit.
- **QG5**: Writer output versus original input provenance, normal versus alternate pointers, header versus payload, selected type versus all types, formula compatibility versus live linkage and continuation selection versus publication remain distinct.
- **QG6**: Original dual-image words/table pointers, 16 nonvacuous formulas, five predecessor rechecks, 260 new/331 predecessor PCs and four custody controls support the bounded claims.
- **QG7**: Ranked continuation preserves lookup/linking, input/cursor provenance, cleanup, other types and native daemon-correlation questions.

## Record lookup and publication increment

The [post-writer publication increment](userclient_record_publication_report.md) closes selected tag lookup, empty/tail append, four-position replacement, old-record retirement requests and parser-gate return. It proves cursor preservation across these paths; the earlier cursor-advancement producer and full staged-envelope contract remain open.

## Staged metadata and cursor increment

The [metadata follow-up](userclient_record_metadata_report.md) establishes this increment. The selected metadata follow-up identifies the staged header and body source consumed by construction/writing and proves its original parser cursor update. Native ownership and complete type/failure coverage remain open.

## Parser cleanup increment

The [cleanup follow-up](userclient_parser_cleanup_report.md) establishes this increment. It establishes selected pending/list/container retirement requests and parser failure output. The valid-node cleanup contract does not establish every incoming allocation or lookup state.

## Parser caller and command dispatch increment

The actual parser caller now has a conditional command-field lookup, protected scalar reader and exact two-value switch. The first command links to the existing hash-input reader; second-body semantics, native storage/ownership and cross-layer correlation remain open. See the [command-dispatch report](userclient_command_dispatch_report.md) for the source contracts, status frontiers and assumption register.

## Caller cleanup and copy-back increment

Caller cleanup callback0x1a, distinct staged/auxiliary buffers, finite protected copy-back and outer allocation/retirement/status contracts are now established conditionally. Native identity, aliases, callee effects and cross-layer transaction correlation remain open. See the [caller-return report](userclient_caller_return_report.md) for original requests, proofs, scope and assumption probes.


The [query writer contract](userclient_query_writer_report.md) now establishes the three conditional14 B records: exact big-endian tags, raw type97 77 (parser-normalized0xa129), length4 and big-endian scalars0x4c0b0000/0x1f8/0x99ab. Each writer reaches the shared list lookup with W8 callback index0x6c (separate W0 control0x19) and retained pending-node/constructor-return state. This resolves the earlier query-byte frontier; actual query list publication/order, resulting serializer extent and native daemon pairing remain unknown. No additional Mach endpoint is established.
