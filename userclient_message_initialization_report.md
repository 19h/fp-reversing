# FPMessage initialization and common-parser re-entry

The source-built 112-byte attribute now feeds a separate 128-byte `site.FPMessage` allocation. The selected initializer reads all 107 defined attribute bytes, skips its five unwritten bytes, copies the two 32-byte fields and transforms the cached16 field with a fixed XOR mask. It writes 123 message bytes; five message bytes remain unwritten. Successful initialization hands the new message and retained input pointer/encoded extent to the previously analysed common FPTTLV parser at `0xfffffe000a636338`.

This advances the [attribute frontier](userclient_message_attributes_report.md) through message formation and an exact source-level parser re-entry. It does not establish native allocation, lifetime, authentication, input-layer identity, parsing completion or daemon/kext transport. Existing reference data sufficed; no IDB or original input was modified.

## Evidence custody

| Evidence | Identity / coverage |
| --- | --- |
| Original kernel collection SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Decoded checks SHA-256 | `ee8476cd7d45c03decdb7b7c0262a92b996c4f0ee7bdd2edc86aaf6666c86c61` |
| Decoded audit SHA-256 | `d617ec6a8652f52a94965058f3279b8b4d4c776e0cb9f164e20e8428a32d4144` |
| Selected flattened source | 24 spans / 628 words; all selected words covered; 25 original table pointers |
| Local zero-fill envelope | `[0xfffffe000a687d64, 0xfffffe000a687ecc)`, 360 bytes / 90 words captured; 80 words covered by the selected 32-byte contract |
| Local zero-fill envelope SHA-256 | `3afa55aa16f0f681267c4ae3df7e9d93b6486d5758fac263a36270c940e96f2f` |
| New source obligations | 425 nonvacuous UNSAT partitions across thirteen semantic contracts, including eight alignment-specific zero-fill contracts |
| Retained source obligations | 157 complete attribute-mode partitions re-solved in fresh contexts |
| Prefix custody | Five additional cells / 40 bytes per predecessor; 150 cells / 1200 bytes over thirty original prefixes |
| Bank custody | Six relations checked over all 256 inputs each: 1536 cases; three original sixteen-byte constant arrays |
| Conditional evaluations | Six retained u32 cases times four message-allocation/mode profiles, plus four exact ADID-field projections: 28 SAT/UNSAT pairs |
| Byte checks | 1722 message bytes; 2996 preserved attribute bytes; 896 zero-summary bytes; 224 transformed-field bytes; 56 protected ADID bytes |
| Controls | Three copied-source mutations produce satisfiable violations under satisfiable premises |

The [generator](triage_evidence/recover_userclient_message_initialization.py) rebuilds the preceding receipt and compares selected words with both pinned images, verifies original descriptors/fixups/banks/constants and reconstructs saved roots from original prefix stores. The [auditor](triage_evidence/audit_userclient_message_initialization.py) adopts the complete actual attribute state, proves the local zero-fill summary from source, and executes message initialization and parser handoff. The [delivery verifier](triage_evidence/verify_userclient_message_initialization_delivery.py) rebuilds receipts and checks publication custody. Frozen [checks](triage_evidence/userclient_message_initialization_checks.json.zst) and [audit](triage_evidence/userclient_message_initialization_audit.json.zst) are compressed JSON; hashes concern decoded bytes.

| Claim | Established result |
| --- | --- |
| MI1 | Original stores reconstruct the five additional frame roots, including the input-holder cell, 32-byte workspace, controller address and two bank bases. Earlier decoded/table/attribute outputs remain source-derived. |
| MI2 | Entry stages the retained original input pointer I and encoded extent N XOR SUCCESS, saves its callback and clears a separate 32-byte workspace through the local helper. |
| MI3 | For exactly32 zero bytes, the local helper covers every destination alignment, confines stores to that extent and preserves SP/X19-X30. Its X0 return differs from the standard C memset return. |
| MI4 | Nonzero extent requests the original 128-byte site.FPMessage descriptor; allocator NULL publishes raw `0xce515bb2` before pending cleanup without reading attribute bytes. |
| MI5 | Non-NULL allocation initializes two leading u64 fields and consumes all 107 defined attribute bytes; the five unwritten attribute bytes are never read on the selected path. |
| MI6 | The sixteen-byte source loop reduces to bytewise XOR with mask `e43a4ec1536f29ded6b30e155e083e20`; byte order is preserved despite descending traversal. |
| MI7 | The two source-built attribute modes yield distinct message word+0x14 values, while completing 123 defined message bytes and leaving five bytes unwritten. |
| MI8 | The new message, I and encoded extent enter the exact common-parser interface at `0xfffffe000a636338`. Exact ADID-field projections are conditional source results, with no whole-packet or native transport identity inferred. |

## Control and allocation interfaces

F/C/S/H/J/Z retain their earlier private-model meanings. P is the arbitrary raw selected-table payload, A the source-built attribute, M the new message allocation, I the retained original incoming input pointer and N its u32 extent. P and I are distinct interface variables. Complete composed profiles retain the earlier u32-record constraint N=14. A separate source cut establishes the extent gate for every u32 N without claiming that the composed predecessors observe N=0.

```text
actual table hit -> source-built attribute A
    |
    +-> a6575b0: stage I / encoded N / callback; clear 32-byte workspace
          |
          +-> N == 0: private early return [independent source cut]
          |
          +-> N != 0: request 128-byte FPMessage M
                |
                +-> M == 0 -> outer callback -> raw error -> pending cleanup
                |
                +-> M != 0 -> zero leading fields -> consume attribute A
                      -> copy64 / transform16 / metadata / derived flag
                      -> publish parser context M, I, encoded N
                      -> pending common FPTTLV parser at a636338
```

| Emission | Target / exact source interface |
| --- | --- |
| BRAA `0xfffffe000a636d30` | Entry `0xfffffe000a6575b0`, IA modifier0x2854; incoming X8=C+0x360, X20=I, W22=N XOR SUCCESS |
| BLRAA `0xfffffe000a657648` | Local helper `0xfffffe000a687d64`, IA modifier0x46ae; X0=S+0xcc8, W1=0, X2=32; nominal return `0xfffffe000a65764c` |
| BLRAA `0xfffffe000a657758` | Typed allocator adapter `0xfffffe000c4ba154`, IA modifier0xd0c8; X0=descriptor `0xfffffe000847b560`; nominal return `0xfffffe000a65775c` |
| BRAA `0xfffffe000a65793c` | Attribute-to-message initializer `0xfffffe000a653874`, IA modifier0x2ee0; X0=M, X19=A |
| BRAA `0xfffffe000a653d70` | Saved private callback `0xfffffe000a653e54`, IA modifier0x7fb0; selected initialized M and SUCCESS remain in source state |
| BRAA `0xfffffe000a656c04` | Common-parser entry `0xfffffe000a636338`, IA modifier0xb40b; target not executed in this increment |
| BRAA `0xfffffe000a641b38` | Pending cleanup `0xfffffe000a6621e4`, IA modifier0x682a, after allocation-failure status publication |

| Typed descriptor field | Original value |
| --- | --- |
| Address | `0xfffffe000847b560` |
| Name | `site.FPMessage` |
| Signature | `1122222222222222` |
| Flags u32 | 0x64 |
| Allocation extent | 128 bytes |
| Allocator slot | `0xfffffe000847a7b8`, target `0xfffffe000c4ba154` |
| Descriptor slot / bias | `0xfffffe00084723e0`, original target minus12 yields the descriptor |

The sixteen-character signature is recorded verbatim. This increment does not assign allocator scanning semantics to its characters. The adapter is the same pinned typed-allocation adapter documented by the preceding allocation reports; the new proof establishes this caller's descriptor and call interface, rather than executing a native allocator. Ordinary allocator return explicitly preserves X19-X29, SP and declared caller storage; volatile registers are forgotten before supplying symbolic M. Caller-storage preservation is an environment premise in addition to the register ABI.

## Local 32-byte zero-fill contract

The original local helper is captured separately from the 628 selected flattened words. Eight source executions partition destination addresses by D AND7=0..7, with a writable nonwrapping 32-byte extent, W1=0 and X2=32. They execute actual alignment-prefix, u64 stores and byte-tail instructions. Every byte D+0..31 is written zero exactly once; no other store occurs. SP and X19-X30 remain unchanged. The selected paths cover 80 of the captured 90 words; the remaining generic-length paths are not proved by this increment.

| Destination alignment | X0 at RET |
| --- | --- |
| D AND7=0 | D+32 |
| D AND7=1..7 | D+31 |

Thus the helper is not assigned the standard C memset return contract, which would return D. Its caller does not consume this return value. The composed model applies the proved 32-byte memory summary at S+0xcc8 and conservatively forgets volatile registers. It does not inject an assumed external zeroing effect or replay arbitrary native memory operations. All eight source contracts are re-established before accepting the summary application.

## Attribute-to-message mapping

Offsets are hexadecimal; multi-byte fields are little-endian. The selected initializer writes M+0 and M+8 as zero u64 values, then consumes A. All 107 initialized attribute byte positions are read; A+0x52..0x53 and A+0x6d..0x6f are absent from the read set.

| Message location / extent | Source-built value | Source evidence |
| --- | --- | --- |
| M+0x00..0x0f / 16 bytes | Two zero u64 fields | STR at `0xfffffe000a657818` and `0xfffffe000a65786c` |
| M+0x10..0x13 / 4 bytes | A+0..3 = u32 0x3908f615 | Post-index LDR `0xfffffe000a6538e8`; STR `0xfffffe000a6538f0` |
| M+0x14..0x17 / 4 bytes | Mode0: u32 1; mode!=0: u32 0 | A+4 copy `0xfffffe000a653cb4`; A+0x48 gate `0xfffffe000a653d24`; override `0xfffffe000a653d54` |
| M+0x18..0x37 / 32 bytes | A+0x08..0x27 | Descending byte-copy pairs `0xfffffe000a653934..0xfffffe000a653a30` |
| M+0x38..0x57 / 32 bytes | A+0x28..0x47 | Descending byte-copy pairs `0xfffffe000a653a34..0xfffffe000a653b30` |
| M+0x58..0x5b / 4 bytes | A+0x48: 32 in mode0, zero otherwise | STR `0xfffffe000a6538f8` |
| M+0x5c..0x5f / 4 bytes | A+0x4c: zero | STR `0xfffffe000a653900` |
| M+0x60 / 1 byte | A+0x50: zero in mode0, 1 otherwise | STRB `0xfffffe000a653908` |
| M+0x61 / 1 byte | A+0x51: 0x1a | STRB `0xfffffe000a653910` |
| M+0x62..0x63 / 2 bytes | Unwritten by this path | No selected source store |
| M+0x64..0x67 / 4 bytes | A+0x54..0x57 = P+0..3 | STR `0xfffffe000a653920` |
| M+0x68..0x77 / 16 bytes | A+0x58..0x67 XOR fixed mask | Sixteen loop stores at `0xfffffe000a653c6c` |
| M+0x78..0x7b / 4 bytes | A+0x68: u32 16 | STR `0xfffffe000a653918` |
| M+0x7c / 1 byte | 0xca with bit0 replaced by A+0x6c bit0: 0xcb | BFXIL `0xfffffe000a65392c`; STRB `0xfffffe000a653930` |
| M+0x7d..0x7f / 3 bytes | Unwritten by this path | No selected source store |

The A+4 word is zero on both actual attribute profiles. Its zero branch tests A+0x48 and changes M+0x14 to1 only when that length is nonzero. This increment establishes those two source-built cases, not the initializer's behavior for arbitrary externally supplied attributes. The generated32/cached32 distinction and all 64 earlier random requests retain their [attribute-report](userclient_message_attributes_report.md) scope. No cryptographic role is assigned to these fields.

The five unwritten attribute bytes are not copied into the five unwritten message bytes. Each set remains unknown in its own allocation epoch. No native allocator zeroing, observable export or information disclosure follows from the store/read sets alone.

For output index i=0..15, the source loop uses j=i-15. It reads A+0x67+j and writes M+0x77+j. All arithmetic on its mask words is modular; the stored byte equals:

```text
M[0x68+i] = A[0x58+i] XOR K[i]
K[i] = low8(-0x37*(i-15)-0x39)
       XOR B1[i] XOR B2[i] XOR B3[i] XOR 0x70
K = e4 3a 4e c1 53 6f 29 de d6 b3 0e 15 5e 08 3e 20
```

| Constant array | Original sixteen-byte range / selected pointer |
| --- | --- |
| B1 | `0xfffffe0007945f20..0xfffffe0007945f2f`; pool-selected pointer `0xfffffe0007945f24`, combined with +0xb+j |
| B2 | `0xfffffe0007942886..0xfffffe0007942895`; pointer `0xfffffe000794288c`, combined with +9+j |
| B3 | `0xfffffe0007932064..0xfffffe0007932073`; pointer `0xfffffe0007932064`, combined with +0xf+j |

The three bank decoders select these pointers for every controller-derived byte input. The source-derived loop control gives X12=0xdfb, making the second effective pointer offset `0xdfb-0xdf2=9`. Source byte-array reads and all sixteen output positions are checked explicitly. The mask is an exact local byte transform; no algorithm name or native secret identity is inferred.

## Parser handoff, errors and environmental boundaries

| Location / width | Source-derived value / emitter |
| --- | --- |
| C+0x5d0 / u64 | Saved outer callback `0xfffffe000a636d34`; STR `0xfffffe000a6575c4` |
| C+0x430 / u64 | C+0x360, retained output-cell address; STR `0xfffffe000a6575c8` |
| C+0x498 / u64 | I; STR through reconstructed F+0x6b8 at `0xfffffe000a6575d4` |
| S+0x150 / u32 | N XOR SUCCESS; STR `0xfffffe000a6575cc` |
| C+0x788 / u64 | M, including zero on allocation failure; STR `0xfffffe000a657794` |
| C+0x448 / u64 | Private initializer callback `0xfffffe000a653e54`; STR `0xfffffe000a653898` |
| C+0x718 / u64 | M for common parser; STR `0xfffffe000a656b98` |
| C+0x18 / u64 | I for common parser; STR `0xfffffe000a656b9c` |
| S+0xc8 / u32 | N XOR SUCCESS; STR `0xfffffe000a656bcc` |
| S+0x1e0 / u32 | 0xfbb3f478; STR `0xfffffe000a656bd0` |
| S+0xab8 / u32, failure only | 0xce515bb2; STR `0xfffffe000a641b1c` |

The last successful transfer is emitted at `0xfffffe000a656c04` to the exact block already analysed in the [early FPTTLV entry report](userclient_fpttlv_entry_report.md). This proves a control/data interface join: C+0x718 now names M, while C+0x18 and S+0xc8 carry the retained input pointer and encoded extent. The earlier parser's previous allocation/context epoch is not silently reused as this operation's completed parse. This increment stops before re-entry executes and reads no input-content byte through I.

Only pointer and extent custody are established for I here. Its relation to a native daemon packet layer, readable extent at the next parser invocation, contents and nonaliasing with the new message remain unproved by this increment. The message ownership premises separate M from the private roots/frame, H/J/Z, table header/array, A, raw selected payload P and image; they do not supply an independent native input-buffer epoch. No preservation claim is made for I's unmodelled bytes.

Allocation-NULL profiles skip the attribute initializer and parser handoff, return through `0xfffffe000a665154` and the outer callback, then publish the raw failure at S+0xab8 before pending cleanup. The independent extent gate selects the same private early-return block for N=0. That gate alone neither establishes its complete empty-input status nor makes N=0 reachable in the composed N=14 predecessor environment.

All new actual stores are checked against the separate 128-byte M extent or exact caller C/S/F cells. Under the stated ownership and allocator-storage premises, the protected record, H/J objects, shared table/array and all 107 defined attribute bytes are preserved. The local zero-fill summary has its own proved 32-byte exception at S+0xcc8. The earlier symbolic S+0xd0c word remains unchanged; no missing private value, random output, native message pointer or native payload byte is supplied. The stopped continuous guest is not extended beyond `0xfffffe000a654ae4`.

Successful profiles have 36 new u32 controller observations and 51 certified bank applications; allocation-NULL profiles have four and three respectively. Controller reads remain independent inputs. Each finite projection uses declared capacity128; general source contracts retain the preceding arbitrary positive-capacity premises. Four synthetic ADID-field projections preserve `fa83411297770000000400000000`, V=0 and all fourteen protected bytes without submitting a whole packet.

| Copied-source control | Detected violation / boundary |
| --- | --- |
| STRB `0xfffffe000a653938`: destination +0x37 -> +0x36 | Actual store misses the required M+0x37 destination; no value is invented for the unwritten target byte |
| MADD `0xfffffe000a653c50`: addend W24 -> WZR | The transformed byte at M+0x77 differs from the fixed-mask oracle |
| MOV `0xfffffe000a653d50`: immediate1 ->0 | Mode0 message word+0x14 differs from1 |

All controls stop at the pending common-parser transfer and have satisfiable environments and violations. UNSAT of every bounded counterexample partition proves its complete source conjunction; SAT premise checks prevent vacuity. No new Mach port, right disposition or Mach-message emission is established. The [Mach-port report](mach_ports_report.md) retains the separate transport evidence.

The selected initializer and exactly32-byte zero-fill take O(1) time/space with fixed copy/call counts. Evidence construction takes O(I+16I+8I+C*I+1536+query-DAG size) time/space, excluding SMT search. New partitions have 60-second solver bounds; retained formulas have 120-second bounds in fresh contexts. Source-query count is not a count of native observations.

## Assumption register

| Assumption | Dependent claims / stress test or falsification probe |
| --- | --- |
| MI-A1: Pinned images and dependency custody | MI1-MI8. Rehash both images, zero-fill envelope, source spans, original fixups/descriptors/banks/constants and preceding receipts. A different image invalidates these address-specific joins. |
| MI-A2: Complete prior source state and saved-root epochs | MI1-MI8. Reconstruct all 150 additional cells from original stores and re-solve 157 prior partitions. Intervening writes or another object/callback epoch invalidate the composition. |
| MI-A3: Writable separated nonwrapping M and declared existing roots | MI3-MI8. SAT-check every profile, compare each load/store address and width, and reject overlaps with admitted roots/image. I's independent content/epoch/readability is explicitly outside this ownership claim. |
| MI-A4: Ordinary authenticated allocator return and caller-storage preservation | MI4-MI8. Check target/modifier/link/SP, volatile havoc and saved registers; establish real allocator/PAC effects before claiming native admission. The source-proved local zero-fill has a separate summary contract. |
| MI-A5: Exact source lift, complete alignment partition and certified banks | MI2-MI8. Rebuild all eight zero-fill alignments, 1536 bank cases, six source-selected pointers, arrays, all new obligations and three mutations. Inspect post-index address updates and all 123 message bytes. |
| MI-A6: Source-built attribute domain and symbolic external inputs | MI5-MI8. Vary payload bytes, all provider words and the saved unknown workspace value under the two mode conditions. Inspect the exact attribute read set; arbitrary external attribute flags require separate path analysis. |
| MI-A7: Phase-qualified status, derived ADID substitutions and pending-parser interpretation | MI4-MI8. Compare raw status cells, exact ADID/protected bytes and context handoff. Execute the new parser epoch and match a native transport/input layer before claiming full parsing or daemon correspondence. |

## Bounded continuation

| Impact | Specific next interface / falsification target |
| --- | --- |
| High | Execute the common parser at `0xfffffe000a636338` from the new M/I/encoded-N context, preserving this operation's allocation/status epoch; compare its typed allocations and return routing with the earlier parser case. |
| High | Establish the original-input buffer's readable bytes, nonaliasing/lifetime and packet-layer identity at this re-entry. Pointer/extent equality alone does not join native daemon and kext transactions. |
| High | Trace consumers of M+0x14, the transformed16 field and the two 32-byte fields before assigning protocol or cryptographic roles. |
| High | Follow matching producer/table/attribute/message epochs and their cleanup/replacement synchronization; the exact local initializer does not establish native ownership. |
| Medium | Trace the five unwritten message bytes to later reads/copies/export boundaries, separately from the five skipped attribute bytes. Their contents and observability remain unknown. |
| Medium | Recover descriptor-signature interpretation in the pinned deeper allocator and compare its sixteen characters with actual message pointer consumers. |
| Low | Extend the local byte-fill proof to other lengths/values only for a located caller; the current 32-byte, zero-value and nonstandard-return contract must remain qualified. |

## Quality gates

- **QG1**: Pass. The report contains factual source contracts and requires no normative judgment.
- **QG2**: Pass. MI-A1 through MI-A7 identify dependent claims and explicit falsification probes.
- **QG3**: Pass for this increment. Message allocation, zero-fill ABI, complete selected initialization, fixed transform, status failure and parser re-entry are covered; the overall interface investigation remains active.
- **QG4**: Pass. u32/u64 widths, byte extents, hexadecimal offsets, modular operations, alignment partition, counts and algorithmic bounds are reproducible.
- **QG5**: Pass. Five skipped attribute bytes and five unwritten message bytes remain distinct; generic helper paths, arbitrary attributes, I's content/epoch, native allocation/PAC and complete parsing remain explicit unknowns.
- **QG6**: Pass. Original words/fixups/descriptors/constants, source queries, prior rechecks and satisfiable mutation controls provide primary provenance.
- **QG7**: Pass. Impact-ranked continuation covers parser epoch, input/transport identity, field consumers, ownership, unwritten-byte observation and deeper allocation metadata.
