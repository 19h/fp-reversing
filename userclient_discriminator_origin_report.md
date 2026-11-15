# UIDList discriminator algorithm and input-cell boundaries

The selected producer derives the UIDList node+0 discriminator from a nullable byte-string pointer loaded through scratch+0x128. A nonnull input uses a 5381-seeded, 64-bit wrapping `33*h + unsigned_byte` recurrence over bytes preceding NUL, followed by a single reduction modulo `2^32 - 1`. The producer stores the u32 result at source+0xc90 and rejects a zero result. A null pointer stores zero and rejects; a nonnull empty string stores 5381 and proceeds. An earlier raw-status gate must admit this work. These are conditional source contracts, with valid input storage and selected frame/dispatcher epochs assumed.

The discriminator is distinct from the u32 tunnel marker read at source+0x20 and subsequently tracked at node+4. Original input identity, the original marker producer, alias-complete saved-status effects, native lifetime/synchronization and successful daemon-kext transaction correlation remain unknown. This increment extends [UIDList publication](userclient_uidlist_publication_report.md), [replacement](userclient_uidlist_replacement_report.md), [replacement bootstrap](userclient_replacement_bootstrap_report.md) and [table insertion](secure_tunnel_table_insertion_report.md).

## Primary evidence and validation

| Artifact | SHA-256 of decoded content | Scope |
| --- | --- | --- |
| Normalized kext | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` | Pinned instruction/data image |
| Original kernel collection | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` | Original instruction words and pointer-format-8 chain membership |
| [Checks](triage_evidence/userclient_discriminator_origin_checks.json.zst) | `8cc0ee712b5eea591b69eb0049103b20db5109f6106299ef344ad401360ad07c` | 11 spans, 131 selected instructions, seven terminal transfers; six-cell inventory across 50,634 instructions |
| [Audit](triage_evidence/userclient_discriminator_origin_audit.json.zst) | `f282559f4763dfe5b85d01d483ce4e522e341d7e517ed0ffbc02ef3a1a95743a` | 13 new nonvacuous UNSAT obligations, seven predecessor query rechecks, 272 independent integer replays |

The [extractor](triage_evidence/recover_userclient_discriminator_origin.py), [audit](triage_evidence/audit_userclient_discriminator_origin.py) and [delivery verifier](triage_evidence/verify_userclient_discriminator_origin_delivery.py) reconstruct these results. Twelve instruction obligations and one unsigned-integer reduction certificate comprise the 13 new queries. They cover 301 proof instruction instances and all 131 selected PCs. Seven existing formulas revalidate discriminator search/publication, marker-to-key correspondence, post-writer marker transfer and both null-holder saved-status gates. Those are frozen-query re-solves with fresh enclosing-function byte custody, not fresh complete predecessor replays.

The separate integer interpreter reads the captured arithmetic, memory and branch instructions. It shares the disassembler with the symbolic model but does not use its lift, Z3 expressions or rewrite machinery. Its 272 cases cover all 256 first-byte values, null and empty inputs, embedded NUL, trailing bytes after NUL, nonzero byte sequences through length 1,024 B and an unsuccessful initial status. They are compared with an independent compact unsigned-integer hash implementation. Four altered-evidence comparisons reject a changed instruction, modulus claim, inventory write count or unsupported native-input-identity claim. These comparisons are custody controls, not semantic native mutation experiments. No native target or IDB executes or changes.

| Claim | Established result | Principal dependency |
| --- | --- | --- |
| DO1 | SP+0x478 retains C+0x128; selected initialization clears that pointer cell | DO-A1, DO-A2 |
| DO2 | Exact raw-status gate before nullable pointer handling | DO-A1, DO-A2 |
| DO3 | Distinct null-pointer, empty-string and first-nonzero-byte paths | DO-A1-DO-A3 |
| DO4 | Universal u64/u8 recurrence, next-byte gate and preserved loop state | DO-A1-DO-A4 |
| DO5 | Exact unsigned magic reduction modulo 0xffffffff | DO-A1, DO-A4, DO-A5 |
| DO6 | u32 result store, full64 zero test and local status assignment | DO-A1-DO-A5 |
| DO7 | Discriminator search channel remains separate from marker/key channels | DO-A1, DO-A2, DO-A6 |
| DO8 | Complete bounded literal-base reference inventory and its alias limitations | DO-A1, DO-A7 |
| DO9 | Replays, cost and external-interface boundaries | DO-A1-DO-A8 |

## Selected control flow and fields

C is the current scratch base in X2, S the source base in X4, P the pointer loaded through C+0x128 and K the resulting u32 discriminator. Register roles are phase specific. Table indices below are private dispatcher indices, not external IOKit selectors.

```text
raw status32 == 0x31ae0066 ?
  +-- no: failure continuation
  +-- yes: P = load_u64(C+0x128)
       +-- P == 0: store_u32(S+0xc90, 0) -> failure
       +-- P != 0: load unsigned first byte
            +-- NUL: store_u32(S+0xc90, 5381) -> next phase
            +-- nonzero: repeat 64-bit 33*h+byte until next NUL
                         K = h mod 0xffffffff
                         store_u32(S+0xc90, K)
                         +-- K == 0: failure
                         +-- K != 0: next phase

S+0xc90 -> node+0 discriminator -> exact equality during list search
S+0x20  -> separate tunnel-marker/key channel -> tunnel+0x6c -> node+4
```

The second line of data flow composes previously established marker transfers under their object/frame premises. It does not establish the original write of source+0x20.

| Site / field | Width | Recovered action |
| --- | --- | --- |
| `0xfffffe000a635d5c`..`0xfffffe000a635d60` | address64 | C+0x128 -> SP+0x478 |
| `0xfffffe000a63dd44` | store64 | Clear C+0x128 in the selected initialization phase |
| `0xfffffe000a6570e8` | comparison32 | Raw status equals 0x31ae0066 to enter pointer handling |
| `0xfffffe000a65712c` / `0xfffffe000a657130` | two loads64 | Saved address -> C+0x128 -> P |
| `0xfffffe000a657184` | load8 | Read unsigned byte P[0] only on the selected nonnull path |
| `0xfffffe000a6571a4` | seed64 via W write | h=5381, zero-extended into X11 |
| `0xfffffe000a6571f0` | store32 | Empty-input K=5381 at S+0xc90 |
| `0xfffffe000a657214` / `0xfffffe000a657234` | index64 / load8 | Increment index and load the next byte |
| `0xfffffe000a657224`..`0xfffffe000a657230` | arithmetic64 | Selected recurrence for the current byte |
| `0xfffffe000a657268`..`0xfffffe000a65727c` | arithmetic64/128 | Magic unsigned quotient and remainder |
| `0xfffffe000a6572a0` / `0xfffffe000a6572a4` | store32 / test64 | Store low32 result; test the full X10 value for zero |
| `0xfffffe000a6572c4` | assignment32 | Local W23=0xce515bbf after the derived/null result gate |
| `0xfffffe000a65bb9c` | load32 | Separate insertion marker from S+0x20 into W22 |
| `0xfffffe000a636690` | store32 | Initial saved status at SP+0x9ec is 0xce515bb2 |

| Private index | Original pointer slot | Target | Selected meaning |
| --- | --- | --- | --- |
| 0x9e3 | `0xfffffe0008477e38` | `0xfffffe000a657110` | Status success -> pointer gate |
| 0x2d5 | `0xfffffe00084745c8` | `0xfffffe000a65ef14` | Status/zero-result rejection |
| 0xa08 | `0xfffffe0008477f60` | `0xfffffe000a657164` | Nonnull pointer -> first-byte gate |
| 0xa2d | `0xfffffe0008478088` | `0xfffffe000a657294` | Null pointer -> zero store/gate |
| 0x595 | `0xfffffe0008475bc8` | `0xfffffe000a6571e4` | Empty string -> default store |
| 0x580 | `0xfffffe0008475b20` | `0xfffffe000a657208` | Current nonzero byte / loop continuation |
| 0x6b6 | `0xfffffe00084764d0` | `0xfffffe000a65725c` | Next NUL -> final reduction |
| 0x8b7 | `0xfffffe00084774d8` | `0xfffffe000a657294` | Reduced result -> store/gate |
| 0x275 | `0xfffffe00084742c8` | `0xfffffe000a6572d0` | Nonzero discriminator / empty-string continuation |

The terminal BRAA modifiers are 0x3c58 for status/default/result gates, 0x24ea for the pointer gate, 0x8d40 for first-byte/loop gates and 0x6efe for reduction. Each original pointer slot and terminal word is captured. Native PAC/BTI behavior and whole incoming reachability remain unproved. The selected computational spans begin after BTI landing instructions.

## Arithmetic reconstruction

The loop's opaque byte addition uses constants A and B:

```text
A = 0xfffeffd7bf3f5bfb
B = 0x0001002840c0a405
A+B = 0  (mod 2^64)

t = (zero_extend_u64(byte) XOR A)
    + (0x1f6 AND (zero_extend_u64(byte) << 1)) + B
t = zero_extend_u64(byte)  (mod 2^64), for every byte in [0,255]
h_next = 33*h + t          (mod 2^64)
```

The all-hash64/all-byte8 obligation proves the identity from the original instructions, the next-byte address/index increment and branch, and preservation of the loop's pointer, constants and phase registers. Induction therefore gives the compact recurrence for a stable valid finite NUL-terminated input admitted by the selected entry phase. NUL is a terminator and does not enter the recurrence. No length value participates in the captured loop; upstream input extent and termination guarantees remain unknown.

For final h, the source computes:

```text
p = 2^32 - 1 = 4294967295
m = 0x8000000080000001
d = 2^95
q = floor(h*m / d)          # UMULH then logical shift by31
r = h - q*p
```

The source obligation establishes the exact high-product/shift/remainder expression. The separate integer certificate uses h=p*a+b,0<=b<p,0<=a<=2^32+1 and0<=h<2^64. Here e=m*p-d=2147483647. Exact bounds give:

```text
0 <= a*e+b*m <= (2^32+1)*e+(p-1)*m
             = d-2147483651 < d
h*m = a*d + (a*e+b*m)
therefore q=a and r=b, with 0<=r<=4294967294
```

The h*m product fits unsigned128. Consequently the source's full64 zero test and stored u32 zero test agree on a valid reduced result. The generic result-gate query still proves the actual full64 predicate separately, without assuming that an arbitrary u64 input already lies in the reduced domain.

This is a 64-bit wrapping recurrence followed by a final modulus; replacing it with a wrapping32 recurrence changes results. For the observed replay input bytes `alpha` followed by NUL and ignored suffix, the stored result is 253193308 (`0x0f176c5c`), with six byte reads including NUL. A leading NUL with ignored suffix produces 5381 with one read. Null input produces 0 with no byte read. An unsuccessful initial status reaches rejection before a discriminator store or byte read. These bounded examples support the general obligations and do not establish an upstream business identity.

## Literal-base inventory and open producer boundaries

The extractor decodes all 50,634 instructions in the pinned `_PRnut72j9` container and tests operand byte-range overlap, including paired accesses. The inventory concerns the named base register and literal displacement at each instruction. It does not assume that identically named registers retain one object identity across the complete dispatcher.

| Cell syntax | Extent | Direct reads | Direct writes | Interpretation boundary |
| --- | --- | --- | --- | --- |
| SP+0x9ec | 4 B | 47 | 1 | One literal-base initialization; aliases/calls/SP epochs remain open |
| SP+0x478 | 8 B | 2 | 1 | Saved C+0x128 address; read by pointer gate and earlier path at `0xfffffe000a63ddb4` |
| X4+0xc90 | 4 B | 2 | 2 | Empty/default and derived/null stores; node publication/search reads |
| X4+0x20 | 4 B | 1 | 0 | Marker input read; original producer is not closed |
| X4+0xd8c | 4 B | 1 | 2 | Initial raw-success default and later candidate-marker capture; update read |
| X2+0x128 | 8 B | 0 | 1 | Direct clear; actual input load uses an alias through X9 |

The scan excludes indexed operands: zero with SP base, 11 with X2 base and two with X4 base. More importantly, it does not classify writes through other registers, escaped pointers, callees or a changed SP epoch. The input read through X9 itself demonstrates why zero direct reads/writes cannot establish semantic absence. No uninitialized use, native saved-status invariant or resource defect follows from this inventory.

The predecessor [insertion contract](secure_tunnel_table_insertion_report.md) reads marker M from S+0x20, derives the table-key word from M XOR0x31ae0066 and writes M back to the candidate tunnel+0x6c after the occupied-entry request. [Publication](userclient_uidlist_publication_report.md) captures that candidate marker at S+0xd8c and writes node+4, while node+0 receives K. The seven re-solved queries preserve this conditional separation and both replacement-bootstrap fallback status gates. The current inventory does not locate an original source+0x20 write through aliases and does not convert the initial SP+0x9ec default into a final native-domain assertion.

No new Mach endpoint, message, port transfer or emission site is established. K is used here as a byte-string-derived list equality discriminator; source bytes alone do not identify it as a PID, user identity, entitlement, Mach name or cryptographic key. Existing external interfaces remain in the [Mach-port report](mach_ports_report.md), [interface ABI](interface_abi_report.md) and [context/task flow](context_descriptor_task_flow_report.md).

For a valid stable input with L bytes preceding NUL, this selected producer takes O(L) time and O(1) auxiliary storage, reading L+1 bytes on a nonnull admitted input. Null-pointer and initial-status rejection paths use O(1) work. A later finite-list search over N nodes adds O(N), under the predecessor's acyclic stable-list premise. These bounds exclude upstream input construction, full dispatcher reachability and native memory-fault/PAC behavior. Extraction and inventory take O(B+I) time/space; symbolic/replay construction takes O(I+L+query DAG), with SMT search separate and 30 s/query limits.

## Assumption register

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| DO-A1: Pinned original/normalized images, fixups and predecessor receipts | DO1-DO9 provenance | Fresh enclosing-function byte comparison, exact pointer/transfer capture, dependency hashes, reconstructed queries and four altered-evidence controls |
| DO-A2: Selected dispatcher status/token/phase and stable C/S/SP cell epochs | DO1-DO9 composition | Capture all incoming edges, root stores and intervening effects before claiming native reachability; current exact gates do not establish the incoming path |
| DO-A3: Nonnull P points to readable stable bytes through the first NUL, with nonwrapping index/address arithmetic | DO3, DO4, DO9 input traversal | Universal u8 gates/address obligations and concrete null/empty/NUL/high-byte cases; recover upstream length, termination and lifetime guarantees |
| DO-A4: AArch64 unsigned widths, zero-extension on W writes and instruction semantics in the bounded models | DO4-DO6, DO9 algorithm | All-hash64/all-byte8 recurrence, exact product/shift obligation, separate integer interpreter and wraparound-length replays; native execution remains separate |
| DO-A5: Euclidean unsigned representation of final h | DO5/DO6 modulus and zero equivalence | Nonvacuous linear-integer quotient certificate, exact m/p/d/e values, remainder range and unsigned128 product bound |
| DO-A6: Predecessor context/tunnel/node/marker identity and ordinary call premises | DO7 channel composition | Re-solve seven selected source formulas; trace actual producer and common object epochs before assigning native/business identity |
| DO-A7: Inventory is syntactic literal-base overlap in one pinned container | DO8 reference counts | Fresh full-container decode and byte-width classification; inspect aliases, indexed operands, escaped pointers, call effects and SP changes before asserting exhaustive semantic writers |
| DO-A8: Native input identity, marker origin, ownership, serialization and daemon correlation remain open | DO9 architectural scope | Close earlier C+0x128 output path, S+0x20 aliases and correlated daemon/provider transactions; names and hash constants do not supply those identities |

## Bounded continuation

| Impact | Evidence target | Contribution |
| --- | --- | --- |
| High | Earlier saved input-cell address use at `0xfffffe000a63ddb4` and following dispatcher path | Recover input producer, decoded type, length/termination guarantees and external influence |
| High | Aliased source+0x20 writes and marker/object lifetime | Establish original marker generation and its epoch before table insertion |
| High | Saved-status escaped aliases/call effects and full SP epoch chain | Restrict native saved-status values beyond the literal-base initialization |
| Medium | All global holder/list/table writers and caller synchronization | Compose hash/search/update with native object lifetime and serialization |
| Medium | Correlated fairplayd selector26/context/connection evidence | Bind the recovered fields to an observed successful daemon-kext exchange |
| Low | Other users of the 5381/33/final-modulus computation | Determine reuse and compatibility of this private discriminator algorithm |

## Quality gates

- **QG1**: Factual algorithm, operand and interface claims require no normative conclusion.
- **QG2**: DO-A1-DO-A8 register assumptions, dependent claims and falsification probes.
- **QG3**: Status/pointer/NUL gates, complete selected recurrence, exact modulus, zero-result predicate, input-cell root and six-cell inventory are covered. Original marker/input producers and the wider investigation remain active.
- **QG4**: u8/u32/u64/u128 widths, modulo2^64 recurrence, modulus 4294967295, quotient bounds, byte reads and algorithmic costs are explicit and reproducible.
- **QG5**: Null/empty/zero-hash outcomes, 64-bit versus32-bit recurrence, full64 test versus stored32 result, discriminator versus marker and syntactic versus semantic writers remain distinct.
- **QG6**: Original instructions/fixups, 13 nonvacuous queries, seven predecessor query rechecks, 272 independent integer replays and four custody controls support the bounded claims.
- **QG7**: Ranked continuation retains input identity/extent, marker generation, alias/SP effects, serialization and daemon correlation as open requirements.

## Shared input-reader increment

The earlier scratch+0x128 producer is now traced in the [shared input-reader report](userclient_input_reader_report.md): a protected tagged-node reader requests and copies exactly L bytes before resuming the hash gate. It adds no terminator in that path. Whether upstream content supplies NUL remains unknown; the prior valid finite NUL-terminated hash-input premise is therefore still required.

## Container-staging increment

The [upstream staging/parser report](userclient_container_staging_report.md) proves exact low32 size recovery and protected input staging before a shared FPTTLV parser, followed by the selected scratch+0x600 reader handoff. The complete nonempty parser and field-level NUL contract remain unknown, so the discriminator traversal retains its valid finite NUL-terminated-input premise.

## Record-node construction increment

The [node-construction follow-up](userclient_record_nodes_report.md) establishes the conditional allocation and writer handoff corresponding structurally to the input reader's node layout. Original tag identity, completed payload serialization and decoded termination remain unknown.

## Protected record-writer increment

The [writer-side follow-up](userclient_record_writer_report.md) proves header encoding compatible with the selected reader and an exact-L protected payload copy for type0x6685. Original tag identity, source payload termination and live list/reader linkage remain unknown.

## Record lookup and publication increment

The [record-publication increment](userclient_record_publication_report.md) connects selected writer output to tag-based append/replacement. Original tag business identity, decoded payload termination, cursor progress and native live-reader/daemon correlation remain separate requirements.

## Staged metadata and cursor increment

The [metadata follow-up](userclient_record_metadata_report.md) establishes this increment. The selected metadata chain supplies staged-byte tag/type/length provenance and bounded cursor progress. It does not establish the wider original marker producer or tag business meaning.

## Parser cleanup increment

The [cleanup follow-up](userclient_parser_cleanup_report.md) establishes this increment. Selected failure state is retained across node/container cleanup and restored to the parser caller. Original wider discriminator/input identity remains unestablished.

## Parser caller and command dispatch increment

The actual parser caller now has a conditional command-field lookup, protected scalar reader and exact two-value switch. The first command links to the existing hash-input reader; second-body semantics, native storage/ownership and cross-layer correlation remain open. See the [command-dispatch report](userclient_command_dispatch_report.md) for the source contracts, status frontiers and assumption register.
