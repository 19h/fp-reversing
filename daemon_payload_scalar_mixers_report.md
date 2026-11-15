# fairplayd: equivalent payload scalar mixers and scratch byte history

Count-source continuation: [The count-flow report](daemon_payload_count_flow_report.md) now joins the original context+0x1c count read, advanced +0x20 data pointer, saved count and loop gates. Count 6 explains the four-byte direct read plus two-byte scratch-prefix replacement. The earlier scalar-mixer and scratch-history receipts remain unchanged; native constructor epoch and application schema remain unknown.

The two remaining payload mixers implement the same bijective u32 affine transformation. Both consume a shared big-endian four-byte reader's result, then emit `BE32(u32(D * 0x01ef2eff + 0x00833631))` after the established owner-offset normalization. Their retained inputs are 0 and 25,597, producing `00833631` and `69114534` at final-owner offsets 117 and 121. These are two separate four-byte source reads and emissions. A combined application u64 interpretation remains unknown. [PS1-PS6; PS-A1-PS-A4]

The second input's physical bytes have mixed producer history: four encoded scratch bytes `20 a3 63 fd` are written, then two context bytes overwrite their prefix, yielding `00 00 63 fd`. The reader consumes this later state. The six context byte offsets involved, +0x20 through +0x25, coincide with the previously recovered network-data field layout; a native constructor-to-consumer epoch join remains unknown. This is additional local data-flow evidence, with no newly established Mach port, disposition or emission site. [PS2-PS6; PS-A2,PS-A5-PS-A6]

| Evidence | Primary provenance and boundary |
| --- | --- |
| PS1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; exact original instruction bytes for the shared reader, both mixers, byte encoders, prefix copies and word stores. |
| PS2 | [Record extension](daemon_record_extension_report.md), [body origins](daemon_digest_body_origins_report.md), [retained structure](daemon_digest_record_structure_report.md), and their pinned receipts; admitted private-model paths, fixture bytes, owner identities and declared allocation/free returns remain dependencies. |
| PS3 | [Extractor](triage_evidence/recover_daemon_payload_scalar_mixers.py), [checks](triage_evidence/daemon_payload_scalar_mixers_checks.json.zst): original chunks, frames, effects, per-read predecessors, source words and scratch timeline for classes 2/3, interval 3. |
| PS4 | [Independent auditor](triage_evidence/audit_daemon_payload_scalar_mixers.py), [audit](triage_evidence/daemon_payload_scalar_mixers_audit.json.zst): complete selected-chunk scalar replay, inverse checks, scratch write-history reconstruction and twelve source/composition obligations. |
| PS5 | [Publication verifier](triage_evidence/verify_daemon_payload_scalar_mixers_publication.py): fresh extraction/audit comparison, proof reconstruction and re-solving, exact manifest delta, original-input custody and path checks. |
| PS6 | [Context state publication](daemon_context_state_publish_report.md) independently maps six network-record bytes to C+0x20..C+0x25; [post-seed output](daemon_postseed_output_report.md) and PS2 qualify the address/cache/text-dependent byte encoder and owner-offset normalization. Positional correspondence alone does not establish a native object epoch. |

Decoded checks SHA-256: `8abdca9c7bcd681797345d9cd20123a6c429761feacf9e212c12c519310e74d1`. Decoded audit SHA-256: `e8691cddd430c2eeba98e6d70bdafbbb0c226cfb4823f82e3f279b540530a870`. PS3-PS4 pin parent receipts, decoded intervals and code dependencies. Existing original-image/reference data sufficed; no additional IDA data was required. [PS1-PS5]

## Source contract and exact decomposition

Let `D=BE32(b0,b1,b2,b3)`, A denote entry W8 at either mixer, and V denote the four emitted bytes interpreted as BE32 after the established owner-offset mask is removed. All additions, multiplications and intermediate results below are modulo 2^32. B denotes bytes; source PC ranges are half-open. [PS1,PS3-PS4; PS-A3]

```text
four source bytes
    -> reader 0x100a8d894: A = D XOR 0x6703cce9
    -> either mixer:      W11 = (D * 0x01ef2eff + 0x00833631)
                                XOR 0xe4b5bf34
    -> four byte stores -> owner-offset mask normalization -> BE32(V)

V = u32(D * 0x01ef2eff + 0x00833631)
D = u32((V - 0x00833631) * 0xa46fd0ff)
```

The inverse exists because the multiplier is odd and `u32(0x01ef2eff * 0xa46fd0ff)=1`. The inverse theorem holds for every u32 input. It establishes injectivity of this local scalar transform; it does not establish injectivity of the earlier scratch construction or of a complete protocol. [PS4; PS-A4]

The proof splits the original instruction streams into exact live-register contracts. This avoids treating matching retained outputs as a general semantic proof. Define `g=u32((A XOR 0x6703cce9)+0x74c239af)` and `u=u32(g*0x01ef2eff+bias)`. The original carry network returns `(u+delta) XOR 0xe4b5bf34`. Both `u32(bias+delta)` equal `0x434d4ee0`; `u32(0x74c239af*0x01ef2eff+0x434d4ee0)=0x00833631`. [PS1,PS4]

| Variant | Triple-XOR/addition range | Multiply/add range | Carry-network range | bias | delta | FP-relative u32 side read |
| --- | --- | --- | --- | --- | --- | --- |
| A | `0x100a630cc..0x100a6311c` | `0x100a6311c..0x100a63130` | `0x100a63130..0x100a63288` | `0x8ab88387` | `0xb894cb59` | -0xe8 |
| B | `0x100a86930..0x100a86980` | `0x100a86980..0x100a86994` | `0x100a86994..0x100a86b00` | `0xbc5121c0` | `0x86fc2d20` | -0xe4 |

The side loads remain part of the architectural contract: both load the owner pointer from X6+0x18 and add `0xa7a8e5ca` to the respective saved u32 in W10. The universal carry proofs keep those two loaded values arbitrary, prove both effective addresses and preserve the owner-pointer result in X9. Neither loaded value contributes to W11. Complete retained caller/store replay separately checks the actual destination addresses. This differs from the packed-field producer's X5+8 interface. [PS1-PS4]

The shared reader consumes bytes at `base + u32(position + 0xfe53bc45 + k)`, k=0..3. Actual entry position `0x01ac43bb` makes the four indices 0,1,2,3. The general address theorem retains each separate u32 wrap before zero extension; contiguity is a property of these retained inputs, not of every possible position. The reader theorem uses the explicitly recorded phase registers W12/W13/W14/W15/W16/W0; it proves all 32 independently variable input bits, the selected dispatch pointer and modifier `0x68f8`. Authenticated branches are modeled logically; hardware PAC is not executed. [PS3-PS4; PS-A3]

| Final-owner offset / B | Input read addresses | Physical source bytes | D / decimal | Mixer entry A | Caller/store W11 | Normalized output V |
| --- | --- | --- | --- | --- | --- | --- |
| 117 | `0x6500115b40..0x6500115b43` | `00000000` | 0 | `0x6703cce9` | `0xe4368905` | `00833631` |
| 121 | `0x680005fe23..0x680005fe26` | `000063fd` | 25,597 | `0x6703af14` | `0x8da4fa00` | `69114534` |

Each row occurs in both retained contexts. For the second, `u32(0x63fd*0x01ef2eff)=0x688e0f03`, followed by `u32(0x688e0f03+0x00833631)=0x69114534`. The full source paths join these words to the previously established digest-body bytes; digest/AES identity is inherited, not re-derived in this increment. [PS2-PS4]

## Scratch lifetime and context touch points

The first source base is `0x6500115b40`, offset 32 B within the retained 552 B context owner at `0x6500115b20`. All four bytes are incoming fixtures in interval 3, with provenance `byte_equivalent_preceding_source_state`; their native construction is not proved here. The second base is stack scratch at `0x680005fe23`. Its bytes have four exact in-interval predecessor links per context, independently recovered by predecessor searches. [PS3-PS4; PS-A2]

```text
within interval 3, both retained contexts

W19=0x4e59f9bb -> temper -> W9=0x6e1a6b02
    -> four address/cache/text-dependent byte stores
       scratch = 20 a3 63 fd
    -> copy context+36 and context+37 into scratch+0 and scratch+1
       scratch = 00 00 63 fd
    -> BE32 reader -> D=0x000063fd -> mixer B -> V=0x69114534
```

| Source visit | Store PC | Scratch offset / B | Stored byte | Meaning in the retained sequence |
| --- | --- | --- | --- | --- |
| 99864 | `0x100a0ca74` | 3 | fd | First encoded byte, shift 0 |
| 99968 | `0x100a0ca74` | 2 | 63 | Second encoded byte, shift 8 |
| 100072 | `0x100a0ca74` | 1 | a3 | Third encoded byte, shift 16; later overwritten |
| 100176 | `0x100a0ca74` | 0 | 20 | Fourth encoded byte, shift 24; later overwritten |
| 100257 | `0x100a396ac` | 0 | 00 | Copy from context+36, read at `0x100a396a4` |
| 100275 | `0x100a396ac` | 1 | 00 | Copy from context+37, same read PC |

The later reader's four loads occur at visits 100336, 100341, 100346 and 100352. A four-byte snapshot taken before the two copy stores would supply the wrong input. Conversely, the consumed low two bytes are preserved encoder outputs, not copies of context bytes. All six writes, including overwritten outputs, are retained and replayed. [PS3-PS4]

For each scratch encoder, the established source formula is `stored8=low8((W9 >> (shift AND 31)) XOR u32(31*low32(destination)) XOR ta XOR tb XOR 0xd7)`. Here cached word `0xa0018891`, text base `0x100822058` and mask `0xfff0c01200007fff` determine the exact source text-byte addresses, retained in PS3. PS4 independently recalculates all eight encoder events and replays the original instructions. The two retained raw scratch bytes therefore cannot be read directly as the low16 bits of W9. The tempering input producer, cache initialization and application use remain unknown. [PS2-PS4,PS6; PS-A5]

The additional tempering source theorem covers arbitrary u32 W19 under phase W10=`0xbc66`. A total of 1,384 frame checks and instruction-definition scans establish W9 preservation through all eight scratch-encoder entries. One arbitrary-byte copy theorem covers both observed copy steps and their modular effective addresses. [PS3-PS4]

The context offset mapping is consistent with PS6's six-byte network-data publication, but that earlier constructor and these retained fixtures are distinct evidentiary epochs. Assigning a native MAC address, a device identifier, a combined 48-bit value or a single u64 to this payload requires additional producer/consumer evidence. Each such application meaning is unknown here. [PS2,PS6; PS-A6]

The exact local eight-byte pre-mixer construction is therefore `context[32:38] || scratch_encoder_byte2 || scratch_encoder_byte3`. Under the retained inputs it is `00 00 00 00 00 00 63 fd`. Applying the inverse separately to the two normalized words recovers this construction. The final two bytes depend on the scratch destination, cache, original-image text and tempered word; their application role, such as padding or a separate field, remains unknown. [PS3-PS4]

```text
context +32 +33 +34 +35  +36 +37     scratch +2 +3
         |   |   |   |    |   |               |  |
         +---+---+---+    +---+---------------+--+
            BE32 D0              BE32 D1
                |                    |
          affine mixer A       affine mixer B
                |                    |
        owner+[117,121)       owner+[121,125)
```

## Assumptions, validation and bounded continuation

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PS-A1: The pinned original image is the intended specimen | All PC mappings and universal source contracts | Rehash the image and dependencies; compare every retained original instruction byte. A mismatch invalidates the corresponding source result. |
| PS-A2: Parent path admissions, defined fixtures, owners and declared API returns apply | Concrete values, addresses and event order | Match decoded parent intervals and exact frames/effects; preserve unknown upstream fixture/native origins; require native observations before promoting modeled addresses to live identities. |
| PS-A3: The stated reader phase and original word normalization apply | BE32-to-A and emitted-V composition | Check every actual phase register, all source loads, complete mixer/caller/store paths and the inherited mask. A different phase or codec requires a separate contract. |
| PS-A4: Arithmetic is u32 with modular wrap | Affine decomposition, inverse and injectivity | Prove all-u32 stage/composition/inverse equations. Retain per-index u32 wrap before zero extension; avoid host-width or signed-shift substitution. |
| PS-A5: Scratch values are interpreted at the actual read epoch | Value 25,597 and the prefix-overwrite explanation | Independently scan all overlapping prior writes, retain overwritten bytes, replay every encoder/copy, and test the earlier `20a363fd` snapshot as a contradictory read input. Entropy provenance remains unknown. |
| PS-A6: Context offset correspondence is structural only | Relationship to the previously recovered network-data field | Join constructor writes, pointer identity and native lifetime to this exact consumer; positional coincidence alone does not establish those joins or application names. |

Independent replay checks 1,462 original A64 instruction visits, 47,360 GP/SP values, 1,480 NZCV frames, 192 reads, 28 writes and eight logical authenticated edges in eighteen chunks. Source byte custody checks 184 in-interval predecessor bytes and separates 668 incoming/image bytes. For the four scalar inputs specifically, eight predecessor bytes and eight incoming bytes are distinguished; four incoming prefix-copy bytes remain separate. These categories overlap the full selected-read census and must not be summed as disjoint populations. [PS3-PS4]

Twelve nonvacuous UNSAT obligations cover the shared BE32 reader, six original mixer stage contracts, two compositions, the scalar inverse, scratch-word tempering and prefix copy. Full target execution, native API/IPC, new allocation-return premises and IDB mutations are absent. The complete interface investigation remains active; native schema, port ownership, message emission identity and daemon-kext pairing remain unknown. [PS3-PS5]

Scalar transformation and its inverse take O(1) time and O(1) space per four-byte word. For P decoded parent bytes, C chunks, E parent events/fixture bytes, Q selected read-byte queries and V selected visits, extraction/audit take O(P+CE+Q log(E+Q)+32V) time and O(parent receipts+largest interval+selected frames) space; proof-DAG construction/storage and solver search are additional. Each solver query has a 30 s timeout. All byte extents, u32/bit widths, addresses, visit counts and equations are exact. [PS3-PS5]

| Impact | Bounded continuation or pattern | Discriminating evidence |
| --- | --- | --- |
| High | Join the six context bytes to this retained consumer's producer epoch | Match constructor/cache publication, actual pointer identity and ordered reads. This can establish the architectural role without inventing a payload field name. |
| High | Explain the scratch prefix replacement and its downstream reader | Recover the copy bound/selection and independent consumer constraints; an affine bijection after the read does not recover overwritten scratch bits. |
| High | Join the structured owner to a transport/kext transaction | Require exact buffer/selector/message and port/right/transaction identity; these internal affine scalar contracts provide no such identity. |
| Medium | Recover W19/cache/indexed-bank producers in the same epochs | Follow source definitions and cache lifetime; repeated zero fixtures and tempering constants do not establish native randomness or a device value. |
| Low | Consolidate source-navigation names for both equivalent mixer bodies | Preserve distinct source PCs, side-load interfaces and arbitrary-u32 contracts when assigning analytical labels. |

**QG1** passes: factual source analysis. **QG2** passes: PS-A1-PS-A6 identify dependencies and falsification probes. **QG3** passes for both remaining mixers, their inputs, overwrite history and architectural touch points; the full investigation remains incomplete. **QG4** passes: byte/bit widths, modular calculations, event order, complexity and solver limits are explicit. **QG5** passes: separate u32 reads, combined-value uncertainty, scratch epochs, local injectivity and constructor-epoch uncertainty remain distinguished. **QG6** passes after primary-byte comparison, independent replay, fresh source-proof verification, input custody and exact publication checks. **QG7** passes: continuation covers context provenance, prefix selection, state/cache producers and native transaction identity.
