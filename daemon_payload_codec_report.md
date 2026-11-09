# Record-node construction, address-indexed byte codec and list append

Original source establishes that the payload producer and list serializer use the same address-indexed XOR mask. Their scalar arithmetic reduces to a common seed and seven rotate/add/XOR rounds. The producer stores `B XOR m(A)` at record-buffer address A; the serializer reads that address and applies the same mask, recovering B. This closes the conditional payload-encoding inverse left open by [the list-output report](daemon_list_output_report.md). It does not establish the complete constructor, native ownership, phase production or a daemon-kext transport join. [PC1-PC8]

The retained Arcade profiles provide an independent byte comparison: 24 fully known encoded buffers at retirement decode to the exact outer record bodies supplied to XPC in 12 send cases. Their last writes precede final output construction and their retirement snapshots follow it. Original source also establishes a 32 B node projection, payload-plus-header extent and separate empty/nonempty append contracts. [PC1-PC6]

Primary evidence: [source, preserved registers and frozen buffer summaries](triage_evidence/daemon_payload_codec_source.json), [component queries and translations](triage_evidence/daemon_payload_codec_checks.json), [extractor](triage_evidence/recover_daemon_payload_codec.py), [validator](triage_evidence/validate_daemon_payload_codec.py), [preservation](triage_evidence/daemon_payload_codec_delivery.json) and [scoped gates](triage_evidence/daemon_payload_codec_quality_gates.json). The original [Arcade profiles](triage_evidence/arcade_subscription_profiles.json) were read without rerunning their generators or target code. No target execution, new emulation, host IPC or IDB mutation occurred. Reference files sufficed; additional IDA access was unnecessary.

| Provenance or check | Exact scope |
| --- | --- |
| Original thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Fresh source | 19 fragments, 1455 instructions, 5820 B; six original pointer records |
| Prior byte recapture | 34 ranges, 5908 B, from the list-output and record-stream ledgers |
| Register survival | X8/X10 survive 11 unique intervening fragments with no calls; producer-loop constant/input registers are separately checked for writes |
| Static certificate | 14 UNSAT component queries; 413 translated instruction instances; eight altered-evidence controls rejected |
| Retained private evidence | 12 profiles; 24 key-to-payload episodes, 24 descending payload-write spans, 3619 payload stores; 24 decoded retirement snapshots |
| Monolithic query | `unknown` under a 15000 ms solver timeout; retained separately and not counted as a passed proof |

All addresses below are original unslid VAs. Offsets are hexadecimal; byte extents are decimal unless prefixed `0x`. All u64 arithmetic is modulo 2^64 and u32 arithmetic modulo 2^32. The generic codec proofs concern scalar identities; nonwrapping valid native owners are separate premises.

## Node and container ABI [PC1-PC3, PC6-PC7]

| Object | Offset | Width | Established role |
| --- | --- | --- | --- |
| Container | `0x00` | 8 B | Head in the empty append and serializer consumer contracts |
| Container | `0x08` | 8 B | Tail, loaded by append gate and updated by both append paths |
| Node | `0x00` | 8 B | Next pointer, initially zero; later written through old tail |
| Node | `0x08` | 8 B | Previous pointer, initially zero; nonempty append copies the later tail reload here |
| Node | `0x10` | 4 B | Plain record extent `u32(payload_extent+10)` |
| Node | `0x14` | 4 B | Not assigned a semantic field by this increment |
| Node | `0x18` | 8 B | Record-buffer pointer, also consumed by serializer setup `0x10087bbbc` in the prior source ledger |

| Source site | Contract |
| --- | --- |
| `0x100695920..0x100695928` | W0=32 before the node-allocation call; retained import model identifies `_malloc` |
| `0x10069592c` | Save returned node pointer at frame+`0x38a0` |
| `0x100948a8c` | X20 receives the node pointer |
| `0x100948aa0` | Clear node+0 and node+8 with `STP XZR,XZR` |
| `0x100948b9c` | Store `u32(payload_extent+10)` at node+`0x10`, under the input codec `W21=payload_extent XOR 0x8b3dc651` |
| `0x100948bf8` | Record-buffer allocation call with that extent in W0 |
| `0x100948bfc` | Immediately store returned X0 at node+`0x18` |
| `0x1006f0218..0x1006f0228` | Load container from frame+`0x5508`, tail from container+8 and node from frame+`0x38a0` |

The original `_malloc` bind at slot `0x10109ff58`, IA diversity `0x6aa4`, agrees with the retained call models. This increment does not freshly prove every mutable bank-root expression at these call sites. Source argument/store contracts and retained import identity are distinct evidence layers.

In every retained send profile there are five 32 B node calls and five paired record-buffer calls. The immediate return-PC `STR X0` and recorded destination address support 60 modeled node-to-buffer assignments. Native malloc success, allocation ownership and the full pre-allocation admission path remain unknown. The extent theorem is modular; a nonwrapping `P+10` allocation additionally requires `P<=0xfffffff5`. No new allocation-failure execution was performed.

## Append contracts and tail reload [PC3, PC6-PC7]

At compatible incoming phase `0x9c85`, the gate at `0x1006f0208` selects original table index `0x9c85` for a null loaded tail and `0x9ca7` for a nonnull tail. Both pointers have IA diversity `0xc537`.

| Branch | Original target | Exact ordered memory effects |
| --- | --- | --- |
| Empty | `0x1004def68` | `container.head=N; container.tail=N` through a paired store |
| Nonempty | `0x10069a4a0` | `*T1=N; T2=container.tail; N.prev=T2; container.tail=N` |

T1 is the tail loaded by the gate; T2 is the tail reloaded after the first nonempty store. Under stable, valid, disjoint list ownership, T1=T2 and `*T1` is the old tail's next field. Without that premise, the source establishes the ordered stores and reload, not a consistent concurrent append. Neither the paired store nor these ordinary loads/stores establishes atomic publication or locking.

Both paths set raw local marker `0x8b3dc651` and use an authenticated continuation with diversity `0x9b18`. Native return and public success are separate questions. The retained profiles contain two empty and three nonempty appends per case: 24 and 36 occurrences respectively. These are historical private-model occurrences, not native concurrency tests.

```text
empty container                  nonempty container, stable-tail premise
  head=0, tail=0                   head -> ... -> T -> 0
       |                                           |
       v                                           v
  head=N, tail=N                   T.next=N; N.prev=T; tail=N

node N, 32 B projection
  +0 next | +8 prev | +16 extent32 | +20 unknown | +24 buffer64
                                                        |
                                                        v
                          encoded 10 B header | encoded payload
```

## Compact address-indexed codec [PC1-PC5, PC8]

The producer body begins at `0x100614278`. Its byte store is `0x1006143d8`. For payload extent n and iteration i, `i=n-1,...,0`, it reads source+i and writes record-buffer+10+i. The serializer body at `0x1009c3d34` reads node-buffer+j; at j=10+i it accesses the same encoded byte address. It writes the transformed byte at `0x1009c3f8c`. The XOR cancellation requires this address identity, stable bytes and the selected source phases.

The following pseudocode specifies the common scalar mask. `ROR64` is a 64-bit rotate right; operations wrap at 64 bits. q, x and y are unsigned 64-bit words. `A` is the absolute byte address within the encoded buffer, not its relative payload index.

```text
r = ROR64(A & 0xfffffffffffffff8, 8)
q = r - ((2*r + 0x4458ba66c9cbab3e) & 0x64b05f970e467982)
q = q + 0x98848cfeec091260
x = q ^ 0x91e690049073ef48
y = q ^ 0x8084799fb75d43b3
for k in K[0..6]:
    x = (ROR64(x,8) + y) ^ k
    y = ROR64(y,61) ^ x
m(A) = (x >> (8*(A & 7))) & 0xff

producer: encoded[A] = source_byte ^ m(A)
consumer: output_byte = encoded[A] ^ m(A) = source_byte
```

The last y update is unused by the returned mask; the formal final-round lemma requires only x. The word calculation is common to the eight byte addresses in each aligned 8 B group. Byte selection uses the corresponding low-to-high byte of that word. Wire record fields remain big-endian, as established by the separate record grammar; the internal word's byte selection does not change that wire convention. Algorithm or library identity is unknown.

| Round | Common constant K | Producer slice, half-open | Consumer slice, half-open |
| --- | --- | --- | --- |
| 1 | `324a764c67af2e0e` | `100614304..100614330` | `1009c3de0..1009c3e2c` |
| 2 | `e70987b7a1f527b0` | `100614330..100614340` | `1009c3e2c..1009c3e4c` |
| 3 | `9032dc5079388982` | `100614340..100614360` | `1009c3e4c..1009c3e9c` |
| 4 | `144db9b1af6b5721` | `100614360..100614378` | `1009c3e9c..1009c3ee4` |
| 5 | `eb8e58819a88bf30` | `100614378..100614398` | `1009c3ee4..1009c3f3c` |
| 6 | `7faaf81a732f68b4` | `100614398..1006143c0` | `1009c3f3c..1009c3f5c` |
| 7 | `4f99108510ad96e0` | `1006143c0..1006143cc` | `1009c3f5c..1009c3f74` |

Some boundaries carry a precomputed `ROR64(x,8)` into the next slice. Each round lemma quantifies over arbitrary incoming u64 x/y and explicitly supplies that precomputation. This is a proved compositional cut, not a chosen runtime state.

## Phase, key survival and loop boundary [PC2-PC5]

The original catalog contains one pointer to producer `0x100614278`: table index `0xb1df`, slot `0x101092de8`, IA diversity `0x990a`, address diversity zero. The setup expression at `0x1005e58cc` maps to that index if and only if its incoming W11 is `0x4cf4`; it then produces loop phase W11=`0xb16e`. This is an all-u32 preimage theorem. It does not establish the native upstream phase producer.

The setup loads record-buffer through node+`0x18` and source through frame+`0xa670`. The two inherited constants in X8/X10 originate at `0x1008ecd30` and `0x1008ecd00`. The remaining round constants are established by `0x1005e5934..0x1005e5a24`. Original register-write analysis confirms X8/X10 survive the intervening header blocks without calls; a separate check confirms the producer loop preserves its key, phase, source and buffer registers.

Each retained profile supplies two matching recorded key-to-payload branch episodes. Their PAC authentication was bypassed by the historical private model. No actual incoming W11 snapshot or hardware authentication is inferred from a branch target alone.

At the producer tail, nonzero i selects repeat index `0xb1df`; i=0 selects `0xb16e`. `MOV X15,X17` transfers the decremented countdown into the next iteration. Under n>0 and valid bounded owners, the loop performs n reads and n writes, descending through payload offsets n+9 to 10 without writing the header. Generic source-pointer validity, n production and full native loop reachability remain premises.

## Retained encoded-buffer comparison [PC1, PC4-PC6]

For each of the 12 successful send profiles, the retirement snapshots at modeled free return-PC `0x1007cf704` contain two fully known encoded outer-record buffers. Applying the scalar mask to every stored byte yields a 14 B scalar record and a `10+Li` B nested-span record. Concatenating these gives the final XPC body's exact bytes. Appending `00 00 00 00 50 DB 00 00 00 0E` and 14 zero bytes reproduces the complete XPC packet SHA-256 retained by [the record-stream report](daemon_record_stream_report.md).

| Recorded cases | n including NUL (B) | Li (B) | Producer payload stores per profile | Encoded retirement extents (B) | Final packet (B) |
| --- | --- | --- | --- | --- | --- |
| default; count0/count1/count57/countmax; opaque0/opaquemax | 57 | 112 | 169 | 14,122 | 160 |
| path_empty | 1 | 64 | 65 | 14,74 | 112 |
| path_one | 2 | 64 | 66 | 14,74 | 112 |
| path15 | 16 | 80 | 96 | 14,90 | 128 |
| path16 | 17 | 80 | 97 | 14,90 | 128 |
| path1023 | 1024 | 1088 | 2112 | 14,1098 | 1136 |

The combined first row represents seven profiles. Thus total payload stores are `7*169+65+66+96+97+2112=3619`. This is an exact count from retained write records, independently consistent with n+Li. The journal records store PCs, destinations and widths; it does not supply stored values for every heap write. The byte values compared here come from explicitly known retirement snapshots.

For each encoded snapshot, all recorded writes to that allocation finish before the first final-output write; retirement occurs after the last final-output write. No intervening encoded-buffer mutation is recorded by this journal. Native races and writes outside its coverage remain outside that observation. The generic producer inverse theorem covers the payload loop; the complete header transformation is supported here by finite byte agreement, not a new universal header-constructor theorem.

## Certificate limits and reproduction

The accepted certificate consists of the common seed, seven universal round lemmas, common byte selection/XOR cancellation, producer repeat partition, phase preimage, stored node extent, append partition and append stores: 14 component queries. Composing the seed, rounds and selection proves the scalar payload inverse at the same address. An undischarged monolithic query is retained as `unknown`; it supplies no additional proof. No solver result establishes control reachability or native API behavior.

The byte decoder used for frozen snapshots evaluates the compact scalar formula; it does not execute original instructions or reconstruct a target request. Extraction is O(image bytes + fixup count + retained journal bytes) time/space. Decoding is O(snapshot bytes) with seven constant-size rounds per byte and O(snapshot bytes) output space. Static translation is O(selected instructions); solver complexity is separate, with a 15000 ms per-query timeout. All dimensional calculations concern bytes; machine widths and modular arithmetic are explicit.

```text
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_payload_codec.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_payload_codec.py
```

## Assumption register and falsification probes

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| PC1 | Exact recorded thin-image build; all source addresses and constants | Rehash executable, recapture bytes/fixups and compare prior ranges; other builds invalidate address transfer |
| PC2 | Selected producer and consumer phases and original constant origins; generic codec | Source phase-preimage query, register-write checks and retained branch episodes; actual upstream production remains unknown |
| PC3 | Native records/containers have valid disjoint owners and stable relevant fields; operational layout/append | Establish producer/allocator/lifetime evidence; aliasing or tail mutation breaks list interpretation while ordered stores remain factual |
| PC4 | Producer stores and consumer reads the same encoded byte address, with stable bytes | Compare source node+24 assignment, serializer getter and frozen journal intervals; relocation without re-encoding does not satisfy this identity |
| PC5 | Formal stage cuts supply the stated common x/y and precomputed rotate; composed inverse | Universal seed/round/selection lemmas cover both source slices; altered constant or cut invalidates composition |
| PC6 | Historical private API/write/retirement models represent their recorded behavior; finite joins | Compare source SHA, fully known masks, pointer/extent pairs, write order and XPC packet hashes; native behavior remains unknown |
| PC7 | Nonwrapping payload+10 and full source admission; allocation interpretation | Modular theorem alone is insufficient; require payload<=fffffff5 and the actual preceding guards |
| PC8 | Payload inverse is not a complete constructor/transport proof | Prove header constructor for all inputs, actual frame epochs and endpoint/peer ownership before extending scope |

## Bounded continuation and quality gates

| Impact | Next evidence target | Uncertainty resolved |
| --- | --- | --- |
| High | Connect native producer/list epochs and actual selected phases to the established serializer output path | Whether conditional codec and ownership contracts form one native transaction |
| High | Complete universal header-constructor and list-lifetime contracts | Whether every node field and encoded byte is initialized consistently before serialization |
| High | Identify build-matched daemon/kext endpoints and rights across selector26/RPC502/700 | Principal cross-layer transport gap; no new Mach name or right is established here |
| Medium | Recover admission/count production and append locking/owner context | Valid extent domain, stable-tail premise and native concurrency semantics |
| Low | Use the compact seven-round formula for subsequent static comparisons | Avoid repeated instruction-shaped explanations without assigning an unsupported algorithm identity |

QG1: No normative content is required. QG2: PC1-PC8 identify dependencies and falsification probes. QG3: Node roles, append/control contracts, payload data flow and finite XPC byte agreement are covered for this increment; broad goal completion is unproved. QG4: Byte extents, endianness, u32/u64 modular arithmetic and algorithmic cost are explicit. QG5: Component proofs, the `unknown` monolithic query, finite header agreement, historical private models and native behavior are distinguished. QG6: Original instructions/fixups, source-linked translations and preserved frozen journals provide primary provenance; memory supplied a locator, not current-build proof. QG7: Impact-bounded continuations retain the native phase, owner, header and endpoint obligations.

The goal remains active. Native PAC, delivery, peer authorization, allocator ownership, full constructor reachability and complete daemon-kext interaction remain unknown.
