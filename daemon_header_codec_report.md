# Encoded word writer, header construction and u32 scalar ABI

The component at `0x100546c90` is a general encoded big-endian u32 writer. It writes four bytes at a caller-selected offset, applying the address-indexed mask established in [the payload-codec report](daemon_payload_codec_report.md). Original callers use offsets 0, 6 and 10 for record identifiers, header lengths and u32 scalar payloads. The two-byte writer at `0x1007b28a4` emits the discriminator at offsets 4 and 5. Together these establish the conditional ten-byte header and u32 scalar serialization contracts. [HC1-HC8]

The encoded word supplied to the helper is not itself the wire word. Its clear wire result is `F XOR 0x8a1bf900`, where F is the helper's incoming W22. Caller transformations reduce the final field codec to XOR `0x8b3dc651`. The discriminator caller similarly reduces to `wire_tag=internal_tag XOR 0x11c3`, agreeing with the established reader. Native phase production, ownership, admission and transport pairing remain unknown.

Primary artifacts: [fresh source, pointers and retained stores](triage_evidence/daemon_header_codec_source.json), [queries and instruction translations](triage_evidence/daemon_header_codec_checks.json), [extractor](triage_evidence/recover_daemon_header_codec.py), [validator](triage_evidence/validate_daemon_header_codec.py), [preservation](triage_evidence/daemon_header_codec_delivery.json), [quality gates](triage_evidence/daemon_header_codec_quality_gates.json). The [original profiles](triage_evidence/arcade_subscription_profiles.json) remain historical private-model evidence. No target execution, new emulation, host IPC or IDB mutation occurred. Reference data sufficed without further IDA access.

| Provenance or check | Verified scope |
| --- | --- |
| Thin daemon | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Fresh source | 12 fragments, 967 instructions, 3868 B; 18 four-instruction constant groups; 12 original pointer records |
| Prior source recapture | 19 ranges, 5820 B, from the payload-codec ledger |
| Static certificate | 72 UNSAT queries: 63 new component queries and nine rechecked accepted payload queries |
| Translation | 687 instruction instances, 679 SSA definitions; counts include repeated source slices and constant materializations |
| Retained private evidence | 12 send profiles, 60 constructed headers, 600 header-byte stores, 144 u32 scalar-payload byte stores, 156 word-writer entries and 60 tag-writer entries |
| Altered controls | Eight altered source/store/entry/liveness records rejected |

All addresses are unslid original VAs. Offsets/constants are hexadecimal; byte counts are decimal unless prefixed `0x`. Arithmetic is modulo u32/u64 as marked. Native readable/writable extents, nonwrapping addresses and ownership are separate premises.

## General encoded word writer [HC1-HC4]

Let B be the record-buffer pointer loaded by the helper, o a caller offset, and F the incoming W22/u32. The offset is passed in encoded form as `X19=0x71134a47fbd9f0b7+o`, modulo u64. The helper's address constants cancel that base. For j=0..3:

```text
A = B + o + j
clear_byte = BE32(F XOR 0x8a1bf900)[j]
stored[A] = clear_byte XOR m(A)
```

Here m(A) is the same address-indexed byte mask used by the payload producer and serializer. The generic offset theorem quantifies over arbitrary u64 B/o; its modular address identities do not establish native pointer validity.

| Byte | Original store | Clear byte before address mask |
| --- | --- | --- |
| 0 | `0x100546e54` | `u8(F>>24) XOR 0x8a` |
| 1 | `0x100546fe8` | `u8(F>>16) XOR 0x1b` |
| 2 | `0x1005471b4` | `u8(F>>8) XOR 0xf9` |
| 3 | `0x1005472a8` | `u8(F)` |

On entry the helper resolves a continuation from original table index W24, then reloads the buffer through X16. After the stores it loads frame+`0x9d0` into X22 and branches to the resolved continuation with IA diversity `0xa918`. Thus incoming W22 is data, while outgoing X22 is a later control value. Treating W22 as one persistent semantic variable across the component would be incorrect.

## Header and scalar caller contracts [HC2-HC6]

K denotes the shared-core frame SP. `H_e` is the raw incoming identifier operand in W19, `P_e` is u32[K+`0x988`], and V is u32[K+`0x8f8`]. These names describe this component interface; a universal mapping back to public request fields has not been proved here.

| Use | Original preparation | Offset o | Helper F | Clear wire word |
| --- | --- | --- | --- | --- |
| Identifier | `0x1008314ec` and key setup | 0 | `H_e XOR 0x01263f51` | `H_e XOR 0x8b3dc651` |
| Header length | `0x1005979d4 -> 0x100615004` | 6 | `P_e XOR 0x01263f51` | `P_e XOR 0x8b3dc651` |
| u32 scalar payload | `0x100534f24 -> 0x100615004` | 10 | `V XOR 0x01263f51` | `V XOR 0x8b3dc651` |

The last row agrees with the [reader's u32 scalar convention](daemon_xpc_records_report.md): reading that BE32 payload and XORing `0x8b3dc651` yields V. This establishes the scalar value codec, not an application-specific meaning for V.

The identifier preparation reaches key-setup index `0x54e5` if and only if incoming W23=`0xc714`. Under that condition it produces W24=`0x29a`, W21=`0x6cf4`, X16=node+`0x18`, and the identifier F above. W19 survives the preceding captured node/buffer allocation fragments; native upstream identifier production remains unproved.

The length and scalar callers require the selected control epoch `u32[K+0x9d0]=0x6cf4` or the equivalent supplied incoming phase. Key setup writes W21=`0x30b3` and W7=`0x01263f51`; source register-write checks show these survive the relevant helpers. The common caller at `0x100615004` forms index `0x9da7` and transforms W20 into helper F. X19 selects offset 6 or 10 through the encoded base; W24 selects the corresponding continuation.

| Original index | Target | IA diversity | Role |
| --- | --- | --- | --- |
| `0x54e5` | `0x1008ecb78` | `0x07ac` | Key/field setup |
| `0x9da7` | `0x100546c90` | `0x1911` | Word-writer entry |
| `0x29a` | `0x100617400` | `0xa918` | Identifier return / tag preparation |
| `0x2cff` | `0x1007b28a4` | `0x4b13` | Tag-writer entry |
| `0xa6f` | `0x1005979d4` | `0x82dd` | Tag return / length preparation |
| `0x1824` | `0x100615004` | `0xd637` | Common word call |
| `0x2a2` | `0x10047cd38` | `0xa918` | Length return |
| `0x6866` | `0x1004f4bc4` | `0x7132` | Subsequent constructor type dispatch |
| `0x282` | `0x1005ae7a0` | `0xa918` | Scalar-word return frontier; downstream semantics not recovered here |

All selected records use address diversity zero. Additional original fixups to the scalar-return address are retained in the source ledger; the role above uses the exact index/modifier pair. No hardware authentication or native return is established.

The same target `0x1005ae7a0` also appears at index `0xb16e`/IA`0x990a`, the proved span-payload loop end from the preceding increment. Indices `0x4cf4`/IA`0x62b1` and `0x134c`/IA`0xd08c` also point there; their full entry roles are not recovered here. This is a static control-flow convergence, not proof that the incoming register/frame states are equivalent.

## Discriminator writer and ten-byte layout [HC2-HC6]

Key setup reads a signed 16-bit internal discriminator T at K+`0xa65e`, stores its sign-extended form, and derives `C32=sign_extend16(T) XOR 0xffff9da3` at K+`0x958`. The return block `0x100617400` supplies `u8(C32>>8)` and C32 to the two-byte writer. Its clear bytes are:

| Store | Address | Clear value before m(A) |
| --- | --- | --- |
| `0x1007b29f0` | B+4 | `u8(C32>>8) XOR 0x8c` |
| `0x1007b2b50` | B+5 | `u8(C32) XOR 0x60` |

Consequently the clear BE16 word is `T XOR 0x9da3 XOR 0x8c60 = T XOR 0x11c3`, for every 16-bit T. Signed extension has no effect on those two emitted bytes. The source emits this codec independently of whether a particular T satisfies the constructor's preceding admission logic. That complete admission logic is outside this increment.

Under the established caller epochs and stable buffer-pointer premise, the encoded header decodes to:

```text
offset    0           4       6                 10
          +-----------+-------+------------------+
wire      | H: BE32   |T:BE16 | P: BE32          |
          +-----------+-------+------------------+
H = H_e XOR 8b3dc651
T = internal_T XOR 11c3
P = P_e XOR 8b3dc651

u32 payload, selected scalar route
offset   10                 14
          +------------------+
wire      | BE32(V^8b3dc651) |
          +------------------+
```

The word and tag helpers independently reload the buffer pointer through the node's +`0x18` field. One contiguous header therefore requires those loads to agree and the relevant frame aliases to name the same node. The source does not make the ten-byte construction atomic.

The header P originates in a frame field; the earlier [node-extent theorem](daemon_payload_codec_report.md) consumes an incoming encoded payload operand. Their identical XOR codecs do not prove that these are the same value in every path. The source join from that incoming operand to the saved frame field, together with admission and ownership, remains required for a universal allocator/header-length equality claim. The retained cases are consistent with that equality.

## Shorter common mask and proof composition [HC1-HC4]

The common address-mask seed simplifies further than the preceding payload report's equivalent expression. With all operations modulo u64:

```text
s = ROR64(A & 0xfffffffffffffff8, 8) + 0x622c5d3364e5d59f
x = s XOR 0xa7bebfcf1750d389
y = s XOR 0xb6dc5654307e7f72
for each of the seven constants in the payload-codec report:
    x = (ROR64(x,8) + y) XOR constant
    y = ROR64(y,61) XOR x
m(A) = u8(x >> (8*(A & 7)))
```

The final unused y update can be omitted. A separate all-u64-address query proves equivalence with the prior seed. Each of the six byte-specific source calculations has its own seed lemma, seven arbitrary-state round lemmas and exact byte-selection/store lemma. The 42 round lemmas use explicit source-carried precomputed rotates where necessary. Thus the proof does not infer equivalence from six example addresses or finite packet agreement.

The 72 accepted queries comprise one seed-normalization query, six byte-seed queries, 42 round queries, six selection queries, eight address/caller/field queries and nine rechecked prior payload queries. The earlier monolithic payload query remains recorded as `unknown` in its own report; it is not used as evidence here. The present accepted result is compositional and conditional, not a complete native path proof.

## Retained source occurrence and store offsets [HC1, HC6]

Each of the 12 preserved send profiles allocates five constructed record buffers. Their journals contain exactly ten header-byte stores per record, in identifier/tag/length order. Three scalar records additionally receive four stores at payload offsets 10-13. The same word-helper entry is used thirteen times per profile: five identifier writes from key setup and eight length/scalar writes from the common caller.

| Per-profile quantity | Count | Total across 12 profiles |
| --- | --- | --- |
| Constructed headers | 5 | 60 |
| Header-byte stores | 50 | 600 |
| Scalar-payload byte stores | 12 | 144 |
| Word-helper entries | 13 | 156 |
| Tag-helper entries | 5 | 60 |

These observations recover the helper's general role beyond header construction. Store records provide PCs, destinations and widths, not arbitrary incoming register snapshots or all stored values. Exact encoded/decoded snapshot comparisons remain in [the payload report](daemon_payload_codec_report.md), while XPC pointer/extent/message lineage remains in [the record-stream report](daemon_record_stream_report.md). Private PAC bypass, API models and synthetic allocation addresses remain attached to those observations. No new native port or emission site is established.

## Register and frame epochs

W21 is an encoded payload operand in the earlier node-construction projection. The record-allocation block later repurposes X21 as a table base. Identifier preparation then assigns W21=`0x6cf4`, and key setup replaces it with `0x30b3`. Each role is local to its source epoch. The header-length field is read from K+`0x988`; it cannot be identified with a later W21 value by register name.

Likewise W22 is a raw field at word-helper entry, a restored control value at word-helper exit, a tag continuation index in tag preparation and a code pointer after the tag helper resolves that continuation. Source register-write sets and named-load boundaries retain those transitions. These facts constrain deobfuscation and any future C type reconstruction; they do not establish native frame lifetime or concurrent access policy.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
| --- | --- | --- |
| HC1 | Exact thin-image identity, constant origins and original fixups; all source results | Rehash image, recapture all 12 fragments and 19 prior ranges; build mismatch invalidates address transfer |
| HC2 | Selected preparation/core/key epochs and compatible continuations; assembled caller contracts | Phase preimage and argument queries, register-write sets and original index/modifier records; native upstream phase production remains unknown |
| HC3 | Arbitrary-state round cuts include the specified precomputed rotates; common mask | Rebuild six seeds, 42 round lemmas and six store selections; changed constants/cuts invalidate composition |
| HC4 | Valid nonwrapping owners and stable encoded bytes; operational stores and serializer inverse | Establish actual allocator/frame/lifetime path; modular address identities alone do not prove pointer validity |
| HC5 | Repeated buffer loads and saved aliases identify one node/buffer; ten-byte header | Track node+24 and frame pointer epochs; differing pointers prevent a contiguous-header conclusion |
| HC6 | Frozen private journals faithfully record their own modeled events; finite occurrence counts | Compare pinned profiles, exact store-PC/offset/width sequences and PAC-bypass labels; native behavior remains unknown |
| HC7 | Header frame length equals the earlier incoming payload operand only after a producer join | Trace assignments to K+0xa660/K+0x988 from the actual constructor entry; matching codecs alone are insufficient |
| HC8 | Selected routes do not imply complete constructor or transport admission | Recover type/size checks, u64 scalar route, native returns and endpoint rights before extending the claim |

## Bounded continuation, reproduction and gates

| Impact | Next evidence target | Uncertainty resolved |
| --- | --- | --- |
| High | Join incoming constructor fields to the saved frame identifier/type/length/value operands | Actual external control and allocator/header-length equality |
| High | Recover complete type/extent admission and 8 B scalar serialization | Full typed-record constructor contract, including wire tag8485 |
| High | Establish native phase/owner/endpoint continuity across daemon and FairPlayIOKit | Unresolved selector26/RPC502/700 pairing and actual rights/delivery |
| Medium | Follow return frontier `0x1005ae7a0` and constructor cleanup/list lifetime | Status propagation and ownership after scalar construction |
| Low | Reuse the shorter seed and general encoded-word helper semantics | Compact comparisons without repeating byte-shaped instruction circuits |

```text
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/recover_daemon_header_codec.py
PYTHONPATH=triage_evidence /Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_daemon_header_codec.py
```

Extraction is O(image bytes + fixup count + retained journal bytes), for the fixed 12-profile corpus. Translation is O(selected instruction instances); solving has separate bit-vector solver complexity and a 15000 ms per-query timeout. Stored quantities and offsets use B; wire fields explicitly use BE16/BE32 and internal operations explicitly use u32/u64 modular arithmetic. No physical measurements occur.

QG1: No normative conclusion is required. QG2: HC1-HC8 identify dependencies and falsification probes. QG3: General word/tag writer roles, header/scalar caller ABI, control/field epochs and finite occurrences are covered for this increment; broad completion remains unproved. QG4: Widths, endianness, byte extents, modular addresses and complexity are explicit. QG5: Universal components, selected phases, repeated-pointer premises, the missing allocator/frame join and historical private observations are distinguished. QG6: Original bytes/fixups, source-linked translations and frozen journals provide primary provenance; memory is a locator only. QG7: Impact-bounded continuations preserve the complete constructor, native owner and endpoint obligations.

The goal remains active. Native authorization, PAC, ownership, return behavior, complete constructor admission and daemon-kext exchange remain unknown.
