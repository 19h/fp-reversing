# Existing-record u32 reader: header, extent, type and borrowed output

The existing-record continuation of0x100847998 is a conditional u32 reader. After the prior first-match lookup, it accepts wire tag0x9777 with a declared4 B payload that fits the node's buffer extent, writes BE32(payload) through the saved borrowed output pointer, and returns raw success0x8b3dc651. Recognized wire tags0x8485 and0x50db return raw0x74c29cd6 without that output write. Other tags, nonfitting extents and a u32 payload extent other than4 B return raw0x74c29d8f. Pointer validity, stable owners/frames and normal completion remain explicit premises. [ER1-ER7]

The reader's tag representation differs from the constructor's: low16(reader W24)=wire_tag XOR0x4799. Its signed type partition therefore uses0xd0ee,0xc31c and0x1742, not the constructor's0x86b4,0x9546 and0x4118. The output is the wire scalar's BE32 numeric value, not the constructor's internally XOR-encoded operand. These distinctions are source-proved. [ER2,ER3,ER5]

Evidence: [source, fixups, liveness and retained occurrence limits](triage_evidence/daemon_existing_scalar_reader_source.json), [36-query certificate](triage_evidence/daemon_existing_scalar_reader_checks.json), [extractor](triage_evidence/recover_daemon_existing_scalar_reader.py), [validator](triage_evidence/validate_daemon_existing_scalar_reader.py), [preservation](triage_evidence/daemon_existing_scalar_reader_delivery.json), [scoped gates](triage_evidence/daemon_existing_scalar_reader_quality_gates.json). Prior contracts: [entry, miss and population route](daemon_scalar_field_population_report.md), [first-match lookup and word decoder](daemon_constructor_lookup_report.md), [header writer](daemon_header_codec_report.md), [payload codec](daemon_payload_codec_report.md), [builder owners and finish](daemon_builder_owner_join_report.md).

| Evidence | Verified scope |
| --- | --- |
| Pinned thin image | `/Users/___/Downloads/zut/fairplayd.arm64e`; SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Original source |19 fragments,1335 instructions,5340 B |
| Pointer/control records |21 original pointer records,28 selected slot/modifier matches; every captured fragment ends in BRAA and contains no other control transfer |
| Liveness |23 explicit register-preservation checks across the relevant constant, cursor and round-key intervals |
| New tag codec |Two seed lemmas,14 round lemmas and one two-byte merge/address lemma |
| Source certificate |36 UNSAT queries,1556 translated instruction instances,1487 SSA definitions;1316 distinct nonbranch source sites covered |
| Reused source |47 ranges/6332 B freshly compared with original bytes; prior four-word-mask cuts retain their pinned seed/round obligations |
| Retained profiles |12 successful historical profiles; zero entries into the selected found-record route |

Addresses/constants are hexadecimal; extents use B. K is the shared frame, C1=[builder+8], NODE the matched node, BUF=[NODE+18], SIZE/u32=[NODE+10], PL/u32 the decoded declared payload extent, OUT the caller's borrowed output pointer, and C=0x797188010b5fa78c the encoded cursor-zero representation. Arithmetic wraps at u32/u64 width unless an explicit nonwrapping bound is given. All role names are analytical.

## Conditional reader grammar and status precedence

The [earlier entry certificate](daemon_scalar_field_population_report.md) establishes C1/key/OUT/continuation staging, first-match lookup, null-buffer handling and the initial SIZE>=10 B header gate. The new source completes the selected found-value continuation under those entry premises.

```text
first matching identifier in C1
        |
  valid NODE and nonnull BUF
        |
  SIZE >= 10 B
        |
  decode header identifier, tag, PL
        |
  PL + 10 <= SIZE ? ---- no ---> raw74c29d8f
        |
       yes
        |
  wire tag9777 ? -- yes --> PL == 4 ? -- no --> raw74c29d8f
        |                       |
        no                     yes
        |                       |
  tag8485 or50db ?          read payload at BUF+10
    /          \                |
  yes          no          recheck saved tag
   |            |               |
 raw74c29cd6  raw74c29d8f   *OUT/u32 = BE32(payload)
                                 |
                             raw8b3dc651
```

The new final grammar query composes the source-proved signed/equality partitions for every raw32-bit tag value and every u32 PL/SIZE. Its premise is a shared, stable tag/extent epoch. The initial lookup/null/short-buffer outcomes retain their previously established precedence; they are not replaced by this post-header grammar. No public error-number meaning is assigned to any raw marker. [ER2-ER6]

| Condition in selected route | Raw low32 result | Borrowed OUT effect |
| --- | --- | --- |
| Null C1 or null matched BUF |0x74c29d88, prior entry contract | No direct output write |
| Lookup reaches end |0x74c29ded, prior lookup contract | No value-output write |
| SIZE<10 B |0x74c29d8f, prior header gate | No direct output write |
| PL+10>SIZE |0x74c29d8f | No direct output write |
| Fitting wire tag8485 or50db |0x74c29cd6 | No direct output write |
| Unknown tag, or tag9777 with PL!=4 |0x74c29d8f | No direct output write |
| Fitting tag9777/PL4, stable saved tag and writable OUT |0x8b3dc651 | Writes exactly4 B, numeric BE32(payload) |

These output-effect statements require OUT/frame/record owners to be disjoint where specified. The source saves OUT's address; it does not initialize its pointee on entry. Contents after a nonwriting result therefore remain caller/epoch-dependent. A nonnull found node must be valid before its buffer/size fields are read; a numeric extent is not a proof of backing ownership. [ER3,ER4]

## Header offsets, codecs and representations

The common four-byte decoder0x100800004 has two related32-bit outputs:

```text
W1 = BE32(unmasked bytes) XOR0x8ec35f08
W4 = BE32(unmasked bytes) XOR0x8b3dc651
```

The new word-output lemma verifies both representations, all four byte addresses and X28's carried first-round key. It reuses the prior original-source canonical address-mask seed/round lemmas; it does not substitute the same value for W1 and W4.

The new two-byte reader0x1005122cc uses the same canonical address-dependent byte mask. Its two seeds and seven rounds per byte are separately proved from original instructions. The merge proves:

```text
low16(W24) = BE16(unmasked bytes at BUF+O+4) XOR0x4799
```

Its exact byte addresses are BUF+O+4 and BUF+O+5. Upper16 bits of W24 can contain intermediate merge bits and are not declared a zero-extended tag. Dispatch explicitly applies SXTH/UXTH; the saved header tag uses a16-bit store. At the selected entry O=0. [ER2,ER5]

| Header/payload field | Offset / extent | Source representation and continuation |
| --- | --- | --- |
| Identifier |0 /4 B | First word reader returns through selector74 ->0x10051e2c0; this continuation does not recompare the decoded identifier. Identity selection relies on prior first-match lookup and stable BUF. |
| Tag |4 /2 B |0x10051e2c0 ->0x1005122cc; selector212 ->0x1004e2ee8 |
| Declared PL |6 /4 B |0x1004e2ee8 ->0x100530d34 ->word reader; selectoref ->0x10052b3e8 |
| U32 payload |10 /4 B |0x1005be67c ->0x100530d34 ->word reader; selectorb3 ->0x100530108 |

The actual reader/constructor tag encodings are:

| Wire tag | Constructor internal tag | Reader low16 tag | Reader signed16 value |
| --- | --- | --- | --- |
|0x9777 |0x86b4 |0xd0ee |-12050 |
|0x8485 |0x9546 |0xc31c |-15588 |
|0x50db |0x4118 |0x1742 |5954 |

Constructor tags XOR0x11c3 to the wire tag; reader tags XOR0x4799 from it. The lower split at0x10052af04 tests signed low16<0xd0ee; its lower branch checks0xc31c. The other branch at0x10058ead4 splits at signed0x1742, then checks0xd0ee or0x1742 exactly. Source register outputs compose between these stages: in particular the u32 checker receives the post-split phase0x643c, not the original core phase0x6cf4. [ER2,ER5]

## Frame epochs and the nonwrapping extent gate

The complete386-instruction decoder preparation0x1006f6bf0 is translated with explicit named loads. Under the selected entry cursor C and SIZE/u32, it establishes these critical fields:

| Frame field | Prepared value | Consumer |
| --- | --- | --- |
| K+978 /8 B | C+10 | End-cursor formation |
| K+970 /8 B |0xd68943be | Biased end-range comparison |
| K+958 /8 B | zero_extend64(SIZE) | Range-control comparison |
| K+950 /8 B | zero_extend64(SIZE)+0xd68943b4 | Biased upper bound |
| K+8f8 /8 B |0x661a590b302baf96+6 | Length-word encoded offset |
| K+818 /8 B |0x661a590b302baf96+10 | Payload-word encoded offset |

Other preparation loads read shared context/frame state and remain valid-read premises. The certificate translates them without claiming native owner/reaching-definition validity for every unrelated field. The selected constants and preserved buffer/offset/return inputs are checked independently of those unrelated loaded values. [ER3-ER5]

At0x10052b3e8, W1 XOR0x8ec35f08 recovers PL. The source saves C+10+zero_extend64(PL) at K+95a0. Its arithmetic/condition tree selects the fitting edge exactly when:

```text
zero_extend64(PL) + 10 <= zero_extend64(SIZE)
```

This is a u64 comparison with u32 inputs; it cannot wrap as a32-bit PL+10 addition. For the selected u32 branch PL=4, so SIZE>=14 B. SIZE can exceed14 B: this getter does not require exact total record length14 B. Recognized alternate tags need the common declared-extent fit but are not given u32 success or an extra u64-length-equals8 requirement by this source path. [ER2,ER5]

K+959e stores low16(tag); K+980 first receives the raw tag W24 and later the selected u32 tag marker. K+95a0 holds the encoded end cursor. K+8048 holds encoded cursor zero on earlier entry, then the encoded end cursor on alternate-type or completed payload return. K+84cc begins as an entry marker and later holds W4 from the payload decoder. These meanings belong to distinct epochs; they are not one immutable structure type. [ER3,ER5]

## Borrowed output and caller behavior

At0x100530108, the payload decoder's W4 is saved at K+84cc. The source reloads the saved16-bit tag, publishes the end cursor to K+8048 and rechecks tag0xd0ee. The actual output continuation0x100506a0c loads OUT from K+4ca0 and computes:

```text
temporary = BE32(payload) XOR0x8b3dc651
*OUT/u32  = temporary XOR0x8b3dc651
          = BE32(payload)
```

The output store is0x100506a30. Raw success0x8b3dc651 then returns through0x1006f76a8 using CONT=[K+7af0], whose selected caller is0x1006985d4. A writable4 B OUT owner is required; this path supplies no separate null-output guard. No fault fixture was executed. [ER3-ER6]

For the previously recovered builder caller, only exact miss0x74c29ded selects generated-field population. A successful existing u32 record therefore bypasses that helper and reaches the common finish. Other reader markers also reach common finish, where the prior exact-success/disposal contract applies. The continuation does not use the borrowed scalar to generate a replacement value on success. This control-flow join remains conditional on the same frame/continuation epoch. [ER2,ER3,ER6]

## Retained evidence and IPC boundary

All twelve retained successful profiles enter the miss/population route, with zero found-record entries. Their recorded nested field0xf6964e3e/tag9777/PL4/payload04f2abb5 is compatible with the source grammar; this increment does not execute that packet through the existing-value reader or call it an observed accepted input. Five altered source/evidence controls are rejected by fresh-source comparison.

Every newly captured fragment has one terminal BRAA and no other control transfer. This selected reader interval contains no API call, Mach send/receive, port construction or right emission. The prior buffer-to-XPC lineage supplies the surrounding private-model context. Native owners, shared-state synchronization, hardware PAC, peer identity and selector26/RPC502/700 daemon-kext pairing remain unknown. No target/native execution, new emulation, native API/IPC, IDA access, IDB mutation or memory-store update occurred. [ER4,ER7]

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| ER1 | Original ranges, fixups and build identity are pinned. All address roles depend on this image. | Rehash/recapture19 fragments,21 pointer records and47 prior ranges; independently compare selected fixup text with dyld_info. Reject cross-build substitutions. |
| ER2 | Selected core phase, table, saved continuations and register epochs apply. Control/status grammar depends on these conditions. | Compose actual stage outputs, including post-split phases; check28 slot/modifier pairs and23 liveness intervals. Equal modifiers alone are insufficient. |
| ER3 | NODE/BUF/frame/OUT owners are readable/writable, stable, nonwrapping for the accesses and disjoint where required. Output, identity and frame joins depend on these premises. | Recover owners and last writes; check exact field/store/load addresses and widths; distinguish declared SIZE from backing ownership. Concurrent mutation and arbitrary aliasing remain unproved. |
| ER4 | Full preparation and source codec paths complete normally, including unrelated context reads. Native memory/PAC success is not assumed proved. | Preserve named-load boundaries, full source capture and control census; require actual owner/initialization/authentication evidence before native claims. |
| ER5 | Canonical address-mask seed/round lemmas and unchanged constants apply at each decoder epoch. Header/PL/value interpretation depends on this composition. | New two-seed/14-round/tag-merge proofs; check word W1/W4 separately, carried round key and frame offsets. Upper tag bits remain incidental; do not substitute constructor tag encoding. |
| ER6 | Prior first-match entry/miss/header guards and builder finish contracts apply to the same C1/OUT/CONT owners. End-to-end caller behavior depends on this reuse. | Recheck source operand identities and saved fields; distinguish a copied output address from initialized output contents. No direct OUT write is inferred on nonwriting results under disjoint owners. |
| ER7 | Frozen observations retain their historical scope. The found-reader execution count is zero. | Rehash profiles, inspect entry-event counts and retain packet bytes only as compatibility evidence. Native endpoint pairing and full goal completion remain unknown. |

For k examined candidates, the reused first-match search takes O(k) time and O(1) traversal storage under a finite stable acyclic list. The selected found-record reader performs bounded header and4 B payload decoding, O(1) additional work/storage; header PL is checked without traversing its entire payload. Capture/check work is linear in source/retained bytes plus instructions; SMT resource use is additional, with15000 ms per query. The1556 translation instances intentionally overlap codec merge/seed/round components;1316 distinct nonbranch source sites are covered. No exact-once translation claim is made.

## Bounded continuation opportunities

| Impact | Next target | Question resolved |
| --- | --- | --- |
| High | Owners/reaching writes for all386-instruction preparation context reads. | Native reader admissibility and initialization epochs beyond named-load premises. |
| High | Remaining builder fields and collection serialization consumers. | Complete field grammar and representation/ownership transfer into IPC. |
| High | Same-build native owners/endpoints for selector26/RPC502/700. | Actual daemon-kext/deeper transaction pairing. |
| Medium | Other callers of0x100847998 and corresponding u64/span accessors. | Shared reader API family and whether raw status roles generalize. |
| Medium | Shared collection mutation and buffer lifetime synchronization. | Identity/range/value stability across lookup and repeated reads. |
| Low | Typed names/comments only after source/runtime identity checks. | Readable local symbols without propagating unverified public semantics. |

## Scoped quality gates

- QG1: Technical source/interface facts require no normative conclusion.
- QG2: ER1-ER7 specify dependencies and falsification probes.
- QG3: Conditional found-reader type/extent/output/status and builder-caller behavior are covered; native memory/context validity and the broad interface goal remain incomplete.
- QG4: u16/u32/u64 representations, signed16 dispatch, nonwrapping u64 extent arithmetic, BE16/BE32 and4/10/14 B extents are explicit.
- QG5:36 accepted UNSAT queries include the composed status grammar; source-backed liveness and epochs prevent phase/encoding substitutions. Overlapping codec ledgers and zero retained found-path entries remain explicit.
- QG6: Original bytes/fixups, source translations, pinned prior mask proofs and historical profile counts provide primary provenance; no new target/native run or IDB/memory mutation occurred.
- QG7: Continuations remain bounded and impact-labeled; native pairing and full goal completion are unknown.


## Subsequent preparation-footprint refinement

The [later cache/footprint certificate](daemon_reader_context_footprint_report.md) resolves the addresses of every preparation load and store and recovers all50 affine cache values for this selected entry. The six critical values and complete next-word-reader input register projection are independent of25 other prior values,while44 cache fields retain those values. Native working-frame/TABLE roots,initialization and producer epochs remain premises;compiler containment does not establish the active frame owner.
