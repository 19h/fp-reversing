# Conditional buffer growth, 20-byte append and cleanup interfaces

The pending 77 B allocator interface leads to a source-level grow/copy/append cycle under separately declared API returns. A non-NULL return supplies a fresh 77 B owner H, initially undefined. Original instructions copy the old 57 B buffer F into H, update U's pointer and encoded extent, overwrite F, and request its free. After a declared free return, the source defines H's 20 B tail, changes two earlier bytes, constructs a linked stack node and reaches the same allocator site requesting 97 B. No 97 B return or owner is supplied. [DG1-DG5; DG-A1-DG-A5]

The NULL return follows a distinct cleanup interface: overwrite F/57 B, request and continue its free, overwrite U/48 B, request and continue its free, clear S's U pointer, then stop before an undefined 8 B read at S+0x30. These are conditional model executions, with explicit register clobbers, owner changes and byte invalidation; no native allocation, free, IPC, hardware PAC or IDB mutation executes. Actual native initializer epoch and daemon-kext transaction pairing remain unknown. [DG1-DG5; DG-A2-DG-A5]

```text
152 inherited malloc77 frontiers; 116 B prior conditional entry definitions
  x NULL / fresh77 owner returns
  x two declared SIMD/NZCV and void-return patterns
  = 608 member-specific branch exports

NULL:
  overwrite F57 -> free(F) at 1003174d0
    [declared return; F retired and invalidated]
  overwrite U48 -> free(U) at 100336dec
    [declared return; U retired and invalidated]
  S+0 = NULL -> STOP before S+30 / 8 B at 10074abc8

fresh H77, no initial payload bytes:
  copy F57 -> H[0..56]; write H[1..4]; publish H and raw77 in U
  overwrite F57 -> free(F) at 100a8e84c
    [declared return; F retired and invalidated]
  define H[57..76], change H[15..16]
  source-built node -> inherited terminal node -> NULL
  -> STOP before malloc97 at 100d640ac; H77 remains live
```

| Evidence | Primary artifact and scope |
| --- | --- |
| DG1 | Original `fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`; original instruction words and authenticated import slots. |
| DG2 | [Polynomial report](daemon_descriptor_polynomial_report.md), [checks](triage_evidence/daemon_descriptor_polynomial_checks.json.zst) and [replay](triage_evidence/daemon_descriptor_polynomial_replay.json.zst) qualify the 152 inherited pending-malloc states and their separate root/node premises. |
| DG3 | [Extractor](triage_evidence/recover_daemon_descriptor_growth.py) and [checks](triage_evidence/daemon_descriptor_growth_checks.json.zst): four shared branch classes, ten original intervals, explicit API effects and all 608 per-parent exports. |
| DG4 | [Independent auditor](triage_evidence/replay_daemon_descriptor_growth.py) and [receipt](triage_evidence/daemon_descriptor_growth_replay.json.zst): complete frame/effect replay, admissions, ABI recipe reconstruction, pointer custody, byte-copy pairs, owner snapshots, node-writer provenance and three source obligations. |
| DG5 | [Publication verifier](triage_evidence/verify_daemon_descriptor_growth_publication.py): fresh replay/proof reconstruction, original-word checks, exact manifest delta, preserved inputs and decoded path hygiene. |

## ABI premises, class admission and lifetime boundaries

No further root, node or payload byte is supplied. The inherited entry has 104 B of conditional root definitions and 12 B of terminal-node fields, totaling 116 B; its 4 B descriptor gap remains an inherited unknown unless an original source effect defines it. The new premises are NULL or the model pointer H=`0x6600080000` as a malloc return, a disjoint 77 B owner for H when non-NULL, and declared void-free returns. Fresh H has no defined initial bytes. Each free removes exactly its matching modeled owner and invalidates all its bytes; each API event also invalidates the modeled 4 B errno cell. [DG2-DG4; DG-A2-DG-A4]

Each original interval is admitted by ordered incoming byte demands, required registers, configuration and owner equality. The two NULL classes have 272 and 32 members; the two non-NULL classes also have 272 and 32 members. Each member denotes one parent and one ABI pattern. Differences not consumed by a journal survive in that member's own export. Candidate groups rejected by admission receive a separately executed representative. [DG3-DG4]

None of the ten source intervals accesses a vector register or requires incoming NZCV. X1..X17 are defined before use in each interval; X0 is required for the allocator-result paths and is not required after the continued frees. This qualifies sharing the journals across the declared SIMD/NZCV patterns. Each ABI-entry recipe preserves its own parent's X18..X29 and the low 64 bits of Q8..Q15, rather than copying a representative's saved values into another parent. Twenty fresh recipe comparisons against the underlying API-premise helper, covering both patterns at every representative event, pass. Native calling-environment behavior outside the declared ABI effects remains unknown. [DG3-DG4; DG-A3-DG-A4]

| Pending API site | Argument X0 | Original bind slot / logical authentication | Continued effect |
| --- | --- | --- | --- |
| `0x100d640ac`, initial | 77 B | malloc: `0x10109ff58`, IA `0x6aa4`, address diversity 0 | Declared NULL or fresh H/77 B return |
| `0x1003174d0`, NULL route | F=`0x6600070000` | free: `0x10109ff30`, IA `0x46a2`, address diversity 0 | Declared F/57 B retirement |
| `0x100336dec`, NULL route | U=`0x6600060000` | Same free bind and authentication | Declared U/48 B retirement |
| `0x100a8e84c`, non-NULL route | F=`0x6600070000` | Same free bind and authentication | Declared F/57 B retirement |
| `0x100d640ac`, later | 97 B | Same malloc bind and authentication | Pending; no return supplied |

Every listed pending call is `BLRAA`; original pointer-format-12 records independently confirm the bind name, ordinal, key, diversity and address-diversity field. The pointer-custody audit starts at the four pinned polynomial parents' original slot chains, carries tags through each declared API invalidation and checks every admitted parent-pointer class against the shared journal. Import model addresses are placeholders, not native function addresses. [DG1-DG4; DG-A1-DG-A4]

## Copy, publication and append data flow

The non-NULL path's copy body at `0x100b5c9b0..0x100b5c9b8` decrements X9, reads F[X9] and writes the same byte to H[X9]. There are 57 read/write pairs, at offsets 56 down to 0, before the old-F overwrite. A universal source obligation proves the one-byte transfer and index decrement. F and H are disjoint under the declared owner premise; no initial H payload is required. [DG1, DG3-DG4; DG-A2-DG-A3]

Before the first pending free, H has 57 defined bytes and an undefined 20 B tail. Its byte 0 and offsets 5..56 retain the copied bytes. Original stores at `0x100c70e28`, `0x100c70e80`, `0x100c70ed0`, `0x100c70f18` change offsets 1..4 to `b7 15 1d 05`. U+8 becomes H, and U+0x10/U+0x14 both contain raw u32 `0x10ecc45e`, which decodes to 77 B under the recovered bias. U retains its 40 defined bytes and 8 unknown bytes. These establish local pointer/extent publication; a complete native structure type remains unknown. [DG3-DG4; DG-A3-DG-A5]

After the declared free(F) return, twenty source byte stores cover every previously undefined tail byte exactly once. The final tail is `9e6fd1e444283e0c873eed801e6d07049b2d3b36`. The following groups describe source-store layout; their native field names and complete value codecs remain unknown. [DG3-DG4; DG-A3-DG-A5]

| H offsets, decimal | Bytes in increasing address order | Writer group |
| --- | --- | --- |
| 57..60 / 4 B | `9e 6f d1 e4` | Four stores at `0x100c70e28`, `0x100c70e80`, `0x100c70ed0`, `0x100c70f18` |
| 61..64 / 4 B | `44 28 3e 0c` | Same four-store group |
| 65..68 / 4 B | `87 3e ed 80` | Same four-store group |
| 69..70 / 2 B | `1e 6d` | Descending-byte stores at `0x100a0ca74` |
| 71..72 / 2 B | `07 04` | `0x100b755ac`, `0x100b755f8` |
| 73..76 / 4 B | `9b 2d 3b 36` | Descending-byte stores at `0x100a0ca74` |
| 15..16 / 2 B, earlier region | `60 b3` | `0x100b755ac`, `0x100b755f8` |

H is fully defined at 77 B by the next allocation frontier. The tail width is 4+4+4+2+2+4=20 B; the two earlier-byte changes do not extend its size. U still points to H and retains its raw77 pair. S still points to U, with its inherited 53/64 B definedness. J/552 B has no interval writes and retains its bytes in both routes; other private/global source state effects remain recorded in the journals. [DG3-DG4]

## Source-built node and recurrent allocator interface

The later original source writes a new private node at `0x680005fdf0`. Its two consumed fields have exact current-interval writers, and the subsequent walk reads those fields before the inherited terminal-node fields. [DG3-DG4; DG-A3-DG-A4]

| Node field | Original writer | Subsequent consumed value |
| --- | --- | --- |
| New b+0 / u32 | `0x100b005c4` | Raw `0x706d2ed6` |
| New b+8 / u64 | `0x100b005c0` | Raw q=`0x000000d0000c08d0`; q-b=`0x6800060ae0` |
| Inherited node `0x6800060ae0` +0 / u32 | Earlier separate premise; no overwrite in this interval | Raw `0xb5d0fba6` |
| Inherited node +8 / u64 | Earlier separate premise; no overwrite in this interval | q=node, hence next=0 |

This establishes a concrete two-node chain **within the conditional model**: source-built node -> inherited premised node -> NULL. The source-built node's current writers strengthen the local producer/consumer join; the inherited tail and initial native epoch remain conditional. This does not establish a native linked-list allocation, cross-thread lifetime or a Mach/IOKit buffer identity. [DG2-DG4; DG-A2-DG-A5]

At the later extent-update entry `0x100c05638`, W8=`0x74c239c3`, W21=`0x28` and W22=old raw `0x10ecc45e`. Original instructions implement `new_raw=u32(old_raw-W8+W21+0x74c239af)`, hence `new_raw=old_raw+20=0x10ecc472` in this phase. At `0x100d64014`, W10=`0xc4eb` selects the same recovered count bias `0xef133bef`; X0 becomes `zero_extend64(u32(new_raw+0xef133bef))=97` B. The report therefore establishes 57 B -> modeled H/77 B -> **pending 97 B request**, with source-derived 20 B arithmetic in both recovered phases. It does not establish an unbounded growth law or successful 97 B allocation. [DG2-DG4; DG-A3-DG-A5]

## NULL cleanup and atomic-value touchpoint

The NULL route writes all 57 F bytes at `0x1002c5104` before the first free request. After the declared free(F) return, it writes all 48 U bytes at `0x1002a9a04` before the second free request. These are observed nonzero overwrite patterns in the model; no native erasure guarantee is inferred. After free(U)'s declared return, `0x1006d1354` clears S+0/8 B. Both F and U have no remaining modeled owner or defined bytes; S remains a live 64 B owner. The next source read at `0x10074abc8` requires the still-undefined S+0x30/8 B. S's other unknown fields remain unresolved. [DG3-DG4; DG-A2-DG-A5]

Between the two free requests, source `0x1003adb90` executes `CASAL W13,W10,[X8]` with X8=`0x1010b5de0`, expected W13=`0x5d96`, desired W10=`0xa94ef`, and the current 4 B word equal to the expected value. The two NULL representatives each produce the source value transition `0x00005d96 -> 0x000a94ef`, checked by independent CAS replay. The global word is an architectural control-state touchpoint. Native atomicity, synchronization participation and concurrent mutation are not established by this sequential model. [DG1, DG3-DG4; DG-A4-DG-A5]

No new Mach-port name, right transfer, external send/receive emission or actual daemon-kext transaction is established. The recovered interfaces concern local allocator/free calls, encoded pointer/extent publication, byte stores, descriptor links and global control-state mutation. Their native transport joins remain unknown. [DG1-DG5; DG-A5]

## Verification and assumption register

Ten intervals across four classes retain 247,506 original visits, 41,994 reads, 13,090 writes, 10,662 logical edges and 64 internal calls. Independent replay checks 7,920,512 GP/SP values, 7,920,512 Q values, 247,516 NZCV frames, 216,596 read bytes, 57,288 write bytes and 10,594 authenticated edges; the remaining 68 edges are 40 RETAB and 28 RET returns. Two representative CAS value transitions are checked. The 608 branch admissions comprise 1,520 interval admissions, 2,940,048 incoming byte demands and 12,160 incoming register demands. Eight changed/missing demanded-byte controls, four changed-SP controls and four changed-owner controls are rejected; four per-parent saved-X18 controls pass. Three new nonvacuous source obligations are UNSAT. [DG3-DG5]

Time is O(visits*frame state + admissions*demands + proof DAG), excluding solver search complexity and publication input I/O; storage is O(receipts + parent maps + largest interval + proof DAG). Source proofs qualify one-byte copying, the generic extent-update equation and the phase-specific decoded allocation count. Byte widths, addresses and extents use B; indices and event counts are dimensionless. Arithmetic wraps at u32/u64 widths. Model/original-image addresses do not establish native ASLR mappings. Receipts use `zstd --ultra -22 -q -T1` with decoded round-trip checks. Retained primary evidence suffices; IDA is not accessed. [DG1-DG5]

| Assumption | Dependent results | Stress test / falsification probe |
| --- | --- | --- |
| DG-A1: Pinned image, fixups, dependencies and inherited receipts apply | Source interfaces, byte effects and logical targets | Check parent/source/dependency hashes, every visited original word and independently decoded authenticated imports. |
| DG-A2: API returns and owner effects are explicit separate premises | Both allocation outcomes, retirements and subsequent frontiers | Start fresh H with zero defined bytes; reject overlapping owners; invalidate retired bytes and errno; retain inherited root/node and native-epoch qualifications. |
| DG-A3: Exact admitted machine/byte phase applies | Shared journals, copy/append layout and 97 B request | Admit every interval for all 608 branches; verify own exports, all 57 copy pairs, 20 distinct tail stores, source-built node writers and full-width arithmetic. |
| DG-A4: Sequential instruction semantics and declared ABI preservation apply | Replay, pointer custody, CAS and per-parent saved values | Reconstruct both ABI patterns at every representative event; verify all frames, origin journals, byte effects, fault controls and saved-X18 perturbations; native PAC/concurrency remain unknown. |
| DG-A5: Local interface evidence does not establish complete native identity | Structure naming, ownership and transport interpretation | Require actual initializer/lifetime evidence, full codec/field semantics, later allocation outcomes and actual Mach/IOKit buffer/transaction joins. |

| Impact | Bounded next evidence | Present limit |
| --- | --- | --- |
| High | Recover the 20 B append's value inputs and repeated four-/two-byte writer codecs | Concrete byte layout and writers are established; native field names and semantic values remain unknown. |
| High | Recover complete helper status/return meanings and later 97 B outcomes | The request is pending; no 97 B owner exists in this increment. |
| High | Join the new node producer's value encoding to the walk and polynomial contract | Current writer-to-reader custody is established; inherited terminal node and native epoch remain conditional. |
| High | Join U/H/S identities to actual daemon-kext IPC buffers | No new native transport evidence or right transfer is established. |
| Medium | Establish the global CAS word's broader state machine and synchronization contract | One sequential successful-value case is established; competing states and native scheduling remain unknown. |

**QG1**: factual source/ABI analysis. **QG2**: DG-A1-DG-A5 state dependencies and falsification probes. **QG3**: the growth/append/cleanup increment is covered; the complete interface goal remains active. **QG4**: byte widths, masks, arithmetic, counts and complexity are explicit. **QG5**: conditional API effects, native unknowns, modeled node provenance and pending allocation are distinguished. **QG6**: fresh complete replay, admissions, source proofs, import records and publication checks qualify primary evidence. **QG7**: impact-labeled adjacent interfaces and remaining evidence are explicit.

Follow-up: The [append-field follow-up](daemon_append_fields_report.md) resolves the repeated four-/two-byte writer codecs and the indexed array-word mixer, and records exact longer-producer inputs and last-writer custody. It independently checks 4,018 selected source instructions and 35 source obligations without adding a target interval or allocator return. The general longer-producer reductions, native field names and transport pairing remain unknown.

The [local record-span follow-up](daemon_record_spans_report.md) proves the constructor span calculation 4*count+20 and its addition to the old header, decodes four payload scalars 0/1/0/1, and joins the later 97 B request to the scalar20 at offset57 rather than the enclosing scalar76 at offset1. Contiguous span endpoints and the record-start+14 values support a nested record and child-count interpretation; complete native schema and daemon-kext identity remain unknown. Twenty-three nonvacuous obligations, 20,112 independently replayed instructions and 3,192 field checks across 456 exports qualify this increment. No new target interval or API-return premise is added; the full goal remains active.
