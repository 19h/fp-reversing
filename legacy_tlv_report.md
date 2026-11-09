# Source-only 64-bit record append and admission contracts

The named kext wrapper `_zzLw2eOVu9pOHqpiNw1K4ki` at `0xfffffe000a50c2b0` appends a 12-byte record in the established selector-`0x224` context:

```text
offset  width, bytes  representation
0       2             BE16(low16(input W1))
2       2             BE16(8)
4       8             BE64(input X2)
```

X0 supplies a carrier whose inspected fields include an output-buffer pointer, entry limit/count and byte limit/cursor. The complete private source path returns zero after appending and advancing both counts. Five checked rejection classes return `0xffff5966` without changing the carrier or output buffer. These are original instruction effects; the inner operation and kernel copy are no longer output-effect models in this increment. PAC remains abstracted, and actual native object/request admissibility remains **unknown**.

[Contracts](triage_evidence/legacy_tlv_contracts.json), [retained source compositions](triage_evidence/legacy_tlv_profiles.json), [distinct fresh replays](triage_evidence/legacy_tlv_replays.json), [independent checks](triage_evidence/legacy_tlv_checks.json) and [six source-derived proofs](triage_evidence/legacy_tlv_proofs.json) retain the evidence. This extends the [legacy bridge report](legacy_stack_report.md). The broad interface investigation remains active and incomplete.

```text
named wrapper(X0=carrier, W1=tag32, X2=value64)
  -> address-keyed outer record P
  -> original bridge A52FD18
       -> stage BE64(value) in an eight-byte local cell
       -> inner record Q: operation=224, length=8, tag16, carrier
  -> original operation entry A55E8B0
       carrier present?
       buffer pointer present?
       carrier header == 1?
       entry_count < entry_limit?
       u32(byte_cursor + 12) <= byte_limit?
        |
        +-- reject -> Q.status = 5E5571AF
        |
        +-- append four header bytes
            -> original copy wrapper/stub/kernel memcpy alias, length=8
            -> entry_count += 1; byte_cursor += 12
            -> Q.status = 5E561849
  -> original bridge copies Q.status to P.status
  -> named wrapper returns u32(P.status + A1A9E7B7)
```

This is an in-memory TLV-shaped format. No native Mach/IOKit emission or producer-consumer binding to a daemon parser is established. Its four-byte header differs from the previously documented ten-byte daemon reply header.

## Assumption register

| ID | Assumption / scope | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LT1 | Pinned original KC and normalized kext define this build | All addresses, symbols, instructions and slots | Rehash sources; compare compiler envelopes, exact spans and original chained-pointer membership; runtime identity is separate |
| LT2 | Private mapped storage and abstracted PAC support conditional instruction semantics | Complete private append/rejection paths | Reject source escapes/unmodeled operations; compare each visited instruction; establish real authentication, mappings and reachability independently |
| LT3 | Carrier fixtures provide the inspected 160-byte extent and declared fields | Admission and object-update checks | Recover the native constructor, full type, field invariants and lifetime; the extent is a minimum accessed prefix, not `sizeof` |
| LT4 | Successful fixture positions fit an independent mapped buffer and do not wrap u32(cursor+12) | Contiguous 12-byte packet interpretation | Inspect actual capacity/allocation and cursor invariants; the source guard itself performs a wrapping u32 sum |
| LT5 | Carrier, output buffer and staged local payload do not alias in the successful fixtures | Preservation outside the packet and original eight-byte copy | Establish actual pointer provenance/alias constraints; no native ownership or general overlap conclusion follows |
| LT6 | Seven mutable-global fixtures have no concurrent modification | Constant table selection and composed control flow | Recheck original/zero/declared-noise fixtures, exhaustive banks and ordered global epochs; native serialization is unproved |
| LT7 | The outer wrapper supplies the particular operation/length codec recovered here | Selector 0x224, length 8 and named-wrapper role | Compare original records and key expressions; other inner-entry operations/record producers remain separate |
| LT8 | The tag slice admits low16 projection; other lifts preserve architectural W/X widths | Universal local tag/payload/header/counter identities | Reject unsupported instructions/undefined symbolic inputs; re-lift original spans and independently check concrete epochs; these are not whole-program reachability proofs |
| LT9 | The earlier daemon format remains a separate established contract | Four-byte versus ten-byte format comparison | Find actual producer/consumer call and buffer lineage; matching tag constants alone do not establish compatibility |

LT1-LT9 qualify the corresponding results throughout. Fresh replay shares the private engine with retained execution. Independent source-instruction lifting, compact packet construction and byte-epoch reconstruction test different properties without proving the engine's full correctness.

## Primary source and exact interfaces

| Source | Identity / coverage |
| --- | --- |
| Original KC | SHA-256 `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized FairPlayIOKit | SHA-256 `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| Current source | Ten original compiler envelopes, fifteen checked spans including four symbolic slices, one complete kernel copy envelope |
| Dispatch provenance | Four new exhaustive banks plus eighteen rechecked predecessor banks; eight original state slots and three additional bindings |
| Identity / preservation | [Fresh identity](triage_evidence/legacy_tlv_source_identity.json), [baseline preservation](triage_evidence/legacy_tlv_preservation.json), [scoped gates](triage_evidence/legacy_tlv_quality_gates.json) |

| Interface / site | Target / established role |
| --- | --- |
| `0xfffffe000a50c2b0` | Exact `_zzLw2eOVu9pOHqpiNw1K4ki`; outer `(X0,W1,X2)` / W0 interface |
| `0xfffffe000a50c4cc` | Call unnamed bridge `0xfffffe000a52fd18`, modifier `0x9d3a` |
| `0xfffffe000a5302ac` | Call unnamed operation entry `0xfffffe000a55e8b0`, modifier `0x1103` |
| `0xfffffe000a51a600` | Original payload-copy call, modifier `0x1103` |
| Table slot `0xfffffe0008471470` | Copy wrapper `0xfffffe000a508cf4` |
| Copy wrapper tail | Stub `0xfffffe000a69f334` |
| Stub slot `0xfffffe000847c4c8` | Kernel `0xfffffe000c647f10`; exact aliases `_memcpy` and `_memmove` |
| `0xfffffe000a5355f8` | Shared source store to inner record Q+`0x10` |
| `0xfffffe000a5302b4` | Source status copy to outer record P+`0x10` |

Names are exact-address matches; unnamed entries remain unnamed. The import stub is retained as a checked 16-byte span; no complete compiler envelope is inferred beyond the last available function-start entry. Shared fragments reside in several compiler envelopes, so enclosing compiler bounds do not establish source-level ownership or a single frame for every physical neighbor.

## Carrier admission and source order

The following field names describe observed uses; the native structure/type name is unknown.

| Carrier offset | Width, bytes | Observed role in this context |
| --- | ---: | --- |
| `+0x00` | 4 | Header word must equal 1 |
| `+0x08` | 4 | Upper bound on entry count |
| `+0x0c` | 4 | Upper bound used by byte-capacity comparison |
| `+0x90` | 8 | Output-buffer pointer, required nonnull |
| `+0x98` | 4 | Entry count, checked then incremented by 1 |
| `+0x9c` | 4 | Byte cursor, advanced by four header bytes and eight payload bytes |

The last accessed word ends at `+0xa0`, giving a 160-byte minimum accessed prefix. This does not identify the carrier with the earlier AES carrier or any other object sharing a numeric field offset.

| Admission stage | Source fragment / dispatch | Failure destination |
| --- | --- | --- |
| Carrier nonnull | Entry `0xfffffe000a55e8b0`; dispatch `0xfffffe000a55ea84` | State `0x224` -> shared return |
| Inner data pointer and carrier buffer pointer nonnull | `0xfffffe000a55fba0` | State `0x2bf` -> shared return |
| Header word == 1 | `0xfffffe000a588840` | State `0x53f` -> shared return |
| Unsigned entry_count < entry_limit | `0xfffffe000a54f6c4` | State `0x224` -> shared return |
| Unsigned u32(byte_cursor+12) <= byte_limit | `0xfffffe000a58ffa4` | State `0x53f` -> shared return |
| Accepted append | State `0x549` -> `0xfffffe000a51a45c` | Source header/copy/count updates |

The outer bridge always supplies a nonnull pointer to its source-initialized eight-byte local payload. Null value64 therefore represents eight zero bytes rather than a null payload pointer.

All rejection cases return before buffer/carrier writes. Global obfuscation state and private frames still receive their original source writes. Passing the capacity comparison alone is not a proof of nonwrapping cursor arithmetic or valid native buffer extent; LT3-LT5 retain those requirements explicitly.

## Compact record, staging and result

The bridge and operation entry use different source expressions for an identical u32 address key K(Q). For q=low32(Q), the retained formulas are:

```text
KG = ((((0xc5fb06fa OR (q << 1)) - q + 0x1d027c83)
       XOR 0xac756b1b) * 0xcfc386d7) mod 2^32
KD = ((((2*(q AND 0xbf13e450) - q + 0x40ec1baf)
       XOR 0x0e64f3c9) * 0xcfc386d7) mod 2^32)
KG == KD
```

| Inner record Q field | Source-established value / decoding |
| --- | --- |
| `+0x00`, pointer | Q-8, pointing to eight fully source-written payload bytes |
| `+0x08`, u16 | `low16(0x6609-KG)`; decoded with KD-`0x6601` -> 8 |
| `+0x0a`, u16 | `low16((tag16 XOR 0x8151)+KG)` |
| `+0x0c`, u32 | `0x224 XOR KG`; decoded with KD -> `0x224` |
| `+0x10`, u32 | Source-written operation status |
| `+0x18`, pointer | Original outer carrier X0 |

The 152-instruction payload-staging slice follows the previously observed affine intermediate and recovers **BE64(original X2)**. The offset at that intermediate does not change the final staged value. A separate 42-instruction low16 slice recovers the outer tag. A source-derived 86-instruction header lift proves the four output bytes and their cursor-relative positions; a five-instruction tail proves the counter updates. Total lifted instructions: 285.

For nonwrapping, nonoverlapping valid fixture positions, the compact local behavior is:

```text
if carrier == NULL: reject
if carrier.buffer == NULL: reject
if carrier.header != 1: reject
if u32(carrier.entry_count) >= u32(carrier.entry_limit): reject
if u32(carrier.byte_cursor + 12) > u32(carrier.byte_limit): reject

buffer[cursor : cursor+12] = BE16(low16(tag32)) || BE16(8) || BE64(value64)
carrier.entry_count = u32(carrier.entry_count + 1)
carrier.byte_cursor = u32(carrier.byte_cursor + 12)
return 0

reject: return 0xffff5966
```

The actual source computes u32 indices and a u32 capacity sum. The contiguous-slice notation uses LT4-LT5 and does not erase those fixed-width operations.

Header stores occur at `0xfffffe000a51a4bc`, `...a51a4c4`, `...a51a598` and `...a51a5a4`. The byte cursor is stored after each two-byte header pair. The copy at `0xfffffe000a51a600` receives `(X0=buffer+old_cursor+4, X1=Q-8, X2=8)` in the nonwrapping fixtures. Original kernel copy instructions transfer those eight source-written bytes. At `0xfffffe000a51a614`, source stores entry_count+1 and old_cursor+12 after copy completion.

The shared epilogue writes `0x5e561849` on this append path or `0x5e5571af` on these rejection paths. Original bridge code forwards that memory status; the named wrapper adds `0xa1a9e7b7` modulo `2^32`. The respective sums are 0 and `0xffff5966`. No errno/domain name is assigned to the latter value, and incidental X0 from an inner call is not the status carrier.

## Comparison with the daemon format

| Property | Current kext append context | Previously established daemon reply parser |
| --- | --- | --- |
| Header size | 4 bytes | 10 bytes |
| Leading fields | u16 tag, u16 length | u32 raw key, u16 wire tag, u32 length |
| Scalar payload here | 8 bytes, big-endian | Tag-dependent 4-/8-byte scalar or span |
| Native producer-consumer link | Unknown | Separate parser contract |

The daemon format is documented in the [interface ABI report](interface_abi_report.md), with its earlier source/table readback. The current fixtures include numeric tags also seen there, but that does not connect the formats or establish compatible emitted requests. A buffer/call lineage is required.

## Verification, bounded continuation and quality gates

| Fresh check | Coverage |
| --- | ---: |
| Complete source-only private cases | 312 |
| Appends / rejections | 192 / 120 |
| Source visits / instruction bytes rechecked | 246972 / 987888 |
| Read epochs / source-write epochs | 36984 / 14904 |
| Source-staged payload bytes summed over cases | 2496 |
| Source-written appended bytes | 2304 |
| Original kernel-copy bytes | 1536 |
| Exhaustive bank inputs | 5632 across 22 rules |
| Source-derived local proofs | 6 |

Rejections cover 12 null-carrier, 12 null-buffer, 36 bad-header, 24 entry-limit and 36 byte-capacity cases. Successful cases vary eight tag fixtures, four full64 payload fixtures, original/zero/declared-noise globals and two aligned placements. One tag fixture includes nonzero high16 input bits. Cursor/count placements vary within independently mapped buffers. Every successful case preserves buffer bytes outside its 12-byte append and carrier bytes outside the two count words.

Fresh verification compares whole retained/fresh executions, reconstructs every source read/write epoch and record snapshot, checks source-written payload provenance, follows every dispatch, and independently constructs the compact packet and admission result. No API effect-model provenance occurs. The six original SMT formulas and normalized counterparts are retained; fresh verification re-lifts original spans, solves the newly derived formulas, checks equivalence to retained originals and solves both representations. The proofs establish local key/selector/length/tag/payload/header/counter identities; they do not establish native object validity, concurrency or external request acceptance.

Time/retained space is `O(B+C*(V+E)+256R+I)` for pinned bytes B, cases C, visits V, events E, bank rules R and lifted instructions I, plus solver-dependent cost. Source runs are bounded at 30000 visits and each solver query at 30000 ms. Widths and offsets are bytes or unsigned fixed-width integers; the timeout is 30 s.

```sh
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_legacy_tlv.py
```

| Impact | Remaining question | Discriminating evidence |
| --- | --- | --- |
| High | Who constructs this carrier and invokes the named append wrapper? | Recover actual caller records, field initialization, buffer allocation and lifetime |
| High | How does this compact format reach a consumer or IPC boundary? | Follow source buffer/cursor lineage to serialization/emission/receiver code; retain the four-/ten-byte distinction |
| High | Which runtime invariants constrain byte-cursor arithmetic and aliasing? | Establish constructor/caller ranges and actual buffer ownership; local u32 guards alone are insufficient |
| Medium | Which additional payload widths use the shared inner operation? | Resolve their verified record codecs and operation/length fields without generalizing from the fixed eight-byte context |
| Medium | Does the unresolved allocator store populate FairPlay cached RW cell `0xfffffe000ccceab8`? | Establish original X20 reaching definitions and dispatcher/frame state; this increment adds no such publication proof |

QG1 passes for factual technical analysis. QG2 is LT1-LT9 with dependencies and falsification probes. QG3 passes for the current append/admission/format/copy/status interface; the broader goal remains incomplete. QG4 covers unsigned widths, byte epochs, bounds, units and complexity. QG5 separates fixed-wrapper/generic-entry roles, four-/ten-byte formats, private/native effects and safe-fixture/wrapping arithmetic. QG6 uses rechecked primary bytes/metadata, exhaustive banks, 312 fresh source compositions and six source-derived proofs. QG7 is the impact-labeled continuation table. Original inputs, IDBs, external `dump.md` and published predecessor evidence remain preserved.
