# Compact span/u32 fields and complete provider request prefixes

The two remaining request-field helpers append to the same compact stream as the [64-bit appender](legacy_tlv_report.md). `_JmmzRQjC7QF6ZQbBA` copies a span after a four-byte big-endian tag/length header. `_Hpu7ZBOFQYIwvPDYn9` stages a big-endian u32, then uses that same generic insertion path. The four [source-constructed provider requests](lskd_request_report.md) now reach their execution-call boundaries with complete source-written field streams.

The pointer-valued span fields contain **raw little-endian pointer representations** in this arm64e build. Context64 and scalar32 use big-endian value encodings. This establishes an internal memory format and source request preparation; native ownership, interpretation of pointer referents, execution and Mach transport remain **unknown**. No cryptographic/provider operation executes.

[Primary contracts](triage_evidence/lskd_fields_contracts.json), [retained source runs](triage_evidence/lskd_fields_profiles.json), [distinct fresh replays](triage_evidence/lskd_fields_replays.json), [independent checks](triage_evidence/lskd_fields_checks.json), [eight source-derived proof pairs](triage_evidence/lskd_fields_proofs.json), [source identity](triage_evidence/lskd_fields_source_identity.json), [preservation](triage_evidence/lskd_fields_preservation.json) and [scoped quality gates](triage_evidence/lskd_fields_quality_gates.json) retain the evidence. The broad objective remains active and incomplete.

```text
provider -> original constructor -> source-published request pointer
         -> context64: header(BE16 tag, BE16 8) + BE64(context)
         -> span:      header(BE16 tag, BE16 n) + original source bytes
            or u32:   header(BE16 tag, BE16 4) + BE32(value)
         -> source count/cursor updates
         -> STOP before _TdtbU9WbbSyE1sdsj
```

## Assumption register

| ID | Assumption / bound | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| LF1 | Original KC and normalized image are the pinned build | Instructions, symbols, slots and census | Rehash both; compare exact envelopes/spans and original chain membership; native runtime identity is separate |
| LF2 | Guarded private storage and abstracted PAC support conditional instruction execution | All replay results | Reject unmodeled calls, unknown private reads and source escapes; compare each visited instruction; native PAC/reachability remain unproved |
| LF3 | Provider typed allocation returns the declared object, clobbers caller-saved registers, and constructor records satisfy inherited LR4 alignment | 48 constructor/provider compositions | Validate actual allocator/view state separately; all 48 captured constructor records are at offset8 modulo16; model writes no memory; standalone fields use storage fixtures |
| LF4 | Declared carrier, buffer and source extents are accessible and distinct | Copies, snapshots and compact expected streams | Recover native capacities, ownership and aliases; private mapped extents are not native validity evidence |
| LF5 | Symbolic cells are distinct and shared key lemmas precede decoded-field claims | Eight compositional local proofs | Re-lift source, check each original/normalized formula and concrete record/byte epochs; arbitrary aliases and whole-program equivalence are excluded |
| LF6 | Mutable-global fixtures have no concurrent modification | Protected dispatch and source status flow | Recheck original/zero/noise fixtures and all byte inputs of retained rules; native synchronization remains separate |
| LF7 | Standalone cases use safe nonwrapping buffer offsets; arithmetic identities are fixed-width | Capacity/counter expectations | Recover actual producer cursor bounds separately; modulo-u32 identities do not prove allocation safety |
| LF8 | Four valid provider prefixes stop before execution with the declared parameter fixtures | Complete prepared streams and pointer lineage | Continue actual execution/response/cleanup interfaces; no policy, cryptographic or acceptance result follows |
| LF9 | Caller census covers only aligned direct branches and exact aligned qwords in stated segments | Six span calls, one u32 call and metadata matches | Expand indirect/computed/biased references and other modules; additional R2nPsUOYx6h caller is static-only here |
| LF10 | Raw copied pointer bytes have this build's little-endian representation | Mixed-endian prepared streams | Inspect the actual eventual consumer and address-space contract; no external pointer transfer or referent layout is inferred |

LF1-LF10 qualify the corresponding results. Retained/fresh equality shares the engine. Compact packet construction, source-derived formulas and independent byte-epoch reconstruction test additional properties without proving the engine, heap model or native context.

## Primary source and exact helper ABIs

| Source item | Pinned identity / scope |
| --- | --- |
| Original KC SHA-256 | `d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe` |
| Normalized kext SHA-256 | `2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c` |
| New extraction | Three compiler envelopes, eight spans, twelve exhaustive bank rules, eight original bank-pointer roots |
| Span wrapper | Exact `_JmmzRQjC7QF6ZQbBA`, `0xfffffe000a50bdfc..0xfffffe000a50c048` |
| U32 wrapper | Exact `_Hpu7ZBOFQYIwvPDYn9`, `0xfffffe000a50df34..0xfffffe000a50e170` |
| U32 internal bridge | Unnamed `0xfffffe000a54daf8`; executable prefix through `0xfffffe000a54df90` |

The bridge compiler envelope extends to `0xfffffe000a54e220` and contains later shared chunks. The probe allows only its prefix ending at `0xfffffe000a54df90`; those later chunks never execute. Exact nlist equality supplies names; no nearest-symbol assignment is made.

| Helper | Entry ABI | Prepared generic record / result |
| --- | --- | --- |
| Span | X0=carrier, W1=tag32, X2=source pointer, W3=length32 | Tag16 and length16 are the low16 projections; successful bytes=`BE16(tag16) || BE16(length16) || source[0:length16]` |
| U32 | X0=carrier, W1=tag32, W2=value32 | Tag16 is the low16 projection; successful bytes=`BE16(tag16) || 00 04 || BE32(value32)` |

The span wrapper builds a partial 32-byte record directly and calls generic entry `0xfffffe000a55e8b0` at `0xfffffe000a50c00c`, modifier `0x1103`. U32 builds a partial 24-byte record and calls bridge `0xfffffe000a54daf8` at `0xfffffe000a50e134`, modifier `0x1322`. That bridge stages four payload bytes and a partial 32-byte generic record, calling the same generic entry at `0xfffffe000a54df54`, modifier `0x1103`.

| Generic record offset | Width, bytes | Recovered meaning |
| --- | ---: | --- |
| +0 | 8 | Payload/source pointer |
| +8 | 2 | Encoded length; `u16(field + key32 - 0x6601)` recovers length16 |
| +0xa | 2 | Encoded tag; `u16((field - key32) XOR 0x8151)` recovers tag16 |
| +0xc | 4 | Encoded selector; XOR key32 recovers `0x224` |
| +0x10 | 4 | Source-written status on return |
| +0x18 | 8 | Carrier pointer |

Padding/unwritten cells retain explicit unknown provenance. The generic source-key formula is `u32((u32(2*(r32 & 0xbf13e450) - r32 + 0x40ec1baf) XOR 0x0e64f3c9) * 0xcfc386d7)`. Key-source equalities and decoded fields are separate lemmas. These field-key proofs do not use the preceding constructor's alignment-qualified key identity; provider construction still inherits that constructor's assumptions.

## Admission, copies and status

The common path requires nonnull carrier, nonnull source pointer, nonnull carrier buffer pointer, carrier header word=1, entry_count<entry_limit and `u32(byte_cursor + 4 + length16) <= byte_limit`. Successful paths write the header, run the original kernel copy helper for length16 bytes, then advance entry count by1 and cursor by `4+length16`. The compact header proof covers all tag16/length16 values and modulo-u32 cursor arithmetic; successful concrete fixtures stay within declared extents.

The original copy chain remains call `0xfffffe000a51a600` -> wrapper `0xfffffe000a508cf4` -> stub `0xfffffe000a69f334` -> original slot `0xfffffe000847c4c8` -> exact `_memcpy` / `_memmove`, `0xfffffe000c647f10`. All copied source bytes and their source-written destination epochs are checked. No copy-memory effect is modeled.

Successful wrappers return0; the checked rejection classes return `0xffff5966`, with carrier/buffer fixture bytes unchanged. A nonnull source with length0 appends a four-byte header and advances the entry count. A null source with length0 is rejected. Lengths `0x10000` and `0x10001` narrow to0 and1; this is an ABI property, not a claim about native caller bounds. U32 ignores the high32 bits of an incoming X2 value. A raw span's contents receive no integer byte reversal.

## Complete requests from four actual providers

All rows include the first tag0x72/context64 record. Each appender receives the object pointer originally published into that provider's own source-zeroed stack slot. The execution call itself remains unexecuted.

| Provider / operation | Subsequent fields in source order | Entries / bytes used / reserved | Stopped execution call |
| --- | --- | --- | --- |
| `eJ7hqOh8Z` / 0x1b69 | None | 1 / 12 / 12 | `0xfffffe000a5058e0` |
| `KDGetReEncryptionVault` / 0x1b6b | Tag0x8b: LE64(original output-buffer pointer) | 2 / 24 / 24 | `0xfffffe000a505a2c` |
| `sxvHysrIgQq2V` / 0x1b6a | Tags0x6b,0x6c,0x89,0x8a: LE64(parameter+0, +0xa0, +0x60, +0xbc) respectively | 5 / 60 / 64 | `0xfffffe000a505c68` |
| `ZURJElCowjwysX` / 0x1b6c | Tag0x7e: BE32(word at parameter+0x10) | 2 / 20 / 20 | `0xfffffe000a505eb4` |

The AVD caller's original pointer setup is at `0xfffffe000a505af4..0xfffffe000a505b0c`. Its four span call sites are `0xfffffe000a505b90`, `0xfffffe000a505bc8`, `0xfffffe000a505c00` and `0xfffffe000a505c38`. These copy eight-byte stack pointer representations, not the contents of the referenced parameter regions. Original code still clears parameter+0xf0. Its 64-byte reserved capacity has four zero bytes after the 60-byte request. The eventual consumer's meanings for these subregions remain unknown.

At every execution boundary, X0 is the source-constructed request, X1 points to a source-zeroed response-reference slot, and all preceding field helpers returned0 in source. This establishes preparation and call ABI, not execution, response allocation, reference balance or native policy behavior. Operation codes and field tags are not established Mach message IDs. The four-byte compact header remains separate from the earlier ten-byte daemon reply format.

## Bounded caller census

Each target scan checks 422089 aligned text words; together they perform 844178 checks of the same segment for two targets. The source-identity artifact also retains the exact additional caller envelope and symbol.

| Target | Direct BL sites | Other exact aligned qword matches |
| --- | --- | --- |
| Span helper | `0xfffffe000a5056ac`, `0xfffffe000a5059fc`, `0xfffffe000a505b90`, `0xfffffe000a505bc8`, `0xfffffe000a505c00`, `0xfffffe000a505c38` | `0xfffffe000ce9c218`, linkedit metadata |
| U32 helper | `0xfffffe000a505e84` | `0xfffffe000ce9c2a8`, linkedit metadata |

The extra span site at `0xfffffe000a5056ac` belongs to exact `com_apple_driver_FairPlayIOKit::R2nPsUOYx6h`, entry `0xfffffe000a505638`. Its provider prefix is not replayed in this increment. Thus six direct call sites are identified, while current complete provider compositions cover five of those span sites and the sole direct u32 site. Metadata matches are not additional native function-pointer callers. Indirect/biased/computed references and other modules remain outside the census.

## Validation and continuation

Eight original/normalized SMT pairs prove span key agreement, span decoded fields, u32 outer-key agreement, u32 big-endian payload, u32 inner-key agreement, u32 tag/selector/length, variable four-byte headers and variable counter updates. The source lift covers 383 instruction instances; the same 20-instruction generic-key slice is lifted twice with distinct symbolic inputs. Proofs use explicit shared-key composition and fixed symbolic cells, not a monolithic native-memory model.

| Fresh evidence | Count |
| --- | ---: |
| Cases / source visits / instruction bytes | 336 / 280500 / 1122000 |
| Read / source-write epochs | 49128 / 21264 |
| Generic source records / original copy calls / copied payload bytes | 408 / 336 / 1830 |
| Standalone returns / successful appends / rejected cases | 288 / 216 / 72 |
| Nonnull zero-length / narrowed-length appends | 36 / 36 |
| Provider compositions / heap register-return models / pointer publications | 48 / 48 / 48 |
| Provider field appends / publication consumptions | 120 / 120 |
| Provider pointer representations / packet bytes | 60 / 1392 |
| Rechecked exhaustive rules / byte inputs | 54 / 13824 |

Original/zero/declared-noise globals, two aligned placements, tag narrowing, length narrowing, scalar32 boundaries and two provider contexts are checked. Standalone field runs use no API-effect model. Provider runs use only the declared typed-heap register model; source clearing, initialization, publication, scalar staging and copying execute as original instructions. No model writes memory. All completed field returns restore entry SP. No target/native/IPC/crypto or synchronization backend executes.

Complexity is `O(B+C*(V+E)+W+256R+I)` for source bytes B, cases C, visits V, events E, census-word checks W, exhaustive rule checks R and lifted instruction instances I, plus solver-dependent cost. Each guest run has a 30000-visit bound and each solver a 30 s timeout. Rule counts include predecessor rechecks, not54 distinct permutation families.

```sh
PYTHONPATH=triage_evidence:/opt/homebrew/Cellar/z3/5.3.1/lib/python3.15/site-packages \
Z3_LIBRARY_PATH=/tmp/rpc502-parser-z3-runtime \
/Users/___/Downloads/zut/.venv/bin/python -P triage_evidence/validate_lskd_fields.py
```

| Impact | Remaining interface question | Discriminating evidence |
| --- | --- | --- |
| High | How does execution consume this mixed-endian stream and its embedded pointer representations? | Follow actual request/execution-carrier and dispatcher lineages; identify address-space and ownership contracts |
| High | How does R2nPsUOYx6h prepare its variable-length input span? | Follow the exact additional caller through constructor, source append and execution boundary; keep accepted processing separate |
| High | Is any compact stream transported to the daemon or only consumed within kernel facilities? | Establish concrete emission/receiver or internal-consumer linkage; numeric tag matching is insufficient |
| Medium | Which producer invariants bound length16, entry counts, cursor arithmetic and aliases natively? | Actual caller bounds, native allocator/type-view lifecycle and serialization evidence |
| Medium | What completes dynamic construction and response cleanup? | Continue the stopped IOMallocData branch and exact execution/response/destructor interfaces |

QG1 passes for factual technical analysis. QG2 is LF1-LF10 with dependent claims and falsification probes. QG3 passes for span/u32 helpers, bounded census and four prepared provider requests; the broader objective remains incomplete. QG4 covers byte extents, bit widths, endian representation, modulo arithmetic, counts and bounded complexity. QG5 separates span/scalar encodings, null/non-null zero-length inputs, static/replayed callers, reserved/used bytes and private/native contexts. QG6 uses primary source bytes, exact symbols/chains, 336 fresh cases and eight source-derived proof pairs. QG7 is the impact-labeled continuation table. Original inputs, IDBs, external dump.md and published predecessors remain preserved.
