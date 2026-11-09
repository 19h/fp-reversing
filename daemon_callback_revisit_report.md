# Daemon callback revisit, byte emission and context transform

The former unknown read at `0x1003ECB98` is a copy boundary. Retaining arbitrary byte identities permits a further 160,048 original-instruction visits, through two byte-output calls and an address/self-text-bound context transform, to the known rwlock creator at `0x100492644 -> 0x10043A240`. This increment establishes internal contracts and a new arena-resident lock destination. No additional Mach or IOKit emission occurs in this inspected continuation. The full investigation remains active.

Evidence is conditional on the retained reference input state and the logical pointer-authentication abstraction [CR1-CR5]. Four independent A64 replays match 640,192 visits, including 704 copied unknown-byte effects. Thirteen source-local proof pairs are unsatisfiable; 33 isolated context-codec cases, 64 isolated byte-reader cases and 3,008 isolated SIMD instruction cases pass. A further fresh 160,048-visit replay passes in the independent checker. These counts describe verification, not native execution.

Primary evidence: [snapshot](triage_evidence/daemon_callback_revisit_snapshot.json), [source journal](triage_evidence/daemon_callback_revisit_profiles.json), [original-source contracts](triage_evidence/daemon_callback_revisit_contracts.json), [source proofs](triage_evidence/daemon_callback_revisit_proofs.json), [four A64 replays](triage_evidence/daemon_callback_revisit_replays.json), [independent checks](triage_evidence/daemon_callback_revisit_checks.json), [SIMD checks](triage_evidence/daemon_callback_simd_checks.json), [compact context checks](triage_evidence/daemon_callback_payload_checks.json), [byte-reader checks](triage_evidence/daemon_callback_reader_checks.json), [preservation](triage_evidence/daemon_callback_revisit_preservation.json), [scoped gates](triage_evidence/daemon_callback_revisit_quality_gates.json). The earlier [global-state report](daemon_global_state_report.md), [state-generator report](daemon_prng_output_report.md), [lock creator report](daemon_rwlock_lifecycle_report.md) and [RAX trace report](zut_trace_report.md) retain their original evidence boundaries.

## Assumption register

| ID | Assumption / dependent result | Stress test or falsification probe |
|---|---|---|
| CR1 | Preferred-image addresses refer to the retained thin arm64e image, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. All address claims depend on this identity. | Rehash source; compare all 3,013 journal opcodes and 16 retained spans to original bytes. |
| CR2 | Entry is the sealed prior reference case17; earlier declared entropy/time/allocation inputs and the captured stack-canary fixture remain conditional. Continuation reachability depends on that state. | Capture replays the full sealed prefix and continuation, requires exact prior result, and hashes all 187 snapshot regions. Native input/state differences can select other paths. |
| CR3 | The private frame has `F=0x640000B520`; arena owner is `H=0x6500100000`, extent90,000 bytes. These are fixture addresses. | Check source-derived roots, owner masks, register state and all actual effective addresses; vary allocation/frame bases in a future composed run. |
| CR4 | Unknown backing bytes are unspecified values with retained origin aliases. The 112 inherited backing bytes do not become source definitions. | Independently vary physical backing with alias preservation in four replays; assert zero SSA arithmetic definitions and only integer/origin byte terms. |
| CR5 | BRAA/BLRAA, PACIBSP and authenticated returns are interpreted as logical control transfers. Native PAC success is unknown. | Check original opcode, call target, modifier and logical X30; native authentication requires a separate compatible runtime observation. |
| CR6 | The selected output-record caller supplies four-byte-aligned R; actual `R=F+0xAF8` is eight-byte-aligned. Caller-key agreement depends on alignment. | SMT caller identity explicitly requires `R & 3 == 0`; the decoder-key proof itself is unrestricted. Do not extend the caller theorem outside this premise. |
| CR7 | Two observed byte-output requests have decoded length4 and control0xB399. Other control modes and lengths are unknown. | Vary decoded length/control in a bounded source continuation; retain the tag-dependent progress condition and output bounds. |
| CR8 | The cached512-byte table and selected self-text window retain prior published values during these readers. | Check all continuation writes for overlap with the cached table: zero; verify each code read directly against original image bytes. |
| CR9 | The selected code address is `A=0x100822058`, mask0x7FFF; preferred-image self-text is readable. Native runtime modification/relocation effects are unknown. | Compare live mapped text and published encoded globals before composing native read results. |
| CR10 | SIMD proof uses the observed index-table and multiplier constants. Seed, vector input and position are arbitrary within the source-local identity. | Isolated original opcodes, arbitrary-bit SMT vector identity and varied complete2184-byte source runs independently test the model. |
| CR11 | The payload extent2184 bytes is the accessed transform extent, not a recovered native type size. | Trace adjacent metadata reads/writes and subsequent consumers; retain guard bytes in isolated codec fixtures. |
| CR12 | The frozen creator contract composes at decoded control0xAED7 with the new destination cell. Native allocation/init success is unknown. | Verify new caller record and target; then model both allocation/init outcomes before extending the journal. No creator/API executes here. |
| CR13 | Current scalar state-generator schedule is the already recovered full-twist-before-output schedule. | Recompute both624-word twists from captured state; compare all1,248 original state writes, selected words and final counters. |
| CR14 | No emission claim is restricted to this 160,048-visit continuation and its terminal pre-call boundary. | Inspect every source visit/call target; continuing beyond the creator or selecting another path can expose further interfaces. |
| CR15 | Live IDB verification is not refreshed in this increment. File evidence supplies the retained instructions and fixups. | Reconnect the correct IDB and compare original addresses/bytes; prior unavailable bridge probes remain in the preceding report. |

## Control and data sequence

```text
sealed pre-read state at 0x1003ECB98
  |
  +-- copy 48 arbitrary bytes; preserve origin identities
  +-- descending arena fills: 636 + 2268 byte writes
  +-- 0x100301504 -> 0x100ADD594 -> 0x100ACD9C4
  |     global state step / dynamic stack / twist / emit 4 encoded bytes
  +-- selected self-text: eight chained u32 reads
  +-- context: transform 2184 bytes, then 272 u64 swaps
  +-- 0x1003FAE4C -> 0x100ADD594 -> 0x100ACD9C4
  |     next state step / twist / emit 4 encoded bytes
  +-- pack creator record: control0xAED7, destination H+0x15B28
  +-- stop before 0x100492644 -> 0x10043A240
        known malloc(200) / pthread_rwlock_init contract
```

This sequence establishes a source-selected initialization path. It does not establish native startup completion, lock lifetime, concurrency guarantees, or a continuous path from the newly created lock to the IOKit entry [CR2,CR5,CR12].

## Unknown copies and arena fills

Six original u64 locations contribute48 unknown bytes: `F+0x468`, `+0x480`, `+0x4A0`, `+0x4A8`, `+0x4C0`, `+0x588`. The formerly terminal load is `LDR X9,[SP,#0x4A0]` at `0x1003ECB98`. These values remain literal origin-byte copies or truncations. No unknown enters arithmetic, effective-address generation, flags or branch selection in the committed journal [CR2-CR4]. This is a conditional noninterference result for these bytes, rather than a recovered producer for them.

| Fill writer | Writes | Half-open address range | Relation |
|---|---:|---|---|
| `0x1004C8398`, first invocation | 636 | `[0x6500115AD8,0x6500115D54)` | Descending addresses |
| `0x1004C8398`, second invocation | 2268 | `[0x650011522C,0x6500115B08)` | Descending addresses |

The ranges overlap48 bytes and cover2856 distinct bytes: `636+2268-48=2856`. The cached table begins at `0x6500115D6C`,24 bytes after the first range's end. No continuation write touches its512-byte extent. The fill's index is context-derived and increases while its write count decreases; a zero-based index is not assumed. The byte-fill recurrence has not been reduced to a generic semantic contract.

## Private stack-adjustment adapter

| Interface | Source | Recovered contract |
|---|---|---|
| Outer call | `0x100301504`, `0x1003FAE4C` | BLRAA to0x100ADD594, IA modifier0x22A0; X0=R, X1=in/out u64 stack-adjustment cell |
| Global state update | `0x100ADD6C0..0x100ADD6CC`, store0x100ADD728 | `C1=u64(C*0x2EC5+1)`, global0x1010B8D78 |
| Dynamic reserve | `0x100ADD72C..0x100ADD750` | `reserve=16*((C1>>60)+1)` bytes,16..256, in addition to64-byte fixed frame |
| Temporary cell | Same reserve block | At dynamic SP, store `u64(C-0xB0)` |
| Nested call | `0x100ADD7D4` | BLRAA to0x100ACD9C4, IA modifier0x7C25; forwards R and pointer to temporary cell |
| Nested bias restoration | `0x100ACDB14..0x100ACDB20` | Add0xB0 to the temporary state |
| Return channel | `0x100ADD7D8..0x100ADD7E8` | `deltaSP=((low32(*temp)-low32(C)) & 0xFFFF)<<4`, written as u64 through original X1 |
| Caller stack repair | `0x100301508..0x100301518`, second return0x1003FAE50 | Caller adds returned delta to SP |

Both observed deltas are zero. This cell is a stack-adjustment channel. The global arithmetic state, the decoded output control and the caller's phase word have separate roles [CR5-CR7].

| Invocation | C | C1 | Dynamic reserve | Caller adjustment cell |
|---|---|---|---:|---|
| First | `0xBAB0C03DC992AAB9` | `0x6C8F09C4788A9E5E` | 112 bytes | `F+0x650` |
| Second | `0x6C8F09C4788A9E5E` | `0x3DD3D1D9AB20C257` | 64 bytes | `F+0x648` |

The nested callee has a further816-byte fixed frame. PACIBSP/RETAB behavior is abstracted, not authenticated [CR5]. The original unauthenticated bind at0x1010B1E18 names `___stack_chk_guard`; captured RAM resolves that slot to fixture address0x6400001000 containing0xFEDCBA9876543210. Both source calls reload and compare this unchanged fixture at return. Original bind decoding and fixture RAM are separate evidence; the native guard address/value are unknown [CR2].

## Address-coded output record and state consumption

For `r=low32(R)`, all arithmetic below wraps at32 bits:

```text
K = u32((r XOR 0xEAAE0AC9) * 0x7398180B)
length = u16(raw_length - low16(K) - 0x153B)
control = u32(raw_control + K)
guard = (output_pointer != NULL) AND (length != 0)
```

The key source is `0x100ACDB20..0x100ACDB54`; fields and guard are decoded at `0x100ACDB54..0x100ACDB84`. Source-local proofs cover arbitrary input bits. Minimum accessed record extent is24 bytes; unread bytes are not assigned meanings [CR6,CR7].

| Offset | Width | Meaning |
|---|---:|---|
| R+0x00 | 8 bytes | Unread by this decoder |
| R+0x08 | 8 bytes | Output-buffer pointer |
| R+0x10 | 2 bytes | Encoded length |
| R+0x12 | 2 bytes | Unread |
| R+0x14 | 4 bytes | Encoded control |

Both invocations use `R=0x640000C018`, `K=0xC79E4EFB`, encoded length0x643A and encoded control0x3862649E, decoding to length4/control0xB399. The caller's0xB020 phase gains0x379 before encoding; it is not the decoded control.

| Call | Output pointer | Output bytes in increasing memory order | Selected state word | Tempered word |
|---|---|---|---|---|
| First | `F+0x5B4=0x640000BAD4` | `BE 38 73 3C` | index130,0x99821A72 | 0x9CD51D84 |
| Second | `F+0x608=0x640000BB28` | `3A 0E E2 CA` | index131,0x49A8DDEB | 0x15C5BD81 |

Each consumes a further complete624-word state twist, with indices/counters advancing130->131->132. All1,248 state writes match the independently computed recurrence. The generated u32 word supplies the byte-emission machinery; the output is additionally position/table/self-text dependent. No native entropy or statistical distribution claim follows [CR2,CR7,CR13].

## Cached-table and self-text readers

The prior globals now have observed readers:

| Global / data | Reader | Observed role |
|---|---|---|
| 0x1010C67D4, value255 | `0x100A0C9C0` | AND0x0BA3CCC8 selects table byte offset200 |
| 0x1010C8268, pointerD | `0x100A0C9C4`, table load0x100A0C9D8 | Read u32 from cached512-byte table atD+200 |
| 0x1010C6800, encoded window mask | `0x100A0C9F8` | XOR low32 constant0xA7A730EC; zero-extended u32 indices make effective mask0x7FFF |
| 0x1010CA2A8, encoded address | `0x100A0CA14` | XOR full64-bit constant0x12AF5504870A589F to obtainA |
| Self-text byte | `0x100A0CA30`, `0x100A0CA54` | Two bytes per output byte;16 observed byte reads |
| Self-text u32 | `0x100462674`, `684`, `694`, `6A4`, `6B4`, `6C4`, `6D4`, `6E4` | Eight chained u32 reads for context seed |

A scalar single-byte reader model is:

```text
position = output_base + remaining_index
T = u32(table_u32_at_D_plus_200 + low32(position))
i1 = u32(T + (P XOR 0x0BA37F51)) & 0x7FFF
i2 = u32(T + 0x0BA3CCCA) & 0x7FFF
tag = low8(B XOR u32(31*low32(position)) XOR text[i1] XOR text[i2])
output[position] = tag XOR low8(V) XOR 6
```

P, B and V denote the incoming W13, W14 and W11 of the retained reader block, not recovered high-level argument names. Original A64 tests cover64 varied combinations. Observed writes descend through each four-byte output at `0x100A0CA74`. Later progress depends on comparison with tag0xD7; complete termination and arbitrary-length behavior remain unknown [CR7].

The word reader begins with `t=0xF72A8FF6` and repeats eight times:

```text
t = u32(t XOR read_u32(A + (t & 0x7FFF)))
```

It yields `t=0x487B0E7B`. These reads can be unaligned. A read starting at the final three window bytes can extend at most3 bytes beyond its nominal32768-byte window; the preceding [section-window proof](daemon_global_state_report.md) supplies a16-byte section-end margin. Byte readers remain inside the nominal window. All24 observed reads match original image bytes [CR8,CR9].

## Compact context transform

The accessed payload begins at `Pctx=0x6500115274`, extent`0x888=2184` bytes, containing273 u64 words. At `0x100462810..0x100462818` the source combines the code fold and address:

```text
seed = u32(u32(low32(Pctx) * 0x41DA4F94) XOR t)
     = 0x4546796B       # retained context
```

The transform at `0x100462818..0x100462974` reduces to:

```text
for i in 0..2183:
    m = low8(seed XOR u32((i + seed) * (i - seed)))
    byte[i] = u8((byte[i] XOR m) * 0x93)
for i in 272 down to 1:
    j = u32((u32(seed + i) XOR seed) * 0x01000193) % i
    swap_u64(word[i], word[j])
```

The vector loop transforms2176 bytes in136 iterations of16 bytes; a four-byte tail loop covers8 bytes in two iterations. The source-local arbitrary-bit vector identity and the byte inverse `0x93 * 0x9B == 1 mod256` are proved. Inversion first applies the swaps in increasing i order, then multiplies each byte by0x9B and XORs the same mask. Both directions take O(n) time; the in-place algorithm needs O(1) auxiliary storage. The fixture uses O(n) storage for independent comparison.

The strict `j<i` bound excludes same-address XOR swaps. In reverse order, each transposition inserts one new index into the existing cycle; induction and inversion give one273-word cycle. All33 isolated seeds/input patterns match original A64 outputs, inverse recovery and cycle length. This establishes reversible encoding/permutation for the fixed extent and observed constants. Cryptographic strength, native structure type and downstream meaning are unknown [CR9-CR11].

AdvSIMD semantics are independently checked on70 original source opcodes. USHL coverage includes all256 signed least-significant-byte shift counts with three different upper24-bit patterns; this matches the primary [Arm instruction-set reference, D6.271](https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab). Complete transform tests additionally check untouched16-byte guards on both sides.

## New lock-creation destination

| Item | Value / source |
|---|---|
| Record address | R=0x640000C018 |
| Destination field store | `0x1004925CC`, R+8, value0x6500115B28 |
| Raw control store | `0x1004925E4`, R, u32 value0x31C22EDC |
| Creator key | `low32(R) XOR 0xDC40790B = 0xDC40B913` |
| Decoded control | `u32(raw + key*0x5973A279) = 0xAED7` |
| Selected call | `0x100492644`, BLRAA modifier0x8C6D ->0x10043A240 |
| Destination ownership | H+0x15B28, inside the90,000-byte arena and first fill range |

The [frozen creator contract](daemon_rwlock_lifecycle_report.md) allocates200 bytes, clears the first8 bytes, calls `pthread_rwlock_init(pointer,NULL)`, and publishes the pointer through the supplied destination only on initialization return0. This new call supplies an arena cell; earlier calls supplied global cells0x1010C8240 and0x1010C5748. The current run stops before entering the creator. Lock allocation/init outcomes, destination lifetime, object owner/type, and later acquisition/reclamation are unknown [CR12].

## Bounded continuation opportunities

| Impact | Bounded next investigation | Evidence gained / remaining falsification |
|---|---|---|
| High | Compose frozen creator success, allocation-failure and init-failure contracts at the new arena destination. | Establish subsequent pointer/status consumers; check whether publication is required before later transport. |
| High | Follow the two generated four-byte output buffers into later state fields/requests. | Determine whether these bytes influence IPC control, payload, synchronization or only internal context encoding. |
| High | Follow the transformed2184-byte payload and its adjacent metadata to their first external interface. | Connect source-recovered context semantics to the daemon/kext ABI; present transport linkage is unknown. |
| Medium | Recover general byte-output mode/length progression including tag0xD7. | Determine complete output bounds/termination and partial-word state scheduling. |
| Medium | Vary retained API inputs, owner addresses and self-text selection. | Distinguish address dependence from invariant behavior; reference-path coverage alone cannot establish all startup paths. |
| Medium | Recover producers of the48 retained arbitrary bytes and readers of the new lock cell. | Replace copy-only provenance with producer/lifetime evidence; current noninterference does not supply field meanings. |
| Low | Reduce the descending-fill arithmetic and audit other self-text-reader sites. | Broaden semantic naming beyond the two actual readers. No cross-component mechanism identity is established. |

## Scoped quality gates

| Gate | Result and evidence |
|---|---|
| QG1 | Pass: factual interface and binary analysis. |
| QG2 | Pass: CR1-CR15 give dependencies and falsification probes. |
| QG3 | Pass for this increment: unknown copies, internal ABI, state consumption, table/code readers, payload transform and creator destination covered; full objective active. |
| QG4 | Pass: u8/u16/u32/u64 wrapping, half-open byte ranges, stack-byte units,2184=273*8,136*16+2*4=2184, and636+2268-48=2856 explicit. |
| QG5 | Pass within scope: eight word reads distinguished from16 byte reads, stack adjustment distinguished from decoded control, cached-table non-overlap checked, nominal-window versus section margin distinguished, native effects unknown. |
| QG6 | Pass within scope: original image/opcodes/fixup bits,13 source proof pairs, four A64 continuations, SIMD/reader/codec fixtures and fresh independent replay. Live IDB/native execution unavailable for these claims. |
| QG7 | Pass: impact-labeled bounded continuation table; no claim of full investigation completion. |

The [independent checker](triage_evidence/validate_daemon_callback_revisit.py) rehashes dependencies and source bytes, rechecks all26 SMT files, recomputes state/reader/record values and performs fresh source replays. The preservation checker retains3179 of3185 prior artifacts exactly; only the five aggregate/status reports and manifest publisher change. Original three supplied inputs and the thin source remain unchanged.
