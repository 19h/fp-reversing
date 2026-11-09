# Digest routing, saved continuation, and buffered-update contracts

The source now supports compact routing predicates for two context-processing callers and a saved-continuation ABI at `0x100AEE3A4`. Under two specific caller modes, the callee normalizes its control state to internal phase `471C` and compares `W2 + (W10 & 63)` with 64. The original saved-continuation consumer and its encoded pointer diversity further constrain candidate caller modes. These are conditional source contracts; the identity-string path's missing native frame inputs, completed digest, 36-byte cache contents, and kext/transport linkage remain unknown. The full daemon/kext/deeper-interface investigation remains active.

This continues the [identity UTF-8/SHA-1 preparation report](daemon_identity_cache_report.md). It adds 15 source proof pairs, 128 isolated A64 fragment checks / 2,080 original instruction visits, seven current-IDB byte ranges / 548 bytes, and precise bounded censuses. It does not resume the stopped identity path by supplying a guessed pointer or control phase.

## Evidence and scope

| Evidence | Verified extent |
| --- | --- |
| Thin daemon | SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e` |
| Live IDB | `fairplayd`, target `6b117c693e3b`; seven original-byte ranges / 548 bytes and read-only xrefs |
| Original source | Eight selected spans and six complete byte-order candidate spans |
| Literal modifier census | Six `MOV X17,#A86E; BRAA ...,X17` pairs across original text |
| Routing enumeration | 65,536 low16 values per main route; 131,072 total |
| Source proofs | 15 original/simplified pairs; 30 SMT files; 144 lifted instructions |
| Isolated A64 verification | 128 persisted and freshly recomputed fragments; 400 reads / 544 writes |
| Continuation evidence | 13 original IA7315/ad0 slots; seven routing intersections; 448 low6-count checks |
| Retained counterexample | 48 earlier after-unlock edges select a different target despite the same A86E modifier |

[Contracts and original spans](triage_evidence/daemon_digest_routes_contracts.json), [source proofs](triage_evidence/daemon_digest_routes_proofs.json), [isolated A64 cases](triage_evidence/daemon_digest_routes_profiles.json), and [independent checks](triage_evidence/daemon_digest_routes_checks.json) contain the evidence. [Preservation](triage_evidence/daemon_digest_routes_preservation.json) and [delivery gates](triage_evidence/daemon_digest_routes_quality_gates.json) record final sealing. No IDB mutation, native API, target process, Mach/IOKit operation, or hardware PAC executes.

Addresses and offsets below are hexadecimal. F is the relevant outer SP; T=`0x101039EF0`; `u32`/`u64` arithmetic wraps modulo 2^32/2^64. Mathematical routing equivalences do not assert that every satisfying control word denotes a valid native frame or continuation cell.

## Entry target and exact routing predicates

Original slot `0x101071540` is T+8*6ECA and contains an authenticated chained rebase to `0x100AEE3A4`, IA diversity A86E, address diversity disabled. The current IDB reports that slot as the target's data xref. The literal-modifier census is a candidate search; a matching diversity alone does not identify a caller.

For the context-initializing caller at `0x100B5C580`, let P be incoming W9. Its source entry index reduces to:

```text
I_new = (P XOR 0x0C58) XOR (P + 0x5E8E)
I_new == 0x6ECA  <=>  (P AND 0x6292) == 0x0202
```

For the saved-context caller at `0x100BAE14C`:

```text
I_existing = (P + 0x6A4A) XOR P
I_existing == 0x6ECA  <=>  (P AND 0x6ECA) == 0x0240
```

Both equivalences are proved over every u32 P. The first admits 1,024 low16 values, or 2^26 u32 values; the second admits 128 low16 values, or 2^23 u32 values. These are exact counts of the algebraic predicates, not counts of native callers or executable continuations. In particular, high phase bits also affect the callee's signed table lookup.

| Literal branch site | Source-local condition for entry index 6ECA | Necessary root / cutpoint premise |
| --- | --- | --- |
| `0x100208F08` | W28=6ECA | X26=T after the unlock call |
| `0x100780830` | W11 XOR (X10!=0 ? 12 : 0)=6ECA | Saved table root at F+9D8 is T; prior byte-store owner valid |
| `0x100834F84` | W11 at `834E6C` equals `E9FE5904` | Saved root at F+9D8 is T; preceding source stores valid |
| `0x100A1E4E8` | W11 XOR (D4*(W13 AND 1))=6ECA | Cut at `A1E4C8`; saved root at F+9D8 is T |
| `0x100B5C61C` | `(P AND 6292)==0202` | X30=T; P is W9 at the context-initializing block |
| `0x100BAE17C` | `(P AND 6ECA)==0240` | X30=T; P is W9 at the saved-context block |

The census covers the literal MOV-immediate/BRAA construction only. It excludes neither register-loaded modifiers nor other constructions. Byte-order starts after preceding terminal instructions are not proven CFG entry boundaries. Upstream state and valid pointer owners remain separate prerequisites for every candidate.

The earlier clock corpus supplies a concrete limitation on this search method: all 48 retained visits to `0x100208F08` load slot `0x101071560` (index 6ECE), target `0x1002A78B8`. That slot also uses IA A86E. None of these visits selects `0x100AEE3A4`. The entry/alternate target fixups and ordered edges are independently rechecked. These conditional observations do not exclude a different native caller state.

## Argument and frame contracts

The context-initializing block uses a source cursor Q at F+3620. It reserves 128 bytes and sets C=F+39F0+Q. Its 100-byte context shares the encoded SHA-1 state layout recovered earlier.

| Source input / output | Exact source effect |
| --- | --- |
| F+2DF8, u64 | Loaded into X8; pointed input bytes are not read in the checked fragment |
| F+2B38, u64 | Loaded as a pointed record base O |
| O+E0, u32 | Loaded into W2, zero-extending into X2 |
| F+2D70, u64 | Copied to F+3648 |
| F+3640, u64 | Copied to F+35A8 |
| Q at F+3620 | Replaced by Q+128 modulo u64 |
| C=F+39F0+Q | Returned in X4 and saved to F+3388 |
| C+0x64 (100 bytes) | Saved to F+31C8 |
| C+40, u64 | Zero, covering both u32 counter words |
| C+48..C+58 | Five encoded state words: `93BC0EF6 1B34867E 6C43F109 E4CB7981 372BCC07` |
| C+5C / C+60, u32 | Output size20 / selector2 |

The 64-byte C+00..C+3F buffer is not initialized by this block. Its initialization must be established at later source writes. The isolated tests check the actual byte coverage and leave this buffer undefined in their ledgers.

The earlier [object initializer](daemon_object_initialization_report.md) stores 44 at a record's +E0 field. This caller reads +E0 from O loaded through F+2B38. The pointer identity between those records is unknown; the matching offset and value do not establish an object-to-digest data path.

The saved-context block instead loads X26 from F+2988, X4 from F+2A70, and W2 from F+2A68. It also reads W10 from `load64(F+2A60)+6C`. X8 remains an incoming value at this block. The +6C owner must not be assumed to be the 100-byte context; it lies beyond that extent, and its native type remains unknown.

At `0x100AEE3A4`, the callee captures a distinct continuation index P in W9:

| Callee destination | Stored value |
| --- | --- |
| F+2F48, u64 | `load64(T + 8*signed32(P))` |
| F+2B88, u64 | X4 |
| F+2C8C, u32 | Low32(X2) |
| F+3490, u64 | X8 |

The new symbolic address lift preserves SXTW for this load. Four isolated negative-index cases verify the actual signed address against original logical table bytes. The all-u32 proof remains conditional on the referenced table cell being valid; it does not establish valid native memory for arbitrary P.

The direct unsigned-immediate access census finds one store to F+2F48, at `0x100AEE3B0`, and one load, at `0x100BB2278`. The consumer loads X8, sets X17=7315, and branches through X8 at `0x100BB2280`. This supports a saved-continuation interface under preservation and same-frame premises. A complete continuous path from every candidate entry to that consumer is not established. Computed, paired, alias and overlapping accesses remain outside the direct-encoding census.

## Continuation constraints and buffered-update modes

Assume the original table cells retain their logical targets, the saved continuation is preserved in the same frame, and the path returns through BB2280. The encoded continuation slot must then carry IA diversity7315/ad0. There are 13 such original authenticated-rebase slots in the inspected image. Intersecting them with the two routing predicates gives these seven source-local candidates:

| Caller family | P | Original continuation slot | Target | Raw-count convention for every low6 counter value? |
| --- | --- | --- | --- | --- |
| Context-initializing | 032B | `10103B848` | `10094DEC4` | Yes |
| Context-initializing | 0362 | `10103BA00` | `100126FB8` | No |
| Context-initializing | 0367 | `10103BA28` | `10018B6D0` | No |
| Context-initializing | 036B | `10103BA48` | `10061AFE0` | No |
| Saved context | 0354 | `10103B990` | `10061B144` | No |
| Saved context | 0371 | `10103BA78` | `100BE25B8` | Yes |
| Saved context | 0375 | `10103BA98` | `1004818F8` | No |

The other candidates may use different argument representations or may be unreachable from these blocks; neither interpretation is established. They are not discarded as native-impossible. Pointer-authentication metadata is checked, but native signing, hardware authentication and table preservation are not proved.

For P=032B in the first caller, W12=P+5E8E=61B9. For P=0371 in the second caller, W12=P+5E48=61B9. The callee also supplies W13=-1A9D before the count fragment. Original instructions `AEE3C0..434` then reduce to:

```text
internal phase = 0x61B9 - 0x1A9D = 0x471C
S = (W2 + (W10 AND 63)) mod 2^32
```

Both identities are proved for every u32 W2 and W10 under W12=61B9 and the source-produced W13. The 64 low6 values were additionally checked for all seven continuation-compatible candidate modes. Only the two indicated modes give the raw-count convention across that domain. This is a source representation classification, not a proof that they are the native callers.

| Source count predicate | Selected index / slot | Original target / IA diversity |
| --- | --- | --- |
| Unsigned S < 64 | 624A / `10106B140` | `100BAA9D4` / 5DF8 |
| Unsigned S >= 64 | 61B9 / `10106ACB8` | `100BE3CE4` / 5DF8 |

The addition wraps modulo u32 before comparison. No native buffer-safety, overflow handling, or arbitrary-length processing conclusion follows from this local predicate. Internal phase471C is not assigned a Mach message or IOKit selector role.

```
B5C580, P=032B ---- initializes context ----+
                                          +-> AEE3A4 -> save table[P], context, word, input
BAE14C, P=0371 ---- loads saved arguments --+      |
                                                 +-> S<64: BAA9D4
                                                 `-> S>=64: BE3CE4

under saved-slot/frame preservation:
  BB2278 -> BB2280, IA7315 -> 94DEC4 or BE25B8 for the two raw-count modes

upstream native callers and identity-path frame continuity: unknown
```

## Bounded continuation questions and assumption register

| Impact | Next question | Required evidence |
| --- | --- | --- |
| High | Join an actual native caller mode | Recover the producer of P=032B/0371, table roots and saved input fields from a real predecessor |
| High | Resolve identity compression's frame gaps | Join its state to AEE3A4 or another actual producer; do not transplant the isolated fragment fixtures |
| High | Establish object/input ownership | Resolve F+2B38/F+2DF8 and the saved-context +6C owner before assigning field or input types |
| High | Complete cache-to-driver data flow | Continue actual digest sinks/cache writes and join a known Mach/IOKit emission and driver consumer |
| Medium | Verify the return invariant | Establish frame continuity, preserved F+2F48 and actual BB2280 reachability |
| Medium | Understand the other five continuation modes | Recover their argument encodings and predecessor predicates rather than excluding them by the raw-count convention |
| Low | Extend the bounded caller census | Include register-loaded modifiers and computed/paired/alias frame accesses |

| ID | Premise / dependent claims | Stress or falsification probe |
| --- | --- | --- |
| DR1 | Source/IDB identities / all source addresses | Rehash thin input; compare current bytes, original slots and xrefs |
| DR2 | T is the dispatch root / caller index-to-target claims | Recover actual root producer; another root invalidates these target identities |
| DR3 | P and other input registers are source-local symbols / routing predicates | All-u32 proofs, full low16 enumeration, explicit upstream-reachability gap |
| DR4 | Isolated fragment input owners are valid / A64 field checks | Defined-byte ledgers, two placements, three word values, no branch/API execution |
| DR5 | Cursor/frame arithmetic is meaningful / context placement | Source proof modulo u64; actual owner bounds, alignment and native frame remain prerequisites |
| DR6 | Encoded context fields identify the prior SHA-1 convention / context label | Compare exact five words, counters, size20 and selector2; no completed digest claim |
| DR7 | Callee table lookup uses signed32(P) / saved target | Explicit SXTW lift and four negative-index cases; invalid native cells remain excluded by premise |
| DR8 | Original continuation cells, same frame, preserved F+2F48, return at BB2280 / 13-slot filtering | Recover intervening control/memory effects and actual authentication; do not treat metadata as execution |
| DR9 | Raw-count convention is an additional representation premise / two selected modes | Check all 64 low6 values for all seven candidates and universal source identities for W12=61B9 |
| DR10 | Direct/literal censuses are bounded / candidate completeness | Search alternate modifier construction and alias/computed/paired/overlapping accesses |
| DR11 | +E0/+6C pointer identities are unknown / data-owner conclusions | Trace actual roots; do not equate fields by numeric offset alone |
| DR12 | Native caller, full digest/cache and transport remain open / architectural limits | Require continuous source/native caller evidence and actual emission/consumer linkage |

Use the pinned Python/Z3 environment recorded in the preceding report. Run `recover_daemon_digest_routes.py`, `prove_daemon_digest_routes.py`, `probe_daemon_digest_routes.py`, and `validate_daemon_digest_routes.py` in that order from `triage_evidence`. The A64 tests are isolated original-instruction fragments; they stop before branch dispatch and do not form a continuous native caller chain. Census/replay time is linear in inspected bytes/visits/effects plus the fixed enumeration domains; expression construction is linear in lifted instructions. SMT queries have a 30-second resource limit and no claimed polynomial bound.

QG1: factual technical scope. QG2: DR1-DR12 and probes. QG3: this increment is covered; the full objective is incomplete. QG4: signed/unsigned widths, modulo arithmetic, context extents and predicate counts are explicit. QG5: routing, continuation compatibility, raw-count convention, isolated execution and native reachability are separated. QG6: original source/fixups, live IDB, source proofs, fresh A64 fragments and independent byte ledgers support the scoped claims. QG7: impact-bounded continuation table supplied.
