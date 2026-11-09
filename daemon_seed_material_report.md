# Daemon seed material, state mixing, comparison ABI, and first twist interface

The recovered source combines **three entropy returns, low32 wall-clock seconds, microseconds, and low32 of an arena-interior pointer** into the 624-word global state at `0x1010C784C`. It performs 624 first-pass updates, 623 second-pass updates, and forces word 0 to `0x80000000`. The mutable four-word material returns to its original encoding after the first pass. The whole continuation stops before an input-dependent table read at `0x10035C6F8`; the following update is separately proved statically.

The complete leaf at `0x100427514` selects signed or unsigned u64 less-than from an address-coded private record. Its minimum accessed footprint is 36 bytes; that is not an established C object size or wire layout. No new Mach/IOKit emission or right transfer is established. Downstream generator consumers and their IPC dependencies remain unknown. The full investigation remains active.

## Provenance and assumption register

Primary image: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are preferred virtual addresses. [Contracts](triage_evidence/daemon_seed_material_contracts.json) retain 16 source spans, 39 original fixups, four exhaustive byte banks, installed SDK documentation, 551 matching live-IDB rows, and four decoded context summaries. The IDB views cover 419 of the 1,235 new path-pool instruction rows; all pool bytes are checked against the original image, and replay checks every executed instruction byte. The earlier [entropy-return](daemon_entropy_return_report.md) and [context-transfer](daemon_context_transfer_report.md) artifacts remain frozen.

| ID | Assumption or evidence boundary | Dependent result | Stress test / falsification probe |
| --- | --- | --- | --- |
| SM1 | The pinned daemon is the intended specimen | PCs, fields, routines | Rehash bytes and compare explicit live-IDB target; native daemon/kext version pairing remains unknown |
| SM2 | Four sealed incoming states and their startup/global-word premises apply | Whole continuations | Replay full prefixes; investigate nonzero `0x1010C8258` and other native writers separately |
| SM3 | Declared frame and 90,000-byte arena owners are valid, disjoint and mapped | Memory interfaces | Check all effective addresses/widths; retain exact F/H placements |
| SM4 | Entropy returns are arbitrary u32 inputs with unknown distribution | Seed equations | Symbolic roots plus four finite input tuples; arbitrary upper X0 bits |
| SM5 | Time output/status roots are independent declared inputs for source sensitivity analysis | Clock/status data flow | Separate success-output cases from the counterfactual -1/status-output case; no native failure-output guarantee follows |
| SM6 | API preservation of SP, X18-X29 and D8-D15 low halves applies | Register continuity | Arbitrary caller-saved GPR/vector/NZCV values; verify preservation around all four summaries |
| SM7 | API summaries write only the declared caller-output bytes | Memory provenance | Define exactly sec64/usec32; leave padding unknown; library/errno side effects are outside the model |
| SM8 | Selected A64 and bit-vector semantics are adequate | Source contracts | Independent instruction/effect replay, 27 proof pairs, register-shift masking, fail-closed unsupported operations |
| SM9 | Caller record normalization uses an 8-byte-aligned R | Caller/callee key agreement | A source-derived 4-byte-aligned counterexample breaks the normalization; no native unaligned record is observed |
| SM10 | Original fixups supply abstract decoded targets | Dispatch identity | Verify original format12 words, imports, diversity and all 256 inputs per bank; native PAC remains unknown |
| SM11 | The four representations bound whole-path reachability coverage | Counts and complete-state results | Compare both F/H placements; arbitrary native slide, scheduling and address placement are not proved |
| SM12 | A no-output time failure is a hypothesis | Unknown-input reader experiment | Return -1 without output writes, retain byte origins, and stop before their first arithmetic transform; actual failure behavior remains unknown |
| SM13 | The twist slice receives the correct carried current word and its initialized two-entry table | Static next-update rule | Prove both candidate addresses and the source table literal; the post-lookup slice is unexecuted in the whole-prefix replays |
| SM14 | Prior owned artifacts are frozen except the six aggregate reporting/publisher paths | Preservation | Verify the 2,939-entry prior manifest, exactly six changes, and all three original inputs |

Whole-path statements depend on SM1-SM11. The failure experiment additionally depends on SM12; the static continuation depends on SM13. A source-local universal lemma does not establish arbitrary native reachability.

## Recovered data flow

```text
entropy E1 ----------------> initial 624-word expansion
                                      |
E3, microseconds, low32(seconds), E2 -> key[4]
                                      ^
                        low32(arena-interior pointer)
                                      |
                         mix 624 + mix 623
                                      |
                      state[0] = 0x80000000
                                      |
                    first twist table read [stopped]
                                      |
                     later consumers / IPC: unknown
```

All word operations below use u32 modulo 2^32. Pointer and address codecs use u64 modulo 2^64. Time seconds are signed64 SDK storage consumed as raw low32 bits; microseconds are consumed as raw u32 bits. Units are seconds and microseconds, with `1 us = 10^-6 s`. The numerical cases are declared outputs, not observed wall-clock samples.

## 32-byte frame reservation and external-call ABI

Source `0x1002DC094..0x1002DC0AC` reads frame cursor O at F+`0x5C0`, saves Q=`F+0x660+O` at F+`0x580` and F+`0x498`, and advances O by 32 bytes. In all four incoming contexts O=16, so Q=F+`0x670`. The source reserves adjacent material and time-output regions:

| Q-relative offset | Extent | Meaning and producer |
| --- | --- | --- |
| +`0x00` | 4 bytes | E3 XOR `0x5CF7672B`, store `0x1002DC414` |
| +`0x04` | 4 bytes | u32 microseconds XOR the same constant, store `0x1002DC350` |
| +`0x08` | 4 bytes | low32 seconds XOR the same constant, store `0x1002DC330` |
| +`0x0C` | 4 bytes | E2 XOR the same constant, store `0x1002DC3B0` |
| +`0x10` | 8 bytes | Declared `timeval.tv_sec` output |
| +`0x18` | 4 bytes | Declared `timeval.tv_usec` output |
| +`0x1C` | 4 bytes | Padding remains unknown and unread through the frontier |

| Call site | Interface | Scope |
| --- | --- | --- |
| `0x100409574` | `arc4random() -> E1:u32` | Sealed preceding increment |
| `0x1002DC308` | `gettimeofday(Q+0x10,NULL)` | Declared sec64/usec32 writes; integer status independent in the sensitivity model |
| `0x1002DC3A0` | `arc4random() -> E2:u32` | Zero arguments |
| `0x1002DC400` | `arc4random() -> E3:u32` | Zero arguments |

Both later entropy sites select original slot `0x1010A0050`, `_arc4random` from `/usr/lib/libSystem.B.dylib`, authenticated IA diversity `0x2692`, address diversity 0 and total addend 0. Four exhaustive byte-bank contracts cover 1,024 input bytes in total, including both entropy selections and comparison-helper selections. Untouched argument registers beyond each API's arity have no established argument role.

The installed primary `gettimeofday(2)` documentation specifies return 0 for success and -1 for error with errno. It does not establish that a failing call leaves every output byte unchanged. The source reads the seconds word immediately after the call; the 37-instruction continuation to the next entropy site does not read or write X0/W0. Library/errno side effects are not modeled.

## Complete private less-than leaf

Analysis label: `compare_select_less_record`; no IDB symbol is changed. The 40-instruction leaf `0x100427514..0x1004275B0` has no calls or stack frame, preserves X0=R, and writes only the u32 at R+`0x0C`. It modifies scratch registers and NZCV. Define:

```text
K = u64((R XOR 0x0179FA0FE732D262) * 0xBA209EF7)
k = low32(K)
```

| Offset | Width | Decoded field |
| --- | --- | --- |
| +`0x00` | u64 | A = raw + K |
| +`0x08` | u32 | mode = raw XOR k; only bit 0 is tested |
| +`0x0C` | u32 | Output |
| +`0x10` | u32 | true_choice = raw XOR k |
| +`0x14` | u32 | false_choice = raw + k |
| +`0x18` | u64 | B = raw XOR K |
| +`0x20` | u32 | mask = raw XOR k |

```text
choose = (mode & 1) ? signed64(A) < signed64(B) : unsigned64(A) < unsigned64(B)
output = mask XOR (choose ? true_choice : false_choice)
```

The accessed range ends at R+`0x23`: 36 bytes. The caller also writes a word at +`0x24`, which this complete leaf does not read. A native C structure size, tail padding, and broader reserved-object extent are not inferred from the 36-byte footprint. The frame reuses the earlier private record area at R=F+`0xAF8`.

The helper prekey identity holds for every u64 R. The caller's earlier producer at `0x10032CA54..0x10032CA94` agrees under 8-byte alignment. The multiplier inverse is `0x101B14BF85AD82C7`. A SAT counterexample at R=`0x640000BF1C` distinguishes actual caller prekey `0x0179FA6BE7326D7A` from the aligned8 identity `0x0179FA6BE7326D7E`; that point is outside the caller proof domain.

All three recovered callers use mode 0 and slot `0x10109FF38` -> `0x100427514`, IA diversity `0x46A2`:

| Caller | Calls per context | Predicate over the selected counters | Result index |
| --- | --- | --- | --- |
| `0x1002FBC28` | 624 | Always false over its decoded A/B range | `0x16A4` |
| `0x100317E6C` | 624 | `3 < j+1`, true 156 times | true `0x17B1`, false `0x17C3` |
| `0x1003069D0` | 623 | Always false over its decoded A/B range | `0x1627` |

| Index | Original slot | Decoded target | IA diversity |
| --- | --- | --- | --- |
| `0x16A4` | `0x101045410` | `0x10031D914` | `0x2466` |
| `0x17B1` | `0x101045C78` | `0x10038EC80` | `0xD245` |
| `0x17C3` | `0x101045D08` | `0x100288A94` | `0xD245` |
| `0x1627` | `0x101045028` | `0x10049D6BC` | `0xEA71` |

These are internal control selectors. The signed comparison mode is established from complete leaf source and universal proofs; it is not exercised by these three callers.

## Complete mixed-state semantics and allocator dependence

Let P be the u64 read from F+`0x358`, and d=low32(P). P lies inside the declared arena owner H in all four contexts. Its broader allocator/cursor role is unknown; the proof uses the actual source pointer and byte ownership.

| Context | F | H | P |
| --- | --- | --- | --- |
| 0 | `0x640000B420` | `0x6500000000` | `0x6500015D34` |
| 1 | `0x640000B420` | `0x6500100000` | `0x6500115D34` |
| 16 | `0x640000B520` | `0x6500000000` | `0x6500015D14` |
| 17 | `0x640000B520` | `0x6500100000` | `0x6500115D14` |

The compact model below uses decoded key words. Actual frame words are XOR-encoded by `0x5CF7672B`; XOR mutation commutes with that fixed encoding.

```c
mt[0] = E1;
for (i = 1; i < 624; ++i)
    mt[i] = 1812433253u * (mt[i-1] ^ (mt[i-1] >> 30)) + i;

key[0] = E3; key[1] = microseconds;
key[2] = low32(seconds); key[3] = E2;
i = 1; j = 0;
repeat (624) {
    mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525u)) + key[j] + j;
    if (++i == 624) { mt[0] = mt[623]; i = 1; }
    if (++j == 4) { j = 0; key[0] ^= d; }
    else key[j] ^= u32(d + 1);
}
repeat (623) {
    mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941u)) - i;
    if (++i == 624) { mt[0] = mt[623]; i = 1; }
}
mt[0] = 0x80000000u;
```

All arithmetic affecting mt/key is modulo 2^32. This uses O(N) time and O(N) state for N=624, plus four key words and O(1) auxiliary counters. State extent is `624*4=2,496 bytes`. First-pass destination indices are 1..623,1; second-pass indices are 2..623,1. The two wrap stores copy word 623 to word 0. The final force overwrites word 0.

The key-index wrap at `0x10038ECA0` XORs encoded word 0 with d. The other path at `0x100288ACC` XORs encoded words 1..3 with u32(d+1). Each word changes 156 times; paired XORs restore it, so the final material record equals its initial encoding. The local formulas are proved for arbitrary u32 key words and arbitrary u64 P.

The 24 independent replays compare all 624 resulting words with this compact model. With identical API scalar inputs, all four P representations produce different state hashes. This establishes allocator/address dependence in the declared cases; it does not establish native address disclosure, output distribution, or a downstream transport effect. The extra key mutation and arbitrary first entropy seed delimit any comparison with a canonical MT initializer.

## Initialized twist-table interface and current frontier

The earlier source store at `0x1002DC0C0` initializes eight bytes at F+`0x6D8`:

| Offset | Encoded u32 | XOR `0x94FDEAB5` |
| --- | --- | --- |
| F+`0x6D8` | `0x94FDEAB5` | 0 |
| F+`0x6DC` | `0x0DF55A6A` | `0x9908B0DF` |

At `0x10035C6F8`, the address is `F+0x6D8 + 4*(next_word & 1)`. Both choices occur among the numerical replays. The source uses current-word high bit, next-word lower bits and state[i+397]. A source-local proof for byte offsets 0..904, divisible by 4, establishes:

```text
y = (current & 0x80000000) | (next & 0x7FFFFFFF)
updated = far XOR (y >> 1) XOR ((next & 1) ? 0x9908B0DF : 0)
```

The source clears next's low bit before shifting; this yields the same shifted value. The full symbolic path stops before the data-dependent load because its memory model requires concrete addresses. The two addresses, table contents and following local update are established separately. This is an MT19937-style first-twist interface, not completed recovery of all twist phases, tempering, generator lifetime, or output consumers. No lookup or update beyond the frontier is executed by the whole-prefix replays.

## Unknownness, conditional failure, and verification

[Four symbolic journals](triage_evidence/daemon_seed_material_profiles.json) each retain 259,584 new source visits and 10,185 ordered SSA definitions. The old 112 arbitrary private bytes per context retain their origins; no additional unknown private input is used on this path. Exactly 1,250 new global state-word writes occur per context. The helper is invoked 1,871 times per context, with all input records and result stores decoded independently.

The inherited loader-tail probe list contains 524 events per context on already cached, source-defined state words. [The recovery audit](triage_evidence/daemon_seed_material_contracts.json) reconstructs prior cache availability and finds zero new tail materializations. These probes do not supply zero state words or replace the source's API-derived values.

[Twenty-four A64 replays](triage_evidence/daemon_seed_material_replays.json) match **7,260,744 source visits including prefixes**, of which **6,230,016 belong to this new continuation**. All GPR/vector/NZCV, read and write effects match. Tests cover two caller-clobber/backing patterns, four incoming representations, scalar boundary/reference cases, and two status/high-seconds sensitivity groups. Changing only status or high32 seconds preserves the mixed state in those groups. Padding stays unknown. These counts are software observations, not durations.

[The conditional failure experiment](triage_evidence/daemon_seed_material_failure.json) declares return -1 with no caller-output writes. Four source contexts retain zero defined output bytes, load four unknown byte origins at `0x1002DC30C`, and stop at `0x1002DC318` before their first non-copy arithmetic transformation. Sixteen isolated A64 replays execute only the three reader/setup instructions with varied physical backing bits; no input byte becomes source-defined and no memory write occurs. This supports the conditional source behavior. It does not observe a failing native API call, establish its output-write behavior, or establish consequences beyond the reader.

[Twenty-seven proof pairs](triage_evidence/daemon_seed_material_proofs.json) cover 209 lifted instruction visits in 19 slices, plus four nonempty-domain witnesses and the alignment counterexample. Static post-lookup proof coverage is separated from dynamic prefix coverage. [Independent checks](triage_evidence/daemon_seed_material_checks.json) also rerun four complete A64 cases. [Preservation](triage_evidence/daemon_seed_material_preservation.json) and [scoped gates](triage_evidence/daemon_seed_material_quality_gates.json) retain hashes and verification counts. Scripts scale with source visits, byte effects and serialized SSA bytes; solver complexity is separate, with a 30 s per-query limit.

No native API, actual Mach/IOKit operation, native PAC, or IDB mutation is performed. The global gate word at `0x1010B5DE0` is source-written `0xA94EF` at `0x1003133C8` and `0x5D96` at `0x1004875CC`; the latter precedes the twist frontier. Actual concurrent-reader synchronization remains unknown. The earlier comparison word `0x1010C8258` is not written in this continuation.

## Bounded continuation opportunities

| Impact | Next investigation | Discriminating evidence |
| --- | --- | --- |
| High | Complete twist phases, tempering and output consumers | Bounded two-entry memory model, source recurrences, output stores and def-use chains to established IPC buffers |
| High | Recover native/global lifecycle of `0x1010C8258` and gate ownership | Full writer/caller sets, nonzero branch, locking and publication order |
| High | Resolve arena-interior pointer production and lifetime | Source producer of F+0x358 and its owner/suballocation contract; separate pointer bits from entropy/clock inputs |
| Medium | Extend time error/errno contracts | Actual library implementation or observed write/status behavior; preserve unknown padding/output hypotheses |
| Medium | Relate state generation to daemon/kext messages | Proven output dependency at Mach/IOKit call sites; initialized state alone is insufficient |
| Low | Expand representation and source-library comparisons | Additional stack/heap/slides and bounded source comparisons without asserting build provenance |

## Scoped quality gates

| Gate | Result |
| --- | --- |
| QG1 | Pass: factual technical analysis |
| QG2 | Pass: SM1-SM14, dependency tags and falsification probes |
| QG3 | Pass for this increment: material/time/allocator interfaces, full mixed state, complete less-than leaf and first-twist boundary; full objective active |
| QG4 | Pass: u32/u64 arithmetic, byte extents, time units, loop counts and complexity explicit |
| QG5 | Pass: source-defined versus backing bytes, accessed footprint versus object size, fixed versus input-dependent control, failure hypothesis versus observation, and static versus replayed twist coverage distinguished |
| QG6 | Pass: pinned source/fixups, SDK primary documentation, live-IDB matching, SMT obligations and independent A64 effects |
| QG7 | Pass: bounded impact-labeled continuation table |

Full-goal completion is false.
