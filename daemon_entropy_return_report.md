# Daemon entropy return, scalar state initialization, and time ABI

The original continuation after `arc4random` at `0x100409574` initializes **624 contiguous u32 words at `0x1010C784C`**. Its compact recurrence matches the 32-bit MT19937 seed expansion in the installed libc++ primary source. The subsequent generator, its output consumers, and any role in daemon/kext messages remain unknown. This increment ends before the `gettimeofday` call at `0x1002DC308`; its immediate output consumers are separately recovered statically. The full interface investigation remains active.

The seed array and the earlier comparison input `0x1010C8258` are distinct storage. No new Mach port, IOKit selector, message emission, or right transfer is established here.

## Provenance and assumption register

Primary daemon: `/Users/___/Downloads/zut/fairplayd.arm64e`, SHA-256 `4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e`. Addresses are preferred image addresses, with declared private frame placements. [Contracts](triage_evidence/daemon_entropy_return_contracts.json) contain four original spans, three original authenticated fixups, an exhaustive 256-input bank, 188 matched live-IDB rows, installed SDK/header hashes, and compile-only arm64e ABI checks. The overlapping IDB views cover all 64 original instructions in the new path pool, including the unexecuted final call. Source/native identity beyond this pinned image remains unknown.

| ID | Assumption or boundary | Dependent results | Stress test / falsification probe |
| --- | --- | --- | --- |
| ER1 | The pinned thin daemon is the intended specimen | PCs, data addresses, routine identities | Rehash original bytes and import metadata; compare all new path bytes with the explicit live IDB |
| ER2 | The four sealed incoming contexts apply | Selected complete paths | Restore and check every prefix read/write and GPR boundary; independently replay each prefix with the continuation |
| ER3 | Declared frame/arena owners are valid and disjoint from the image | Memory effects | Check every A64 effective address and byte; reject unknown-dependent or out-of-owner accesses |
| ER4 | The declared API model supplies an arbitrary u32 result and makes no memory writes; its distribution and native side effects are unknown | Seed data flow | Symbolic seed plus arbitrary upper X0 bits; six finite seeds and two clobber patterns |
| ER5 | ABI preservation of SP, X18-X29 and D8-D15 low halves applies | Continuation state | Make X1-X17, remaining vector portions and NZCV arbitrary; verify all preserved values before/after the model |
| ER6 | Selected source instruction semantics are adequate | Universal source lemmas | Eleven paired SMT counterexample queries, independent A64 effect checks, and fail-closed unsupported operations |
| ER7 | Original fixups identify abstract decoded targets | Internal branches and import identity | Decode the three original words and bank; native PAC authentication and runtime resolution remain unknown |
| ER8 | The preceding fresh-image zero-fill and selected startup premises apply | Entry through the zero-word branch | Preserve the `0x1010C8258` premise; enumerate its other writers and nonzero continuation separately |
| ER9 | Preferred image addresses and two selected frame/arena placements bound representation coverage | Concrete addresses and counts | Re-run under additional placements/slides; arbitrary native ASLR is not proved |
| ER10 | The installed SDK is comparison evidence | API signature/layout and initializer correspondence | Hash headers and compile static assertions; the specimen's build SDK and source provenance remain unknown |
| ER11 | No time call has executed in this increment | Output unknownness and failure limits | All 16 output bytes lack source definitions at the boundary; establish actual API writes/status before any dynamic continuation |
| ER12 | Existing artifacts remain frozen except the six aggregate reporting/publisher paths | Preservation | Compare the 2,895-entry prior manifest, permit exactly six changes, and rehash the three original input files |

All runtime statements below depend on ER1-ER9. Installed-source comparisons additionally depend on ER10. Post-time dynamic behavior is conditional on readable API-output storage, ER11.

## Exact internal and external interfaces

These are flattened internal jump fragments; their register roles do not establish separately callable C functions.

| Site or storage | Recovered contract | Scope |
| --- | --- | --- |
| `0x100409574` | `_arc4random`, zero arguments, returned low 32 bits consumed | External call modeled; no entropy API executed |
| `0x100409578` | `STR W0,[X28]`; X28=`0x1010C784C` | First state word, not the comparison-control word |
| `0x100409584..0x1004095AC` | Initial index 1; phase constants and coefficient below | Original source setup |
| `0x1002FBEE4..0x1002FBF28` | One scalar seed expansion and indirect loop/exit selection | 623 iterations on every selected path |
| `0x101068588` | Index `0x5CD3` -> `0x1002FBEE4` | Original auth-rebase, IA diversity `0xD0A9`, address diversity 0 |
| `0x101068658` | Index `0x5CED` -> `0x1002DC290` | Original auth-rebase, same diversity |
| `0x1010C784C..0x1010C820B` | 624 u32 words, 2,496 bytes, inside `__DATA,__common` | Complete source-written state extent before the time call |
| `0x1002DC2A0` | Store 624 at frame+`0x60C` | Local completion/index value; wider lifecycle role unknown |
| `0x1002DC2A4..0x1002DC2A8` | frame+`0x580` contains frame+`0x670`; X0 becomes frame+`0x680` | First time-call argument |
| `0x10109FF20` | `_gettimeofday` from `/usr/lib/libSystem.B.dylib` | Original auth-bind, import 142, IA diversity `0x9298`, total addend 0 |
| `0x1002DC308` | `gettimeofday(frame+0x680,NULL)` | Boundary opcode retained; time call unexecuted |
| `0x1010C8258` | Earlier zero/nonzero comparison input | No write to this word in the new continuation |

```text
arc4random() -- low32 --> [0x1010C784C] = state[0]
                              |
                         623 expansions
                              v
                      state[0..623], 2496 B
                              |
                      frame+0x60C = 624
                              |
                 gettimeofday(frame+0x680, NULL)
                              |  not executed here
             seconds low32 / microseconds u32
                              v
               XOR 0x5CF7672B -> frame+0x678/+0x674
```

## Compact seed semantics and proof domain

All word arithmetic is modulo 2^32; addresses are u64. The source's obfuscation phases satisfy `0x55B365AE + 0xAA4C9A53 = 1 (mod 2^32)`.

```c
state[0] = entropy_u32;
for (uint32_t i = 1; i <= 623; ++i) {
    uint32_t previous = state[i - 1];
    state[i] = 0x6C078965u * (previous ^ (previous >> 30)) + i;
}
frame_word_0x60C = 624;
```

The carried W0 and stored word agree on every iteration. The source's W9 phase enters as `i-1+0x55B365AE` and leaves as `i+0x55B365AE`. The exit selector is `((i>622 ? 62 : 0) XOR 0x5CD3)`, with an unsigned comparison. Starting at 1, the first exit is after writing index 623. The initializer uses O(624) time, O(1) auxiliary words and 624 words of output state. State extent is `624 words * 4 bytes/word = 2,496 bytes`; the last word begins at `0x1010C8208`.

[Eleven source proof pairs](triage_evidence/daemon_entropy_return_proofs.json) lift 77 instruction visits across six slices. They establish the seed store, setup, all-u32 recurrence/carry, single-word destination, inductive phase/index, termination selector, time arguments/cursor, controller formula, time import under its exhaustive bank lemma, and both time-output codecs. The loop domain is u64 index 1..623 and an aligned nonwrapping frame; four SAT premise witnesses cover both frame placements and endpoint indices. This is a source-level induction contract, distinct from finite replay coverage.

The installed libc++ header `__random/mersenne_twister_engine.h` contains the same seed rule at lines 179-183 and the `mt19937` parameters including width 32, state size 624 and coefficient 1812433253 at lines 450-466. Its file hash and exact matched declarations are in the contracts. The SDK initializer resets its own internal cursor to 0, whereas the recovered source stores 624 in a private frame field whose later lifecycle is unknown; no object-layout equivalence follows. These facts identify the recovered initialization recurrence. They do not establish the specimen's twist/tempering implementation, distribution, runtime seed quality, or a dependency on libc++.

## Time ABI, import selection, and immediate output consumers

Let A and B be the low u32 words read through `0x1010B7DD8` and `0x1010C4670`. The original controller projection is `t=u32(((A+B) XOR 0xA6)*0x0A5CD4CF)`. For the actual source byte banks L=`0x100FC4230`, R=`0x101031FA0`, exhaustive enumeration proves `x XOR R[L[x] XOR 0xF3] = 0x43` for every byte x. Consequently, the selected table index is always `0xCBC3+0x43=0xCC06`, slot `0x10109FF20`. The source proof covers every u32 A/B and every resulting t under that checked bank lemma. The call has two arguments; untouched X2-X7 are caller-saved remnants and have no established argument role.

Compile-only installed arm64e SDK checks establish:

| `struct timeval` component | Offset / extent | Observed consumer |
| --- | --- | --- |
| `tv_sec` | +0, 8 bytes | `LDR W8,[X22,#0x10]` at `0x1002DC30C` reads only low 32 bits |
| `tv_usec` | +8, 4 bytes | `LDR W8,[X22,#0x18]` at `0x1002DC334` |
| Tail padding | +12, 4 bytes | No read in the immediate consumer slice |
| Whole object | 16 bytes, alignment 8 | X22=frame+`0x670`; API pointer=X22+`0x10` |

Units are seconds for `tv_sec` and microseconds for `tv_usec` (`1 us = 10^-6 s`). No wall-clock sample or microsecond-range validation is supplied here. The fixed phase at this boundary reduces both output transforms to XOR:

| Source operation | Stored scalar | Destination |
| --- | --- | --- |
| `0x1002DC30C..0x1002DC330` | `low32(tv_sec) XOR 0x5CF7672B` | frame+`0x678`, private record+8 |
| `0x1002DC334..0x1002DC350` | `u32(tv_usec) XOR 0x5CF7672B` | frame+`0x674`, private record+4 |

The output pointer's complete 16-byte range has **zero source-defined bytes** before the call in all four incoming contexts and the new continuation. It is separate from the earlier source-filled frame+`0x6F0` region. The very next instruction reads the seconds word. A 37-instruction straight-line liveness audit from `0x1002DC30C` to the next entropy call at `0x1002DC3A0` finds no X0/W0 read or write. Thus the integer time-return status does not gate these immediate output reads. Actual API failure, output-write behavior, native uninitialized-data behavior and later consequences remain unknown. No failing native execution is claimed.

## Verification and preserved scope

[Symbolic profiles](triage_evidence/daemon_entropy_return_profiles.json) retain four exact continuations: **11,259 new source visits each**, 64 distinct instruction rows including the next call, and 2,501 ordered SSA definitions per context. The definitions preserve exact data expressions without expanding a recurrence into a repeated expression tree. Addresses and control targets must remain concrete; unsupported operations and transformed private unknown inputs fail closed. The source path contains 15 setup visits, 623*18 iteration visits and 30 pre-call visits: `15+11,214+30=11,259`.

[Independent A64 replays](triage_evidence/daemon_entropy_return_replays.json) cover seeds 0, 1, 5489, `0x12345678`, `0x80000000`, `0xFFFFFFFF`; two arbitrary caller-clobber/private-backing patterns; and original context indices 0, 1, 16, 17. All **48 replays**, totaling **2,061,456 source visits including the preserved prefixes**, match every recorded GPR/vector/NZCV and memory effect. They independently compare all 624 output words against the compact recurrence. Private unknown bytes retain their earlier origins and masks. These are software observation counts, not durations.

[Independent checks](triage_evidence/daemon_entropy_return_checks.json) also rerun four complete prefix/continuation cases, both forms of all eleven SMT queries, source bytes/fixups/SDK checks, and post-time status liveness. [Preservation](triage_evidence/daemon_entropy_return_preservation.json) checks 2,895 prior artifacts and the three original inputs; only the five aggregate reports and aggregate manifest publisher may change. The new scripts use time/space proportional to traced visits, byte events, ordered expression serialization and the largest journal; SMT solver complexity is separate and each query is bounded to 30 s.

The declared entropy-return model performs no memory writes; library state and other native side effects are outside coverage. No native entropy/time API, actual Mach/IOKit operation, native PAC, or IDB mutation occurs. Library-internal entropy/time transport is unknown. The selected inter-call source stretch establishes no new Mach port emission or right transfer.

## Bounded continuation opportunities

| Impact | Next investigation | Evidence that resolves it |
| --- | --- | --- |
| High | Trace the state generator and every state-array consumer | Original writers/readers, twist/tempering source semantics, and downstream IPC buffer dependencies |
| High | Complete time success/failure and subsequent entropy flow | Exact API-defined bytes/status contract; preserve padding/unknown bytes and trace the next two entropy results |
| High | Recover writers and lifecycle of `0x1010C8258` | Full writer set, synchronization/readiness ordering, and the nonzero continuation |
| Medium | Determine the complete frame+`0x670` private record and lifetime | All field writers/readers, escape sites and callback ownership |
| Medium | Relate initialized state and time scalars to daemon/kext messages | Def-use chains ending at established Mach descriptors or IOKit argument buffers; shared constants alone are insufficient |
| Low | Expand placement, slide and compiler comparison coverage | Additional explicit representations and source comparisons without asserting build provenance |

## Scoped quality gates

| Gate | Result and evidence |
| --- | --- |
| QG1 | Pass: factual technical analysis |
| QG2 | Pass: ER1-ER12 and their falsification probes |
| QG3 | Pass for this increment: entropy return, complete seed expansion, next time ABI and immediate consumers; full objective remains active |
| QG4 | Pass: u32/u64 widths, 2,496-byte extent, timeval layout, units and software counts explicit |
| QG5 | Pass: seed/control storage, API arguments/remnants, symbolic/finite/native coverage, output/padding and initializer/generator limits separated |
| QG6 | Pass: pinned original source, complete path IDB-byte coverage, fixups, SDK primary sources, proofs and independent A64 replay |
| QG7 | Pass: impact-labeled continuation opportunities bounded to unresolved interfaces |

The [machine-readable scoped gates](triage_evidence/daemon_entropy_return_quality_gates.json) retain validation counts and provenance hashes. Full-goal completion is false.
